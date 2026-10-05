using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Pinhole.Turn;
using Xunit;

namespace Pinhole.Tests;

/// <summary>An in-process RFC 5766 TURN server that actually enforces the protocol: 401
/// challenge, long-term-credential MESSAGE-INTEGRITY on every authenticated request,
/// nonce rotation with 438, allocation expiry, and permission-gated relayed data.</summary>
public sealed class FakeTurnServer : IDisposable
{
    private const uint Cookie = 0x2112A442;
    private const ushort TypeAllocate = 0x0003;
    private const ushort TypeRefresh = 0x0004;
    private const ushort TypeSendInd = 0x0016;
    private const ushort TypeCreatePerm = 0x0008;
    private const ushort ClassError = 0x0110;

    private const ushort AttrUsername = 0x0006;
    private const ushort AttrMessageIntegrity = 0x0008;
    private const ushort AttrErrorCode = 0x0009;
    private const ushort AttrLifetime = 0x000D;
    private const ushort AttrXorPeerAddress = 0x0012;
    private const ushort AttrData = 0x0013;
    private const ushort AttrRealm = 0x0014;
    private const ushort AttrNonce = 0x0015;
    private const ushort AttrXorRelayed = 0x0016;
    private const ushort AttrXorMapped = 0x0020;

    private readonly Socket _main;
    private readonly string _realm;
    private readonly string _user;
    private readonly int _lifetimeSeconds;
    private readonly byte[] _key;
    private readonly Dictionary<EndPoint, Allocation> _byControl = new();
    private readonly Dictionary<IPEndPoint, Allocation> _byRelayed = new();
    private readonly byte[] _buf = new byte[4096];
    private int _nonceVersion;
    private volatile bool _running = true;

    public FakeTurnServer(string realm = "pinhole-test", string user = "user", string password = "pass", int lifetimeSeconds = 600, int port = 0, IPAddress? bindAddress = null)
    {
        _realm = realm;
        _user = user;
        _lifetimeSeconds = lifetimeSeconds;
        _key = MD5.HashData(Encoding.UTF8.GetBytes($"{user}:{realm}:{password}"));
        _main = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _main.ReceiveTimeout = 200; // bounded wakeups keep dispose from wedging on macOS
        _main.Bind(new IPEndPoint(bindAddress ?? IPAddress.Loopback, port));
        Control = (IPEndPoint)_main.LocalEndPoint!;
        new Thread(Run) { IsBackground = true, Name = "fake-turn" }.Start();
    }

    private sealed class Allocation
    {
        public required Socket RelayPortHolder;
        public required IPEndPoint Relayed;
        public required EndPoint Control;
        public required DateTimeOffset ExpiresAt;
        public required HashSet<IPAddress> Permitted;
    }

    public IPEndPoint Control { get; }

    public int StaleNonceReplies { get; private set; }
    public int RefreshSuccesses { get; private set; }
    public int BadIntegrityRejections { get; private set; }
    public int ExpiredRejections { get; private set; }
    public int PermissionsGranted { get; private set; }
    public int InboundDropped { get; private set; }
    public int SendsReceived { get; private set; }
    public int SendsForwarded { get; private set; }
    public int SendsUnknownTarget { get; private set; }
    public int AllocateRejections { get; private set; }

    public void RotateNonce() => Interlocked.Increment(ref _nonceVersion);

    /// <summary>Test seam: the next N permission requests are silently dropped — a lost UDP
    /// request that proves nothing about the allocation's health.</summary>
    public int DropNextPermissions;

    /// <summary>Test seam: when non-zero, every authenticated ALLOCATE is refused with this
    /// error code (e.g. 429 quota, 401 revoked credentials) and no allocation is made.
    /// Counts in <see cref="AllocateRejections"/> so a test can bound retry storms.</summary>
    public int RejectAllocationsWithCode;

    /// <summary>When true (the default), a data indication is only delivered to an
    /// allocation that holds a permission for the SENDER's relayed address — the RFC 5766
    /// receive-side gate real TURN servers enforce and the sender-side check above does
    /// not. Turning it off reproduces the lab's historical permissive behavior.</summary>
    public bool StrictInbound = true;

    /// <summary>Total successful allocations over this server's lifetime — a realloc flap
    /// detector for the relay-recovery tests.</summary>
    public int Allocations { get; private set; }

    private string CurrentNonce => $"n{Volatile.Read(ref _nonceVersion) + 1}";

    private void Run()
    {
        while (_running)
        {
            int n;
            EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
            try
            {
                n = _main.ReceiveFrom(_buf, SocketFlags.None, ref remote);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                continue;
            }

            if (n < 20)
            {
                continue;
            }

            ushort type = BinaryPrimitives.ReadUInt16BigEndian(_buf);
            byte[] msg = _buf[..n];
            byte[] txid = msg[8..20];
            try
            {
                List<(ushort Type, byte[] Value)> attrs = ParseAttrs(msg);
                switch (type)
                {
                    case TypeAllocate:
                        HandleAllocate(remote, msg, txid, attrs);
                        break;
                    case TypeRefresh:
                        HandleRefresh(remote, msg, txid, attrs);
                        break;
                    case TypeCreatePerm:
                        HandlePermission(remote, msg, txid, attrs);
                        break;
                    case TypeSendInd:
                        HandleSendIndication(remote, attrs);
                        break;
                }
            }
            catch (SocketException)
            {
                // A reply to a client that disposed mid-flight (ICMP unreachable) must cost
                // one datagram — an unhandled throw on this thread kills the test host.
            }
            catch (ObjectDisposedException)
            {
                return;
            }
        }
    }

    private void HandleAllocate(EndPoint remote, byte[] msg, byte[] txid, List<(ushort Type, byte[] Value)> attrs)
    {
        if (attrs.All(a => a.Type != AttrUsername))
        {
            ReplyError(remote, TypeAllocate | ClassError, txid, 401, "Unauthorized");
            return;
        }

        if (!ValidateAuth(msg, attrs, out string presentedNonce))
        {
            BadIntegrityRejections++;
            ReplyError(remote, TypeAllocate | ClassError, txid, 401, "Unauthorized");
            return;
        }

        if (presentedNonce != CurrentNonce)
        {
            StaleNonceReplies++;
            ReplyError(remote, TypeAllocate | ClassError, txid, 438, "Stale Nonce");
            return;
        }

        if (RejectAllocationsWithCode is var injected and not 0)
        {
            AllocateRejections++;
            ReplyError(remote, TypeAllocate | ClassError, txid, (ushort)injected, "Injected");
            return;
        }

        var portHolder = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        portHolder.Bind(new IPEndPoint(((IPEndPoint)_main.LocalEndPoint!).Address, 0));
        var relayed = (IPEndPoint)portHolder.LocalEndPoint!;
        var alloc = new Allocation
        {
            RelayPortHolder = portHolder,
            Relayed = relayed,
            Control = remote,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(_lifetimeSeconds),
            Permitted = new HashSet<IPAddress>(),
        };
        lock (_byControl) _byControl[remote] = alloc;
        lock (_byRelayed) _byRelayed[relayed] = alloc;
        Allocations++;

        Reply(remote, Build(TypeAllocate | 0x0100, txid,
            Attr(AttrXorRelayed, Xor(relayed)),
            Attr(AttrXorMapped, Xor((IPEndPoint)remote)),
            Attr(AttrLifetime, U32((uint)_lifetimeSeconds))));
    }

    private void HandleRefresh(EndPoint remote, byte[] msg, byte[] txid, List<(ushort Type, byte[] Value)> attrs)
    {
        if (!ValidateAuth(msg, attrs, out string presentedNonce))
        {
            BadIntegrityRejections++;
            ReplyError(remote, TypeRefresh | ClassError, txid, 401, "Unauthorized");
            return;
        }

        if (presentedNonce != CurrentNonce)
        {
            StaleNonceReplies++;
            ReplyError(remote, TypeRefresh | ClassError, txid, 438, "Stale Nonce");
            return;
        }

        Allocation? alloc;
        lock (_byControl) _byControl.TryGetValue(remote, out alloc);
        if (alloc is null || alloc.ExpiresAt < DateTimeOffset.UtcNow)
        {
            ExpiredRejections++;
            ReplyError(remote, TypeRefresh | ClassError, txid, 437, "Allocation Mismatch");
            return;
        }

        alloc.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(_lifetimeSeconds);
        RefreshSuccesses++;
        Reply(remote, Build(TypeRefresh | 0x0100, txid, Attr(AttrLifetime, U32((uint)_lifetimeSeconds))));
    }

    private void HandlePermission(EndPoint remote, byte[] msg, byte[] txid, List<(ushort Type, byte[])> attrs)
    {
        if (DropNextPermissions > 0)
        {
            DropNextPermissions--;
            return; // the request vanishes: no reply, no state change — pure loss
        }

        if (!ValidateAuth(msg, attrs, out string presentedNonce))
        {
            BadIntegrityRejections++;
            ReplyError(remote, TypeCreatePerm | ClassError, txid, 401, "Unauthorized");
            return;
        }

        if (presentedNonce != CurrentNonce)
        {
            StaleNonceReplies++;
            ReplyError(remote, TypeCreatePerm | ClassError, txid, 438, "Stale Nonce");
            return;
        }

        Allocation? alloc;
        lock (_byControl) _byControl.TryGetValue(remote, out alloc);
        if (alloc is null || alloc.ExpiresAt < DateTimeOffset.UtcNow)
        {
            ExpiredRejections++;
            ReplyError(remote, TypeCreatePerm | ClassError, txid, 437, "Allocation Mismatch");
            return;
        }

        byte[]? peer = attrs.FirstOrDefault(a => a.Type == AttrXorPeerAddress).Item2;
        if (peer is not null && peer.Length >= 8)
        {
            alloc.Permitted.Add(Unxor(peer).Address);
        }

        PermissionsGranted++;
        Reply(remote, Build(TypeCreatePerm | 0x0100, txid));
    }

    private void HandleSendIndication(EndPoint remote, List<(ushort Type, byte[] Value)> attrs)
    {
        Allocation? alloc;
        lock (_byControl) _byControl.TryGetValue(remote, out alloc);
        if (alloc is null)
        {
            return;
        }

        SendsReceived++;

        if (alloc.ExpiresAt < DateTimeOffset.UtcNow)
        {
            ExpiredRejections++;
            return;
        }

        byte[]? peerRaw = attrs.FirstOrDefault(a => a.Type == AttrXorPeerAddress).Value;
        byte[]? data = attrs.FirstOrDefault(a => a.Type == AttrData).Value;
        if (peerRaw is not { Length: >= 8 } || data is null)
        {
            return;
        }

        IPEndPoint peer = Unxor(peerRaw);
        if (!alloc.Permitted.Contains(peer.Address))
        {
            return;
        }

        Allocation? target;
        lock (_byRelayed) _byRelayed.TryGetValue(peer, out target);
        if (target is null)
        {
            SendsUnknownTarget++;
            return;
        }

        // The receive-side half of RFC 5762/5766 permissions: delivery requires the
        // RECEIVER's allocation to permit the sender's relayed address too. Without this
        // gate the lab cannot see permission-bootstrap bugs — everything would just flow.
        if (StrictInbound && !target.Permitted.Contains(alloc.Relayed.Address))
        {
            InboundDropped++;
            return;
        }

        byte[] indTxid = RandomNumberGenerator.GetBytes(12);
        byte[] ind = Build(0x0017, indTxid, Attr(AttrXorPeerAddress, Xor(alloc.Relayed)), Attr(AttrData, data));
        SendsForwarded++;
        Reply(target.Control, ind);
    }

    private bool ValidateAuth(byte[] msg, List<(ushort Type, byte[] Value)> attrs, out string nonce)
    {
        nonce = "";
        string? user = null, realm = null, presented = null;
        byte[]? mi = null;
        int miOffset = -1;
        int pos = 20;
        foreach ((ushort t, byte[] v) in attrs)
        {
            if (t == AttrUsername) user = Encoding.UTF8.GetString(v);
            else if (t == AttrRealm) realm = Encoding.UTF8.GetString(v);
            else if (t == AttrNonce) presented = Encoding.UTF8.GetString(v);
            else if (t == AttrMessageIntegrity) { mi = v; miOffset = pos; }

            pos += 4 + ((v.Length + 3) & ~3);
        }

        if (mi is null || user != _user || realm != _realm || presented is null)
        {
            return false;
        }

        byte[] expected = HMACSHA1.HashData(_key, msg.AsSpan(0, miOffset));
        if (!expected.AsSpan().SequenceEqual(mi))
        {
            return false;
        }

        nonce = presented;
        return true;
    }

    private static List<(ushort Type, byte[] Value)> ParseAttrs(byte[] msg)
    {
        var list = new List<(ushort, byte[])>();
        int end = Math.Min(msg.Length, 20 + BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(2)));
        int pos = 20;
        while (pos + 4 <= end)
        {
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(pos));
            int len = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(pos + 2));
            int vlen = Math.Min(len, end - pos - 4);
            if (vlen >= 0)
            {
                list.Add((type, msg.AsSpan(pos + 4, vlen).ToArray()));
            }

            pos += 4 + ((len + 3) & ~3);
        }

        return list;
    }

    private void Reply(EndPoint to, byte[] msg) => _main.SendTo(msg, SocketFlags.None, to);

    private void ReplyError(EndPoint to, ushort errorType, byte[] txid, int code, string reason)
    {
        byte[] errCode = new byte[4 + reason.Length];
        errCode[2] = (byte)(code / 100);
        errCode[3] = (byte)(code % 100);
        Encoding.ASCII.GetBytes(reason).CopyTo(errCode, 4);
        Reply(to, Build(errorType, txid, Attr(AttrErrorCode, errCode), Attr(AttrRealm, Utf8(_realm)), Attr(AttrNonce, Utf8(CurrentNonce))));
    }

    private static byte[] Build(ushort type, byte[] txid, params byte[][] attrs)
    {
        int body = attrs.Sum(a => a.Length);
        byte[] msg = new byte[20 + body];
        BinaryPrimitives.WriteUInt16BigEndian(msg, type);
        BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(2), (ushort)body);
        BinaryPrimitives.WriteUInt32BigEndian(msg.AsSpan(4), Cookie);
        txid.CopyTo(msg, 8);
        int pos = 20;
        foreach (byte[] a in attrs)
        {
            a.CopyTo(msg, pos);
            pos += a.Length;
        }

        return msg;
    }

    private static byte[] Attr(ushort type, ReadOnlySpan<byte> value)
    {
        byte[] a = new byte[4 + ((value.Length + 3) & ~3)];
        BinaryPrimitives.WriteUInt16BigEndian(a, type);
        BinaryPrimitives.WriteUInt16BigEndian(a.AsSpan(2), (ushort)value.Length);
        value.CopyTo(a.AsSpan(4));
        return a;
    }

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] U32(uint v)
    {
        byte[] b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        return b;
    }

    private static byte[] Xor(IPEndPoint ep)
    {
        byte[] raw = ep.Address.GetAddressBytes();
        byte[] dst = new byte[4 + raw.Length];
        dst[1] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(dst.AsSpan(2), (ushort)(ep.Port ^ (Cookie >> 16)));
        for (int i = 0; i < raw.Length; i++)
        {
            dst[4 + i] = i < 4 ? (byte)(raw[i] ^ (byte)(Cookie >> (24 - i * 8))) : raw[i];
        }

        return dst;
    }

    private static IPEndPoint Unxor(byte[] value)
    {
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(2));
        port ^= (ushort)(Cookie >> 16);
        Span<byte> raw = stackalloc byte[4];
        for (int i = 0; i < 4; i++)
        {
            raw[i] = (byte)(value[4 + i] ^ (byte)(Cookie >> (24 - i * 8)));
        }

        return new IPEndPoint(new IPAddress(raw), port);
    }

    public void Dispose()
    {
        _running = false;
        _main.Dispose();
        lock (_byControl)
        {
            foreach (Allocation alloc in _byControl.Values)
            {
                alloc.RelayPortHolder.Dispose();
            }
        }
    }
}

public sealed class TurnClientTests
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task Allocate_ChallengeAuth_And_RelayDataBothWays()
    {
        using FakeTurnServer server = new();
        await using TurnClient a = await TurnClient.AllocateAsync(server.Control, "user", "pass");
        await using TurnClient b = await TurnClient.AllocateAsync(server.Control, "user", "pass");

        Assert.NotNull(a.RelayedAddress);
        Assert.NotNull(b.RelayedAddress);
        Assert.NotEqual(a.RelayedAddress, b.RelayedAddress);
        Assert.True(a.IsAlive);
        Assert.Equal(0, server.BadIntegrityRejections);

        var aGot = new TaskCompletionSource<(IPEndPoint From, byte[] Data)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var bGot = new TaskCompletionSource<(IPEndPoint From, byte[] Data)>(TaskCreationOptions.RunContinuationsAsynchronously);
        a.Received += (from, data) => aGot.TrySetResult((from, data));
        b.Received += (from, data) => bGot.TrySetResult((from, data));

        await a.CreatePermissionAsync(b.RelayedAddress!.Address);
        await b.CreatePermissionAsync(a.RelayedAddress!.Address);

        a.Send("alpha"u8.ToArray(), b.RelayedAddress);
        b.Send("beta"u8.ToArray(), a.RelayedAddress);

        (IPEndPoint fromAtA, byte[] atA) = await aGot.Task.WaitAsync(DefaultTimeout);
        (IPEndPoint fromAtB, byte[] atB) = await bGot.Task.WaitAsync(DefaultTimeout);
        Assert.Equal("beta"u8.ToArray(), atA);
        Assert.Equal("alpha"u8.ToArray(), atB);
        Assert.Equal(b.RelayedAddress, fromAtA);
        Assert.Equal(a.RelayedAddress, fromAtB);
    }

    [Fact]
    public async Task SendAsync_PermissionIsCached()
    {
        using FakeTurnServer server = new();
        await using TurnClient a = await TurnClient.AllocateAsync(server.Control, "user", "pass");
        await using TurnClient b = await TurnClient.AllocateAsync(server.Control, "user", "pass");

        var bGot = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        int seen = 0;
        b.Received += (_, _) => { if (Interlocked.Increment(ref seen) == 2) bGot.TrySetResult(seen); };

        // Receive-side permission, as RFC 5766 requires before the server delivers anything
        // to b's allocation (the fake enforces it by default now).
        await b.CreatePermissionAsync(a.RelayedAddress!.Address);

        await a.SendAsync("one"u8.ToArray(), b.RelayedAddress!);
        await a.SendAsync("two"u8.ToArray(), b.RelayedAddress!);
        await bGot.Task.WaitAsync(DefaultTimeout);

        // Two permissions total: b's explicit one, and exactly one lazy sender-side permit
        // for the peer despite two sends — the cache is the subject.
        Assert.Equal(2, server.PermissionsGranted);
    }

    [Fact]
    public async Task StaleNonce_And_AllocationRefresh_KeepRelayAlive()
    {
        // 9 s allocation: the client refreshes every 5 s tick, so without working refresh the
        // allocation expires and later sends/rejects are observable server-side.
        using FakeTurnServer server = new(lifetimeSeconds: 9);
        await using TurnClient a = await TurnClient.AllocateAsync(server.Control, "user", "pass");
        await using TurnClient b = await TurnClient.AllocateAsync(server.Control, "user", "pass");

        var aGot = new TaskCompletionSource<(IPEndPoint, byte[])>(TaskCreationOptions.RunContinuationsAsynchronously);
        a.Received += (from, data) => aGot.TrySetResult((from, data));
        await a.CreatePermissionAsync(b.RelayedAddress!.Address);
        await b.CreatePermissionAsync(a.RelayedAddress!.Address);
        b.Send("before"u8.ToArray(), a.RelayedAddress);
        (IPEndPoint _, byte[] before) = await aGot.Task.WaitAsync(DefaultTimeout);
        Assert.Equal("before"u8.ToArray(), before);

        server.RotateNonce();
        await Task.Delay(TimeSpan.FromSeconds(13)); // original expiry was 9 s

        Assert.True(server.StaleNonceReplies >= 1, $"expected 438s after rotation, got {server.StaleNonceReplies}");
        Assert.True(server.RefreshSuccesses >= 1, "allocation was never refreshed");
        Assert.Equal(0, server.BadIntegrityRejections);
        Assert.Equal(0, server.ExpiredRejections);

        var aGot2 = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        a.Received += (_, data) => aGot2.TrySetResult(data);
        b.Send("after"u8.ToArray(), a.RelayedAddress);
        byte[] after = await aGot2.Task.WaitAsync(DefaultTimeout);
        Assert.Equal("after"u8.ToArray(), after);
        Assert.True(a.IsAlive);
        Assert.True(b.IsAlive);
    }

    [Fact]
    public async Task RecvLoop_SurvivesGarbagePackets()
    {
        using FakeTurnServer server = new();
        await using TurnClient a = await TurnClient.AllocateAsync(server.Control, "user", "pass");

        // Blast non-STUN garbage at the client's socket; a strict receive loop would exit.
        using Socket junk = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        byte[] noise = new byte[64];
        Random.Shared.NextBytes(noise);
        for (int i = 0; i < 200; i++)
        {
            junk.SendTo(noise, SocketFlags.None, a.LocalEndPoint);
        }

        await using TurnClient b = await TurnClient.AllocateAsync(server.Control, "user", "pass");
        await a.CreatePermissionAsync(b.RelayedAddress!.Address);
        await b.CreatePermissionAsync(a.RelayedAddress!.Address);
        var aGot = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        a.Received += (_, data) => aGot.TrySetResult(data);
        b.Send("post-noise"u8.ToArray(), a.RelayedAddress);
        byte[] got = await aGot.Task.WaitAsync(DefaultTimeout);
        Assert.Equal("post-noise"u8.ToArray(), got);
        Assert.True(a.IsAlive);
    }

    [Fact]
    public async Task DisposeAsync_CompletesPromptly()
    {
        using FakeTurnServer server = new();
        TurnClient a = await TurnClient.AllocateAsync(server.Control, "user", "pass");
        ValueTask dispose = a.DisposeAsync();
        await dispose.AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(a.IsAlive);
    }
}
