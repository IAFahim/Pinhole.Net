using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Pinhole.Turn;

/// <summary>The server answered and refused: a definitive error response (437 allocation
/// mismatch, 401 after re-auth, …) proving the credentials or allocation this client holds
/// are unusable on that server. Distinct from a timeout or transport fault, which proves
/// nothing — callers must treat this type as retire-the-client evidence and everything
/// else as transient.</summary>
public sealed class TurnRejectException(int code, string reason)
    : InvalidOperationException($"TURN {code} {reason}")
{
    /// <summary>The RFC 5766 error code the server answered with.</summary>
    public int Code { get; } = code;
}

/// <summary>
/// A relayed connection through any RFC 5766 TURN server: allocate, refresh, permission and
/// send/data indications over one UDP socket, authenticated with long-term credentials.
/// No native dependencies. Allocation and permission refreshes run on a background loop;
/// a 438 stale nonce is adopted and the request retried once. Inbound payloads surface via
/// <see cref="Received"/>; the address peers send to is <see cref="RelayedAddress"/>.
/// </summary>
public sealed class TurnClient : IAsyncDisposable
{
    private const uint Cookie = 0x2112A442;
    private const ushort MethodAllocate = 0x0003;
    private const ushort MethodRefresh = 0x0004;
    private const ushort MethodSendIndication = 0x0016;
    private const ushort MethodDataIndication = 0x0017;
    private const ushort MethodCreatePermission = 0x0008;
    private const ushort ClassError = 0x0110;
    private const int StaleNonceCode = 438;

    private const ushort AttrMappedAddress = 0x0001;
    private const ushort AttrUsername = 0x0006;
    private const ushort AttrMessageIntegrity = 0x0008;
    private const ushort AttrErrorCode = 0x0009;
    private const ushort AttrLifetime = 0x000D;
    private const ushort AttrXorPeerAddress = 0x0012;
    private const ushort AttrData = 0x0013;
    private const ushort AttrRealm = 0x0014;
    private const ushort AttrNonce = 0x0015;
    private const ushort AttrXorRelayedAddress = 0x0016;
    private const ushort AttrRequestedTransport = 0x0019;

    private static readonly TimeSpan TransactTimeout = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan PermissionRefreshEvery = TimeSpan.FromSeconds(240);

    private readonly Socket _udp;
    private readonly string _username;
    private readonly string _credential;
    private readonly ConcurrentDictionary<ulong, TaskCompletionSource<byte[]>> _pending = new();
    private readonly Dictionary<IPAddress, DateTimeOffset> _permitted = new();
    private readonly CancellationTokenSource _shutdown = new();
    private byte[] _integrityKey = Array.Empty<byte>();
    private string? _realm;
    private string? _nonce;
    private int _lifetime = 600;
    private DateTimeOffset _lastAllocate = DateTimeOffset.UtcNow;
    private int _refreshFailures;
    private int _disposed;

    private TurnClient(IPEndPoint server, string username, string credential)
    {
        _username = username;
        _credential = credential;
        Server = server;
        Username = username;
        Credential = credential;
        _udp = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        // Blocked receives must wake up periodically: closing the socket while a sync
        // receive holds it spins forever in SafeSocketHandle.CloseAsIs on macOS, so
        // disposal needs the receive loop to come back and observe the disposed flag.
        _udp.ReceiveTimeout = 200;
        if (OperatingSystem.IsWindows())
        {
            const int sioUdpConnreset = -1744830452;
            _udp.IOControl(sioUdpConnreset, new byte[] { 0 }, null);
        }

        _udp.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0));
        _udp.Connect(server);
        LocalEndPoint = (IPEndPoint)_udp.LocalEndPoint!;
        Thread recv = new(RecvLoop) { IsBackground = true, Name = "turn-recv" };
        recv.Start();
    }

    /// <summary>Local endpoint of the relay socket, bound before the allocation handshake and valid as soon as the client exists. This is not the address peers should send to — that is <see cref="RelayedAddress"/>.</summary>
    public IPEndPoint LocalEndPoint { get; }

    /// <summary>The TURN server being relayed through, as passed to <see cref="AllocateAsync(IPEndPoint, string, string, CancellationToken)"/>. The socket is connected to it; every packet this client exchanges goes to this endpoint only.</summary>
    public IPEndPoint Server { get; }

    /// <summary>The long-term-credential username (RFC 5389) supplied at allocation.</summary>
    public string Username { get; }

    /// <summary>The long-term-credential secret supplied at allocation. Kept in plain memory for the client's whole life — it re-derives the integrity key whenever the server rotates its realm — so it cannot be scrubbed on dispose.</summary>
    public string Credential { get; }

    /// <summary>The relayed address the server allocated: the address peers send to. Null until <see cref="AllocateAsync(IPEndPoint, string, string, CancellationToken)"/> succeeds; fixed for the client's lifetime after that.</summary>
    public IPEndPoint? RelayedAddress { get; private set; }

    /// <summary>False once the socket is gone: after <see cref="DisposeAsync"/>, after a failed allocation, or after three consecutive failed allocation refreshes — the refresh loop closes the socket then so traffic fails visibly instead of black-holing. An internal flag, not a probe: a path that died quietly still reports true.</summary>
    public bool IsAlive => Volatile.Read(ref _disposed) == 0;

    /// <summary>Raised with the origin peer and payload of every Data Indication. Handlers run synchronously on the dedicated receive thread — the same thread that completes permission and refresh transactions — so a slow handler stalls both directions of the client, and a throwing handler becomes an unhandled thread exception. Each payload array is a private copy and may be retained.</summary>
    public event Action<IPEndPoint, byte[]>? Received;

    /// <summary>
    /// Allocates a relay on <paramref name="server"/> using long-term credentials: an unauthenticated
    /// Allocate first learns the realm and nonce, the authenticated retry allocates. On success starts
    /// the background refresh loop and returns a client with <see cref="RelayedAddress"/> set. Each
    /// transaction waits at most 8 s; server error responses surface as
    /// <see cref="InvalidOperationException"/>. On any failure the socket is already closed — there is
    /// nothing left to dispose.
    /// </summary>
    public static async Task<TurnClient> AllocateAsync(IPEndPoint server, string username, string credential, CancellationToken ct = default)
    {
        var client = new TurnClient(server, username, credential);
        try
        {
            await client.Allocate(ct).ConfigureAwait(false);
            client._lastAllocate = DateTimeOffset.UtcNow;
            _ = client.RefreshLoop();
            return client;
        }
        catch
        {
            client.CloseSocket();
            throw;
        }
    }

    /// <summary>
    /// Asks the server to accept traffic to and from <paramref name="peerIp"/>. TURN permissions are
    /// per-IP, not per-port. A 438 stale nonce is adopted and the request rebuilt once with the fresh
    /// realm and nonce. Also records the peer so <see cref="SendAsync(ReadOnlyMemory{byte}, IPEndPoint, CancellationToken)"/>
    /// skips its own permission request while the entry is under 240 s old. Throws on error response or timeout.
    /// </summary>
    public async Task CreatePermissionAsync(IPAddress peerIp, CancellationToken ct = default)
    {
        byte[] resp = await Transact(() =>
        {
            byte[] txid = NewTxid();
            return Request(MethodCreatePermission, txid,
                [Attr(AttrXorPeerAddress, XorAddress(peerIp, 0, txid)), Attr(AttrUsername, Utf8(_username)), Attr(AttrRealm, Utf8(_realm ?? "")), Attr(AttrNonce, Utf8(_nonce ?? ""))]);
        }, ct).ConfigureAwait(false);
        ThrowIfError(resp);
        lock (_permitted)
        {
            _permitted[peerIp] = DateTimeOffset.UtcNow;
        }
    }

    /// <summary>
    /// Sends <paramref name="payload"/> to <paramref name="peer"/> as a Send Indication, first creating
    /// or refreshing the peer's permission when it is unseen or its entry is 240 s old. The await — and
    /// any throw — covers only that permission request; the indication itself is unacknowledged
    /// fire-and-forget with no delivery guarantee, and a socket error on it is swallowed.
    /// </summary>
    public async Task SendAsync(ReadOnlyMemory<byte> payload, IPEndPoint peer, CancellationToken ct = default)
    {
        bool needsPermit;
        lock (_permitted)
        {
            needsPermit = !_permitted.TryGetValue(peer.Address, out DateTimeOffset seen)
                || DateTimeOffset.UtcNow - seen >= PermissionRefreshEvery;
        }

        if (needsPermit)
        {
            await CreatePermissionAsync(peer.Address, ct).ConfigureAwait(false);
        }

        byte[] txid = NewTxid();
        byte[] msg = Message(MethodSendIndication, txid,
            Concat(Attr(AttrXorPeerAddress, XorAddress(peer.Address, peer.Port, txid)), Attr(AttrData, payload.Span)));
        SendIndication(msg);
    }

    /// <summary>
    /// Raw fire-and-forget Send Indication: no permission handling, so the server silently drops the
    /// data unless the peer was already permitted via <see cref="CreatePermissionAsync(IPAddress, CancellationToken)"/>
    /// or <see cref="SendAsync(ReadOnlyMemory{byte}, IPEndPoint, CancellationToken)"/>. Never waits on the
    /// network — a UDP send is a buffer handoff — and a socket error is swallowed, not reported.
    /// </summary>
    public void Send(ReadOnlySpan<byte> payload, IPEndPoint peer)
    {
        byte[] txid = NewTxid();
        byte[] msg = Message(MethodSendIndication, txid,
            Concat(Attr(AttrXorPeerAddress, XorAddress(peer.Address, peer.Port, txid)), Attr(AttrData, payload)));
        SendIndication(msg);
    }

    private void SendIndication(byte[] msg)
    {
        try
        {
            _udp.Send(msg);
        }
        catch (SocketException)
        {
            // Indications are unacknowledged; a transient ICMP-reported error must not
            // kill the caller's send pump. The next indication goes out as usual.
        }
    }

    private async Task Allocate(CancellationToken ct)
    {
        byte[] first = Message(MethodAllocate, NewTxid(), Attr(AttrRequestedTransport, [17, 0, 0, 0]));
        byte[] resp = await SendAndAwait(first, ct).ConfigureAwait(false);
        foreach ((ushort type, byte[] value) in Attributes(resp))
        {
            if (type == AttrRealm)
            {
                _realm = Encoding.UTF8.GetString(value);
            }
            else if (type == AttrNonce)
            {
                _nonce = Encoding.UTF8.GetString(value);
            }
        }

        _integrityKey = MD5.HashData(Utf8($"{_username}:{_realm}:{_credential}"));

        resp = await Transact(() =>
        {
            byte[] txid = NewTxid();
            return Request(MethodAllocate, txid,
                [Attr(AttrRequestedTransport, [17, 0, 0, 0]), Attr(AttrUsername, Utf8(_username)), Attr(AttrRealm, Utf8(_realm ?? "")), Attr(AttrNonce, Utf8(_nonce ?? ""))]);
        }, ct).ConfigureAwait(false);
        ThrowIfError(resp);
        foreach ((ushort type, byte[] value) in Attributes(resp))
        {
            if (type is AttrXorRelayedAddress or AttrMappedAddress && value.Length >= 8)
            {
                RelayedAddress = DecodeAddress(value, resp.AsSpan(8, 12), type != AttrMappedAddress);
            }
            else if (type == AttrLifetime && value.Length >= 4)
            {
                _lifetime = (int)BinaryPrimitives.ReadUInt32BigEndian(value);
            }
        }

        if (RelayedAddress is null)
        {
            throw new InvalidOperationException("TURN allocate returned no relayed address");
        }
    }

    private async Task RefreshLoop()
    {
        while (!_shutdown.IsCancellationRequested)
        {
            try
            {
                int tickSeconds = Math.Clamp(_lifetime / 3, 5, 30);
                await Task.Delay(TimeSpan.FromSeconds(tickSeconds), _shutdown.Token).ConfigureAwait(false);

                DateTimeOffset now = DateTimeOffset.UtcNow;
                // Due with two spare ticks before expiry, so one misaligned tick can
                // never let the allocation lapse.
                TimeSpan refreshDue = TimeSpan.FromSeconds(Math.Max(1, _lifetime - 2 * tickSeconds));
                if (now - _lastAllocate >= refreshDue)
                {
                    await RefreshAllocationAsync(_shutdown.Token).ConfigureAwait(false);
                }

                await RefreshStalePermissionsAsync(now, _shutdown.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex) when (ex is SocketException or InvalidOperationException or TimeoutException or ObjectDisposedException)
            {
                // A failed refresh tick must not stop the loop; three in a row close the
                // socket inside RefreshAllocationAsync so the failure surfaces visibly.
            }
        }
    }

    private async Task RefreshAllocationAsync(CancellationToken ct)
    {
        try
        {
            byte[] resp = await Transact(() =>
            {
                byte[] txid = NewTxid();
                return Request(MethodRefresh, txid,
                    [Attr(AttrUsername, Utf8(_username)), Attr(AttrRealm, Utf8(_realm ?? "")), Attr(AttrNonce, Utf8(_nonce ?? ""))]);
            }, ct).ConfigureAwait(false);
            ThrowIfError(resp);
            foreach ((ushort type, byte[] value) in Attributes(resp))
            {
                if (type == AttrLifetime && value.Length >= 4)
                {
                    _lifetime = (int)BinaryPrimitives.ReadUInt32BigEndian(value);
                }
            }

            _lastAllocate = DateTimeOffset.UtcNow;
            _refreshFailures = 0;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // After repeated failed refreshes the allocation is gone; close the socket
            // so the connection fails visibly instead of silently black-holing traffic.
            if (Interlocked.Increment(ref _refreshFailures) >= 3)
            {
                CloseSocket();
            }
        }
    }

    private async Task RefreshStalePermissionsAsync(DateTimeOffset now, CancellationToken ct)
    {
        IPAddress[] stale;
        lock (_permitted)
        {
            stale = _permitted.Where(kv => now - kv.Value >= PermissionRefreshEvery).Select(kv => kv.Key).ToArray();
        }

        foreach (IPAddress peer in stale)
        {
            try
            {
                await CreatePermissionAsync(peer, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                lock (_permitted)
                {
                    _permitted.Remove(peer);
                }
            }
        }
    }

    private byte[] Request(ushort method, byte[] txid, byte[][] attrs)
    {
        byte[] body = Concat(attrs);
        byte[] msg = new byte[20 + body.Length + 24];
        Header(msg, method, body.Length + 24, txid);
        body.CopyTo(msg, 20);
        int miOff = 20 + body.Length;
        BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(miOff), AttrMessageIntegrity);
        BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(miOff + 2), 20);
        byte[] hmac = HMACSHA1.HashData(_integrityKey, msg.AsSpan(0, miOff));
        hmac.CopyTo(msg, miOff + 4);
        return msg;
    }

    private async Task<byte[]> Transact(Func<byte[]> build, CancellationToken ct)
    {
        byte[] resp = await SendAndAwait(build(), ct).ConfigureAwait(false);
        if (TryAdoptRotatedAuth(resp))
        {
            // 438 stale nonce: the server rotated its nonce; rebuild with the fresh
            // realm/nonce (the builders read the updated fields) and retry once.
            resp = await SendAndAwait(build(), ct).ConfigureAwait(false);
        }

        return resp;
    }

    private bool TryAdoptRotatedAuth(byte[] resp)
    {
        if (!IsError(resp, StaleNonceCode))
        {
            return false;
        }

        string? nonce = null;
        string? realm = null;
        foreach ((ushort at, byte[] v) in Attributes(resp))
        {
            if (at == AttrNonce)
            {
                nonce = Encoding.UTF8.GetString(v);
            }
            else if (at == AttrRealm)
            {
                realm = Encoding.UTF8.GetString(v);
            }
        }

        if (nonce is null)
        {
            return false;
        }

        _nonce = nonce;
        if (realm is not null && realm != _realm)
        {
            _realm = realm;
            _integrityKey = MD5.HashData(Utf8($"{_username}:{_realm}:{_credential}"));
        }

        return true;
    }

    private async Task<byte[]> SendAndAwait(byte[] msg, CancellationToken ct)
    {
        ulong key = BinaryPrimitives.ReadUInt64BigEndian(msg.AsSpan(8));
        var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[key] = tcs;
        try
        {
            _udp.Send(msg);
            return await tcs.Task.WaitAsync(TransactTimeout, ct).ConfigureAwait(false);
        }
        finally
        {
            _pending.TryRemove(key, out _);
        }
    }

    private void RecvLoop()
    {
        byte[] buf = new byte[2048];
        while (Volatile.Read(ref _disposed) == 0)
        {
            int n;
            try
            {
                n = _udp.Receive(buf);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException) when (_shutdown.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException)
            {
                // Transient errors (ICMP-reported unreachable, interface flap) must not
                // stop the receive loop; pace briefly so a persistent error cannot spin.
                Thread.Sleep(20);
                continue;
            }
            catch
            {
                return;
            }

            if (n < 20 || BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(4)) != Cookie)
            {
                continue;
            }

            ushort type = BinaryPrimitives.ReadUInt16BigEndian(buf);
            if (type == MethodDataIndication)
            {
                IPEndPoint? from = null;
                byte[]? data = null;
                foreach ((ushort at, byte[] v) in Attributes(buf[..n]))
                {
                    if (at == AttrXorPeerAddress && v.Length >= 8)
                    {
                        from = DecodeAddress(v, buf.AsSpan(8, 12), true);
                    }
                    else if (at == AttrData)
                    {
                        data = v;
                    }
                }

                if (from is not null && data is not null)
                {
                    try
                    {
                        Received?.Invoke(from, data);
                    }
                    catch (Exception)
                    {
                        // A throwing handler must cost only its own indication: this thread
                        // also completes every permission and refresh transaction.
                    }
                }
            }
            else
            {
                ulong key = BinaryPrimitives.ReadUInt64BigEndian(buf.AsSpan(8));
                if (_pending.TryGetValue(key, out TaskCompletionSource<byte[]>? tcs))
                {
                    tcs.TrySetResult(buf[..n]);
                }
            }
        }
    }

    private static bool IsError(byte[] resp, int code)
    {
        ushort type = BinaryPrimitives.ReadUInt16BigEndian(resp);
        if ((type & ClassError) != ClassError)
        {
            return false;
        }

        foreach ((ushort at, byte[] v) in Attributes(resp))
        {
            if (at == AttrErrorCode && v.Length >= 4 && v[2] * 100 + v[3] == code)
            {
                return true;
            }
        }

        return false;
    }

    private static void ThrowIfError(byte[] resp)
    {
        ushort type = BinaryPrimitives.ReadUInt16BigEndian(resp);
        if ((type & ClassError) != ClassError)
        {
            return;
        }

        int code = -1;
        string reason = "";
        foreach ((ushort at, byte[] v) in Attributes(resp))
        {
            if (at == AttrErrorCode && v.Length >= 4)
            {
                code = v[2] * 100 + v[3];
                reason = Encoding.UTF8.GetString(v, 4, v.Length - 4);
            }
        }

        throw new TurnRejectException(code, reason);
    }

    private static byte[] Message(ushort type, byte[] txid, byte[] attrs)
    {
        byte[] msg = new byte[20 + attrs.Length];
        Header(msg, type, attrs.Length, txid);
        attrs.CopyTo(msg, 20);
        return msg;
    }

    private static void Header(byte[] msg, ushort type, int len, byte[] txid)
    {
        BinaryPrimitives.WriteUInt16BigEndian(msg, type);
        BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(2), (ushort)len);
        BinaryPrimitives.WriteUInt32BigEndian(msg.AsSpan(4), Cookie);
        txid.CopyTo(msg, 8);
    }

    private static byte[] NewTxid() => RandomNumberGenerator.GetBytes(12);

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Attr(ushort type, ReadOnlySpan<byte> value)
    {
        byte[] a = new byte[4 + ((value.Length + 3) & ~3)];
        BinaryPrimitives.WriteUInt16BigEndian(a, type);
        BinaryPrimitives.WriteUInt16BigEndian(a.AsSpan(2), (ushort)value.Length);
        value.CopyTo(a.AsSpan(4));
        return a;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int len = 0;
        foreach (byte[] p in parts)
        {
            len += p.Length;
        }

        byte[] r = new byte[len];
        int pos = 0;
        foreach (byte[] p in parts)
        {
            p.CopyTo(r, pos);
            pos += p.Length;
        }

        return r;
    }

    private static List<(ushort Type, byte[] Value)> Attributes(byte[] msg)
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

    private static byte[] XorAddress(IPAddress ip, int port, ReadOnlySpan<byte> txid)
    {
        byte[] raw = ip.GetAddressBytes();
        byte[] dst = new byte[4 + raw.Length];
        dst[1] = (byte)(raw.Length == 4 ? 0x01 : 0x02);
        BinaryPrimitives.WriteUInt16BigEndian(dst.AsSpan(2), (ushort)(port ^ (Cookie >> 16)));
        for (int i = 0; i < raw.Length; i++)
        {
            byte m = i switch
            {
                < 4 => (byte)(Cookie >> (24 - i * 8)),
                _ => txid[i - 4],
            };
            dst[4 + i] = (byte)(raw[i] ^ m);
        }

        return dst;
    }

    private static IPEndPoint? DecodeAddress(ReadOnlySpan<byte> value, ReadOnlySpan<byte> txid, bool xor)
    {
        byte family = value[1];
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(value[2..]);
        if (xor)
        {
            port ^= (ushort)(Cookie >> 16);
        }

        if (family == 0x01 && value.Length >= 8)
        {
            Span<byte> raw = stackalloc byte[4];
            value.Slice(4, 4).CopyTo(raw);
            if (xor)
            {
                raw[0] ^= 0x21;
                raw[1] ^= 0x12;
                raw[2] ^= 0xA4;
                raw[3] ^= 0x42;
            }

            return new IPEndPoint(new IPAddress(raw), port);
        }

        if (family == 0x02 && value.Length >= 20)
        {
            Span<byte> raw = stackalloc byte[16];
            value.Slice(4, 16).CopyTo(raw);
            if (xor)
            {
                Span<byte> mask = stackalloc byte[16];
                BinaryPrimitives.WriteUInt32BigEndian(mask, Cookie);
                txid.CopyTo(mask[4..]);
                for (int i = 0; i < 16; i++)
                {
                    raw[i] ^= mask[i];
                }
            }

            return new IPEndPoint(new IPAddress(raw), port);
        }

        return null;
    }

    private void CloseSocket()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _udp.Dispose();
        }
    }

    /// <summary>Cancels the refresh loop and closes the socket; the receive thread notices within its
    /// 200 ms receive poll. No deallocation Refresh is sent, so the server holds the allocation open
    /// until its lifetime — 600 s unless the server negotiated otherwise — expires. Completes
    /// synchronously and is safe to call more than once.</summary>
    public async ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        CloseSocket();
        await Task.CompletedTask;
    }
}
