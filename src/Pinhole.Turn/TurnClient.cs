using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Pinhole.Turn;

public sealed class TurnClient : IAsyncDisposable
{
    private const uint Cookie = 0x2112A442;
    private const ushort MethodAllocate = 0x0003;
    private const ushort MethodRefresh = 0x0004;
    private const ushort MethodSendIndication = 0x0016;
    private const ushort MethodDataIndication = 0x0017;
    private const ushort MethodCreatePermission = 0x0008;
    private const ushort ClassError = 0x0110;

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
    private const ushort AttrXorMappedAddress = 0x0020;

    private static readonly TimeSpan TransactTimeout = TimeSpan.FromSeconds(8);

    private readonly Socket _udp;
    private readonly string _username;
    private readonly string _credential;
    private readonly ConcurrentDictionary<ulong, TaskCompletionSource<byte[]>> _pending = new();
    private readonly HashSet<IPAddress> _permitted = new();
    private readonly CancellationTokenSource _shutdown = new();
    private byte[] _integrityKey = Array.Empty<byte>();
    private string? _realm;
    private string? _nonce;
    private int _lifetime = 600;
    private int _disposed;

    private TurnClient(IPEndPoint server, string username, string credential)
    {
        _username = username;
        _credential = credential;
        _udp = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        _udp.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0));
        _udp.Connect(server);
        Thread recv = new(RecvLoop) { IsBackground = true, Name = "turn-recv" };
        recv.Start();
    }

    public IPEndPoint? RelayedAddress { get; private set; }

    public event Action<IPEndPoint, byte[]>? Received;

    public static async Task<TurnClient> AllocateAsync(IPEndPoint server, string username, string credential, CancellationToken ct = default)
    {
        var client = new TurnClient(server, username, credential);
        try
        {
            await client.Allocate(ct).ConfigureAwait(false);
            _ = client.RefreshLoop();
            return client;
        }
        catch
        {
            client.CloseSocket();
            throw;
        }
    }

    public async Task CreatePermissionAsync(IPAddress peerIp, CancellationToken ct = default)
    {
        byte[] txid = NewTxid();
        byte[] peer = XorAddress(peerIp, 0, txid);
        byte[] msg = Request(MethodCreatePermission, txid,
            [Attr(AttrXorPeerAddress, peer), Attr(AttrUsername, Utf8(_username)), Attr(AttrRealm, Utf8(_realm ?? "")), Attr(AttrNonce, Utf8(_nonce ?? ""))]);
        byte[] resp = await Transact(msg, txid, ct).ConfigureAwait(false);
        ThrowIfError(resp);
        lock (_permitted)
        {
            _permitted.Add(peerIp);
        }
    }

    public async Task SendAsync(ReadOnlyMemory<byte> payload, IPEndPoint peer, CancellationToken ct = default)
    {
        bool needsPermit;
        lock (_permitted)
        {
            needsPermit = _permitted.Add(peer.Address);
        }

        if (needsPermit)
        {
            await CreatePermissionAsync(peer.Address, ct).ConfigureAwait(false);
        }

        byte[] txid = NewTxid();
        byte[] msg = Message(MethodSendIndication, txid,
            Concat(Attr(AttrXorPeerAddress, XorAddress(peer.Address, peer.Port, txid)), Attr(AttrData, payload.Span)));
        _udp.Send(msg);
    }

    public void Send(ReadOnlySpan<byte> payload, IPEndPoint peer)
    {
        byte[] txid = NewTxid();
        byte[] msg = Message(MethodSendIndication, txid,
            Concat(Attr(AttrXorPeerAddress, XorAddress(peer.Address, peer.Port, txid)), Attr(AttrData, payload)));
        _udp.Send(msg);
    }

    private async Task Allocate(CancellationToken ct)
    {
        byte[] txid = NewTxid();
        byte[] first = Message(MethodAllocate, txid, Attr(AttrRequestedTransport, [17, 0, 0, 0]));
        byte[] resp = await Transact(first, txid, ct).ConfigureAwait(false);
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

        txid = NewTxid();
        byte[] authed = Request(MethodAllocate, txid,
            [Attr(AttrRequestedTransport, [17, 0, 0, 0]), Attr(AttrUsername, Utf8(_username)), Attr(AttrRealm, Utf8(_realm ?? "")), Attr(AttrNonce, Utf8(_nonce ?? ""))]);
        resp = await Transact(authed, txid, ct).ConfigureAwait(false);
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
        TimeSpan every = TimeSpan.FromSeconds(_lifetime * 2 / 3);
        while (!_shutdown.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(every, _shutdown.Token).ConfigureAwait(false);
                byte[] txid = NewTxid();
                byte[] msg = Request(MethodRefresh, txid,
                    [Attr(AttrUsername, Utf8(_username)), Attr(AttrRealm, Utf8(_realm ?? "")), Attr(AttrNonce, Utf8(_nonce ?? ""))]);
                await Transact(msg, txid, _shutdown.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception)
            {
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

    private async Task<byte[]> Transact(byte[] msg, byte[] txid, CancellationToken ct)
    {
        ulong key = BinaryPrimitives.ReadUInt64BigEndian(txid);
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
                    Received?.Invoke(from, data);
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

        throw new InvalidOperationException($"TURN {code} {reason}");
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

    public async ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        CloseSocket();
        await Task.CompletedTask;
    }
}
