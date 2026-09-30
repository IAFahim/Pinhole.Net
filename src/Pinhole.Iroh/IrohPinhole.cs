using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using N0.IrohNet;
using Pinhole;

namespace Pinhole.Iroh;

public sealed class IrohPinhole : IAsyncDisposable
{
    private unsafe Endpoint* _ep;
    private readonly byte[] _alpn;
    internal readonly List<IPAddress> _addrs;

    private unsafe IrohPinhole(Endpoint* ep, byte[] alpn)
    {
        _ep = ep;
        _alpn = alpn;
        Ticket = IrohEngine.Ticket(ep);
        _addrs = IrohEngine.Addrs(ep);
    }

    public string Ticket { get; }
    public IReadOnlyList<IPAddress> DirectAddresses => _addrs;

    public static async Task<IrohPinhole> BindAsync(string alpn = "pinhole/0", string? secretKey = null, CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            byte[] alpnBytes = Encoding.ASCII.GetBytes(alpn);
            unsafe
            {
                Endpoint* ep = IrohEngine.Bind(alpnBytes, secretKey);
                _ = IrohEngine.TryOnline(ep, 15_000);
                return new IrohPinhole(ep, alpnBytes);
            }
        }, ct).ConfigureAwait(false);
    }

    public async Task<IrohLink> ConnectAsync(string peerTicket, CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            unsafe
            {
                return new IrohLink(this, IrohEngine.Connect(_ep, peerTicket, _alpn), true);
            }
        }, ct).ConfigureAwait(false);
    }

    public async Task<IrohLink> AcceptAsync(CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            unsafe
            {
                return new IrohLink(this, IrohEngine.Accept(_ep, _alpn), false);
            }
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await Task.Run(() =>
        {
            unsafe
            {
                Endpoint* ep = _ep;
                if (ep != null)
                {
                    iroh.endpoint_close(ep);
                    _ep = null;
                }
            }
        }).ConfigureAwait(false);
    }
}

public sealed class IrohLink : IAsyncDisposable
{
    private readonly IrohPinhole _node;
    private readonly bool _initiator;
    internal unsafe Connection* _conn;
    internal unsafe SendStream* _send;
    internal unsafe RecvStream* _recv;
    internal readonly TaskCompletionSource ReadDone = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal unsafe IrohLink(IrohPinhole node, Connection* conn, bool initiator)
    {
        _node = node;
        _conn = conn;
        _initiator = initiator;
    }

    public event Action<byte[]>? Received;

    public async Task IntroduceAsync(PeerSocket pin, CancellationToken ct = default)
    {
        await Task.Run(() =>
        {
            unsafe
            {
                SendStream* send;
                RecvStream* recv;
                if (_initiator)
                {
                    IrohEngine.OpenBi(_conn, &send, &recv);
                }
                else
                {
                    IrohEngine.AcceptBi(_conn, &send, &recv);
                }

                _send = send;
                _recv = recv;
                IrohEngine.WriteFrame(send, IrohEngine.PackIntro(_node._addrs, pin.LocalPort));
            }
        }, ct).ConfigureAwait(false);
        _ = Task.Run(() =>
        {
            try
            {
                IrohEngine.ReadLoop(this, pin);
            }
            finally
            {
                ReadDone.TrySetResult();
            }
        });
        await pin.Connected.WaitAsync(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
    }

    public async Task SendAsync(ReadOnlyMemory<byte> payload, CancellationToken ct = default)
    {
        await Task.Run(() =>
        {
            unsafe
            {
                IrohEngine.WriteFrame(_send, payload.Span);
            }
        }, ct).ConfigureAwait(false);
    }

    internal void RaiseReceived(byte[] payload) => Received?.Invoke(payload);

    public async ValueTask DisposeAsync()
    {
        await Task.Run(() =>
        {
            unsafe
            {
                if (_send != null)
                {
                    _ = iroh.send_stream_finish(_send);
                    _send = null;
                }

                if (_conn != null)
                {
                    iroh.connection_close(_conn);
                    _conn = null;
                }
            }
        }).ConfigureAwait(false);
        await Task.WhenAny(ReadDone.Task, Task.Delay(2000)).ConfigureAwait(false);
        await Task.Run(() =>
        {
            unsafe
            {
                if (_recv != null)
                {
                    iroh.recv_stream_free(_recv);
                    _recv = null;
                }
            }
        }).ConfigureAwait(false);
    }
}

internal static unsafe class IrohEngine
{
    public static Endpoint* Bind(byte[] alpn, string? secretKey)
    {
        EndpointConfig config = iroh.endpoint_config_default();
        fixed (byte* a = alpn)
        {
            iroh.endpoint_config_add_alpn(&config, new slice_ref_uint8 { ptr = a, len = (nuint)alpn.Length });
        }

        SecretKey* key = null;
        if (secretKey is not null)
        {
            key = iroh.secret_key_default();
            byte[] keyBytes = Encoding.ASCII.GetBytes(secretKey + "\0");
            fixed (byte* k = keyBytes)
            {
                if (iroh.secret_key_from_base32(k, &key) == KeyResult.KEY_RESULT_OK)
                {
                    iroh.endpoint_config_add_secret_key(&config, key);
                }
            }
        }

        Endpoint* ep = iroh.endpoint_default();
        EndpointResult r = iroh.endpoint_bind(&config, null, null, &ep);
        if (key != null)
        {
            iroh.secret_key_free(key);
        }

        iroh.endpoint_config_free(config);
        if (r != EndpointResult.ENDPOINT_RESULT_OK)
        {
            iroh.endpoint_free(ep);
            throw new InvalidOperationException($"iroh bind failed: {r}");
        }

        return ep;
    }

    public static EndpointResult TryOnline(Endpoint* ep, ulong timeoutMs) => iroh.endpoint_online(&ep, timeoutMs);

    public static string Ticket(Endpoint* ep)
    {
        EndpointAddr addr = iroh.endpoint_addr_default();
        EndpointResult r = iroh.endpoint_addr(&ep, &addr);
        if (r != EndpointResult.ENDPOINT_RESULT_OK)
        {
            throw new InvalidOperationException($"endpoint_addr failed: {r}");
        }

        byte* s = iroh.endpoint_addr_as_str(&addr);
        string ticket = Encoding.UTF8.GetString(MemoryMarshal.CreateReadOnlySpanFromNullTerminated(s));
        iroh.rust_free_string(s);
        iroh.endpoint_addr_free(addr);
        return ticket;
    }

    public static List<IPAddress> Addrs(Endpoint* ep)
    {
        var addrs = new List<IPAddress>();
        EndpointAddr addr = iroh.endpoint_addr_default();
        if (iroh.endpoint_addr(&ep, &addr) != EndpointResult.ENDPOINT_RESULT_OK)
        {
            return addrs;
        }

        for (nuint i = 0; ; i++)
        {
            SocketAddr* sa = iroh.endpoint_addr_ip_addrs_nth(&addr, i);
            if (sa == null)
            {
                break;
            }

            byte* s = iroh.socket_addr_as_str(sa);
            string text = Encoding.UTF8.GetString(MemoryMarshal.CreateReadOnlySpanFromNullTerminated(s));
            iroh.rust_free_string(s);
            if (TryParseIp(text, out IPAddress? ip))
            {
                addrs.Add(ip!);
            }
        }

        iroh.endpoint_addr_free(addr);
        return addrs;
    }

    public static Connection* Connect(Endpoint* ep, string ticket, byte[] alpn)
    {
        EndpointAddr addr = iroh.endpoint_addr_default();
        byte[] ticketBytes = Encoding.ASCII.GetBytes(ticket + "\0");
        AddrResult ar;
        fixed (byte* t = ticketBytes)
        {
            ar = iroh.endpoint_addr_from_string(t, &addr);
        }

        if (ar != AddrResult.ADDR_RESULT_OK)
        {
            throw new InvalidOperationException($"bad ticket: {ar}");
        }

        Connection* conn = iroh.connection_default();
        EndpointResult r;
        fixed (byte* a = alpn)
        {
            r = iroh.endpoint_connect(&ep, new slice_ref_uint8 { ptr = a, len = (nuint)alpn.Length }, addr, &conn);
        }

        if (r != EndpointResult.ENDPOINT_RESULT_OK)
        {
            iroh.connection_free(conn);
            throw new InvalidOperationException($"iroh connect failed: {r}");
        }

        return conn;
    }

    public static Connection* Accept(Endpoint* ep, byte[] alpn)
    {
        Connection* conn = iroh.connection_default();
        EndpointResult r;
        fixed (byte* a = alpn)
        {
            r = iroh.endpoint_accept(&ep, new slice_ref_uint8 { ptr = a, len = (nuint)alpn.Length }, &conn);
        }

        if (r != EndpointResult.ENDPOINT_RESULT_OK)
        {
            iroh.connection_free(conn);
            throw new InvalidOperationException($"iroh accept failed: {r}");
        }

        return conn;
    }

    public static void OpenBi(Connection* conn, SendStream** send, RecvStream** recv)
    {
        *send = iroh.send_stream_default();
        *recv = iroh.recv_stream_default();
        EndpointResult r = iroh.connection_open_bi(&conn, send, recv);
        if (r != EndpointResult.ENDPOINT_RESULT_OK)
        {
            throw new InvalidOperationException($"open_bi failed: {r}");
        }
    }

    public static void AcceptBi(Connection* conn, SendStream** send, RecvStream** recv)
    {
        *send = iroh.send_stream_default();
        *recv = iroh.recv_stream_default();
        EndpointResult r = iroh.connection_accept_bi(&conn, send, recv);
        if (r != EndpointResult.ENDPOINT_RESULT_OK)
        {
            throw new InvalidOperationException($"accept_bi failed: {r}");
        }
    }

    public static byte[] PackIntro(List<IPAddress> addrs, int udpPort)
    {
        using var ms = new MemoryStream(64);
        Span<byte> port = stackalloc byte[2];
        BitConverter.TryWriteBytes(port, (ushort)udpPort);
        ms.Write(port);
        ms.WriteByte((byte)Math.Min(addrs.Count, 16));
        foreach (IPAddress ip in addrs.Take(16))
        {
            byte[] raw = ip.GetAddressBytes();
            ms.WriteByte((byte)(raw.Length == 4 ? 4 : 6));
            ms.Write(raw);
        }

        return ms.ToArray();
    }

    public static void WriteFrame(SendStream* send, ReadOnlySpan<byte> payload)
    {
        if (payload.Length > 0xffff)
        {
            throw new ArgumentOutOfRangeException(nameof(payload), "frame too large");
        }

        byte[] frame = new byte[payload.Length + 2];
        BitConverter.TryWriteBytes(frame.AsSpan(0, 2), (ushort)payload.Length);
        payload.CopyTo(frame.AsSpan(2));
        fixed (byte* f = frame)
        {
            EndpointResult r = iroh.send_stream_write(&send, new slice_ref_uint8 { ptr = f, len = (nuint)frame.Length });
            if (r != EndpointResult.ENDPOINT_RESULT_OK)
            {
                throw new InvalidOperationException($"stream write failed: {r}");
            }
        }
    }

    public static void ReadLoop(IrohLink link, PeerSocket pin)
    {
        unsafe
        {
            RecvStream* recv = link._recv;
            Span<byte> hdr = stackalloc byte[2];
            if (!ReadExact(recv, hdr))
            {
                return;
            }

            int n = hdr[0] | hdr[1] << 8;
            byte[] intro = new byte[n];
            if (!ReadExact(recv, intro))
            {
                return;
            }

            ApplyIntro(pin, intro);
            while (true)
            {
                if (!ReadExact(recv, hdr))
                {
                    return;
                }

                n = hdr[0] | hdr[1] << 8;
                if (n == 0)
                {
                    continue;
                }

                byte[] body = new byte[n];
                if (!ReadExact(recv, body))
                {
                    return;
                }

                link.RaiseReceived(body);
            }
        }
    }

    private static bool ReadExact(RecvStream* recv, Span<byte> dst)
    {
        int got = 0;
        while (got < dst.Length)
        {
            long n;
            fixed (byte* d = dst)
            {
                n = iroh.recv_stream_read(&recv, new slice_mut_uint8 { ptr = d + got, len = (nuint)(dst.Length - got) });
            }

            if (n <= 0)
            {
                return false;
            }

            got += (int)n;
        }

        return true;
    }

    private static void ApplyIntro(PeerSocket pin, ReadOnlySpan<byte> intro)
    {
        if (intro.Length < 3)
        {
            return;
        }

        int port = intro[0] | intro[1] << 8;
        int count = intro[2];
        int pos = 3;
        for (int i = 0; i < count && pos < intro.Length; i++)
        {
            int len = intro[pos] == 4 ? 4 : 16;
            pos++;
            if (pos + len > intro.Length)
            {
                break;
            }

            try
            {
                pin.AddCandidate(new IPEndPoint(new IPAddress(intro.Slice(pos, len).ToArray()), port));
            }
            catch (ArgumentException)
            {
            }

            pos += len;
        }
    }

    private static bool TryParseIp(ReadOnlySpan<char> socketAddr, out IPAddress? ip)
    {
        ip = null;
        int end = socketAddr.LastIndexOf(':');
        if (end <= 0)
        {
            return false;
        }

        ReadOnlySpan<char> host = socketAddr[..end];
        if (host.StartsWith('['))
        {
            host = host[1..];
        }

        return IPAddress.TryParse(host, out ip);
    }
}
