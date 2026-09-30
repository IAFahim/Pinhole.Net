using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using N0.IrohNet;
using Pinhole;

namespace Pinhole.Iroh;

/// <summary>An iroh-backed rendezvous/relay node: free signaling plus a relay fallback while UDP punching proceeds.</summary>
public sealed class IrohPinhole : IAsyncDisposable
{
    private readonly IrohEndpoint _endpoint;
    private readonly byte[] _alpn;

    private IrohPinhole(IrohEndpoint endpoint, byte[] alpn, string ticket)
    {
        _endpoint = endpoint;
        _alpn = alpn;
        Ticket = ticket;
    }

    public string Ticket { get; }

    /// <summary>Local interface addresses offered to peers as hole-punch candidates.</summary>
    public IReadOnlyList<IPAddress> DirectAddresses => LocalInterfaceAddresses();

    public static async Task<IrohPinhole> BindAsync(string alpn = "pinhole/0", string? secretKey = null, CancellationToken ct = default)
    {
        byte[] alpnBytes = Encoding.ASCII.GetBytes(alpn);
        IrohSecretKey? key = secretKey is null ? null : IrohSecretKey.FromBase32(secretKey);
        try
        {
            IrohEndpoint endpoint = await IrohEndpoint.BindAsync(new IrohEndpointOptions
            {
                Alpns = [alpnBytes],
                RelayMode = IrohRelayMode.Default,
                Discovery = IrohDiscoveryConfig.None,
                SecretKey = key,
            }, ct).ConfigureAwait(false);

            // Best-effort online wait, matching the previous behavior: binding succeeds even
            // when relays are unreachable; connecting later may still work.
            _ = await endpoint.WaitForOnlineAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);

            IrohNodeAddr addr = endpoint.LocalAddr();
            return new IrohPinhole(endpoint, alpnBytes, addr.Ticket);
        }
        finally
        {
            key?.Dispose();
        }
    }

    public async Task<IrohLink> ConnectAsync(string peerTicket, CancellationToken ct = default)
    {
        IrohConnection conn = await _endpoint.ConnectAsync(IrohNodeAddr.Parse(peerTicket), _alpn, ct).ConfigureAwait(false);
        return new IrohLink(this, conn, initiator: true);
    }

    public async Task<IrohLink> AcceptAsync(CancellationToken ct = default)
    {
        IrohConnection conn = await _endpoint.AcceptAsync(ct).ConfigureAwait(false);
        return new IrohLink(this, conn, initiator: false);
    }

    public ValueTask DisposeAsync() => _endpoint.DisposeAsync();

    private static List<IPAddress> LocalInterfaceAddresses()
    {
        var addrs = new List<IPAddress>();
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (UnicastIPAddressInformation unicast in nic.GetIPProperties().UnicastAddresses)
            {
                IPAddress ip = unicast.Address;
                if (ip.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                    || IPAddress.IsLoopback(ip)
                    || ip.IsIPv6LinkLocal
                    || ip.IsIPv6SiteLocal)
                {
                    continue;
                }

                addrs.Add(ip);
            }
        }

        return addrs;
    }
}

/// <summary>A framed bidirectional link over an iroh connection; carries the punch intro and app payloads.</summary>
public sealed class IrohLink : IAsyncDisposable
{
    private readonly IrohPinhole _node;
    private readonly IrohConnection _conn;
    private readonly bool _initiator;
    private readonly CancellationTokenSource _shutdown = new();
    private Stream? _stream;
    private Task? _readLoop;

    internal IrohLink(IrohPinhole node, IrohConnection conn, bool initiator)
    {
        _node = node;
        _conn = conn;
        _initiator = initiator;
    }

    public event Action<byte[]>? Received;

    /// <summary>Exchanges punch candidates over the link's stream and starts the receive loop; resolves once the UDP path is punched (or after 15 s).</summary>
    public async Task IntroduceAsync(PeerSocket pin, CancellationToken ct = default)
    {
        Stream stream = _initiator
            ? await _conn.OpenStreamAsync(ct).ConfigureAwait(false)
            : await _conn.AcceptStreamAsync(ct).ConfigureAwait(false);
        _stream = stream;

        await WriteFrameAsync(stream, PackIntro(_node.DirectAddresses, pin.LocalPort), ct).ConfigureAwait(false);
        _readLoop = Task.Run(() => ReadLoopAsync(this, pin, _shutdown.Token));
        await pin.Connected.WaitAsync(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
    }

    public async Task SendAsync(ReadOnlyMemory<byte> payload, CancellationToken ct = default)
    {
        Stream stream = _stream ?? throw new InvalidOperationException("the link must be introduced before sending");
        await WriteFrameAsync(stream, payload, ct).ConfigureAwait(false);
    }

    internal void RaiseReceived(byte[] payload) => Received?.Invoke(payload);

    public async ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        if (_readLoop is not null)
        {
            // The read loop unwinds within one 250 ms read slice; bound the wait regardless.
            await Task.WhenAny(_readLoop, Task.Delay(TimeSpan.FromSeconds(3))).ConfigureAwait(false);
        }

        if (_stream is not null)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
        }

        await _conn.DisposeAsync().ConfigureAwait(false);
    }

    private static async Task WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        if (payload.Length > 0xffff)
        {
            throw new ArgumentOutOfRangeException(nameof(payload), "frame too large");
        }

        byte[] frame = new byte[payload.Length + 2];
        BitConverter.TryWriteBytes(frame.AsSpan(0, 2), (ushort)payload.Length);
        payload.Span.CopyTo(frame.AsSpan(2));
        await stream.WriteAsync(frame, ct).ConfigureAwait(false);
    }

    private static async Task ReadLoopAsync(IrohLink link, PeerSocket pin, CancellationToken ct)
    {
        Stream stream = link._stream!;
        try
        {
            byte[] header = new byte[2];
            if (!await ReadExactAsync(stream, header, ct).ConfigureAwait(false))
            {
                return;
            }

            int introLength = header[0] | header[1] << 8;
            byte[] intro = new byte[introLength];
            if (!await ReadExactAsync(stream, intro, ct).ConfigureAwait(false))
            {
                return;
            }

            ApplyIntro(pin, intro);
            while (!ct.IsCancellationRequested)
            {
                if (!await ReadExactAsync(stream, header, ct).ConfigureAwait(false))
                {
                    return;
                }

                int n = header[0] | header[1] << 8;
                if (n == 0)
                {
                    continue;
                }

                byte[] body = new byte[n];
                if (!await ReadExactAsync(stream, body, ct).ConfigureAwait(false))
                {
                    return;
                }

                link.RaiseReceived(body);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception)
        {
            // A closed stream or dropped connection ends the loop; dispose owns teardown.
        }
    }

    private static async Task<bool> ReadExactAsync(Stream stream, Memory<byte> dst, CancellationToken ct)
    {
        int got = 0;
        while (got < dst.Length)
        {
            int n = await stream.ReadAsync(dst[got..], ct).ConfigureAwait(false);
            if (n <= 0)
            {
                return false;
            }

            got += n;
        }

        return true;
    }

    private static byte[] PackIntro(IReadOnlyList<IPAddress> addrs, int udpPort)
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
}
