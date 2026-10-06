using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pinhole;

/// <summary>The built-in lookup provider: speaks the <c>Pinhole.Rendezvous</c> UDP
/// introducer wire (REG/WANT/INTRO), extended so a REGistered node may attach its signed
/// address record and an INTRO carries that record back verbatim. The introducer is a
/// store-and-forward directory that never validates records — every adopted endpoint is
/// verified against the dialer's pinned key before use, so a malicious introducer can
/// only deny availability. One short-lived socket per operation: publishes are one
/// datagram per configured server, resolves wait a bounded few seconds for the first
/// record-bearing INTRO, and nothing listens between operations.</summary>
internal sealed class RendezvousLookup : IPinholeLookupProvider
{
    private static readonly TimeSpan PublishConfirmWait = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ResolveWait = TimeSpan.FromSeconds(3);
    private const int MaxWireRecord = 1024; // records are ~450 bytes today; room to grow

    private readonly ulong _selfId;
    private readonly IPEndPoint[] _servers;

    public RendezvousLookup(ulong selfId, IReadOnlyList<IPEndPoint> servers)
    {
        if (servers.Count == 0)
        {
            throw new ArgumentException("at least one rendezvous endpoint is required", nameof(servers));
        }

        _selfId = selfId;
        _servers = servers.ToArray();
    }

    public async Task PublishAsync(ReadOnlyMemory<byte> signedRecord, CancellationToken ct)
    {
        string message = $"REG {_selfId:x16} {Base64Url.Encode(signedRecord.Span)}";
        using Socket udp = NewSocket();
        using var confirm = CancellationTokenSource.CreateLinkedTokenSource(ct);
        confirm.CancelAfter(PublishConfirmWait);
        foreach (IPEndPoint server in _servers)
        {
            await udp.SendToAsync(Encoding.ASCII.GetBytes(message), SocketFlags.None, ToWire(server), confirm.Token).ConfigureAwait(false);
        }

        // Waiting for one OBS turns "server down" into a detectable failure the publisher
        // can back off from, instead of a silent datagram into the void.
        await ExpectAsync(udp, "OBS", confirm.Token).ConfigureAwait(false);
    }

    public async Task<byte[]?> ResolveAsync(ulong peerId, CancellationToken ct)
    {
        string message = $"WANT {_selfId:x16} {peerId:x16}";
        using Socket udp = NewSocket();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(ResolveWait);
        foreach (IPEndPoint server in _servers)
        {
            await udp.SendToAsync(Encoding.ASCII.GetBytes(message), SocketFlags.None, ToWire(server), deadline.Token).ConfigureAwait(false);
        }

        // First record-bearing INTRO for the target wins. A legacy bare-endpoint INTRO
        // carries no signature, so it can never be adopted — unknown-endpoint redirects are
        // exactly the traffic-redirection abuse signed records exist to prevent.
        byte[] buffer = new byte[2048];
        IPEndPoint any = new(IPAddress.IPv6Any, 0);
        while (!deadline.IsCancellationRequested)
        {
            SocketReceiveFromResult res;
            try
            {
                res = await udp.ReceiveFromAsync(buffer, SocketFlags.None, any, deadline.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (SocketException)
            {
                // An ICMP error from one server is not a verdict on the others. The
                // operation's deadline still bounds a directory where nobody replies.
                continue;
            }

            string[] parts = Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim().Split(' ');
            if (parts is ["INTRO", var idText, var payload]
                && ulong.TryParse(idText, NumberStyles.HexNumber, null, out ulong id) && id == peerId
                && payload.Length <= MaxWireRecord)
            {
                try
                {
                    return Base64Url.Decode(payload);
                }
                catch (FormatException)
                {
                    return null;
                }
            }
        }

        return null;
    }

    private static async Task ExpectAsync(Socket udp, string prefix, CancellationToken ct)
    {
        byte[] buffer = new byte[256];
        IPEndPoint any = new(IPAddress.IPv6Any, 0);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                SocketReceiveFromResult res = await udp.ReceiveFromAsync(buffer, SocketFlags.None, any, ct).ConfigureAwait(false);
                if (Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).StartsWith(prefix, StringComparison.Ordinal))
                {
                    return;
                }
            }
            catch (OperationCanceledException)
            {
                throw new TimeoutException("no rendezvous server acknowledged the registration");
            }
            catch (SocketException)
            {
                continue;
            }
        }

        throw new TimeoutException("no rendezvous server acknowledged the registration");
    }

    private static Socket NewSocket()
    {
        var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        if (OperatingSystem.IsWindows())
        {
            // A failed UDP destination otherwise makes the next receive (or send) fail,
            // even when a different directory server has a valid reply waiting.
            const int sioUdpConnreset = -1744830452;
            udp.IOControl(sioUdpConnreset, new byte[] { 0 }, null);
        }
        udp.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        return udp;
    }

    private static IPEndPoint ToWire(IPEndPoint ep)
    {
        // Same mapping PeerSocket performs: the socket is dual-mode IPv6, so v4 servers must
        // be v4-mapped, and an unspecified address (a server reported as "[::]:port") can
        // only ever mean loopback here.
        if (ep.Address.AddressFamily == AddressFamily.InterNetwork || ep.Address.Equals(IPAddress.IPv6Any))
        {
            IPAddress mapped = ep.Address.Equals(IPAddress.IPv6Any) ? IPAddress.IPv6Loopback : ep.Address.MapToIPv6();
            ep = new IPEndPoint(mapped, ep.Port);
        }

        return ep;
    }
}
