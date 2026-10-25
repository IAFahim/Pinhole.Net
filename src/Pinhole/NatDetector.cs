using System.Net;
using System.Net.Sockets;
using System.Diagnostics.CodeAnalysis;

namespace Pinhole;

public enum NatType
{
    Unknown,

    Cone,

    Symmetric,
}

public static class NatDetector
{
    public static async Task<NatBehaviorReport> InspectAsync(IPEndPoint server, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(server);
        if (!StunBindingMessage.Usable(server)) throw new ArgumentException("A unicast STUN endpoint with a port is required", nameof(server));
        await using var node = await PinholeNode.BindAsync(new PinholeOptions
        {
            Bind = new(server.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0),
            StunServers = [], Relays = [], IrohRelayUrls = [], DerpRelayUrls = [], Listen = false, PublishIrohAddress = false,
            Encryption = PinholeEncryption.Disabled, EnableTcpTransport = false, EnableInterfaceCandidates = false,
            EnablePortMapping = false, EnableLanDiscovery = false, EnableNetworkWatch = false,
            EnablePathValidation = false, EnablePmtud = false, StunRefreshInterval = TimeSpan.Zero,
        }, ct).ConfigureAwait(false);
        return await NatBehaviorMeasurement.InspectAsync(node.Engine.DiagnosticLocalEndpoint, server,
            node.Engine.ProbeBindingAsync, ct).ConfigureAwait(false);
    }

    [SuppressMessage("ApiDesign", "RS0026", Justification = "These existing optional cancellation-token overloads must retain their published source and reflection contracts.")]
    public static async Task<NatType> DetectAsync(CancellationToken ct = default)
    {
        PinholeOptions defaults = await PinholeOptions.DefaultAsync(ct).ConfigureAwait(false);
        return await DetectAsync(defaults.ResolvedStun, ct).ConfigureAwait(false);
    }

    [SuppressMessage("ApiDesign", "RS0026", Justification = "These existing optional cancellation-token overloads must retain their published source and reflection contracts.")]
    public static async Task<NatType> DetectAsync(IReadOnlyList<IPEndPoint> servers, CancellationToken ct = default)
    {
        if (servers.Count < 2)
        {
            return NatType.Unknown;
        }

        using var socket = new PeerSocket(0x4E); // 'N': an idle frame type for a probe-only socket
        var seen = new List<IPEndPoint>();
        foreach (IPEndPoint server in servers)
        {
            IPEndPoint mapped;
            try
            {
                // Detection must stay snappy even with a dead server in the list: cap each
                // probe well under the punch engine's signaling timeout.
                using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                probeCts.CancelAfter(TimeSpan.FromSeconds(3));
                mapped = await socket.ProbeStunAsync(server, probeCts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException or TimeoutException or OperationCanceledException)
            {
                ct.ThrowIfCancellationRequested();
                continue; // an unresponsive server must not sink the verdict
            }

            seen.Add(mapped);
        }

        return Classify(seen);
    }

    // IPv4 and IPv6 naturally have different endpoints. Only compare observations within
    // one family, or a healthy dual-stack network would be mislabeled symmetric.
    internal static NatType Classify(IReadOnlyList<IPEndPoint> observations)
    {
        var comparable = observations.GroupBy(ep => ep.AddressFamily).Where(group => group.Count() >= 2).ToArray();
        if (comparable.Length == 0) return NatType.Unknown;
        return comparable.Any(group => group.Distinct().Count() > 1) ? NatType.Symmetric : NatType.Cone;
    }
}
