using System.Net;
using System.Net.Sockets;
using System.Diagnostics.CodeAnalysis;

namespace Pinhole;

/// <summary>The verdict of a NAT detection pass.</summary>
public enum NatType
{
    /// <summary>Not enough evidence: no server answered, or only one did (a single mapping
    /// proves nothing about mapping behavior).</summary>
    Unknown,

    /// <summary>Every server observed the same mapped endpoint: the NAT reuses one mapping
    /// regardless of the tested destinations (endpoint-independent mapping).
    /// Filtering and the other peer's network still decide direct reachability.</summary>
    Cone,

    /// <summary>Different servers observed different mapped endpoints: the NAT creates a
    /// mapping per destination. Direct traversal depends on the other peer's filtering
    /// behavior and any explicit port mapping; relay fallback may be needed.</summary>
    Symmetric,
}

/// <summary>Classifies the local NAT by comparing what several STUN servers observe of the
/// SAME socket. This is the cheap, honest test: it separates symmetric NATs (per-destination
/// mappings) from endpoint-independent mappings. Finer
/// subtyping requires a cooperating alternate-address server; use <see cref="InspectAsync"/>
/// for a separate, bounded diagnostic pass when one is available.</summary>
public static class NatDetector
{
    /// <summary>Measure mapping and positive filtering evidence with a cooperating RFC 5780
    /// STUN server. Uses a fresh diagnostic UDP socket, never the application's socket.
    /// At most seven requests, each bounded by two seconds; unsupported servers and
    /// unanswered alternate responses produce unknown results. Does not prove punching
    /// success, future allocation, NAT count or another source socket's behavior.</summary>
    public static async Task<NatBehaviorReport> InspectAsync(IPEndPoint server, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(server);
        if (!StunBindingMessage.Usable(server)) throw new ArgumentException("A unicast STUN endpoint with a port is required", nameof(server));
        await using var node = await PinholeNode.BindAsync(new PinholeOptions
        {
            Bind = new(server.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0),
            StunServers = [], Relays = [], IrohRelayUrls = [], Listen = false, PublishIrohAddress = false,
            Encryption = PinholeEncryption.Disabled, EnableTcpTransport = false, EnableInterfaceCandidates = false,
            EnablePortMapping = false, EnableLanDiscovery = false, EnableNetworkWatch = false,
            EnablePathValidation = false, EnablePmtud = false, StunRefreshInterval = TimeSpan.Zero,
        }, ct).ConfigureAwait(false);
        return await NatBehaviorMeasurement.InspectAsync(node.Engine.DiagnosticLocalEndpoint, server,
            node.Engine.ProbeBindingAsync, ct).ConfigureAwait(false);
    }

    /// <summary>Runs detection against the free public STUN catalog.</summary>
    [SuppressMessage("ApiDesign", "RS0026", Justification = "These existing optional cancellation-token overloads must retain their published source and reflection contracts.")]
    public static async Task<NatType> DetectAsync(CancellationToken ct = default)
    {
        PinholeOptions defaults = await PinholeOptions.DefaultAsync(ct).ConfigureAwait(false);
        return await DetectAsync(defaults.ResolvedStun, ct).ConfigureAwait(false);
    }

    /// <summary>Runs detection against explicit servers. Needs at least two responsive
    /// servers to conclude anything; each probe reuses one socket, because the mapping
    /// under test belongs to the socket, not the request.</summary>
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
