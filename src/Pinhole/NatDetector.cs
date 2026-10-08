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
    /// regardless of destination (endpoint-independent mapping) — hole punching works.</summary>
    Cone,

    /// <summary>Different servers observed different mapped endpoints: the NAT creates a
    /// mapping per destination. Direct traversal depends on the other peer's filtering
    /// behavior and any explicit port mapping; relay fallback may be needed.</summary>
    Symmetric,
}

/// <summary>Classifies the local NAT by comparing what several STUN servers observe of the
/// SAME socket. This is the cheap, honest test: it separates symmetric NATs (per-destination
/// mappings) from endpoint-independent mappings. Finer
/// subtyping (restricted vs port-restricted cone) needs a cooperating server answering from
/// alternate ports, which public infrastructure does not offer.</summary>
public static class NatDetector
{
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
