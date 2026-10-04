using System.Net;
using System.Net.Sockets;

namespace Pinhole;

/// <summary>A relay the node can allocate a TURN allocation on when a direct path fails.</summary>
public sealed record TurnServerConfig(IPEndPoint Server, string Username, string Credential);

/// <summary>Options for <see cref="PinholeNode.BindAsync(PinholeOptions?, CancellationToken)"/>.
/// Parameterless binding uses free STUN providers and public iroh HTTPS relays.
/// Use DefaultAsync and a with-expression to customize those defaults.</summary>
public sealed record PinholeOptions
{
    /// <summary>Local UDP endpoint to bind. Default: any address, OS-assigned port.</summary>
    public IPEndPoint? Bind { get; init; }

    /// <summary>STUN servers probed at bind for the reflexive candidate. Null (default)
    /// resolves the free provider catalog; an empty list disables the reflexive stage.</summary>
    public IReadOnlyList<IPEndPoint>? StunServers { get; init; }

    /// <summary>Optional TURN relays allocated as additional fallback paths. Supply credentials
    /// issued by the operator. The parameterless defaults use iroh relays instead.</summary>
    public IReadOnlyList<TurnServerConfig>? Relays { get; init; }

    /// <summary>Iroh HTTPS relay URLs used for introductions and datagram fallback.
    /// Parameterless BindAsync uses the public n0 relays; an empty list disables them.
    /// Pass explicit URLs for a privately hosted iroh relay.</summary>
    public IReadOnlyList<Uri>? IrohRelayUrls { get; init; }

    /// <summary>Accept connections dialed by unknown peers (default true). When false, only
    /// peers this node dials itself can establish a connection. Strangers are bounded: a
    /// flood of handshakes from unknown peer IDs stops materializing new state after 1024
    /// connections, so a hostile scan cannot exhaust memory.</summary>
    public bool Listen { get; init; } = true;

    /// <summary>React to OS network-configuration changes (default true): re-probe STUN and,
    /// when the socket's network is gone, rebind and re-announce so connections survive the
    /// roam. Disable on platforms with unreliable change notifications and call
    /// <see cref="PinholeNode.RoamNowAsync(System.Threading.CancellationToken)"/> yourself.</summary>
    public bool EnableNetworkWatch { get; init; } = true;

    /// <summary>How long <see cref="PinholeNode.ConnectAsync(string, CancellationToken)"/>
    /// keeps trying the chain (punch, then relay) before failing. Default 15 s.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>Budget for the bind-time STUN probes and relay allocation. Failures are
    /// tolerated: the node comes up with whatever candidates were observed. Default 5 s.</summary>
    public TimeSpan BindProbeBudget { get; init; } = TimeSpan.FromSeconds(5);

    internal IReadOnlyList<IPEndPoint> ResolvedStun { get; init; } = Array.Empty<IPEndPoint>();
    internal IReadOnlyList<TurnServerConfig> ResolvedRelays { get; init; } = Array.Empty<TurnServerConfig>();
    internal IReadOnlyList<Uri> ResolvedIrohRelays { get; init; } = Array.Empty<Uri>();

    /// <summary>Default options: free STUN for reflexive candidates and the public n0 iroh
    /// HTTPS relays for introductions and fallback. No TURN account or native library is needed.
    /// Unreachable infrastructure simply contributes fewer candidates.</summary>
    public static async Task<PinholeOptions> DefaultAsync(CancellationToken ct = default)
    {
        Task<IPEndPoint[]> stun = TryCall(
            () => Providers.Resolver.FreeStunAsync(ct),
            Array.Empty<IPEndPoint>());

        return new PinholeOptions
        {
            ResolvedStun = Dedupe((await stun.ConfigureAwait(false)).Take(8)),
            ResolvedIrohRelays =
            [
                new Uri("https://aps1-1.relay.n0.iroh.link/"),
                new Uri("https://euc1-1.relay.n0.iroh.link/"),
                new Uri("https://use1-1.relay.n0.iroh.link/"),
                new Uri("https://usw1-1.relay.n0.iroh.link/"),
            ],
        };
    }

    private static async Task<T> TryCall<T>(Func<Task<T>> work, T fallback)
    {
        try
        {
            return await work().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or HttpRequestException)
        {
            return fallback;
        }
    }

    private static IReadOnlyList<IPEndPoint> Dedupe(IEnumerable<IPEndPoint> endpoints)
    {
        var seen = new HashSet<IPEndPoint>();
        var list = new List<IPEndPoint>();
        foreach (IPEndPoint ep in endpoints)
        {
            if (seen.Add(ep))
            {
                list.Add(ep);
            }
        }

        return list;
    }
}
