using System.Net;
using System.Net.Sockets;

namespace Pinhole;

/// <summary>A relay the node can allocate a TURN allocation on when a direct path fails.</summary>
public sealed record TurnServerConfig(IPEndPoint Server, string Username, string Credential);

/// <summary>Options for <see cref="PinholeNode.BindAsync(PinholeOptions?, CancellationToken)"/>.
/// Every infrastructure setting is tri-state: null means "use the free defaults", an empty
/// list means "disable this provider", and explicit entries replace the defaults. Scalar
/// settings keep their values in every case — customizing one never drops the others.</summary>
public sealed record PinholeOptions
{
    /// <summary>Local UDP endpoint to bind. Default: any address, OS-assigned port.</summary>
    public IPEndPoint? Bind { get; init; }

    /// <summary>STUN servers probed at bind for the reflexive candidate. Null (default)
    /// resolves the free provider catalog; an empty list disables the reflexive stage.</summary>
    public IReadOnlyList<IPEndPoint>? StunServers { get; init; }

    /// <summary>Optional TURN relays allocated as additional fallback paths. Supply credentials
    /// issued by the operator. There is no default: null and empty both mean no TURN.</summary>
    public IReadOnlyList<TurnServerConfig>? Relays { get; init; }

    /// <summary>Iroh HTTPS relay URLs used for introductions and datagram fallback.
    /// Null (default) uses the public n0 relays; an empty list disables them.</summary>
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

    /// <summary>Validate silent direct-path death (default true). NAT mappings expire and
    /// firewalls drop packets without any send error, so a connection that has received
    /// nothing on its direct path for <see cref="PathValidationIdle"/> is probed with the
    /// token-checked ping protocol; after <see cref="PathValidationMaxUnansweredProbes"/>
    /// unanswered probes the path is treated as dead (relay fallback, or an honest Dead)
    /// exactly as a send failure would be. This is transport path maintenance only — app
    /// heartbeats, retransmission, and delivery guarantees stay outside the library.
    /// Disable for allocation benchmarks that never receive.</summary>
    public bool EnablePathValidation { get; init; } = true;

    /// <summary>Direct-path silence before the first validation probe. Default 5 s.</summary>
    public TimeSpan PathValidationIdle { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Pace between validation probes; also the deadline for each probe's reply.
    /// Default 1 s.</summary>
    public TimeSpan PathValidationProbeInterval { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>Consecutive unanswered probes before the direct path is declared suspect.
    /// Default 3 — one lost probe or a busy moment never degrades a live path.</summary>
    public int PathValidationMaxUnansweredProbes { get; init; } = 3;

    /// <summary>Capacity of the per-connection receive buffer (default 0 = off). With a
    /// positive capacity every received datagram is copied into a bounded queue that exists
    /// from handshake time, so <see cref="PinholeConnection.ReceiveAsync"/> can drain
    /// datagrams that arrived before the app first reads — closing the accept/subscribe race
    /// the <see cref="PinholeConnection.Received"/> event cannot close. A full queue drops
    /// the oldest datagram (counted in <see cref="PinholeConnection.DroppedDatagrams"/>) and
    /// never blocks the receive loop. Unreliable means unreliable: buffering adds local
    /// queueing only, never network reliability.</summary>
    public int ReceiveBufferCapacity { get; init; }

    internal IReadOnlyList<IPEndPoint> ResolvedStun { get; init; } = Array.Empty<IPEndPoint>();
    internal IReadOnlyList<TurnServerConfig> ResolvedRelays { get; init; } = Array.Empty<TurnServerConfig>();
    internal IReadOnlyList<Uri> ResolvedIrohRelays { get; init; } = Array.Empty<Uri>();

    // Test seams so resolution tests can observe catalog lookups without touching the network.
    internal Func<CancellationToken, Task<IPEndPoint[]>>? StunCatalog { get; init; }
    internal Func<CancellationToken, Task<IPEndPoint[]>>? RelayCatalog { get; init; }

    internal static readonly Uri[] PublicIrohRelays =
    [
        new Uri("https://aps1-1.relay.n0.iroh.link/"),
        new Uri("https://euc1-1.relay.n0.iroh.link/"),
        new Uri("https://use1-1.relay.n0.iroh.link/"),
        new Uri("https://usw1-1.relay.n0.iroh.link/"),
    ];

    /// <summary>Default options: free STUN for reflexive candidates and the public n0 iroh
    /// HTTPS relays for introductions and fallback. No TURN account or native library is needed.
    /// Unreachable infrastructure simply contributes fewer candidates.</summary>
    public static Task<PinholeOptions> DefaultAsync(CancellationToken ct = default) =>
        ResolveAsync(null, ct);

    /// <summary>Fills in the infrastructure defaults a partially customized options object
    /// left unspecified, without touching the settings the caller did set. Cancellation
    /// during resolution propagates before any engine resource exists.</summary>
    internal static async Task<PinholeOptions> ResolveAsync(PinholeOptions? options, CancellationToken ct = default)
    {
        options ??= new PinholeOptions();
        Validate(options);

        // STUN: null resolves the free catalog; an empty or explicit list is the caller's
        // final answer. Already-resolved lists (DefaultAsync) are never looked up twice.
        IReadOnlyList<IPEndPoint> resolvedStun = options.ResolvedStun;
        if (options.StunServers is null && resolvedStun.Count == 0)
        {
            resolvedStun = Dedupe((await ResolveStunCatalogAsync(options, ct).ConfigureAwait(false)).Take(8));
        }

        // Iroh relays: null gets the public n0 relays; empty or explicit lists are final.
        IReadOnlyList<Uri> resolvedIroh = options.ResolvedIrohRelays;
        if (options.IrohRelayUrls is null && resolvedIroh.Count == 0)
        {
            resolvedIroh = PublicIrohRelays;
        }

        if (ReferenceEquals(resolvedStun, options.ResolvedStun) && ReferenceEquals(resolvedIroh, options.ResolvedIrohRelays))
        {
            return options;
        }

        return options with { ResolvedStun = resolvedStun, ResolvedIrohRelays = resolvedIroh };
    }

    private static void Validate(PinholeOptions options)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(options.PathValidationIdle, TimeSpan.FromMilliseconds(50));
        ArgumentOutOfRangeException.ThrowIfLessThan(options.PathValidationProbeInterval, TimeSpan.FromMilliseconds(20));
        ArgumentOutOfRangeException.ThrowIfLessThan(options.PathValidationMaxUnansweredProbes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.ReceiveBufferCapacity, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.ReceiveBufferCapacity, 65536);
    }

    private static async Task<IPEndPoint[]> ResolveStunCatalogAsync(PinholeOptions options, CancellationToken ct)
    {
        Task<IPEndPoint[]> lookup = (options.StunCatalog ?? Providers.Resolver.FreeStunAsync)(ct);
        try
        {
            return await lookup.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or HttpRequestException)
        {
            return Array.Empty<IPEndPoint>(); // dead infrastructure costs candidates, never the bind
        }
        // OperationCanceledException propagates: cancellation halts the bind, it is not tolerated.
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
