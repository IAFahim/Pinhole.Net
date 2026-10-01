using System.Net;
using System.Net.Sockets;

namespace Pinhole;

/// <summary>A relay the node can allocate a TURN allocation on when a direct path fails.</summary>
public sealed record TurnServerConfig(IPEndPoint Server, string Username, string Credential);

/// <summary>Options for <see cref="PinholeNode.BindAsync(PinholeOptions?, CancellationToken)"/>.
/// Defaults use the free public infrastructure: STUN probes against the free providers and a
/// TURN allocation on the free OpenRelay server. Pass empty lists to disable a stage.</summary>
public sealed record PinholeOptions
{
    /// <summary>Local UDP endpoint to bind. Default: any address, OS-assigned port.</summary>
    public IPEndPoint? Bind { get; init; }

    /// <summary>STUN servers probed at bind for the reflexive candidate. Null (default)
    /// resolves the free provider catalog; an empty list disables the reflexive stage.</summary>
    public IReadOnlyList<IPEndPoint>? StunServers { get; init; }

    /// <summary>TURN relays allocated as the standing fallback path. Null (default) uses the
    /// free OpenRelay preset; an empty list disables the relay stage (direct-only node).</summary>
    public IReadOnlyList<TurnServerConfig>? Relays { get; init; }

    /// <summary>Accept connections dialed by unknown peers (default true). When false, only
    /// peers this node dials itself can establish a connection.</summary>
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

    /// <summary>Default options: the free STUN catalog for the reflexive candidate and the
    /// free OpenRelay TURN server as the fallback relay. Every stage is best-effort — DNS or
    /// allocation failures simply contribute fewer candidates.</summary>
    public static async Task<PinholeOptions> DefaultAsync(CancellationToken ct = default)
    {
        Task<IPEndPoint[]> stun = TryCall(
            () => Providers.Resolver.FreeStunAsync(ct),
            Array.Empty<IPEndPoint>());

        TurnServerConfig? openRelay = null;
        try
        {
            IPEndPoint ep = await ResolveAsync("openrelay.metered.ca", 80, ct).ConfigureAwait(false);
            openRelay = new TurnServerConfig(ep, "openrelayproject", "openrelayproject");
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
        }

        return new PinholeOptions
        {
            ResolvedStun = Dedupe((await stun.ConfigureAwait(false)).Take(8)),
            ResolvedRelays = openRelay is null ? [] : [openRelay],
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

    private static async Task<IPEndPoint> ResolveAsync(string host, int port, CancellationToken ct)
    {
        if (IPAddress.TryParse(host, out IPAddress? ip))
        {
            return new IPEndPoint(ip, port);
        }

        IPAddress[] addrs = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        return addrs.Length > 0 ? new IPEndPoint(addrs[0], port) : throw new SocketException((int)SocketError.HostNotFound);
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
