using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;

namespace Pinhole;

public sealed record TurnServerConfig(IPEndPoint Server, string Username, string Credential);

public sealed record PinholeOptions
{
    public IPEndPoint? Bind { get; init; }

    public IReadOnlyList<IPEndPoint>? StunServers { get; init; }

    public IReadOnlyList<TurnServerConfig>? Relays { get; init; }

    public IReadOnlyList<Uri>? IrohRelayUrls { get; init; }

    public IReadOnlyList<Uri>? DerpRelayUrls { get; init; }

    public bool PublishIrohAddress { get; init; } = true;

    public bool PublishDirectIrohAddresses { get; init; } = true;

    public Uri IrohDiscoveryUrl { get; init; } = new("https://dns.iroh.link/pkarr");

    internal HttpMessageHandler? IrohDiscoveryHandler { get; init; }
    internal Func<ILanChannel>? LanChannelFactory { get; init; }
    internal Func<Uri, CancellationToken, Task<WebSocket>>? IrohWebSocketFactory { get; init; }
    internal Func<Uri, CancellationToken, Task<WebSocket>>? DerpWebSocketFactory { get; init; }

    public bool RelaySignalingOnly { get; init; }

    public bool Listen { get; init; } = true;

    public bool EnableNetworkWatch { get; init; } = true;

    public bool EnableTcpTransport { get; init; } = true;

    public bool EnableDirectUdp { get; init; } = true;

    public bool EnableInterfaceCandidates { get; init; } = true;

    public bool EnablePortPrediction { get; init; } = true;

    internal Func<IReadOnlyList<UdpInterfaceSource>>? InterfaceSourceProvider { get; init; }
    internal UdpSocketFactory? InterfaceUdpSocketFactory { get; init; }

    public bool AdvertiseLinkLocal { get; init; } = true;

    public bool EnablePortMapping { get; init; } = true;

    public bool EnableIPv6FirewallPinholes { get; init; } = true;

    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(15);

    public PinholeEncryption Encryption { get; init; } = PinholeEncryption.Required;

    public byte[]? IdentityKeySeed { get; init; }

    public byte[]? Knock { get; init; }

    public bool HybridKeyExchange { get; init; }

    public IReadOnlyList<IPEndPoint>? RendezvousEndpoints { get; init; }

    public IReadOnlyList<IPinholeLookupProvider>? LookupProviders { get; init; }

    public TimeSpan BindProbeBudget { get; init; } = TimeSpan.FromSeconds(5);

    public TimeSpan StunRefreshInterval { get; init; } = TimeSpan.FromMinutes(1);

    public TimeSpan PmtuReprobeInterval { get; init; } = TimeSpan.FromMinutes(5);

    public bool EnablePathValidation { get; init; } = true;

    public TimeSpan PathValidationIdle { get; init; } = TimeSpan.FromSeconds(5);

    public TimeSpan PathValidationProbeInterval { get; init; } = TimeSpan.FromSeconds(1);

    public int PathValidationMaxUnansweredProbes { get; init; } = 3;

    public bool EnablePmtud { get; init; } = true;

    public bool EnableLanDiscovery { get; init; } = true;

    public TimeSpan KeepaliveInterval { get; init; }

    public int ReceiveBufferCapacity { get; init; }

    internal IReadOnlyList<IPEndPoint> ResolvedStun { get; init; } = Array.Empty<IPEndPoint>();
    internal IReadOnlyList<TurnServerConfig> ResolvedRelays { get; init; } = Array.Empty<TurnServerConfig>();
    internal IReadOnlyList<Uri> ResolvedIrohRelays { get; init; } = Array.Empty<Uri>();
    internal IReadOnlyList<Uri> ResolvedDerpRelays { get; init; } = Array.Empty<Uri>();

    internal IReadOnlyList<IPEndPoint>? GatewayOverride { get; init; }
    internal IPEndPoint? SsdpUnicastOverride { get; init; }
    internal TimeSpan PortMappingLease { get; init; } = TimeSpan.FromHours(2);

    internal Func<CancellationToken, Task<IPEndPoint[]>>? StunCatalog { get; init; }
    internal Func<CancellationToken, Task<IPEndPoint[]>>? RelayCatalog { get; init; }

    internal UdpSocketFactory? UdpSocketFactory { get; init; }

    internal int? MaxConnectionsOverride { get; init; }

    internal static readonly Uri[] PublicIrohRelays =
    [
        new Uri("https://aps1-1.relay.n0.iroh.link/"),
        new Uri("https://euc1-1.relay.n0.iroh.link/"),
        new Uri("https://use1-1.relay.n0.iroh.link/"),
        new Uri("https://usw1-1.relay.n0.iroh.link/"),
    ];

    internal static readonly Uri[] PublicDerpRelays =
    [
        new Uri("https://tc304a.ipn.dev/"),
        new Uri("https://tc303a.ipn.dev/"),
        new Uri("https://tc301a.ipn.dev/"),
        new Uri("https://tc302a.ipn.dev/"),
    ];

    public static Task<PinholeOptions> DefaultAsync(CancellationToken ct = default) =>
        ResolveAsync(null, ct);

    internal static async Task<PinholeOptions> ResolveAsync(PinholeOptions? options, CancellationToken ct = default)
    {
        options ??= new PinholeOptions();
        Validate(options);

        IReadOnlyList<IPEndPoint> resolvedStun = options.ResolvedStun;
        if (options.StunServers is null && resolvedStun.Count == 0)
        {
            resolvedStun = Dedupe((await ResolveStunCatalogAsync(options, ct).ConfigureAwait(false)).Take(8));
        }

        IReadOnlyList<Uri> resolvedIroh = options.ResolvedIrohRelays;
        if (options.IrohRelayUrls is null && resolvedIroh.Count == 0)
        {
            resolvedIroh = PublicIrohRelays;
        }

        IReadOnlyList<Uri> resolvedDerp = options.ResolvedDerpRelays;
        if (options.DerpRelayUrls is null && resolvedDerp.Count == 0)
            resolvedDerp = PublicDerpRelays;

        if (ReferenceEquals(resolvedStun, options.ResolvedStun) && ReferenceEquals(resolvedIroh, options.ResolvedIrohRelays)
            && ReferenceEquals(resolvedDerp, options.ResolvedDerpRelays))
        {
            return options;
        }

        return options with { ResolvedStun = resolvedStun, ResolvedIrohRelays = resolvedIroh, ResolvedDerpRelays = resolvedDerp };
    }

    private static void Validate(PinholeOptions options)
    {
        IrohAddress.ValidateRelay(options.IrohDiscoveryUrl);
        if (options.DerpRelayUrls is { } derpUrls)
        {
            if (derpUrls.Count > ConnectionString.MaxCandidates) throw new ArgumentOutOfRangeException(nameof(options), "too many DERP relays");
            foreach (Uri url in derpUrls)
            {
                IrohAddress.ValidateRelay(url);
                if (url.AbsoluteUri.Length > 64 || url.AbsoluteUri.Any(ch => ch > 127))
                    throw new ArgumentException("DERP candidate URLs are limited to 64 ASCII bytes", nameof(options));
            }
        }
        if (options.PublishIrohAddress && options.Encryption == PinholeEncryption.Disabled)
            throw new ArgumentException("Pinhole iroh discovery requires an encrypted session with a static key", nameof(options));
        if (options.RelaySignalingOnly && options.Encryption != PinholeEncryption.Required)
            throw new ArgumentException("RelaySignalingOnly requires authenticated encrypted sessions", nameof(options));
        if (options.IdentityKeySeed is { Length: not NodeIdentity.KeyLength })
            throw new ArgumentOutOfRangeException(nameof(options), $"IdentityKeySeed must be {NodeIdentity.KeyLength} bytes");
        if (options.Knock is { } knock)
        {
            if (knock.Length is < 8 or > ConnectionString.MaxKnockLength)
                throw new ArgumentOutOfRangeException(nameof(options),
                    $"Knock must be 8..{ConnectionString.MaxKnockLength} bytes — generate a >=16-byte secret, not a password-sized string");
            if (options.Encryption == PinholeEncryption.Disabled)
                throw new ArgumentException("a knock requires an encrypted node: the static public key keys its mac1", nameof(options));
        }
        if (options.HybridKeyExchange && options.Encryption == PinholeEncryption.Disabled)
            throw new ArgumentException("hybrid key exchange requires an encrypted node: it extends the X25519 handshake", nameof(options));
        if (options.LookupProviders is { } providers && providers.Any(p => p is null))
            throw new ArgumentOutOfRangeException(nameof(options), "LookupProviders must not contain null entries");
        ArgumentOutOfRangeException.ThrowIfLessThan(options.PathValidationIdle, TimeSpan.FromMilliseconds(50));
        ArgumentOutOfRangeException.ThrowIfLessThan(options.PathValidationProbeInterval, TimeSpan.FromMilliseconds(20));
        ArgumentOutOfRangeException.ThrowIfLessThan(options.PathValidationMaxUnansweredProbes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.ReceiveBufferCapacity, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.ReceiveBufferCapacity, 65536);
        if (options.StunRefreshInterval > TimeSpan.Zero && options.StunRefreshInterval < TimeSpan.FromMilliseconds(100))
            throw new ArgumentOutOfRangeException(nameof(options), "StunRefreshInterval must be zero (off) or at least 100 ms");
        if (options.KeepaliveInterval > TimeSpan.Zero && options.KeepaliveInterval < TimeSpan.FromMilliseconds(100))
            throw new ArgumentOutOfRangeException(nameof(options), "KeepaliveInterval must be zero (off) or at least 100 ms");
        if (options.PmtuReprobeInterval < TimeSpan.FromSeconds(1))
            throw new ArgumentOutOfRangeException(nameof(options), "PmtuReprobeInterval must be at least 1 s");
        if (options.MaxConnectionsOverride is <= 0)
            throw new ArgumentOutOfRangeException(nameof(options), "MaxConnectionsOverride must be positive when set");
    }

    private static async Task<IPEndPoint[]> ResolveStunCatalogAsync(PinholeOptions options, CancellationToken ct)
    {
        Task<IPEndPoint[]> lookup = (options.StunCatalog ?? Providers.Resolver.FreeStunAsync)(ct);
        try
        {

            return await lookup.WaitAsync(options.BindProbeBudget + CatalogSlack, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or HttpRequestException or TimeoutException)
        {
            return Array.Empty<IPEndPoint>();
        }

    }

    private static readonly TimeSpan CatalogSlack = TimeSpan.FromSeconds(2);

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
