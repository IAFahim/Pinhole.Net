using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;

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

    /// <summary>Publish this node through native iroh signed pkarr discovery (default true).
    /// The record binds the endpoint ID to this node's Pinhole static key, so compatible
    /// Android clients can dial by ID or native ticket without dropping peer authentication.
    /// Set false for offline nodes or when <see cref="Encryption"/> is disabled.</summary>
    public bool PublishIrohAddress { get; init; } = true;

    /// <summary>Include direct and reflexive IP addresses in native iroh discovery
    /// (default true), so peers resolving an endpoint ID can attempt direct connections.
    /// Set false to publish relay URLs and the signed session-key binding only.
    /// A shared native ticket may still carry direct addresses.</summary>
    public bool PublishDirectIrohAddresses { get; init; } = true;

    /// <summary>Native HTTP pkarr discovery service. Default https://dns.iroh.link/pkarr.
    /// HTTP is accepted only on loopback for local integration tests.</summary>
    public Uri IrohDiscoveryUrl { get; init; } = new("https://dns.iroh.link/pkarr");

    internal HttpMessageHandler? IrohDiscoveryHandler { get; init; }
    internal Func<ILanChannel>? LanChannelFactory { get; init; }
    internal Func<Uri, CancellationToken, Task<WebSocket>>? IrohWebSocketFactory { get; init; }

    /// <summary>Use relays only for authenticated handshakes, candidate exchange,
    /// path probes and close (default false). Connect/Accept wait for a direct
    /// application path; application datagrams are never sent or delivered through
    /// a relay. Requires <see cref="PinholeEncryption.Required"/>. A relay introduction
    /// can improve punching but cannot guarantee a permitted direct route.</summary>
    public bool RelaySignalingOnly { get; init; }

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

    /// <summary>Try an encrypted direct TCP sidecar when UDP has not opened (default
    /// true). It normally listens on the UDP port's numeric value, negotiates framing
    /// and uses the same pinned session keys. Healthy UDP is preferred. A failed TCP
    /// bind or dial never prevents UDP/relay use. Plaintext nodes do not enable TCP.</summary>
    public bool EnableTcpTransport { get; init; } = true;

    /// <summary>Try direct UDP session routes (default true). Set false to use direct
    /// TCP and configured relays. The UDP socket remains bound for discovery/STUN;
    /// this does not prohibit UDP used by an explicitly configured TURN provider.</summary>
    public bool EnableDirectUdp { get; init; } = true;

    /// <summary>Advertise IPv6 link-local candidates (default true). Access networks that
    /// isolate IPv4 between wireless and wired clients but bridge IPv6 — common on guest and
    /// enterprise WiFi — leave link-local as the only direct path, and a peer that dials the
    /// bare address re-scopes it onto its own radio/ethernet link. At most two candidates,
    /// wireless first, appended after every routable address. Link-local probes start after
    /// routable probes and try each local LAN interface; cellular and tunnel interfaces are
    /// excluded. Set false to omit these LAN-only fallback candidates.</summary>
    public bool AdvertiseLinkLocal { get; init; } = true;

    /// <summary>Ask the network's router for explicit UDP and enabled TCP port mappings (PCP, then
    /// NAT-PMP, then UPnP — the same strategy iroh's portmapper uses; default true). A
    /// granted mapping is advertised as a reflexive candidate, which makes many hard home
    /// NATs directly punchable and works even where hole punching alone would fail.
    /// Discovery is entirely background and best-effort: routers without these protocols
    /// simply contribute no mapping, and nothing about the bind ever waits on it. Disable
    /// on networks where router control traffic is unwelcome.</summary>
    public bool EnablePortMapping { get; init; } = true;

    /// <summary>Also request UPnP IPv6 firewall pinholes for this node's global IPv6
    /// endpoints (default true; requires <see cref="EnablePortMapping"/>). Uses at
    /// most two Wi-Fi/Ethernet source addresses and only the actual UDP/TCP listening
    /// ports. Refusal or unsupported gateways contribute no lease. This does not
    /// change the host firewall or prove end-to-end reachability.</summary>
    public bool EnableIPv6FirewallPinholes { get; init; } = true;

    /// <summary>How long <see cref="PinholeNode.ConnectAsync(string, CancellationToken)"/>
    /// keeps trying the chain (punch, then relay) before failing. Default 15 s.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>Wire encryption and peer authentication (default <see cref="PinholeEncryption.Required"/>).
    /// Every session runs an X25519 handshake and is sealed with AES-256-GCM: traffic is
    /// confidential, tamper-proof, replay-proof, and the peer is authenticated against the
    /// static key embedded in its connection string — a man in the middle cannot substitute
    /// itself, strip the handshake, or read a byte. <see cref="PinholeEncryption.Optional"/>
    /// still accepts pre-1.6 plaintext peers when they cannot speak crypto;
    /// <see cref="PinholeEncryption.Disabled"/> reproduces the old plaintext wire.</summary>
    public PinholeEncryption Encryption { get; init; } = PinholeEncryption.Required;

    /// <summary>The 32-byte private seed of this node's long-term X25519 identity. Leave
    /// null for a fresh identity per process; persist and pass one when peer identity should
    /// survive restarts (peers pin the public half from connection strings). The seed is
    /// also the root of the Ed25519 endpoint identity: with a seed, the peer ID, static key,
    /// and endpoint key are all stable across restarts, and peers holding an old connection
    /// string can rediscover this node through a lookup provider instead of a new ticket.</summary>
    public byte[]? IdentityKeySeed { get; init; }

    /// <summary>Endpoints of <c>Pinhole.Rendezvous</c> introducers used as the built-in
    /// address-lookup provider. Null and empty (default) disable it. Requires a persisted
    /// <see cref="IdentityKeySeed"/> to be useful across restarts; publishing additionally
    /// requires <see cref="Listen"/>. See docs/REDISCOVERY.md for the trust model — the
    /// introducer is never trusted, only the record signatures are.</summary>
    public IReadOnlyList<IPEndPoint>? RendezvousEndpoints { get; init; }

    /// <summary>Application-supplied lookup providers (signed DNS, pkarr, an iroh-style
    /// directory — anything implementing <see cref="IPinholeLookupProvider"/>), consulted
    /// alongside any <see cref="RendezvousEndpoints"/>. All providers are queried in
    /// parallel and the first record that verifies against the dialer's pinned endpoint key
    /// wins; a provider that is down or lying can only deny availability.</summary>
    public IReadOnlyList<IPinholeLookupProvider>? LookupProviders { get; init; }

    /// <summary>Budget for the bind-time STUN probes and relay allocation. Failures are
    /// tolerated: the node comes up with whatever candidates were observed. Default 5 s.</summary>
    public TimeSpan BindProbeBudget { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>How often the node re-probes its STUN servers to refresh the server-reflexive
    /// candidates (the same periodic re-discovery iroh performs). NAT mappings move silently —
    /// DHCP renews, router reboots — without any OS network event, so the node re-checks on a
    /// timer and, when the observed mapping changed, re-advertises its candidates to every
    /// peer; regenerate and re-share connection strings after a change. Working direct paths
    /// are never torn down by a refresh. Default 1 minute; zero or negative disables.</summary>
    public TimeSpan StunRefreshInterval { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>How often PMTUD re-verifies the confirmed path MTU (RFC 8899 suggests
    /// five minutes; the default matches). A path whose MTU SHRANK after confirmation — a
    /// VPN or tunnel engaged mid-connection — is caught by this re-verification and falls
    /// back to the guaranteed floor before re-climbing. Values below one second are for
    /// tests that need to compress the cycle.</summary>
    public TimeSpan PmtuReprobeInterval { get; init; } = TimeSpan.FromMinutes(5);

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

    /// <summary>Discover the direct path's MTU (default true), RFC 8899-style: padded
    /// token-checked pings climb from the guaranteed 1200-byte payload floor, a matching
    /// pong confirms a size, and three unanswered probes abandon it for a cooldown. A
    /// confirmed size raises <see cref="PinholeConnection.PathMtu"/> — and with it the
    /// largest payload <see cref="PinholeConnection.Send"/> accepts above the floor. Probing
    /// restarts whenever the connection moves off its direct path. Disable for exact
    /// worst-case payload budgets.</summary>
    public bool EnablePmtud { get; init; } = true;

    /// <summary>Announce this node on the local network as
    /// <c>&lt;peer-id&gt;._pinhole._udp.local</c> (default true) so peers running
    /// <see cref="PinholeNode.DiscoverLanPeersAsync"/> find it with no server and no
    /// clipboard. The announcement carries the peer ID, static public key, NAT hint, and
    /// local addresses — discovered sessions get the same key pinning as shared-string
    /// ones. Set false to disable LAN announcements. Failures to announce (no multicast
    /// in containers) never fail the bind.</summary>
    public bool EnableLanDiscovery { get; init; } = true;

    /// <summary>Send a heartbeat ping at this interval on every open connection (default
    /// zero = off). The pings ride the connection's current path — direct or relay — and
    /// their pongs refresh the NAT mapping in both directions, keep half-idle firewalls
    /// from forgetting the flow, and feed <see cref="PinholeConnection.LastRtt"/>. They
    /// count in <see cref="PinholeConnection.Stats"/> like caller pings: the app asked
    /// for them. This is a heartbeat, not reliability — delivery guarantees stay out.</summary>
    public TimeSpan KeepaliveInterval { get; init; }

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

    // Test seams so port-mapping tests can aim PCP/PMP at an in-process fake gateway and
    // SSDP at an in-process fake IGD instead of the real network, plus a fast lease for
    // renewal observations.
    internal IReadOnlyList<IPEndPoint>? GatewayOverride { get; init; }
    internal IPEndPoint? SsdpUnicastOverride { get; init; }
    internal TimeSpan PortMappingLease { get; init; } = TimeSpan.FromHours(2);

    // Test seams so resolution tests can observe catalog lookups without touching the network.
    internal Func<CancellationToken, Task<IPEndPoint[]>>? StunCatalog { get; init; }
    internal Func<CancellationToken, Task<IPEndPoint[]>>? RelayCatalog { get; init; }

    /// <summary>Test seam for the topology lab: replaces the OS UDP socket with an
    /// in-process network that routes datagrams between nodes through injected NATs,
    /// loss, and delay. Null (always, in production) binds real sockets.</summary>
    internal UdpSocketFactory? UdpSocketFactory { get; init; }

    /// <summary>Test seam for the stranger-flood bound (#34): replaces the engine's
    /// 1024-connection cap on unknown-peer materializations so a flood test reaches it
    /// in a handful of handshakes instead of a thousand. Null keeps production's cap;
    /// the bound is checked before insert either way (see NodeEngine.CreateIncoming).</summary>
    internal int? MaxConnectionsOverride { get; init; }

    internal static readonly Uri[] PublicIrohRelays =
    [
        new Uri("https://aps1-1.relay.n0.iroh.link/"),
        new Uri("https://euc1-1.relay.n0.iroh.link/"),
        new Uri("https://use1-1.relay.n0.iroh.link/"),
        new Uri("https://usw1-1.relay.n0.iroh.link/"),
    ];

    /// <summary>Default options: free STUN for reflexive candidates and the public n0 iroh
    /// HTTPS relays for introductions and fallback, signed endpoint/direct-address
    /// publication, and LAN announcements. No TURN account or native library is needed.
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
        IrohAddress.ValidateRelay(options.IrohDiscoveryUrl);
        if (options.PublishIrohAddress && options.Encryption == PinholeEncryption.Disabled)
            throw new ArgumentException("Pinhole iroh discovery requires an encrypted session with a static key", nameof(options));
        if (options.RelaySignalingOnly && options.Encryption != PinholeEncryption.Required)
            throw new ArgumentException("RelaySignalingOnly requires authenticated encrypted sessions", nameof(options));
        if (options.IdentityKeySeed is { Length: not NodeIdentity.KeyLength })
            throw new ArgumentOutOfRangeException(nameof(options), $"IdentityKeySeed must be {NodeIdentity.KeyLength} bytes");
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
