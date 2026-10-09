using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using Pinhole.Turn;

namespace Pinhole;

internal enum FrameType : byte
{
    Punc = 0x50, // punch probe; body = the sender's handshake token (u32 LE), or token + X25519 ephemeral + static (v2)
    Pack = 0x51, // punch ack; body = [echo of the received PUNC token][sender's own token], plus v2 keys + confirm MAC
    Data = 0x52,  // body = [sender's token][payload] — sealed (counter + AES-GCM) once a session exists
    Ping = 0x53,  // body = [sender's token][timestamp:8]
    Pong = 0x54,  // body = [sender's token][timestamp:8]
    Announce = 0x55, // body = [sender's token][count][candidate TLV stream]
    Bye = 0x56,   // body = [sender's token]
    Hsck = 0x57,  // handshake confirm; body = [sender's token][confirm MAC:16] — the dialer's proof after a verified PACK
    Predict = 0x58, // sealed, negotiated, bounded prediction control; never a reflexive candidate
}

// Wire authentication model: every frame carries the sender's per-connection token at
// offset HeaderSize. Punc teaches the receiver the dialer's token, Pack delivers the
// responder's, and every later frame must echo the token the receiver learned. The token
// is random per connection and never appears in the connection string, so holding the
// string (public by design) lets a stranger dial, but not spoof, hijack, or kill an
// established session.

/// <summary>Per-peer state. One node multiplexes these over its shared UDP sources and TCP sidecar;
/// every frame carries the sender's peer ID so the receiver demuxes without a socket pair per
/// conversation. Frame handlers run on the receive thread, state transitions take
/// <see cref="Gate"/>, counters are Interlocked.</summary>
internal sealed class ConnState
{
    public required ulong PeerId { get; init; }
    public required uint Token { get; init; }

    public readonly object Gate = new();
    public volatile PinholeConnectionState State = PinholeConnectionState.Punching;
    public volatile PathKind Path = PathKind.None;
    public DateTimeOffset PathSince = DateTimeOffset.UtcNow;
    public SocketAddress? DirectRemote;      // where direct frames go (last-wins by peer ID)
    public IPEndPoint? DirectRemoteEp;       // display form of DirectRemote
    public TcpLink? DirectTcp;               // null on UDP; authenticated stream on TCP
    public IUdpSocket? DirectUdpSocket;      // null for the wildcard socket; actual source on a bound interface
    public TcpLink? PendingTcp;              // incoming TCP stranger, not accepted before proof
    public bool IncomingQueued;
    public bool IsIncoming;
    public bool PeerCandidatesReceived;
    public bool AwaitInitialCandidateExchange;
    public long LastCandidateAnnouncement;
    public long RelayedDatagramsBlocked;
    public long PortPredictionProbesSent;
    public volatile PortPredictionState? Prediction;
    public int TcpDialing;
    public long LastTcpAttempt;
    public TcpLink? ProbeTcp;
    public IUdpSocket? ProbeUdpSocket;
    public IPEndPoint? RelayRemote;          // peer's relayed address
    public volatile bool RelayReady;         // permission for RelayRemote exists on our allocation
    public readonly List<PinholeCandidate> PeerCandidates = new(); // guarded by engine gate
    public bool SymmetricHint;               // peer advertised a symmetric NAT: relay-first scheduling
    public uint RemoteToken;                 // learned from the peer's frames; staleness filter
    public bool RemoteTokenKnown;
    public ConnectionCrypto? Crypto;         // handshake + sealers; null = plaintext session (guarded by Gate for the handshake fields)
    public byte[]? PinnedStaticKey;          // the v2 connection string's static key (dial side, immutable)
    public byte[]? PinnedEndpointKey;        // the v3 connection string's endpoint key (dial side, immutable)
    public bool HsckSent;                    // Gate: our confirm went out in an Hsck frame
    public bool Announced;
    public long LastKickTicks = Environment.TickCount64; // monotonic: suspend-proof punch budget
    public volatile bool BlackholeDirect;    // test hook: drop this peer's direct frames
    public int PunchGeneration;
    public long LastLookupTicks;           // Gate; cadence for punch-time record lookups
    public long DeadSinceTicks;            // Gate; when the punch budget condemned the connection
    public int PermitInFlight;               // single-flight guard for TURN permission round trips
    public IrohRelay? Iroh;
    public byte[]? IrohPeerKey;
    public bool IrohConfirmed;
    public byte[] PuncFrame = Array.Empty<byte>(); // built with the connection's token
    public DatagramBuffer? Buffer;      // non-null only with ReceiveBufferCapacity > 0

    public readonly TaskCompletionSource Connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource Closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly CancellationTokenSource Dead = new();

    // Silent-death path validation (monotonic Environment.TickCount64 everywhere). Only
    // frames RECEIVED on the direct path count as activity — a successful UDP send proves
    // nothing, or a dead path that never errors would look alive forever.
    public long LastDirectRxTicks;       // Volatile; written under Gate
    public long LastRelayRxTicks;        // Volatile; receive thread only — relay-leg liveness clock
    public bool ProbeOutstanding;        // Gate
    public long ProbeNonce;              // Gate; TickCount64 | ProbeMarker
    public long ProbeDeadlineTicks;      // Gate
    public SocketAddress? ProbeTarget;   // Gate; the endpoint the outstanding probe went to
    public int UnansweredProbes;         // Gate
    public long PathProbesSent;          // Interlocked; separate from caller ping stats
    public long PathProbeReplies;        // Interlocked; only matched, direct-endpoint replies

    // RFC 8899-style path MTU discovery. The 1200-byte API floor is presumed good; padded
    // pings climb from there, and a confirmed size raises the app payload ceiling. All
    // fields are guarded by Gate except the counters.
    public int PmtuWire;                   // Gate; confirmed wire capacity (0 = unprobed)
    public bool PmtuVerifiedSize;          // Gate; the confirmed size itself was (re)verified
    public bool PmtuOutstanding;           // Gate
    public long PmtuProbeNonce;            // Gate; TickCount64 | PmtuProbeMarker
    public int PmtuProbeSize;              // Gate; wire bytes of the outstanding probe
    public int PmtuProbeTries;             // Gate
    public long PmtuDeadlineTicks;         // Gate
    public SocketAddress? PmtuProbeTarget; // Gate; the endpoint the probe went to
    public IUdpSocket? PmtuProbeUdpSocket;
    public long PmtuNextProbeTicks;        // Gate; cooldown after failure / ceiling
    public long PmtuProbesSent;            // Interlocked
    public volatile int DropAboveBytes;    // test hook: direct frames larger than this are black-holed
    public long KeepaliveNextTicks;        // Gate; zero-interval (off) never reaches this path

    public PinholeConnection? Public;
    public PinholeDatagramHandler? Received;
    public Action<PinholeConnectionState>? StateChanged;

    public long Sent, ReceivedCount, SendFailed, BytesSent, BytesReceived, PingsSent, PongsReceived;
    public long LastRttTicks = long.MinValue; // Interlocked
    public double RttEwmaTicks;              // guarded by Gate
    public int ConsecutiveSendFailures;
}

internal sealed partial class NodeEngine : IDisposable
{
    public const int MaxPayload = 1200;
    private const int HeaderSize = CryptoWire.HeaderLength;

    /// <summary>Upper bound on connections a stranger flood can materialize. Applications
    /// dialing peers themselves are not bounded by this — only unknown-peer PUNCs are.</summary>
    internal const int MaxConnections = 1024;
    private readonly int _maxConns; // production cap unless PinholeOptions.MaxConnectionsOverride says otherwise

    // Must exceed the largest legit announce: HeaderSize + token + count + 32 fat relay
    // candidates (~170 bytes each) lands near 5.5 KB; a smaller buffer would truncate and
    // silently drop exactly the relay-heavy announces that matter most.
    private const int RecvBufferSize = 8192;
    private const uint StunCookie = 0x2112A442;

    private static readonly TimeSpan PunchPace = TimeSpan.FromMilliseconds(200);
    private const long LinkLocalFallbackDelayMs = 600;
    private static readonly TimeSpan UpgradePace = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan SymmetricDirectTrickle = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan DeadBeaconPace = TimeSpan.FromSeconds(1);
    private const long DeadBeaconBudgetMs = 300_000; // five minutes of post-Dead beacons
    private const int MaxUpgradeAttempts = 120; // then passive: peer frames can still open direct
    private static readonly TimeSpan RelayRetryBackoff = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RelayMaxBackoff = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RecoverDebounce = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(2);

    // Path MTU discovery. The frame overhead every sealed payload pays, the presumed-good
    // floor (the 1200-byte API guarantee), and the Ethernet plateaus probed up to. The
    // nonce marker is positive — path probes took the sign bit — and cannot collide with
    // caller pings, whose timestamps are TickCount64 readings.
    internal const int PmtuOverhead = HeaderSize + CryptoWire.TokenLength + CryptoWire.SealedOverhead;
    internal const int PmtuBaseWire = MaxPayload + PmtuOverhead;
    private const int PmtuCeilingV4 = 1472; // Ethernet IPv4: 1500 - 20 - 8
    private const int PmtuCeilingV6 = 1452; // Ethernet IPv6: 1500 - 40 - 8
    private const int PmtuStepBytes = 128;
    private const int PmtuProbeAttempts = 3;
    // RFC 8899 re-probe cadence comes from PmtuReprobeInterval (default 5 min): a settled
    // path re-verifies its confirmed size, catching a mid-connection MTU shrink.
    private const long PmtuProbeMarker = 1L << 62;

    private readonly ulong _peerId;
    private readonly PinholeOptions _options;
    private readonly NodeIdentity? _identity; // long-term X25519 identity; null = plaintext node
    private readonly object _gate = new();
    // Hot path: every frame routes through Lookup, on the receive thread for arrivals and
    // the caller's thread for sends. A ConcurrentDictionary keeps those reads lock-free so
    // the two hot threads never ping-pong the old global lock's cache line. Mutations
    // (dial, incoming, close) are rare and individually atomic.
    private readonly ConcurrentDictionary<ulong, ConnState> _conns = new();
    private readonly Channel<ConnState>? _incoming;
    private readonly List<RelaySlot> _relays = new();
    private readonly Dictionary<Uri, IrohRelay> _irohRelays = new();
    private readonly RelayIdentity? _endpointIdentity; // Ed25519 endpoint key; null = random per-bind peer id only
    private readonly Action<IrohPath, ReadOnlyMemory<byte>>? _rawReceive;
    private readonly List<PinholeCandidate> _localCandidates = new(); // guarded by _gate
    private HashSet<IPEndPoint> _lastRelayedAddresses = new();       // relay-change detector, guarded by _gate
    private readonly List<IPEndPoint> _reflexive = new();             // guarded by _gate
    private IPEndPoint? _mappedEndpoint;                              // router-granted mapping (UPnP/PMP/PCP), guarded by _gate
    private IPEndPoint? _mappedTcpEndpoint;
    private NatHint _observedNatHint;                                 // derived from multi-server STUN observations, guarded by _gate
    private PortMappingService? _portMap;
    private PortMappingService? _tcpPortMap;
    private IPv6FirewallService? _ipv6Firewall;
    private InterfaceUdpTransport? _interfaceUdp;
    private int _interfaceNetworkChanged;
    private long _nextInterfaceRefresh;
    private int _ipv6NetworkChanged;
    private long _nextIPv6FirewallRefresh;
    private sealed record StunAttempt(byte[] Transaction, IPEndPoint Server, IUdpSocket Socket, TaskCompletionSource<StunBindingReply> Reply);
    private readonly ConcurrentDictionary<ulong, StunAttempt> _stunPending = new();
    private readonly CancellationTokenSource _shutdown = new();
    // Address-lookup providers (built-in rendezvous + application-supplied). Empty unless
    // configured: rediscovery is opt-in infrastructure, never a default network behavior.
    private readonly List<IPinholeLookupProvider> _lookup = [];
    // Replay/rollback guard for adopted records: highest sequence per peer. Bounded by
    // MaxCachedSequences; a cache that fills simply stops protecting new peers (their
    // records still verify by signature, expiry, and pin — the guard is hardening, not the
    // authentication boundary).
    private readonly ConcurrentDictionary<ulong, ulong> _recordSequence = new();
    private const int MaxCachedSequences = 1024;
    private static readonly TimeSpan PublishInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan PublishMaxBackoff = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RecordTtl = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan LookupBudget = TimeSpan.FromSeconds(3);
    private Task? _publishLoop; // one publisher for the whole node, dies with shutdown
    private int _publishing;          // single-flight guard for publish operations
    private int _publishKick;         // single-flight guard for event-triggered publishes
    private long _lastPublishTicks;   // rate limit for event-triggered publishes

    // Volatile: sends and the receive loop read it per frame without taking _gate. A rebind
    // swaps in a fresh socket; a sender briefly racing the swap gets the old socket and a
    // caught ObjectDisposedException — the same send-failure handling a dead path already
    // triggers, and rebinds are rare.
    private volatile IUdpSocket _udp = null!;
    private TcpTransport? _tcp;
    private long _recovering; // single-flight guard for recovery
    private volatile bool _disposed;
    private int _networkWatchHooked;
    private Task? _maintenance; // one scheduler for the whole node (path validation + STUN refresh)
    private long _nextStunRefreshTicks; // maintenance deadline; 0 = refresh disabled
    private long _nextRelayEnsureTicks;  // maintenance deadline for retrying dead TURN slots
    private int _relayEnsuring;          // single-flight guard for that retry
    private int _stunRefreshing; // single-flight guard for reflexive refreshes

    public NodeEngine(PinholeOptions options, RelayIdentity? rawIdentity = null,
        Action<IrohPath, ReadOnlyMemory<byte>>? rawReceive = null)
    {
        // The Ed25519 endpoint identity exists whenever the node has iroh relays (they
        // authenticate with it) or a persisted seed (which derives it stably). A persisted
        // seed therefore also stabilizes the peer ID — it is the hash of the endpoint key.
        byte[]? endpointSeed = EndpointIdentity.DeriveEndpointSeed(options.IdentityKeySeed);
        _rawReceive = rawReceive;
        if (rawIdentity is not null)
            _endpointIdentity = rawIdentity;
        else if (endpointSeed is not null || options.PublishIrohAddress || (options.IrohRelayUrls ?? options.ResolvedIrohRelays).Count > 0)
            _endpointIdentity = new RelayIdentity(endpointSeed);
        _peerId = _endpointIdentity?.PeerId ?? BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        _options = options;
        _maxConns = options.MaxConnectionsOverride ?? MaxConnections;
        _identity = options.Encryption != PinholeEncryption.Disabled ? new NodeIdentity(options.IdentityKeySeed) : null;
        _incoming = options.Listen ? Channel.CreateUnbounded<ConnState>() : null;
        if (options.RendezvousEndpoints is { Count: > 0 } || options.LookupProviders is { Count: > 0 })
        {
            List<IPinholeLookupProvider> providers = new(options.LookupProviders ?? []);
            if (options.RendezvousEndpoints is { Count: > 0 } endpoints)
                providers.Add(new RendezvousLookup(_peerId, endpoints));
            _lookup = providers;
        }
    }

    public ulong PeerId => _peerId;

    /// <summary>This node's long-term X25519 public key (32 bytes), embedded in v2 connection
    /// strings and used to authenticate every session's far end; null on plaintext nodes.</summary>
    public byte[]? StaticPublicKey => _identity?.PublicKey;

    /// <summary>This node's Ed25519 endpoint public key (32 bytes), embedded in v3 connection
    /// strings and used to sign its address records; null when neither a persisted identity
    /// seed nor iroh relays gave the node an endpoint identity.</summary>
    public byte[]? EndpointPublicKey => _endpointIdentity?.PublicKey;
    internal RelayIdentity? EndpointRelayIdentity => _endpointIdentity;

    public bool HasRelay
    {
        get
        {
            lock (_gate)
                return !_disposed && (_irohRelays.Values.Any(r => r.IsAlive)
                    || AliveRelayClientsNoLock().Any(c => c.RelayedAddress is not null));
        }
    }

    internal Channel<ConnState>? Incoming => _incoming;

    public void DisposeConnection(ConnState c) => _ = CloseAsync(c);

    private DatagramBuffer? CreateBuffer() =>
        _options.ReceiveBufferCapacity > 0 ? new DatagramBuffer(_options.ReceiveBufferCapacity) : null;

    public int LocalPort
    {
        get
        {
            lock (_gate)
            {
                return _udp.LocalEndPoint.Port;
            }
        }
    }

    private sealed record RelaySlot(TurnServerConfig Config)
    {
        public TurnClient? Client;
        public DateTimeOffset NextRetry = DateTimeOffset.MinValue;
        public TimeSpan Backoff = RelayRetryBackoff; // doubles per failure; success resets
    }

    // ------------------------------------------------------------------ bind

    public async Task BindAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            _udp = CreateSocket(_options.Bind);
        }

        if (_options.EnableTcpTransport && _identity is not null && _rawReceive is null && _options.UdpSocketFactory is null)
            _tcp = new TcpTransport(new IPEndPoint(_options.Bind?.Address ?? IPAddress.IPv6Any, LocalPort), OnTcpFrame, OnTcpClosed);

        StartRecvLoop();

        if (_options.EnableInterfaceCandidates && _options.EnableDirectUdp && _rawReceive is null
            && (_options.UdpSocketFactory is null || _options.InterfaceUdpSocketFactory is not null))
        {
            _interfaceUdp = new InterfaceUdpTransport(_options, TryProbeFromAsync, OnInterfaceFrame, OnInterfaceCandidatesChanged);
            RefreshInterfaceCandidates();
        }

        try
        {
            await Task.WhenAll(ProbeStunAllAsync(ct), EnsureRelaysAsync(ct), EnsureIrohRelaysAsync(ct)).WaitAsync(_options.BindProbeBudget, ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // Bind is best-effort: slow or dead infrastructure costs its candidates, not the node.
        }

        RefreshLocalCandidates();
        _ = PermitCatalogRelaysAsync(CancellationToken.None);

        // Signed address records: the bind-time RefreshLocalCandidates kick above publishes
        // once the first candidate set exists; this loop keeps it fresh on a jittered
        // heartbeat with backoff. Publishing needs a listening node with an endpoint
        // identity — a dial-only node has no address worth serving.
        if (_lookup.Count > 0 && _options.Listen && _endpointIdentity is not null)
        {
            _publishLoop = PublishLoopAsync(_shutdown.Token);
        }

        // Router port mapping (UPnP/PMP/PCP): entirely background, entirely best-effort.
        // A loopback bind can never be reached through a router, so it skips the chatter.
        bool bindIsLoopback = _options.Bind is { } bound
            && (bound.Address.Equals(IPAddress.Loopback) || bound.Address.Equals(IPAddress.IPv6Loopback));
        if (_options.EnablePortMapping && !bindIsLoopback)
        {
            _portMap = new PortMappingService(_options, OnPortMappingChanged);
            _portMap.Ensure(LocalPort);
            if (_tcp is not null)
            {
                _tcpPortMap = new PortMappingService(_options, OnTcpPortMappingChanged, ProtocolType.Tcp);
                if (_tcp.ListeningPort is { } tcpPort) _tcpPortMap.Ensure(tcpPort);
            }
            if (_options.EnableIPv6FirewallPinholes && _options.UdpSocketFactory is null && _rawReceive is null)
            {
                _ipv6Firewall = new IPv6FirewallService(_options, OnIPv6FirewallChanged);
                RefreshIPv6Firewall();
            }
        }

        if (_options.EnablePathValidation || _options.StunRefreshInterval > TimeSpan.Zero || _portMap is not null || _relays.Count > 0)
        {
            if (_options.StunRefreshInterval > TimeSpan.Zero)
            {
                _nextStunRefreshTicks = Environment.TickCount64 + (long)_options.StunRefreshInterval.TotalMilliseconds;
            }

            _nextRelayEnsureTicks = Environment.TickCount64 + (long)RelayRetryBackoff.TotalMilliseconds;
            _maintenance = MaintenanceLoopAsync(_shutdown.Token);
        }

        if (_options.EnableNetworkWatch && Interlocked.CompareExchange(ref _networkWatchHooked, 1, 0) == 0)
        {
            NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
        }
    }

    private void OnNetworkAddressChanged(object? sender, EventArgs e)
    {
        if (_disposed)
        {
            return;
        }

        Volatile.Write(ref _ipv6NetworkChanged, 1);
        Volatile.Write(ref _interfaceNetworkChanged, 1);

        // Interface churn fires several events per roam; collapse them into one recovery pass.
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(RecoverDebounce, _shutdown.Token).ConfigureAwait(false);
                await RecoverAsync(forceRebind: false, CancellationToken.None).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        });
    }

    private IUdpSocket CreateSocket(IPEndPoint? bind) =>
        _options.UdpSocketFactory is { } build ? build(bind) : SystemUdpSocket.Create(bind);

    // ------------------------------------------------------------------ local candidates

    public IReadOnlyList<PinholeCandidate> LocalCandidatesSnapshot()
    {
        PinholeCandidate[] snapshot;
        bool changed;
        lock (_gate)
        {
            changed = SynchronizeMappedLeasesNoLock();
            if (changed || _interfaceUdp is not null) RefreshLocalCandidatesNoLock();
            snapshot = CandidateSelection.Published(_localCandidates, _mappedEndpoint, _mappedTcpEndpoint, InterfaceCandidatesSnapshot());
        }
        if (changed) PublishAddressRecordSoon();
        return snapshot;
    }

    public IReadOnlyList<IPEndPoint> ReflexiveSnapshot()
    {
        lock (_gate)
        {
            return _reflexive.ToArray();
        }
    }

    /// <summary>The router-granted external endpoint (UPnP/NAT-PMP/PCP), or null. This is
    /// already included in the advertised candidates; exposed for diagnostics and tests.</summary>
    public IPEndPoint? MappedEndpointSnapshot(bool tcp = false)
    {
        return (tcp ? _tcpPortMap : _portMap)?.Current;
    }

    internal int? TcpListeningPort => _tcp?.ListeningPort;

    internal IReadOnlyList<PinholeInterfaceCandidates> InterfaceCandidatesSnapshot() => _interfaceUdp?.Snapshot() ?? [];

    private void RefreshInterfaceCandidates(bool invalidate = false)
    {
        if (_disposed || _interfaceUdp is null) return;
        bool changed = Interlocked.Exchange(ref _interfaceNetworkChanged, 0) != 0;
        _interfaceUdp.Refresh(invalidate || changed);
        _nextInterfaceRefresh = Environment.TickCount64 + 30_000;
    }

    private void OnInterfaceCandidatesChanged()
    {
        if (_disposed) return;
        lock (_gate) RefreshLocalCandidatesNoLock();
        foreach (ConnState c in ConnectionsSnapshot())
            if (c.DirectUdpSocket is { } socket && _interfaceUdp?.Contains(socket) != true) NotifyPathSuspect(c);
        PublishAddressRecordSoon();
        ReannounceAndRepunch();
    }

    internal IReadOnlyList<IPEndPoint> IPv6FirewallSnapshot(bool tcp = false) =>
        _ipv6Firewall?.Snapshot(tcp ? ProtocolType.Tcp : ProtocolType.Udp) ?? [];

    private void RefreshIPv6Firewall(bool invalidate = false)
    {
        if (_disposed || _ipv6Firewall is null) return;
        bool changed = Interlocked.Exchange(ref _ipv6NetworkChanged, 0) != 0;
        _ipv6Firewall.Refresh(IPv6FirewallService.Gather(_options.Bind), _options.EnableDirectUdp ? LocalPort : 0,
            _tcp?.ListeningPort, invalidate || changed);
        _nextIPv6FirewallRefresh = Environment.TickCount64 + 30_000;
    }

    private void OnIPv6FirewallChanged()
    {
        if (_disposed) return;
        PublishAddressRecordSoon();
        ReannounceAndRepunch(); // a new permission may make an already advertised host reachable
    }

    /// <summary>NAT classification derived from multi-server STUN observations: servers
    /// that observe divergent mappings mean per-destination (symmetric) NAT. Manual hints
    /// set through <see cref="PinholeNode.SetNatHint"/> always win over this observation.</summary>
    public NatHint ObservedNatHint
    {
        get
        {
            lock (_gate)
            {
                return _observedNatHint;
            }
        }
    }

    /// <summary>Port-mapping callback: swap the mapped candidate and gently re-announce to
    /// every peer — the working paths keep working and only learn the new candidate.</summary>
    private void OnPortMappingChanged(IPEndPoint? mapped) => OnPortMappingChanged(mapped, tcp: false);
    private void OnTcpPortMappingChanged(IPEndPoint? mapped) => OnPortMappingChanged(mapped, tcp: true);

    private void OnPortMappingChanged(IPEndPoint? mapped, bool tcp)
    {
        if (_disposed) return;
        lock (_gate)
        {
            // Publication is serialized outside the lease lock. Re-read the desired
            // state after taking the node lock so a delayed notification cannot restore
            // an expired or invalidated endpoint.
            mapped = (tcp ? _tcpPortMap : _portMap)?.Current;
            if (tcp) _mappedTcpEndpoint = mapped; else _mappedEndpoint = mapped;
            RefreshLocalCandidatesNoLock();
        }

        PublishAddressRecordSoon();
        foreach (ConnState c in ConnectionsSnapshot())
        {
            if (c.State != PinholeConnectionState.Closed)
            {
                AnnounceTo(c); // withdrawal is just as important as an added candidate
            }
        }
    }

    private void RefreshLocalCandidates()
    {
        lock (_gate)
        {
            RefreshLocalCandidatesNoLock();
        }

        RefreshIPv6Firewall();

        // Every path that changes reachability funnels through here — bind, rebind, STUN
        // mapping moves, router port-mapping changes — so this is the one hook that
        // republishes the signed address record after a roam or restart.
        PublishAddressRecordSoon();
    }

    /// <summary>Caller must hold <see cref="_gate"/>. Split out so the STUN refresh can
    /// swap the reflexive set and rebuild the advertised candidates as ONE critical
    /// section — otherwise an observer can see the new <c>PublicEndpoints</c> while the
    /// connection string still carries the old mapping.</summary>
    private void RefreshLocalCandidatesNoLock()
    {
        SynchronizeMappedLeasesNoLock();
        int port = LocalPort;
        _localCandidates.Clear();
        _localCandidates.Add(new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, port)));
        List<IPEndPoint> hosts = HostEndpoints(port, _options.AdvertiseLinkLocal);
        foreach (IPEndPoint ep in hosts.Where(ep => !ep.Address.IsIPv6LinkLocal))
        {
            _localCandidates.Add(new PinholeCandidate(CandidateKind.Direct, ep));
        }

        foreach (IPEndPoint ep in _reflexive)
        {
            _localCandidates.Add(new PinholeCandidate(CandidateKind.Reflexive, ep));
        }

        foreach (PinholeInterfaceCandidates source in InterfaceCandidatesSnapshot())
        {
            if (!_localCandidates.Any(c => c.Kind == CandidateKind.Direct && c.Address.Equals(source.LocalEndpoint)))
                _localCandidates.Add(new(CandidateKind.Direct, source.LocalEndpoint));
            foreach (IPEndPoint external in source.ReflexiveEndpoints)
                if (!_localCandidates.Any(c => c.Kind == CandidateKind.Reflexive && c.Address.Equals(external)))
                    _localCandidates.Add(new(CandidateKind.Reflexive, external));
        }

        // A router-granted mapping is advertised as a reflexive candidate: it is an address
        // the world can use to reach this socket, exactly like a STUN observation, and the
        // peer needs no new wire semantics to punch it.
        if (_mappedEndpoint is { } mapped && !_localCandidates.Any(c => c.Kind == CandidateKind.Reflexive && c.Address.Equals(mapped)))
        {
            _localCandidates.Add(new PinholeCandidate(CandidateKind.Reflexive, mapped));
        }

        // Keep the existing candidate-origin schema. New peers negotiate a framed TCP
        // sidecar at host/reflexive tuples; old peers can still try UDP and then fallback.
        if (_mappedTcpEndpoint is { } tcpMapped && !_localCandidates.Any(c => c.Kind == CandidateKind.Reflexive && c.Address.Equals(tcpMapped)))
            _localCandidates.Add(new PinholeCandidate(CandidateKind.Reflexive, tcpMapped));

        foreach (TurnClient client in AliveRelayClientsNoLock())
        {
            if (client.RelayedAddress is { } relayed)
            {
                _localCandidates.Add(new PinholeCandidate(CandidateKind.Relay, relayed, client.Server, client.Username, client.Credential));
            }
        }

        foreach (IPEndPoint ep in hosts.Where(ep => ep.Address.IsIPv6LinkLocal))
        {
            _localCandidates.Add(new PinholeCandidate(CandidateKind.Direct, ep));
        }

        if (_endpointIdentity is not null)
        {
            foreach (IrohRelay relay in _irohRelays.Values.Where(r => r.IsAlive))
                _localCandidates.Add(new PinholeCandidate(CandidateKind.IrohRelay,
                    new IPEndPoint(IPAddress.None, 0), RelayUrl: relay.Url, RelayKey: _endpointIdentity.PublicKey));
        }
    }

    private bool SynchronizeMappedLeasesNoLock()
    {
        IPEndPoint? udp = _portMap?.Current, tcp = _tcpPortMap?.Current;
        bool changed = !Equals(_mappedEndpoint, udp) || !Equals(_mappedTcpEndpoint, tcp);
        _mappedEndpoint = udp;
        _mappedTcpEndpoint = tcp;
        return changed;
    }

    private static List<IPEndPoint> HostEndpoints(int port, bool advertiseLinkLocal)
    {
        var seen = new HashSet<IPAddress>();
        var list = new List<IPEndPoint>();
        // Link-locals are collected separately and appended last when enabled:
        // they are a fallback for access networks that isolate IPv4 between wireless and
        // wired clients but bridge IPv6. Only radio/ethernet links qualify (tunnels and
        // bridges on macOS/Windows would flood the candidate list), at most two ride along,
        // wireless first. Scope stays local — peers re-scope onto their own outgoing
        // interface when sending, so the address rides the wire bare.
        var linkLocal = new List<(int Rank, IPEndPoint EndPoint)>();
        try
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }

                foreach (UnicastIPAddressInformation addr in nic.GetIPProperties().UnicastAddresses)
                {
                    IPAddress ip = addr.Address;
                    if (ip.IsIPv6Teredo || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Loopback))
                    {
                        continue;
                    }

                    if (ip.IsIPv6LinkLocal)
                    {
                        if (advertiseLinkLocal && nic.NetworkInterfaceType is NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ethernet)
                        {
                            linkLocal.Add((nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? 0 : 1, new IPEndPoint(ip, port)));
                        }
                        continue;
                    }

                    if (seen.Add(ip))
                    {
                        list.Add(new IPEndPoint(ip, port));
                    }

                    if (list.Count >= 8)
                    {
                        return list;
                    }
                }
            }
        }
        catch (NetworkInformationException)
        {
        }

        if (advertiseLinkLocal)
        {
            foreach (IPEndPoint ep in linkLocal.OrderBy(t => t.Rank).Take(2).Select(t => t.EndPoint))
            {
                if (list.Count >= 8) break;
                if (seen.Add(ep.Address))
                {
                    list.Add(ep);
                }
            }
        }

        return list;
    }

    // ------------------------------------------------------------------ STUN

    public Task<IPEndPoint> ProbeStunAsync(IPEndPoint server, CancellationToken ct = default) => ProbeStunFromAsync(_udp, server, ct);

    internal async Task<IPEndPoint> ProbeStunFromAsync(IUdpSocket source, IPEndPoint server, CancellationToken ct) =>
        (await ProbeBindingFromAsync(source, server, server, 0, ct).ConfigureAwait(false)).Mapped;

    internal IPEndPoint DiagnosticLocalEndpoint => _udp.LocalEndPoint;
    internal Task<StunBindingReply> ProbeBindingAsync(IPEndPoint server, IPEndPoint expectedReply, uint change, CancellationToken ct) =>
        ProbeBindingFromAsync(_udp, server, expectedReply, change, ct);

    private async Task<StunBindingReply> ProbeBindingFromAsync(IUdpSocket source, IPEndPoint server, IPEndPoint expectedReply, uint change, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        byte[] req = StunBindingMessage.Request(change);
        ulong key = BinaryPrimitives.ReadUInt64BigEndian(req.AsSpan(8));
        var tcs = new TaskCompletionSource<StunBindingReply>(TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = new StunAttempt(req.AsSpan(8, 12).ToArray(), new IPEndPoint(expectedReply.Address, expectedReply.Port), source, tcs);
        if (!_stunPending.TryAdd(key, pending)) throw new InvalidOperationException("STUN transaction collision");
        try
        {
            TrackPredictionContact(source, server);
            source.SendTo(req, ToWire(server));
            // Two expiry sources on one WaitAsync race each other: on a stalled runner both
            // fire before either is observed and the timeout can mask the caller's token.
            // The probe's own deadline is a linked source instead, translated back — so an
            // externally canceled probe always surfaces as cancellation, never as timeout.
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(ProbeTimeout);
            try
            {
                return await tcs.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new TimeoutException($"STUN server {server} did not answer within {ProbeTimeout.TotalSeconds:0.#}s");
            }
        }
        finally
        {
            _stunPending.TryRemove(key, out _);
        }
    }

    /// <summary>Probes every configured server in parallel; slow or dead servers cost
    /// nothing because the whole batch is bounded by the bind budget.</summary>
    public async Task ProbeStunAllAsync(CancellationToken ct)
    {
        IPEndPoint[] observed = await ProbeStunObservedAsync(ct).ConfigureAwait(false);
        ObserveNatHint(observed);
        foreach (IPEndPoint ep in observed)
        {
            lock (_gate)
            {
                if (!_reflexive.Contains(ep))
                {
                    _reflexive.Add(ep);
                }
            }
        }

        RefreshLocalCandidates();
    }

    /// <summary>Classifies the NAT from the raw multi-server observations: two servers
    /// seeing the same mapping means endpoint-independent (cone) mapping, divergent ones
    /// mean per-destination (symmetric), which changes punch pacing. Address families are
    /// compared separately: different IPv4 and IPv6 endpoints are normal on dual-stack.
    /// One observation can never distinguish the behaviors, and a pass where too few
    /// servers answered never clears an earlier, better-informed classification.</summary>
    private void ObserveNatHint(IPEndPoint[] observedPerServer)
    {
        if (observedPerServer.Length < 2)
        {
            return;
        }

        NatType classification = NatDetector.Classify(observedPerServer);
        if (classification == NatType.Unknown) return;
        NatHint seen = classification == NatType.Symmetric ? NatHint.Symmetric : NatHint.Cone;
        lock (_gate)
        {
            _observedNatHint = seen;
        }
    }

    /// <summary>The raw observation behind a probe pass: one task per configured server, the
    /// whole batch bounded by the bind budget, and the endpoints that answered. Late probes
    /// (past the budget) are simply not part of the result.</summary>
    private async Task<IPEndPoint[]> ProbeStunObservedAsync(CancellationToken ct)
    {
        IReadOnlyList<IPEndPoint> servers = BasicStunServers();
        if (servers.Count == 0)
        {
            return Array.Empty<IPEndPoint>();
        }

        Task<IPEndPoint?>[] probes = servers.Select(s => TryProbe(s, ct)).ToArray();
        try
        {
            await Task.WhenAll(probes).WaitAsync(_options.BindProbeBudget, ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
        }

        return probes
            .Where(p => p.IsCompletedSuccessfully && p.Result is not null)
            .Select(p => p.Result!)
            .ToArray();
    }

    private async Task<IPEndPoint?> TryProbe(IPEndPoint server, CancellationToken ct)
        => await TryProbeFromAsync(_udp, server, ct).ConfigureAwait(false);

    private async Task<IPEndPoint?> TryProbeFromAsync(IUdpSocket source, IPEndPoint server, CancellationToken ct)
    {
        try
        {
            return await ProbeStunFromAsync(source, server, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or TimeoutException or ObjectDisposedException)
        {
            return null;
        }
    }

    private IReadOnlyList<IPEndPoint> ResolvedStun() => _options.StunServers ?? _options.ResolvedStun;

    private StunAttempt? MatchingStun(byte[] buf, int n, IUdpSocket socket, SocketAddress remote)
    {
        if (n < 20 || BinaryPrimitives.ReadUInt16BigEndian(buf) != 0x0101
            || BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(4)) != StunCookie
            || n != 20 + BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(2))) return null;
        ulong key = BinaryPrimitives.ReadUInt64BigEndian(buf.AsSpan(8));
        return _stunPending.TryGetValue(key, out StunAttempt? pending) && ReferenceEquals(pending.Socket, socket)
            && buf.AsSpan(8, 12).SequenceEqual(pending.Transaction) && ToEndpoint(remote).Equals(pending.Server) ? pending : null;
    }

    private void OnStunResponse(byte[] buf, int n, IUdpSocket socket, SocketAddress remote)
    {
        if (MatchingStun(buf, n, socket, remote) is not { } pending)
        {
            return;
        }

        if (StunBindingMessage.TryRead(buf.AsSpan(0, n), pending.Server, out StunBindingReply? reply))
            pending.Reply.TrySetResult(reply!);
    }

    // ------------------------------------------------------------------ relays

    private IrohRelay? IrohRelayFor(Uri url)
    {
        if (_endpointIdentity is null || _disposed) return null;
        IrohRelay relay;
        lock (_gate)
        {
            if (_irohRelays.TryGetValue(url, out relay!)) return relay;
            if (_irohRelays.Count >= ConnectionString.MaxCandidates) return null;
            relay = new IrohRelay(url, _endpointIdentity, _options.IrohWebSocketFactory);
            relay.Received += HandleIrohData;
            relay.Changed += IrohChanged;
            _irohRelays.Add(url, relay);
        }
        _ = relay.StartAsync(_shutdown.Token);
        return relay;
    }

    private async Task EnsureIrohRelaysAsync(CancellationToken ct)
    {
        var clients = (_options.IrohRelayUrls ?? _options.ResolvedIrohRelays)
            .Select(IrohRelayFor).OfType<IrohRelay>().ToArray();
        if (clients.Length > 0)
            await Task.WhenAny(clients.Select(c => c.StartAsync(ct))).ConfigureAwait(false);
    }

    internal async Task PrepareRawRelayAsync(Uri url, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        IrohRelay relay = IrohRelayFor(url)
            ?? throw new InvalidOperationException("the relay connection limit was reached");
        await relay.StartAsync(ct).ConfigureAwait(false);
        while (!relay.IsAlive)
            await Task.Delay(TimeSpan.FromMilliseconds(100), ct).ConfigureAwait(false);
    }

    internal void SendRaw(IrohPath path, ReadOnlySpan<byte> payload)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (path.DirectAddress is { } direct)
        {
            IPEndPoint target = direct.AddressFamily == AddressFamily.InterNetwork
                ? new IPEndPoint(direct.Address.MapToIPv6(), direct.Port) : direct;
            _udp.SendTo(payload, target.Serialize());
        }
        else if (path.RelayUrl is { } url && path.Key is { } key)
        {
            if (IrohRelayFor(url)?.Send(key, payload) != true)
                throw new IOException("the iroh relay is disconnected or its send queue is full");
        }
        else throw new ArgumentException("invalid iroh path", nameof(path));
    }

    private void IrohChanged(IrohRelay relay)
    {
        if (_disposed) return;
        RefreshLocalCandidates();
        foreach (ConnState c in ConnectionsSnapshot())
        {
            try
            {
                if (c.State == PinholeConnectionState.Closed) continue;
                if (!relay.IsAlive && c.Path == PathKind.Relay && c.Iroh == relay)
                    NotifyPathSuspect(c);
                if (relay.IsAlive)
                {
                    AnnounceTo(c);
                    PinholeCandidate[] targets;
                    lock (_gate) targets = c.PeerCandidates.ToArray();
                    foreach (PinholeCandidate target in targets.Where(t => t.Kind == CandidateKind.IrohRelay && t.RelayUrl == relay.Url))
                        SendViaIroh(c.PuncFrame, target);
                    KickPunch(c);
                }
            }
            catch (Exception)
            {
                // A throwing state-change handler must not stop the shared relay or its other peers.
            }
        }
    }

    private void HandleIrohData(IrohRelay relay, byte[] source, byte[] frame)
    {
        if (_rawReceive is not null)
        {
            if (!_disposed)
            {
                try { _rawReceive(IrohPath.Relay(relay.Url, Convert.ToHexString(source).ToLowerInvariant()), frame); }
                catch (FormatException) { } // invalid relay source keys cost only that datagram
            }
            return;
        }
        if (_disposed || frame.Length < HeaderSize + 4
            || frame[0] is < (byte)FrameType.Punc or > (byte)FrameType.Predict) return;
        ulong sender = BinaryPrimitives.ReadUInt64LittleEndian(SHA256.HashData(source));
        if (sender != BinaryPrimitives.ReadUInt64LittleEndian(frame.AsSpan(1))) return;
        try { Dispatch(frame, new Arrival(relay, source)); }
        catch (Exception)
        {
            // Match the UDP receive loop: one malformed frame or throwing handler costs one datagram.
        }
    }

    private void SendViaIroh(ReadOnlySpan<byte> frame, PinholeCandidate candidate)
    {
        if (candidate.RelayUrl is { } url && candidate.RelayKey is { Length: 32 } key)
            IrohRelayFor(url)?.Send(key, frame);
    }

    // Relay client access MUST go through materialized snapshots: an iterator holding
    // _gate across a yield would keep the lock alive over the caller's awaits (permission
    // round trips), deadlocking the TurnClient receive thread that needs _gate to dispatch.
    private List<TurnClient> AliveRelayClients()
    {
        lock (_gate)
        {
            return AliveRelayClientsNoLock();
        }
    }

    private List<TurnClient> AliveRelayClientsNoLock()
    {
        var list = new List<TurnClient>(_relays.Count);
        foreach (RelaySlot slot in _relays)
        {
            if (slot.Client is { IsAlive: true } client)
            {
                list.Add(client);
            }
        }

        return list;
    }

    private async Task EnsureRelaysAsync(CancellationToken ct)
    {
        List<RelaySlot> cold;
        lock (_gate)
        {
            IReadOnlyList<TurnServerConfig> configs = _options.Relays ?? _options.ResolvedRelays;
            foreach (TurnServerConfig config in configs)
            {
                if (_relays.All(r => r.Config != config))
                {
                    _relays.Add(new RelaySlot(config));
                }
            }

            cold = _relays.Where(r => r.Client is not { IsAlive: true } && r.NextRetry <= DateTimeOffset.UtcNow).ToList();
        }

        if (cold.Count == 0)
        {
            return;
        }

        await Task.WhenAll(cold.Select(slot => AllocateSlotAsync(slot, ct))).ConfigureAwait(false);
        RefreshLocalCandidates();
        ReannounceIfRelayAddressesChanged();
    }

    /// <summary>A relay (re)allocation changes this node's relayed addresses. Connected peers
    /// still hold the old ones, and a relayed-only session's only route is through them — so
    /// a changed set must be blasted to every peer immediately. This closes the old "TURN
    /// restart requires a fresh ticket" gap: the peer's announce handler adopts our new
    /// relay candidates and re-punches without any out-of-band action.</summary>
    private void ReannounceIfRelayAddressesChanged()
    {
        HashSet<IPEndPoint> current = new();
        lock (_gate)
        {
            foreach (TurnClient client in AliveRelayClientsNoLock())
            {
                if (client.RelayedAddress is { } relayed)
                {
                    current.Add(relayed);
                }
            }

            if (current.SetEquals(_lastRelayedAddresses))
            {
                return;
            }

            _lastRelayedAddresses = current;
        }

        foreach (ConnState c in ConnectionsSnapshot())
        {
            if (c.State != PinholeConnectionState.Closed)
            {
                AnnounceTo(c, blast: true);
            }
        }
    }

    private async Task AllocateSlotAsync(RelaySlot slot, CancellationToken ct)
    {
        try
        {
            TurnClient client = await TurnClient.AllocateAsync(slot.Config.Server, slot.Config.Username, slot.Config.Credential, ct).ConfigureAwait(false);
            client.Received += HandleRelayData;
            lock (_gate)
            {
                slot.Client = client;
                slot.Backoff = RelayRetryBackoff;
            }

            // Receive-side bootstrap for strict TURN servers: an allocation only receives
            // from IPs it permitted, and a peer relaying through the same server arrives
            // from that server's IP. Permitting our own configured relay servers (and the
            // free catalog, in PermitCatalogRelaysAsync) is what lets two strangers behind
            // one shared relay find each other without any out-of-band permission exchange.
            foreach (IPEndPoint own in (_options.Relays ?? _options.ResolvedRelays).Select(r => r.Server).Append(slot.Config.Server))
            {
                try
                {
                    await client.CreatePermissionAsync(own.Address, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is SocketException or OperationCanceledException or InvalidOperationException or TimeoutException)
                {
                }
            }
        }
        catch (Exception)
        {
            // Servers see every client at once when an allocation expires or a relay restarts;
            // jitter spreads that herd without meaningfully delaying anyone. Each further
            // failure doubles the wait up to RelayMaxBackoff — a down or rate-limiting relay
            // costs one datagram per ladder step, never a reconnect storm.
            lock (_gate)
            {
                slot.NextRetry = DateTimeOffset.UtcNow + Jitter(slot.Backoff);
                slot.Backoff = TimeSpan.FromTicks(Math.Min(slot.Backoff.Ticks * 2, RelayMaxBackoff.Ticks));
            }
        }
    }

    private static TimeSpan Jitter(TimeSpan delay) =>
        delay * (1 + (RandomNumberGenerator.GetInt32(0, 41) - 20) / 100.0); // ±20%

    /// <summary>A stranger's relayed traffic can only be delivered to our allocation if we
    /// permit its source IP. Strangers dial through the free relays, so pre-opening the
    /// catalog's server IPs makes "connect from a connection string alone" work. With no
    /// TURN relay configured there is no allocation to permit anything on, and the catalog
    /// is never looked up.</summary>
    private async Task PermitCatalogRelaysAsync(CancellationToken ct)
    {
        if ((_options.Relays ?? _options.ResolvedRelays).Count == 0)
        {
            return;
        }

        IPEndPoint[] servers = await (_options.RelayCatalog ?? Providers.Resolver.FreeRelayServersAsync)(ct).ConfigureAwait(false);
        foreach (TurnClient client in AliveRelayClients())
        {
            foreach (IPEndPoint server in servers)
            {
                try
                {
                    await client.CreatePermissionAsync(server.Address, ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is SocketException or OperationCanceledException or InvalidOperationException or TimeoutException)
                {
                }
            }
        }
    }

    /// <summary>Permits a learned peer's TURN server (and relayed address) on every alive
    /// allocation of ours — announced relay candidates are the only in-band way the accept
    /// side learns where a dialer's relayed traffic will come from.</summary>
    private async Task PermitPeerRelayServerAsync(PinholeCandidate relay)
    {
        foreach (TurnClient client in AliveRelayClients())
        {
            foreach (IPAddress? ip in new[] { relay.RelayServer?.Address, relay.Address.Address })
            {
                if (ip is null)
                {
                    continue;
                }

                try
                {
                    await client.CreatePermissionAsync(ip, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is SocketException or OperationCanceledException or InvalidOperationException or TimeoutException)
                {
                }
            }
        }
    }

    private void HandleRelayData(IPEndPoint from, byte[] data)
    {
        // Length gate only: TurnClient already guards its handlers, and Dispatch's own
        // guarantees make a malformed frame cost nothing.
        if (data.Length < HeaderSize)
        {
            return;
        }

        Dispatch(data, new Arrival(from));
    }

    // ------------------------------------------------------------------ connections

    public ConnState? Lookup(ulong peerId)
    {
        return _conns.TryGetValue(peerId, out ConnState? c) ? c : null;
    }

    public IReadOnlyList<ConnState> ConnectionsSnapshot()
    {
        return _conns.Values.ToArray();
    }

    /// <summary>Monitoring/test accessor: the peer's latest advertised candidates, copied
    /// under the engine gate (the live list is rebuilt by every announce).</summary>
    internal PinholeCandidate[] PeerCandidatesSnapshot(ulong peerId)
    {
        lock (_gate)
        {
            return _conns.TryGetValue(peerId, out ConnState? c) ? c.PeerCandidates.ToArray() : [];
        }
    }

    // ------------------------------------------------------------------ signed address records

    /// <summary>Keeps the node's signed address record fresh at every lookup provider:
    /// publish, wait one interval (plus jitter), repeat. A publish nobody acknowledges
    /// doubles the wait up to <see cref="PublishMaxBackoff"/>; the first success resets it —
    /// bounded provider access even when every provider is down.</summary>
    private async Task PublishLoopAsync(CancellationToken ct)
    {
        TimeSpan backoff = PublishInterval;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                bool anyAlive = await PublishAddressRecordAsync(ct).ConfigureAwait(false);
                if (anyAlive)
                {
                    backoff = PublishInterval;
                }
                else
                {
                    TimeSpan doubled = TimeSpan.FromTicks(backoff.Ticks * 2);
                    backoff = doubled < PublishMaxBackoff ? doubled : PublishMaxBackoff;
                }
                int jitterMs = Random.Shared.Next(0, 2000);
                await Task.Delay(backoff + TimeSpan.FromMilliseconds(jitterMs), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>One signed record of the node's current direct/reflexive reachability,
    /// delivered to every provider. Single-flight: a loop heartbeat and an event kick
    /// racing each other collapse into one datagram burst.</summary>
    private async Task<bool> PublishAddressRecordAsync(CancellationToken ct)
    {
        if (_endpointIdentity is null || _lookup.Count == 0 || _disposed)
        {
            return false;
        }

        if (Interlocked.Exchange(ref _publishing, 1) != 0)
        {
            return true; // a publish in flight counts as alive
        }

        try
        {
            byte[]? wire = BuildSignedRecord();
            if (wire is null)
            {
                return false;
            }

            Task<bool>[] sends = _lookup.Select(p => SafePublishAsync(p, wire, ct)).ToArray();
            bool[] results = await Task.WhenAll(sends).ConfigureAwait(false);
            Volatile.Write(ref _lastPublishTicks, Environment.TickCount64);
            return results.Any(ok => ok);
        }
        finally
        {
            Volatile.Write(ref _publishing, 0);
        }
    }

    /// <summary>Event-triggered publish (route change, rebind, port-mapping change): debounced,
    /// rate-limited to one burst per five seconds so candidate churn never becomes a
    /// provider flood. The heartbeat loop is separate and unaffected.</summary>
    private void PublishAddressRecordSoon()
    {
        if (_lookup.Count == 0 || _endpointIdentity is null || !_options.Listen || _disposed)
        {
            return;
        }

        if (Environment.TickCount64 - Volatile.Read(ref _lastPublishTicks) < 5000)
        {
            return;
        }

        if (Interlocked.Exchange(ref _publishKick, 1) != 0)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(250, _shutdown.Token).ConfigureAwait(false); // collapse event bursts
                await PublishAddressRecordAsync(_shutdown.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException or TimeoutException)
            {
                // Publishing is best-effort; the heartbeat loop retries with backoff.
            }
            finally
            {
                Volatile.Write(ref _publishKick, 0);
            }
        });
    }

    private byte[]? BuildSignedRecord()
    {
        List<IPEndPoint> endpoints = new(AddressRecord.MaxEndpoints);
        List<IPEndPoint> relayed = new(AddressRecord.MaxRelayedEndpoints);
        HashSet<IPEndPoint> seen = new();
        foreach (PinholeCandidate candidate in LocalCandidatesSnapshot())
        {
            if (candidate.Kind is not (CandidateKind.Direct or CandidateKind.Reflexive))
            {
                continue;
            }

            if (seen.Add(candidate.Address) && endpoints.Count < AddressRecord.MaxEndpoints)
            {
                endpoints.Add(candidate.Address);
            }
        }

        // Relayed addresses go in as bare endpoints — the address a peer's own allocation
        // on the same server may send at. Credentials never do: a record is public, and a
        // resolver only adopts relayed endpoints on servers it is itself configured to use.
        foreach (TurnClient client in AliveRelayClients())
        {
            if (client.RelayedAddress is { } address && seen.Add(address) && relayed.Count < AddressRecord.MaxRelayedEndpoints)
            {
                relayed.Add(address);
            }
        }

        if (endpoints.Count == 0 && relayed.Count == 0)
        {
            return null;
        }

        return new AddressRecord
        {
            PeerId = _peerId,
            EndpointKey = _endpointIdentity!.PublicKey,
            Sequence = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            ExpiresAtUtc = DateTimeOffset.UtcNow.Add(RecordTtl),
            Endpoints = endpoints,
            RelayedEndpoints = relayed,
        }.EncodeSigned(_endpointIdentity);
    }

    private static async Task<bool> SafePublishAsync(IPinholeLookupProvider provider, byte[] wire, CancellationToken ct)
    {
        try
        {
            await provider.PublishAsync(wire, ct).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return false; // one dead provider never blocks the others or the caller
        }
    }

    /// <summary>Races every lookup provider for the peer's current record and returns the
    /// first one that verifies against the pinned endpoint key — a lying or stale provider
    /// result is simply not first-verified. The overall budget bounds provider access.</summary>
    private async Task<AddressRecord?> ResolveVerifiedRecordAsync(ulong peerId, byte[] pinnedKey, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, _shutdown.Token);
        deadline.CancelAfter(LookupBudget);
        List<Task<byte[]?>> pending = _lookup.Select(p => SafeResolveAsync(p, peerId, deadline.Token)).ToList();
        try
        {
            while (pending.Count > 0)
            {
                Task<byte[]?> done = await Task.WhenAny(pending).ConfigureAwait(false);
                pending.Remove(done);
                if (done.IsCompletedSuccessfully
                    && done.Result is { Length: > 0 } wire
                    && AddressRecord.TryParseVerified(wire, peerId, pinnedKey, DateTimeOffset.UtcNow, out AddressRecord? record)
                    && record is not null)
                {
                    return record;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }

        return null;
    }

    private static async Task<byte[]?> SafeResolveAsync(IPinholeLookupProvider provider, ulong peerId, CancellationToken ct)
    {
        try
        {
            return await provider.ResolveAsync(peerId, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null; // providers are availability dependencies, never error paths
        }
    }

    /// <summary>Adopts a verified record's endpoints into a live dial's candidate list. The
    /// record already passed signature, pin, and expiry checks; the per-peer sequence cache
    /// adds rollback protection — a record strictly older than the newest adopted for the
    /// peer is a rollback, while re-adopting the same sequence is an idempotent retry (a
    /// redial inside one publish interval still finds its record useful).</summary>
    internal bool AcceptRecordSequence(ulong peerId, ulong sequence)
    {
        if (_recordSequence.TryGetValue(peerId, out ulong seen) && sequence < seen)
        {
            return false;
        }

        if (_recordSequence.Count < MaxCachedSequences || _recordSequence.ContainsKey(peerId))
        {
            _recordSequence[peerId] = sequence;
        }

        return true;
    }

    /// <summary>Runs beside a dial: while the punch loop races the ticket's own (possibly
    /// dead) candidates, this asks the lookup providers where the peer is now and, when a
    /// record verifies against the ticket's pinned endpoint key, merges its fresh endpoints
    /// into the punch. Best-effort by construction — no result simply leaves the dial on its
    /// original candidates.</summary>
    private async Task ResolveViaLookupAsync(ConnState c, byte[] pinnedKey, CancellationToken ct)
    {
        try
        {
            AddressRecord? record = await ResolveVerifiedRecordAsync(c.PeerId, pinnedKey, ct).ConfigureAwait(false);
            if (record is null || !AcceptRecordSequence(c.PeerId, record.Sequence))
            {
                return;
            }

            bool added = false;
            lock (_gate)
            {
                if (c.State is PinholeConnectionState.Dead or PinholeConnectionState.Closed)
                {
                    return;
                }

                HashSet<IPEndPoint> known = new(c.PeerCandidates.Select(x => x.Address));
                foreach (IPEndPoint ep in record.Endpoints)
                {
                    if (known.Add(ep))
                    {
                        c.PeerCandidates.Add(new PinholeCandidate(CandidateKind.Direct, ep));
                        added = true;
                    }
                }

                // Relayed endpoints are adopted only where we run an allocation ourselves
                // (matched by server IP): our own credentials for that server apply, and
                // sending at the peer's relayed address through it needs nothing else.
                foreach (IPEndPoint relayed in record.RelayedEndpoints)
                {
                    TurnServerConfig? config = (_options.Relays ?? _options.ResolvedRelays)
                        .FirstOrDefault(r => r.Server.Address.Equals(relayed.Address));
                    if (config is null || !known.Add(relayed))
                    {
                        continue;
                    }

                    c.PeerCandidates.Add(new PinholeCandidate(
                        CandidateKind.Relay, relayed, config.Server, config.Username, config.Credential));
                    added = true;
                }
            }

            if (added)
            {
                KickPunch(c);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException or FormatException)
        {
        }
    }

    public ConnState ConnectAsync(ConnectionString cs, CancellationToken ct)
    {
        var c = new ConnState
        {
            PeerId = cs.PeerId,
            Token = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)),
            SymmetricHint = cs.NatHint == NatHint.Symmetric,
            AwaitInitialCandidateExchange = _options.RelaySignalingOnly
                && cs.Candidates.Any(candidate => candidate.Kind is CandidateKind.Relay or CandidateKind.IrohRelay),
            // Crypto is attempted exactly when the string vouches for a static key: a v2
            // string's publisher speaks the handshake, a v1 string's does not, so nothing is
            // negotiated on the wire — no downgrade window exists to strip.
            PinnedStaticKey = _identity is not null && cs.StaticKey is not null ? cs.StaticKey : null,
            PinnedEndpointKey = cs.EndpointKey,
            Crypto = _identity is not null && cs.StaticKey is not null
                ? ConnectionCrypto.New(_identity, _peerId, cs.PeerId)
                : null,
        };
        c.Buffer = CreateBuffer();
        c.PuncFrame = BuildPunc(c);
        c.Public = new PinholeConnection(this, c);
        // Before publication: no other thread can see c through the table, so seeding the
        // peer candidates needs no lock.
        c.PeerCandidates.AddRange(cs.Candidates);

        if (_disposed) throw new ObjectDisposedException(nameof(PinholeNode));
        // Atomic check-and-insert: two concurrent dials at the same target must share one
        // connection, not silently overwrite each other's entry.
        while (true)
        {
            if (_conns.TryGetValue(cs.PeerId, out ConnState? existing))
            {
                if (existing.State is not (PinholeConnectionState.Dead or PinholeConnectionState.Closed))
                {
                    return existing; // idempotent dials (and in-flight dials) return the live connection
                }

                // A dead husk from an earlier attempt: remove it (only if still that husk)
                // and loop to install ours — losing a race simply retries.
                if (!_conns.TryRemove(new KeyValuePair<ulong, ConnState>(cs.PeerId, existing)))
                {
                    continue;
                }

                Transition(existing, PinholeConnectionState.Closed);
                existing.Dead.Cancel();
            }

            if (_conns.TryAdd(cs.PeerId, c))
            {
                break;
            }
        }

        if (cs.Candidates.Any(x => x.Kind == CandidateKind.Relay))
        {
            // Relay candidates need our own allocation to send through, and the peer's
            // allocation needs a permission for our relay server's IP before it delivers.
            _ = WarmRelayForDialAsync(cs, ct);
        }

        // A v3 ticket pins the peer's endpoint key, so its candidates can be rediscovered:
        // race the lookup providers alongside the punch for the peer's current record. v1/v2
        // tickets pin nothing, so nothing a provider says about them is adoptable.
        if (_lookup.Count > 0 && cs.EndpointKey is { } pinnedKey)
        {
            _ = ResolveViaLookupAsync(c, pinnedKey, ct);
        }

        KickPunch(c);
        return c;
    }

    private async Task WarmRelayForDialAsync(ConnectionString cs, CancellationToken ct)
    {
        try
        {
            await EnsureRelaysAsync(ct).ConfigureAwait(false);
            foreach (TurnClient client in AliveRelayClients())
            {
                foreach (PinholeCandidate candidate in cs.Candidates.Where(x => x.Kind == CandidateKind.Relay))
                {
                    await TryPermitAsync(client, candidate.Address.Address, ct).ConfigureAwait(false);
                }
            }

            if (Lookup(cs.PeerId) is { State: PinholeConnectionState.Punching } c)
            {
                KickPunch(c);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or InvalidOperationException or TimeoutException or ObjectDisposedException)
        {
            // Warming is best-effort: the dial proceeds on whatever paths it can reach.
        }
    }

    private ConnState? CreateIncoming(ulong peerId, uint token, in Arrival arrival, bool cryptoHandshake)
    {
        // Check before allocating stranger state and again after insertion. Outgoing
        // dials and TCP receive workers can race for the remaining slots; the insertion
        // that loses that race gives way instead of leaving excess stranger state.
        if (_conns.Count >= _maxConns)
        {
            return null;
        }

        var c = new ConnState
        {
            PeerId = peerId,
            Token = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)),
            RemoteToken = token,
            RemoteTokenKnown = true,
            IsIncoming = true,
            AwaitInitialCandidateExchange = _options.RelaySignalingOnly && arrival.ViaRelay,
            Crypto = cryptoHandshake && _identity is not null ? ConnectionCrypto.New(_identity, _peerId, peerId) : null,
        };
        c.Buffer = CreateBuffer();
        c.PuncFrame = BuildPunc(c);
        c.Public = new PinholeConnection(this, c);
        // Two PUNCs raced: the first entry wins, the second becomes nothing.
        if (!_conns.TryAdd(peerId, c))
        {
            return _conns.TryGetValue(peerId, out ConnState? first) ? first : null;
        }

        if (_conns.Count > _maxConns)
        {
            // A concurrent dial won the race to the last slot; the stranger gives way.
            _conns.TryRemove(new KeyValuePair<ulong, ConnState>(peerId, c));
            return null;
        }

        if (arrival.ViaRelay)
        {
            RelayPathConfirmed(c, arrival);
        }
        else
        {
            DirectPathConfirmed(c, arrival);
        }

        if (arrival.Tcp is null && c.Crypto is null && !_options.RelaySignalingOnly)
        {
            c.IncomingQueued = true;
            _incoming?.Writer.TryWrite(c);
        }
        else if (arrival.Tcp is not null) c.PendingTcp = arrival.Tcp;
        return c;
    }

    public async Task CloseAsync(ConnState c)
    {
        // Identity check: a concurrent re-dial may have replaced this entry, and the
        // loser's close must not tear down the winner's live connection.
        _conns.TryRemove(new KeyValuePair<ulong, ConnState>(c.PeerId, c));

        Span<byte> bye = stackalloc byte[HeaderSize + CryptoWire.TokenLength + CryptoWire.SealedOverhead];
        int len = BuildFrame(c, FrameType.Bye, ReadOnlySpan<byte>.Empty, bye);
        try
        {
            RouteFrame(c, bye[..len]);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
        {
        }

        Transition(c, PinholeConnectionState.Closed);
        c.DirectTcp?.CloseGracefully();
        _tcp?.ClosePeer(c.PeerId, c.DirectTcp);
        c.Dead.Cancel();
        await Task.CompletedTask.ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ punch

    public void KickPunch(ConnState c)
    {
        lock (c.Gate)
        {
            c.LastKickTicks = Environment.TickCount64;
        }

        int gen = Interlocked.Increment(ref c.PunchGeneration);
        _ = PunchLoop(c, gen);
    }

    private async Task PunchLoop(ConnState c, int gen)
    {
        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token, c.Dead.Token);
        int upgradeAttempts = 0;
        DateTimeOffset lastDirectPunch = DateTimeOffset.MinValue;
        try
        {
            while (!stop.IsCancellationRequested && Volatile.Read(ref c.PunchGeneration) == gen)
            {
                if (c.State == PinholeConnectionState.Closed
                    || c.State == PinholeConnectionState.Open && c.DirectTcp is null)
                {
                    return;
                }

                if ((c.State == PinholeConnectionState.Degraded || c.State == PinholeConnectionState.Open)
                    && ++upgradeAttempts > MaxUpgradeAttempts)
                {
                    return; // stop poking; direct can still open passively from the peer's frames
                }

                if (c.State == PinholeConnectionState.Punching)
                {
                    lock (c.Gate)
                    {
                        // Monotonic clock on purpose: after a suspend/wake the wall clock jumps
                        // forward by the sleep, and a UtcNow comparison would condemn the
                        // punch before a single post-wake probe could answer.
                        if (Environment.TickCount64 - c.LastKickTicks > (long)_options.ConnectTimeout.TotalMilliseconds)
                        {
                            Transition(c, PinholeConnectionState.Dead);
                            c.DeadSinceTicks = Environment.TickCount64;
                            // Dead is revivable, and the peer can only revive us if our
                            // frames keep telling it where we now are — after a rebind the
                            // old candidates it holds are dead, so an announce has nowhere
                            // to land. A real session (its dial or handshake completed)
                            // therefore keeps a slow beacon: one paced round per second for
                            // five minutes, after which it goes quiet and stays passively
                            // revivable. Stranger-flood husks never completed a handshake
                            // and never beacon — no reflection amplification.
                            if (!c.Connected.Task.IsCompleted || Environment.TickCount64 - c.DeadSinceTicks > DeadBeaconBudgetMs)
                            {
                                return;
                            }
                        }
                    }
                }

                if (c.State == PinholeConnectionState.Dead
                    && Environment.TickCount64 - c.DeadSinceTicks > DeadBeaconBudgetMs)
                {
                    return; // beacon budget spent; passive revival still works
                }

                PinholeCandidate[] candidates;
                lock (_gate)
                {
                    candidates = c.PeerCandidates.ToArray();

                    // A stuck punch whose ticket pins an endpoint key asks the lookup
                    // providers where the peer is NOW, on a slow cadence: unsuccessful
                    // recovery is one of the events that must refresh reachability. This is
                    // also the only retry that keeps firing once the session has fallen to
                    // Punching (NotifyPathSuspect no longer runs there).
                    if (c.PinnedEndpointKey is { } pinned && _lookup.Count > 0
                        && Environment.TickCount64 - c.LastLookupTicks > 5000)
                    {
                        c.LastLookupTicks = Environment.TickCount64;
                        _ = ResolveViaLookupAsync(c, pinned, stop.Token);
                    }
                }

                if (_options.RelaySignalingOnly && c.Crypto is { Established: true }
                    && c.State is PinholeConnectionState.Punching or PinholeConnectionState.Dead
                    && Environment.TickCount64 - Volatile.Read(ref c.LastCandidateAnnouncement) >= 1000)
                    AnnounceTo(c); // retry control exchange without resetting the initial dial budget

                // A symmetric hint is scheduling advice, not a ban: relay candidates carry
                // the session — per-destination mappings make public reflexives hopeless —
                // while direct candidates keep a one-second trickle. LAN peers (no NAT in
                // the way) and router-mapped endpoints (punch-anywhere by construction)
                // still connect directly even when the hint says the NAT maps
                // per-destination; the hopeless cases cost one datagram per second.
                bool punchDirects = !c.SymmetricHint || DateTimeOffset.UtcNow - lastDirectPunch >= SymmetricDirectTrickle;
                MaybeStartPortPrediction(c);
                if (c.Prediction is { Finished: false } || Volatile.Read(ref _predictionMeasuring) != 0) punchDirects = false;
                if (punchDirects)
                {
                    lastDirectPunch = DateTimeOffset.UtcNow;
                }

                foreach (PinholeCandidate candidate in candidates)
                {
                    if (stop.IsCancellationRequested)
                    {
                        return;
                    }

                    if (!punchDirects && candidate.Kind is not (CandidateKind.Relay or CandidateKind.IrohRelay))
                    {
                        continue;
                    }

                    if (c.AwaitInitialCandidateExchange && !Volatile.Read(ref c.PeerCandidatesReceived)
                        && candidate.Kind is not (CandidateKind.Relay or CandidateKind.IrohRelay)) continue;

                    // Give ordinary routes (especially same-machine loopback) time to win
                    // before probing LAN-only fallbacks. Once Open, this loop stops.
                    if (candidate.Address.Address.IsIPv6LinkLocal
                        && Environment.TickCount64 - c.LastKickTicks < LinkLocalFallbackDelayMs)
                    {
                        continue;
                    }

                    try
                    {
                        if (candidate.Kind == CandidateKind.IrohRelay)
                        {
                            SendViaIroh(c.PuncFrame, candidate);
                        }
                        else if (candidate.Kind == CandidateKind.Relay)
                        {
                            SendViaRelayTo(c.PuncFrame, candidate.Address, candidate.RelayServer?.Address);
                        }
                        else
                        {
                            if (TraceEnabled) TraceLine($"punch direct {c.PeerId:x16} -> {candidate.Address}");
                            SendToWire(candidate.Address, c.PuncFrame);
                        }
                    }
                    catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
                    {
                        // One unroutable candidate (or a brief interface flap) must not kill
                        // the punch; the pacing delay below bounds retries.
                    }
                }

                if (_tcp is not null && c.Crypto is not null && c.DirectTcp is null
                    && (!c.AwaitInitialCandidateExchange || Volatile.Read(ref c.PeerCandidatesReceived))
                    && Environment.TickCount64 - c.LastKickTicks >= 1200)
                    _ = TryTcpPathsAsync(c, candidates, stop.Token);

                TimeSpan pace = c.State switch
                {
                    PinholeConnectionState.Dead => DeadBeaconPace,
                    PinholeConnectionState.Degraded => UpgradePace,
                    PinholeConnectionState.Open => UpgradePace,
                    _ => PunchPace,
                };
                await Task.Delay(pace, stop.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    // ------------------------------------------------------------------ path validation

    // High bit of a probe's timestamp marks it as maintenance; caller pings keep their
    // plain TickCount64 so RTT stats and monitoring counters never mix.
    private const long ProbeMarker = unchecked((long)0x8000000000000000);

    /// <summary>One scheduler for the whole node: no per-connection timers and nothing on
    /// the send path. Dies with the node's shutdown token. Carries both recurring chores:
    /// direct-path validation and the periodic STUN refresh.</summary>
    private async Task MaintenanceLoopAsync(CancellationToken ct)
    {
        double intervalMs = _options.PathValidationProbeInterval.TotalMilliseconds;
        TimeSpan tick = TimeSpan.FromMilliseconds(Math.Clamp(intervalMs / 2, 20, 500));
        long refreshMs = (long)_options.StunRefreshInterval.TotalMilliseconds;
        bool refresh = refreshMs > 0;
        bool validate = _options.EnablePathValidation;
        bool pmtud = _options.EnablePmtud;
        bool keepalive = _options.KeepaliveInterval > TimeSpan.Zero;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(tick, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            if (refresh && Environment.TickCount64 >= Volatile.Read(ref _nextStunRefreshTicks))
            {
                Volatile.Write(ref _nextStunRefreshTicks, Environment.TickCount64 + refreshMs);
                _ = RefreshReflexiveAsync(ct);
            }

            // An idle node must still heal its own relay fleet: a dead or refused TURN slot
            // retries on the slot's backoff ladder (via EnsureRelaysAsync's NextRetry check),
            // checked here once per RelayRetryBackoff. Without this, a relay that died while
            // nobody was dialing would stay dead until the next dial.
            if (Environment.TickCount64 >= Volatile.Read(ref _nextRelayEnsureTicks))
            {
                Volatile.Write(ref _nextRelayEnsureTicks, Environment.TickCount64 + (long)RelayRetryBackoff.TotalMilliseconds);
                if (Interlocked.Exchange(ref _relayEnsuring, 1) == 0)
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await EnsureRelaysAsync(CancellationToken.None).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException or TimeoutException)
                        {
                        }
                        finally
                        {
                            Volatile.Write(ref _relayEnsuring, 0);
                        }
                    });
                }
            }

            _portMap?.Tick(Environment.TickCount64);
            _tcpPortMap?.Tick(Environment.TickCount64);
            _interfaceUdp?.Tick(Environment.TickCount64);
            if (_interfaceUdp is not null && Environment.TickCount64 >= _nextInterfaceRefresh) RefreshInterfaceCandidates();
            if (_ipv6Firewall is not null && Environment.TickCount64 >= _nextIPv6FirewallRefresh)
                RefreshIPv6Firewall();

            if (validate || pmtud || keepalive)
            {
                foreach (ConnState c in ConnectionsSnapshot())
                {
                    if (validate)
                    {
                        ValidatePath(c);
                    }

                    if (pmtud)
                    {
                        DiscoverPathMtu(c);
                    }

                    if (keepalive)
                    {
                        MaybeKeepalive(c);
                    }
                }
            }
        }
    }

    /// <summary>Periodic re-discovery (iroh performs the same refresh): NAT mappings move with
    /// no OS event, so re-probe every STUN server and, when the observed reflexive set moved,
    /// replace it and re-advertise the new candidates to every peer over its current path.
    /// Open direct paths keep working — their endpoints come from the peer's own frames, not
    /// from STUN — and a fully silent probe batch changes nothing: a lost network is
    /// <see cref="RecoverAsync"/>'s call, not this timer's.</summary>
    private async Task RefreshReflexiveAsync(CancellationToken ct)
    {
        if (_disposed || Interlocked.Exchange(ref _stunRefreshing, 1) != 0)
        {
            return;
        }

        try
        {
            // Two servers can observe the same mapping (one NAT, same public port): dedupe
            // before comparing or every refresh would look like a change.
            IPEndPoint[] perServer = await ProbeStunObservedAsync(ct).ConfigureAwait(false);
            if (perServer.Length == 0)
            {
                // Every configured STUN server went silent while at least one used to
                // answer: this is the bounded periodic revalidation for platforms whose
                // network-change notifications are absent or delayed. The mapping-change
                // logic below cannot fire from zero observations, so a network that went
                // away entirely would otherwise stay unnoticed until a dial fails.
                // RecoverAsync probes, rebinds only on confirmed silence, and debounces.
                if (_reflexive.Count > 0)
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await Task.Delay(RecoverDebounce, _shutdown.Token).ConfigureAwait(false);
                            await RecoverAsync(forceRebind: false, CancellationToken.None).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                        }
                    });
                }

                return;
            }

            ObserveNatHint(perServer);
            IPEndPoint[] observed = new HashSet<IPEndPoint>(perServer).ToArray();

            bool changed;
            lock (_gate)
            {
                changed = observed.Length != _reflexive.Count || observed.Any(ep => !_reflexive.Contains(ep));
                if (changed)
                {
                    _reflexive.Clear();
                    _reflexive.AddRange(observed);
                    RefreshLocalCandidatesNoLock(); // same critical section: no torn state between the two views
                }
            }

            if (!changed)
            {
                return;
            }

            foreach (ConnState c in ConnectionsSnapshot())
            {
                if (c.State != PinholeConnectionState.Closed)
                {
                    AnnounceTo(c); // gentle: the peer keeps its working path and only learns our new candidates
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            Volatile.Write(ref _stunRefreshing, 0);
        }
    }

    /// <summary>Detects the silent direct-path death a send error never reports: NAT expiry,
    /// a router, or a firewall dropping packets in both directions. After the idle window
    /// with no direct-path RECEIVE, probes run until enough consecutive answers fail to
    /// arrive, then the path is declared suspect exactly as a send failure would be.</summary>
    private void ValidatePath(ConnState c)
    {
        long now = Environment.TickCount64;
        if (c.State == PinholeConnectionState.Degraded && c.Path == PathKind.Relay)
        {
            ValidateRelayPath(c);
            return;
        }

        bool suspect = false;
        lock (c.Gate)
        {
            if (c.State != PinholeConnectionState.Open || c.Path != PathKind.Direct || c.DirectRemote is null)
            {
                ResetPathProbesNoLock(c);
                return;
            }

            long lastRx = Volatile.Read(ref c.LastDirectRxTicks);
            if (lastRx > 0 && now - lastRx < _options.PathValidationIdle.TotalMilliseconds)
            {
                ResetPathProbesNoLock(c); // live traffic; any half-finished probe sequence is forgotten
                return;
            }

            if (c.ProbeOutstanding)
            {
                if (now < c.ProbeDeadlineTicks)
                {
                    return; // this probe's reply may still land
                }

                c.ProbeOutstanding = false;
                c.UnansweredProbes++;
                if (c.UnansweredProbes >= _options.PathValidationMaxUnansweredProbes)
                {
                    c.UnansweredProbes = 0;
                    suspect = true;
                }
                else
                {
                    return; // next tick sends the next probe
                }
            }
        }

        if (suspect)
        {
            NotifyPathSuspect(c); // outside the gate: it takes c.Gate itself
            return;
        }

        SendPathProbe(c);
    }

    /// <summary>The relay leg of a degraded session gets the same liveness honesty the
    /// direct path gets: silence beyond <see cref="PinholeOptions.PathValidationIdle"/> is
    /// probed with the token ping (which rides the relay), and persistent silence escalates
    /// through <see cref="NotifyPathSuspect"/> — whose permit re-validation retires a ghost
    /// allocation (a restarted relay) instead of black-holing until the minutes-long TURN
    /// refresh cadence notices. Reuses the direct probe slots: a connection validates one
    /// leg at a time, and a leg switch resets the counters.</summary>
    private void ValidateRelayPath(ConnState c)
    {
        long now = Environment.TickCount64;
        bool suspect = false;
        bool probe = false;
        lock (c.Gate)
        {
            if (c.State != PinholeConnectionState.Degraded || c.Path != PathKind.Relay || !c.RelayReady)
            {
                return;
            }

            long lastRx = Volatile.Read(ref c.LastRelayRxTicks);
            if (lastRx > 0 && now - lastRx < _options.PathValidationIdle.TotalMilliseconds)
            {
                ResetPathProbesNoLock(c); // live relay traffic; any half-finished probe sequence is forgotten
                return;
            }

            if (c.ProbeOutstanding)
            {
                if (now < c.ProbeDeadlineTicks)
                {
                    return; // this probe's reply may still land
                }

                c.ProbeOutstanding = false;
                c.UnansweredProbes++;
                if (c.UnansweredProbes >= _options.PathValidationMaxUnansweredProbes)
                {
                    c.UnansweredProbes = 0;
                    suspect = true;
                }
                else
                {
                    return; // next tick sends the next probe
                }
            }
            else
            {
                probe = true;
                c.ProbeOutstanding = true;
                c.ProbeDeadlineTicks = now + (long)_options.PathValidationProbeInterval.TotalMilliseconds;
            }
        }

        if (suspect)
        {
            // The condemned relay leg loses its ready mark BEFORE NotifyPathSuspect: a
            // stale RelayReady would keep the session Degraded forever, sending into a
            // relay that no longer owns the peer's address. Unready, the next arrival
            // from one of the peer's live legs re-adopts through RelayPathConfirmed.
            lock (c.Gate)
            {
                c.RelayReady = false;
            }

            NotifyPathSuspect(c); // outside the gate: it takes c.Gate itself
            return;
        }

        if (probe)
        {
            PingUncounted(c); // RouteFrame sends degraded traffic via the relay leg
        }
    }

    private void ResetPathProbesNoLock(ConnState c)
    {
        c.ProbeOutstanding = false;
        c.ProbeTarget = null;
        c.ProbeTcp = null;
        c.ProbeUdpSocket = null;
        c.UnansweredProbes = 0;
    }

    private void SendPathProbe(ConnState c)
    {
        long now = Environment.TickCount64;
        long nonce = now | ProbeMarker;
        SocketAddress? target;
        lock (c.Gate)
        {
            if (c.State != PinholeConnectionState.Open || c.Path != PathKind.Direct)
            {
                return;
            }

            target = c.DirectRemote;
            if (target is null)
            {
                return;
            }

            c.ProbeOutstanding = true;
            c.ProbeNonce = nonce;
            c.ProbeTarget = target;
            c.ProbeTcp = c.DirectTcp;
            c.ProbeUdpSocket = c.DirectUdpSocket;
            c.ProbeDeadlineTicks = now + (long)_options.PathValidationProbeInterval.TotalMilliseconds;
        }

        Span<byte> frame = stackalloc byte[PmtuBaseWire];
        Span<byte> nonceBytes = stackalloc byte[8];
        BitConverter.TryWriteBytes(nonceBytes, nonce);
        int len = BuildFloorPing(c, nonceBytes, frame);
        try
        {
            SendDirect(c, target, frame[..len]);
            Interlocked.Increment(ref c.PathProbesSent);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            // An unsendable probe simply goes unanswered; the timeout accounting above
            // handles it. Real send failures are surfaced by Send with its own trigger.
        }
    }

    /// <summary>One heartbeat per interval on every live connection — a caller ping, so
    /// its pongs refresh the NAT mapping both ways and feed RTT, and it counts in caller
    /// stats because the app asked for it.</summary>
    private void MaybeKeepalive(ConnState c)
    {
        long intervalMs = (long)_options.KeepaliveInterval.TotalMilliseconds;
        long now = Environment.TickCount64;
        lock (c.Gate)
        {
            if (c.State is not (PinholeConnectionState.Open or PinholeConnectionState.Degraded)
                || now < c.KeepaliveNextTicks)
            {
                return;
            }

            c.KeepaliveNextTicks = now + intervalMs;
        }

        Ping(c);
    }

    // ------------------------------------------------------------------ path MTU discovery

    /// <summary>Drives one connection's RFC 8899-style climb: padded pings step the wire
    /// size upward, a matching pong confirms a size, and three unanswered probes abandon a
    /// size for a long cooldown. Only direct paths are probed — relays tunnel whatever they
    /// are handed — and leaving the direct path forgets everything: a new path may have a
    /// smaller MTU than the last one proved.</summary>
    private void DiscoverPathMtu(ConnState c)
    {
        long now = Environment.TickCount64;
        SocketAddress? target;
        long nonce;
        int size;
        lock (c.Gate)
        {
            if (c.State != PinholeConnectionState.Open || c.Path != PathKind.Direct || c.DirectRemote is null || c.DirectTcp is not null)
            {
                if (c.PmtuWire != 0 || c.PmtuOutstanding)
                {
                    c.PmtuWire = 0;
                    c.PmtuOutstanding = false;
                    c.PmtuNextProbeTicks = 0;
                }
                return;
            }

            if (c.PmtuOutstanding)
            {
                if (now < c.PmtuDeadlineTicks)
                {
                    return; // this probe's pong may still land
                }

                if (++c.PmtuProbeTries >= PmtuProbeAttempts)
                {
                    // The size never answered. An over-MTU probe is silently dropped by the
                    // network, not errored, so absence of a pong IS the measurement.
                    c.PmtuOutstanding = false;
                    if (c.PmtuProbeSize == c.PmtuWire && c.PmtuWire > PmtuBaseWire)
                    {
                        // The CONFIRMED size no longer traverses: the path's MTU shrank
                        // under us. Fall back to the guaranteed floor and re-climb —
                        // app-sized sends stop blackholing within one probe cycle.
                        c.PmtuWire = PmtuBaseWire;
                        c.PmtuVerifiedSize = false;
                        c.PmtuNextProbeTicks = 0;
                        return;
                    }

                    // A failed climb starts the cooldown; the cycle after EVERY cooldown
                    // re-verifies the confirmed size first (VerifiedSize reset here), so a
                    // path that shrank later is caught on the next cooldown, not never.
                    c.PmtuVerifiedSize = false;
                    c.PmtuNextProbeTicks = now + (long)_options.PmtuReprobeInterval.TotalMilliseconds;
                    return;
                }
            }
            else
            {
                if (now < c.PmtuNextProbeTicks)
                {
                    return;
                }

                int next;
                if (c.PmtuWire > PmtuBaseWire && !c.PmtuVerifiedSize)
                {
                    // RFC 8899 size re-verification: prove the CONFIRMED size still
                    // traverses before climbing further. A path whose MTU shrank after the
                    // confirmation (a VPN or tunnel engaged mid-connection) silently drops
                    // app-sized frames while small validation probes keep passing — without
                    // this, the stale confirmation would blackhole large payloads forever.
                    next = c.PmtuWire;
                }
                else
                {
                    next = NextPmtuSizeLocked(c);
                    if (next <= 0)
                    {
                        c.PmtuNextProbeTicks = now + (long)_options.PmtuReprobeInterval.TotalMilliseconds; // ceiling reached; re-climb later
                        return;
                    }
                }

                c.PmtuProbeSize = next;
                c.PmtuProbeTries = 0;
                c.PmtuOutstanding = true;
            }

            c.PmtuProbeNonce = now | PmtuProbeMarker;
            c.PmtuDeadlineTicks = now + (long)_options.PathValidationProbeInterval.TotalMilliseconds;
            c.PmtuProbeTarget = c.DirectRemote;
            c.PmtuProbeUdpSocket = c.DirectUdpSocket;
            target = c.PmtuProbeTarget;
            nonce = c.PmtuProbeNonce;
            size = c.PmtuProbeSize;
        }

        SendPmtuProbe(c, target!, nonce, size);
    }

    /// <summary>The next wire size worth probing: one step above what is confirmed, capped
    /// by the remote address family's Ethernet plateau. Zero means the ceiling is proven.
    /// The endpoint form decides the family — the dual-mode socket reports even IPv4 peers
    /// as v4-mapped IPv6 sockaddrs, and mapping back recovers the true 1472-byte budget.</summary>
    private static int NextPmtuSizeLocked(ConnState c)
    {
        int ceiling = PmtuCeilingLocked(c);
        int floor = Math.Max(c.PmtuWire, PmtuBaseWire);
        return floor >= ceiling ? 0 : Math.Min(ceiling, floor + PmtuStepBytes);
    }

    private static int PmtuCeilingLocked(ConnState c) =>
        c.DirectRemoteEp is { Address.AddressFamily: System.Net.Sockets.AddressFamily.InterNetwork }
            ? PmtuCeilingV4
            : PmtuCeilingV6;

    /// <summary>One padded Ping: the nonce in front, zero padding behind, sized so the
    /// whole sealed frame lands on the probe size. The peer echoes the nonce in its Pong —
    /// small, cheap, and proof the full-size datagram traversed the path.</summary>
    private void SendPmtuProbe(ConnState c, SocketAddress target, long nonce, int size)
    {
        Span<byte> body = stackalloc byte[size - PmtuOverhead];
        BitConverter.TryWriteBytes(body, nonce); // the padding behind it stays zero
        Span<byte> frame = stackalloc byte[size];
        int len = BuildFrame(c, FrameType.Ping, body, frame);
        try
        {
            SendToWire(target, frame[..len]);
            Interlocked.Increment(ref c.PmtuProbesSent);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            // An unsendable probe just goes unanswered; the attempt accounting handles it.
        }
    }

    private static bool SameEndPoint(SocketAddress? left, SocketAddress? right)
    {
        if (ReferenceEquals(left, right))
        {
            return true;
        }

        if (left is null || right is null || left.Family != right.Family || left.Size != right.Size)
        {
            return false;
        }

        // Vectorized over the public buffer: a per-byte indexer loop here was the top
        // managed cost on the receive thread once the allocation fix landed.
        return left.Buffer.Span[..left.Size].SequenceEqual(right.Buffer.Span[..right.Size]);
    }

    // ------------------------------------------------------------------ sending

    public void Send(ConnState c, ReadOnlySpan<byte> payload)
    {
        ArgumentOutOfRangeException.ThrowIfZero(payload.Length); // a zero-length Data frame is undeliverable by definition
        int ceiling;
        lock (c.Gate)
        {
            // PMTUD may have proven the path can carry more than the API floor; it can never
            // prove less — 1200 bytes are guaranteed from the moment the session opens.
            ceiling = c.PmtuWire > 0 ? c.PmtuWire - PmtuOverhead : MaxPayload;
        }
        ArgumentOutOfRangeException.ThrowIfGreaterThan(payload.Length, ceiling);
        switch (c.State)
        {
            case PinholeConnectionState.Punching:
                throw new InvalidOperationException("connection is not open yet");
            case PinholeConnectionState.Dead:
                throw new InvalidOperationException("connection is dead: no usable path (call RoamNowAsync to recover)");
            case PinholeConnectionState.Closed:
                throw new ObjectDisposedException(nameof(PinholeConnection));
        }

        int n = payload.Length + HeaderSize + CryptoWire.TokenLength + CryptoWire.SealedOverhead;
        Span<byte> frame = stackalloc byte[n];
        int len = BuildFrame(c, FrameType.Data, payload, frame);
        try
        {
            RouteFrame(c, frame[..len]);
            Interlocked.Increment(ref c.Sent);
            Interlocked.Add(ref c.BytesSent, payload.Length);
            if (Volatile.Read(ref c.ConsecutiveSendFailures) != 0)
            {
                Interlocked.Exchange(ref c.ConsecutiveSendFailures, 0);
            }
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            Interlocked.Increment(ref c.SendFailed);
            if (Interlocked.Increment(ref c.ConsecutiveSendFailures) >= 3)
            {
                NotifyPathSuspect(c);
            }

            throw;
        }
    }

    public void Ping(ConnState c)
    {
        if (SendPingFrame(c))
        {
            Interlocked.Increment(ref c.PingsSent);
        }
    }

    /// <summary>The path-maintenance variant: same wire probe, but transport-internal
    /// probes must not inflate the app-visible ping stats — <c>PingsSent</c> counts the
    /// pings the app asked for, exactly as the keepalive contract documents.</summary>
    internal void PingUncounted(ConnState c) => SendPingFrame(c);

    private bool SendPingFrame(ConnState c)
    {
        if (c.State is not (PinholeConnectionState.Open or PinholeConnectionState.Degraded))
        {
            return false;
        }

        Span<byte> frame = stackalloc byte[PmtuBaseWire];
        Span<byte> timestamp = stackalloc byte[8];
        BitConverter.TryWriteBytes(timestamp, Environment.TickCount64);
        int len = BuildFloorPing(c, timestamp, frame);
        try
        {
            RouteFrame(c, frame[..len]);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
        {
            return false; // a probe that cannot leave simply goes unanswered
        }

        return true;
    }

    /// <summary>Sends on the connection's current path: direct when open, relay when degraded.</summary>
    private void RouteFrame(ConnState c, ReadOnlySpan<byte> frame)
    {
        if (c.Path == PathKind.Direct && c.DirectRemote is { } direct)
        {
            SendDirect(c, direct, frame);
            return;
        }

        if (_options.RelaySignalingOnly && frame[0] == (byte)FrameType.Data)
            throw new InvalidOperationException("direct application path is unavailable; relays are signaling-only");

        if (c.Iroh is { IsAlive: true } iro && c.IrohConfirmed && c.IrohPeerKey is { } key)
        {
            if (!iro.Send(key, frame)) throw new SocketException((int)SocketError.NoBufferSpaceAvailable);
            return;
        }

        if (c.RelayRemote is { } relay && c.RelayReady)
        {
            SendViaRelayTo(frame, relay);
            return;
        }

        throw new InvalidOperationException("no usable path");
    }

    private void SendToWire(IPEndPoint ep, ReadOnlySpan<byte> frame)
    {
        if (!_options.EnableDirectUdp) throw new SocketException((int)SocketError.NetworkUnreachable);
        // Volatile read, no lock: this runs once per sent frame, and the rebind that swaps
        // the socket is rare enough to pay for itself with a caught send error.
        if (ep.Address.IsIPv6LinkLocal && ep.Address.ScopeId == 0)
        {
            foreach (IPEndPoint scoped in ScopeLinkLocal(ep, LinkLocalSendScopes()))
            {
                try { _udp.SendTo(frame, ToWire(scoped)); }
                catch (SocketException) { } // one down link must not suppress the other LAN scopes
            }
            return;
        }
        try { _udp.SendTo(frame, ToWire(ep)); }
        finally { _interfaceUdp?.SendCandidates(frame, ep); } // a failed default route cannot suppress other interfaces
    }

    private void SendToWire(SocketAddress sa, ReadOnlySpan<byte> frame)
    {
        if (!_options.EnableDirectUdp) throw new SocketException((int)SocketError.NetworkUnreachable);
        _udp.SendTo(frame, sa);
    }

    private void SendDirect(ConnState c, SocketAddress target, ReadOnlySpan<byte> frame)
    {
        if (c.DirectTcp is { } tcp && SameEndPoint(target, c.DirectRemote))
        {
            if (!tcp.Send(frame)) throw new SocketException((int)SocketError.NoBufferSpaceAvailable);
        }
        else if (c.DirectUdpSocket is { } source) source.SendTo(frame, target);
        else SendToWire(target, frame);
    }

    internal void OnTcpFrame(TcpLink tcp, ReadOnlyMemory<byte> frame)
    {
        if (_disposed || frame.Length < HeaderSize + CryptoWire.TokenLength) return;
        ulong id = BinaryPrimitives.ReadUInt64LittleEndian(frame.Span[1..]);
        if (!tcp.BindPeer(id)) { tcp.Dispose(); return; }
        if (Lookup(id) is { Crypto: null }) { tcp.Dispose(); return; }
        if (tcp.AuthenticatedPeer != id && (FrameType)frame.Span[0] is not
            (FrameType.Punc or FrameType.Pack or FrameType.Hsck or FrameType.Ping or FrameType.Pong)) return;
        // The TCP sidecar offers only authenticated sessions, even when the UDP node
        // permits legacy plaintext. Never create a TCP stranger from a legacy probe.
        if (frame.Span[0] == (byte)FrameType.Punc && frame.Length != HeaderSize + CryptoWire.PuncCryptoBody) { tcp.Dispose(); return; }
        Dispatch(frame.Span, new Arrival(tcp));
    }

    internal void OnTcpClosed(TcpLink tcp)
    {
        ConnState? c = Lookup(tcp.BoundPeer);
        if (c is null) return;
        bool suspect = false;
        lock (c.Gate)
        {
            if (ReferenceEquals(c.PendingTcp, tcp) && !c.IncomingQueued)
            {
                _conns.TryRemove(new KeyValuePair<ulong, ConnState>(c.PeerId, c));
                Transition(c, PinholeConnectionState.Closed);
                c.Dead.Cancel();
            }
            else if (ReferenceEquals(c.DirectTcp, tcp) && c.State != PinholeConnectionState.Closed)
            {
                c.DirectTcp = null;
                c.DirectRemote = null;
                suspect = true;
            }
        }
        if (suspect) NotifyPathSuspect(c);
    }

    private async Task TryTcpPathsAsync(ConnState c, PinholeCandidate[] candidates, CancellationToken stop)
    {
        long lastAttempt = Volatile.Read(ref c.LastTcpAttempt);
        if (_tcp is not { } transport || c.Crypto is null || c.Dead.IsCancellationRequested
            || lastAttempt != 0 && Environment.TickCount64 - lastAttempt < 5_000
            || Interlocked.CompareExchange(ref c.TcpDialing, 1, 0) != 0) return;
        try
        {
            Volatile.Write(ref c.LastTcpAttempt, Environment.TickCount64);
            IReadOnlyList<int> scopes = LinkLocalSendScopes();
            IPEndPoint[] targets = candidates.Where(candidate => candidate.Kind is CandidateKind.Direct or CandidateKind.Reflexive)
                .SelectMany(candidate => ScopeLinkLocal(candidate.Address, scopes)).Distinct().Take(8).ToArray();
            await Task.WhenAll(targets.Select(async target =>
            {
                TcpLink? link = await transport.ConnectAsync(target, stop).ConfigureAwait(false);
                if (link is null || !link.BindPeer(c.PeerId)) return;
                if (c.State == PinholeConnectionState.Closed || c.Dead.IsCancellationRequested) { link.Dispose(); return; }
                if (c.State == PinholeConnectionState.Open && c.Path == PathKind.Direct && c.DirectTcp is null) return;
                link.Send(c.PuncFrame);
                if (c.Crypto is { Established: true, PeerConfirmed: true })
                    SendTcpProof(c, link);
            })).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException or IOException) { }
        finally { Volatile.Write(ref c.TcpDialing, 0); }
    }

    private void SendTcpProof(ConnState c, TcpLink tcp)
    {
        if (c.Crypto is not { Established: true } || !tcp.BeginProof(out long challenge)) return;
        Span<byte> payload = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(payload, challenge);
        Span<byte> frame = stackalloc byte[HeaderSize + CryptoWire.TokenLength + 8 + CryptoWire.SealedOverhead];
        int length = BuildFrame(c, FrameType.Ping, payload, frame);
        if (!tcp.Send(frame[..length])) tcp.Dispose();
    }

    /// <summary>Sends to the peer's relayed address through our allocation on the SAME
    /// server whenever one exists — a relayed address lives on its server, so the target IP
    /// is itself the routing hint. Cross-server forwarding is legal TURN, but the receiver's
    /// allocation only holds permissions for relay servers it knows about, so same-server is
    /// the route that arrives. Falls back to any alive allocation when we have none there.</summary>
    private void SendViaRelayTo(ReadOnlySpan<byte> frame, IPEndPoint peer, IPAddress? viaServer = null)
    {
        List<TurnClient> alive = AliveRelayClients();
        TurnClient? client = alive.FirstOrDefault(c => c.Server.Address.Equals(viaServer ?? peer.Address));
        client ??= alive.FirstOrDefault();
        if (client is null)
        {
            throw new InvalidOperationException("no relay allocation available");
        }

        client.Send(frame, peer);
    }

    private static SocketAddress ToWire(IPEndPoint ep)
    {
        // The socket is dual-mode IPv6: IPv4 targets must be v4-mapped or Windows sendto
        // rejects the address family outright.
        if (ep.Address.AddressFamily == AddressFamily.InterNetwork)
        {
            ep = new IPEndPoint(ep.Address.MapToIPv6(), ep.Port);
        }
        return ep.Serialize();
    }

    internal static IReadOnlyList<IPEndPoint> ScopeLinkLocal(IPEndPoint ep, IReadOnlyList<int> scopes)
    {
        if (!ep.Address.IsIPv6LinkLocal || ep.Address.ScopeId != 0) return [ep];
        return scopes.Where(scope => scope > 0).Distinct().Take(4)
            .Select(scope => new IPEndPoint(new IPAddress(ep.Address.GetAddressBytes(), scope), ep.Port)).ToArray();
    }

    private static IReadOnlyList<int> LinkLocalSendScopes()
    {
        try
        {
            // A scope identifies OUR interface. Try each LAN link instead of choosing the
            // first one; mobile, virtual, and tunnel interfaces cannot reach this LAN peer.
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.OperationalStatus == OperationalStatus.Up
                    && nic.NetworkInterfaceType is NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ethernet)
                .OrderBy(nic => nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? 0 : 1)
                .Select(nic => (Nic: nic, Props: nic.GetIPProperties()))
                .Where(t => t.Props.UnicastAddresses.Any(a => a.Address.IsIPv6LinkLocal))
                .Select(t => t.Props.GetIPv6Properties()?.Index ?? 0)
                .Where(index => index > 0).Distinct().Take(4).ToArray();
        }
        catch (NetworkInformationException)
        {
        }
        return [];
    }

    // ------------------------------------------------------------------ receive

    private void StartRecvLoop()
    {
        new Thread(RecvLoop) { IsBackground = true, Name = "pinhole-node-recv" }.Start();
    }

    private void RecvLoop()
    {
        byte[] buf = new byte[_rawReceive is null ? RecvBufferSize : 65535];
        // One scratch address, reused for every receive: the recvmsg writes into it, the
        // frame handlers only read it, and the engine clones it exactly when a connection
        // adopts the endpoint as its own (a per-datagram copy was 8% of the receive thread).
        var remote = new SocketAddress(AddressFamily.InterNetworkV6);
        int addressCapacity = remote.Size;
        while (!_shutdown.IsCancellationRequested)
        {
            int n;
            IUdpSocket receiving = _udp;
            try
            {
                // BSD may return a native IPv4 sockaddr on a dual-mode socket. ReceiveFrom
                // shrinks Size to that address; restore capacity before the next receive.
                remote.Size = addressCapacity;
                n = receiving.ReceiveFrom(buf, remote);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException) when (_shutdown.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException)
            {
                continue;
            }

            if (_shutdown.IsCancellationRequested) return;

            if (n < 0 || (n == 0 && _rawReceive is null))
            {
                continue;
            }

            if (_rawReceive is not null)
            {
                // Raw iroh packets can have any first byte, including Pinhole's frame tags.
                // Consume only this engine's outstanding STUN responses; everything else
                // belongs to the protocol above the raw transport.
                bool stun = MatchingStun(buf, n, receiving, remote) is not null;
                if (stun)
                {
                    try { OnStunResponse(buf, n, receiving, remote); } catch (Exception) { }
                }
                else
                {
                    try { _rawReceive(IrohPath.Direct(ToEndpoint(remote)), buf.AsMemory(0, n)); }
                    catch (Exception)
                    {
                        // Match the session dispatcher: a bad address or throwing handler
                        // must cost one datagram, never the shared receive thread.
                    }
                }
            }
            else if (_options.EnableDirectUdp && buf[0] is >= (byte)FrameType.Punc and <= (byte)FrameType.Hsck && n >= HeaderSize)
            {
                try
                {
                    Dispatch(buf.AsSpan(0, n), new Arrival(remote));
                }
                catch (Exception)
                {
                    // A malformed frame or a throwing user handler must not deafen the socket.
                }
            }
            else if (n >= 20 && BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(4)) == StunCookie)
            {
                try
                {
                    OnStunResponse(buf, n, receiving, remote);
                }
                catch (Exception)
                {
                    // A malformed STUN response must cost its probe, never the receive loop.
                }
            }
        }
    }

    private void OnInterfaceFrame(IUdpSocket socket, byte[] buffer, int count, SocketAddress remote)
    {
        if (_disposed || _interfaceUdp?.Contains(socket) != true) return;
        if (count >= 20 && BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(4)) == StunCookie)
            OnStunResponse(buffer, count, socket, remote);
        else if (_options.EnableDirectUdp && count >= HeaderSize && buffer[0] is >= (byte)FrameType.Punc and <= (byte)FrameType.Hsck)
            Dispatch(buffer.AsSpan(0, count), new Arrival(remote, socket));
    }

    private readonly struct Arrival
    {
        public readonly bool ViaRelay;
        public readonly SocketAddress? Direct;
        public readonly IPEndPoint? Relay;
        public readonly IrohRelay? Iroh;
        public readonly byte[]? IrohPeerKey;
        public readonly TcpLink? Tcp;
        public readonly IUdpSocket? UdpSocket;

        public Arrival(TcpLink tcp)
        {
            ViaRelay = false;
            Tcp = tcp;
            Direct = ToWire(tcp.Remote);
        }

        public Arrival(SocketAddress direct, IUdpSocket? udpSocket = null)
        {
            ViaRelay = false;
            Direct = direct;
            Relay = null;
            UdpSocket = udpSocket;
        }

        public Arrival(IPEndPoint relay)
        {
            ViaRelay = true;
            Direct = null;
            Relay = relay;
        }

        public Arrival(IrohRelay relay, byte[] key)
        {
            ViaRelay = true;
            Iroh = relay;
            IrohPeerKey = key;
        }
    }

    private void Dispatch(ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        FrameType type = (FrameType)frame[0];
        ConnState? c = Lookup(BinaryPrimitives.ReadUInt64LittleEndian(frame[1..]));
        if (c is not null && arrival.ViaRelay
            && c.RelayRemote?.Address.Equals(arrival.Relay?.Address) == true)
        {
            // Relay-leg liveness clock — and only traffic from the leg we SEND on may wind
            // it. With several relays, the peer keeps probing our other relayed addresses
            // too; those cross-leg arrivals proved nothing about our current leg, and
            // counting them kept dead legs looking alive (the liveness honest path below
            // then never fired, and data kept black-holing into the dead server).
            Volatile.Write(ref c.LastRelayRxTicks, Environment.TickCount64);
        }

        if (c is { BlackholeDirect: true } && !arrival.ViaRelay)
        {
            return; // test hook: the direct path to this peer is a black hole; relayed frames still pass
        }

        if (c is { DropAboveBytes: > 0 } && frame.Length > c.DropAboveBytes)
        {
            return; // test hook: a size-selective black hole — an over-MTU network, exactly
        }

        if (TraceEnabled && (type is FrameType.Data or FrameType.Punc or FrameType.Pack))
        {
            TraceLine($"recv {type} from {BinaryPrimitives.ReadUInt64LittleEndian(frame[1..]):x16} via {(arrival.ViaRelay ? "relay" : "direct")} {(c is null ? "NO-CONN" : $"state={c.State} handler={(c.Received is null ? "none" : "on")}")}");
        }

        if (c is null)
        {
            if (type != FrameType.Punc || !_options.Listen || _disposed)
            {
                return;
            }

            // Exact-length stranger gate: the punch probe is either legacy (13 B) or carries
            // the crypto handshake (77 B) — anything else is malformed. The encryption policy
            // decides which kinds of strangers may materialize a connection at all, so a
            // Required node never creates state for a plaintext scan, and no negotiation
            // happens after creation — there is no downgrade window to strip.
            bool legacy = frame.Length == HeaderSize + CryptoWire.PuncLegacyBody;
            bool crypto = frame.Length == HeaderSize + CryptoWire.PuncCryptoBody;
            if (!legacy && !crypto)
            {
                return;
            }

            if ((legacy && _options.Encryption == PinholeEncryption.Required)
                || (crypto && _options.Encryption == PinholeEncryption.Disabled))
            {
                return;
            }

            c = CreateIncoming(
                BinaryPrimitives.ReadUInt64LittleEndian(frame[1..]),
                BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]),
                arrival,
                crypto);
            if (c is null)
            {
                return; // connection table full: a stranger flood gets no more objects
            }
        }

        if (type is not (FrameType.Punc or FrameType.Pack) && !TokenOk(c, frame))
        {
            return; // post-handshake frame without the connection token: spoofed, drop it
        }

        // Everything except the handshake frames is sealed once a session exists. The frame
        // decrypts into thread-local scratch prefixed with the untouched header and token, so
        // every handler below parses one layout regardless of the session's existence.
        int wireLength = frame.Length;
        if (type is not (FrameType.Punc or FrameType.Pack or FrameType.Hsck) && c.Crypto is { } cryptoState)
        {
            if (!cryptoState.Established)
            {
                // We offered crypto (the string pinned a key); an honest peer cannot speak
                // plaintext here and its sealed frames cannot precede the PACK that carries
                // our half of the keys. This frame is hostile or reordered beyond recovery.
                cryptoState.CountRejected();
                return;
            }

            byte[] scratch = CryptoScratch();
            frame[..(HeaderSize + CryptoWire.TokenLength)].CopyTo(scratch);
            if (!cryptoState.Recv!.Open(frame, scratch.AsSpan(HeaderSize + CryptoWire.TokenLength), out int plainLen))
            {
                cryptoState.CountRejected(); // tampered, replayed, or from a bogus epoch
                return;
            }

            cryptoState.MarkPeerConfirmed(); // only a key holder can seal a frame that opens
            if (arrival.ViaRelay) RelayPathConfirmed(c, arrival);
            frame = scratch.AsSpan(0, HeaderSize + CryptoWire.TokenLength + plainLen);
        }

        switch (type)
        {
            case FrameType.Punc:
                OnPunc(c, frame, arrival);
                break;
            case FrameType.Pack:
                OnPack(c, frame, arrival);
                break;
            case FrameType.Data:
                OnData(c, frame, arrival);
                break;
            case FrameType.Ping:
                OnPing(c, frame, arrival, wireLength);
                break;
            case FrameType.Pong:
                OnPong(c, frame, arrival);
                break;
            case FrameType.Announce:
                OnAnnounce(c, frame, arrival);
                break;
            case FrameType.Predict:
                OnPrediction(c, frame, arrival);
                break;
            case FrameType.Hsck:
                OnHsck(c, frame, arrival);
                break;
            case FrameType.Bye:
                // Remove only this connection's entry: a Bye from a replaced husk must not
                // tear down the re-dial winner registered under the same peer ID.
                _conns.TryRemove(new KeyValuePair<ulong, ConnState>(c.PeerId, c));
                Transition(c, PinholeConnectionState.Closed);
                _tcp?.ClosePeer(c.PeerId, c.DirectTcp);
                c.Dead.Cancel();
                break;
        }
    }

    [ThreadStatic] private static byte[]? s_cryptoScratch;

    private static byte[] CryptoScratch() => s_cryptoScratch ??= new byte[RecvBufferSize];

    /// <summary>Post-handshake frames must prove the per-connection token the peer learned
    /// during the Punc/Pack exchange. Without it, anyone holding the connection string
    /// (which carries the peer ID but never the token) could close a session with a forged
    /// Bye or re-point its direct path with a forged Data from their own address.</summary>
    private static bool TokenOk(ConnState c, ReadOnlySpan<byte> frame) =>
        c.RemoteTokenKnown
        && frame.Length >= HeaderSize + 4
        && BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]) == c.RemoteToken;

    private void OnPunc(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        if (frame.Length is not (HeaderSize + CryptoWire.PuncLegacyBody or HeaderSize + CryptoWire.PuncCryptoBody))
        {
            return;
        }

        bool cryptoPunc = frame.Length == HeaderSize + CryptoWire.PuncCryptoBody;
        uint token = BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]);

        if (cryptoPunc && c.PinnedStaticKey is { } pinned
            && !frame.Slice(HeaderSize + CryptoWire.TokenLength + CryptoWire.EphemeralLength, CryptoWire.StaticKeyLength).SequenceEqual(pinned))
        {
            c.Crypto?.CountRejected();
            return; // an initial/reverse PUNC must honor the same pin as its PACK
        }

        ConnectionCrypto? crypto;
        lock (c.Gate)
        {
            if (!c.RemoteTokenKnown)
            {
                c.RemoteToken = token;
                c.RemoteTokenKnown = true;
            }
            else if (c.RemoteToken != token)
            {
                return; // stale frames from an older connection to the same peer ID
            }

            if (c.Crypto is not null && cryptoPunc)
            {
                // First-seen keys derive the session; a retried PUNC must repeat them exactly —
                // different keys for the same token is a stale or substituted handshake.
                ReadOnlySpan<byte> body = frame[(HeaderSize + CryptoWire.TokenLength)..];
                if (!c.Crypto.TryPeerKeys(body[..CryptoWire.EphemeralLength], body[CryptoWire.EphemeralLength..]))
                {
                    c.Crypto.CountRejected();
                    return;
                }
            }
            else if (c.Crypto is not null || cryptoPunc)
            {
                // A plaintext PUNC on a connection that offered crypto, or a crypto PUNC on a
                // plaintext one: neither is a state any honest peer produces.
                c.Crypto?.CountRejected();
                return;
            }

            crypto = c.Crypto;
        }

        // The PACK doubles as the handshake's second flight. Crypto bodies answer crypto
        // PUNCs deterministically — same keys, same confirm MAC, on every retransmission.
        if (crypto is { Established: true })
        {
            Span<byte> pack = stackalloc byte[HeaderSize + CryptoWire.PackCryptoBody];
            WriteHeader(pack, FrameType.Pack);
            BinaryPrimitives.WriteUInt32LittleEndian(pack[HeaderSize..], token);         // echo: proof we saw the PUNC
            BinaryPrimitives.WriteUInt32LittleEndian(pack[(HeaderSize + 4)..], c.Token); // ours: so the dialer can authenticate us
            crypto.MyEphPublic.CopyTo(pack[(HeaderSize + 8)..]);
            crypto.MyStaticPublic.CopyTo(pack[(HeaderSize + 8 + CryptoWire.EphemeralLength)..]);
            crypto.MyConfirm().CopyTo(pack[(HeaderSize + 8 + CryptoWire.EphemeralLength + CryptoWire.StaticKeyLength)..]);
            SendOnArrival(arrival, pack);
            if (arrival.Tcp is { } tcp) SendTcpProof(c, tcp);
            else if (!arrival.ViaRelay) SendUdpIntroductionProbe(c, arrival);
        }
        else
        {
            Span<byte> pack = stackalloc byte[HeaderSize + CryptoWire.PackLegacyBody];
            WriteHeader(pack, FrameType.Pack);
            BinaryPrimitives.WriteUInt32LittleEndian(pack[HeaderSize..], token);
            BinaryPrimitives.WriteUInt32LittleEndian(pack[(HeaderSize + 4)..], c.Token);
            SendOnArrival(arrival, pack);
        }

        if (arrival.ViaRelay)
        {
            RelayPathConfirmed(c, arrival);
        }
        else
        {
            DirectPathConfirmed(c, arrival);
        }

        if (!c.Announced)
        {
            c.Announced = true;
            AnnounceTo(c, target: arrival);
        }
    }

    private void OnPack(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        // body = [echo of our PUNC token][the responder's own token] (+ keys and confirm in v2)
        if (frame.Length < HeaderSize + CryptoWire.PackLegacyBody
            || BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]) != c.Token)
        {
            if (TraceEnabled)
            {
                TraceLine($"pack token mismatch from {BinaryPrimitives.ReadUInt64LittleEndian(frame[1..]):x16} via {(arrival.ViaRelay ? "relay" : "direct")} (wanted {c.Token:x8}, got {BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]):x8})");
            }
            return; // not an echo of our handshake token
        }

        bool cryptoPack = frame.Length == HeaderSize + CryptoWire.PackCryptoBody;
        if (!cryptoPack && frame.Length != HeaderSize + CryptoWire.PackLegacyBody)
        {
            return; // neither a legacy nor a v2 PACK
        }

        if (!cryptoPack && c.Crypto is not null)
        {
            // We dialed with a key the string vouches for; a plaintext PACK means someone
            // stripped the handshake. Fail the connection — never fall back to plaintext.
            c.Crypto.CountRejected();
            HandshakeFailed(c, "encryption was refused by the answering peer: the connection string promised a static key");
            return;
        }

        if (cryptoPack)
        {
            ReadOnlySpan<byte> body = frame[(HeaderSize + 2 * CryptoWire.TokenLength)..];
            ConnectionCrypto? crypto = c.Crypto;
            if (crypto is null)
            {
                return; // we never offered crypto; a crypto PACK is bogus
            }

            if (c.PinnedStaticKey is { } pinned && !body.Slice(CryptoWire.EphemeralLength, CryptoWire.StaticKeyLength).SequenceEqual(pinned))
            {
                // The answering key is not the key the string vouches for: a machine in the
                // middle, or a stale string. Either way the session is dead on arrival.
                crypto.CountRejected();
                HandshakeFailed(c, "peer static key does not match its connection string: possible man in the middle");
                return;
            }

            bool sendHsck;
            lock (c.Gate)
            {
                // The responder's token rides the same PACK the legacy handshake uses it for.
                c.RemoteToken = BinaryPrimitives.ReadUInt32LittleEndian(frame[(HeaderSize + CryptoWire.TokenLength)..]);
                c.RemoteTokenKnown = true;

                if (!crypto.TryPeerKeys(body[..CryptoWire.EphemeralLength], body.Slice(CryptoWire.EphemeralLength, CryptoWire.StaticKeyLength)))
                {
                    crypto.CountRejected();
                    if (TraceEnabled)
                    {
                        TraceLine($"pack key agreement failed from {c.PeerId:x16}");
                    }
                    return;
                }

                if (!crypto.VerifyPeerConfirm(body.Slice(CryptoWire.EphemeralLength + CryptoWire.StaticKeyLength, CryptoWire.ConfirmLength)))
                {
                    crypto.CountRejected();
                    HandshakeFailed(c, "handshake confirmation failed: the answering peer does not hold the advertised key");
                    return;
                }

                crypto.MarkPeerConfirmed();
                sendHsck = !c.HsckSent;
                c.HsckSent = true;
            }

            // Third flight: our confirm back, which also asks the responder to re-announce
            // (its first sealed announce may have arrived before we could open it).
            if (sendHsck)
            {
                Span<byte> hsck = stackalloc byte[HeaderSize + CryptoWire.HsckBody];
                WriteHeader(hsck, FrameType.Hsck);
                BinaryPrimitives.WriteUInt32LittleEndian(hsck[HeaderSize..], c.Token);
                crypto.MyConfirm().CopyTo(hsck[(HeaderSize + CryptoWire.TokenLength)..]);
                SendOnArrival(arrival, hsck);
            }
            if (arrival.Tcp is { } tcp) SendTcpProof(c, tcp);
            else if (!arrival.ViaRelay) SendUdpIntroductionProbe(c, arrival);
        }
        else
        {
            lock (c.Gate)
            {
                c.RemoteToken = BinaryPrimitives.ReadUInt32LittleEndian(frame[(HeaderSize + 4)..]);
                c.RemoteTokenKnown = true;
            }
        }

        if (arrival.ViaRelay)
        {
            RelayPathConfirmed(c, arrival);
        }
        else
        {
            // A crypto PACK that verified its confirm MAC is authenticated evidence: the
            // answering peer proved possession of the key inside this very frame. The
            // sealed-evidence gate exists to stop UNauthenticated frames from promoting a
            // path, not to demand a sealed envelope from a peer still holding the
            // handshake's plaintext flights.
            DirectPathConfirmed(c, arrival, sealedEvidence: cryptoPack && c.Crypto is not null);
        }

        if (!c.Announced)
        {
            c.Announced = true;
            AnnounceTo(c, target: arrival);
        }
    }

    private void OnHsck(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        if (frame.Length != HeaderSize + CryptoWire.HsckBody)
        {
            return;
        }

        lock (c.Gate)
        {
            if (c.Crypto is not { Established: true } crypto)
            {
                return;
            }

            if (!crypto.VerifyPeerConfirm(frame[(HeaderSize + CryptoWire.TokenLength)..]))
            {
                crypto.CountRejected();
                return;
            }

            crypto.MarkPeerConfirmed();
        }

        if (arrival.Tcp is { } tcp) SendTcpProof(c, tcp);

        if (arrival.ViaRelay) RelayPathConfirmed(c, arrival);
        else if (arrival.Tcp is null) SendUdpIntroductionProbe(c, arrival);

        // The dialer heard our PACK — re-announce, in case the first sealed announce lost
        // the race against the PACK that delivered our half of the keys.
        AnnounceTo(c, target: arrival);
    }

    /// <summary>The crypto handshake is unrecoverably broken (stripped, substituted, or
    /// unconfirmed by a peer whose string vouches for a key). The connection dies honestly
    /// instead of limping on in plaintext.</summary>
    private void HandshakeFailed(ConnState c, string reason)
    {
        if (c.State is PinholeConnectionState.Closed)
        {
            return;
        }

        c.Connected.TrySetException(new InvalidOperationException(reason));
        Telemetry.ConnectionRefused(reason);
        Transition(c, PinholeConnectionState.Dead);
        c.Dead.Cancel();
    }

    private void OnData(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        if (frame.Length < HeaderSize + 4 + 1)
        {
            return;
        }

        if (_options.RelaySignalingOnly && arrival.ViaRelay)
        {
            Interlocked.Increment(ref c.RelayedDatagramsBlocked);
            return; // authenticated application data on a forbidden transport is still forbidden
        }

        // Any valid frame from the peer is proof of a live path, and its source address is
        // the newest truth about where the peer lives (last-wins by peer ID — roaming).
        if (arrival.ViaRelay)
        {
            RelayPathConfirmed(c, arrival);
        }
        else
        {
            DirectPathConfirmed(c, arrival, sealedEvidence: true);
        }

        Interlocked.Increment(ref c.ReceivedCount);
        Interlocked.Add(ref c.BytesReceived, frame.Length - HeaderSize - 4);
        // Buffered mode queues first (the queue exists from handshake time), then the
        // zero-copy event path fires for anyone still subscribed.
        c.Buffer?.Enqueue(frame[(HeaderSize + 4)..]);
        c.Received?.Invoke(frame[(HeaderSize + 4)..]);
    }

    private void OnPing(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival, int wireLength)
    {
        if (frame.Length < HeaderSize + 4 + 8)
        {
            return;
        }

        if (!arrival.ViaRelay && c.AwaitInitialCandidateExchange && !Volatile.Read(ref c.PeerCandidatesReceived)) return;

        if (!arrival.ViaRelay)
        {
            if (arrival.Tcp is { } tcp)
            {
                if (tcp.AuthenticatedPeer == 0 && frame.Length >= HeaderSize + CryptoWire.TokenLength + 8)
                    tcp.ObserveChallenge(BinaryPrimitives.ReadInt64LittleEndian(frame[(HeaderSize + CryptoWire.TokenLength)..]));
                SendTcpProof(c, tcp);
            }
            DirectPathConfirmed(c, arrival, sealedEvidence: true);
            // Inbound evidence cuts both ways: a datagram this size arrived, so the path
            // carries it. Cap at the probe ceiling — this only ever replaces a probe, and
            // keeps buffer sizing honest on loopback's 64k MTU.
            // The decrypted handler view excludes the AES-GCM counter/tag. MTU evidence
            // must use the received wire size and never lower the guaranteed payload floor.
            if (arrival.Tcp is null && _options.EnablePmtud && wireLength >= PmtuBaseWire)
            {
                lock (c.Gate)
                {
                    int ceiling = PmtuCeilingLocked(c);
                    if (wireLength > c.PmtuWire && wireLength <= ceiling)
                        c.PmtuWire = wireLength;
                }
            }
        }

        Span<byte> pong = stackalloc byte[HeaderSize + CryptoWire.TokenLength + 8 + CryptoWire.SealedOverhead];
        int len = BuildFrame(c, FrameType.Pong, frame.Slice(HeaderSize + 4, 8), pong);
        SendOnArrival(arrival, pong[..len]);
    }

    private void OnPong(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        if (frame.Length < HeaderSize + 4 + 8)
        {
            return;
        }

        long echoed = BitConverter.ToInt64(frame[(HeaderSize + 4)..]);
        if (arrival.Tcp is { } stream && stream.AuthenticatedPeer != c.PeerId)
        {
            if (stream.ConfirmProof(c.PeerId, echoed))
            {
                DirectPathConfirmed(c, arrival, sealedEvidence: true);
                if (ReferenceEquals(c.DirectTcp, stream))
                {
                    AnnounceTo(c);
                    KickPunch(c); // bounded UDP upgrade attempts while TCP carries the data
                }
                else stream.CloseGracefully();
            }
            return; // transport challenges are not application pings or RTT samples
        }
        if (echoed < 0)
        {
            // Maintenance probe reply: it certifies the direct path only when it matches
            // the outstanding probe's nonce AND arrives from the endpoint that probe was
            // sent to (ProbeTarget, snapshotted at send time — DirectRemote may since have
            // been re-pointed by the peer's own frames). A caller ping's pong, relayed
            // traffic, or a reply from anywhere else counts for nothing.
            lock (c.Gate)
            {
                if (c.ProbeOutstanding && c.ProbeNonce == echoed
                    && !arrival.ViaRelay && ReferenceEquals(arrival.Tcp, c.ProbeTcp)
                    && ReferenceEquals(arrival.UdpSocket, c.ProbeUdpSocket) && SameEndPoint(arrival.Direct, c.ProbeTarget))
                {
                    c.ProbeOutstanding = false;
                    c.ProbeTarget = null;
                    c.UnansweredProbes = 0;
                    Interlocked.Increment(ref c.PathProbeReplies);
                }
            }

            if (!arrival.ViaRelay && arrival.Direct is { } direct)
            {
                DirectPathConfirmed(c, arrival, sealedEvidence: true);
            }

            return;
        }

        if ((echoed & PmtuProbeMarker) != 0)
        {
            // A PMTUD probe's pong: confirm the probe size only when the nonce matches the
            // outstanding probe AND the reply came from the endpoint it was sent to — the
            // same discipline path probes apply, for the same reason.
            lock (c.Gate)
            {
                if (c.PmtuOutstanding && c.PmtuProbeNonce == echoed
                    && !arrival.ViaRelay && arrival.Tcp is null && ReferenceEquals(arrival.UdpSocket, c.PmtuProbeUdpSocket)
                    && SameEndPoint(arrival.Direct, c.PmtuProbeTarget))
                {
                    c.PmtuOutstanding = false;
                    if (c.PmtuProbeSize > c.PmtuWire)
                    {
                        c.PmtuWire = c.PmtuProbeSize;
                        c.PmtuVerifiedSize = false; // the new size earns its own re-verification later
                    }
                    else
                    {
                        c.PmtuVerifiedSize = true; // the confirmed size re-verified; keep climbing
                    }

                    c.PmtuNextProbeTicks = 0; // climb again on the next tick
                }
            }

            if (!arrival.ViaRelay && arrival.Direct is { } pmtuDirect)
            {
                DirectPathConfirmed(c, arrival, sealedEvidence: true); // a confirmed probe is path liveness too
            }

            return;
        }

        if (!arrival.ViaRelay && arrival.Direct is { } callerDirect)
        {
            DirectPathConfirmed(c, arrival, sealedEvidence: true); // an answered caller ping is direct-path activity too
        }

        long rttTicks = (Environment.TickCount64 - echoed) * TimeSpan.TicksPerMillisecond;
        Interlocked.Exchange(ref c.LastRttTicks, rttTicks);
        Interlocked.Increment(ref c.PongsReceived);
        lock (c.Gate)
        {
            c.RttEwmaTicks = c.RttEwmaTicks == 0 ? rttTicks : c.RttEwmaTicks + 0.25 * (rttTicks - c.RttEwmaTicks);
        }
    }

    private void OnAnnounce(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        if (frame.Length <= HeaderSize + 4)
        {
            return;
        }

        byte[] body = frame[(HeaderSize + 4)..].ToArray();
        List<PinholeCandidate> fresh = new();
        bool hasNewDirect;
        bool firstCandidates;
        try
        {
            var reader = new CandidateCodec.Reader(body, 0);
            byte count = reader.ReadByte();
            fresh.EnsureCapacity(count);
            if (count > ConnectionString.MaxCandidates) return;
            for (int i = 0; i < count; i++)
            {
                fresh.Add(CandidateCodec.Read(ref reader));
            }

            if (!reader.AtEnd) return;

            lock (_gate)
            {
                hasNewDirect = fresh.Any(candidate => candidate.Kind is CandidateKind.Direct or CandidateKind.Reflexive
                    && !c.PeerCandidates.Any(old => old.Kind == candidate.Kind && old.Address.Equals(candidate.Address)));
                c.PeerCandidates.Clear();
                c.PeerCandidates.AddRange(fresh);
            }
            lock (c.Gate)
            {
                firstCandidates = !c.PeerCandidatesReceived;
                c.PeerCandidatesReceived = true;
            }
        }
        catch (FormatException)
        {
            return;
        }

        // A peer advertising a TURN candidate is telling us which server it relays through.
        // Permitting that server's IP on our own allocations is what lets its frames reach
        // us on strict TURN servers — the receive-side permission this peer cannot create
        // for us any other way. Best-effort and fire-and-forget: the permit costs one
        // datagram per server and races nothing.
        foreach (PinholeCandidate relay in fresh.Where(x => x.Kind == CandidateKind.Relay))
        {
            _ = PermitPeerRelayServerAsync(relay);
        }

        if (!arrival.ViaRelay)
        {
            DirectPathConfirmed(c, arrival, sealedEvidence: true);
        }

        if (c.State is PinholeConnectionState.Punching or PinholeConnectionState.Dead
            && (!_options.RelaySignalingOnly || firstCandidates || hasNewDirect)
            || (c.State == PinholeConnectionState.Degraded || c.State == PinholeConnectionState.Open && c.DirectTcp is not null) && hasNewDirect)
        {
            KickPunch(c); // the peer just told us where it now lives
        }
    }

    private void SendOnArrival(in Arrival arrival, ReadOnlySpan<byte> frame)
    {
        try
        {
            if (arrival.Tcp is { } tcp)
            {
                if (!tcp.Send(frame)) throw new SocketException((int)SocketError.NoBufferSpaceAvailable);
            }
            else if (arrival.Iroh is { } iro && arrival.IrohPeerKey is { } key)
            {
                iro.Send(key, frame);
            }
            else if (arrival.ViaRelay)
            {
                SendViaRelayTo(frame, arrival.Relay!);
            }
            else if (arrival.Direct is { } direct)
            {
                if (arrival.UdpSocket is { } socket) socket.SendTo(frame, direct);
                else SendToWire(direct, frame);
            }
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
        {
            // The reply path was momentary; its loss costs one frame, nothing more.
        }
    }

    private void SendUdpIntroductionProbe(ConnState c, in Arrival arrival)
    {
        if (c.Crypto is not { Established: true }) return;
        if (c.AwaitInitialCandidateExchange && !Volatile.Read(ref c.PeerCandidatesReceived)) return;
        Span<byte> payload = stackalloc byte[8];
        RandomNumberGenerator.Fill(payload);
        // A transport-control nonce uses the maintenance marker, so its pong is
        // authenticated evidence without manufacturing an application RTT sample.
        BinaryPrimitives.WriteInt64LittleEndian(payload, BinaryPrimitives.ReadInt64LittleEndian(payload) | ProbeMarker);
        Span<byte> frame = stackalloc byte[PmtuBaseWire];
        int length = BuildFloorPing(c, payload, frame);
        SendOnArrival(arrival, frame[..length]);
    }

    /// <summary>Builds a Ping padded to the guaranteed wire floor. Peers size their
    /// path MTU from inbound Ping frames; a sub-floor Ping would shrink a legacy
    /// peer's payload budget below zero (its ceiling arithmetic has no floor once a
    /// Ping has been seen). The leading bytes carry the nonce/timestamp; the padding
    /// behind them stays zero — the same shape <see cref="SendPmtuProbe"/> uses.</summary>
    private int BuildFloorPing(ConnState c, ReadOnlySpan<byte> leading, Span<byte> frame)
    {
        Span<byte> body = stackalloc byte[PmtuBaseWire - PmtuOverhead];
        leading.CopyTo(body);
        body[leading.Length..].Clear();
        return BuildFrame(c, FrameType.Ping, body, frame);
    }

    private void AnnounceTo(ConnState c, bool blast = false, Arrival? target = null)
    {
        if (_options.RelaySignalingOnly && (c.State == PinholeConnectionState.Closed || c.Crypto is not { Established: true })) return;
        Volatile.Write(ref c.LastCandidateAnnouncement, Environment.TickCount64);
        IReadOnlyList<PinholeCandidate> candidates = LocalCandidatesSnapshot();
        var payload = new MemoryStream(32 + candidates.Count * 32);
        payload.WriteByte((byte)candidates.Count);
        foreach (PinholeCandidate candidate in candidates)
        {
            try
            {
                CandidateCodec.Write(payload, candidate);
            }
            catch (InvalidOperationException)
            {
                payload.SetLength(0); // a malformed candidate list must not kill the announce
                payload.WriteByte(0);
                break;
            }
        }

        byte[] body = payload.GetBuffer();
        int bodyLen = (int)payload.Length;

        // Announce frames are sealed like everything else post-handshake; the biggest legal
        // one (32 fat relay candidates) needs the rented path rather than the stack.
        int cap = HeaderSize + CryptoWire.TokenLength + bodyLen + CryptoWire.SealedOverhead;
        if (cap <= 1024)
        {
            Span<byte> frame = stackalloc byte[cap];
            int len = BuildFrame(c, FrameType.Announce, body.AsSpan(0, bodyLen), frame);
            AnnounceSend(c, frame[..len], blast, target);
            return;
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(cap);
        try
        {
            int len = BuildFrame(c, FrameType.Announce, body.AsSpan(0, bodyLen), rented.AsSpan(0, cap));
            AnnounceSend(c, rented.AsSpan(0, len), blast, target);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private void AnnounceSend(ConnState c, ReadOnlySpan<byte> frame, bool blast, Arrival? sendOn)
    {
        if (blast)
        {
            // Right after a rebind no path is confirmed live, but the PEER's own addresses
            // are still valid targets: the announce carries our new candidates to wherever
            // the peer currently is, and its reply frames teach us the newest path back.
            SendOnArrival(CurrentArrival(c), frame);
            PinholeCandidate[] targets;
            lock (_gate)
            {
                targets = c.PeerCandidates.ToArray();
            }

            foreach (PinholeCandidate target in targets)
            {
                if (target.Kind == CandidateKind.IrohRelay)
                {
                    SendViaIroh(frame, target);
                }
                else if (target.Kind == CandidateKind.Relay)
                {
                    try
                    {
                        SendViaRelayTo(frame, target.Address, target.RelayServer?.Address);
                    }
                    catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
                    {
                        // Right after a rebind the relay slots are cold; the announce must
                        // still reach the direct candidates rather than abort the recovery.
                    }
                }
                else
                {
                    try
                    {
                        SendToWire(target.Address, frame);
                    }
                    catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                    {
                    }
                }
            }

            return;
        }

        SendOnArrival(sendOn ?? CurrentArrival(c), frame);
    }

    private Arrival CurrentArrival(ConnState c)
    {
        if (c.Path == PathKind.Direct && c.DirectRemote is { } sa)
        {
            if (c.DirectTcp is { } tcp) return new Arrival(tcp);
            return new Arrival(sa, c.DirectUdpSocket);
        }

        if (c.Iroh is { IsAlive: true } iro && c.IrohConfirmed && c.IrohPeerKey is { } key)
            return new Arrival(iro, key);
        return c.RelayRemote is { } ep ? new Arrival(ep) : default;
    }

    // ------------------------------------------------------------------ paths & state

    // PINHOLE_TRACE=1 logs every direct-path adoption change — debugging aid for NAT
    // hairpin mysteries; compiled out of the hot path when unset. PINHOLE_TRACE_FILE=<path>
    // mirrors the lines to a file (xunit swallows console output from engine threads).
    private static readonly bool TraceEnabled = Environment.GetEnvironmentVariable("PINHOLE_TRACE") == "1"
        || Environment.GetEnvironmentVariable("PINHOLE_TRACE_FILE") is { Length: > 0 };

    private static readonly object TraceGate = new();

    private static void TraceLine(string line)
    {
        Console.WriteLine("[pinhole] " + line);
        if (Environment.GetEnvironmentVariable("PINHOLE_TRACE_FILE") is { Length: > 0 } path)
        {
            try
            {
                lock (TraceGate)
                {
                    File.AppendAllText(path, $"[{DateTimeOffset.UtcNow:HH:mm:ss.fff}] [pid {Environment.ProcessId}] {line}\n");
                }
            }
            catch (IOException)
            {
            }
        }
    }

    private void TracePath(ConnState c, SocketAddress source)
    {
        if (!TraceEnabled)
        {
            return;
        }

        IPEndPoint next = ToEndpoint(source);
        TraceLine($"peer {c.PeerId:x16} path -> {next} (was {c.DirectRemoteEp}, state {c.State}/{c.Path})");
    }

    private void DirectPathConfirmed(ConnState c, in Arrival arrival, bool sealedEvidence = false)
    {
        SocketAddress source = arrival.Direct!;
        lock (c.Gate)
        {
            if (c.State == PinholeConnectionState.Closed || c.BlackholeDirect)
            {
                return; // test hook: this direct path is dead; nothing can confirm it
            }

            if (c.Crypto is not null && (!c.Crypto.PeerConfirmed || arrival.Tcp is null && !sealedEvidence)) return;
            if (c.AwaitInitialCandidateExchange && !Volatile.Read(ref c.PeerCandidatesReceived)) return;

            if (arrival.Tcp is { } tcp)
            {
                if (c.Crypto is not { PeerConfirmed: true } || tcp.AuthenticatedPeer != c.PeerId || !tcp.IsReady) return;
                if (c.Path == PathKind.Direct && c.DirectTcp is null && c.DirectRemote is not null
                    && Environment.TickCount64 - c.LastDirectRxTicks < _options.PathValidationIdle.TotalMilliseconds) return;
                if (c.Path == PathKind.Direct && c.DirectTcp is { IsReady: true } current && !ReferenceEquals(current, tcp)
                    && Environment.TickCount64 - c.LastDirectRxTicks < _options.PathValidationIdle.TotalMilliseconds
                    && !tcp.PreferredTo(current, preferInitiator: _peerId < c.PeerId)) return;
            }

            if (c.State == PinholeConnectionState.Open && c.Path == PathKind.Direct
                && ReferenceEquals(c.DirectTcp, arrival.Tcp) && SameEndPoint(c.DirectRemote, source)
                && ReferenceEquals(c.DirectUdpSocket, arrival.UdpSocket))
            {
                // Fast path, taken for every ordinary datagram: the endpoint is already the
                // connection's truth, so the frame only refreshes direct-path activity.
                Volatile.Write(ref c.LastDirectRxTicks, Environment.TickCount64);
                return;
            }

            // A restored UDP path can have exactly the same address as before its
            // outage. It must still promote a relay-carried or pending session to Open.

            // The receive loop reuses its scratch SocketAddress; an adopted endpoint must be
            // private to the connection. Cloning only on change keeps the per-datagram
            // receive path allocation-free while endpoint churn still pays one copy.
            SocketAddress adopted = Clone(source);
            TracePath(c, adopted);
            c.DirectRemote = adopted;
            c.DirectRemoteEp = ToEndpoint(adopted);
            bool transportChanged = !ReferenceEquals(c.DirectTcp, arrival.Tcp) || !ReferenceEquals(c.DirectUdpSocket, arrival.UdpSocket);
            TcpLink? previousTcp = c.DirectTcp;
            c.DirectTcp = arrival.Tcp;
            c.DirectUdpSocket = arrival.UdpSocket;
            if (transportChanged) previousTcp?.CloseGracefully();
            if (c.IsIncoming && !c.IncomingQueued)
            {
                c.IncomingQueued = true;
                _incoming?.Writer.TryWrite(c);
            }
            Volatile.Write(ref c.LastDirectRxTicks, Environment.TickCount64);
            // Migration: the endpoint changed (roam, family switch), so the confirmed MTU
            // belongs to the OLD path. Forget it and re-climb — a v6 path's plateau and a
            // freshly-engaged VPN's overhead say so independently.
            if (c.PmtuWire != 0 || c.PmtuOutstanding)
            {
                c.PmtuWire = 0;
                c.PmtuOutstanding = false;
                c.PmtuVerifiedSize = false;
                c.PmtuNextProbeTicks = 0;
            }

            if (c.Connected.Task.IsFaulted)
            {
                return; // the dial faulted (pin mismatch, refused handshake): this husk is not revivable
            }

            if (c.State != PinholeConnectionState.Open)
            {
                c.State = PinholeConnectionState.Open;
                c.Path = PathKind.Direct;
                c.PathSince = DateTimeOffset.UtcNow;
                Interlocked.Exchange(ref c.ConsecutiveSendFailures, 0);
                ResetPathProbesNoLock(c);
                c.Connected.TrySetResult();
                c.StateChanged?.Invoke(c.State);
            }
            else if (c.Path != PathKind.Direct)
            {
                // A direct frame while relayed: newest-path-wins migration.
                c.Path = PathKind.Direct;
                c.PathSince = DateTimeOffset.UtcNow;
                ResetPathProbesNoLock(c);
                c.StateChanged?.Invoke(c.State);
            }
            else if (transportChanged)
            {
                c.PathSince = DateTimeOffset.UtcNow;
                ResetPathProbesNoLock(c);
                c.StateChanged?.Invoke(c.State);
            }
        }
    }

    private void RelayPathConfirmed(ConnState c, in Arrival arrival)
    {
        if (arrival.Iroh is not { } relay)
        {
            RelayPathConfirmed(c, arrival.Relay!);
            return;
        }

        bool kick = false;
        lock (c.Gate)
        {
            if (c.State == PinholeConnectionState.Closed || c.Connected.Task.IsFaulted) return;
            c.Iroh = relay;
            c.IrohPeerKey = arrival.IrohPeerKey;
            c.IrohConfirmed = true;
            if (!_options.RelaySignalingOnly && (c.Crypto is null || c.Crypto.PeerConfirmed)
                && c.State is PinholeConnectionState.Punching or PinholeConnectionState.Dead)
            {
                c.State = PinholeConnectionState.Degraded;
                c.Path = PathKind.Relay;
                c.PathSince = DateTimeOffset.UtcNow;
                if (c.IsIncoming && !c.IncomingQueued)
                { c.IncomingQueued = true; _incoming?.Writer.TryWrite(c); }
                c.Connected.TrySetResult();
                c.StateChanged?.Invoke(c.State);
                kick = true;
            }
        }
        if (kick) KickPunch(c);
    }

    private void RelayPathConfirmed(ConnState c, IPEndPoint peerRelayed)
    {
        lock (c.Gate)
        {
            if (c.State == PinholeConnectionState.Closed)
            {
                return;
            }

            // Leg hysteresis: a confirmed relay leg is never demoted by the peer's OTHER
            // legs. With two relays configured, both sides punch both of the peer's relayed
            // addresses, and every cross-leg arrival used to flip RelayReady off and force a
            // permission round trip — a livelock in which data sends never found the leg
            // ready. Arrivals still count as relay traffic (the dispatch stamp) whatever leg
            // they rode; the leg only changes when it actually fails and path validation
            // suspects it.
            if (c.RelayReady)
            {
                // The permit already exists (dial-time warm-up counts), but promotion needs
                // PeerConfirmed — which may only have arrived NOW, with this relayed frame.
                // Re-run the promotion check; a pre-warmed leg must not wedge a Punching
                // connection that completed its handshake after the permit landed.
                PromoteRelayLegNoLock(c);
                return;
            }

            if (Interlocked.CompareExchange(ref c.PermitInFlight, 1, 0) != 0)
            {
                return;
            }

            c.RelayRemote = peerRelayed;
            // Single-flight: a relayed frame burst must not spawn one permission round
            // trip per frame or replace its target while the first is still in the air.
        }

        _ = PermitRelayAsync(c, peerRelayed);
    }

    /// <summary>Relay-leg promotion, under the connection gate. The leg is proven usable
    /// (permitted) and the peer cryptographically confirmed; a Punching or Dead session
    /// becomes Degraded and hands its awaiter the connection. Callers re-run this whenever
    /// either fact arrives second — the permit may pre-date the handshake, or the
    /// handshake the permit.</summary>
    private void PromoteRelayLegNoLock(ConnState c)
    {
        if (!_options.RelaySignalingOnly && (c.Crypto is null || c.Crypto.PeerConfirmed)
            && c.State is PinholeConnectionState.Punching or PinholeConnectionState.Dead)
        {
            c.State = PinholeConnectionState.Degraded;
            c.Path = PathKind.Relay;
            c.PathSince = DateTimeOffset.UtcNow;
            if (c.IsIncoming && !c.IncomingQueued)
            { c.IncomingQueued = true; _incoming?.Writer.TryWrite(c); }
            c.Connected.TrySetResult();
            c.StateChanged?.Invoke(c.State);
            KickPunch(c); // relay is confirmed usable; direct upgrade probing continues
        }
    }

    private async Task PermitRelayAsync(ConnState c, IPEndPoint peer)
    {
        try
        {
            await EnsureRelaysAsync(CancellationToken.None).ConfigureAwait(false);
            foreach (TurnClient client in AliveRelayClients())
            {
                if (!await TryPermitAsync(client, peer.Address, CancellationToken.None).ConfigureAwait(false))
                {
                    if (TraceEnabled)
                    {
                        TraceLine($"permit failed for {c.PeerId:x16} toward {peer} (clients {AliveRelayClients().Count})");
                    }
                    return; // the slot was retired; the reconnect's fresh permit finishes this
                }
            }

            lock (c.Gate)
            {
                if (c.RelayRemote is { } current && !current.Address.Equals(peer.Address))
                {
                    return; // a newer relay address superseded this permit mid-flight
                }

                c.RelayReady = true;
                Telemetry.Recovery("relay-heal");
                if (c.State == PinholeConnectionState.Closed) return;
                PromoteRelayLegNoLock(c); // no-op unless the handshake has confirmed the peer
            }

            if (_options.RelaySignalingOnly) AnnounceTo(c);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or InvalidOperationException or TimeoutException or ObjectDisposedException)
        {
            // The permission round trip failed; the next relayed frame will retry.
        }
        finally
        {
            Volatile.Write(ref c.PermitInFlight, 0);
        }
    }

    /// <summary>One permission round trip with the evidence discipline the relay-recovery
    /// review requires: a <see cref="Turn.TurnRejectException"/> is the server itself
    /// refusing (allocation gone, credentials refused) — retire the client and reallocate
    /// immediately, because a restarted relay otherwise leaves a ghost allocation
    /// black-holing traffic until the minutes-long refresh cadence notices. Everything
    /// else — a timeout, a transport fault — proves nothing: one lost UDP request must not
    /// flap a healthy allocation, so it is retried a few times and then abandoned to the
    /// next trigger, never retired.</summary>
    private async Task<bool> TryPermitAsync(TurnClient client, IPAddress peer, CancellationToken ct)
    {
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                await client.CreatePermissionAsync(peer, ct).ConfigureAwait(false);
                return true;
            }
            catch (TurnRejectException)
            {
                await RetireRelayClientAsync(client).ConfigureAwait(false);
                return false;
            }
            catch (Exception ex) when (attempt < 4
                && ex is SocketException or TimeoutException or ObjectDisposedException or InvalidOperationException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250), ct).ConfigureAwait(false);
            }
        }
    }

    private async Task RetireRelayClientAsync(TurnClient client)
    {
        Telemetry.Recovery("relay-retire");
        client.Received -= HandleRelayData;
        _ = client.DisposeAsync();
        lock (_gate)
        {
            foreach (RelaySlot slot in _relays)
            {
                if (ReferenceEquals(slot.Client, client))
                {
                    slot.Client = null; // NextRetry stays: a live server reconnects immediately
                }
            }
        }

        await EnsureRelaysAsync(CancellationToken.None).ConfigureAwait(false);
        Telemetry.Recovery("relay-reallocate");
    }

    /// <summary>The path looks dead (send errors or a simulated failure): re-punch toward the
    /// known candidates; a usable relay keeps the session alive as Degraded.</summary>
    public void NotifyPathSuspect(ConnState c)
    {
        lock (c.Gate)
        {
            if (c.State is not (PinholeConnectionState.Open or PinholeConnectionState.Degraded))
            {
                return;
            }

            if (c.State == PinholeConnectionState.Open)
            {
                if (!_options.RelaySignalingOnly && ((c.Iroh is { IsAlive: true } && c.IrohConfirmed) || (c.RelayRemote is not null && c.RelayReady)))
                {
                    c.State = PinholeConnectionState.Degraded;
                    c.Path = PathKind.Relay;
                }
                else
                {
                    c.State = PinholeConnectionState.Punching;
                    c.Path = PathKind.None;
                }

                c.StateChanged?.Invoke(c.State);
            }
            else if (c.Iroh is not { IsAlive: true } && !(c.RelayRemote is not null && c.RelayReady))
            {
                c.State = PinholeConnectionState.Punching;
                c.Path = PathKind.None;
                c.StateChanged?.Invoke(c.State);
            }
        }

        KickPunch(c);
        Telemetry.Recovery("path-suspect");

        // A suspect relay path re-validates its allocation: the permit round trip either
        // confirms the relay leg or (TryPermitAsync) retires a ghost client — a restarted
        // relay's stale allocation — and reallocates, instead of waiting out the
        // minutes-long refresh cadence while every relayed frame black-holes.
        if (c.RelayRemote is { } relayPeer && Interlocked.CompareExchange(ref c.PermitInFlight, 1, 0) == 0)
        {
            _ = PermitRelayAsync(c, relayPeer);
        }

        // And when the ticket pinned the peer's endpoint key, the lookup providers may know
        // where the peer moved to (both allocations changed, both old addresses dead): fetch
        // its current signed record and fold any verified endpoint into this dial's punch.
        if (c.PinnedEndpointKey is { } pinned && _lookup.Count > 0)
        {
            _ = ResolveViaLookupAsync(c, pinned, CancellationToken.None);
        }
    }

    private void Transition(ConnState c, PinholeConnectionState state)
    {
        lock (c.Gate)
        {
            if (c.State == PinholeConnectionState.Closed)
            {
                return;
            }

            c.State = state;
            if (state == PinholeConnectionState.Closed)
            {
                c.Path = PathKind.None;
                c.Closed.TrySetResult();
                c.Buffer?.Complete(); // readers drain what is buffered, then see EOF
            }

            c.StateChanged?.Invoke(state);
        }
    }

    // ------------------------------------------------------------------ roaming

    /// <summary>Re-probes the world and, when the socket's network is gone, rebinds the
    /// socket, re-allocates the relays, and re-announces to every peer. Connection objects
    /// survive the whole maneuver. A single lost STUN probe proves nothing (servers
    /// rate-limit); every configured server must go silent before a rebind happens.</summary>
    public async Task RecoverAsync(bool forceRebind, CancellationToken ct)
    {
        if (_disposed || Interlocked.Exchange(ref _recovering, 1) != 0)
        {
            return;
        }

        try
        {
            RefreshInterfaceCandidates();
            RefreshIPv6Firewall(); // interface changes matter even if the STUN mapping stayed the same
            IReadOnlyList<IPEndPoint> stunServers = ResolvedStun();
            bool needRebind = forceRebind;

            if (!needRebind && stunServers.Count > 0)
            {
                IPEndPoint? probe = null;
                foreach (IPEndPoint server in stunServers.Take(3))
                {
                    probe = await TryProbe(server, ct).ConfigureAwait(false);
                    if (probe is not null)
                    {
                        break;
                    }
                }

                if (probe is not null)
                {
                    lock (_gate)
                    {
                        if (_reflexive.Contains(probe))
                        {
                            return; // the mapping did not move; nothing to do
                        }

                        _reflexive.Add(probe);
                    }

                    RefreshLocalCandidates();
                    ReannounceAndRepunch();
                    return;
                }

                needRebind = true; // every STUN server silent: the socket's network is gone
            }

            if (needRebind)
            {
                await RebindAsync(ct).ConfigureAwait(false);
            }
        }
        finally
        {
            Volatile.Write(ref _recovering, 0);
        }
    }

    private async Task RebindAsync(CancellationToken ct)
    {
        Telemetry.Recovery("rebind");
        IUdpSocket old;
        IUdpSocket fresh;
        lock (_gate)
        {
            old = _udp;
            fresh = CreateSocket(_options.Bind);
            _udp = fresh;
        }

        StartRecvLoop();
        old.Dispose();
        _tcp?.Rebind(new IPEndPoint(_options.Bind?.Address ?? IPAddress.IPv6Any, LocalPort));

        List<TurnClient> oldClients;
        lock (_gate)
        {
            oldClients = _relays.Select(r => r.Client).Where(c => c is not null).Cast<TurnClient>().ToList();
            foreach (RelaySlot slot in _relays)
            {
                slot.Client = null;
                slot.NextRetry = DateTimeOffset.MinValue;
            }

            _reflexive.Clear();
            _mappedEndpoint = null; // the mapping points at the old port; rediscovery targets the new one
            _mappedTcpEndpoint = null;
        }

        foreach (TurnClient client in oldClients)
        {
            client.Received -= HandleRelayData;
            _ = client.DisposeAsync();
        }

        _portMap?.Rebind(_udp.LocalEndPoint.Port); // LocalPort takes _gate; we hold none here
        _tcpPortMap?.Rebind(_tcp?.ListeningPort ?? 0);
        RefreshInterfaceCandidates(invalidate: true);
        RefreshIPv6Firewall(invalidate: true);
        await Task.WhenAll(ProbeStunAllAsync(ct), EnsureRelaysAsync(ct), EnsureIrohRelaysAsync(ct)).ConfigureAwait(false);
        RefreshLocalCandidates();
        ReannounceAndRepunch();
    }

    private void ReannounceAndRepunch()
    {
        foreach (ConnState c in ConnectionsSnapshot())
        {
            if (c.State == PinholeConnectionState.Closed)
            {
                continue;
            }

            lock (c.Gate)
            {
                c.DirectRemote = null; // the old direct path is invalid after a rebind
                c.DirectRemoteEp = null;
                if (c.State == PinholeConnectionState.Open)
                {
                    bool relayed = c.Iroh is { IsAlive: true } && c.IrohConfirmed;
                    c.State = relayed ? PinholeConnectionState.Degraded : PinholeConnectionState.Punching;
                    c.Path = relayed ? PathKind.Relay : PathKind.None;
                    c.StateChanged?.Invoke(c.State);
                }
            }

            if (c.RelayRemote is not null)
            {
                // The peer's relayed address survives the rebind; re-prove it usable.
                c.RelayReady = false;
                _ = PermitRelayAsync(c, c.RelayRemote);
            }

            AnnounceTo(c, blast: true);
            KickPunch(c);
        }
    }

    // ------------------------------------------------------------------ test hooks

    internal Task SimulateInterfaceLossAsync() => RecoverAsync(forceRebind: true, CancellationToken.None);

    /// <summary>Test/diagnostic accessor: each managed TURN slot's server and live relayed
    /// address (null when the slot has no allocation right now).</summary>
    internal IReadOnlyList<(IPEndPoint Server, IPEndPoint? Relayed)> RelayAllocations()
    {
        lock (_gate)
        {
            return _relays.Select(r => (r.Config.Server, r.Client is { IsAlive: true } c ? c.RelayedAddress : null)).ToList();
        }
    }

    /// <summary>Test/diagnostic accessor: the relayed address this node currently sends the
    /// peer's frames at, and whether that leg is confirmed usable.</summary>
    internal (IPEndPoint? Remote, bool Ready) PeerRelayLeg(ulong peerId)
    {
        lock (_gate)
        {
            return _conns.TryGetValue(peerId, out ConnState? c) ? (c.RelayRemote, c.RelayReady) : (null, false);
        }
    }

    /// <summary>Test/diagnostic accessor: how many TURN slots this node manages.</summary>
    internal int RelaysConfiguredCount
    {
        get { lock (_gate) return _relays.Count; }
    }

    /// <summary>Test hook: pretends the relay backoff ladder has expired, so a test can
    /// exercise retry behavior without waiting out the 30 s first step.</summary>
    internal void TestExpediteRelayRetry()
    {
        lock (_gate)
        {
            foreach (RelaySlot slot in _relays)
            {
                slot.NextRetry = DateTimeOffset.MinValue;
                slot.Backoff = RelayRetryBackoff;
            }
        }
    }

    /// <summary>Test hook: one relay-ensure pass right now — the same pass a path-suspect
    /// cycle, a dial, or the maintenance tick triggers, without waiting for their timers.</summary>
    internal Task ForceRelayEnsureAsync() => EnsureRelaysAsync(CancellationToken.None);

    internal void SimulateDirectPathDeath(ulong peerId)
    {
        if (Lookup(peerId) is not { } c)
        {
            return;
        }

        c.BlackholeDirect = true;
        NotifyPathSuspect(c);
    }

    /// <summary>Test hook: the direct path to this peer becomes a silent black hole — frames
    /// die in both directions with no send errors and no notifications. Exactly the failure
    /// path validation exists to detect on its own.</summary>
    internal void SimulateSilentDirectPathLoss(ulong peerId)
    {
        if (Lookup(peerId) is { } c)
        {
            c.BlackholeDirect = true;
        }
    }

    /// <summary>Test hook: the direct path works again (NAT rebind recovered, firewall rule
    /// lifted). The engine's own probing re-opens it; no notification is pushed.</summary>
    internal void SimulateDirectPathRestore(ulong peerId)
    {
        if (Lookup(peerId) is { } c)
        {
            c.BlackholeDirect = false;
        }
    }

    /// <summary>Test hook: restart the punch loop for a connection the budget gave up on.</summary>
    internal void RetryPunch(ulong peerId)
    {
        if (Lookup(peerId) is { } c)
        {
            KickPunch(c);
        }
    }

    // ------------------------------------------------------------------ dispose

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (Interlocked.CompareExchange(ref _networkWatchHooked, 0, 1) == 1)
        {
            NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
        }

        _portMap?.Shutdown(); // releases the router mapping in the background, bounded
        _tcpPortMap?.Shutdown();
        _interfaceUdp?.Dispose();
        _ipv6Firewall?.Dispose();
        _shutdown.Cancel();
        foreach (ConnState c in ConnectionsSnapshot())
        {
            _ = CloseAsync(c);
        }

        _incoming?.Writer.TryComplete();
        lock (_gate)
        {
            _udp.Dispose();
            _tcp?.Dispose();
            foreach (IrohRelay relay in _irohRelays.Values) relay.Dispose();
            foreach (RelaySlot slot in _relays)
            {
                if (slot.Client is { } client)
                {
                    client.Received -= HandleRelayData;
                    _ = client.DisposeAsync();
                }
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    private byte[] BuildPunc(ConnState c)
    {
        // The punch probe doubles as the crypto handshake's first flight: a crypto dial
        // carries this connection's ephemeral and static public keys, deterministically, in
        // every retransmission — key agreement must not depend on which probe lands.
        byte[] frame = new byte[HeaderSize + (c.Crypto is null ? CryptoWire.PuncLegacyBody : CryptoWire.PuncCryptoBody)];
        frame[0] = (byte)FrameType.Punc;
        BitConverter.TryWriteBytes(frame.AsSpan(1), _peerId);
        BitConverter.TryWriteBytes(frame.AsSpan(HeaderSize), c.Token);
        if (c.Crypto is { } crypto)
        {
            crypto.MyEphPublic.CopyTo(frame.AsSpan(HeaderSize + CryptoWire.TokenLength));
            crypto.MyStaticPublic.CopyTo(frame.AsSpan(HeaderSize + CryptoWire.TokenLength + CryptoWire.EphemeralLength));
        }

        return frame;
    }

    /// <summary>Builds one post-handshake frame into <paramref name="dst"/>: legacy
    /// [header][token][body] or, once the session is derived, [header][token][counter][sealed
    /// body]. The 13-byte plaintext prefix is the AEAD associated data, so the frame type,
    /// sender id, and token are tamper-evident too. Returns the frame length.</summary>
    private int BuildFrame(ConnState c, FrameType type, ReadOnlySpan<byte> body, Span<byte> dst)
    {
        WriteHeader(dst, type);
        BinaryPrimitives.WriteUInt32LittleEndian(dst[HeaderSize..], c.Token);
        if (c.Crypto is { Established: true } crypto)
        {
            crypto.Send!.Seal(dst[(HeaderSize + CryptoWire.TokenLength)..], dst[..(HeaderSize + CryptoWire.TokenLength)], body);
            return HeaderSize + CryptoWire.TokenLength + CryptoWire.SealedOverhead + body.Length;
        }

        body.CopyTo(dst[(HeaderSize + CryptoWire.TokenLength)..]);
        return HeaderSize + CryptoWire.TokenLength + body.Length;
    }

    private void WriteHeader(Span<byte> frame, FrameType type)
    {
        frame[0] = (byte)type;
        BitConverter.TryWriteBytes(frame[1..], _peerId);
    }

    private static IPEndPoint ToEndpoint(SocketAddress sa)
    {
        IPAddress any = sa.Family == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any;
        IPEndPoint ep = (IPEndPoint)new IPEndPoint(any, 0).Create(sa);
        if (ep.Address.IsIPv4MappedToIPv6)
        {
            ep.Address = ep.Address.MapToIPv4();
        }

        return ep;
    }

    private static SocketAddress Clone(SocketAddress src)
    {
        var dst = new SocketAddress(src.Family, src.Size);
        for (int i = 0; i < src.Size; i++)
        {
            dst[i] = src[i];
        }

        return dst;
    }
}
