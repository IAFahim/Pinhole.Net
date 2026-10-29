using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using Pinhole.Core;
using Pinhole.Crypto;
using Pinhole.Turn;

namespace Pinhole;

internal enum FrameType : byte
{
    Punc = 0x50,
    Pack = 0x51,
    Data = 0x52,
    Ping = 0x53,
    Pong = 0x54,
    Announce = 0x55,
    Bye = 0x56,
    Hsck = 0x57,
    Predict = 0x58,
    Cookie = 0x59,
    Kem = 0x5A,
}

internal sealed class ConnState
{
    public required ulong PeerId { get; init; }
    public required uint Token { get; init; }

    public readonly object Gate = new();
    public volatile PinholeConnectionState State = PinholeConnectionState.Punching;
    public volatile PathKind Path = PathKind.None;
    public DateTimeOffset PathSince = DateTimeOffset.UtcNow;
    public SocketAddress? DirectRemote;
    public IPEndPoint? DirectRemoteEp;
    public TcpLink? DirectTcp;
    public IUdpSocket? DirectUdpSocket;
    public TcpLink? PendingTcp;
    public bool IncomingQueued;
    public bool IsIncoming;
    public bool DialAdoptedIncoming;
    public bool PeerCandidatesReceived;
    public bool AwaitInitialCandidateExchange;
    public long LastCandidateAnnouncement;
    public long RelayedDatagramsBlocked;
    public long PortPredictionProbesSent;
    public volatile PortPredictionState? Prediction;
    public int TcpDialing;
    public long LastTcpAttempt;
    public long LastTcpLinkTicks;
    public TcpLink? ProbeTcp;
    public IUdpSocket? ProbeUdpSocket;
    public IPEndPoint? RelayRemote;
    public volatile bool RelayReady;
    public readonly List<PinholeCandidate> PeerCandidates = new();
    public bool SymmetricHint;
    public HandshakeState Handshake;
    public ConnectionCrypto? Crypto;
    public byte[]? PinnedStaticKey;
    public byte[]? PinnedEndpointKey;
    public byte[]? PinnedKnock;
    public bool Announced;
    public long LastKickTicks = Environment.TickCount64;
    public volatile bool BlackholeDirect;
    public int PunchGeneration;
    public long DeadSinceTicks;
    public int PermitInFlight;
    public IKeyedRelay? PacketRelay;
    public byte[]? PacketRelayPeerKey;
    public bool PacketRelayConfirmed;
    public byte[] PuncFrame = Array.Empty<byte>();
    public bool PuncFrameV4;
    public bool PuncFrameDowngraded;
    public byte[]? KemFrame;
    public byte[]? Cookie;
    public bool StrangerAdmitted;

    public long FirstPuncTicks;
    public DatagramBuffer? Buffer;

    public readonly TaskCompletionSource Connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource Closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly CancellationTokenSource Dead = new();

    public long LastDirectRxTicks;
    public long LastRelayRxTicks;
    public SocketAddress? ProbeTarget;
    public long PathProbesSent;
    public long PathProbeReplies;

    public PmtuState Pmtu;
    public SocketAddress? PmtuProbeTarget;
    public IUdpSocket? PmtuProbeUdpSocket;
    public long PmtuProbesSent;
    public volatile int DropAboveBytes;
    public KeepaliveState Keepalive;
    public PunchState Punch;

    public PinholeConnection? Public;
    public PinholeDatagramHandler? Received;
    public Action<PinholeConnectionState>? StateChanged;

    public long Sent, ReceivedCount, SendFailed, BytesSent, BytesReceived, PingsSent, PongsReceived;

    public long PuncsSent, PuncsReceived, PacksSent, PacksReceived, HscksReceived, HandshakeRejects;
    public long KemsReceived, HybridHolds;

    public uint LastRejectWanted, LastRejectGot;
    public long LastRejectKind;
    public string? LastRejectFrom;
    public readonly long[] RejectsByKind = new long[9];
    public long LastRttTicks = long.MinValue;
    public int ConsecutiveSendFailures;
}

internal sealed partial class NodeEngine : IDisposable
{
    public const int MaxPayload = 1200;
    private const int HeaderSize = CryptoWire.HeaderLength;

    internal const int MaxConnections = 1024;
    private readonly int _maxConns;

    private const int RecvBufferSize = 8192;
    private const uint StunCookie = 0x2112A442;

    private static readonly TimeSpan RelayRetryBackoff = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RelayMaxBackoff = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RecoverDebounce = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(2);

    internal const int PmtuOverhead = HeaderSize + CryptoWire.TokenLength + CryptoWire.SealedOverhead;
    internal const int PmtuBaseWire = MaxPayload + PmtuOverhead;
    private const int PmtuCeilingV4 = 1472;
    private const int PmtuCeilingV6 = 1452;
    private const int PmtuStepBytes = 128;
    private const int PmtuProbeAttempts = 3;

    private readonly ulong _peerId;
    private readonly PinholeOptions _options;
    private readonly NodeIdentity? _identity;
    private readonly object _gate = new();

    private readonly ConcurrentDictionary<ulong, ConnState> _conns = new();
    private readonly Channel<ConnState>? _incoming;
    private readonly List<RelaySlot> _relays = new();
    private readonly Dictionary<Uri, IrohRelay> _irohRelays = new();
    private readonly Dictionary<Uri, DerpRelay> _derpRelays = new();
    private readonly RelayIdentity? _endpointIdentity;
    private readonly Action<IrohPath, ReadOnlyMemory<byte>>? _rawReceive;
    private readonly List<PinholeCandidate> _localCandidates = new();
    private HashSet<IPEndPoint> _lastRelayedAddresses = new();
    private readonly List<IPEndPoint> _reflexive = new();
    private IPEndPoint? _mappedEndpoint;
    private IPEndPoint? _mappedTcpEndpoint;
    private NatHint _observedNatHint;
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

    private readonly List<IPinholeLookupProvider> _lookup = [];

    private readonly ConcurrentDictionary<ulong, ulong> _recordSequence = new();
    private const int MaxCachedSequences = 1024;
    private static readonly TimeSpan PublishInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan PublishMaxBackoff = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RecordTtl = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan LookupBudget = TimeSpan.FromSeconds(3);
    private Task? _publishLoop;
    private int _publishing;
    private int _publishKick;
    private long _lastPublishTicks;

    private volatile IUdpSocket _udp = null!;
    private TcpTransport? _tcp;
    private long _recovering;
    private volatile bool _disposed;
    private int _networkWatchHooked;
    private Task? _maintenance;
    private long _nextStunRefreshTicks;

    private long _recvDatagrams;
    private long _recvLastTick;
    private long _noConnDrops;

    private sealed record ClosedHandshake(string Summary, uint RemoteToken, byte[]? PeerEphemeral, long ClosedTicks);
    private readonly ConcurrentDictionary<ulong, ClosedHandshake> _lastClosedHandshake = new();
    private readonly object _closedHandshakeGate = new();
    private readonly Queue<ulong> _closedHandshakeOrder = new();
    internal long StaleHandshakeDrops;

    private long _mac1Refused;
    private long _handshakeKeyAgreements;
    private long _cookieDemanded;
    private long _cookieAccepted;
    private long _ledgerRefused;

    internal bool LegacyHandshakeV3Only;
    internal long Mac1Refused => Volatile.Read(ref _mac1Refused);
    internal long HandshakeKeyAgreements => Volatile.Read(ref _handshakeKeyAgreements);
    internal long CookieDemanded => Volatile.Read(ref _cookieDemanded);
    internal long CookieAccepted => Volatile.Read(ref _cookieAccepted);
    internal long StrangerLedgerRefused => Volatile.Read(ref _ledgerRefused);
    internal CookieArmor CookieArmor => _cookieArmor!;
    private readonly CookieArmor? _cookieArmor;
    private readonly StrangerLedger _strangerLedger = new();
    internal int CookieLoadSources => _cookieArmor?.TrackedSources ?? 0;
    internal int StrangerLedgerSources => _strangerLedger.TrackedSources;
    internal bool HandshakeV4Active => !LegacyHandshakeV3Only && _identity is not null;

    internal byte[]? Knock => _knock;
    private readonly byte[]? _knock;
    private readonly byte[]? _knockMac1Key;

    private readonly byte[]? _mlkemSeed;
    private readonly byte[]? _mlkemPublicKey;
    private long _hybridHandshakes;

    internal byte[]? MlKemPublicKey => _mlkemPublicKey;

    internal long HybridHandshakes => Volatile.Read(ref _hybridHandshakes);

    private ReadOnlySpan<byte> OwnMac1Key => _knockMac1Key ?? _identity!.PublicKey;

    internal const long HandshakeV4FallbackMs = 3000;
    private long _nextRelayEnsureTicks;
    private int _relayEnsuring;
    private int _stunRefreshing;
    private long _nextHuskReapTicks;
    private const long HuskReapIntervalMs = 1000;

    public NodeEngine(PinholeOptions options, RelayIdentity? rawIdentity = null,
        Action<IrohPath, ReadOnlyMemory<byte>>? rawReceive = null)
    {

        byte[]? endpointSeed = EndpointIdentity.DeriveEndpointSeed(options.IdentityKeySeed);
        _rawReceive = rawReceive;
        if (rawIdentity is not null)
            _endpointIdentity = rawIdentity;
        else if (endpointSeed is not null || options.PublishIrohAddress || (options.IrohRelayUrls ?? options.ResolvedIrohRelays).Count > 0)
            _endpointIdentity = new RelayIdentity(endpointSeed);
        _peerId = _endpointIdentity?.PeerId ?? BinaryPrimitives.ReadUInt64LittleEndian(RandomNumberGenerator.GetBytes(8));
        _options = options;
        _maxConns = options.MaxConnectionsOverride ?? MaxConnections;
        _identity = options.Encryption != PinholeEncryption.Disabled ? new NodeIdentity(options.IdentityKeySeed) : null;

        _knock = options.Knock?.ToArray();
        if (_knock is not null && _identity is not null)
        {
            Span<byte> key = stackalloc byte[NodeIdentity.KeyLength];
            CryptoWire.KnockMac1Key(key, _identity.PublicKey, _knock);
            _knockMac1Key = key.ToArray();
        }

        if (options.HybridKeyExchange && HybridKem.IsSupported && _identity is not null)
        {
            _mlkemSeed = HybridKem.DerivePrivateSeed(_identity.ExportPrivateSeed());
            _mlkemPublicKey = HybridKem.PublicKeyFromSeed(_mlkemSeed);
        }

        _cookieArmor = _identity is not null ? new CookieArmor() : null;
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

    public byte[]? StaticPublicKey => _identity?.PublicKey;

    public byte[]? EndpointPublicKey => _endpointIdentity?.PublicKey;
    internal RelayIdentity? EndpointRelayIdentity => _endpointIdentity;

    public bool HasRelay
    {
        get
        {
            lock (_gate)
                return !_disposed && (_irohRelays.Values.Any(r => r.IsAlive)
                    || _derpRelays.Values.Any(r => r.IsAlive)
                    || AliveRelayClientsNoLock().Any(c => c.RelayedAddress is not null));
        }
    }

    internal Channel<ConnState>? Incoming => _incoming;

    public void DisposeConnection(ConnState c) => _ = CloseAsync(c);

    private DatagramBuffer? CreateBuffer() =>
        _options.ReceiveBufferCapacity > 0 ? new DatagramBuffer(_options.ReceiveBufferCapacity) : null;

    private PmtuState NewPmtuState() => PmtuState.Create(
        PmtuBaseWire, PmtuStepBytes, PmtuProbeAttempts, PmtuCeilingV4, PmtuCeilingV6,
        (long)_options.PmtuReprobeInterval.TotalMilliseconds,
        (long)_options.PathValidationProbeInterval.TotalMilliseconds);

    private KeepaliveState NewKeepaliveState() => KeepaliveState.Create(
        (long)_options.KeepaliveInterval.TotalMilliseconds,
        (long)_options.PathValidationProbeInterval.TotalMilliseconds,
        _options.PathValidationMaxUnansweredProbes);

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
        public TimeSpan Backoff = RelayRetryBackoff;
    }

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
            await Task.WhenAll(ProbeStunAllAsync(ct), EnsureRelaysAsync(ct), EnsureKeyedRelaysAsync(ct)).WaitAsync(_options.BindProbeBudget, ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {

        }

        RefreshLocalCandidates();
        _ = PermitCatalogRelaysAsync(CancellationToken.None);

        if (_lookup.Count > 0 && _options.Listen && _endpointIdentity is not null)
        {
            _publishLoop = PublishLoopAsync(_shutdown.Token);
        }

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
        ReannounceAndRepunch();
    }

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

    private void OnPortMappingChanged(IPEndPoint? mapped) => OnPortMappingChanged(mapped, tcp: false);
    private void OnTcpPortMappingChanged(IPEndPoint? mapped) => OnPortMappingChanged(mapped, tcp: true);

    private void OnPortMappingChanged(IPEndPoint? mapped, bool tcp)
    {
        if (_disposed) return;
        lock (_gate)
        {

            mapped = (tcp ? _tcpPortMap : _portMap)?.Current;
            if (tcp) _mappedTcpEndpoint = mapped; else _mappedEndpoint = mapped;
            RefreshLocalCandidatesNoLock();
        }

        PublishAddressRecordSoon();
        foreach (ConnState c in ConnectionsSnapshot())
        {
            if (c.State != PinholeConnectionState.Closed)
            {
                AnnounceTo(c);
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

        PublishAddressRecordSoon();
    }

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

        if (_mappedEndpoint is { } mapped && !_localCandidates.Any(c => c.Kind == CandidateKind.Reflexive && c.Address.Equals(mapped)))
        {
            _localCandidates.Add(new PinholeCandidate(CandidateKind.Reflexive, mapped));
        }

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
        foreach (DerpRelay relay in _derpRelays.Values.Where(r => r.IsAlive))
            _localCandidates.Add(new PinholeCandidate(CandidateKind.DerpRelay,
                new IPEndPoint(IPAddress.None, 0), RelayUrl: relay.Url, RelayKey: relay.PublicKey));
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

            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(ProbeTimeout);

            TimeSpan interval = TimeSpan.FromMilliseconds(500);
            while (true)
            {
                source.SendTo(req, ToWire(server));
                try
                {
                    return await tcs.Task.WaitAsync(interval, deadline.Token).ConfigureAwait(false);
                }
                catch (TimeoutException) when (!deadline.IsCancellationRequested)
                {
                    interval = TimeSpan.FromMilliseconds(Math.Min(interval.TotalMilliseconds * 2, 1_000));
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    throw new TimeoutException($"STUN server {server} did not answer within {ProbeTimeout.TotalSeconds:0.#}s");
                }
            }
        }
        finally
        {
            _stunPending.TryRemove(key, out _);
        }
    }

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

    private IrohRelay? IrohRelayFor(Uri url)
    {
        if (_endpointIdentity is null || _disposed) return null;
        IrohRelay relay;
        lock (_gate)
        {
            if (_irohRelays.TryGetValue(url, out relay!)) return relay;
            if (_irohRelays.Count + _derpRelays.Count >= ConnectionString.MaxCandidates) return null;
            relay = new IrohRelay(url, _endpointIdentity, _options.IrohWebSocketFactory);
            relay.Received += HandleKeyedRelayData;
            relay.Changed += KeyedRelayChanged;
            _irohRelays.Add(url, relay);
        }
        _ = relay.StartAsync(_shutdown.Token);
        return relay;
    }

    private DerpRelay? DerpRelayFor(Uri url)
    {
        if (_identity is null || _rawReceive is not null || _disposed) return null;
        DerpRelay relay;
        lock (_gate)
        {
            if (_derpRelays.TryGetValue(url, out relay!)) return relay;
            if (_irohRelays.Count + _derpRelays.Count >= ConnectionString.MaxCandidates) return null;
            relay = new DerpRelay(url, _identity, _options.DerpWebSocketFactory);
            relay.Received += HandleKeyedRelayData;
            relay.Changed += KeyedRelayChanged;
            _derpRelays.Add(url, relay);
        }
        _ = relay.StartAsync(_shutdown.Token);
        return relay;
    }

    private async Task EnsureKeyedRelaysAsync(CancellationToken ct)
    {
        IKeyedRelay[] clients = (_options.IrohRelayUrls ?? _options.ResolvedIrohRelays)
            .Select(IrohRelayFor).OfType<IKeyedRelay>()
            .Concat((_options.DerpRelayUrls ?? _options.ResolvedDerpRelays).Select(DerpRelayFor).OfType<IKeyedRelay>()).ToArray();
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

    private void KeyedRelayChanged(IKeyedRelay relay)
    {
        if (_disposed) return;
        if (TraceEnabled && !relay.IsAlive && relay is DerpRelay { LastError: not null } derp)
            TraceLine($"DERP {relay.Url.Host}: {derp.LastError}");
        RefreshLocalCandidates();
        foreach (ConnState c in ConnectionsSnapshot())
        {
            try
            {
                if (c.State == PinholeConnectionState.Closed) continue;
                if (!relay.IsAlive && c.Path == PathKind.Relay && c.PacketRelay == relay)
                    NotifyPathSuspect(c);
                if (relay.IsAlive)
                {
                    AnnounceTo(c);
                    PinholeCandidate[] targets;
                    lock (_gate) targets = c.PeerCandidates.ToArray();
                    foreach (PinholeCandidate target in targets.Where(t => t.Kind == relay.Kind && t.RelayUrl == relay.Url))
                    {
                        NotePuncSent(c);
                        SendViaKeyedRelay(c.PuncFrame, target);
                        if (c.KemFrame is { } kem)
                        {
                            SendViaKeyedRelay(kem, target);
                        }
                    }
                    KickPunch(c);
                }
            }
            catch (Exception)
            {

            }
        }
    }

    private void HandleKeyedRelayData(IKeyedRelay relay, byte[] source, byte[] frame)
    {
        if (_rawReceive is not null)
        {
            if (!_disposed)
            {
                try { _rawReceive(IrohPath.Relay(relay.Url, Convert.ToHexString(source).ToLowerInvariant()), frame); }
                catch (FormatException) { }
            }
            return;
        }
        if (_disposed || frame.Length < HeaderSize + 4
            || frame[0] is < (byte)FrameType.Punc or (> (byte)FrameType.Predict and not (byte)FrameType.Kem)) return;
        if (relay.Kind == CandidateKind.IrohRelay)
        {
            ulong sender = BinaryPrimitives.ReadUInt64LittleEndian(SHA256.HashData(source));
            if (sender != BinaryPrimitives.ReadUInt64LittleEndian(frame.AsSpan(1))) return;
        }
        else
        {

            ReadOnlySpan<byte> staticKey;
            if (frame[0] == (byte)FrameType.Punc
                && (frame.Length == HeaderSize + CryptoWire.PuncCryptoBody
                    || HandshakeV4Active && (frame.Length == HeaderSize + CryptoWire.PuncCryptoBodyV4
                        || frame.Length == HeaderSize + CryptoWire.PuncCryptoBodyV4Mac2)))
                staticKey = frame.AsSpan(HeaderSize + CryptoWire.TokenLength + CryptoWire.EphemeralLength, 32);
            else if (frame[0] == (byte)FrameType.Pack
                && (frame.Length == HeaderSize + CryptoWire.PackCryptoBody
                    || HandshakeV4Active && frame.Length == HeaderSize + CryptoWire.PackCryptoBodyV4))
                staticKey = frame.AsSpan(HeaderSize + 2 * CryptoWire.TokenLength + CryptoWire.EphemeralLength, 32);
            else
            {
                ConnState? c = Lookup(BinaryPrimitives.ReadUInt64LittleEndian(frame.AsSpan(1)));
                if (c is null) return;
                lock (c.Gate) staticKey = c.Crypto?.PeerStaticPublic;
            }
            if (staticKey.Length != 32 || !staticKey.SequenceEqual(source)) return;
        }
        try { Dispatch(frame, new Arrival(relay, source)); }
        catch (Exception)
        {

        }
    }

    private void SendViaKeyedRelay(ReadOnlySpan<byte> frame, PinholeCandidate candidate)
    {
        if (candidate.RelayUrl is { } url && candidate.RelayKey is { Length: 32 } key)
        {
            IKeyedRelay? relay = candidate.Kind == CandidateKind.DerpRelay ? DerpRelayFor(url) : IrohRelayFor(url);
            relay?.Send(key, frame);
        }
    }

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
        TurnClient? retired = null;
        try
        {
            TurnClient client = await TurnClient.AllocateAsync(slot.Config.Server, slot.Config.Username, slot.Config.Credential, ct).ConfigureAwait(false);
            client.Received += HandleRelayData;
            lock (_gate)
            {
                retired = slot.Client;
                slot.Client = client;
                slot.Backoff = RelayRetryBackoff;
            }

            IEnumerable<IPAddress> bootstrap = (_options.Relays ?? _options.ResolvedRelays)
                .Select(r => r.Server.Address).Append(slot.Config.Server.Address);
            if (client.RelayedAddress is { } relayed) bootstrap = bootstrap.Append(relayed.Address);
            foreach (IPAddress own in bootstrap.Distinct())
            {
                try
                {
                    await client.CreatePermissionAsync(own, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is SocketException or OperationCanceledException or InvalidOperationException or TimeoutException)
                {
                }
            }
        }
        catch (Exception)
        {

            lock (_gate)
            {
                slot.NextRetry = DateTimeOffset.UtcNow + Jitter(slot.Backoff);
                slot.Backoff = TimeSpan.FromTicks(Math.Min(slot.Backoff.Ticks * 2, RelayMaxBackoff.Ticks));
            }
        }
        finally
        {

            if (retired is not null)
            {
                retired.Received -= HandleRelayData;
                await retired.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static TimeSpan Jitter(TimeSpan delay) =>
        delay * (1 + (RandomNumberGenerator.GetInt32(0, 41) - 20) / 100.0);

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

        if (data.Length < HeaderSize)
        {
            return;
        }

        Dispatch(data, new Arrival(from));
    }

    public ConnState? Lookup(ulong peerId)
    {
        return _conns.TryGetValue(peerId, out ConnState? c) ? c : null;
    }

    public IReadOnlyList<ConnState> ConnectionsSnapshot()
    {
        return _conns.Values.ToArray();
    }

    internal PinholeCandidate[] PeerCandidatesSnapshot(ulong peerId)
    {
        lock (_gate)
        {
            return _conns.TryGetValue(peerId, out ConnState? c) ? c.PeerCandidates.ToArray() : [];
        }
    }

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

    private async Task<bool> PublishAddressRecordAsync(CancellationToken ct)
    {
        if (_endpointIdentity is null || _lookup.Count == 0 || _disposed)
        {
            return false;
        }

        if (Interlocked.Exchange(ref _publishing, 1) != 0)
        {
            return true;
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
                await Task.Delay(250, _shutdown.Token).ConfigureAwait(false);
                await PublishAddressRecordAsync(_shutdown.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException or TimeoutException)
            {

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
            return false;
        }
    }

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
            return null;
        }
    }

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
            Token = BinaryPrimitives.ReadUInt32LittleEndian(RandomNumberGenerator.GetBytes(4)),
            SymmetricHint = cs.NatHint == NatHint.Symmetric,
            AwaitInitialCandidateExchange = _options.RelaySignalingOnly
                && cs.Candidates.Any(candidate => candidate.Kind is CandidateKind.Relay or CandidateKind.IrohRelay or CandidateKind.DerpRelay),

            PinnedStaticKey = _identity is not null && cs.StaticKey is not null ? cs.StaticKey : null,
            PinnedEndpointKey = cs.EndpointKey,
            PinnedKnock = cs.Knock,
            Crypto = _identity is not null && cs.StaticKey is not null
                ? ConnectionCrypto.New(_identity, _peerId, cs.PeerId, cs.Knock, HybridDialKey(cs))
                : null,
        };
        c.Buffer = CreateBuffer();
        c.Pmtu = NewPmtuState();
        c.Keepalive = NewKeepaliveState();
        c.Punch = PunchState.Create((long)_options.ConnectTimeout.TotalMilliseconds);
        c.Handshake = HandshakeState.Create(c.Token, c.Crypto is not null);
        SetPuncFrame(c);
        SetKemFrame(c);
        c.Public = new PinholeConnection(this, c);

        c.PeerCandidates.AddRange(cs.Candidates);

        if (_disposed) throw new ObjectDisposedException(nameof(PinholeNode));

        while (true)
        {
            if (_conns.TryGetValue(cs.PeerId, out ConnState? existing))
            {
                if (existing.State is not (PinholeConnectionState.Dead or PinholeConnectionState.Closed))
                {
                    bool armIncoming;
                    lock (existing.Gate)
                    {
                        if (existing.State is PinholeConnectionState.Dead or PinholeConnectionState.Closed) continue;

                        byte[]? knownStatic = existing.Crypto?.PeerStaticPublic ?? existing.PinnedStaticKey;
                        if (cs.StaticKey is { } requestedStatic
                            && (existing.Crypto is null || knownStatic is not null && !knownStatic.AsSpan().SequenceEqual(requestedStatic)))
                        {

                            if (existing.IsIncoming && !existing.Handshake.RemoteTokenAuthenticated && !existing.Connected.Task.IsCompleted)
                            {
                                if (_conns.TryRemove(new KeyValuePair<ulong, ConnState>(cs.PeerId, existing)))
                                {
                                    Transition(existing, PinholeConnectionState.Closed);
                                    existing.Dead.Cancel();
                                }
                                continue;
                            }
                            throw new InvalidOperationException("existing connection does not match the requested peer static key");
                        }
                        if (cs.EndpointKey is { } requestedEndpoint && existing.PinnedEndpointKey is { } knownEndpoint
                            && !knownEndpoint.AsSpan().SequenceEqual(requestedEndpoint))
                            throw new InvalidOperationException("existing connection does not match the requested endpoint key");

                        armIncoming = existing.IsIncoming && !existing.Connected.Task.IsCompleted && !existing.DialAdoptedIncoming;
                        if (armIncoming)
                        {
                            existing.DialAdoptedIncoming = true;
                            existing.PinnedStaticKey = cs.StaticKey;
                            existing.PinnedEndpointKey = cs.EndpointKey;
                            existing.PinnedKnock = cs.Knock;
                            existing.SymmetricHint = cs.NatHint == NatHint.Symmetric;
                        }
                    }
                    if (armIncoming)
                    {

                        lock (_gate)
                            foreach (PinholeCandidate candidate in cs.Candidates)
                                if (existing.PeerCandidates.Count < ConnectionString.MaxCandidates
                                    && !existing.PeerCandidates.Any(old => old.Kind == candidate.Kind
                                        && old.Address.Equals(candidate.Address) && old.RelayUrl == candidate.RelayUrl))
                                    existing.PeerCandidates.Add(candidate);
                        if (cs.Candidates.Any(x => x.Kind == CandidateKind.Relay)) _ = WarmRelayForDialAsync(cs, ct);
                        if (_lookup.Count > 0 && cs.EndpointKey is { } endpoint) _ = ResolveViaLookupAsync(existing, endpoint, ct);
                        KickPunch(existing);
                    }
                    return existing;
                }

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

            _ = WarmRelayForDialAsync(cs, ct);
        }

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

        }
    }

    private ReadOnlySpan<byte> HybridDialKey(ConnectionString cs) =>
        _options.HybridKeyExchange && HybridKem.IsSupported && cs.MlKemKey is { } key ? key : default;

    private void SetKemFrame(ConnState c)
    {
        if (c.Crypto?.MlKemCiphertext is not { } ciphertext)
        {
            c.KemFrame = null;
            return;
        }

        byte[] frame = new byte[HeaderSize + CryptoWire.KemBody];
        frame[0] = (byte)FrameType.Kem;
        BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(1), _peerId);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(HeaderSize), c.Token);
        ciphertext.CopyTo(frame.AsSpan(HeaderSize + CryptoWire.TokenLength));
        c.KemFrame = frame;
    }

    private ConnState? CreateIncoming(ulong peerId, uint token, in Arrival arrival, bool cryptoHandshake)
    {

        if (_conns.Count >= _maxConns)
        {
            return null;
        }

        var c = new ConnState
        {
            PeerId = peerId,
            Token = BinaryPrimitives.ReadUInt32LittleEndian(RandomNumberGenerator.GetBytes(4)),
            IsIncoming = true,
            AwaitInitialCandidateExchange = _options.RelaySignalingOnly && arrival.ViaRelay,

            Crypto = cryptoHandshake && _identity is not null ? ConnectionCrypto.New(_identity, _peerId, peerId, _knock) : null,
        };
        c.Punch = PunchState.Create((long)_options.ConnectTimeout.TotalMilliseconds);
        c.Handshake = HandshakeState.Create(c.Token, c.Crypto is not null);
        c.Handshake.RemoteToken = token;
        c.Handshake.RemoteTokenKnown = true;
        c.Buffer = CreateBuffer();
        c.Pmtu = NewPmtuState();
        c.Keepalive = NewKeepaliveState();
        SetPuncFrame(c);
        c.Public = new PinholeConnection(this, c);

        if (!_conns.TryAdd(peerId, c))
        {
            return _conns.TryGetValue(peerId, out ConnState? first) ? first : null;
        }

        if (_conns.Count > _maxConns)
        {

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

            if (!c.IncomingQueued)
            {
                c.IncomingQueued = true;
                _incoming?.Writer.TryWrite(c);
            }
        }
        else if (arrival.Tcp is not null) c.PendingTcp = arrival.Tcp;
        return c;
    }

    private void RememberClosedHandshake(ConnState c)
    {

        ClosedHandshake closed;
        lock (c.Gate)
            closed = new(LiveHandshakeSummary(c) + $" final={c.State}", c.Handshake.RemoteToken,
                c.Crypto is { PeerConfirmed: true } crypto ? crypto.PeerEphPublic?.ToArray() : null, Environment.TickCount64);
        lock (_closedHandshakeGate)
        {
            if (!_lastClosedHandshake.ContainsKey(c.PeerId)) _closedHandshakeOrder.Enqueue(c.PeerId);
            _lastClosedHandshake[c.PeerId] = closed;
            while (_lastClosedHandshake.Count > MaxConnections && _closedHandshakeOrder.TryDequeue(out ulong oldest))
                _lastClosedHandshake.TryRemove(oldest, out _);
        }
    }

    public async Task CloseAsync(ConnState c)
    {
        RememberClosedHandshake(c);

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

    private void ReapUnestablishedHusks()
    {
        long budget = (long)_options.ConnectTimeout.TotalMilliseconds;
        long now = Environment.TickCount64;
        foreach (ConnState c in ConnectionsSnapshot())
        {
            if (c.Connected.Task.IsCompleted)
            {
                continue;
            }

            bool reap;
            lock (c.Gate)
            {
                reap = c.State is PinholeConnectionState.Punching or PinholeConnectionState.Dead
                    && now - c.LastKickTicks > budget;
                if (reap && c.State == PinholeConnectionState.Punching)
                {
                    Transition(c, PinholeConnectionState.Dead);
                    c.DeadSinceTicks = now;
                }
            }

            if (reap)
            {
                _conns.TryRemove(new KeyValuePair<ulong, ConnState>(c.PeerId, c));
                c.Dead.Cancel();
            }
        }
    }

    public void KickPunch(ConnState c)
    {
        lock (c.Gate)
        {
            c.LastKickTicks = Environment.TickCount64;

            PunchInput kick = default;
            kick.Kind = PunchInputKind.Kick;
            PunchSchedulerMachine.Step(ref c.Punch, in kick, new Tick(c.LastKickTicks), Span<Effect>.Empty);
        }

        int gen = Interlocked.Increment(ref c.PunchGeneration);
        _ = PunchLoop(c, gen);
    }

    private async Task PunchLoop(ConnState c, int gen)
    {
        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token, c.Dead.Token);

        Effect[] effects = new Effect[8];
        try
        {
            while (!stop.IsCancellationRequested && Volatile.Read(ref c.PunchGeneration) == gen)
            {
                long now = Environment.TickCount64;
                MaybeStartPortPrediction(c);
                PinholeConnectionState state = c.State;

                if (c.PuncFrameV4 && !c.PuncFrameDowngraded && c.PinnedKnock is null
                    && state == PinholeConnectionState.Punching)
                {
                    long first = Volatile.Read(ref c.FirstPuncTicks);
                    if (first != 0 && now - first > HandshakeV4FallbackMs
                        && Volatile.Read(ref c.PuncsReceived) == 0
                        && Volatile.Read(ref c.PacksReceived) == 0
                        && Volatile.Read(ref c.HscksReceived) == 0)
                    {
                        c.PuncFrameDowngraded = true;
                        c.PuncFrame = BuildPunc(c, v4: false);
                        c.PuncFrameV4 = false;
                        c.KemFrame = null;
                        c.Crypto?.AbandonHybridHold();
                        if (TraceEnabled)
                        {
                            TraceLine($"handshake v4 unanswered by {c.PeerId:x16} for {HandshakeV4FallbackMs}ms; falling back to unversioned puncs");
                        }
                    }
                }
                PunchInput input = default;
                input.Kind = PunchInputKind.Tick;
                input.Phase = (byte)state;
                input.OpenWithoutDirectTcp = state == PinholeConnectionState.Open && c.DirectTcp is null;
                input.ConnectedCompleted = c.Connected.Task.IsCompleted;
                input.PinnedLookupPossible = c.PinnedEndpointKey is not null && _lookup.Count > 0;
                input.RelaySignalingOnly = _options.RelaySignalingOnly;
                input.Established = c.Crypto is { Established: true };
                input.SymmetricHint = c.SymmetricHint;
                input.PredictionActive = c.Prediction is { Finished: false } || Volatile.Read(ref _predictionMeasuring) != 0;
                input.AwaitExchange = c.AwaitInitialCandidateExchange;
                input.PeerCandidatesReceived = Volatile.Read(ref c.PeerCandidatesReceived);
                input.TcpEligible = _tcp is not null && c.Crypto is not null && c.DirectTcp is null;
                input.AnnounceRetryDue = now - Volatile.Read(ref c.LastCandidateAnnouncement) >= 1000;
                input.NowMs = now;
                input.KickedAtMs = c.LastKickTicks;
                input.DeadSinceMs = c.DeadSinceTicks;

                bool endLoop = false, condemned = false, lookup = false, announce = false, tcpProbe = false;
                bool punchRelay = false, punchDirect = false, punchLinkLocal = false;
                long wakeAt = now + PunchSchedulerMachine.PunchPaceMs;
                int n = PunchSchedulerMachine.Step(ref c.Punch, in input, new Tick(now), effects);
                for (int i = 0; i < n; i++)
                {
                    switch (effects[i].Kind)
                    {
                        case EffectKind.Notify:
                            switch ((PunchNotify)effects[i].Value)
                            {
                                case PunchNotify.Stop: endLoop = true; break;
                                case PunchNotify.CondemnDead: condemned = true; break;
                                case PunchNotify.Lookup: lookup = true; break;
                                case PunchNotify.Announce: announce = true; break;
                                case PunchNotify.TcpProbe: tcpProbe = true; break;
                            }
                            break;
                        case EffectKind.Transmit:
                            if (effects[i].Path == EffectPath.Relay) punchRelay = true;
                            else if (effects[i].Path == EffectPath.DirectLinkLocal) punchLinkLocal = true;
                            else if (effects[i].Path == EffectPath.Direct) punchDirect = true;
                            break;
                        case EffectKind.Arm:
                            wakeAt = effects[i].Value;
                            break;
                    }
                }

                if (condemned)
                {

                    lock (c.Gate)
                    {
                        Transition(c, PinholeConnectionState.Dead);
                        c.DeadSinceTicks = now;
                    }
                }

                if (endLoop)
                {
                    return;
                }

                PinholeCandidate[] candidates;
                lock (_gate)
                {
                    candidates = c.PeerCandidates.ToArray();
                    if (lookup && c.PinnedEndpointKey is { } pinned && _lookup.Count > 0)
                    {

                        _ = ResolveViaLookupAsync(c, pinned, stop.Token);
                    }
                }

                if (announce)
                {
                    AnnounceTo(c);
                }

                foreach (PinholeCandidate candidate in candidates)
                {
                    if (stop.IsCancellationRequested)
                    {
                        return;
                    }

                    bool relay = candidate.Kind is CandidateKind.Relay or CandidateKind.IrohRelay or CandidateKind.DerpRelay;
                    if (relay)
                    {
                        if (!punchRelay)
                        {
                            continue;
                        }
                    }
                    else
                    {
                        if (!punchDirect)
                        {
                            continue;
                        }

                        if (candidate.Address.Address.IsIPv6LinkLocal && !punchLinkLocal)
                        {
                            continue;
                        }
                    }

                    try
                    {
                        if (candidate.Kind is CandidateKind.IrohRelay or CandidateKind.DerpRelay)
                        {
                            NotePuncSent(c);
                            SendViaKeyedRelay(c.PuncFrame, candidate);
                            if (c.KemFrame is { } kem)
                            {
                                SendViaKeyedRelay(kem, candidate);
                            }
                        }
                        else if (candidate.Kind == CandidateKind.Relay)
                        {
                            NotePuncSent(c);
                            SendViaRelayTo(c.PuncFrame, candidate.Address, candidate.RelayServer?.Address);
                            if (c.KemFrame is { } kem)
                            {
                                SendViaRelayTo(kem, candidate.Address, candidate.RelayServer?.Address);
                            }
                        }
                        else
                        {
                            if (TraceEnabled) TraceLine($"punch direct {c.PeerId:x16} -> {candidate.Address}");
                            NotePuncSent(c);
                            SendToWire(candidate.Address, c.PuncFrame);
                            if (c.KemFrame is { } kem)
                            {
                                SendToWire(candidate.Address, kem);
                            }
                            Interlocked.Increment(ref c.PuncsSent);
                        }
                    }
                    catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
                    {

                    }
                }

                if (tcpProbe)
                {
                    _ = TryTcpPathsAsync(c, candidates, stop.Token);
                }

                await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(1, wakeAt - now)), stop.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }

    }

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

            if (Environment.TickCount64 >= Volatile.Read(ref _nextHuskReapTicks))
            {
                Volatile.Write(ref _nextHuskReapTicks, Environment.TickCount64 + HuskReapIntervalMs);
                ReapUnestablishedHusks();
            }

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

    private async Task RefreshReflexiveAsync(CancellationToken ct)
    {
        if (_disposed || Interlocked.Exchange(ref _stunRefreshing, 1) != 0)
        {
            return;
        }

        try
        {

            IPEndPoint[] perServer = await ProbeStunObservedAsync(ct).ConfigureAwait(false);
            if (perServer.Length == 0)
            {

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
                    RefreshLocalCandidatesNoLock();
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
                    AnnounceTo(c);
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

    private void ValidatePath(ConnState c)
    {
        long now = Environment.TickCount64;
        if (c.State == PinholeConnectionState.Degraded && c.Path == PathKind.Relay)
        {
            ValidateRelayPath(c);
            return;
        }

        Span<Effect> effects = stackalloc Effect[2];
        bool suspect = false;
        SocketAddress? target = null;
        long nonce = 0;
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
                ResetPathProbesNoLock(c);
                return;
            }

            KeepaliveInput input = default;
            input.Kind = KeepaliveInputKind.ProbeTick;
            input.PathEligible = true;
            input.RecentActivity = false;
            input.Path = EffectPath.Direct;
            int n = KeepaliveMachine.Step(ref c.Keepalive, in input, new Tick(now), effects);
            for (int i = 0; i < n; i++)
            {
                if (effects[i].Kind == EffectKind.Notify)
                {
                    suspect = true;
                }
                else if (effects[i].Kind == EffectKind.Transmit)
                {
                    nonce = effects[i].Value;
                    target = c.DirectRemote;
                    c.ProbeTarget = target;
                    c.ProbeTcp = c.DirectTcp;
                    c.ProbeUdpSocket = c.DirectUdpSocket;
                }
            }
        }

        if (suspect)
        {
            NotifyPathSuspect(c);
            return;
        }

        if (target is not null)
        {
            SendDirectProbe(c, target, nonce);
        }
    }

    private void ValidateRelayPath(ConnState c)
    {
        long now = Environment.TickCount64;
        Span<Effect> effects = stackalloc Effect[2];
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
                ResetPathProbesNoLock(c);
                return;
            }

            KeepaliveInput input = default;
            input.Kind = KeepaliveInputKind.ProbeTick;
            input.PathEligible = true;
            input.RecentActivity = false;
            input.Path = EffectPath.Relay;
            int n = KeepaliveMachine.Step(ref c.Keepalive, in input, new Tick(now), effects);
            for (int i = 0; i < n; i++)
            {
                if (effects[i].Kind == EffectKind.Notify)
                {
                    suspect = true;
                }
                else if (effects[i].Kind == EffectKind.Transmit)
                {
                    probe = true;
                }
            }
        }

        if (suspect)
        {

            lock (c.Gate)
            {
                c.RelayReady = false;
            }

            NotifyPathSuspect(c);
            return;
        }

        if (probe)
        {
            PingUncounted(c);
        }
    }

    private void ResetPathProbesNoLock(ConnState c)
    {
        KeepaliveInput reset = default;
        reset.Kind = KeepaliveInputKind.PathChanged;
        KeepaliveMachine.Step(ref c.Keepalive, in reset, new Tick(Environment.TickCount64), Span<Effect>.Empty);
        c.ProbeTarget = null;
        c.ProbeTcp = null;
        c.ProbeUdpSocket = null;
    }

    private void SendDirectProbe(ConnState c, SocketAddress target, long nonce)
    {
        Span<byte> frame = stackalloc byte[PmtuBaseWire];
        Span<byte> nonceBytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(nonceBytes, nonce);
        int len = BuildFloorPing(c, nonceBytes, frame);
        try
        {
            SendDirect(c, target, frame[..len]);
            Interlocked.Increment(ref c.PathProbesSent);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {

        }
    }

    private void MaybeKeepalive(ConnState c)
    {
        long now = Environment.TickCount64;
        Span<Effect> effects = stackalloc Effect[2];
        bool ping = false;
        lock (c.Gate)
        {
            KeepaliveInput input = default;
            input.Kind = KeepaliveInputKind.MaintainTick;
            input.PathEligible = c.State is PinholeConnectionState.Open or PinholeConnectionState.Degraded;
            ping = KeepaliveMachine.Step(ref c.Keepalive, in input, new Tick(now), effects) > 0;
        }

        if (ping)
        {
            Ping(c);
        }
    }

    private void DiscoverPathMtu(ConnState c)
    {
        long now = Environment.TickCount64;
        Span<Effect> effects = stackalloc Effect[2];
        SocketAddress? target = null;
        long nonce = 0;
        int size = 0;
        lock (c.Gate)
        {
            PmtuInput input = default;
            input.Kind = PmtuInputKind.Tick;
            input.PathEligible = c.State == PinholeConnectionState.Open && c.Path == PathKind.Direct
                && c.DirectRemote is not null && c.DirectTcp is null;
            input.IPv4 = PmtuPathIsV4NoLock(c);
            int n = PmtuMachine.Step(ref c.Pmtu, in input, new Tick(now), effects);
            for (int i = 0; i < n; i++)
            {
                if (effects[i].Kind != EffectKind.Transmit)
                {
                    continue;
                }

                c.PmtuProbeTarget = c.DirectRemote;
                c.PmtuProbeUdpSocket = c.DirectUdpSocket;
                target = c.PmtuProbeTarget;
                nonce = effects[i].Value;
                size = effects[i].Length;
            }
        }

        if (target is not null)
        {
            SendPmtuProbe(c, target, nonce, size);
        }
    }

    private static bool PmtuPathIsV4NoLock(ConnState c) =>
        c.DirectRemoteEp is { Address.AddressFamily: System.Net.Sockets.AddressFamily.InterNetwork };

    private void SendPmtuProbe(ConnState c, SocketAddress target, long nonce, int size)
    {
        Span<byte> body = stackalloc byte[size - PmtuOverhead];
        BinaryPrimitives.WriteInt64LittleEndian(body, nonce);
        Span<byte> frame = stackalloc byte[size];
        int len = BuildFrame(c, FrameType.Ping, body, frame);
        try
        {
            SendToWire(target, frame[..len]);
            Interlocked.Increment(ref c.PmtuProbesSent);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {

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

        return left.Buffer.Span[..left.Size].SequenceEqual(right.Buffer.Span[..right.Size]);
    }

    public void Send(ConnState c, ReadOnlySpan<byte> payload)
    {
        ArgumentOutOfRangeException.ThrowIfZero(payload.Length);
        int ceiling;
        lock (c.Gate)
        {

            ceiling = c.Pmtu.Wire > 0 ? c.Pmtu.Wire - PmtuOverhead : MaxPayload;
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

    internal void PingUncounted(ConnState c) => SendPingFrame(c);

    private bool SendPingFrame(ConnState c)
    {
        if (c.State is not (PinholeConnectionState.Open or PinholeConnectionState.Degraded))
        {
            return false;
        }

        Span<byte> frame = stackalloc byte[PmtuBaseWire];
        Span<byte> timestamp = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(timestamp, Environment.TickCount64);
        int len = BuildFloorPing(c, timestamp, frame);
        try
        {
            RouteFrame(c, frame[..len]);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
        {
            return false;
        }

        return true;
    }

    private void RouteFrame(ConnState c, ReadOnlySpan<byte> frame)
    {
        if (c.Path == PathKind.Direct && c.DirectRemote is { } direct)
        {
            SendDirect(c, direct, frame);
            return;
        }

        if (_options.RelaySignalingOnly && frame[0] == (byte)FrameType.Data)
            throw new InvalidOperationException("direct application path is unavailable; relays are signaling-only");

        if (c.PacketRelay is { IsAlive: true } iro && c.PacketRelayConfirmed && c.PacketRelayPeerKey is { } key)
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

        if (ep.Address.IsIPv6LinkLocal && ep.Address.ScopeId == 0)
        {
            foreach (IPEndPoint scoped in ScopeLinkLocal(ep, LinkLocalSendScopes()))
            {
                try { _udp.SendTo(frame, ToWire(scoped)); }
                catch (SocketException) { }
            }
            return;
        }
        try { _udp.SendTo(frame, ToWire(ep)); }
        finally { _interfaceUdp?.SendCandidates(frame, ep); }
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
            (FrameType.Punc or FrameType.Pack or FrameType.Hsck or FrameType.Kem or FrameType.Ping or FrameType.Pong)) return;

        if (frame.Span[0] == (byte)FrameType.Punc
            && frame.Length != HeaderSize + CryptoWire.PuncCryptoBody
            && !(HandshakeV4Active && frame.Length == HeaderSize + CryptoWire.PuncCryptoBodyV4)) { tcp.Dispose(); return; }
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
        long now = Environment.TickCount64;
        long lastAttempt = Volatile.Read(ref c.LastTcpAttempt);
        long lastLink = Volatile.Read(ref c.LastTcpLinkTicks);
        if (_tcp is not { } transport || c.Crypto is null || c.Dead.IsCancellationRequested

            || lastAttempt != 0 && now - lastAttempt < 1_000

            || lastLink != 0 && now - lastLink < 5_000
            || Interlocked.CompareExchange(ref c.TcpDialing, 1, 0) != 0) return;
        try
        {
            Volatile.Write(ref c.LastTcpAttempt, now);
            IReadOnlyList<int> scopes = LinkLocalSendScopes();
            IPEndPoint[] targets = candidates.Where(candidate => candidate.Kind is CandidateKind.Direct or CandidateKind.Reflexive)
                .SelectMany(candidate => ScopeLinkLocal(candidate.Address, scopes)).Distinct().Take(8).ToArray();
            await Task.WhenAll(targets.Select(async target =>
            {
                TcpLink? link = await transport.ConnectAsync(target, stop).ConfigureAwait(false);
                if (link is not null) Volatile.Write(ref c.LastTcpLinkTicks, Environment.TickCount64);
                if (link is null || !link.BindPeer(c.PeerId)) return;
                if (c.State == PinholeConnectionState.Closed || c.Dead.IsCancellationRequested) { link.Dispose(); return; }
                if (c.State == PinholeConnectionState.Open && c.Path == PathKind.Direct && c.DirectTcp is null) return;
                NotePuncSent(c);
                link.Send(c.PuncFrame);
                if (c.KemFrame is { } kem)
                {
                    link.Send(kem);
                }
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

    private void StartRecvLoop()
    {
        new Thread(RecvLoop) { IsBackground = true, Name = "pinhole-node-recv" }.Start();
    }

    private void RecvLoop()
    {
        byte[] buf = new byte[_rawReceive is null ? RecvBufferSize : 65535];

        var remote = new SocketAddress(AddressFamily.InterNetworkV6);
        int addressCapacity = remote.Size;
        while (!_shutdown.IsCancellationRequested)
        {
            int n;
            IUdpSocket receiving = _udp;
            try
            {

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

            Interlocked.Increment(ref _recvDatagrams);
            Volatile.Write(ref _recvLastTick, Environment.TickCount64);

            if (_rawReceive is not null)
            {

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

                    }
                }
            }
            else if (_options.EnableDirectUdp && n >= HeaderSize
                && (buf[0] is >= (byte)FrameType.Punc and <= (byte)FrameType.Hsck or (byte)FrameType.Cookie or (byte)FrameType.Kem))
            {
                try
                {
                    Dispatch(buf.AsSpan(0, n), new Arrival(remote));
                }
                catch (Exception)
                {

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

                }
            }
        }
    }

    private void OnInterfaceFrame(IUdpSocket socket, byte[] buffer, int count, SocketAddress remote)
    {
        if (_disposed || _interfaceUdp?.Contains(socket) != true) return;
        if (count >= 20 && BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(4)) == StunCookie)
            OnStunResponse(buffer, count, socket, remote);
        else if (_options.EnableDirectUdp && count >= HeaderSize
            && (buffer[0] is >= (byte)FrameType.Punc and <= (byte)FrameType.Hsck or (byte)FrameType.Cookie or (byte)FrameType.Kem))
            Dispatch(buffer.AsSpan(0, count), new Arrival(remote, socket));
    }

    private readonly struct Arrival
    {
        public readonly bool ViaRelay;
        public readonly SocketAddress? Direct;
        public readonly IPEndPoint? Relay;
        public readonly IKeyedRelay? PacketRelay;
        public readonly byte[]? PacketRelayPeerKey;
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

        public Arrival(IKeyedRelay relay, byte[] key)
        {
            ViaRelay = true;
            PacketRelay = relay;
            PacketRelayPeerKey = key;
        }
    }

    private void Dispatch(ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        FrameType type = (FrameType)frame[0];
        ConnState? c = Lookup(BinaryPrimitives.ReadUInt64LittleEndian(frame[1..]));
        if (c is not null && arrival.ViaRelay
            && c.RelayRemote?.Address.Equals(arrival.Relay?.Address) == true)
        {

            Volatile.Write(ref c.LastRelayRxTicks, Environment.TickCount64);
        }

        if (c is { BlackholeDirect: true } && !arrival.ViaRelay)
        {
            return;
        }

        if (c is { DropAboveBytes: > 0 } && frame.Length > c.DropAboveBytes)
        {
            return;
        }

        if (TraceEnabled && (type is FrameType.Data or FrameType.Punc or FrameType.Pack))
        {
            TraceLine($"recv {type} from {BinaryPrimitives.ReadUInt64LittleEndian(frame[1..]):x16} via {(arrival.ViaRelay ? "relay" : "direct")} {(c is null ? "NO-CONN" : $"state={c.State} handler={(c.Received is null ? "none" : "on")}")}");
        }

        if (c is null)
        {
            if (type != FrameType.Punc || !_options.Listen || _disposed)
            {
                Interlocked.Increment(ref _noConnDrops);
                return;
            }

            bool legacy = frame.Length == HeaderSize + CryptoWire.PuncLegacyBody;
            bool v4 = HandshakeV4Active && frame.Length == HeaderSize + CryptoWire.PuncCryptoBodyV4;
            bool v4Mac2 = HandshakeV4Active && frame.Length == HeaderSize + CryptoWire.PuncCryptoBodyV4Mac2;
            bool crypto = frame.Length == HeaderSize + CryptoWire.PuncCryptoBody || v4 || v4Mac2;
            if (!legacy && !crypto)
            {
                return;
            }

            if (_knock is not null && !v4 && !v4Mac2)
            {
                return;
            }

            if ((legacy && _options.Encryption == PinholeEncryption.Required)
                || (crypto && _options.Encryption == PinholeEncryption.Disabled))
            {
                return;
            }

            if ((v4 || v4Mac2) && !CryptoWire.VerifyMac1(CryptoWire.Mac1View(frame), OwnMac1Key))
            {
                Interlocked.Increment(ref _mac1Refused);
                Telemetry.FrameRejected("handshake", "mac1");
                return;
            }

            Span<byte> strangerSourceKey = stackalloc byte[MaxSocketAddressBytes];
            SocketAddress? strangerSource = !arrival.ViaRelay && arrival.Tcp is null ? arrival.Direct : null;
            bool strangerDirectSource = strangerSource is not null;
            int strangerLedgerKeyLength = strangerDirectSource ? WriteSourceKey(strangerSource!, strangerSourceKey) : 0;
            (bool strangerCookieRequired, bool strangerCookieOk) = CookieVerdict(
                frame, v4Mac2, mac1Eligible: true, sessionCompleted: false, arrival,
                strangerSourceKey, out int strangerSourceKeyLength);
            if (strangerCookieRequired && !strangerCookieOk)
            {
                Interlocked.Increment(ref _cookieDemanded);
                SendCookieReply(BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]),
                    strangerSourceKey[..strangerSourceKeyLength], arrival);
                if (TraceEnabled)
                {
                    TraceLine($"cookie demanded for stranger punc from {BinaryPrimitives.ReadUInt64LittleEndian(frame[1..]):x16}");
                }
                return;
            }

            if (strangerDirectSource
                && !_strangerLedger.TryCharge(strangerSourceKey[..strangerLedgerKeyLength], Environment.TickCount64,
                    BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..])))
            {
                Interlocked.Increment(ref _ledgerRefused);
                Telemetry.FrameRejected("handshake", "ledger");
                return;
            }

            if (crypto && _lastClosedHandshake.TryGetValue(BinaryPrimitives.ReadUInt64LittleEndian(frame[1..]), out ClosedHandshake? closed)
                && Environment.TickCount64 - closed.ClosedTicks < 60_000
                && closed.PeerEphemeral is { } ephemeral
                && BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]) == closed.RemoteToken
                && frame.Slice(HeaderSize + CryptoWire.TokenLength, CryptoWire.EphemeralLength).SequenceEqual(ephemeral))
            {
                Interlocked.Increment(ref StaleHandshakeDrops);
                return;
            }

            if (TraceEnabled)
            {
                TraceLine($"stranger punc from {BinaryPrimitives.ReadUInt64LittleEndian(frame[1..]):x16} " +
                          $"via {(arrival.ViaRelay ? "relay" : arrival.Tcp is not null ? "tcp" : "direct")}");
            }
            c = CreateIncoming(
                BinaryPrimitives.ReadUInt64LittleEndian(frame[1..]),
                BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]),
                arrival,
                crypto);
            if (c is null)
            {
                return;
            }

            c.StrangerAdmitted = true;
        }

        bool sealedFrame = type is not (FrameType.Punc or FrameType.Pack or FrameType.Hsck or FrameType.Cookie or FrameType.Kem)
            && c.Crypto is not null;
        if (type is not (FrameType.Punc or FrameType.Pack or FrameType.Cookie) && !sealedFrame && !TokenOk(c, frame))
        {
            return;
        }

        int wireLength = frame.Length;
        if (sealedFrame && c.Crypto is { } cryptoState)
        {
            byte[] scratch = CryptoScratch();
            int plainLen;
            lock (c.Gate)
            {

                if (!cryptoState.Established || frame.Length < HeaderSize + CryptoWire.TokenLength
                    || c.Handshake.RemoteTokenAuthenticated && !TokenOk(c, frame))
                {
                    cryptoState.CountRejected();
                    return;
                }

                frame[..(HeaderSize + CryptoWire.TokenLength)].CopyTo(scratch);
                if (!cryptoState.Recv!.Open(frame, scratch.AsSpan(HeaderSize + CryptoWire.TokenLength), out plainLen))
                {
                    cryptoState.CountRejected();
                    return;
                }

                c.Handshake.RemoteToken = BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]);
                c.Handshake.RemoteTokenKnown = true;
                c.Handshake.RemoteTokenAuthenticated = true;
                cryptoState.MarkPeerConfirmed();
                NoteArrivalValidated(arrival);
            }

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
            case FrameType.Cookie:
                OnCookie(c, frame, arrival);
                break;
            case FrameType.Kem:
                OnKem(c, frame, arrival);
                break;
            case FrameType.Bye:
                RememberClosedHandshake(c);

                _conns.TryRemove(new KeyValuePair<ulong, ConnState>(c.PeerId, c));
                Transition(c, PinholeConnectionState.Closed);
                _tcp?.ClosePeer(c.PeerId, c.DirectTcp);
                c.Dead.Cancel();
                break;
        }
    }

    [ThreadStatic] private static byte[]? s_cryptoScratch;

    private static byte[] CryptoScratch() => s_cryptoScratch ??= new byte[RecvBufferSize];

    private static bool TokenOk(ConnState c, ReadOnlySpan<byte> frame) =>
        c.Handshake.RemoteTokenKnown
            && frame.Length >= HeaderSize + 4
            && BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]) == c.Handshake.RemoteToken;

    private bool Mac1OkForConn(ConnState c, ReadOnlySpan<byte> frame)
    {
        ReadOnlySpan<byte> mac1Frame = CryptoWire.Mac1View(frame);
        if (c.PinnedStaticKey is { } pin)
        {
            if (c.PinnedKnock is { } knock)
            {
                Span<byte> key = stackalloc byte[NodeIdentity.KeyLength];
                CryptoWire.KnockMac1Key(key, pin, knock);
                return CryptoWire.VerifyMac1(mac1Frame, key);
            }

            if (CryptoWire.VerifyMac1(mac1Frame, pin))
            {
                return true;
            }
        }

        return CryptoWire.VerifyMac1(mac1Frame, OwnMac1Key);
    }

    private byte[] Mac1KeyFor(ConnState c)
    {
        if (c.PinnedStaticKey is { } pin)
        {
            if (c.PinnedKnock is { } knock)
            {
                Span<byte> key = stackalloc byte[NodeIdentity.KeyLength];
                CryptoWire.KnockMac1Key(key, pin, knock);
                return key.ToArray();
            }

            return pin;
        }

        return OwnMac1Key.ToArray();
    }

    private const int MaxSocketAddressBytes = 32;

    private static int WriteSourceKey(SocketAddress source, Span<byte> destination)
    {
        int size = Math.Min(source.Size, destination.Length);
        for (int i = 0; i < size; i++)
        {
            destination[i] = source[i];
        }

        return size;
    }

    private void NoteArrivalValidated(in Arrival arrival)
    {
        if (arrival.ViaRelay || arrival.Tcp is not null || arrival.Direct is not { } source)
        {
            return;
        }

        Span<byte> key = stackalloc byte[MaxSocketAddressBytes];
        int length = WriteSourceKey(source, key);
        _strangerLedger.NoteValidated(key[..length], Environment.TickCount64);
    }

    private (bool Required, bool Ok) CookieVerdict(ReadOnlySpan<byte> frame, bool mac2Capable, bool mac1Eligible,
        bool sessionCompleted, in Arrival arrival, Span<byte> sourceKeyBuf, out int sourceKeyLength)
    {
        sourceKeyLength = 0;
        if (!mac1Eligible || sessionCompleted
            || _cookieArmor is not { } armor || !HandshakeV4Active
            || arrival.ViaRelay || arrival.Tcp is not null || arrival.Direct is not { } source)
        {
            return (false, true);
        }

        sourceKeyLength = WriteSourceKey(source, sourceKeyBuf);
        ReadOnlySpan<byte> sourceKey = sourceKeyBuf[..sourceKeyLength];
        if (!armor.NotePuncAndCheckLoad(sourceKey, Environment.TickCount64))
        {
            return (false, true);
        }

        if (mac2Capable && armor.VerifyMac2(frame, sourceKey))
        {
            Interlocked.Increment(ref _cookieAccepted);
            return (true, true);
        }

        return (true, false);
    }

    private void SendCookieReply(uint echoToken, ReadOnlySpan<byte> sourceKey, in Arrival arrival)
    {
        Span<byte> cookie = stackalloc byte[CryptoWire.CookieFrameLength];
        WriteHeader(cookie, FrameType.Cookie);
        BinaryPrimitives.WriteUInt32LittleEndian(cookie[HeaderSize..], echoToken);
        cookie[HeaderSize + CryptoWire.TokenLength] = _cookieArmor!.Mint(
            cookie[(HeaderSize + CryptoWire.TokenLength + 1)..], sourceKey);
        SendOnArrival(arrival, cookie);
    }

    private static long StepHandshake(ref HandshakeState state, in HandshakeInput input, out long kind, out long reply)
    {
        Span<Effect> effects = stackalloc Effect[2];
        int n = HandshakeMachine.Step(ref state, in input, new Tick(Environment.TickCount64), effects);
        kind = 0;
        reply = -1;
        long fail = 0;
        for (int i = 0; i < n; i++)
        {
            if (effects[i].Kind == EffectKind.Notify)
            {
                kind = effects[i].Value;
            }
            else if (effects[i].Kind == EffectKind.Transmit)
            {
                reply = effects[i].Value;
            }
            else if (effects[i].Kind == EffectKind.Close)
            {
                fail = effects[i].Value;
            }
        }

        return fail;
    }

    private void OnPunc(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        bool v4Punc = HandshakeV4Active && frame.Length == HeaderSize + CryptoWire.PuncCryptoBodyV4;
        bool v4PuncMac2 = HandshakeV4Active && frame.Length == HeaderSize + CryptoWire.PuncCryptoBodyV4Mac2;
        if (frame.Length is not (HeaderSize + CryptoWire.PuncLegacyBody or HeaderSize + CryptoWire.PuncCryptoBody)
            && !v4Punc && !v4PuncMac2)
        {
            return;
        }

        if (_knock is not null && !v4Punc && !v4PuncMac2)
        {
            return;
        }

        bool cryptoPunc = v4Punc || v4PuncMac2 || frame.Length == HeaderSize + CryptoWire.PuncCryptoBody;
        uint token = BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]);

        ConnectionCrypto? crypto;
        long reply;
        Span<byte> puncSourceKey = stackalloc byte[MaxSocketAddressBytes];
        int puncSourceKeyLength = 0;
        SocketAddress? puncSource = !arrival.ViaRelay && arrival.Tcp is null ? arrival.Direct : null;
        bool puncDirectSource = puncSource is not null;
        if (puncDirectSource)
        {
            puncSourceKeyLength = WriteSourceKey(puncSource!, puncSourceKey);
        }

        lock (c.Gate)
        {

            bool mac1Ok = !v4Punc && !v4PuncMac2 || Mac1OkForConn(c, frame);

            bool sessionCompleted = c.Crypto is { PeerConfirmed: true };
            bool strangerAdmitted = c.StrangerAdmitted;
            c.StrangerAdmitted = false;
            (bool cookieRequired, bool cookieOk) = strangerAdmitted || sessionCompleted ? (false, true)
                : CookieVerdict(
                    frame, v4PuncMac2, mac1Eligible: mac1Ok,
                    sessionCompleted: sessionCompleted, arrival,
                    puncSourceKey, out _);
            bool pricedReplyBlocked = !strangerAdmitted && !sessionCompleted && puncDirectSource
                && !_strangerLedger.TryCharge(puncSourceKey[..puncSourceKeyLength], Environment.TickCount64,
                    BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]));
            if (pricedReplyBlocked)
            {
                Interlocked.Increment(ref _ledgerRefused);
            }

            bool pinMatches = true;
            if (cryptoPunc && c.PinnedStaticKey is { } pinned)
            {
                pinMatches = frame.Slice(HeaderSize + CryptoWire.TokenLength + CryptoWire.EphemeralLength, CryptoWire.StaticKeyLength).SequenceEqual(pinned);
            }

            HandshakeInput input = default;
            input.Kind = HandshakeInputKind.PuncBegin;
            input.CryptoBody = cryptoPunc;
            input.PinMatches = pinMatches;
            input.Mac1Present = v4Punc || v4PuncMac2;
            input.Mac1Ok = mac1Ok;
            input.CookieRequired = cookieRequired;
            input.CookieOk = cookieOk;
            input.PricedReplyBlocked = pricedReplyBlocked;
            input.FrameToken = token;
            StepHandshake(ref c.Handshake, in input, out long kind, out reply);
            if (kind == HandshakeMachine.RejectMac1)
            {

                Interlocked.Increment(ref _mac1Refused);
                Telemetry.FrameRejected("handshake", "mac1");
                return;
            }

            if (kind == HandshakeMachine.RejectPricedReply)
            {
                Telemetry.FrameRejected("handshake", "ledger");
                return;
            }

            if (reply == HandshakeMachine.ReplyCookie)
            {

                Interlocked.Increment(ref _cookieDemanded);
                if (TraceEnabled)
                {
                    TraceLine($"cookie demanded for punc from {c.PeerId:x16} under load");
                }
            }
            else
            {
                Interlocked.Increment(ref c.PuncsReceived);
            }
            if (kind == HandshakeMachine.RejectPin)
            {
                Reject(c, 5);
                c.Crypto?.CountRejected();
                return;
            }
            if (kind == HandshakeMachine.RejectPuncToken)
            {
                Reject(c, 3, c.Handshake.RemoteToken, token, arrival);
                return;
            }
            if (kind == HandshakeMachine.RejectMixedMode)
            {
                Reject(c, 6);
                c.Crypto?.CountRejected();
                return;
            }

            if (kind == HandshakeMachine.NeedKeys)
            {

                Interlocked.Increment(ref _handshakeKeyAgreements);
                ReadOnlySpan<byte> body = frame[(HeaderSize + CryptoWire.TokenLength)..];
                bool accepted = c.Crypto!.TryPeerKeys(
                    body[..CryptoWire.EphemeralLength],
                    body.Slice(CryptoWire.EphemeralLength, CryptoWire.StaticKeyLength));
                HandshakeInput keys = default;
                keys.Kind = HandshakeInputKind.PuncKeys;
                keys.Accepted = accepted;
                keys.FrameToken = token;
                StepHandshake(ref c.Handshake, in keys, out kind, out reply);
                if (kind == HandshakeMachine.RejectPuncKeys)
                {
                    RejectKeys(c, body[..CryptoWire.EphemeralLength]);
                    c.Crypto.CountRejected();
                    return;
                }
            }

            crypto = c.Crypto;
        }

        if (reply == HandshakeMachine.ReplyCookie)
        {
            SendCookieReply(token, puncSourceKey[..puncSourceKeyLength], arrival);
            return;
        }

        if (reply == HandshakeMachine.ReplyPackCrypto)
        {
            SendCryptoPack(c, token, arrival, v4: v4Punc || v4PuncMac2);
            if (arrival.Tcp is { } tcp) SendTcpProof(c, tcp);
            else if (!arrival.ViaRelay && crypto is { PeerConfirmed: true }) SendUdpIntroductionProbe(c, arrival);
        }
        else if (reply == HandshakeMachine.ReplyPackLegacy)
        {
            Span<byte> pack = stackalloc byte[HeaderSize + CryptoWire.PackLegacyBody];
            WriteHeader(pack, FrameType.Pack);
            BinaryPrimitives.WriteUInt32LittleEndian(pack[HeaderSize..], token);
            BinaryPrimitives.WriteUInt32LittleEndian(pack[(HeaderSize + 4)..], c.Token);
            SendOnArrival(arrival, pack);
        }
        else
        {
            return;
        }
        Interlocked.Increment(ref c.PacksSent);
        if (TraceEnabled)
        {
            TraceLine($"answered punc for {c.PeerId:x16} (established={crypto is { Established: true }})");
        }

        if (arrival.ViaRelay)
        {
            RelayPathConfirmed(c, arrival);
        }
        else
        {
            DirectPathConfirmed(c, arrival);
        }
    }

    private void SendCryptoPack(ConnState c, uint echoToken, in Arrival arrival, bool v4)
    {
        ConnectionCrypto crypto = c.Crypto!;
        int packLength = HeaderSize + CryptoWire.PackCryptoBody + (v4 ? CryptoWire.Mac1ExtLength : 0);
        Span<byte> pack = stackalloc byte[packLength];
        WriteHeader(pack, FrameType.Pack);
        BinaryPrimitives.WriteUInt32LittleEndian(pack[HeaderSize..], echoToken);
        BinaryPrimitives.WriteUInt32LittleEndian(pack[(HeaderSize + 4)..], c.Token);
        crypto.MyEphPublic.CopyTo(pack[(HeaderSize + 8)..]);
        crypto.MyStaticPublic.CopyTo(pack[(HeaderSize + 8 + CryptoWire.EphemeralLength)..]);
        crypto.MyConfirm().CopyTo(pack[(HeaderSize + 8 + CryptoWire.EphemeralLength + CryptoWire.StaticKeyLength)..]);
        if (v4)
        {
            CryptoWire.WriteMac1Ext(pack, OwnMac1Key);
        }

        SendOnArrival(arrival, pack);
    }

    private void OnKem(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        if (frame.Length != HeaderSize + CryptoWire.KemBody)
        {
            return;
        }

        lock (c.Gate)
        {
            Interlocked.Increment(ref c.KemsReceived);
            if (c.Crypto is not { Established: true } crypto || crypto.PeerConfirmed || crypto.HybridLatched)
            {
                return;
            }

            if (_mlkemSeed is not { } seed)
            {
                return;
            }

            byte[]? shared = HybridKem.Decapsulate(seed, frame[(HeaderSize + CryptoWire.TokenLength)..]);
            if (shared is null || !crypto.TryUpgradeHybrid(shared))
            {
                return;
            }

            Interlocked.Increment(ref _hybridHandshakes);
            if (TraceEnabled)
            {
                TraceLine($"hybrid upgrade for {c.PeerId:x16} via {(arrival.ViaRelay ? "relay" : arrival.Tcp is not null ? "tcp" : "direct")}");
            }
        }

        SendCryptoPack(c, BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]), arrival, v4: HandshakeV4Active);
        Interlocked.Increment(ref c.PacksSent);
    }

    private void OnPack(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {

        if (frame.Length < HeaderSize + CryptoWire.PackLegacyBody)
        {
            Reject(c, 2);
            return;
        }

        uint echo = BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]);
        uint peerToken = BinaryPrimitives.ReadUInt32LittleEndian(frame[(HeaderSize + CryptoWire.TokenLength)..]);
        bool v4Pack = HandshakeV4Active && frame.Length == HeaderSize + CryptoWire.PackCryptoBodyV4;
        bool cryptoPack = v4Pack || frame.Length == HeaderSize + CryptoWire.PackCryptoBody;
        bool lengthOk = cryptoPack || frame.Length == HeaderSize + CryptoWire.PackLegacyBody;

        if (cryptoPack && c.Crypto is null)
        {
            return;
        }

        bool sendHsck = false;
        bool legacyLatched = false;
        lock (c.Gate)
        {

            bool promisedKnockMac1 = c.PinnedKnock is not null && cryptoPack;
            bool mac1Ok = !v4Pack && !promisedKnockMac1 || Mac1OkForConn(c, frame);

            bool pinMatches = true;
            if (cryptoPack && c.PinnedStaticKey is { } pinned)
            {
                pinMatches = frame.Slice(HeaderSize + 2 * CryptoWire.TokenLength + CryptoWire.EphemeralLength, CryptoWire.StaticKeyLength).SequenceEqual(pinned);
            }

            HandshakeInput input = default;
            input.Kind = HandshakeInputKind.PackBegin;
            input.CryptoBody = cryptoPack;
            input.PinMatches = pinMatches;
            input.BodyPlausible = true;
            input.LengthClassOk = lengthOk;
            input.Mac1Present = v4Pack || promisedKnockMac1;
            input.Mac1Ok = mac1Ok;
            input.FrameToken = echo;
            input.PeerToken = peerToken;
            StepHandshake(ref c.Handshake, in input, out long kind, out _);
            if (kind == HandshakeMachine.RejectMac1)
            {

                Interlocked.Increment(ref _mac1Refused);
                Telemetry.FrameRejected("handshake", "mac1");
                return;
            }

            if (kind == HandshakeMachine.RejectPackEcho)
            {
                Reject(c, 1, c.Token, echo, arrival);
                if (TraceEnabled)
                {
                    TraceLine($"pack token mismatch from {BinaryPrimitives.ReadUInt64LittleEndian(frame[1..]):x16} via {(arrival.ViaRelay ? "relay" : "direct")} (wanted {c.Token:x8}, got {echo:x8})");
                }
                return;
            }
            if (kind == HandshakeMachine.RejectMixedMode)
            {

                Reject(c, 6);
                c.Crypto!.CountRejected();
                HandshakeFailed(c, "encryption was refused by the answering peer: the connection string promised a static key");
                return;
            }
            if (kind == HandshakeMachine.RejectPin)
            {
                Reject(c, 5);
                c.Crypto!.CountRejected();
                HandshakeFailed(c, "peer static key does not match its connection string: possible man in the middle");
                return;
            }
            if (kind == HandshakeMachine.RejectPackPeerToken)
            {
                Reject(c, 8, c.Handshake.RemoteToken, peerToken, arrival);
                c.Crypto!.CountRejected();
                return;
            }

            if (cryptoPack)
            {

                Interlocked.Increment(ref c.PacksReceived);
                if (TraceEnabled)
                {
                    TraceLine($"crypto pack from {c.PeerId:x16} via {(arrival.ViaRelay ? "relay" : arrival.Tcp is not null ? "tcp" : "direct")}");
                }
            }
            else if (lengthOk)
            {
                legacyLatched = true;
            }
            else if (kind == 0)
            {
                return;
            }

            if (kind == HandshakeMachine.NeedKeys)
            {

                Interlocked.Increment(ref _handshakeKeyAgreements);
                ReadOnlySpan<byte> body = frame[(HeaderSize + 2 * CryptoWire.TokenLength)..];
                ReadOnlySpan<byte> eph = body[..CryptoWire.EphemeralLength];
                ReadOnlySpan<byte> stat = body.Slice(CryptoWire.EphemeralLength, CryptoWire.StaticKeyLength);
                ReadOnlySpan<byte> confirm = body.Slice(CryptoWire.EphemeralLength + CryptoWire.StaticKeyLength, CryptoWire.ConfirmLength);
                ConnectionCrypto crypto = c.Crypto!;
                bool accepted = crypto.TryPeerKeys(eph, stat)
                    || crypto.TrySupersedeUnconfirmed(
                        eph,
                        stat,
                        confirm,
                        allowUnexposedIncoming: c.DialAdoptedIncoming && !c.Handshake.RemoteTokenAuthenticated && !c.Connected.Task.IsCompleted);
                if (accepted && crypto.HybridPending && !crypto.VerifyPeerConfirm(confirm)
                    && crypto.ClassicalConfirmMatches(eph, stat, confirm))
                {

                    Interlocked.Increment(ref c.HybridHolds);
                    return;
                }

                bool confirmOk = accepted && crypto.VerifyPeerConfirm(confirm);
                if (confirmOk && crypto.HybridPending && !crypto.PeerConfirmed)
                {
                    Interlocked.Increment(ref _hybridHandshakes);
                }

                HandshakeInput keys = default;
                keys.Kind = HandshakeInputKind.PackKeys;
                keys.Accepted = accepted;
                keys.ConfirmOk = confirmOk;
                keys.FrameToken = echo;
                keys.PeerToken = peerToken;
                StepHandshake(ref c.Handshake, in keys, out kind, out long reply);
                if (kind == HandshakeMachine.RejectPuncKeys)
                {
                    RejectKeys(c, eph);
                    crypto.CountRejected();
                    if (TraceEnabled)
                    {
                        TraceLine($"pack key agreement failed from {c.PeerId:x16}");
                    }
                    return;
                }
                if (kind == HandshakeMachine.RejectPackConfirm)
                {
                    Reject(c, 7);
                    crypto.CountRejected();
                    HandshakeFailed(c, "handshake confirmation failed: the answering peer does not hold the advertised key");
                    return;
                }

                sendHsck = reply == HandshakeMachine.ReplyHsck;
                crypto.MarkPeerConfirmed();
                NoteArrivalValidated(arrival);
            }
        }

        if (legacyLatched)
        {
            Interlocked.Increment(ref c.PacksReceived);
        }

        if (sendHsck)
        {
            Span<byte> hsck = stackalloc byte[HeaderSize + CryptoWire.HsckBody];
            WriteHeader(hsck, FrameType.Hsck);
            BinaryPrimitives.WriteUInt32LittleEndian(hsck[HeaderSize..], c.Token);
            c.Crypto!.MyConfirm().CopyTo(hsck[(HeaderSize + CryptoWire.TokenLength)..]);
            SendOnArrival(arrival, hsck);
        }
        if (cryptoPack)
        {
            if (arrival.Tcp is { } tcp) SendTcpProof(c, tcp);
            else if (!arrival.ViaRelay) SendUdpIntroductionProbe(c, arrival);
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

    private void OnHsck(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        if (frame.Length != HeaderSize + CryptoWire.HsckBody)
        {
            return;
        }

        Interlocked.Increment(ref c.HscksReceived);
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

        NoteArrivalValidated(arrival);

        if (arrival.Tcp is { } tcp) SendTcpProof(c, tcp);

        if (arrival.ViaRelay) RelayPathConfirmed(c, arrival);
        else if (arrival.Tcp is null) SendUdpIntroductionProbe(c, arrival);

        AnnounceTo(c, target: arrival);
    }

    private void HandshakeFailed(ConnState c, string reason)
    {
        lock (c.Gate)
        {

            if (c.State is PinholeConnectionState.Closed || c.Crypto is { PeerConfirmed: true }) return;
            c.Connected.TrySetException(new InvalidOperationException(reason));
            Telemetry.ConnectionRefused(reason);
            Transition(c, PinholeConnectionState.Dead);
            c.Dead.Cancel();
        }
    }

    private void OnCookie(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        if (frame.Length != CryptoWire.CookieFrameLength || c.Crypto is null)
        {
            return;
        }

        uint echo = BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]);
        lock (c.Gate)
        {
            if (echo != c.Token || c.State != PinholeConnectionState.Punching || !c.PuncFrameV4)
            {
                return;
            }

            c.Cookie = frame.Slice(HeaderSize + CryptoWire.TokenLength + 1, CryptoWire.CookieLength).ToArray();
            SetPuncFrame(c);
        }

        if (TraceEnabled)
        {
            TraceLine($"cookie received from {c.PeerId:x16}; retrying punc with mac2");
        }

        KickPunch(c);
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
            return;
        }

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

            if (arrival.Tcp is null && _options.EnablePmtud && wireLength >= PmtuBaseWire)
            {
                lock (c.Gate)
                {
                    PmtuInput evidence = default;
                    evidence.Kind = PmtuInputKind.InboundEvidence;
                    evidence.IPv4 = PmtuPathIsV4NoLock(c);
                    evidence.WireLength = wireLength;
                    PmtuMachine.Step(ref c.Pmtu, in evidence, new Tick(Environment.TickCount64), Span<Effect>.Empty);
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

        long echoed = BinaryPrimitives.ReadInt64LittleEndian(frame[(HeaderSize + 4)..]);
        if (arrival.Tcp is { } stream && stream.AuthenticatedPeer != c.PeerId)
        {
            if (stream.ConfirmProof(c.PeerId, echoed))
            {
                DirectPathConfirmed(c, arrival, sealedEvidence: true);
                if (ReferenceEquals(c.DirectTcp, stream))
                {
                    AnnounceTo(c);
                    KickPunch(c);
                }
                else stream.CloseGracefully();
            }
            return;
        }
        if (echoed < 0)
        {

            lock (c.Gate)
            {
                if (!arrival.ViaRelay && ReferenceEquals(arrival.Tcp, c.ProbeTcp)
                    && ReferenceEquals(arrival.UdpSocket, c.ProbeUdpSocket) && SameEndPoint(arrival.Direct, c.ProbeTarget))
                {
                    bool wasOutstanding = c.Keepalive.ProbeOutstanding;
                    KeepaliveInput ack = default;
                    ack.Kind = KeepaliveInputKind.ProbeAcked;
                    ack.Echo = echoed;
                    KeepaliveMachine.Step(ref c.Keepalive, in ack, new Tick(Environment.TickCount64), Span<Effect>.Empty);
                    if (wasOutstanding && !c.Keepalive.ProbeOutstanding)
                    {
                        c.ProbeTarget = null;
                        Interlocked.Increment(ref c.PathProbeReplies);
                    }
                }
            }

            if (!arrival.ViaRelay && arrival.Direct is { } direct)
            {
                DirectPathConfirmed(c, arrival, sealedEvidence: true);
            }

            return;
        }

        if ((echoed & PmtuMachine.ProbeMarker) != 0)
        {

            lock (c.Gate)
            {
                if (!arrival.ViaRelay && arrival.Tcp is null && ReferenceEquals(arrival.UdpSocket, c.PmtuProbeUdpSocket)
                    && SameEndPoint(arrival.Direct, c.PmtuProbeTarget))
                {
                    PmtuInput ack = default;
                    ack.Kind = PmtuInputKind.PongAcked;
                    ack.Nonce = echoed;
                    PmtuMachine.Step(ref c.Pmtu, in ack, new Tick(Environment.TickCount64), Span<Effect>.Empty);
                }
            }

            if (!arrival.ViaRelay && arrival.Direct is { } pmtuDirect)
            {
                DirectPathConfirmed(c, arrival, sealedEvidence: true);
            }

            return;
        }

        if (!arrival.ViaRelay && arrival.Direct is { } callerDirect)
        {
            DirectPathConfirmed(c, arrival, sealedEvidence: true);
        }

        long nowMs = Environment.TickCount64;
        long rttTicks = (nowMs - echoed) * TimeSpan.TicksPerMillisecond;
        Interlocked.Exchange(ref c.LastRttTicks, rttTicks);
        Interlocked.Increment(ref c.PongsReceived);
        lock (c.Gate)
        {
            KeepaliveInput sample = default;
            sample.Kind = KeepaliveInputKind.RttSample;
            sample.Echo = echoed;
            KeepaliveMachine.Step(ref c.Keepalive, in sample, new Tick(nowMs), Span<Effect>.Empty);
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
            KickPunch(c);
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
            else if (arrival.PacketRelay is { } iro && arrival.PacketRelayPeerKey is { } key)
            {
                iro.Send(key, frame);
            }
            else if (arrival.ViaRelay)
            {
                SendViaRelayTo(frame, arrival.Relay!);
            }
            else if (arrival.Direct is { } direct)
            {
                bool unsealedHandshakeFrame = frame.Length > 0 && frame[0]
                    is (byte)FrameType.Punc or (byte)FrameType.Pack or (byte)FrameType.Hsck
                        or (byte)FrameType.Cookie or (byte)FrameType.Kem;
                bool viaInterfaceSlot = arrival.UdpSocket is { } candidate && _interfaceUdp?.Contains(candidate) == true;
                if (arrival.UdpSocket is { } socket && (!viaInterfaceSlot || unsealedHandshakeFrame))
                {
                    socket.SendTo(frame, direct);
                }
                else
                {
                    SendToWire(direct, frame);
                }
            }
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
        {

        }
    }

    private void SendUdpIntroductionProbe(ConnState c, in Arrival arrival)
    {
        if (c.Crypto is not { Established: true }) return;
        if (c.AwaitInitialCandidateExchange && !Volatile.Read(ref c.PeerCandidatesReceived)) return;
        Span<byte> payload = stackalloc byte[8];
        RandomNumberGenerator.Fill(payload);

        BinaryPrimitives.WriteInt64LittleEndian(payload, BinaryPrimitives.ReadInt64LittleEndian(payload) | KeepaliveMachine.ProbeMarker);
        Span<byte> frame = stackalloc byte[PmtuBaseWire];
        int length = BuildFloorPing(c, payload, frame);
        SendOnArrival(arrival, frame[..length]);
    }

    private int BuildFloorPing(ConnState c, ReadOnlySpan<byte> leading, Span<byte> frame)
    {
        Span<byte> body = stackalloc byte[PmtuBaseWire - PmtuOverhead];
        leading.CopyTo(body);
        body[leading.Length..].Clear();
        return BuildFrame(c, FrameType.Ping, body, frame);
    }

    private void AnnounceTo(ConnState c, bool blast = false, Arrival? target = null)
    {
        if (c.IsIncoming && c.Crypto is not { PeerConfirmed: true }) return;
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
                payload.SetLength(0);
                payload.WriteByte(0);
                break;
            }
        }

        byte[] body = payload.GetBuffer();
        int bodyLen = (int)payload.Length;

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

            SendOnArrival(CurrentArrival(c), frame);
            PinholeCandidate[] targets;
            lock (_gate)
            {
                targets = c.PeerCandidates.ToArray();
            }

            foreach (PinholeCandidate target in targets)
            {
                if (target.Kind is CandidateKind.IrohRelay or CandidateKind.DerpRelay)
                {
                    SendViaKeyedRelay(frame, target);
                }
                else if (target.Kind == CandidateKind.Relay)
                {
                    try
                    {
                        SendViaRelayTo(frame, target.Address, target.RelayServer?.Address);
                    }
                    catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
                    {

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

        if (c.PacketRelay is { IsAlive: true } iro && c.PacketRelayConfirmed && c.PacketRelayPeerKey is { } key)
            return new Arrival(iro, key);
        return c.RelayRemote is { } ep ? new Arrival(ep) : default;
    }

    private static readonly bool TraceEnabled = Environment.GetEnvironmentVariable("PINHOLE_TRACE") == "1"
        || Environment.GetEnvironmentVariable("PINHOLE_TRACE_FILE") is { Length: > 0 };

    private static readonly object TraceGate = new();

    internal static void TraceTransport(string message)
    {
        if (TraceEnabled) TraceLine(message);
    }

    private static void TraceLine(string line)
    {

        if (Environment.GetEnvironmentVariable("PINHOLE_TRACE") == "1")
        {
            Console.WriteLine("[pinhole] " + line);
        }
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
                return;
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

                Volatile.Write(ref c.LastDirectRxTicks, Environment.TickCount64);
                return;
            }

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

            if (c.Pmtu.Wire != 0 || c.Pmtu.Outstanding)
            {
                PmtuInput migrated = default;
                migrated.Kind = PmtuInputKind.PathMigrated;
                PmtuMachine.Step(ref c.Pmtu, in migrated, new Tick(Environment.TickCount64), Span<Effect>.Empty);
            }

            if (c.Connected.Task.IsFaulted)
            {
                return;
            }

            if (c.State != PinholeConnectionState.Open)
            {
                PathSelectorInput direct = DirectVerdict(c);
                StepPathSelector(c, in direct);
                c.PathSince = DateTimeOffset.UtcNow;
                Interlocked.Exchange(ref c.ConsecutiveSendFailures, 0);
                ResetPathProbesNoLock(c);
                c.Connected.TrySetResult();
                c.StateChanged?.Invoke(c.State);
            }
            else if (c.Path != PathKind.Direct)
            {

                PathSelectorInput direct = DirectVerdict(c);
                StepPathSelector(c, in direct);
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
        if (arrival.PacketRelay is not { } relay)
        {
            RelayPathConfirmed(c, arrival.Relay!);
            return;
        }

        bool kick = false;
        lock (c.Gate)
        {
            if (c.State == PinholeConnectionState.Closed || c.Connected.Task.IsFaulted) return;

            if (c.PacketRelay is not { IsAlive: true } || !c.PacketRelayConfirmed)
            {
                c.PacketRelay = relay;
                c.PacketRelayPeerKey = arrival.PacketRelayPeerKey;
                c.PacketRelayConfirmed = true;
            }
            PathSelectorInput relayVerdict = RelayVerdict(c);
            if (StepPathSelector(c, in relayVerdict))
            {
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

            if (c.RelayReady)
            {

                PromoteRelayLegNoLock(c);
                return;
            }

            if (Interlocked.CompareExchange(ref c.PermitInFlight, 1, 0) != 0)
            {
                return;
            }

            c.RelayRemote = peerRelayed;

        }

        _ = PermitRelayAsync(c, peerRelayed);
    }

    private void PromoteRelayLegNoLock(ConnState c)
    {
        PathSelectorInput relay = RelayVerdict(c);
        if (StepPathSelector(c, in relay))
        {
            c.PathSince = DateTimeOffset.UtcNow;
            if (c.IsIncoming && !c.IncomingQueued)
            { c.IncomingQueued = true; _incoming?.Writer.TryWrite(c); }
            c.Connected.TrySetResult();
            c.StateChanged?.Invoke(c.State);
            KickPunch(c);
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
                    return;
                }
            }

            lock (c.Gate)
            {
                if (c.RelayRemote is { } current && !current.Address.Equals(peer.Address))
                {
                    return;
                }

                c.RelayReady = true;
                Telemetry.Recovery("relay-heal");
                if (c.State == PinholeConnectionState.Closed) return;
                PromoteRelayLegNoLock(c);
            }

            if (_options.RelaySignalingOnly) AnnounceTo(c);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or InvalidOperationException or TimeoutException or ObjectDisposedException)
        {

        }
        finally
        {
            Volatile.Write(ref c.PermitInFlight, 0);
        }
    }

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
                    slot.Client = null;
                }
            }
        }

        await EnsureRelaysAsync(CancellationToken.None).ConfigureAwait(false);
        Telemetry.Recovery("relay-reallocate");
    }

    public void NotifyPathSuspect(ConnState c)
    {
        lock (c.Gate)
        {
            if (c.State is not (PinholeConnectionState.Open or PinholeConnectionState.Degraded))
            {
                return;
            }

            bool legAlive = c.PacketRelay is { IsAlive: true } && c.PacketRelayConfirmed;
            bool permitted = c.RelayRemote is not null && c.RelayReady;
            PathSelectorInput verdict = default;
            verdict.Kind = PathSelectorInputKind.DirectLost;
            verdict.RelayUsable = c.State == PinholeConnectionState.Open
                ? !_options.RelaySignalingOnly && (legAlive || permitted)
                : legAlive || permitted;
            if (StepPathSelector(c, in verdict))
            {
                c.StateChanged?.Invoke(c.State);
            }
        }

        KickPunch(c);
        Telemetry.Recovery("path-suspect");

        if (c.RelayRemote is { } relayPeer && Interlocked.CompareExchange(ref c.PermitInFlight, 1, 0) == 0)
        {
            _ = PermitRelayAsync(c, relayPeer);
        }

        if (c.PinnedEndpointKey is { } pinned && _lookup.Count > 0)
        {
            _ = ResolveViaLookupAsync(c, pinned, CancellationToken.None);
        }
    }

    private static bool StepPathSelector(ConnState c, in PathSelectorInput input)
    {
        PathSelectorState selector = PathSelectorState.Create((ConnPhase)c.State, (PathSel)c.Path);
        Span<Effect> effects = stackalloc Effect[1];
        int n = PathSelectorMachine.Step(ref selector, in input, new Tick(Environment.TickCount64), effects);
        c.State = (PinholeConnectionState)selector.Phase;
        c.Path = (PathKind)selector.Path;
        return n > 0;
    }

    private static PathSelectorInput DirectVerdict(ConnState c)
    {
        PathSelectorInput input = default;
        input.Kind = PathSelectorInputKind.DirectConfirmed;
        return input;
    }

    private PathSelectorInput RelayVerdict(ConnState c)
    {
        PathSelectorInput input = default;
        input.Kind = PathSelectorInputKind.RelayConfirmed;
        input.PeerConfirmed = c.Crypto is null || c.Crypto.PeerConfirmed;
        input.RelaySignalingOnly = _options.RelaySignalingOnly;
        return input;
    }

    private void Transition(ConnState c, PinholeConnectionState state)
    {
        lock (c.Gate)
        {
            if (c.State == PinholeConnectionState.Closed)
            {
                return;
            }

            PathSelectorInput verdict = default;
            verdict.Kind = PathSelectorInputKind.Forced;
            verdict.ForcedPhase = (byte)state;
            StepPathSelector(c, in verdict);
            if (state == PinholeConnectionState.Closed)
            {
                c.Closed.TrySetResult();
                c.Buffer?.Complete();
            }

            c.StateChanged?.Invoke(state);
        }
    }

    public async Task RecoverAsync(bool forceRebind, CancellationToken ct)
    {
        if (_disposed || Interlocked.Exchange(ref _recovering, 1) != 0)
        {
            return;
        }

        try
        {
            RefreshInterfaceCandidates();
            RefreshIPv6Firewall();
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
                            return;
                        }

                        _reflexive.Clear();
                        _reflexive.Add(probe);
                        RefreshLocalCandidatesNoLock();
                    }

                    foreach (ConnState c in ConnectionsSnapshot())
                    {
                        if (c.State != PinholeConnectionState.Closed)
                        {
                            AnnounceTo(c);
                        }
                    }

                    return;
                }

                needRebind = true;
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
            _mappedEndpoint = null;
            _mappedTcpEndpoint = null;
        }

        foreach (TurnClient client in oldClients)
        {
            client.Received -= HandleRelayData;
            _ = client.DisposeAsync();
        }

        _portMap?.Rebind(_udp.LocalEndPoint.Port);
        _tcpPortMap?.Rebind(_tcp?.ListeningPort ?? 0);
        RefreshInterfaceCandidates(invalidate: true);
        RefreshIPv6Firewall(invalidate: true);
        await Task.WhenAll(ProbeStunAllAsync(ct), EnsureRelaysAsync(ct), EnsureKeyedRelaysAsync(ct)).ConfigureAwait(false);
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
                c.DirectRemote = null;
                c.DirectRemoteEp = null;
                if (c.State == PinholeConnectionState.Open)
                {
                    PathSelectorInput verdict = default;
                    verdict.Kind = PathSelectorInputKind.DirectLost;
                    verdict.RelayUsable = c.PacketRelay is { IsAlive: true } && c.PacketRelayConfirmed;
                    if (StepPathSelector(c, in verdict))
                    {
                        c.StateChanged?.Invoke(c.State);
                    }
                }
            }

            if (c.RelayRemote is not null)
            {

                c.RelayReady = false;
                _ = PermitRelayAsync(c, c.RelayRemote);
            }

            AnnounceTo(c, blast: true);
            KickPunch(c);
        }
    }

    internal Task SimulateInterfaceLossAsync() => RecoverAsync(forceRebind: true, CancellationToken.None);

    internal IReadOnlyList<(IPEndPoint Server, IPEndPoint? Relayed)> RelayAllocations()
    {
        lock (_gate)
        {
            return _relays.Select(r => (r.Config.Server, r.Client is { IsAlive: true } c ? c.RelayedAddress : null)).ToList();
        }
    }

    internal (IPEndPoint? Remote, bool Ready) PeerRelayLeg(ulong peerId)
    {
        lock (_gate)
        {
            return _conns.TryGetValue(peerId, out ConnState? c) ? (c.RelayRemote, c.RelayReady) : (null, false);
        }
    }

    internal int RelaysConfiguredCount
    {
        get { lock (_gate) return _relays.Count; }
    }

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

    internal void SimulateSilentDirectPathLoss(ulong peerId)
    {
        if (Lookup(peerId) is { } c)
        {
            c.BlackholeDirect = true;
        }
    }

    internal void SimulateDirectPathRestore(ulong peerId)
    {
        if (Lookup(peerId) is { } c)
        {
            c.BlackholeDirect = false;
        }
    }

    internal void RetryPunch(ulong peerId)
    {
        if (Lookup(peerId) is { } c)
        {
            KickPunch(c);
        }
    }

    internal string HandshakeSummary(ulong peerId)
    {
        if (Lookup(peerId) is { } c)
        {
            return LiveHandshakeSummary(c);
        }

        return _lastClosedHandshake.TryGetValue(peerId, out ClosedHandshake? last)
            ? last.Summary + " (since closed)"
            : "no conn";
    }

    private void Reject(ConnState c, int kind, uint wanted = 0, uint got = 0, in Arrival arrival = default)
    {
        Interlocked.Increment(ref c.HandshakeRejects);
        Interlocked.Increment(ref c.RejectsByKind[kind]);
        Volatile.Write(ref c.LastRejectKind, kind);
        if (kind is 1 or 3 or 8)
        {
            Volatile.Write(ref c.LastRejectWanted, wanted);
            Volatile.Write(ref c.LastRejectGot, got);
            Volatile.Write(ref c.LastRejectFrom,
                arrival.Direct is { } d ? ToEndpoint(d).ToString()
                : arrival.Tcp is null ? arrival.Relay?.ToString() : "tcp");
        }
    }

    private static void RejectKeys(ConnState c, ReadOnlySpan<byte> arrivingEph)
    {
        Interlocked.Increment(ref c.HandshakeRejects);
        Interlocked.Increment(ref c.RejectsByKind[4]);
        Volatile.Write(ref c.LastRejectKind, 4);
        if (Volatile.Read(ref c.RejectsByKind[4]) == 1)
        {
            c.Crypto?.NoteKeyReject(arrivingEph);
        }
    }

    private static string LiveHandshakeSummary(ConnState c)
    {
        string line = $"self={c.Token:x8} remote={(c.Handshake.RemoteTokenKnown ? c.Handshake.RemoteToken.ToString("x8") : "-")} "
            + $"my-eph={c.Crypto?.MyEphPrefix ?? "-"} "
            + $"punc↑{Volatile.Read(ref c.PuncsSent)} punc↓{Volatile.Read(ref c.PuncsReceived)} "
            + $"pack↑{Volatile.Read(ref c.PacksSent)} pack↓{Volatile.Read(ref c.PacksReceived)} "
            + $"hsck↓{Volatile.Read(ref c.HscksReceived)} rejects={Volatile.Read(ref c.HandshakeRejects)}";
        long kind = Volatile.Read(ref c.LastRejectKind);
        if (kind != 0)
        {
            line += RejectSuffix(kind, c);
        }
        if (Volatile.Read(ref c.HandshakeRejects) > 0)
        {
            long[] byKind = c.RejectsByKind;
            line += $" by-kind[{string.Join(",", Enumerable.Range(1, byKind.Length - 1).Select(k => $"{k}:{Volatile.Read(ref byKind[k])}"))}]";
        }
        if (c.Crypto is { } crypto && Volatile.Read(ref crypto.SupersededLatches) > 0)
        {
            line += $" latch-healed={Volatile.Read(ref crypto.SupersededLatches)}";
        }
        return line;
    }

    private static string RejectSuffix(long kind, ConnState c) => kind switch
    {
        1 => $" last=pack-token wanted {Volatile.Read(ref c.LastRejectWanted):x8} got {Volatile.Read(ref c.LastRejectGot):x8} from {Volatile.Read(ref c.LastRejectFrom) ?? "?"}",
        2 => " last=pack-length",
        3 => $" last=punc-token wanted {Volatile.Read(ref c.LastRejectWanted):x8} got {Volatile.Read(ref c.LastRejectGot):x8} from {Volatile.Read(ref c.LastRejectFrom) ?? "?"}",
        4 => " last=punc-keys" + (c.Crypto?.KeyRejectSummary ?? ""),
        5 => " last=punc-pin",
        6 => " last=mixed-mode",
        7 => " last=pack-confirm",
        8 => $" last=pack-peer-token wanted {Volatile.Read(ref c.LastRejectWanted):x8} got {Volatile.Read(ref c.LastRejectGot):x8} from {Volatile.Read(ref c.LastRejectFrom) ?? "?"}",
        _ => "",
    };

    internal string RecvDiagnostics() =>
        $"rx={Volatile.Read(ref _recvDatagrams)} last-rx-ago={(_recvLastTick == 0 ? -1 : Environment.TickCount64 - Volatile.Read(ref _recvLastTick))}ms no-conn-drops={Volatile.Read(ref _noConnDrops)}";

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

        _portMap?.Shutdown();
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

            _udp?.Dispose();
            _tcp?.Dispose();
            foreach (IrohRelay relay in _irohRelays.Values) relay.Dispose();
            foreach (DerpRelay relay in _derpRelays.Values) relay.Dispose();
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

    private byte[] BuildPunc(ConnState c, bool v4)
    {

        byte[]? mac2Key = v4 ? c.Cookie : null;
        byte[] frame = new byte[HeaderSize + (c.Crypto is null ? CryptoWire.PuncLegacyBody
            : CryptoWire.PuncCryptoBody + (v4 ? CryptoWire.Mac1ExtLength + (mac2Key is null ? 0 : CryptoWire.Mac2ExtLength) : 0))];
        frame[0] = (byte)FrameType.Punc;
        BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(1), _peerId);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(HeaderSize), c.Token);
        if (c.Crypto is { } crypto)
        {
            crypto.MyEphPublic.CopyTo(frame.AsSpan(HeaderSize + CryptoWire.TokenLength));
            crypto.MyStaticPublic.CopyTo(frame.AsSpan(HeaderSize + CryptoWire.TokenLength + CryptoWire.EphemeralLength));
            if (v4)
            {

                byte[] mac1Key = Mac1KeyFor(c);
                if (mac2Key is { } cookie)
                {
                    CryptoWire.WriteMac1Ext(frame.AsSpan()[..^CryptoWire.Mac2ExtLength], mac1Key);
                    CryptoWire.WriteMac2Ext(frame, cookie);
                }
                else
                {
                    CryptoWire.WriteMac1Ext(frame, mac1Key);
                }
            }
        }

        return frame;
    }

    private void SetPuncFrame(ConnState c)
    {
        c.PuncFrame = BuildPunc(c, v4: HandshakeV4Active && c.Crypto is not null);
        c.PuncFrameV4 = HandshakeV4Active && c.Crypto is not null;
        Volatile.Write(ref c.FirstPuncTicks, 0);
    }

    private static void NotePuncSent(ConnState c)
    {
        if (Volatile.Read(ref c.FirstPuncTicks) == 0)
        {
            Volatile.Write(ref c.FirstPuncTicks, Environment.TickCount64);
        }
    }

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
        BinaryPrimitives.WriteUInt64LittleEndian(frame[1..], _peerId);
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
