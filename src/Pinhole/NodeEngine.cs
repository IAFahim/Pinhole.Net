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
}

// Wire authentication model: every frame carries the sender's per-connection token at
// offset HeaderSize. Punc teaches the receiver the dialer's token, Pack delivers the
// responder's, and every later frame must echo the token the receiver learned. The token
// is random per connection and never appears in the connection string, so holding the
// string (public by design) lets a stranger dial, but not spoof, hijack, or kill an
// established session.

/// <summary>Per-peer state. One node multiplexes many of these over its single UDP socket;
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
    public IPEndPoint? RelayRemote;          // peer's relayed address
    public volatile bool RelayReady;         // permission for RelayRemote exists on our allocation
    public readonly List<PinholeCandidate> PeerCandidates = new(); // guarded by engine gate
    public bool SymmetricHint;               // peer advertised a symmetric NAT: relay-first scheduling
    public uint RemoteToken;                 // learned from the peer's frames; staleness filter
    public bool RemoteTokenKnown;
    public ConnectionCrypto? Crypto;         // handshake + sealers; null = plaintext session (guarded by Gate for the handshake fields)
    public byte[]? PinnedStaticKey;          // the v2 connection string's static key (dial side, immutable)
    public bool HsckSent;                    // Gate: our confirm went out in an Hsck frame
    public bool Announced;
    public DateTimeOffset LastKick = DateTimeOffset.UtcNow;
    public volatile bool BlackholeDirect;    // test hook: drop this peer's direct frames
    public int PunchGeneration;
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
    public bool PmtuOutstanding;           // Gate
    public long PmtuProbeNonce;            // Gate; TickCount64 | PmtuProbeMarker
    public int PmtuProbeSize;              // Gate; wire bytes of the outstanding probe
    public int PmtuProbeTries;             // Gate
    public long PmtuDeadlineTicks;         // Gate
    public SocketAddress? PmtuProbeTarget; // Gate; the endpoint the probe went to
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

internal sealed class NodeEngine : IDisposable
{
    public const int MaxPayload = 1200;
    private const int HeaderSize = CryptoWire.HeaderLength;

    /// <summary>Upper bound on connections a stranger flood can materialize. Applications
    /// dialing peers themselves are not bounded by this — only unknown-peer PUNCs are.</summary>
    internal const int MaxConnections = 1024;

    // Must exceed the largest legit announce: HeaderSize + token + count + 32 fat relay
    // candidates (~170 bytes each) lands near 5.5 KB; a smaller buffer would truncate and
    // silently drop exactly the relay-heavy announces that matter most.
    private const int RecvBufferSize = 8192;
    private const uint StunCookie = 0x2112A442;

    private static readonly TimeSpan PunchPace = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan UpgradePace = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan SymmetricDirectTrickle = TimeSpan.FromSeconds(1);
    private const int MaxUpgradeAttempts = 120; // then passive: peer frames can still open direct
    private static readonly TimeSpan RelayRetryBackoff = TimeSpan.FromSeconds(30);
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
    private const long PmtuReprobeDelayMs = 300_000; // RFC 8899: re-probe a settled path periodically
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
    private readonly RelayIdentity? _relayIdentity;
    private readonly List<PinholeCandidate> _localCandidates = new(); // guarded by _gate
    private readonly List<IPEndPoint> _reflexive = new();             // guarded by _gate
    private IPEndPoint? _mappedEndpoint;                              // router-granted mapping (UPnP/PMP/PCP), guarded by _gate
    private NatHint _observedNatHint;                                 // derived from multi-server STUN observations, guarded by _gate
    private PortMappingService? _portMap;
    private readonly ConcurrentDictionary<ulong, TaskCompletionSource<IPEndPoint>> _stunPending = new();
    private readonly CancellationTokenSource _shutdown = new();

    // Volatile: sends and the receive loop read it per frame without taking _gate. A rebind
    // swaps in a fresh socket; a sender briefly racing the swap gets the old socket and a
    // caught ObjectDisposedException — the same send-failure handling a dead path already
    // triggers, and rebinds are rare.
    private volatile IUdpSocket _udp = null!;
    private long _recovering; // single-flight guard for recovery
    private volatile bool _disposed;
    private int _networkWatchHooked;
    private Task? _maintenance; // one scheduler for the whole node (path validation + STUN refresh)
    private long _nextStunRefreshTicks; // maintenance deadline; 0 = refresh disabled
    private int _stunRefreshing; // single-flight guard for reflexive refreshes

    public NodeEngine(PinholeOptions options)
    {
        if ((options.IrohRelayUrls ?? options.ResolvedIrohRelays).Count > 0)
            _relayIdentity = new RelayIdentity();
        _peerId = _relayIdentity?.PeerId ?? BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        _options = options;
        _identity = options.Encryption != PinholeEncryption.Disabled ? new NodeIdentity(options.IdentityKeySeed) : null;
        _incoming = options.Listen ? Channel.CreateUnbounded<ConnState>() : null;
    }

    public ulong PeerId => _peerId;

    /// <summary>This node's long-term X25519 public key (32 bytes), embedded in v2 connection
    /// strings and used to authenticate every session's far end; null on plaintext nodes.</summary>
    public byte[]? StaticPublicKey => _identity?.PublicKey;

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
    }

    // ------------------------------------------------------------------ bind

    public async Task BindAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            _udp = CreateSocket(_options.Bind);
        }

        StartRecvLoop();

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

        // Router port mapping (UPnP/PMP/PCP): entirely background, entirely best-effort.
        // A loopback bind can never be reached through a router, so it skips the chatter.
        bool bindIsLoopback = _options.Bind is { } bound
            && (bound.Address.Equals(IPAddress.Loopback) || bound.Address.Equals(IPAddress.IPv6Loopback));
        if (_options.EnablePortMapping && !bindIsLoopback)
        {
            _portMap = new PortMappingService(_options, OnPortMappingChanged);
            _portMap.Ensure(LocalPort);
        }

        if (_options.EnablePathValidation || _options.StunRefreshInterval > TimeSpan.Zero || _portMap is not null)
        {
            if (_options.StunRefreshInterval > TimeSpan.Zero)
            {
                _nextStunRefreshTicks = Environment.TickCount64 + (long)_options.StunRefreshInterval.TotalMilliseconds;
            }

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
        lock (_gate)
        {
            return _localCandidates.Take(ConnectionString.MaxCandidates).ToArray();
        }
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
    public IPEndPoint? MappedEndpointSnapshot()
    {
        lock (_gate)
        {
            return _mappedEndpoint;
        }
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
    private void OnPortMappingChanged(IPEndPoint? mapped)
    {
        lock (_gate)
        {
            if (Equals(_mappedEndpoint, mapped))
            {
                return;
            }

            _mappedEndpoint = mapped;
            RefreshLocalCandidatesNoLock();
        }

        if (mapped is not null)
        {
            foreach (ConnState c in ConnectionsSnapshot())
            {
                if (c.State != PinholeConnectionState.Closed)
                {
                    AnnounceTo(c);
                }
            }
        }
    }

    private void RefreshLocalCandidates()
    {
        lock (_gate)
        {
            RefreshLocalCandidatesNoLock();
        }
    }

    /// <summary>Caller must hold <see cref="_gate"/>. Split out so the STUN refresh can
    /// swap the reflexive set and rebuild the advertised candidates as ONE critical
    /// section — otherwise an observer can see the new <c>PublicEndpoints</c> while the
    /// connection string still carries the old mapping.</summary>
    private void RefreshLocalCandidatesNoLock()
    {
        int port = LocalPort;
        _localCandidates.Clear();
        _localCandidates.Add(new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, port)));
        foreach (IPEndPoint ep in HostEndpoints(port))
        {
            _localCandidates.Add(new PinholeCandidate(CandidateKind.Direct, ep));
        }

        foreach (IPEndPoint ep in _reflexive)
        {
            _localCandidates.Add(new PinholeCandidate(CandidateKind.Reflexive, ep));
        }

        // A router-granted mapping is advertised as a reflexive candidate: it is an address
        // the world can use to reach this socket, exactly like a STUN observation, and the
        // peer needs no new wire semantics to punch it.
        if (_mappedEndpoint is { } mapped && !_localCandidates.Any(c => c.Kind == CandidateKind.Reflexive && c.Address.Equals(mapped)))
        {
            _localCandidates.Add(new PinholeCandidate(CandidateKind.Reflexive, mapped));
        }

        foreach (TurnClient client in AliveRelayClientsNoLock())
        {
            if (client.RelayedAddress is { } relayed)
            {
                _localCandidates.Add(new PinholeCandidate(CandidateKind.Relay, relayed, client.Server, client.Username, client.Credential));
            }
        }

        if (_relayIdentity is not null)
        {
            foreach (IrohRelay relay in _irohRelays.Values.Where(r => r.IsAlive))
                _localCandidates.Add(new PinholeCandidate(CandidateKind.IrohRelay,
                    new IPEndPoint(IPAddress.None, 0), RelayUrl: relay.Url, RelayKey: _relayIdentity.PublicKey));
        }
    }

    private static List<IPEndPoint> HostEndpoints(int port)
    {
        var seen = new HashSet<IPAddress>();
        var list = new List<IPEndPoint>();
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
                    if (ip.IsIPv6LinkLocal || ip.IsIPv6Teredo || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Loopback))
                    {
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

        return list;
    }

    // ------------------------------------------------------------------ STUN

    public async Task<IPEndPoint> ProbeStunAsync(IPEndPoint server, CancellationToken ct = default)
    {
        byte[] req = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(req, 0x0001);
        BinaryPrimitives.WriteUInt32BigEndian(req.AsSpan(4), StunCookie);
        RandomNumberGenerator.Fill(req.AsSpan(8));
        ulong key = BinaryPrimitives.ReadUInt64BigEndian(req.AsSpan(8));
        var tcs = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
        _stunPending[key] = tcs;
        try
        {
            _udp.SendTo(req, ToWire(server));
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
    /// mean per-destination (symmetric) — the hint dialers use to skip a hopeless punch.
    /// One observation can never distinguish the behaviors, and a pass where too few
    /// servers answered never clears an earlier, better-informed classification.</summary>
    private void ObserveNatHint(IPEndPoint[] observedPerServer)
    {
        if (observedPerServer.Length < 2)
        {
            return;
        }

        NatHint seen = observedPerServer.Distinct().Count() > 1 ? NatHint.Symmetric : NatHint.Cone;
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
        IReadOnlyList<IPEndPoint> servers = ResolvedStun();
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
    {
        try
        {
            return await ProbeStunAsync(server, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or TimeoutException or ObjectDisposedException)
        {
            return null;
        }
    }

    private IReadOnlyList<IPEndPoint> ResolvedStun() => _options.StunServers ?? _options.ResolvedStun;

    private void OnStunResponse(byte[] buf, int n)
    {
        if (n < 20)
        {
            return;
        }

        ulong key = BinaryPrimitives.ReadUInt64BigEndian(buf.AsSpan(8));
        if (!_stunPending.TryGetValue(key, out TaskCompletionSource<IPEndPoint>? tcs))
        {
            return;
        }

        int end = Math.Min(n, 20 + BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(2)));
        int pos = 20;
        while (pos + 4 <= end)
        {
            ushort attrType = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(pos));
            int attrLen = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(pos + 2));
            if (pos + 4 + attrLen > end)
            {
                break; // a hostile or broken server claims an attribute past the message end
            }

            if ((attrType is 0x0020 or 0x0001) && attrLen >= 8
                && TryDecodeAddress(buf.AsSpan(pos + 4, attrLen), buf.AsSpan(8, 12), attrType == 0x0020, out IPEndPoint? ep))
            {
                tcs.TrySetResult(ep!);
                return;
            }

            pos += 4 + ((attrLen + 3) & ~3);
        }
    }

    private static bool TryDecodeAddress(ReadOnlySpan<byte> value, ReadOnlySpan<byte> txid, bool xor, out IPEndPoint? ep)
    {
        ep = null;
        byte family = value[1];
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(value[2..]);
        if (xor)
        {
            port ^= (ushort)(StunCookie >> 16);
        }

        if (family == 0x01 && value.Length >= 8)
        {
            Span<byte> raw = stackalloc byte[4];
            value.Slice(4, 4).CopyTo(raw);
            if (xor)
            {
                raw[0] ^= 0x21;
                raw[1] ^= 0x12;
                raw[2] ^= 0xA4;
                raw[3] ^= 0x42;
            }

            ep = new IPEndPoint(new IPAddress(raw), port);
            return true;
        }

        if (family == 0x02 && value.Length >= 20)
        {
            Span<byte> raw = stackalloc byte[16];
            value.Slice(4, 16).CopyTo(raw);
            if (xor)
            {
                Span<byte> mask = stackalloc byte[16];
                BinaryPrimitives.WriteUInt32BigEndian(mask, StunCookie);
                txid.CopyTo(mask[4..]);
                for (int i = 0; i < 16; i++)
                {
                    raw[i] ^= mask[i];
                }
            }

            ep = new IPEndPoint(new IPAddress(raw), port);
            return true;
        }

        return false;
    }

    // ------------------------------------------------------------------ relays

    private IrohRelay? IrohRelayFor(Uri url)
    {
        if (_relayIdentity is null || _disposed) return null;
        IrohRelay relay;
        lock (_gate)
        {
            if (_irohRelays.TryGetValue(url, out relay!)) return relay;
            if (_irohRelays.Count >= ConnectionString.MaxCandidates) return null;
            relay = new IrohRelay(url, _relayIdentity);
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
        if (_disposed || frame.Length < HeaderSize + 4
            || frame[0] is < (byte)FrameType.Punc or > (byte)FrameType.Hsck) return;
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
            }
        }
        catch (Exception)
        {
            // Servers see every client at once when an allocation expires or a relay restarts;
            // jitter spreads that herd without meaningfully delaying anyone.
            slot.NextRetry = DateTimeOffset.UtcNow + Jitter(RelayRetryBackoff);
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

    public ConnState ConnectAsync(ConnectionString cs, CancellationToken ct)
    {
        var c = new ConnState
        {
            PeerId = cs.PeerId,
            Token = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)),
            SymmetricHint = cs.NatHint == NatHint.Symmetric,
            // Crypto is attempted exactly when the string vouches for a static key: a v2
            // string's publisher speaks the handshake, a v1 string's does not, so nothing is
            // negotiated on the wire — no downgrade window exists to strip.
            PinnedStaticKey = _identity is not null && cs.StaticKey is not null ? cs.StaticKey : null,
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
        // Stranger flood bound, checked BEFORE the insert: with the single receive thread
        // as the only writer, the table then never crosses the bound at all, and no
        // observer can catch the overshoot window an insert-then-remove would leave. The
        // post-insert check below stays for the rare case of a concurrent dial landing
        // between this read and the insert.
        if (_conns.Count >= MaxConnections)
        {
            return null;
        }

        var c = new ConnState
        {
            PeerId = peerId,
            Token = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)),
            RemoteToken = token,
            RemoteTokenKnown = true,
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

        if (_conns.Count > MaxConnections)
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
            DirectPathConfirmed(c, arrival.Direct!);
        }

        _incoming?.Writer.TryWrite(c);
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
        c.Dead.Cancel();
        await Task.CompletedTask.ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ punch

    public void KickPunch(ConnState c)
    {
        lock (c.Gate)
        {
            c.LastKick = DateTimeOffset.UtcNow;
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
                if (c.State is PinholeConnectionState.Open or PinholeConnectionState.Closed)
                {
                    return;
                }

                if (c.State == PinholeConnectionState.Degraded && ++upgradeAttempts > MaxUpgradeAttempts)
                {
                    return; // stop poking; direct can still open passively from the peer's frames
                }

                if (c.State == PinholeConnectionState.Punching)
                {
                    lock (c.Gate)
                    {
                        if (DateTimeOffset.UtcNow - c.LastKick > _options.ConnectTimeout)
                        {
                            Transition(c, PinholeConnectionState.Dead);
                            return;
                        }
                    }
                }

                PinholeCandidate[] candidates;
                lock (_gate)
                {
                    candidates = c.PeerCandidates.ToArray();
                }

                // A symmetric hint is scheduling advice, not a ban: relay candidates carry
                // the session — per-destination mappings make public reflexives hopeless —
                // while direct candidates keep a one-second trickle. LAN peers (no NAT in
                // the way) and router-mapped endpoints (punch-anywhere by construction)
                // still connect directly even when the hint says the NAT maps
                // per-destination; the hopeless cases cost one datagram per second.
                bool punchDirects = !c.SymmetricHint || DateTimeOffset.UtcNow - lastDirectPunch >= SymmetricDirectTrickle;
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

                    try
                    {
                        if (candidate.Kind == CandidateKind.IrohRelay)
                        {
                            SendViaIroh(c.PuncFrame, candidate);
                        }
                        else if (candidate.Kind == CandidateKind.Relay)
                        {
                            SendViaRelayTo(c.PuncFrame, candidate.Address);
                        }
                        else
                        {
                            SendToWire(candidate.Address, c.PuncFrame);
                        }
                    }
                    catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
                    {
                        // One unroutable candidate (or a brief interface flap) must not kill
                        // the punch; the pacing delay below bounds retries.
                    }
                }

                await Task.Delay(c.State == PinholeConnectionState.Degraded ? UpgradePace : PunchPace, stop.Token).ConfigureAwait(false);
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

            _portMap?.Tick(Environment.TickCount64);

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
                return;
            }

            ObserveNatHint(perServer);
            IPEndPoint[] observed = new HashSet<IPEndPoint>(perServer).ToArray();
            if (observed.Length == 0)
            {
                return;
            }

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
            c.ProbeDeadlineTicks = now + (long)_options.PathValidationProbeInterval.TotalMilliseconds;
        }

        Span<byte> frame = stackalloc byte[HeaderSize + CryptoWire.TokenLength + 8 + CryptoWire.SealedOverhead];
        Span<byte> nonceBytes = stackalloc byte[8];
        BitConverter.TryWriteBytes(nonceBytes, nonce);
        int len = BuildFrame(c, FrameType.Ping, nonceBytes, frame);
        try
        {
            SendToWire(target, frame[..len]);
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
            if (c.State != PinholeConnectionState.Open || c.Path != PathKind.Direct || c.DirectRemote is null)
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
                    // The size never answered: keep the confirmed floor and cool down. An
                    // over-MTU probe is silently dropped by the network, not errored, so
                    // absence of a pong IS the measurement.
                    c.PmtuOutstanding = false;
                    c.PmtuNextProbeTicks = now + PmtuReprobeDelayMs;
                    return;
                }
            }
            else
            {
                if (now < c.PmtuNextProbeTicks)
                {
                    return;
                }

                int next = NextPmtuSizeLocked(c);
                if (next <= 0)
                {
                    c.PmtuNextProbeTicks = now + PmtuReprobeDelayMs; // ceiling reached; re-climb later
                    return;
                }

                c.PmtuProbeSize = next;
                c.PmtuProbeTries = 0;
                c.PmtuOutstanding = true;
            }

            c.PmtuProbeNonce = now | PmtuProbeMarker;
            c.PmtuDeadlineTicks = now + (long)_options.PathValidationProbeInterval.TotalMilliseconds;
            c.PmtuProbeTarget = c.DirectRemote;
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

        Span<byte> frame = stackalloc byte[HeaderSize + CryptoWire.TokenLength + 8 + CryptoWire.SealedOverhead];
        Span<byte> timestamp = stackalloc byte[8];
        BitConverter.TryWriteBytes(timestamp, Environment.TickCount64);
        int len = BuildFrame(c, FrameType.Ping, timestamp, frame);
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
            SendToWire(direct, frame);
            return;
        }

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
        // Volatile read, no lock: this runs once per sent frame, and the rebind that swaps
        // the socket is rare enough to pay for itself with a caught send error.
        _udp.SendTo(frame, ToWire(ep));
    }

    private void SendToWire(SocketAddress sa, ReadOnlySpan<byte> frame)
    {
        _udp.SendTo(frame, sa);
    }

    private void SendViaRelayTo(ReadOnlySpan<byte> frame, IPEndPoint peer)
    {
        TurnClient? client = AliveRelayClients().FirstOrDefault();
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

    // ------------------------------------------------------------------ receive

    private void StartRecvLoop()
    {
        new Thread(RecvLoop) { IsBackground = true, Name = "pinhole-node-recv" }.Start();
    }

    private void RecvLoop()
    {
        byte[] buf = new byte[RecvBufferSize];
        // One scratch address, reused for every receive: the recvmsg writes into it, the
        // frame handlers only read it, and the engine clones it exactly when a connection
        // adopts the endpoint as its own (a per-datagram copy was 8% of the receive thread).
        var remote = new SocketAddress(AddressFamily.InterNetworkV6);
        while (!_shutdown.IsCancellationRequested)
        {
            int n;
            try
            {
                n = _udp.ReceiveFrom(buf, remote);
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

            if (n <= 0)
            {
                continue;
            }

            if (buf[0] is >= (byte)FrameType.Punc and <= (byte)FrameType.Hsck && n >= HeaderSize)
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
                    OnStunResponse(buf, n);
                }
                catch (Exception)
                {
                    // A malformed STUN response must cost its probe, never the receive loop.
                }
            }
        }
    }

    private readonly struct Arrival
    {
        public readonly bool ViaRelay;
        public readonly SocketAddress? Direct;
        public readonly IPEndPoint? Relay;
        public readonly IrohRelay? Iroh;
        public readonly byte[]? IrohPeerKey;

        public Arrival(SocketAddress direct)
        {
            ViaRelay = false;
            Direct = direct;
            Relay = null;
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
        if (c is not null && arrival.ViaRelay)
        {
            Volatile.Write(ref c.LastRelayRxTicks, Environment.TickCount64); // relay-leg liveness clock
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
                OnPing(c, frame, arrival);
                break;
            case FrameType.Pong:
                OnPong(c, frame, arrival);
                break;
            case FrameType.Announce:
                OnAnnounce(c, frame, arrival);
                break;
            case FrameType.Hsck:
                OnHsck(c, frame, arrival);
                break;
            case FrameType.Bye:
                // Remove only this connection's entry: a Bye from a replaced husk must not
                // tear down the re-dial winner registered under the same peer ID.
                _conns.TryRemove(new KeyValuePair<ulong, ConnState>(c.PeerId, c));
                Transition(c, PinholeConnectionState.Closed);
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
            DirectPathConfirmed(c, arrival.Direct!);
        }

        if (!c.Announced)
        {
            c.Announced = true;
            AnnounceTo(c);
        }
    }

    private void OnPack(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        // body = [echo of our PUNC token][the responder's own token] (+ keys and confirm in v2)
        if (frame.Length < HeaderSize + CryptoWire.PackLegacyBody
            || BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]) != c.Token)
        {
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
            DirectPathConfirmed(c, arrival.Direct!);
        }

        if (!c.Announced)
        {
            c.Announced = true;
            AnnounceTo(c);
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
            if (c.Crypto is not { Established: true } crypto || crypto.PeerConfirmed)
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

        // The dialer heard our PACK — re-announce, in case the first sealed announce lost
        // the race against the PACK that delivered our half of the keys.
        AnnounceTo(c);
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
        Transition(c, PinholeConnectionState.Dead);
        c.Dead.Cancel();
    }

    private void OnData(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        if (frame.Length < HeaderSize + 4 + 1)
        {
            return;
        }

        // Any valid frame from the peer is proof of a live path, and its source address is
        // the newest truth about where the peer lives (last-wins by peer ID — roaming).
        if (arrival.ViaRelay)
        {
            RelayPathConfirmed(c, arrival);
        }
        else
        {
            DirectPathConfirmed(c, arrival.Direct!);
        }

        Interlocked.Increment(ref c.ReceivedCount);
        Interlocked.Add(ref c.BytesReceived, frame.Length - HeaderSize - 4);
        // Buffered mode queues first (the queue exists from handshake time), then the
        // zero-copy event path fires for anyone still subscribed.
        c.Buffer?.Enqueue(frame[(HeaderSize + 4)..]);
        c.Received?.Invoke(frame[(HeaderSize + 4)..]);
    }

    private void OnPing(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        if (frame.Length < HeaderSize + 4 + 8)
        {
            return;
        }

        if (!arrival.ViaRelay)
        {
            DirectPathConfirmed(c, arrival.Direct!);
            // Inbound evidence cuts both ways: a datagram this size arrived, so the path
            // carries it. Cap at the probe ceiling — this only ever replaces a probe, and
            // keeps buffer sizing honest on loopback's 64k MTU.
            lock (c.Gate)
            {
                int ceiling = PmtuCeilingLocked(c);
                if (frame.Length > c.PmtuWire && frame.Length <= ceiling)
                {
                    c.PmtuWire = frame.Length;
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
                    && !arrival.ViaRelay && SameEndPoint(arrival.Direct, c.ProbeTarget))
                {
                    c.ProbeOutstanding = false;
                    c.ProbeTarget = null;
                    c.UnansweredProbes = 0;
                    Interlocked.Increment(ref c.PathProbeReplies);
                }
            }

            if (!arrival.ViaRelay && arrival.Direct is { } direct)
            {
                DirectPathConfirmed(c, direct);
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
                    && !arrival.ViaRelay && SameEndPoint(arrival.Direct, c.PmtuProbeTarget))
                {
                    c.PmtuOutstanding = false;
                    c.PmtuWire = Math.Max(c.PmtuWire, c.PmtuProbeSize);
                    c.PmtuNextProbeTicks = 0; // climb again on the next tick
                }
            }

            if (!arrival.ViaRelay && arrival.Direct is { } pmtuDirect)
            {
                DirectPathConfirmed(c, pmtuDirect); // a confirmed probe is path liveness too
            }

            return;
        }

        if (!arrival.ViaRelay && arrival.Direct is { } callerDirect)
        {
            DirectPathConfirmed(c, callerDirect); // an answered caller ping is direct-path activity too
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
        try
        {
            var reader = new CandidateCodec.Reader(body, 0);
            byte count = reader.ReadByte();
            var fresh = new List<PinholeCandidate>(count);
            for (int i = 0; i < count && !reader.AtEnd; i++)
            {
                fresh.Add(CandidateCodec.Read(ref reader));
            }

            lock (_gate)
            {
                c.PeerCandidates.Clear();
                c.PeerCandidates.AddRange(fresh);
            }
        }
        catch (FormatException)
        {
            return;
        }

        if (!arrival.ViaRelay)
        {
            DirectPathConfirmed(c, arrival.Direct!);
        }

        if (c.State is PinholeConnectionState.Punching or PinholeConnectionState.Dead)
        {
            KickPunch(c); // the peer just told us where it now lives
        }
    }

    private void SendOnArrival(in Arrival arrival, ReadOnlySpan<byte> frame)
    {
        try
        {
            if (arrival.Iroh is { } iro && arrival.IrohPeerKey is { } key)
            {
                iro.Send(key, frame);
            }
            else if (arrival.ViaRelay)
            {
                SendViaRelayTo(frame, arrival.Relay!);
            }
            else if (arrival.Direct is { } direct)
            {
                SendToWire(direct, frame);
            }
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
        {
            // The reply path was momentary; its loss costs one frame, nothing more.
        }
    }

    private void AnnounceTo(ConnState c, bool blast = false)
    {
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
            AnnounceSend(c, frame[..len], blast);
            return;
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(cap);
        try
        {
            int len = BuildFrame(c, FrameType.Announce, body.AsSpan(0, bodyLen), rented.AsSpan(0, cap));
            AnnounceSend(c, rented.AsSpan(0, len), blast);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private void AnnounceSend(ConnState c, ReadOnlySpan<byte> frame, bool blast)
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
                        SendViaRelayTo(frame, target.Address);
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

        SendOnArrival(CurrentArrival(c), frame);
    }

    private Arrival CurrentArrival(ConnState c)
    {
        if (c.Path == PathKind.Direct && c.DirectRemote is { } sa)
        {
            return new Arrival(sa);
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

    private void DirectPathConfirmed(ConnState c, SocketAddress source)
    {
        lock (c.Gate)
        {
            if (c.State == PinholeConnectionState.Closed || c.BlackholeDirect)
            {
                return; // test hook: this direct path is dead; nothing can confirm it
            }

            if (SameEndPoint(c.DirectRemote, source))
            {
                // Fast path, taken for every ordinary datagram: the endpoint is already the
                // connection's truth, so the frame only refreshes direct-path activity.
                Volatile.Write(ref c.LastDirectRxTicks, Environment.TickCount64);
                return;
            }

            // The receive loop reuses its scratch SocketAddress; an adopted endpoint must be
            // private to the connection. Cloning only on change keeps the per-datagram
            // receive path allocation-free while endpoint churn still pays one copy.
            SocketAddress adopted = Clone(source);
            TracePath(c, adopted);
            c.DirectRemote = adopted;
            c.DirectRemoteEp = ToEndpoint(adopted);
            Volatile.Write(ref c.LastDirectRxTicks, Environment.TickCount64);
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
            if (c.State == PinholeConnectionState.Closed) return;
            c.Iroh = relay;
            c.IrohPeerKey = arrival.IrohPeerKey;
            c.IrohConfirmed = true;
            if (c.State is PinholeConnectionState.Punching or PinholeConnectionState.Dead)
            {
                c.State = PinholeConnectionState.Degraded;
                c.Path = PathKind.Relay;
                c.PathSince = DateTimeOffset.UtcNow;
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
        }

        if (c.RelayRemote?.Address.Equals(peerRelayed.Address) == true && c.RelayReady)
        {
            c.RelayRemote = peerRelayed;
            return;
        }

        c.RelayRemote = peerRelayed;
        c.RelayReady = false;
        if (Interlocked.CompareExchange(ref c.PermitInFlight, 1, 0) == 0)
        {
            // Single-flight: a relayed frame burst must not spawn one permission round
            // trip per frame while the first is still in the air.
            _ = PermitRelayAsync(c, peerRelayed);
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
                    return; // the slot was retired; the reconnect's fresh permit finishes this
                }
            }

            bool kick = false;
            lock (c.Gate)
            {
                if (c.RelayRemote is { } current && !current.Address.Equals(peer.Address))
                {
                    return; // a newer relay address superseded this permit mid-flight
                }

                c.RelayReady = true;
                if (c.State is PinholeConnectionState.Punching or PinholeConnectionState.Dead)
                {
                    c.State = PinholeConnectionState.Degraded;
                    c.Path = PathKind.Relay;
                    c.PathSince = DateTimeOffset.UtcNow;
                    c.Connected.TrySetResult();
                    c.StateChanged?.Invoke(c.State);
                    kick = true;
                }
            }

            if (kick)
            {
                KickPunch(c); // relay is confirmed usable; direct upgrade probing continues
            }
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

    /// <summary>One permission round trip that treats failure as evidence about the
    /// allocation, not just the attempt: a rejected or timed-out permit retires the client
    /// so the next <see cref="EnsureRelaysAsync"/> reallocates. Without this, a restarted
    /// relay leaves every node holding a ghost allocation — "alive" locally, unknown to the
    /// server — and relayed traffic black-holes until the minutes-long refresh cadence
    /// notices. A retired-but-healthy allocation costs one realloc round trip.</summary>
    private async Task<bool> TryPermitAsync(TurnClient client, IPAddress peer, CancellationToken ct)
    {
        try
        {
            await client.CreatePermissionAsync(peer, ct).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is SocketException or InvalidOperationException or TimeoutException or ObjectDisposedException)
        {
            await RetireRelayClientAsync(client).ConfigureAwait(false);
            return false;
        }
    }

    private async Task RetireRelayClientAsync(TurnClient client)
    {
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
                if ((c.Iroh is { IsAlive: true } && c.IrohConfirmed) || (c.RelayRemote is not null && c.RelayReady))
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

        // A suspect relay path re-validates its allocation: the permit round trip either
        // confirms the relay leg or (TryPermitAsync) retires a ghost client — a restarted
        // relay's stale allocation — and reallocates, instead of waiting out the
        // minutes-long refresh cadence while every relayed frame black-holes.
        if (c.RelayRemote is { } relayPeer && Interlocked.CompareExchange(ref c.PermitInFlight, 1, 0) == 0)
        {
            _ = PermitRelayAsync(c, relayPeer);
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
        }

        foreach (TurnClient client in oldClients)
        {
            client.Received -= HandleRelayData;
            _ = client.DisposeAsync();
        }

        await Task.WhenAll(ProbeStunAllAsync(ct), EnsureRelaysAsync(ct), EnsureIrohRelaysAsync(ct)).ConfigureAwait(false);
        RefreshLocalCandidates();
        _portMap?.Rebind(_udp.LocalEndPoint.Port); // LocalPort takes _gate; we hold none here
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
        _shutdown.Cancel();
        foreach (ConnState c in ConnectionsSnapshot())
        {
            _ = CloseAsync(c);
        }

        _incoming?.Writer.TryComplete();
        lock (_gate)
        {
            _udp.Dispose();
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
        IPEndPoint ep = (IPEndPoint)new IPEndPoint(IPAddress.IPv6Any, 0).Create(sa);
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
