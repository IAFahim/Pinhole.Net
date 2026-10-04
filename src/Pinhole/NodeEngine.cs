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
    Punc = 0x50, // punch probe; body = the sender's handshake token (u32 LE)
    Pack = 0x51, // punch ack; body = [echo of the received PUNC token][sender's own token]
    Data = 0x52,  // body = [sender's token][payload]
    Ping = 0x53,  // body = [sender's token][timestamp:8]
    Pong = 0x54,  // body = [sender's token][timestamp:8]
    Announce = 0x55, // body = [sender's token][count][candidate TLV stream]
    Bye = 0x56,   // body = [sender's token]
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
    public bool SymmetricHint;               // peer advertised a symmetric NAT: skip the punch
    public uint RemoteToken;                 // learned from the peer's frames; staleness filter
    public bool RemoteTokenKnown;
    public bool Announced;
    public DateTimeOffset LastKick = DateTimeOffset.UtcNow;
    public volatile bool BlackholeDirect;    // test hook: drop this peer's direct frames
    public int PunchGeneration;
    public int PermitInFlight;               // single-flight guard for TURN permission round trips
    public IrohRelay? Iroh;
    public byte[]? IrohPeerKey;
    public bool IrohConfirmed;
    public byte[] PuncFrame = Array.Empty<byte>(); // built with the connection's token

    public readonly TaskCompletionSource Connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource Closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly CancellationTokenSource Dead = new();

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
    private const int HeaderSize = 9;

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
    private const int MaxUpgradeAttempts = 120; // then passive: peer frames can still open direct
    private static readonly TimeSpan RelayRetryBackoff = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RecoverDebounce = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(2);

    private readonly ulong _peerId;
    private readonly PinholeOptions _options;
    private readonly object _gate = new();
    private readonly Dictionary<ulong, ConnState> _conns = new();
    private readonly Channel<ConnState>? _incoming;
    private readonly List<RelaySlot> _relays = new();
    private readonly Dictionary<Uri, IrohRelay> _irohRelays = new();
    private readonly RelayIdentity? _relayIdentity;
    private readonly List<PinholeCandidate> _localCandidates = new(); // guarded by _gate
    private readonly List<IPEndPoint> _reflexive = new();             // guarded by _gate
    private readonly ConcurrentDictionary<ulong, TaskCompletionSource<IPEndPoint>> _stunPending = new();
    private readonly CancellationTokenSource _shutdown = new();

    private Socket _udp = null!;
    private long _recovering; // single-flight guard for recovery
    private volatile bool _disposed;
    private int _networkWatchHooked;

    public NodeEngine(PinholeOptions options)
    {
        if ((options.IrohRelayUrls ?? options.ResolvedIrohRelays).Count > 0)
            _relayIdentity = new RelayIdentity();
        _peerId = _relayIdentity?.PeerId ?? BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        _options = options;
        _incoming = options.Listen ? Channel.CreateUnbounded<ConnState>() : null;
    }

    public ulong PeerId => _peerId;

    internal Channel<ConnState>? Incoming => _incoming;

    public void DisposeConnection(ConnState c) => _ = CloseAsync(c);

    public int LocalPort
    {
        get
        {
            lock (_gate)
            {
                return ((IPEndPoint)_udp.LocalEndPoint!).Port;
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

    private Socket CreateSocket(IPEndPoint? bind)
    {
        var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        // Blocked receives must wake up periodically: closing a socket while a sync receive
        // holds it spins forever in SafeSocketHandle.CloseAsIs on macOS, so disposal needs the
        // receive loop to come back and observe the disposed state.
        udp.ReceiveTimeout = 200;
        udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, 4 * 1024 * 1024);
        udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, 4 * 1024 * 1024);
        if (OperatingSystem.IsWindows())
        {
            const int sioUdpConnreset = -1744830452;
            udp.IOControl(sioUdpConnreset, new byte[] { 0 }, null);
        }

        // A dual-mode socket cannot bind a bare IPv4 address; map it so a caller's
        // IPAddress.Loopback/Any bind option works instead of throwing.
        IPEndPoint? bindV6 = bind is { Address.AddressFamily: AddressFamily.InterNetwork }
            ? new IPEndPoint(bind.Address.MapToIPv6(), bind.Port)
            : bind;
        udp.Bind(bindV6 ?? new IPEndPoint(IPAddress.IPv6Any, 0));
        return udp;
    }

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

    private void RefreshLocalCandidates()
    {
        int port = LocalPort;
        lock (_gate)
        {
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
            Socket udp;
            lock (_gate)
            {
                udp = _udp;
            }

            udp.SendTo(req, SocketFlags.None, ToWire(server));
            return await tcs.Task.WaitAsync(ProbeTimeout, ct).ConfigureAwait(false);
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
        IReadOnlyList<IPEndPoint> servers = ResolvedStun();
        if (servers.Count == 0)
        {
            return;
        }

        Task<IPEndPoint?>[] probes = servers.Select(s => TryProbe(s, ct)).ToArray();
        try
        {
            await Task.WhenAll(probes).WaitAsync(_options.BindProbeBudget, ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
        }

        foreach (Task<IPEndPoint?> probe in probes)
        {
            if (probe.IsCompletedSuccessfully && probe.Result is { } ep)
            {
                lock (_gate)
                {
                    if (!_reflexive.Contains(ep))
                    {
                        _reflexive.Add(ep);
                    }
                }
            }
        }

        RefreshLocalCandidates();
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
            || frame[0] is < (byte)FrameType.Punc or > (byte)FrameType.Bye) return;
        ulong sender = BinaryPrimitives.ReadUInt64LittleEndian(SHA256.HashData(source));
        if (sender != BinaryPrimitives.ReadUInt64LittleEndian(frame.AsSpan(1))) return;
        try { Dispatch(frame, frame.Length, new Arrival(relay, source)); }
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
            slot.NextRetry = DateTimeOffset.UtcNow + RelayRetryBackoff;
        }
    }

    /// <summary>A stranger's relayed traffic can only be delivered to our allocation if we
    /// permit its source IP. Strangers dial through the free relays, so pre-opening the
    /// catalog's server IPs makes "connect from a connection string alone" work.</summary>
    private async Task PermitCatalogRelaysAsync(CancellationToken ct)
    {
        IPEndPoint[] servers = await Providers.Resolver.FreeRelayServersAsync(ct).ConfigureAwait(false);
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

        Dispatch(data, data.Length, new Arrival(from));
    }

    // ------------------------------------------------------------------ connections

    public ConnState? Lookup(ulong peerId)
    {
        lock (_gate)
        {
            return _conns.TryGetValue(peerId, out ConnState? c) ? c : null;
        }
    }

    public IReadOnlyList<ConnState> ConnectionsSnapshot()
    {
        lock (_gate)
        {
            return _conns.Values.ToArray();
        }
    }

    public ConnState ConnectAsync(ConnectionString cs, CancellationToken ct)
    {
        var c = new ConnState
        {
            PeerId = cs.PeerId,
            Token = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)),
            SymmetricHint = cs.NatHint == NatHint.Symmetric,
        };
        c.PuncFrame = BuildPunc(c.Token);
        c.Public = new PinholeConnection(this, c);

        ConnState? husk;
        lock (_gate)
        {
            // Atomic check-and-insert: two concurrent dials at the same target must share
            // one connection, not silently overwrite each other's entry.
            if (_conns.TryGetValue(cs.PeerId, out ConnState? existing)
                && existing.State is not (PinholeConnectionState.Dead or PinholeConnectionState.Closed))
            {
                return existing; // idempotent dials (and in-flight dials) return the live connection
            }

            husk = existing; // a dead husk from an earlier attempt: replaced below
            _conns[cs.PeerId] = c;
            c.PeerCandidates.AddRange(cs.Candidates);
        }

        if (husk is not null)
        {
            Transition(husk, PinholeConnectionState.Closed);
            husk.Dead.Cancel();
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
                    await client.CreatePermissionAsync(candidate.Address.Address, ct).ConfigureAwait(false);
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

    private ConnState? CreateIncoming(ulong peerId, uint token, in Arrival arrival)
    {
        var c = new ConnState
        {
            PeerId = peerId,
            Token = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)),
            RemoteToken = token,
            RemoteTokenKnown = true,
        };
        c.PuncFrame = BuildPunc(c.Token);
        c.Public = new PinholeConnection(this, c);
        lock (_gate)
        {
            if (_conns.TryGetValue(peerId, out ConnState? first))
            {
                return first; // two PUNCs raced; keep the first
            }

            if (_conns.Count >= MaxConnections)
            {
                return null; // stranger flood: refuse to materialize more state
            }

            _conns[peerId] = c;
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
        lock (_gate)
        {
            // Identity check: a concurrent re-dial may have replaced this entry, and the
            // loser's close must not tear down the winner's live connection.
            if (_conns.TryGetValue(c.PeerId, out ConnState? registered) && registered == c)
            {
                _conns.Remove(c.PeerId);
            }
        }

        Span<byte> bye = stackalloc byte[HeaderSize + 4];
        WriteHeader(bye, FrameType.Bye);
        BinaryPrimitives.WriteUInt32LittleEndian(bye[HeaderSize..], c.Token);
        try
        {
            RouteFrame(c, bye);
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

                foreach (PinholeCandidate candidate in candidates)
                {
                    if (stop.IsCancellationRequested)
                    {
                        return;
                    }

                    if (c.SymmetricHint && candidate.Kind is not (CandidateKind.Relay or CandidateKind.IrohRelay))
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

    // ------------------------------------------------------------------ sending

    public void Send(ConnState c, ReadOnlySpan<byte> payload)
    {
        ArgumentOutOfRangeException.ThrowIfZero(payload.Length); // a zero-length Data frame is undeliverable by definition
        ArgumentOutOfRangeException.ThrowIfGreaterThan(payload.Length, MaxPayload);
        switch (c.State)
        {
            case PinholeConnectionState.Punching:
                throw new InvalidOperationException("connection is not open yet");
            case PinholeConnectionState.Dead:
                throw new InvalidOperationException("connection is dead: no usable path (call RoamNowAsync to recover)");
            case PinholeConnectionState.Closed:
                throw new ObjectDisposedException(nameof(PinholeConnection));
        }

        int n = payload.Length + HeaderSize + 4;
        Span<byte> frame = stackalloc byte[n];
        WriteHeader(frame, FrameType.Data);
        BinaryPrimitives.WriteUInt32LittleEndian(frame[HeaderSize..], c.Token);
        payload.CopyTo(frame[(HeaderSize + 4)..]);
        try
        {
            RouteFrame(c, frame);
            Interlocked.Increment(ref c.Sent);
            Interlocked.Add(ref c.BytesSent, payload.Length);
            Interlocked.Exchange(ref c.ConsecutiveSendFailures, 0);
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
        if (c.State is not (PinholeConnectionState.Open or PinholeConnectionState.Degraded))
        {
            return;
        }

        Span<byte> frame = stackalloc byte[HeaderSize + 4 + 8];
        WriteHeader(frame, FrameType.Ping);
        BinaryPrimitives.WriteUInt32LittleEndian(frame[HeaderSize..], c.Token);
        BitConverter.TryWriteBytes(frame[(HeaderSize + 4)..], Environment.TickCount64);
        try
        {
            RouteFrame(c, frame);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
        {
            return; // a probe that cannot leave simply goes unanswered
        }

        Interlocked.Increment(ref c.PingsSent);
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
        Socket udp;
        lock (_gate)
        {
            udp = _udp;
        }

        udp.SendTo(frame, SocketFlags.None, ToWire(ep));
    }

    private void SendToWire(SocketAddress sa, ReadOnlySpan<byte> frame)
    {
        Socket udp;
        lock (_gate)
        {
            udp = _udp;
        }

        udp.SendTo(frame, SocketFlags.None, sa);
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
        var remote = new SocketAddress(AddressFamily.InterNetworkV6);
        while (!_shutdown.IsCancellationRequested)
        {
            int n;
            try
            {
                n = _udp.ReceiveFrom(buf, SocketFlags.None, remote);
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

            if (buf[0] is >= (byte)FrameType.Punc and <= (byte)FrameType.Bye && n >= HeaderSize)
            {
                ulong sender = BitConverter.ToUInt64(buf, 1);
                if (Lookup(sender) is { BlackholeDirect: true })
                {
                    continue; // test hook: the direct path to this peer is a black hole
                }

                try
                {
                    Dispatch(buf, n, new Arrival(Clone(remote)));
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

    private void Dispatch(byte[] buf, int n, in Arrival arrival)
    {
        FrameType type = (FrameType)buf[0];
        ReadOnlySpan<byte> frame = buf.AsSpan(0, n);
        ConnState? c = Lookup(BitConverter.ToUInt64(buf, 1));
        if (TraceEnabled && (type is FrameType.Data or FrameType.Punc or FrameType.Pack))
        {
            TraceLine($"recv {type} from {BitConverter.ToUInt64(buf, 1):x16} via {(arrival.ViaRelay ? "relay" : "direct")} {(c is null ? "NO-CONN" : $"state={c.State} handler={(c.Received is null ? "none" : "on")}")}");
        }

        if (c is null)
        {
            if (type != FrameType.Punc || frame.Length < HeaderSize + 4 || !_options.Listen || _disposed)
            {
                return;
            }

            c = CreateIncoming(BitConverter.ToUInt64(buf, 1), BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]), arrival);
            if (c is null)
            {
                return; // connection table full: a stranger flood gets no more objects
            }
        }

        if (type is not (FrameType.Punc or FrameType.Pack) && !TokenOk(c, frame))
        {
            return; // post-handshake frame without the connection token: spoofed, drop it
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
                OnPong(c, frame);
                break;
            case FrameType.Announce:
                OnAnnounce(c, frame, arrival);
                break;
            case FrameType.Bye:
                lock (_gate)
                {
                    _conns.Remove(c.PeerId);
                }

                Transition(c, PinholeConnectionState.Closed);
                c.Dead.Cancel();
                break;
        }
    }

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
        if (frame.Length < HeaderSize + 4)
        {
            return;
        }

        uint token = BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]);
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
        }

        Span<byte> pack = stackalloc byte[HeaderSize + 8];
        WriteHeader(pack, FrameType.Pack);
        BinaryPrimitives.WriteUInt32LittleEndian(pack[HeaderSize..], token);         // echo: proof we saw the PUNC
        BinaryPrimitives.WriteUInt32LittleEndian(pack[(HeaderSize + 4)..], c.Token); // ours: so the dialer can authenticate us
        SendOnArrival(arrival, pack);

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
        // body = [echo of our PUNC token][the responder's own token]
        if (frame.Length < HeaderSize + 8
            || BinaryPrimitives.ReadUInt32LittleEndian(frame[HeaderSize..]) != c.Token)
        {
            return; // not an echo of our handshake token
        }

        lock (c.Gate)
        {
            c.RemoteToken = BinaryPrimitives.ReadUInt32LittleEndian(frame[(HeaderSize + 4)..]);
            c.RemoteTokenKnown = true;
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
        }

        Span<byte> pong = stackalloc byte[HeaderSize + 4 + 8];
        WriteHeader(pong, FrameType.Pong);
        BinaryPrimitives.WriteUInt32LittleEndian(pong[HeaderSize..], c.Token);
        frame.Slice(HeaderSize + 4, 8).CopyTo(pong[(HeaderSize + 4)..]);
        SendOnArrival(arrival, pong);
    }

    private void OnPong(ConnState c, ReadOnlySpan<byte> frame)
    {
        if (frame.Length < HeaderSize + 4 + 8)
        {
            return;
        }

        long rttTicks = (Environment.TickCount64 - BitConverter.ToInt64(frame[(HeaderSize + 4)..])) * TimeSpan.TicksPerMillisecond;
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
        Span<byte> token = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(token, c.Token);
        payload.Write(token);
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
                payload.Write(token);
                payload.WriteByte(0);
                break;
            }
        }

        byte[] frame = new byte[HeaderSize + payload.Length];
        WriteHeader(frame, FrameType.Announce);
        payload.GetBuffer().AsSpan(0, (int)payload.Length).CopyTo(frame.AsSpan(HeaderSize));

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

            TracePath(c, source);
            c.DirectRemote = source;
            c.DirectRemoteEp = ToEndpoint(source);
            if (c.State != PinholeConnectionState.Open)
            {
                c.State = PinholeConnectionState.Open;
                c.Path = PathKind.Direct;
                c.PathSince = DateTimeOffset.UtcNow;
                Interlocked.Exchange(ref c.ConsecutiveSendFailures, 0);
                c.Connected.TrySetResult();
                c.StateChanged?.Invoke(c.State);
            }
            else if (c.Path != PathKind.Direct)
            {
                // A direct frame while relayed: newest-path-wins migration.
                c.Path = PathKind.Direct;
                c.PathSince = DateTimeOffset.UtcNow;
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
                await client.CreatePermissionAsync(peer.Address, CancellationToken.None).ConfigureAwait(false);
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
        Socket old;
        Socket fresh;
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
        }

        foreach (TurnClient client in oldClients)
        {
            client.Received -= HandleRelayData;
            _ = client.DisposeAsync();
        }

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

    internal void SimulateDirectPathDeath(ulong peerId)
    {
        if (Lookup(peerId) is not { } c)
        {
            return;
        }

        c.BlackholeDirect = true;
        NotifyPathSuspect(c);
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

    private byte[] BuildPunc(uint token)
    {
        byte[] frame = new byte[HeaderSize + 4];
        frame[0] = (byte)FrameType.Punc;
        BitConverter.TryWriteBytes(frame.AsSpan(1), _peerId);
        BitConverter.TryWriteBytes(frame.AsSpan(HeaderSize), token);
        return frame;
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
