using System.Net;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Pinhole;

public sealed class PinholeNode : IAsyncDisposable, IDisposable
{
    private const string InvalidCodeMessage = "Invalid connection string. Copy your friend's current connection string and try again.";
    private const string SelfConnectionMessage = "That is your own connection string. Use your friend's string, or listen for an incoming connection.";
    private const string IncompatibleMessage = "The peer's connection string predates encryption and this node requires it. Ask for a fresh string from a current node, or set Encryption=Optional to allow plaintext peers.";
    private readonly NodeEngine _engine;
    private readonly PinholeOptions _options;
    private volatile NatHint _natHint = NatHint.Unknown;
    private LanDiscovery? _lan;
    private readonly HttpClient _irohHttp;
    private readonly IrohDiscovery _irohDiscovery;
    private readonly CancellationTokenSource _irohStop = new();
    private Task? _irohPublisher;
    private int _disposed;
    internal const string IrohProtocolPrefix = "pinhole-v1:";

    private PinholeNode(NodeEngine engine, PinholeOptions options)
    {
        _engine = engine;
        _options = options;
        _irohHttp = options.IrohDiscoveryHandler is { } handler
            ? new HttpClient(handler, disposeHandler: false) : new HttpClient();
        _irohHttp.Timeout = TimeSpan.FromSeconds(5);
        _irohDiscovery = new IrohDiscovery(_irohHttp, options.IrohDiscoveryUrl);
    }

    public static async Task<PinholeNode> BindAsync(PinholeOptions? options = null, CancellationToken ct = default)
    {
        PinholeOptions resolved = await PinholeOptions.ResolveAsync(options, ct).ConfigureAwait(false);
        var engine = new NodeEngine(resolved);
        try
        {
            await engine.BindAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            engine.Dispose();
            throw;
        }

        var node = new PinholeNode(engine, resolved);
        node.StartLanAnnouncement();
        if (resolved.PublishIrohAddress)
        {
            try { await node.PublishIrohAddressAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            catch (Exception ex) when (ex is HttpRequestException or IOException) { }
            catch { node.Dispose(); throw; }
            node._irohPublisher = node.PublishIrohLoopAsync();
        }
        return node;
    }

    private void StartLanAnnouncement()
    {
        if (!_options.EnableLanDiscovery)
        {
            return;
        }

        try
        {
            ILanChannel channel = _options.LanChannelFactory?.Invoke() ?? new MulticastLanChannel();
            _lan = new LanDiscovery(
                channel,
                PeerId,
                StaticPublicKey,
                () => LocalLanAddresses(),
                LocalPort,
                NatHint);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            // No multicast on this interface (common in containers): announcing is
            // best-effort, never a bind failure.
        }
    }

    private IReadOnlyList<IPAddress> LocalLanAddresses() =>
        _engine.LocalCandidatesSnapshot()
            .Where(c => c.Kind == CandidateKind.Direct)
            .Select(c => c.Address.Address)
            .Where(a => !IPAddress.IsLoopback(a))
            .Distinct()
            .ToList();

    public static async Task<IReadOnlyList<LanPeer>> DiscoverLanPeersAsync(TimeSpan window, CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(window, TimeSpan.FromMilliseconds(100));
        using var channel = new MulticastLanChannel();
        return await LanDiscovery.BrowseAsync(channel, window, ct).ConfigureAwait(false);
    }

    public ulong PeerId => _engine.PeerId;

    public int LocalPort => _engine.LocalPort;

    public int? TcpListeningPort => _engine.TcpListeningPort;

    public byte[]? StaticPublicKey => _engine.StaticPublicKey;

    public byte[]? EndpointPublicKey => _engine.EndpointPublicKey;

    // Knock-aware: a knock-configured node's string carries the secret (version 4) —
    // only what this string hands out may connect. LAN-discovery strings never do: a
    // multicast announcement would hand the knock to every listener.
    public string ConnectionString => new ConnectionString(
        _engine.PeerId,
        _engine.LocalCandidatesSnapshot(),
        NatHint,
        _engine.StaticPublicKey,
        _engine.EndpointPublicKey,
        _options.Knock).ToString();

    public IrohAddress IrohAddress
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            byte[] key = EndpointPublicKey ?? throw new InvalidOperationException("enable iroh relays, publication, or a persisted identity first");
            var candidates = _engine.LocalCandidatesSnapshot();
            return new IrohAddress(Convert.ToHexString(key),
                candidates.Where(c => c.Kind is CandidateKind.Direct or CandidateKind.Reflexive).Select(c => c.Address).ToArray(),
                candidates.Where(c => c.Kind == CandidateKind.IrohRelay).Select(c => c.RelayUrl!).ToArray());
        }
    }

    public Task PublishIrohAddressAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ct.ThrowIfCancellationRequested();
        byte[] pin = StaticPublicKey ?? throw new InvalidOperationException("Pinhole discovery requires encryption");
        IrohAddress address = IrohAddress;
        var record = new IrohAddress(address.EndpointId,
            _options.PublishDirectIrohAddresses ? address.DirectAddresses : [], address.RelayUrls)
        {
            UserData = IrohProtocolPrefix + Convert.ToHexString(pin).ToLowerInvariant(),
            DerpRelayUrls = _engine.LocalCandidatesSnapshot().Where(c => c.Kind == CandidateKind.DerpRelay)
                .Select(c => c.RelayUrl!).Distinct().ToArray(),
        };
        return _irohDiscovery.PublishAsync(record, _engine.EndpointRelayIdentity!, ct);
    }

    private async Task PublishIrohLoopAsync()
    {
        int failures = 0;
        while (!_irohStop.IsCancellationRequested)
        {
            try
            {
                double jitter = RandomNumberGenerator.GetInt32(900, 1101) / 1000.0;
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(30L << Math.Min(failures, 4), 300) * jitter), _irohStop.Token).ConfigureAwait(false);
                await PublishIrohAddressAsync(_irohStop.Token).ConfigureAwait(false);
                failures = 0;
            }
            catch (OperationCanceledException) when (_irohStop.IsCancellationRequested) { return; }
            catch (ObjectDisposedException) when (_irohStop.IsCancellationRequested) { return; }
            catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException) { failures++; }
        }
    }

    public async Task<PinholeConnection> ConnectIrohAsync(string ticketOrEndpointId, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ct.ThrowIfCancellationRequested();
        if (StaticPublicKey is null) throw new InvalidOperationException("Pinhole iroh sessions require encryption");
        IrohAddress ticket = Pinhole.IrohAddress.Parse(ticketOrEndpointId);
        if (EndpointPublicKey is { } local && ticket.Key.AsSpan().SequenceEqual(local))
            throw new ArgumentException(SelfConnectionMessage, nameof(ticketOrEndpointId));
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, _irohStop.Token);
        deadline.CancelAfter(_options.ConnectTimeout);
        IrohAddress record = await _irohDiscovery.ResolveAsync(ticket.EndpointId, deadline.Token).ConfigureAwait(false);
        if (record.UserData is not { } data || !data.StartsWith(IrohProtocolPrefix, StringComparison.Ordinal)
            || data.Length != IrohProtocolPrefix.Length + 64)
            throw new InvalidOperationException("the endpoint does not advertise a signed Pinhole session key");
        byte[] pin;
        try { pin = Convert.FromHexString(data[IrohProtocolPrefix.Length..]); }
        catch (FormatException ex) { throw new InvalidDataException("invalid signed Pinhole session key", ex); }
        var candidates = ticket.RelayUrls.Concat(record.RelayUrls).Distinct()
            .Select(url => new PinholeCandidate(CandidateKind.IrohRelay, new IPEndPoint(IPAddress.None, 0), RelayUrl: url, RelayKey: record.Key))
            .Concat(record.DerpRelayUrls.Select(url => new PinholeCandidate(CandidateKind.DerpRelay,
                new IPEndPoint(IPAddress.None, 0), RelayUrl: url, RelayKey: pin)))
            .Concat(ticket.DirectAddresses.Concat(record.DirectAddresses).Distinct()
                .Select(ip => new PinholeCandidate(CandidateKind.Direct, ip)))
            .Take(Pinhole.ConnectionString.MaxCandidates).ToArray();
        ulong id = BinaryPrimitives.ReadUInt64LittleEndian(SHA256.HashData(record.Key));
        return await ConnectPeerAsync(new ConnectionString(id, candidates, NatHint.Unknown, pin, record.Key), deadline.Token).ConfigureAwait(false);
    }

    public IReadOnlyList<IPEndPoint> PublicEndpoints => _engine.ReflexiveSnapshot();

    public IReadOnlyList<PinholeInterfaceCandidates> InterfaceCandidates => _engine.InterfaceCandidatesSnapshot();

    public IPEndPoint? PortMappedEndpoint => _engine.MappedEndpointSnapshot();

    public IPEndPoint? TcpPortMappedEndpoint => _engine.MappedEndpointSnapshot(tcp: true);

    public IReadOnlyList<IPEndPoint> IPv6FirewallEndpoints => _engine.IPv6FirewallSnapshot();

    public IReadOnlyList<IPEndPoint> TcpIPv6FirewallEndpoints => _engine.IPv6FirewallSnapshot(tcp: true);

    public NatHint NatHint => _natHint != Pinhole.NatHint.Unknown
        ? _natHint
        : _engine.MappedEndpointSnapshot() is not null ? NatHint.Cone : _engine.ObservedNatHint;

    public bool HasRelay => _engine.HasRelay;

    public IReadOnlyList<PinholeConnection> Connections =>
        _engine.ConnectionsSnapshot().Select(c => c.Public!).ToArray();

    public async Task<PinholeConnection> AcceptAsync(CancellationToken ct = default)
    {
        if (_engine.Incoming is not { } incoming)
        {
            throw new InvalidOperationException("node is not listening (Listen=false)");
        }

        ConnState c;
        try
        {
            c = await incoming.Reader.ReadAsync(ct).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            throw new ObjectDisposedException(nameof(PinholeNode), "the node was disposed while waiting");
        }

        await c.Connected.Task.WaitAsync(_options.ConnectTimeout, ct).ConfigureAwait(false);
        Telemetry.AttemptOutcome(Telemetry.OutcomeAcceptEstablished, PathName(c));
        return c.Public!;
    }

    public async Task<PinholeConnection> ConnectAsync(string connectionString, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(connectionString);
        ct.ThrowIfCancellationRequested();
        if (!TryParseCode(connectionString, out ConnectionString? cs))
            throw new FormatException(InvalidCodeMessage);
        if (cs.PeerId == PeerId)
            throw new ArgumentException(SelfConnectionMessage, nameof(connectionString));
        if (_options.Encryption == PinholeEncryption.Required && cs.StaticKey is null)
            throw new InvalidOperationException(IncompatibleMessage);

        return await ConnectPeerAsync(cs, ct).ConfigureAwait(false);
    }

    public async Task<PinholeConnectResult> TryConnectAsync(string? connectionString, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (!TryParseCode(connectionString, out ConnectionString? cs))
            return PinholeConnectResult.Failed(PinholeConnectFailure.InvalidConnectionString, InvalidCodeMessage);
        if (cs.PeerId == PeerId)
            return PinholeConnectResult.Failed(PinholeConnectFailure.SelfConnection, SelfConnectionMessage);
        if (_options.Encryption == PinholeEncryption.Required && cs.StaticKey is null)
            return PinholeConnectResult.Failed(PinholeConnectFailure.PeerIncompatible, IncompatibleMessage);

        try
        {
            return PinholeConnectResult.Connected(await ConnectPeerAsync(cs, ct).ConfigureAwait(false));
        }
        catch (TimeoutException ex)
        {
            return PinholeConnectResult.Failed(PeerHasRelay(cs)
                ? PinholeConnectFailure.TimedOut : PinholeConnectFailure.NoRelayFallback, ex.Message);
        }
    }

    private static bool TryParseCode(string? text,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out ConnectionString? cs)
    {
        cs = null;
        if (string.IsNullOrWhiteSpace(text)) return false;
        text = text.Trim();
        if (!text.Contains(':')) text = Pinhole.ConnectionString.Scheme + ":" + text;
        return Pinhole.ConnectionString.TryParse(text, out cs);
    }

    private static bool PeerHasRelay(ConnectionString cs) =>
        cs.Candidates.Any(c => c.Kind is CandidateKind.Relay or CandidateKind.IrohRelay or CandidateKind.DerpRelay);

    private async Task<PinholeConnection> ConnectPeerAsync(ConnectionString cs, CancellationToken ct)
    {
        ConnState c = _engine.ConnectAsync(cs, ct);
        var establish = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            await c.Connected.Task.WaitAsync(_options.ConnectTimeout, ct).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            await _engine.CloseAsync(c).ConfigureAwait(false);
            Telemetry.AttemptOutcome(Telemetry.OutcomeDialTimeout);
            string message = PeerHasRelay(cs)
                ? _options.RelaySignalingOnly
                    ? "Direct connection timed out. Relays are permitted only for signaling, so application traffic needs a direct UDP or TCP path. Keep both apps running and check their host firewalls and current candidates."
                    : "Connection timed out. Keep both apps running and use your friend's current connection string. The peer may be offline, or a relay path could not be established."
                : "Direct connection timed out and your friend's connection string has no relay fallback. Share a fresh string after their relay connects, or try connecting from both PCs at the same time.";
            throw new TimeoutException(message, ex);
        }
        catch (OperationCanceledException)
        {
            await _engine.CloseAsync(c).ConfigureAwait(false);
            Telemetry.AttemptOutcome(Telemetry.OutcomeDialCancelled);
            throw;
        }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException)
        {
            // The handshake itself refused the peer (pinning mismatch, refused encryption,
            // failed confirmation): the cause is counted where it happened, in
            // HandshakeFailed — this is only the attempt's terminal outcome.
            Telemetry.AttemptOutcome(Telemetry.OutcomeDialFaulted);
            throw;
        }

        Telemetry.AttemptOutcome(Telemetry.OutcomeDialEstablished, PathName(c));
        Telemetry.EstablishDuration(establish.Elapsed.TotalMilliseconds, PathName(c));
        return c.Public!;
    }

    private static string PathName(ConnState c) => c.Path == PathKind.Relay ? "relay" : "direct";

    public Task RoamNowAsync(CancellationToken ct = default) => _engine.RecoverAsync(forceRebind: false, ct);

    internal NodeEngine Engine => _engine;

    public void SetNatHint(NatHint hint) => _natHint = hint;

    public async ValueTask DisposeAsync()
    {
        Dispose();
        if (_irohPublisher is { } publisher) await publisher.ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _irohStop.Cancel();
        _irohHttp.Dispose();
        _lan?.Dispose();
        _engine.Dispose();
    }
}
