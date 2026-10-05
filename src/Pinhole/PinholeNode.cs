using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Pinhole;

/// <summary>A Pinhole endpoint: one UDP socket, zero or more relay allocations, and every
/// connection this peer is part of — all multiplexed over the same port.
///
/// Bind, hand out the connection string, dial or accept. How the string travels between the
/// two peers — clipboard, your server, your game lobby — is the application's concern.</summary>
public sealed class PinholeNode : IAsyncDisposable, IDisposable
{
    private const string InvalidCodeMessage = "Invalid connection string. Copy your friend's current connection string and try again.";
    private const string SelfConnectionMessage = "That is your own connection string. Use your friend's string, or listen for an incoming connection.";
    private const string IncompatibleMessage = "The peer's connection string predates encryption and this node requires it. Ask for a fresh string from a current node, or set Encryption=Optional to allow plaintext peers.";
    private readonly NodeEngine _engine;
    private readonly PinholeOptions _options;
    private volatile NatHint _natHint = NatHint.Unknown;
    private LanDiscovery? _lan;

    private PinholeNode(NodeEngine engine, PinholeOptions options)
    {
        _engine = engine;
        _options = options;
    }

    /// <summary>Binds the UDP socket, probes the configured free STUN servers for the
    /// reflexive candidate, connects to the configured iroh HTTPS relays, and allocates any
    /// configured TURN relays as additional fallback paths. Infrastructure left unspecified
    /// in <paramref name="options"/> gets the free defaults — customizing one setting never
    /// drops the rest; explicit empty lists disable their provider. Unreachable
    /// infrastructure costs candidates, never the bind.</summary>
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
        return node;
    }

    /// <summary>Announces on the LAN when <see cref="PinholeOptions.EnableLanDiscovery"/>
    /// is set: the node becomes <c>&lt;peer-id&gt;._pinhole._udp.local</c> on the local
    /// link, answerable by <see cref="DiscoverLanPeersAsync"/>. Off by default — announcing
    /// is a network-visible behavior an app should choose. Never throws: a multicast-less
    /// environment simply stays unannounced.</summary>
    private void StartLanAnnouncement()
    {
        if (!_options.EnableLanDiscovery)
        {
            return;
        }

        try
        {
            var channel = new MulticastLanChannel();
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
            .Where(c => c.Kind == CandidateKind.Direct && c.Address.AddressFamily == AddressFamily.InterNetwork)
            .Select(c => c.Address.Address)
            .Where(a => !IPAddress.IsLoopback(a))
            .Distinct()
            .ToList();

    /// <summary>Asks the local link for pinhole nodes and collects who answers during the
    /// window (both query responses and unsolicited announcements count). Each result is a
    /// dialable peer — v2 strings carrying the announcer's static key when it runs
    /// encryption, so discovered sessions are man-in-the-middle proof like any other.
    /// Needs no node of your own; two queries a second apart cover ordinary loss.</summary>
    public static async Task<IReadOnlyList<LanPeer>> DiscoverLanPeersAsync(TimeSpan window, CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(window, TimeSpan.FromMilliseconds(100));
        using var channel = new MulticastLanChannel();
        return await LanDiscovery.BrowseAsync(channel, window, ct).ConfigureAwait(false);
    }

    /// <summary>This peer's stable ID (random per bind).</summary>
    public ulong PeerId => _engine.PeerId;

    /// <summary>The bound UDP port.</summary>
    public int LocalPort => _engine.LocalPort;

    /// <summary>This node's long-term X25519 public key (32 bytes), embedded in every
    /// connection string this node publishes — peers pin the handshake's answering key
    /// against it, which is what makes sessions man-in-the-middle proof. Null when
    /// <see cref="PinholeOptions.Encryption"/> is <see cref="PinholeEncryption.Disabled"/>.
    /// Persist a seed via <see cref="PinholeOptions.IdentityKeySeed"/> for identity across restarts.</summary>
    public byte[]? StaticPublicKey => _engine.StaticPublicKey;

    /// <summary>The single discovery artifact: "pinhole1:..." carrying this peer's ID, its
    /// static key, and direct/reflexive/relay candidates. Regenerate and re-share after roaming.</summary>
    public string ConnectionString => new ConnectionString(
        _engine.PeerId,
        _engine.LocalCandidatesSnapshot(),
        NatHint,
        _engine.StaticPublicKey).ToString();

    /// <summary>The server-reflexive addresses observed at bind (one per responding STUN server).</summary>
    public IReadOnlyList<IPEndPoint> PublicEndpoints => _engine.ReflexiveSnapshot();

    /// <summary>The external endpoint the network's router granted this socket (UPnP,
    /// NAT-PMP, or PCP), or null. It is already advertised as a reflexive candidate in
    /// <see cref="ConnectionString"/>; this property exists for diagnostics.</summary>
    public IPEndPoint? PortMappedEndpoint => _engine.MappedEndpointSnapshot();

    /// <summary>The NAT classification embedded in future connection strings: a manual
    /// <see cref="SetNatHint"/> override when one is set, otherwise the classification the
    /// engine derives by itself from multi-server STUN observations — two servers observing
    /// the same mapping is a cone NAT, divergent mappings a symmetric one whose reflexive
    /// candidates are useless to dialers. One exception: while a router port mapping is
    /// live, the advertised candidates include an endpoint that is punchable from anywhere,
    /// so the honest hint is <see cref="NatHint.Cone"/> even behind a symmetric NAT.</summary>
    public NatHint NatHint => _natHint != Pinhole.NatHint.Unknown
        ? _natHint
        : _engine.MappedEndpointSnapshot() is not null ? NatHint.Cone : _engine.ObservedNatHint;

    /// <summary>Whether this node currently has a live iroh or TURN relay available.
    /// This can change as relays disconnect or reconnect; it does not guarantee a peer is reachable.</summary>
    public bool HasRelay => _engine.HasRelay;

    /// <summary>Every live connection this node is part of, keyed by nothing — a snapshot list.</summary>
    public IReadOnlyList<PinholeConnection> Connections =>
        _engine.ConnectionsSnapshot().Select(c => c.Public!).ToArray();

    /// <summary>Waits for a peer to dial this node's connection string and returns the
    /// connection. Multiple waiters each get their own incoming connection.</summary>
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

        await c.Connected.Task.WaitAsync(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        return c.Public!;
    }

    /// <summary>Dials a peer from its connection string. The chain runs internally — direct
    /// punch first, relay as the standing fallback — and the task completes when connected on
    /// either path. Surrounding whitespace and codes without the pinhole1: prefix are accepted.
    /// Malformed codes throw FormatException, self-dials throw ArgumentException, and failed
    /// attempts throw TimeoutException. Use TryConnectAsync to get a result for these expected failures.</summary>
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

    /// <summary>Dials a pasted connection code and returns either a connection or a failure
    /// with a reason and message. Accepts surrounding whitespace and an omitted pinhole1: prefix.
    /// Cancellation still throws OperationCanceledException; unexpected errors are not hidden.</summary>
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
        cs.Candidates.Any(c => c.Kind is CandidateKind.Relay or CandidateKind.IrohRelay);

    private async Task<PinholeConnection> ConnectPeerAsync(ConnectionString cs, CancellationToken ct)
    {
        ConnState c = _engine.ConnectAsync(cs, ct);
        try
        {
            await c.Connected.Task.WaitAsync(_options.ConnectTimeout, ct).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            await _engine.CloseAsync(c).ConfigureAwait(false);
            string message = PeerHasRelay(cs)
                ? "Connection timed out. Keep both apps running and use your friend's current connection string. The peer may be offline, or a relay path could not be established."
                : "Direct connection timed out and your friend's connection string has no relay fallback. Share a fresh string after their relay connects, or try connecting from both PCs at the same time.";
            throw new TimeoutException(message, ex);
        }
        catch (OperationCanceledException)
        {
            await _engine.CloseAsync(c).ConfigureAwait(false);
            throw;
        }

        return c.Public!;
    }

    /// <summary>Re-probes the world right now: re-probes STUN, rebinds the socket if its
    /// network is gone, re-allocates relays, and re-announces to every peer. Connections
    /// survive as the same objects. Also fires automatically (debounced) when the machine's
    /// network configuration changes.</summary>
    public Task RoamNowAsync(CancellationToken ct = default) => _engine.RecoverAsync(forceRebind: false, ct);

    internal NodeEngine Engine => _engine;

    /// <summary>Overrides the NAT hint embedded in future connection strings (symmetric
    /// NATs tell dialers to skip the hopeless punch). The override beats the automatic
    /// classification; passing <see cref="NatHint.Unknown"/> returns to automatic mode,
    /// where the engine classifies from multi-server STUN observations by itself. Set from
    /// <see cref="NatDetector"/> results when the app knows better than the observations.</summary>
    public void SetNatHint(NatHint hint) => _natHint = hint;

    /// <summary>Shuts the node down: every connection is closed (best-effort bye to each peer),
    /// the LAN goodbye is sent if announcing, relays are released, and the socket is disposed. Idempotent.</summary>
    public ValueTask DisposeAsync()
    {
        _lan?.Dispose();
        _engine.Dispose();
        return ValueTask.CompletedTask;
    }

    /// <summary>Shuts the node down: every connection is closed (best-effort bye to each peer),
    /// the LAN goodbye is sent if announcing, relays are released, and the socket is disposed. Idempotent.</summary>
    public void Dispose()
    {
        _lan?.Dispose();
        _engine.Dispose();
    }
}
