using System.Net;
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
    private readonly NodeEngine _engine;
    private readonly PinholeOptions _options;
    private volatile NatHint _natHint = NatHint.Unknown;

    private PinholeNode(NodeEngine engine, PinholeOptions options)
    {
        _engine = engine;
        _options = options;
    }

    /// <summary>Binds the UDP socket, probes the configured free STUN servers for the
    /// reflexive candidate, connects to the configured iroh HTTPS relays, and allocates any
    /// configured TURN relays as additional fallback paths. Unreachable infrastructure costs candidates,
    /// never the bind.</summary>
    public static async Task<PinholeNode> BindAsync(PinholeOptions? options = null, CancellationToken ct = default)
    {
        options ??= await PinholeOptions.DefaultAsync(ct).ConfigureAwait(false);
        var engine = new NodeEngine(options);
        try
        {
            await engine.BindAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            engine.Dispose();
            throw;
        }

        return new PinholeNode(engine, options);
    }

    /// <summary>This peer's stable ID (random per bind).</summary>
    public ulong PeerId => _engine.PeerId;

    /// <summary>The bound UDP port.</summary>
    public int LocalPort => _engine.LocalPort;

    /// <summary>The single discovery artifact: "pinhole1:..." carrying this peer's ID and
    /// direct/reflexive/relay candidates. Regenerate and re-share after roaming.</summary>
    public string ConnectionString => new ConnectionString(
        _engine.PeerId,
        _engine.LocalCandidatesSnapshot(),
        _natHint).ToString();

    /// <summary>The server-reflexive addresses observed at bind (one per responding STUN server).</summary>
    public IReadOnlyList<IPEndPoint> PublicEndpoints => _engine.ReflexiveSnapshot();

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

    /// <summary>Sets the NAT hint embedded in future connection strings (symmetric NATs tell
    /// dialers to skip the hopeless punch). Set from <see cref="NatDetector"/> results.</summary>
    public void SetNatHint(NatHint hint) => _natHint = hint;

    /// <summary>Shuts the node down: every connection is closed (best-effort bye to each peer), relays are released, and the socket is disposed. Idempotent.</summary>
    public ValueTask DisposeAsync()
    {
        _engine.Dispose();
        return ValueTask.CompletedTask;
    }

    /// <summary>Shuts the node down: every connection is closed (best-effort bye to each peer), relays are released, and the socket is disposed. Idempotent.</summary>
    public void Dispose() => _engine.Dispose();
}
