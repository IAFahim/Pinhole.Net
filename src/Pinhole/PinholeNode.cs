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
    private readonly NodeEngine _engine;
    private readonly PinholeOptions _options;
    private volatile NatHint _natHint = NatHint.Unknown;

    private PinholeNode(NodeEngine engine, PinholeOptions options)
    {
        _engine = engine;
        _options = options;
    }

    /// <summary>Binds the UDP socket, probes the configured free STUN servers for the
    /// reflexive candidate, and allocates the configured free TURN relays as the standing
    /// fallback. Every stage is best-effort: unreachable infrastructure costs candidates,
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
    /// either path. It fails only when the whole chain fails.</summary>
    public async Task<PinholeConnection> ConnectAsync(string connectionString, CancellationToken ct = default)
    {
        ConnectionString cs = Pinhole.ConnectionString.Parse(connectionString);
        if (cs.PeerId == PeerId)
        {
            throw new ArgumentException("connection string points at this node itself", nameof(connectionString));
        }

        ConnState c = _engine.ConnectAsync(cs, ct);
        try
        {
            await c.Connected.Task.WaitAsync(_options.ConnectTimeout, ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            await _engine.CloseAsync(c).ConfigureAwait(false);
            throw new TimeoutException(
                "could not connect: the direct punch failed and no relay path was established " +
                "(the peer's connection string carries no relay candidate, or the relay is unreachable)");
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
