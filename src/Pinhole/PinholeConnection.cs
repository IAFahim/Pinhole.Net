using System.Net;
using System.Runtime.CompilerServices;

namespace Pinhole;

/// <summary>Lifecycle of a connection. <see cref="Open"/> means a direct path is active;
/// <see cref="Degraded"/> means the connection lives on a relay (fully usable, higher
/// latency); <see cref="Dead"/> means no path exists right now — the object survives and can
/// come back; <see cref="Closed"/> is terminal and only ever reached by closing.</summary>
public enum PinholeConnectionState
{
    /// <summary>Trying candidates; nothing is flowing yet.</summary>
    Punching = 0,

    /// <summary>A direct path is active and carrying traffic.</summary>
    Open = 1,

    /// <summary>Relay-only after direct-path trouble; fully usable, higher latency.</summary>
    Degraded = 2,

    /// <summary>No usable path after the punch budget ran out; the object survives and can still come back.</summary>
    Dead = 3,

    /// <summary>Terminal, and only ever reached by closing.</summary>
    Closed = 4,
}

/// <summary>The physical path a connection is currently using.</summary>
public enum PathKind : byte
{
    /// <summary>No path in use.</summary>
    None = 0,

    /// <summary>Peer-to-peer across the public internet through the punched hole.</summary>
    Direct = 1,

    /// <summary>Through an iroh HTTPS relay or a TURN relay.</summary>
    Relay = 2,
}

/// <summary>Snapshot of the current path.</summary>
public sealed record PinholePath(PathKind Kind, IPEndPoint? Remote, DateTimeOffset Since)
{
    /// <summary>The HTTPS relay URL when the path uses an iroh relay.</summary>
    public Uri? RelayUrl { get; init; }
    /// <summary>The "no path" sentinel: null remote, timestamp at the Unix epoch.</summary>
    public static readonly PinholePath None = new(PathKind.None, null, DateTimeOffset.UnixEpoch);
}

/// <summary>Plain counters describing a connection's traffic. Loss on an unreliable datagram
/// path cannot be observed directly; <see cref="PingsLost"/> is the honest approximation —
/// pings sent minus pongs received.</summary>
public readonly record struct PinholeStats(
    long DatagramsSent,
    long DatagramsReceived,
    long DatagramsSendFailed,
    long BytesSent,
    long BytesReceived,
    long PingsSent,
    long PongsReceived)
{
    /// <summary>Pings sent minus pongs received, floored at zero — the honest approximation of loss this layer can offer.</summary>
    public long PingsLost => Math.Max(0, PingsSent - PongsReceived);
}

/// <summary>One open-forever datagram connection to a peer, identified by stable peer ID —
/// never by IP. Roaming, rebinding, and path death are handled inside: the same object keeps
/// delivering while the network underneath changes. It ends only when the app closes it.</summary>
public sealed class PinholeConnection : IAsyncDisposable, IDisposable
{
    /// <summary>The conservative maximum payload of one <see cref="Send"/> call. Larger
    /// datagrams would fragment or die silently in the network; keep the protocol above
    /// this layer chunked.</summary>
    public const int MaxPayload = NodeEngine.MaxPayload;

    private readonly NodeEngine _engine;
    private readonly ConnState _c;
    private int _readInFlight; // single-reader guard for the buffered API

    internal PinholeConnection(NodeEngine engine, ConnState c)
    {
        _engine = engine;
        _c = c;
    }

    /// <summary>The peer's stable ID, taken from its connection string.</summary>
    public ulong PeerId => _c.PeerId;

    /// <summary>Whether this session is encrypted: the X25519 handshake completed and every
    /// frame on the wire is sealed (AES-256-GCM, replay-protected). Always true between
    /// current nodes; false only for plaintext-legacy peers accepted by an
    /// <see cref="PinholeEncryption.Optional"/> node.</summary>
    public bool IsEncrypted
    {
        get
        {
            lock (_c.Gate)
            {
                return _c.Crypto is { Established: true };
            }
        }
    }

    /// <summary>The peer's long-term X25519 public key (32 bytes) once the handshake
    /// delivered it — the identity to pin (trust on first use or against a directory) if
    /// the connection string did not already vouch for it. Null on plaintext sessions.</summary>
    public byte[]? RemoteStaticKey
    {
        get
        {
            lock (_c.Gate)
            {
                return _c.Crypto?.PeerStaticPublic;
            }
        }
    }

    /// <summary>Frames dropped because they failed authentication — tampered, replayed, or
    /// plaintext where a session was promised. Steady zero on a healthy path.</summary>
    public long FramesRejected
    {
        get
        {
            ConnectionCrypto? crypto = _c.Crypto;
            return crypto is null ? 0 : System.Threading.Interlocked.Read(ref crypto.Rejected);
        }
    }

    /// <summary>The wire size in bytes the direct path is proven to carry — starts at the
    /// 1237-byte floor (the 1200-byte <see cref="MaxPayload"/> guarantee plus frame
    /// overhead) and rises as path-MTU discovery confirms bigger sizes. The largest payload
    /// <see cref="Send"/> accepts is <see cref="PathMtu"/> minus 37; resets to the floor
    /// whenever the connection leaves its direct path.</summary>
    public int PathMtu
    {
        get
        {
            lock (_c.Gate)
            {
                return _c.PmtuWire > 0 ? _c.PmtuWire : NodeEngine.PmtuBaseWire;
            }
        }
    }

    /// <summary>Current lifecycle state; changes are also surfaced on <see cref="StateChanged"/>.</summary>
    public PinholeConnectionState State => _c.State;

    /// <summary>Fires on every state transition (on a receive thread — keep handlers fast).</summary>
    public event Action<PinholeConnectionState>? StateChanged
    {
        add => _c.StateChanged += value;
        remove => _c.StateChanged -= value;
    }

    /// <summary>Datagrams received from the peer (on a receive thread — keep handlers fast).
    /// The span is only valid during the call — copy it if it must outlive the handler.</summary>
    public event PinholeDatagramHandler? Received
    {
        add => _c.Received += value;
        remove => _c.Received -= value;
    }

    /// <summary>Waits for the next buffered datagram and returns it, or null at end of
    /// stream (the connection closed and the buffer drained). Requires
    /// <see cref="PinholeOptions.ReceiveBufferCapacity"/> &gt; 0 at bind — the buffer must
    /// exist before the handshake completes, which is exactly the race this API closes: a
    /// datagram that arrived before the first read is returned by the first read. The
    /// returned memory is owned by the connection until handed to you and stays valid after
    /// later reads. One reader at a time: a concurrent receive throws
    /// <see cref="InvalidOperationException"/>. Cancellation ends the pending read without
    /// closing the connection; roaming and relay fallback never end the stream.</summary>
    public async ValueTask<ReadOnlyMemory<byte>?> ReceiveAsync(CancellationToken ct = default)
    {
        DatagramBuffer? buffer = _c.Buffer;
        if (buffer is null)
        {
            throw new InvalidOperationException(
                "ReceiveAsync requires ReceiveBufferCapacity > 0 at bind; subscribe to the Received event instead.");
        }

        if (Interlocked.CompareExchange(ref _readInFlight, 1, 0) != 0)
        {
            throw new InvalidOperationException("a receive is already in flight on this connection (single reader).");
        }

        try
        {
            byte[]? datagram = await buffer.ReadAsync(ct).ConfigureAwait(false);
            // Branch, don't ternary: "cond ? null : struct" targeting a nullable struct
            // compiles the null arm to default(struct) — an empty memory, not EOF.
            if (datagram is null)
            {
                return null;
            }

            return new ReadOnlyMemory<byte>(datagram);
        }
        finally
        {
            Volatile.Write(ref _readInFlight, 0);
        }
    }

    /// <summary>Enumerates buffered datagrams until the connection closes (end of stream).
    /// Same contract as <see cref="ReceiveAsync"/>: needs buffering enabled at bind, one
    /// reader at a time, cancellation stops the enumeration without closing anything, and
    /// datagrams that arrived before the first iteration are still delivered.</summary>
    public async IAsyncEnumerable<ReadOnlyMemory<byte>> ReadAllAsync(
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        while (await ReceiveAsync(ct).ConfigureAwait(false) is { } datagram)
        {
            yield return datagram;
        }
    }

    /// <summary>Datagrams dropped by the receive buffer because it was full (drop-oldest).
    /// Zero when buffering is disabled.</summary>
    public long DroppedDatagrams => _c.Buffer?.Dropped ?? 0;

    /// <summary>Path-validation probes sent by the maintenance scheduler (internal:
    /// monitoring only, deliberately separate from caller Ping/RTT stats).</summary>
    internal long PathProbesSent => Interlocked.Read(ref _c.PathProbesSent);

    /// <summary>Maintenance probes that came back matched and from the probed endpoint.</summary>
    internal long PathProbeReplies => Interlocked.Read(ref _c.PathProbeReplies);

    /// <summary>Sends one unreliable datagram on the current path. The direct UDP path allocates nothing;
    /// empty payloads and payloads above <see cref="MaxPayload"/> throw before touching the
    /// network (a zero-length datagram is undeliverable by definition).</summary>
    public void Send(ReadOnlySpan<byte> payload) => _engine.Send(_c, payload);

    /// <summary>Sends a path probe and schedules the round-trip time into
    /// <see cref="LastRtt"/>/<see cref="AverageRtt"/>. A diagnostic tool that never throws —
    /// a probe that cannot leave simply goes unanswered — and Pinhole never schedules
    /// keepalives for you.</summary>
    public void Ping() => _engine.Ping(_c);

    /// <summary>Round-trip time of the most recent answered ping, if any.</summary>
    public TimeSpan? LastRtt
    {
        get
        {
            long ticks = Interlocked.Read(ref _c.LastRttTicks);
            return ticks == long.MinValue ? null : TimeSpan.FromTicks(Math.Max(0, ticks));
        }
    }

    /// <summary>Exponentially-smoothed round-trip time across answered pings, if any.</summary>
    public TimeSpan? AverageRtt
    {
        get
        {
            lock (_c.Gate)
            {
                return _c.RttEwmaTicks > 0 ? TimeSpan.FromTicks((long)_c.RttEwmaTicks) : null;
            }
        }
    }

    /// <summary>Snapshot of the path currently in use.</summary>
    public PinholePath Path
    {
        get
        {
            lock (_c.Gate)
            {
                return _c.Path switch
                {
                    PathKind.Direct when _c.DirectRemoteEp is { } ep => new PinholePath(PathKind.Direct, ep, _c.PathSince),
                    PathKind.Relay when _c.Iroh is { IsAlive: true } relay && _c.IrohConfirmed => new PinholePath(PathKind.Relay, null, _c.PathSince) { RelayUrl = relay.Url },
                    PathKind.Relay when _c.RelayRemote is { } ep => new PinholePath(PathKind.Relay, ep, _c.PathSince),
                    _ => PinholePath.None,
                };
            }
        }
    }

    /// <summary>Plain traffic counters — zero-dep, AOT-safe.</summary>
    public PinholeStats Stats => new(
        Interlocked.Read(ref _c.Sent),
        Interlocked.Read(ref _c.ReceivedCount),
        Interlocked.Read(ref _c.SendFailed),
        Interlocked.Read(ref _c.BytesSent),
        Interlocked.Read(ref _c.BytesReceived),
        Interlocked.Read(ref _c.PingsSent),
        Interlocked.Read(ref _c.PongsReceived));

    /// <summary>Completes when the connection is closed — by this side, by the peer's bye, or
    /// by disposing the node. Roaming never completes it.</summary>
    public Task Closed => _c.Closed.Task;

    /// <summary>Closes the connection and notifies the peer (best effort). Idempotent.</summary>
    public async Task CloseAsync()
    {
        await _engine.CloseAsync(_c).ConfigureAwait(false);
    }

    /// <summary>Closes the connection — same as <see cref="CloseAsync"/>, with the best-effort bye fire-and-forget rather than awaited.</summary>
    public ValueTask DisposeAsync()
    {
        _engine.DisposeConnection(_c);
        return ValueTask.CompletedTask;
    }

    /// <summary>Closes the connection — same as <see cref="CloseAsync"/>, with the best-effort bye fire-and-forget rather than awaited.</summary>
    public void Dispose() => _engine.DisposeConnection(_c);
}
