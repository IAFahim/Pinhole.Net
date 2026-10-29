using System.Net;
using System.Runtime.CompilerServices;

namespace Pinhole;

public enum PinholeConnectionState
{
    Punching = 0,

    Open = 1,

    Degraded = 2,

    Dead = 3,

    Closed = 4,
}

public enum PathKind : byte
{
    None = 0,

    Direct = 1,

    Relay = 2,
}

public enum DirectTransport : byte
{
    Udp = 0,
    Tcp = 1,
}

public sealed record PinholePath(PathKind Kind, IPEndPoint? Remote, DateTimeOffset Since)
{
    public Uri? RelayUrl { get; init; }
    public DirectTransport? Transport { get; init; } = Kind == PathKind.Direct ? Pinhole.DirectTransport.Udp : null;
    public static readonly PinholePath None = new(PathKind.None, null, DateTimeOffset.UnixEpoch);
}

public readonly record struct PinholeStats(
    long DatagramsSent,
    long DatagramsReceived,
    long DatagramsSendFailed,
    long BytesSent,
    long BytesReceived,
    long PingsSent,
    long PongsReceived)
{
    public long PingsLost => Math.Max(0, PingsSent - PongsReceived);
}

public sealed class PinholeConnection : IAsyncDisposable, IDisposable
{
    public const int MaxPayload = NodeEngine.MaxPayload;

    private readonly NodeEngine _engine;
    private readonly ConnState _c;
    private int _readInFlight;

    internal PinholeConnection(NodeEngine engine, ConnState c)
    {
        _engine = engine;
        _c = c;
    }

    public ulong PeerId => _c.PeerId;

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

    public bool RelaySignalingReady
    {
        get
        {
            lock (_c.Gate) return _c.Crypto is { PeerConfirmed: true }
                && (_c.PacketRelay is { IsAlive: true } && _c.PacketRelayConfirmed || _c.RelayRemote is not null && _c.RelayReady);
        }
    }

    public long RelayedDatagramsBlocked => Interlocked.Read(ref _c.RelayedDatagramsBlocked);

    public long PortPredictionProbesSent => Interlocked.Read(ref _c.PortPredictionProbesSent);

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

    public string? RemoteConfirmationCode
    {
        get
        {
            byte[]? staticKey = _c.PinnedStaticKey;
            if (staticKey is null)
            {
                lock (_c.Gate)
                {
                    staticKey = _c.Crypto?.PeerStaticPublic;
                }
            }

            return staticKey is null
                ? null
                : PinholeHost.FormatConfirmation(PinholeHost.ConfirmationFingerprint(_c.PeerId, staticKey, _c.PinnedEndpointKey));
        }
    }

    public long FramesRejected
    {
        get
        {
            ConnectionCrypto? crypto = _c.Crypto;
            return crypto is null ? 0 : System.Threading.Interlocked.Read(ref crypto.Rejected);
        }
    }

    public int PathMtu
    {
        get
        {
            lock (_c.Gate)
            {
                return _c.Pmtu.Wire > 0 ? _c.Pmtu.Wire : NodeEngine.PmtuBaseWire;
            }
        }
    }

    public PinholeConnectionState State => _c.State;

    public event Action<PinholeConnectionState>? StateChanged
    {
        add => _c.StateChanged += value;
        remove => _c.StateChanged -= value;
    }

    public event PinholeDatagramHandler? Received
    {
        add => _c.Received += value;
        remove => _c.Received -= value;
    }

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

    public async IAsyncEnumerable<ReadOnlyMemory<byte>> ReadAllAsync(
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        while (await ReceiveAsync(ct).ConfigureAwait(false) is { } datagram)
        {
            yield return datagram;
        }
    }

    public long DroppedDatagrams => _c.Buffer?.Dropped ?? 0;

    internal long PathProbesSent => Interlocked.Read(ref _c.PathProbesSent);

    internal long PathProbeReplies => Interlocked.Read(ref _c.PathProbeReplies);

    public void Send(ReadOnlySpan<byte> payload) => _engine.Send(_c, payload);

    public void Ping() => _engine.Ping(_c);

    public TimeSpan? LastRtt
    {
        get
        {
            long ticks = Interlocked.Read(ref _c.LastRttTicks);
            return ticks == long.MinValue ? null : TimeSpan.FromTicks(Math.Max(0, ticks));
        }
    }

    public TimeSpan? AverageRtt
    {
        get
        {
            lock (_c.Gate)
            {
                return _c.Keepalive.RttEwmaTicks > 0 ? TimeSpan.FromTicks((long)_c.Keepalive.RttEwmaTicks) : null;
            }
        }
    }

    public PinholePath Path
    {
        get
        {
            lock (_c.Gate)
            {
                return _c.Path switch
                {
                    PathKind.Direct when _c.DirectRemoteEp is { } ep => new PinholePath(PathKind.Direct, ep, _c.PathSince)
                    { Transport = _c.DirectTcp is null ? DirectTransport.Udp : DirectTransport.Tcp },
                    PathKind.Relay when _c.PacketRelay is { IsAlive: true } relay && _c.PacketRelayConfirmed => new PinholePath(PathKind.Relay, null, _c.PathSince) { RelayUrl = relay.Url },
                    PathKind.Relay when _c.RelayRemote is { } ep => new PinholePath(PathKind.Relay, ep, _c.PathSince),
                    _ => PinholePath.None,
                };
            }
        }
    }

    public PinholeStats Stats => new(
        Interlocked.Read(ref _c.Sent),
        Interlocked.Read(ref _c.ReceivedCount),
        Interlocked.Read(ref _c.SendFailed),
        Interlocked.Read(ref _c.BytesSent),
        Interlocked.Read(ref _c.BytesReceived),
        Interlocked.Read(ref _c.PingsSent),
        Interlocked.Read(ref _c.PongsReceived));

    public Task Closed => _c.Closed.Task;

    public async Task CloseAsync()
    {
        await _engine.CloseAsync(_c).ConfigureAwait(false);
    }

    public ValueTask DisposeAsync()
    {
        _engine.DisposeConnection(_c);
        return ValueTask.CompletedTask;
    }

    public void Dispose() => _engine.DisposeConnection(_c);
}
