using System.Buffers.Binary;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Pinhole;

// Managed implementation of the iroh-relay v1/v2 WebSocket transport, not iroh QUIC.
internal sealed class RelayIdentity
{
    private readonly Ed25519PrivateKeyParameters _secret;
    public byte[] PublicKey { get; }
    public ulong PeerId { get; }

    public RelayIdentity(byte[]? seed = null)
    {
        _secret = new Ed25519PrivateKeyParameters(seed ?? RandomNumberGenerator.GetBytes(32));
        PublicKey = _secret.GeneratePublicKey().GetEncoded();
        PeerId = BinaryPrimitives.ReadUInt64LittleEndian(SHA256.HashData(PublicKey));
    }

    public byte[] Authenticate(ReadOnlySpan<byte> challenge)
    {
        if (challenge.Length != 16) throw new InvalidDataException("invalid iroh relay challenge");
        var hash = new Blake3Digest();
        hash.Init(Blake3Parameters.Context(Encoding.UTF8.GetBytes("iroh-relay handshake v1 challenge signature")));
        hash.BlockUpdate(challenge);
        byte[] message = new byte[32];
        hash.DoFinal(message);
        var signer = new Ed25519Signer();
        signer.Init(true, _secret);
        signer.BlockUpdate(message);
        byte[] auth = new byte[98];
        auth[0] = 1; // ClientAuth, QUIC varint (one byte).
        PublicKey.CopyTo(auth, 1); // postcard's fixed-size public key.
        auth[33] = 64; // postcard serde_bytes signature length.
        signer.GenerateSignature().CopyTo(auth, 34);
        return auth;
    }
}

internal sealed class IrohRelay : IDisposable
{
    private const int MaxMessage = 1024 * 1024;
    private readonly RelayIdentity _identity;
    private readonly CancellationTokenSource _stop = new();
    private readonly Channel<byte[]> _outgoing = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(512)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.Wait,
    });
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private ClientWebSocket? _socket;
    private Task? _loop;
    private int _alive;

    public Uri Url { get; }
    public bool IsAlive => Volatile.Read(ref _alive) != 0;
    public event Action<IrohRelay, byte[], byte[]>? Received;
    public event Action<IrohRelay>? Changed;
    public string? LastError { get; private set; }

    /// <summary>Reconnect delay after the given number of consecutive failed connections:
    /// capped exponential backoff with ±10% jitter, the same practice iroh uses — a relay
    /// outage must not produce a synchronized retry storm from every client. Brief blips
    /// still heal fast: the first retry lands near one second, the delay doubles per
    /// consecutive failure up to thirty, and the count resets on the first successful
    /// authentication.</summary>
    internal static TimeSpan RetryDelay(int failedAttempts)
    {
        long baseMs = Math.Min(1000L << Math.Min(failedAttempts, 5), 30_000);
        double jitter = RandomNumberGenerator.GetInt32(-1000, 1001) / 10_000.0;
        return TimeSpan.FromMilliseconds(baseMs * (1 + jitter));
    }

    public IrohRelay(Uri url, RelayIdentity identity)
    {
        if (!url.IsAbsoluteUri || url.Scheme is not ("https" or "http")
            || (url.Scheme == "http" && !url.IsLoopback)
            || url.UserInfo.Length != 0 || url.Query.Length != 0 || url.Fragment.Length != 0)
            throw new ArgumentException("relay URL must use HTTPS (HTTP is allowed on loopback)", nameof(url));
        Url = url;
        _identity = identity;
    }

    public Task StartAsync(CancellationToken ct = default)
    {
        lock (_ready)
        {
            _loop ??= RunAsync();
        }
        return _ready.Task.WaitAsync(ct);
    }

    public bool Send(ReadOnlySpan<byte> destination, ReadOnlySpan<byte> payload)
    {
        if (!IsAlive || destination.Length != 32 || payload.Length > 65536) return false;
        byte[] frame = new byte[34 + payload.Length];
        frame[0] = 4; // ClientToRelayDatagram.
        destination.CopyTo(frame.AsSpan(1, 32));
        frame[33] = 0; // No ECN marking.
        payload.CopyTo(frame.AsSpan(34));
        return _outgoing.Writer.TryWrite(frame);
    }

    private async Task RunAsync()
    {
        int failures = 0;
        while (!_stop.IsCancellationRequested)
        {
            using var socket = new ClientWebSocket();
            using var connection = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            _socket = socket;
            try
            {
                socket.Options.AddSubProtocol("iroh-relay-v2");
                socket.Options.AddSubProtocol("iroh-relay-v1");
                socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(15);
#if NET9_0_OR_GREATER // KeepAliveTimeout ships with .NET 9; older runtimes use the stack default
                socket.Options.KeepAliveTimeout = TimeSpan.FromSeconds(15);
#endif
                var url = new UriBuilder(Url) { Scheme = Url.Scheme == "https" ? "wss" : "ws", Path = "/relay" };
                using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(connection.Token))
                {
                    deadline.CancelAfter(TimeSpan.FromSeconds(10));
                    await socket.ConnectAsync(url.Uri, deadline.Token).ConfigureAwait(false);
                    if (socket.SubProtocol is not ("iroh-relay-v1" or "iroh-relay-v2"))
                        throw new InvalidDataException("relay did not negotiate an iroh protocol");
                    byte[] challenge = await ReadAsync(socket, deadline.Token).ConfigureAwait(false);
                    if (challenge.Length != 17 || challenge[0] != 0)
                        throw new InvalidDataException("relay did not send its authentication challenge");
                    await socket.SendAsync(_identity.Authenticate(challenge.AsSpan(1)), WebSocketMessageType.Binary, true, deadline.Token).ConfigureAwait(false);
                    byte[] confirmed = await ReadAsync(socket, deadline.Token).ConfigureAwait(false);
                    if (confirmed.Length != 1 || confirmed[0] != 2)
                        throw new InvalidDataException("relay rejected authentication");
                }

                failures = 0; // authenticated: the next drop starts the ladder from the bottom again
                LastError = null;
                Volatile.Write(ref _alive, 1);
                _ready.TrySetResult();
                Changed?.Invoke(this);
                Task receive = ReceiveAsync(socket, connection.Token);
                Task send = SendAsync(socket, connection.Token);
                await Task.WhenAny(receive, send).ConfigureAwait(false);
                connection.Cancel();
                socket.Abort();
                await Task.WhenAll(receive, send).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is WebSocketException or HttpRequestException or IOException
                or OperationCanceledException or InvalidDataException)
            {
                // InvalidDataException included: a relay that answers garbage must cost a
                // reconnect cycle, not silently kill this relay's loop forever.
                LastError = ex.Message;
            }
            finally
            {
                connection.Cancel();
                socket.Abort();
                Volatile.Write(ref _alive, 0);
                while (_outgoing.Reader.TryRead(out _)) { }
                Changed?.Invoke(this);
            }

            TimeSpan pause = RetryDelay(failures++);
            try { await Task.Delay(pause, _stop.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
        _ready.TrySetCanceled(_stop.Token);
    }

    private async Task SendAsync(ClientWebSocket socket, CancellationToken ct)
    {
        await foreach (byte[] frame in _outgoing.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            await socket.SendAsync(frame, WebSocketMessageType.Binary, true, ct).ConfigureAwait(false);
    }

    private async Task ReceiveAsync(ClientWebSocket socket, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            byte[] frame = await ReadAsync(socket, ct).ConfigureAwait(false);
            if (frame.Length == 0) throw new InvalidDataException("empty relay frame");
            if (frame[0] == 9 && frame.Length == 9)
            {
                frame[0] = 10; // Protocol pong (not a WebSocket pong).
                if (!_outgoing.Writer.TryWrite(frame)) throw new IOException("relay send queue is full");
            }
            else if (frame[0] is 6 or 7)
            {
                int header = frame[0] == 6 ? 34 : 36;
                if (frame.Length < header) throw new InvalidDataException("truncated relay datagram");
                byte[] source = frame.AsSpan(1, 32).ToArray();
                int size = frame[0] == 6 ? frame.Length - header : BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(34));
                if (size == 0 || size > 65536) throw new InvalidDataException("invalid relay datagram size");
                for (int offset = header; offset < frame.Length; offset += size)
                    Received?.Invoke(this, source, frame.AsSpan(offset, Math.Min(size, frame.Length - offset)).ToArray());
            }
            else if (frame[0] == 12 || (frame[0] == 13 && frame.Length == 2 && frame[1] == 1))
            {
                throw new IOException("relay requested reconnection");
            }
        }
    }

    private static async Task<byte[]> ReadAsync(ClientWebSocket socket, CancellationToken ct)
    {
        byte[] buffer = new byte[4096];
        int used = 0;
        while (true)
        {
            var result = await socket.ReceiveAsync(buffer.AsMemory(used), ct).ConfigureAwait(false);
            if (result.MessageType != WebSocketMessageType.Binary) throw new IOException("relay connection closed or sent a non-binary message");
            used += result.Count;
            if (result.EndOfMessage) return buffer.AsSpan(0, used).ToArray();
            if (used == buffer.Length)
            {
                if (buffer.Length >= MaxMessage) throw new InvalidDataException("relay frame exceeds size limit");
                Array.Resize(ref buffer, Math.Min(buffer.Length * 2, MaxMessage));
            }
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        try { _socket?.Abort(); }
        catch (ObjectDisposedException) { }
    }
}
