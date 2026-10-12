using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;

namespace Pinhole;

// Managed DERP v2 over the official "derp" WebSocket transport. This consumes
// Tailcat-compatible relays; it does not implement Tailcat/WireGuard peer tunnels.
internal sealed class DerpRelay : IKeyedRelay
{
    internal const int MaxDatagramSize = 65536;
    internal const int MaxFrameSize = (1 << 20) + DerpBox.NonceSize;
    private readonly NodeIdentity _identity;
    private readonly Func<Uri, CancellationToken, Task<WebSocket>>? _connect;
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Channel<byte[]> _outgoing = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(512)
    {
        SingleReader = true, FullMode = BoundedChannelFullMode.Wait,
    });
    private readonly object _rateGate = new();
    private int _bytesPerSecond, _burst;
    private double _tokens;
    private long _lastRefill;
    private Task? _loop;
    private WebSocket? _socket;
    private int _alive;

    public Uri Url { get; }
    public CandidateKind Kind => CandidateKind.DerpRelay;
    public byte[] PublicKey => _identity.PublicKey;
    public bool IsAlive => Volatile.Read(ref _alive) != 0;
    public string? LastError { get; private set; }
    public event Action<IKeyedRelay, byte[], byte[]>? Received;
    public event Action<IKeyedRelay>? Changed;

    public DerpRelay(Uri url, NodeIdentity identity, Func<Uri, CancellationToken, Task<WebSocket>>? connect = null)
    {
        IrohAddress.ValidateRelay(url);
        Url = url;
        _identity = identity;
        _connect = connect;
    }

    public Task StartAsync(CancellationToken ct = default)
    {
        lock (_ready) _loop ??= RunAsync();
        return _ready.Task.WaitAsync(ct);
    }

    public bool Send(ReadOnlySpan<byte> destination, ReadOnlySpan<byte> payload)
    {
        if (!IsAlive || destination.Length != 32 || payload.Length is 0 or > MaxDatagramSize) return false;
        byte[] frame = EncodeFrame(0x04, new byte[32 + payload.Length]);
        destination.CopyTo(frame.AsSpan(5, 32));
        payload.CopyTo(frame.AsSpan(37));
        // Honor the relay's advertised byte budget, including DERP framing, just as
        // the upstream client does. Drops are consistent with the datagram API.
        lock (_rateGate)
        {
            if (_bytesPerSecond > 0)
            {
                long now = Stopwatch.GetTimestamp();
                _tokens = Math.Min(_burst, _tokens + Stopwatch.GetElapsedTime(_lastRefill, now).TotalSeconds * _bytesPerSecond);
                _lastRefill = now;
                if (_tokens < frame.Length) return true; // upstream drops without declaring the path dead
                _tokens -= frame.Length;
            }
            return _outgoing.Writer.TryWrite(frame);
        }
    }

    private async Task RunAsync()
    {
        int failures = 0;
        while (!_stop.IsCancellationRequested)
        {
            WebSocket? socket = null;
            using var connection = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            try
            {
                using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(connection.Token))
                {
                    deadline.CancelAfter(TimeSpan.FromSeconds(10));
                    var url = new UriBuilder(Url) { Scheme = Url.Scheme == "https" ? "wss" : "ws", Path = "/derp" };
                    socket = await (_connect is null ? ConnectAsync(url.Uri, deadline.Token) : _connect(url.Uri, deadline.Token)).ConfigureAwait(false);
                    _socket = socket;
                    if (socket.SubProtocol != "derp") throw new InvalidDataException("relay did not negotiate DERP");
                    await AuthenticateAsync(socket, deadline.Token).ConfigureAwait(false);
                }
                failures = 0;
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
                or OperationCanceledException or InvalidDataException or CryptographicException or JsonException)
            {
                LastError = $"{ex.GetType().Name}: {ex.Message}";
                for (Exception? cause = ex.InnerException; cause is not null; cause = cause.InnerException)
                    LastError += $" -> {cause.GetType().Name}: {cause.Message}";
            }
            finally
            {
                connection.Cancel();
                socket?.Abort();
                socket?.Dispose();
                Volatile.Write(ref _alive, 0);
                while (_outgoing.Reader.TryRead(out _)) { }
                Changed?.Invoke(this);
            }
            try { await Task.Delay(IrohRelay.RetryDelay(failures++), _stop.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
        _ready.TrySetCanceled(_stop.Token);
    }

    private async Task AuthenticateAsync(WebSocket socket, CancellationToken ct)
    {
        var (type, greeting) = await ReadFrameAsync(socket, ct).ConfigureAwait(false);
        if (type != 0x01 || greeting.Length is < 40 or > 1024 || !greeting.AsSpan(0, 8).SequenceEqual("DERP🔑"u8))
            throw new InvalidDataException("invalid DERP server greeting");
        byte[] secret = _identity.ExportPrivateSeed();
        byte[] key;
        try { key = DerpBox.SharedKey(secret, greeting.AsSpan(8, 32)); }
        finally { CryptographicOperations.ZeroMemory(secret); }
        try
        {
            byte[] box = DerpBox.Seal(key, "{\"version\":2,\"CanAckPings\":true,\"AppName\":\"pinhole\"}"u8);
            byte[] info = new byte[32 + box.Length];
            PublicKey.CopyTo(info, 0);
            box.CopyTo(info, 32);
            await socket.SendAsync(EncodeFrame(0x02, info), WebSocketMessageType.Binary, true, ct).ConfigureAwait(false);
            var (confirmedType, confirmed) = await ReadFrameAsync(socket, ct).ConfigureAwait(false);
            if (confirmedType != 0x03) throw new InvalidDataException("DERP relay rejected authentication");
            using var json = JsonDocument.Parse(DerpBox.Open(key, confirmed));
            if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("invalid DERP server info");
            int rate = ReadLimit(json.RootElement, "TokenBucketBytesPerSecond");
            int burst = ReadLimit(json.RootElement, "TokenBucketBytesBurst");
            if ((rate == 0) != (burst == 0)) throw new InvalidDataException("incomplete DERP rate limit");
            lock (_rateGate)
            {
                _bytesPerSecond = rate; _burst = burst; _tokens = burst;
                _lastRefill = Stopwatch.GetTimestamp();
            }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static int ReadLimit(JsonElement info, string name)
    {
        if (!info.TryGetProperty(name, out var value)) return 0;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out int number) || number < 0)
            throw new InvalidDataException("invalid DERP rate limit");
        return number;
    }

    private static async Task<WebSocket> ConnectAsync(Uri uri, CancellationToken ct)
    {
        var socket = new ClientWebSocket();
        try
        {
            socket.Options.AddSubProtocol("derp");
            socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(15);
#if NET9_0_OR_GREATER
            socket.Options.KeepAliveTimeout = TimeSpan.FromSeconds(15);
#endif
            await socket.ConnectAsync(uri, ct).ConfigureAwait(false);
            return socket;
        }
        catch { socket.Dispose(); throw; }
    }

    private async Task SendAsync(WebSocket socket, CancellationToken ct)
    {
        await foreach (byte[] frame in _outgoing.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            await socket.SendAsync(frame, WebSocketMessageType.Binary, true, ct).ConfigureAwait(false);
    }

    private async Task ReceiveAsync(WebSocket socket, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(130)); // two missed upstream keepalives
            var (type, body) = await ReadFrameAsync(socket, deadline.Token).ConfigureAwait(false);
            switch (type)
            {
                case 0x05: // RecvPacket v2: source Curve25519 key, then datagram
                    if (body.Length is <= 32 or > MaxDatagramSize + 32) throw new InvalidDataException("invalid DERP datagram size");
                    Received?.Invoke(this, body[..32], body[32..]);
                    break;
                case 0x12: // Ping: pong must use the shared send lane
                    if (body.Length != 8) throw new InvalidDataException("invalid DERP ping");
                    if (!_outgoing.Writer.TryWrite(EncodeFrame(0x13, body))) throw new IOException("DERP send queue is full");
                    break;
                case 0x06:
                    if (body.Length != 0) throw new InvalidDataException("invalid DERP keepalive");
                    break;
                case 0x14:
                    if (body.Length != 0) throw new IOException("DERP relay reported an unhealthy connection");
                    break;
                case 0x15:
                    throw new IOException("DERP relay requested reconnection");
                // PeerGone, Pong, and future informational frames do not carry data.
            }
        }
    }

    internal static byte[] EncodeFrame(byte type, ReadOnlySpan<byte> body)
    {
        byte[] frame = new byte[5 + body.Length];
        frame[0] = type;
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1), (uint)body.Length);
        body.CopyTo(frame.AsSpan(5));
        return frame;
    }

    internal static async Task<(byte Type, byte[] Body)> ReadFrameAsync(WebSocket socket, CancellationToken ct)
    {
        byte[] header = new byte[5];
        await ReadExactlyAsync(socket, header, ct).ConfigureAwait(false);
        uint length = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1));
        if (length > MaxFrameSize) throw new InvalidDataException("DERP frame exceeds size limit");
        byte[] body = new byte[(int)length];
        await ReadExactlyAsync(socket, body, ct).ConfigureAwait(false);
        return (header[0], body);
    }

    private static async Task ReadExactlyAsync(WebSocket socket, Memory<byte> buffer, CancellationToken ct)
    {
        while (buffer.Length > 0)
        {
            var read = await socket.ReceiveAsync(buffer, ct).ConfigureAwait(false);
            if (read.MessageType != WebSocketMessageType.Binary) throw new IOException("DERP connection closed or sent non-binary data");
            buffer = buffer[read.Count..]; // DERP is a byte stream across WebSocket messages
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        _socket?.Abort();
        _outgoing.Writer.TryComplete();
    }
}
