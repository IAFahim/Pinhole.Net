using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text.Json;
using System.Threading.Channels;

namespace Pinhole.Tests;

// DERP's server-side layout, modeled without sockets or external services. Receives
// split across messages and coalesced control frames exercise its byte-stream framing.
internal sealed class InMemoryDerpRelay : IDisposable
{
    internal sealed record Datagram(byte[] Source, byte[] Destination, byte[] Payload);
    private readonly NodeIdentity _server = new();
    private readonly ConcurrentDictionary<string, Connection> _clients = new();
    internal readonly ConcurrentQueue<Datagram> Traffic = new();
    internal readonly Uri Url;
    internal int Authentications, Pongs;
    internal bool Paused, CorruptServerInfo;
    internal int BytesPerSecond, Burst;

    internal InMemoryDerpRelay(string host = "derp.example.test") => Url = new Uri($"https://{host}/");

    internal Task<WebSocket> ConnectAsync(Uri url, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (url != new UriBuilder(Url) { Scheme = "wss", Path = "/derp" }.Uri || Paused)
            throw new WebSocketException("modeled DERP relay unavailable");
        return Task.FromResult<WebSocket>(new Connection(this));
    }

    internal void DisconnectClients()
    {
        foreach (Connection connection in _clients.Values) connection.Abort();
    }

    internal void Inject(byte[] destination, byte[] wire)
    {
        if (_clients.TryGetValue(Convert.ToHexString(destination), out Connection? connection)) connection.Enqueue(wire);
    }

    private static byte[] Frame(byte type, byte[] body)
    {
        byte[] wire = new byte[5 + body.Length];
        wire[0] = type;
        BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(1), (uint)body.Length);
        body.CopyTo(wire, 5);
        return wire;
    }

    private sealed class Connection : WebSocket
    {
        private readonly InMemoryDerpRelay _relay;
        private readonly Channel<byte[]> _incoming = Channel.CreateBounded<byte[]>(1024);
        private WebSocketState _state = WebSocketState.Open;
        private byte[]? _partial;
        private int _offset;
        private byte[]? _key;

        internal Connection(InMemoryDerpRelay relay)
        {
            _relay = relay;
            byte[] greeting = Frame(0x01, [.. "DERP🔑"u8, .. relay._server.PublicKey]);
            // A header and its body may span independently completed WS messages.
            Enqueue(greeting[..3]); Enqueue(greeting[3..]);
        }

        internal void Enqueue(byte[] wire)
        {
            if (_state == WebSocketState.Open && !_incoming.Writer.TryWrite(wire))
                throw new WebSocketException("modeled DERP queue full");
        }

        public override WebSocketCloseStatus? CloseStatus => null;
        public override string? CloseStatusDescription => null;
        public override WebSocketState State => _state;
        public override string SubProtocol => "derp";
        public override void Abort()
        {
            _state = WebSocketState.Aborted;
            _incoming.Writer.TryComplete();
            if (_key is not null) _relay._clients.TryRemove(new KeyValuePair<string, Connection>(Convert.ToHexString(_key), this));
        }
        public override void Dispose() => Abort();
        public override Task CloseAsync(WebSocketCloseStatus status, string? description, CancellationToken ct)
        { Abort(); return Task.CompletedTask; }
        public override Task CloseOutputAsync(WebSocketCloseStatus status, string? description, CancellationToken ct) => CloseAsync(status, description, ct);

        public override Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType type, bool endOfMessage, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (_state != WebSocketState.Open || type != WebSocketMessageType.Binary || !endOfMessage)
                throw new WebSocketException("invalid modeled DERP send");
            byte[] frame = buffer.ToArray();
            if (frame.Length < 5 || BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(1)) != frame.Length - 5)
                throw new WebSocketException("invalid DERP framing");
            byte[] body = frame[5..];
            if (_key is null)
            {
                if (frame[0] != 0x02 || body.Length < 72) throw new WebSocketException("invalid DERP login");
                byte[] key = body[..32];
                byte[] secret = _relay._server.ExportPrivateSeed();
                byte[] shared = DerpBox.SharedKey(secret, key);
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
                using var client = JsonDocument.Parse(DerpBox.Open(shared, body.AsSpan(32)));
                if (client.RootElement.GetProperty("version").GetInt32() != 2
                    || !client.RootElement.GetProperty("CanAckPings").GetBoolean()
                    || client.RootElement.GetProperty("AppName").GetString() != "pinhole")
                    throw new WebSocketException("invalid DERP client info");
                byte[] info = System.Text.Encoding.UTF8.GetBytes($"{{\"version\":2,\"TokenBucketBytesPerSecond\":{_relay.BytesPerSecond},\"TokenBucketBytesBurst\":{_relay.Burst}}}");
                byte[] box = DerpBox.Seal(shared, info);
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(shared);
                if (_relay.CorruptServerInfo) box[^1] ^= 1;
                _key = key;
                if (!_relay._clients.TryAdd(Convert.ToHexString(key), this)) throw new WebSocketException("duplicate DERP identity");
                Interlocked.Increment(ref _relay.Authentications);
                // Several DERP frames can also share a single WS message.
                Enqueue([.. Frame(0x03, box), .. Frame(0x12, [1, 2, 3, 4, 5, 6, 7, 8]), .. Frame(0x06, [])]);
            }
            else if (frame[0] == 0x13 && body.AsSpan().SequenceEqual(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }))
                Interlocked.Increment(ref _relay.Pongs);
            else if (frame[0] == 0x04 && body.Length is > 32 and <= 65568)
            {
                byte[] destination = body[..32];
                byte[] payload = body[32..];
                _relay.Traffic.Enqueue(new(_key, destination, payload));
                if (_relay._clients.TryGetValue(Convert.ToHexString(destination), out Connection? recipient))
                    recipient.Enqueue(Frame(0x05, [.. _key, .. payload]));
            }
            else throw new WebSocketException("unexpected DERP client frame");
            return Task.CompletedTask;
        }

        public override async Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken ct)
        {
            if (_partial is null)
            {
                try { _partial = await _incoming.Reader.ReadAsync(ct); }
                catch (ChannelClosedException ex) { throw new WebSocketException("modeled DERP connection closed", ex); }
                _offset = 0;
            }
            int count = Math.Min(7, Math.Min(buffer.Count, _partial.Length - _offset));
            _partial.AsSpan(_offset, count).CopyTo(buffer.AsSpan());
            _offset += count;
            bool end = _offset == _partial.Length;
            if (end) _partial = null;
            return new WebSocketReceiveResult(count, WebSocketMessageType.Binary, end);
        }
    }

    public void Dispose()
    {
        Paused = true;
        DisconnectClients();
    }
}
