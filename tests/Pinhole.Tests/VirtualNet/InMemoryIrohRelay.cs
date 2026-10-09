using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Pinhole.Tests;

/// <summary>A bounded modeled relay speaking the independent server-side iroh
/// challenge/auth/datagram layout. Production IrohRelay and session crypto still
/// run unchanged. This fixture does not model real TLS, sockets or NAT traversal.</summary>
internal sealed class InMemoryIrohRelay : IDisposable
{
    internal sealed record Datagram(byte[] Source, byte[] Destination, byte[] Payload);
    internal static readonly Uri Url = new("https://relay.example.test");
    internal ConcurrentQueue<Datagram> Traffic { get; } = new();
    private readonly ConcurrentDictionary<string, Connection> _clients = new();
    private readonly ConcurrentDictionary<byte, int> _drop = new();
    internal int Authentications;
    internal int Clients => _clients.Count;
    internal void DropNext(byte type, int count) => _drop[type] = count;

    internal Task<WebSocket> ConnectAsync(Uri url, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (url != new Uri("wss://relay.example.test/relay")) throw new WebSocketException("unexpected relay URL");
        return Task.FromResult<WebSocket>(new Connection(this));
    }

    private void Forward(Connection sender, byte[] frame)
    {
        if (sender.Key is null || frame.Length < 35 || frame[0] != 4 || frame[33] != 0)
            throw new WebSocketException("invalid client-to-relay datagram");
        byte[] destination = frame.AsSpan(1, 32).ToArray();
        byte[] payload = frame.AsSpan(34).ToArray();
        Traffic.Enqueue(new(sender.Key, destination, payload));
        while (_drop.TryGetValue(payload[0], out int remaining) && remaining > 0)
            if (_drop.TryUpdate(payload[0], remaining - 1, remaining)) return;
        Deliver(sender.Key, destination, payload);
    }

    internal void Deliver(byte[] source, byte[] destination, byte[] payload)
    {
        if (!_clients.TryGetValue(Convert.ToHexString(destination), out Connection? recipient)) return;
        byte[] message = new byte[34 + payload.Length];
        message[0] = 6; source.CopyTo(message, 1); message[33] = 0; payload.CopyTo(message, 34);
        recipient.Enqueue(message);
    }

    private sealed class Connection : WebSocket
    {
        private readonly InMemoryIrohRelay _relay;
        private readonly byte[] _challenge = RandomNumberGenerator.GetBytes(16);
        private readonly Channel<byte[]> _incoming = Channel.CreateBounded<byte[]>(512);
        private WebSocketState _state = WebSocketState.Open;
        private byte[]? _partial;
        private int _offset;
        internal byte[]? Key;

        internal Connection(InMemoryIrohRelay relay)
        {
            _relay = relay;
            Enqueue([0, .. _challenge]);
        }
        internal void Enqueue(byte[] frame)
        {
            if (State == WebSocketState.Open && !_incoming.Writer.TryWrite(frame))
                throw new WebSocketException("modeled relay queue is full");
        }
        public override WebSocketCloseStatus? CloseStatus => null;
        public override string? CloseStatusDescription => null;
        public override WebSocketState State => _state;
        public override string? SubProtocol => "iroh-relay-v2";
        public override void Abort()
        {
            _state = WebSocketState.Aborted;
            _incoming.Writer.TryComplete();
            if (Key is not null) _relay._clients.TryRemove(new KeyValuePair<string, Connection>(Convert.ToHexString(Key), this));
        }
        public override void Dispose() => Abort();
        public override Task CloseAsync(WebSocketCloseStatus closeStatus, string? statusDescription, CancellationToken ct)
        { Abort(); return Task.CompletedTask; }
        public override Task CloseOutputAsync(WebSocketCloseStatus closeStatus, string? statusDescription, CancellationToken ct) => CloseAsync(closeStatus, statusDescription, ct);

        public override Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType type, bool endOfMessage, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (State != WebSocketState.Open || type != WebSocketMessageType.Binary || !endOfMessage)
                throw new WebSocketException("invalid modeled relay send");
            byte[] frame = buffer.ToArray();
            if (Key is null)
            {
                if (frame.Length != 98 || frame[0] != 1 || frame[33] != 64) throw new WebSocketException("invalid client authentication");
                byte[] key = frame.AsSpan(1, 32).ToArray();
                var hash = new Blake3Digest();
                hash.Init(Blake3Parameters.Context(Encoding.UTF8.GetBytes("iroh-relay handshake v1 challenge signature")));
                hash.BlockUpdate(_challenge, 0, _challenge.Length);
                byte[] message = new byte[32]; hash.DoFinal(message, 0);
                var signer = new Ed25519Signer(); signer.Init(false, new Ed25519PublicKeyParameters(key, 0));
                signer.BlockUpdate(message, 0, message.Length);
                if (!signer.VerifySignature(frame.AsSpan(34).ToArray())) throw new WebSocketException("invalid endpoint signature");
                Key = key;
                if (!_relay._clients.TryAdd(Convert.ToHexString(key), this)) throw new WebSocketException("duplicate endpoint");
                Interlocked.Increment(ref _relay.Authentications);
                Enqueue([2]);
            }
            else if (frame[0] == 4) _relay.Forward(this, frame);
            else if (frame[0] != 10) throw new WebSocketException("unexpected relay message type");
            return Task.CompletedTask;
        }

        public override async Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken ct)
        {
            if (_partial is null)
            {
                try { _partial = await _incoming.Reader.ReadAsync(ct); }
                catch (ChannelClosedException ex) { throw new WebSocketException("modeled relay closed", ex); }
                _offset = 0;
            }
            int count = Math.Min(31, Math.Min(buffer.Count, _partial.Length - _offset));
            _partial.AsSpan(_offset, count).CopyTo(buffer.AsSpan()); _offset += count;
            bool end = _offset == _partial.Length;
            if (end) _partial = null;
            return new WebSocketReceiveResult(count, WebSocketMessageType.Binary, end);
        }
    }

    public void Dispose()
    {
        foreach (Connection connection in _clients.Values) connection.Abort();
        _clients.Clear();
    }
}
