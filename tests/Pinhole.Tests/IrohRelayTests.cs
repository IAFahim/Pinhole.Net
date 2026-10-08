using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace Pinhole.Tests;

public sealed class IrohRelayTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Options(FakeIrohRelay server) => new()
    {
        StunServers = [], Relays = [], IrohRelayUrls = [server.Url],
        EnableNetworkWatch = false, EnablePortMapping = false, ConnectTimeout = Timeout,
    };

    private static string RelayOnly(PinholeNode node)
    {
        ConnectionString full = ConnectionString.Parse(node.ConnectionString);
        return new ConnectionString(node.PeerId,
            full.Candidates.Where(c => c.Kind == CandidateKind.IrohRelay).ToArray(),
            staticKey: full.StaticKey).ToString();
    }

    private static async Task Exchange(PinholeConnection from, PinholeConnection to, string text)
    {
        var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnReceived(ReadOnlySpan<byte> body) => received.TrySetResult(Encoding.UTF8.GetString(body));
        to.Received += OnReceived;
        try
        {
            from.Send(Encoding.UTF8.GetBytes(text));
            Assert.Equal(text, await received.Task.WaitAsync(Timeout));
        }
        finally { to.Received -= OnReceived; }
    }

    [Fact]
    public void ConnectionString_IrohCandidate_RoundTrips_AndRejectsUnsafeUrls()
    {
        var identity = new RelayIdentity();
        var candidate = new PinholeCandidate(CandidateKind.IrohRelay, new IPEndPoint(IPAddress.None, 0),
            RelayUrl: new Uri("https://aps1-1.relay.n0.iroh.link/"), RelayKey: identity.PublicKey);
        string text = new ConnectionString(identity.PeerId, [candidate]).ToString();
        var parsed = ConnectionString.Parse(text).Candidates.Single();
        Assert.Equal(candidate.RelayUrl, parsed.RelayUrl);
        Assert.Equal(identity.PublicKey, parsed.RelayKey);
        Assert.Equal(text, new ConnectionString(identity.PeerId, [parsed]).ToString());
        Assert.Throws<InvalidOperationException>(() => new ConnectionString(identity.PeerId,
            [candidate with { RelayUrl = new Uri("http://example.com/") }]).ToString());
        Assert.Throws<InvalidOperationException>(() => new ConnectionString(identity.PeerId,
            [candidate with { RelayKey = new byte[31] }]).ToString());
        for (int i = 0; i < text.Length; i++) Assert.False(ConnectionString.TryParse(text[..i], out _));
    }

    [Fact]
    public async Task PublicRelayProtocol_AuthenticatesAndAnswersPings()
    {
        await using var server = new FakeIrohRelay();
        using var client = new IrohRelay(server.Url, new RelayIdentity());
        await client.StartAsync().WaitAsync(Timeout);
        await TestPoll.UntilAsync(Timeout, () => server.Pongs > 0);
        Assert.True(client.IsAlive);
        Assert.Equal(1, server.Authentications);
    }

    [Fact]
    public async Task FreshDirectAnnouncement_RestartsPassiveRelayedSession_ThenUpgrades()
    {
        await using var server = new FakeIrohRelay();
        using var socket = new PunchRecordingSocket(SystemUdpSocket.Create(null));
        await using var a = await PinholeNode.BindAsync(Options(server) with { UdpSocketFactory = _ => socket });
        await using var b = await PinholeNode.BindAsync(Options(server));
        Task<PinholeConnection> accept = a.AcceptAsync();
        await using var atB = await b.ConnectAsync(RelayOnly(a));
        await using var atA = await accept.WaitAsync(Timeout);
        await TestPoll.UntilAsync(Timeout, () => a.Engine.Lookup(b.PeerId)?.IrohConfirmed == true
            && b.Engine.Lookup(a.PeerId)?.IrohConfirmed == true);
        a.Engine.SimulateDirectPathDeath(b.PeerId);
        b.Engine.SimulateDirectPathDeath(a.PeerId);
        await TestPoll.UntilAsync(Timeout, () => atA.State == PinholeConnectionState.Degraded && atB.State == PinholeConnectionState.Degraded);
        // End the old upgrade workers, as they do after their finite probing budget.
        Interlocked.Increment(ref a.Engine.Lookup(b.PeerId)!.PunchGeneration);
        Interlocked.Increment(ref b.Engine.Lookup(a.PeerId)!.PunchGeneration);
        await Task.Delay(1200);
        int oldPort = b.LocalPort;
        await b.Engine.SimulateInterfaceLossAsync().WaitAsync(Timeout);
        Assert.NotEqual(oldPort, b.LocalPort);
        // The new address arrives over the authenticated relay channel. The listener must
        // actively probe it even though its previous upgrade worker has gone passive.
        await TestPoll.UntilAsync(Timeout, () => socket.PunchTargets.Any(target => target.Port == b.LocalPort));
        a.Engine.SimulateDirectPathRestore(b.PeerId);
        b.Engine.SimulateDirectPathRestore(a.PeerId);
        await TestPoll.UntilAsync(Timeout, () => atA.Path.Kind == PathKind.Direct && atB.Path.Kind == PathKind.Direct);
        await Exchange(atA, atB, "fresh mobile address A to B");
        await Exchange(atB, atA, "fresh mobile address B to A");
    }

    private sealed class PunchRecordingSocket(IUdpSocket inner) : IUdpSocket
    {
        public readonly ConcurrentQueue<IPEndPoint> PunchTargets = new();
        public IPEndPoint LocalEndPoint => inner.LocalEndPoint;
        public void SendTo(ReadOnlySpan<byte> frame, SocketAddress to)
        {
            if (!frame.IsEmpty && frame[0] == (byte)FrameType.Punc)
                PunchTargets.Enqueue((IPEndPoint)new IPEndPoint(IPAddress.IPv6Any, 0).Create(to));
            inner.SendTo(frame, to);
        }
        public int ReceiveFrom(Span<byte> buffer, SocketAddress from) => inner.ReceiveFrom(buffer, from);
        public void Dispose() => inner.Dispose();
    }

    [Fact]
    public async Task RelayIntroduction_ExchangesCandidates_ThenUpgradesBothSidesToUdp()
    {
        await using var server = new FakeIrohRelay();
        await using var a = await PinholeNode.BindAsync(Options(server));
        await using var b = await PinholeNode.BindAsync(Options(server));
        Task<PinholeConnection> accept = a.AcceptAsync();
        await using var atB = await b.ConnectAsync(RelayOnly(a));
        await using var atA = await accept.WaitAsync(Timeout);
        await TestPoll.UntilAsync(Timeout, () => atA.Path.Kind == PathKind.Direct && atB.Path.Kind == PathKind.Direct);
        await Exchange(atA, atB, "upgraded A to B");
        await Exchange(atB, atA, "upgraded B to A");
    }

    [Fact]
    public async Task Dialer_CanReachAPeerRegisteredOnADifferentRelay()
    {
        await using var relayA = new FakeIrohRelay();
        await using var relayB = new FakeIrohRelay();
        await using var a = await PinholeNode.BindAsync(Options(relayA));
        await using var b = await PinholeNode.BindAsync(Options(relayB));
        Task<PinholeConnection> accept = a.AcceptAsync();
        await using var atB = await b.ConnectAsync(RelayOnly(a));
        await using var atA = await accept.WaitAsync(Timeout);
        await TestPoll.UntilAsync(Timeout, () => a.Engine.Lookup(b.PeerId)?.IrohConfirmed == true
            && b.Engine.Lookup(a.PeerId)?.IrohConfirmed == true);
        a.Engine.SimulateDirectPathDeath(b.PeerId);
        b.Engine.SimulateDirectPathDeath(a.PeerId);

        await Exchange(atA, atB, "different home relays A to B");
        await Exchange(atB, atA, "different home relays B to A");
        Assert.True(relayA.Authentications >= 2);
        Assert.Equal(PathKind.Relay, atA.Path.Kind);
        Assert.Equal(PathKind.Relay, atB.Path.Kind);
    }

    [Fact]
    public async Task DirectPathDeath_UsesIrohFallback_WithoutClosingTheConnection()
    {
        await using var server = new FakeIrohRelay();
        await using var a = await PinholeNode.BindAsync(Options(server));
        await using var b = await PinholeNode.BindAsync(Options(server));
        Task<PinholeConnection> accept = a.AcceptAsync();
        await using var atB = await b.ConnectAsync(a.ConnectionString);
        await using var atA = await accept.WaitAsync(Timeout);
        await TestPoll.UntilAsync(Timeout, () => a.Engine.Lookup(b.PeerId)?.IrohConfirmed == true
            && b.Engine.Lookup(a.PeerId)?.IrohConfirmed == true);
        a.Engine.SimulateDirectPathDeath(b.PeerId);
        b.Engine.SimulateDirectPathDeath(a.PeerId);
        Assert.Equal(PathKind.Relay, atA.Path.Kind);
        Assert.Equal(server.Url, atA.Path.RelayUrl);
        Assert.Equal(PinholeConnectionState.Degraded, atB.State);
        Assert.False(atA.Closed.IsCompleted);
        Assert.False(atB.Closed.IsCompleted);
        await Exchange(atA, atB, "fallback A to B");
        await Exchange(atB, atA, "fallback B to A");
    }

    [Fact]
    public async Task ThrowingReceiveHandler_DoesNotStopTheSharedRelay()
    {
        await using var server = new FakeIrohRelay();
        await using var a = await PinholeNode.BindAsync(Options(server));
        await using var b = await PinholeNode.BindAsync(Options(server));
        Task<PinholeConnection> accept = a.AcceptAsync();
        await using var atB = await b.ConnectAsync(RelayOnly(a));
        await using var atA = await accept.WaitAsync(Timeout);
        await TestPoll.UntilAsync(Timeout, () => a.Engine.Lookup(b.PeerId)?.IrohConfirmed == true
            && b.Engine.Lookup(a.PeerId)?.IrohConfirmed == true);
        a.Engine.SimulateDirectPathDeath(b.PeerId);
        b.Engine.SimulateDirectPathDeath(a.PeerId);

        var invoked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void Throw(ReadOnlySpan<byte> body)
        {
            invoked.TrySetResult();
            throw new ApplicationException("user callback failed");
        }
        atB.Received += Throw;
        atA.Send("first message"u8);
        await invoked.Task.WaitAsync(Timeout);
        atB.Received -= Throw;

        await Exchange(atA, atB, "after throwing callback");
        await Exchange(atB, atA, "reply after throwing callback");
        Assert.Equal(2, server.Authentications);
    }

    [Fact]
    public async Task RelayReconnect_PreservesIdentityAndConnectionObjects()
    {
        await using var server = new FakeIrohRelay();
        await using var a = await PinholeNode.BindAsync(Options(server));
        await using var b = await PinholeNode.BindAsync(Options(server));
        Task<PinholeConnection> accept = a.AcceptAsync();
        await using var atB = await b.ConnectAsync(RelayOnly(a));
        await using var atA = await accept.WaitAsync(Timeout);
        await TestPoll.UntilAsync(Timeout, () => a.Engine.Lookup(b.PeerId)?.IrohConfirmed == true
            && b.Engine.Lookup(a.PeerId)?.IrohConfirmed == true);
        a.Engine.SimulateDirectPathDeath(b.PeerId);
        b.Engine.SimulateDirectPathDeath(a.PeerId);
        int before = server.Authentications;
        Assert.True(a.HasRelay);
        Assert.True(b.HasRelay);

        // Deterministic fault injection: gate new authentications FIRST so the clients'
        // reconnect attempts cannot win the race against observing the disconnected state.
        server.PauseNewAuthentications();
        await server.DisconnectAllAsync();
        await TestPoll.UntilAsync(Timeout, () => !a.HasRelay && !b.HasRelay);
        Assert.False(atA.Closed.IsCompleted);

        server.ResumeNewAuthentications();
        await TestPoll.UntilAsync(Timeout, () => server.Authentications >= before + 2
            && atA.State == PinholeConnectionState.Degraded && atB.State == PinholeConnectionState.Degraded);
        Assert.True(a.HasRelay);
        Assert.True(b.HasRelay);
        Assert.Same(atA, a.Connections.Single());
        Assert.Same(atB, b.Connections.Single());
        Assert.False(atA.Closed.IsCompleted);
        await Exchange(atA, atB, "after relay reconnect");
    }
}

internal sealed class FakeIrohRelay : IAsyncDisposable
{
    private sealed record Client(WebSocket Socket)
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public async Task Send(byte[] message, CancellationToken ct)
        {
            await Gate.WaitAsync(ct);
            try
            {
                if (Socket.State != WebSocketState.Open) throw new WebSocketException(WebSocketError.InvalidState);
                await Socket.SendAsync(message, WebSocketMessageType.Binary, true, ct);
            }
            finally { Gate.Release(); }
        }

        public async Task CloseOutput(CancellationToken ct)
        {
            // CloseOutput shares WebSocket's send lane. Use the same gate as forwarded
            // packets so disconnect injection cannot create overlapping sends on Windows.
            await Gate.WaitAsync(ct);
            try { await Socket.CloseOutputAsync(WebSocketCloseStatus.EndpointUnavailable, "killed", ct); }
            finally { Gate.Release(); }
        }
    }

    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<string, Client> _clients = new();
    private readonly ConcurrentBag<Task> _sessions = [];
    private readonly Task _accept;
    private readonly ConcurrentQueue<byte[]> _forwarded = new();
    private int _authentications;
    private int _pongs;
    private int _authGate; // 1 = refuse new authentications, deterministically
    public int Authentications => Volatile.Read(ref _authentications);
    public int Pongs => Volatile.Read(ref _pongs);
    public Uri Url { get; }

    /// <summary>Payload bytes of every datagram this relay forwarded (addressing stripped),
    /// in order — lets tests prove a relayed transfer is opaque end to end.</summary>
    public IReadOnlyList<byte[]> Forwarded => _forwarded.ToArray();

    /// <summary>While paused, new relay connections are refused at the websocket level —
    /// reconnecting clients keep failing until Resume, so tests can observe the
    /// disconnected state without racing the retry loop.</summary>
    public void PauseNewAuthentications() => Volatile.Write(ref _authGate, 1);

    public void ResumeNewAuthentications() => Volatile.Write(ref _authGate, 0);

    public FakeIrohRelay()
    {
        using var port = new TcpListener(IPAddress.Loopback, 0);
        port.Start();
        Url = new Uri($"http://127.0.0.1:{((IPEndPoint)port.LocalEndpoint).Port}/");
        port.Stop();
        _listener.Prefixes.Add(Url.AbsoluteUri);
        _listener.Start();
        _accept = Accept();
    }

    private async Task Accept()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                HttpListenerContext context = await _listener.GetContextAsync().WaitAsync(_stop.Token);
                _sessions.Add(Serve(context));
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or HttpListenerException or ObjectDisposedException) { }
    }

    private async Task Serve(HttpListenerContext context)
    {
        Client? client = null;
        string? name = null;
        try
        {
            var accepted = await context.AcceptWebSocketAsync("iroh-relay-v2");
            using WebSocket socket = accepted.WebSocket;
            if (Volatile.Read(ref _authGate) == 1)
            {
                await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "gated", CancellationToken.None);
                return;
            }

            client = new Client(socket);
            byte[] challenge = new byte[17];
            RandomNumberGenerator.Fill(challenge.AsSpan(1));
            await client.Send(challenge, _stop.Token);
            byte[] auth = await Read(socket);
            if (auth.Length != 98 || auth[0] != 1 || auth[33] != 64) throw new InvalidDataException("invalid authentication frame");
            byte[] key = auth.AsSpan(1, 32).ToArray();
            var hash = new Blake3Digest();
            hash.Init(Blake3Parameters.Context(Encoding.UTF8.GetBytes("iroh-relay handshake v1 challenge signature")));
            hash.BlockUpdate(challenge.AsSpan(1));
            byte[] message = new byte[32];
            hash.DoFinal(message);
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(key));
            verifier.BlockUpdate(message);
            if (!verifier.VerifySignature(auth.AsSpan(34).ToArray())) throw new InvalidDataException("invalid signature");
            name = Convert.ToHexString(key);
            _clients[name] = client;
            await client.Send([2], _stop.Token);
            Interlocked.Increment(ref _authentications);
            await client.Send([9, 1, 2, 3, 4, 5, 6, 7, 8], _stop.Token);
            while (!_stop.IsCancellationRequested)
            {
                byte[] frame = await Read(socket);
                if (frame is [10, 1, 2, 3, 4, 5, 6, 7, 8]) Interlocked.Increment(ref _pongs);
                else if (frame.Length >= 34 && frame[0] == 4
                    && _clients.TryGetValue(Convert.ToHexString(frame.AsSpan(1, 32)), out Client? target))
                {
                    frame[0] = 6;
                    key.CopyTo(frame, 1);
                    _forwarded.Enqueue(frame.AsSpan(34).ToArray());
                    await target.Send(frame, _stop.Token);
                }
            }
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or IOException or ObjectDisposedException) { }
        finally
        {
            if (name is not null && client is not null)
                ((ICollection<KeyValuePair<string, Client>>)_clients).Remove(new(name, client));
        }
    }

    private async Task<byte[]> Read(WebSocket socket)
    {
        byte[] buffer = new byte[8192];
        int used = 0;
        while (true)
        {
            var result = await socket.ReceiveAsync(buffer.AsMemory(used), _stop.Token);
            if (result.MessageType != WebSocketMessageType.Binary) throw new IOException("socket closed");
            used += result.Count;
            if (result.EndOfMessage) return buffer.AsSpan(0, used).ToArray();
            if (used == buffer.Length) throw new IOException("oversized test frame");
        }
    }

    public async Task DisconnectAllAsync()
    {
        // A bare Abort() on the managed (unix) HttpListener websocket frequently leaves the
        // loopback client completely uninformed — no FIN, no RST — so the client sits on its
        // pending receive until its own keepalive ladder fires, far beyond any test budget.
        // CloseOutputAsync flushes a CLOSE frame the client observes instantly without
        // joining the session's pending receive (a full CloseAsync handshake would); the
        // Abort backstop then covers sessions that were mid-write.
        foreach (Client client in _clients.Values)
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                await client.CloseOutput(timeout.Token);
            }
            catch (Exception ex) when (ex is WebSocketException or ObjectDisposedException
                or InvalidOperationException or OperationCanceledException or TimeoutException)
            {
            }
            client.Socket.Abort();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        // Close the sockets before stopping the listener: HttpListener.Stop disposes response
        // streams that a session mid-write is still using, and that race throws from inside
        // the runtime's own cleanup. The listener is going away either way.
        await DisconnectAllAsync();
        try { _listener.Stop(); }
        catch (ObjectDisposedException) { }
        await _accept;
        await Task.WhenAll(_sessions).WaitAsync(TimeSpan.FromSeconds(3));
        try { _listener.Close(); }
        catch (ObjectDisposedException) { }
    }
}
