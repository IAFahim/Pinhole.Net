using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Pinhole.Tests;

public sealed class WorkerCoordinatorTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);
    private static PinholeOptions Offline(bool relay = false) => new()
    {
        Bind = new IPEndPoint(IPAddress.Loopback, 0), StunServers = [], Relays = relay ? null : [],
        IrohRelayUrls = [], LookupProviders = [], RendezvousEndpoints = [],
        PublishIrohAddress = false, EnablePortMapping = false, EnableNetworkWatch = false,
        EnableLanDiscovery = false, EnableInterfaceCandidates = false,
        EnableDirectUdp = !relay, EnableTcpTransport = false, ReceiveBufferCapacity = 32,
        EnablePmtud = false, StunRefreshInterval = TimeSpan.Zero,
        BindProbeBudget = TimeSpan.FromSeconds(5), ConnectTimeout = TimeSpan.FromSeconds(8)
    };

    [Theory]
    [InlineData("http://public.example")]
    [InlineData("https://user:password@example.com")]
    [InlineData("https://example.com?token=value")]
    public async Task InsecureOrCredentialBearingCoordinatorUrl_IsRejected(string url)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => PinholeSession.HostAsync(new PinholeHostSettings
        { CoordinatorUrl = new Uri(url), NodeOptions = Offline() }));
    }

    [Fact]
    public async Task HttpFallback_PairsTwoPinnedPeersAndExchangesEncryptedDatagrams()
    {
        await using var service = new CoordinatorStub();
        await using var host = await PinholeSession.HostAsync(new PinholeHostSettings
        { CoordinatorUrl = service.Url, NodeOptions = Offline() }).WaitAsync(Timeout);
        await using var joined = await PinholeSession.JoinAsync(host.Code.ToLowerInvariant(), new PinholeJoinSettings
        { CoordinatorUrl = service.Url, NodeOptions = Offline() }).WaitAsync(Timeout);
        await using var accepted = await host.AcceptAsync().WaitAsync(Timeout);
        Assert.True(service.WebSocketRejected);
        Assert.True(joined.IsEncrypted && accepted.IsEncrypted);
        await Exchange(accepted, joined);
    }

    [Fact]
    public async Task DistinctTurnDataAddresses_MutualWorkerTicketsEstablishEncryptedRelay()
    {
        using var turn = new FakeTurnServer(bindAddress: IPAddress.Loopback,
            relayedAddresses: [IPAddress.Parse("192.0.2.41"), IPAddress.Parse("192.0.2.42")]);
        await using var service = new CoordinatorStub(new TurnServerConfig(turn.Control, "user", "pass"));
        await using var host = await PinholeSession.HostAsync(new PinholeHostSettings
        { CoordinatorUrl = service.Url, NodeOptions = Offline(relay: true) }).WaitAsync(Timeout);
        await using var joined = await PinholeSession.JoinAsync(host.Code, new PinholeJoinSettings
        { CoordinatorUrl = service.Url, NodeOptions = Offline(relay: true) }).WaitAsync(Timeout);
        await using var accepted = await host.AcceptAsync().WaitAsync(Timeout);
        Assert.Equal(PathKind.Relay, joined.Path.Kind);
        Assert.Equal(PathKind.Relay, accepted.Path.Kind);
        Assert.True(joined.IsEncrypted && accepted.IsEncrypted);
        await Exchange(accepted, joined);
    }

    [Fact]
    public async Task TcpOnly_CoordinatorPairsPinnedPeersWithoutUdpOrRelayData()
    {
        await using var service = new CoordinatorStub();
        PinholeOptions Options() => Offline() with
        {
            Bind = SidecarSockets.ProbeDualStackEndpoint(IPAddress.Loopback),
            EnableDirectUdp = false, EnableTcpTransport = true
        };
        await using var host = await PinholeSession.HostAsync(new PinholeHostSettings
        { CoordinatorUrl = service.Url, NodeOptions = Options() }).WaitAsync(Timeout);
        await using var joined = await PinholeSession.JoinAsync(host.Code, new PinholeJoinSettings
        { CoordinatorUrl = service.Url, NodeOptions = Options() }).WaitAsync(Timeout);
        await using var accepted = await host.AcceptAsync().WaitAsync(Timeout);
        Assert.Equal(DirectTransport.Tcp, joined.Path.Transport);
        Assert.Equal(DirectTransport.Tcp, accepted.Path.Transport);
        Assert.True(joined.IsEncrypted && accepted.IsEncrypted);
        await Exchange(accepted, joined);
    }

    [Fact]
    public async Task CancelledAccept_DoesNotCancelTheSharedPairingTask()
    {
        await using var service = new CoordinatorStub();
        await using var host = await PinholeSession.HostAsync(new PinholeHostSettings
        { CoordinatorUrl = service.Url, NodeOptions = Offline() }).WaitAsync(Timeout);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => host.AcceptAsync(canceled.Token));
        await using var joined = await PinholeSession.JoinAsync(host.Code, new PinholeJoinSettings
        { CoordinatorUrl = service.Url, NodeOptions = Offline() }).WaitAsync(Timeout);
        await using var accepted = await host.AcceptAsync().WaitAsync(Timeout);
        await Exchange(accepted, joined);
    }

    [Fact]
    public async Task UnknownCode_HonorsWaitTimeout()
    {
        await using var service = new CoordinatorStub();
        await Assert.ThrowsAsync<TimeoutException>(() => PinholeSession.JoinAsync("ZZZZZZZZZ", new PinholeJoinSettings
        {
            CoordinatorUrl = service.Url, NodeOptions = Offline(), WaitTimeout = TimeSpan.FromMilliseconds(300),
            PollInterval = TimeSpan.FromMilliseconds(50)
        }).WaitAsync(Timeout));
    }

    [Fact]
    public void UnpinnedCoordinatorInvitation_IsRejected()
    {
        var invitation = new ConnectionString(123, [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 23456))]);
        Assert.Throws<InvalidDataException>(() => WorkerCoordinator.ValidateInvitation(invitation.ToString()));
    }

    private static async Task Exchange(PinholeConnection a, PinholeConnection b)
    {
        byte[] data = RandomNumberGenerator.GetBytes(128);
        a.Send(data);
        Assert.Equal(data, (await b.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value.ToArray());
        b.Send(data);
        Assert.Equal(data, (await a.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value.ToArray());
    }

    /// <summary>Small HTTP fixture, deliberately refusing WebSockets to cover the
    /// polling fallback. The production JS room's admission/auth rules have their
    /// own tests; this fixture exercises the real C# node and credential plumbing.</summary>
    private sealed class CoordinatorStub : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly object _gate = new();
        private readonly Task _loop;
        private readonly TurnServerConfig? _turn;
        private string? _code, _hostToken, _joinToken, _hostInvitation, _joinInvitation;
        public bool WebSocketRejected { get; private set; }
        public Uri Url { get; }

        public CoordinatorStub(TurnServerConfig? turn = null)
        {
            _turn = turn;
            _listener.Start();
            Url = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}");
            _loop = ListenAsync();
        }
        private async Task ListenAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    TcpClient client = await _listener.AcceptTcpClientAsync(_stop.Token);
                    _ = HandleAsync(client);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException) { }
        }
        private async Task HandleAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    using NetworkStream stream = client.GetStream();
                    using var reader = new StreamReader(stream, Encoding.ASCII, false, 4096, leaveOpen: true);
                    string[] first = (await reader.ReadLineAsync(_stop.Token) ?? "").Split(' ');
                    if (first.Length < 2) return;
                    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    string? line;
                    while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(_stop.Token)))
                    {
                        int colon = line.IndexOf(':');
                        if (colon > 0) headers[line[..colon]] = line[(colon + 1)..].Trim();
                    }
                    int length = headers.TryGetValue("Content-Length", out var value) ? int.Parse(value) : 0;
                    if (length > 8192) return;
                    var chars = new char[length];
                    int read = 0;
                    while (read < length)
                    {
                        int count = await reader.ReadAsync(chars.AsMemory(read), _stop.Token);
                        if (count == 0) throw new IOException("Incomplete HTTP request.");
                        read += count;
                    }
                    string token = headers.GetValueOrDefault("Authorization", "");
                    string[] path = first[1].Split('/', StringSplitOptions.RemoveEmptyEntries);
                    if (path.Length < 3) return;
                    string code = path[2];
                    string action = path.Length > 3 ? path[3] : "";
                    int status = 200;
                    string? peer = null;
                    bool giveCredentials = false;
                    lock (_gate)
                    {
                        if (action == "events") { WebSocketRejected = true; status = 400; }
                        else if (first[0] == "PUT" && action.Length == 0)
                        { _code = code; _hostToken = token; giveCredentials = true; }
                        else if (_code != code) status = 404;
                        else if (first[0] == "POST" && action == "join")
                        {
                            if (_joinToken is not null && _joinToken != token) status = 409;
                            else { _joinToken = token; peer = _hostInvitation; giveCredentials = true; }
                        }
                        else if (token != _hostToken && token != _joinToken) status = 401;
                        else if (first[0] == "PUT" && action == "ticket")
                        {
                            using JsonDocument document = JsonDocument.Parse(new string(chars));
                            string invitation = document.RootElement.GetProperty("invitation").GetString()!;
                            if (token == _hostToken) _hostInvitation = invitation;
                            else _joinInvitation = invitation;
                            peer = token == _hostToken ? _joinInvitation : _hostInvitation;
                        }
                        else if (first[0] == "DELETE") { _code = null; status = 204; }
                        else peer = token == _hostToken ? _joinInvitation : _hostInvitation;
                    }
                    object[] ice = giveCredentials && _turn is { } turn
                        ? [new { urls = new[] { $"turn:{turn.Server.Address}:{turn.Server.Port}?transport=udp" }, username = turn.Username, credential = turn.Credential }]
                        : [];
                    byte[] response = status == 204 ? [] : JsonSerializer.SerializeToUtf8Bytes(new { version = 1, peerInvitation = peer, iceServers = ice });
                    string header = $"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(header), _stop.Token);
                    await stream.WriteAsync(response, _stop.Token);
                }
                catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException or SocketException) { }
            }
        }
        public async ValueTask DisposeAsync()
        {
            _stop.Cancel(); _listener.Stop();
            await _loop;
            _stop.Dispose();
        }
    }
}
