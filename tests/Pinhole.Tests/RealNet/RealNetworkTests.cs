using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Pinhole.Blobs;
using Xunit;
using static Pinhole.Tests.ExternalTools;

namespace Pinhole.Tests;

public sealed class RealNetworkTests
{
    private const string RelayEnv = "IROH_RELAY_BIN";

    private static PinholeOptions RealRelayOptions(Uri relayUrl, bool listen) => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [relayUrl], DerpRelayUrls = [],
        Listen = listen,
        ConnectTimeout = TimeSpan.FromSeconds(12),
        BindProbeBudget = TimeSpan.FromSeconds(10),
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false,
        EnablePortMapping = false,
        ReceiveBufferCapacity = 4096,
    };

    private static int FreePort()
    {
        using var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    private static async Task<(ExternalProcess Relay, Uri Url, string Version, string LogDir)> StartRelayAsync()
    {
        string bin = FindTool(RelayEnv, "iroh-relay")!;
        int port = FreePort();
        string logDir = LogDirFor("iroh-relay");
        Directory.CreateDirectory(logDir);
        string config = Path.Combine(logDir, "relay.toml");
        await File.WriteAllTextAsync(config, $"http_bind_addr = \"127.0.0.1:{port}\"\n");
        ExternalProcess relay = await StartAsync(bin, $"--dev --config-path {config}", logDir, "iroh-relay", port, CancellationToken.None);
        return (relay, new Uri($"http://127.0.0.1:{port}/"), Version(bin), logDir);
    }

    private static ConnectionString RelayOnly(PinholeNode answerer)
    {
        ConnectionString full = Pinhole.ConnectionString.Parse(answerer.ConnectionString);
        var relayCandidates = full.Candidates.Where(c => c.Kind == CandidateKind.IrohRelay).ToArray();
        Assert.NotEmpty(relayCandidates);
        return new ConnectionString(full.PeerId, relayCandidates, full.NatHint, full.StaticKey);
    }

    [RealNetFact(RelayEnv, "iroh-relay")]
    public async Task RawIrohConnectivity_RealRelay_PreservesPacketsWithoutPinholeFraming()
    {
        (ExternalProcess relay, Uri url, string version, string logDir) = await StartRelayAsync();
        await using var relayGuard = relay;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await using var a = await IrohTransport.BindAsync(new IrohTransportOptions { Network = RealRelayOptions(url, listen: false), PublishAddress = false });
        await using var b = await IrohTransport.BindAsync(new IrohTransportOptions { Network = RealRelayOptions(url, listen: false), PublishAddress = false });
        await TestPoll.UntilAsync(TestBudget.Bind, () => a.HasRelay && b.HasRelay);
        IrohRoute route = await a.ConnectAsync(new IrohAddress(b.EndpointId, relayUrls: [url]).ToString());
        Assert.All(route.Paths, p => Assert.Null(p.DirectAddress));
        foreach (int size in new[] { 1, 1200, 60000, 65502 })
        {
            byte[] payload = RandomNumberGenerator.GetBytes(size);
            payload[0] = 0xc0;
            route.Send(payload);
            IrohDatagram atB = await b.ReceiveAsync().AsTask().WaitAsync(TestBudget.Io);
            Assert.Equal(a.EndpointId, atB.Path.EndpointId);
            Assert.Equal(payload, atB.Payload.ToArray());
            b.SendTo(atB.Path, payload);
            Assert.Equal(payload, (await a.ReceiveAsync().AsTask().WaitAsync(TestBudget.Io)).Payload.ToArray());
        }
        WriteReport(logDir, "raw-iroh-connectivity", "iroh-relay", version,
            nameof(SystemUdpSocket), "native identity-routed raw datagrams", passed: true, sw.Elapsed.TotalSeconds,
            "1/1200/60000/65502-byte packets verified both directions; no direct candidate or Pinhole framing");
    }

    [RealNetFact(RelayEnv, "iroh-relay")]
    public async Task RelayOnly_RealIrohRelayServer_ConnectsAndFlowsOnRealSockets()
    {
        string logDir = LogDirFor("relay-only");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var ct = CancellationToken.None;
        (ExternalProcess relay, Uri url, string version, _) = await StartRelayAsync();
        await using var relayGuard = relay;
        try
        {

            PinholeOptions relayOnly = RealRelayOptions(url, listen: true) with
                { EnableDirectUdp = false, EnableTcpTransport = false };
            await using PinholeNode a = await PinholeNode.BindAsync(relayOnly, ct);
            await using PinholeNode b = await PinholeNode.BindAsync(relayOnly, ct);
            await TestPoll.UntilAsync(TestBudget.Bind, () => a.HasRelay && b.HasRelay);

            Task<PinholeConnection> accept = a.AcceptAsync(ct);
            await using PinholeConnection dialer = await b.ConnectAsync(RelayOnly(a).ToString(), ct).WaitAsync(TestBudget.Handshake, ct);
            await using PinholeConnection answerer = await accept.WaitAsync(TestBudget.Handshake, ct);

            Assert.Equal(PinholeConnectionState.Degraded, dialer.State);
            Assert.Equal(PathKind.Relay, dialer.Path.Kind);
            Assert.True(dialer.IsEncrypted, "relay-routed sessions are still end-to-end encrypted");

            var gotAtAnswerer = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            answerer.Received += p => gotAtAnswerer.TrySetResult(p.ToArray());
            dialer.Send("real relay, real sockets"u8);
            Assert.Equal("real relay, real sockets"u8.ToArray(), await gotAtAnswerer.Task.WaitAsync(TestBudget.Io, ct));

            WriteReport(logDir, "relay-only-real-iroh-relay", "iroh-relay", version,
                nameof(SystemUdpSocket), "iroh-relay ws v1/v2 (dev http)", passed: true, sw.Elapsed.TotalSeconds);
        }
        catch
        {
            WriteReport(logDir, "relay-only-real-iroh-relay", "iroh-relay", version,
                nameof(SystemUdpSocket), "iroh-relay ws v1/v2 (dev http)", passed: false, sw.Elapsed.TotalSeconds,
                "logs: " + logDir);
            throw;
        }
    }

    [RealNetFact(RelayEnv, "iroh-relay")]
    public async Task BlobTransfer_ThroughRealIrohRelay_VerifiesEndToEnd()
    {
        string logDir = LogDirFor("blob-through-real-relay");
        Directory.CreateDirectory(logDir);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var ct = CancellationToken.None;
        (ExternalProcess relay, Uri url, string version, _) = await StartRelayAsync();
        await using var relayGuard = relay;
        try
        {
            string src = Path.Combine(logDir, "payload.bin");
            await File.WriteAllBytesAsync(src, RandomNumberGenerator.GetBytes(256 * 1024), ct);

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions
            {
                NodeOptions = RealRelayOptions(url, listen: true),
            }, ct);
            await using PinholeNode probe = await PinholeNode.BindAsync(RealRelayOptions(url, listen: false), ct);
            await TestPoll.UntilAsync(TestBudget.Bind, () => server.Node.HasRelay && probe.HasRelay);

            BlobTicket full = server.Ticket;
            var ticket = new BlobTicket
            {
                Kind = full.Kind,
                Root = full.Root,
                Name = full.Name,
                ConnectionString = RelayOnly(server.Node).ToString(),
                PreSharedKey = full.PreSharedKey,
            };

            string dest = Path.Combine(logDir, "dest");
            BlobDownloadResult result = await BlobClient.DownloadAsync(ticket, dest, options: new BlobDownloadOptions
            {
                NodeOptions = RealRelayOptions(url, listen: false),
            }, ct: ct).WaitAsync(TimeSpan.FromSeconds(90), ct);

            Assert.Equal(256 * 1024, result.Bytes);
            byte[] downloaded = await File.ReadAllBytesAsync(result.Path, ct);
            byte[] original = await File.ReadAllBytesAsync(src, ct);
            Assert.True(downloaded.AsSpan().SequenceEqual(original),
                "the relayed download verified against the ticket root");

            WriteReport(logDir, "blob-through-real-iroh-relay", "iroh-relay", version,
                nameof(SystemUdpSocket), "iroh-relay ws v1/v2 (dev http)", passed: true, sw.Elapsed.TotalSeconds,
                "256 KiB verified over the relay leg");
        }
        catch
        {
            WriteReport(logDir, "blob-through-real-iroh-relay", "iroh-relay", version,
                nameof(SystemUdpSocket), "iroh-relay ws v1/v2 (dev http)", passed: false, sw.Elapsed.TotalSeconds,
                "logs: " + logDir);
            throw;
        }
    }

    [RealNetFact(RelayEnv, "iroh-relay")]
    public async Task RelayRestart_RealProcessDeath_ConnectionHealsOntoAvailablePath()
    {
        string logDir = LogDirFor("relay-restart-real");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var ct = CancellationToken.None;
        string bin = FindTool(RelayEnv, "iroh-relay")!;
        string version = Version(bin);
        int port = FreePort();
        Directory.CreateDirectory(logDir);
        string config = Path.Combine(logDir, "relay.toml");
        await File.WriteAllTextAsync(config, $"http_bind_addr = \"127.0.0.1:{port}\"\n");
        var url = new Uri($"http://127.0.0.1:{port}/");

        ExternalProcess? relay = null;
        try
        {
            relay = await StartAsync(bin, $"--dev --config-path {config}", logDir, "iroh-relay-1", port, ct);
            await using PinholeNode a = await PinholeNode.BindAsync(RealRelayOptions(url, listen: true), ct);
            await using PinholeNode b = await PinholeNode.BindAsync(RealRelayOptions(url, listen: true), ct);
            await TestPoll.UntilAsync(TestBudget.Bind, () => a.HasRelay && b.HasRelay);

            Task<PinholeConnection> accept = a.AcceptAsync(ct);
            await using PinholeConnection dialer = await b.ConnectAsync(RelayOnly(a).ToString(), ct).WaitAsync(TestBudget.Handshake, ct);
            await using PinholeConnection answerer = await accept.WaitAsync(TestBudget.Handshake, ct);
            var before = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            answerer.Received += p => before.TrySetResult(p.ToArray());
            dialer.Send("before"u8);
            Assert.Equal("before"u8.ToArray(), await before.Task.WaitAsync(TestBudget.Io, ct));

            await relay.DisposeAsync();

            relay = await StartAsync(bin, $"--dev --config-path {config}", logDir, "iroh-relay-2", port, ct);
            var after = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            answerer.Received += p => after.TrySetResult(p.ToArray());

            var swHeal = System.Diagnostics.Stopwatch.StartNew();
            while (!after.Task.IsCompleted && swHeal.Elapsed < TimeSpan.FromSeconds(45))
            {
                dialer.Send("after"u8);
                await Task.Delay(500, ct);
            }

            Assert.Equal("after"u8.ToArray(), await after.Task.WaitAsync(TestBudget.Io, ct));
            Assert.Same(dialer, b.Connections.Single(c => c.PeerId == a.PeerId));

            string healedPath = dialer.Path.Kind.ToString().ToLowerInvariant();
            WriteReport(logDir, "relay-restart-real-process", "iroh-relay", version,
                nameof(SystemUdpSocket), "iroh-relay ws v1/v2 (dev http)", passed: true, sw.Elapsed.TotalSeconds,
                $"healed in {swHeal.Elapsed.TotalSeconds:0.0}s onto {healedPath} after real relay process death");
        }
        catch
        {
            WriteReport(logDir, "relay-restart-real-process", "iroh-relay", version,
                nameof(SystemUdpSocket), "iroh-relay ws v1/v2 (dev http)", passed: false, sw.Elapsed.TotalSeconds,
                "logs: " + logDir);
            throw;
        }
        finally
        {
            if (relay is not null)
            {
                await relay.DisposeAsync();
            }
        }
    }

    [RealNetFact(CoturnEnv, "turnserver")]
    public async Task TurnRelay_RealCoturnServer_ConnectsAndFlowsOnRealSockets()
    {
        string logDir = LogDirFor("turn-coturn");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var ct = CancellationToken.None;
        string bin = FindTool(CoturnEnv, "turnserver")!;
        int port = FreePort();
        const string user = "pinhole", pass = "test-only-credential";

        await using var turn = await StartAsync(bin,
            $"-n --lt-cred-mech -u {user}:{pass} -p {port} --no-tls --no-dtls --no-cli",
            logDir, "turnserver", expectTcpPort: null, ct);
        try
        {
            PinholeOptions Options(bool listen) => new()
            {
                StunServers = [],
                Relays = [new TurnServerConfig(new IPEndPoint(IPAddress.Loopback, port), user, pass)],
                IrohRelayUrls = [], DerpRelayUrls = [],
                Listen = listen,
                ConnectTimeout = TimeSpan.FromSeconds(12),
                BindProbeBudget = TimeSpan.FromSeconds(10),
                PublishIrohAddress = false,
                EnableLanDiscovery = false,
                EnableNetworkWatch = false,
                EnablePortMapping = false,
                ReceiveBufferCapacity = 4096,
            };

            await using PinholeNode a = await PinholeNode.BindAsync(Options(listen: true), ct);
            await using PinholeNode b = await PinholeNode.BindAsync(Options(listen: true), ct);
            await TestPoll.UntilAsync(TestBudget.Bind, () => a.HasRelay && b.HasRelay);

            ConnectionString full = Pinhole.ConnectionString.Parse(a.ConnectionString);
            var turnCandidates = full.Candidates.Where(c => c.Kind == CandidateKind.Relay).ToArray();
            Assert.NotEmpty(turnCandidates);
            string turnOnly = new ConnectionString(full.PeerId, turnCandidates, full.NatHint, full.StaticKey).ToString();

            Task<PinholeConnection> accept = a.AcceptAsync(ct);
            await using PinholeConnection dialer = await b.ConnectAsync(turnOnly, ct).WaitAsync(TestBudget.Handshake, ct);
            await using PinholeConnection answerer = await accept.WaitAsync(TestBudget.Handshake, ct);
            Assert.Equal(PathKind.Relay, dialer.Path.Kind);

            var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            answerer.Received += p => got.TrySetResult(p.ToArray());
            dialer.Send("real turn"u8);
            Assert.Equal("real turn"u8.ToArray(), await got.Task.WaitAsync(TestBudget.Io, ct));

            WriteReport(logDir, "turn-real-coturn", "coturn", Version(bin),
                nameof(SystemUdpSocket), "RFC 5766 TURN (UDP, long-term credentials)", passed: true, sw.Elapsed.TotalSeconds);
        }
        catch
        {
            WriteReport(logDir, "turn-real-coturn", "coturn", Version(bin),
                nameof(SystemUdpSocket), "RFC 5766 TURN (UDP, long-term credentials)", passed: false, sw.Elapsed.TotalSeconds,
                "logs: " + logDir);
            throw;
        }
    }
}
