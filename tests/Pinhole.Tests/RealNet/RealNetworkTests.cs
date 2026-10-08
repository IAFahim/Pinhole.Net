using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Pinhole.Blobs;
using Xunit;
using static Pinhole.Tests.ExternalTools;

namespace Pinhole.Tests;

/// <summary>#26: REAL network infrastructure, REAL OS sockets. These tests launch a real
/// iroh-relay server (the reference implementation of the relay protocol Pinhole speaks)
/// and run the production <see cref="SystemUdpSocket"/> path against it — no virtual
/// network, no fake relay. A real TURN server (coturn) serves the TURN scenario when
/// provided. Tools are located via env vars (IROH_RELAY_BIN, COTURN_BIN) or PATH; each run
/// leaves report.json + captured server logs in <c>$TMPDIR/pinhole-realnet/&lt;scenario&gt;-*</c>
/// as evidence (kept on both pass and fail).
///
/// Pinned infrastructure (issue #26: test-only, never a production dependency):
///   IROH_RELAY_BIN: cargo install iroh-relay --features server --version 1.3.0 --locked
///   COTURN_BIN:     any coturn `turnserver` build (e.g. distro package)
/// Public relay operators are never contacted.</summary>
public sealed class RealNetworkTests
{
    private const string RelayEnv = "IROH_RELAY_BIN";

    private static PinholeOptions RealRelayOptions(Uri relayUrl, bool listen) => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [relayUrl],
        Listen = listen,
        ConnectTimeout = TimeSpan.FromSeconds(12),
        BindProbeBudget = TimeSpan.FromSeconds(10),
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false,
        EnablePortMapping = false,
        ReceiveBufferCapacity = 4096,
    };

    /// <summary>A loopback port currently free (bind-then-release; the window is a
    /// millisecond-scale race against nothing in an isolated test run).</summary>
    private static int FreePort()
    {
        using var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    /// <summary>Starts a real iroh-relay server on a fresh loopback port. Dev mode serves
    /// plain HTTP + the real relay WebSocket protocol; TLS is irrelevant on loopback, and
    /// the engine accepts http:// relay URLs only for loopback — exactly this setup.</summary>
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

    /// <summary>The answerer's string with every non-relay candidate removed: on loopback
    /// the direct path would always win, so relay-only is how the scenario proves the
    /// relay leg carried the session (no hidden UDP bypass, the #26 requirement).</summary>
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
            payload[0] = 0xc0; // an arbitrary protocol packet, not a Pinhole frame
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
            await using PinholeNode a = await PinholeNode.BindAsync(RealRelayOptions(url, listen: true), ct);
            await using PinholeNode b = await PinholeNode.BindAsync(RealRelayOptions(url, listen: true), ct);
            await TestPoll.UntilAsync(TestBudget.Bind, () => a.HasRelay && b.HasRelay);

            Task<PinholeConnection> accept = a.AcceptAsync(ct);
            await using PinholeConnection dialer = await b.ConnectAsync(RelayOnly(a).ToString(), ct).WaitAsync(TestBudget.Handshake, ct);
            await using PinholeConnection answerer = await accept.WaitAsync(TestBudget.Handshake, ct);

            // What carried the session, over a real socket and a real relay server.
            // Relay-only is the engine's Degraded state by definition: Open means direct.
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

            // Force the whole download over the relay: strip the server's loopback-direct
            // candidates from the ticket's embedded string.
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

            // The relay PROCESS dies — a real server restart, not a simulated fault.
            await relay.DisposeAsync();

            // Same port, fresh process: the engine's relay clients reconnect on their own
            // backoff and the LOGICAL connection (same object) carries traffic again.
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

            // On loopback the engine may heal onto the direct path once the answerer has
            // announced its full candidate list (correct resilience, honestly recorded);
            // relay-specific healing with no direct alternative is what the topology
            // lab's UDP-blocked-hotel scenario proves. Either way: same connection
            // object, data flowing, over real sockets and a really-dead relay process.
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

        // A real TURN server: long-term credentials, UDP listener only, no TLS/CLI —
        // exactly the RFC 5766 allocation path TurnClient speaks.
        await using var turn = await StartAsync(bin,
            $"-n --lt-cred-mech -u {user}:{pass} -p {port} --no-tls --no-dtls --no-cli",
            logDir, "turnserver", expectTcpPort: null, ct);
        try
        {
            PinholeOptions Options(bool listen) => new()
            {
                StunServers = [],
                Relays = [new TurnServerConfig(new IPEndPoint(IPAddress.Loopback, port), user, pass)],
                IrohRelayUrls = [],
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

            // TURN-only: strip the answerer's loopback-direct candidates.
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
