using System.Net;
using System.Net.Sockets;
using System.Text;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

/// <summary>The topology lab (#20's first deliverable): every scenario the connection
/// audit (#15) claimed, replayed against an in-process internet whose NATs translate and
/// filter for real. The expected direct-vs-relay outcomes below are not aspirations — they
/// are the classical hole-punching physics table (RFC 5128): cone×cone punches through
/// mutual mappings, symmetric pairs reach each other only when the far side's filter admits
/// a fresh per-destination port, and symmetric×(port-restricted|symmetric) cannot punch at
/// all and must ride the relay.</summary>
public sealed class TopologyLabTests(ITestOutputHelper output)
{
    private static readonly TimeSpan Settle = TimeSpan.FromSeconds(15); // relay-introduce → direct-upgrade budget
    private static readonly TimeSpan Quiet = TimeSpan.FromSeconds(6);   // "stays on the relay" observation window

    public static IEnumerable<object[]> NatPairings() =>
        from listener in new[] { VirtualNatKind.FullCone, VirtualNatKind.RestrictedCone, VirtualNatKind.PortRestricted, VirtualNatKind.Symmetric }
        from dialer in new[] { VirtualNatKind.FullCone, VirtualNatKind.RestrictedCone, VirtualNatKind.PortRestricted, VirtualNatKind.Symmetric }
        select new object[] { listener, dialer };

    /// <summary>The classical reachability table, in terms of what the engine's machinery
    /// (simultaneous punches, observed-source adoption, relay introduction, upgrade
    /// probing) can extract from each NAT pairing.</summary>
    private static PathKind ExpectedPath(VirtualNatKind listener, VirtualNatKind dialer) => (listener, dialer) switch
    {
        (VirtualNatKind.Symmetric, VirtualNatKind.Symmetric) => PathKind.Relay,
        (VirtualNatKind.Symmetric, VirtualNatKind.PortRestricted) => PathKind.Relay,
        (VirtualNatKind.PortRestricted, VirtualNatKind.Symmetric) => PathKind.Relay,
        _ => PathKind.Direct,
    };

    private static async Task<(PinholeConnection DialerSide, PinholeConnection ListenerSide)> ConnectAsync(
        PinholeNode listener, PinholeNode dialer, string? listenerString = null)
    {
        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection dialerSide = await dialer.ConnectAsync(listenerString ?? listener.ConnectionString).WaitAsync(TestBudget.Handshake);
        PinholeConnection listenerSide = await accept.WaitAsync(TestBudget.Handshake);
        return (dialerSide, listenerSide);
    }

    private static async Task ExchangeAsync(PinholeConnection from, PinholeConnection to, string marker)
    {
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        to.Received += payload => got.TrySetResult(payload.ToArray());
        from.Send(Encoding.UTF8.GetBytes(marker));
        byte[] answer = await got.Task.WaitAsync(TestBudget.Io);
        Assert.Equal(marker, Encoding.UTF8.GetString(answer));
    }

    /// <summary>Exchange that retries until the path heals — for use right after a network
    /// event (mapping expiry, roam) where in-flight frames die and recovery is asynchronous.</summary>
    private static async Task ExchangeEventuallyAsync(PinholeConnection from, PinholeConnection to, string marker, TimeSpan budget)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < budget)
        {
            var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            void Handler(ReadOnlySpan<byte> payload)
            {
                if (Encoding.UTF8.GetString(payload) == marker)
                {
                    got.TrySetResult(payload.ToArray());
                }
            }

            to.Received += Handler;
            from.Send(Encoding.UTF8.GetBytes(marker));
            try
            {
                byte[] answer = await got.Task.WaitAsync(TimeSpan.FromMilliseconds(500));
                Assert.Equal(marker, Encoding.UTF8.GetString(answer));
                return;
            }
            catch (TimeoutException)
            {
                // path not healed yet — retry
            }
            finally
            {
                to.Received -= Handler;
            }
        }

        Assert.Fail($"no exchange within {budget}");
    }

    // ------------------------------------------------------------------ the 16-cell NAT matrix

    [Theory]
    [MemberData(nameof(NatPairings))]
    public async Task NatMatrix_BothSidesBehindNats_PairConnectsAndFlows(VirtualNatKind listenerKind, VirtualNatKind dialerKind)
    {
        using VirtualLab lab = new(withTurn: true);
        VirtualNat listenerNat = lab.Nat(listenerKind, "203.0.113.10", "172.31.10.0/24");
        VirtualNat dialerNat = lab.Nat(dialerKind, "203.0.113.20", "172.31.20.0/24");
        await using PinholeNode listener = await lab.BindNodeAsync(listenerNat);
        await using PinholeNode dialer = await lab.BindNodeAsync(dialerNat);

        (PinholeConnection conn, PinholeConnection atListener) = await ConnectAsync(listener, dialer);
        await ExchangeAsync(conn, atListener, $"matrix {listenerKind}->{dialerKind} forward");
        await ExchangeAsync(atListener, conn, $"matrix {listenerKind}->{dialerKind} reverse");

        PathKind expected = ExpectedPath(listenerKind, dialerKind);
        if (expected == PathKind.Direct)
        {
            await TestPoll.UntilAsync(Settle, () => conn.Path.Kind == PathKind.Direct);
        }
        else
        {
            // The physics forbid a direct path: after the quiet window the session must
            // still be relayed — and still carrying traffic.
            Assert.Equal(PathKind.Relay, conn.Path.Kind);
            await Task.Delay(Quiet);
            Assert.Equal(PathKind.Relay, conn.Path.Kind);
            await ExchangeAsync(conn, atListener, "relay-only pair still flowing");
        }

        Assert.True(listenerNat.MappingsCreated > 0, $"listener NAT translated nothing — {lab.Net.Counters()}");
        Assert.True(dialerNat.MappingsCreated > 0, $"dialer NAT translated nothing — {lab.Net.Counters()}");
        output.WriteLine($"L{listenerKind} x D{dialerKind} -> {conn.Path.Kind} | {lab.Net.Counters()}");
    }

    // ------------------------------------------------------------------ adversarial scenarios

    [Fact]
    public async Task UdpFullyBlockedHotel_SessionRidesTheRelayAndNotOneDirectDatagramEscapes()
    {
        using VirtualLab lab = new(withTurn: true);
        VirtualNat listenerNat = lab.Nat(VirtualNatKind.FullCone, "203.0.113.10", "172.31.10.0/24");
        VirtualNat dialerNat = lab.Nat(VirtualNatKind.FullCone, "203.0.113.20", "172.31.20.0/24");
        listenerNat.BlockAllOutboundDirect = true;
        dialerNat.BlockAllOutboundDirect = true;
        await using PinholeNode listener = await lab.BindNodeAsync(listenerNat);
        await using PinholeNode dialer = await lab.BindNodeAsync(dialerNat);

        (PinholeConnection conn, PinholeConnection atListener) = await ConnectAsync(listener, dialer);
        Assert.Equal(PathKind.Relay, conn.Path.Kind);
        await ExchangeAsync(conn, atListener, "hotel wifi, B -> A");
        await ExchangeAsync(atListener, conn, "hotel wifi, A -> B");

        // Every direct attempt — punches, STUN probes, everything — died in the virtual
        // internet; the session exists only because the relay carried it.
        Assert.Equal(0L, lab.Net.Delivered);
        Assert.True(lab.Net.Unroutable > 0, "the blocked path must have seen (and dropped) direct attempts");
        output.WriteLine(lab.Net.Counters());
    }

    [Fact]
    public async Task CgnatHairpin_TwoNodesBehindOneNat_PunchThroughTheLoop()
    {
        using VirtualLab lab = new();
        VirtualNat shared = lab.Nat(VirtualNatKind.FullCone, "203.0.113.30", "172.31.30.0/24");
        await using PinholeNode a = await lab.BindNodeAsync(shared);
        await using PinholeNode b = await lab.BindNodeAsync(shared);

        // Both advertise reflexives on the shared NAT's public address; reaching each other
        // means the NAT must hairpin its own public endpoints back inside.
        (PinholeConnection conn, PinholeConnection atA) = await ConnectAsync(a, b);
        await TestPoll.UntilAsync(Settle, () => conn.Path.Kind == PathKind.Direct);
        await ExchangeAsync(conn, atA, "hairpin, B -> A");
        await ExchangeAsync(atA, conn, "hairpin, A -> B");
        Assert.True(shared.MappingsCreated >= 2, "both sides punched a mapping through the shared box");
        output.WriteLine(lab.Net.Counters());
    }

    [Fact]
    public async Task NatMappingExpiresSilently_OutboundKeepalivesMintTheNewPath()
    {
        using VirtualLab lab = new();
        VirtualNat listenerNat = lab.Nat(VirtualNatKind.FullCone, "203.0.113.10", "172.31.10.0/24");
        VirtualNat dialerNat = lab.Nat(VirtualNatKind.FullCone, "203.0.113.20", "172.31.20.0/24");
        await using PinholeNode listener = await lab.BindNodeAsync(listenerNat, tweak: o => o with { KeepaliveInterval = TimeSpan.FromMilliseconds(200) });
        await using PinholeNode dialer = await lab.BindNodeAsync(dialerNat, tweak: o => o with { KeepaliveInterval = TimeSpan.FromMilliseconds(200) });

        (PinholeConnection conn, PinholeConnection atListener) = await ConnectAsync(listener, dialer);
        await TestPoll.UntilAsync(Settle, () => conn.Path.Kind == PathKind.Direct);
        await ExchangeAsync(conn, atListener, "before expiry");

        // Every mapping dies with no notification — the DHCP-renew/router-reboot case.
        listenerNat.ExpireMappings();

        // The listener's next outbound keepalive allocates a fresh public port; the dialer
        // adopts the observed source and the path heals without any app involvement.
        await ExchangeEventuallyAsync(conn, atListener, "after expiry", TestBudget.Scenario);
        await ExchangeAsync(atListener, conn, "after expiry, reverse");
        Assert.Equal(PathKind.Direct, conn.Path.Kind);
        Assert.True(listenerNat.ExpiredMappings > 0);
        output.WriteLine(lab.Net.Counters());
    }

    [Fact]
    public async Task V4ToV6Roam_SameConnectionObjectFlowsOnTheNewFamily()
    {
        using VirtualLab lab = new(withV6Stun: true);
        await using PinholeNode a = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.10"), 0));

        // B starts in a second v4 region and, on its first rebind, moves to IPv6 — the
        // hotel-to-mobile-with-v6 story. Every (re)bind attaches at a fresh port.
        int binds = 0;
        PinholeOptions bOptions = lab.BaseOptions(o => o with { ConnectTimeout = TimeSpan.FromSeconds(10) }) with
        {
            UdpSocketFactory = _ => Interlocked.Increment(ref binds) == 1
                ? lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), 31001))
                : lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("2001:db8::20"), 31000 + binds)),
        };
        await using PinholeNode b = await PinholeNode.BindAsync(bOptions);

        (PinholeConnection conn, PinholeConnection atA) = await ConnectAsync(a, b);
        await TestPoll.UntilAsync(Settle, () => conn.Path.Kind == PathKind.Direct);
        await ExchangeAsync(conn, atA, "over IPv4, B -> A");

        // The old v4 region dies, then B rebinds: new socket, new family, same connection.
        lab.Net.AddRule(LinkRule.Blackhole(Subnet.Parse(VirtualLab.Hosts4SecondRegion)));
        await b.Engine.SimulateInterfaceLossAsync().WaitAsync(TestBudget.Io);

        await TestPoll.UntilAsync(TestBudget.Scenario, () => conn.State == PinholeConnectionState.Open
            && conn.Path.Kind == PathKind.Direct);
        await ExchangeAsync(conn, atA, "over IPv6, B -> A");
        await ExchangeAsync(atA, conn, "over IPv6, A -> B");

        // Roaming is invisible to the app: same object, still exactly one connection.
        Assert.Same(conn, b.Connections.Single(c => c.PeerId == a.PeerId));
        Assert.True(binds >= 2, "the rebind asked the factory for a fresh socket");
        output.WriteLine(lab.Net.Counters());
    }

    [Fact]
    public async Task RelayRestart_FreshRedial_SessionsHealViaReallocation()
    {
        // A fixed-port TURN relay so "restart" means the same endpoint comes back. The pair's
        // direct path is blackholed: every session here is relay-carried.
        using var probe = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int relayPort = ((IPEndPoint)probe.Client.LocalEndPoint!).Port;
        probe.Dispose();
        using VirtualLab lab = new(withTurn: true, turnPort: relayPort);
        Subnet aSide = Subnet.Parse("192.0.2.10/32");
        Subnet bSide = Subnet.Parse("192.0.2.20/32");
        lab.Net.AddRule(LinkRule.Directional(aSide, bSide, dropAll: true));
        lab.Net.AddRule(LinkRule.Directional(bSide, aSide, dropAll: true));

        await using PinholeNode a = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.10"), 0));
        await using PinholeNode b = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.20"), 0));

        // The connection STAYS OPEN across the restart: its relay leg going silent is what
        // drives path validation to suspect, which (post-fix) retires the ghost allocation
        // and re-advertises fresh relay candidates. The old relayed endpoint is captured for
        // the comparison.
        (PinholeConnection first, PinholeConnection atA) = await ConnectAsync(a, b);
        Assert.Equal(PathKind.Relay, first.Path.Kind);
        await ExchangeAsync(first, atA, "before the restart");
        IPEndPoint oldRelayed = RelayCandidate(a)!;

        // The relay process dies; a fresh one returns on the same endpoint. Both nodes still
        // hold allocations the successor knows nothing about — ghost clients that would
        // black-hole every relayed frame for a full refresh cycle (~minutes) if nothing
        // retired them.
        lab.Turn!.Dispose();
        using FakeTurnServer successor = RestartTurnOnPort(relayPort);

        await TestPoll.UntilAsync(TestBudget.Scenario, () =>
            RelayCandidate(a) is { } fresh && !fresh.Equals(oldRelayed));

        // The old session closes from the server side — its Bye cannot ride the stale relay
        // path, and a fresh dial must not meet a live session for the same peer. Then the
        // documented re-share flow: redial on the fresh string; the dialer's own ghost gets
        // retired by the failed warm-permit, exactly as on the server side.
        await atA.DisposeAsync();
        await first.DisposeAsync();
        (PinholeConnection second, PinholeConnection atA2) = await ConnectAsync(a, b, a.ConnectionString);
        await TestPoll.UntilAsync(TestBudget.Scenario, () => second.Path.Kind == PathKind.Relay);
        await ExchangeAsync(second, atA2, "after the restart, B -> A");
        await ExchangeAsync(atA2, second, "after the restart, A -> B");
        Assert.True(successor.PermissionsGranted > 0, "the successor actually carried the session");
        output.WriteLine($"redial after relay restart healed in-band — {lab.Net.Counters()}");
    }

    private static IPEndPoint? RelayCandidate(PinholeNode node) =>
        ConnectionString.Parse(node.ConnectionString).Candidates
            .FirstOrDefault(c => c.Kind == CandidateKind.Relay)?.Address;

    [Fact]
    public async Task LostPermitRequest_HealthyAllocationMustNotFlap()
    {
        using VirtualLab lab = new(withTurn: true);
        Subnet aSide = Subnet.Parse("192.0.2.10/32");
        Subnet bSide = Subnet.Parse("192.0.2.20/32");
        lab.Net.AddRule(LinkRule.Directional(aSide, bSide, dropAll: true));
        lab.Net.AddRule(LinkRule.Directional(bSide, aSide, dropAll: true));
        await using PinholeNode a = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.10"), 0));
        await using PinholeNode b = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.20"), 0));
        Assert.Equal(2, lab.Turn!.Allocations); // one allocation per node at bind

        // The dialer's first warm-permit request vanishes — one lost UDP datagram, proving
        // nothing about the allocation. The client must retry the permit and keep the
        // allocation; retiring here (#24's flap scenario) would realloc on every loss.
        lab.Turn.DropNextPermissions = 1;

        (PinholeConnection conn, PinholeConnection atA) = await ConnectAsync(a, b);
        Assert.Equal(PathKind.Relay, conn.Path.Kind);
        await ExchangeAsync(conn, atA, "one lost permit changed nothing");

        Assert.Equal(2, lab.Turn.Allocations); // no retire, no realloc
        Assert.True(lab.Turn.PermissionsGranted > 0, "the retried permit actually landed");
    }

    [Fact]
    public async Task RelayLegValidation_ProbesWithout_CountingAsAppPings()
    {
        using VirtualLab lab = new(withTurn: true);
        Subnet aSide = Subnet.Parse("192.0.2.10/32");
        Subnet bSide = Subnet.Parse("192.0.2.20/32");
        lab.Net.AddRule(LinkRule.Directional(aSide, bSide, dropAll: true));
        lab.Net.AddRule(LinkRule.Directional(bSide, aSide, dropAll: true));
        await using PinholeNode a = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.10"), 0));
        await using PinholeNode b = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.20"), 0));

        (PinholeConnection conn, PinholeConnection atA) = await ConnectAsync(a, b);
        Assert.Equal(PathKind.Relay, conn.Path.Kind);

        // Idle past the relay-leg idle window plus several probe rounds: the transport's
        // own liveness probes fly (and the healthy relay answers, so the session never
        // flaps state) — but none of them may surface as app-requested pings.
        await Task.Delay(TimeSpan.FromSeconds(9));
        Assert.Equal(PinholeConnectionState.Degraded, conn.State);
        Assert.Equal(0L, conn.Stats.PingsSent);
        await ExchangeAsync(conn, atA, "still alive after idle");
    }

    [Fact]
    public async Task RelayOutage_MidTransfer_TheDirectPathCarriesTheSession()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-lab-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            using VirtualLab lab = new(withTurn: true);

            byte[] data = new byte[300_000];
            Random.Shared.NextBytes(data);
            string src = Path.Combine(dir, "outage.bin");
            await File.WriteAllBytesAsync(src, data);
            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions
            {
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("192.0.2.10"), 0)),
                }),
            });

            long quarter = data.Length / 4;
            var restarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var progress = new Progress<BlobProgress>(p =>
            {
                if (p.VerifiedBytes >= quarter)
                {
                    restarted.TrySetResult();
                }
            });

            Task<BlobDownloadResult> download = Task.Run(() => BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
                progress: progress,
                options: new BlobDownloadOptions
                {
                    NodeOptions = lab.BaseOptions(o => o with
                    {
                        UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("192.0.2.20"), 0)),
                    }),
                }));

            Assert.True(await Task.WhenAny(restarted.Task, Task.Delay(TestBudget.Scenario)) == restarted.Task,
                $"transfer never reached {quarter} verified bytes — {lab.Net.Counters()}");
            Assert.Equal(PathKind.Direct, server.Node.Connections.Single().Path.Kind);

            // The relay dies mid-transfer while the direct path is healthy: a non-event for
            // the transfer, and the engine must not flap the session over it.
            lab.Turn!.Dispose();

            BlobDownloadResult result = await download.WaitAsync(TestBudget.Scenario);
            Assert.Equal(data.Length, result.Bytes);
            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(dir, "out", "outage.bin")));
            output.WriteLine($"relay died mid-transfer; direct path carried it — {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static FakeTurnServer RestartTurnOnPort(int port)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                return new FakeTurnServer(port: port);
            }
            catch (SocketException) when (attempt < 20)
            {
                Thread.Sleep(100);
            }
        }
    }

    [Fact]
    public async Task MidTransferRoam_ADirectoryDownloadCompletesOnTheReboundPath()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-lab-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            using VirtualLab lab = new();
            VirtualNat serverNat = lab.Nat(VirtualNatKind.FullCone, "203.0.113.10", "172.31.10.0/24");

            // Three files so the roam lands across a stream transition: the next file's
            // Hello→Welcome handshake must ride out the server's rebind, not die on it.
            string srcDir = Path.Combine(dir, "serve");
            Directory.CreateDirectory(srcDir);
            byte[][] files = [new byte[500_000], new byte[300_000], new byte[300_000]];
            for (int i = 0; i < files.Length; i++)
            {
                Random.Shared.NextBytes(files[i]);
                await File.WriteAllBytesAsync(Path.Combine(srcDir, $"part{i}.bin"), files[i]);
            }

            await using var server = await BlobServer.ServeAsync(srcDir, new BlobServeOptions
            {
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateBehindNat(serverNat),
                }),
            });

            var firstFileDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var progress = new Progress<BlobProgress>(p =>
            {
                if (p.FilesDone >= 1)
                {
                    firstFileDone.TrySetResult();
                }
            });

            Task<BlobDownloadResult> download = Task.Run(() => BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
                progress: progress,
                options: new BlobDownloadOptions
                {
                    NodeOptions = lab.BaseOptions(o => o with
                    {
                        UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("192.0.2.20"), 0)),
                    }),
                }));

            Assert.True(await Task.WhenAny(firstFileDone.Task, Task.Delay(TestBudget.Scenario)) == firstFileDone.Task,
                $"transfer never finished its first file — {lab.Net.Counters()}");

            // The server's interface dies mid-transfer: new socket, new private address, new
            // NAT mapping. In-flight chunks, the next file's Hello→Welcome, and the
            // downloader's ARQ re-requests must all find the rebound path.
            await server.Node.Engine.SimulateInterfaceLossAsync().WaitAsync(TestBudget.Io);

            BlobDownloadResult result = await download.WaitAsync(TestBudget.Scenario);
            Assert.Equal(files.Sum(f => f.Length), result.Bytes);
            for (int i = 0; i < files.Length; i++)
            {
                Assert.Equal(files[i], await File.ReadAllBytesAsync(Path.Combine(dir, "out", "serve", $"part{i}.bin")));
            }

            output.WriteLine(lab.Net.Counters());
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
