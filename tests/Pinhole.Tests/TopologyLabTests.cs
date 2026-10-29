using System.Net;
using System.Net.Sockets;
using System.Text;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;
using Pinhole.Sim;

namespace Pinhole.Tests;

public sealed class TopologyLabTests(ITestOutputHelper output)
{
    private static readonly TimeSpan Settle = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan Quiet = TimeSpan.FromSeconds(6);

    public static IEnumerable<object[]> NatPairings() =>
        from listener in new[] { VirtualNatKind.FullCone, VirtualNatKind.RestrictedCone, VirtualNatKind.PortRestricted, VirtualNatKind.Symmetric }
        from dialer in new[] { VirtualNatKind.FullCone, VirtualNatKind.RestrictedCone, VirtualNatKind.PortRestricted, VirtualNatKind.Symmetric }
        select new object[] { listener, dialer };

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

            }
            finally
            {
                to.Received -= Handler;
            }
        }

        Assert.Fail($"no exchange within {budget}");
    }

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

            Assert.Equal(PathKind.Relay, conn.Path.Kind);
            await Task.Delay(Quiet);
            Assert.Equal(PathKind.Relay, conn.Path.Kind);
            await ExchangeEventuallyAsync(conn, atListener, "relay-only pair still flowing", TestBudget.Scenario);
        }

        Assert.True(listenerNat.MappingsCreated > 0, $"listener NAT translated nothing — {lab.Net.Counters()}");
        Assert.True(dialerNat.MappingsCreated > 0, $"dialer NAT translated nothing — {lab.Net.Counters()}");
        output.WriteLine($"L{listenerKind} x D{dialerKind} -> {conn.Path.Kind} | {lab.Net.Counters()}");
    }

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

        listenerNat.ExpireMappings();

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

        lab.Net.AddRule(LinkRule.Blackhole(Subnet.Parse(VirtualLab.Hosts4SecondRegion)));
        await b.Engine.SimulateInterfaceLossAsync().WaitAsync(TestBudget.Io);

        await TestPoll.UntilAsync(TestBudget.Scenario, () => conn.State == PinholeConnectionState.Open
            && conn.Path.Kind == PathKind.Direct);
        await ExchangeAsync(conn, atA, "over IPv6, B -> A");
        await ExchangeAsync(atA, conn, "over IPv6, A -> B");

        Assert.Same(conn, b.Connections.Single(c => c.PeerId == a.PeerId));
        Assert.True(binds >= 2, "the rebind asked the factory for a fresh socket");
        output.WriteLine(lab.Net.Counters());
    }

    [Fact]
    public async Task RelayRestart_FreshRedial_SessionsHealViaReallocation()
    {

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

        (PinholeConnection first, PinholeConnection atA) = await ConnectAsync(a, b);
        Assert.Equal(PathKind.Relay, first.Path.Kind);
        await ExchangeAsync(first, atA, "before the restart");
        IPEndPoint oldRelayed = RelayCandidate(a)!;

        lab.Turn!.Dispose();
        using FakeTurnServer successor = RestartTurnOnPort(relayPort, lab.TurnAddress(0));

        await TestPoll.UntilAsync(TestBudget.Scenario, () =>
            RelayCandidate(a) is { } fresh && !fresh.Equals(oldRelayed));

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
        Assert.Equal(2, lab.Turn!.Allocations);

        lab.Turn.DropNextPermissions = 1;

        (PinholeConnection conn, PinholeConnection atA) = await ConnectAsync(a, b);
        Assert.Equal(PathKind.Relay, conn.Path.Kind);
        await ExchangeAsync(conn, atA, "one lost permit changed nothing");

        Assert.Equal(2, lab.Turn.Allocations);
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

    private static FakeTurnServer RestartTurnOnPort(int port, IPAddress address)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                return new FakeTurnServer(port: port, bindAddress: address);
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
