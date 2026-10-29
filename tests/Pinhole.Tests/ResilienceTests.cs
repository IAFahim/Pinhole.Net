using System.Net;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Xunit.Abstractions;
using Pinhole.Sim;

namespace Pinhole.Tests;

public sealed class ResilienceTests
{
    private readonly ITestOutputHelper _output;
    private static readonly TimeSpan Settle = TimeSpan.FromSeconds(15);

    public ResilienceTests(ITestOutputHelper output) => _output = output;

    private static async Task<(PinholeConnection DialerSide, PinholeConnection ListenerSide)> ConnectAsync(
        PinholeNode listener, PinholeNode dialer)
    {
        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection dialerSide = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(TestBudget.Handshake);
        PinholeConnection listenerSide = await accept.WaitAsync(TestBudget.Handshake);
        return (dialerSide, listenerSide);
    }

    private static async Task<bool> TryExchangeAsync(PinholeConnection from, PinholeConnection to, string marker)
    {
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Handler(ReadOnlySpan<byte> payload) => got.TrySetResult(payload.ToArray());
        to.Received += Handler;
        try
        {
            from.Send(Encoding.UTF8.GetBytes(marker));
            var done = await Task.WhenAny(got.Task, Task.Delay(TimeSpan.FromSeconds(3)));
            return done == got.Task && Encoding.UTF8.GetString(got.Task.Result) == marker;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        finally
        {
            to.Received -= Handler;
        }
    }

    private static async Task<bool> ExchangeUntilAsync(PinholeConnection from, PinholeConnection to, string marker, TimeSpan budget)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < budget)
        {
            if (await TryExchangeAsync(from, to, marker))
            {
                return true;
            }

            await Task.Delay(300);
        }

        return false;
    }

    private static Task<PinholeNode> HostAsync(VirtualLab lab, string address) =>
        lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse(address), 0),
            tweak: o => o with
            {
                ConnectTimeout = TimeSpan.FromSeconds(4),
                PathValidationIdle = TimeSpan.FromMilliseconds(400),
                PathValidationProbeInterval = TimeSpan.FromMilliseconds(150),
                StunRefreshInterval = TimeSpan.FromSeconds(2),
            });

    [Fact]
    public async Task BriefOutage_1s_ConnectionNeverEvenNotices()
    {
        using VirtualLab lab = new();
        await using PinholeNode nodeA = await HostAsync(lab, "192.0.2.10");
        await using PinholeNode nodeB = await HostAsync(lab, "192.0.2.20");
        (PinholeConnection atB, PinholeConnection atA) = await ConnectAsync(nodeA, nodeB);
        Assert.True(await ExchangeUntilAsync(atB, atA, "before the blip", Settle));

        LinkRule cut = LinkRule.Blackhole(Subnet.Parse("192.0.2.10/32"));
        lab.Net.AddRule(cut);
        await Task.Delay(TimeSpan.FromSeconds(1));
        lab.Net.RemoveRule(cut);

        Assert.Equal(PinholeConnectionState.Open, atB.State);
        Assert.True(await TryExchangeAsync(atB, atA, "after the blip"));
        _output.WriteLine("1 s outage: never left Open");
    }

    [Fact]
    public async Task Outage30s_SessionWoundsHonestly_HealsSameObject_NoStorm()
    {
        using VirtualLab lab = new();
        await using PinholeNode nodeA = await HostAsync(lab, "192.0.2.10");
        await using PinholeNode nodeB = await HostAsync(lab, "192.0.2.20");
        (PinholeConnection atB, PinholeConnection atA) = await ConnectAsync(nodeA, nodeB);
        Assert.True(await ExchangeUntilAsync(atB, atA, "before the outage", Settle));

        LinkRule cut = LinkRule.Blackhole(Subnet.Parse("192.0.2.10/32"));
        lab.Net.AddRule(cut);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(15),
            () => atB.State is PinholeConnectionState.Punching or PinholeConnectionState.Dead);
        long baseline = lab.Net.Delivered + lab.Net.Unroutable;
        await Task.Delay(TimeSpan.FromSeconds(30));
        long spent = lab.Net.Delivered + lab.Net.Unroutable - baseline;

        Assert.True(spent < 30 * 40, $"recovery burned {spent} datagrams during the outage");

        lab.Net.RemoveRule(cut);
        Assert.True(await ExchangeUntilAsync(atB, atA, "after 30 s of silence", Settle),
            "the same connection object did not come back after the route returned");
        Assert.Equal(PinholeConnectionState.Open, atB.State);
        _output.WriteLine($"30 s outage healed; {spent} datagrams spent wounded");
    }

    [Fact]
    public async Task OutageLongerThanEveryBudget_DeadIsHonest_AndRevives()
    {
        using VirtualLab lab = new();
        await using PinholeNode nodeA = await HostAsync(lab, "192.0.2.10");
        await using PinholeNode nodeB = await HostAsync(lab, "192.0.2.20");
        (PinholeConnection atB, PinholeConnection atA) = await ConnectAsync(nodeA, nodeB);
        Assert.True(await ExchangeUntilAsync(atB, atA, "before", Settle));

        LinkRule cut = LinkRule.Blackhole(Subnet.Parse("192.0.2.10/32"));
        lab.Net.AddRule(cut);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(15), () => atB.State == PinholeConnectionState.Dead);
        await Task.Delay(TimeSpan.FromSeconds(8));

        lab.Net.RemoveRule(cut);

        Assert.True(await ExchangeUntilAsync(atB, atA, "revived from Dead", Settle),
            "a Dead connection did not revive when the route returned");
        Assert.Equal(PinholeConnectionState.Open, atB.State);
        _output.WriteLine("long outage: honest Dead, then same-object revival");
    }

    [Fact]
    public async Task SuspendLikePause_TimersFireOnce_NoStorm_TrafficReturns()
    {
        using VirtualLab lab = new();
        await using PinholeNode nodeA = await HostAsync(lab, "192.0.2.10");
        await using PinholeNode nodeB = await HostAsync(lab, "192.0.2.20");
        (PinholeConnection atB, PinholeConnection atA) = await ConnectAsync(nodeA, nodeB);
        Assert.True(await ExchangeUntilAsync(atB, atA, "before the pause", Settle));
        long probesBefore = atB.PathProbesSent;

        LinkRule cut = LinkRule.Blackhole(Subnet.Parse("192.0.2.10/32"));
        lab.Net.AddRule(cut);
        await Task.Delay(TimeSpan.FromSeconds(12));
        lab.Net.RemoveRule(cut);

        Assert.True(await ExchangeUntilAsync(atB, atA, "after the pause", Settle));
        long baseline = lab.Net.Delivered;
        await Task.Delay(TimeSpan.FromSeconds(2));
        long idleSends = lab.Net.Delivered - baseline;
        Assert.True(idleSends < 120, $"{idleSends} datagrams in 2 s of idle — timer storm");
        Assert.True(atB.PathProbesSent - probesBefore < 200, "probe storm after the pause");
        _output.WriteLine($"pause survived; {idleSends} idle datagrams in the 2 s after recovery");
    }

    [Fact]
    public async Task NoNetworkWatch_TotalStunSilence_TriggersTheBoundedRevalidation()
    {
        using VirtualLab lab = new();
        await using PinholeNode nodeA = await HostAsync(lab, "192.0.2.10");
        await using PinholeNode nodeB = await HostAsync(lab, "192.0.2.20");
        (PinholeConnection atB, PinholeConnection atA) = await ConnectAsync(nodeA, nodeB);
        Assert.True(await ExchangeUntilAsync(atB, atA, "before", Settle));
        int portBefore = nodeA.LocalPort;

        LinkRule cutStun1 = LinkRule.Blackhole(Subnet.Parse("192.0.2.53/32"));
        LinkRule cutStun2 = LinkRule.Blackhole(Subnet.Parse("192.0.2.54/32"));
        lab.Net.AddRule(cutStun1);
        lab.Net.AddRule(cutStun2);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(20), () => nodeA.LocalPort != portBefore);

        lab.Net.RemoveRule(cutStun1);
        lab.Net.RemoveRule(cutStun2);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(15), () => nodeA.PublicEndpoints.Count > 0);
        _output.WriteLine($"STUN silence triggered rebind {portBefore} -> {nodeA.LocalPort} with the session intact");
    }

    [Fact]
    public async Task MtuShrankMidFlow_ReverificationFallsBackToTheFloor()
    {
        using VirtualLab lab = new();
        await using PinholeNode nodeA = await lab.BindNodeAsync(
            hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.10"), 0),
            tweak: o => o with { PmtuReprobeInterval = TimeSpan.FromSeconds(1) });
        await using PinholeNode nodeB = await lab.BindNodeAsync(
            hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.20"), 0),
            tweak: o => o with { PmtuReprobeInterval = TimeSpan.FromSeconds(1) });
        (PinholeConnection atB, PinholeConnection atA) = await ConnectAsync(nodeA, nodeB);
        Assert.True(await ExchangeUntilAsync(atB, atA, "before the tunnel", Settle));

        int floor = NodeEngine.PmtuBaseWire;
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(30), () => atB.PathMtu > floor);

        nodeA.Engine.Lookup(nodeB.PeerId)!.DropAboveBytes = 1300;
        nodeB.Engine.Lookup(nodeA.PeerId)!.DropAboveBytes = 1300;

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(30), () => atB.PathMtu == floor);
        Assert.True(await ExchangeUntilAsync(atB, atA, "over the tunnel", Settle));
        _output.WriteLine($"MTU shrank mid-flow; fell back to the {floor}-byte floor and kept flowing");
    }

    [Fact]
    public async Task MtuClimbResetsOnPathMigration()
    {
        using VirtualLab lab = new();
        int nextPort = 32000;
        PinholeOptions HostOptions(string address) => lab.BaseOptions(o => o with
        {

            UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse(address), System.Threading.Interlocked.Increment(ref nextPort))),
            PmtuReprobeInterval = TimeSpan.FromSeconds(1),
        });

        await using PinholeNode nodeA = await PinholeNode.BindAsync(HostOptions("198.51.100.10"));
        await using PinholeNode nodeB = await PinholeNode.BindAsync(HostOptions("198.51.100.20"));
        (PinholeConnection atB, PinholeConnection atA) = await ConnectAsync(nodeA, nodeB);
        Assert.True(await ExchangeUntilAsync(atB, atA, "before the migration", Settle));
        int floor = NodeEngine.PmtuBaseWire;
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(20), () => atB.PathMtu > floor);

        var reopenedMtu = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        void ObserveReopen(PinholeConnectionState state)
        {
            if (state == PinholeConnectionState.Open) reopenedMtu.TrySetResult(atB.PathMtu);
        }
        atB.StateChanged += ObserveReopen;
        int oldPort = nodeB.LocalPort;
        try
        {
            await nodeB.Engine.SimulateInterfaceLossAsync();
            Assert.NotEqual(oldPort, nodeB.LocalPort);
            Assert.Equal(floor, await reopenedMtu.Task.WaitAsync(TimeSpan.FromSeconds(20)));
            await TestPoll.UntilAsync(TimeSpan.FromSeconds(30), () => atB.PathMtu > floor);
            Assert.True(await ExchangeUntilAsync(atB, atA, "after the migration", Settle));
            _output.WriteLine($"migration reset the climb ({oldPort} -> {nodeB.LocalPort}) and re-climbed");
        }
        finally
        {
            atB.StateChanged -= ObserveReopen;
        }
    }

    [Fact]
    public async Task FaultedDial_IsNeverZombieRevived()
    {
        using VirtualLab lab = new();
        await using PinholeNode victim = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.10"), 0));
        await using PinholeNode dialer = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.20"), 0));

        ConnectionString honest = Pinhole.ConnectionString.Parse(victim.ConnectionString);
        string poisoned = new ConnectionString(honest.PeerId, honest.Candidates, honest.NatHint,
            staticKey: RandomNumberGenerator.GetBytes(32)).ToString();
        await Assert.ThrowsAnyAsync<Exception>(() => dialer.ConnectAsync(poisoned));
        await Task.Delay(TimeSpan.FromSeconds(3));

        PinholeConnection? husk = dialer.Connections.FirstOrDefault(c => c.PeerId == honest.PeerId);
        Assert.True(husk is null || husk.State is PinholeConnectionState.Dead or PinholeConnectionState.Closed,
            $"a faulted dial was revived to {husk?.State}");
    }

    [Fact]
    public async Task DisposeDuringRecovery_WinsOverRecovery()
    {
        using VirtualLab lab = new();
        await using PinholeNode nodeA = await HostAsync(lab, "192.0.2.10");
        PinholeNode nodeB = await HostAsync(lab, "192.0.2.20");
        (PinholeConnection atB, PinholeConnection atA) = await ConnectAsync(nodeA, nodeB);
        Assert.True(await ExchangeUntilAsync(atB, atA, "before", Settle));

        LinkRule cut = LinkRule.Blackhole(Subnet.Parse("192.0.2.10/32"));
        lab.Net.AddRule(cut);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(10),
            () => atB.State is PinholeConnectionState.Punching or PinholeConnectionState.Dead);
        _ = nodeB.RoamNowAsync();
        nodeB.Dispose();

        lab.Net.RemoveRule(cut);

        await Task.Delay(TimeSpan.FromSeconds(3));
        Assert.False(atA.State == PinholeConnectionState.Open,
            "a disposed peer's connection came back to life");
        Assert.Empty(nodeB.Connections);
        long baseline = lab.Net.Delivered + lab.Net.Unroutable;
        await Task.Delay(TimeSpan.FromSeconds(2));
        long idle = lab.Net.Delivered + lab.Net.Unroutable - baseline;
        Assert.True(idle < 100, $"{idle} datagrams after disposal — recovery outlived it");
        _output.WriteLine($"dispose during recovery won; survivor idles at {idle / 2.0:F0}/s");
    }
}
