using System.Net;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

/// <summary>#31 — logical connections preserved through outages, suspend-like pauses,
/// missing network notifications, and MTU changes. The semantics under test are the
/// documented ones: <see cref="PinholeConnectionState.Dead"/> is an honest "no usable
/// path" the same object can return from; <see cref="PinholeConnectionState.Closed"/> is
/// terminal and only reached by closing; a dial that FAULTED is never revived. Long-outage
/// cells compress the engine's configurable timers below the outage so one real wait
/// exercises the "longer than every retry budget" regime, and PMTU re-verification uses
/// the configurable re-probe interval rather than its five-minute default.</summary>
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
            return false; // pathless pending state: sending is refused until a path returns
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

    /// <summary>Host node with every engine timer small enough that a ~12 s outage exceeds
    /// them all — the compressed stand-in for the issue's long-outage regime.</summary>
    private static Task<PinholeNode> HostAsync(VirtualLab lab, string address) =>
        lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse(address), 0),
            tweak: o => o with
            {
                ConnectTimeout = TimeSpan.FromSeconds(4),
                PathValidationIdle = TimeSpan.FromMilliseconds(400),
                PathValidationProbeInterval = TimeSpan.FromMilliseconds(150),
                StunRefreshInterval = TimeSpan.FromSeconds(2),
            });

    // ------------------------------------------------------------------ the outage ladder

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

        // A one-second blip is under the validation budget: state never left Open and the
        // next datagram flows with no recovery ceremony at all.
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

        // Bounded recovery work while no route exists: the wounded session paces itself at
        // a few datagrams per second — 30 s of silence may not look like a retry storm.
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
        await Task.Delay(TimeSpan.FromSeconds(8)); // comfortably past the 4 s punch budget too

        lab.Net.RemoveRule(cut);
        // Dead is not Closed: the same object returns to authenticated traffic when a route
        // exists again — sealed frames keep their counters and replay window throughout.
        Assert.True(await ExchangeUntilAsync(atB, atA, "revived from Dead", Settle),
            "a Dead connection did not revive when the route returned");
        Assert.Equal(PinholeConnectionState.Open, atB.State);
        _output.WriteLine("long outage: honest Dead, then same-object revival");
    }

    // ------------------------------------------------------------------ suspend-like pause

    [Fact]
    public async Task SuspendLikePause_TimersFireOnce_NoStorm_TrafficReturns()
    {
        using VirtualLab lab = new();
        await using PinholeNode nodeA = await HostAsync(lab, "192.0.2.10");
        await using PinholeNode nodeB = await HostAsync(lab, "192.0.2.20");
        (PinholeConnection atB, PinholeConnection atA) = await ConnectAsync(nodeA, nodeB);
        Assert.True(await ExchangeUntilAsync(atB, atA, "before the pause", Settle));
        long probesBefore = atB.PathProbesSent;

        // A suspend-like pause: total silence in both directions, long enough that every
        // absolute-deadline timer (validation, refresh) is far past due when traffic
        // returns. The engine uses one scheduler with absolute deadlines, so waking runs
        // each chore once — never a replayed backlog of timers.
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

    // ------------------------------------------------------------------ notifications absent

    [Fact]
    public async Task NoNetworkWatch_TotalStunSilence_TriggersTheBoundedRevalidation()
    {
        using VirtualLab lab = new();
        await using PinholeNode nodeA = await HostAsync(lab, "192.0.2.10");
        await using PinholeNode nodeB = await HostAsync(lab, "192.0.2.20");
        (PinholeConnection atB, PinholeConnection atA) = await ConnectAsync(nodeA, nodeB);
        Assert.True(await ExchangeUntilAsync(atB, atA, "before", Settle));
        int portBefore = nodeA.LocalPort;

        // EnableNetworkWatch is false everywhere in the lab: the platform notification will
        // never fire. Cut node A's visibility of BOTH configured STUN servers: the periodic
        // refresh then observes total silence where it used to see answers, and that
        // transition must itself drive recovery — the bounded periodic revalidation for
        // platforms whose notifications are absent or delayed.
        LinkRule cutStun1 = LinkRule.Blackhole(Subnet.Parse("192.0.2.53/32"));
        LinkRule cutStun2 = LinkRule.Blackhole(Subnet.Parse("192.0.2.54/32"));
        lab.Net.AddRule(cutStun1);
        lab.Net.AddRule(cutStun2);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(20), () => nodeA.LocalPort != portBefore);

        // The session survives the notificationless rebind: the rebind re-announces, and
        // the wounded/dead sides keep bounded beacons until the peer's observed-source
        // replies revive the path. Then visibility returns and the node is fully itself.
        // Session survival across a rebind is RoamingTests' proven claim; here the subject
        // is the trigger itself. (A both-sides-Dead rebind with STUN-dark reflexives is a
        // known lab gap: beacons flow but PACK replies do not return — see TESTING.md.)
        lab.Net.RemoveRule(cutStun1);
        lab.Net.RemoveRule(cutStun2);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(15), () => nodeA.PublicEndpoints.Count > 0);
        _output.WriteLine($"STUN silence triggered rebind {portBefore} -> {nodeA.LocalPort} with the session intact");
    }

    // ------------------------------------------------------------------ MTU changes

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
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(30), () => atB.PathMtu > floor); // the climb confirmed something

        // A VPN/tunnel engages: everything above 1300 wire bytes now dies in the network,
        // while small validation probes keep passing — the classic silent shrink.
        nodeA.Engine.Lookup(nodeB.PeerId)!.DropAboveBytes = 1300;
        nodeB.Engine.Lookup(nodeA.PeerId)!.DropAboveBytes = 1300;

        // The confirmed size re-verifies, fails its probe cycle, and falls back to the
        // guaranteed floor — after which traffic sized to the floor flows again.
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
            // Distinct explicit ports: a 0 port would leave the virtual socket's
            // LocalEndPoint unusable for the port-change assertion.
            UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse(address), System.Threading.Interlocked.Increment(ref nextPort))),
            PmtuReprobeInterval = TimeSpan.FromSeconds(1),
        });

        await using PinholeNode nodeA = await PinholeNode.BindAsync(HostOptions("198.51.100.10"));
        await using PinholeNode nodeB = await PinholeNode.BindAsync(HostOptions("198.51.100.20"));
        (PinholeConnection atB, PinholeConnection atA) = await ConnectAsync(nodeA, nodeB);
        Assert.True(await ExchangeUntilAsync(atB, atA, "before the migration", Settle));
        int floor = NodeEngine.PmtuBaseWire;
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(20), () => atB.PathMtu > floor);

        // Migrate B: a forced rebind gives it a fresh port, so the direct endpoint changes —
        // a path migration. The confirmed MTU belonged to the old endpoint and must be
        // forgotten, then re-earned on the new path.
        // Capture the reset at the Open transition: the engine invokes it under the
        // connection lock, before a PMTU reply can raise the floor again. Polling for the
        // transient floor after awaiting the rebind can miss it on a busy CI runner.
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

    // ------------------------------------------------------------------ terminal semantics

    [Fact]
    public async Task FaultedDial_IsNeverZombieRevived()
    {
        using VirtualLab lab = new();
        await using PinholeNode victim = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.10"), 0));
        await using PinholeNode dialer = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("192.0.2.20"), 0));

        // A ticket that pins SOMEONE ELSE's static key: the victim's honest handshake is
        // refused by the pin, the dial faults, and the husk must stay dead no matter how
        // much valid-looking traffic the victim keeps sending afterward.
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
        _ = nodeB.RoamNowAsync(); // recovery in flight...
        nodeB.Dispose();          // ...and the user disposes anyway

        lab.Net.RemoveRule(cut);
        // The route is back, but the disposed node answers nothing, forever: its peer's
        // connection must NOT come back to life, and the only remaining traffic is the
        // survivor's own bounded recovery pace (a few datagrams per second).
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
