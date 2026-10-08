using System.Diagnostics;
using System.Net;
using System.Text;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Issue #12: a silently dead direct path (NAT expiry, firewall, dropped packets —
/// no send error, no notification) must be detected by the engine itself and handled with
/// the existing machinery: relay fallback, honest death, upgrade-back. Thresholds are
/// injected small so the suite never sleeps real seconds. Relay traffic never certifies a
/// direct path, one lost probe never degrades a live one, and monitoring counters stay
/// separate from caller Ping/RTT stats.</summary>
public sealed class PathValidationTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    // Detection budget ≈ idle + maxUnanswered × interval ≈ 0.7 s in these tests.
    private static readonly TimeSpan Idle = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan Interval = TimeSpan.FromMilliseconds(150);

    private static PinholeOptions Opts(bool validation = true, FakeIrohRelay? server = null,
        TimeSpan? connectTimeout = null, TimeSpan? idle = null) => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = server is null ? [] : [server.Url],
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false, EnablePortMapping = false,
        EnablePathValidation = validation,
        PathValidationIdle = idle ?? Idle,
        PathValidationProbeInterval = Interval,
        PathValidationMaxUnansweredProbes = 3,
        ConnectTimeout = connectTimeout ?? TimeSpan.FromSeconds(8),
    };

    private static async Task<(PinholeConnection AtDialer, PinholeConnection AtListener)> ConnectPairAsync(
        PinholeNode listener, PinholeNode dialer)
    {
        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection dialerSide = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        PinholeConnection listenerSide = await accept.WaitAsync(Timeout);
        return (dialerSide, listenerSide);
    }

    private static async Task AssertExchangeAsync(PinholeConnection from, PinholeConnection to, string marker)
    {
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Handler(ReadOnlySpan<byte> body) => got.TrySetResult(body.ToArray());
        to.Received += Handler;
        try
        {
            var sw = Stopwatch.StartNew();
            while (!got.Task.IsCompleted && sw.Elapsed < Timeout)
            {
                from.Send(Encoding.UTF8.GetBytes(marker)); // unreliable: retransmit until heard
                await Task.Delay(50);
            }

            Assert.Equal(marker, Encoding.UTF8.GetString(await got.Task.WaitAsync(TimeSpan.FromSeconds(1))));
        }
        finally
        {
            to.Received -= Handler;
        }
    }

    [Fact]
    public async Task SilentDirectLoss_WithRelay_FallsBackWithoutAnyoneNotifying()
    {
        await using var server = new FakeIrohRelay();
        await using var a = await PinholeNode.BindAsync(Opts(server: server));
        await using var b = await PinholeNode.BindAsync(Opts(server: server));
        (PinholeConnection atB, PinholeConnection atA) = await ConnectPairAsync(a, b);
        await TestPoll.UntilAsync(Timeout, () => a.Engine.Lookup(b.PeerId)?.IrohConfirmed == true
            && b.Engine.Lookup(a.PeerId)?.IrohConfirmed == true);
        Assert.Equal(PinholeConnectionState.Open, atB.State);

        // The fault injector only drops packets — no NotifyPathSuspect, no send errors.
        // The engine has to notice on its own within the detection budget.
        a.Engine.SimulateSilentDirectPathLoss(b.PeerId);
        b.Engine.SimulateSilentDirectPathLoss(a.PeerId);

        await TestPoll.UntilAsync(Timeout, () => atA.State == PinholeConnectionState.Degraded
            && atB.State == PinholeConnectionState.Degraded);
        Assert.Equal(PathKind.Relay, atA.Path.Kind);
        Assert.Same(atA, a.Connections.Single());
        Assert.False(atA.Closed.IsCompleted);
        await AssertExchangeAsync(atA, atB, "detected silently, flowing on relay");

        // Relay traffic keeps flowing but never falsely certifies the dead direct path.
        Assert.Equal(PinholeConnectionState.Degraded, atA.State);
        Assert.Equal(PathKind.Relay, atA.Path.Kind);
    }

    [Fact]
    public async Task RestoredUdp_UpgradesTheSameConnectionBackToDirect()
    {
        await using var server = new FakeIrohRelay();
        // Bind to loopback so alternate NIC addresses cannot accidentally reopen the
        // session and hide a failure to promote its ORIGINAL direct address.
        var options = Opts(server: server) with { Bind = new IPEndPoint(IPAddress.Loopback, 0) };
        await using var a = await PinholeNode.BindAsync(options);
        await using var b = await PinholeNode.BindAsync(options);
        (PinholeConnection atB, PinholeConnection atA) = await ConnectPairAsync(a, b);
        // The initial race can establish a relay session first. This scenario restores
        // the original UDP path, so record it only after BOTH sides actually select it.
        IPEndPoint? originalA = null, originalB = null;
        await TestPoll.UntilAsync(Timeout, () =>
        {
            PinholePath pathA = atA.Path, pathB = atB.Path;
            if (atA.State != PinholeConnectionState.Open || atB.State != PinholeConnectionState.Open
                || pathA.Kind != PathKind.Direct || pathB.Kind != PathKind.Direct || pathA.Remote is null || pathB.Remote is null) return false;
            originalA = pathA.Remote;
            originalB = pathB.Remote;
            return true;
        });
        await TestPoll.UntilAsync(Timeout, () => a.Engine.Lookup(b.PeerId)?.IrohConfirmed == true
            && b.Engine.Lookup(a.PeerId)?.IrohConfirmed == true);

        a.Engine.SimulateSilentDirectPathLoss(b.PeerId);
        b.Engine.SimulateSilentDirectPathLoss(a.PeerId);
        await TestPoll.UntilAsync(Timeout, () => atA.State == PinholeConnectionState.Degraded
            && atB.State == PinholeConnectionState.Degraded);

        // The NAT rebind recovers: UDP works again, and the engine's own probing upgrades.
        a.Engine.SimulateDirectPathRestore(b.PeerId);
        b.Engine.SimulateDirectPathRestore(a.PeerId);
        await TestPoll.UntilAsync(Timeout, () => atA.State == PinholeConnectionState.Open
            && atB.State == PinholeConnectionState.Open);
        Assert.Equal(PathKind.Direct, atA.Path.Kind);
        Assert.Equal(originalA, a.Engine.Lookup(b.PeerId)!.DirectRemoteEp);
        Assert.Equal(originalB, b.Engine.Lookup(a.PeerId)!.DirectRemoteEp);
        Assert.Same(atA, a.Connections.Single());
        await AssertExchangeAsync(atB, atA, "back on direct, same object");
    }

    [Fact]
    public async Task SilentLoss_WithoutRelay_IsHonestlyDead_AndComesBack()
    {
        await using var a = await PinholeNode.BindAsync(Opts(connectTimeout: TimeSpan.FromSeconds(1)));
        await using var b = await PinholeNode.BindAsync(Opts(connectTimeout: TimeSpan.FromSeconds(1)));
        (PinholeConnection atB, PinholeConnection atA) = await ConnectPairAsync(a, b);
        Assert.Equal(PinholeConnectionState.Open, atB.State);

        a.Engine.SimulateSilentDirectPathLoss(b.PeerId);
        b.Engine.SimulateSilentDirectPathLoss(a.PeerId);

        // No fallback exists: bounded re-punch, then an honest Dead — never a fake Open.
        await TestPoll.UntilAsync(Timeout, () => atA.State == PinholeConnectionState.Dead
            && atB.State == PinholeConnectionState.Dead);
        Assert.False(atA.Closed.IsCompleted, "Dead is not Closed; the object survives");

        // The network heals; the connection comes back on its own kick.
        a.Engine.SimulateDirectPathRestore(b.PeerId);
        b.Engine.SimulateDirectPathRestore(a.PeerId);
        a.Engine.RetryPunch(b.PeerId);
        await TestPoll.UntilAsync(Timeout, () => atA.State == PinholeConnectionState.Open
            && atB.State == PinholeConnectionState.Open);
        await AssertExchangeAsync(atB, atA, "resurrected after honest death");
    }

    [Fact]
    public async Task HealthyDirectTraffic_ProducesNoProbes_AndStaysOpen()
    {
        // A wider idle window than the file default: the flood paces at ~20 ms and a single
        // scheduler stall on a loaded CI runner must not read as a dead path.
        await using var a = await PinholeNode.BindAsync(Opts(idle: TimeSpan.FromMilliseconds(500)));
        await using var b = await PinholeNode.BindAsync(Opts(idle: TimeSpan.FromMilliseconds(500)));
        (PinholeConnection atB, PinholeConnection atA) = await ConnectPairAsync(a, b);

        // One-way flood for far longer than the idle window: the RECEIVER hears constant
        // direct traffic and must never probe; the SENDER hears nothing, so its probes run —
        // and are answered, which is exactly a healthy one-way stream staying Open.
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < TimeSpan.FromMilliseconds(2000))
        {
            atB.Send("streaming"u8);
            await Task.Delay(20);
        }

        Assert.Equal(0, atA.PathProbesSent);
        Assert.Equal(PinholeConnectionState.Open, atA.State);
        Assert.True(atB.PathProbesSent > 0, "the silent-receiver side probes, as designed");
        Assert.True(atB.PathProbeReplies > 0, "its probes are answered on the live path");
        Assert.Equal(PinholeConnectionState.Open, atB.State);
        Assert.Equal(0, atB.Stats.PingsSent); // monitoring counters stay out of caller stats
    }

    [Fact]
    public async Task TransientLoss_BelowTheUnansweredBudget_DoesNotDegrade()
    {
        using var net = new VirtualNetwork();
        var socketA = new DropProbeSocket(net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 31010)));
        var socketB = new DropProbeSocket(net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), 31020)));
        // No caller pings, PMTU probes, or keepalive traffic: every Ping below is an
        // actual liveness probe. Drop one per sender, independent of runner scheduling.
        var options = Opts() with { EnablePmtud = false, KeepaliveInterval = TimeSpan.Zero };
        await using var a = await PinholeNode.BindAsync(options with { UdpSocketFactory = _ => socketA });
        await using var b = await PinholeNode.BindAsync(options with { UdpSocketFactory = _ => socketB });
        Task<PinholeConnection> accept = a.AcceptAsync();
        string ticket = new ConnectionString(a.PeerId,
            [new PinholeCandidate(CandidateKind.Direct, socketA.LocalEndPoint)], staticKey: a.StaticPublicKey).ToString();
        using PinholeConnection atB = await b.ConnectAsync(ticket).WaitAsync(Timeout);
        using PinholeConnection atA = await accept.WaitAsync(Timeout);

        int disturbed = 0;
        atA.StateChanged += s => { if (s is not PinholeConnectionState.Open) Interlocked.Increment(ref disturbed); };
        atB.StateChanged += s => { if (s is not PinholeConnectionState.Open) Interlocked.Increment(ref disturbed); };

        long repliesBefore = atA.PathProbeReplies + atB.PathProbeReplies;
        socketA.Arm();
        socketB.Arm();
        await TestPoll.UntilAsync(Timeout, () => socketA.Dropped + socketB.Dropped > 0
            && atA.PathProbeReplies + atB.PathProbeReplies > repliesBefore);
        Assert.InRange(socketA.Dropped + socketB.Dropped, 1, 2);
        Assert.Equal(0, disturbed);
        Assert.Equal(PinholeConnectionState.Open, atA.State);
        Assert.Equal(PinholeConnectionState.Open, atB.State);
        Assert.True(atA.PathProbeReplies + atB.PathProbeReplies > repliesBefore,
            "a real lost probe was followed by an authenticated probe reply");
    }

    [Fact]
    public async Task ValidationDisabled_IdleSilentConnection_StaysOpen()
    {
        await using var a = await PinholeNode.BindAsync(Opts(validation: false));
        await using var b = await PinholeNode.BindAsync(Opts(validation: false));
        (PinholeConnection atB, PinholeConnection atA) = await ConnectPairAsync(a, b);

        a.Engine.SimulateSilentDirectPathLoss(b.PeerId);
        b.Engine.SimulateSilentDirectPathLoss(a.PeerId);
        await Task.Delay(TimeSpan.FromMilliseconds(900));

        Assert.Equal(PinholeConnectionState.Open, atA.State); // opted out: nobody probes
        Assert.Equal(0, atA.PathProbesSent);
    }

    [Fact]
    public async Task Disposal_StopsTheMonitor()
    {
        await using var a = await PinholeNode.BindAsync(Opts());
        await using var b = await PinholeNode.BindAsync(Opts());
        (PinholeConnection _, PinholeConnection atA) = await ConnectPairAsync(a, b);

        // A alone goes deaf: its probes run (and the peer's answers are dropped by the
        // blackhole), so the counter climbs — until the node is disposed.
        a.Engine.SimulateSilentDirectPathLoss(b.PeerId);
        await TestPoll.UntilAsync(Timeout, () => atA.PathProbesSent > 0);
        a.Dispose();
        long sent = atA.PathProbesSent;
        await Task.Delay(TimeSpan.FromMilliseconds(500));
        Assert.Equal(sent, atA.PathProbesSent); // the scheduler died with the node
    }

    private sealed class DropProbeSocket(IUdpSocket inner) : IUdpSocket
    {
        private int _armed;
        private int _dropped;
        public int Dropped => Volatile.Read(ref _dropped);
        public IPEndPoint LocalEndPoint => inner.LocalEndPoint;
        public void Arm() => Volatile.Write(ref _armed, 1);
        public int ReceiveFrom(Span<byte> buffer, SocketAddress from) => inner.ReceiveFrom(buffer, from);
        public void SendTo(ReadOnlySpan<byte> frame, SocketAddress to)
        {
            if (!frame.IsEmpty && frame[0] == (byte)FrameType.Ping
                && Interlocked.CompareExchange(ref _armed, 0, 1) == 1)
            {
                Interlocked.Increment(ref _dropped);
                return;
            }
            inner.SendTo(frame, to);
        }
        public void Dispose() => inner.Dispose();
    }
}
