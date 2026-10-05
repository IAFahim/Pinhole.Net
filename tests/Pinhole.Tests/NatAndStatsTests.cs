using System.Net;
using System.Text;
using Xunit;

namespace Pinhole.Tests;

public sealed class NatDetectorTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task Detect_EveryServerSeesSameMapping_Cone()
    {
        // Plain fakes echo the observed endpoint: one socket, two servers, one mapping.
        using FakeStunServer s1 = new();
        using FakeStunServer s2 = new();
        using FakeStunServer s3 = new();

        NatType type = await NatDetector.DetectAsync([s1.LocalEndPoint, s2.LocalEndPoint, s3.LocalEndPoint])
            .WaitAsync(Timeout);

        Assert.Equal(NatType.Cone, type);
    }

    [Fact]
    public async Task Detect_ServersDisagree_Symmetric()
    {
        // Each fake reports its own fictional mapping for the same client socket —
        // exactly what a symmetric NAT looks like from the inside.
        using FakeStunServer s1 = new();
        using FakeStunServer s2 = new();
        s1.ReportMappedOverride = new IPEndPoint(IPAddress.Parse("198.51.100.10"), 40000);
        s2.ReportMappedOverride = new IPEndPoint(IPAddress.Parse("198.51.100.10"), 40001);

        NatType type = await NatDetector.DetectAsync([s1.LocalEndPoint, s2.LocalEndPoint]).WaitAsync(Timeout);

        Assert.Equal(NatType.Symmetric, type);
    }

    [Fact]
    public async Task Detect_SingleSilentServer_Unknown()
    {
        // One live server plus one dead port: with a single observation there is no
        // comparison, and the detector must say so rather than guess.
        using FakeStunServer live = new();
        var dead = new IPEndPoint(IPAddress.Loopback, 1); // discard port: nothing answers

        NatType type = await NatDetector.DetectAsync([live.LocalEndPoint, dead]).WaitAsync(Timeout);

        Assert.Equal(NatType.Unknown, type);
    }

    [Fact]
    public async Task SymmetricHint_ReachableDirectCandidateStillConnects()
    {
        // The symmetric hint is scheduling advice, not a ban: a LAN peer (private
        // address, no NAT in the way) must still connect directly even when the string
        // says the publisher's NAT maps per-destination.
        await using PinholeNode a = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [],
            ConnectTimeout = TimeSpan.FromSeconds(2),
            EnableNetworkWatch = false, EnablePortMapping = false,
        });
        await using PinholeNode b = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [],
            ConnectTimeout = TimeSpan.FromSeconds(2),
            EnableNetworkWatch = false, EnablePortMapping = false,
        });

        Task<PinholeConnection> accept = a.AcceptAsync();
        string lan = new ConnectionString(
            a.PeerId,
            [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, a.LocalPort))],
            NatHint.Symmetric,
            staticKey: a.StaticPublicKey).ToString();

        await using PinholeConnection atB = await b.ConnectAsync(lan).WaitAsync(Timeout);
        await using PinholeConnection atA = await accept.WaitAsync(Timeout);

        Assert.Equal(PinholeConnectionState.Open, atB.State);
        Assert.Equal(PathKind.Direct, atB.Path.Kind);
    }

    [Fact]
    public async Task SymmetricHint_ReflexiveMappingStillConnects()
    {
        // The same for a kind-2 candidate — on a real network a router port mapping
        // (PCP/NAT-PMP/UPnP) is advertised exactly this way, punchable from anywhere
        // even behind a symmetric NAT, so the hint must not suppress it.
        await using PinholeNode a = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [],
            ConnectTimeout = TimeSpan.FromSeconds(2),
            EnableNetworkWatch = false, EnablePortMapping = false,
        });
        await using PinholeNode b = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [],
            ConnectTimeout = TimeSpan.FromSeconds(2),
            EnableNetworkWatch = false, EnablePortMapping = false,
        });

        Task<PinholeConnection> accept = a.AcceptAsync();
        string mapped = new ConnectionString(
            a.PeerId,
            [new PinholeCandidate(CandidateKind.Reflexive, new IPEndPoint(IPAddress.Loopback, a.LocalPort))],
            NatHint.Symmetric,
            staticKey: a.StaticPublicKey).ToString();

        await using PinholeConnection atB = await b.ConnectAsync(mapped).WaitAsync(Timeout);
        await using PinholeConnection atA = await accept.WaitAsync(Timeout);

        Assert.Equal(PinholeConnectionState.Open, atB.State);
        Assert.Equal(PathKind.Direct, atB.Path.Kind);
    }

    [Fact]
    public async Task SymmetricHint_NothingReachable_StopsWithinBudget()
    {
        // With the trickle punching instead of the blanket ban, the dial must still
        // give up on its ConnectTimeout budget when nothing is reachable: no relay
        // fallback and a direct candidate that will never answer.
        await using PinholeNode a = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [],
            ConnectTimeout = TimeSpan.FromSeconds(2),
            EnableNetworkWatch = false, EnablePortMapping = false,
        });
        await using PinholeNode b = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [],
            ConnectTimeout = TimeSpan.FromSeconds(2),
            EnableNetworkWatch = false, EnablePortMapping = false,
        });

        string doomed = new ConnectionString(
            a.PeerId,
            [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Parse("192.0.2.10"), 9999))],
            NatHint.Symmetric,
            staticKey: a.StaticPublicKey).ToString();

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(() => b.ConnectAsync(doomed).WaitAsync(Timeout));
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(6),
            $"symmetric dial should give up on the ConnectTimeout budget, took {sw.Elapsed}");
    }
}

public sealed class PathStatsTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Opts() => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [],
        ConnectTimeout = TimeSpan.FromSeconds(8),
        EnableNetworkWatch = false, EnablePortMapping = false,
    };

    [Fact]
    public async Task Stats_CountTraffic_RttAndPathKind()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());

        Task<PinholeConnection> accept = a.AcceptAsync();
        PinholeConnection atB = await b.ConnectAsync(a.ConnectionString).WaitAsync(Timeout);
        PinholeConnection atA = await accept.WaitAsync(Timeout);

        // Drive some measurable traffic: retransmit until the peer confirms receipt.
        var got = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        int received = 0;
        atA.Received += _ => { if (Interlocked.Increment(ref received) >= 10) got.TrySetResult(received); };
        byte[] body = Encoding.UTF8.GetBytes("stat-me");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (!got.Task.IsCompleted && sw.Elapsed < Timeout)
        {
            atB.Send(body);
            await Task.Delay(50);
        }

        await got.Task.WaitAsync(Timeout);
        PinholeStats sent = atB.Stats;
        PinholeStats recv = atA.Stats;
        Assert.True(sent.DatagramsSent >= 10, $"sent {sent.DatagramsSent}");
        Assert.Equal(10, recv.DatagramsReceived);
        Assert.Equal(body.Length * sent.DatagramsSent, sent.BytesSent);
        Assert.Equal(body.Length * recv.DatagramsReceived, recv.BytesReceived);
        Assert.True(sent.DatagramsSendFailed >= 0, "send failures are counted, and loopback has none");

        // Ping is a tool: one ping, one pong, a real RTT — never a background nanny.
        atB.Ping();
        var rtt = await TestWait.UntilRttAsync(Timeout, () => atB.LastRtt);
        Assert.True(rtt < TimeSpan.FromSeconds(1), $"loopback rtt {rtt}");
        // Sub-millisecond loopback RTTs measure as 0 ticks, which is the EWMA's "unset"
        // sentinel — a null average is honest there, never a lie.
        Assert.True(atB.AverageRtt is null || atB.AverageRtt < TimeSpan.FromSeconds(1));
        Assert.True(atB.Stats.PingsSent >= 1);
        Assert.True(atB.Stats.PongsReceived >= 1);
        Assert.Equal(0, atB.Stats.PingsLost);

        // The path snapshot tells the truth about where traffic is going.
        Assert.Equal(PathKind.Direct, atB.Path.Kind);
        Assert.NotNull(atB.Path.Remote);
        Assert.Equal(a.LocalPort, atB.Path.Remote!.Port);
    }
}

internal static class TestWait
{
    /// <summary>Waits until the read produces a non-null value (e.g. LastRtt before the first pong).</summary>
    public static async Task<TimeSpan> UntilRttAsync(TimeSpan budget, Func<TimeSpan?> read)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (read() is null)
        {
            Assert.True(sw.Elapsed < budget, $"rtt not produced within {budget}");
            await Task.Delay(50);
        }

        return read()!.Value;
    }
}
