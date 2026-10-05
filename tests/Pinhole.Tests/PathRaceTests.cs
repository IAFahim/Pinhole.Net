using System.Diagnostics;
using System.Net;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

/// <summary>#28: viable direct and relay paths are raced within one connection deadline —
/// the dialer's punch loop already offers PUNCs to every candidate (direct and relay) on
/// the same 200 ms tick while the relay allocation warms concurrently; these tests PROVE
/// the race semantics with clocks: whichever path answers first carries the session,
/// inside a fraction of the deadline, and neither path's slowness blocks the other.</summary>
public sealed class PathRaceTests(ITestOutputHelper output)
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(15); // the engine default
    private static readonly TimeSpan Settle = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task DirectCrawls_RelayAnswersFirst_SessionLandsOnRelayInFractionOfDeadline()
    {
        // Two internet hosts with a viable-but-slow direct path (3 s RTT: punch-and-answer
        // needs at least one round trip) and a fast relay (real loopback TURN, unshaped —
        // exactly the asymmetric hotel case). The relay must win the race long before the
        // direct path could even complete its first exchange.
        using VirtualLab lab = new(withTurn: true);
        await using PinholeNode a = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("198.51.100.10"), 0));
        await using PinholeNode b = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("198.51.100.20"), 0));

        Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
        lab.Net.AddRule(LinkRule.Directional(region, region, delay: TimeSpan.FromMilliseconds(1500)));

        Task<PinholeConnection> accept = a.AcceptAsync();
        var sw = Stopwatch.StartNew();
        await using PinholeConnection conn = await b.ConnectAsync(a.ConnectionString).WaitAsync(Deadline);
        sw.Stop();

        Assert.Equal(PathKind.Relay, conn.Path.Kind);
        await using PinholeConnection atA = await accept.WaitAsync(Settle);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5),
            $"the relay race took {sw.Elapsed.TotalSeconds:F1}s; a direct-first-then-fallback chain would burn the 3 s direct RTT first ({lab.Net.Counters()})");
        output.WriteLine($"relay won the race in {sw.Elapsed.TotalMilliseconds:F0} ms (direct RTT was 3 s) | {lab.Net.Counters()}");
    }

    [Fact]
    public async Task BothPathsViable_DirectAnswersFirst_SessionLandsDirect()
    {
        // The race must not develop a relay bias: with both paths fast, the direct path's
        // lower latency wins and the session opens Direct.
        using VirtualLab lab = new(withTurn: true);
        await using PinholeNode a = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("198.51.100.10"), 0));
        await using PinholeNode b = await lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse("198.51.100.20"), 0));


        output.WriteLine($"dialer addr: {b.LocalPort}");
        Task<PinholeConnection> accept = a.AcceptAsync();
        var sw = Stopwatch.StartNew();
        await using PinholeConnection conn = await b.ConnectAsync(a.ConnectionString).WaitAsync(Deadline);
        await using PinholeConnection atA = await accept.WaitAsync(Settle);
        sw.Stop();

        await TestPoll.UntilAsync(Settle, () => conn.Path.Kind == PathKind.Direct);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5),
            $"a both-paths-fast dial took {sw.Elapsed.TotalSeconds:F1}s | {lab.Net.Counters()}");
        output.WriteLine($"direct won the race in {sw.Elapsed.TotalMilliseconds:F0} ms | {lab.Net.Counters()}");
    }

    [Fact]
    public async Task DirectHopeless_SymmetricPair_RelayCarriesWithinDeadline()
    {
        // Symmetric × symmetric: the physics forbid a direct path. The race's promise is
        // that the relay leg alone connects within the SAME single deadline — no
        // direct-first-then-fallback sequencing that burns the clock on hopeless punches.
        using VirtualLab lab = new(withTurn: true);
        VirtualNat aNat = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.10", "172.31.10.0/24");
        VirtualNat bNat = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.20", "172.31.20.0/24");
        await using PinholeNode a = await lab.BindNodeAsync(aNat);
        await using PinholeNode b = await lab.BindNodeAsync(bNat);

        Task<PinholeConnection> accept = a.AcceptAsync();
        var sw = Stopwatch.StartNew();
        await using PinholeConnection conn = await b.ConnectAsync(a.ConnectionString).WaitAsync(Deadline);
        await using PinholeConnection atA = await accept.WaitAsync(Settle);
        sw.Stop();

        Assert.Equal(PathKind.Relay, conn.Path.Kind);
        Assert.True(sw.Elapsed < Deadline, "connected within the one connection deadline");
        output.WriteLine($"symmetric pair relayed in {sw.Elapsed.TotalSeconds:F1}s of the {Deadline.TotalSeconds:F0}s deadline | {lab.Net.Counters()}");
    }
}
