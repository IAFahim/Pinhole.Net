using System.Diagnostics;
using Pinhole.Sim;
using Xunit;

namespace Pinhole.Tests.Sim;

public sealed class SimPropertyGates
{
    private const int SweepSeeds = 1000;
    private const int SweepTicks = 2000;

    [Fact]
    public void P4_SameSeed_ReplaysTheIdenticalEffectLogHash_OnPmtuAndKeepalive()
    {
        Stopwatch sw = Stopwatch.StartNew();
        for (int seed = 0; seed < SweepSeeds; seed++)
        {
            byte[] first = MachineSimScenarios.Pmtu(seed, SweepTicks).Hash;
            byte[] replay = MachineSimScenarios.Pmtu(seed, SweepTicks).Hash;
            Assert.True(first.AsSpan().SequenceEqual(replay), $"PMTU seed {seed} replayed a different effect log");

            byte[] firstKeepalive = MachineSimScenarios.Keepalive(seed, SweepTicks).Hash;
            byte[] replayKeepalive = MachineSimScenarios.Keepalive(seed, SweepTicks).Hash;
            Assert.True(firstKeepalive.AsSpan().SequenceEqual(replayKeepalive),
                $"keepalive seed {seed} replayed a different effect log");
        }

        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(60),
            $"{SweepSeeds}-seed x 2-machine x 2-replay sweep took {sw.Elapsed.TotalSeconds:F1}s; budget is 60 s");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(8)]
    [InlineData(13)]
    [InlineData(21)]
    [InlineData(34)]
    [InlineData(55)]
    [InlineData(89)]
    [InlineData(144)]
    public void P2_EventuallyGoodPath_PmtuConfirmsTheWire_WithinBoundedTicks(int seed)
    {

        const long lossStopsAtMs = 20_000;
        const long recoveryBudgetMs = 70_000;
        int ticks = (int)((lossStopsAtMs + recoveryBudgetMs) / MachineSimScenarios.TickStepMs) + 10;

        MachineSimScenarios.PmtuRun run = MachineSimScenarios.Pmtu(
            seed, ticks, pongLoss: 0.6, lossStopsAtMs: lossStopsAtMs);

        Assert.True(run.ConfirmedAtTickMs >= 0,
            "the eventually-good path never confirmed a wire size within the window");
        Assert.True(run.ConfirmedAtTickMs <= lossStopsAtMs + recoveryBudgetMs,
            $"confirmed at {run.ConfirmedAtTickMs} ms, {run.ConfirmedAtTickMs - lossStopsAtMs} ms after " +
            $"the path turned good; budget is {recoveryBudgetMs} ms");
    }

    [Fact]
    public void DifferentSeeds_ProduceDifferentLogs_SomewhereInTheSweep()
    {

        HashSet<string> pmtu = [];
        HashSet<string> keepalive = [];
        for (int seed = 0; seed < SweepSeeds; seed++)
        {
            pmtu.Add(Convert.ToHexString(MachineSimScenarios.Pmtu(seed, SweepTicks).Hash));
            keepalive.Add(Convert.ToHexString(MachineSimScenarios.Keepalive(seed, SweepTicks).Hash));
        }

        Assert.True(pmtu.Count > 1, $"the PMTU sweep collapsed to {pmtu.Count} digest(s)");
        Assert.True(keepalive.Count > 1, $"the keepalive sweep collapsed to {keepalive.Count} digest(s)");
    }
}
