using System.Diagnostics;
using System.Net;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

/// <summary>The congestion-control validation (#20 part 2): CC vs the fixed-window
/// baseline (the internal <c>FixedWindowArq</c> seam reproduces pre-1.9.0 behavior), over
/// a real bottleneck — serialized transmissions, a bounded FIFO that drops on overflow,
/// propagation delay — with competing flows sharing it. The bar is deliberately NOT
/// "faster everywhere": on an uncongested link the fixed window can win outright. The bar
/// is: at comparable goodput under congestion, materially lower queue delay and fewer
/// wasted retransmissions, and a near-even split between competing flows that the fixed
/// window does not achieve. Every rung logs its full physics line; seeds are recorded so
/// any regression re-runs the same world.</summary>
public sealed class CongestionTests(ITestOutputHelper output)
{
    private const double Capacity = 1.5 * 1024 * 1024; // 1.5 MiB/s per direction
    private const long QueueBytes = 96 * 1024;
    private static readonly TimeSpan Propagation = TimeSpan.FromMilliseconds(30);
    private static readonly TimeSpan RungBudget = TimeSpan.FromSeconds(90);

    private sealed record RunResult(double GoodputBps, double MeanQueueWaitMs, long MaxQueueWaitMs, long QueueDrops,
        long ReRequests, long Retransmissions);

    [Fact]
    public async Task HeadToHead_Bottleneck_CcCutsQueueDelayAndWasteAcrossSeeds()
    {
        // Three recorded seeds; the assertion aggregates so one noisy world cannot flip the
        // verdict. No random loss — every drop on this link is congestion the sender caused.
        var byMode = new Dictionary<bool, List<RunResult>>();
        foreach (bool fixedWindow in new[] { false, true })
        {
            byMode[fixedWindow] = [];
            foreach (int seed in new[] { 11, 22, 33 })
            {
                RunResult run = await RunSingleFlowAsync(fixedWindow, seed, randomLoss: 0);
                byMode[fixedWindow].Add(run);
                output.WriteLine($"{Mode(fixedWindow)} seed={seed}: {Line(run)}");
            }
        }

        RunResult cc = Average(byMode[false]);
        RunResult baseline = Average(byMode[true]);
        output.WriteLine($"AVERAGE cc:         {Line(cc)}");
        output.WriteLine($"AVERAGE fixed-1.8:  {Line(baseline)}");

        Assert.True(cc.MeanQueueWaitMs < baseline.MeanQueueWaitMs,
            $"CC mean queue wait ({cc.MeanQueueWaitMs:F1} ms) must beat the fixed window ({baseline.MeanQueueWaitMs:F1} ms)");
        Assert.True(cc.QueueDrops < baseline.QueueDrops,
            $"CC queue drops ({cc.QueueDrops}) must beat the fixed window ({baseline.QueueDrops})");
        Assert.True(cc.GoodputBps > 0.7 * baseline.GoodputBps,
            $"CC goodput ({cc.GoodputBps / 1024:F0} KiB/s) must stay within 70% of the fixed window ({baseline.GoodputBps / 1024:F0} KiB/s)");
    }

    [Fact]
    public async Task Fairness_TwoCompetingFlows_ConvergeNearEvenSplit()
    {
        (double ccJain, string ccLine) = await RunCompetingPairAsync(fixedWindow: false);
        output.WriteLine($"CC pair:    jain={ccJain:F2} {ccLine}");
        (double baselineJain, string baselineLine) = await RunCompetingPairAsync(fixedWindow: true);
        output.WriteLine($"fixed pair: jain={baselineJain:F2} (recorded, not asserted) {baselineLine}");

        Assert.True(ccJain >= 0.80, $"two CC flows must split the bottleneck near-evenly (Jain {ccJain:F2})");
    }

    /// <summary>The congestion+corruption mix, longer transfers, recorded seeds: every rung
    /// completes and verifies under both control laws; the table is the artifact. No
    /// throughput ordering is asserted — reducing congestion and sharing capacity are the
    /// point, and on clean-ish links the fixed window is allowed to be faster.</summary>
    [Theory]
    [InlineData(0.02, 11)]
    [InlineData(0.02, 22)]
    [InlineData(0.10, 11)]
    [InlineData(0.10, 22)]
    public async Task LossUnderBottleneck_BothControlLaws_CompleteAndVerify(double loss, int seed)
    {
        foreach (bool fixedWindow in new[] { false, true })
        {
            RunResult run = await RunSingleFlowAsync(fixedWindow, seed, randomLoss: loss);
            output.WriteLine($"{Mode(fixedWindow)} loss={loss:P0} seed={seed}: {Line(run)}");
        }
    }

    // ------------------------------------------------------------------ world

    private static string Mode(bool fixedWindow) => fixedWindow ? "fixed-1.8" : "cc";

    private static string Line(RunResult r) =>
        $"goodput={r.GoodputBps / 1024:F0} KiB/s queueWait(mean {r.MeanQueueWaitMs:F1} ms, max {r.MaxQueueWaitMs} ms) " +
        $"qdrops={r.QueueDrops} re-requests={r.ReRequests} retransmissions={r.Retransmissions}";

    private static RunResult Average(List<RunResult> runs) => new(
        runs.Average(r => r.GoodputBps),
        runs.Average(r => r.MeanQueueWaitMs),
        (long)runs.Average(r => r.MaxQueueWaitMs),
        (long)runs.Average(r => r.QueueDrops),
        (long)runs.Average(r => r.ReRequests),
        (long)runs.Average(r => r.Retransmissions));

    /// <summary>One provider→downloader flow across the shared bottleneck. 2 MiB: long
    /// enough that the control law's steady state, not its startup, dominates.</summary>
    private async Task<RunResult> RunSingleFlowAsync(bool fixedWindow, int seed, double randomLoss)
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            const long size = 2 * 1024 * 1024;
            await using BlobServer server = await ServeAsync(lab, dir, host: ".10", size);
            LinkRule bottleneck = AddBottleneck(lab, randomLoss, seed);

            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir, host: ".20",
                fixedWindow: fixedWindow).WaitAsync(RungBudget);
            sw.Stop();

            Assert.Equal(size, result.Bytes);
            long retransmissions = server.ChunksServed - size / BlobWire.MaxChunkData;
            return new RunResult(
                result.Bytes / sw.Elapsed.TotalSeconds,
                bottleneck.MeanQueueWaitMs(Volatile.Read(ref bottleneck.Passed)),
                Volatile.Read(ref bottleneck.MaxQueueWaitMs),
                Volatile.Read(ref bottleneck.QueueDrops),
                result.ReRequests,
                retransmissions);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>Two independent provider→downloader pairs crossing the same bottleneck —
    /// the fairness topology. Jain index over the two flows' goodput, each measured by its
    /// own completion time from a simultaneous start.</summary>
    private async Task<(double Jain, string Line)> RunCompetingPairAsync(bool fixedWindow)
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            const long size = 1024 * 1024;
            await using BlobServer serverA = await ServeAsync(lab, Path.Combine(dir, "a"), host: ".10", size);
            await using BlobServer serverB = await ServeAsync(lab, Path.Combine(dir, "b"), host: ".11", size);
            LinkRule bottleneck = AddBottleneck(lab, randomLoss: 0, seed: 44);

            var clocks = new[] { Stopwatch.StartNew(), Stopwatch.StartNew() };
            Task<(BlobDownloadResult Result, double Seconds)>[] downloads =
            [
                RunFlowAsync(0),
                RunFlowAsync(1),
            ];
            var results = await Task.WhenAll(downloads).WaitAsync(RungBudget);

            Assert.All(results, r => Assert.Equal(size, r.Result.Bytes));
            double[] goodput = results.Select(r => size / r.Seconds).ToArray();
            double jain = Math.Pow(goodput.Sum(), 2) / (goodput.Length * goodput.Sum(g => g * g));

            string line = $"per-flow=[{goodput[0] / 1024:F0} KiB/s, {goodput[1] / 1024:F0} KiB/s] " +
                          $"qdrops={Volatile.Read(ref bottleneck.QueueDrops)} " +
                          $"queueWait(mean {bottleneck.MeanQueueWaitMs(Volatile.Read(ref bottleneck.Passed)):F1} ms, " +
                          $"max {Volatile.Read(ref bottleneck.MaxQueueWaitMs)} ms) " +
                          $"re-req=[{results[0].Result.ReRequests}, {results[1].Result.ReRequests}]";
            return (jain, line);

            async Task<(BlobDownloadResult Result, double Seconds)> RunFlowAsync(int slot) => await Task.Run(async () =>
            {
                BlobDownloadResult r = await DownloadAsync(lab, slot == 0 ? serverA : serverB,
                    Path.Combine(dir, slot == 0 ? "outA" : "outB"), slot == 0 ? ".20" : ".21", fixedWindow);
                clocks[slot].Stop();
                return (r, clocks[slot].Elapsed.TotalSeconds);
            });
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static LinkRule AddBottleneck(VirtualLab lab, double randomLoss, int seed)
    {
        Subnet providers = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
        Subnet downloaders = Subnet.Parse(VirtualLab.Hosts4);
        LinkRule rule = LinkRule.Bottleneck(providers, downloaders, Capacity, QueueBytes, Propagation,
            forwardLoss: randomLoss > 0 ? new IndependentLoss(randomLoss, seed) : null,
            reverseLoss: randomLoss > 0 ? new IndependentLoss(randomLoss, seed + 1) : null);
        lab.Net.AddRule(rule);
        return rule;
    }

    private static async Task<BlobServer> ServeAsync(VirtualLab lab, string dir, string host, long size)
    {
        Directory.CreateDirectory(dir);
        byte[] data = new byte[size];
        Random.Shared.NextBytes(data);
        string src = Path.Combine(dir, "shared.bin");
        await File.WriteAllBytesAsync(src, data);
        return await BlobServer.ServeAsync(src, new BlobServeOptions
        {
            NodeOptions = lab.BaseOptions(o => o with
            {
                UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100" + host), 33010)),
            }),
        });
    }

    private static Task<BlobDownloadResult> DownloadAsync(VirtualLab lab, BlobServer server, string dir, string host,
        bool fixedWindow) =>
        BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
            options: new BlobDownloadOptions
            {
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("192.0.2" + host), 33020)),
                }),
                FixedWindowArq = fixedWindow,
            });

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-cc-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
