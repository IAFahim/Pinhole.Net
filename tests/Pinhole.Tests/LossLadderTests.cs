using System.Diagnostics;
using System.Net;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

// Wall-clock goodput comparisons require steady CPU availability. Other test
// collections must not start/finish workloads between the measured rungs.
[CollectionDefinition(nameof(LossLadderTimingCollection), DisableParallelization = true)]
public sealed class LossLadderTimingCollection { }

/// <summary>The loss ladder (#20's baseline deliverable): the blob ARQ's fixed 4×64-chunk
/// window and 900 ms re-requests driven by increasing loss — independent rungs and a
/// Gilbert-Elliott burst rung — with goodput recorded per rung. These curves are the
/// baseline the ARQ congestion-control work is judged against: re-run this file before and
/// after any CC change. Assertions stay deliberately loose (completion, integrity, curve
/// ordering) — exact goodput numbers are machine-dependent and belong in the logs, not the
/// asserts. Each rung runs in its own lab and directory: loss chains, counters, and resume
/// sidecars never bleed between rungs.</summary>
[Collection(nameof(LossLadderTimingCollection))]
public sealed class LossLadderTests(ITestOutputHelper output)
{
    private const long RungBytes = 512 * 1024; // 512 chunks — enough for the window to cycle
    private static readonly TimeSpan RungBudget = TimeSpan.FromSeconds(60);

    [Theory]
    [InlineData(0.01)]
    [InlineData(0.05)]
    [InlineData(0.20)]
    public async Task IndependentRung_TransferCompletesAndVerifies(double loss)
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            await using BlobServer server = await ServeAsync(lab, dir);
            AddIndependentLoss(lab, loss, seed: 101);

            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir).WaitAsync(RungBudget);
            sw.Stop();

            AssertVerified(dir, result);
            long minimumChunks = RungBytes / BlobWire.MaxChunkData;
            if (loss >= 0.05)
            {
                Assert.True(server.ChunksServed > minimumChunks,
                    $"loss={loss:P0}: expected re-transmissions (served {server.ChunksServed}, floor {minimumChunks})");
            }

            output.WriteLine($"rung iid p={loss:P0}: {result.Bytes} B in {sw.Elapsed.TotalSeconds:F1}s " +
                             $"= {result.Bytes / sw.Elapsed.TotalSeconds / 1024:F0} KiB/s | {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task BurstyRung_GilbertElliott_TransferCompletesAndVerifies()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            await using BlobServer server = await ServeAsync(lab, dir);
            lab.Net.AddRule(BurstRule(meanLoss: 0.10, meanBurstPackets: 8, seed: 303));

            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir).WaitAsync(RungBudget);
            sw.Stop();

            AssertVerified(dir, result);
            output.WriteLine($"rung GE mean=10% burst=8: {result.Bytes} B in {sw.Elapsed.TotalSeconds:F1}s " +
                             $"= {result.Bytes / sw.Elapsed.TotalSeconds / 1024:F0} KiB/s | {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>The curve itself: goodput at 2% must beat 10%, and the bursty rung must
    /// beat the 10% scattered rung — measured in one process so machine speed cancels
    /// out. (The controller era inverted the old "bursty ≤ 2%" ordering: long clean
    /// stretches between bursts let the window ramp, so GE(10%, burst 8) legitimately
    /// runs near the clean rate — bursty loss is FRIENDLIER to a window-controlled
    /// receiver than constant scatter, and the assertion now says so.)</summary>
    [Fact]
    public async Task LadderCurve_GoodputFallsAsLossRises()
    {
        double at2 = await RunIsolatedRungAsync(0.02, 501);
        double at10 = await RunIsolatedRungAsync(0.10, 502);
        double burst = await RunIsolatedBurstAsync(701);

        output.WriteLine($"ladder curve: 2% -> {at2:F0} B/s, 10% -> {at10:F0} B/s, GE(10%, burst 8) -> {burst:F0} B/s");
        Assert.True(at10 < at2, $"goodput at 10% loss ({at10:F0} B/s) must fall below 2% ({at2:F0} B/s)");
        Assert.True(burst > at10, $"bursty-loss goodput ({burst:F0} B/s) must beat scattered 10% ({at10:F0} B/s)");
    }

    /// <summary>#14's pause/resume-under-loss box: bursty loss, then the path vanishes for
    /// three seconds mid-transfer, then returns. The ARQ's re-requests must ride through
    /// the gap and the transfer must still verify.</summary>
    [Fact]
    public async Task PauseUnderLoss_BlackholeMidTransfer_ThenResumeAndVerify()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            await using BlobServer server = await ServeAsync(lab, dir);
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(BurstRule(meanLoss: 0.05, meanBurstPackets: 6, seed: 601));

            long third = RungBytes / 3;
            var paused = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var progress = new Progress<BlobProgress>(p =>
            {
                if (p.VerifiedBytes >= third)
                {
                    paused.TrySetResult();
                }
            });

            Task<BlobDownloadResult> download = Task.Run(() => DownloadAsync(lab, server, dir, progress));
            Assert.True(await Task.WhenAny(paused.Task, Task.Delay(TestBudget.Scenario)) == paused.Task,
                $"transfer never reached a third — {lab.Net.Counters()}");

            LinkRule outage = LinkRule.Blackhole(region);
            lab.Net.AddRule(outage);
            await Task.Delay(TimeSpan.FromSeconds(3));
            lab.Net.RemoveRule(outage);

            BlobDownloadResult result = await download.WaitAsync(TestBudget.Scenario);
            AssertVerified(dir, result);
            output.WriteLine($"paused 3 s at a third under 5% bursty loss; finished anyway — {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>#36 regression: a file larger than the sink's reorder horizon (512
    /// chunks) under loss. Before the horizon cap, requests raced up to a whole 1 MiB
    /// window ahead of the applied prefix; arrivals past the 512-chunk reorder buffer
    /// were dropped on the floor WITH their reservation consumed — counted as
    /// duplicates on the wire and never re-requested (a guaranteed stall once a
    /// leading chunk died first). Now requests stay inside the sliding horizon, so
    /// duplicate bytes must stay a small fraction of the payload.</summary>
    [Fact]
    public async Task BeyondReorderHorizon_NoDuplicateFlood()
    {
        const long fileBytes = 1024 * 1024; // 1024 chunks — forces the horizon to slide
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            byte[] data = new byte[fileBytes];
            Random.Shared.NextBytes(data);
            string src = Path.Combine(dir, "big.bin");
            await File.WriteAllBytesAsync(src, data);
            await using BlobServer server = await BlobServer.ServeAsync(src, new BlobServeOptions
            {
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 32010)),
                }),
            });
            AddIndependentLoss(lab, 0.10, seed: 909);

            var stats = new BlobTransferStats();
            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await BlobClient.DownloadAsync(server.Ticket,
                Path.Combine(dir, "out"),
                options: new BlobDownloadOptions
                {
                    Stats = stats,
                    NodeOptions = lab.BaseOptions(o => o with
                    {
                        UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), 32020)),
                    }),
                }).WaitAsync(RungBudget);
            sw.Stop();

            Assert.Equal(fileBytes, result.Bytes);
            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(dir, "out", "big.bin")));
            Assert.True(stats.DuplicateBytes <= fileBytes / 8,
                $"duplicate waste {stats.DuplicateBytes / 1024} KiB exceeded an eighth of the {fileBytes / 1024} KiB payload");
            output.WriteLine($"1 MiB beyond reorder horizon at 10% loss: {sw.Elapsed.TotalSeconds:F1}s, " +
                             $"dup={stats.DuplicateBytes / 1024} KiB, retransmits={stats.Retransmits} | {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ------------------------------------------------------------------ rung plumbing

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-ladder-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void AddIndependentLoss(VirtualLab lab, double loss, int seed)
    {
        Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
        lab.Net.AddRule(LinkRule.Between(region, region, new IndependentLoss(loss, seed), new IndependentLoss(loss, seed + 1)));
    }

    private static LinkRule BurstRule(double meanLoss, double meanBurstPackets, int seed)
    {
        Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
        return LinkRule.Between(region, region,
            new GilbertElliottLoss(meanLoss, meanBurstPackets, seed),
            new GilbertElliottLoss(meanLoss, meanBurstPackets, seed + 1));
    }

    private static async Task<BlobServer> ServeAsync(VirtualLab lab, string dir)
    {
        byte[] data = new byte[RungBytes];
        Random.Shared.NextBytes(data);
        string src = Path.Combine(dir, "rung.bin");
        await File.WriteAllBytesAsync(src, data);
        return await BlobServer.ServeAsync(src, new BlobServeOptions
        {
            NodeOptions = lab.BaseOptions(o => o with
            {
                UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 32010)),
            }),
        });
    }

    private static Task<BlobDownloadResult> DownloadAsync(VirtualLab lab, BlobServer server, string dir,
        IProgress<BlobProgress>? progress = null) =>
        BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
            progress: progress,
            options: new BlobDownloadOptions
            {
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), 32020)),
                }),
            });

    private static void AssertVerified(string dir, BlobDownloadResult result)
    {
        Assert.Equal(RungBytes, result.Bytes);
        Assert.Equal(RungBytes, new FileInfo(Path.Combine(dir, "out", "rung.bin")).Length);
    }

    private async Task<double> RunIsolatedRungAsync(double loss, int seed)
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            await using BlobServer server = await ServeAsync(lab, dir);
            AddIndependentLoss(lab, loss, seed);

            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir).WaitAsync(RungBudget);
            sw.Stop();
            AssertVerified(dir, result);
            output.WriteLine($"rung iid p={loss:P0}: {result.Bytes} B in {sw.Elapsed.TotalSeconds:F1}s — {lab.Net.Counters()}");
            return result.Bytes / sw.Elapsed.TotalSeconds;
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private async Task<double> RunIsolatedBurstAsync(int seed)
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            await using BlobServer server = await ServeAsync(lab, dir);
            lab.Net.AddRule(BurstRule(0.10, 8, seed));

            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir).WaitAsync(RungBudget);
            sw.Stop();
            AssertVerified(dir, result);
            return result.Bytes / sw.Elapsed.TotalSeconds;
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
