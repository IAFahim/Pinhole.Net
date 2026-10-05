using System.Diagnostics;
using System.Net;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

/// <summary>The loss ladder: the shipped blob ARQ (paced AIMD since 1.9.0 — before that the
/// fixed 4×64 window; both measured head-to-head in <c>CongestionTests</c>) driven by
/// increasing loss — independent rungs and a Gilbert-Elliott burst rung — with goodput
/// recorded per rung. Re-run this file around any ARQ change. Assertions stay deliberately
/// loose (completion, integrity, curve ordering that holds under the shipped control law) —
/// exact goodput is machine-dependent and belongs in the logs. Each rung runs in its own
/// lab and directory: loss chains, counters, and resume sidecars never bleed between
/// rungs.</summary>
public sealed class LossLadderTests(ITestOutputHelper output)
{
    private const long RungBytes = 1024 * 1024;      // theory rungs
    private const long CurveBytes = 2 * 1024 * 1024; // the curve needs steady state, not startup
    private static readonly TimeSpan RungBudget = TimeSpan.FromSeconds(90);

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

    /// <summary>The curve itself, at a size where the control law reaches steady state:
    /// goodput falls as loss rises (2 MiB rungs, one process so machine speed cancels out
    /// of the comparison). The burst rung is recorded, not asserted — under the RTT-adaptive
    /// RTO, clustered loss heals in one round trip per burst and can legitimately beat
    /// independent loss at a lower mean rate.</summary>
    [Fact]
    public async Task LadderCurve_GoodputFallsAsLossRises()
    {
        double at2 = await RunIsolatedRungAsync(0.02, 501, CurveBytes);
        double at10 = await RunIsolatedRungAsync(0.10, 502, CurveBytes);
        double at20 = await RunIsolatedRungAsync(0.20, 503, CurveBytes);
        double burst = await RunIsolatedBurstAsync(701, CurveBytes);

        output.WriteLine($"ladder curve (CC): 2% -> {at2:F0} B/s, 10% -> {at10:F0} B/s, 20% -> {at20:F0} B/s, " +
                         $"GE(10%, burst 8) -> {burst:F0} B/s");
        Assert.True(at10 < at2, $"goodput at 10% loss ({at10:F0} B/s) must fall below 2% ({at2:F0} B/s)");
        Assert.True(at20 < at2, $"goodput at 20% loss ({at20:F0} B/s) must fall below 2% ({at2:F0} B/s)");
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

    private static async Task<BlobServer> ServeAsync(VirtualLab lab, string dir, long size = RungBytes)
    {
        byte[] data = new byte[size];
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

    private static void AssertVerified(string dir, BlobDownloadResult result, long size = RungBytes)
    {
        Assert.Equal(size, result.Bytes);
        Assert.Equal(size, new FileInfo(Path.Combine(dir, "out", "rung.bin")).Length);
    }

    private async Task<double> RunIsolatedRungAsync(double loss, int seed, long size)
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            await using BlobServer server = await ServeAsync(lab, dir, size);
            AddIndependentLoss(lab, loss, seed);

            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir).WaitAsync(RungBudget);
            sw.Stop();
            AssertVerified(dir, result, size);
            output.WriteLine($"rung iid p={loss:P0}: {result.Bytes} B in {sw.Elapsed.TotalSeconds:F1}s — {lab.Net.Counters()}");
            return result.Bytes / sw.Elapsed.TotalSeconds;
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private async Task<double> RunIsolatedBurstAsync(int seed, long size)
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            await using BlobServer server = await ServeAsync(lab, dir, size);
            lab.Net.AddRule(BurstRule(0.10, 8, seed));

            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir).WaitAsync(RungBudget);
            sw.Stop();
            AssertVerified(dir, result, size);
            return result.Bytes / sw.Elapsed.TotalSeconds;
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
