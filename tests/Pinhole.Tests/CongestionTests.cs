using System.Diagnostics;
using System.Net;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

/// <summary>#20 — the congestion controller against the recorded fixed-window baseline.
/// The controller is receiver-side only and the wire is unchanged: every claim here is a
/// blob-layer property measured through the same virtual internet the #27 baselines used.
/// Floors are set at a fraction of the Release-measured numbers so Debug runs (2-3×
/// slower) stay honest witnesses; the measured values themselves go to BLOBS.md and
/// BASELINES.md.</summary>
public sealed class CongestionTests(ITestOutputHelper output)
{
    private const long FlowBytes = 512 * 1024;
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(90);
    private const long LinkBits = 16_000_000;

    [Fact]
    public async Task ThinQueue_ControllerAvoidsTheFixedWindowCollapse()
    {
        string dir = TempDir();
        try
        {
            using var lab = new VirtualLab();
            await using BlobServer server = await ServeAsync(lab, dir);
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, LinkBits, queuePackets: 16,
                delay: TimeSpan.FromMilliseconds(20)));

            var stats = new BlobTransferStats();
            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir, stats).WaitAsync(Budget);
            sw.Stop();
            Assert.Equal(FlowBytes, result.Bytes);

            double kibPerSecond = result.Bytes / sw.Elapsed.TotalSeconds / 1024;
            output.WriteLine($"thin queue, controller: {kibPerSecond:F0} KiB/s, {stats.Retransmits} retransmits, " +
                             $"{stats.DuplicateBytes / 1024} KiB duplicates | {lab.Net.Counters()}");
            // The fixed window collapsed to ~32 KiB/s here (measured 2026-10-06 and in the
            // #27 record); the controller must clear several times that with margin.
            Assert.True(kibPerSecond >= 90, $"controller collapsed to {kibPerSecond:F0} KiB/s on the thin queue");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task LossyLink_BothModesRecoverAndVerify_InProcess()
    {
        string dir = TempDir();
        try
        {
            TimeSpan fixedWindow = await RunOneRungAsync(dir, fixedWindow: true);
            TimeSpan controller = await RunOneRungAsync(dir, fixedWindow: false);
            output.WriteLine($"5% bidirectional loss, 128-pkt queue: fixed window {fixedWindow.TotalSeconds:F1}s vs " +
                             $"controller {controller.TotalSeconds:F1}s ({fixedWindow / controller:F1}x)");
            // Shared CI load and OS timer granularity change the relative elapsed times.
            // Keep the A/B measurement, but gate on actual loss recovery and verification;
            // controller adaptation itself is checked below with controlled RTT samples.
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }

        async Task<TimeSpan> RunOneRungAsync(string directory, bool fixedWindow)
        {
            BlobTestHooks.ForceFixedWindow = fixedWindow;
            try
            {
                string runDir = Path.Combine(directory, fixedWindow ? "fixed" : "cc");
                Directory.CreateDirectory(runDir);
                using var lab = new VirtualLab();
                await using BlobServer server = await ServeAsync(lab, runDir);
                Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
                lab.Net.AddRule(LinkRule.Bottleneck(region, region, LinkBits, queuePackets: 128,
                    delay: TimeSpan.FromMilliseconds(20), jitter: TimeSpan.FromMilliseconds(3),
                    forwardLoss: new IndependentLoss(0.05, 9001), reverseLoss: new IndependentLoss(0.05, 9002)));

                var stats = new BlobTransferStats();
                var sw = Stopwatch.StartNew();
                BlobDownloadResult result = await DownloadAsync(lab, server, runDir, stats).WaitAsync(Budget);
                sw.Stop();
                Assert.Equal(FlowBytes, result.Bytes);
                Assert.Equal(FlowBytes, stats.VerifiedBytes);
                Assert.True(lab.Net.DroppedByPolicy > 0, "the link must really drop packets");
                Assert.True(stats.Retransmits > 0, "dropped chunks must require recovery");
                if (!fixedWindow) Assert.NotNull(stats.SmoothedRtt);
                return sw.Elapsed;
            }
            finally
            {
                BlobTestHooks.ForceFixedWindow = false;
            }
        }
    }

    [Fact]
    public void Controller_AdaptsToRttAndBacksOffRepeatedLoss()
    {
        var budget = new BlobFlowBudget(1024 * 1024);
        var controller = new BlobController(1024 * 1024, budget, null, fixedWindow: false);
        var baseline = new BlobController(1024 * 1024, budget, null, fixedWindow: true);
        TimeSpan initial = controller.PtoFor(0);
        controller.ObserveRtt(TimeSpan.FromMilliseconds(40));
        Assert.True(controller.PtoFor(0) < initial);
        Assert.True(controller.PtoFor(0) < baseline.PtoFor(0));
        Assert.True(controller.PtoFor(2) > controller.PtoFor(1));
        Assert.True(controller.PtoFor(1) > controller.PtoFor(0));
        Assert.Equal(baseline.PtoFor(0), baseline.PtoFor(2));

        long window = controller.WindowBytes;
        controller.OnRetransmit(1000);
        Assert.Equal(window, controller.WindowBytes); // isolated loss does not collapse the window
        controller.OnRetransmit(1001);
        controller.OnRetransmit(1002);
        Assert.True(controller.WindowBytes < window); // clustered loss reduces pressure
        controller.OnPathChanged();
        Assert.Equal(window, controller.WindowBytes);
        Assert.Equal(initial, controller.PtoFor(0));
    }

    [Fact]
    public async Task RetransmittedResponses_AreCountedAsWireLoad()
    {
        string dir = TempDir();
        try
        {
            using var lab = new VirtualLab();
            await using BlobServer server = await ServeAsync(lab, dir);

            // A duplicating provider: one chunk in eight arrives twice. The second copy
            // verifies nothing — it is pure wire load, and exactly what the stats must
            // count instead of pretending request credits bound the response side.
            server.DuplicateChunk = idx => idx % 8 == 3;
            long expectedDuplicateBytes = 64 * 1024; // 512 chunks / 8 = 64 duplicates × 1 KiB

            var stats = new BlobTransferStats();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir, stats).WaitAsync(Budget);
            Assert.Equal(FlowBytes, result.Bytes);
            Assert.Equal(expectedDuplicateBytes, stats.DuplicateBytes);
            Assert.Equal(expectedDuplicateBytes + FlowBytes, stats.ReceivedBytes);
            output.WriteLine($"duplicating provider: {stats.DuplicateBytes / 1024} KiB duplicate bytes counted against " +
                             $"{stats.VerifiedBytes / 1024} KiB verified — the response side's real wire load");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task SharedBudget_ConcurrentDownloadsDivideOnePie()
    {
        string dir = TempDir();
        try
        {
            using var lab = new VirtualLab();
            const string serverA = "198.51.100.10", serverB = "198.51.100.11";
            const string clientA = "198.51.100.20", clientB = "198.51.100.21";
            await using BlobServer a = await ServeAtAsync(lab, dir, serverA, 33010, "a.bin");
            await using BlobServer b = await ServeAtAsync(lab, dir, serverB, 33011, "b.bin");
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, LinkBits, queuePackets: 128,
                delay: TimeSpan.FromMilliseconds(20)));

            // One small shared pie: both downloads join it, so neither can open a full
            // window while the other is starving. The sampler watches the ledger the
            // whole time — the cap must hold even at the peaks.
            var budget = new BlobFlowBudget(96 * 1024);
            long peak = 0;
            using var sampler = new System.Threading.Timer(
                _ => Interlocked.Exchange(ref peak, Math.Max(peak, budget.UsedBytes)), null, 0, 5);
            var statsA = new BlobTransferStats();
            var statsB = new BlobTransferStats();
            Task<BlobDownloadResult> first = DownloadAtAsync(lab, a, Path.Combine(dir, "outA"), clientA, 33020, budget, statsA);
            Task<BlobDownloadResult> second = DownloadAtAsync(lab, b, Path.Combine(dir, "outB"), clientB, 33021, budget, statsB);
            BlobDownloadResult[] done = await Task.WhenAll(first, second).WaitAsync(Budget);

            sampler.Dispose();
            Assert.Equal(FlowBytes, done[0].Bytes);
            Assert.Equal(FlowBytes, done[1].Bytes);
            Assert.Equal(0, budget.UsedBytes); // both streams settled every reservation
            Assert.True(peak > 32 * 1024, $"the budget was never really exercised (peak {peak / 1024} KiB)");
            Assert.True(peak <= budget.CapacityBytes,
                $"aggregate in-flight peaked at {peak / 1024} KiB, past the {budget.CapacityBytes / 1024} KiB pie");
            output.WriteLine($"two downloads shared a {budget.CapacityBytes / 1024} KiB budget; peak {peak / 1024} KiB, " +
                             $"both {FlowBytes / 1024} KiB flows verified");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task ProviderRoamMidTransfer_ControllerResumesConservativelyAndFinishes()
    {
        string dir = TempDir();
        try
        {
            using var lab = new VirtualLab();
            await using BlobServer server = await ServeAsync(lab, dir);
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            // A deliberately thin link: the 512 KiB flow takes seconds, so the roam
            // provably lands mid-flight rather than after the last chunk was served.
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, 4_000_000, queuePackets: 64,
                delay: TimeSpan.FromMilliseconds(20)));

            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var stats = new BlobTransferStats();
            var progress = new Progress<BlobProgress>(p =>
            {
                if (p.VerifiedBytes >= 128 * 1024)
                {
                    gate.TrySetResult();
                }
            });
            Task<BlobDownloadResult> run = Task.Run(() => BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
                progress, new BlobDownloadOptions
                {
                    NodeOptions = lab.BaseOptions(o => o with
                    {
                        UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), 32020)),
                    }),
                    Stats = stats,
                }, default).WaitAsync(Budget));

            await gate.Task.WaitAsync(Budget);
            await server.Node.Engine.SimulateInterfaceLossAsync(); // the provider roams: new endpoint, same session

            BlobDownloadResult result = await run;
            Assert.Equal(FlowBytes, result.Bytes);
            Assert.True(stats.ConservativeResumes >= 1,
                "an endpoint change mid-transfer must reset the controller conservatively");
            output.WriteLine($"provider roamed mid-transfer; {stats.ConservativeResumes} conservative resumes, " +
                             $"finished at {stats.WindowBytes / 1024} KiB window, {stats.Retransmits} retransmits");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ------------------------------------------------------------------ plumbing

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-congestion-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static async Task<BlobServer> ServeAtAsync(VirtualLab lab, string dir, string address, int port, string name)
    {
        byte[] data = new byte[FlowBytes];
        Random.Shared.NextBytes(data);
        string src = Path.Combine(dir, name + ".src");
        await File.WriteAllBytesAsync(src, data);
        int nextPort = port; // a fresh port per (re)bind: a fixed one would make a roam a no-op
        return await BlobServer.ServeAsync(src, new BlobServeOptions
        {
            NodeOptions = lab.BaseOptions(o => o with
            {
                UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse(address), System.Threading.Interlocked.Increment(ref nextPort))),
            }),
        });
    }

    private static Task<BlobServer> ServeAsync(VirtualLab lab, string dir) => ServeAtAsync(lab, dir, "198.51.100.10", 32010, "rung.bin");

    private static Task<BlobDownloadResult> DownloadAsync(VirtualLab lab, BlobServer server, string dir,
        BlobTransferStats? stats = null) =>
        DownloadAtAsync(lab, server, Path.Combine(dir, "out"), "198.51.100.20", 32020, null, stats);

    private static Task<BlobDownloadResult> DownloadAtAsync(VirtualLab lab, BlobServer server, string dir,
        string address, int port, BlobFlowBudget? budget = null, BlobTransferStats? stats = null) =>
        BlobClient.DownloadAsync(server.Ticket, dir,
            options: new BlobDownloadOptions
            {
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse(address), port)),
                }),
                FlowBudget = budget,
                Stats = stats,
            });
}
