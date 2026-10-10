using System.Diagnostics;
using System.Net;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

/// <summary>#27: the bottleneck and recovery baselines the congestion-control work (#20)
/// will be judged against. Every scenario runs the real blob stack through the virtual
/// internet's finite-bandwidth link — one shared FIFO drained at a fixed rate, tail-dropped
/// when full — so these numbers mean the same thing every run: goodput through a real
/// queue, healing from queue-induced loss, seed-to-seed variance, and how a fat RTT flows
/// against a thin one over one bottleneck. Exact numbers are machine-dependent and go to
/// the logs and docs/BASELINES.md; the assertions are completion, integrity, and physical
/// sanity (measured rate cannot exceed the link). TCP competition is explicitly out of the
/// lab's reach — there is no real TCP peer in-process — and is documented as such.</summary>
public sealed class BottleneckTests(ITestOutputHelper output)
{
    private const long FlowBytes = 512 * 1024;
    private static readonly TimeSpan FlowBudget = TimeSpan.FromSeconds(75);

    // The lab's bottleneck: 16 Mbit/s (2 MiB/s), 20 ms each way → ~157 packets of
    // bandwidth-delay product; the deep-queue rung holds a full RTT of it, the thin-queue
    // rung barely holds a burst.
    private const long LinkBits = 16_000_000;
    private static readonly TimeSpan OneWay = TimeSpan.FromMilliseconds(20);

    [Fact]
    [Trait("Category", "Performance")]
    public async Task FiniteBandwidth_DeepQueue_TransferSaturatesLinkUnderDelay()
    {
        string dir = TempDir();
        try
        {
            // A 2 MiB flow, not the class's 512 KiB default: the receive window opens small
            // and ramps over ~40 ms RTTs, and on a slow runner the ramp alone can eat a
            // quarter of a short flow (observed 435 KiB/s vs the 1953 ceiling, zero loss,
            // queue depth 1). The saturation claim needs the sustained phase to dominate.
            const long bytes = 2 * 1024 * 1024;
            using var lab = new VirtualLab();
            await using BlobServer server = await ServeAsync(lab, dir, bytes);
            AddBottleneck(lab, queuePackets: 256);

            var transfer = new TransferProgress();
            var stats = new BlobTransferStats();
            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir, transfer, stats).WaitAsync(FlowBudget);
            sw.Stop();
            Assert.Equal(bytes, result.Bytes);

            Assert.True(transfer.Bytes > 0 && transfer.Elapsed > TimeSpan.Zero);
            double kibPerSecond = transfer.Bytes / transfer.Elapsed.TotalSeconds / 1024;
            output.WriteLine($"deep queue: {result.Bytes} B in {sw.Elapsed.TotalSeconds:F2}s total; " +
                             $"{transfer.Bytes} B in {transfer.Elapsed.TotalSeconds:F2}s receiving = {kibPerSecond:F0} KiB/s " +
                             $"(link ceiling {LinkBits / 8 / 1024:F0} KiB/s) | {lab.Net.Counters()} | " +
                             $"requests={stats.RequestsSent}, retransmits={stats.Retransmits}, loss-windows={stats.LossEvents}, " +
                             $"resumes={stats.ConservativeResumes}, duplicate-bytes={stats.DuplicateBytes}, " +
                             $"rtt-ms={stats.SmoothedRtt?.TotalMilliseconds:F1}, window={stats.WindowBytes}");
            Assert.True(kibPerSecond <= LinkBits / 8 / 1024 * 1.05,
                $"measured {kibPerSecond:F0} KiB/s exceeds the 16 Mbit/s link — the shaper is not shaping");
            Assert.True(kibPerSecond >= LinkBits / 8 / 1024 * 0.25,
                $"goodput collapsed to {kibPerSecond:F0} KiB/s on a clean 16 Mbit/s link — the baseline is broken");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task FiniteBandwidth_ThinQueue_TailDropLossHealsAndVerifies()
    {
        string dir = TempDir();
        try
        {
            using var lab = new VirtualLab();
            await using BlobServer server = await ServeAsync(lab, dir);
            LinkRule rule = AddBottleneck(lab, queuePackets: 16);

            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir).WaitAsync(FlowBudget);
            sw.Stop();
            AssertVerified(dir, result);

            long minimumChunks = FlowBytes / BlobWire.MaxChunkData;
            output.WriteLine($"thin queue: {result.Bytes} B in {sw.Elapsed.TotalSeconds:F2}s " +
                             $"({result.Bytes / sw.Elapsed.TotalSeconds / 1024:F0} KiB/s), served {server.ChunksServed} " +
                             $"vs floor {minimumChunks} | {lab.Net.Counters()}");
            Assert.True(server.ChunksServed > minimumChunks,
                "a 16-packet queue under a bursty sender must overflow; the ARQ must have re-requested");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData(801)]
    [InlineData(802)]
    [InlineData(803)]
    [InlineData(804)]
    [InlineData(805)]
    public async Task MultipleSeeds_SteadyStateGoodput_EverySeedCompletes(int seed)
    {
        string dir = TempDir();
        try
        {
            using var lab = new VirtualLab();
            await using BlobServer server = await ServeAsync(lab, dir);
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, LinkBits, queuePackets: 128,
                delay: OneWay, jitter: TimeSpan.FromMilliseconds(3),
                forwardLoss: new IndependentLoss(0.05, seed), reverseLoss: new IndependentLoss(0.05, seed + 1)));

            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await DownloadAsync(lab, server, dir).WaitAsync(FlowBudget);
            sw.Stop();
            AssertVerified(dir, result);
            output.WriteLine($"seed {seed}: {result.Bytes / sw.Elapsed.TotalSeconds / 1024:F0} KiB/s " +
                             $"({sw.Elapsed.TotalSeconds:F1}s) | {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task MixedRtt_TwoConcurrentFlows_BothCompleteOverOneBottleneck()
    {
        string dir = TempDir();
        try
        {
            using var lab = new VirtualLab();

            // Two servers, two downloaders, one shared bottleneck; the near flow crosses at
            // 5 ms, the far one at 120 ms — the classic thin-RTT-fattens-first contest.
            const string nearServer = "198.51.100.10", farServer = "198.51.100.11";
            const string nearClient = "198.51.100.20", farClient = "198.51.100.21";
            await using BlobServer near = await ServeAtAsync(lab, dir, nearServer, 41010, "near.bin");
            await using BlobServer far = await ServeAtAsync(lab, dir, farServer, 41011, "far.bin");

            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, LinkBits, queuePackets: 128));
            lab.Net.AddRule(new LinkRule
            {
                Match = (src, dst) => IsAny(src, farClient, farServer) && IsAny(dst, farClient, farServer),
                Delay = TimeSpan.FromMilliseconds(120),
            });

            var sw = Stopwatch.StartNew();
            Task<BlobDownloadResult> nearRun = DownloadAtAsync(lab, near, dir, nearClient, 41020, "near");
            Task<BlobDownloadResult> farRun = DownloadAtAsync(lab, far, dir, farClient, 41021, "far");
            BlobDownloadResult[] done = await Task.WhenAll(nearRun, farRun).WaitAsync(FlowBudget);
            sw.Stop();

            Assert.Equal(FlowBytes, done[0].Bytes);
            Assert.Equal(FlowBytes, done[1].Bytes);
            output.WriteLine($"mixed RTT: both {FlowBytes / 1024} KiB flows completed in {sw.Elapsed.TotalSeconds:F1}s " +
                             $"over one 16 Mbit/s bottleneck (near 5 ms vs far 120 ms) | {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ------------------------------------------------------------------ plumbing

    private static bool IsAny(IPEndPoint ep, string a, string b) =>
        ep.Address.ToString() == a || ep.Address.ToString() == b;

    private static LinkRule AddBottleneck(VirtualLab lab, int queuePackets)
    {
        Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
        LinkRule rule = LinkRule.Bottleneck(region, region, LinkBits, queuePackets, delay: OneWay);
        lab.Net.AddRule(rule);
        return rule;
    }

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-bottleneck-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static async Task<BlobServer> ServeAsync(VirtualLab lab, string dir, long bytes = FlowBytes) =>
        await ServeAtAsync(lab, dir, "198.51.100.10", 32010, "rung.bin", bytes);

    private static async Task<BlobServer> ServeAtAsync(VirtualLab lab, string dir, string address, int port, string name,
        long bytes = FlowBytes)
    {
        byte[] data = new byte[bytes];
        Random.Shared.NextBytes(data);
        string src = Path.Combine(dir, name + ".src");
        await File.WriteAllBytesAsync(src, data);
        return await BlobServer.ServeAsync(src, new BlobServeOptions
        {
            NodeOptions = lab.BaseOptions(o => o with
            {
                UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse(address), port)),
            }),
        });
    }

    private static Task<BlobDownloadResult> DownloadAsync(VirtualLab lab, BlobServer server, string dir,
        IProgress<BlobProgress>? progress = null, BlobTransferStats? stats = null) =>
        DownloadAtAsync(lab, server, dir, "198.51.100.20", 32020, "out", progress, stats);

    private static Task<BlobDownloadResult> DownloadAtAsync(VirtualLab lab, BlobServer server, string dir,
        string address, int port, string name, IProgress<BlobProgress>? progress = null, BlobTransferStats? stats = null) =>
        BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, name + "-out"), progress,
            options: new BlobDownloadOptions
            {
                Stats = stats,
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse(address), port)),
                }),
            });

    private static void AssertVerified(string dir, BlobDownloadResult result) => Assert.Equal(FlowBytes, result.Bytes);

    private sealed class TransferProgress : IProgress<BlobProgress>
    {
        private long _firstTick;
        private long _lastTick;
        private long _firstBytes;
        private long _lastBytes;
        public long Bytes => _lastBytes - _firstBytes;
        public TimeSpan Elapsed => Stopwatch.GetElapsedTime(_firstTick, _lastTick);
        public void Report(BlobProgress progress)
        {
            long now = Stopwatch.GetTimestamp();
            if (_firstTick == 0)
            {
                _firstTick = now;
                _firstBytes = progress.VerifiedBytes;
            }
            _lastTick = now;
            _lastBytes = progress.VerifiedBytes;
        }
    }
}
