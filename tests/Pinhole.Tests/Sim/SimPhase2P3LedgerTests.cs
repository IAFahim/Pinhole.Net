using System.Diagnostics;
using System.Net;
using Pinhole.Blobs;
using Pinhole.Sim;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests.Sim;

public sealed class SimPhase2P3LedgerTests(ITestOutputHelper output)
{
    private const long FlowBytes = 512 * 1024;
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(90);

    [Fact]
    public async Task P3_ReservedEqualsOutstanding_AtEveryObservedStep_AndDrainsToZeroOnCompletion()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = await LabAsync();
            await using BlobServer server = await ServeAsync(lab, dir);

            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, 8_000_000, queuePackets: 128,
                delay: TimeSpan.FromMilliseconds(20),
                forwardLoss: new GilbertElliottLoss(0.02, 6, seed: 21),
                reverseLoss: new GilbertElliottLoss(0.01, 4, seed: 22)));

            var flow = new BlobFlowBudget(2 * 1024 * 1024);
            using var watch = LedgerWatch.Attach();
            var sw = Stopwatch.StartNew();
            BlobDownloadResult result;
            try
            {
                result = await DownloadAsync(lab, server, dir, flow).WaitAsync(Budget);
            }
            finally
            {
                sw.Stop();
                watch.Detach();
            }

            Assert.Equal(FlowBytes, result.Bytes);
            watch.AssertConserved();
            Assert.Equal(0, flow.UsedBytes);
            output.WriteLine($"conserved over {watch.Ticks} observations, peak reservation " +
                             $"{watch.MaxReserved / 1024} KiB, {sw.Elapsed.TotalSeconds:F1}s | {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task P3_CancellationDuringBlackout_ReleasesEveryHold()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = await LabAsync();
            await using BlobServer server = await ServeAsync(lab, dir);
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, 8_000_000, queuePackets: 128,
                delay: TimeSpan.FromMilliseconds(20)));

            var flow = new BlobFlowBudget(2 * 1024 * 1024);
            using var watch = LedgerWatch.Attach();
            using var cts = new CancellationTokenSource();
            var sw = Stopwatch.StartNew();
            Task run = Task.Run(() => DownloadAsync(lab, server, dir, flow, cts.Token));
            try
            {

                await TestPoll.UntilAsync(TimeSpan.FromSeconds(20), () => watch.Ticks > 10 && watch.MaxReserved > 0);

                LinkRule cut = LinkRule.Blackhole(region);
                lab.Net.AddRule(cut);
                cts.Cancel();

                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run).WaitAsync(TimeSpan.FromSeconds(15));
            }
            finally
            {
                sw.Stop();
                watch.Detach();
            }

            watch.AssertConserved();
            Assert.Equal(0, flow.UsedBytes);
            output.WriteLine($"cancel-during-blackout unwound {watch.MaxReserved / 1024} KiB of holds " +
                             $"across {watch.Ticks} observations in {sw.Elapsed.TotalSeconds:F1}s");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task P3_FailedTransfer_RidesItsRecoveryBudget_AndUnwindsToZero()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = await LabAsync();
            await using BlobServer server = await ServeAsync(lab, dir);
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, 8_000_000, queuePackets: 128,
                delay: TimeSpan.FromMilliseconds(20)));

            server.DropChunk = index => index >= 100;

            var flow = new BlobFlowBudget(2 * 1024 * 1024);
            using var watch = LedgerWatch.Attach();
            var sw = Stopwatch.StartNew();
            try
            {
                await Assert.ThrowsAsync<TimeoutException>(() =>
                    DownloadAsync(lab, server, dir, flow, recovery: TimeSpan.FromSeconds(8)).WaitAsync(Budget));
            }
            finally
            {
                sw.Stop();
                watch.Detach();
            }

            watch.AssertConserved();
            Assert.Equal(0, flow.UsedBytes);

            output.WriteLine($"failed transfer unwound to zero across {server.ConnectionsAccepted} dial(s), " +
                             $"{watch.Ticks} observations, peak {watch.MaxReserved / 1024} KiB, {sw.Elapsed.TotalSeconds:F1}s");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private sealed class LedgerWatch : IDisposable
    {
        private readonly object _gate = new();
        private readonly List<string> _violations = [];

        public long Ticks;
        public long MaxReserved;

        public static LedgerWatch Attach()
        {
            LedgerWatch watch = new();
            BlobTestHooks.Ledger = watch.Observe;
            return watch;
        }

        public void Detach() => BlobTestHooks.Ledger = null;

        private void Observe(long budgetHolds, long pacerInFlight, long outstandingHolds)
        {
            lock (_gate)
            {
                Ticks++;
                MaxReserved = Math.Max(MaxReserved, budgetHolds);
                if (budgetHolds != outstandingHolds || budgetHolds != pacerInFlight)
                {
                    _violations.Add($"budget={budgetHolds} pacer={pacerInFlight} holds={outstandingHolds}");
                }
            }
        }

        public void AssertConserved()
        {
            lock (_gate)
            {
                Assert.True(Ticks > 0, "the ledger probe never observed a tick — the gate is vacuous");
                Assert.True(MaxReserved > 0, "no reservation was ever taken — the gate is vacuous");
                Assert.Empty(_violations);
            }
        }

        public void Dispose() => Detach();
    }

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-sim-p3-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static Task<VirtualLab> LabAsync() => Task.FromResult(new VirtualLab());

    private static async Task<BlobServer> ServeAsync(VirtualLab lab, string dir)
    {
        byte[] data = new byte[FlowBytes];
        Random.Shared.NextBytes(data);
        string src = Path.Combine(dir, "ledger.bin");
        await File.WriteAllBytesAsync(src, data);
        return await BlobServer.ServeAsync(src, new BlobServeOptions
        {
            NodeOptions = lab.BaseOptions(o => o with
            {
                UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 34210)),
            }),
        });
    }

    private static Task<BlobDownloadResult> DownloadAsync(VirtualLab lab, BlobServer server, string dir,
        BlobFlowBudget flow, CancellationToken ct = default, TimeSpan? recovery = null) =>
        BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"), null, new BlobDownloadOptions
        {
            NodeOptions = lab.BaseOptions(o => o with
            {
                UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), 34220)),
            }),
            FlowBudget = flow,
            RecoveryTimeout = recovery ?? TimeSpan.FromMinutes(10),
            Stats = new BlobTransferStats(),
        }, ct);
}
