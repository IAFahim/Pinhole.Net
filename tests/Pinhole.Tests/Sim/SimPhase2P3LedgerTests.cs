using System.Diagnostics;
using System.Net;
using Pinhole.Blobs;
using Pinhole.Sim;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests.Sim;

// R3 property gate P3 at END-TO-END level: ledger conservation over a full
// BlobClient/BlobServer run on the virtual network. The reservation ledger has
// three faces that must agree at every observed step — the shared BlobFlowBudget
// holds, the pacer's in-flight bytes, and the downloader's live outstanding holds
// (requested chunks whose reservation has not been released at a PTO expiry or an
// arrival) — and all three must rest at exactly zero once a transfer completes,
// is cancelled mid-blackout, or fails its recovery budget. Observations ride the
// same AsyncLocal discipline as BlobTestHooks.Trace: one snapshot per downloader
// control tick, on the thread that owns every ledger mutation, so a snapshot is
// never torn and parallel transfers never cross-observe. Every stochastic model
// is seeded; a rerun reproduces the verdict (the shaper drains on wall time, so
// tick-for-tick traces are not claimed — the conservation invariant is).
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
            // A shaped, lossy link: PTO expiries release holds mid-flight and re-requests
            // come back as unbudgeted healing traffic — the exact traffic pattern the
            // ledger accounting must survive. Both loss models are seeded.
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
            Assert.Equal(0, flow.UsedBytes); // quiescence: nothing pinned after Commit
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
                // Mid-flight: reservations exist and the loop is ticking before the cut.
                await TestPoll.UntilAsync(TimeSpan.FromSeconds(20), () => watch.Ticks > 10 && watch.MaxReserved > 0);

                // The hostile case: the whole region goes dark while holds are out, then
                // the caller cancels. The unwind (not the transfer) is under test.
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
            Assert.Equal(0, flow.UsedBytes); // a cancelled download leaks no share of the pie
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

            // The provider serves the first 100 chunks and then goes silent on a live
            // path: the stall clock fires, the recovery loop re-dials into the same
            // silence, and the shared allowance runs out. Every dial mints a fresh
            // StreamDownloader against the SAME injected budget — conservation must
            // hold across the whole ride, and the failure must leave it at zero.
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
            Assert.Equal(0, flow.UsedBytes); // a failed transfer pins nothing on its way out
            // The stall clock is bounded by the remaining recovery allowance, so an 8 s
            // budget is legitimately exhausted inside the FIRST stalled attempt — the
            // dial count is context, not the property.
            output.WriteLine($"failed transfer unwound to zero across {server.ConnectionsAccepted} dial(s), " +
                             $"{watch.Ticks} observations, peak {watch.MaxReserved / 1024} KiB, {sw.Elapsed.TotalSeconds:F1}s");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ------------------------------------------------------------------ ledger watch

    private sealed class LedgerWatch : IDisposable
    {
        private readonly object _gate = new();
        private readonly List<string> _violations = [];

        // Written only inside Observe's lock; polled cross-thread as plain longs —
        // aligned 64-bit reads, and the poll only needs "has this ever moved".
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

    // ------------------------------------------------------------------ plumbing

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
