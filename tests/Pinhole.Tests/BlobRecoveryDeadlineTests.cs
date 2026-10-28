using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;
using Pinhole.Sim;

namespace Pinhole.Tests;

public sealed class BlobRecoveryDeadlineTests(ITestOutputHelper output)
{
    private static readonly TimeSpan Ceiling = TimeSpan.FromSeconds(10);

    [Fact]
    public void HealthyIntervals_DoNotSpendOrResetRecoveryAllowance()
    {
        long now = 100;
        var budget = new BlobClient.RecoveryBudget(TimeSpan.FromSeconds(1), () => now);
        budget.Begin();
        now += 100;
        budget.End();

        now += 300_000; // Five minutes of healthy progress after the first dial.
        budget.Check();
        Assert.Equal(TimeSpan.FromMilliseconds(900), budget.Remaining);

        budget.Begin();
        now += 899;
        budget.End();
        Assert.Equal(TimeSpan.FromMilliseconds(1), budget.Remaining);
        now += 300_000;
        Assert.Equal(TimeSpan.FromMilliseconds(1), budget.Remaining);
    }

    [Fact]
    public void RepeatedDisruptions_ExpireAtTheirSharedAllowance()
    {
        long now = 100;
        var budget = new BlobClient.RecoveryBudget(TimeSpan.FromSeconds(1), () => now);
        budget.Begin();
        now += 600;
        budget.End();
        now += 300_000;

        budget.Begin();
        now += 300;
        budget.Begin(); // A retry inside this outage cannot restart its clock.
        now += 99;
        budget.Check();
        Assert.Equal(TimeSpan.FromMilliseconds(1), budget.Remaining);
        now++;
        Assert.Throws<TimeoutException>(budget.Check);
    }

    [Fact]
    public void DelayedPathLossObservation_CountsTimeSinceLastVerifiedProgress()
    {
        long now = 100;
        var budget = new BlobClient.RecoveryBudget(TimeSpan.FromMilliseconds(750), () => now);
        long lastVerified = now;
        now += 750;
        budget.Begin(lastVerified);
        Assert.Throws<TimeoutException>(budget.Check);
        Assert.Equal(TimeSpan.Zero, budget.Remaining);
    }

    [Fact]
    public async Task UnreachableProvider_RecoveryBudgetCancelsThePendingDial()
    {
        string dir = TempDir();
        try
        {
            using var lab = new VirtualLab();
            var ticket = new BlobTicket
            {
                Kind = BlobKind.File,
                Name = "missing.bin",
                Root = RandomNumberGenerator.GetBytes(32),
                ConnectionString = new ConnectionString(0x12345678,
                    [new PinholeCandidate(CandidateKind.Direct, new(IPAddress.Parse("198.51.100.10"), 35110))],
                    staticKey: new NodeIdentity().PublicKey).ToString(),
            };
            var watch = Stopwatch.StartNew();
            TimeoutException failure = await Assert.ThrowsAsync<TimeoutException>(() =>
                BlobClient.DownloadAsync(ticket, Path.Combine(dir, "out"), options: Options(lab) with
                {
                    RecoveryTimeout = TimeSpan.FromMilliseconds(750),
                    NodeOptions = ClientOptions(lab) with { ConnectTimeout = TimeSpan.FromSeconds(15) },
                }).WaitAsync(Ceiling));

            Assert.Contains("re-established", failure.Message);
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), "a dial must not outlive its recovery allowance");
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(750)]
    public async Task PermanentBlackout_EndsThePausedStreamAndReturnsItsReservations(int recoveryMs)
    {
        string dir = TempDir();
        try
        {
            using var lab = new VirtualLab();
            await using BlobServer server = await ServeAsync(lab, dir);
            server.DropChunk = index => index >= 4;
            LinkRule cut = LinkRule.Blackhole(Subnet.Parse(VirtualLab.Hosts4SecondRegion));
            int cutApplied = 0;
            var progress = new InlineProgress(p =>
            {
                if (p.VerifiedBytes >= 4 * 1024 && Interlocked.Exchange(ref cutApplied, 1) == 0)
                    lab.Net.AddRule(cut);
            });
            var flow = new BlobFlowBudget(64 * 1024);
            var watch = Stopwatch.StartNew();
            TimeoutException failure = await Assert.ThrowsAsync<TimeoutException>(() =>
                BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"), progress, Options(lab) with
                {
                    RecoveryTimeout = TimeSpan.FromMilliseconds(recoveryMs),
                    FlowBudget = flow,
                }).WaitAsync(Ceiling));

            Assert.Equal(1, cutApplied);
            Assert.Contains("re-established", failure.Message);
            Assert.Equal(0, flow.UsedBytes);
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), "paused stall clocks must not remove the recovery deadline");
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public async Task LivePathWithoutChunks_IsBoundedByTheRemainingRecoveryAllowance()
    {
        string dir = TempDir();
        try
        {
            using var lab = new VirtualLab();
            await using BlobServer server = await ServeAsync(lab, dir);
            server.DropChunk = index => index >= 4;
            var flow = new BlobFlowBudget(64 * 1024);
            var watch = Stopwatch.StartNew();
            TimeoutException failure = await Assert.ThrowsAsync<TimeoutException>(() =>
                BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"), options: Options(lab) with
                {
                    RecoveryTimeout = TimeSpan.FromMilliseconds(750),
                    FlowBudget = flow,
                }).WaitAsync(Ceiling));

            Assert.True(server.ChunksServed >= 4, "the transfer reached real chunk requests before stalling");
            Assert.Contains("re-established", failure.Message);
            Assert.Equal(0, flow.UsedBytes);
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), "the 30-second attempt clock must not extend a shorter allowance");
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void SweepArm_YieldsToTheStallClockButNeverSpins()
    {
        // Healthy tail: a fresh 30s limit against a young flight never bites,
        // so the arm is exactly the PTO's, backoff and all.
        Assert.Equal(12_000, BlobClient.SweepArmMs(ptoMs: 12_000, sentAtMs: 10_000,
            lastVerifiedMs: 9_900, limitMs: 30_000, answerMs: 3_000));

        // The CI-stress shape: srtt pegged at the PTO ceiling puts the next
        // natural re-request 12s out while the spent allowance bounds the death
        // clock at lastVerified + 5.5s. The arm collapses to whatever still
        // lets a re-request fire and be answered in time — 2.5s here.
        Assert.Equal(2_500, BlobClient.SweepArmMs(ptoMs: 12_000, sentAtMs: 5_000,
            lastVerifiedMs: 5_000, limitMs: 5_500, answerMs: 3_000));

        // Inside the answer window the arm floors at 250ms — a dying tail
        // re-requests instead of idling, but never spins the loop — and the
        // floor never stretches the arm past the PTO itself.
        Assert.Equal(BlobClient.SweepFloorMs, BlobClient.SweepArmMs(ptoMs: 12_000, sentAtMs: 9_000,
            lastVerifiedMs: 5_000, limitMs: 5_500, answerMs: 3_000));
        Assert.Equal(150, BlobClient.SweepArmMs(ptoMs: 150, sentAtMs: 9_000,
            lastVerifiedMs: 5_000, limitMs: 5_500, answerMs: 3_000));
    }

    [Fact]
    public void LocalStallCredit_IgnoresJitterAndForgivesOnlyBlockedTime()
    {
        const long tick = 5; // the downloader's ControlTick cadence

        // Normal iteration cadence and scheduling jitter around it — including the
        // ~16 ms idle-wake granularity of Windows timers — credit nothing: a
        // healthy flight keeps aging toward its PTO.
        Assert.Equal(0, BlobClient.LocalStallCreditMs(gapMs: 3, tickMs: tick));
        Assert.Equal(0, BlobClient.LocalStallCreditMs(gapMs: 16, tickMs: tick)); // Windows idle-wake gap
        Assert.Equal(0, BlobClient.LocalStallCreditMs(gapMs: 50, tickMs: tick)); // at the threshold, not past it

        // A blocked loop — a verifier stall on the loop's own thread, a GC pause —
        // is not wire time: all but one tick comes back, so a flight's age at
        // resume is its pre-stall age plus one tick. A 350 ms verifier stall (the
        // BufferedResponses shape) cannot age a young flight toward the 150 ms
        // PTO floor, while a flight already at its PTO edge still expires.
        Assert.Equal(55, BlobClient.LocalStallCreditMs(gapMs: 60, tickMs: tick));
        Assert.Equal(345, BlobClient.LocalStallCreditMs(gapMs: 350, tickMs: tick));
        Assert.Equal(4_995, BlobClient.LocalStallCreditMs(gapMs: 5_000, tickMs: tick));
    }

    [Fact]
    public async Task HealthyTimeBeforeProviderRestart_DoesNotSpendRecoveryAllowance()
    {
        string dir = TempDir();
        // The whole scenario is shaper-paced (1 Mbps token bucket), so every phase has a
        // hard wall-clock floor that runner load can only lengthen, never shrink.
        TimeSpan allowance = TimeSpan.FromSeconds(10);
        TimeSpan halfFloor = TimeSpan.FromSeconds(12);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(75));
        Task<BlobDownloadResult>? download = null;
        try
        {
            using var lab = new VirtualLab();
            byte[] seed = RandomNumberGenerator.GetBytes(32);
            byte[] expected = TestDispose.Pattern(3 * 1024 * 1024, 0xA3);
            string source = Path.Combine(dir, "asset.bin");
            await File.WriteAllBytesAsync(source, expected);
            BlobServeOptions serveOptions = new()
            {
                Encrypt = false,
                NodeOptions = ServerOptions(lab) with { IdentityKeySeed = seed },
            };
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, 1_000_000, 128,
                delay: TimeSpan.FromMilliseconds(20)));
            await using BlobServer server = await BlobServer.ServeAsync(source, serveOptions);
            long half = expected.Length / 2;
            var halfDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var progress = new InlineProgress(p =>
            {
                if (p.VerifiedBytes >= half) halfDone.TrySetResult();
            });
            var watch = Stopwatch.StartNew();
            // Half the file is 1.5 MiB over a 1 Mbps shaper: at least ~12.4 s (minus the
            // bucket's 0.2 s burst credit) plus the dial — a floor the 10 s allowance stays
            // under, so "the healthy portion exceeds the allowance" is physics, not timing.
            // The allowance itself covers the restart chain: silent path death (~5 s of
            // ride-out with these validation knobs), a 0.5 s backoff, re-dial and the first
            // verified chunk — 5 s could not absorb that on a loaded runner (CI failures at
            // ~14 s: recovery expired right after the restart).
            // Clock accounting is also tested above without scheduler/timer noise;
            // this scenario verifies actual provider replacement and checkpoint reuse.
            download = BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"), progress,
                Options(lab) with
                {
                    RecoveryTimeout = allowance,
                    // The blackout fixtures use one 20 ms probe, shorter than this
                    // link's 40 ms RTT. Give healthy traffic a valid probe budget here.
                    // The knobs are also near their safe minimum: the 128-packet queue
                    // drains for ~1 s at 1 Mbps, so probe replies can legitimately lag
                    // a full interval; anything tighter falsely declares the healthy
                    // path dead mid-transfer.
                    NodeOptions = ClientOptions(lab) with
                    {
                        PathValidationIdle = TimeSpan.FromSeconds(2),
                        PathValidationProbeInterval = TimeSpan.FromSeconds(1),
                        PathValidationMaxUnansweredProbes = 3,
                    },
                }, stop.Token);
            Task first = await Task.WhenAny(halfDone.Task, download).WaitAsync(TimeSpan.FromSeconds(45));
            if (first == download)
            {
                await download; // Report a transfer failure immediately, before the progress wait.
                Assert.Fail("the transfer finished before the provider-restart trigger");
            }
            Assert.True(watch.Elapsed > allowance, "the healthy portion must exceed the recovery allowance");
            output.WriteLine($"healthy half ({half} B) verified at {watch.Elapsed.TotalSeconds:F1}s, "
                + $"allowance {allowance.TotalSeconds:F0}s, floor {halfFloor.TotalSeconds:F0}s");
            await server.DisposeAsync();
            await using BlobServer successor = await BlobServer.ServeAsync(source, serveOptions);

            BlobDownloadResult result;
            try { result = await download.WaitAsync(TimeSpan.FromSeconds(45)); }
            catch (TimeoutException ex)
            {
                Assert.Fail($"provider-restart recovery failed after {watch.Elapsed}: {ex}; "
                    + $"successor accepted={successor.ConnectionsAccepted}, chunks={successor.ChunksServed}; "
                    + $"network={lab.Net.Counters()}; "
                    + $"handshakes={string.Join("; ", successor.Node.Connections.Select(c => successor.Node.Engine.HandshakeSummary(c.PeerId)))}");
                throw;
            }
            Assert.True(result.Resumed);
            Assert.True(successor.ConnectionsAccepted >= 1);
            Assert.Equal(expected, await File.ReadAllBytesAsync(result.Path));
            output.WriteLine($"resumed from checkpoint and finished at {watch.Elapsed.TotalSeconds:F1}s total");
        }
        finally
        {
            stop.Cancel();
            if (download is not null)
            {
                try { await download.WaitAsync(TestBudget.Teardown); }
                catch (Exception ex) when (ex is OperationCanceledException or TimeoutException) { }
            }
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task DirectionalTailBlackoutWithSpentAllowance_StillFinishes()
    {
        string dir = TempDir();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        Task<BlobDownloadResult>? download = null;
        try
        {
            using var lab = new VirtualLab();
            byte[] seed = RandomNumberGenerator.GetBytes(32);
            byte[] expected = TestDispose.Pattern(2 * 1024 * 1024, 0xA3);
            string source = Path.Combine(dir, "asset.bin");
            await File.WriteAllBytesAsync(source, expected);
            // The shaper rule carries both directions' loss as runtime toggles:
            // the virtual network consults only the first matching rule, so a
            // blackout rule added at run time would sit forever behind the
            // bottleneck and drop nothing. Address order picks sides — the
            // loss model applied is the one whose source compares smaller, and
            // the provider's .10 sorts before the client's .20, so
            // ForwardLoss carries provider→client data.
            ToggleLoss providerToClient = new();
            ToggleLoss clientToProvider = new();
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, 1_000_000, 128,
                delay: TimeSpan.FromMilliseconds(20),
                forwardLoss: providerToClient, reverseLoss: clientToProvider));
            await using BlobServer server = await BlobServer.ServeAsync(source, new BlobServeOptions
            {
                Encrypt = false,
                NodeOptions = ServerOptions(lab) with { IdentityKeySeed = seed },
            });

            // Phase one spends most of the allowance through a real path loss.
            // Phase two recreates the loss shape of the CI-stress failures:
            // the provider→client direction goes dark mid-tail while the path
            // itself stays valid — client requests keep reaching the provider,
            // whose answers die in the dark — so nothing trips path validation
            // and the stall clock runs the whole cut. The clamp that keeps the
            // sweep inside the death clock is unit-tested above; this scenario
            // proves the whole path end to end: ride out the cut, sweep, heal,
            // finish against what remains of the allowance.
            long total = expected.Length;
            var fullCut = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var tailCut = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int stage = 0;
            var progress = new InlineProgress(p =>
            {
                if (p.VerifiedBytes >= total / 4 && Interlocked.CompareExchange(ref stage, 1, 0) == 0)
                {
                    providerToClient.Enable();
                    clientToProvider.Enable();
                    fullCut.TrySetResult();
                }
                else if (p.VerifiedBytes >= total * 3 / 4 && Interlocked.CompareExchange(ref stage, 2, 1) == 1)
                {
                    providerToClient.Enable();
                    tailCut.TrySetResult();
                }
            });
            var watch = Stopwatch.StartNew();
            download = BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"), progress,
                Options(lab) with
                {
                    // 16s was calibrated before the handshake's v4 mac1 armor: each
                    // re-dial under total silence now spends the 3s v4 fallback window
                    // (v4 PUNCs into the dark, then the one-shot unversioned retry)
                    // before the handshake can complete — a bounded, documented
                    // protocol cost the allowance must have room for.
                    RecoveryTimeout = TimeSpan.FromSeconds(20),
                    NodeOptions = ClientOptions(lab) with
                    {
                        PathValidationIdle = TimeSpan.FromSeconds(2),
                        PathValidationProbeInterval = TimeSpan.FromSeconds(1),
                        PathValidationMaxUnansweredProbes = 3,
                        ConnectTimeout = TimeSpan.FromSeconds(8),
                    },
                }, stop.Token);

            // The full cut must outlast the ~5s these validation knobs need to
            // declare the silent path dead; the tail cut must outlast the first
            // natural PTO expiry (~3s at the ceiling) so the re-request flight
            // is genuinely lost, not merely late. The allowance is sized so
            // that even a slow runner's redial and answer latencies leave the
            // post-cut remainder more than a round trip of headroom — the
            // scenario must finish on every matrix leg, not race its budget.
            await fullCut.Task.WaitAsync(TimeSpan.FromSeconds(20));
            await Task.Delay(TimeSpan.FromSeconds(7), stop.Token);
            providerToClient.Disable();
            clientToProvider.Disable();
            await tailCut.Task.WaitAsync(TimeSpan.FromSeconds(25));
            await Task.Delay(TimeSpan.FromSeconds(3), stop.Token);
            providerToClient.Disable();

            BlobDownloadResult result = await download.WaitAsync(TimeSpan.FromSeconds(45));
            Assert.Equal(expected, await File.ReadAllBytesAsync(result.Path));
            output.WriteLine($"survived both blackouts and finished at {watch.Elapsed.TotalSeconds:F1}s");
        }
        finally
        {
            stop.Cancel();
            if (download is not null)
            {
                try { await download.WaitAsync(TestBudget.Teardown); }
                catch (Exception ex) when (ex is OperationCanceledException or TimeoutException) { }
            }
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task RepeatedBlackouts_SpendOneSharedAllowance()
    {
        string dir = TempDir();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        Task<BlobDownloadResult>? download = null;
        try
        {
            using var lab = new VirtualLab();
            await using BlobServer server = await ServeAsync(lab, dir);
            long allowedChunks = 8;
            server.DropChunk = index => index >= Volatile.Read(ref allowedChunks);
            LinkRule cut = LinkRule.Blackhole(Subnet.Parse(VirtualLab.Hosts4SecondRegion));
            var firstCut = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var secondCut = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int stage = 0;
            var progress = new InlineProgress(p =>
            {
                if (p.VerifiedBytes >= 16 * 1024 && Interlocked.CompareExchange(ref stage, 2, 1) == 1)
                {
                    lab.Net.AddRule(cut);
                    secondCut.TrySetResult();
                }
                else if (p.VerifiedBytes >= 8 * 1024 && Interlocked.CompareExchange(ref stage, 1, 0) == 0)
                {
                    lab.Net.AddRule(cut);
                    firstCut.TrySetResult();
                }
            });
            var flow = new BlobFlowBudget(64 * 1024);
            download = BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"), progress,
                Options(lab) with { RecoveryTimeout = TimeSpan.FromSeconds(8), FlowBudget = flow }, stop.Token);
            await firstCut.Task.WaitAsync(Ceiling);
            await Task.Delay(TimeSpan.FromSeconds(5), stop.Token);
            Volatile.Write(ref allowedChunks, 16);
            lab.Net.RemoveRule(cut);
            Task second = await Task.WhenAny(secondCut.Task, download).WaitAsync(Ceiling);
            if (second == download) await download; // report the real fault instead of hiding it behind a wait
            await secondCut.Task;

            // The first outage used over half the allowance. A fresh eight-second
            // clock on the second outage would fail to terminate within this wait.
            TimeoutException failure = await Assert.ThrowsAsync<TimeoutException>(async () =>
                await download.WaitAsync(TimeSpan.FromSeconds(4.5)));
            Assert.Contains("re-established", failure.Message);
            Assert.Equal(0, flow.UsedBytes);
        }
        finally
        {
            stop.Cancel();
            if (download is not null)
            {
                try { await download.WaitAsync(TestBudget.Teardown); }
                catch (Exception ex) when (ex is OperationCanceledException or TimeoutException) { }
            }
            Directory.Delete(dir, recursive: true);
        }
    }

    private sealed class InlineProgress(Action<BlobProgress> report) : IProgress<BlobProgress>
    {
        public void Report(BlobProgress value) => report(value);
    }

    private static PinholeOptions ServerOptions(VirtualLab lab) => lab.BaseOptions(o => o with
    {
        UdpSocketFactory = _ => lab.Net.CreateHost(new(IPAddress.Parse("198.51.100.10"), 35110)),
    });

    private static PinholeOptions ClientOptions(VirtualLab lab) => lab.BaseOptions(o => o with
    {
        UdpSocketFactory = _ => lab.Net.CreateHost(new(IPAddress.Parse("198.51.100.20"), 35120)),
        PathValidationIdle = TimeSpan.FromMilliseconds(50),
        PathValidationProbeInterval = TimeSpan.FromMilliseconds(20),
        PathValidationMaxUnansweredProbes = 1,
        ConnectTimeout = TimeSpan.FromSeconds(8),
    });

    private static BlobDownloadOptions Options(VirtualLab lab) => new() { NodeOptions = ClientOptions(lab) };

    private static async Task<BlobServer> ServeAsync(VirtualLab lab, string dir)
    {
        string source = Path.Combine(dir, "asset.bin");
        await File.WriteAllBytesAsync(source, TestDispose.Pattern(128 * 1024, 0xA3));
        return await BlobServer.ServeAsync(source, new BlobServeOptions { NodeOptions = ServerOptions(lab) });
    }

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-recovery-deadline-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
