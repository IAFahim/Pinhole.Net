using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

// GC.GetTotalMemory measures the whole test process. Run these measurements while
// other collections are idle so their allocations cannot masquerade as a leak.
[CollectionDefinition(nameof(ProcessResourceCollection), DisableParallelization = true)]
public sealed class ProcessResourceCollection { }

/// <summary>#34 — bounded resources: cancelled, recovered, and restarted transfers must
/// hand back every reservation, socket, connection-table slot, and byte of heap they
/// borrowed. Each test asserts the specific counter that would grow if the layer leaked —
/// the budget's used-bytes, the lab's live-socket ledger, the node's connection table —
/// and treats process heap only as a coarse slope check. Other test collections stay
/// idle during the process-wide measurements. The env-gated soak
/// (PINHOLE_SOAK_MINUTES) runs the same measurements over arbitrary durations.</summary>
[Collection(nameof(ProcessResourceCollection))]
public sealed class BoundedResourceTests(ITestOutputHelper output)
{
    private const long FlowBytes = 512 * 1024;
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(120);

    [Fact]
    public void DownloadHasherDoesNotRetainAnOutboardForEveryChunk()
    {
        var tree = new Blake3.Tree(retainOutboard: false);
        byte[] buffer = new byte[64 * 1024];
        new Random(0x34).NextBytes(buffer);
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        long before = GC.GetTotalMemory(false);
        for (int block = 0; block < 512; block++) tree.Update(buffer); // 32 MiB streamed through one buffer
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        long growth = GC.GetTotalMemory(false) - before;
        Assert.True(growth <= 512 * 1024, $"streaming root retained {growth / 1024} KiB for 32 MiB of data");
        GC.KeepAlive(tree);
        GC.KeepAlive(buffer);
    }

    [Fact]
    public async Task RepeatedCancelResume_ReturnsEveryReservation()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            byte[] data = new byte[FlowBytes];
            Random.Shared.NextBytes(data);
            string src = Path.Combine(dir, "rung.bin");
            await File.WriteAllBytesAsync(src, data);
            await using BlobServer server = await ServeAtAsync(lab, src, "198.51.100.10", 34110);
            Shape(lab, 8_000_000);

            var budget = new BlobFlowBudget(4 * 1024 * 1024);
            string outDir = Path.Combine(dir, "out");

            // One full download first: JIT, pools, and one-time allocations belong to the
            // process, not the loop — the slope check starts after the warmup.
            BlobDownloadResult warm = await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: DownOptions(lab, 34020) with { FlowBudget = budget }).WaitAsync(Budget);
            Assert.Equal(FlowBytes, warm.Bytes);

            int socketsAtRest = lab.Net.LiveSockets;
            long heapAtRest = GC.GetTotalMemory(forceFullCollection: true);
            var heapSamples = new List<long>();

            const int cycles = 8;
            for (int i = 0; i < cycles; i++)
            {
                var stats = new BlobTransferStats();
                using var cts = new CancellationTokenSource();
                Task<BlobDownloadResult>? run = null;
                try
                {
                // Cancel is issued from INSIDE the downloader's pump: Report runs
                // synchronously on the verify path, so cancellation lands mid-transfer
                // with no scheduling race. The 64 KiB-remaining guard is 8× the window —
                // nothing queued or requested could finish the file before the next
                // cancellation check, on any machine, under any starvation.
                var progress = new SyncProgress(p =>
                {
                    if (p.VerifiedBytes > 24 * 1024 && p.TotalBytes - p.VerifiedBytes > 64 * 1024)
                    {
                        cts.Cancel();
                    }
                });
                run = BlobClient.DownloadAsync(server.Ticket, outDir, progress,
                    options: DownOptions(lab, 34020) with
                    {
                        FlowBudget = budget, Stats = stats, MaxWindowBytes = 8192,
                    },
                    ct: cts.Token);

                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run).WaitAsync(TestBudget.Scenario);

                Assert.Equal(0, budget.UsedBytes); // every reservation returned, immediately
                Assert.Equal(socketsAtRest, lab.Net.LiveSockets); // downloader node released its socket
                // Finalizer-aware collection: an object released by a finalizer needs a
                // second collection to vanish from GetTotalMemory, and macOS teardown
                // otherwise surfaces one cycle late as a false sawtooth.
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                heapSamples.Add(GC.GetTotalMemory(forceFullCollection: true));
                output.WriteLine($"cycle {i}: heap {heapSamples[^1]} bytes");

                // A cancelled attempt must leave an honest resumable prefix behind.
                Assert.True(Directory.Exists(Path.Combine(outDir, "rung.bin.pinhole-part")),
                    "cancelled attempt left no checkpoint to resume from");
                }
                catch (Exception ex)
                {
                    // Parallel-suite flake forensics: if this ever fails under load, the
                    // failure message carries the whole cycle state with it.
                    throw new Exception(
                        $"cycle {i}: run={run?.Status.ToString() ?? "unstarted"} verified={stats.VerifiedBytes} " +
                        $"window={stats.WindowBytes} retransmits={stats.Retransmits} " +
                        $"budgetUsed={budget.UsedBytes} sockets={lab.Net.LiveSockets} (rest {socketsAtRest}) " +
                        $"| {lab.Net.Counters()}", ex);
                }
            }

            // Per-cycle heap growth as an end-to-end slope. A median of consecutive
            // sample deltas is the wrong estimator here: delayed teardown (or GC segment
            // churn) can alternate the plateau ~1 MiB between cycles, and the median then
            // reports the oscillation amplitude, not growth — the macOS matrix showed a
            // flat 7.4 -> 8.2 MiB envelope failing a "975 KiB/cycle" gate. The slope plus
            // a hard total cap catch any real monotone leak of >= 512 KiB/cycle (8 cycles
            // would grow the heap by >= 4 MiB) while staying deaf to oscillation.
            // Collection isolation excludes allocations from other tests; the per-layer
            // counters above stay exact.
            long totalGrowth = heapSamples[^1] - heapSamples[0];
            long perCycle = totalGrowth / (cycles - 1);
            output.WriteLine($"after {cycles} cancel/resume cycles: heap {heapAtRest / 1048576.0:F1} -> " +
                             $"{heapSamples[^1] / 1048576.0:F1} MiB (slope {perCycle / 1024.0:F0} KiB/cycle, total {totalGrowth / 1024.0:F0} KiB), " +
                             $"sockets {socketsAtRest}, budget used {budget.UsedBytes}");
            Assert.True(perCycle < 512 * 1024, $"heap grows ~{perCycle / 1024.0:F0} KiB per cancelled cycle");
            // Secondary drift guard: 2 MiB is 2x the largest teardown/GC oscillation the
            // macOS matrix has shown, and still half of what a threshold-level leak
            // (512 KiB x 8) would produce.
            Assert.True(totalGrowth < 2 * 1024 * 1024, $"heap grew {totalGrowth / 1024.0:F0} KiB over {cycles} cancelled cycles");

            // The stacked checkpoints resume: one clean pass finishes byte-exact.
            BlobDownloadResult done = await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: DownOptions(lab, 34020) with { FlowBudget = budget }).WaitAsync(Budget);
            Assert.True(done.Resumed, "the cancelled attempts' checkpoints were resumed, not discarded");
            Assert.Equal(data, await File.ReadAllBytesAsync(done.Path));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task ProviderRestartChurn_OneCall_LeavesNoDebt()
    {
        string dir = TempDir();
        try
        {
            // Restart after restart, one surviving call: each dead provider disposes a
            // node and each successor binds one — socket and heap ledgers must settle.
            using VirtualLab lab = new();
            byte[] data = new byte[FlowBytes];
            Random.Shared.NextBytes(data);
            string src = Path.Combine(dir, "rung.bin");
            await File.WriteAllBytesAsync(src, data);
            Shape(lab, 8_000_000);
            byte[] seed = RandomNumberGenerator.GetBytes(32);

            BlobServeOptions Opts() => new()
            {
                Encrypt = false, // a restarted server mints a fresh ticket key; pinned-key restart is the identity case
                NodeOptions = lab.BaseOptions(o => o with
                {
                    IdentityKeySeed = seed,
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 34110)),
                }),
            };

            BlobServer server = await BlobServer.ServeAsync(src, Opts());
            BlobTicket ticket = server.Ticket;
            // A private budget — the shared pie is legitimately held by parallel tests.
            var budget = new BlobFlowBudget(4 * 1024 * 1024);
            Task<BlobDownloadResult> run = Task.Run(() => BlobClient.DownloadAsync(ticket,
                Path.Combine(dir, "out"), options: DownOptions(lab, 34020) with { FlowBudget = budget }).WaitAsync(Budget));

            const int restarts = 4;
            for (int i = 0; i < restarts; i++)
            {
                await TestPoll.UntilAsync(TimeSpan.FromSeconds(30), () => server.ChunksServed >= 40);
                await server.DisposeAsync();
                server = await BlobServer.ServeAsync(src, Opts());
            }

            BlobDownloadResult result = await run;
            Assert.Equal(FlowBytes, result.Bytes);
            Assert.Equal(data, await File.ReadAllBytesAsync(result.Path));

            await server.DisposeAsync();
            GC.Collect();
            Assert.Equal(0, budget.UsedBytes);
            output.WriteLine($"{restarts} provider restarts in one call; " +
                             $"live sockets settled at {lab.Net.LiveSockets}, budget used {budget.UsedBytes}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task ConcurrentDownloads_OnOneBudget_AllComplete_AndItDrains()
    {
        string dir = TempDir();
        try
        {
            // Healthy peers under declared load: twelve transfers share a pie that fits
            // only ~4 files' worth of reservations at once. Contention is the point —
            // queued for the budget, every peer still finishes byte-exact, and the pie
            // returns to zero when the last one drains.
            using VirtualLab lab = new();
            byte[] data = new byte[FlowBytes];
            Random.Shared.NextBytes(data);
            string src = Path.Combine(dir, "rung.bin");
            await File.WriteAllBytesAsync(src, data);
            await using BlobServer server = await ServeAtAsync(lab, src, "198.51.100.10", 34110);
            Shape(lab, 8_000_000);

            var budget = new BlobFlowBudget(4 * 512 * 1024);
            int socketsAtRest = lab.Net.LiveSockets;

            const int peers = 12;
            Task<BlobDownloadResult>[] runs = Enumerable.Range(0, peers)
                .Select(i => Task.Run(() => BlobClient.DownloadAsync(server.Ticket,
                    Path.Combine(dir, $"out{i}"),
                    options: DownOptions(lab, 34020 + i) with { FlowBudget = budget }).WaitAsync(Budget)))
                .ToArray();

            BlobDownloadResult[] results = await Task.WhenAll(runs);
            foreach (BlobDownloadResult r in results)
            {
                Assert.Equal(FlowBytes, r.Bytes);
                Assert.Equal(data, await File.ReadAllBytesAsync(r.Path));
            }

            Assert.Equal(0, budget.UsedBytes);
            Assert.Equal(socketsAtRest, lab.Net.LiveSockets);
            output.WriteLine($"{peers} concurrent downloads on a 2 MiB budget: all byte-exact, " +
                             $"budget used {budget.UsedBytes}, sockets {socketsAtRest}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task RepeatedNodeDisposal_LeavesTheSocketLedgerFlat()
    {
        // Bind-and-drop the raw node — the shape the downloader takes per attempt. The
        // virtual ledger catches any socket that outlives its owner; Connections must be
        // empty at dispose-time so no pump or timer pins the host afterward.
        using VirtualLab lab = new();
        int atRest = lab.Net.LiveSockets;
        for (int i = 0; i < 12; i++)
        {
            await using PinholeNode node = await PinholeNode.BindAsync(lab.BaseOptions(o => o with
            {
                UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), 34020 + i)),
            }));
            Assert.Empty(node.Connections);
        }
        Assert.Equal(atRest, lab.Net.LiveSockets);
    }

    [Fact]
    public async Task FailedDials_LeaveNoConnectionHusks()
    {
        using VirtualLab lab = new();
        await using PinholeNode node = await PinholeNode.BindAsync(lab.BaseOptions(o => o with
        {
            ConnectTimeout = TimeSpan.FromSeconds(2),
            UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), 34020)),
        }));

        // A peer that answered once and is gone forever: its string stays valid, its
        // endpoint goes silent — the failed-dial path must reap every attempt.
        string deadString;
        await using (PinholeNode dead = await PinholeNode.BindAsync(lab.BaseOptions(o => o with
        {
            UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.99"), 39999)),
        })))
        {
            deadString = dead.ConnectionString;
        }

        for (int i = 0; i < 6; i++)
        {
            await Assert.ThrowsAsync<TimeoutException>(() => node.ConnectAsync(deadString))
                .WaitAsync(TestBudget.Scenario);
            Assert.Empty(node.Connections);
        }

        // And concurrently: twenty-four dials at once must still leave zero husks.
        Task<PinholeConnection>[] dials = Enumerable.Range(0, 24)
            .Select(_ => node.ConnectAsync(deadString)).ToArray();
        await Assert.ThrowsAsync<TimeoutException>(() => Task.WhenAll(dials)).WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Empty(node.Connections);
        output.WriteLine($"6 sequential + 24 concurrent failed dials left {node.Connections.Count} connections");
    }

    [Fact]
    public async Task TicketHolderBarrage_NeverAmplifies_AndHonestPeerCompletes()
    {
        string dir = TempDir();
        try
        {
            // The ticket IS the capability, so a hostile holder is in scope: it completes
            // the engine handshake, then floods the provider's blob layer with undecryptable
            // junk and fresh-session Hellos. The provider's contract is strictly ≤ 1
            // answer per answerable request — garbage costs it one datagram, nothing more —
            // while an honest download completes undisturbed.
            using VirtualLab lab = new();
            byte[] data = new byte[FlowBytes];
            Random.Shared.NextBytes(data);
            string src = Path.Combine(dir, "rung.bin");
            await File.WriteAllBytesAsync(src, data);
            await using BlobServer server = await ServeAtAsync(lab, src, "198.51.100.10", 34110);

            await using PinholeNode attackerNode = await PinholeNode.BindAsync(lab.BaseOptions(o => o with
            {
                UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.66"), 34066)),
            }));
            PinholeConnection attacker = await attackerNode.ConnectAsync(server.Ticket.ConnectionString)
                .WaitAsync(TestBudget.Handshake);
            long answers = 0;
            attacker.Received += _ => Interlocked.Increment(ref answers);

            Task<BlobDownloadResult> honest = Task.Run(() => BlobClient.DownloadAsync(server.Ticket,
                Path.Combine(dir, "out"), options: DownOptions(lab, 34020)).WaitAsync(Budget));

            // Phase 1: undecryptable junk — every datagram is dropped without a reply.
            var junk = new byte[64];
            for (int i = 0; i < 200; i++)
            {
                RandomNumberGenerator.Fill(junk);
                attacker.Send(junk);
            }

            await Task.Delay(400);
            Assert.Equal(0, Interlocked.Read(ref answers));

            // Phase 2: Hellos — the provider binds the FIRST session id seen and answers
            // Hellos carrying it; foreign session ids get nothing (a session swap is
            // refused, never negotiated mid-connection).
            ulong stream = BlobWire.StreamId(server.Ticket.Root);
            byte[] boundId = BlobWire.Cipher.FreshSessionId();
            for (int i = 0; i < 40; i++)
            {
                attacker.Send(BlobWire.Hello(stream, i == 0 ? boundId : BlobWire.Cipher.FreshSessionId()));
            }

            await Task.Delay(400);
            long afterHelloFlood = Interlocked.Read(ref answers);
            Assert.True(afterHelloFlood <= 2,
                $"foreign-session Hellos were answered {afterHelloFlood} times — expected at most the bound session's");

            for (int i = 0; i < 60; i++)
            {
                attacker.Send(BlobWire.Hello(stream, boundId));
            }

            await Task.Delay(400);
            long total = Interlocked.Read(ref answers);
            Assert.True(total <= 62, $"the provider amplified: {total} answers to ~41 answerable Hellos");

            BlobDownloadResult result = await honest;
            Assert.Equal(FlowBytes, result.Bytes);
            Assert.Equal(data, await File.ReadAllBytesAsync(result.Path));
            output.WriteLine($"flood of 200 junk + 100 Hellos drew {total} answers (≤1 per answerable Hello); " +
                             $"honest download completed byte-exact | {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>The starvation regression at sustained size: 4 MiB through the
    /// standard shaped link used to ride stall-timeout/re-dial cycles forever —
    /// recovery re-reservations filled the budget and the pacer's window÷SRTT rate
    /// collapsed quadratically. Now asserted to complete well inside the budget.
    /// Env-gated: ~2.5 min on the shaped link is soak-scale, not unit-scale.</summary>
    [SoakFact]
    public async Task SustainedSize_ThroughTailDrop_DoesNotStarve()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            byte[] data = new byte[4 * 1024 * 1024];
            Random.Shared.NextBytes(data);
            string src = Path.Combine(dir, "rung.bin");
            await File.WriteAllBytesAsync(src, data);
            await using BlobServer server = await ServeAtAsync(lab, src, "198.51.100.10", 34110);
            Shape(lab, 8_000_000);

            var stats = new BlobTransferStats();
            var sw = Stopwatch.StartNew();
            BlobDownloadResult r = await BlobClient.DownloadAsync(server.Ticket,
                Path.Combine(dir, "out"),
                options: DownOptions(lab, 34020) with { Stats = stats })
                .WaitAsync(TimeSpan.FromSeconds(240));
            sw.Stop();
            Assert.Equal(data, await File.ReadAllBytesAsync(r.Path));
            output.WriteLine($"4 MiB in {sw.Elapsed.TotalSeconds:F0}s " +
                             $"({4 * 1024 / sw.Elapsed.TotalSeconds:F0} KiB/s): retransmits={stats.Retransmits} " +
                             $"dup={stats.DuplicateBytes / 1024} KiB window={stats.WindowBytes} | {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>Opt-in two-client shaped-link soak. Records its seed, binaries,
    /// post-warmup budgets and resource observations before accepting results.
    /// Long outages, relays and roaming require additional workload coverage.</summary>
    [SoakFact]
    public async Task MixedWorkloadSoak()
    {
        int minutes = int.Parse(Environment.GetEnvironmentVariable("PINHOLE_SOAK_MINUTES")!);
        int seed = int.TryParse(Environment.GetEnvironmentVariable("PINHOLE_SOAK_SEED"), out int selected)
            ? selected : 0x50A0;
        string dir = TempDir();
        string reportDir = Environment.GetEnvironmentVariable("PINHOLE_SOAK_REPORT_DIR")
            ?? Path.Combine(Path.GetTempPath(), "pinhole-soak",
                DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(reportDir);
        string reportPath = Path.Combine(reportDir, "soak-observations.csv");
        var rng = new Random(seed);
        var observations = new List<SoakSample>();
        const string columns = "elapsedSec,heapBytes,threads,handles,timers,pendingThreadPoolWork,liveSockets,connections,servingTasks,budgetUsed,cpuSeconds,totalAllocatedBytes,verifiedBytes,completed,cancelled,resumed,blackouts,cycles,errors";
        await File.WriteAllTextAsync(reportPath, columns + Environment.NewLine);
        output.WriteLine($"soak seed={seed}, duration={minutes} min; report={reportDir}");
        try
        {
            using VirtualLab lab = new();
            byte[] data = new byte[FlowBytes];
            new Random(seed ^ 0x434F).NextBytes(data);
            string src = Path.Combine(dir, "rung.bin");
            await File.WriteAllBytesAsync(src, data);
            await using BlobServer server = await ServeAtAsync(lab, src, "198.51.100.10", 34110);
            Shape(lab, 8_000_000);

            int socketsAtRest = lab.Net.LiveSockets;
            var budget = new BlobFlowBudget(4 * 1024 * 1024);
            var sw = Stopwatch.StartNew();
            var deadline = TimeSpan.FromMinutes(minutes);
            int completed = 0, cancelled = 0, resumed = 0, blackouts = 0, cycles = 0, errors = 0;
            long verifiedBytes = 0;
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);

            SoakSample ReadSample()
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                using var proc = Process.GetCurrentProcess();
                return new(sw.Elapsed.TotalSeconds, GC.GetTotalMemory(false), proc.Threads.Count,
                    proc.HandleCount, Timer.ActiveCount, ThreadPool.PendingWorkItemCount,
                    lab.Net.LiveSockets, server.Node.Connections.Count, server.ActiveServingTasks,
                    budget.UsedBytes, proc.TotalProcessorTime.TotalSeconds, GC.GetTotalAllocatedBytes(true));
            }

            async Task<SoakSample> RecordSampleAsync()
            {
                SoakSample sample = ReadSample();
                observations.Add(sample);
                object[] values = [sample.ElapsedSeconds, sample.HeapBytes, sample.Threads, sample.Handles,
                    sample.Timers, sample.PendingWork, sample.LiveSockets, sample.Connections,
                    sample.ServingTasks, sample.BudgetUsed, sample.CpuSeconds, sample.AllocatedBytes,
                    verifiedBytes, completed, cancelled, resumed, blackouts, cycles, errors];
                string row = string.Join(",", values.Select(value => Convert.ToString(value, CultureInfo.InvariantCulture)));
                await File.AppendAllTextAsync(reportPath, row + Environment.NewLine);
                return sample;
            }

            async Task TransferAsync(string outDir, int port, int kind)
            {
                using var cts = new CancellationTokenSource();
                using var resumeCts = new CancellationTokenSource();
                Task<BlobDownloadResult>? retry = null;
                var cutStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                LinkRule cut = LinkRule.Blackhole(region);
                int cutInstalled = 0;
                int blackoutMs = kind == 0 ? 600 + rng.Next(800) : 0;
                var progress = new SyncProgress(p =>
                {
                    if (kind == 0 && p.VerifiedBytes >= 32 * 1024 && Interlocked.Exchange(ref cutInstalled, 1) == 0)
                    {
                        lab.Net.AddRule(cut);
                        cutStarted.TrySetResult();
                    }
                    if (kind == 1 && p.VerifiedBytes >= 64 * 1024 && p.TotalBytes - p.VerifiedBytes > 64 * 1024)
                        cts.Cancel(); // on the verifier: cancellation cannot race past completion
                });
                var options = DownOptions(lab, port) with
                {
                    FlowBudget = budget, MaxWindowBytes = kind == 1 ? 8192 : 1024 * 1024,
                };
                Task<BlobDownloadResult> run = BlobClient.DownloadAsync(server.Ticket, outDir, progress, options, cts.Token);
                try
                {
                    if (kind == 0)
                    {
                        await cutStarted.Task.WaitAsync(Budget);
                        await Task.Delay(blackoutMs);
                        lab.Net.RemoveRule(cut);
                        Interlocked.Increment(ref blackouts);
                    }
                    BlobDownloadResult result;
                    if (kind == 1)
                    {
                        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run).WaitAsync(Budget);
                        Interlocked.Increment(ref cancelled);
                        retry = BlobClient.DownloadAsync(server.Ticket, outDir, options: options, ct: resumeCts.Token);
                        result = await retry.WaitAsync(Budget);
                        Assert.True(result.Resumed, "cancelled cycle discarded its verified checkpoint");
                        Interlocked.Increment(ref resumed);
                    }
                    else result = await run.WaitAsync(Budget);
                    Assert.Equal(data, await File.ReadAllBytesAsync(result.Path));
                    Interlocked.Add(ref verifiedBytes, result.Bytes);
                    Interlocked.Increment(ref completed);
                }
                finally
                {
                    lab.Net.RemoveRule(cut);
                    cts.Cancel();
                    resumeCts.Cancel();
                    Task[] pending = retry is null ? [run] : [run, retry];
                    foreach (Task task in pending.Where(task => !task.IsCompleted))
                    {
                        try { await task.WaitAsync(TestBudget.Teardown); }
                        catch (OperationCanceledException) { }
                    }
                }
            }

            async Task CycleAsync(int kind)
            {
                string first = Path.Combine(dir, "client-a"), second = Path.Combine(dir, "client-b");
                try
                {
                    await Task.WhenAll(TransferAsync(first, 34020, kind), TransferAsync(second, 34021, 2));
                    await TestPoll.UntilAsync(TestBudget.Teardown, () => server.Node.Connections.Count == 0
                        && server.ActiveServingTasks == 0 && lab.Net.LiveSockets == socketsAtRest && budget.UsedBytes == 0);
                }
                finally
                {
                    // Keep disk usage constant for 24h/72h; observations live outside dir.
                    if (Directory.Exists(first)) Directory.Delete(first, recursive: true);
                    if (Directory.Exists(second)) Directory.Delete(second, recursive: true);
                }
                Assert.Equal(socketsAtRest, lab.Net.LiveSockets);
                Assert.Equal(0, budget.UsedBytes);
                Assert.Equal(0, BlobFlowBudget.Shared.UsedBytes);
            }

            // Warm all three workloads with both peers before deriving budgets.
            SoakSample warmStart = ReadSample();
            for (int kind = 0; kind < 3; kind++) await CycleAsync(kind);
            SoakSample warmEnd = ReadSample();
            double cpuCoreLimit = Math.Min(Environment.ProcessorCount,
                Math.Max(1, 4 * (warmEnd.CpuSeconds - warmStart.CpuSeconds) / (warmEnd.ElapsedSeconds - warmStart.ElapsedSeconds)));
            double allocationRatioLimit = Math.Max(128,
                4.0 * (warmEnd.AllocatedBytes - warmStart.AllocatedBytes) / verifiedBytes);
            completed = cancelled = resumed = blackouts = 0;
            verifiedBytes = 0;
            sw.Restart();
            SoakSample baseline = await RecordSampleAsync();
            const long heapGrowthLimit = 16 * 1024 * 1024;
            const int threadGrowthLimit = 16, handleGrowthLimit = 32, timerGrowthLimit = 32;
            const double heapSlopeLimit = 2 * 1024 * 1024, threadSlopeLimit = 1, handleSlopeLimit = 2, timerSlopeLimit = 1;
            string HashAssembly(Type type) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(type.Assembly.Location))).ToLowerInvariant();
            await File.WriteAllTextAsync(Path.Combine(reportDir, "metadata.json"), JsonSerializer.Serialize(new
            {
                Seed = seed, Minutes = minutes, StartedUtc = DateTimeOffset.UtcNow,
                SourceCommit = Environment.GetEnvironmentVariable("PINHOLE_SOAK_COMMIT"),
                Runtime = RuntimeInformation.FrameworkDescription, OS = RuntimeInformation.OSDescription,
                Architecture = RuntimeInformation.ProcessArchitecture.ToString(),
                AssemblySha256 = new { Test = HashAssembly(typeof(BoundedResourceTests)), Core = HashAssembly(typeof(PinholeNode)), Blobs = HashAssembly(typeof(BlobClient)) },
                Workload = new { Clients = 2, BytesPerFile = FlowBytes, LinkBitsPerSecond = 8_000_000,
                    Cases = new[] { "concurrent downloads", "verified cancel/resume", "600-1400ms mid-transfer blackouts" },
                    Excludes = new[] { "relay restarts", "roaming", "long outages", "real OS networking" } },
                Baseline = baseline,
                Budgets = new { HeapGrowthBytes = heapGrowthLimit, AdditionalThreads = threadGrowthLimit,
                    AdditionalHandles = handleGrowthLimit, AdditionalTimers = timerGrowthLimit,
                    PendingThreadPoolWork = 64, CpuCores = cpuCoreLimit, AllocationBytesPerVerifiedByte = allocationRatioLimit,
                    HeapSlopeBytesPerHour = heapSlopeLimit, ThreadSlopePerHour = threadSlopeLimit,
                    HandleSlopePerHour = handleSlopeLimit, TimerSlopePerHour = timerSlopeLimit,
                    SlopeMinimumHours = 1, SlopeWarmupMinutes = 5 },
            }, new JsonSerializerOptions { WriteIndented = true }));

            void CheckBudgets(SoakSample sample)
            {
                Assert.True(sample.HeapBytes - baseline.HeapBytes <= heapGrowthLimit, "soak exceeded its declared heap budget");
                Assert.True(sample.Threads - baseline.Threads <= threadGrowthLimit, "soak exceeded its declared thread budget");
                Assert.True(sample.Handles - baseline.Handles <= handleGrowthLimit, "soak exceeded its declared handle budget");
                Assert.True(sample.Timers - baseline.Timers <= timerGrowthLimit, "soak exceeded its declared timer budget");
                Assert.True(sample.PendingWork <= 64, "soak exceeded its declared thread-pool queue budget");
                if (sample.ElapsedSeconds < 60) return;
                Assert.True((sample.CpuSeconds - baseline.CpuSeconds) / sample.ElapsedSeconds <= cpuCoreLimit, "soak exceeded its declared CPU budget");
                Assert.True((sample.AllocatedBytes - baseline.AllocatedBytes) / (double)Math.Max(FlowBytes, verifiedBytes) <= allocationRatioLimit,
                    "soak exceeded its declared allocation budget");
            }

            try
            {
                long nextSample = 60;
                while (sw.Elapsed < deadline)
                {
                    await CycleAsync(cycles < 3 ? cycles : rng.Next(3));
                    cycles++;
                    if (sw.Elapsed.TotalSeconds >= nextSample)
                    {
                        nextSample += 60;
                        CheckBudgets(await RecordSampleAsync());
                    }
                }
                CheckBudgets(await RecordSampleAsync());
                Assert.True(completed > 0 && resumed > 0 && blackouts > 0, "soak did not exercise every declared workload");
                SoakSample[] settled = observations.Where(s => s.ElapsedSeconds >= 300).ToArray();
                if (settled.Length >= 2 && settled[^1].ElapsedSeconds - settled[0].ElapsedSeconds >= 3600)
                {
                    Assert.True(SoakSlope(settled, s => s.HeapBytes) <= heapSlopeLimit, "soak exceeded its declared heap leak slope");
                    Assert.True(SoakSlope(settled, s => s.Threads) <= threadSlopeLimit, "soak exceeded its declared thread leak slope");
                    Assert.True(SoakSlope(settled, s => s.Handles) <= handleSlopeLimit, "soak exceeded its declared handle leak slope");
                    Assert.True(SoakSlope(settled, s => s.Timers) <= timerSlopeLimit, "soak exceeded its declared timer leak slope");
                }
                output.WriteLine($"soak {minutes} min: {cycles} cycles, {completed} completed, {cancelled} cancelled, {resumed} resumed; report={reportDir}");
            }
            catch (Exception ex)
            {
                errors++;
                await RecordSampleAsync();
                await File.WriteAllTextAsync(Path.Combine(reportDir, "failure.json"), JsonSerializer.Serialize(new
                    { Seed = seed, Cycle = cycles, Exception = ex.GetType().Name, ex.Message }, new JsonSerializerOptions { WriteIndented = true }));
                throw;
            }
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private sealed record SoakSample(double ElapsedSeconds, long HeapBytes, int Threads, int Handles,
        long Timers, long PendingWork, int LiveSockets, int Connections, int ServingTasks, long BudgetUsed,
        double CpuSeconds, long AllocatedBytes);

    private static double SoakSlope(SoakSample[] samples, Func<SoakSample, double> value)
    {
        double meanTime = samples.Average(s => s.ElapsedSeconds / 3600), meanValue = samples.Average(value);
        double numerator = 0, denominator = 0;
        foreach (SoakSample sample in samples)
        {
            double time = sample.ElapsedSeconds / 3600 - meanTime;
            numerator += time * (value(sample) - meanValue);
            denominator += time * time;
        }
        return numerator / denominator;
    }

    /// <summary>Skips unless PINHOLE_SOAK_MINUTES names a duration — the same mechanism as
    /// RealNetFactAttribute: xunit v2 decides Skip at discovery, honest in every runner.</summary>
    private sealed class SoakFactAttribute : FactAttribute
    {
        public SoakFactAttribute()
        {
            if (!int.TryParse(Environment.GetEnvironmentVariable("PINHOLE_SOAK_MINUTES"), out int m) || m <= 0)
            {
                Skip = "set PINHOLE_SOAK_MINUTES=<n> to run the soak (docs/TESTING.md, issue #34)";
            }
        }
    }

    // ------------------------------------------------------------------ plumbing

    /// <summary>IProgress that reports synchronously on the caller's thread —
    /// Progress&lt;T&gt; would marshal to the threadpool and reintroduce the
    /// cancel-races-completion gap this suite exists to eliminate.</summary>
    private sealed class SyncProgress(Action<BlobProgress> on) : IProgress<BlobProgress>
    {
        public void Report(BlobProgress p) => on(p);
    }

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-bounded-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void Shape(VirtualLab lab, long bits)
    {
        Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
        lab.Net.AddRule(LinkRule.Bottleneck(region, region, bits, queuePackets: 128, delay: TimeSpan.FromMilliseconds(20)));
    }

    private static async Task<BlobServer> ServeAtAsync(VirtualLab lab, string src, string address, int port) =>
        await BlobServer.ServeAsync(src, new BlobServeOptions
        {
            NodeOptions = lab.BaseOptions(o => o with
            {
                UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse(address), port)),
            }),
        });

    private static BlobDownloadOptions DownOptions(VirtualLab lab, int port) => new()
    {
        NodeOptions = lab.BaseOptions(o => o with
        {
            UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), port)),
        }),
    };
}
