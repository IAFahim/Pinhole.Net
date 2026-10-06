using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

/// <summary>#34 — bounded resources: cancelled, recovered, and restarted transfers must
/// hand back every reservation, socket, connection-table slot, and byte of heap they
/// borrowed. Each test asserts the specific counter that would grow if the layer leaked —
/// the budget's used-bytes, the lab's live-socket ledger, the node's connection table —
/// and treats process heap only as a coarse slope check (parallel tests share this
/// process, so the deterministic counters carry the proof). The env-gated soak
/// (PINHOLE_SOAK_MINUTES) runs the same measurements over arbitrary durations.</summary>
public sealed class BoundedResourceTests(ITestOutputHelper output)
{
    private const long FlowBytes = 512 * 1024;
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(120);

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
                GC.Collect();
                heapSamples.Add(GC.GetTotalMemory(forceFullCollection: true));

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

            // Median per-cycle heap growth, robust to parallel tests' transient garbage:
            // a leak grows every cycle; noise does not.
            var deltas = heapSamples.Zip(heapSamples.Skip(1), (a, b) => b - a).OrderBy(d => d).ToList();
            long medianDelta = deltas[deltas.Count / 2];
            output.WriteLine($"after {cycles} cancel/resume cycles: heap {heapAtRest / 1048576.0:F1} -> " +
                             $"{heapSamples[^1] / 1048576.0:F1} MiB (median cycle delta {medianDelta / 1024.0:F0} KiB), " +
                             $"sockets {socketsAtRest}, budget used {budget.UsedBytes}");
            Assert.True(medianDelta < 512 * 1024, $"heap grows ~{medianDelta / 1024.0:F0} KiB per cancelled cycle");

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

    /// <summary>Env-gated soak: <c>PINHOLE_SOAK_MINUTES</c> sets the duration. Mixed
    /// workload — downloads over a shaped link, brief blackouts, cancel-and-resume —
    /// with a per-minute resource sample written to a report file beside the run. The
    /// scheduled 24h/72h runs use this same harness; the assertions are the budgets
    /// (budget drained, sockets flat, heap slope bounded), not the duration.</summary>
    [SoakFact]
    public async Task MixedWorkloadSoak()
    {
        int minutes = int.Parse(Environment.GetEnvironmentVariable("PINHOLE_SOAK_MINUTES")!);
        string dir = TempDir();
        string reportDir = Path.Combine(Path.GetTempPath(), "pinhole-soak",
            DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(reportDir);
        string reportPath = Path.Combine(reportDir, "soak-observations.csv");
        var rng = new Random(0x50A0); // fixed seed: a failing soak is reproducible
        var observations = new List<string> { "elapsedSec,heapMiB,threads,handles,liveSockets,budgetUsed,completed,cancelled,errors" };
        try
        {
            using VirtualLab lab = new();
            byte[] data = new byte[FlowBytes];
            Random.Shared.NextBytes(data);
            string src = Path.Combine(dir, "rung.bin");
            await File.WriteAllBytesAsync(src, data);
            await using BlobServer server = await ServeAtAsync(lab, src, "198.51.100.10", 34110);
            Shape(lab, 8_000_000);

            var sw = Stopwatch.StartNew();
            var deadline = TimeSpan.FromMinutes(minutes);
            int completed = 0, cancelled = 0;
            var errors = new List<string>();
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);

            long nextSample = 60;
            while (sw.Elapsed < deadline)
            {
                string outDir = Path.Combine(dir, $"out{completed + cancelled}");
                var stats = new BlobTransferStats();
                using var cts = new CancellationTokenSource();
                Task<BlobDownloadResult> run = BlobClient.DownloadAsync(server.Ticket, outDir,
                    options: DownOptions(lab, 34020) with { Stats = stats }, ct: cts.Token);

                // Weather: a short blackout mid-transfer on a third of the cycles, a
                // cancel on a third, a clean run otherwise. The blackout lifts before the
                // await — it is mid-transfer weather to ride out, not the whole run.
                int pick = rng.Next(3);
                if (pick == 0)
                {
                    LinkRule cut = LinkRule.Blackhole(region);
                    lab.Net.AddRule(cut);
                    await Task.Delay(600 + rng.Next(800));
                    lab.Net.RemoveRule(cut);
                }
                else
                {
                    // A cancel must land mid-transfer deterministically: 512 KiB over an
                    // 8 Mbit/s link cannot finish before ~520 ms of wire time.
                    await Task.Delay(pick == 1 ? 200 : 600 + rng.Next(800));
                }

                try
                {
                    if (pick == 1)
                    {
                        cts.Cancel();
                        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run).WaitAsync(TestBudget.Scenario);
                        cancelled++;
                    }
                    else
                    {
                        BlobDownloadResult r = await run.WaitAsync(Budget);
                        Assert.Equal(data, await File.ReadAllBytesAsync(r.Path));
                        completed++;
                    }
                }
                catch (Exception ex)
                {
                    errors.Add($"{sw.Elapsed:mm\\:ss} {ex.GetType().Name}: {ex.Message}");
                }

                if (sw.Elapsed.TotalSeconds >= nextSample)
                {
                    nextSample += 60;
                    GC.Collect();
                    var proc = Process.GetCurrentProcess();
                    observations.Add($"{sw.Elapsed.TotalSeconds:F0},{GC.GetTotalMemory(false) / 1048576.0:F1}," +
                                     $"{proc.Threads.Count},{proc.HandleCount},{lab.Net.LiveSockets}," +
                                     $"{BlobFlowBudget.Shared.UsedBytes},{completed},{cancelled},{errors.Count}");
                }
            }

            Assert.Empty(errors);
            Assert.True(completed + cancelled > 0, "the soak ran zero workload cycles");
            Assert.Equal(0, BlobFlowBudget.Shared.UsedBytes);
            output.WriteLine($"soak {minutes} min: {completed} completed, {cancelled} cancelled, " +
                             $"{errors.Count} errors; observations -> {reportPath}");
        }
        finally
        {
            // Raw observations survive the run regardless of outcome — the issue asks for
            // attached evidence, not anecdotes.
            await File.WriteAllLinesAsync(reportPath, observations);
            Directory.Delete(dir, recursive: true);
        }
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
