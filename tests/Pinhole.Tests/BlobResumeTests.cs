using System.Diagnostics;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;
using Pinhole.Sim;

namespace Pinhole.Tests;

public sealed class BlobResumeTests(ITestOutputHelper output)
{
    private const long FlowBytes = 512 * 1024;
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(120);

    [Fact]
    public async Task ThirtySecondBlackhole_SameCall_RidesOutAndCompletes()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = await LabAsync(dir);
            await using BlobServer server = await ServeAsync(lab, dir);
            Shape(lab, 8_000_000);
            var stats = new BlobTransferStats();
            var sw = Stopwatch.StartNew();
            Task<BlobDownloadResult> run = Task.Run(() => DownloadAsync(lab, server, dir, stats));

            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            LinkRule cut = LinkRule.Blackhole(region);
            lab.Net.AddRule(cut);
            await Task.Delay(TimeSpan.FromSeconds(30));
            lab.Net.RemoveRule(cut);

            BlobDownloadResult result = await run.WaitAsync(Budget);
            sw.Stop();
            Assert.Equal(FlowBytes, result.Bytes);
            output.WriteLine($"30 s total blackout survived in one call ({sw.Elapsed.TotalSeconds:F0}s total), " +
                             $"{stats.Retransmits} retransmits, {stats.ConservativeResumes} conservative resumes");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task DirectPathCut_MidTransfer_CompletesThroughTheRelay()
    {
        string dir = TempDir();
        try
        {

            using var lab = new VirtualLab(withTurn: true);
            await using BlobServer server = await ServeAtAsync(lab, dir, "198.51.100.10", 34010);
            Shape(lab, 8_000_000);
            Task<BlobDownloadResult> run = Task.Run(() => BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
                options: DownOptions(lab, 34020)).WaitAsync(Budget));
            await Task.Delay(600);

            var a = Subnet.Parse("198.51.100.10/32");
            var b = Subnet.Parse("198.51.100.20/32");
            lab.Net.AddRule(LinkRule.Directional(a, b, dropAll: true));
            lab.Net.AddRule(LinkRule.Directional(b, a, dropAll: true));

            BlobDownloadResult result = await run;
            Assert.Equal(FlowBytes, result.Bytes);
            output.WriteLine($"direct path cut mid-transfer; completed through the relay in one call | {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task ProviderRebindAndBlackout_MidTransfer_SameCallCompletes()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = await LabAsync(dir);
            await using BlobServer server = await ServeAtAsync(lab, dir, "198.51.100.10", 34110);
            Shape(lab, 8_000_000);
            Task<BlobDownloadResult> run = Task.Run(() => DownloadAsync(lab, server, dir));

            await Task.Delay(700);
            await server.Node.Engine.SimulateInterfaceLossAsync();

            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            LinkRule cut = LinkRule.Blackhole(region);
            lab.Net.AddRule(cut);
            await Task.Delay(TimeSpan.FromSeconds(3));
            lab.Net.RemoveRule(cut);

            BlobDownloadResult result = await run.WaitAsync(Budget);
            Assert.Equal(FlowBytes, result.Bytes);
            output.WriteLine("provider rebind + 3 s blackout mid-transfer; completed in one call");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task ProviderRestart_SameTicket_ResumesFromCheckpointInOneCall()
    {
        string dir = TempDir();
        try
        {

            byte[] seed = RandomNumberGenerator.GetBytes(32);
            using VirtualLab lab = await LabAsync(dir);
            byte[] data = new byte[FlowBytes];
            Random.Shared.NextBytes(data);
            string src = Path.Combine(dir, "rung.bin");
            await File.WriteAllBytesAsync(src, data);
            Shape(lab, 8_000_000);

            Task<BlobDownloadResult> RunAsync(BlobServer from) =>
                BlobClient.DownloadAsync(from.Ticket, Path.Combine(dir, "out"),
                    options: DownOptions(lab, 34020));

            BlobServeOptions Opts() => new()
            {
                Encrypt = false,
                NodeOptions = lab.BaseOptions(o => o with
                {
                    IdentityKeySeed = seed,
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 34110)),
                }),
            };

            await using BlobServer server = await BlobServer.ServeAsync(src, Opts());

            server.DropChunk = index => index >= 120;
            Task<BlobDownloadResult> run = Task.Run(() => RunAsync(server).WaitAsync(Budget));

            string statePath = Path.Combine(dir, "out", "rung.bin.pinhole-part", "state");
            long savedPrefix = 0;
            await TestPoll.UntilAsync(TimeSpan.FromSeconds(20), () =>
            {
                try
                {

                    using var state = new FileStream(statePath, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);
                    if (state.Length != 56) return false;
                    Span<byte> body = stackalloc byte[56];
                    state.ReadExactly(body);
                    if (!body[..8].SequenceEqual("PBPART01"u8)) return false;
                    savedPrefix = BinaryPrimitives.ReadInt64LittleEndian(body[48..]);
                    return savedPrefix >= 120;
                }
                catch (IOException) { return false; }
            });
            await server.DisposeAsync();

            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            LinkRule cut = LinkRule.Blackhole(region);
            lab.Net.AddRule(cut);
            await using BlobServer successor = await BlobServer.ServeAsync(src, Opts());
            var requested = new ConcurrentQueue<long>();
            successor.DropChunk = index => { requested.Enqueue(index); return false; };
            lab.Net.RemoveRule(cut);

            BlobDownloadResult result = await run;
            Assert.Equal(FlowBytes, result.Bytes);
            Assert.True(result.Resumed);
            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(dir, "out", "rung.bin")));
            Assert.NotEmpty(requested);
            Assert.True(requested.Min() >= savedPrefix,
                $"successor requested chunk {requested.Min()} below saved prefix {savedPrefix}");
            output.WriteLine($"result.Resumed={result.Resumed}, successor connections={successor.ConnectionsAccepted}, " +
                             $"first-server connections={server.ConnectionsAccepted}");

            long totalChunks = data.Length / 1024;
            Assert.True(successor.ChunksServed < totalChunks + 120,
                $"the re-dial resumed from the checkpoint, not from zero (successor served {successor.ChunksServed}, "
                + $"first request {requested.Min()}, total {totalChunks})");
            output.WriteLine($"provider died and restarted; the original call re-dialed the same ticket and finished " +
                             $"({successor.ChunksServed} chunks served by the successor vs {savedPrefix} checkpointed before the death)");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task IncompatiblePeer_RefusalIsTerminal_NotRiddenOut()
    {
        string dir = TempDir();
        try
        {

            using VirtualLab lab = await LabAsync(dir);
            var v1 = new ConnectionString(0x1234,
                [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Parse("198.51.100.10"), 34110))]);
            var ticket = new BlobTicket
            {
                Kind = BlobKind.File,
                Root = RandomNumberGenerator.GetBytes(32),
                Name = "rung.bin",
                ConnectionString = v1.ToString(),
            };

            var sw = Stopwatch.StartNew();
            await Assert.ThrowsAsync<InvalidOperationException>(() => BlobClient.DownloadAsync(
                ticket, Path.Combine(dir, "out"), options: DownOptions(lab, 34020)).WaitAsync(Budget));
            sw.Stop();
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10),
                $"a refused handshake must surface promptly, not ride the 10 min recovery budget ({sw.Elapsed.TotalSeconds:F1}s)");
            output.WriteLine($"kepless peer refused terminally in {sw.Elapsed.TotalMilliseconds:F0} ms");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task TamperedFrame_IsTerminal_NeverRiddenOut()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = await LabAsync(dir);
            await using BlobServer server = await ServeAsync(lab, dir);
            server.CorruptChunk = (_, data) => data[0] ^= 0xFF;

            var sw = Stopwatch.StartNew();
            InvalidDataException ex = await Assert.ThrowsAsync<InvalidDataException>(
                () => DownloadAsync(lab, server, dir).WaitAsync(Budget));
            sw.Stop();
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(35),
                $"tampering must surface via the first bad chunk, not via recovery budgets ({sw.Elapsed.TotalSeconds:F0}s)");
            output.WriteLine($"tampered chunk failed verification terminally in {sw.Elapsed.TotalSeconds:F1}s: {ex.Message}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Cancellation_DuringBlackout_TerminatesPromptly()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = await LabAsync(dir);
            await using BlobServer server = await ServeAsync(lab, dir);
            using var cts = new CancellationTokenSource();
            Task run = DownloadAsync(lab, server, dir, ct: cts.Token);

            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            LinkRule cut = LinkRule.Blackhole(region);
            lab.Net.AddRule(cut);
            await Task.Delay(1000);
            var sw = Stopwatch.StartNew();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run).WaitAsync(TimeSpan.FromSeconds(10));
            sw.Stop();
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"cancellation took {sw.Elapsed.TotalSeconds:F1}s to be honored");
            output.WriteLine($"cancellation during a blackout honored in {sw.Elapsed.TotalMilliseconds:F0} ms");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task SessionRecreations_NeverReuseAKeyOrNoncePair()
    {
        string dir = TempDir();
        try
        {

            using VirtualLab lab = await LabAsync(dir);
            byte[] data = new byte[FlowBytes];
            Random.Shared.NextBytes(data);
            string src = Path.Combine(dir, "rung.bin");
            await File.WriteAllBytesAsync(src, data);
            await using BlobServer server = await BlobServer.ServeAsync(src, new BlobServeOptions
            {
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 34110)),
                }),
            });

            var nonces = new List<(byte[] Session, byte[] Nonce)>();
            BlobWire.WelcomeNonceSeen = (s, n) => { lock (nonces) { nonces.Add(((byte[])s.Clone(), (byte[])n.Clone())); } };
            try
            {
                server.DropChunk = idx => idx >= 80;
                var stats = new BlobTransferStats();
                Task<BlobDownloadResult> run = Task.Run(() => BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
                    null, new BlobDownloadOptions
                    {
                        NodeOptions = lab.BaseOptions(o => o with
                        {
                            UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), 34020)),
                        }),
                        Stats = stats,
                    }).WaitAsync(Budget));

                await TestPoll.UntilAsync(TimeSpan.FromSeconds(60), () => server.ConnectionsAccepted >= 2);
                server.DropChunk = null;
                BlobDownloadResult result = await run;
                Assert.Equal(FlowBytes, result.Bytes);

                lock (nonces)
                {
                    var perSession = nonces
                        .GroupBy(x => Convert.ToHexString(x.Session))
                        .ToDictionary(g => g.Key, g => g.Select(x => Convert.ToHexString(x.Nonce)).Distinct().ToList());
                    output.WriteLine($"{perSession.Count} sessions adopted {nonces.Count} Welcomes' provider nonces, " +
                                     $"{server.ConnectionsAccepted} connections");
                    Assert.True(perSession.Count >= 2, $"expected a recreated session after the stall, saw {perSession.Count}");

                    Assert.All(perSession.Values, v => Assert.Single(v));
                    Assert.Equal(perSession.Count, perSession.Values.Select(v => v[0]).Distinct().Count());
                }
            }
            finally
            {
                BlobWire.WelcomeNonceSeen = null;
            }
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task DirectoryTransfer_ProviderRestart_ManifestAndRootsCarryAcrossRedial()
    {
        string dir = TempDir();
        try
        {

            using VirtualLab lab = await LabAsync(dir);
            string tree = Path.Combine(dir, "tree");
            Directory.CreateDirectory(Path.Combine(tree, "sub"));
            var files = new Dictionary<string, byte[]>();
            for (int i = 0; i < 3; i++)
            {
                byte[] content = new byte[150 * 1024];
                Random.Shared.NextBytes(content);
                string rel = i == 0 ? "first.bin" : $"sub/file{i}.bin";
                await File.WriteAllBytesAsync(Path.Combine(tree, rel), content);
                files[rel] = content;
            }
            long totalChunks = files.Values.Sum(b => (b.Length + Blake3.ChunkSize - 1) / Blake3.ChunkSize);
            Shape(lab, 8_000_000);
            byte[] seed = RandomNumberGenerator.GetBytes(32);

            BlobServeOptions Opts() => new()
            {
                Encrypt = false,
                NodeOptions = lab.BaseOptions(o => o with
                {
                    IdentityKeySeed = seed,
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 34110)),
                }),
            };

            await using BlobServer server = await BlobServer.ServeAsync(tree, Opts());

            var filesDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var progress = new Progress<BlobProgress>(p =>
            {
                if (p.FilesDone >= 2 && p.VerifiedBytes > 320 * 1024)
                {
                    filesDone.TrySetResult();
                }
            });
            Task<BlobDownloadResult> run = Task.Run(() => BlobClient.DownloadAsync(server.Ticket,
                Path.Combine(dir, "out"), progress, options: DownOptions(lab, 34020)).WaitAsync(Budget));

            await filesDone.Task.WaitAsync(TestBudget.Scenario);
            await server.DisposeAsync();
            await using BlobServer successor = await BlobServer.ServeAsync(tree, Opts());

            BlobDownloadResult result = await run;
            foreach ((string rel, byte[] content) in files)
            {
                Assert.Equal(content, await File.ReadAllBytesAsync(Path.Combine(dir, "out", "tree", rel)));
            }
            Assert.True(result.Resumed, "the surviving call resumed from the pre-restart checkpoints");

            Assert.True(successor.ChunksServed < totalChunks,
                $"successor re-served the whole tree ({successor.ChunksServed} chunks vs total {totalChunks}) — no carry-over");
            output.WriteLine($"directory restart: successor served {successor.ChunksServed}/{totalChunks} chunks " +
                             $"(manifest fetched once, finished files skipped, in-flight file resumed)");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-resume-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static Task<VirtualLab> LabAsync(string dir) => Task.FromResult(new VirtualLab());

    private static void Shape(VirtualLab lab, long bits)
    {
        Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
        lab.Net.AddRule(LinkRule.Bottleneck(region, region, bits, queuePackets: 128, delay: TimeSpan.FromMilliseconds(20)));
    }

    private static async Task<BlobServer> ServeAtAsync(VirtualLab lab, string dir, string address, int port)
    {
        byte[] data = new byte[FlowBytes];
        Random.Shared.NextBytes(data);
        string src = Path.Combine(dir, "rung.bin");
        await File.WriteAllBytesAsync(src, data);
        return await BlobServer.ServeAsync(src, new BlobServeOptions
        {
            NodeOptions = lab.BaseOptions(o => o with
            {
                UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse(address), port)),
            }),
        });
    }

    private static Task<BlobServer> ServeAsync(VirtualLab lab, string dir) => ServeAtAsync(lab, dir, "198.51.100.10", 34010);

    private static BlobDownloadOptions DownOptions(VirtualLab lab, int port) => new()
    {
        NodeOptions = lab.BaseOptions(o => o with
        {
            UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), port)),
        }),
    };

    private static Task<BlobDownloadResult> DownloadAsync(VirtualLab lab, BlobServer server, string dir,
        BlobTransferStats? stats = null, CancellationToken ct = default) =>
        BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"), null,
            stats is null ? DownOptions(lab, 34020) : DownOptions(lab, 34020) with { Stats = stats }, ct);
}
