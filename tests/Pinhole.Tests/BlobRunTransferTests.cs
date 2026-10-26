using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

// R2 verified runs: behavioral gates for the v4 client/server path. Every run must
// chain to the ticket root before any of its bytes reach the disk, resume must be
// O(1) in the committed-run state, and every honest interop combination (v4/v4,
// v4/v3 fallback, v3/v4, plaintext) still completes byte-exact.
public sealed class BlobRunTransferTests
{
    private readonly ITestOutputHelper _output;

    public BlobRunTransferTests(ITestOutputHelper output) => _output = output;

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private static PinholeOptions Offline() => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [],
        DerpRelayUrls = [],
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false,
        EnablePortMapping = false,
    };

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-blob-runs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void DeleteDir(string dir)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                Directory.Delete(dir, recursive: true);
                return;
            }
            catch (IOException) when (attempt < 10)
            {
                Thread.Sleep(50);
            }
            catch (UnauthorizedAccessException) when (attempt < 10)
            {
                Thread.Sleep(50);
            }
        }
    }

    private static byte[] RandomBytes(long size)
    {
        var data = new byte[size];
        RandomNumberGenerator.Fill(data);
        return data;
    }

    // 300_000 bytes = 293 chunks = 4 full runs + a 37-chunk ragged tail.
    private const long MultiRunBytes = 300_000;

    // ---------------------------------------------------------------- gate 1: forged proofs

    [Fact]
    public async Task ForgedRun_NoVerifiedRunByteReachesTheDisk()
    {
        string dir = TempDir();
        try
        {
            string src = Path.Combine(dir, "forged.bin");
            await File.WriteAllBytesAsync(src, RandomBytes(MultiRunBytes));

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            server.CorruptProof = (_, runIndex, siblings) =>
            {
                if (runIndex == 2 && siblings.Length > 0)
                {
                    siblings[0] ^= 0x80; // every proof attempt for run 2 lies
                }
            };

            string outDir = Path.Combine(dir, "out");
            await Assert.ThrowsAsync<InvalidDataException>(() => BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() })).WaitAsync(Timeout);

            string target = Path.Combine(outDir, "forged.bin");
            Assert.False(File.Exists(target), "a forged run must never publish the target file");
            string dataPath = Path.Combine(target + ".pinhole-part", "data");
            Assert.True(File.Exists(dataPath), "the abandoned attempt left its part directory");
            // Only runs committed before the forgery may exist on disk: run 2 starts at
            // chunk 128, so the data file cannot extend past 128 KiB.
            Assert.True(new FileInfo(dataPath).Length <= 128 * 1024,
                $"part data extends to {new FileInfo(dataPath).Length} bytes past the first forged run");
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    // ---------------------------------------------------------------- gate 2: self-consistent CV lies

    [Fact]
    public async Task LyingChunkCvs_AreRejectedBeforeAnyWrite()
    {
        string dir = TempDir();
        try
        {
            string src = Path.Combine(dir, "lying.bin");
            await File.WriteAllBytesAsync(src, RandomBytes(MultiRunBytes));

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            // The lie is self-consistent: the data is flipped AND the frame's CV is
            // recomputed over the flipped bytes, so the per-chunk check passes and only
            // the run's root proof can catch it.
            server.CorruptChunk = (idx, data) =>
            {
                if (idx is >= 128 and < 192)
                {
                    data[0] ^= 0xFF;
                }
            };
            server.ReworkChunkCv = (idx, data) => idx is >= 128 and < 192
                ? Blake3.ChunkCv(data, (ulong)idx, root: false) // self-consistent lie
                : null; // null keeps the honest outboard CV

            string outDir = Path.Combine(dir, "out");
            await Assert.ThrowsAsync<InvalidDataException>(() => BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() })).WaitAsync(Timeout);

            string target = Path.Combine(outDir, "lying.bin");
            Assert.False(File.Exists(target), "a lying run must never publish the target file");
            string dataPath = Path.Combine(target + ".pinhole-part", "data");
            Assert.True(new FileInfo(dataPath).Length <= 128 * 1024,
                "no byte of the lying run may reach the disk before its root verifies");
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    // ---------------------------------------------------------------- gate 3: hostile Head bounds

    [Fact]
    public async Task HostileHead_IsBounded()
    {
        string dir = TempDir();
        try
        {
            byte[] root = RandomNumberGenerator.GetBytes(32);
            byte[] psk = RandomNumberGenerator.GetBytes(32);
            using var oracle = new LyingHeadOracle();
            oracle.Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var ticket = new BlobTicket
            {
                Kind = BlobKind.File,
                Root = root,
                Name = "huge.bin",
                ConnectionString = oracle.DialString,
                PreSharedKey = psk,
            };

            using var deadline = new CancellationTokenSource(Timeout);
            Task serve = oracle.ServeLyingHeadAsync(psk, root, BlobClient.MaxDeclaredTotalBytes + 1, deadline.Token);
            var watch = System.Diagnostics.Stopwatch.StartNew();
            InvalidDataException failure = await Assert.ThrowsAsync<InvalidDataException>(() => BlobClient.DownloadAsync(
                ticket, Path.Combine(dir, "out"),
                options: new BlobDownloadOptions { NodeOptions = Offline() with { EnablePathValidation = false } },
                ct: deadline.Token));
            watch.Stop();
            Assert.Contains("transfer bound", failure.Message, StringComparison.Ordinal);
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), "the bound fires at the Head, not after a stall");
            deadline.Cancel();
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public void ManifestMemory_IsBounded()
    {
        // The MemorySink bound is unit-tested directly: wiring a whole lying directory
        // server would duplicate the lying-Head oracle for one integer comparison.
        string dir = TempDir();
        try
        {
            var sink = new BlobClient.MemorySink();
            sink.UseVerifiedRuns();
            long chunks = BlobClient.MemorySink.MaxManifestBytes / Blake3.ChunkSize + 1;
            InvalidDataException failure = Assert.Throws<InvalidDataException>(() => sink.Init(chunks * Blake3.ChunkSize, chunks));
            Assert.Contains("in-memory bound", failure.Message, StringComparison.Ordinal);

            var honest = new BlobClient.MemorySink();
            honest.UseVerifiedRuns();
            honest.Init(1024, 1); // inside the bound: accepted
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    // ---------------------------------------------------------------- gate 4: O(1) resume

    [Fact]
    public async Task ResumeIsO1_NoPrefixRehash()
    {
        string dir = TempDir();
        try
        {
            string src = Path.Combine(dir, "o1.bin");
            await File.WriteAllBytesAsync(src, RandomBytes(400_000));

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            string outDir = Path.Combine(dir, "out");
            string target = Path.Combine(outDir, "o1.bin");
            string part = target + ".pinhole-part";

            using var cancelFirst = new CancellationTokenSource();
            server.DropChunk = idx => idx >= 130; // run 0 commits, the tail cannot finish
            Task firstRun = Task.Run(() => BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }, ct: cancelFirst.Token));
            await TestPoll.UntilAsync(Timeout, () =>
            {
                try
                {
                    byte[] state = File.ReadAllBytes(Path.Combine(part, "state"));
                    return state.Length > 61 && state.AsSpan(0, 8).SequenceEqual("PBPART02"u8) && (state[60] & 1) == 1;
                }
                catch (IOException) { return false; }
            });
            cancelFirst.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstRun).WaitAsync(Timeout);

            // Sink-level evidence (the rehash counter seam), taken while the interrupted
            // part state is still on disk: a v4 FileSink resuming the committed state
            // never reads or re-hashes the prefix — O(1) in the state file.
            byte[] data = await File.ReadAllBytesAsync(src);
            var resumedSink = new BlobClient.FileSink(target, server.Ticket.Root);
            resumedSink.UseVerifiedRuns();
            resumedSink.Init(400_000, 400_000 / Blake3.ChunkSize + (400_000 % Blake3.ChunkSize == 0 ? 0 : 1));
            Assert.True(resumedSink.Resumed);
            Assert.True(resumedSink.RunCommitted(0), "run 0 was checkpointed before the interrupt");
            Assert.False(resumedSink.RunCommitted(2), "run 2 never completed under the drop");
            Assert.Equal(0, resumedSink.RehashedPrefixChunks);
            resumedSink.Abandon();

            // Request-pattern evidence: record every chunk index the successor serves
            // from here on; the resume must start at or past the committed extent.
            var requested = new System.Collections.Concurrent.ConcurrentQueue<long>();
            server.DropChunk = idx => { requested.Enqueue(idx); return false; };

            BlobDownloadResult result = await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);

            Assert.True(result.Resumed, "the second call resumed from the committed-run state");
            Assert.Equal(data, await File.ReadAllBytesAsync(target));
            Assert.NotEmpty(requested);
            Assert.True(requested.Min() >= 64,
                $"the resume requested chunk {requested.Min()} below the committed bitmap extent (64)");
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public void RunStateResume_IsO1_AndSkipsNothingVerified()
    {
        // Pure sink-level check of the PBPART02 round-trip: commit runs, restart the
        // sink over the same part directory, and confirm the bitmap + fold state come
        // back without a single prefix read (RehashedPrefixChunks stays 0).
        string dir = TempDir();
        try
        {
            string target = Path.Combine(dir, "sink.bin");
            byte[] root = RandomNumberGenerator.GetBytes(32);
            const int chunks = 192; // 3 runs
            const long totalBytes = chunks * Blake3.ChunkSize;

            var first = new BlobClient.FileSink(target, root);
            first.UseVerifiedRuns();
            first.Init(totalBytes, chunks);
            byte[] chunk = RandomBytes(Blake3.ChunkSize);
            byte[] cv = RandomBytes(32);
            for (int r = 0; r < 2; r++) // a fully committed file never checkpoints
            {
                byte[][] run = Enumerable.Range(0, 64).Select(_ => chunk).ToArray();
                first.ApplyRun(r, 64, run, cv);
            }

            first.Checkpoint();
            Assert.Equal(1, first.CheckpointWrites);
            first.Abandon();

            var resumed = new BlobClient.FileSink(target, root);
            resumed.UseVerifiedRuns();
            resumed.Init(totalBytes, chunks);
            Assert.True(resumed.Resumed);
            Assert.Equal(128, resumed.Applied);
            Assert.Equal(0, resumed.RehashedPrefixChunks);
            Assert.True(resumed.RunCommitted(0) && resumed.RunCommitted(1) && !resumed.RunCommitted(2));
            resumed.Reject();
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public void TruncatedRunState_RestartsClean_AndLegacyStateIsIgnored()
    {
        string dir = TempDir();
        try
        {
            string target = Path.Combine(dir, "torn.bin");
            byte[] root = RandomNumberGenerator.GetBytes(32);
            const int chunks = 192;
            const long totalBytes = chunks * Blake3.ChunkSize;
            string part = target + ".pinhole-part";

            var writer = new BlobClient.FileSink(target, root);
            writer.UseVerifiedRuns();
            writer.Init(totalBytes, chunks);
            byte[][] run = Enumerable.Range(0, 64).Select(_ => RandomBytes(Blake3.ChunkSize)).ToArray();
            writer.ApplyRun(0, 64, run, RandomBytes(32));
            writer.Checkpoint();
            writer.Abandon();

            // The data file no longer covers the committed run: the state is void.
            using (var data = File.Open(Path.Combine(part, "data"), FileMode.Open, FileAccess.Write))
            {
                data.SetLength(1024);
            }

            var torn = new BlobClient.FileSink(target, root);
            torn.UseVerifiedRuns();
            torn.Init(totalBytes, chunks);
            Assert.False(torn.Resumed);
            Assert.Equal(0, torn.Applied);
            torn.Abandon();

            // A v3 PBPART01 state in the part directory is not resumed across formats.
            Directory.Delete(part, recursive: true);
            Directory.CreateDirectory(part);
            var legacy = new byte[56];
            "PBPART01"u8.CopyTo(legacy);
            root.CopyTo(legacy, 8);
            BinaryPrimitives.WriteInt64LittleEndian(legacy.AsSpan(40), totalBytes);
            BinaryPrimitives.WriteInt64LittleEndian(legacy.AsSpan(48), 64);
            File.WriteAllBytes(Path.Combine(part, "state"), legacy);
            File.WriteAllBytes(Path.Combine(part, "data"), RandomBytes(totalBytes));

            var mixed = new BlobClient.FileSink(target, root);
            mixed.UseVerifiedRuns();
            mixed.Init(totalBytes, chunks);
            Assert.False(mixed.Resumed);
            Assert.Equal(0, mixed.Applied);
            mixed.Abandon();
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    // ---------------------------------------------------------------- gate 5: adversarial matrix

    [Theory]
    [InlineData("corrupt-chunk")]
    [InlineData("lying-cv")]
    [InlineData("forged-proof")]
    [InlineData("dropped-proof")]
    [InlineData("duplicated-frames")]
    [InlineData("reordered-frames")]
    [InlineData("truncated")]
    public async Task AdversarialProvider_NeverPartiallyPublishes(string mode)
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(MultiRunBytes);
            string src = Path.Combine(dir, "adv.bin");
            await File.WriteAllBytesAsync(src, data);

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            var droppedProofs = new HashSet<long>();
            switch (mode)
            {
                case "corrupt-chunk":
                    server.CorruptChunk = (idx, bytes) => { if (idx == 7) bytes[0] ^= 0xFF; };
                    break;
                case "lying-cv":
                    server.CorruptChunk = (idx, bytes) => { if (idx is >= 128 and < 192) bytes[0] ^= 0xFF; };
                    server.ReworkChunkCv = (idx, bytes) => idx is >= 128 and < 192
                        ? Blake3.ChunkCv(bytes, (ulong)idx, root: false) // self-consistent lie
                        : null;
                    break;
                case "forged-proof":
                    server.CorruptProof = (_, runIndex, siblings) =>
                    {
                        if (runIndex == 2 && siblings.Length > 0) siblings[0] ^= 0x80;
                    };
                    break;
                case "dropped-proof":
                    server.DropProof = runIndex => runIndex == 1 && droppedProofs.Add(runIndex);
                    break;
                case "duplicated-frames":
                    server.DuplicateChunk = idx => idx % 7 == 0;
                    break;
                case "reordered-frames":
                    server.DeliverProofsBeforeChunks = true;
                    break;
                case "truncated":
                    server.DropChunk = idx => idx >= 100;
                    break;
            }

            string outDir = Path.Combine(dir, "out");
            string target = Path.Combine(outDir, "adv.bin");
            var options = new BlobDownloadOptions
            {
                NodeOptions = Offline(),
                RecoveryTimeout = mode == "truncated" ? TimeSpan.FromSeconds(3) : TimeSpan.FromMinutes(10),
            };

            if (mode is "corrupt-chunk" or "lying-cv" or "forged-proof")
            {
                await Assert.ThrowsAsync<InvalidDataException>(() =>
                    BlobClient.DownloadAsync(server.Ticket, outDir, options: options)).WaitAsync(Timeout);
                Assert.False(File.Exists(target), $"mode {mode} must never publish the target");
                string dataPath = Path.Combine(target + ".pinhole-part", "data");
                if (File.Exists(dataPath))
                {
                    long cap = mode == "corrupt-chunk" ? 7 * 1024 : 128 * 1024;
                    Assert.True(new FileInfo(dataPath).Length <= cap,
                        $"mode {mode} left {new FileInfo(dataPath).Length} bytes of unverified data");
                }
            }
            else if (mode == "truncated")
            {
                TimeoutException failure = await Assert.ThrowsAsync<TimeoutException>(() =>
                    BlobClient.DownloadAsync(server.Ticket, outDir, options: options)).WaitAsync(Timeout);
                Assert.Contains("re-established", failure.Message, StringComparison.Ordinal);
                Assert.False(File.Exists(target), "a truncated transfer must never publish the target");
            }
            else
            {
                await BlobClient.DownloadAsync(server.Ticket, outDir, options: options).WaitAsync(Timeout);
                Assert.Equal(data, await File.ReadAllBytesAsync(target));
                Assert.False(Directory.Exists(target + ".pinhole-part"), "part directory cleaned after success");
            }

            if (mode == "dropped-proof")
            {
                Assert.Contains(1, droppedProofs); // one drop happened and was healed
            }
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    // ---------------------------------------------------------------- gate 6: interop matrix

    [Fact]
    public async Task V4Client_V4Server_CompletesByteExact()
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(MultiRunBytes);
            string src = Path.Combine(dir, "interop.bin");
            await File.WriteAllBytesAsync(src, data);

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            string outDir = Path.Combine(dir, "out");
            BlobDownloadResult result = await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);
            Assert.Equal(data, await File.ReadAllBytesAsync(result.Path));
            Assert.Equal(data.Length, result.Bytes);
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public async Task V4Client_LegacyV3Server_FallsBackAndCompletes()
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(MultiRunBytes);
            string src = Path.Combine(dir, "legacy-server.bin");
            await File.WriteAllBytesAsync(src, data);

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            server.LegacyV3Only = true; // closes on Hello v4, answers Hello v3

            string outDir = Path.Combine(dir, "out");
            BlobDownloadResult result = await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);
            Assert.Equal(data, await File.ReadAllBytesAsync(result.Path));
            Assert.True(server.ConnectionsAccepted >= 2,
                "the v4 attempt was refused, then exactly one v3 re-dial completed the transfer");
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public async Task LegacyV3Client_V4Server_StillServesV3()
    {
        // A pre-v4 downloader emulated at the wire: v3 Hello, v3 Welcome, sealed Head
        // opened under the v3 ticket key, and an honest chunk frame. The v4 provider
        // must keep this legacy path byte-identical.
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(5000);
            string src = Path.Combine(dir, "legacy-client.bin");
            await File.WriteAllBytesAsync(src, data);
            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            BlobTicket ticket = server.Ticket;

            await using var node = await PinholeNode.BindAsync(Offline() with { Listen = false, ReceiveBufferCapacity = 64 });
            await using PinholeConnection conn = await node.ConnectAsync(ticket.ConnectionString);
            byte[] sessionId = BlobWire.Cipher.FreshSessionId();
            ulong stream = BlobWire.StreamId(ticket.Root);
            conn.Send(BlobWire.Hello(stream, sessionId));
            using var receiveCts = new CancellationTokenSource(TestBudget.Io);

            BlobWire.Frame welcome = await NextBlobFrameAsync(conn, receiveCts.Token);
            Assert.Equal(BlobWire.TypeWelcome, welcome.Type);
            Assert.Equal(BlobWire.ProtocolVersion, welcome.Version);
            Assert.Equal(sessionId, welcome.SessionId);

            var cipher = BlobWire.Cipher.For(ticket.PreSharedKey, ticket.Root, sessionId, welcome.ProviderNonce!);
            ulong watermark = 0;
            Assert.True(cipher!.TryOpen(fromProvider: true, welcome.SealedHead!, ref watermark, out byte[] head));
            Assert.True(BlobWire.Frame.TryParse(head, out BlobWire.Frame headFrame));
            Assert.Equal(BlobWire.TypeHead, headFrame.Type);
            Assert.Equal(data.Length, headFrame.TotalBytes);

            conn.Send(cipher.Seal(asProvider: false, 1, BlobWire.Request(stream, 0, 1)));
            ReadOnlyMemory<byte>? chunkPayload = await conn.ReceiveAsync(receiveCts.Token);
            Assert.NotNull(chunkPayload);
            Assert.True(cipher.TryOpen(fromProvider: true, chunkPayload!.Value.Span, ref watermark, out byte[] chunkPlain));
            Assert.True(BlobWire.Frame.TryParse(chunkPlain, out BlobWire.Frame chunk));
            Assert.Equal(BlobWire.TypeChunk, chunk.Type);
            Assert.Equal(0, chunk.Index);
            Assert.Equal(data[..1024], chunk.ChunkData);
            Assert.Equal(Blake3.ChunkCv(chunk.ChunkData, 0, root: false), chunk.ChunkCv);
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public async Task PlaintextTicket_BothV4Capable_CompletesOnV3Semantics()
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(MultiRunBytes);
            string src = Path.Combine(dir, "plain.bin");
            await File.WriteAllBytesAsync(src, data);

            await using var server = await BlobServer.ServeAsync(src,
                new BlobServeOptions { Encrypt = false, NodeOptions = Offline() });
            string outDir = Path.Combine(dir, "out");
            BlobDownloadResult result = await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);
            Assert.Equal(data, await File.ReadAllBytesAsync(result.Path));
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    private static async Task<BlobWire.Frame> NextBlobFrameAsync(PinholeConnection conn, CancellationToken ct)
    {
        ReadOnlyMemory<byte>? payload = await conn.ReceiveAsync(ct);
        Assert.NotNull(payload);
        Assert.True(BlobWire.Frame.TryParse(payload!.Value.Span, out BlobWire.Frame frame));
        return frame;
    }

    // ---------------------------------------------------------------- gate 7: run shapes

    public static IEnumerable<object[]> RunSizes() =>
        new object[][] { [0L], [5L], [1024L], [5000L], [64 * 1024L], [65 * 1024L], [200_000L], [300_000L] };

    [Theory]
    [MemberData(nameof(RunSizes))]
    public async Task V4Transfers_CompleteByteExact_AcrossRunShapes(long size)
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(size);
            string src = Path.Combine(dir, "shape.bin");
            await File.WriteAllBytesAsync(src, data);

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            string outDir = Path.Combine(dir, "out");
            BlobDownloadResult result = await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);
            Assert.Equal(data, await File.ReadAllBytesAsync(result.Path));
            Assert.Equal(size, result.Bytes);
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public async Task RunsCommit_OutOfOrder_Run1Last()
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(MultiRunBytes); // 5 runs
            string src = Path.Combine(dir, "ooo.bin");
            await File.WriteAllBytesAsync(src, data);

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            // Hold run 1 (chunks 64..127) back until the runs around it have been
            // served, so it commits last: the fold prefix stalls at run 1 while runs
            // 2..4 commit sparse, then the drain and final fold must still hit the
            // root. The release counts chunks SERVED BY THE PROVIDER, not client
            // progress: progress timing is scheduler-dependent and hung this test on
            // every non-Linux CI runner, while the served-chunk counter flips at the
            // same point on any OS. Budget 90s: the heal is 64 single-chunk PTO
            // re-requests, which loaded runners stretch without anything being wrong.
            long started = Environment.TickCount64;
            long run1ServeAttempts = 0; // provider dropped a run-1 chunk (a request DID reach it)
            int othersServed = 0;
            long releasedAtMs = -1;
            int released = 0;
            server.DropChunk = idx =>
            {
                if (idx is >= 64 and < 128)
                {
                    Interlocked.Increment(ref run1ServeAttempts);
                    return Volatile.Read(ref released) == 0;
                }

                if (Interlocked.Increment(ref othersServed) >= 200
                    && Interlocked.Exchange(ref released, 1) == 0)
                {
                    releasedAtMs = Environment.TickCount64 - started;
                }

                return false;
            };

            // The failure mode is CI-only (loaded macOS/Windows runners): a silent
            // hang to the budget with no internal stall error. On any failure the
            // client-side state timeline and the provider counters land in the test
            // output so the failed job's log IS the diagnosis.
            string outDir = Path.Combine(dir, "out");
            var timeline = new List<string>(512);
            BlobTestHooks.Trace = line => { lock (timeline) timeline.Add(line); };
            BlobDownloadResult result;
            try
            {
                result = await BlobClient.DownloadAsync(server.Ticket, outDir,
                    options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(TimeSpan.FromSeconds(90));
            }
            catch (Exception ex)
            {
                _output.WriteLine($"FAILED after {(Environment.TickCount64 - started) / 1000.0:0.0}s: {ex.GetType().Name}: {ex.Message}");
                lock (timeline)
                {
                    _output.WriteLine($"provider: chunksServed={server.ChunksServed} connectionsAccepted={server.ConnectionsAccepted} " +
                        $"run1ServeAttempts={Interlocked.Read(ref run1ServeAttempts)} othersServed={Volatile.Read(ref othersServed)} " +
                        $"released={(Volatile.Read(ref released) == 1 ? $"at {releasedAtMs / 1000.0:0.0}s" : "never")}");
                    _output.WriteLine($"client timeline ({timeline.Count} snapshots):");
                    foreach (string line in timeline.Take(20))
                    {
                        _output.WriteLine("  " + line);
                    }

                    if (timeline.Count > 20)
                    {
                        _output.WriteLine("  ... tail:");
                        foreach (string line in timeline.Skip(Math.Max(20, timeline.Count - 80)))
                        {
                            _output.WriteLine("  " + line);
                        }
                    }
                }

                throw;
            }
            finally
            {
                BlobTestHooks.Trace = null;
            }

            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(outDir, "ooo.bin")));
            _ = result;
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public void FileSink_RunFold_MatchesTheStreamingRoot()
    {
        // The sink's incremental fold (prefix stack + sparse final run) must equal the
        // oracle FoldRunsToRoot over the same run CVs, for forward AND reverse commit
        // orders — reverse exercises the sparse set and the drain.
        foreach (int chunkCount in new[] { 65, 100, 128, 129, 192, 200, 1000, 1025 })
        {
            foreach (bool reverse in new[] { false, true })
            {
                string dir = TempDir();
                try
                {
                    byte[] data = new byte[chunkCount * 1024L];
                    for (int i = 0; i < data.Length; i++)
                    {
                        data[i] = (byte)(i * 31 + 7);
                    }

                    var tree = new Blake3.Tree();
                    tree.Update(data);
                    byte[] root = tree.RootHash();
                    IReadOnlyList<byte[]> cvs = tree.ChunkCvs;
                    var runTree = new RunTree(cvs, chunkCount);
                    long runs = RunVerify.RunCount(chunkCount);
                    bool singleRun = runs == 1;

                    var sink = new BlobClient.FileSink(Path.Combine(dir, "fold.bin"), root);
                    sink.UseVerifiedRuns();
                    sink.Init(data.Length, chunkCount);
                    for (long step = 0; step < runs; step++)
                    {
                        long r = reverse ? runs - 1 - step : step;
                        int len = RunVerify.RunLength(r, chunkCount);
                        var leaves = new byte[len * RunVerify.CvSize];
                        var chunks = new byte[len][];
                        for (int c = 0; c < len; c++)
                        {
                            cvs[(int)(r * RunVerify.RunChunks + c)].CopyTo(leaves.AsSpan(c * RunVerify.CvSize));
                            chunks[c] = data.AsSpan((int)(r * RunVerify.RunChunks + c) * 1024, 1024).ToArray();
                        }

                        byte[] runCv = new byte[32];
                        Assert.True(RunVerify.FoldRun(leaves, len, rootOnFinal: singleRun, runCv));
                        sink.ApplyRun(r, len, chunks, runCv);
                    }

                    Assert.True(sink.Applied >= chunkCount);
                    byte[] folded = sink.Complete();
                    Assert.True(root.AsSpan().SequenceEqual(folded),
                        $"chunkCount={chunkCount} reverse={reverse}: fold mismatch");
                    sink.Reject();
                }
                finally
                {
                    DeleteDir(dir);
                }
            }
        }
    }

    [Fact]
    public void RunCheckpoint_IsDirtyChecked_NoWriteStormWhileStalled()
    {
        string dir = TempDir();
        try
        {
            var sink = new BlobClient.FileSink(Path.Combine(dir, "runs.bin"), RandomNumberGenerator.GetBytes(32));
            sink.UseVerifiedRuns();
            sink.Init(192 * 1024, 192);
            var chunks = Enumerable.Range(0, 64).Select(_ => RandomBytes(1024)).ToArray();

            sink.ApplyRun(0, 64, chunks, RandomNumberGenerator.GetBytes(32));
            sink.Checkpoint();
            Assert.Equal(1, sink.CheckpointWrites);

            for (int i = 0; i < 20; i++)
            {
                sink.Checkpoint(); // stalled: the committed-run set has not moved
            }

            Assert.Equal(1, sink.CheckpointWrites);
            sink.ApplyRun(1, 64, chunks, RandomNumberGenerator.GetBytes(32));
            sink.Checkpoint();
            Assert.Equal(2, sink.CheckpointWrites);
            Assert.Equal(128, sink.Applied);
            sink.Reject();
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    // ---------------------------------------------------------------- gate 8: proof loss

    [Fact]
    public async Task ProofLoss_HealsViaRunReRequest()
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(MultiRunBytes);
            string src = Path.Combine(dir, "proofloss.bin");
            await File.WriteAllBytesAsync(src, data);

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            int attempts = 0;
            server.DropProof = runIndex =>
            {
                if (runIndex == 1)
                {
                    attempts++;
                    return attempts == 1; // lose exactly the first proof for run 1
                }

                return false;
            };

            string outDir = Path.Combine(dir, "out");
            await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);
            Assert.True(attempts >= 2, $"run 1's proof was sent {attempts} times; the loss never healed");
            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(outDir, "proofloss.bin")));
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    // ---------------------------------------------------------------- lying-Head oracle

    // The smallest adversarial provider that matters for the Head bound: a real engine
    // handshake, a genuine v4 Welcome, and a sealed Head declaring an absurd size.
    private sealed class LyingHeadOracle : IDisposable
    {
        public readonly Socket Sock = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        public readonly ulong PeerId = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        public readonly NodeIdentity Identity = new();
        public const uint EngineToken = 0x00C0FFEE;
        private ConnectionCrypto? _crypto;
        private BlobWire.Cipher? _cipher;
        private readonly byte[] _providerNonce = BlobWire.Cipher.FreshSessionId();
        private ulong _blobCounter;

        public IPEndPoint Ep => (IPEndPoint)Sock.LocalEndPoint!;

        public string DialString => new ConnectionString(
            PeerId, [new PinholeCandidate(Pinhole.CandidateKind.Direct, Ep)], NatHint.Unknown, Identity.PublicKey).ToString();

        public async Task ServeLyingHeadAsync(byte[] psk, byte[] root, long declaredBytes, CancellationToken ct = default)
        {
            var peer = new IPEndPoint(IPAddress.Loopback, 0);
            byte[] buf = new byte[8192];
            byte[] plain = new byte[8192];
            ulong stream = BlobWire.StreamId(root);
            long declaredChunks = declaredBytes / Blake3.ChunkSize + (declaredBytes % Blake3.ChunkSize == 0 ? 0 : 1);

            EndPoint client = new IPEndPoint(IPAddress.Loopback, 0);
            uint clientToken = 0;
            while (!ct.IsCancellationRequested)
            {
                SocketReceiveFromResult r;
                try
                {
                    r = await Sock.ReceiveFromAsync(buf, peer, ct);
                }
                catch (Exception ex) when (ex is ObjectDisposedException or SocketException)
                {
                    return;
                }

                if (r.ReceivedBytes == 9 + CryptoWire.PuncCryptoBody && buf[0] == 0x50)
                {
                    client = r.RemoteEndPoint!;
                    clientToken = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(9));
                    _crypto = ConnectionCrypto.New(Identity, PeerId, BinaryPrimitives.ReadUInt64LittleEndian(buf.AsSpan(1)));
                    if (!_crypto.TryPeerKeys(buf.AsSpan(13, 32), buf.AsSpan(45, 32)))
                    {
                        throw new InvalidOperationException("oracle could not derive the downloader's keys");
                    }

                    byte[] pack = new byte[9 + CryptoWire.PackCryptoBody];
                    pack[0] = 0x51;
                    BinaryPrimitives.WriteUInt64LittleEndian(pack.AsSpan(1), PeerId);
                    BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(9), clientToken);
                    BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(13), EngineToken);
                    _crypto.MyEphPublic.CopyTo(pack.AsSpan(17));
                    _crypto.MyStaticPublic.CopyTo(pack.AsSpan(49));
                    _crypto.MyConfirm().CopyTo(pack.AsSpan(81));
                    await Sock.SendToAsync(pack, client, ct);
                    await SendSealedAsync(client, new byte[8], ct, frameType: 0x53);
                    break;
                }
            }

            // Answer every Hello with a genuine v4 Welcome sealing the lying Head, then
            // serve nothing else: the Head bound has everything it needs to fire.
            while (!ct.IsCancellationRequested)
            {
                int received;
                int len;
                try
                {
                    SocketReceiveFromResult r = await Sock.ReceiveFromAsync(buf, peer, ct);
                    received = r.ReceivedBytes;
                    if (received < 13 || buf[0] is 0x50 or 0x51 or 0x57)
                    {
                        continue;
                    }

                    if (!_crypto!.Recv!.Open(buf.AsSpan(0, received), plain, out len))
                    {
                        continue;
                    }
                }
                catch (Exception ex) when (ex is ObjectDisposedException or SocketException)
                {
                    return;
                }

                if (!BlobWire.Frame.TryParse(plain.AsSpan(0, len), out BlobWire.Frame f)
                    || f.Type != BlobWire.TypeHello
                    || f.SessionId is not { } sid)
                {
                    continue;
                }

                _cipher ??= BlobWire.Cipher.For(psk, root, sid, _providerNonce, BlobWire.CurrentVersion)!;
                byte[] head = _cipher.Seal(asProvider: true, ++_blobCounter,
                    BlobWire.Head(stream, declaredBytes, declaredChunks));
                byte[] welcome = BlobWire.Welcome(stream, sid, _providerNonce, head, BlobWire.CurrentVersion);
                await SendSealedAsync(client, welcome, ct).ConfigureAwait(false);
            }
        }

        private async Task SendSealedAsync(EndPoint to, ReadOnlyMemory<byte> blobPayload, CancellationToken ct,
            byte frameType = 0x52)
        {
            var frame = new byte[13 + CryptoWire.SealedOverhead + blobPayload.Length];
            frame[0] = frameType;
            BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(1), PeerId);
            BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(9), EngineToken);
            _crypto!.Send!.Seal(frame.AsSpan(13), frame.AsSpan(0, 13), blobPayload.Span);
            try
            {
                await Sock.SendToAsync(frame, to, ct);
            }
            catch (Exception ex) when (ex is ObjectDisposedException or SocketException)
            {
            }
        }

        public void Dispose() => Sock.Dispose();
    }
}
