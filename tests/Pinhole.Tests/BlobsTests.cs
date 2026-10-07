using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Pinhole.Blobs;
using Xunit;

namespace Pinhole.Tests;

/// <summary>The sendme-parity feature: serve a file or directory from one machine, download
/// it from another with a single ticket — verified chunk by chunk while streaming, resumed
/// across restarts, healed through datagram loss, and (by default) encrypted so the relays
/// forward nothing but ciphertext.</summary>
public sealed class BlobsTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private static PinholeOptions Offline() => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [],
        EnableNetworkWatch = false,
        EnablePortMapping = false,
    };

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-blobs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static byte[] RandomBytes(long size)
    {
        var data = new byte[size];
        RandomNumberGenerator.Fill(data);
        return data;
    }

    public static IEnumerable<object[]> FileSizes() =>
        new object[][] { [0], [1], [500], [1024], [1025], [5000], [300_000] };

    [Theory]
    [MemberData(nameof(FileSizes))]
    public async Task FileRoundtrip_ExactBytes(long size)
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(size);
            string src = Path.Combine(dir, "source.bin");
            await File.WriteAllBytesAsync(src, data);

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            string downloadDir = Path.Combine(dir, "out");
            BlobDownloadResult result = await BlobClient.DownloadAsync(server.Ticket, downloadDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);

            string saved = Path.Combine(downloadDir, "source.bin");
            Assert.True(File.Exists(saved), "downloaded file exists");
            Assert.Equal(data, await File.ReadAllBytesAsync(saved));
            Assert.Equal(size, result.Bytes);
            Assert.False(result.Resumed);
            Assert.False(Directory.Exists(saved + ".pinhole-part"), "part directory is cleaned up");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task DirectoryRoundtrip_PreservesTree()
    {
        string dir = TempDir();
        try
        {
            string tree = Path.Combine(dir, "tree");
            Directory.CreateDirectory(Path.Combine(tree, "sub"));
            await File.WriteAllBytesAsync(Path.Combine(tree, "a.txt"), "alpha"u8.ToArray());
            await File.WriteAllBytesAsync(Path.Combine(tree, "sub", "b.bin"), RandomBytes(3000));
            await File.WriteAllBytesAsync(Path.Combine(tree, "empty.txt"), Array.Empty<byte>());

            await using var server = await BlobServer.ServeAsync(tree, new BlobServeOptions { NodeOptions = Offline() });
            string outDir = Path.Combine(dir, "out");
            BlobDownloadResult result = await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);

            string root = Path.Combine(outDir, "tree");
            Assert.Equal("alpha", await File.ReadAllTextAsync(Path.Combine(root, "a.txt")));
            Assert.Equal(3000, new FileInfo(Path.Combine(root, "sub", "b.bin")).Length);
            Assert.Equal(0, new FileInfo(Path.Combine(root, "empty.txt")).Length);
            Assert.Equal(3000 + 5, result.Bytes);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task LostChunks_AreReRequestedUntilComplete()
    {
        string dir = TempDir();
        try
        {
            string src = Path.Combine(dir, "lossy.bin");
            await File.WriteAllBytesAsync(src, RandomBytes(200_000));

            var serveOpts = new BlobServeOptions { NodeOptions = Offline() };
            await using var server = await BlobServer.ServeAsync(src, serveOpts);
            // Lose a deterministic scattered set of chunk TRANSMISSIONS (each exactly once,
            // like datagrams that hit a lossy path): the downloader's sweep must notice the
            // holes and re-request until every chunk lands on its second attempt.
            var lostOnce = new HashSet<long>();
            server.DropChunk = idx => idx is 3 or 17 or 40 or 41 or 42 && lostOnce.Add(idx);

            string outDir = Path.Combine(dir, "out");
            await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);
            Assert.Equal(await File.ReadAllBytesAsync(src), await File.ReadAllBytesAsync(Path.Combine(outDir, "lossy.bin")));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task CorruptChunk_AbortsImmediately()
    {
        string dir = TempDir();
        try
        {
            string src = Path.Combine(dir, "honest.bin");
            await File.WriteAllBytesAsync(src, RandomBytes(50_000));

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            // A lying provider: chunk 5's bytes get flipped after the honest CV was built.
            server.CorruptChunk = (idx, data) =>
            {
                if (idx == 5)
                {
                    data[0] ^= 0xFF;
                }
            };

            await Assert.ThrowsAsync<InvalidDataException>(() => BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
                options: new BlobDownloadOptions { NodeOptions = Offline() })).WaitAsync(Timeout);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task FailedDownload_DoesNotPoisonTheServer_OrTheNextAttempt()
    {
        // The iroh-net-bindings "process stays healthy" pattern: a failed transfer must
        // leave both sides fully usable — the server serves the next stranger, and a
        // retry from the same downloader resumes past the checkpoint instead of starting
        // over poisoned by the aborted attempt's part state.
        string dir = TempDir();
        try
        {
            byte[] data = TestDispose.Pattern(300_000, 0x5A);
            string src = Path.Combine(dir, "poison.bin");
            await File.WriteAllBytesAsync(src, data);

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            var droppedOnce = new HashSet<long>();
            server.CorruptChunk = (idx, bytes) =>
            {
                if (idx == 10 && droppedOnce.Add(idx))
                {
                    bytes[0] ^= 0xFF; // lie exactly once, then serve honestly
                }
            };

            string outDir = Path.Combine(dir, "out");
            await Assert.ThrowsAsync<InvalidDataException>(() => BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() })).WaitAsync(Timeout);
            Assert.True(server.ConnectionsAccepted >= 1, "the failed attempt did reach the server");

            // A fresh downloader (new connection, new node) completes over the same server.
            BlobDownloadResult fresh = await BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "fresh"),
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);
            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(dir, "fresh", "poison.bin")));

            // And the ORIGINAL destination finishes too: its part state is honest (the
            // corrupt chunk never passed CV verification, so it was never applied) and
            // the second pass re-requests chunk 10 from a now-honest provider.
            BlobDownloadResult retried = await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);
            Assert.True(retried.Resumed, "the retry continued from the aborted attempt's checkpoint");
            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(outDir, "poison.bin")));
            Assert.False(Directory.Exists(Path.Combine(outDir, "poison.bin") + ".pinhole-part"));
            _ = fresh;
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task ServerDisposal_WaitsForActiveFileReaders()
    {
        string dir = TempDir();
        using var releaseReader = new ManualResetEventSlim();
        using var stopDownload = new CancellationTokenSource(TestBudget.Scenario);
        var readerEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        BlobServer? server = null;
        Task<BlobDownloadResult>? download = null;
        try
        {
            string src = Path.Combine(dir, "held.bin");
            await File.WriteAllBytesAsync(src, RandomBytes(4096));
            server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            server.CorruptChunk = (_, _) =>
            {
                // ReadChunk has opened the file. Hold that worker at a real chunk
                // boundary so shutdown cannot win a race with resource cleanup.
                readerEntered.TrySetResult();
                if (!releaseReader.Wait(TestBudget.Teardown))
                    throw new TimeoutException("the test did not release the file reader");
            };
            download = BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
                options: new BlobDownloadOptions { NodeOptions = Offline() }, ct: stopDownload.Token);
            await readerEntered.Task.WaitAsync(TestBudget.Io);

            Task disposing = server.DisposeAsync().AsTask();
            await Task.WhenAny(disposing, Task.Delay(200));
            Assert.False(disposing.IsCompleted, "server shutdown must wait for its active file reader");
            releaseReader.Set();
            stopDownload.Cancel();
            await disposing.WaitAsync(TestBudget.Teardown);

            // In particular, Windows must allow immediate exclusive access after
            // DisposeAsync returns, without sleeps or deletion retries.
            using FileStream reopened = File.Open(src, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        finally
        {
            releaseReader.Set();
            stopDownload.Cancel();
            if (server is not null) await server.DisposeAsync().AsTask().WaitAsync(TestBudget.Teardown);
            if (download is not null)
            {
                try { await download.WaitAsync(TestBudget.Teardown); }
                catch (OperationCanceledException) { }
            }
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task ProviderDisposedMidTransfer_FailsFastAndHonestly()
    {
        // The sendme Ctrl-C contract: when the provider goes away, the downloader must
        // surface a real error quickly — not spin its re-request machinery for the full
        // stall budget. The pump notices the closed connection and the run loop
        // converts quiet into an exception.
        string dir = TempDir();
        try
        {
            string src = Path.Combine(dir, "big.bin");
            await File.WriteAllBytesAsync(src, TestDispose.Pattern(2_000_000, 0xC3));

            var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            server.DropChunk = idx => idx >= 4; // head flows, tail never arrives: the transfer cannot finish

            var watch = System.Diagnostics.Stopwatch.StartNew();
            var failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            _ = Task.Run(async () =>
            {
                try
                {
                    await BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
                        options: new BlobDownloadOptions
                        {
                            NodeOptions = Offline(),
                            RecoveryTimeout = TimeSpan.FromSeconds(12), // route loss is ridden out — but not forever
                        });
                    failed.TrySetResult(null!);
                }
                catch (Exception ex)
                {
                    failed.TrySetResult(ex);
                }
            });

            // Wait until the transfer is actually in flight, then pull the provider's plug.
            await TestPoll.UntilAsync(Timeout, () => server.ConnectionsAccepted >= 1 && server.ChunksServed >= 4);
            await TestDispose.BoundedAsync(server, "blob server mid-transfer");
            Exception? ex = await failed.Task.WaitAsync(TestBudget.Scenario);
            watch.Stop();

            // An unreachable provider is ROUTE LOSS, not rejection: the recovery loop
            // re-dials until its (here short) budget dies, then surfaces a failure that
            // says exactly that — never the bare 30s stall, never a hang.
            Assert.NotNull(ex);
            Assert.True(ex is TimeoutException && ex.Message.Contains("re-established", StringComparison.Ordinal),
                $"wrong failure surfaced: {ex.GetType().Name}: {ex.Message}");
            Assert.True(watch.Elapsed < TestBudget.Scenario, $"failure took {watch.Elapsed.TotalSeconds:0.0}s to surface");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task InterruptedDownload_ResumesFromTheCheckpoint()
    {
        string dir = TempDir();
        try
        {
            string src = Path.Combine(dir, "resume.bin");
            await File.WriteAllBytesAsync(src, RandomBytes(400_000));

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            string outDir = Path.Combine(dir, "out");
            string target = Path.Combine(outDir, "resume.bin");

            using var cancelFirst = new CancellationTokenSource();
            var firstProgress = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var progress = new Progress<BlobProgress>(p =>
            {
                if (p.VerifiedBytes >= 20_000)
                {
                    firstProgress.TrySetResult();
                }
            });

            // Drop the tail so the first attempt provably cannot finish — on loopback the
            // transfer outruns any progress-callback cancellation otherwise.
            server.DropChunk = idx => idx >= 50;
            Task firstRun = Task.Run(() => BlobClient.DownloadAsync(server.Ticket, outDir, progress,
                new BlobDownloadOptions { NodeOptions = Offline() }, cancelFirst.Token));
            await firstProgress.Task.WaitAsync(Timeout);
            cancelFirst.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstRun).WaitAsync(Timeout);
            Assert.True(Directory.Exists(target + ".pinhole-part"), "interrupted download left its part directory");

            // Second run continues from the checkpoint and finishes the job.
            server.DropChunk = null;
            BlobDownloadResult result = await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);

            Assert.True(result.Resumed, "the second run resumed from part state");
            Assert.Equal(await File.ReadAllBytesAsync(src), await File.ReadAllBytesAsync(target));
            Assert.False(Directory.Exists(target + ".pinhole-part"), "part directory is cleaned up after success");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Cipher_SessionIdBindsTheKey_TwoConnectionsNeverShareOne()
    {
        // Two connections on one ticket used to restart the same per-ticket key with the
        // same counters — ChaCha20-Poly1305 (key, nonce) reuse across connections. The
        // downloader and provider each contribute a 256-bit nonce to the connection key.
        byte[] psk = RandomNumberGenerator.GetBytes(32);
        byte[] root = RandomNumberGenerator.GetBytes(32);
        byte[] binding = BlobWire.Cipher.FreshSessionId();
        byte[] sidA = BlobWire.Cipher.FreshSessionId();
        byte[] sidB = BlobWire.Cipher.FreshSessionId();

        BlobWire.Cipher? providerA = BlobWire.Cipher.For(psk, root, sidA, binding);
        BlobWire.Cipher? downloaderA = BlobWire.Cipher.For(psk, root, sidA, binding); // same connection, both ends
        BlobWire.Cipher? connectionB = BlobWire.Cipher.For(psk, root, sidB, binding);
        Assert.NotNull(providerA);
        Assert.NotNull(downloaderA);
        Assert.NotNull(connectionB);

        // Connection A's first provider frame (counter 1): its own far end opens it...
        ulong seen = 0;
        byte[] wireA = providerA!.Seal(asProvider: true, 1, "chunk-of-A"u8.ToArray());
        Assert.True(downloaderA!.TryOpen(fromProvider: true, wireA, ref seen, out byte[] plain));
        Assert.Equal("chunk-of-A"u8.ToArray(), plain);

        // ...connection B must not — same ticket, same role, same counter, different key.
        ulong seenB = 0;
        Assert.False(connectionB!.TryOpen(fromProvider: true, wireA, ref seenB, out _),
            "a second connection on the same ticket must not read the first one's frames");

        // And B sealing at its own counter 1 is a distinct (key, nonce) pair, not a collision.
        byte[] wireB = connectionB.Seal(asProvider: true, 1, "chunk-of-B"u8.ToArray());
        Assert.False(providerA.TryOpen(fromProvider: true, wireB, ref seen, out _));
    }

    [Fact]
    public void Cipher_RepeatedSessionId_ProviderNonceStillForksTheKey()
    {
        // Session uniqueness must not rest on the downloader alone: a buggy or hostile
        // client that repeats an earlier session id gets the same id-derived input — but
        // the provider contributes an independent 256-bit nonce on each connection.
        byte[] psk = RandomNumberGenerator.GetBytes(32);
        byte[] root = RandomNumberGenerator.GetBytes(32);
        byte[] repeated = BlobWire.Cipher.FreshSessionId();
        byte[] first = BlobWire.Cipher.FreshSessionId();
        byte[] second = BlobWire.Cipher.FreshSessionId();

        var conn1 = BlobWire.Cipher.For(psk, root, repeated, first)!;
        var conn2 = BlobWire.Cipher.For(psk, root, repeated, second)!;
        var conn1Again = BlobWire.Cipher.For(psk, root, repeated, first)!; // both ends of one connection agree

        byte[] wire = conn1.Seal(asProvider: true, 1, "connection one"u8.ToArray());
        ulong seen = 0;
        Assert.True(conn1Again.TryOpen(fromProvider: true, wire, ref seen, out _));

        seen = 0;
        Assert.False(conn2.TryOpen(fromProvider: true, wire, ref seen, out _),
            "a repeated session id must not reproduce the key across connections");
        byte[] wire2 = conn2.Seal(asProvider: true, 1, "connection two"u8.ToArray());
        seen = 0;
        Assert.False(conn1.TryOpen(fromProvider: true, wire2, ref seen, out _));
    }

    [Theory]
    [InlineData(PinholeEncryption.Required)]
    [InlineData(PinholeEncryption.Disabled)]
    public async Task SameTicket_RepeatedClientNonce_ProviderFreshnessAndHelloRetries(PinholeEncryption encryption)
    {
        string dir = TempDir();
        try
        {
            string src = Path.Combine(dir, "nonce.bin");
            await File.WriteAllBytesAsync(src, RandomBytes(500));
            var options = Offline() with { Encryption = encryption, ReceiveBufferCapacity = 64 };
            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = options });
            await using var node1 = await PinholeNode.BindAsync(options);
            await using var node2 = await PinholeNode.BindAsync(options);
            await using var conn1 = await node1.ConnectAsync(server.Ticket.ConnectionString);
            await using var conn2 = await node2.ConnectAsync(server.Ticket.ConnectionString);
            byte[] repeated = new byte[32]; // even a downloader repeating a constant id is safe for the provider
            ulong stream = BlobWire.StreamId(server.Ticket.Root);

            async Task<BlobWire.Frame> Welcome(PinholeConnection conn)
            {
                conn.Send(BlobWire.Hello(stream, repeated));
                using var receiveCts = new CancellationTokenSource(TestBudget.Io);
                var payload = await conn.ReceiveAsync(receiveCts.Token);
                Assert.NotNull(payload);
                Assert.True(BlobWire.Frame.TryParse(payload.Value.Span, out BlobWire.Frame frame));
                Assert.Equal(BlobWire.TypeWelcome, frame.Type);
                Assert.Equal(BlobWire.ProtocolVersion, frame.Version);
                Assert.Equal(repeated, frame.SessionId);
                Assert.Equal(32, frame.ProviderNonce!.Length);
                return frame;
            }

            BlobWire.Frame first = await Welcome(conn1);
            BlobWire.Frame retry = await Welcome(conn1);
            BlobWire.Frame second = await Welcome(conn2);
            Assert.Equal(first.ProviderNonce, retry.ProviderNonce);
            Assert.False(first.ProviderNonce.AsSpan().SequenceEqual(second.ProviderNonce));
            var cipher1 = BlobWire.Cipher.For(server.Ticket.PreSharedKey, server.Ticket.Root, repeated, first.ProviderNonce!)!;
            ulong watermark = 0;
            Assert.True(cipher1.TryOpen(fromProvider: true, first.SealedHead!, ref watermark, out _));
            Assert.True(cipher1.TryOpen(fromProvider: true, retry.SealedHead!, ref watermark, out _), "retry uses a fresh counter");
            watermark = 0;
            Assert.False(cipher1.TryOpen(fromProvider: true, second.SealedHead!, ref watermark, out _));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Cipher_ForgedAndReplayedCounters_NeverMoveTheWatermark()
    {
        // The blob layer's replay watermark obeys the same rule the session layer learned
        // the hard way: it moves only on authenticated frames. A forged far-future
        // counter must not starve the frames behind it, and a replayed old counter must
        // not re-admit the frames before it.
        var c = BlobWire.Cipher.For(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32),
            BlobWire.Cipher.FreshSessionId(), BlobWire.Cipher.FreshSessionId())!;
        ulong watermark = 5;
        byte[] genuine5 = c.Seal(asProvider: true, 5, "real"u8.ToArray());

        byte[] forged = new byte[8 + 4 + 16]; // counter 100, garbage everything else
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(forged, 100);
        Assert.False(c.TryOpen(fromProvider: true, forged, ref watermark, out _));
        Assert.Equal(5UL, watermark); // the forgery moved nothing

        byte[] genuine6 = c.Seal(asProvider: true, 6, "next"u8.ToArray());
        Assert.True(c.TryOpen(fromProvider: true, genuine6, ref watermark, out _));
        Assert.Equal(6UL, watermark); // genuine frames still land after the forgery

        Assert.False(c.TryOpen(fromProvider: true, genuine5, ref watermark, out _));
        Assert.Equal(6UL, watermark); // the replay of an authenticated old frame moved nothing

        byte[] genuine7 = c.Seal(asProvider: true, 7, "more"u8.ToArray());
        Assert.True(c.TryOpen(fromProvider: true, genuine7, ref watermark, out _));
    }

    [Fact]
    public void Welcome_RejectsTamperingAndNonceSwaps_AndKeepsReplayStateAcrossStreams()
    {
        byte[] psk = RandomBytes(32), root = RandomBytes(32), clientNonce = RandomBytes(32), providerNonce = RandomBytes(32);
        var session = new BlobWire.DownloadSession(psk, root, clientNonce);
        var provider = BlobWire.Cipher.For(psk, root, clientNonce, providerNonce)!;
        ulong stream = BlobWire.StreamId(root);
        byte[] head = provider.Seal(asProvider: true, 1, BlobWire.Head(stream, 500, 1));
        byte[] welcome = BlobWire.Welcome(stream, clientNonce, providerNonce, head);

        // A forged first response must not bind the wrong nonce, cipher, or counter.
        foreach (int offset in new[] { 1, 9, 10, 42, welcome.Length - 1 })
        {
            byte[] tampered = welcome.ToArray();
            tampered[offset] ^= 1;
            Assert.False(session.TryOpen(tampered, stream, out _));
        }

        byte[] forgedHead = provider.Seal(asProvider: true, 10_000, BlobWire.Head(stream, 500, 1));
        forgedHead[^1] ^= 1;
        Assert.False(session.TryOpen(BlobWire.Welcome(stream, clientNonce, providerNonce, forgedHead), stream, out _));
        Assert.True(session.TryOpen(welcome, stream, out BlobWire.Frame first));
        Assert.Equal(500, first.TotalBytes);
        Assert.False(session.TryOpen(welcome, stream, out _), "a Welcome is replay protected too");

        byte[] otherNonce = RandomBytes(32);
        var swapped = BlobWire.Cipher.For(psk, root, clientNonce, otherNonce)!;
        byte[] swappedHead = swapped.Seal(asProvider: true, 100, BlobWire.Head(stream, 500, 1));
        Assert.False(session.TryOpen(BlobWire.Welcome(stream, clientNonce, otherNonce, swappedHead), stream, out _));

        byte[] chunk = provider.Seal(asProvider: true, 2, BlobWire.Chunk(stream, 0, RandomBytes(32), RandomBytes(500)));
        Assert.True(session.TryOpen(chunk, stream, out _), "a rejected nonce swap does not poison the established session");

        ulong nextStream = stream ^ 1;
        byte[] nextHead = provider.Seal(asProvider: true, 3, BlobWire.Head(nextStream, 50, 1));
        Assert.True(session.TryOpen(BlobWire.Welcome(nextStream, clientNonce, providerNonce, nextHead), nextStream, out _));
        Assert.False(session.TryOpen(chunk, stream, out _), "switching directory streams must not reset replay state");
    }

    [Fact]
    public async Task BlobEncryption_TransfersWithoutCoreEncryption()
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(5000);
            string src = Path.Combine(dir, "independent.bin");
            await File.WriteAllBytesAsync(src, data);
            var options = Offline() with { Encryption = PinholeEncryption.Disabled };
            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = options });
            Assert.NotNull(server.Ticket.PreSharedKey);
            var result = await BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
                options: new BlobDownloadOptions { NodeOptions = options }).WaitAsync(Timeout);
            Assert.Equal(data, await File.ReadAllBytesAsync(result.Path));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task SameTicket_SimultaneousDownloads_BothVerify()
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(200_000);
            string src = Path.Combine(dir, "shared.bin");
            await File.WriteAllBytesAsync(src, data);

            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            byte[] expected = data;
            BlobDownloadResult[] results = await Task.WhenAll(
                Task.Run(() => BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out1"),
                    options: new BlobDownloadOptions { NodeOptions = Offline() })),
                Task.Run(() => BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out2"),
                    options: new BlobDownloadOptions { NodeOptions = Offline() }))).WaitAsync(Timeout);

            foreach (BlobDownloadResult result in results)
            {
                Assert.Equal(expected.Length, result.Bytes);
            }

            Assert.Equal(expected, await File.ReadAllBytesAsync(Path.Combine(dir, "out1", "shared.bin")));
            Assert.Equal(expected, await File.ReadAllBytesAsync(Path.Combine(dir, "out2", "shared.bin")));
            Assert.True(server.ConnectionsAccepted >= 2, "both downloads got their own connection");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task LegacyHello_EncryptedProvider_RefusesByHangingUp_AndKeepsServing(int version)
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(4096);
            string src = Path.Combine(dir, "legacy.bin");
            await File.WriteAllBytesAsync(src, data);
            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = Offline() });
            BlobTicket ticket = server.Ticket;

            // A pre-2.0 downloader emulated from the raw v1 cipher (production code only
            // ever gets the open-only detector): it seals under the fixed per-ticket key
            // and sends a Hello with an empty body.
            await using var node = await PinholeNode.BindAsync(Offline() with { Listen = false, ReceiveBufferCapacity = 64 });
            await using PinholeConnection conn = await node.ConnectAsync(ticket.ConnectionString);

            var legacy = BlobWire.Cipher.ForLegacyEmulation(ticket.PreSharedKey!, ticket.Root);
            ulong stream = BlobWire.StreamId(ticket.Root);
            var legacyHello = new byte[version == 1 ? 9 : 41];
            legacyHello[0] = BlobWire.TypeHello;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(legacyHello.AsSpan(1), stream);

            conn.Send(version == 1 ? legacy.Seal(asProvider: false, 1, legacyHello) : legacyHello);
            await TestPoll.UntilAsync(TimeSpan.FromSeconds(5), () => conn.State == PinholeConnectionState.Closed); // fast, not the 20 s first-contact timeout
            Assert.Equal(0, server.ChunksServed); // nothing was served under the legacy key

            // Failure isolation: the refusal poisoned nothing — the next (current) downloader
            // of the same ticket completes against the same server.
            string outDir = Path.Combine(dir, "out");
            BlobDownloadResult result = await BlobClient.DownloadAsync(ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);
            Assert.Equal(data.Length, result.Bytes);
            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(outDir, "legacy.bin")));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Ticket_Roundtrips_AndRejectsGarbage()
    {
        var ticket = new BlobTicket
        {
            Kind = BlobKind.File,
            Root = RandomNumberGenerator.GetBytes(32),
            ConnectionString = new Pinhole.ConnectionString(0xABCDEF01,
                [new PinholeCandidate(Pinhole.CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 5000))]).ToString(),
            Name = "holiday.jpg",
            PreSharedKey = RandomNumberGenerator.GetBytes(32),
        };

        Assert.True(BlobTicket.TryParse(ticket.ToString(), out BlobTicket? parsed));
        Assert.Equal(ticket.Root, parsed!.Root);
        Assert.Equal(ticket.Name, parsed.Name);
        Assert.Equal(BlobKind.File, parsed.Kind);
        Assert.NotNull(parsed.PreSharedKey);

        Assert.False(BlobTicket.TryParse("pinholeblob1:!!!!", out _));
        Assert.False(BlobTicket.TryParse("pinhole1:whatever", out _));
        Assert.False(BlobTicket.TryParse("", out _));
    }

    [Fact]
    public async Task PlainTickets_WorkWhenEncryptionIsOff()
    {
        string dir = TempDir();
        try
        {
            string src = Path.Combine(dir, "lan.bin");
            await File.WriteAllBytesAsync(src, RandomBytes(80_000));

            await using var server = await BlobServer.ServeAsync(src,
                new BlobServeOptions { Encrypt = false, NodeOptions = Offline() });
            Assert.Null(server.Ticket.PreSharedKey);

            string outDir = Path.Combine(dir, "out");
            await BlobClient.DownloadAsync(server.Ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() }).WaitAsync(Timeout);
            Assert.Equal(await File.ReadAllBytesAsync(src), await File.ReadAllBytesAsync(Path.Combine(outDir, "lan.bin")));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Cipher_RejectsTamperingReplayAndRoleConfusion()
    {
        byte[] sessionId = BlobWire.Cipher.FreshSessionId();
        var cipher = BlobWire.Cipher.For(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32),
            sessionId, BlobWire.Cipher.FreshSessionId())!;
        byte[] plain = RandomNumberGenerator.GetBytes(200);

        byte[] wire = cipher.Seal(asProvider: true, 7, plain);
        ulong watermark = 0;
        Assert.True(cipher.TryOpen(fromProvider: true, wire, ref watermark, out byte[] opened));
        Assert.Equal(plain, opened);
        Assert.Equal(7UL, watermark);

        byte[] tampered = (byte[])wire.Clone();
        tampered[10] ^= 1;
        Assert.False(cipher.TryOpen(fromProvider: true, tampered, ref watermark, out _), "flipped bit must fail the tag");
        Assert.Equal(7UL, watermark);

        Assert.False(cipher.TryOpen(fromProvider: true, wire, ref watermark, out _), "replay is refused");
        Assert.False(cipher.TryOpen(fromProvider: true, wire, ref watermark, out _), "counter regression is refused");
        Assert.Equal(7UL, watermark);

        byte[] fromDownloader = cipher.Seal(asProvider: false, 1, plain);
        Assert.False(cipher.TryOpen(fromProvider: true, fromDownloader, ref watermark, out _), "roles must not cross");

        var otherKey = BlobWire.Cipher.For(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32),
            BlobWire.Cipher.FreshSessionId(), BlobWire.Cipher.FreshSessionId())!;
        ulong otherWatermark = 0;
        Assert.False(otherKey.TryOpen(fromProvider: true, wire, ref otherWatermark, out _), "tickets never share keys");
    }

    [Fact]
    public async Task RelayedTransfer_ForwardsNothingButCiphertext()
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(120_000);
            string src = Path.Combine(dir, "secret.bin");
            await File.WriteAllBytesAsync(src, data);
            byte[] marker = data[50_000..50_032]; // a needle from mid-file

            await using var relay = new FakeIrohRelay();
            var relayOptions = new PinholeOptions
            {
                StunServers = [],
                Relays = [],
                IrohRelayUrls = [relay.Url],
                EnableNetworkWatch = false,
                ConnectTimeout = Timeout,
            };
            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions { NodeOptions = relayOptions });

            // A ticket whose only candidate is the relay: the downloader has no direct
            // address to punch at, so the handshake — and everything until the engine
            // negotiates an upgrade — rides the relay.
            var full = Pinhole.ConnectionString.Parse(server.Ticket.ConnectionString);
            string relayOnly = new Pinhole.ConnectionString(full.PeerId,
                full.Candidates.Where(c => c.Kind == Pinhole.CandidateKind.IrohRelay).ToArray(),
                staticKey: full.StaticKey).ToString();
            var relayTicket = new BlobTicket
            {
                Kind = server.Ticket.Kind,
                Root = server.Ticket.Root,
                Name = server.Ticket.Name,
                ConnectionString = relayOnly,
                PreSharedKey = server.Ticket.PreSharedKey,
            };

            string outDir = Path.Combine(dir, "out");
            BlobDownloadResult result = await BlobClient.DownloadAsync(relayTicket, outDir,
                options: new BlobDownloadOptions { NodeOptions = relayOptions }).WaitAsync(Timeout);
            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(outDir, "secret.bin")));
            Assert.NotEmpty(relay.Forwarded);

            foreach (byte[] datagram in relay.Forwarded)
            {
                Assert.True(datagram.AsSpan().IndexOf(marker) < 0,
                    "file bytes crossed the relay in the clear — the ticket key must wrap every frame");
            }
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ---------------------------------------------------------------- wire-oracle adversarial provider

    /// <summary>A hand-rolled provider speaking the real wire — engine crypto handshake
    /// from a raw socket, then blob frames sealed under the connection's true cipher —
    /// used to inject hostile frames into a genuine download.</summary>
    private sealed class BlobsOracle : IDisposable
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

        /// <summary>The ticket's connection string, pinning this oracle's static key.</summary>
        public string DialString => new ConnectionString(
            PeerId, [new PinholeCandidate(Pinhole.CandidateKind.Direct, Ep)], NatHint.Unknown, Identity.PublicKey).ToString();

        /// <summary>Answers the downloader's engine handshake, then serves the stream
        /// adversarially: a genuine Head, one forged chunk frame claiming a far-future
        /// counter with a garbage tag, then every genuine chunk. The download must
        /// complete anyway — the watermark must not have moved for the forgery.</summary>
        public async Task ServeAdversariallyAsync(byte[] psk, byte[] root, byte[] content, CancellationToken ct = default)
        {
            var peer = new IPEndPoint(IPAddress.Loopback, 0);
            byte[] buf = new byte[8192];
            byte[] plain = new byte[8192];
            ulong stream = BlobWire.StreamId(root);
            long totalChunks = (content.Length + Blake3.ChunkSize - 1) / Blake3.ChunkSize;

            // Phase 1: engine handshake. The crypto PUNC names the dialer; answer PACK
            // from the address it arrived on.
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
                    BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(9), clientToken); // echo: we saw the PUNC
                    BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(13), EngineToken); // our token for the client to pin
                    _crypto.MyEphPublic.CopyTo(pack.AsSpan(17));
                    _crypto.MyStaticPublic.CopyTo(pack.AsSpan(49));
                    _crypto.MyConfirm().CopyTo(pack.AsSpan(81));
                    await Sock.SendToAsync(pack, client, ct);
                    break;
                }
            }

            // Phase 2: serve. Only the Hello (plaintext inside the engine-sealed Data
            // frame) is answered; everything else the client sends is ignored.
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
                        continue; // handshake frames are plaintext by design
                    }

                    if (!_crypto!.Recv!.Open(buf.AsSpan(0, received), plain, out len))
                    {
                        continue; // not sealed under the session keys: not the downloader
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

                // Retries keep the same cipher and counter space, like a real provider.
                _cipher ??= BlobWire.Cipher.For(psk, root, sid, _providerNonce)!;
                byte[] head = _cipher.Seal(asProvider: true, ++_blobCounter, BlobWire.Head(stream, content.Length, totalChunks));
                byte[] welcome = BlobWire.Welcome(stream, sid, _providerNonce, head);
                byte[] forgedWelcome = welcome.ToArray();
                forgedWelcome[42] ^= 1; // changed provider nonce, same sealed Head: must not bind the client
                await SendSealedAsync(client, forgedWelcome, ct).ConfigureAwait(false);
                await SendSealedAsync(client, welcome, ct).ConfigureAwait(false);

                // The forgery: a chunk frame claiming counter 10_000 with a corrupted
                // tag. It must be refused and consume nothing.
                byte[] first = ChunkFrame(stream, content, 0);
                byte[] forged = _cipher.Seal(asProvider: true, 10_000, first);
                forged[^1] ^= 0xFF;
                await SendSealedAsync(client, forged, ct).ConfigureAwait(false);

                // Every genuine chunk after it, small counters: all must land.
                for (long i = 0; i < totalChunks; i++)
                {
                    await SendBlobAsync(client, ChunkFrame(stream, content, i), ct).ConfigureAwait(false);
                }
            }
        }

        private static byte[] ChunkFrame(ulong stream, byte[] content, long index)
        {
            int len = (int)Math.Min(Blake3.ChunkSize, content.Length - index * Blake3.ChunkSize);
            var chunk = new byte[len];
            Array.Copy(content, index * Blake3.ChunkSize, chunk, 0, len);
            return BlobWire.Chunk(stream, index, Blake3.ChunkCv(chunk, (ulong)index, root: false), chunk);
        }

        private Task SendBlobAsync(EndPoint to, byte[] plain, CancellationToken ct)
        {
            byte[] sealedBlob = _cipher!.Seal(asProvider: true, ++_blobCounter, plain);
            return SendSealedAsync(to, sealedBlob, ct);
        }

        /// <summary>Wraps one blob payload in a genuine engine Data frame — sealed under
        /// the session keys, so the client's engine accepts it; only the inner blob layer
        /// sees hostility.</summary>
        private async Task SendSealedAsync(EndPoint to, ReadOnlyMemory<byte> blobPayload, CancellationToken ct)
        {
            var frame = new byte[13 + CryptoWire.SealedOverhead + blobPayload.Length];
            frame[0] = 0x52; // Data
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

    [Fact]
    public async Task WireOracle_ForgedInnerCounter_MidTransfer_DownloadStillCompletes()
    {
        string dir = TempDir();
        try
        {
            byte[] data = RandomBytes(5000); // 5 chunks
            var tree = new Blake3.Tree();
            tree.Update(data);
            byte[] root = tree.RootHash();
            byte[] psk = RandomNumberGenerator.GetBytes(32);

            using var oracle = new BlobsOracle();
            oracle.Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var ticket = new BlobTicket
            {
                Kind = BlobKind.File,
                Root = root,
                Name = "oracle.bin",
                ConnectionString = oracle.DialString,
                PreSharedKey = psk,
            };

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            Task serve = oracle.ServeAdversariallyAsync(psk, root, data, cts.Token);
            string outDir = Path.Combine(dir, "out");
            BlobDownloadResult result = await BlobClient.DownloadAsync(ticket, outDir,
                options: new BlobDownloadOptions { NodeOptions = Offline() with { EnablePathValidation = false } })
                .WaitAsync(Timeout);

            Assert.Equal(data.Length, result.Bytes);
            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(outDir, "oracle.bin")));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
