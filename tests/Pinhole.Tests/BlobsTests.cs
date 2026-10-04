using System.Net;
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
        var cipher = BlobWire.Cipher.For(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32))!;
        byte[] plain = RandomNumberGenerator.GetBytes(200);

        byte[] wire = cipher.Seal(asProvider: true, 7, plain);
        Assert.True(cipher.TryOpen(fromProvider: true, wire, 0, out byte[] opened, out ulong counter));
        Assert.Equal(plain, opened);
        Assert.Equal(7UL, counter);

        byte[] tampered = (byte[])wire.Clone();
        tampered[10] ^= 1;
        Assert.False(cipher.TryOpen(fromProvider: true, tampered, 0, out _, out _), "flipped bit must fail the tag");

        Assert.False(cipher.TryOpen(fromProvider: true, wire, 7, out _, out _), "replay is refused");
        Assert.False(cipher.TryOpen(fromProvider: true, wire, 8, out _, out _), "counter regression is refused");

        byte[] fromDownloader = cipher.Seal(asProvider: false, 1, plain);
        Assert.False(cipher.TryOpen(fromProvider: true, fromDownloader, 0, out _, out _), "roles must not cross");

        var otherKey = BlobWire.Cipher.For(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32))!;
        Assert.False(otherKey.TryOpen(fromProvider: true, wire, 0, out _, out _), "tickets never share keys");
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
                full.Candidates.Where(c => c.Kind == Pinhole.CandidateKind.IrohRelay).ToArray()).ToString();
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
}
