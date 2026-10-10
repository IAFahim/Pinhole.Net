using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using Pinhole.Blobs;
using Xunit;

namespace Pinhole.Tests;

/// <summary>RecoveryTimeout must bound unavailable routes without bounding healthy
/// transfer time. These tests exercise the actual downloader over the virtual socket
/// seam, including cancellation of pending dials and release of request reservations.</summary>
public sealed class BlobRecoveryDeadlineTests
{
    private static readonly TimeSpan Ceiling = TimeSpan.FromSeconds(10);

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
    public async Task HealthyTimeBeforeProviderRestart_DoesNotSpendRecoveryAllowance()
    {
        string dir = TempDir();
        using var stop = new CancellationTokenSource(Ceiling + Ceiling);
        Task<BlobDownloadResult>? download = null;
        try
        {
            using var lab = new VirtualLab();
            byte[] seed = RandomNumberGenerator.GetBytes(32);
            byte[] expected = TestDispose.Pattern(512 * 1024, 0xA3);
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
            var halfDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var progress = new InlineProgress(p =>
            {
                if (p.VerifiedBytes >= expected.Length / 2) halfDone.TrySetResult();
            });
            var watch = Stopwatch.StartNew();
            TimeSpan allowance = TimeSpan.FromSeconds(1);
            download = BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"), progress,
                Options(lab) with { RecoveryTimeout = allowance }, stop.Token);
            await halfDone.Task.WaitAsync(Ceiling);
            Assert.True(watch.Elapsed > allowance, "the healthy portion must exceed the recovery allowance");
            await server.DisposeAsync();
            await using BlobServer successor = await BlobServer.ServeAsync(source, serveOptions);

            BlobDownloadResult result = await download.WaitAsync(Ceiling);
            Assert.True(result.Resumed);
            Assert.True(successor.ConnectionsAccepted >= 1);
            Assert.Equal(expected, await File.ReadAllBytesAsync(result.Path));
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
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(15));
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
                Options(lab) with { RecoveryTimeout = TimeSpan.FromSeconds(4), FlowBudget = flow }, stop.Token);
            await firstCut.Task.WaitAsync(Ceiling);
            await Task.Delay(TimeSpan.FromMilliseconds(2500), stop.Token);
            Volatile.Write(ref allowedChunks, 16);
            lab.Net.RemoveRule(cut);
            await secondCut.Task.WaitAsync(Ceiling);

            // The first outage used over half the allowance. A fresh four-second
            // clock on the second outage would fail to terminate within this wait.
            TimeoutException failure = await Assert.ThrowsAsync<TimeoutException>(async () =>
                await download.WaitAsync(TimeSpan.FromSeconds(3)));
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
