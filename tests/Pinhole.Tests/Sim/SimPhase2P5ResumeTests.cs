using System.Net;
using System.Security.Cryptography;
using Pinhole.Blobs;
using Pinhole.Sim;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests.Sim;

// R3 property gate P5 at END-TO-END level: blob resume is idempotent —
// Resume(Resume(x)) = Resume(x). x is a mid-flight PBPART02 checkpoint (verified-run
// bitmap + fold state on disk); Resume(x) is a completed, root-verified destination
// file with the checkpoint consumed; the second Resume is a THIRD call of the same
// ticket against the same destination, and it must be a no-op on the wire: zero
// provider connections, zero chunks served, no checkpoint churn, identical file
// bytes. A third call that re-downloads anything means the completed destination is
// not recognized as the transfer's own fixed point. The ledger probe rides the same
// runs (P3 discipline, for free) so conservation is asserted across every dial the
// property exercises. Every stochastic model here is seeded (this suite runs clean
// links; see SimPhase2P1SealTests for the hostile ones).
public sealed class SimPhase2P5ResumeTests(ITestOutputHelper output)
{
    private const long FlowBytes = 512 * 1024;
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task P5_SecondResume_IsAWireNoOp_SameFileSameCheckpointState()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            byte[] data = new byte[FlowBytes];
            RandomNumberGenerator.Fill(data);
            string src = Path.Combine(dir, "resume.bin");
            await File.WriteAllBytesAsync(src, data);
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, 8_000_000, queuePackets: 128,
                delay: TimeSpan.FromMilliseconds(20)));
            await using BlobServer server = await BlobServer.ServeAsync(src, new BlobServeOptions
            {
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 34310)),
                }),
            });

            string dest = Path.Combine(dir, "out");
            string partDir = Path.Combine(dest, "resume.bin.pinhole-part");
            var flow = new BlobFlowBudget(2 * 1024 * 1024);
            var violations = new List<string>();
            long ticks = 0;
            BlobTestHooks.Ledger = (budgetHolds, pacerInFlight, outstandingHolds) =>
            {
                System.Threading.Interlocked.Increment(ref ticks);
                if (budgetHolds != outstandingHolds || budgetHolds != pacerInFlight)
                {
                    lock (violations) violations.Add($"budget={budgetHolds} pacer={pacerInFlight} holds={outstandingHolds}");
                }
            };

            try
            {
                // ---- x: interrupt a healthy transfer mid-flight; the checkpoint is the state.
                long verified = 0;
                var progress = new Progress<BlobProgress>(p => Volatile.Write(ref verified, p.VerifiedBytes));
                using var cts = new CancellationTokenSource();
                Task run1 = Task.Run(() => DownloadAsync(lab, server, dest, flow, progress, cts.Token));
                await TestPoll.UntilAsync(TimeSpan.FromSeconds(20), () => Volatile.Read(ref verified) >= 128 * 1024);
                cts.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run1).WaitAsync(TimeSpan.FromSeconds(15));

                Assert.True(Directory.Exists(partDir), "the interrupted transfer left no checkpoint to resume from");
                Assert.True(File.Exists(Path.Combine(partDir, "state")), "the checkpoint state file is missing");

                // ---- Resume(x): the same call re-dials and finishes from the checkpoint.
                BlobDownloadResult second = await DownloadAsync(lab, server, dest, flow).WaitAsync(Budget);
                Assert.Equal(FlowBytes, second.Bytes);
                Assert.True(second.Resumed, "the second call must resume, not restart");
                Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(dest, "resume.bin")));
                Assert.False(Directory.Exists(partDir), "commit consumed the checkpoint");
                long servedAfterResume = server.ChunksServed;
                long connectionsAfterResume = server.ConnectionsAccepted;

                // ---- Resume(Resume(x)): the fixed point. No dial, no chunk, no state churn.
                BlobDownloadResult third = await DownloadAsync(lab, server, dest, flow).WaitAsync(Budget);
                Assert.Equal(FlowBytes, third.Bytes);
                Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(dest, "resume.bin")));
                Assert.False(Directory.Exists(partDir), "the no-op resurrected checkpoint state");
                Assert.Equal(servedAfterResume, server.ChunksServed);
                Assert.Equal(connectionsAfterResume, server.ConnectionsAccepted);
            }
            finally
            {
                BlobTestHooks.Ledger = null;
            }

            Assert.Empty(violations); // the ledger stayed conserved across every dial
            Assert.Equal(0, flow.UsedBytes);
            output.WriteLine($"resume idempotent: {server.ChunksServed} chunks served total across " +
                             $"{server.ConnectionsAccepted} connections, {ticks} ledger observations");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task P5_TamperedDestination_IsNotTrusted_AndIsOverwrittenByAHonestDownload()
    {
        // The safety valve of the idempotence fix: a destination that exists but does
        // not hash to the ticket root is NOT the fixed point. The call must fall
        // through to a full wire download and overwrite the tampered bytes.
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new();
            byte[] data = new byte[FlowBytes];
            RandomNumberGenerator.Fill(data);
            string src = Path.Combine(dir, "tamper.bin");
            await File.WriteAllBytesAsync(src, data);
            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            lab.Net.AddRule(LinkRule.Bottleneck(region, region, 8_000_000, queuePackets: 128,
                delay: TimeSpan.FromMilliseconds(20)));
            await using BlobServer server = await BlobServer.ServeAsync(src, new BlobServeOptions
            {
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 34310)),
                }),
            });

            string dest = Path.Combine(dir, "out");
            Directory.CreateDirectory(dest);
            byte[] tampered = (byte[])data.Clone();
            tampered[^1] ^= 0xFF;
            await File.WriteAllBytesAsync(Path.Combine(dest, "tamper.bin"), tampered);

            BlobDownloadResult result = await DownloadAsync(lab, server, dest, new BlobFlowBudget(2 * 1024 * 1024))
                .WaitAsync(Budget);

            Assert.Equal(FlowBytes, result.Bytes);
            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(dest, "tamper.bin"))); // healed, not trusted
            Assert.True(server.ChunksServed > 0, "the tampered destination was trusted without a wire download");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ------------------------------------------------------------------ plumbing

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-sim-p5-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static Task<BlobDownloadResult> DownloadAsync(VirtualLab lab, BlobServer server, string dest,
        BlobFlowBudget flow, IProgress<BlobProgress>? progress = null, CancellationToken ct = default) =>
        BlobClient.DownloadAsync(server.Ticket, dest, progress, new BlobDownloadOptions
        {
            NodeOptions = lab.BaseOptions(o => o with
            {
                UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), 34320)),
            }),
            FlowBudget = flow,
        }, ct);
}
