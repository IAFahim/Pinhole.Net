using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using Pinhole.Blobs;
using Pinhole.Sim;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests.Sim;

public sealed class SimPhase2P1SealTests(ITestOutputHelper output)
{
    private const int SessionDatagrams = 800;
    private const long BlobBytes = 256 * 1024;
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task P1_HostileNet_SessionDeliversEachDatagramExactlyOnce_IntactOrNotAtAll()
    {
        using VirtualLab lab = new(seed: 7);
        Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
        LinkRule hostile = LinkRule.Hostile(region, region,
            duplicate: new IndependentDuplication(0.12, seed: 11),
            corrupt: new IndependentCorruption(0.04, seed: 13),
            delay: TimeSpan.FromMilliseconds(10), jitter: TimeSpan.FromMilliseconds(25));
        lab.Net.AddRule(hostile);

        await using PinholeNode listenerNode = await lab.BindNodeAsync(
            hostAddress: new IPEndPoint(IPAddress.Parse("198.51.100.10"), 0),
            tweak: o => o with { ConnectTimeout = TimeSpan.FromSeconds(10) });
        await using PinholeNode dialerNode = await lab.BindNodeAsync(
            hostAddress: new IPEndPoint(IPAddress.Parse("198.51.100.20"), 0),
            tweak: o => o with { ConnectTimeout = TimeSpan.FromSeconds(10) });

        Task<PinholeConnection> accept = listenerNode.AcceptAsync();
        PinholeConnection dialer = await dialerNode.ConnectAsync(listenerNode.ConnectionString).WaitAsync(Budget);
        PinholeConnection listener = await accept.WaitAsync(Budget);

        var sendCount = new long[SessionDatagrams];
        var deliveryCount = new long[SessionDatagrams];
        long deliveries = 0;
        long deliveriesCorrupt = 0;
        long echoesFailed = 0;
        long retransmits = 0;

        listener.Received += payload =>
        {
            long seq = BinaryPrimitives.ReadInt64LittleEndian(payload);
            bool intact = seq >= 0 && seq < SessionDatagrams && payload.SequenceEqual(Payload(seq));
            lock (deliveryCount)
            {
                deliveries++;
                if (!intact)
                {
                    deliveriesCorrupt++;
                }
                else
                {
                    deliveryCount[seq]++;
                }
            }

            try
            {
                listener.Send(payload);
            }
            catch (InvalidOperationException)
            {
                echoesFailed++;
            }
        };

        bool[] acked = new bool[SessionDatagrams];
        int acks = 0;
        dialer.Received += payload =>
        {
            long seq = BinaryPrimitives.ReadInt64LittleEndian(payload);
            if (seq >= 0 && seq < SessionDatagrams && !acked[seq])
            {
                acked[seq] = true;
                Interlocked.Increment(ref acks);
            }
        };

        void Send(int seq)
        {
            try
            {
                dialer.Send(Payload(seq));
                lock (sendCount) sendCount[seq]++;
            }
            catch (InvalidOperationException)
            {

            }
        }

        var sw = Stopwatch.StartNew();
        for (int seq = 0; seq < SessionDatagrams; seq++)
        {
            Send(seq);
            await Task.Delay(2);
        }

        while (Volatile.Read(ref acks) < SessionDatagrams)
        {
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(30),
                $"only {Volatile.Read(ref acks)}/{SessionDatagrams} datagrams were acked through the hostile leg");
            await Task.Delay(150);
            for (int seq = 0; seq < SessionDatagrams; seq++)
            {
                if (!acked[seq])
                {
                    retransmits++;
                    Send(seq);
                }
            }
        }

        await Task.Delay(1000);

        lock (sendCount)
        lock (deliveryCount)
        {
            Assert.Equal(0, deliveriesCorrupt);
            for (int seq = 0; seq < SessionDatagrams; seq++)
            {
                Assert.True(sendCount[seq] >= 1, $"seq {seq} was never successfully sent");
                Assert.True(deliveryCount[seq] >= 1, $"seq {seq} was never delivered");
                Assert.True(deliveryCount[seq] <= sendCount[seq],
                    $"seq {seq} was delivered {deliveryCount[seq]} times but sent only {sendCount[seq]} — " +
                    "the hostile net's duplicate double-delivered");
            }
        }

        Assert.Equal(deliveries, listener.Stats.DatagramsReceived);

        Assert.True(hostile.Duplicated >= 24, $"only {hostile.Duplicated} duplicates crossed");
        Assert.True(hostile.Corrupted >= 8, $"only {hostile.Corrupted} corrupted crossings");
        Assert.True(listener.FramesRejected > 0, "the receiver never refused a hostile frame");
        Assert.True(dialer.FramesRejected > 0, "the echo direction never refused a hostile frame");

        output.WriteLine($"{SessionDatagrams} datagrams: {deliveries} deliveries ({retransmits} app retransmits, " +
                         $"{echoesFailed} refused echoes) | hostile: duplicated={hostile.Duplicated} corrupted={hostile.Corrupted} " +
                         $"| refused: receiver={listener.FramesRejected} sender={dialer.FramesRejected} " +
                         $"| {lab.Net.Counters()} in {sw.Elapsed.TotalSeconds:F1}s");
    }

    [Fact]
    public async Task P1_HostileNet_BlobTransferStaysByteExact_UnderDuplicationCorruptionAndLoss()
    {
        string dir = TempDir();
        try
        {
            using VirtualLab lab = new(seed: 17);
            byte[] data = new byte[BlobBytes];
            RandomNumberGenerator.Fill(data);
            string src = Path.Combine(dir, "seal.bin");
            await File.WriteAllBytesAsync(src, data);

            Subnet region = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            LinkRule hostile = LinkRule.Hostile(region, region,
                duplicate: new IndependentDuplication(0.12, seed: 31),
                corrupt: new IndependentCorruption(0.03, seed: 33),
                forwardLoss: new GilbertElliottLoss(0.02, 8, seed: 35),
                reverseLoss: new GilbertElliottLoss(0.02, 6, seed: 37),
                delay: TimeSpan.FromMilliseconds(10), jitter: TimeSpan.FromMilliseconds(15));
            lab.Net.AddRule(hostile);

            await using BlobServer server = await BlobServer.ServeAsync(src, new BlobServeOptions
            {
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 34410)),
                }),
            });

            var stats = new BlobTransferStats();
            var sw = Stopwatch.StartNew();
            BlobDownloadResult result = await BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"), null,
                new BlobDownloadOptions
                {
                    NodeOptions = lab.BaseOptions(o => o with
                    {
                        UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.20"), 34420)),
                    }),
                    Stats = stats,
                }).WaitAsync(Budget);
            sw.Stop();

            Assert.Equal(BlobBytes, result.Bytes);
            Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(dir, "out", "seal.bin")));

            Assert.True(hostile.Duplicated >= 16, $"only {hostile.Duplicated} duplicates crossed");
            Assert.True(hostile.Corrupted >= 4, $"only {hostile.Corrupted} corrupted crossings");
            Assert.True(hostile.Lost >= 4, $"only {hostile.Lost} datagrams were lost");
            output.WriteLine($"byte-exact {BlobBytes / 1024} KiB through duplication+corruption+loss in " +
                             $"{sw.Elapsed.TotalSeconds:F1}s | duplicated={hostile.Duplicated} corrupted={hostile.Corrupted} " +
                             $"lost={hostile.Lost} | retransmits={stats.Retransmits} requests={stats.RequestsSent} " +
                             $"| {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static byte[] Payload(long seq)
    {
        int length = 24 + (int)(seq * 37 % 200);
        var payload = new byte[length];
        BinaryPrimitives.WriteInt64LittleEndian(payload, seq);
        for (int i = 8; i < length; i++)
        {
            payload[i] = (byte)(seq * 31 + i * 17 + 5);
        }

        return payload;
    }

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-sim-p1-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
