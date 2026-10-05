using System.Diagnostics;
using System.Net;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

public sealed class DiagCc(ITestOutputHelper output)
{
    [Fact]
    public async Task Trace()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-diag-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            using VirtualLab lab = new();
            byte[] data = new byte[128 * 1024];
            Random.Shared.NextBytes(data);
            string src = Path.Combine(dir, "d.bin");
            await File.WriteAllBytesAsync(src, data);
            await using var server = await BlobServer.ServeAsync(src, new BlobServeOptions
            {
                NodeOptions = lab.BaseOptions(o => o with
                {
                    UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 33010)),
                }),
            });

            Subnet providers = Subnet.Parse(VirtualLab.Hosts4SecondRegion);
            Subnet downloaders = Subnet.Parse(VirtualLab.Hosts4);
            LinkRule rule = LinkRule.Bottleneck(providers, downloaders, 1.5 * 1024 * 1024, 96 * 1024,
                TimeSpan.Zero);
            lab.Net.AddRule(rule);

            var progress = new Progress<BlobProgress>(p => output.WriteLine($"progress: {p.VerifiedBytes}/{p.TotalBytes}"));
            Task<BlobDownloadResult> download = Task.Run(() => BlobClient.DownloadAsync(server.Ticket, Path.Combine(dir, "out"),
                progress: progress,
                options: new BlobDownloadOptions
                {
                    NodeOptions = lab.BaseOptions(o => o with
                    {
                        UdpSocketFactory = _ => lab.Net.CreateHost(new IPEndPoint(IPAddress.Parse("192.0.2.20"), 33020)),
                    }),
                }));

            var sw = Stopwatch.StartNew();
            BlobClient.CcTrace = line => output.WriteLine($"[{sw.Elapsed.Seconds:F0}s] {line}");
            int hello = 0, req = 0, ticks = 0, chunkRx = 0;
            BlobClient.LoopTick += () => Interlocked.Increment(ref ticks);
            BlobServer.ServeTrace = line =>
            {
                if (line.EndsWith(" 4")) { Interlocked.Increment(ref chunkRx); }
            };
            while (sw.Elapsed < TimeSpan.FromSeconds(20))
            {
                await Task.Delay(1000);
                output.WriteLine($"t+{sw.Elapsed.Seconds}: chunksServed={server.ChunksServed} chunkRx~={Volatile.Read(ref chunkRx)} loopTicks={Interlocked.Exchange(ref ticks, 0)} conns=[{string.Join(",", server.Node.Connections.Select(c => $"{c.PeerId:x8}:{c.State}:{c.Path.Kind}"))}] {lab.Net.Counters()}");
                if (download.IsCompleted)
                {
                    break;
                }
            }

            BlobDownloadResult result = await download.WaitAsync(TimeSpan.FromSeconds(25));
            output.WriteLine($"done: {result.Bytes} bytes, re-requests={result.ReRequests}, {lab.Net.Counters()}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
