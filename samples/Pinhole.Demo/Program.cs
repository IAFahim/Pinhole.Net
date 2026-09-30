using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using Pinhole;

if (args.Length == 0)
{
    Console.Error.WriteLine("usage: pinhole-demo <rendezvous ip:port> <myIdHex> [peerIdHex]");
    Console.Error.WriteLine("       pinhole-demo bench [count] [size]");
    return 2;
}

if (args[0] == "bench")
{
    return await Bench(args.Length > 1 ? int.Parse(args[1]) : 100_000, args.Length > 2 ? int.Parse(args[2]) : 64);
}

if (args.Length < 2)
{
    Console.Error.WriteLine("usage: pinhole-demo <rendezvous ip:port> <myIdHex> [peerIdHex]");
    return 2;
}

IPEndPoint server = IPEndPoint.Parse(args[0]);
ulong me = ulong.Parse(args[1], NumberStyles.HexNumber);

using PeerSocket peer = new(me);
peer.AddRendezvous(server);
peer.Received += data => Console.WriteLine($"peer: {Encoding.UTF8.GetString(data)}");

IPEndPoint observed = await peer.RegisterAsync();
Console.WriteLine($"registered as {me:x4} — rendezvous sees me at {observed}");

if (args.Length > 2)
{
    ulong target = ulong.Parse(args[2], NumberStyles.HexNumber);
    Console.WriteLine($"dialing {target:x4}…");
    await peer.ConnectAsync(target);
}

await peer.Connected;
Console.WriteLine($"pinhole open to {peer.Peer} — type lines to send, Ctrl-C quits");

_ = Task.Run(async () =>
{
    while (true)
    {
        peer.Ping();
        await Task.Delay(5000);
        if (peer.LastRtt is { } rtt)
        {
            Console.WriteLine($"  rtt {rtt.TotalMilliseconds:F0} ms");
        }
    }
});

while (Console.ReadLine() is { Length: > 0 } line)
{
    peer.Send(Encoding.UTF8.GetBytes(line));
}

return 0;

static async Task<int> Bench(int n, int size)
{
    using var a = new PeerSocket(1);
    using var b = new PeerSocket(2);
    _ = a.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, b.LocalPort));
    _ = b.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, a.LocalPort));
    await Task.WhenAll(a.Connected, b.Connected);

    int received = 0;
    var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    b.Received += _ => { if (Interlocked.Increment(ref received) == n) done.TrySetResult(); };

    byte[] msg = new byte[size];
    int gc0 = GC.CollectionCount(0);
    long allocBefore = GC.GetAllocatedBytesForCurrentThread();
    Stopwatch sw = Stopwatch.StartNew();
    for (int i = 0; i < n; i++)
    {
        a.Send(msg);
    }

    await Task.WhenAny(done.Task, Task.Delay(30_000));
    sw.Stop();
    long alloc = GC.GetAllocatedBytesForCurrentThread() - allocBefore;
    Console.WriteLine($"{received}/{n} datagrams in {sw.Elapsed.TotalSeconds:F2}s ({received / sw.Elapsed.TotalSeconds:F0} dps)");
    Console.WriteLine($"alloc {alloc} B total, {(double)alloc / Math.Max(1, received):F1} B/dgram, gen0 GCs {GC.CollectionCount(0) - gc0}");
    return 0;
}
