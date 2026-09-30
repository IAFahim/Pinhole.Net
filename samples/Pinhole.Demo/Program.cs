using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using N0.IrohNet;
using Pinhole;
using Pinhole.Iroh;

if (args.Length == 0)
{
    Console.Error.WriteLine("usage: pinhole-demo <rendezvous ip:port> <myIdHex> [peerIdHex]");
    Console.Error.WriteLine("       pinhole-demo iroh [peerTicket]");
    Console.Error.WriteLine("       pinhole-demo bench [count] [size]");
    return 2;
}

if (args[0] == "bench")
{
    return await Bench(args.Length > 1 ? int.Parse(args[1]) : 100_000, args.Length > 2 ? int.Parse(args[2]) : 64);
}

if (args[0] == "iroh")
{
    return await IrohChat(args.Length > 1 ? args[1] : null);
}

if (args[0] == "bindtest")
{
    return await BindTest();
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

static unsafe Task<int> BindTest()
{
    byte[] alpn = Encoding.ASCII.GetBytes("pinhole/0");
    EndpointConfig config = iroh.endpoint_config_default();
    config.relay_mode = RelayMode.RELAY_MODE_DEFAULT;
    config.discovery_cfg = DiscoveryConfig.DISCOVERY_CONFIG_ALL;
    fixed (byte* a = alpn)
    {
        iroh.endpoint_config_add_alpn(&config, new slice_ref_uint8 { ptr = a, len = (nuint)alpn.Length });
    }

    Endpoint* ep = iroh.endpoint_default();
    EndpointResult r = iroh.endpoint_bind(&config, null, null, &ep);
    Console.WriteLine($"bind result: {r} ep: {(nint)ep:x}");
    iroh.endpoint_config_free(config);
    if (ep != null)
    {
        iroh.endpoint_free(ep);
    }

    return Task.FromResult(0);
}

static async Task<int> IrohChat(string? ticket)
{
    await using IrohPinhole node = await IrohPinhole.BindAsync();
    using var pin = new PeerSocket(0);
    Console.WriteLine($"ticket: {node.Ticket}");
    Console.WriteLine($"addrs:  {string.Join(", ", node.DirectAddresses)}");
    await using IrohLink link = ticket is null ? await node.AcceptAsync() : await node.ConnectAsync(ticket);

    pin.Received += d => Console.WriteLine($"peer(udp):   {Encoding.UTF8.GetString(d)}");
    link.Received += d => Console.WriteLine($"peer(relay): {Encoding.UTF8.GetString(d)}");

    Console.WriteLine("introducing over iroh…");
    bool fast = false;
    try
    {
        await link.IntroduceAsync(pin);
        fast = true;
        Console.WriteLine($"pinhole open to {pin.Peer} — UDP fast path active");
    }
    catch (Exception e)
    {
        Console.WriteLine($"punch failed ({e.Message}) — staying on iroh relay path");
    }

    while (Console.ReadLine() is { Length: > 0 } line)
    {
        byte[] body = Encoding.UTF8.GetBytes(line);
        if (fast)
        {
            pin.Send(body);
        }
        else
        {
            await link.SendAsync(body);
        }
    }

    return 0;
}

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
