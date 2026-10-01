using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using Pinhole;
using Pinhole.Providers;
using Pinhole.Turn;

if (args.Length == 0)
{
    Console.Error.WriteLine("usage: pinhole-demo node [connectionString]");
    Console.Error.WriteLine("       pinhole-demo rendezvous <ip:port> <myIdHex> [peerIdHex]");
    Console.Error.WriteLine("       pinhole-demo stun [host:port]");
    Console.Error.WriteLine("       pinhole-demo turn <host:port> <user> <pass> [peerRelayed ep]");
    Console.Error.WriteLine("       pinhole-demo bench [count] [size]");
    return 2;
}

if (args[0] == "node")
{
    return await NodeChat(args.Length > 1 ? args[1] : null);
}

if (args[0] == "stun")
{
    return await StunProbe(args.Length > 1 ? args[1] : "stun.l.google.com:19302");
}

if (args[0] == "turn")
{
    if (args.Length < 4)
    {
        Console.Error.WriteLine("usage: pinhole-demo turn <host:port> <user> <pass> [peerRelayed ep]");
        return 2;
    }

    return await TurnRelay(args[1], args[2], args[3], args.Length > 4 ? args[4] : null);
}

if (args[0] == "bench")
{
    return await Bench(args.Length > 1 ? int.Parse(args[1]) : 100_000, args.Length > 2 ? int.Parse(args[2]) : 64);
}

if (args[0] == "rendezvous")
{
    return await RendezvousChat(args[1..]);
}

Console.Error.WriteLine($"unknown mode '{args[0]}'");
return 2;

// ---------------------------------------------------------------------------------------------

// The README program, verbatim shape: bind, print the connection string, dial or accept,
// exchange datagrams. Direct when punchable, relayed when not — the chain runs inside.
static async Task<int> NodeChat(string? connectionString)
{
    await using PinholeNode node = await PinholeNode.BindAsync();
    Console.WriteLine($"peer id   {node.PeerId:x16}");
    Console.WriteLine($"udp port  {node.LocalPort}");
    if (node.PublicEndpoints.Count > 0)
    {
        Console.WriteLine($"public    {string.Join(", ", node.PublicEndpoints)}");
    }

    Console.WriteLine();
    Console.WriteLine("connection string (paste it to the peer — how is your problem):");
    Console.WriteLine(node.ConnectionString);
    Console.WriteLine();

    PinholeConnection conn = connectionString is null
        ? await node.AcceptAsync()
        : await node.ConnectAsync(connectionString);

    Console.WriteLine($"connected to {conn.PeerId:x16} — state {conn.State}, path {conn.Path.Kind} ({conn.Path.Remote})");
    Console.WriteLine("type lines to send, Ctrl-C quits");

    conn.Received += d => Console.WriteLine($"peer: {Encoding.UTF8.GetString(d)}");
    conn.StateChanged += s => Console.WriteLine($"  path state -> {s}");
    _ = Task.Run(async () =>
    {
        while (true)
        {
            await Task.Delay(5000);
            conn.Ping();
            if (conn.LastRtt is { } rtt)
            {
                Console.WriteLine($"  rtt {rtt.TotalMilliseconds:F1} ms via {conn.Path.Kind}");
            }
        }
    });

    while (Console.ReadLine() is { Length: > 0 } line)
    {
        conn.Send(Encoding.UTF8.GetBytes(line));
    }

    return 0;
}

// The 1:1 rendezvous introducer flow over the raw PeerSocket engine (pre-session layer).
static async Task<int> RendezvousChat(string[] args)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("usage: pinhole-demo rendezvous <ip:port> <myIdHex> [peerIdHex]");
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

    // Snapshot before any await: GetAllocatedBytesForCurrentThread is per-thread, and
    // the continuation after an await can resume on a different thread-pool thread.
    long alloc = GC.GetAllocatedBytesForCurrentThread() - allocBefore;
    await Task.WhenAny(done.Task, Task.Delay(30_000));
    sw.Stop();
    Console.WriteLine($"{received}/{n} datagrams in {sw.Elapsed.TotalSeconds:F2}s ({received / sw.Elapsed.TotalSeconds:F0} dps)");
    Console.WriteLine($"alloc {alloc} B total, {(double)alloc / Math.Max(1, received):F1} B/dgram, gen0 GCs {GC.CollectionCount(0) - gc0}");
    return 0;
}

static async Task<int> StunProbe(string target)
{
    IPEndPoint server = await ResolveEp(target);
    using var pin = new PeerSocket(0x51);
    IPEndPoint observed = await pin.ProbeStunAsync(server);
    Console.WriteLine($"stun {server} sees this socket at {observed}");
    return 0;
}

static async Task<int> TurnRelay(string target, string user, string pass, string? peer)
{
    IPEndPoint server = await ResolveEp(target);
    await using TurnClient turn = await TurnClient.AllocateAsync(server, user, pass);
    Console.WriteLine($"allocated relayed addr {turn.RelayedAddress}");
    turn.Received += (from, data) => Console.WriteLine($"relay <= {from}: {Encoding.UTF8.GetString(data)}");
    if (peer is null)
    {
        await turn.CreatePermissionAsync(server.Address);
        Console.WriteLine("paste this addr to a peer, waiting…");
        await Task.Delay(600_000);
        return 0;
    }

    IPEndPoint peerEp = IPEndPoint.Parse(peer);
    while (Console.ReadLine() is { Length: > 0 } line)
    {
        await turn.SendAsync(Encoding.UTF8.GetBytes(line), peerEp);
    }

    return 0;
}

static async Task<IPEndPoint> ResolveEp(string s)
{
    int colon = s.LastIndexOf(':');
    string host = s[..colon];
    int port = int.Parse(s[(colon + 1)..]);
    if (IPAddress.TryParse(host, out IPAddress? ip))
    {
        return new IPEndPoint(ip, port);
    }

    IPAddress[] addrs = await Dns.GetHostAddressesAsync(host);
    return new IPEndPoint(addrs[0], port);
}
