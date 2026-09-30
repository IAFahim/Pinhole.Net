using System.Globalization;
using System.Net;
using System.Text;
using Pinhole;

// pinhole-demo <rendezvous ip:port> <myIdHex> [peerIdHex]
//   with peerIdHex:    ask the rendezvous for an intro, then punch
//   without:           register and wait for someone to punch in

if (args.Length < 2)
{
    Console.Error.WriteLine("usage: pinhole-demo <rendezvous ip:port> <myIdHex> [peerIdHex]");
    return 2;
}

IPEndPoint server = IPEndPoint.Parse(args[0]);
ulong me = ulong.Parse(args[1], NumberStyles.HexNumber);

using PeerSocket peer = new(server, me);
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
