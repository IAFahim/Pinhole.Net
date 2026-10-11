using System.Net;
using System.Net.Sockets;
using System.Text;
using Pinhole;
using Pinhole.Providers;

// Everyone runs this sample. Paste a friend's invitation; keep accepting others.
Console.InputEncoding = Console.OutputEncoding = Encoding.UTF8;
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };

try
{
    IPEndPoint[] stun = [];
    try { stun = await StunServers.GoogleAsync(stop.Token); }
    catch (SocketException) { }
    await using var node = await PinholeNode.BindAsync(new PinholeOptions
    { ReceiveBufferCapacity = 64, StunServers = stun, Relays = [] }, stop.Token);

    // One node, many encrypted connections. Direct UDP/TCP or public iroh fallback.
    await new GroupChat(node).RunAsync(args, stop.Token);
    return 0;
}
catch (OperationCanceledException) when (stop.IsCancellationRequested) { return 0; }
catch (Exception e) { Console.Error.WriteLine($"Chat failed: {e.Message}"); return 1; }
