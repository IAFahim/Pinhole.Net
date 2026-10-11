using System.Net;
using System.Net.Sockets;
using Pinhole;
using Pinhole.Providers;

// No arguments: host. One argument: join the friend's full pinhole1: invitation.
if (args.Length > 1) { Console.Error.WriteLine("Usage: Pinhole.Tiny [invitation]"); return 1; }
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };

try
{
    // Google STUN and the library's public iroh relays; no Cloudflare Worker or TURN.
    IPEndPoint[] stun = [];
    try { stun = await StunServers.GoogleAsync(stop.Token); }
    catch (SocketException) { } // relay/LAN paths can still work if STUN DNS fails
    await using var node = await PinholeNode.BindAsync(new PinholeOptions
    { ReceiveBufferCapacity = 32, StunServers = stun, Relays = [] }, stop.Token);

    if (args.Length == 0) Console.WriteLine($"Share this invitation: {node.ConnectionString}");
    Console.WriteLine("Waiting for your friend...");
    await using var peer = args.Length == 0
        ? await node.AcceptAsync(stop.Token)
        : await node.ConnectAsync(args[0], stop.Token);
    await ChatConsole.RunAsync(peer, stop.Token);
    return 0;
}
catch (OperationCanceledException) when (stop.IsCancellationRequested) { return 0; }
catch (Exception e) { Console.Error.WriteLine($"Connection failed: {e.Message}"); return 1; }
