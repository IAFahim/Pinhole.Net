// Interop harness host: copied into a git worktree of another release commit and
// compiled against that tree's sources. Keep this file to the API surface that exists
// on every release under test (serve, ticket, download, infrastructure-free options).
using System.Net;
using Pinhole;
using Pinhole.Blobs;

PinholeOptions OfflineLoopback() => new()
{
    Bind = new IPEndPoint(IPAddress.Loopback, 0),
    StunServers = [],
    Relays = [],
    IrohRelayUrls = [],
    EnableNetworkWatch = false,
    EnablePortMapping = false,
    EnableLanDiscovery = false,
    EnablePathValidation = false,
    ReceiveBufferCapacity = 16, // echo/dial modes need ReceiveAsync, which requires a buffer at bind
};

switch (args[0])
{
    case "serve":
    {
        await using var server = await BlobServer.ServeAsync(args[1],
            new BlobServeOptions { NodeOptions = OfflineLoopback() });
        Console.WriteLine("TICKET " + server.Ticket);
        await Task.Delay(Timeout.Infinite);
        break;
    }
    case "download":
    {
        BlobTicket ticket = BlobTicket.Parse(args[1]);
        BlobDownloadResult result = await BlobClient.DownloadAsync(ticket, args[2],
            options: new BlobDownloadOptions { NodeOptions = OfflineLoopback() });
        Console.WriteLine($"OK {result.Bytes}");
        break;
    }
    case "echo":
    {
        // Old node as the reachable side: prints its connection string, accepts one
        // peer, and echoes datagrams until killed. Exercises the 1.9.0 datagram API a
        // game would use, not just the blob layer.
        await using var node = await PinholeNode.BindAsync(OfflineLoopback());
        Console.WriteLine("TICKET " + node.ConnectionString);
        await using var peer = await node.AcceptAsync();
        Console.WriteLine($"PEER encrypted={peer.IsEncrypted} kind={peer.Path.Kind}");
        while (true)
        {
            ReadOnlyMemory<byte>? received = await peer.ReceiveAsync();
            if (received is { } payload)
            {
                peer.Send(payload.Span);
            }
        }
    }
    case "dial":
    {
        // Old node as the dialer: connects to the current side's connection string,
        // then echoes datagrams until killed.
        await using var node = await PinholeNode.BindAsync(OfflineLoopback());
        await using var peer = await node.ConnectAsync(args[1]);
        Console.WriteLine($"PEER encrypted={peer.IsEncrypted} kind={peer.Path.Kind}");
        while (true)
        {
            ReadOnlyMemory<byte>? received = await peer.ReceiveAsync();
            if (received is { } payload)
            {
                peer.Send(payload.Span);
            }
        }
    }
    default:
        Console.Error.WriteLine($"unknown mode {args[0]}");
        return 2;
}
return 0;
