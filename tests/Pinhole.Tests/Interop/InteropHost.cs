

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
    ReceiveBufferCapacity = 16,
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
