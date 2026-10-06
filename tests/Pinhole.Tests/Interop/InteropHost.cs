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
    default:
        Console.Error.WriteLine($"unknown mode {args[0]}");
        return 2;
}
return 0;
