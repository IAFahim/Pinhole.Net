using System.Net;
using Pinhole;

// Two-process host/join example for the minimal SDK (#45 M2). One session per process;
// exchange bytes with a friend using a 9-character code. First run a directory:
//   dotnet run --project src/Pinhole.Rendezvous -c Release -- 44711
// or use the deployed Cloudflare Worker URL (no directory process needed).
//
//   host:  dotnet run -c Release -- host 127.0.0.1:44711
//   join:  dotnet run -c Release -- join 127.0.0.1:44711 ABCDEFGHJ
//   host:  dotnet run -c Release -- host https://pinhole-coordinator.fahimmanowarj5.workers.dev
//   join:  dotnet run -c Release -- join https://pinhole-coordinator.fahimmanowarj5.workers.dev ABCDEFGHJ
//
// SDK statements per side: bind, read the code, accept/join, send, receive, dispose.

string mode = args.Length > 0 ? args[0] : "host";
string address = args.Length > 1 ? args[1]
    : Environment.GetEnvironmentVariable("PINHOLE_COORDINATOR")
        ?? Environment.GetEnvironmentVariable("PINHOLE_DIRECTORY") ?? "127.0.0.1:44711";
Uri? coordinator = Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https" ? uri : null;
IPEndPoint[] directories = coordinator is null ? [IPEndPoint.Parse(address)] : [];

switch (mode)
{
    case "host":
    {
        await using var host = await PinholeSession.HostAsync(new PinholeHostSettings
        {
            RendezvousEndpoints = directories, CoordinatorUrl = coordinator,
        });
        Console.WriteLine($"share this code: {host.Code}");
        Console.WriteLine($"confirmation:    {host.ConfirmationCode}  (compare aloud with your friend)");
        Console.WriteLine($"full invitation: {host.FullInvitation}");
        await using var connection = await host.AcceptAsync();
        Console.WriteLine($"peer connected via {connection.Path.Kind}/{connection.Path.Transport}, encrypted={connection.IsEncrypted}");
        connection.Send("hello from the host"u8.ToArray());
        if (await connection.ReceiveAsync() is { } reply)
        {
            Console.WriteLine($"peer says: {System.Text.Encoding.UTF8.GetString(reply.Span)}");
        }
        break;
    }
    case "join":
    {
        string code = args.Length > 2 ? args[2]
            : throw new ArgumentException("join needs the host's code: join <coordinator-url|directory> <code>");
        await using var connection = await PinholeSession.JoinAsync(code, new PinholeJoinSettings
        {
            RendezvousEndpoints = directories, CoordinatorUrl = coordinator,
        });
        Console.WriteLine($"connected via {connection.Path.Kind}/{connection.Path.Transport}, encrypted={connection.IsEncrypted}");
        if (await connection.ReceiveAsync() is { } greeting)
        {
            Console.WriteLine($"host says: {System.Text.Encoding.UTF8.GetString(greeting.Span)}");
        }
        connection.Send("hello from the joiner"u8.ToArray());
        break;
    }
    default:
        Console.Error.WriteLine("usage: host <coordinator-url|directory> | join <coordinator-url|directory> <code>");
        return 2;
}

return 0;
