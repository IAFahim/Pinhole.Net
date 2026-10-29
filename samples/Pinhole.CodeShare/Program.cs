using System.Net;
using Pinhole;

using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
try
{
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
                    RendezvousEndpoints = directories,
                    CoordinatorUrl = coordinator,
                    NodeOptions = SampleNetwork.Options(),
                }, stop.Token);
                Console.WriteLine($"share this code: {host.Code}");
                Console.WriteLine($"confirmation:    {host.ConfirmationCode}  (compare aloud with your friend)");
                Console.WriteLine($"full invitation: {host.FullInvitation}");
                await using var connection = await host.AcceptAsync(stop.Token);
                Console.WriteLine($"peer connected via {connection.Path.Kind}/{connection.Path.Transport}, encrypted={connection.IsEncrypted}");
                connection.Send("hello from the host"u8.ToArray());
                if (await connection.ReceiveAsync(stop.Token) is { } reply)
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
                    RendezvousEndpoints = directories,
                    CoordinatorUrl = coordinator,
                    NodeOptions = SampleNetwork.Options(),
                }, stop.Token);
                Console.WriteLine($"connected via {connection.Path.Kind}/{connection.Path.Transport}, encrypted={connection.IsEncrypted}");
                if (await connection.ReceiveAsync(stop.Token) is { } greeting)
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
}
catch (OperationCanceledException) when (stop.IsCancellationRequested) { return 0; }
catch (Exception e) { Console.Error.WriteLine($"Connection failed: {e.Message}"); return 1; }
