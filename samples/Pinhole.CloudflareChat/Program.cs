using Pinhole;

// No arguments: host. One argument: join the friend's nine-character code.
if (args.Length > 1) { Console.Error.WriteLine("Usage: Pinhole.CloudflareChat [code]"); return 1; }
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };

try
{
    Console.WriteLine("Starting Pinhole.CloudflareChat...");
    var coordinator = new Uri(Environment.GetEnvironmentVariable("PINHOLE_COORDINATOR")
        ?? "https://pinhole-coordinator.fahimmanowarj5.workers.dev");
    PinholeOptions options = SampleNetwork.Options();
    await using var host = args.Length == 0
        ? await PinholeSession.HostAsync(new PinholeHostSettings { CoordinatorUrl = coordinator, NodeOptions = options }, stop.Token)
        : null;
    if (host is not null) Console.WriteLine($"Share this code: {host.Code}");
    Console.WriteLine("Waiting for your friend...");
    await using var peer = host is not null
        ? await host.AcceptAsync(stop.Token)
        : await PinholeSession.JoinAsync(args[0], new PinholeJoinSettings { CoordinatorUrl = coordinator, NodeOptions = options }, stop.Token);
    await ChatConsole.RunAsync(peer, stop.Token);
    return 0;
}
catch (OperationCanceledException) when (stop.IsCancellationRequested) { return 0; }
catch (Exception e) { Console.Error.WriteLine($"Connection failed: {e.Message}"); return 1; }
