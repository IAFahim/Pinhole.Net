using System.Text;
using Pinhole;

// No arguments: share your invitation, or paste a friend's. One argument: join.
if (args.Length > 1) { Console.Error.WriteLine("Usage: Pinhole.Tiny [invitation]"); return 1; }
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
Console.InputEncoding = Console.OutputEncoding = Encoding.UTF8;

try
{
    Console.WriteLine("Starting Pinhole.Tiny...");
    await using var node = await PinholeNode.BindAsync(SampleNetwork.Options(), stop.Token);
    await InvitationChat.RunAsync(node, args.FirstOrDefault(), stop.Token);
    return 0;
}
catch (OperationCanceledException) when (stop.IsCancellationRequested) { return 0; }
catch (Exception e) { Console.Error.WriteLine($"Connection failed: {e.Message}"); return 1; }
