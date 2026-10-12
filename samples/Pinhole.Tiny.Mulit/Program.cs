using System.Text;
using Pinhole;

// Everyone runs this sample. Paste a friend's invitation; keep accepting others.
Console.InputEncoding = Console.OutputEncoding = Encoding.UTF8;
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };

try
{
    Console.WriteLine("Starting Pinhole.Tiny.Mulit...");
    await using var node = await PinholeNode.BindAsync(SampleNetwork.Options(), stop.Token);

    // One node, many encrypted connections. Direct UDP/TCP or iroh/DERP fallback.
    await new GroupChat(node).RunAsync(args, stop.Token);
    return 0;
}
catch (OperationCanceledException) when (stop.IsCancellationRequested) { return 0; }
catch (Exception e) { Console.Error.WriteLine($"Chat failed: {e.Message}"); return 1; }
