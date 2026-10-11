using System.Text;
using Pinhole;

// Shared console UI. Both samples use the same Send/Receive API once connected.
internal static class ChatConsole
{
    internal static async Task RunAsync(PinholeConnection peer, CancellationToken ct)
    {
        Console.InputEncoding = Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine($"Connected: {peer.Path.Kind} {peer.Path.Transport}, encrypted={peer.IsEncrypted}");
        Console.WriteLine("Type a message and press Enter. /quit or Ctrl+C exits.");
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task receiving = ReceiveAsync(peer, stop.Token);
        Task sending = Task.Run(() =>
        {
            // Console input blocks, so keep it off the receive loop's thread.
            while (!stop.IsCancellationRequested && Console.ReadLine() is { } line && line != "/quit")
            {
                if (line.Length == 0) continue;
                if (Encoding.UTF8.GetByteCount(line) > PinholeConnection.MaxPayload)
                { Console.WriteLine($"Message too long: maximum {PinholeConnection.MaxPayload} UTF-8 bytes."); continue; }
                if (!stop.IsCancellationRequested) peer.Send(Encoding.UTF8.GetBytes(line));
            }
        });
        try { await await Task.WhenAny(sending, receiving); }
        finally
        {
            stop.Cancel();
            try { await receiving; }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
        Console.WriteLine("Disconnected.");
    }

    private static async Task ReceiveAsync(PinholeConnection peer, CancellationToken ct)
    {
        await foreach (var message in peer.ReadAllAsync(ct))
            Console.WriteLine("Friend: " + Encoding.UTF8.GetString(message.Span));
    }
}
