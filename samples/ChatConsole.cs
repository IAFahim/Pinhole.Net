using System.Text;
using Pinhole;

internal static class ChatConsole
{
    internal static async Task RunAsync(PinholeConnection peer, CancellationToken ct,
        Task<string?>? pendingInput = null)
    {

        if (Console.InputEncoding.CodePage != Encoding.UTF8.CodePage)
            Console.InputEncoding = Encoding.UTF8;
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine($"Connected: {SampleNetwork.Describe(peer)}, encrypted={peer.IsEncrypted}");
        Console.WriteLine("Type a message and press Enter. /quit or Ctrl+C exits.");
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task receiving = ReceiveAsync(peer, stop.Token);
        Task sending = Task.Run(async () =>
        {

            while (!stop.IsCancellationRequested)
            {
                string? line = pendingInput is null ? Console.ReadLine()
                    : await pendingInput.WaitAsync(stop.Token);
                pendingInput = null;
                if (line is null or "/quit") break;
                if (line.Length == 0) continue;
                if (Encoding.UTF8.GetByteCount(line) > PinholeConnection.MaxPayload)
                { Console.WriteLine($"Message too long: maximum {PinholeConnection.MaxPayload} UTF-8 bytes."); continue; }
                if (!stop.IsCancellationRequested)
                {
                    try { peer.Send(Encoding.UTF8.GetBytes(line)); }
                    catch (Exception e) when (e is InvalidOperationException or System.Net.Sockets.SocketException)
                    { Console.WriteLine($"Message could not be sent: {e.Message}"); }
                }
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
