// sendme, the Pinhole edition: one ticket moves a file or a whole directory between
// machines — chunk-verified while streaming, encrypted end to end, resumable across
// restarts, using direct UDP/TCP or the configured relay fallback.
//   dotnet run --project samples/Pinhole.Send -- send ~/photos.tar       # prints a ticket, serves until Ctrl-C
//   dotnet run --project samples/Pinhole.Send -- recv <ticket> ~/dl      # downloads into ~/dl
using System.Diagnostics;
using Pinhole.Blobs;

using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
try
{
    switch (args)
    {
        case ["send", string path]:
            await Send(path, encrypt: true, stop.Token);
            return 0;
        case ["send", string path, "--plain"]:
            await Send(path, encrypt: false, stop.Token);
            return 0;
        case ["recv", string ticket]:
            return await Recv(ticket, ".", stop.Token);
        case ["recv", string ticket, string dir]:
            return await Recv(ticket, dir, stop.Token);
        default:
            Console.WriteLine("""
            usage:
              send <path> [--plain]   serve a file or directory until Ctrl-C, printing its ticket
              recv <ticket> [dir]     download the ticket's content into dir (default: current)
            """);
            return 1;
    }
}
catch (OperationCanceledException) when (stop.IsCancellationRequested) { return 0; }
catch (Exception e) { Console.Error.WriteLine($"Transfer failed: {e.Message}"); return 1; }

static async Task Send(string path, bool encrypt, CancellationToken ct)
{
    Console.WriteLine("Preparing the file and connecting...");
    await using var server = await BlobServer.ServeAsync(path,
        new BlobServeOptions { Encrypt = encrypt, NodeOptions = SampleNetwork.Options() }, ct);
    Console.WriteLine("ticket (hand this to the receiver):");
    Console.WriteLine("  " + SampleNetwork.ShareInvitation(server.Ticket.ToString()));
    Console.WriteLine();
    Console.WriteLine($"serving {Path.GetFileName(path)} until Ctrl-C…");
    try
    {
        while (true)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), ct);
            Console.WriteLine($"  connections: {server.ConnectionsAccepted}, chunks served: {server.ChunksServed}");
        }
    }
    catch (OperationCanceledException)
    {
    }
}

static async Task<int> Recv(string ticketText, string dir, CancellationToken ct)
{
    var gate = new object();
    var watch = Stopwatch.StartNew();
    var progress = new Progress<BlobProgress>(p =>
    {
        lock (gate)
        {
            double pct = p.TotalBytes == 0 ? 100 : 100.0 * p.VerifiedBytes / p.TotalBytes;
            string files = p.FilesTotal > 1 ? $", file {Math.Min(p.FilesDone + 1, p.FilesTotal)}/{p.FilesTotal}" : "";
            Console.Write($"\r{pct,5:0.0}% of {Format(p.TotalBytes)}{files}   ");
        }
    });

    BlobDownloadResult result;
    try
    {
        result = await BlobClient.DownloadAsync(BlobTicket.Parse(SampleNetwork.NormalizeInvitation(ticketText)), dir,
            progress, new BlobDownloadOptions { NodeOptions = SampleNetwork.Options() }, ct);
    }
    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"download failed: {ex.Message}");
        return 1;
    }

    Console.WriteLine();
    Console.WriteLine($"saved {result.Path} ({Format(result.Bytes)}, {(result.Resumed ? "resumed" : "fresh")}, {watch.Elapsed.TotalSeconds:0.0}s)");
    return 0;
}

static string Format(long bytes) => bytes switch
{
    >= 1 << 30 => $"{bytes / (double)(1 << 30):0.##} GiB",
    >= 1 << 20 => $"{bytes / (double)(1 << 20):0.##} MiB",
    >= 1 << 10 => $"{bytes / (double)(1 << 10):0.##} KiB",
    _ => $"{bytes} B",
};
