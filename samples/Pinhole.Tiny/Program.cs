using System.Net;
using System.Net.Sockets;
using System.Text;
using Pinhole;
using Pinhole.Providers;

// No arguments: share your invitation, or paste a friend's. One argument: join.
if (args.Length > 1) { Console.Error.WriteLine("Usage: Pinhole.Tiny [invitation]"); return 1; }
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
Console.InputEncoding = Console.OutputEncoding = Encoding.UTF8;

try
{
    // Google STUN and the library's public iroh relays; no Cloudflare Worker or TURN.
    IPEndPoint[] stun = [];
    try { stun = await StunServers.GoogleAsync(stop.Token); }
    catch (SocketException) { } // relay/LAN paths can still work if STUN DNS fails
    await using var node = await PinholeNode.BindAsync(new PinholeOptions
    { ReceiveBufferCapacity = 32, StunServers = stun, Relays = [] }, stop.Token);

    Task<string?>? pendingInput = null;
    using var accepting = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
    Task<PinholeConnection> connection;
    if (args.Length != 0)
    {
        Console.WriteLine("Joining your friend...");
        connection = node.ConnectAsync(NormalizeInvitation(args[0]), stop.Token);
    }
    else
    {
        // Avoid underscores, which chat apps can consume as formatting when sharing.
        string share = node.ConnectionString.Replace('-', '+').Replace('_', '/');
        Console.WriteLine($"Share this invitation: {share}");
        Console.WriteLine("Paste your friend's full pinhole1: invitation and press Enter, or leave this window open for them to join. /quit exits.");
        connection = node.AcceptAsync(accepting.Token);
        pendingInput = Task.Run(Console.ReadLine);
        while (await Task.WhenAny(connection, pendingInput).WaitAsync(stop.Token) != connection)
        {
            string? invitation = (await pendingInput) is { } line ? NormalizeInvitation(line) : null;
            pendingInput = null;
            if (invitation is null or "/quit") { accepting.Cancel(); return 0; }
            if (!ConnectionString.TryParse(invitation, out _))
            {
                Console.WriteLine("Invalid invitation: copy the entire pinhole1: string as plain text; sharing apps may remove characters. Still waiting for your friend...");
                pendingInput = Task.Run(Console.ReadLine);
                continue;
            }
            accepting.Cancel();
            // If the friend joined as we pasted, keep that already accepted connection.
            try { await connection; }
            catch (OperationCanceledException) when (accepting.IsCancellationRequested)
            { connection = node.ConnectAsync(invitation, stop.Token); }
            break;
        }
    }
    await using var peer = await connection;
    await ChatConsole.RunAsync(peer, stop.Token, pendingInput);
    return 0;
}
catch (OperationCanceledException) when (stop.IsCancellationRequested) { return 0; }
catch (Exception e) { Console.Error.WriteLine($"Connection failed: {e.Message}"); return 1; }

// The SDK's wire format stays base64url; this console accepts either share spelling.
static string NormalizeInvitation(string text) =>
    text.Trim().Trim('"', '\'', '`').Replace('+', '-').Replace('/', '_');
