using System.Text;
using Pinhole;

// Run this on both PCs and exchange the printed connection strings.
Console.WriteLine("Starting connection...");
await using PinholeNode node = await PinholeNode.BindAsync();

string myConnectionString = node.ConnectionString;
Console.WriteLine("Your connection string (share this with your friend):");
Console.WriteLine(myConnectionString);
Console.WriteLine();
bool hasRelay = ConnectionString.Parse(myConnectionString).Candidates.Any(c => c.Kind is CandidateKind.Relay or CandidateKind.IrohRelay);
if (hasRelay)
{
    Console.WriteLine("One person presses Enter to listen; the other pastes the listener's connection string.");
}
else
{
    Console.WriteLine("No relay available. On different networks, both paste each other's connection strings.");
    Console.WriteLine("Paste on both PCs within 15 seconds of each other to try a direct connection.");
}

PinholeConnection connected;
while (true)
{
    Console.Write("Paste your friend's connection string, Enter to listen, or /quit: ");
    string? peerConnectionString = Console.ReadLine()?.Trim();
    if (peerConnectionString is null or "/quit") return;
    if (peerConnectionString.Length == 0)
    {
        Console.WriteLine("Waiting for your friend...");
        connected = await node.AcceptAsync();
        break;
    }

    // Accept the code on its own if the "pinhole1:" prefix wasn't copied.
    if (!peerConnectionString.Contains(':'))
    {
        peerConnectionString = ConnectionString.Scheme + ":" + peerConnectionString;
    }

    if (!ConnectionString.TryParse(peerConnectionString, out ConnectionString? peer))
    {
        Console.WriteLine("Invalid connection string. Copy your friend's connection string and try again.");
        continue;
    }

    if (peer.PeerId == node.PeerId)
    {
        Console.WriteLine("That is your own connection string. Paste your friend's, or press Enter to listen.");
        continue;
    }

    Console.WriteLine("Connecting to your friend...");
    try
    {
        connected = await node.ConnectAsync(peerConnectionString);
        break;
    }
    catch (TimeoutException)
    {
        Console.WriteLine("Connection timed out. Keep both apps running and paste each other's current strings around the same time.");
        if (!peer.Candidates.Any(c => c.Kind is CandidateKind.Relay or CandidateKind.IrohRelay))
        {
            Console.WriteLine("Your friend's string has no relay. If direct attempts keep failing, a working relay is needed.");
        }
    }
}

await using PinholeConnection connection = connected;

connection.Received += data => Console.WriteLine($"Friend: {Encoding.UTF8.GetString(data)}");

Console.WriteLine("Connected. Type messages and press Enter to send. Type /quit to exit.");
while (Console.ReadLine() is { } line && line != "/quit")
{
    if (line.Length == 0)
    {
        continue;
    }

    byte[] message = Encoding.UTF8.GetBytes(line);
    if (message.Length > PinholeConnection.MaxPayload)
    {
        Console.WriteLine($"Message too long (maximum {PinholeConnection.MaxPayload} UTF-8 bytes).");
        continue;
    }

    connection.Send(message);
}
