using System.Text;
using Pinhole;

// Run this on both PCs and exchange the printed connection strings.
Console.WriteLine("Starting connection...");
await using PinholeNode node = await PinholeNode.BindAsync();

string myConnectionString = node.ConnectionString;
Console.WriteLine("Your connection string (share this with your friend):");
Console.WriteLine(myConnectionString);
Console.WriteLine();
if (node.HasRelay)
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

    Console.WriteLine("Connecting to your friend...");
    PinholeConnectResult result = await node.TryConnectAsync(peerConnectionString);
    if (result.IsSuccess)
    {
        connected = result.Connection;
        break;
    }
    Console.WriteLine(result.ErrorMessage);
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
