using System.Text;
using Pinhole;
using Pinhole.Iroh;

// Run this on both PCs. PC A presses Enter; PC B pastes PC A's ticket.
Console.WriteLine("Starting connection...");
await using IrohPinhole node = await IrohPinhole.BindAsync();

Console.WriteLine("Your connection ticket (share this with your friend):");
Console.WriteLine(node.Ticket);
Console.WriteLine();
Console.WriteLine("One person presses Enter to listen; the other pastes the listener's ticket.");
Console.Write("Paste your friend's ticket, or press Enter to listen: ");
string? peerTicket = Console.ReadLine()?.Trim();
if (peerTicket is null)
{
    return;
}

if (peerTicket.Length == 0)
{
    Console.WriteLine("Waiting for your friend...");
}
else
{
    Console.WriteLine("Connecting to your friend...");
}

await using IrohLink connection = peerTicket.Length == 0
    ? await node.AcceptAsync()
    : await node.ConnectAsync(peerTicket);

using PeerSocket udp = new(0);
udp.Received += data => Console.WriteLine($"Friend: {Encoding.UTF8.GetString(data)}");
connection.Received += data => Console.WriteLine($"Friend: {Encoding.UTF8.GetString(data)}");

Console.WriteLine("Connected. Preparing chat...");
bool useUdp = false;
try
{
    await connection.IntroduceAsync(udp);
    useUdp = true;
}
catch (TimeoutException)
{
    // Different networks may block direct UDP; the iroh connection remains usable.
    Console.WriteLine("Using the iroh fallback connection.");
}

Console.WriteLine("Type messages and press Enter to send. Type /quit to exit.");
while (Console.ReadLine() is { } line && line != "/quit")
{
    if (line.Length == 0)
    {
        continue;
    }

    byte[] message = Encoding.UTF8.GetBytes(line);
    if (useUdp)
    {
        udp.Send(message);
    }
    else
    {
        await connection.SendAsync(message);
    }
}