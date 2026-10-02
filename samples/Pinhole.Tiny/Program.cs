// Pinhole in 30 lines. Two machines, one ticket, a chat. That's the whole library.
//   dotnet run -- project samples/Pinhole.Tiny                  # machine A: prints the ticket
//   dotnet run -- project samples/Pinhole.Tiny <ticket>         # machine B: dials A anywhere on earth
using System.Text;
using Pinhole;

await using var node = await PinholeNode.BindAsync();

if (args.Length == 0)
{
    Console.WriteLine("give this ticket to your friend: " + node.ConnectionString);
}

var conn = args.Length == 0 ? await node.AcceptAsync() : await node.ConnectAsync(args[0]);

Console.WriteLine($"connected ({conn.Path.Kind} path) — type away");
conn.Received += d => Console.WriteLine("friend: " + Encoding.UTF8.GetString(d));

while (Console.ReadLine() is { Length: > 0 } line)
{
    conn.Send(Encoding.UTF8.GetBytes(line));
}
