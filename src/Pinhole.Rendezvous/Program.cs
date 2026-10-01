using System.Globalization;
using Pinhole.Rendezvous;

int port = args.Length > 0 ? int.Parse(args[0]) : 7777;
TimeSpan ttl = args.Length > 1 ? TimeSpan.FromSeconds(double.Parse(args[1], CultureInfo.InvariantCulture)) : TimeSpan.FromSeconds(120);

await using RendezvousServer server = RendezvousServer.Start(port, ttl);
Console.WriteLine($"pinhole rendezvous listening on [::]:{server.LocalEndPoint.Port}");
await Task.Delay(Timeout.Infinite);
