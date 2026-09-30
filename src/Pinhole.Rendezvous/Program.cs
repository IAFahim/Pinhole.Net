using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

// pinhole-rendezvous — UDP signaling server: doubles as STUN (it sees each peer's
// mapped public endpoint) and as the introducer that swaps candidate addresses.
//
//   REG <id>            → records (id → sender endpoint), replies "OBS <ip:port>"
//   WANT <me> <target>  → sends "INTRO <other> <ep>" to both sides;
//                         target unknown → "WAIT <target>", INTROs fire when it REGs
// Entries expire after Ttl seconds unless refreshed by a re-REG.

int port = args.Length > 0 ? int.Parse(args[0]) : 7777;
TimeSpan ttl = TimeSpan.FromSeconds(120);

using var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
udp.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
Console.WriteLine($"pinhole rendezvous listening on [::]:{port}");

ConcurrentDictionary<ulong, (IPEndPoint Ep, DateTimeOffset Seen)> nodes = new();
ConcurrentDictionary<ulong, List<(ulong Id, IPEndPoint Ep)>> wants = new();
byte[] buffer = new byte[2048];

Task Say(IPEndPoint to, string line) =>
    udp.SendToAsync(new ArraySegment<byte>(Encoding.ASCII.GetBytes(line + '\n')), SocketFlags.None, to);

while (true)
{
    SocketReceiveFromResult res = await udp.ReceiveFromAsync(
        new ArraySegment<byte>(buffer), SocketFlags.None, new IPEndPoint(IPAddress.IPv6Any, 0)).ConfigureAwait(false);
    if (res.ReceivedBytes == 0)
    {
        continue;
    }

    IPEndPoint remote = (IPEndPoint)res.RemoteEndPoint;
    string[] parts = Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
    switch (parts)
    {
        case ["REG", var idText] when ulong.TryParse(idText, NumberStyles.HexNumber, null, out ulong id):
            nodes[id] = (remote, DateTimeOffset.UtcNow);
            await Say(remote, $"OBS {remote}").ConfigureAwait(false);
            if (wants.TryRemove(id, out List<(ulong Id, IPEndPoint Ep)>? waiters))
            {
                foreach ((ulong waiterId, IPEndPoint waiterEp) in waiters)
                {
                    await Say(waiterEp, $"INTRO {id:x16} {remote}").ConfigureAwait(false);
                    await Say(remote, $"INTRO {waiterId:x16} {waiterEp}").ConfigureAwait(false);
                }
            }

            break;
        case ["WANT", var meText, var targetText]
            when ulong.TryParse(meText, NumberStyles.HexNumber, null, out ulong me)
                 && ulong.TryParse(targetText, NumberStyles.HexNumber, null, out ulong target):
            if (nodes.TryGetValue(target, out (IPEndPoint Ep, DateTimeOffset Seen) entry)
                && entry.Seen > DateTimeOffset.UtcNow - ttl)
            {
                await Say(remote, $"INTRO {target:x16} {entry.Ep}").ConfigureAwait(false);
                await Say(entry.Ep, $"INTRO {me:x16} {remote}").ConfigureAwait(false);
            }
            else
            {
                wants.AddOrUpdate(target,
                    _ => new List<(ulong, IPEndPoint)> { (me, remote) },
                    (_, list) => { lock (list) { list.Add((me, remote)); } return list; });
                await Say(remote, $"WAIT {target:x16}").ConfigureAwait(false);
            }

            break;
    }
}
