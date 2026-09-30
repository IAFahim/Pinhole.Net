using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

int port = args.Length > 0 ? int.Parse(args[0]) : 7777;
TimeSpan ttl = args.Length > 1 ? TimeSpan.FromSeconds(double.Parse(args[1], CultureInfo.InvariantCulture)) : TimeSpan.FromSeconds(120);
const int MaxNodes = 4096;
const int MaxWaitersPerTarget = 64;

using var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
udp.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
Console.WriteLine($"pinhole rendezvous listening on [::]:{port}");

ConcurrentDictionary<ulong, (IPEndPoint Ep, DateTimeOffset Seen)> nodes = new();
ConcurrentDictionary<ulong, List<(ulong Id, IPEndPoint Ep, DateTimeOffset At)>> wants = new();
byte[] buffer = new byte[2048];

_ = SweepLoop();

async Task SweepLoop()
{
    while (true)
    {
        await Task.Delay(ttl / 2).ConfigureAwait(false);
        DateTimeOffset cutoff = DateTimeOffset.UtcNow - ttl;
        foreach (var (id, (_, seen)) in nodes)
        {
            if (seen < cutoff)
            {
                nodes.TryRemove(id, out _);
            }
        }

        foreach (var (target, list) in wants)
        {
            bool empty;
            lock (list)
            {
                list.RemoveAll(w => w.At < cutoff);
                empty = list.Count == 0;
            }

            if (empty)
            {
                wants.TryRemove(target, out _);
            }
        }

        Console.WriteLine($"rendezvous sweep: nodes={nodes.Count} wants={wants.Count}");
    }
}

void EvictOldestNode()
{
    ulong? oldest = null;
    DateTimeOffset oldestSeen = DateTimeOffset.MaxValue;
    foreach (var (key, (_, seen)) in nodes)
    {
        if (seen < oldestSeen)
        {
            (oldest, oldestSeen) = (key, seen);
        }
    }

    if (oldest is { } id)
    {
        nodes.TryRemove(id, out _);
    }
}

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
            if (nodes.Count > MaxNodes)
            {
                EvictOldestNode();
            }

            await Say(remote, $"OBS {remote}").ConfigureAwait(false);
            if (wants.TryRemove(id, out List<(ulong Id, IPEndPoint Ep, DateTimeOffset At)>? waiters))
            {
                foreach ((ulong waiterId, IPEndPoint waiterEp, _) in waiters)
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
                    _ => new List<(ulong, IPEndPoint, DateTimeOffset)> { (me, remote, DateTimeOffset.UtcNow) },
                    (_, list) =>
                    {
                        lock (list)
                        {
                            if (list.Count >= MaxWaitersPerTarget)
                            {
                                list.RemoveAt(0);
                            }

                            list.Add((me, remote, DateTimeOffset.UtcNow));
                        }

                        return list;
                    });
                await Say(remote, $"WAIT {target:x16}").ConfigureAwait(false);
            }

            break;
    }
}
