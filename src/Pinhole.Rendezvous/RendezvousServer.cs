using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pinhole.Rendezvous;

/// <summary>A tiny UDP introducer: nodes REGister, waiters WANT a target, and both sides receive
/// an INTRO when the target registers. Entries are TTL-swept and bounded so memory stays flat.</summary>
public sealed class RendezvousServer : IAsyncDisposable
{
    public const int MaxNodes = 4096;
    public const int MaxWaitersPerTarget = 64;

    private readonly Socket _udp;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _run;
    private readonly ConcurrentDictionary<ulong, (IPEndPoint Ep, DateTimeOffset Seen)> _nodes = new();
    private readonly ConcurrentDictionary<ulong, List<(ulong Id, IPEndPoint Ep, DateTimeOffset At)>> _wants = new();

    private RendezvousServer(Socket udp, TimeSpan ttl)
    {
        _udp = udp;
        _ttl = ttl;
        LocalEndPoint = (IPEndPoint)udp.LocalEndPoint!;
        _run = Task.WhenAll(ReceiveLoop(), SweepLoop());
    }

    public IPEndPoint LocalEndPoint { get; }

    private TimeSpan _ttl;

    public static RendezvousServer Start(int port = 0, TimeSpan? ttl = null)
    {
        var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        // An introducer receives registration bursts; the default buffer drops them.
        udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, 4 * 1024 * 1024);
        udp.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
        return new RendezvousServer(udp, ttl ?? TimeSpan.FromSeconds(120));
    }

    public int NodeCount => _nodes.Count;

    public int WantCount => _wants.Count;

    internal int WaitersFor(ulong target)
    {
        if (!_wants.TryGetValue(target, out List<(ulong, IPEndPoint, DateTimeOffset)>? list))
        {
            return 0;
        }

        lock (list)
        {
            return list.Count;
        }
    }

    private async Task ReceiveLoop()
    {
        byte[] buffer = new byte[2048];
        IPEndPoint any = new(IPAddress.IPv6Any, 0);
        while (!_shutdown.IsCancellationRequested)
        {
            SocketReceiveFromResult res;
            try
            {
                res = await _udp.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, any).ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException) when (_shutdown.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException)
            {
                continue;
            }

            if (res.ReceivedBytes == 0)
            {
                continue;
            }

            IPEndPoint remote = (IPEndPoint)res.RemoteEndPoint;
            string[] parts = Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            switch (parts)
            {
                case ["REG", var idText] when ulong.TryParse(idText, NumberStyles.HexNumber, null, out ulong id):
                    _nodes[id] = (remote, DateTimeOffset.UtcNow);
                    if (_nodes.Count > MaxNodes)
                    {
                        EvictOldestNode();
                    }

                    await Say(remote, $"OBS {remote}").ConfigureAwait(false);
                    if (_wants.TryRemove(id, out List<(ulong Id, IPEndPoint Ep, DateTimeOffset At)>? waiters))
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
                    if (_nodes.TryGetValue(target, out (IPEndPoint Ep, DateTimeOffset Seen) entry)
                        && entry.Seen > DateTimeOffset.UtcNow - _ttl)
                    {
                        await Say(remote, $"INTRO {target:x16} {entry.Ep}").ConfigureAwait(false);
                        await Say(entry.Ep, $"INTRO {me:x16} {remote}").ConfigureAwait(false);
                    }
                    else
                    {
                        _wants.AddOrUpdate(target,
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
    }

    private async Task SweepLoop()
    {
        while (!_shutdown.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_ttl / 2, _shutdown.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            DateTimeOffset cutoff = DateTimeOffset.UtcNow - _ttl;
            foreach (var (id, (_, seen)) in _nodes)
            {
                if (seen < cutoff)
                {
                    _nodes.TryRemove(id, out _);
                }
            }

            foreach (var (target, list) in _wants)
            {
                bool empty;
                lock (list)
                {
                    list.RemoveAll(w => w.At < cutoff);
                    empty = list.Count == 0;
                }

                if (empty)
                {
                    _wants.TryRemove(target, out _);
                }
            }
        }
    }

    private void EvictOldestNode()
    {
        ulong? oldest = null;
        DateTimeOffset oldestSeen = DateTimeOffset.MaxValue;
        foreach (var (key, (_, seen)) in _nodes)
        {
            if (seen < oldestSeen)
            {
                (oldest, oldestSeen) = (key, seen);
            }
        }

        if (oldest is { } id)
        {
            _nodes.TryRemove(id, out _);
        }
    }

    private Task Say(IPEndPoint to, string line) =>
        _udp.SendToAsync(new ArraySegment<byte>(Encoding.ASCII.GetBytes(line + '\n')), SocketFlags.None, to);

    public async ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        _udp.Dispose();
        try
        {
            await _run.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The loops end on socket disposal; a faulted loop is irrelevant at shutdown.
        }
    }
}
