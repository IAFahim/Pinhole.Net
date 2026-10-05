using System.Net;

namespace Pinhole.Tests;

/// <summary>An in-process internet for the topology lab: datagram routing between attached
/// sockets through per-test NATs, with drop/delay/reorder shaping on the links. Zero-delay
/// packets are delivered synchronously on the sender's thread (preserving causal order,
/// exactly like loopback UDP); delayed packets ride a scheduler thread, where jitter
/// produces reorder. Rules with bandwidth become bottleneck links: packets serialize one
/// at a time, wait in a bounded FIFO that drops on overflow, and their wait is recorded.
/// Every packet's fate is counted, so a failing scenario reports its physics, not just its
/// outcome.</summary>
internal sealed class VirtualNetwork : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<IPEndPoint, VirtualUdpSocket> _internet = new();
    private readonly List<VirtualNat> _nats = [];
    private readonly List<LinkRule> _rules = [];
    private readonly List<ScheduledPacket> _inflight = [];
    private readonly Dictionary<LinkRule, ShapedLink[]> _links = [];
    private readonly Thread _scheduler;
    private readonly AutoResetEvent _wake = new(false);
    private volatile bool _disposed;

    public long Delivered;
    public long DroppedByPolicy;
    public long Unroutable;

    public VirtualNetwork()
    {
        _scheduler = new Thread(RunScheduler) { IsBackground = true, Name = "virtual-net" };
        _scheduler.Start();
    }

    /// <summary>Installs a shaping rule; first match wins, rules see post-NAT addresses.</summary>
    public void AddRule(LinkRule rule)
    {
        lock (_gate)
        {
            _rules.Add(rule);
            if (rule.IsBottleneck)
            {
                _links[rule] = [new ShapedLink(rule), new ShapedLink(rule)];
            }
        }
    }

    public void RemoveRule(LinkRule rule)
    {
        lock (_gate)
        {
            _rules.Remove(rule);
            _links.Remove(rule);
        }
    }

    /// <summary>Attaches a socket directly to the internet at <paramref name="address"/> —
    /// the endpoint peers dial is the endpoint the engine bound.</summary>
    public VirtualUdpSocket CreateHost(IPEndPoint address)
    {
        var socket = new VirtualUdpSocket(this, address, nat: null);
        lock (_gate)
        {
            _internet[address] = socket;
        }

        return socket;
    }

    /// <summary>Attaches a socket on <paramref name="nat"/>'s private side.</summary>
    public VirtualUdpSocket CreateBehindNat(VirtualNat nat) => nat.Attach();

    // Called by sockets: one datagram leaves an attached socket toward dest.
    internal void RouteFrom(VirtualUdpSocket sender, IPEndPoint dest, byte[] payload)
    {
        IPEndPoint source = sender.Address;
        if (sender.Nat is { } nat)
        {
            if (!nat.TryTranslateOutbound(sender, dest, out source))
            {
                Interlocked.Increment(ref Unroutable); // a fully blocked NAT: not one direct byte leaves
                return;
            }
        }

        Continue(source, dest, payload);
    }

    // Post-NAT routing: shape the internet leg, then deliver.
    private void Continue(IPEndPoint source, IPEndPoint dest, byte[] payload)
    {
        LinkRule? rule;
        lock (_gate)
        {
            rule = _rules.FirstOrDefault(r => r.Match(source, dest));
        }

        if (rule is { DropAll: true })
        {
            Interlocked.Increment(ref rule.Lost);
            Interlocked.Increment(ref DroppedByPolicy);
            return;
        }

        if (rule is { IsBottleneck: true })
        {
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                ShapedLink link = _links[rule][rule.DirectionOf(source, dest)];
                if (!link.Enqueue(source, dest, payload))
                {
                    Interlocked.Increment(ref rule.QueueDrops); // the router buffer is full: congestion loss
                }

                _wake.Set();
            }

            return;
        }

        ApplyLossAndForward(rule, source, dest, payload);
    }

    private void ApplyLossAndForward(LinkRule? rule, IPEndPoint source, IPEndPoint dest, byte[] payload)
    {
        if (rule?.LossFor(source, dest)?.LoseNext() == true)
        {
            Interlocked.Increment(ref rule.Lost);
            Interlocked.Increment(ref DroppedByPolicy);
            return;
        }

        if (rule is not null)
        {
            Interlocked.Increment(ref rule.Passed);
        }

        TimeSpan delay = rule?.Delay ?? TimeSpan.Zero;
        if (rule is { } shaped && shaped.Jitter > TimeSpan.Zero)
        {
            delay += TimeSpan.FromMilliseconds(Random.Shared.NextDouble() * shaped.Jitter.TotalMilliseconds);
        }

        if (delay <= TimeSpan.Zero)
        {
            Deliver(source, dest, payload);
            return;
        }

        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _inflight.Add(new ScheduledPacket(DateTimeOffset.UtcNow + delay, source, dest, payload));
            _wake.Set();
        }
    }

    private void Deliver(IPEndPoint source, IPEndPoint dest, byte[] payload)
    {
        VirtualUdpSocket? host = null;
        VirtualNat? owner = null;
        lock (_gate)
        {
            if (!_internet.TryGetValue(dest, out host))
            {
                owner = _nats.FirstOrDefault(n => n.Owns(dest));
            }
        }

        if (host is not null)
        {
            Interlocked.Increment(ref Delivered);
            host.Enqueue(source, payload);
            return;
        }

        if (owner is not null && owner.TryTranslateInbound(dest, source, out VirtualUdpSocket? internalSocket))
        {
            Interlocked.Increment(ref Delivered);
            internalSocket!.Enqueue(source, payload);
            return;
        }

        // No host, no mapping, or the NAT's filter refused: silence, like a real network.
        Interlocked.Increment(ref Unroutable);
    }

    private void RunScheduler()
    {
        while (!_disposed)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            // Bottleneck transmitters: work-conserving — drain every packet whose
            // serialization time has passed, each occupying the link for size/bandwidth.
            lock (_gate)
            {
                foreach (ShapedLink[] pair in _links.Values)
                {
                    foreach (ShapedLink link in pair)
                    {
                        link.TransmitDue(now, ForwardFromLink);
                    }
                }
            }

            List<ScheduledPacket> due = [];
            lock (_gate)
            {
                for (int i = _inflight.Count - 1; i >= 0; i--)
                {
                    if (_inflight[i].Due <= now)
                    {
                        due.Add(_inflight[i]);
                        _inflight.RemoveAt(i);
                    }
                }
            }

            foreach (ScheduledPacket packet in due)
            {
                Deliver(packet.Source, packet.Dest, packet.Payload);
            }

            _wake.WaitOne(5);
        }
    }

    // Delivery for bottleneck packets after serialization: propagation delay rides the
    // ordinary scheduled-packet path.
    private void ForwardFromLink(LinkRule rule, IPEndPoint source, IPEndPoint dest, byte[] payload,
        DateTimeOffset notBefore)
    {
        // Called under _gate from TransmitDue.
        TimeSpan jitter = rule.Jitter > TimeSpan.Zero
            ? TimeSpan.FromMilliseconds(Random.Shared.NextDouble() * rule.Jitter.TotalMilliseconds)
            : TimeSpan.Zero;
        _inflight.Add(new ScheduledPacket(notBefore + rule.Delay + jitter, source, dest, payload));
    }

    internal void Register(VirtualNat nat)
    {
        lock (_gate)
        {
            _nats.Add(nat);
        }
    }

    /// <summary>A one-line physics report for failure messages and the goodput log.</summary>
    public string Counters()
    {
        lock (_gate)
        {
            string rules = string.Join("; ", _rules.Select(r =>
            {
                string bottleneck = r.IsBottleneck
                    ? $",bw={r.BandwidthBytesPerSecond / 1024:F0}KiB/s,qdrops={Interlocked.Read(ref r.QueueDrops)},qwait={r.MeanQueueWaitMs(Interlocked.Read(ref r.Passed)):F1}ms(max {Interlocked.Read(ref r.MaxQueueWaitMs)}ms)"
                    : "";
                return $"rule(passed={Interlocked.Read(ref r.Passed)},lost={Interlocked.Read(ref r.Lost)}{bottleneck})";
            }));
            string nats = string.Join("; ", _nats.Select(n => n.Counters()));
            return $"delivered={Interlocked.Read(ref Delivered)} dropped={Interlocked.Read(ref DroppedByPolicy)} " +
                   $"unroutable={Interlocked.Read(ref Unroutable)} {rules} {nats}".Trim();
        }
    }

    public void Dispose()
    {
        VirtualUdpSocket[] hosts;
        VirtualNat[] boxes;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _inflight.Clear();
            _links.Clear();
            hosts = _internet.Values.ToArray();
            boxes = _nats.ToArray();
        }

        foreach (VirtualUdpSocket socket in hosts)
        {
            socket.Dispose();
        }

        foreach (VirtualNat nat in boxes)
        {
            nat.Dispose();
        }

        _wake.Set();
    }

    private readonly record struct ScheduledPacket(
        DateTimeOffset Due, IPEndPoint Source, IPEndPoint Dest, byte[] Payload);

    /// <summary>One direction of a bottleneck link: a bounded FIFO feeding a work-conserving
    /// transmitter. State is guarded by the network's gate (the scheduler and sender
    /// threads are the only touchers).</summary>
    private sealed class ShapedLink(LinkRule rule)
    {
        private readonly Queue<(byte[] Payload, IPEndPoint Source, IPEndPoint Dest, DateTimeOffset Enqueued)> _queue = new();
        private long _queuedBytes;
        private DateTimeOffset _busyUntil = DateTimeOffset.MinValue;

        public bool Enqueue(IPEndPoint source, IPEndPoint dest, byte[] payload)
        {
            if (_queuedBytes + payload.Length > rule.QueueCapacityBytes)
            {
                return false; // buffer full: this packet dies at the router
            }

            _queue.Enqueue((payload, source, dest, DateTimeOffset.UtcNow));
            _queuedBytes += payload.Length;
            return true;
        }

        public void TransmitDue(DateTimeOffset now,
            Action<LinkRule, IPEndPoint, IPEndPoint, byte[], DateTimeOffset> schedule)
        {
            // Back-to-back transmission in virtual time: each packet starts at the link's
            // earliest free moment (backlog extends into the future — that wait IS the
            // queueing delay), occupies the link for size/bandwidth, then propagates.
            while (_queue.Count > 0)
            {
                (byte[] payload, IPEndPoint source, IPEndPoint dest, DateTimeOffset enqueued) = _queue.Dequeue();
                _queuedBytes -= payload.Length;
                DateTimeOffset start = _busyUntil > now ? _busyUntil : now;
                _busyUntil = start + TimeSpan.FromSeconds(payload.Length / rule.BandwidthBytesPerSecond);

                long waited = (long)(start - enqueued).TotalMilliseconds;
                Interlocked.Add(ref rule.TotalQueueWaitMs, waited);
                long seenMax = Volatile.Read(ref rule.MaxQueueWaitMs);
                while (waited > seenMax)
                {
                    long prior = Interlocked.CompareExchange(ref rule.MaxQueueWaitMs, waited, seenMax);
                    if (prior == seenMax)
                    {
                        break;
                    }

                    seenMax = prior;
                }

                // The wire's random loss applies at transmission; queue overflow already
                // dropped its victims at enqueue. Both count as loss for the sender to see.
                if (rule.LossFor(source, dest)?.LoseNext() == true)
                {
                    Interlocked.Increment(ref rule.Lost);
                    continue;
                }

                Interlocked.Increment(ref rule.Passed);
                schedule(rule, source, dest, payload, _busyUntil);
            }
        }
    }
}
