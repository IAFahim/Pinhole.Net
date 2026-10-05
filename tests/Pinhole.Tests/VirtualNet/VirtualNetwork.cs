using System.Net;

namespace Pinhole.Tests;

/// <summary>An in-process internet for the topology lab: datagram routing between attached
/// sockets through per-test NATs, with drop/delay/reorder shaping on the links. Zero-delay
/// packets are delivered synchronously on the sender's thread (preserving causal order,
/// exactly like loopback UDP); delayed packets ride a scheduler thread, where jitter
/// produces reorder. Every packet's fate is counted, so a failing scenario reports its
/// physics, not just its outcome.</summary>
internal sealed class VirtualNetwork : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<IPEndPoint, VirtualUdpSocket> _internet = new();
    private readonly List<VirtualNat> _nats = [];
    private readonly List<LinkRule> _rules = [];
    private readonly List<ScheduledPacket> _inflight = [];
    private readonly Dictionary<LinkRule, Shaper> _shapers = new();
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
        }
    }

    public void RemoveRule(LinkRule rule)
    {
        lock (_gate)
        {
            _rules.Remove(rule);
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

        bool lost = rule switch
        {
            { DropAll: true } => true,
            _ => rule?.LossFor(source, dest)?.LoseNext() == true,
        };
        if (lost)
        {
            if (rule is not null)
            {
                Interlocked.Increment(ref rule.Lost);
            }

            Interlocked.Increment(ref DroppedByPolicy);
            return;
        }

        if (rule is not null)
        {
            Interlocked.Increment(ref rule.Passed);
        }

        // A finite-bandwidth rule parks the packet in its shared FIFO instead of crossing
        // now; the scheduler drains it at the configured rate and applies the rule's
        // propagation delay as the packet leaves the queue.
        if (rule is { BitsPerSecond: > 0 } shaped)
        {
            Shaper shaper;
            lock (_gate)
            {
                if (!_shapers.TryGetValue(shaped, out shaper!))
                {
                    shaper = new Shaper(this, shaped.BitsPerSecond, shaped.QueuePackets);
                    _shapers[shaped] = shaper;
                }
            }

            shaper.Enqueue(source, dest, payload);
            return;
        }

        ScheduleCrossing(rule, source, dest, payload);
    }

    /// <summary>Applies the rule's propagation delay/jitter (or delivers immediately on a
    /// zero-delay link, preserving causal order like loopback UDP).</summary>
    private void ScheduleCrossing(LinkRule? rule, IPEndPoint source, IPEndPoint dest, byte[] payload)
    {
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
            List<ScheduledPacket> due = [];
            List<(LinkRule Rule, List<(IPEndPoint Source, IPEndPoint Dest, byte[] Payload)> Emitted)> drained = [];
            lock (_gate)
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                for (int i = _inflight.Count - 1; i >= 0; i--)
                {
                    if (_inflight[i].Due <= now)
                    {
                        due.Add(_inflight[i]);
                        _inflight.RemoveAt(i);
                    }
                }

                foreach ((LinkRule rule, Shaper shaper) in _shapers)
                {
                    List<(IPEndPoint, IPEndPoint, byte[])> emitted = shaper.Drain(now);
                    if (emitted.Count > 0)
                    {
                        drained.Add((rule, emitted));
                    }
                }
            }

            // Due packets were collected newest-first (backwards removal is O(1)); deliver
            // oldest-first: chronological, causal order — exactly what loopback UDP gives.
            // Reversed batches would trip the engine's strictly-increasing replay window
            // and reject all but one frame per tick (found by the #27 delay rungs).
            for (int i = due.Count - 1; i >= 0; i--)
            {
                Deliver(due[i].Source, due[i].Dest, due[i].Payload);
            }

            // Drained packets left the bottleneck; propagation delay applies from now.
            foreach ((LinkRule rule, var emitted) in drained)
            {
                foreach ((IPEndPoint source, IPEndPoint dest, byte[] payload) in emitted)
                {
                    ScheduleCrossing(rule, source, dest, payload);
                }
            }

            _wake.WaitOne(5);
        }
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
                string shaper = _shapers.TryGetValue(r, out Shaper? s) && (s.QueuedDropped > 0 || s.Dequeued > 0)
                    ? $" shaped(dequeued={s.Dequeued},tailDropped={s.QueuedDropped},depth={s.Depth})"
                    : "";
                return $"rule(passed={Interlocked.Read(ref r.Passed)},lost={Interlocked.Read(ref r.Lost)}){shaper}";
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

    /// <summary>One shared finite-bandwidth FIFO (the bottleneck link): packets enter on
    /// arrival (a full queue tail-drops), and <see cref="Drain"/> releases exactly as many
    /// bytes as the elapsed time × rate paid for. Queue delay is emergent — a burst sits in
    /// the queue until the link can send it — so a small queue turns bursts into loss and a
    /// deep one into bufferbloat, the two regimes the #27 baseline must record.</summary>
    internal sealed class Shaper(VirtualNetwork net, long bitsPerSecond, int queuePackets)
    {
        private readonly object _gate = new();
        private readonly Queue<(IPEndPoint Source, IPEndPoint Dest, byte[] Payload)> _queue = new();
        private double _creditBits;
        private DateTimeOffset _lastDrain = DateTimeOffset.UtcNow;

        public long QueuedDropped;
        public long Dequeued;
        public int Depth { get { lock (_gate) { return _queue.Count; } } }

        public void Enqueue(IPEndPoint source, IPEndPoint dest, byte[] payload)
        {
            lock (_gate)
            {
                if (_queue.Count >= queuePackets)
                {
                    Interlocked.Increment(ref QueuedDropped);
                    Interlocked.Increment(ref net.DroppedByPolicy);
                    return;
                }

                _queue.Enqueue((source, dest, payload));
            }
        }

        /// <summary>Called by the scheduler: pays out credit for the elapsed time and
        /// releases whole packets while their byte-cost fits.</summary>
        public List<(IPEndPoint Source, IPEndPoint Dest, byte[] Payload)> Drain(DateTimeOffset now)
        {
            lock (_gate)
            {
                if (_queue.Count == 0)
                {
                    _lastDrain = now;
                    _creditBits = 0;
                    return [];
                }

                _creditBits += (now - _lastDrain).TotalSeconds * bitsPerSecond;
                _lastDrain = now;
                // A modest burst allowance keeps the link from idling between scheduler
                // ticks; real links serialize packet-by-packet, the lab per 5 ms tick.
                _creditBits = Math.Min(_creditBits, bitsPerSecond * 0.2);
                var emitted = new List<(IPEndPoint, IPEndPoint, byte[])>();
                while (_queue.Count > 0 && _queue.Peek().Payload.Length * 8L <= _creditBits)
                {
                    (IPEndPoint source, IPEndPoint dest, byte[] payload) = _queue.Dequeue();
                    _creditBits -= payload.Length * 8L;
                    Interlocked.Increment(ref Dequeued);
                    emitted.Add((source, dest, payload));
                }

                return emitted;
            }
        }
    }
}
