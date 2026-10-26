using System.Net;

namespace Pinhole.Sim;

// What one datagram crossing the shaped internet leg owes the caller: hand it
// over now, hold it for Delay, or nothing at all (parked in a shaper FIFO / lost).
public enum LinkDecisionKind : byte
{
    Deliver = 0,
    Schedule = 1,
    Shaped = 2,
    Dropped = 3,
}

public readonly record struct LinkDecision(LinkDecisionKind Kind, TimeSpan Delay)
{
    public static LinkDecision DeliverNow => new(LinkDecisionKind.Deliver, TimeSpan.Zero);
    public static LinkDecision Drop => new(LinkDecisionKind.Dropped, TimeSpan.Zero);
}

// The internet leg of a virtual network, minus the delivery vehicle: first-match
// rules with their loss models and counters, per-rule bandwidth shapers, and
// delay/jitter draws. Emitted from the test tree's VirtualNetwork so a future
// event-driven sim can reuse the exact pipeline semantics on a SimClock instead
// of a scheduler thread. The jitter stream is injected, never ambient — the old
// fixture drew it from Random.Shared, which no seed could pin.
internal sealed class LinkPipeline
{
    private readonly object _gate = new();
    private readonly List<LinkRule> _rules = [];
    private readonly Dictionary<LinkRule, Shaper> _shapers = new();
    private readonly Random _jitter;

    public LinkPipeline(Random jitterRandom)
    {
        _jitter = jitterRandom;
    }

    public long DroppedByPolicy;

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

    // Post-NAT crossing of one datagram: match the first rule, let its loss model
    // speak, and either park it in the rule's shaper FIFO or report the crossing
    // delay the caller must wait out. Counters match the fixture's old inline
    // pipeline: lost datagrams bump the rule's Lost and DroppedByPolicy.
    public LinkDecision Cross(IPEndPoint source, IPEndPoint dest, byte[] payload)
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
            return LinkDecision.Drop;
        }

        if (rule is not null)
        {
            Interlocked.Increment(ref rule.Passed);
        }

        // A finite-bandwidth rule parks the packet in its shared FIFO instead of
        // crossing now; the caller drains it at the configured rate and applies
        // the rule's propagation delay as the packet leaves the queue.
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
            return new LinkDecision(LinkDecisionKind.Shaped, TimeSpan.Zero);
        }

        TimeSpan delay = PropagationDelay(rule);
        return delay <= TimeSpan.Zero
            ? LinkDecision.DeliverNow
            : new LinkDecision(LinkDecisionKind.Schedule, delay);
    }

    // The rule's propagation delay plus jitter drawn from the injected stream.
    public TimeSpan PropagationDelay(LinkRule? rule)
    {
        TimeSpan delay = rule?.Delay ?? TimeSpan.Zero;
        if (rule is { } shaped && shaped.Jitter > TimeSpan.Zero)
        {
            delay += TimeSpan.FromMilliseconds(_jitter.NextDouble() * shaped.Jitter.TotalMilliseconds);
        }

        return delay;
    }

    // Drain every shaper at the caller's notion of now. Emitted packets have left
    // the bottleneck but still owe their propagation delay: the caller schedules
    // the crossing via PropagationDelay.
    public List<(LinkRule Rule, List<(IPEndPoint Source, IPEndPoint Dest, byte[] Payload)> Emitted)> DrainShapers(
        DateTimeOffset now)
    {
        List<(LinkRule Rule, List<(IPEndPoint Source, IPEndPoint Dest, byte[] Payload)> Emitted)> drained = [];
        lock (_gate)
        {
            foreach ((LinkRule rule, Shaper shaper) in _shapers)
            {
                List<(IPEndPoint, IPEndPoint, byte[])> emitted = shaper.Drain(now);
                if (emitted.Count > 0)
                {
                    drained.Add((rule, emitted));
                }
            }
        }

        return drained;
    }

    // Rule and shaper counters in the format the fixture's Counters() line embeds.
    public string RuleCounters()
    {
        lock (_gate)
        {
            return string.Join("; ", _rules.Select(r =>
            {
                string shaper = _shapers.TryGetValue(r, out Shaper? s) && (s.QueuedDropped > 0 || s.Dequeued > 0)
                    ? $" shaped(dequeued={s.Dequeued},tailDropped={s.QueuedDropped},depth={s.Depth})"
                    : "";
                return $"rule(passed={Interlocked.Read(ref r.Passed)},lost={Interlocked.Read(ref r.Lost)}){shaper}";
            }));
        }
    }

    internal sealed class Shaper(LinkPipeline pipeline, long bitsPerSecond, int queuePackets)
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
                    Interlocked.Increment(ref pipeline.DroppedByPolicy);
                    return;
                }

                _queue.Enqueue((source, dest, payload));
            }
        }

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
