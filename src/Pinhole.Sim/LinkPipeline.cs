using System.Net;

namespace Pinhole.Sim;

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

    public LinkDecision Cross(IPEndPoint source, IPEndPoint dest, byte[] payload,
        List<(byte[] Payload, TimeSpan Delay)>? duplicates = null)
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

        byte[]? copy = null;
        if (rule?.DuplicateFor(source, dest)?.DuplicateNext() == true && duplicates is not null)
        {
            copy = (byte[])payload.Clone();
            Interlocked.Increment(ref rule!.Duplicated);
        }

        CorruptInPlace(rule, source, dest, payload);
        if (copy is not null)
        {
            CorruptInPlace(rule, source, dest, copy);
        }

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
            if (copy is not null)
            {
                shaper.Enqueue(source, dest, copy);
            }

            return new LinkDecision(LinkDecisionKind.Shaped, TimeSpan.Zero);
        }

        TimeSpan delay = PropagationDelay(rule);
        if (copy is not null)
        {
            duplicates!.Add((copy, PropagationDelay(rule)));
        }

        return delay <= TimeSpan.Zero
            ? LinkDecision.DeliverNow
            : new LinkDecision(LinkDecisionKind.Schedule, delay);
    }

    private static void CorruptInPlace(LinkRule? rule, IPEndPoint source, IPEndPoint dest, byte[] payload)
    {
        int offset = rule?.CorruptFor(source, dest)?.FlipOffset(payload.Length) ?? -1;
        if (offset >= 0)
        {
            payload[offset] ^= 0x80;
            Interlocked.Increment(ref rule!.Corrupted);
        }
    }

    public bool AnyDuplication
    {
        get
        {
            lock (_gate)
            {
                return _rules.Any(r => r.DuplicatesAnything);
            }
        }
    }

    public TimeSpan PropagationDelay(LinkRule? rule)
    {
        TimeSpan delay = rule?.Delay ?? TimeSpan.Zero;
        if (rule is { } shaped && shaped.Jitter > TimeSpan.Zero)
        {
            delay += TimeSpan.FromMilliseconds(_jitter.NextDouble() * shaped.Jitter.TotalMilliseconds);
        }

        return delay;
    }

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
