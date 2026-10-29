using System.Net;
using Pinhole.Sim;

namespace Pinhole.Tests;

internal sealed class VirtualNetwork : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<IPEndPoint, VirtualUdpSocket> _internet = new();
    private readonly List<VirtualNat> _nats = [];
    private readonly Dictionary<IPEndPoint, VirtualUdpSocket> _behindNat = new();
    private readonly LinkPipeline _links;
    private readonly List<ScheduledPacket> _inflight = [];
    private readonly Thread _scheduler;
    private readonly AutoResetEvent _wake = new(false);
    private volatile bool _disposed;

    public long Delivered;
    public long Unroutable;
    public long DroppedByPolicy => _links.DroppedByPolicy;

    public int LiveSockets => _liveSockets;
    private int _liveSockets;
    internal void SocketAttached() => Interlocked.Increment(ref _liveSockets);
    internal void SocketDetached() => Interlocked.Decrement(ref _liveSockets);

    public VirtualNetwork(int seed = 0)
    {
        _links = new LinkPipeline(new Random(seed));
        _scheduler = new Thread(RunScheduler) { IsBackground = true, Name = "virtual-net" };
        _scheduler.Start();
    }

    public void AddRule(LinkRule rule) => _links.AddRule(rule);

    public void RemoveRule(LinkRule rule) => _links.RemoveRule(rule);

    public VirtualUdpSocket CreateHost(IPEndPoint address)
    {
        lock (_gate)
        {
            if (address.Port == 0)
            {
                do
                {
                    address = new IPEndPoint(address.Address, Interlocked.Increment(ref _nextEphemeralPort));
                }
                while (_internet.ContainsKey(address));
            }

            var socket = new VirtualUdpSocket(this, address, nat: null);
            _internet[address] = socket;
            return socket;
        }
    }

    private int _nextEphemeralPort = 50000;

    public VirtualUdpSocket CreateBehindNat(VirtualNat nat)
    {
        lock (_gate)
        {
            var socket = new VirtualUdpSocket(this, nat.AllocateInternalEndpoint(), nat);
            _behindNat[socket.Address] = socket;
            return socket;
        }
    }

    internal void RouteFrom(VirtualUdpSocket sender, IPEndPoint dest, byte[] payload)
    {
        IPEndPoint source = sender.Address;
        if (sender.Nat is { } nat)
        {
            if (!nat.TryTranslateOutbound(sender.Address, dest, out source))
            {
                Interlocked.Increment(ref Unroutable);
                return;
            }
        }

        Continue(source, dest, payload);
    }

    private void Continue(IPEndPoint source, IPEndPoint dest, byte[] payload)
    {
        List<(byte[] Payload, TimeSpan Delay)>? duplicates = _links.AnyDuplication ? [] : null;
        LinkDecision decision = _links.Cross(source, dest, payload, duplicates);
        Apply(decision, source, dest, payload);
        if (duplicates is not null)
        {
            foreach ((byte[] copy, TimeSpan delay) in duplicates)
            {
                Apply(delay <= TimeSpan.Zero ? LinkDecision.DeliverNow
                    : new LinkDecision(LinkDecisionKind.Schedule, delay), source, dest, copy);
            }
        }
    }

    private void Apply(LinkDecision decision, IPEndPoint source, IPEndPoint dest, byte[] payload)
    {
        switch (decision.Kind)
        {
            case LinkDecisionKind.Deliver:
                Deliver(source, dest, payload);
                break;
            case LinkDecisionKind.Schedule:
                ScheduleCrossing(decision.Delay, source, dest, payload);
                break;
            case LinkDecisionKind.Shaped:
            case LinkDecisionKind.Dropped:
                break;
        }
    }

    private void ScheduleCrossing(TimeSpan delay, IPEndPoint source, IPEndPoint dest, byte[] payload)
    {
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
        VirtualUdpSocket? behindNat = null;
        lock (_gate)
        {
            if (!_internet.TryGetValue(dest, out host))
            {
                VirtualNat? owner = _nats.FirstOrDefault(n => n.Owns(dest));
                if (owner is not null && owner.TryTranslateInbound(dest, source, out IPEndPoint? internalDest))
                {
                    _behindNat.TryGetValue(internalDest!, out behindNat);
                }
            }
        }

        if (host is not null || behindNat is not null)
        {
            Interlocked.Increment(ref Delivered);
            (host ?? behindNat)!.Enqueue(source, payload);
            return;
        }

        Interlocked.Increment(ref Unroutable);
    }

    private void RunScheduler()
    {
        while (!_disposed)
        {
            List<ScheduledPacket> due = [];
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
            }

            List<(LinkRule Rule, List<(IPEndPoint Source, IPEndPoint Dest, byte[] Payload)> Emitted)> drained =
                _links.DrainShapers(DateTimeOffset.UtcNow);

            for (int i = due.Count - 1; i >= 0; i--)
            {
                Deliver(due[i].Source, due[i].Dest, due[i].Payload);
            }

            foreach ((LinkRule rule, var emitted) in drained)
            {
                foreach ((IPEndPoint source, IPEndPoint dest, byte[] payload) in emitted)
                {
                    ScheduleCrossing(_links.PropagationDelay(rule), source, dest, payload);
                }
            }

            _wake.WaitOne(5);
        }
    }

    internal void Register(VirtualNat nat)
    {
        lock (_gate)
        {
            if (!_nats.Contains(nat))
            {
                _nats.Add(nat);
            }
        }
    }

    public string Counters()
    {
        VirtualNat[] boxes;
        lock (_gate)
        {
            boxes = _nats.ToArray();
        }

        string rules = _links.RuleCounters();
        string nats = string.Join("; ", boxes.Select(n => n.Counters()));
        return $"delivered={Interlocked.Read(ref Delivered)} dropped={Interlocked.Read(ref _links.DroppedByPolicy)} " +
               $"unroutable={Interlocked.Read(ref Unroutable)} {rules} {nats}".Trim();
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
}
