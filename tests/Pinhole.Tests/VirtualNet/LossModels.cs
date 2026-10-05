using System.Net;

namespace Pinhole.Tests;

/// <summary>One direction of a link's drop decision. Implementations keep their own state
/// chains, so a rule with one model per direction produces independent sequences. The chain
/// is guarded: the engine sends from several threads and the models are stateful.</summary>
internal abstract class LossModel
{
    private readonly object _gate = new();

    public bool LoseNext()
    {
        lock (_gate)
        {
            return LoseNextCore();
        }
    }

    protected abstract bool LoseNextCore();
}

/// <summary>Independent (Bernoulli) loss — the simple rungs of the ladder.</summary>
internal sealed class IndependentLoss(double probability, int seed) : LossModel
{
    private readonly Random _rng = new(seed);

    protected override bool LoseNextCore() => _rng.NextDouble() < probability;
}

/// <summary>Two-state Gilbert-Elliott loss: a Good state with rare loss, a Bad state with
/// heavy loss, and Markov transitions between them. Bursts of loss — what a real radio or
/// congested uplink produces, and what a fixed-interval re-request design handles worst.
/// Parameterized by mean loss rate and mean burst length in packets.</summary>
internal sealed class GilbertElliottLoss(double meanLossRate, double meanBurstPackets, int seed) : LossModel
{
    private readonly Random _rng = new(seed);
    private readonly double _enterBad = meanLossRate / meanBurstPackets;
    private readonly double _exitBad = 1.0 / meanBurstPackets;
    private readonly double _lossInGood = Math.Min(meanLossRate * 0.1, 0.005);
    private readonly double _lossInBad = Math.Min(0.5 + meanLossRate * 0.5, 1.0);
    private bool _bad;

    protected override bool LoseNextCore()
    {
        _bad = _bad ? _rng.NextDouble() >= _exitBad : _rng.NextDouble() < _enterBad;
        return _rng.NextDouble() < (_bad ? _lossInBad : _lossInGood);
    }
}

/// <summary>An IPv4 or IPv6 prefix used to address-match link rules and blackholes. The
/// virtual internet's address plan uses documentation ranges (192.0.2.0/24,
/// 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/48) — no packet can leak into a real one.</summary>
internal readonly record struct Subnet(IPAddress Base, int PrefixLength)
{
    public static Subnet Parse(string cidr)
    {
        int slash = cidr.IndexOf('/');
        return new Subnet(IPAddress.Parse(cidr[..slash]), int.Parse(cidr[(slash + 1)..]));
    }

    public bool Contains(IPEndPoint endpoint)
    {
        byte[] address = Normalize(endpoint.Address);
        byte[] baseline = Normalize(Base);
        if (address.Length != baseline.Length)
        {
            return false;
        }

        int fullBytes = PrefixLength / 8;
        for (int i = 0; i < fullBytes; i++)
        {
            if (address[i] != baseline[i])
            {
                return false;
            }
        }

        int remainderBits = PrefixLength % 8;
        if (remainderBits == 0)
        {
            return true;
        }

        byte mask = (byte)(0xFF << (8 - remainderBits));
        return (address[fullBytes] & mask) == (baseline[fullBytes] & mask);
    }

    private static byte[] Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4().GetAddressBytes() : address.GetAddressBytes();
}

/// <summary>One shaping rule over a region of the virtual internet. First matching rule
/// wins; unmatched traffic crosses clean. <see cref="Match"/> sees post-NAT (internet)
/// addresses, so a rule on a subnet shapes exactly the packets that traverse it.
/// With <see cref="BandwidthBytesPerSecond"/> the rule becomes a bottleneck link: packets
/// serialize one at a time (size/bandwidth each), wait in a bounded FIFO that drops on
/// overflow — real congestion loss a sender can cause and observe — and the wait is
/// recorded so tests can compare queueing delay between senders.</summary>
internal sealed class LinkRule
{
    public required Func<IPEndPoint, IPEndPoint, bool> Match { get; init; }
    public LossModel? ForwardLoss { get; init; }
    public LossModel? ReverseLoss { get; init; }
    public TimeSpan Delay { get; init; }
    public TimeSpan Jitter { get; init; }
    public bool DropAll { get; init; }

    /// <summary>Link capacity in bytes/s; zero (default) keeps the immediate/scheduler
    /// delay model with no serialization. Each direction gets its own transmitter and
    /// queue, like a full-duplex link.</summary>
    public double BandwidthBytesPerSecond { get; init; }

    /// <summary>Bounded FIFO capacity in bytes for the bandwidth model; overflow drops
    /// (counted as <see cref="QueueDrops"/>) exactly like a router buffer out of room.</summary>
    public long QueueCapacityBytes { get; init; }

    public long Passed;
    public long Lost;
    public long QueueDrops;
    public long TotalQueueWaitMs;
    public long MaxQueueWaitMs;

    public bool IsBottleneck => BandwidthBytesPerSecond > 0;

    /// <summary>Mean time packets spent waiting in the bounded queue (serialization
    /// excluded) — the congestion metric CC is judged on.</summary>
    public double MeanQueueWaitMs(long transmitted) => transmitted == 0 ? 0 : (double)TotalQueueWaitMs / transmitted;

    /// <summary>The loss chain for one direction. With two chains the split is by stable
    /// endpoint ordering, so each direction of a link keeps its own independent sequence.</summary>
    public LossModel? LossFor(IPEndPoint source, IPEndPoint dest)
    {
        if (ReverseLoss is null)
        {
            return ForwardLoss;
        }

        return Compare(source, dest) < 0 ? ForwardLoss : ReverseLoss;
    }

    /// <summary>Which directional transmitter/queue a packet uses (0/1), split by the same
    /// stable endpoint ordering as <see cref="LossFor"/>.</summary>
    public int DirectionOf(IPEndPoint source, IPEndPoint dest) => Compare(source, dest) < 0 ? 0 : 1;

    private static int Compare(IPEndPoint a, IPEndPoint b)
    {
        int c = CompareBytes(Normalize(a.Address), Normalize(b.Address));
        return c != 0 ? c : a.Port.CompareTo(b.Port);
    }

    private static int CompareBytes(byte[] left, byte[] right)
    {
        int n = Math.Min(left.Length, right.Length);
        for (int i = 0; i < n; i++)
        {
            if (left[i] != right[i])
            {
                return left[i].CompareTo(right[i]);
            }
        }

        return left.Length.CompareTo(right.Length);
    }

    private static byte[] Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4().GetAddressBytes() : address.GetAddressBytes();

    /// <summary>Shapes both directions of the path between two subnets (the loss ladder:
    /// one rule, two independent loss chains).</summary>
    public static LinkRule Between(Subnet a, Subnet b, LossModel forward, LossModel reverse,
        TimeSpan delay = default, TimeSpan jitter = default) => new()
    {
        Match = (src, dst) => (a.Contains(src) && b.Contains(dst)) || (b.Contains(src) && a.Contains(dst)),
        ForwardLoss = forward,
        ReverseLoss = reverse,
        Delay = delay,
        Jitter = jitter,
    };

    /// <summary>A full-duplex bottleneck between two subnets: each direction serializes
    /// at <paramref name="bandwidthBytesPerSecond"/> with a bounded FIFO of
    /// <paramref name="queueBytes"/>. Competing flows across the same pair of subnets
    /// share one transmitter per direction — the fairness topology.</summary>
    public static LinkRule Bottleneck(Subnet a, Subnet b, double bandwidthBytesPerSecond, long queueBytes,
        TimeSpan propagation = default, LossModel? forwardLoss = null, LossModel? reverseLoss = null,
        TimeSpan jitter = default) => new()
    {
        Match = (src, dst) => (a.Contains(src) && b.Contains(dst)) || (b.Contains(src) && a.Contains(dst)),
        ForwardLoss = forwardLoss,
        ReverseLoss = reverseLoss,
        Delay = propagation,
        Jitter = jitter,
        BandwidthBytesPerSecond = bandwidthBytesPerSecond,
        QueueCapacityBytes = queueBytes,
    };

    /// <summary>A directional rule: only src→dst is shaped.</summary>
    public static LinkRule Directional(Subnet srcSubnet, Subnet dstSubnet, LossModel? loss = null,
        bool dropAll = false, TimeSpan delay = default, TimeSpan jitter = default) => new()
    {
        Match = (src, dst) => srcSubnet.Contains(src) && dstSubnet.Contains(dst),
        ForwardLoss = loss,
        DropAll = dropAll,
        Delay = delay,
        Jitter = jitter,
    };

    /// <summary>A black hole around one subnet: every packet into or out of it dies.</summary>
    public static LinkRule Blackhole(Subnet subnet) => new()
    {
        Match = (src, dst) => subnet.Contains(src) || subnet.Contains(dst),
        DropAll = true,
    };
}
