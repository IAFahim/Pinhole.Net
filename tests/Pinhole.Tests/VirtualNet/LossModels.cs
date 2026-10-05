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
/// <see cref="BitsPerSecond"/> installs a finite-bandwidth bottleneck: every matching
/// packet shares ONE FIFO drained at that rate, with <see cref="QueuePackets"/> of
/// standing room — a full queue tail-drops, exactly the finite-queue behavior the
/// congestion-control baseline (#27) needs. Shaping applies after the loss decision;
/// the rule's delay/jitter is propagation time applied when a packet leaves the queue.</summary>
internal sealed class LinkRule
{
    public required Func<IPEndPoint, IPEndPoint, bool> Match { get; init; }
    public LossModel? ForwardLoss { get; init; }
    public LossModel? ReverseLoss { get; init; }
    public TimeSpan Delay { get; init; }
    public TimeSpan Jitter { get; init; }
    public bool DropAll { get; init; }
    public long BitsPerSecond { get; init; }
    public int QueuePackets { get; init; }

    public long Passed;
    public long Lost;

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

    /// <summary>A bandwidth bottleneck between two subnets: one shared FIFO, tail-dropped
    /// when full, drained at <paramref name="bitsPerSecond"/> in both directions. Optional
    /// independent loss chains ride the same rule — remember first-match-wins, so loss that
    /// should apply to shaped traffic must live here, not in a second overlapping rule.</summary>
    public static LinkRule Bottleneck(Subnet a, Subnet b, long bitsPerSecond, int queuePackets,
        TimeSpan delay = default, TimeSpan jitter = default,
        LossModel? forwardLoss = null, LossModel? reverseLoss = null) => new()
    {
        Match = (src, dst) => (a.Contains(src) && b.Contains(dst)) || (b.Contains(src) && a.Contains(dst)),
        Delay = delay,
        Jitter = jitter,
        BitsPerSecond = bitsPerSecond,
        QueuePackets = queuePackets,
        ForwardLoss = forwardLoss,
        ReverseLoss = reverseLoss,
    };

    /// <summary>A black hole around one subnet: every packet into or out of it dies.</summary>
    public static LinkRule Blackhole(Subnet subnet) => new()
    {
        Match = (src, dst) => subnet.Contains(src) || subnet.Contains(dst),
        DropAll = true,
    };
}
