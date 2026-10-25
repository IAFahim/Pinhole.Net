using System.Net;

namespace Pinhole.Tests;

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

internal sealed class IndependentLoss(double probability, int seed) : LossModel
{
    private readonly Random _rng = new(seed);

    protected override bool LoseNextCore() => _rng.NextDouble() < probability;
}

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

    public static LinkRule Between(Subnet a, Subnet b, LossModel forward, LossModel reverse,
        TimeSpan delay = default, TimeSpan jitter = default) => new()
    {
        Match = (src, dst) => (a.Contains(src) && b.Contains(dst)) || (b.Contains(src) && a.Contains(dst)),
        ForwardLoss = forward,
        ReverseLoss = reverse,
        Delay = delay,
        Jitter = jitter,
    };

    public static LinkRule Directional(Subnet srcSubnet, Subnet dstSubnet, LossModel? loss = null,
        bool dropAll = false, TimeSpan delay = default, TimeSpan jitter = default) => new()
    {
        Match = (src, dst) => srcSubnet.Contains(src) && dstSubnet.Contains(dst),
        ForwardLoss = loss,
        DropAll = dropAll,
        Delay = delay,
        Jitter = jitter,
    };

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

    public static LinkRule Blackhole(Subnet subnet) => new()
    {
        Match = (src, dst) => subnet.Contains(src) || subnet.Contains(dst),
        DropAll = true,
    };
}
