using System.Net;

namespace Pinhole.Sim;

internal sealed class LinkRule
{
    public required Func<IPEndPoint, IPEndPoint, bool> Match { get; init; }
    public LossModel? ForwardLoss { get; init; }
    public LossModel? ReverseLoss { get; init; }
    public DuplicationModel? ForwardDuplicate { get; init; }
    public DuplicationModel? ReverseDuplicate { get; init; }
    public CorruptionModel? ForwardCorrupt { get; init; }
    public CorruptionModel? ReverseCorrupt { get; init; }
    public TimeSpan Delay { get; init; }
    public TimeSpan Jitter { get; init; }
    public bool DropAll { get; init; }
    public long BitsPerSecond { get; init; }
    public int QueuePackets { get; init; }

    public long Passed;
    public long Lost;
    public long Duplicated;  // Interlocked: copies the rule emitted onto the wire
    public long Corrupted;   // Interlocked: crossings that left with a flipped byte

    public bool DuplicatesAnything => ForwardDuplicate is not null || ReverseDuplicate is not null;

    public LossModel? LossFor(IPEndPoint source, IPEndPoint dest)
    {
        if (ReverseLoss is null)
        {
            return ForwardLoss;
        }

        return Compare(source, dest) < 0 ? ForwardLoss : ReverseLoss;
    }

    // Same direction split as LossFor: a null reverse model means the forward model
    // speaks for both directions.
    public DuplicationModel? DuplicateFor(IPEndPoint source, IPEndPoint dest)
    {
        if (ReverseDuplicate is null)
        {
            return ForwardDuplicate;
        }

        return Compare(source, dest) < 0 ? ForwardDuplicate : ReverseDuplicate;
    }

    public CorruptionModel? CorruptFor(IPEndPoint source, IPEndPoint dest)
    {
        if (ReverseCorrupt is null)
        {
            return ForwardCorrupt;
        }

        return Compare(source, dest) < 0 ? ForwardCorrupt : ReverseCorrupt;
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

    // A hostile internet leg (R3/P1): everything that crosses is liable to be
    // duplicated, delayed+reordered, and byte-corrupted — the receiving AEAD must
    // refuse every corrupted or replayed copy while the honest stream gets through.
    public static LinkRule Hostile(Subnet a, Subnet b,
        DuplicationModel? duplicate = null, CorruptionModel? corrupt = null,
        LossModel? forwardLoss = null, LossModel? reverseLoss = null,
        TimeSpan delay = default, TimeSpan jitter = default) => new()
    {
        Match = (src, dst) => (a.Contains(src) && b.Contains(dst)) || (b.Contains(src) && a.Contains(dst)),
        ForwardDuplicate = duplicate,
        ForwardCorrupt = corrupt,
        ForwardLoss = forwardLoss,
        ReverseLoss = reverseLoss,
        Delay = delay,
        Jitter = jitter,
    };
}
