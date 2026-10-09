using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Pinhole;

internal sealed class PortPredictionState
{
    internal readonly ulong LocalId = NewId();
    internal ulong PeerId;
    internal volatile bool PeerCapable, Started, Finished;
    internal IPEndPoint[]? LocalTargets, PeerTargets;
    internal readonly IUdpSocket Source;
    internal PortPredictionState(IUdpSocket source) => Source = source;
    private static ulong NewId()
    {
        Span<byte> bytes = stackalloc byte[8];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        ulong id = BinaryPrimitives.ReadUInt64LittleEndian(bytes);
        return id == 0 ? 1 : id;
    }
}

internal static class PortPrediction
{
    internal const int MaxTargets = 8;
    internal const int SampleCount = 4;
    internal const int MaxStep = 16;
    internal const int ProbeRounds = 6;

    internal static IPEndPoint[] Predict(IReadOnlyList<IPEndPoint> observations)
    {
        if (observations.Count != SampleCount || observations.Any(o => !Eligible(o))
            || observations.Any(o => !o.Address.Equals(observations[0].Address))) return [];
        int step = observations[1].Port - observations[0].Port;
        if (step is <= 0 or > MaxStep) return [];
        for (int i = 2; i < observations.Count; i++) if (observations[i].Port - observations[i - 1].Port != step) return [];
        int last = observations[^1].Port;
        if (last + MaxTargets * step > ushort.MaxValue) return []; // no wrapping into unrelated ports
        return Enumerable.Range(1, MaxTargets).Select(i => new IPEndPoint(observations[0].Address, last + i * step)).ToArray();
    }

    internal static bool Eligible(IPEndPoint endpoint)
    {
        if (endpoint.AddressFamily != AddressFamily.InterNetwork || !StunBindingMessage.Usable(endpoint)) return false;
        byte[] b = endpoint.Address.GetAddressBytes();
        return b[0] != 10 && b[0] != 127 && !(b[0] == 172 && b[1] is >= 16 and <= 31)
            && !(b[0] == 192 && b[1] == 168) && !(b[0] == 169 && b[1] == 254)
            && !(b[0] == 100 && b[1] is >= 64 and <= 127);
    }

    internal static byte[] Offer(ulong id, IReadOnlyList<IPEndPoint> targets)
    {
        if (id == 0 || targets.Count is < 1 or > MaxTargets || targets.Any(t => !Eligible(t)))
            throw new ArgumentException("Invalid bounded prediction offer", nameof(targets));
        byte[] body = new byte[11 + targets.Count * 6]; body[0] = 1; body[1] = 2;
        BinaryPrimitives.WriteUInt64LittleEndian(body.AsSpan(2), id); body[10] = (byte)targets.Count;
        for (int i = 0; i < targets.Count; i++)
        {
            targets[i].Address.GetAddressBytes().CopyTo(body, 11 + i * 6);
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(15 + i * 6), (ushort)targets[i].Port);
        }
        return body;
    }

    internal static IPEndPoint[]? ReadOffer(ReadOnlySpan<byte> body, IReadOnlyList<IPAddress> advertisedAddresses)
    {
        if (body.Length < 11 || body[0] != 1 || body[1] != 2 || body[10] is < 1 or > MaxTargets
            || body.Length != 11 + body[10] * 6) return null;
        var targets = new IPEndPoint[body[10]];
        for (int i = 0; i < targets.Length; i++)
        {
            targets[i] = new(new IPAddress(body.Slice(11 + i * 6, 4)), BinaryPrimitives.ReadUInt16BigEndian(body[(15 + i * 6)..]));
            if (!Eligible(targets[i]) || !advertisedAddresses.Contains(targets[i].Address)) return null;
        }
        if (targets.Distinct().Count() != targets.Length || targets.Any(t => !t.Address.Equals(targets[0].Address))) return null;
        // A peer may offer a stable cone mapping, or the same bounded ascending
        // sequence this implementation derives. Arbitrary port lists are refused.
        if (targets.Length != 1)
        {
            if (targets.Length != MaxTargets) return null;
            int step = targets[1].Port - targets[0].Port;
            if (step is <= 0 or > MaxStep) return null;
            for (int i = 2; i < targets.Length; i++) if (targets[i].Port - targets[i - 1].Port != step) return null;
        }
        return targets;
    }
}
