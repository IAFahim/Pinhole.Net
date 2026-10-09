using System.Buffers.Binary;

namespace Pinhole;

/// <summary>The versioned TCP envelope around unchanged encrypted Pinhole frames.</summary>
internal static class TcpFrameCodec
{
    internal static byte[] Encode(ReadOnlySpan<byte> frame)
    {
        if (frame.Length is < 13 or > TcpTransport.MaxFrame) throw new ArgumentOutOfRangeException(nameof(frame));
        byte[] packet = new byte[frame.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(packet, (ushort)frame.Length);
        frame.CopyTo(packet.AsSpan(2));
        return packet;
    }

    internal static async Task NegotiateAsync(Stream stream, bool initiator, CancellationToken ct)
    {
        byte[] preface = new byte[TcpTransport.Preface.Length];
        if (initiator) await stream.WriteAsync(TcpTransport.Preface.ToArray(), ct).ConfigureAwait(false);
        await stream.ReadExactlyAsync(preface, ct).ConfigureAwait(false);
        if (!preface.AsSpan().SequenceEqual(TcpTransport.Preface)) throw new IOException("unsupported Pinhole TCP framing");
        if (!initiator) await stream.WriteAsync(preface, ct).ConfigureAwait(false);
    }

    internal static async ValueTask<int> ReadAsync(Stream stream, byte[] header, Memory<byte> buffer, TimeSpan bodyTimeout, CancellationToken ct)
    {
        if (header.Length < 2) throw new ArgumentException("TCP header scratch needs two bytes", nameof(header));
        // An idle authenticated session can wait indefinitely for its next frame. Once
        // even one header byte arrives, the rest must arrive within a bounded window.
        await stream.ReadExactlyAsync(header.AsMemory(0, 1), ct).ConfigureAwait(false);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(bodyTimeout);
        await stream.ReadExactlyAsync(header.AsMemory(1, 1), deadline.Token).ConfigureAwait(false);
        int length = BinaryPrimitives.ReadUInt16BigEndian(header);
        if (length is < 13 or > TcpTransport.MaxFrame || length > buffer.Length) throw new IOException("invalid Pinhole TCP frame length");
        await stream.ReadExactlyAsync(buffer[..length], deadline.Token).ConfigureAwait(false);
        return length;
    }
}
