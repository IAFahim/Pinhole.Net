using System.Buffers.Binary;

namespace Pinhole.Wire;

public static class WirePrimitives
{
    public const ulong VarintMax = (1UL << 62) - 1;

    public static bool TryReadU16Be(ReadOnlySpan<byte> b, out ushort value)
    {
        if (b.Length < 2)
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt16BigEndian(b);
        return true;
    }

    public static bool TryReadU32Be(ReadOnlySpan<byte> b, out uint value)
    {
        if (b.Length < 4)
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt32BigEndian(b);
        return true;
    }

    public static bool TryReadU64Be(ReadOnlySpan<byte> b, out ulong value)
    {
        if (b.Length < 8)
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt64BigEndian(b);
        return true;
    }

    public static bool TryReadU16Le(ReadOnlySpan<byte> b, out ushort value)
    {
        if (b.Length < 2)
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt16LittleEndian(b);
        return true;
    }

    public static bool TryReadU64Le(ReadOnlySpan<byte> b, out ulong value)
    {
        if (b.Length < 8)
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt64LittleEndian(b);
        return true;
    }

    public static int WriteU16Be(Span<byte> b, ushort value)
    {
        if (b.Length < 2) ThrowTooSmall();
        BinaryPrimitives.WriteUInt16BigEndian(b, value);
        return 2;
    }

    public static int WriteU32Be(Span<byte> b, uint value)
    {
        if (b.Length < 4) ThrowTooSmall();
        BinaryPrimitives.WriteUInt32BigEndian(b, value);
        return 4;
    }

    public static int WriteU64Be(Span<byte> b, ulong value)
    {
        if (b.Length < 8) ThrowTooSmall();
        BinaryPrimitives.WriteUInt64BigEndian(b, value);
        return 8;
    }

    public static int WriteU16Le(Span<byte> b, ushort value)
    {
        if (b.Length < 2) ThrowTooSmall();
        BinaryPrimitives.WriteUInt16LittleEndian(b, value);
        return 2;
    }

    public static int WriteU64Le(Span<byte> b, ulong value)
    {
        if (b.Length < 8) ThrowTooSmall();
        BinaryPrimitives.WriteUInt64LittleEndian(b, value);
        return 8;
    }

    public static bool TryReadVarint(ReadOnlySpan<byte> b, out ulong value, out int length)
    {
        value = 0;
        length = 0;
        if (b.Length < 1)
        {
            return false;
        }

        int size = b[0] switch
        {
            >= 0xC0 => 8,
            >= 0x80 => 4,
            >= 0x40 => 2,
            _ => 1,
        };

        if (b.Length < size)
        {
            return false;
        }

        length = size;
        value = size switch
        {
            1 => b[0] & 0x3FUL,
            2 => ((b[0] & 0x3FUL) << 8) | b[1],
            4 => ((ulong)(b[0] & 0x3FUL) << 24) | ((ulong)b[1] << 16) | ((ulong)b[2] << 8) | b[3],
            _ => ((ulong)(b[0] & 0x3FUL) << 56) | ((ulong)b[1] << 48) | ((ulong)b[2] << 40) | ((ulong)b[3] << 32)
                | ((ulong)b[4] << 24) | ((ulong)b[5] << 16) | ((ulong)b[6] << 8) | b[7],
        };

        if (VarintLength(value) != size)
        {

            value = 0;
            length = 0;
            return false;
        }

        return true;
    }

    public static int WriteVarint(Span<byte> b, ulong value)
    {
        if (value > VarintMax) ThrowVarintRange();
        int size = VarintLength(value);
        if (b.Length < size) ThrowTooSmall();
        switch (size)
        {
            case 1:
                b[0] = (byte)value;
                break;
            case 2:
                b[0] = (byte)(0x40 | (value >> 8));
                b[1] = (byte)value;
                break;
            case 4:
                b[0] = (byte)(0x80 | (value >> 24));
                b[1] = (byte)(value >> 16);
                b[2] = (byte)(value >> 8);
                b[3] = (byte)value;
                break;
            default:
                b[0] = (byte)(0xC0 | (value >> 56));
                b[1] = (byte)(value >> 48);
                b[2] = (byte)(value >> 40);
                b[3] = (byte)(value >> 32);
                b[4] = (byte)(value >> 24);
                b[5] = (byte)(value >> 16);
                b[6] = (byte)(value >> 8);
                b[7] = (byte)value;
                break;
        }

        return size;
    }

    public static int VarintLength(ulong value) =>
        value < (1UL << 6) ? 1 : value < (1UL << 14) ? 2 : value < (1UL << 30) ? 4 : 8;

    private static void ThrowTooSmall() => throw new ArgumentException("destination span too small");

    private static void ThrowVarintRange() => throw new ArgumentOutOfRangeException("value", "varint values are at most 62 bits");
}
