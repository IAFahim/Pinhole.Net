using System.Buffers.Binary;
using System.Text;

namespace Pinhole.Wire;

public readonly record struct ManifestEntry(string Path, long Size, byte[] Root);

public readonly record struct ManifestValue(string Name, ManifestEntry[] Entries);

public static class ManifestCodec
{
    public const int RootLength = 32;

    public const int MaxTextBytes = ushort.MaxValue;

    private const int MinEntryBytes = 2 + 8 + RootLength;

    public static bool TryRead(ReadOnlySpan<byte> data, out ManifestValue value)
    {
        value = default;
        if (!WirePrimitives.TryReadU16Le(data, out ushort nameLen))
        {
            return false;
        }

        if (2 + nameLen + 4 > data.Length)
        {
            return false;
        }

        if (!IsValidUtf8(data.Slice(2, nameLen)))
        {
            return false;
        }

        string name = Encoding.UTF8.GetString(data.Slice(2, nameLen));
        int pos = 2 + nameLen;
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(pos, 4));
        pos += 4;
        if ((long)count * MinEntryBytes > data.Length - pos)
        {
            return false;
        }

        var entries = new ManifestEntry[(int)count];
        for (int i = 0; i < count; i++)
        {
            if (!WirePrimitives.TryReadU16Le(data[pos..], out ushort pathLen))
            {
                return false;
            }

            pos += 2;
            if (pos + pathLen + 8 + RootLength > data.Length)
            {
                return false;
            }

            ReadOnlySpan<byte> pathBytes = data.Slice(pos, pathLen);
            if (!IsValidUtf8(pathBytes))
            {
                return false;
            }

            string path = Encoding.UTF8.GetString(pathBytes);
            pos += pathLen;
            long size = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(pos, 8));
            if (size < 0)
            {
                return false;
            }

            pos += 8;
            byte[] root = data.Slice(pos, RootLength).ToArray();
            pos += RootLength;
            entries[i] = new ManifestEntry(path, size, root);
        }

        if (pos != data.Length)
        {
            return false;
        }

        value = new ManifestValue(name, entries);
        return true;
    }

    public static int Write(Span<byte> destination, in ManifestValue value)
    {
        ArgumentNullException.ThrowIfNull(value.Entries);

        ValidateUtf16(value.Name);
        int nameLen = Encoding.UTF8.GetByteCount(value.Name);
        if (nameLen > MaxTextBytes)
        {
            ThrowTextTooLong("manifest name");
        }

        long total = 2 + nameLen + 4;
        foreach (ManifestEntry entry in value.Entries)
        {
            ArgumentNullException.ThrowIfNull(entry.Path);
            ArgumentNullException.ThrowIfNull(entry.Root);
            ValidateUtf16(entry.Path);
            int pathLen = Encoding.UTF8.GetByteCount(entry.Path);
            if (pathLen > MaxTextBytes)
            {
                ThrowTextTooLong("entry path");
            }

            if (entry.Size < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "entry sizes cannot be negative");
            }

            if (entry.Root.Length != RootLength)
            {
                throw new ArgumentException($"entry root must be {RootLength} bytes", nameof(value));
            }

            total += 2 + pathLen + 8 + RootLength;
        }

        if (total > destination.Length)
        {
            ThrowTooSmall();
        }

        int pos = WirePrimitives.WriteU16Le(destination, (ushort)nameLen);
        pos += Encoding.UTF8.GetBytes(value.Name.AsSpan(), destination.Slice(pos));
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(pos, 4), (uint)value.Entries.Length);
        pos += 4;
        foreach (ManifestEntry entry in value.Entries)
        {
            pos += WirePrimitives.WriteU16Le(destination.Slice(pos), (ushort)Encoding.UTF8.GetByteCount(entry.Path));
            pos += Encoding.UTF8.GetBytes(entry.Path.AsSpan(), destination.Slice(pos));
            BinaryPrimitives.WriteInt64LittleEndian(destination.Slice(pos, 8), entry.Size);
            pos += 8;
            entry.Root.CopyTo(destination.Slice(pos, RootLength));
            pos += RootLength;
        }

        return (int)total;
    }

    private static bool IsValidUtf8(ReadOnlySpan<byte> span)
    {
        int i = 0;
        while (i < span.Length)
        {
            byte lead = span[i];
            if (lead < 0x80)
            {
                i++;
                continue;
            }

            int len = lead switch
            {
                >= 0xC2 and <= 0xDF => 2,
                >= 0xE0 and <= 0xEF => 3,
                >= 0xF0 and <= 0xF4 => 4,
                _ => 0,
            };
            if (len == 0 || i + len > span.Length)
            {
                return false;
            }

            for (int k = 1; k < len; k++)
            {
                if ((span[i + k] & 0xC0) != 0x80)
                {
                    return false;
                }
            }

            if ((lead == 0xE0 && span[i + 1] < 0xA0)
                || (lead == 0xED && span[i + 1] >= 0xA0)
                || (lead == 0xF0 && span[i + 1] < 0x90)
                || (lead == 0xF4 && span[i + 1] > 0x8F))
            {
                return false;
            }

            i += len;
        }

        return true;
    }

    private static void ValidateUtf16(string text)
    {
        for (int i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]))
            {
                if (i + 1 == text.Length || !char.IsLowSurrogate(text[i + 1]))
                {
                    throw new ArgumentException("text contains an unpaired surrogate and has no UTF-8 encoding", nameof(text));
                }

                i++;
            }
            else if (char.IsLowSurrogate(text[i]))
            {
                throw new ArgumentException("text contains an unpaired surrogate and has no UTF-8 encoding", nameof(text));
            }
        }
    }

    private static void ThrowTextTooLong(string what) =>
        throw new ArgumentException($"{what} exceeds {MaxTextBytes} UTF-8 bytes and has no manifest encoding", "value");

    private static void ThrowTooSmall() => throw new ArgumentException("destination span too small");
}
