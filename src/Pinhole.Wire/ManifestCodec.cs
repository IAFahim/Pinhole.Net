using System.Buffers.Binary;
using System.Text;

namespace Pinhole.Wire;

// One directory-manifest entry. Root is always a 32-byte BLAKE3 root.
public readonly record struct ManifestEntry(string Path, long Size, byte[] Root);

// The directory manifest as a value. Manifest bytes are BLAKE3-hashed into the
// ticket root, so Write must be byte-exact: the same value always produces the
// same bytes, and decoding a payload then re-encoding it reproduces the payload.
public readonly record struct ManifestValue(string Name, ManifestEntry[] Entries);

// Canonical codec for the directory manifest, mirrored from BlobTicket's
// internal Manifest encode/decode. Layout (all integers little-endian):
//   u16 nameLen, nameLen bytes of UTF-8
//   u32 entryCount
//   per entry: u16 pathLen, pathLen bytes of UTF-8, i64 size (>= 0), 32-byte root
//   and nothing else: trailing bytes are rejected.
// Tightenings over the legacy decoder: names and paths must be valid UTF-8 (the
// legacy GetString replaces bad bytes with U+FFFD, silently changing the hash
// preimage) and Write refuses the values the legacy encoder could emit but its
// own decoder rejects (negative sizes, non-32-byte roots, >65535-byte text).
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
            return false; // the claimed count cannot fit in what is left: truncated (or lying) input
        }

        var entries = new ManifestEntry[(int)count];
        for (int i = 0; i < count; i++)
        {
            if (!WirePrimitives.TryReadU16Le(data[pos..], out ushort pathLen))
            {
                return false; // the count fit-check guarantees these two bytes; total regardless
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
            return false; // trailing bytes are not part of any entry
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

    // Strict UTF-8 well-formedness: rejects bare continuations, overlong forms
    // (C0/C1 leads, E0 <A0, F0 <90), surrogate halves (ED >=A0), and anything
    // above U+10FFFF (F4 >8F) — everything the lossy Encoding.UTF8 decode would
    // quietly turn into U+FFFD.
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

                i++; // the low half is consumed with its lead
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
