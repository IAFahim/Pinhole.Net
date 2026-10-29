using System.Buffers.Binary;
using System.Text;

namespace Pinhole.Wire;

public enum WireBlobKind : byte
{
    File = 1,

    Directory = 2,
}

public readonly record struct BlobTicketValue(
    WireBlobKind Kind,
    byte[] Root,
    string ConnectionString,
    string Name,
    byte[]? PreSharedKey);

public static class BlobTicketCodec
{
    public const string Scheme = "pinholeblob1";

    public const int MaxTextLength = 16 * 1024;

    public const int RootLength = 32;

    public const int PskLength = 32;

    public const int MaxNameBytes = 255;

    public const int MaxBinaryLength = 3 + MaxNameBytes + RootLength + PskLength + 2 + ushort.MaxValue;

    private const byte Version = 1;
    private const byte FlagDirectory = 1;
    private const byte FlagEncrypted = 2;
    private const byte KnownFlags = FlagDirectory | FlagEncrypted;

    public static bool TryRead(ReadOnlySpan<byte> payload, out BlobTicketValue value)
    {
        value = default;
        if (payload.Length < 4)
        {
            return false;
        }

        if (payload[0] != Version)
        {
            return false;
        }

        byte flags = payload[1];
        if ((flags & ~KnownFlags) != 0)
        {
            return false;
        }

        int nameLen = payload[2];
        bool encrypted = (flags & FlagEncrypted) != 0;
        int pos = 3 + nameLen;
        if (pos + RootLength + 2 + (encrypted ? PskLength : 0) > payload.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> nameBytes = payload.Slice(3, nameLen);
        if (!IsValidUtf8(nameBytes))
        {
            return false;
        }

        ReadOnlySpan<byte> root = payload.Slice(pos, RootLength);
        pos += RootLength;
        byte[]? psk = null;
        if (encrypted)
        {
            psk = payload.Slice(pos, PskLength).ToArray();
            pos += PskLength;
        }

        if (!WirePrimitives.TryReadU16Le(payload[pos..], out ushort csLen))
        {
            return false;
        }

        pos += 2;
        if (csLen == 0 || pos + csLen != payload.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> csBytes = payload.Slice(pos);
        if (csBytes.IndexOfAnyExceptInRange((byte)0, (byte)0x7F) >= 0)
        {
            return false;
        }

        value = new BlobTicketValue(
            (flags & FlagDirectory) != 0 ? WireBlobKind.Directory : WireBlobKind.File,
            root.ToArray(),
            Encoding.ASCII.GetString(csBytes),
            Encoding.UTF8.GetString(nameBytes),
            psk);
        return true;
    }

    public static int Write(Span<byte> destination, in BlobTicketValue value)
    {
        int total = PayloadLength(in value);
        if (destination.Length < total)
        {
            ThrowTooSmall();
        }

        byte[]? psk = value.PreSharedKey;
        destination[0] = Version;
        destination[1] = (byte)((value.Kind == WireBlobKind.Directory ? FlagDirectory : 0) | (psk is null ? 0 : FlagEncrypted));

        int fullNameLen = Encoding.UTF8.GetByteCount(value.Name);
        int nameLen = fullNameLen <= MaxNameBytes ? fullNameLen : TruncatedNameLength(value.Name);
        destination[2] = (byte)nameLen;
        if (nameLen == fullNameLen)
        {
            Encoding.UTF8.GetBytes(value.Name.AsSpan(), destination.Slice(3));
        }
        else
        {
            byte[] full = Encoding.UTF8.GetBytes(value.Name);
            full.AsSpan(0, nameLen).CopyTo(destination.Slice(3));
        }

        int pos = 3 + nameLen;
        value.Root.CopyTo(destination.Slice(pos, RootLength));
        pos += RootLength;
        psk?.CopyTo(destination.Slice(pos, PskLength));
        pos += psk is null ? 0 : PskLength;
        WirePrimitives.WriteU16Le(destination.Slice(pos, 2), (ushort)value.ConnectionString.Length);
        for (int i = 0; i < value.ConnectionString.Length; i++)
        {
            destination[pos + 2 + i] = (byte)value.ConnectionString[i];
        }

        return total;
    }

    public static string WriteText(in BlobTicketValue value)
    {
        byte[] payload = new byte[PayloadLength(in value)];
        Write(payload, in value);
        string text = Scheme + ":" + Convert.ToBase64String(payload).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (text.Length > MaxTextLength)
        {
            throw new ArgumentException($"ticket text exceeds {MaxTextLength} characters and has no readable form", nameof(value));
        }

        return text;
    }

    public static bool TryReadText(string? text, out BlobTicketValue value)
    {
        value = default;
        if (text is null || text.Length > MaxTextLength)
        {
            return false;
        }

        int colon = text.IndexOf(':');
        if (colon <= 0 || !text.AsSpan(0, colon).SequenceEqual(Scheme))
        {
            return false;
        }

        string body = text[(colon + 1)..].Trim();
        if (!TryDecodeBase64Url(body, out byte[] payload))
        {
            return false;
        }

        return TryRead(payload, out value);
    }

    private static int PayloadLength(in BlobTicketValue value)
    {
        if (value.Kind is not (WireBlobKind.File or WireBlobKind.Directory))
        {
            throw new ArgumentOutOfRangeException(nameof(value), "unknown blob kind");
        }

        if (value.Root.Length != RootLength)
        {
            throw new ArgumentException($"root must be {RootLength} bytes", nameof(value));
        }

        if (value.PreSharedKey is { Length: not PskLength })
        {
            throw new ArgumentException($"pre-shared key must be {PskLength} bytes", nameof(value));
        }

        string cs = value.ConnectionString;
        if (cs.Length == 0 || cs.Length > ushort.MaxValue)
        {
            throw new ArgumentException("connection string must hold between 1 and 65535 characters", nameof(value));
        }

        foreach (char c in cs)
        {
            if (c > 0x7F)
            {
                throw new ArgumentException("connection string must be ASCII", nameof(value));
            }
        }

        ValidateUtf16(value.Name);
        int nameLen = Encoding.UTF8.GetByteCount(value.Name);
        if (nameLen > MaxNameBytes)
        {
            nameLen = TruncatedNameLength(value.Name);
        }

        return 3 + nameLen + RootLength + (value.PreSharedKey is null ? 0 : PskLength) + 2 + cs.Length;
    }

    private static int TruncatedNameLength(string name)
    {
        byte[] full = Encoding.UTF8.GetBytes(name);
        int cut = MaxNameBytes;
        while (cut > 0 && (full[cut] & 0xC0) == 0x80)
        {
            cut--;
        }

        return cut;
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

    private static bool TryDecodeBase64Url(string text, out byte[] payload)
    {
        payload = [];
        foreach (char c in text)
        {
            if (!(c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_' or '='))
            {
                return false;
            }
        }

        int pad = (4 - text.Length % 4) % 4;
        char[] base64 = new char[text.Length + pad];
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            base64[i] = c == '-' ? '+' : c == '_' ? '/' : c;
        }

        for (int i = 0; i < pad; i++)
        {
            base64[text.Length + i] = '=';
        }

        byte[] buffer = new byte[base64.Length / 4 * 3];
        if (!Convert.TryFromBase64Chars(base64, buffer, out int written))
        {
            return false;
        }

        payload = written == buffer.Length ? buffer : buffer[..written];
        return true;
    }

    private static void ThrowTooSmall() => throw new ArgumentException("destination span too small");
}
