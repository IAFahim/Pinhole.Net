using System.Buffers.Binary;
using System.Text;

namespace Pinhole.Blobs;

/// <summary>Kind of content a ticket grants: a single file, or a directory manifest.</summary>
public enum BlobKind : byte
{
    /// <summary>The ticket pins one file's root; downloading writes that one file.</summary>
    File = 1,

    /// <summary>The ticket root is a manifest's root; downloading writes the whole tree.</summary>
    Directory = 2,
}

/// <summary>The single artifact a receiver needs — the sendme ticket, Pinhole-style:
/// "pinholeblob1:&lt;base64url&gt;". Carries the sender's live connection string (peer ID +
/// direct/reflexive/relay candidates — full roaming power), the BLAKE3 root that pins the
/// content, the content kind, a display-name hint, and — by default — a 32-byte pre-shared
/// key so every blob frame is AEAD-encrypted end to end (public relays read nothing but
/// ciphertext). The string is a capability: anyone holding it can download, exactly like
/// holding the underlying connection string lets them dial.</summary>
public sealed class BlobTicket
{
    /// <summary>The scheme prefix every encoded ticket starts with; the digit is the format version.</summary>
    public const string Scheme = "pinholeblob1";

    /// <summary>The hard cap on encoded length accepted by <see cref="Parse"/> — longer
    /// strings are rejected as malformed, not parsed.</summary>
    public const int MaxEncodedLength = 16 * 1024;

    /// <summary>Whether the root pins a single file or a directory manifest.</summary>
    public required BlobKind Kind { get; init; }

    /// <summary>The 32-byte BLAKE3 root pinning the exact content — the download only
    /// succeeds if every byte verifies against it.</summary>
    public required byte[] Root { get; init; }

    /// <summary>The provider's live connection string, with full candidate and roaming power.</summary>
    public required string ConnectionString { get; init; }

    /// <summary>Display-name hint: the suggested filename (files) or directory name.</summary>
    public string Name { get; init; } = "";

    /// <summary>The 32-byte ticket pre-shared key; null when the provider serves plaintext.</summary>
    public byte[]? PreSharedKey { get; init; }

    /// <summary>True when frames are AEAD-wrapped under this ticket's key.</summary>
    public bool Encrypted => PreSharedKey is not null;

    /// <summary>Encodes as "pinholeblob1:…" (base64url); see docs/BLOBS.md for the layout.</summary>
    public override string ToString()
    {
        byte[] cs = Encoding.ASCII.GetBytes(ConnectionString);
        byte[] name = Encoding.UTF8.GetBytes(Name);
        if (name.Length > 255)
        {
            name = name[..255];
        }

        byte[] psk = PreSharedKey ?? Array.Empty<byte>();
        var payload = new MemoryStream(13 + 32 + psk.Length + 2 + cs.Length + name.Length);
        payload.WriteByte(1); // version
        payload.WriteByte((byte)((Kind == BlobKind.Directory ? 1 : 0) | (PreSharedKey is null ? 0 : 2)));
        payload.WriteByte((byte)name.Length);
        payload.Write(name);
        payload.Write(Root);
        if (psk.Length > 0)
        {
            payload.Write(psk);
        }

        payload.Write(BitConverter.GetBytes((ushort)cs.Length));
        payload.Write(cs);
        return Scheme + ":" + Pinhole.Base64Url.Encode(payload.GetBuffer().AsSpan(0, (int)payload.Length));
    }

    /// <summary>Attempts a <see cref="Parse"/> without throwing: false on any malformed
    /// input (wrong scheme, bad base64url, wrong version, truncated or trailing payload).</summary>
    public static bool TryParse(string? text, out BlobTicket? ticket)
    {
        try
        {
            ticket = Parse(text);
            return true;
        }
        catch (FormatException)
        {
            ticket = null;
            return false;
        }
    }

    /// <summary>Strict parse: throws <see cref="FormatException"/> on anything but a
    /// well-formed current-version ticket, and <see cref="ArgumentNullException"/> on null.
    /// Surrounding whitespace after the colon is tolerated (terminal paste artifacts).</summary>
    public static BlobTicket Parse(string? text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.Length > MaxEncodedLength)
        {
            throw new FormatException($"ticket exceeds {MaxEncodedLength} characters");
        }

        int colon = text.IndexOf(':');
        if (colon <= 0 || text[..colon] != Scheme)
        {
            throw new FormatException($"expected a \"{Scheme}:\" ticket");
        }

        byte[] p = Pinhole.Base64Url.Decode(text[(colon + 1)..].Trim());
        if (p.Length < 13 || p[0] != 1)
        {
            throw new FormatException("unsupported ticket version");
        }

        int pos = 1;
        byte flags = p[pos++];
        var kind = (BlobKind)((flags & 1) + 1);
        if (kind is not (BlobKind.File or BlobKind.Directory))
        {
            throw new FormatException("unknown ticket kind");
        }

        bool encrypted = (flags & 2) != 0;
        int nameLen = p[pos++];
        if (pos + nameLen + 32 + 2 + (encrypted ? 32 : 0) > p.Length)
        {
            throw new FormatException("ticket payload is truncated");
        }

        string name = Encoding.UTF8.GetString(p, pos, nameLen);
        pos += nameLen;
        var root = new byte[32];
        Buffer.BlockCopy(p, pos, root, 0, 32);
        pos += 32;
        byte[]? psk = null;
        if (encrypted)
        {
            psk = new byte[32];
            Buffer.BlockCopy(p, pos, psk, 0, 32);
            pos += 32;
        }

        int csLen = BitConverter.ToUInt16(p, pos);
        pos += 2;
        if (csLen == 0 || pos + csLen != p.Length)
        {
            throw new FormatException("ticket connection string is malformed");
        }

        string cs = Encoding.ASCII.GetString(p, pos, csLen);
        if (!Pinhole.ConnectionString.TryParse(cs, out _))
        {
            throw new FormatException("ticket connection string is malformed");
        }

        return new BlobTicket { Kind = kind, Root = root, ConnectionString = cs, Name = name, PreSharedKey = psk };
    }
}

/// <summary>Binary manifest for directory tickets (deliberately not JSON: reflection-free,
/// AOT-trivial, compact). The manifest itself is a BLAKE3-verified blob, so every entry's
/// hash and path is pinned by the ticket root.</summary>
internal static class Manifest
{
    public sealed record Entry(string Path, long Size, byte[] Root);

    public static byte[] Encode(string name, IReadOnlyList<Entry> entries)
    {
        var payload = new MemoryStream(64 + entries.Count * 64);
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        WriteText(payload, nameBytes);
        payload.Write(BitConverter.GetBytes((uint)entries.Count));
        foreach (Entry e in entries)
        {
            WriteText(payload, Encoding.UTF8.GetBytes(e.Path));
            payload.Write(BitConverter.GetBytes(e.Size));
            payload.Write(e.Root);
        }

        return payload.ToArray();

        static void WriteText(MemoryStream s, byte[] text)
        {
            s.Write(BitConverter.GetBytes((ushort)text.Length));
            s.Write(text);
        }
    }

    public static (string Name, List<Entry> Entries) Decode(ReadOnlySpan<byte> data)
    {
        try
        {
            var reader = new Reader(data);
            string name = Encoding.UTF8.GetString(reader.ReadBytes(reader.ReadU16()));
            uint count = reader.ReadU32();
            var entries = new List<Entry>((int)count);
            for (int i = 0; i < count; i++)
            {
                string path = Encoding.UTF8.GetString(reader.ReadBytes(reader.ReadU16()));
                long size = reader.ReadI64();
                entries.Add(new Entry(path, size, reader.ReadBytes(32).ToArray()));
            }

            if (!reader.AtEnd)
            {
                throw new FormatException();
            }

            return (name, entries);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            throw new FormatException("malformed manifest", ex);
        }
    }

    private ref struct Reader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> _data = data;
        private int _pos;

        public readonly bool AtEnd => _pos == _data.Length;

        public ushort ReadU16()
        {
            ushort v = BinaryPrimitives.ReadUInt16LittleEndian(_data.Slice(_pos, 2));
            _pos += 2;
            return v;
        }

        public uint ReadU32()
        {
            uint v = BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_pos, 4));
            _pos += 4;
            return v;
        }

        public long ReadI64()
        {
            long v = BinaryPrimitives.ReadInt64LittleEndian(_data.Slice(_pos, 8));
            _pos += 8;
            return v;
        }

        public ReadOnlySpan<byte> ReadBytes(int n)
        {
            ReadOnlySpan<byte> s = _data.Slice(_pos, n);
            _pos += n;
            return s;
        }
    }
}
