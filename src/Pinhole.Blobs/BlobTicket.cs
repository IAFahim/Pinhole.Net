using System.Buffers.Binary;
using System.Text;

namespace Pinhole.Blobs;

public enum BlobKind : byte
{
    File = 1,

    Directory = 2,
}

public sealed class BlobTicket
{
    public const string Scheme = "pinholeblob1";

    public const int MaxEncodedLength = 16 * 1024;

    public required BlobKind Kind { get; init; }

    public required byte[] Root { get; init; }

    public required string ConnectionString { get; init; }

    public string Name { get; init; } = "";

    public byte[]? PreSharedKey { get; init; }

    public bool Encrypted => PreSharedKey is not null;

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
        payload.WriteByte(1);
        payload.WriteByte((byte)((Kind == BlobKind.Directory ? 1 : 0) | (PreSharedKey is null ? 0 : 2)));
        payload.WriteByte((byte)name.Length);
        payload.Write(name);
        payload.Write(Root);
        if (psk.Length > 0)
        {
            payload.Write(psk);
        }

        WriteU16(payload, (ushort)cs.Length);
        payload.Write(cs);
        return Scheme + ":" + Pinhole.Base64Url.Encode(payload.GetBuffer().AsSpan(0, (int)payload.Length));

        static void WriteU16(Stream s, ushort value)
        {
            Span<byte> tmp = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(tmp, value);
            s.Write(tmp);
        }
    }

    public static bool TryParse(string? text, out BlobTicket? ticket)
    {
        if (text is null)
        {
            ticket = null;
            return false;
        }

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

        int csLen = BinaryPrimitives.ReadUInt16LittleEndian(p.AsSpan(pos, 2));
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

internal static class Manifest
{
    public sealed record Entry(string Path, long Size, byte[] Root);

    public static byte[] Encode(string name, IReadOnlyList<Entry> entries)
    {
        var payload = new MemoryStream(64 + entries.Count * 64);
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        WriteText(payload, nameBytes);
        WriteU32(payload, (uint)entries.Count);
        foreach (Entry e in entries)
        {
            WriteText(payload, Encoding.UTF8.GetBytes(e.Path));
            WriteU64(payload, e.Size);
            payload.Write(e.Root);
        }

        return payload.ToArray();

        static void WriteText(Stream s, byte[] text)
        {
            WriteU16(s, (ushort)text.Length);
            s.Write(text);
        }

        static void WriteU16(Stream s, ushort value)
        {
            Span<byte> tmp = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(tmp, value);
            s.Write(tmp);
        }

        static void WriteU32(Stream s, uint value)
        {
            Span<byte> tmp = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(tmp, value);
            s.Write(tmp);
        }

        static void WriteU64(Stream s, long value)
        {
            Span<byte> tmp = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(tmp, value);
            s.Write(tmp);
        }
    }

    public static (string Name, List<Entry> Entries) Decode(ReadOnlySpan<byte> data)
    {
        try
        {
            var reader = new Reader(data);
            string name = Encoding.UTF8.GetString(reader.ReadBytes(reader.ReadU16()));
            uint count = reader.ReadU32();

            var entries = new List<Entry>((int)Math.Min(count, 64));
            for (int i = 0; i < count; i++)
            {
                string path = Encoding.UTF8.GetString(reader.ReadBytes(reader.ReadU16()));
                long size = reader.ReadI64();
                if (size < 0)
                {
                    throw new FormatException();
                }

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
