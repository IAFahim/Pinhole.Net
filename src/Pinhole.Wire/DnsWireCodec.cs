using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Unicode;

namespace Pinhole.Wire;

public readonly record struct DnsHeader(ushort Id, ushort Flags, int Questions, int Answers, int Authorities, int Additionals);

public sealed record DnsQuestion(string Name, ushort Type, ushort Class);

// RdataOffset is the record's rdata start inside the whole DNS message: PTR/SRV
// rdata can hold compression pointers, which only resolve against the message.
public sealed record DnsResourceRecord(string Name, ushort Type, ushort Class, uint Ttl, byte[] Rdata, int RdataOffset);

public sealed record DnsMessage(DnsHeader Header, DnsQuestion[] Questions, DnsResourceRecord[] Records);

public readonly record struct DnsSrv(ushort Priority, ushort Weight, ushort Port, string Target);

// Canonical DNS wire codec for the shapes this repo actually puts on the wire:
// the mDNS announcements/queries of Pinhole.DnsCodec (header, PTR/SRV/TXT/A/AAAA
// records, TXT "key=value" peer entries) and the pkarr DNS-TXT payload of
// IrohDiscovery. Byte-compatible with both on every form they produce or accept,
// and total: TryRead never throws on wire-controlled bytes and never returns an
// out-of-range value; Write throws only on programmer error.
//
// Compression pointers: READ accepts them (both existing parsers do; the pkarr
// writer even emits 0xC0 0x0C for repeated owners), with the exact safety rules
// DnsCodec.Reader.TryName uses. WRITE never compresses except through the
// explicit WriteCompressionPointer, which reproduces the pkarr owner encoding.
//
// Canonical rules enforced by TryReadMessage, numbered for the tests:
//   1. at least 12 bytes, and the transaction id is zero: every DNS message the
//      repo sends is mDNS or pkarr (DnsCodec.TryHeader requires bytes 0-1 == 0;
//      IrohDiscovery.CreatePayload writes zeros). Flags pass through unchecked —
//      both existing parsers ignore them, so the codec does not invent rules.
//   2. answers+authorities+additionals <= 256 (DnsCodec.MaxRecords).
//   3. every question and record fits inside the message: a declared record
//      count larger than the records present fails (truncated rdata fails).
//   4. the question+record walk ends exactly at the message end: trailing bytes
//      are rejected. IrohDiscovery.ReadTxt enforces this too; DnsCodec is lenient
//      here — deliberately stricter, pinned in the tests.
//   5. names: label length bytes 1..63; a length byte >= 64 that is not a
//      compression pointer (0x40..0xBF) is rejected; the 0x00 root terminates.
//   6. compression pointers 0xC0|offset: both bytes present, target strictly
//      before the pointer (no forward or self pointers), at most 128 pointer
//      follows per name (loop-safe).
//   7. sum(label bytes + 1 per label) <= 255 after decompression.
//   8. label content is ASCII (< 0x80). DnsCodec substitutes '?' for high bytes;
//      every writer in the repo emits ASCII, so the canonical codec rejects.
//      The empty name (root, zero labels) reads back as "" — mirrors DnsCodec;
//      WriteName cannot produce it (the empty label is rejected).
//   9. PTR rdata is exactly one name and SRV rdata is exactly priority, weight,
//      port and one target name, each ending exactly at the rdata end.
//      DnsCodec ignores rdlength while decompressing those names — deliberately
//      stricter, pinned in the tests.
//  10. mDNS TXT entries (key=value): the length-prefixed strings tile the rdata
//      exactly and are ASCII. DnsCodec.ParseTxt silently drops a malformed tail
//      and lossily maps high bytes to '?' — deliberately stricter, pinned in
//      the tests. Only strings with '=' at index > 0 yield entries (mirror of
//      ParseTxt; junk strings are skipped, not rejected).
//  11. pkarr TXT text: the strings tile the rdata exactly and their
//      concatenation is valid UTF-8. IrohDiscovery.ReadTxt THROWS
//      InvalidDataException on bad UTF-8 (audit C-06); the canonical codec
//      returns false instead — never throws.
public static class DnsWireCodec
{
    public const int HeaderSize = 12;
    public const int MaxLabelBytes = 63;
    public const int MaxNameBytes = 255;
    public const int MaxNameJumps = 128;
    public const int MaxRecords = 256;
    public const int MaxTxtStringBytes = 255;

    public const ushort TypeA = 1;
    public const ushort TypePtr = 12;
    public const ushort TypeTxt = 16;
    public const ushort TypeAaaa = 28;
    public const ushort TypeSrv = 33;
    public const ushort ClassIn = 1;
    public const ushort ClassAny = 255;
    public const ushort CacheFlushBit = 0x8000;

    // ---- header ----

    public static bool TryReadHeader(ReadOnlySpan<byte> message, out DnsHeader header)
    {
        header = default;
        if (message.Length < HeaderSize
            || !WirePrimitives.TryReadU16Be(message, out ushort id)
            || !WirePrimitives.TryReadU16Be(message[2..], out ushort flags)
            || !WirePrimitives.TryReadU16Be(message[4..], out ushort questions)
            || !WirePrimitives.TryReadU16Be(message[6..], out ushort answers)
            || !WirePrimitives.TryReadU16Be(message[8..], out ushort authorities)
            || !WirePrimitives.TryReadU16Be(message[10..], out ushort additionals))
        {
            return false;
        }

        header = new DnsHeader(id, flags, questions, answers, authorities, additionals);
        return true;
    }

    public static int WriteHeader(Span<byte> destination, DnsHeader header)
    {
        if (header.Questions is < 0 or > ushort.MaxValue
            || header.Answers is < 0 or > ushort.MaxValue
            || header.Authorities is < 0 or > ushort.MaxValue
            || header.Additionals is < 0 or > ushort.MaxValue)
        {
            ThrowCountRange();
        }

        if (destination.Length < HeaderSize) ThrowTooSmall();
        Span<byte> cursor = destination;
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, header.Id)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, header.Flags)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, (ushort)header.Questions)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, (ushort)header.Answers)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, (ushort)header.Authorities)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, (ushort)header.Additionals)..];
        return HeaderSize;
    }

    // ---- names ----

    // Reads one name starting at cursor (an absolute offset into message),
    // following compression pointers per rules 5-8. On success cursor advances
    // past the name's first occurrence (terminator or pointer); on failure the
    // cursor is left untouched.
    public static bool TryReadName(ReadOnlySpan<byte> message, ref int cursor, out string? name)
    {
        name = null;
        if ((uint)cursor >= (uint)message.Length)
        {
            return false;
        }

        var labels = new List<string>();
        int pos = cursor, jumps = 0, end = -1, totalLength = 0;
        while (true)
        {
            if (pos >= message.Length)
            {
                return false;
            }

            byte first = message[pos];
            if (first == 0)
            {
                pos++;
                if (end < 0) end = pos;
                break;
            }

            if ((first & 0xC0) == 0xC0)
            {
                if (pos + 1 >= message.Length || ++jumps > MaxNameJumps)
                {
                    return false;
                }

                int target = ((first & 0x3F) << 8) | message[pos + 1];
                if (target >= pos)
                {
                    return false; // forward or self pointer: DnsCodec refuses these too
                }

                if (end < 0) end = pos + 2;
                pos = target;
                continue;
            }

            if (first > MaxLabelBytes || pos + 1 + first > message.Length)
            {
                return false;
            }

            for (int i = pos + 1; i <= pos + first; i++)
            {
                if (message[i] > 0x7F) return false;
            }

            labels.Add(Encoding.ASCII.GetString(message.Slice(pos + 1, first)));
            totalLength += first + 1;
            if (totalLength > MaxNameBytes)
            {
                return false;
            }

            pos += 1 + first;
        }

        cursor = end;
        name = string.Join('.', labels);
        return true;
    }

    // Uncompressed name encoding, mirroring DnsCodec.Writer.WriteName: labels
    // split on '.', each 1..63 ASCII bytes, root terminator appended. The 255
    // total-name cap that DnsCodec only checks on read is enforced here too.
    public static int WriteName(Span<byte> destination, string name)
    {
        int written = 0, totalLength = 0;
        foreach (string label in name.Split('.'))
        {
            if (label.Length is < 1 or > MaxLabelBytes) ThrowLabelLength();
            if (destination.Length < written + 1 + label.Length) ThrowTooSmall();
            foreach (char ch in label)
            {
                if (ch > 0x7F) ThrowNotAscii();
            }

            destination[written++] = (byte)label.Length;
            Encoding.ASCII.GetBytes(label, destination[written..]);
            written += label.Length;
            totalLength += 1 + label.Length;
        }

        if (totalLength > MaxNameBytes) ThrowNameTooLong();
        if (destination.Length < written + 1) ThrowTooSmall();
        destination[written++] = 0;
        return written;
    }

    public static int WriteCompressionPointer(Span<byte> destination, int offset)
    {
        if (offset is < 0 or > 0x3FFF) ThrowPointerRange();
        if (destination.Length < 2) ThrowTooSmall();
        destination[0] = (byte)(0xC0 | (offset >> 8));
        destination[1] = (byte)offset;
        return 2;
    }

    // ---- questions ----

    public static bool TryReadQuestion(ReadOnlySpan<byte> message, ref int cursor, out DnsQuestion? question)
    {
        question = null;
        int start = cursor;
        if (!TryReadName(message, ref cursor, out string? name)
            || !WirePrimitives.TryReadU16Be(message[cursor..], out ushort type)
            || !WirePrimitives.TryReadU16Be(message[(cursor + 2)..], out ushort @class))
        {
            cursor = start;
            return false;
        }

        cursor += 4;
        question = new DnsQuestion(name!, type, @class);
        return true;
    }

    public static int WriteQuestion(Span<byte> destination, DnsQuestion question)
    {
        Span<byte> cursor = destination;
        cursor = cursor[WriteName(cursor, question.Name)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, question.Type)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, question.Class)..];
        return destination.Length - cursor.Length;
    }

    // ---- records ----

    public static bool TryReadResourceRecord(ReadOnlySpan<byte> message, ref int cursor, out DnsResourceRecord? record)
    {
        record = null;
        int start = cursor;
        if (!TryReadName(message, ref cursor, out string? name)
            || !WirePrimitives.TryReadU16Be(message[cursor..], out ushort type)
            || !WirePrimitives.TryReadU16Be(message[(cursor + 2)..], out ushort @class)
            || !WirePrimitives.TryReadU32Be(message[(cursor + 4)..], out uint ttl)
            || !WirePrimitives.TryReadU16Be(message[(cursor + 8)..], out ushort rdLength)
            || cursor + 10 + rdLength > message.Length)
        {
            cursor = start;
            return false;
        }

        int rdataOffset = cursor + 10;
        record = new DnsResourceRecord(name!, type, @class, ttl, message.Slice(rdataOffset, rdLength).ToArray(), rdataOffset);
        cursor = rdataOffset + rdLength;
        return true;
    }

    public static int WriteResourceRecord(Span<byte> destination, string name, ushort type, ushort @class, uint ttl, ReadOnlySpan<byte> rdata)
    {
        Span<byte> cursor = destination;
        cursor = cursor[WriteName(cursor, name)..];
        cursor = cursor[WriteRecordTail(cursor, type, @class, ttl, rdata)..];
        return destination.Length - cursor.Length;
    }

    // Owner passed as already-encoded name bytes (WriteName output or a
    // compression pointer), for the pkarr shape where every answer after the
    // first points back to the first owner.
    public static int WriteResourceRecord(Span<byte> destination, ReadOnlySpan<byte> encodedName, ushort type, ushort @class, uint ttl, ReadOnlySpan<byte> rdata)
    {
        Span<byte> cursor = destination;
        if (cursor.Length < encodedName.Length) ThrowTooSmall();
        encodedName.CopyTo(cursor);
        cursor = cursor[encodedName.Length..];
        cursor = cursor[WriteRecordTail(cursor, type, @class, ttl, rdata)..];
        return destination.Length - cursor.Length;
    }

    // ---- typed rdata readers (rule 9) ----

    public static bool TryReadPtrTarget(ReadOnlySpan<byte> message, DnsResourceRecord record, out string? target)
    {
        target = null;
        if (record.Type != TypePtr || !RdataInMessage(message, record)) return false;
        int cursor = record.RdataOffset;
        if (!TryReadName(message, ref cursor, out string? name) || cursor != record.RdataOffset + record.Rdata.Length)
        {
            return false;
        }

        target = name;
        return true;
    }

    public static bool TryReadSrv(ReadOnlySpan<byte> message, DnsResourceRecord record, out DnsSrv srv)
    {
        srv = default;
        if (record.Type != TypeSrv || record.Rdata.Length < 8 || !RdataInMessage(message, record)) return false;
        if (!WirePrimitives.TryReadU16Be(message[record.RdataOffset..], out ushort priority)
            || !WirePrimitives.TryReadU16Be(message[(record.RdataOffset + 2)..], out ushort weight)
            || !WirePrimitives.TryReadU16Be(message[(record.RdataOffset + 4)..], out ushort port))
        {
            return false;
        }

        int cursor = record.RdataOffset + 6;
        if (!TryReadName(message, ref cursor, out string? target) || cursor != record.RdataOffset + record.Rdata.Length)
        {
            return false;
        }

        srv = new DnsSrv(priority, weight, port, target!);
        return true;
    }

    // mDNS peer TXT framing: "key=value" strings (rule 10). Strings without a
    // '=' at index > 0 are skipped, exactly like DnsCodec.ParseTxt.
    public static bool TryReadTxtEntries(ReadOnlySpan<byte> rdata, out (string Key, string Value)[]? entries)
    {
        entries = null;
        var parsed = new List<(string, string)>();
        int pos = 0;
        while (pos < rdata.Length)
        {
            int len = rdata[pos++];
            if (len > rdata.Length - pos) return false; // ParseTxt drops a malformed tail; canonical rejects
            for (int i = pos; i < pos + len; i++)
            {
                if (rdata[i] > 0x7F) return false;
            }

            string entry = Encoding.ASCII.GetString(rdata.Slice(pos, len));
            pos += len;
            int eq = entry.IndexOf('=');
            if (eq > 0)
            {
                parsed.Add((entry[..eq], entry[(eq + 1)..]));
            }
        }

        entries = parsed.ToArray();
        return true;
    }

    // pkarr TXT framing (rule 11): strings concatenated and strict-UTF-8
    // decoded. Total where IrohDiscovery.ParsePayload throws (C-06).
    public static bool TryReadTxtText(ReadOnlySpan<byte> rdata, out string? text)
    {
        text = null;
        int total = 0, pos = 0;
        while (pos < rdata.Length)
        {
            int len = rdata[pos++];
            if (len > rdata.Length - pos) return false;
            total += len;
            pos += len;
        }

        if (total == 0)
        {
            text = "";
            return true;
        }

        byte[] joined = new byte[total];
        int offset = 0;
        pos = 0;
        while (pos < rdata.Length)
        {
            int len = rdata[pos++];
            rdata.Slice(pos, len).CopyTo(joined.AsSpan(offset));
            offset += len;
            pos += len;
        }

        if (!Utf8.IsValid(joined)) return false;
        text = Encoding.UTF8.GetString(joined);
        return true;
    }

    // ---- rdata writers ----

    public static int WriteSrvRdata(Span<byte> destination, ushort priority, ushort weight, ushort port, string target)
    {
        Span<byte> cursor = destination;
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, priority)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, weight)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, port)..];
        cursor = cursor[WriteName(cursor, target)..];
        return destination.Length - cursor.Length;
    }

    // One length-prefixed ASCII string per entry, mirroring Writer.WriteTxt's
    // framing (each "key=value" string is its own DNS string, at most 255 bytes).
    public static int WriteTxtStrings(Span<byte> destination, ReadOnlySpan<string> strings)
    {
        int written = 0;
        foreach (string text in strings)
        {
            if (text.Length > MaxTxtStringBytes) ThrowTxtTooLong();
            if (destination.Length < written + 1 + text.Length) ThrowTooSmall();
            foreach (char ch in text)
            {
                if (ch > 0x7F) ThrowNotAscii();
            }

            destination[written++] = (byte)text.Length;
            Encoding.ASCII.GetBytes(text, destination[written..]);
            written += text.Length;
        }

        return written;
    }

    // pkarr TXT chunking, byte-identical to IrohDiscovery.CreatePayload: the
    // UTF-8 text is cut into <=255-byte strings, one length byte each.
    public static int WriteTxtText(Span<byte> destination, ReadOnlySpan<byte> utf8Text)
    {
        int written = 0;
        for (int offset = 0; offset < utf8Text.Length; offset += MaxTxtStringBytes)
        {
            int size = Math.Min(MaxTxtStringBytes, utf8Text.Length - offset);
            if (destination.Length < written + 1 + size) ThrowTooSmall();
            destination[written++] = (byte)size;
            utf8Text.Slice(offset, size).CopyTo(destination[written..]);
            written += size;
        }

        return written;
    }

    // ---- mDNS shapes, byte-exact mirrors of DnsCodec.Writer ----

    public static int WritePtrQuestion(Span<byte> destination, string service)
    {
        Span<byte> cursor = destination;
        cursor = cursor[WriteName(cursor, service)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, TypePtr)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, ClassIn)..];
        return destination.Length - cursor.Length;
    }

    public static int WritePtrRecord(Span<byte> destination, string service, string instance, uint ttl)
    {
        Span<byte> cursor = destination;
        cursor = cursor[WriteName(cursor, service)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, TypePtr)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, ClassIn)..];
        cursor = cursor[WirePrimitives.WriteU32Be(cursor, ttl)..];
        int lengthAt = destination.Length - cursor.Length;
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, 0)..];
        int rdata = WriteName(cursor, instance + "." + service);
        PatchRdataLength(destination, lengthAt, rdata);
        return destination.Length - cursor.Length + rdata;
    }

    public static int WriteSrvRecord(Span<byte> destination, string service, string instance, string target, ushort port, uint ttl)
    {
        Span<byte> cursor = destination;
        cursor = cursor[WriteName(cursor, instance + "." + service)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, TypeSrv)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, (ushort)(ClassIn | CacheFlushBit))..];
        cursor = cursor[WirePrimitives.WriteU32Be(cursor, ttl)..];
        int lengthAt = destination.Length - cursor.Length;
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, 0)..];
        int rdata = WriteSrvRdata(cursor, 0, 0, port, target);
        PatchRdataLength(destination, lengthAt, rdata);
        return destination.Length - cursor.Length + rdata;
    }

    public static int WriteTxtRecord(Span<byte> destination, string service, string instance, (string Key, string Value)[] entries, uint ttl)
    {
        string[] strings = new string[entries.Length];
        for (int i = 0; i < entries.Length; i++)
        {
            strings[i] = entries[i].Key + "=" + entries[i].Value;
        }

        Span<byte> cursor = destination;
        cursor = cursor[WriteName(cursor, instance + "." + service)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, TypeTxt)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, (ushort)(ClassIn | CacheFlushBit))..];
        cursor = cursor[WirePrimitives.WriteU32Be(cursor, ttl)..];
        int lengthAt = destination.Length - cursor.Length;
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, 0)..];
        int rdata = WriteTxtStrings(cursor, strings);
        PatchRdataLength(destination, lengthAt, rdata);
        return destination.Length - cursor.Length + rdata;
    }

    public static int WriteAddressRecord(Span<byte> destination, string host, IPAddress address, uint ttl)
    {
        byte[] raw = address.GetAddressBytes();
        if (raw.Length is not (4 or 16)) ThrowAddressFamily();
        ushort type = raw.Length == 16 ? TypeAaaa : TypeA;
        return WriteResourceRecord(destination, host, type, (ushort)(ClassIn | CacheFlushBit), ttl, raw);
    }

    // ---- whole message (rules 1-4) ----

    public static bool TryReadMessage(ReadOnlySpan<byte> message, out DnsMessage? parsed)
    {
        parsed = null;
        if (!TryReadHeader(message, out DnsHeader header) || header.Id != 0) return false;
        if (header.Answers + header.Authorities + header.Additionals > MaxRecords) return false;
        if (!TryWalk(message, header, out int questions, out int records, allocate: null)) return false;
        if (questions != header.Questions || records != header.Answers + header.Authorities + header.Additionals) return false;

        DnsQuestion[] parsedQuestions = new DnsQuestion[questions];
        DnsResourceRecord[] parsedRecords = new DnsResourceRecord[records];
        if (!TryWalk(message, header, out _, out _, (parsedQuestions, parsedRecords))) return false;
        parsed = new DnsMessage(header, parsedQuestions, parsedRecords);
        return true;
    }

    // Mirrors DnsCodec.AsksForOurService: any PTR question for the service,
    // class IN or ANY with the mDNS top bit masked off, name case-insensitive.
    public static bool AsksForService(ReadOnlySpan<byte> message, string service)
    {
        ArgumentNullException.ThrowIfNull(service);
        if (!TryReadMessage(message, out DnsMessage? parsed)) return false;
        foreach (DnsQuestion question in parsed!.Questions)
        {
            if (question.Type == TypePtr
                && (question.Class & 0x7FFF) is ClassIn or ClassAny
                && question.Name.Equals(service, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryWalk(ReadOnlySpan<byte> message, DnsHeader header, out int questions, out int records,
        (DnsQuestion[] Questions, DnsResourceRecord[] Records)? allocate)
    {
        questions = 0;
        records = 0;
        int cursor = HeaderSize;
        for (int i = 0; i < header.Questions; i++)
        {
            if (!TryReadQuestion(message, ref cursor, out DnsQuestion? question)) return false;
            if (allocate is { } sink) sink.Questions[i] = question!;
            questions++;
        }

        int total = header.Answers + header.Authorities + header.Additionals;
        for (int i = 0; i < total; i++)
        {
            if (!TryReadResourceRecord(message, ref cursor, out DnsResourceRecord? record)) return false;
            if (allocate is { } sink) sink.Records[i] = record!;
            records++;
        }

        return cursor == message.Length; // rule 4: no trailing bytes
    }

    private static bool RdataInMessage(ReadOnlySpan<byte> message, DnsResourceRecord record) =>
        record.RdataOffset >= 0 && record.RdataOffset + record.Rdata.Length <= message.Length;

    private static int WriteRecordTail(Span<byte> destination, ushort type, ushort @class, uint ttl, ReadOnlySpan<byte> rdata)
    {
        if (rdata.Length > ushort.MaxValue) ThrowRdataTooLarge();
        if (destination.Length < 10 + rdata.Length) ThrowTooSmall();
        Span<byte> cursor = destination;
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, type)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, @class)..];
        cursor = cursor[WirePrimitives.WriteU32Be(cursor, ttl)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, (ushort)rdata.Length)..];
        rdata.CopyTo(cursor);
        return 10 + rdata.Length;
    }

    private static void PatchRdataLength(Span<byte> destination, int lengthAt, int length)
    {
        if (length > ushort.MaxValue) ThrowRdataTooLarge();
        destination[lengthAt] = (byte)(length >> 8);
        destination[lengthAt + 1] = (byte)length;
    }

    private static void ThrowTooSmall() => throw new ArgumentException("destination span too small");

    private static void ThrowCountRange() => throw new ArgumentOutOfRangeException("counts", "DNS section counts are 0..65535");

    private static void ThrowLabelLength() => throw new ArgumentException("DNS labels are 1-63 bytes");

    private static void ThrowNameTooLong() => throw new ArgumentException("DNS names are at most 255 bytes");

    private static void ThrowNotAscii() => throw new ArgumentException("DNS names and TXT strings are ASCII");

    private static void ThrowTxtTooLong() => throw new ArgumentException("TXT strings are one DNS string each, at most 255 bytes");

    private static void ThrowRdataTooLarge() => throw new ArgumentException("rdata exceeds the 16-bit DNS length field");

    private static void ThrowPointerRange() => throw new ArgumentOutOfRangeException("offset", "compression pointer offsets are 14 bits");

    private static void ThrowAddressFamily() => throw new ArgumentException("address must be IPv4 or IPv6");
}
