using System.Buffers.Binary;
using System.Net;
using System.Reflection;
using System.Text;
using Pinhole.Wire;
using Xunit;

namespace Pinhole.Tests.Wire;

// Differential oracles for DnsWireCodec against the production DNS code: the
// internal Pinhole.DnsCodec (mDNS announcements/queries, TXT peer records) and
// Pinhole.IrohDiscovery (pkarr DNS-TXT payloads) are called directly through
// InternalsVisibleTo; IrohDiscovery.Signable is private and reached through a
// compiled delegate because span parameters cannot be boxed. Everything here is
// seeded and socket-free: no network, no timing, no filesystem.
public sealed class DnsWireCodecTests
{
    private const string Service = "_pinhole._udp.local";

    private delegate byte[] SignableD(ulong timestamp, ReadOnlySpan<byte> dns);

    private static readonly SignableD IrohSignable =
        typeof(IrohDiscovery).GetMethod("Signable", BindingFlags.NonPublic | BindingFlags.Static)!.CreateDelegate<SignableD>();

    private sealed record DnsRecordSpec(string Name, ushort Type, ushort Class, uint Ttl, byte[] Rdata);

    private sealed record GeneratedDns(DnsQuestion[] Questions, DnsRecordSpec[] Records);

    // ---- 1. header ----

    [Fact]
    public void Header_GoldenBytes_RoundTripAndBounds()
    {
        byte[] golden = Convert.FromHexString("000084000000000300000002");
        byte[] buffer = new byte[12];
        Assert.Equal(12, DnsWireCodec.WriteHeader(buffer, new DnsHeader(0, 0x8400, 0, 3, 0, 2)));
        Assert.Equal(golden, buffer);
        Assert.True(DnsWireCodec.TryReadHeader(golden, out DnsHeader header));
        Assert.Equal((ushort)0, header.Id);
        Assert.Equal((ushort)0x8400, header.Flags);
        Assert.Equal(0, header.Questions);
        Assert.Equal(3, header.Answers);
        Assert.Equal(0, header.Authorities);
        Assert.Equal(2, header.Additionals);

        // generic header read: id and flags pass through untouched
        Assert.True(DnsWireCodec.TryReadHeader(Convert.FromHexString("ABCD12340001000200030004"), out DnsHeader passthrough));
        Assert.Equal((ushort)0xABCD, passthrough.Id);
        Assert.Equal((ushort)0x1234, passthrough.Flags);
        Assert.Equal(1, passthrough.Questions);
        Assert.Equal(2, passthrough.Answers);
        Assert.Equal(3, passthrough.Authorities);
        Assert.Equal(4, passthrough.Additionals);

        Assert.False(DnsWireCodec.TryReadHeader([], out _));
        Assert.False(DnsWireCodec.TryReadHeader(golden[..11], out _));

        byte[] small = new byte[11];
        Assert.Throws<ArgumentException>(() => DnsWireCodec.WriteHeader(small, new DnsHeader(0, 0, 0, 0, 0, 0)));
        Assert.Throws<ArgumentOutOfRangeException>(() => DnsWireCodec.WriteHeader(buffer, new DnsHeader(0, 0, 70_000, 0, 0, 0)));
        Assert.Throws<ArgumentOutOfRangeException>(() => DnsWireCodec.WriteHeader(buffer, new DnsHeader(0, 0, 0, -1, 0, 0)));
    }

    // ---- 2. names: labels, pointers, sizes ----

    [Fact]
    public void Names_LabelsPointersAndBoundaries_MirrorDnsCodecRules()
    {
        byte[] buffer = new byte[400];
        int n = DnsWireCodec.WriteName(buffer, Service);
        Assert.Equal(21, n);
        Assert.Equal(Convert.FromHexString("085F70696E686F6C65045F756470056C6F63616C00"), buffer[..n]);

        int cursor = 0;
        Assert.True(DnsWireCodec.TryReadName(buffer.AsSpan(0, n), ref cursor, out string? name));
        Assert.Equal(Service, name);
        Assert.Equal(n, cursor); // advanced past the terminator, DnsCodec.Reader semantics

        // compression pointer reading: a pointer to an earlier name yields the
        // same string and advances the cursor by exactly two bytes
        byte[] pointerMessage = Convert.FromHexString("0377777700" + "C000");
        cursor = 5;
        Assert.True(DnsWireCodec.TryReadName(pointerMessage, ref cursor, out string? pointed));
        Assert.Equal("www", pointed);
        Assert.Equal(7, cursor);

        // backward pointer chain of exactly 128 follows is accepted
        byte[] chain = BuildPointerChain(128, out int start128);
        cursor = start128;
        Assert.True(DnsWireCodec.TryReadName(chain, ref cursor, out string? chained));
        Assert.Equal("", chained); // resolves to the lone root at offset 0

        // 129 follows exceeds MaxNameJumps: refused, not spun
        byte[] tooLong = BuildPointerChain(129, out int start129);
        cursor = start129;
        Assert.False(DnsWireCodec.TryReadName(tooLong, ref cursor, out _));
        Assert.Equal(start129, cursor); // cursor untouched on failure

        // self and forward pointers are refused (DnsCodec: target >= pos)
        cursor = 0;
        Assert.False(DnsWireCodec.TryReadName(Convert.FromHexString("C000"), ref cursor, out _));
        cursor = 1;
        Assert.False(DnsWireCodec.TryReadName(Convert.FromHexString("00C002"), ref cursor, out _));

        // length bytes 64..191 are neither labels nor pointers
        byte[] length64 = new byte[66];
        length64[0] = 64;
        cursor = 0;
        Assert.False(DnsWireCodec.TryReadName(length64, ref cursor, out _));
        length64[0] = 0xBF;
        cursor = 0;
        Assert.False(DnsWireCodec.TryReadName(length64, ref cursor, out _));

        // rule 7: sum(label bytes + one length byte per label) capped at 255
        byte[] at255 = BuildNameBytes(63, 63, 62, 63); // 4*64 - 1 = 255
        cursor = 0;
        Assert.True(DnsWireCodec.TryReadName(at255, ref cursor, out string? big));
        Assert.Equal(4, big!.Split('.').Length);
        byte[] over255 = BuildNameBytes(63, 63, 63, 63); // 256
        cursor = 0;
        Assert.False(DnsWireCodec.TryReadName(over255, ref cursor, out _));

        // rule 8: label bytes >= 0x80 are rejected here; DnsCodec maps them to '?'
        byte[] highByte = [0x02, 0xC3, 0xA0, 0x00];
        cursor = 0;
        Assert.False(DnsWireCodec.TryReadName(highByte, ref cursor, out _));

        // the root name reads as "" (mirrors DnsCodec); WriteName cannot produce it
        byte[] root = [0x00];
        cursor = 0;
        Assert.True(DnsWireCodec.TryReadName(root, ref cursor, out string? empty));
        Assert.Equal("", empty);

        Assert.Throws<ArgumentException>(() => DnsWireCodec.WriteName(buffer, "a..b"));
        Assert.Throws<ArgumentException>(() => DnsWireCodec.WriteName(buffer, ""));
        Assert.Throws<ArgumentException>(() => DnsWireCodec.WriteName(buffer, new string('a', 64)));
        Assert.Throws<ArgumentException>(() => DnsWireCodec.WriteName(buffer, "naïve"));
        Assert.Throws<ArgumentException>(() => DnsWireCodec.WriteName(buffer, string.Join('.', Enumerable.Repeat(new string('a', 63), 5))));
        byte[] two = new byte[2];
        Assert.Equal(2, DnsWireCodec.WriteCompressionPointer(two, 12));
        Assert.Equal([0xC0, 0x0C], two);
        Assert.Throws<ArgumentOutOfRangeException>(() => DnsWireCodec.WriteCompressionPointer(two, 0x4000));
    }

    private static byte[] BuildPointerChain(int pointers, out int start)
    {
        // offset 0 is the bare root; every pointer aims at the previous one
        byte[] message = new byte[1 + 2 * pointers];
        int previous = 0;
        start = 0;
        for (int i = 0; i < pointers; i++)
        {
            int at = 1 + 2 * i;
            message[at] = (byte)(0xC0 | (previous >> 8));
            message[at + 1] = (byte)previous;
            previous = at;
            start = at;
        }

        return message;
    }

    private static byte[] BuildNameBytes(params int[] labelLengths)
    {
        int total = 1;
        foreach (int labelLength in labelLengths)
        {
            total += 1 + labelLength;
        }

        byte[] name = new byte[total];
        int position = 0;
        foreach (int labelLength in labelLengths)
        {
            name[position++] = (byte)labelLength;
            for (int i = 0; i < labelLength; i++)
            {
                name[position++] = (byte)'a';
            }
        }

        name[position] = 0;
        return name;
    }

    // ---- 3. queries: byte-exact with Writer + AsksFor differential ----

    [Fact]
    public void Query_ByteExactWithWriter_AndAsksForServiceDifferential()
    {
        byte[] golden = Convert.FromHexString(
            "000000000001000000000000" + "08" + "5F70696E686F6C65" + "04" + "5F756470" + "05" + "6C6F63616C" + "00" + "000C" + "0001");
        byte[] buffer = new byte[64];
        Span<byte> cursor = buffer;
        cursor = cursor[DnsWireCodec.WriteHeader(cursor, new DnsHeader(0, 0x0000, 1, 0, 0, 0))..];
        cursor = cursor[DnsWireCodec.WritePtrQuestion(cursor, Service)..];
        Assert.Equal(golden, buffer[..(buffer.Length - cursor.Length)]);

        var w = new DnsCodec.Writer();
        w.Header(flags: 0x0000, questions: 1, answers: 0, 0, 0);
        w.WritePtrQuestion(Service);
        Assert.Equal(w.ToArray(), golden); // the golden bytes are exactly the production query

        Assert.True(DnsWireCodec.AsksForService(golden, Service));
        Assert.True(DnsCodec.AsksForOurService(golden));
        Assert.False(DnsWireCodec.AsksForService(golden, "_http._tcp.local"));

        // predicate parity on seeded shapes: type PTR, class masked to IN/ANY,
        // name case-insensitive, matching question anywhere in the list
        var rng = new Random(0x0D05_0001);
        for (int i = 0; i < 400; i++)
        {
            string name = i % 3 == 0 ? Service : i % 3 == 1 ? "_PINHOLE._UDP.LOCAL" : "_http._tcp.local";
            ushort type = (ushort)(i % 5 == 0 ? DnsWireCodec.TypeTxt : i % 5 == 1 ? DnsWireCodec.TypeSrv : DnsWireCodec.TypePtr);
            ushort @class = (ushort)(i % 6 switch
            {
                0 => DnsWireCodec.ClassAny,
                1 => DnsWireCodec.ClassIn,
                2 => DnsWireCodec.ClassIn | DnsWireCodec.CacheFlushBit,
                3 => 3, // CH: no match
                _ => rng.Next(0, 0x10000),
            });

            bool expected = type == DnsWireCodec.TypePtr
                && (@class & 0x7FFF) is DnsWireCodec.ClassIn or DnsWireCodec.ClassAny
                && name.Equals(Service, StringComparison.OrdinalIgnoreCase);

            byte[] query = ComposeQuery(name, type, @class, withJunkQuestion: i % 4 == 0);
            Assert.Equal(expected, DnsWireCodec.AsksForService(query, Service));
            Assert.Equal(expected, DnsCodec.AsksForOurService(query));
        }
    }

    private static byte[] ComposeQuery(string name, ushort type, ushort @class, bool withJunkQuestion)
    {
        byte[] buffer = new byte[256];
        Span<byte> cursor = buffer;
        cursor = cursor[DnsWireCodec.WriteHeader(cursor, new DnsHeader(0, 0, withJunkQuestion ? 2 : 1, 0, 0, 0))..];
        if (withJunkQuestion)
        {
            cursor = cursor[DnsWireCodec.WriteQuestion(cursor, new DnsQuestion("other.x", DnsWireCodec.TypeA, DnsWireCodec.ClassIn))..];
        }

        cursor = cursor[DnsWireCodec.WriteQuestion(cursor, new DnsQuestion(name, type, @class))..];
        return buffer[..(buffer.Length - cursor.Length)].ToArray();
    }

    // ---- 4. announcements: byte-exact with Writer + identical re-read ----

    [Fact]
    public void Announcement_ByteExactWithWriter_AndTryReadsIdenticalValues()
    {
        var rng = new Random(0x0D05_0002);
        for (int i = 0; i < 250; i++)
        {
            ulong peerId = (ulong)rng.NextInt64();
            byte[]? key = i % 3 == 0 ? null : RandomBytes(rng, 32);
            NatHint hint = (NatHint)rng.Next(3);
            IPAddress[] addresses = RandomUsableAddresses(rng, 1 + rng.Next(4));
            int port = rng.Next(1, 65536);
            uint ttl = i % 7 == 0 ? 0u : 120u; // goodbye included

            byte[] mine = ComposeAnnouncementMine(peerId, key, hint, addresses, port, ttl);
            byte[] oracle = ComposeAnnouncementWriter(peerId, key, hint, addresses, port, ttl);
            Assert.Equal(oracle, mine);

            Assert.True(DnsWireCodec.TryReadMessage(mine, out DnsMessage? parsed), $"iteration {i}");
            DnsHeader header = parsed!.Header;
            Assert.Equal((ushort)0, header.Id);
            Assert.Equal((ushort)0x8400, header.Flags);
            Assert.Equal(0, header.Questions);
            Assert.Equal(3 + Math.Min(addresses.Length, 4), header.Answers + header.Authorities + header.Additionals);
            Assert.Equal(header.Answers, parsed.Records.Length);

            DnsResourceRecord ptr = parsed.Records[0];
            Assert.Equal(Service, ptr.Name);
            Assert.Equal(DnsWireCodec.TypePtr, ptr.Type);
            Assert.Equal(DnsWireCodec.ClassIn, ptr.Class);
            Assert.Equal(ttl, ptr.Ttl);
            Assert.True(DnsWireCodec.TryReadPtrTarget(mine, ptr, out string? instanceName));
            Assert.Equal(LanDiscovery.IdText(peerId) + "." + Service, instanceName);

            DnsResourceRecord srv = parsed.Records[1];
            Assert.Equal(LanDiscovery.IdText(peerId) + "." + Service, srv.Name);
            Assert.Equal(DnsWireCodec.TypeSrv, srv.Type);
            Assert.Equal(DnsWireCodec.ClassIn | DnsWireCodec.CacheFlushBit, srv.Class);
            Assert.True(DnsWireCodec.TryReadSrv(mine, srv, out DnsSrv record));
            Assert.Equal((ushort)0, record.Priority);
            Assert.Equal((ushort)0, record.Weight);
            Assert.Equal((ushort)port, record.Port);
            Assert.Equal(LanDiscovery.HostOf(peerId), record.Target);

            DnsResourceRecord txt = parsed.Records[2];
            Assert.Equal(DnsWireCodec.TypeTxt, txt.Type);
            Assert.True(DnsWireCodec.TryReadTxtEntries(txt.Rdata, out (string Key, string Value)[]? entries));
            Assert.Equal(PeerTxtEntries(peerId, key, hint), entries!);

            IPAddress[] selected = LanDiscovery.AnnouncementAddresses(addresses).Take(4).ToArray();
            for (int a = 0; a < header.Answers - 3; a++)
            {
                DnsResourceRecord address = parsed.Records[3 + a];
                Assert.Equal(LanDiscovery.HostOf(peerId), address.Name);
                Assert.Equal(DnsWireCodec.ClassIn | DnsWireCodec.CacheFlushBit, address.Class);
                Assert.Equal(selected[a].GetAddressBytes(), address.Rdata);
                Assert.Equal(address.Rdata.Length == 16 ? DnsWireCodec.TypeAaaa : DnsWireCodec.TypeA, address.Type);
            }
        }
    }

    // ---- 5. peer payloads through the production TryParsePeers ----

    [Fact]
    public void Announcement_ProductionTryParsePeers_AgreesOnEveryField()
    {
        var rng = new Random(0x0D05_0003);
        for (int i = 0; i < 250; i++)
        {
            ulong peerId = (ulong)rng.NextInt64();
            byte[]? key = i % 3 == 0 ? null : RandomBytes(rng, 32);
            NatHint hint = (NatHint)rng.Next(3);
            IPAddress[] addresses = RandomUsableAddresses(rng, 1 + rng.Next(4));
            int port = rng.Next(1, 65536);

            byte[] mine = ComposeAnnouncementMine(peerId, key, hint, addresses, port, 120);
            Assert.True(DnsCodec.TryParsePeers(mine, out IReadOnlyList<LanPeer> peers), $"iteration {i}");
            LanPeer peer = Assert.Single(peers);
            Assert.Equal(peerId, peer.PeerId);
            Assert.Equal(hint, peer.NatHint);
            Assert.True(key is null ? peer.StaticKey is null : key.AsSpan().SequenceEqual(peer.StaticKey));
            IPAddress[] selected = LanDiscovery.AnnouncementAddresses(addresses).Take(4).ToArray();
            Assert.Equal(
                selected.Select(a => new IPEndPoint(a, port)).ToArray(),
                peer.Endpoints.ToArray());
        }

        // two peers in one packet parse to two peers, in PTR order
        ulong first = 0x1111111111111111, second = 0x2222222222222222;
        byte[] multi = ComposeTwoPeerAnnouncement(first, second, out IPEndPoint[] expectedFirst, out IPEndPoint[] expectedSecond);
        Assert.True(DnsWireCodec.TryReadMessage(multi, out _));
        Assert.True(DnsCodec.TryParsePeers(multi, out IReadOnlyList<LanPeer> both));
        Assert.Equal([first, second], both.Select(p => p.PeerId).ToArray());
        Assert.Equal(expectedFirst, both[0].Endpoints.ToArray());
        Assert.Equal(expectedSecond, both[1].Endpoints.ToArray());

        // pinned quirks of TryParsePeers (application rules, not wire rules): a
        // non-hex instance name or an SRV port of zero leaves no buildable peer,
        // so the packet yields false even though the wire format is canonical
        byte[] badInstance = ComposeAnnouncementMine(0, null, NatHint.Unknown, [IPAddress.Parse("192.0.2.1")], 5000, 120, instance: "not-hex-at-all");
        Assert.True(DnsWireCodec.TryReadMessage(badInstance, out _));
        Assert.False(DnsCodec.TryParsePeers(badInstance, out _));

        byte[] zeroPort = ComposeAnnouncementMine(0xAAAAAAAAAAAAAAAA, null, NatHint.Unknown, [IPAddress.Parse("192.0.2.1")], 0, 120);
        Assert.True(DnsWireCodec.TryReadMessage(zeroPort, out DnsMessage? zeroParsed));
        Assert.True(DnsWireCodec.TryReadSrv(zeroPort, zeroParsed!.Records[1], out DnsSrv zeroSrv));
        Assert.Equal((ushort)0, zeroSrv.Port);
        Assert.False(DnsCodec.TryParsePeers(zeroPort, out _));
    }

    // ---- 6. TXT framing ----

    [Fact]
    public void Txt_FramingGoldens_EntriesAndChunkedText()
    {
        // mDNS TXT record golden: owner a.b, TXT, cache-flush class, ttl 120,
        // one DNS string "k=v"
        byte[] golden = Convert.FromHexString("01610162" + "00" + "0010" + "8001" + "00000078" + "0004" + "036B3D76");
        byte[] buffer = new byte[64];
        int n = DnsWireCodec.WriteTxtRecord(buffer, "b", "a", [("k", "v")], 120);
        Assert.Equal(golden.Length, n);
        Assert.Equal(golden, buffer[..n]);

        byte[] wrapped = [.. Convert.FromHexString("000084000000000100000000"), .. golden];
        Assert.True(DnsWireCodec.TryReadMessage(wrapped, out DnsMessage? parsed));
        Assert.True(DnsWireCodec.TryReadTxtEntries(parsed!.Records[0].Rdata, out (string Key, string Value)[]? entries));
        Assert.Single(entries!);
        Assert.Equal("k", entries![0].Key);
        Assert.Equal("v", entries[0].Value);

        // strings without '=' (or with it at index 0) are skipped, mirroring ParseTxt
        Assert.True(DnsWireCodec.TryReadTxtEntries([0x03, (byte)'a', (byte)'=', (byte)'1', 0x02, (byte)'x', (byte)'y', 0x02, (byte)'=', (byte)'z'], out entries));
        (string Key, string Value) skipped = Assert.Single(entries!);
        Assert.Equal("a", skipped.Key);
        Assert.Equal("1", skipped.Value);
        Assert.True(DnsWireCodec.TryReadTxtEntries([], out entries));
        Assert.Empty(entries!);

        // writer guards
        Assert.Throws<ArgumentException>(() => DnsWireCodec.WriteTxtStrings(buffer, [new string('a', 256)]));
        Assert.Throws<ArgumentException>(() => DnsWireCodec.WriteTxtStrings(buffer, ["näch"]));

        // pkarr text chunking: <=255-byte strings, one length byte each
        var rng = new Random(0x0D05_0004);
        foreach (int length in new[] { 0, 1, 254, 255, 256, 509, 510, 511, 600 })
        {
            byte[] utf8 = new byte[length];
            for (int i = 0; i < length; i++)
            {
                utf8[i] = (byte)('a' + (i % 26));
            }

            byte[] rdata = new byte[length + length / 255 + 2];
            int written = DnsWireCodec.WriteTxtText(rdata, utf8);
            int chunks = (length + 254) / 255;
            Assert.Equal(length + chunks, written);
            Assert.True(DnsWireCodec.TryReadTxtText(rdata.AsSpan(0, written), out string? text));
            Assert.Equal(utf8, Encoding.UTF8.GetBytes(text!));
        }

        Assert.True(DnsWireCodec.TryReadTxtText([], out string? emptyText));
        Assert.Equal("", emptyText);

        // multi-byte UTF-8 text round-trips; the same bytes are not ASCII entries
        byte[] accentedRdata = [0x08, 0x68, 0xC3, 0xA9, 0x20, 0xE2, 0x9C, 0x93, 0x00]; // "hé ✓" + NUL
        Assert.False(DnsWireCodec.TryReadTxtEntries(accentedRdata, out _));
        Assert.True(DnsWireCodec.TryReadTxtText(accentedRdata, out string? decoded));
        Assert.Equal("hé ✓\0", decoded);

        // a string length byte that overruns the rdata is refused by both flavors
        Assert.False(DnsWireCodec.TryReadTxtEntries([0x03, 0x61, 0x3D], out _));
        Assert.False(DnsWireCodec.TryReadTxtText([0x05, 0x68, 0x65, 0x6C, 0x6C], out _));
    }

    // ---- 7. pkarr payload: byte-exact with IrohDiscovery both ways ----

    [Fact]
    public void Pkarr_TxtPayload_ByteExactWithCreatePayload_AndParsePayloadBothWays()
    {
        var identity = new RelayIdentity(new byte[32]);
        byte[] key = identity.PublicKey;
        string owner = "_iroh." + IrohEncoding.Encode32(key, zbase: true);
        IPEndPoint first = new(IPAddress.Parse("198.51.100.7"), 41234);
        IPEndPoint second = new(IPAddress.Parse("2001:db8::1"), 443);
        var address = new IrohAddress(Convert.ToHexString(key).ToLowerInvariant(), [first, second], [new Uri("https://relay.example.com/iroh")])
        {
            UserData = "héllo ✓",
        };

        byte[] payload = IrohDiscovery.CreatePayload(address, identity, 1_724_000_000_000_000);
        byte[] dns = payload[72..];

        string[] values =
        [
            "relay=https://relay.example.com/iroh",
            "addr=" + first,
            "addr=" + second,
            "user-data=héllo ✓",
        ];
        byte[] mine = ComposePkarrDns(key, values);
        Assert.Equal(dns, mine);

        // the pkarr compression form: first owner full, every later one C0 0C
        // (first record: 12 header + owner.Length + 2 wire + 10 tail + 1 length byte + text)
        int secondStart = DnsWireCodec.HeaderSize + (owner.Length + 2) + 10 + 1 + values[0].Length;
        Assert.Equal(0xC0, mine[secondStart]);
        Assert.Equal(12, mine[secondStart + 1]);

        Assert.True(DnsWireCodec.TryReadMessage(dns, out DnsMessage? parsed));
        Assert.Equal((ushort)0x8000, parsed!.Header.Flags);
        Assert.Equal(4, parsed.Records.Length);
        foreach (DnsResourceRecord record in parsed.Records)
        {
            Assert.Equal(owner, record.Name); // pointer decompression agrees with ReadTxt
            Assert.Equal(DnsWireCodec.TypeTxt, record.Type);
            Assert.Equal(DnsWireCodec.ClassIn, record.Class);
            Assert.Equal(60u, record.Ttl);
            Assert.True(DnsWireCodec.TryReadTxtText(record.Rdata, out string? text));
            Assert.Contains(text!, values);
        }

        // my bytes, re-signed, are accepted by the production parser
        byte[] resigned = SignPkarr(identity, 1_724_000_000_000_000, mine);
        IrohAddress parsedBack = IrohDiscovery.ParsePayload(key, resigned, out ulong timestamp);
        Assert.Equal(1_724_000_000_000_000UL, timestamp);
        Assert.Equal(address.DirectAddresses, parsedBack.DirectAddresses);
        Assert.Equal(address.RelayUrls, parsedBack.RelayUrls);
        Assert.Equal("héllo ✓", parsedBack.UserData);
        Assert.Empty(parsedBack.DerpRelayUrls);

        // audit C-06 pinned: IrohDiscovery THROWS on malformed UTF-8 in TXT text;
        // the canonical codec returns false instead, never throwing
        byte[] badRdata = [0x02, 0xC3, 0x28];
        Assert.False(DnsWireCodec.TryReadTxtText(badRdata, out _));
        byte[] badDns = ComposePkarrDns(key, ["user-data=ok"], overrideRdata: badRdata);
        InvalidDataException thrown = Assert.Throws<InvalidDataException>(() => IrohDiscovery.ParsePayload(key, SignPkarr(identity, 42, badDns), out _));
        Assert.Equal("malformed UTF-8 in DNS record", thrown.Message);
    }

    private static byte[] SignPkarr(RelayIdentity identity, ulong timestamp, byte[] dns)
    {
        byte[] payload = new byte[72 + dns.Length];
        identity.SignBody(IrohSignable(timestamp, dns)).CopyTo(payload, 0);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(64), timestamp);
        dns.CopyTo(payload, 72);
        return payload;
    }

    private static byte[] ComposePkarrDns(byte[] key, string[] values, byte[]? overrideRdata = null)
    {
        string owner = "_iroh." + IrohEncoding.Encode32(key, zbase: true);
        byte[] ownerBytes = new byte[300];
        int ownerLength = DnsWireCodec.WriteName(ownerBytes, owner);
        byte[] pointer = new byte[2];
        DnsWireCodec.WriteCompressionPointer(pointer, DnsWireCodec.HeaderSize);
        byte[] rdata = new byte[820];
        byte[] text = new byte[800];
        byte[] buffer = new byte[1100];
        Span<byte> cursor = buffer;
        cursor = cursor[DnsWireCodec.WriteHeader(cursor, new DnsHeader(0, 0x8000, 0, values.Length, 0, 0))..];
        for (int i = 0; i < values.Length; i++)
        {
            int rdataLength;
            if (overrideRdata is { } forced && i == values.Length - 1)
            {
                rdataLength = forced.Length;
                forced.CopyTo(rdata, 0);
            }
            else
            {
                int byteCount = Encoding.UTF8.GetBytes(values[i], text);
                rdataLength = DnsWireCodec.WriteTxtText(rdata, text.AsSpan(0, byteCount));
            }

            ReadOnlySpan<byte> encodedOwner = i == 0 ? ownerBytes.AsSpan(0, ownerLength) : pointer;
            cursor = cursor[DnsWireCodec.WriteResourceRecord(cursor, encodedOwner, DnsWireCodec.TypeTxt, DnsWireCodec.ClassIn, 60u, rdata.AsSpan(0, rdataLength))..];
        }

        return buffer[..(buffer.Length - cursor.Length)].ToArray();
    }

    // ---- 8. explicit non-canonical rejections (rule numbers per DnsWireCodec) ----

    [Fact]
    public void Rejections_NonCanonicalForms_AndPinnedParserDivergences()
    {
        byte[] announcement = ComposeAnnouncementMine(0x1122334455667788, null, NatHint.Cone, [IPAddress.Parse("192.168.1.42")], 7777, 120);
        Assert.True(DnsWireCodec.TryReadMessage(announcement, out _));

        // rule 1: zero transaction id, at least 12 bytes
        Assert.False(DnsWireCodec.TryReadMessage([], out _));
        Assert.False(DnsWireCodec.TryReadMessage(announcement[..11], out _));
        byte[] withId = (byte[])announcement.Clone();
        withId[0] = 1;
        Assert.False(DnsWireCodec.TryReadMessage(withId, out _));
        Assert.False(DnsCodec.AsksForOurService(withId)); // DnsCodec agrees on the zero-id rule

        // rule 2: at most 256 records
        byte[] manyRecords = new byte[600];
        Span<byte> cursor = manyRecords;
        cursor = cursor[DnsWireCodec.WriteHeader(cursor, new DnsHeader(0, 0, 0, 300, 0, 0))..];
        for (int i = 0; i < 2; i++)
        {
            cursor = cursor[DnsWireCodec.WriteResourceRecord(cursor, "a.b", DnsWireCodec.TypeTxt, DnsWireCodec.ClassIn, 0u, [])..];
        }

        Assert.False(DnsWireCodec.TryReadMessage(manyRecords.AsSpan(0, manyRecords.Length - cursor.Length), out _));

        // rule 3: counts larger than the records present, and truncated rdata
        byte[] missing = new byte[64];
        cursor = missing;
        cursor = cursor[DnsWireCodec.WriteHeader(cursor, new DnsHeader(0, 0, 0, 2, 0, 0))..];
        cursor = cursor[DnsWireCodec.WriteResourceRecord(cursor, "a.b", DnsWireCodec.TypeA, DnsWireCodec.ClassIn, 0u, [1, 2, 3, 4])..];
        int written = missing.Length - cursor.Length;
        Assert.False(DnsWireCodec.TryReadMessage(missing.AsSpan(0, written), out _));
        byte[] truncatedRdata = (byte[])missing.Clone();
        truncatedRdata[26] = 5; // rdlength low byte (12 + 5-byte owner + 8) claims 5 rdata bytes, 4 present
        Assert.False(DnsWireCodec.TryReadMessage(truncatedRdata.AsSpan(0, written), out _));

        byte[] questionOnly = ComposeQuery(Service, DnsWireCodec.TypePtr, DnsWireCodec.ClassIn, withJunkQuestion: false);
        Assert.False(DnsWireCodec.TryReadMessage(questionOnly[..^1], out _)); // chopped qclass

        // rule 4: trailing bytes are refused here; DnsCodec.TryParsePeers is
        // lenient about them (pinned divergence, like STUN's padding rule)
        byte[] trailing = [.. announcement, 0xFF];
        Assert.False(DnsWireCodec.TryReadMessage(trailing, out _));
        Assert.True(DnsCodec.TryParsePeers(trailing, out IReadOnlyList<LanPeer> stillParsed));
        Assert.Single(stillParsed);

        // rule 8 divergence pin: DnsCodec accepts label bytes >= 0x80 (mapping
        // them to '?'); the canonical codec rejects the whole message
        byte[] nonAsciiExtra = [0x03, 0x61, 0xC3, 0xA0, 0x00, 0x00, 0x10, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        byte[] withHighByteLabel = new byte[announcement.Length + nonAsciiExtra.Length];
        announcement.CopyTo(withHighByteLabel, 0);
        nonAsciiExtra.CopyTo(withHighByteLabel, announcement.Length);
        withHighByteLabel[7]++; // answers count low byte: one more record
        Assert.False(DnsWireCodec.TryReadMessage(withHighByteLabel, out _));
        Assert.True(DnsCodec.TryParsePeers(withHighByteLabel, out _));

        // rule 9: PTR rdata must be exactly one name (DnsCodec decompresses past
        // the declared rdlength without checking the name ends there); SRV rdata
        // needs at least 8 bytes
        byte[] nameBytes = new byte[80];
        int nameLength = DnsWireCodec.WriteName(nameBytes, "0123456789abcdef." + Service);
        byte[] stretchedRdata = [.. nameBytes.AsSpan(0, nameLength).ToArray(), 0x00]; // one stray byte after the name
        byte[] r9 = new byte[200];
        cursor = r9;
        cursor = cursor[DnsWireCodec.WriteHeader(cursor, new DnsHeader(0, 0x8400, 0, 2, 0, 0))..];
        cursor = cursor[DnsWireCodec.WriteResourceRecord(cursor, Service, DnsWireCodec.TypePtr, DnsWireCodec.ClassIn, 120u, stretchedRdata)..];
        cursor = cursor[DnsWireCodec.WriteResourceRecord(cursor, "h.x", DnsWireCodec.TypeSrv, DnsWireCodec.ClassIn, 120u, new byte[7])..];
        byte[] r9Message = r9.AsSpan(0, r9.Length - cursor.Length).ToArray();
        Assert.True(DnsWireCodec.TryReadMessage(r9Message, out DnsMessage? r9Parsed));
        Assert.False(DnsWireCodec.TryReadPtrTarget(r9Message, r9Parsed!.Records[0], out _));
        Assert.False(DnsWireCodec.TryReadSrv(r9Message, r9Parsed.Records[1], out _));

        // the exact shapes DnsCodec.Writer emits decode fine
        Assert.True(DnsWireCodec.TryReadMessage(announcement, out DnsMessage? good));
        Assert.True(DnsWireCodec.TryReadPtrTarget(announcement, good!.Records[0], out string? goodInstance));
        Assert.Equal("1122334455667788." + Service, goodInstance);
        Assert.True(DnsWireCodec.TryReadSrv(announcement, good.Records[1], out DnsSrv goodSrv));
        Assert.Equal((ushort)7777, goodSrv.Port);

        // writers reject programmer errors: oversized TXT text/rdata for the span
        byte[] buffer = new byte[80];
        Assert.Throws<ArgumentException>(() => DnsWireCodec.WriteTxtText(buffer, new byte[100]));
        byte[] huge = new byte[70_000];
        Assert.Throws<ArgumentException>(() => DnsWireCodec.WriteResourceRecord(buffer, "a.b", DnsWireCodec.TypeTxt, DnsWireCodec.ClassIn, 0u, huge));
    }

    // ---- 9. seeded valid messages round-trip through the generic codec ----

    [Fact]
    public void ValidMessages_RoundTrip_EveryQuestionAndRecord()
    {
        var rng = new Random(0x0D05_0005);
        byte[] buffer = new byte[1024];
        for (int i = 0; i < 300; i++)
        {
            GeneratedDns generated = GenerateMessage(rng, buffer, out int length);
            Assert.True(DnsWireCodec.TryReadMessage(buffer.AsSpan(0, length), out DnsMessage? parsed), $"iteration {i}");
            Assert.Equal(generated.Questions, parsed!.Questions);
            Assert.Equal(generated.Records.Length, parsed.Records.Length);
            for (int r = 0; r < generated.Records.Length; r++)
            {
                Assert.Equal(generated.Records[r].Name, parsed.Records[r].Name);
                Assert.Equal(generated.Records[r].Type, parsed.Records[r].Type);
                Assert.Equal(generated.Records[r].Class, parsed.Records[r].Class);
                Assert.Equal(generated.Records[r].Ttl, parsed.Records[r].Ttl);
                Assert.Equal(generated.Records[r].Rdata, parsed.Records[r].Rdata);
                if (generated.Records[r].Type == DnsWireCodec.TypeTxt)
                {
                    Assert.True(DnsWireCodec.TryReadTxtEntries(parsed.Records[r].Rdata, out _));
                }
            }
        }
    }

    // ---- 10. totality fuzz ----

    [Fact]
    public void TotalityFuzz_NeverThrows_NeverOutOfRange()
    {
        var rng = new Random(0x0D05_0006);
        byte[] scratch = new byte[96];
        byte[] valid = new byte[1024];
        for (int i = 0; i < 200_000; i++)
        {
            switch (rng.Next(4))
            {
                case 0:
                {
                    int length = rng.Next(0, 97);
                    rng.NextBytes(scratch.AsSpan(0, length));
                    ExerciseDns(scratch.AsSpan(0, length));
                    break;
                }
                case 1:
                {
                    GenerateMessage(rng, valid, out int length);
                    ExerciseDns(valid.AsSpan(0, length), requireMessage: true);
                    break;
                }
                case 2:
                {
                    GenerateMessage(rng, valid, out int length);
                    valid[rng.Next(length)] ^= (byte)(1 << rng.Next(8));
                    ExerciseDns(valid.AsSpan(0, length));
                    break;
                }
                default:
                {
                    GenerateMessage(rng, valid, out int length);
                    ExerciseDns(valid.AsSpan(0, rng.Next(length + 1)));
                    break;
                }
            }
        }
    }

    private static void ExerciseDns(ReadOnlySpan<byte> input, bool requireMessage = false)
    {
        bool ok = DnsWireCodec.TryReadMessage(input, out DnsMessage? parsed);
        if (requireMessage) Assert.True(ok);
        if (ok)
        {
            DnsHeader header = parsed!.Header;
            Assert.Equal((ushort)0, header.Id);
            Assert.Equal(header.Questions, parsed.Questions.Length);
            Assert.Equal(header.Answers + header.Authorities + header.Additionals, parsed.Records.Length);
            Assert.InRange(header.Answers + header.Authorities + header.Additionals, 0, DnsWireCodec.MaxRecords);
            foreach (DnsQuestion question in parsed.Questions)
            {
                Assert.NotNull(question.Name);
                Assert.InRange(question.Name.Length, 0, 254);
            }

            foreach (DnsResourceRecord record in parsed.Records)
            {
                Assert.NotNull(record.Name);
                Assert.InRange(record.Name.Length, 0, 254);
                Assert.InRange(record.RdataOffset, DnsWireCodec.HeaderSize, input.Length);
                Assert.InRange(record.RdataOffset + record.Rdata.Length, 0, input.Length);
                if (DnsWireCodec.TryReadPtrTarget(input, record, out string? target)) Assert.NotNull(target);
                if (DnsWireCodec.TryReadSrv(input, record, out DnsSrv srv)) Assert.NotNull(srv.Target);
            }
        }

        _ = DnsWireCodec.AsksForService(input, Service);
        _ = DnsCodec.AsksForOurService(input); // the production parser must also survive
        int cursor = input.Length / 3;
        if (DnsWireCodec.TryReadName(input, ref cursor, out string? name))
        {
            Assert.InRange(name!.Length, 0, 254);
            Assert.InRange(cursor, 0, input.Length);
        }

        if (DnsWireCodec.TryReadTxtEntries(input, out (string Key, string Value)[]? entries))
        {
            foreach ((string key, string value) in entries!)
            {
                Assert.InRange(key.Length + value.Length, 0, 254);
            }
        }

        if (DnsWireCodec.TryReadTxtText(input, out string? text))
        {
            Assert.True(Encoding.UTF8.GetByteCount(text!) <= input.Length);
        }
    }

    // ---- shared fixtures ----

    private static GeneratedDns GenerateMessage(Random rng, Span<byte> buffer, out int length)
    {
        var questions = new List<DnsQuestion>();
        var records = new List<DnsRecordSpec>();
        int questionCount = rng.Next(0, 3);
        for (int i = 0; i < questionCount; i++)
        {
            questions.Add(new DnsQuestion(
                RandomName(rng),
                (ushort)(rng.Next(6) switch
                {
                    0 => DnsWireCodec.TypePtr,
                    1 => DnsWireCodec.TypeA,
                    2 => DnsWireCodec.TypeTxt,
                    3 => DnsWireCodec.TypeSrv,
                    _ => rng.Next(0, 0x10000),
                }),
                (ushort)(rng.Next(5) switch
                {
                    0 => DnsWireCodec.ClassIn,
                    1 => DnsWireCodec.ClassAny,
                    2 => DnsWireCodec.ClassIn | DnsWireCodec.CacheFlushBit,
                    _ => rng.Next(0, 0x10000),
                })));
        }

        int recordCount = rng.Next(0, 6);
        byte[] scratch = new byte[80];
        for (int i = 0; i < recordCount; i++)
        {
            string name = rng.Next(5) == 0 ? Service : RandomName(rng);
            uint ttl = rng.Next(4) == 0 ? 0u : (uint)rng.Next(int.MaxValue);
            ushort @class = (ushort)(rng.Next(4) switch
            {
                0 => DnsWireCodec.ClassIn,
                1 => DnsWireCodec.ClassIn | DnsWireCodec.CacheFlushBit,
                _ => rng.Next(0, 0x10000),
            });

            DnsRecordSpec spec;
            switch (rng.Next(8))
            {
                case 0:
                {
                    spec = new DnsRecordSpec(name, DnsWireCodec.TypeA, @class, ttl, RandomBytes(rng, 4));
                    break;
                }

                case 1:
                {
                    spec = new DnsRecordSpec(name, DnsWireCodec.TypeAaaa, @class, ttl, RandomBytes(rng, 16));
                    break;
                }

                case 2:
                {
                    int n = DnsWireCodec.WriteName(scratch, RandomName(rng));
                    spec = new DnsRecordSpec(name, DnsWireCodec.TypePtr, @class, ttl, scratch[..n].ToArray());
                    break;
                }

                case 3:
                {
                    int n = DnsWireCodec.WriteSrvRdata(scratch, 0, 0, (ushort)rng.Next(65536), RandomName(rng));
                    spec = new DnsRecordSpec(name, DnsWireCodec.TypeSrv, @class, ttl, scratch[..n].ToArray());
                    break;
                }

                case 4:
                {
                    int strings = rng.Next(0, 4);
                    string[] texts = new string[strings];
                    for (int s = 0; s < strings; s++)
                    {
                        texts[s] = rng.Next(3) == 0 ? "junk" : "k" + s + "=v" + rng.Next(100);
                    }

                    int n = DnsWireCodec.WriteTxtStrings(scratch, texts);
                    spec = new DnsRecordSpec(name, DnsWireCodec.TypeTxt, @class, ttl, scratch[..n].ToArray());
                    break;
                }

                default:
                {
                    spec = new DnsRecordSpec(name, (ushort)rng.Next(0, 0x10000), @class, ttl, RandomBytes(rng, rng.Next(0, 25)));
                    break;
                }
            }

            records.Add(spec);
        }

        Span<byte> cursor = buffer;
        cursor = cursor[DnsWireCodec.WriteHeader(cursor, new DnsHeader(0, (ushort)(rng.Next(2) == 0 ? 0 : 0x8400), questions.Count, records.Count, 0, 0))..];
        foreach (DnsQuestion question in questions)
        {
            cursor = cursor[DnsWireCodec.WriteQuestion(cursor, question)..];
        }

        foreach (DnsRecordSpec spec in records)
        {
            cursor = cursor[DnsWireCodec.WriteResourceRecord(cursor, spec.Name, spec.Type, spec.Class, spec.Ttl, spec.Rdata)..];
        }

        length = buffer.Length - cursor.Length;
        return new GeneratedDns(questions.ToArray(), records.ToArray());
    }

    private static (string Key, string Value)[] PeerTxtEntries(ulong peerId, byte[]? key, NatHint hint)
    {
        var entries = new List<(string, string)>
        {
            ("id", LanDiscovery.IdText(peerId)),
            ("hint", ((int)hint).ToString()),
        };
        if (key is { } bytes)
        {
            entries.Add(("key", Convert.ToHexString(bytes).ToLowerInvariant()));
        }

        return entries.ToArray();
    }

    private static byte[] ComposeAnnouncementMine(ulong peerId, byte[]? key, NatHint hint, IPAddress[] addresses, int port, uint ttl, string? instance = null)
    {
        instance ??= LanDiscovery.IdText(peerId);
        string host = instance + ".pinhole.local";
        IReadOnlyList<IPAddress> selected = LanDiscovery.AnnouncementAddresses(addresses);
        byte[] buffer = new byte[1500];
        Span<byte> cursor = buffer;
        cursor = cursor[DnsWireCodec.WriteHeader(cursor, new DnsHeader(0, 0x8400, 0, 3 + Math.Min(selected.Count, 4), 0, 0))..];
        cursor = cursor[DnsWireCodec.WritePtrRecord(cursor, Service, instance, ttl)..];
        cursor = cursor[DnsWireCodec.WriteSrvRecord(cursor, Service, instance, host, (ushort)port, ttl)..];
        cursor = cursor[DnsWireCodec.WriteTxtRecord(cursor, Service, instance, PeerTxtEntries(peerId, key, hint), ttl)..];
        foreach (IPAddress address in selected.Take(4))
        {
            cursor = cursor[DnsWireCodec.WriteAddressRecord(cursor, host, address, ttl)..];
        }

        return buffer[..(buffer.Length - cursor.Length)].ToArray();
    }

    private static byte[] ComposeAnnouncementWriter(ulong peerId, byte[]? key, NatHint hint, IPAddress[] addresses, int port, uint ttl)
    {
        string instance = LanDiscovery.IdText(peerId);
        string host = instance + ".pinhole.local";
        IReadOnlyList<IPAddress> selected = LanDiscovery.AnnouncementAddresses(addresses);
        var w = new DnsCodec.Writer();
        w.Header(flags: 0x8400, questions: 0, answers: 3 + Math.Min(selected.Count, 4), 0, 0);
        w.WritePtr(Service, instance, ttl);
        w.WriteSrv(Service, instance, host, (ushort)port, ttl);
        w.WriteTxt(Service, instance, PeerTxtEntries(peerId, key, hint), ttl);
        foreach (IPAddress address in selected.Take(4))
        {
            w.WriteAddress(host, address, ttl);
        }

        return w.ToArray();
    }

    private static byte[] ComposeTwoPeerAnnouncement(ulong first, ulong second, out IPEndPoint[] firstEndpoints, out IPEndPoint[] secondEndpoints)
    {
        IPAddress firstAddress = IPAddress.Parse("192.0.2.10");
        IPAddress secondAddress = IPAddress.Parse("192.0.2.99");
        firstEndpoints = [new IPEndPoint(firstAddress, 4000)];
        secondEndpoints = [new IPEndPoint(secondAddress, 4001)];
        byte[] buffer = new byte[1500];
        Span<byte> cursor = buffer;
        cursor = cursor[DnsWireCodec.WriteHeader(cursor, new DnsHeader(0, 0x8400, 0, 8, 0, 0))..];
        cursor = cursor[DnsWireCodec.WritePtrRecord(cursor, Service, LanDiscovery.IdText(first), 120)..];
        cursor = cursor[DnsWireCodec.WriteSrvRecord(cursor, Service, LanDiscovery.IdText(first), LanDiscovery.HostOf(first), 4000, 120)..];
        cursor = cursor[DnsWireCodec.WriteTxtRecord(cursor, Service, LanDiscovery.IdText(first), PeerTxtEntries(first, null, NatHint.Unknown), 120)..];
        cursor = cursor[DnsWireCodec.WriteAddressRecord(cursor, LanDiscovery.HostOf(first), firstAddress, 120)..];
        cursor = cursor[DnsWireCodec.WritePtrRecord(cursor, Service, LanDiscovery.IdText(second), 120)..];
        cursor = cursor[DnsWireCodec.WriteSrvRecord(cursor, Service, LanDiscovery.IdText(second), LanDiscovery.HostOf(second), 4001, 120)..];
        cursor = cursor[DnsWireCodec.WriteTxtRecord(cursor, Service, LanDiscovery.IdText(second), PeerTxtEntries(second, null, NatHint.Cone), 120)..];
        cursor = cursor[DnsWireCodec.WriteAddressRecord(cursor, LanDiscovery.HostOf(second), secondAddress, 120)..];
        return buffer[..(buffer.Length - cursor.Length)].ToArray();
    }

    private static string RandomName(Random rng)
    {
        const string alphabet = "abz019-_";
        int labels = rng.Next(1, 4);
        var parts = new string[labels];
        for (int i = 0; i < labels; i++)
        {
            int labelLength = rng.Next(1, 11);
            char[] chars = new char[labelLength];
            for (int c = 0; c < labelLength; c++)
            {
                chars[c] = alphabet[rng.Next(alphabet.Length)];
            }

            parts[i] = new string(chars);
        }

        return string.Join('.', parts);
    }

    private static byte[] RandomBytes(Random rng, int length)
    {
        byte[] bytes = new byte[length];
        rng.NextBytes(bytes);
        return bytes;
    }

    private static IPAddress[] RandomUsableAddresses(Random rng, int count)
    {
        var addresses = new List<IPAddress>();
        for (int i = 0; i < count; i++)
        {
            if (rng.Next(2) == 0)
            {
                byte[] v4 = new byte[4];
                v4[0] = (byte)rng.Next(1, 224);
                rng.NextBytes(v4.AsSpan(1));
                addresses.Add(new IPAddress(v4));
            }
            else
            {
                byte[] v6 = new byte[16];
                v6[0] = 0x20;
                rng.NextBytes(v6.AsSpan(1));
                addresses.Add(new IPAddress(v6));
            }
        }

        return [.. addresses.Distinct().Take(4)];
    }
}
