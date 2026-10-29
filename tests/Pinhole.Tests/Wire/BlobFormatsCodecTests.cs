using System.Buffers.Binary;
using System.Net;
using System.Text;
using Pinhole;
using Pinhole.Blobs;
using Pinhole.Wire;
using Xunit;

namespace Pinhole.Tests.Wire;

public sealed class BlobFormatsCodecTests
{
    private const string CommittedTicketGolden =
        "pinholeblob1:AQIBZAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fQEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8kAHBpbmhvbGUxOkFRQUJBQUFBQUFBQUFBQUJCSDhBQUFFQUJRRQ";

    private const int TicketSchemePrefix = 13;

    private static byte[] SeqBytes(int start, int count)
    {
        var b = new byte[count];
        for (int i = 0; i < count; i++)
        {
            b[i] = (byte)(start + i);
        }

        return b;
    }

    private static byte[] RandomBytes(Random rng, int count)
    {
        var b = new byte[count];
        rng.NextBytes(b);
        return b;
    }

    private static byte[] Be64(ulong value)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(b, value);
        return b;
    }

    private static byte[] Le64(long value)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(b, value);
        return b;
    }

    private static string RandomText(Random rng, int maxChars)
    {

        string[] fragments = ["a", "Q", ".", "/", "µ", "ж", "日", "\U0001F600", "7"];
        var sb = new StringBuilder();
        int target = rng.Next(maxChars + 1);
        while (sb.Length < target)
        {
            sb.Append(fragments[rng.Next(fragments.Length)]);
        }

        return sb.ToString();
    }

    private static string RandomConnectionString(Random rng) =>
        new ConnectionString((ulong)rng.NextInt64(),
            [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, rng.Next(1, 65536)))],
            (NatHint)rng.Next(3)).ToString();

    private static BlobTicketValue RandomTicket(Random rng, bool allowOversizedName = false)
    {
        return new BlobTicketValue(
            rng.Next(2) == 0 ? WireBlobKind.File : WireBlobKind.Directory,
            RandomBytes(rng, BlobTicketCodec.RootLength),
            RandomConnectionString(rng),
            RandomText(rng, allowOversizedName ? 300 : 40),
            rng.Next(2) == 0 ? null : RandomBytes(rng, BlobTicketCodec.PskLength));
    }

    private static ManifestValue RandomManifest(Random rng)
    {
        long[] sizes = [0, 1, 1023, 1024, 0x11223344, 1L << 40, long.MaxValue];
        int count = rng.Next(7);
        var entries = new ManifestEntry[count];
        for (int i = 0; i < count; i++)
        {
            entries[i] = new ManifestEntry(RandomText(rng, 24) + "/" + i, sizes[rng.Next(sizes.Length)],
                RandomBytes(rng, ManifestCodec.RootLength));
        }

        return new ManifestValue(RandomText(rng, 12), entries);
    }

    private static byte[] RandomFrameWire(Random rng)
    {
        ulong stream = (ulong)rng.NextInt64();
        switch (rng.Next(11))
        {
            case 0:
            {
                byte[] frame = new byte[BlobFrameCodec.HelloV1Length];
                frame[0] = BlobFrameCodec.TypeHello;
                BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
                return frame;
            }
            case 1:
            {
                byte[] frame = new byte[BlobFrameCodec.HelloV2Length];
                frame[0] = BlobFrameCodec.TypeHello;
                BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
                RandomBytes(rng, BlobFrameCodec.SessionIdLength).CopyTo(frame.AsSpan(9));
                return frame;
            }
            case 2:
                return BlobWire.Hello(stream, RandomBytes(rng, BlobFrameCodec.SessionIdLength));
            case 3:
                return BlobWire.Welcome(stream, RandomBytes(rng, BlobFrameCodec.SessionIdLength),
                    RandomBytes(rng, BlobFrameCodec.SessionIdLength), RandomBytes(rng, BlobFrameCodec.SealedHeadLength));
            case 4:
                return BlobWire.Bye(stream);
            case 5:
            {
                long totalBytes = rng.Next(4) switch
                {
                    0 => 0,
                    1 => 1023,
                    2 => 1024,
                    _ => rng.NextInt64(0, 1 << 22),
                };
                return BlobWire.Head(stream, totalBytes, BlobFrameCodec.ChunkCount(totalBytes));
            }
            case 6:
                return BlobWire.Request(stream, rng.NextInt64(0, 1 << 20), rng.Next(1, BlobFrameCodec.MaxRequestCount + 1));
            case 7:
                return BlobWire.Hello(stream, RandomBytes(rng, BlobFrameCodec.SessionIdLength), BlobWire.CurrentVersion);
            case 8:
                return BlobWire.Welcome(stream, RandomBytes(rng, BlobFrameCodec.SessionIdLength),
                    RandomBytes(rng, BlobFrameCodec.SessionIdLength), RandomBytes(rng, BlobFrameCodec.SealedHeadLength),
                    BlobWire.CurrentVersion);
            case 9:
                return BlobWire.Proof(stream, rng.NextInt64(0, 1 << 20),
                    RandomBytes(rng, 32 * rng.Next(BlobFrameCodec.MaxProofSiblings + 1)));
            default:
            {
                int dataLen = rng.Next(2) == 0 ? rng.Next(1, 65) : rng.Next(1, BlobFrameCodec.MaxChunkData + 1);
                return BlobWire.Chunk(stream, rng.NextInt64(0, 1 << 20), RandomBytes(rng, 32), RandomBytes(rng, dataLen));
            }
        }
    }

    private static void AssertFramesEqual(BlobFrameView view, BlobWire.Frame frame)
    {
        Assert.Equal(frame.Type, view.Type);
        Assert.Equal(frame.Stream, view.Stream);
        Assert.Equal(frame.Version, view.Version);
        Assert.Equal(frame.TotalBytes, view.TotalBytes);
        Assert.Equal(frame.TotalChunks, view.TotalChunks);
        Assert.Equal(frame.StartChunk, view.StartChunk);
        Assert.Equal(frame.Count, view.Count);
        Assert.Equal(frame.Index, view.Index);
        Assert.Equal(frame.SessionId ?? [], view.SessionId.ToArray());
        Assert.Equal(frame.ProviderNonce ?? [], view.ProviderNonce.ToArray());
        Assert.Equal(frame.SealedHead ?? [], view.SealedHead.ToArray());
        Assert.Equal(frame.ChunkCv ?? [], view.ChunkCv.ToArray());
        Assert.Equal(frame.ChunkData ?? [], view.ChunkData.ToArray());
        Assert.Equal(frame.SiblingCvs ?? [], view.SiblingCvs.ToArray());
    }

    private static void AssertTicketsEqual(BlobTicketValue expected, BlobTicketValue actual)
    {
        Assert.Equal(expected.Kind, actual.Kind);
        Assert.Equal(expected.Name, actual.Name);
        Assert.Equal(expected.ConnectionString, actual.ConnectionString);
        Assert.Equal(expected.Root, actual.Root);
        Assert.Equal(expected.PreSharedKey, actual.PreSharedKey);
    }

    private static ReadOnlySpan<byte> MutatedInput(Random rng, ReadOnlySpan<byte> valid, byte[] mutation)
    {
        switch (rng.Next(4))
        {
            case 0:
            {
                int len = rng.Next(0, Math.Min(valid.Length + 1, 128));
                rng.NextBytes(mutation.AsSpan(0, len));
                if (len > 1 && rng.Next(2) == 0)
                {
                    mutation[0] = 1;
                    mutation[1] &= 0x03;
                }

                return mutation.AsSpan(0, len);
            }
            case 1:
                valid.CopyTo(mutation);
                mutation[rng.Next(valid.Length)] ^= (byte)(1 << rng.Next(8));
                return mutation.AsSpan(0, valid.Length);
            case 2:
                return valid[..rng.Next(valid.Length)];
            default:
                valid.CopyTo(mutation);
                mutation[valid.Length] = (byte)rng.Next(256);
                return mutation.AsSpan(0, valid.Length + 1);
        }
    }

    [Fact]
    public void Ticket_RoundTrip_AndGoldenBytes()
    {

        byte[] golden = Convert.FromHexString(
            "0101" + "026869"
            + "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
            + "0200" + "4142");
        var value = new BlobTicketValue(WireBlobKind.Directory, SeqBytes(0, 32), "AB", "hi", null);

        byte[] buffer = new byte[BlobTicketCodec.MaxBinaryLength];
        int written = BlobTicketCodec.Write(buffer, value);
        Assert.Equal(golden.Length, written);
        Assert.Equal(golden, buffer[..written]);

        Assert.True(BlobTicketCodec.TryRead(golden, out BlobTicketValue read));
        Assert.Equal(WireBlobKind.Directory, read.Kind);
        Assert.Equal("hi", read.Name);
        Assert.Equal("AB", read.ConnectionString);
        Assert.Null(read.PreSharedKey);
        Assert.Equal(SeqBytes(0, 32), read.Root);

        int again = BlobTicketCodec.Write(buffer, read);
        Assert.Equal(golden, buffer[..again]);
    }

    [Fact]
    public void Ticket_TextLayer_MatchesCommittedGoldenAndLegacyParser()
    {

        string csText = new ConnectionString(1,
            [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 5))]).ToString();
        var blob = new BlobTicket
        {
            Kind = BlobKind.File,
            Root = SeqBytes(0, 32),
            ConnectionString = csText,
            Name = "d",
            PreSharedKey = SeqBytes(0x40, 32),
        };
        Assert.Equal(CommittedTicketGolden, blob.ToString());

        var value = new BlobTicketValue(WireBlobKind.File, SeqBytes(0, 32), csText, "d", SeqBytes(0x40, 32));
        Assert.Equal(CommittedTicketGolden, BlobTicketCodec.WriteText(value));

        Assert.True(BlobTicketCodec.TryReadText(CommittedTicketGolden, out BlobTicketValue read));
        AssertTicketsEqual(value, read);

        byte[] legacyPayload = Pinhole.Base64Url.Decode(CommittedTicketGolden[TicketSchemePrefix..]);
        byte[] buffer = new byte[BlobTicketCodec.MaxBinaryLength];
        int written = BlobTicketCodec.Write(buffer, read);
        Assert.Equal(legacyPayload, buffer[..written]);
    }

    [Fact]
    public void Ticket_TextLayer_MirrorsLegacyFramingRules()
    {
        var value = new BlobTicketValue(WireBlobKind.File, SeqBytes(0, 32), RandomConnectionString(new Random(7)), "n", null);
        string text = BlobTicketCodec.WriteText(value);
        string payloadText = text[TicketSchemePrefix..];

        string padded = "pinholeblob1:  " + payloadText + "  ";
        Assert.True(BlobTicketCodec.TryReadText(padded, out BlobTicketValue paddedRead));
        AssertTicketsEqual(value, paddedRead);
        Assert.True(BlobTicket.TryParse(padded, out _));

        Assert.False(BlobTicketCodec.TryReadText(null, out _));
        Assert.False(BlobTicketCodec.TryReadText("", out _));
        Assert.False(BlobTicketCodec.TryReadText(" pinholeblob1:" + payloadText, out _));
        Assert.False(BlobTicketCodec.TryReadText("pinhole1:" + payloadText, out _));
        Assert.False(BlobTicketCodec.TryReadText("pinholeblob1:!!!!", out _));
        Assert.False(BlobTicketCodec.TryReadText("pinholeblob1:" + new string('A', BlobTicketCodec.MaxTextLength), out _));

        byte[] payload = Pinhole.Base64Url.Decode(payloadText);
        payload[0] = 2;
        Assert.False(BlobTicketCodec.TryReadText("pinholeblob1:" + Pinhole.Base64Url.Encode(payload), out _));
    }

    [Fact]
    public void Ticket_NameTruncation_StaysOnCodePointBoundary()
    {
        byte[] buffer = new byte[BlobTicketCodec.MaxBinaryLength];
        var value = new BlobTicketValue(WireBlobKind.File, SeqBytes(0, 32), "AB", "", null);

        value = value with { Name = new string('a', 254) + "µ" };
        int written = BlobTicketCodec.Write(buffer, value);
        Assert.Equal(254, buffer[2]);
        Assert.True(BlobTicketCodec.TryRead(buffer[..written], out BlobTicketValue read));
        Assert.Equal(new string('a', 254), read.Name);

        var blob = new BlobTicket
        {
            Kind = BlobKind.File,
            Root = SeqBytes(0, 32),
            ConnectionString = "AB",
            Name = new string('a', 254) + "µ",
        };
        byte[] legacyPayload = Pinhole.Base64Url.Decode(blob.ToString()[TicketSchemePrefix..]);
        Assert.Equal(255, legacyPayload[2]);
        Assert.False(BlobTicketCodec.TryRead(legacyPayload, out _));

        value = value with { Name = new string('a', 252) + "\U0001F600" };
        written = BlobTicketCodec.Write(buffer, value);
        Assert.Equal(252, buffer[2]);
        Assert.True(BlobTicketCodec.TryRead(buffer[..written], out read));
        Assert.Equal(new string('a', 252), read.Name);

        value = value with { Name = new string('a', 255) };
        written = BlobTicketCodec.Write(buffer, value);
        Assert.Equal(255, buffer[2]);
        var blob255 = new BlobTicket
        {
            Kind = BlobKind.File,
            Root = SeqBytes(0, 32),
            ConnectionString = "AB",
            Name = new string('a', 255),
        };
        Assert.Equal(Pinhole.Base64Url.Decode(blob255.ToString()[TicketSchemePrefix..]), buffer[..written]);
    }

    [Fact]
    public void Ticket_Differential_MatchesLegacyEncoderAndParser()
    {
        var rng = new Random(202_610_25);
        byte[] buffer = new byte[BlobTicketCodec.MaxBinaryLength];
        for (int i = 0; i < 2_000; i++)
        {
            BlobTicketValue value = RandomTicket(rng);
            var blob = new BlobTicket
            {
                Kind = value.Kind == WireBlobKind.File ? BlobKind.File : BlobKind.Directory,
                Root = value.Root,
                ConnectionString = value.ConnectionString,
                Name = value.Name,
                PreSharedKey = value.PreSharedKey,
            };

            string legacyText = blob.ToString();
            Assert.Equal(legacyText, BlobTicketCodec.WriteText(value));

            int written = BlobTicketCodec.Write(buffer, value);
            Assert.Equal(Pinhole.Base64Url.Decode(legacyText[TicketSchemePrefix..]), buffer[..written]);

            Assert.True(BlobTicket.TryParse(legacyText, out BlobTicket? parsed));
            Assert.Equal(value.Name, parsed!.Name);
            Assert.Equal(value.ConnectionString, parsed.ConnectionString);
            Assert.Equal(value.Root, parsed.Root);
            Assert.Equal(value.PreSharedKey, parsed.PreSharedKey);
            Assert.Equal(value.Kind == WireBlobKind.File ? BlobKind.File : BlobKind.Directory, parsed.Kind);

            Assert.True(BlobTicketCodec.TryReadText(legacyText, out BlobTicketValue mine));
            AssertTicketsEqual(value, mine);
        }
    }

    [Fact]
    public void Ticket_RejectsNonCanonicalForms()
    {
        string rootHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        byte[] valid = Convert.FromHexString("010000" + rootHex + "02004142");

        foreach (byte badFlag in new byte[] { 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x83, 0xFD })
        {
            byte[] t = (byte[])valid.Clone();
            t[1] = badFlag;
            Assert.False(BlobTicketCodec.TryRead(t, out BlobTicketValue v), $"flags {badFlag:X2}");
            Assert.Equal(default, v);
        }

        byte[] t2 = (byte[])valid.Clone();
        t2[0] = 2;
        Assert.False(BlobTicketCodec.TryRead(t2, out _));

        Assert.False(BlobTicketCodec.TryRead([.. valid, 0x41], out _));
        Assert.False(BlobTicketCodec.TryRead(valid[..^1], out _));

        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010000" + rootHex + "0000"), out _));
        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010000" + rootHex + "03004142"), out _));
        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010000" + rootHex + "0100"), out _));

        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010001C2" + rootHex + "02004142"), out _));

        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010000" + rootHex + "0100" + "80"), out _));
        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010000" + rootHex + "0200" + "8041"), out _));
    }

    [Fact]
    public void Ticket_LegacyParserLeniency_IsPinnedAsDivergence()
    {

        string cs = new ConnectionString(1,
            [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 5))]).ToString();
        byte[] csBytes = Encoding.ASCII.GetBytes(cs);

        List<byte> unknownFlags = [1, 0, 0];
        unknownFlags.AddRange(SeqBytes(0, 32));
        unknownFlags.AddRange([(byte)csBytes.Length, 0]);
        unknownFlags.AddRange(csBytes);
        unknownFlags[1] = 0x04;
        string text1 = "pinholeblob1:" + Pinhole.Base64Url.Encode([.. unknownFlags]);
        Assert.False(BlobTicketCodec.TryReadText(text1, out _));
        Assert.True(BlobTicket.TryParse(text1, out _));

        List<byte> mojibake = [1, 0, 1, 0xC2];
        mojibake.AddRange(SeqBytes(0, 32));
        mojibake.AddRange([(byte)csBytes.Length, 0]);
        mojibake.AddRange(csBytes);
        string text2 = "pinholeblob1:" + Pinhole.Base64Url.Encode([.. mojibake]);
        Assert.False(BlobTicketCodec.TryReadText(text2, out _));
        Assert.True(BlobTicket.TryParse(text2, out BlobTicket? parsed));
        Assert.Equal("\uFFFD", parsed!.Name);
    }

    [Fact]
    public void Ticket_Write_ThrowsOnProgrammerError()
    {
        byte[] buffer = new byte[BlobTicketCodec.MaxBinaryLength];
        var value = new BlobTicketValue(WireBlobKind.File, SeqBytes(0, 32), "AB", "n", null);

        Assert.Throws<ArgumentException>(() => BlobTicketCodec.Write(buffer, value with { Root = new byte[31] }));
        Assert.Throws<ArgumentException>(() => BlobTicketCodec.Write(buffer, value with { PreSharedKey = new byte[31] }));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobTicketCodec.Write(buffer, value with { Kind = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobTicketCodec.Write(buffer, value with { Kind = (WireBlobKind)99 }));
        Assert.Throws<ArgumentException>(() => BlobTicketCodec.Write(buffer, value with { ConnectionString = "" }));
        Assert.Throws<ArgumentException>(() => BlobTicketCodec.Write(buffer, value with { ConnectionString = "café" }));
        Assert.Throws<ArgumentException>(() => BlobTicketCodec.Write(buffer, value with { Name = "a\ud800" }));
        Assert.Throws<ArgumentException>(() => BlobTicketCodec.Write(new byte[8], value));

        Assert.Throws<ArgumentException>(() => BlobTicketCodec.WriteText(value with { ConnectionString = new string('A', 65535) }));
    }

    [Fact]
    public void Manifest_RoundTrip_AndGoldenBytes()
    {

        byte[] golden =
        [
            0x03, 0x00, (byte)'p', (byte)'k', (byte)'g',
            0x02, 0x00, 0x00, 0x00,
            0x05, 0x00, (byte)'a', (byte)'.', (byte)'b', (byte)'i', (byte)'n',
            0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00,
            .. SeqBytes(0, 32),
            0x05, 0x00, (byte)'e', (byte)'m', (byte)'p', (byte)'t', (byte)'y',
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            .. SeqBytes(0xE0, 32),
        ];
        var value = new ManifestValue("pkg",
        [
            new ManifestEntry("a.bin", 0x11223344, SeqBytes(0, 32)),
            new ManifestEntry("empty", 0, SeqBytes(0xE0, 32)),
        ]);

        byte[] buffer = new byte[8192];
        int written = ManifestCodec.Write(buffer, value);
        Assert.Equal(golden.Length, written);
        Assert.Equal(golden, buffer[..written]);

        Assert.True(ManifestCodec.TryRead(golden, out ManifestValue read));
        Assert.Equal("pkg", read.Name);
        Assert.Equal(2, read.Entries.Length);
        Assert.Equal("a.bin", read.Entries[0].Path);
        Assert.Equal(0x11223344, read.Entries[0].Size);
        Assert.Equal(SeqBytes(0, 32), read.Entries[0].Root);
        Assert.Equal("empty", read.Entries[1].Path);
        Assert.Equal(0, read.Entries[1].Size);
        Assert.Equal(SeqBytes(0xE0, 32), read.Entries[1].Root);

        int again = ManifestCodec.Write(buffer, read);
        Assert.Equal(golden, buffer[..again]);

        int emptyWritten = ManifestCodec.Write(buffer, new ManifestValue("", []));
        Assert.Equal(6, emptyWritten);
        Assert.Equal(new byte[6], buffer[..emptyWritten]);
        Assert.True(ManifestCodec.TryRead(new byte[6], out ManifestValue emptyRead));
        Assert.Equal("", emptyRead.Name);
        Assert.Empty(emptyRead.Entries);
    }

    [Fact]
    public void Manifest_Differential_IsByteExactWithLegacyCodec()
    {
        var rng = new Random(0x0FF1CE);
        byte[] buffer = new byte[8192];
        for (int i = 0; i < 2_000; i++)
        {
            ManifestValue value = RandomManifest(rng);
            var legacyEntries = value.Entries.Select(e => new Manifest.Entry(e.Path, e.Size, e.Root)).ToList();
            byte[] legacy = Manifest.Encode(value.Name, legacyEntries);

            int written = ManifestCodec.Write(buffer, value);
            Assert.Equal(legacy.Length, written);
            Assert.Equal(legacy, buffer[..written]);

            (string name, List<Manifest.Entry> entries) = Manifest.Decode(legacy);
            Assert.True(ManifestCodec.TryRead(legacy, out ManifestValue mine));
            Assert.Equal(name, mine.Name);
            Assert.Equal(entries.Count, mine.Entries.Length);
            for (int e = 0; e < entries.Count; e++)
            {
                Assert.Equal(entries[e].Path, mine.Entries[e].Path);
                Assert.Equal(entries[e].Size, mine.Entries[e].Size);
                Assert.Equal(entries[e].Root, mine.Entries[e].Root);
            }

            int again = ManifestCodec.Write(buffer, mine);
            Assert.Equal(legacy, buffer[..again]);
        }
    }

    [Fact]
    public void Manifest_RejectsNonCanonicalForms()
    {
        byte[] valid = Convert.FromHexString(
            "0100" + "6E"
            + "01000000"
            + "0100" + "70"
            + "0100000000000000"
            + Convert.ToHexString(SeqBytes(0, 32)));

        Assert.False(ManifestCodec.TryRead([.. valid, 0], out _));
        Assert.False(ManifestCodec.TryRead(valid[..^10], out _));
        Assert.False(ManifestCodec.TryRead([], out _));
        Assert.False(ManifestCodec.TryRead(new byte[5], out _));

        byte[] negative = (byte[])valid.Clone();
        Array.Fill(negative, (byte)0xFF, 10, 8);
        Assert.False(ManifestCodec.TryRead(negative, out _));

        byte[] mojibake = (byte[])valid.Clone();
        mojibake[9] = 0xC2;
        Assert.False(ManifestCodec.TryRead(mojibake, out _));
        (string _, List<Manifest.Entry> lenient) = Manifest.Decode(mojibake);
        Assert.Equal("\uFFFD", lenient[0].Path);

        byte[] lyingCount = (byte[])valid.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(lyingCount.AsSpan(3), 1000);
        Assert.False(ManifestCodec.TryRead(lyingCount, out _));
        Assert.Throws<FormatException>(() => Manifest.Decode(lyingCount));

        byte[] lyingName = (byte[])valid.Clone();
        lyingName[0] = 0xFF;
        lyingName[1] = 0xFF;
        Assert.False(ManifestCodec.TryRead(lyingName, out _));

        byte[] lyingPath = (byte[])valid.Clone();
        BinaryPrimitives.WriteUInt16LittleEndian(lyingPath.AsSpan(7), 500);
        Assert.False(ManifestCodec.TryRead(lyingPath, out _));
        Assert.Throws<FormatException>(() => Manifest.Decode(lyingPath));
    }

    [Fact]
    public void Manifest_Write_ThrowsOnProgrammerError()
    {
        byte[] buffer = new byte[8192];

        Assert.Throws<ArgumentNullException>(() => ManifestCodec.Write(buffer, new ManifestValue("n", null!)));
        Assert.Throws<ArgumentException>(() => ManifestCodec.Write(buffer, new ManifestValue(new string('a', 65536), [])));
        Assert.Throws<ArgumentException>(() =>
            ManifestCodec.Write(buffer, new ManifestValue("n", [new ManifestEntry(new string('b', 65536), 1, SeqBytes(0, 32))])));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ManifestCodec.Write(buffer, new ManifestValue("n", [new ManifestEntry("p", -1, SeqBytes(0, 32))])));
        Assert.Throws<ArgumentException>(() =>
            ManifestCodec.Write(buffer, new ManifestValue("n", [new ManifestEntry("p", 1, new byte[31])])));
        Assert.Throws<ArgumentException>(() => ManifestCodec.Write(buffer, new ManifestValue("a\ud800", [])));
        Assert.Throws<ArgumentException>(() => ManifestCodec.Write(new byte[5], new ManifestValue("n", [])));
    }

    [Fact]
    public void Frame_Constants_MatchBlobWire()
    {
        Assert.Equal(BlobWire.TypeHello, BlobFrameCodec.TypeHello);
        Assert.Equal(BlobWire.TypeHead, BlobFrameCodec.TypeHead);
        Assert.Equal(BlobWire.TypeReq, BlobFrameCodec.TypeReq);
        Assert.Equal(BlobWire.TypeChunk, BlobFrameCodec.TypeChunk);
        Assert.Equal(BlobWire.TypeBye, BlobFrameCodec.TypeBye);
        Assert.Equal(BlobWire.TypeWelcome, BlobFrameCodec.TypeWelcome);
        Assert.Equal(BlobWire.TypeProof, BlobFrameCodec.TypeProof);
        Assert.Equal(BlobWire.ProtocolVersion, BlobFrameCodec.ProtocolVersion);
        Assert.Equal(BlobWire.CurrentVersion, BlobFrameCodec.CurrentVersion);
        Assert.Equal(BlobWire.MaxChunkData, BlobFrameCodec.MaxChunkData);
        Assert.Equal(BlobWire.MaxRequestCount, BlobFrameCodec.MaxRequestCount);
        Assert.Equal(BlobWire.MaxProofSiblings, BlobFrameCodec.MaxProofSiblings);
        Assert.Equal(BlobWire.SessionIdLength, BlobFrameCodec.SessionIdLength);
    }

    [Fact]
    public void Frame_RoundTrip_AndGoldenBytes()
    {
        byte[] sid = SeqBytes(0, 32);
        byte[] nonce = SeqBytes(0x20, 32);
        byte[] sealedHead = SeqBytes(0x40, 49);
        byte[] cv = SeqBytes(0x60, 32);
        byte[] buffer = new byte[BlobFrameCodec.ChunkMaxLength];

        byte[] hello = [BlobFrameCodec.TypeHello, .. Be64(0x42), BlobFrameCodec.ProtocolVersion, .. sid];
        int w = BlobFrameCodec.WriteHello(buffer, 0x42, sid);
        Assert.Equal(hello, buffer[..w]);
        Assert.Equal(hello, BlobWire.Hello(0x42, sid));

        byte[] welcome = [BlobFrameCodec.TypeWelcome, .. Be64(7), BlobFrameCodec.ProtocolVersion, .. sid, .. nonce, .. sealedHead];
        w = BlobFrameCodec.WriteWelcome(buffer, 7, sid, nonce, sealedHead);
        Assert.Equal(welcome, buffer[..w]);
        Assert.Equal(welcome, BlobWire.Welcome(7, sid, nonce, sealedHead));

        byte[] bye = [BlobFrameCodec.TypeBye, .. Be64(1)];
        w = BlobFrameCodec.WriteBye(buffer, 1);
        Assert.Equal(bye, buffer[..w]);
        Assert.Equal(bye, BlobWire.Bye(1));

        byte[] head = [BlobFrameCodec.TypeHead, .. Be64(0x1122334455667788), .. Le64(1024), .. Le64(1)];
        w = BlobFrameCodec.WriteHead(buffer, 0x1122334455667788, 1024, 1);
        Assert.Equal(head, buffer[..w]);
        Assert.Equal(head, BlobWire.Head(0x1122334455667788, 1024, 1));

        byte[] req = [BlobFrameCodec.TypeReq, .. Be64(9), .. Le64(5), 64, 0];
        w = BlobFrameCodec.WriteRequest(buffer, 9, 5, 64);
        Assert.Equal(req, buffer[..w]);
        Assert.Equal(req, BlobWire.Request(9, 5, 64));

        byte[] chunk = [BlobFrameCodec.TypeChunk, .. Be64(3), .. Le64(7), .. cv, 0xAB];
        w = BlobFrameCodec.WriteChunk(buffer, 3, 7, cv, [0xAB]);
        Assert.Equal(chunk, buffer[..w]);
        Assert.Equal(chunk, BlobWire.Chunk(3, 7, cv, [0xAB]));

        foreach (byte[] frame in new[] { hello, welcome, bye, head, req, chunk })
        {
            Assert.True(BlobFrameCodec.TryParse(frame, out BlobFrameView view));
            Assert.True(BlobWire.Frame.TryParse(frame, out BlobWire.Frame legacy));
            AssertFramesEqual(view, legacy);
        }

        Assert.True(BlobFrameCodec.TryParse(welcome, out BlobFrameView wv));
        Assert.Equal(sid, wv.SessionId.ToArray());
        Assert.Equal(nonce, wv.ProviderNonce.ToArray());
        Assert.Equal(sealedHead, wv.SealedHead.ToArray());

        Assert.True(BlobFrameCodec.TryParse(chunk, out BlobFrameView cvv));
        Assert.Equal(cv, cvv.ChunkCv.ToArray());
        Assert.Equal(new byte[] { 0xAB }, cvv.ChunkData.ToArray());
    }

    [Fact]
    public void Frame_HelloVersionNegotiation_PreservedFromBlobWire()
    {
        byte[] sid = SeqBytes(0, 32);
        byte[] buffer = new byte[BlobFrameCodec.HelloV3Length + 1];
        buffer[0] = BlobFrameCodec.TypeHello;
        BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(1), 1);

        Assert.True(BlobFrameCodec.TryParse(buffer[..BlobFrameCodec.HelloV1Length], out BlobFrameView v1));
        Assert.Equal(1, v1.Version);
        Assert.True(v1.SessionId.IsEmpty);
        Assert.True(BlobWire.Frame.TryParse(buffer[..BlobFrameCodec.HelloV1Length], out BlobWire.Frame f1));
        Assert.Equal(1, f1.Version);
        Assert.Null(f1.SessionId);

        sid.CopyTo(buffer.AsSpan(9));
        Assert.True(BlobFrameCodec.TryParse(buffer[..BlobFrameCodec.HelloV2Length], out BlobFrameView v2));
        Assert.Equal(2, v2.Version);
        Assert.Equal(sid, v2.SessionId.ToArray());

        byte[] v3 = BlobWire.Hello(5, sid);
        Assert.True(BlobFrameCodec.TryParse(v3, out BlobFrameView v3View));
        Assert.Equal(BlobFrameCodec.ProtocolVersion, v3View.Version);
        Assert.Equal(sid, v3View.SessionId.ToArray());

        byte[] v4 = BlobWire.Hello(5, sid, BlobWire.CurrentVersion);
        Assert.True(BlobFrameCodec.TryParse(v4, out BlobFrameView v4View));
        Assert.Equal(BlobFrameCodec.CurrentVersion, v4View.Version);
        Assert.Equal(sid, v4View.SessionId.ToArray());
        Assert.True(BlobWire.Frame.TryParse(v4, out BlobWire.Frame f4));
        Assert.Equal(BlobWire.CurrentVersion, f4.Version);

        foreach (byte bogus in new byte[] { 1, 2, 5, 255 })
        {
            byte[] tampered = [.. v3];
            tampered[9] = bogus;
            Assert.False(BlobFrameCodec.TryParse(tampered, out _), $"hello version {bogus}");
            Assert.False(BlobWire.Frame.TryParse(tampered, out _));
        }

        Assert.False(BlobFrameCodec.TryParse([.. v3, 0], out _));
        Assert.False(BlobFrameCodec.TryParse(v3[..40], out _));
    }

    [Fact]
    public void Frame_RejectsNonCanonicalForms()
    {
        byte[] sid = SeqBytes(0, 32);
        byte[] cv = SeqBytes(0, 32);

        Assert.False(BlobFrameCodec.TryParse(new byte[8], out _));
        Assert.False(BlobFrameCodec.TryParse([0, .. new byte[8]], out _));
        Assert.False(BlobFrameCodec.TryParse([8, .. new byte[8]], out _));
        Assert.False(BlobFrameCodec.TryParse([255, .. new byte[8]], out _));
        Assert.False(BlobFrameCodec.TryParse([7, .. new byte[8]], out _));

        foreach ((long totalBytes, long totalChunks) in new[] { (2048L, 1L), (0L, 1L), (1024L, 2L), (1025L, 1L), (-1L, 0L) })
        {
            Assert.False(BlobFrameCodec.TryParse(BlobWire.Head(1, totalBytes, totalChunks), out _), $"({totalBytes}, {totalChunks})");
        }

        foreach ((long totalBytes, long totalChunks) in new[] { (0L, 0L), (1L, 1L), (1023L, 1L), (1024L, 1L), (1025L, 2L) })
        {
            Assert.True(BlobFrameCodec.TryParse(BlobWire.Head(1, totalBytes, totalChunks), out _), $"({totalBytes}, {totalChunks})");
        }

        Assert.False(BlobFrameCodec.TryParse(BlobWire.Request(1, 0, 0), out _));
        Assert.False(BlobFrameCodec.TryParse(BlobWire.Request(1, 0, 65), out _));
        Assert.False(BlobFrameCodec.TryParse(BlobWire.Request(1, -1, 1), out _));
        Assert.True(BlobFrameCodec.TryParse(BlobWire.Request(1, 0, 1), out _));

        Assert.False(BlobFrameCodec.TryParse(BlobWire.Chunk(1, 0, cv, new byte[0]), out _));
        Assert.False(BlobFrameCodec.TryParse(BlobWire.Chunk(1, 0, cv, new byte[1025]), out _));
        Assert.False(BlobFrameCodec.TryParse(BlobWire.Chunk(1, -1, cv, new byte[1]), out _));
        Assert.True(BlobFrameCodec.TryParse(BlobWire.Chunk(1, 0, cv, new byte[1024]), out _));
        Assert.True(BlobFrameCodec.TryParse(BlobWire.Chunk(1, long.MaxValue, cv, [1]), out _));

        byte[] welcome = BlobWire.Welcome(1, sid, sid, new byte[49]);
        byte[] tampered = [.. welcome];
        tampered[9] = 1;
        Assert.False(BlobFrameCodec.TryParse(tampered, out _));
        Assert.False(BlobFrameCodec.TryParse(welcome[..^1], out _));
        Assert.False(BlobFrameCodec.TryParse([.. welcome, 0], out _));

        Assert.False(BlobFrameCodec.TryParse([BlobFrameCodec.TypeBye, .. Be64(1), 0], out _));
    }

    [Fact]
    public void Frame_Writers_ThrowOnProgrammerError()
    {
        byte[] buffer = new byte[BlobFrameCodec.ProofMaxLength];
        byte[] sid = SeqBytes(0, 32);

        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteHello(buffer, 1, sid[..31]));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteHello(new byte[41], 1, sid));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteHello(buffer, 1, sid, 5));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteHello(buffer, 1, sid, 0));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteWelcome(buffer, 1, sid, sid[..31], new byte[49]));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteWelcome(buffer, 1, sid, sid, new byte[48]));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteWelcome(buffer, 1, sid, sid, new byte[49], 5));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteBye(new byte[8], 1));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteHead(buffer, 1, 2048, 1));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteHead(buffer, 1, -1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteRequest(buffer, 1, 0, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteRequest(buffer, 1, 0, 65));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteRequest(buffer, 1, -1, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteChunk(buffer, 1, -1, sid, [1]));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteChunk(buffer, 1, 0, sid[..31], [1]));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteChunk(buffer, 1, 0, sid, []));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteChunk(buffer, 1, 0, sid, new byte[1025]));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteChunk(new byte[49], 1, 0, sid, [1]));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteProof(buffer, 1, -1, sid));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteProof(buffer, 1, 0, sid[..31]));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteProof(buffer, 1, 0, new byte[65 * 32]));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteProof(new byte[BlobFrameCodec.HeaderLength + 8], 1, 0, []));
    }

    [Fact]
    public void Frame_Differential_MatchesBlobWireBuildersAndParser()
    {
        var rng = new Random(0xF7A11);
        byte[] buffer = new byte[BlobFrameCodec.ProofMaxLength];
        for (int i = 0; i < 3_000; i++)
        {
            byte[] wire = RandomFrameWire(rng);

            Assert.True(BlobWire.Frame.TryParse(wire, out BlobWire.Frame legacy));
            Assert.True(BlobFrameCodec.TryParse(wire, out BlobFrameView view));
            AssertFramesEqual(view, legacy);

            if (view.Type == BlobFrameCodec.TypeHello && wire.Length != BlobFrameCodec.HelloV3Length)
            {
                continue;
            }

            int w = view.Type switch
            {
                BlobFrameCodec.TypeHello => BlobFrameCodec.WriteHello(buffer, view.Stream, view.SessionId, view.Version),
                BlobFrameCodec.TypeWelcome => BlobFrameCodec.WriteWelcome(buffer, view.Stream, view.SessionId,
                    view.ProviderNonce, view.SealedHead, view.Version),
                BlobFrameCodec.TypeBye => BlobFrameCodec.WriteBye(buffer, view.Stream),
                BlobFrameCodec.TypeHead => BlobFrameCodec.WriteHead(buffer, view.Stream, view.TotalBytes, view.TotalChunks),
                BlobFrameCodec.TypeReq => BlobFrameCodec.WriteRequest(buffer, view.Stream, view.StartChunk, view.Count),
                BlobFrameCodec.TypeProof => BlobFrameCodec.WriteProof(buffer, view.Stream, view.Index, view.SiblingCvs),
                _ => BlobFrameCodec.WriteChunk(buffer, view.Stream, view.Index, view.ChunkCv, view.ChunkData),
            };
            Assert.Equal(wire, buffer[..w]);
        }
    }

    [Fact]
    public void Frame_ProofRoundTrip_AndGoldenBytes()
    {
        byte[] cv = SeqBytes(0xA0, 32);
        byte[] buffer = new byte[BlobFrameCodec.ProofMaxLength];

        byte[] proof0 = [BlobFrameCodec.TypeProof, .. Be64(0x42), .. Le64(7), 0];
        Assert.Equal(proof0, BlobWire.Proof(0x42, 7, []));
        int w = BlobFrameCodec.WriteProof(buffer, 0x42, 7, []);
        Assert.Equal(BlobFrameCodec.ProofMinLength, w);
        Assert.Equal(proof0, buffer[..w]);

        byte[] proof1 = [BlobFrameCodec.TypeProof, .. Be64(0x42), .. Le64(7), 1, .. cv];
        Assert.Equal(proof1, BlobWire.Proof(0x42, 7, cv));
        Assert.Equal(proof1, buffer[..BlobFrameCodec.WriteProof(buffer, 0x42, 7, cv)]);

        byte[] cvs3 = [.. SeqBytes(0x00, 32), .. SeqBytes(0x20, 32), .. SeqBytes(0x40, 32)];
        byte[] proof3 = [BlobFrameCodec.TypeProof, .. Be64(ulong.MaxValue), .. Le64(1_000_000), 3, .. cvs3];
        Assert.Equal(proof3, BlobWire.Proof(ulong.MaxValue, 1_000_000, cvs3));
        Assert.Equal(proof3, buffer[..BlobFrameCodec.WriteProof(buffer, ulong.MaxValue, 1_000_000, cvs3)]);

        byte[] cvs64 = SeqBytes(0, 64 * 32);
        byte[] proof64 = BlobWire.Proof(9, 63, cvs64);
        Assert.Equal(BlobFrameCodec.ProofMaxLength, proof64.Length);
        Assert.Equal(BlobFrameCodec.TypeProof, proof64[0]);
        Assert.Equal(Be64(9), proof64[1..9]);
        Assert.Equal(Le64(63), proof64[9..17]);
        Assert.Equal(64, proof64[17]);
        Assert.Equal(cvs64, proof64[18..]);
        Assert.Equal(proof64, buffer[..BlobFrameCodec.WriteProof(buffer, 9, 63, cvs64)]);

        foreach (byte[] frame in new[] { proof0, proof1, proof3, proof64 })
        {
            Assert.True(BlobFrameCodec.TryParse(frame, out BlobFrameView view));
            Assert.True(BlobWire.Frame.TryParse(frame, out BlobWire.Frame legacy));
            AssertFramesEqual(view, legacy);
            Assert.Equal(BlobFrameCodec.TypeProof, view.Type);
        }

        Assert.True(BlobFrameCodec.TryParse(proof3, out BlobFrameView p3));
        Assert.Equal(1_000_000, p3.Index);
        Assert.Equal(3, p3.Count);
        Assert.Equal(SeqBytes(0x00, 32), p3.Sibling(0).ToArray());
        Assert.Equal(SeqBytes(0x20, 32), p3.Sibling(1).ToArray());
        Assert.Equal(SeqBytes(0x40, 32), p3.Sibling(2).ToArray());
        Assert.Equal(cvs3, p3.SiblingCvs.ToArray());

        Assert.True(BlobWire.Frame.TryParse(proof3, out BlobWire.Frame f3));
        Assert.Equal(1_000_000, f3.Index);
        Assert.Equal(3, f3.Count);
        Assert.Equal(cvs3, f3.SiblingCvs);
        Assert.Equal(SeqBytes(0x40, 32), f3.SiblingCvs.AsSpan(64, 32).ToArray());

        Assert.True(BlobFrameCodec.TryParse(proof0, out BlobFrameView p0));
        Assert.Equal(0, p0.Count);
        Assert.True(p0.SiblingCvs.IsEmpty);
        Assert.True(BlobWire.Frame.TryParse(proof0, out BlobWire.Frame f0));
        Assert.NotNull(f0.SiblingCvs);
        Assert.Empty(f0.SiblingCvs);
    }

    [Fact]
    public void Frame_V4HelloWelcome_MatchHandComposedGoldens()
    {
        byte[] sid = SeqBytes(0, 32);
        byte[] nonce = SeqBytes(0x20, 32);
        byte[] sealedHead = SeqBytes(0x40, 49);
        byte[] buffer = new byte[BlobFrameCodec.WelcomeLength];

        byte[] hello4 = [BlobFrameCodec.TypeHello, .. Be64(0x42), BlobFrameCodec.CurrentVersion, .. sid];
        Assert.Equal(BlobFrameCodec.HelloV4Length, hello4.Length);
        Assert.Equal(hello4, BlobWire.Hello(0x42, sid, BlobWire.CurrentVersion));
        Assert.Equal(hello4, buffer[..BlobFrameCodec.WriteHello(buffer, 0x42, sid, BlobFrameCodec.CurrentVersion)]);

        byte[] welcome4 =
            [BlobFrameCodec.TypeWelcome, .. Be64(7), BlobFrameCodec.CurrentVersion, .. sid, .. nonce, .. sealedHead];
        Assert.Equal(BlobFrameCodec.WelcomeV4Length, welcome4.Length);
        Assert.Equal(welcome4, BlobWire.Welcome(7, sid, nonce, sealedHead, BlobWire.CurrentVersion));
        Assert.Equal(welcome4,
            buffer[..BlobFrameCodec.WriteWelcome(buffer, 7, sid, nonce, sealedHead, BlobFrameCodec.CurrentVersion)]);

        foreach (byte[] frame in new[] { hello4, welcome4 })
        {
            Assert.True(BlobFrameCodec.TryParse(frame, out BlobFrameView view));
            Assert.True(BlobWire.Frame.TryParse(frame, out BlobWire.Frame legacy));
            AssertFramesEqual(view, legacy);
            Assert.Equal(BlobFrameCodec.CurrentVersion, view.Version);
            Assert.Equal(BlobWire.CurrentVersion, legacy.Version);
            Assert.Equal(sid, view.SessionId.ToArray());
        }

        Assert.True(BlobFrameCodec.TryParse(welcome4, out BlobFrameView wv));
        Assert.Equal(nonce, wv.ProviderNonce.ToArray());
        Assert.Equal(sealedHead, wv.SealedHead.ToArray());

        byte[] hello3From4 = [.. hello4[..9], BlobWire.ProtocolVersion, .. hello4[10..]];
        Assert.Equal(BlobWire.Hello(0x42, sid), hello3From4);
        byte[] welcome3From4 = [.. welcome4[..9], BlobWire.ProtocolVersion, .. welcome4[10..]];
        Assert.Equal(BlobWire.Welcome(7, sid, nonce, sealedHead), welcome3From4);

        Assert.True(BlobWire.Frame.TryParse(BlobWire.Hello(1, sid), out BlobWire.Frame h));
        Assert.Equal(BlobWire.ProtocolVersion, h.Version);
        Assert.True(BlobWire.Frame.TryParse(BlobWire.Welcome(1, sid, sid, new byte[49]), out BlobWire.Frame w));
        Assert.Equal(BlobWire.ProtocolVersion, w.Version);

        Assert.Throws<ArgumentOutOfRangeException>(() => BlobWire.Hello(1, sid, 5));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobWire.Welcome(1, sid, sid, new byte[49], 5));
    }

    [Fact]
    public void Frame_V4AndProof_RejectNonCanonicalForms()
    {
        byte[] sid = SeqBytes(0, 32);
        byte[] cvs3 = [.. SeqBytes(0, 32), .. SeqBytes(0x20, 32), .. SeqBytes(0x40, 32)];
        byte[] proof3 = BlobWire.Proof(1, 2, cvs3);

        Assert.False(BlobFrameCodec.TryParse(proof3[..^1], out _));
        Assert.False(BlobWire.Frame.TryParse(proof3[..^1], out _));
        Assert.False(BlobFrameCodec.TryParse([.. proof3, 0], out _));
        Assert.False(BlobWire.Frame.TryParse([.. proof3, 0], out _));
        Assert.False(BlobFrameCodec.TryParse(proof3[..8], out _));
        Assert.True(BlobWire.Frame.TryParse(BlobWire.Proof(1, 2, cvs3[..64]), out _));

        byte[] lyingCount = [.. proof3];
        lyingCount[17] = 65;
        Assert.False(BlobFrameCodec.TryParse(lyingCount, out _));
        Assert.False(BlobWire.Frame.TryParse(lyingCount, out _));

        byte[] full65 = new byte[BlobFrameCodec.HeaderLength + 9 + 65 * 32];
        full65[0] = BlobFrameCodec.TypeProof;
        BinaryPrimitives.WriteUInt64BigEndian(full65.AsSpan(1), 1);
        BinaryPrimitives.WriteInt64LittleEndian(full65.AsSpan(9), 2);
        full65[17] = 65;
        Assert.False(BlobFrameCodec.TryParse(full65, out _));
        Assert.False(BlobWire.Frame.TryParse(full65, out _));

        byte[] count255 = new byte[BlobFrameCodec.ProofMaxLength];
        count255[0] = BlobFrameCodec.TypeProof;
        BinaryPrimitives.WriteUInt64BigEndian(count255.AsSpan(1), 1);
        BinaryPrimitives.WriteInt64LittleEndian(count255.AsSpan(9), 2);
        count255[17] = 255;
        Assert.False(BlobFrameCodec.TryParse(count255, out _));
        Assert.False(BlobWire.Frame.TryParse(count255, out _));

        Assert.False(BlobFrameCodec.TryParse(BlobWire.Proof(1, -1, cvs3), out _));
        Assert.False(BlobWire.Frame.TryParse(BlobWire.Proof(1, -1, cvs3), out _));

        byte[] bogusHello = [.. BlobWire.Hello(1, sid, BlobWire.CurrentVersion)];
        bogusHello[9] = 5;
        Assert.False(BlobFrameCodec.TryParse(bogusHello, out _));
        Assert.False(BlobWire.Frame.TryParse(bogusHello, out _));

        byte[] welcome4 = BlobWire.Welcome(1, sid, sid, new byte[49], BlobWire.CurrentVersion);
        foreach (byte bogus in new byte[] { 0, 1, 5, 255 })
        {
            byte[] tampered = [.. welcome4];
            tampered[9] = bogus;
            Assert.False(BlobFrameCodec.TryParse(tampered, out _), $"welcome version {bogus}");
            Assert.False(BlobWire.Frame.TryParse(tampered, out _));
        }

        Assert.Throws<ArgumentException>(() => BlobWire.Proof(1, 0, new byte[33]));
        Assert.Throws<ArgumentException>(() => BlobWire.Proof(1, 0, new byte[65 * 32]));
    }

    [Fact]
    public void Cipher_V4SessionKey_IsDomainSeparatedFromV3()
    {
        byte[] psk = SeqBytes(1, 32), root = SeqBytes(2, 32), sid = SeqBytes(3, 32), nonce = SeqBytes(4, 32);
        var v3 = BlobWire.Cipher.For(psk, root, sid, nonce)!;
        var v4 = BlobWire.Cipher.For(psk, root, sid, nonce, BlobWire.CurrentVersion)!;

        byte[] sealedV3 = v3.Seal(asProvider: true, 1, BlobWire.Bye(1));
        byte[] sealedV4 = v4.Seal(asProvider: true, 1, BlobWire.Bye(1));
        Assert.False(sealedV3.SequenceEqual(sealedV4));

        ulong watermark = 0;
        Assert.True(v3.TryOpen(fromProvider: true, sealedV3, ref watermark, out _));
        Assert.False(v4.TryOpen(fromProvider: true, sealedV3, ref watermark, out _));

        watermark = 0;
        Assert.True(v4.TryOpen(fromProvider: true, sealedV4, ref watermark, out _));
        Assert.False(v3.TryOpen(fromProvider: true, sealedV4, ref watermark, out _));

        Assert.False(v4.TryOpen(fromProvider: true, sealedV4, ref watermark, out _), "v4 replays reject exactly like v3");

        Assert.Throws<ArgumentOutOfRangeException>(() => BlobWire.Cipher.For(psk, root, sid, nonce, 5));
    }

    [Fact]
    public void Cipher_ProofUnderV4Session_OpensAndHoldsWatermarkDiscipline()
    {
        byte[] psk = SeqBytes(1, 32), root = SeqBytes(2, 32), sid = SeqBytes(3, 32), nonce = SeqBytes(4, 32);
        var v4 = BlobWire.Cipher.For(psk, root, sid, nonce, BlobWire.CurrentVersion)!;
        byte[] cvs = [.. SeqBytes(0, 32), .. SeqBytes(0x20, 32), .. SeqBytes(0x40, 32)];
        byte[] proof = BlobWire.Proof(9, 4, cvs);
        byte[] sealedProof = v4.Seal(asProvider: true, 1, proof);

        ulong watermark = 0;
        Assert.True(v4.TryOpen(fromProvider: true, sealedProof, ref watermark, out byte[] plain));
        Assert.Equal(proof, plain);
        Assert.Equal(1UL, watermark);
        Assert.True(BlobWire.Frame.TryParse(plain, out BlobWire.Frame f));
        Assert.Equal(BlobWire.TypeProof, f.Type);
        Assert.Equal(4, f.Index);
        Assert.Equal(3, f.Count);

        byte[] forged = sealedProof.ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(forged, 100);
        forged[^1] ^= 1;
        Assert.False(v4.TryOpen(fromProvider: true, forged, ref watermark, out _));
        Assert.Equal(1UL, watermark);

        Assert.False(v4.TryOpen(fromProvider: true, sealedProof, ref watermark, out _));
        Assert.Equal(1UL, watermark);

        byte[] next = v4.Seal(asProvider: true, 2, BlobWire.Proof(9, 5, []));
        Assert.True(v4.TryOpen(fromProvider: true, next, ref watermark, out byte[] nextPlain));
        Assert.True(BlobWire.Frame.TryParse(nextPlain, out BlobWire.Frame nextFrame));
        Assert.Equal(5, nextFrame.Index);
        Assert.Equal(0, nextFrame.Count);
        Assert.Equal(2UL, watermark);
    }

    [Fact]
    public void DownloadSession_NegotiatesV4Welcome_AndRejectsWrongStream()
    {
        byte[] psk = SeqBytes(1, 32), root = SeqBytes(2, 32), clientNonce = SeqBytes(3, 32), providerNonce = SeqBytes(4, 32);
        var session = new BlobWire.DownloadSession(psk, root, clientNonce);
        var providerV3 = BlobWire.Cipher.For(psk, root, clientNonce, providerNonce)!;
        var providerV4 = BlobWire.Cipher.For(psk, root, clientNonce, providerNonce, BlobWire.CurrentVersion)!;
        ulong stream = BlobWire.StreamId(root);

        byte[] head = providerV4.Seal(asProvider: true, 1, BlobWire.Head(stream, 500, 1));
        byte[] welcome = BlobWire.Welcome(stream, clientNonce, providerNonce, head, BlobWire.CurrentVersion);
        Assert.True(BlobWire.Frame.TryParse(welcome, out BlobWire.Frame parsed));
        Assert.Equal(BlobWire.CurrentVersion, parsed.Version);

        byte[] v3Head = providerV3.Seal(asProvider: true, 1, BlobWire.Head(stream, 500, 1));
        Assert.False(session.TryOpen(BlobWire.Welcome(stream, clientNonce, providerNonce, v3Head, BlobWire.CurrentVersion),
            stream, out _));

        Assert.True(session.TryOpen(welcome, stream, out BlobWire.Frame headFrame));
        Assert.Equal(BlobWire.TypeHead, headFrame.Type);
        Assert.Equal(500, headFrame.TotalBytes);
        Assert.False(session.TryOpen(providerV3.Seal(asProvider: true, 2, BlobWire.Bye(stream)), stream, out _));
        Assert.True(session.TryOpen(
            providerV4.Seal(asProvider: true, 2, BlobWire.Proof(stream, 3, SeqBytes(5, 64))), stream, out BlobWire.Frame proof));
        Assert.Equal(BlobWire.TypeProof, proof.Type);
        Assert.Equal(2, proof.Count);

        ulong other = stream ^ 1;
        byte[] otherHead = providerV4.Seal(asProvider: true, 3, BlobWire.Head(other, 500, 1));
        Assert.False(session.TryOpen(BlobWire.Welcome(other, clientNonce, providerNonce, otherHead, BlobWire.CurrentVersion),
            stream, out _));
    }

    [Fact]
    public void AllCodecs_TotalityFuzz_200KInputs_NeverThrowsOrAcceptsOutOfRange()
    {
        var rng = new Random(0x5EED_0001);
        byte[] ticketScratch = new byte[BlobTicketCodec.MaxBinaryLength];
        byte[] manifestScratch = new byte[8192];
        byte[] frameScratch = new byte[BlobFrameCodec.ProofMaxLength];
        byte[] mutation = new byte[BlobTicketCodec.MaxBinaryLength + 1];
        byte[] reencode = new byte[BlobTicketCodec.MaxBinaryLength];
        for (int i = 0; i < 200_000; i++)
        {
            switch (i % 3)
            {
                case 0:
                    FuzzTicket(rng, ticketScratch, mutation, reencode);
                    break;
                case 1:
                    FuzzManifest(rng, manifestScratch, mutation, reencode);
                    break;
                default:
                    FuzzFrame(rng, frameScratch, mutation);
                    break;
            }
        }
    }

    private static void FuzzTicket(Random rng, byte[] scratch, byte[] mutation, byte[] reencode)
    {
        BlobTicketValue value = RandomTicket(rng, allowOversizedName: rng.Next(10) == 0);
        int written = BlobTicketCodec.Write(scratch, value);
        ReadOnlySpan<byte> input = MutatedInput(rng, scratch.AsSpan(0, written), mutation);

        if (!BlobTicketCodec.TryRead(input, out BlobTicketValue read))
        {
            return;
        }

        Assert.InRange(Encoding.UTF8.GetByteCount(read.Name), 0, BlobTicketCodec.MaxNameBytes);
        Assert.Equal(BlobTicketCodec.RootLength, read.Root.Length);
        Assert.True(read.PreSharedKey is null || read.PreSharedKey.Length == BlobTicketCodec.PskLength);
        Assert.InRange(read.ConnectionString.Length, 1, ushort.MaxValue);
        foreach (char c in read.ConnectionString)
        {
            Assert.True(c < 0x80);
        }

        Assert.True(read.Kind is WireBlobKind.File or WireBlobKind.Directory);

        int n = BlobTicketCodec.Write(reencode, read);
        Assert.True(input.SequenceEqual(reencode.AsSpan(0, n)));
    }

    private static void FuzzManifest(Random rng, byte[] scratch, byte[] mutation, byte[] reencode)
    {
        ManifestValue value = RandomManifest(rng);
        int written = ManifestCodec.Write(scratch, value);
        ReadOnlySpan<byte> input = MutatedInput(rng, scratch.AsSpan(0, written), mutation);

        if (!ManifestCodec.TryRead(input, out ManifestValue read))
        {
            return;
        }

        Assert.InRange(Encoding.UTF8.GetByteCount(read.Name), 0, ManifestCodec.MaxTextBytes);
        foreach (ManifestEntry entry in read.Entries)
        {
            Assert.True(entry.Size >= 0);
            Assert.Equal(ManifestCodec.RootLength, entry.Root.Length);
            Assert.InRange(Encoding.UTF8.GetByteCount(entry.Path), 0, ManifestCodec.MaxTextBytes);
        }

        int n = ManifestCodec.Write(reencode, read);
        Assert.True(input.SequenceEqual(reencode.AsSpan(0, n)));

        (string name, List<Manifest.Entry> entries) = Manifest.Decode(input);
        Assert.Equal(read.Name, name);
        Assert.Equal(read.Entries.Length, entries.Count);
        for (int i = 0; i < entries.Count; i++)
        {
            Assert.Equal(read.Entries[i].Path, entries[i].Path);
            Assert.Equal(read.Entries[i].Size, entries[i].Size);
            Assert.Equal(read.Entries[i].Root, entries[i].Root);
        }
    }

    private static void FuzzFrame(Random rng, byte[] scratch, byte[] mutation)
    {
        byte[] valid = RandomFrameWire(rng);
        valid.CopyTo(scratch, 0);
        ReadOnlySpan<byte> input;
        switch (rng.Next(4))
        {
            case 0:
            {
                int len = rng.Next(0, 128);
                rng.NextBytes(mutation.AsSpan(0, len));
                if (len >= 9 && rng.Next(2) == 0)
                {
                    mutation[0] = (byte)(1 + rng.Next(7));
                }

                input = mutation.AsSpan(0, len);
                break;
            }
            case 1:
                valid.CopyTo(mutation, 0);
                mutation[rng.Next(valid.Length)] ^= (byte)(1 << rng.Next(8));
                input = mutation.AsSpan(0, valid.Length);
                break;
            case 2:
                input = scratch.AsSpan(0, rng.Next(valid.Length));
                break;
            default:
                valid.CopyTo(mutation, 0);
                mutation[valid.Length] = (byte)rng.Next(256);
                input = mutation.AsSpan(0, valid.Length + 1);
                break;
        }

        bool mine = BlobFrameCodec.TryParse(input, out BlobFrameView view);
        bool legacy = BlobWire.Frame.TryParse(input, out BlobWire.Frame frame);
        Assert.Equal(legacy, mine);
        if (!mine)
        {
            return;
        }

        AssertFramesEqual(view, frame);
        Assert.InRange(view.Count, 0, BlobFrameCodec.MaxRequestCount);
        Assert.True(view.TotalBytes >= 0);
        Assert.True(view.TotalChunks >= 0);
        Assert.True(view.StartChunk >= 0);
        Assert.True(view.Index >= 0);
        Assert.True(view.Version is 0 or 1 or 2 or BlobFrameCodec.ProtocolVersion or BlobFrameCodec.CurrentVersion);
        Assert.True(view.ChunkData.Length <= BlobFrameCodec.MaxChunkData);
        Assert.True(view.SealedHead.Length is 0 or BlobFrameCodec.SealedHeadLength);
        Assert.True(view.SessionId.Length is 0 or BlobFrameCodec.SessionIdLength);
        Assert.True(view.ProviderNonce.Length is 0 or BlobFrameCodec.SessionIdLength);
        Assert.Equal(0, view.SiblingCvs.Length % 32);
        Assert.True(view.SiblingCvs.Length <= BlobFrameCodec.MaxProofSiblings * 32);
        Assert.True(view.Type != BlobFrameCodec.TypeProof || view.SiblingCvs.Length == view.Count * 32);
    }
}
