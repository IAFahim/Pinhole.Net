using System.Buffers.Binary;
using System.Net;
using System.Text;
using Pinhole;
using Pinhole.Blobs;
using Pinhole.Wire;
using Xunit;

namespace Pinhole.Tests.Wire;

// Differential-oracle tests for the three blob-layer codecs. The existing
// implementations define the byte formats — BlobTicket's ToString/Parse, the
// internal Manifest encode/decode, and BlobWire.Frame.TryParse — so every test
// here holds the new codecs against them: byte-exact agreement on valid input,
// identical fields both directions, and re-encode stability (the manifest is
// BLAKE3 content-addressed; the ticket has exactly one valid encoding). The
// codecs additionally reject non-canonical forms the legacy parsers tolerate,
// and those divergences are pinned explicitly rather than silently assumed.
public sealed class BlobFormatsCodecTests
{
    private const string CommittedTicketGolden =
        "pinholeblob1:AQIBZAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fQEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8kAHBpbmhvbGUxOkFRQUJBQUFBQUFBQUFBQUJCSDhBQUFFQUJRRQ";

    private const int TicketSchemePrefix = 13; // "pinholeblob1:" — Scheme.Length + 1

    // ------------------------------------------------------------------ fixtures

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
        // fragments cover 1-, 2-, 3-, and 4-byte UTF-8 forms (the last as a pair)
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
        switch (rng.Next(8))
        {
            case 0: // legacy v1 Hello: empty body, receive-only form
            {
                byte[] frame = new byte[BlobFrameCodec.HelloV1Length];
                frame[0] = BlobFrameCodec.TypeHello;
                BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
                return frame;
            }
            case 1: // legacy v2 Hello: raw session id without a version byte
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
            case 0: // raw random bytes, sometimes with a plausible ticket header
            {
                int len = rng.Next(0, Math.Min(valid.Length + 1, 128));
                rng.NextBytes(mutation.AsSpan(0, len));
                if (len > 1 && rng.Next(2) == 0)
                {
                    mutation[0] = 1; // ticket version byte
                    mutation[1] &= 0x03; // known flag bits only
                }

                return mutation.AsSpan(0, len);
            }
            case 1: // single bit flip inside a valid encoding
                valid.CopyTo(mutation);
                mutation[rng.Next(valid.Length)] ^= (byte)(1 << rng.Next(8));
                return mutation.AsSpan(0, valid.Length);
            case 2: // truncation at a random cut
                return valid[..rng.Next(valid.Length)];
            default: // one trailing garbage byte
                valid.CopyTo(mutation);
                mutation[valid.Length] = (byte)rng.Next(256);
                return mutation.AsSpan(0, valid.Length + 1);
        }
    }

    // ------------------------------------------------------------------ ticket: round-trip + goldens

    [Fact]
    public void Ticket_RoundTrip_AndGoldenBytes()
    {
        // Hand-pinned: version 1, flags 0x01 (directory), name "hi",
        // root 0x00..0x1F, no PSK, connection string "AB" (u16 LE length).
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

        // exactly one encoding: re-encoding the decoded value reproduces the bytes
        int again = BlobTicketCodec.Write(buffer, read);
        Assert.Equal(golden, buffer[..again]);
    }

    [Fact]
    public void Ticket_TextLayer_MatchesCommittedGoldenAndLegacyParser()
    {
        // The exact ticket string committed in WireGoldenTests, rebuilt the same way
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

        // binary layer agrees byte-for-byte with the payload the legacy string carries
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

        // whitespace around the payload is tolerated, exactly like BlobTicket.Parse
        string padded = "pinholeblob1:  " + payloadText + "  ";
        Assert.True(BlobTicketCodec.TryReadText(padded, out BlobTicketValue paddedRead));
        AssertTicketsEqual(value, paddedRead);
        Assert.True(BlobTicket.TryParse(padded, out _));

        Assert.False(BlobTicketCodec.TryReadText(null, out _));
        Assert.False(BlobTicketCodec.TryReadText("", out _));
        Assert.False(BlobTicketCodec.TryReadText(" pinholeblob1:" + payloadText, out _)); // before the scheme: not tolerated
        Assert.False(BlobTicketCodec.TryReadText("pinhole1:" + payloadText, out _));
        Assert.False(BlobTicketCodec.TryReadText("pinholeblob1:!!!!", out _)); // strict base64url charset
        Assert.False(BlobTicketCodec.TryReadText("pinholeblob1:" + new string('A', BlobTicketCodec.MaxTextLength), out _));

        byte[] payload = Pinhole.Base64Url.Decode(payloadText);
        payload[0] = 2; // unknown ticket version
        Assert.False(BlobTicketCodec.TryReadText("pinholeblob1:" + Pinhole.Base64Url.Encode(payload), out _));
    }

    [Fact]
    public void Ticket_NameTruncation_StaysOnCodePointBoundary()
    {
        byte[] buffer = new byte[BlobTicketCodec.MaxBinaryLength];
        var value = new BlobTicketValue(WireBlobKind.File, SeqBytes(0, 32), "AB", "", null);

        // 254 ASCII + a 2-byte 'µ' (0xC2 0xB5) = 256 bytes: the cut keeps 254
        value = value with { Name = new string('a', 254) + "µ" };
        int written = BlobTicketCodec.Write(buffer, value);
        Assert.Equal(254, buffer[2]);
        Assert.True(BlobTicketCodec.TryRead(buffer[..written], out BlobTicketValue read));
        Assert.Equal(new string('a', 254), read.Name);

        // the legacy writer cuts at byte 255, mid-code-point; that payload is not
        // valid UTF-8 and this codec rejects it (the legacy parser accepts it, lossily)
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

        // 252 ASCII + a 4-byte emoji = 256 bytes: the cut keeps 252
        value = value with { Name = new string('a', 252) + "\U0001F600" };
        written = BlobTicketCodec.Write(buffer, value);
        Assert.Equal(252, buffer[2]);
        Assert.True(BlobTicketCodec.TryRead(buffer[..written], out read));
        Assert.Equal(new string('a', 252), read.Name);

        // a 255-byte single-byte name fits untouched, agreeing with the legacy bytes
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

    // ------------------------------------------------------------------ ticket: differential

    [Fact]
    public void Ticket_Differential_MatchesLegacyEncoderAndParser()
    {
        var rng = new Random(202_610_25);
        byte[] buffer = new byte[BlobTicketCodec.MaxBinaryLength];
        for (int i = 0; i < 2_000; i++)
        {
            BlobTicketValue value = RandomTicket(rng); // names stay under 255 bytes: both encoders emit them whole
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

            // each parser reads the other's output into the same fields
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

    // ------------------------------------------------------------------ ticket: rejections

    [Fact]
    public void Ticket_RejectsNonCanonicalForms()
    {
        string rootHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        byte[] valid = Convert.FromHexString("010000" + rootHex + "02004142"); // file, empty name, cs "AB"

        foreach (byte badFlag in new byte[] { 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x83, 0xFD })
        {
            byte[] t = (byte[])valid.Clone();
            t[1] = badFlag;
            Assert.False(BlobTicketCodec.TryRead(t, out BlobTicketValue v), $"flags {badFlag:X2}");
            Assert.Equal(default, v);
        }

        byte[] t2 = (byte[])valid.Clone();
        t2[0] = 2;
        Assert.False(BlobTicketCodec.TryRead(t2, out _)); // version

        Assert.False(BlobTicketCodec.TryRead([.. valid, 0x41], out _)); // trailing byte
        Assert.False(BlobTicketCodec.TryRead(valid[..^1], out _)); // truncated

        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010000" + rootHex + "0000"), out _)); // empty connection string
        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010000" + rootHex + "03004142"), out _)); // csLen overruns
        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010000" + rootHex + "0100"), out _)); // csLen promises bytes that are not there

        // a name that is a lone UTF-8 lead byte is not this format's name
        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010001C2" + rootHex + "02004142"), out _));

        // the connection string is ASCII: a high byte has no decoding
        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010000" + rootHex + "0100" + "80"), out _));
        Assert.False(BlobTicketCodec.TryRead(Convert.FromHexString("010000" + rootHex + "0200" + "8041"), out _));
    }

    [Fact]
    public void Ticket_LegacyParserLeniency_IsPinnedAsDivergence()
    {
        // Two forms the legacy BlobTicket parser accepts and this codec rejects:
        // unknown flag bits (silently ignored before) and non-UTF-8 names (decoded
        // to U+FFFD before). The legacy code stays untouched; these assertions
        // document the divergence instead of hiding it.
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

        List<byte> mojibake = [1, 0, 1, 0xC2]; // name is a lone lead byte
        mojibake.AddRange(SeqBytes(0, 32));
        mojibake.AddRange([(byte)csBytes.Length, 0]);
        mojibake.AddRange(csBytes);
        string text2 = "pinholeblob1:" + Pinhole.Base64Url.Encode([.. mojibake]);
        Assert.False(BlobTicketCodec.TryReadText(text2, out _));
        Assert.True(BlobTicket.TryParse(text2, out BlobTicket? parsed));
        Assert.Equal("\uFFFD", parsed!.Name); // the legacy decode is lossy, not strict
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

        // a max-size connection string has a text form longer than any parser accepts
        Assert.Throws<ArgumentException>(() => BlobTicketCodec.WriteText(value with { ConnectionString = new string('A', 65535) }));
    }

    // ------------------------------------------------------------------ manifest: round-trip + goldens

    [Fact]
    public void Manifest_RoundTrip_AndGoldenBytes()
    {
        // Byte-for-byte the vector committed in WireGoldenTests.Manifest_Encode_ExactLittleEndianBytes
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

        // content addressing: the re-encoded value is the identical byte string
        int again = ManifestCodec.Write(buffer, read);
        Assert.Equal(golden, buffer[..again]);

        // the empty manifest is six zero bytes
        int emptyWritten = ManifestCodec.Write(buffer, new ManifestValue("", []));
        Assert.Equal(6, emptyWritten);
        Assert.Equal(new byte[6], buffer[..emptyWritten]);
        Assert.True(ManifestCodec.TryRead(new byte[6], out ManifestValue emptyRead));
        Assert.Equal("", emptyRead.Name);
        Assert.Empty(emptyRead.Entries);
    }

    // ------------------------------------------------------------------ manifest: differential

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

            // my decode of the legacy bytes == the legacy decode of them
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

            // BLAKE3 hashes these bytes into the ticket root: re-encode is identical
            int again = ManifestCodec.Write(buffer, mine);
            Assert.Equal(legacy, buffer[..again]);
        }
    }

    // ------------------------------------------------------------------ manifest: rejections

    [Fact]
    public void Manifest_RejectsNonCanonicalForms()
    {
        byte[] valid = Convert.FromHexString(
            "0100" + "6E"                       // nameLen 1, "n"
            + "01000000"                        // entry count 1
            + "0100" + "70"                     // pathLen 1, "p"
            + "0100000000000000"                // size 1
            + Convert.ToHexString(SeqBytes(0, 32)));

        Assert.False(ManifestCodec.TryRead([.. valid, 0], out _)); // trailing byte
        Assert.False(ManifestCodec.TryRead(valid[..^10], out _)); // truncated mid-entry
        Assert.False(ManifestCodec.TryRead([], out _));
        Assert.False(ManifestCodec.TryRead(new byte[5], out _));

        byte[] negative = (byte[])valid.Clone();
        Array.Fill(negative, (byte)0xFF, 10, 8); // size = -1
        Assert.False(ManifestCodec.TryRead(negative, out _));

        byte[] mojibake = (byte[])valid.Clone();
        mojibake[9] = 0xC2; // path is a lone lead byte: invalid UTF-8
        Assert.False(ManifestCodec.TryRead(mojibake, out _));
        (string _, List<Manifest.Entry> lenient) = Manifest.Decode(mojibake); // legacy accepts, lossily
        Assert.Equal("\uFFFD", lenient[0].Path);

        byte[] lyingCount = (byte[])valid.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(lyingCount.AsSpan(3), 1000); // claims 1000 entries, one present
        Assert.False(ManifestCodec.TryRead(lyingCount, out _));
        Assert.Throws<FormatException>(() => Manifest.Decode(lyingCount));

        byte[] lyingName = (byte[])valid.Clone();
        lyingName[0] = 0xFF;
        lyingName[1] = 0xFF; // nameLen claims 65535 bytes
        Assert.False(ManifestCodec.TryRead(lyingName, out _));

        byte[] lyingPath = (byte[])valid.Clone();
        BinaryPrimitives.WriteUInt16LittleEndian(lyingPath.AsSpan(7), 500); // pathLen claims 500 bytes
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

    // ------------------------------------------------------------------ frame: round-trip + goldens

    [Fact]
    public void Frame_Constants_MatchBlobWire()
    {
        Assert.Equal(BlobWire.TypeHello, BlobFrameCodec.TypeHello);
        Assert.Equal(BlobWire.TypeHead, BlobFrameCodec.TypeHead);
        Assert.Equal(BlobWire.TypeReq, BlobFrameCodec.TypeReq);
        Assert.Equal(BlobWire.TypeChunk, BlobFrameCodec.TypeChunk);
        Assert.Equal(BlobWire.TypeBye, BlobFrameCodec.TypeBye);
        Assert.Equal(BlobWire.TypeWelcome, BlobFrameCodec.TypeWelcome);
        Assert.Equal(BlobWire.ProtocolVersion, BlobFrameCodec.ProtocolVersion);
        Assert.Equal(BlobWire.MaxChunkData, BlobFrameCodec.MaxChunkData);
        Assert.Equal(BlobWire.MaxRequestCount, BlobFrameCodec.MaxRequestCount);
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

        // every golden parses identically on both codecs, and views expose the fields
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

        // v1: empty body, no session id
        Assert.True(BlobFrameCodec.TryParse(buffer[..BlobFrameCodec.HelloV1Length], out BlobFrameView v1));
        Assert.Equal(1, v1.Version);
        Assert.True(v1.SessionId.IsEmpty);
        Assert.True(BlobWire.Frame.TryParse(buffer[..BlobFrameCodec.HelloV1Length], out BlobWire.Frame f1));
        Assert.Equal(1, f1.Version);
        Assert.Null(f1.SessionId);

        // v2: a raw 32-byte session id, no version byte
        sid.CopyTo(buffer.AsSpan(9));
        Assert.True(BlobFrameCodec.TryParse(buffer[..BlobFrameCodec.HelloV2Length], out BlobFrameView v2));
        Assert.Equal(2, v2.Version);
        Assert.Equal(sid, v2.SessionId.ToArray());

        // v3 (current): version byte 3 then the session id
        byte[] v3 = BlobWire.Hello(5, sid);
        Assert.True(BlobFrameCodec.TryParse(v3, out BlobFrameView v3View));
        Assert.Equal(BlobFrameCodec.ProtocolVersion, v3View.Version);
        Assert.Equal(sid, v3View.SessionId.ToArray());

        // 33-byte bodies with a version byte this protocol never spoke: reject
        foreach (byte bogus in new byte[] { 1, 2, 4, 255 })
        {
            byte[] tampered = [.. v3];
            tampered[9] = bogus;
            Assert.False(BlobFrameCodec.TryParse(tampered, out _), $"hello version {bogus}");
            Assert.False(BlobWire.Frame.TryParse(tampered, out _));
        }

        // lengths that are none of the three Hello forms
        Assert.False(BlobFrameCodec.TryParse([.. v3, 0], out _)); // 34-byte body
        Assert.False(BlobFrameCodec.TryParse(v3[..40], out _)); // 31-byte body
    }

    [Fact]
    public void Frame_RejectsNonCanonicalForms()
    {
        byte[] sid = SeqBytes(0, 32);
        byte[] cv = SeqBytes(0, 32);

        Assert.False(BlobFrameCodec.TryParse(new byte[8], out _)); // short header
        Assert.False(BlobFrameCodec.TryParse([0, .. new byte[8]], out _)); // unknown types
        Assert.False(BlobFrameCodec.TryParse([7, .. new byte[8]], out _));
        Assert.False(BlobFrameCodec.TryParse([255, .. new byte[8]], out _));

        // Head: TotalChunks must be exactly ceil(TotalBytes / 1024); negatives reject
        foreach ((long totalBytes, long totalChunks) in new[] { (2048L, 1L), (0L, 1L), (1024L, 2L), (1025L, 1L), (-1L, 0L) })
        {
            Assert.False(BlobFrameCodec.TryParse(BlobWire.Head(1, totalBytes, totalChunks), out _), $"({totalBytes}, {totalChunks})");
        }

        foreach ((long totalBytes, long totalChunks) in new[] { (0L, 0L), (1L, 1L), (1023L, 1L), (1024L, 1L), (1025L, 2L) })
        {
            Assert.True(BlobFrameCodec.TryParse(BlobWire.Head(1, totalBytes, totalChunks), out _), $"({totalBytes}, {totalChunks})");
        }

        // Req: Count in [1, 64], StartChunk >= 0
        Assert.False(BlobFrameCodec.TryParse(BlobWire.Request(1, 0, 0), out _));
        Assert.False(BlobFrameCodec.TryParse(BlobWire.Request(1, 0, 65), out _));
        Assert.False(BlobFrameCodec.TryParse(BlobWire.Request(1, -1, 1), out _));
        Assert.True(BlobFrameCodec.TryParse(BlobWire.Request(1, 0, 1), out _));

        // Chunk: 1..1024 data bytes, Index >= 0
        Assert.False(BlobFrameCodec.TryParse(BlobWire.Chunk(1, 0, cv, new byte[0]), out _));
        Assert.False(BlobFrameCodec.TryParse(BlobWire.Chunk(1, 0, cv, new byte[1025]), out _));
        Assert.False(BlobFrameCodec.TryParse(BlobWire.Chunk(1, -1, cv, new byte[1]), out _));
        Assert.True(BlobFrameCodec.TryParse(BlobWire.Chunk(1, 0, cv, new byte[1024]), out _));
        Assert.True(BlobFrameCodec.TryParse(BlobWire.Chunk(1, long.MaxValue, cv, [1]), out _));

        // Welcome: exactly 114 body bytes with leading version byte 3
        byte[] welcome = BlobWire.Welcome(1, sid, sid, new byte[49]);
        byte[] tampered = [.. welcome];
        tampered[9] = 1;
        Assert.False(BlobFrameCodec.TryParse(tampered, out _));
        Assert.False(BlobFrameCodec.TryParse(welcome[..^1], out _));
        Assert.False(BlobFrameCodec.TryParse([.. welcome, 0], out _));

        // Bye carries nothing
        Assert.False(BlobFrameCodec.TryParse([BlobFrameCodec.TypeBye, .. Be64(1), 0], out _));
    }

    [Fact]
    public void Frame_Writers_ThrowOnProgrammerError()
    {
        byte[] buffer = new byte[BlobFrameCodec.ChunkMaxLength];
        byte[] sid = SeqBytes(0, 32);

        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteHello(buffer, 1, sid[..31]));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteHello(new byte[41], 1, sid));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteWelcome(buffer, 1, sid, sid[..31], new byte[49]));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteWelcome(buffer, 1, sid, sid, new byte[48]));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteBye(new byte[8], 1));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteHead(buffer, 1, 2048, 1)); // lying chunk count
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteHead(buffer, 1, -1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteRequest(buffer, 1, 0, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteRequest(buffer, 1, 0, 65));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteRequest(buffer, 1, -1, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteChunk(buffer, 1, -1, sid, [1]));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteChunk(buffer, 1, 0, sid[..31], [1]));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteChunk(buffer, 1, 0, sid, []));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlobFrameCodec.WriteChunk(buffer, 1, 0, sid, new byte[1025]));
        Assert.Throws<ArgumentException>(() => BlobFrameCodec.WriteChunk(new byte[49], 1, 0, sid, [1]));
    }

    // ------------------------------------------------------------------ frame: differential

    [Fact]
    public void Frame_Differential_MatchesBlobWireBuildersAndParser()
    {
        var rng = new Random(0xF7A11);
        byte[] buffer = new byte[BlobFrameCodec.ChunkMaxLength];
        for (int i = 0; i < 3_000; i++)
        {
            byte[] wire = RandomFrameWire(rng); // includes the two legacy Hello forms

            Assert.True(BlobWire.Frame.TryParse(wire, out BlobWire.Frame legacy));
            Assert.True(BlobFrameCodec.TryParse(wire, out BlobFrameView view));
            AssertFramesEqual(view, legacy);

            // for every frame the current writers can emit, the bytes come out identical
            if (view.Type == BlobFrameCodec.TypeHello && wire.Length != BlobFrameCodec.HelloV3Length)
            {
                continue; // legacy receive-only Hello forms have no writer, by design
            }

            int w = view.Type switch
            {
                BlobFrameCodec.TypeHello => BlobFrameCodec.WriteHello(buffer, view.Stream, view.SessionId),
                BlobFrameCodec.TypeWelcome => BlobFrameCodec.WriteWelcome(buffer, view.Stream, view.SessionId,
                    view.ProviderNonce, view.SealedHead),
                BlobFrameCodec.TypeBye => BlobFrameCodec.WriteBye(buffer, view.Stream),
                BlobFrameCodec.TypeHead => BlobFrameCodec.WriteHead(buffer, view.Stream, view.TotalBytes, view.TotalChunks),
                BlobFrameCodec.TypeReq => BlobFrameCodec.WriteRequest(buffer, view.Stream, view.StartChunk, view.Count),
                _ => BlobFrameCodec.WriteChunk(buffer, view.Stream, view.Index, view.ChunkCv, view.ChunkData),
            };
            Assert.Equal(wire, buffer[..w]);
        }
    }

    // ------------------------------------------------------------------ totality fuzz across all three codecs

    [Fact]
    public void AllCodecs_TotalityFuzz_200KInputs_NeverThrowsOrAcceptsOutOfRange()
    {
        var rng = new Random(0x5EED_0001);
        byte[] ticketScratch = new byte[BlobTicketCodec.MaxBinaryLength];
        byte[] manifestScratch = new byte[8192];
        byte[] frameScratch = new byte[BlobFrameCodec.ChunkMaxLength];
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

        // one ticket, exactly one encoding: re-encoding what parsed is the input
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

        // content addressing: the re-encoded manifest is the identical byte string
        int n = ManifestCodec.Write(reencode, read);
        Assert.True(input.SequenceEqual(reencode.AsSpan(0, n)));

        // one-directional differential: everything this codec accepts, the legacy
        // decoder accepts with the same values (the reverse does not hold: it is lenient)
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
            case 0: // raw random bytes, sometimes with a real frame type byte
            {
                int len = rng.Next(0, 128);
                rng.NextBytes(mutation.AsSpan(0, len));
                if (len >= 9 && rng.Next(2) == 0)
                {
                    mutation[0] = (byte)(1 + rng.Next(6));
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

        // acceptance is byte-for-byte identical to the existing parser
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
        Assert.True(view.Version is 0 or 1 or 2 or BlobFrameCodec.ProtocolVersion);
        Assert.True(view.ChunkData.Length <= BlobFrameCodec.MaxChunkData);
        Assert.True(view.SealedHead.Length is 0 or BlobFrameCodec.SealedHeadLength);
        Assert.True(view.SessionId.Length is 0 or BlobFrameCodec.SessionIdLength);
        Assert.True(view.ProviderNonce.Length is 0 or BlobFrameCodec.SessionIdLength);
    }
}
