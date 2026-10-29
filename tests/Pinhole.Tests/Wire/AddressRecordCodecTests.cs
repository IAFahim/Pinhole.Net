using System.Buffers.Binary;
using System.Net;
using Pinhole;
using Pinhole.Wire;
using Xunit;

namespace Pinhole.Tests.Wire;

public sealed class AddressRecordCodecTests
{

    private const string GoldenSignedHex =
        "0108070605040302016106F86AA1C86018EB49133492B1E3B99FCCCF8CE782210631D35ED00462EDD8"
        + "112233445566778800D2496B000000000104CB0071070D96"
        + "58AF45AAF9905A1B79F91D6BFDF458F0D242195B253DA1122BE250F7FB720F03AC7A00A5B7E40B8073FBD2F049FB95764A5CCEFDEC23A053C2F679D512FB2A0D";

    private const string GoldenV1BodyHex =
        "0108070605040302016106F86AA1C86018EB49133492B1E3B99FCCCF8CE782210631D35ED00462EDD8"
        + "112233445566778800D2496B000000000104CB0071070D96";

    private const string GoldenV2BodyHex =
        "021032547698BADCFE000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
        + "0100000000000000FFFFFFFFFFFFFF7F0204C000020100011020010DB8000000000000000000000001FFFF"
        + "01100000000000000000000000000000000101BB";

    [Fact]
    public void Golden_CommittedSignedVector_FramesAndReserializesByteExact()
    {
        byte[] golden = Convert.FromHexString(GoldenSignedHex);

        RelayIdentity identity = Identity(1);
        var record = new AddressRecord
        {
            PeerId = 0x0102030405060708,
            EndpointKey = identity.PublicKey,
            Sequence = 0x8877665544332211,
            ExpiresAtUtc = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
            Endpoints = [new IPEndPoint(IPAddress.Parse("203.0.113.7"), 3478)],
        };
        Assert.Equal(golden, record.EncodeSigned(identity));

        Assert.True(AddressRecord.TryParseVerified(golden, record.PeerId, identity.PublicKey,
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), out _));

        Assert.True(AddressRecordCodec.TryReadSigned(golden, out SignedAddressRecord signed, out int consumed));
        Assert.Equal(golden.Length, consumed);
        Assert.Equal(65 + AddressRecordCodec.SignatureLength, golden.Length);
        Assert.Equal(0x0102030405060708UL, signed.Body.PeerId);
        Assert.True(signed.Body.EndpointKey.AsSpan().SequenceEqual(identity.PublicKey));
        Assert.Equal(0x8877665544332211UL, signed.Body.Sequence);
        Assert.Equal(1_800_000_000L, signed.Body.ExpiresAtUnixSeconds);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.7"), 3478), signed.Body.Endpoints.Single());
        Assert.Empty(signed.Body.RelayedEndpoints);
        Assert.True(signed.Signature.AsSpan().SequenceEqual(golden[^AddressRecordCodec.SignatureLength..]));

        Span<byte> rewrite = stackalloc byte[AddressRecordCodec.MaxEncodedLength];
        int written = AddressRecordCodec.WriteBody(signed.Body, rewrite);
        Assert.Equal(golden.Length - AddressRecordCodec.SignatureLength, written);
        Assert.True(rewrite[..written].SequenceEqual(golden.AsSpan()[..^AddressRecordCodec.SignatureLength]));
    }

    [Fact]
    public void Body_GoldenVectors_DecodeExactFieldsAndReencodeIdentically()
    {
        byte[] v1 = Convert.FromHexString(GoldenV1BodyHex);
        byte[] v2 = Convert.FromHexString(GoldenV2BodyHex);
        byte[] minimal = Convert.FromHexString(
            "01" + "0000000000000000" + new string('0', 64) + "0000000000000000" + "0000000000000000" + "00");

        Assert.Equal(65, v1.Length);
        Assert.Equal(104, v2.Length);
        Assert.Equal(AddressRecordCodec.MinimumBodyLength, minimal.Length);

        Assert.True(AddressRecordCodec.TryReadBody(v1, out AddressRecordBody body1, out int consumed1));
        Assert.Equal(v1.Length, consumed1);
        Assert.Equal(0x0102030405060708UL, body1.PeerId);
        Assert.True(body1.EndpointKey.AsSpan().SequenceEqual(Identity(1).PublicKey));
        Assert.Equal(0x8877665544332211UL, body1.Sequence);
        Assert.Equal(1_800_000_000L, body1.ExpiresAtUnixSeconds);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.7"), 3478), body1.Endpoints.Single());
        Assert.Empty(body1.RelayedEndpoints);

        Assert.True(AddressRecordCodec.TryReadBody(v2, out AddressRecordBody body2, out int consumed2));
        Assert.Equal(v2.Length, consumed2);
        Assert.Equal(0xFEDCBA9876543210UL, body2.PeerId);
        Assert.True(body2.EndpointKey.AsSpan().SequenceEqual(Key(0)));
        Assert.Equal(1UL, body2.Sequence);
        Assert.Equal(long.MaxValue, body2.ExpiresAtUnixSeconds);
        Assert.Equal(
        [
            new IPEndPoint(IPAddress.Parse("192.0.2.1"), 1),
            new IPEndPoint(IPAddress.Parse("2001:db8::1"), 65535),
        ], body2.Endpoints);
        Assert.Equal(new[] { new IPEndPoint(IPAddress.Parse("::1"), 443) }, body2.RelayedEndpoints);

        Assert.True(AddressRecordCodec.TryReadBody(minimal, out AddressRecordBody body3, out int consumed3));
        Assert.Equal(minimal.Length, consumed3);
        Assert.Equal(0UL, body3.PeerId);
        Assert.Equal(0UL, body3.Sequence);
        Assert.Equal(0L, body3.ExpiresAtUnixSeconds);
        Assert.Empty(body3.Endpoints);
        Assert.Empty(body3.RelayedEndpoints);

        Span<byte> rewrite = stackalloc byte[AddressRecordCodec.MaxEncodedLength];
        foreach (byte[] golden in new[] { v1, v2, minimal })
        {
            Assert.True(AddressRecordCodec.TryReadBody(golden, out AddressRecordBody body, out _));
            int written = AddressRecordCodec.WriteBody(body, rewrite);
            Assert.Equal(golden.Length, written);
            Assert.True(rewrite[..written].SequenceEqual(golden));
        }
    }

    [Fact]
    public void RoundTrip_Matrix_WriteThenReadReproducesFieldsAndBytes()
    {
        var rng = new Random(0xA11CE5);
        byte[] buffer = new byte[AddressRecordCodec.MaxEncodedLength];
        byte[] again = new byte[AddressRecordCodec.MaxEncodedLength];
        ulong[] peerIds = [0, 1, 0x0102030405060708, ulong.MaxValue];
        long[] expiries =
        [
            long.MinValue, -62135596801, -62135596800, -1, 0, 1,
            253402300799, 253402300800, long.MaxValue - 1, long.MaxValue,
        ];

        foreach (ulong peerId in peerIds)
        foreach (long expiry in expiries)
        foreach (int relayedCount in new[] { 0, 1, 4 })
        {
            int directCount = relayedCount == 1 ? AddressRecordCodec.MaxDirectEndpoints : 1;
            RoundTrip(buffer, again,
                new AddressRecordBody(peerId, Key(0x21), ulong.MaxValue, expiry,
                    RandomEndpoints(rng, directCount), RandomEndpoints(rng, relayedCount)),
                $"peer={peerId} expiry={expiry} relayed={relayedCount}");
        }

        var mapped = new IPEndPoint(new IPAddress([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4]), 65535);
        RoundTrip(buffer, again,
            new AddressRecordBody(1, Key(0x42), 1, 1, [new IPEndPoint(IPAddress.Loopback, 0), mapped], []),
            "mapped/port edges");

        static void RoundTrip(byte[] buffer, byte[] again, in AddressRecordBody body, string context)
        {
            int written = AddressRecordCodec.WriteBody(body, buffer);
            Assert.True(AddressRecordCodec.TryReadBody(buffer.AsSpan(0, written), out AddressRecordBody decoded, out int consumed), context);
            Assert.Equal(written, consumed);
            Assert.Equal(body.PeerId, decoded.PeerId);
            Assert.True(decoded.EndpointKey.AsSpan().SequenceEqual(body.EndpointKey), context);
            Assert.Equal(body.Sequence, decoded.Sequence);
            Assert.Equal(body.ExpiresAtUnixSeconds, decoded.ExpiresAtUnixSeconds);
            Assert.Equal(body.Endpoints, decoded.Endpoints);
            Assert.Equal(body.RelayedEndpoints, decoded.RelayedEndpoints);

            Assert.Equal(written, AddressRecordCodec.WriteBody(decoded, again));
            Assert.True(again.AsSpan(0, written).SequenceEqual(buffer.AsSpan(0, written)), context);
        }
    }

    [Fact]
    public void MaxEncodedLength_IsExactWorstCase()
    {
        IPEndPoint[] direct = Enumerable.Range(0, AddressRecordCodec.MaxDirectEndpoints)
            .Select(i => new IPEndPoint(IPAddress.Parse($"2001:db8::{i + 1:x}"), i)).ToArray();
        IPEndPoint[] relayed = Enumerable.Range(0, AddressRecordCodec.MaxRelayedEndpoints)
            .Select(i => new IPEndPoint(IPAddress.Parse($"2001:db8::{i + 101:x}"), i)).ToArray();
        var body = new AddressRecordBody(ulong.MaxValue, Key(0), ulong.MaxValue, long.MaxValue, direct, relayed);

        byte[] tooSmall = new byte[AddressRecordCodec.MaxEncodedLength - 1];
        Assert.Throws<ArgumentException>(() => AddressRecordCodec.WriteBody(body, tooSmall));

        byte[] exact = new byte[AddressRecordCodec.MaxEncodedLength];
        Assert.Equal(AddressRecordCodec.MaxEncodedLength, AddressRecordCodec.WriteBody(body, exact));
        Assert.True(AddressRecordCodec.TryReadBody(exact, out AddressRecordBody decoded, out int consumed));
        Assert.Equal(AddressRecordCodec.MaxEncodedLength, consumed);
        Assert.Equal(AddressRecordCodec.MaxDirectEndpoints, decoded.Endpoints.Length);
        Assert.Equal(AddressRecordCodec.MaxRelayedEndpoints, decoded.RelayedEndpoints.Length);
    }

    [Fact]
    public void TotalityFuzz_NeverThrows_AcceptImpliesExactReencode()
    {
        var rng = new Random(0x5EEDC0DE);
        byte[] scratch = new byte[AddressRecordCodec.MaxEncodedLength + AddressRecordCodec.SignatureLength + 16];
        byte[] bodyBuffer = new byte[AddressRecordCodec.MaxEncodedLength];
        byte[] rewrite = new byte[AddressRecordCodec.MaxEncodedLength];
        bool hostileExpiry = false;

        for (int i = 0; i < 220_000; i++)
        {
            hostileExpiry = i % 997 == 0;
            switch (i % 6)
            {
                case 0:
                {
                    int len = rng.Next(scratch.Length + 1);
                    rng.NextBytes(scratch.AsSpan(0, len));
                    ExerciseBody(scratch.AsSpan(0, len), rewrite);
                    ExerciseSigned(scratch.AsSpan(0, len), rewrite);
                    break;
                }
                case 1:
                {
                    int written = AddressRecordCodec.WriteBody(RandomBody(rng, hostileExpiry), bodyBuffer);
                    bodyBuffer.AsSpan(0, written).CopyTo(scratch);
                    Array.Clear(scratch, written, scratch.Length - written);
                    foreach (int _ in Enumerable.Range(0, 1 + rng.Next(3)))
                    {
                        scratch[rng.Next(written)] ^= (byte)(1 << rng.Next(8));
                    }
                    ExerciseBody(scratch.AsSpan(0, written), rewrite);
                    break;
                }
                case 2:
                {
                    int written = AddressRecordCodec.WriteBody(RandomBody(rng, hostileExpiry), bodyBuffer);
                    ExerciseBody(bodyBuffer.AsSpan(0, rng.Next(written + 1)), rewrite);
                    break;
                }
                case 3:
                {
                    int written = AddressRecordCodec.WriteBody(RandomBody(rng, hostileExpiry), bodyBuffer);
                    bodyBuffer.AsSpan(0, written).CopyTo(scratch);
                    int extra = 1 + rng.Next(8);
                    rng.NextBytes(scratch.AsSpan(written, extra));
                    ExerciseBody(scratch.AsSpan(0, written + extra), rewrite);
                    break;
                }
                case 4:
                {
                    int written = AddressRecordCodec.WriteBody(RandomBody(rng, hostileExpiry), bodyBuffer);
                    bodyBuffer.AsSpan(0, written).CopyTo(scratch);
                    rng.NextBytes(scratch.AsSpan(written, AddressRecordCodec.SignatureLength));
                    int total = written + AddressRecordCodec.SignatureLength;
                    scratch[rng.Next(total)] ^= (byte)(1 << rng.Next(8));
                    ExerciseSigned(scratch.AsSpan(0, total), rewrite);
                    break;
                }
                default:
                {
                    int written = AddressRecordCodec.WriteBody(RandomBody(rng, hostileExpiry), bodyBuffer);
                    bodyBuffer.AsSpan(0, written).CopyTo(scratch);
                    rng.NextBytes(scratch.AsSpan(written, AddressRecordCodec.SignatureLength));
                    int keep = rng.Next(written + AddressRecordCodec.SignatureLength);
                    ExerciseSigned(scratch.AsSpan(0, keep), rewrite);
                    break;
                }
            }
        }
    }

    [Fact]
    public void Rejects_NonCanonicalBodies()
    {
        byte[] v1 = Convert.FromHexString(GoldenV1BodyHex);
        byte[] v2 = Convert.FromHexString(GoldenV2BodyHex);

        List<(string Name, byte[] Bytes)> cases =
        [
            ("empty input", []),
            ("version 0", Patch(v1, 0, 0x00)),
            ("unknown version 3", Patch(v1, 0, 0x03)),
            ("version 255", Patch(v1, 0, 0xFF)),
            ("version with stray high bits", Patch(v1, 0, 0x82)),
            ("direct count over cap", Patch(v1, 57, AddressRecordCodec.MaxDirectEndpoints + 1)),
            ("direct count 255", Patch(v1, 57, 255)),
            ("endpoint family 0", Patch(v1, 58, 0)),
            ("endpoint family 5", Patch(v1, 58, 5)),
            ("endpoint family 6", Patch(v1, 58, 6)),
            ("family 16 claimed over an IPv4 payload", Patch(v1, 58, 16)),
            ("endpoint missing port", v1[..^1]),
            ("endpoint cut inside address", v1[..61]),
            ("endpoint family byte missing", v1[..58]),
            ("trailing byte after v1 body", [.. v1, 0x00]),
            ("trailing byte after v2 body", [.. v2, 0x00]),
            ("v2 relayed count 0 (empty relayed list)", Patch(v2, 84, 0)),
            ("v2 relayed count over cap", Patch(v2, 84, AddressRecordCodec.MaxRelayedEndpoints + 1)),
            ("v2 relayed count byte missing", v2[..84]),
            ("v2 relayed endpoint truncated", v2[..85]),
        ];
        for (int len = 0; len < AddressRecordCodec.MinimumBodyLength; len++)
        {
            cases.Add(($"header truncated to {len} bytes", v1[..len]));
        }

        foreach ((string name, byte[] bytes) in cases)
        {
            Assert.False(AddressRecordCodec.TryReadBody(bytes, out _, out int consumed), name);
            Assert.Equal(0, consumed);
        }
    }

    [Fact]
    public void Rejects_NonCanonicalSignatureFraming()
    {
        byte[] v1 = Convert.FromHexString(GoldenV1BodyHex);
        byte[] signature = Enumerable.Repeat((byte)0xAB, AddressRecordCodec.SignatureLength).ToArray();

        Assert.False(AddressRecordCodec.TryReadSigned([.. v1, .. signature[..^1]], out _, out int consumed));
        Assert.Equal(0, consumed);

        Assert.False(AddressRecordCodec.TryReadSigned([.. v1, .. signature, 0xAA], out _, out consumed));
        Assert.Equal(0, consumed);

        Assert.False(AddressRecordCodec.TryReadSigned(
            new byte[AddressRecordCodec.MinimumBodyLength + AddressRecordCodec.SignatureLength - 1], out _, out consumed));
        Assert.Equal(0, consumed);

        Assert.True(AddressRecordCodec.TryReadSigned([.. v1, .. signature], out SignedAddressRecord framed, out consumed));
        Assert.Equal(v1.Length + AddressRecordCodec.SignatureLength, consumed);
        Assert.True(framed.Signature.AsSpan().SequenceEqual(signature));
    }

    [Fact]
    public void Expiry_HostileRawValues_DecodeTotal_NeverConvert()
    {

        long[] hostile =
        [
            long.MinValue, long.MinValue + 1, -62135596801, -62135596800, -1, 0,
            253402300799, 253402300800, long.MaxValue - 1, long.MaxValue,
        ];
        byte[] buffer = new byte[AddressRecordCodec.MaxEncodedLength];
        RelayIdentity identity = Identity(0x77);
        byte[] realWire = new AddressRecord
        {
            PeerId = 7,
            EndpointKey = identity.PublicKey,
            Sequence = 7,
            ExpiresAtUtc = DateTimeOffset.FromUnixTimeSeconds(2_000_000_000),
            Endpoints = [new IPEndPoint(IPAddress.Loopback, 7)],
        }.EncodeSigned(identity);

        foreach (long value in hostile)
        {
            var body = new AddressRecordBody(7, Key(0x77), 7, value, [new IPEndPoint(IPAddress.Loopback, 7)], []);
            int written = AddressRecordCodec.WriteBody(body, buffer);
            Assert.True(AddressRecordCodec.TryReadBody(buffer.AsSpan(0, written), out AddressRecordBody decoded, out _));
            Assert.Equal(value, decoded.ExpiresAtUnixSeconds);

            byte[] wire = new byte[written + AddressRecordCodec.SignatureLength];
            buffer.AsSpan(0, written).CopyTo(wire);
            Assert.True(AddressRecordCodec.TryReadSigned(wire, out SignedAddressRecord signed, out _));
            Assert.Equal(value, signed.Body.ExpiresAtUnixSeconds);

            byte[] forged = (byte[])realWire.Clone();
            BinaryPrimitives.WriteInt64LittleEndian(forged.AsSpan(49, 8), value);
            Assert.False(AddressRecord.TryParseVerified(forged, 7, identity.PublicKey,
                DateTimeOffset.FromUnixTimeSeconds(1_000_000_000), out _));
        }
    }

    [Fact]
    public void Write_ThrowsOnlyOnProgrammerError()
    {
        byte[] exact = new byte[AddressRecordCodec.MaxEncodedLength];
        IPEndPoint[] seventeen = Enumerable.Range(0, AddressRecordCodec.MaxDirectEndpoints + 1)
            .Select(i => new IPEndPoint(IPAddress.Loopback, i)).ToArray();
        IPEndPoint[] five = Enumerable.Range(0, AddressRecordCodec.MaxRelayedEndpoints + 1)
            .Select(i => new IPEndPoint(IPAddress.Loopback, i)).ToArray();
        var good = new AddressRecordBody(1, Key(0), 1, 1, [new IPEndPoint(IPAddress.Loopback, 1)], []);

        Assert.Throws<InvalidOperationException>(() => AddressRecordCodec.WriteBody(good with { EndpointKey = [] }, exact));
        Assert.Throws<InvalidOperationException>(() => AddressRecordCodec.WriteBody(good with { EndpointKey = new byte[31] }, exact));
        Assert.Throws<InvalidOperationException>(() => AddressRecordCodec.WriteBody(good with { EndpointKey = new byte[33] }, exact));
        Assert.Throws<InvalidOperationException>(() => AddressRecordCodec.WriteBody(good with { Endpoints = seventeen }, exact));
        Assert.Throws<InvalidOperationException>(() => AddressRecordCodec.WriteBody(good with { RelayedEndpoints = five }, exact));

        byte[] tiny = new byte[AddressRecordCodec.MinimumBodyLength - 1];
        Assert.Throws<ArgumentException>(() => AddressRecordCodec.WriteBody(good, tiny));
    }

    [Fact]
    public void Differential_LegacySignedRecords_DecodeMatchAndReserializeByteExact()
    {
        var rng = new Random(0xD1FFE0);
        byte[] rewrite = new byte[AddressRecordCodec.MaxEncodedLength];
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

        for (int i = 0; i < 40; i++)
        {
            RelayIdentity identity = Identity(i + 1);
            var record = new AddressRecord
            {
                PeerId = 0x1000UL + (ulong)i,
                EndpointKey = identity.PublicKey,
                Sequence = (ulong)rng.NextInt64(),
                ExpiresAtUtc = DateTimeOffset.FromUnixTimeSeconds(2_000_000_000 + i),
                Endpoints = RandomEndpoints(rng, rng.Next(0, 5)),
                RelayedEndpoints = i % 3 == 0 ? RandomEndpoints(rng, 1 + rng.Next(4)) : [],
            };
            byte[] wire = record.EncodeSigned(identity);

            Assert.True(AddressRecord.TryParseVerified(wire, record.PeerId, identity.PublicKey, now, out AddressRecord? legacy),
                $"i={i}");

            Assert.True(AddressRecordCodec.TryReadSigned(wire, out SignedAddressRecord mine, out int consumed), $"i={i}");
            Assert.Equal(wire.Length, consumed);
            Assert.Equal(record.PeerId, mine.Body.PeerId);
            Assert.True(mine.Body.EndpointKey.AsSpan().SequenceEqual(identity.PublicKey), $"i={i}");
            Assert.Equal(record.Sequence, mine.Body.Sequence);
            Assert.Equal(record.ExpiresAtUtc.ToUnixTimeSeconds(), mine.Body.ExpiresAtUnixSeconds);
            Assert.Equal(record.Endpoints, mine.Body.Endpoints);
            Assert.Equal(record.RelayedEndpoints, mine.Body.RelayedEndpoints);
            Assert.True(mine.Signature.AsSpan().SequenceEqual(wire[^AddressRecordCodec.SignatureLength..]));

            int rewritten = AddressRecordCodec.WriteBody(mine.Body, rewrite);
            Assert.Equal(wire.Length - AddressRecordCodec.SignatureLength, rewritten);
            Assert.True(rewrite[..rewritten].SequenceEqual(wire.AsSpan()[..^AddressRecordCodec.SignatureLength]), $"i={i}");

            Assert.True(record.Encode().AsSpan().SequenceEqual(rewrite[..rewritten]), $"i={i}");
        }
    }

    [Fact]
    public void Differential_CanonicalWrittenBodies_AcceptedByLegacyVerifiedParser()
    {
        var rng = new Random(0xD1FF0F0);
        byte[] buffer = new byte[AddressRecordCodec.MaxEncodedLength];
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

        for (int i = 0; i < 25; i++)
        {
            RelayIdentity identity = Identity(0x40 + i);
            var body = new AddressRecordBody(
                0xABC0UL + (ulong)i,
                identity.PublicKey,
                (ulong)rng.NextInt64(),
                2_500_000_000 + i,
                RandomEndpoints(rng, rng.Next(0, 4)),
                i % 2 == 0 ? RandomEndpoints(rng, 1 + rng.Next(4)) : []);
            int written = AddressRecordCodec.WriteBody(body, buffer);

            byte[] wire = new byte[written + AddressRecordCodec.SignatureLength];
            buffer.AsSpan(0, written).CopyTo(wire);
            identity.SignBody(wire.AsSpan(0, written)).CopyTo(wire, written);

            Assert.True(AddressRecord.TryParseVerified(wire, body.PeerId, body.EndpointKey, now, out AddressRecord? legacy),
                $"i={i}");
            Assert.Equal(body.PeerId, legacy!.PeerId);
            Assert.True(legacy.EndpointKey.AsSpan().SequenceEqual(body.EndpointKey), $"i={i}");
            Assert.Equal(body.Sequence, legacy.Sequence);
            Assert.Equal(body.ExpiresAtUnixSeconds, legacy.ExpiresAtUtc.ToUnixTimeSeconds());
            Assert.Equal(body.Endpoints, legacy.Endpoints);
            Assert.Equal(body.RelayedEndpoints, legacy.RelayedEndpoints);
        }
    }

    [Fact]
    public void Differential_LegacyParserLeniency_V2EmptyRelayedList_CanonicalCodecRejects()
    {

        RelayIdentity identity = Identity(1);
        byte[] v1 = Convert.FromHexString(GoldenV1BodyHex);
        byte[] v2EmptyRelay = [.. v1];
        v2EmptyRelay[0] = 2;
        v2EmptyRelay = [.. v2EmptyRelay, 0];

        byte[] wire = [.. v2EmptyRelay, .. identity.SignBody(v2EmptyRelay)];
        Assert.True(AddressRecord.TryParseVerified(wire, 0x0102030405060708, identity.PublicKey,
            DateTimeOffset.FromUnixTimeSeconds(1_000_000_000), out AddressRecord? legacy));
        Assert.Empty(legacy!.RelayedEndpoints);

        Assert.False(AddressRecordCodec.TryReadBody(v2EmptyRelay, out _, out int consumed));
        Assert.Equal(0, consumed);
    }

    [Fact]
    public void Constants_AgreeWithLegacyAddressRecord()
    {
        Assert.Equal(AddressRecord.EndpointKeyLength, AddressRecordCodec.EndpointKeyLength);
        Assert.Equal(AddressRecord.SignatureLength, AddressRecordCodec.SignatureLength);
        Assert.Equal(AddressRecord.MaxEndpoints, AddressRecordCodec.MaxDirectEndpoints);
        Assert.Equal(AddressRecord.MaxRelayedEndpoints, AddressRecordCodec.MaxRelayedEndpoints);
        Assert.Equal(58 + 64, AddressRecordCodec.MinimumBodyLength + AddressRecordCodec.SignatureLength);
        Assert.Equal(439, AddressRecordCodec.MaxEncodedLength);
    }

    private static byte[] SeedBytes(int start) => Enumerable.Range(start, 32).Select(i => (byte)i).ToArray();

    private static byte[] Key(int start) => Enumerable.Range(start, 32).Select(i => (byte)i).ToArray();

    private static RelayIdentity Identity(int start) => new(EndpointIdentity.DeriveEndpointSeed(SeedBytes(start)));

    private static byte[] Patch(byte[] source, int index, byte value)
    {
        byte[] clone = (byte[])source.Clone();
        clone[index] = value;
        return clone;
    }

    private static AddressRecordBody RandomBody(Random rng, bool hostileExpiry) => new(
        (ulong)rng.NextInt64(),
        Key(rng.Next(256)),
        (ulong)rng.NextInt64(),
        hostileExpiry
            ? (rng.Next(2) == 0 ? long.MinValue : long.MaxValue)
            : SampleExpiry(rng),
        RandomEndpoints(rng, rng.Next(0, AddressRecordCodec.MaxDirectEndpoints + 1)),
        RandomEndpoints(rng, rng.Next(0, AddressRecordCodec.MaxRelayedEndpoints + 1)));

    private static long SampleExpiry(Random rng) =>
        rng.Next(64) == 0
            ? new[]
            {
                long.MinValue, long.MaxValue, -62135596801L, -62135596800L,
                253402300799L, 253402300800L, -1L, 0L,
            }[rng.Next(8)]
            : rng.NextInt64();

    private static IPEndPoint[] RandomEndpoints(Random rng, int count)
    {
        var endpoints = new IPEndPoint[count];
        for (int i = 0; i < count; i++)
        {
            endpoints[i] = RandomEndpoint(rng);
        }

        return endpoints;
    }

    private static IPEndPoint RandomEndpoint(Random rng)
    {
        byte[] address = new byte[16];
        rng.NextBytes(address);
        int family = rng.Next(2) == 0 ? 4 : 16;
        return new IPEndPoint(new IPAddress(address.AsSpan(0, family)), rng.Next(65536));
    }

    private static void ExerciseBody(ReadOnlySpan<byte> input, Span<byte> rewrite)
    {
        bool ok = AddressRecordCodec.TryReadBody(input, out AddressRecordBody body, out int consumed);
        if (!ok)
        {
            Assert.Equal(0, consumed);
            return;
        }

        Assert.Equal(input.Length, consumed);
        Assert.Equal(AddressRecordCodec.EndpointKeyLength, body.EndpointKey.Length);
        Assert.InRange(body.Endpoints.Length, 0, AddressRecordCodec.MaxDirectEndpoints);
        Assert.InRange(body.RelayedEndpoints.Length, 0, AddressRecordCodec.MaxRelayedEndpoints);
        if (input[0] == 2)
        {
            Assert.NotEmpty(body.RelayedEndpoints);
        }
        else
        {
            Assert.Empty(body.RelayedEndpoints);
        }

        int rewritten = AddressRecordCodec.WriteBody(body, rewrite);
        Assert.Equal(input.Length, rewritten);
        Assert.True(rewrite[..rewritten].SequenceEqual(input));
    }

    private static void ExerciseSigned(ReadOnlySpan<byte> input, Span<byte> rewrite)
    {
        bool ok = AddressRecordCodec.TryReadSigned(input, out SignedAddressRecord record, out int consumed);
        if (!ok)
        {
            Assert.Equal(0, consumed);
            return;
        }

        Assert.Equal(input.Length, consumed);
        Assert.Equal(AddressRecordCodec.SignatureLength, record.Signature.Length);
        Assert.True(record.Signature.AsSpan().SequenceEqual(input[^AddressRecordCodec.SignatureLength..]));

        ExerciseBody(input[..^AddressRecordCodec.SignatureLength], rewrite);
    }
}
