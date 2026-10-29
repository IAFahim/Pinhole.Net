using System.Net;
using System.Net.Sockets;
using System.Text;
using Pinhole;
using Pinhole.Wire;
using Xunit;

namespace Pinhole.Tests.Wire;

public sealed class ConnectionStringCodecTests
{
    private const string GoldenAHex = "010088776655443322110001047f0000019c4001";
    private const string GoldenBHex = "0201000000000000000001011000000000000000000000000000000001003502000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private const string GoldenCHex = "0303ffffffffffffffff020104080808080d960304010203040d9701750370773911111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222";
    private const string GoldenDHex = "01002a2a2a2a2a2a2a2a0001047f0000010001041368747470733a2f2f722e6578616d706c652f78cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    private const string GoldenEHex = "040588776655443322110001047f0000019c4001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f10abababababababababababababababab";
    private const string GoldenFHex = "040788776655443322110001047f0000019c4001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f222222222222222222222222222222222222222222222222222222222222222208cdcdcdcdcdcdcdcd";

    private const string GoldenAText = "pinhole1:AQCId2ZVRDMiEQABBH8AAAGcQAE";
    private const string GoldenBText = "pinhole1:AgEAAAAAAAAAAAEBEAAAAAAAAAAAAAAAAAAAAAEANQIAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHw";
    private const string GoldenCText = "pinhole1:AwP__________wIBBAgICAgNlgMEAQIDBA2XAXUDcHc5EREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg";
    private const string GoldenDText = "pinhole1:AQAqKioqKioqKgABBH8AAAEAAQQTaHR0cHM6Ly9yLmV4YW1wbGUveM3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3N";
    private const string GoldenEText = "pinhole1:BAWId2ZVRDMiEQABBH8AAAGcQAEAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHxCrq6urq6urq6urq6urq6ur";
    private const string GoldenFText = "pinhole1:BAeId2ZVRDMiEQABBH8AAAGcQAEAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiCM3Nzc3Nzc3N";

    [Fact]
    public void FixedVectors_PinTheByteFormat_AgainstTheReference()
    {
        CheckGolden(GoldenA(), GoldenAHex, GoldenAText);
        CheckGolden(GoldenB(), GoldenBHex, GoldenBText);
        CheckGolden(GoldenC(), GoldenCHex, GoldenCText);
        CheckGolden(GoldenD(), GoldenDHex, GoldenDText);
        CheckGolden(GoldenE(), GoldenEHex, GoldenEText);
        CheckGolden(GoldenF(), GoldenFHex, GoldenFText);
    }

    [Fact]
    public void RoundTrip_BoundaryValues_AgreeWithReference()
    {
        byte[] key = new byte[32];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i * 7 + 1);
        }

        List<ConnectionStringData> values =
        [
            new(0UL, WireNatHint.Unknown, [Direct(IPAddress.Any, 0)], null, null),
            new(ulong.MaxValue, WireNatHint.Symmetric, [Reflexive(IPAddress.IPv6Loopback, 65535)], null, null),
            new(0x4242424242424242UL, WireNatHint.Cone,
                [new CandidateData(WireCandidateKind.Relay, Endpoint(IPAddress.Loopback, 3478),
                    Endpoint(IPAddress.IPv6Loopback, 3479), "", "", null, null)],
                key, null),
            new(9UL, WireNatHint.Unknown,
                [
                    new CandidateData(WireCandidateKind.IrohRelay, Endpoint(IPAddress.Loopback, 1), null, null, null,
                        "https://r.example/" + new string('a', 46), new byte[32]),
                    new CandidateData(WireCandidateKind.DerpRelay, Endpoint(IPAddress.IPv6Loopback, 2), null, null, null,
                        "http://127.0.0.1:99/k", new byte[32]),
                ],
                key, (byte[])[.. key]),

            new(0x5566778899AABBCCUL, WireNatHint.Unknown, [Direct(IPAddress.Loopback, 7)], key, null, [0x5A]),
            new(0x5566778899AABBCDUL, WireNatHint.Cone, [Direct(IPAddress.Loopback, 8)], key, (byte[])[.. key],
                new byte[64]),
            AllFiveKinds(),
            MaxBodyValue(),
        ];

        foreach (ConnectionStringData value in values)
        {
            byte[] body = new byte[ConnectionStringCodec.MaxEncodedLength];
            int written = ConnectionStringCodec.Write(value, body);
            Assert.True(ConnectionStringCodec.TryRead(body.AsSpan(0, written), out ConnectionStringData read, out int consumed));
            Assert.Equal(written, consumed);
            AssertValuesEqual(value, read);

            Assert.True(ConnectionStringCodec.TryWrite(value, body, out int tryWritten));
            Assert.Equal(written, tryWritten);
            var oneShorter = new byte[Math.Max(0, written - 1)];
            Assert.False(ConnectionStringCodec.TryWrite(value, oneShorter, out _));

            string text = ConnectionStringCodec.Encode(value);
            Assert.True(text.Length <= ConnectionStringCodec.MaxStringLength);
            Assert.True(ConnectionStringCodec.TryParse(text, out ConnectionStringData fromText));
            AssertValuesEqual(value, fromText);
            char[] encoded = new char[ConnectionStringCodec.MaxStringLength];
            Assert.True(ConnectionStringCodec.TryEncodeText(value, encoded, out int charsWritten));
            Assert.Equal(text, new string(encoded, 0, charsWritten));

            var reference = ConnectionString.Parse(text);
            AssertMatchesReference(value, reference);
            Assert.Equal(text, reference.ToString());
        }

        ConnectionStringData max = MaxBodyValue();
        Span<byte> maxBody = stackalloc byte[ConnectionStringCodec.MaxEncodedLength];
        Assert.Equal(ConnectionStringCodec.MaxEncodedLength, ConnectionStringCodec.Write(max, maxBody));
        Assert.Equal(ConnectionStringCodec.MaxStringLength, ConnectionStringCodec.Encode(max).Length);
    }

    [Fact]
    public void WriteContract_ProgrammerErrorsThrow_TryVariantsDecline()
    {
        CandidateData good = Direct(IPAddress.Loopback, 80);
        CandidateData good2 = Direct(IPAddress.Loopback, 81);
        var buffer = new byte[ConnectionStringCodec.MaxEncodedLength];

        Assert.Throws<ArgumentNullException>(() => ConnectionStringCodec.Write(default, buffer));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown, [], null, null), buffer));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, (WireNatHint)9, [good], null, null), buffer));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown, [good], new byte[31], null), buffer));
        Assert.Throws<ArgumentException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown, [good], null, new byte[32]), buffer));
        Assert.Throws<ArgumentException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown, [good, good], null, null), buffer));

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown,
                [new CandidateData(WireCandidateKind.Relay, Endpoint(IPAddress.Loopback, 1), Endpoint(IPAddress.Loopback, 2), new string('u', 65), "p", null, null)], null, null), buffer));

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown,
                [new CandidateData((WireCandidateKind)9, Endpoint(IPAddress.Loopback, 1), null, null, null, null, null)], null, null), buffer));

        Assert.Throws<ArgumentException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown,
                [new CandidateData(WireCandidateKind.Relay, Endpoint(IPAddress.Loopback, 1), null, "u", "p", null, null)], null, null), buffer));

        Assert.Throws<ArgumentException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown,
                [new CandidateData(WireCandidateKind.IrohRelay, Endpoint(IPAddress.Loopback, 1), null, null, null, "http://relay.example/x", new byte[32])], null, null), buffer));
        Assert.Throws<ArgumentException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown,
                [new CandidateData(WireCandidateKind.IrohRelay, Endpoint(IPAddress.Loopback, 1), null, null, null, "https://r.example/x", new byte[31])], null, null), buffer));

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown,
                [new CandidateData(WireCandidateKind.Relay, Endpoint(IPAddress.Loopback, 1), Endpoint(IPAddress.Loopback, 2), "u\u00E9", "p", null, null)], null, null), buffer));

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown, [good], new byte[32], null, []), buffer));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown, [good], new byte[32], null, new byte[65]), buffer));
        Assert.Throws<ArgumentException>(() =>
            ConnectionStringCodec.Write(new ConnectionStringData(1, WireNatHint.Unknown, [good], null, null, new byte[16]), buffer));

        var value = new ConnectionStringData(1, WireNatHint.Unknown, [good, good2], null, null);
        int needed = ConnectionStringCodec.Write(value, buffer);
        Assert.Throws<ArgumentException>(() => ConnectionStringCodec.Write(value, buffer[..(needed - 1)]));
        Assert.False(ConnectionStringCodec.TryWrite(value, buffer[..(needed - 1)], out int written));
        Assert.Equal(0, written);
        Assert.False(ConnectionStringCodec.TryWrite(default, buffer, out _));
        Assert.False(ConnectionStringCodec.TryEncodeText(default, new char[8], out _));
    }

    [Fact]
    public void TotalityFuzz_BinaryTryRead_NeverThrowsOrReturnsOutOfRange()
    {
        var rng = new Random(unchecked((int)0xBADC0DE5));
        byte[][] valid =
        [
            Convert.FromHexString(GoldenCHex),
            Convert.FromHexString(GoldenDHex),
            Convert.FromHexString(GoldenEHex),
            Convert.FromHexString(GoldenFHex),
            .. Enumerable.Range(0, 8).Select(i => WriteValue(RandomValue(new Random(1000 + i)))),
        ];

        var scratch = new byte[ConnectionStringCodec.MaxEncodedLength + 16];
        for (int i = 0; i < 200_000; i++)
        {
            byte[] source = valid[rng.Next(valid.Length)];
            ReadOnlySpan<byte> input;
            switch (rng.Next(4))
            {
                case 0:
                {
                    int len = rng.Next(0, 700);
                    rng.NextBytes(scratch.AsSpan(0, len));
                    input = scratch.AsSpan(0, len);
                    break;
                }

                case 1:
                {
                    source.AsSpan().CopyTo(scratch);
                    int bit = rng.Next(source.Length * 8);
                    scratch[bit / 8] ^= (byte)(1 << (bit % 8));
                    input = scratch.AsSpan(0, source.Length);
                    break;
                }

                case 2:
                {
                    input = source.AsSpan(0, rng.Next(source.Length));
                    break;
                }

                default:
                {
                    source.AsSpan().CopyTo(scratch);
                    scratch[rng.Next(source.Length)] = (byte)rng.Next(256);
                    input = scratch.AsSpan(0, source.Length);
                    break;
                }
            }

            bool ok = ConnectionStringCodec.TryRead(input, out ConnectionStringData value, out int consumed);
            if (!ok)
            {
                Assert.Equal(0, consumed);
                Assert.Null(value.Candidates);
                continue;
            }

            Assert.Equal(input.Length, consumed);
            AssertInvariants(value);

            string text = "pinhole1:" + Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            Assert.True(ConnectionString.TryParse(text, out ConnectionString? reference), text);
            Assert.Equal(value.Candidates!.Length, reference!.Candidates.Count);
        }
    }

    [Fact]
    public void TotalityFuzz_TextTryParse_NeverThrowsOrReturnsOutOfRange()
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+=:/! .";
        var rng = new Random(unchecked((int)0xF00DBEEF));
        string[] valid =
        [
            GoldenAText,
            GoldenCText,
            GoldenDText,
            .. Enumerable.Range(0, 5).Select(i => ConnectionStringCodec.Encode(RandomValue(new Random(2000 + i)))),
        ];

        var scratch = new char[256];
        for (int i = 0; i < 100_000; i++)
        {
            string source = valid[rng.Next(valid.Length)];
            string text;
            switch (rng.Next(4))
            {
                case 0:
                {
                    int len = rng.Next(0, 80);
                    for (int j = 0; j < len; j++)
                    {
                        scratch[j] = alphabet[rng.Next(alphabet.Length)];
                    }

                    text = new string(scratch, 0, len);
                    if (rng.Next(2) == 0)
                    {
                        text = "pinhole1:" + text;
                    }

                    break;
                }

                case 1:
                {
                    var chars = source.ToCharArray();
                    chars[rng.Next(chars.Length)] = alphabet[rng.Next(alphabet.Length)];
                    text = new string(chars);
                    break;
                }

                case 2:
                {
                    text = source[..rng.Next(source.Length)];
                    break;
                }

                default:
                {
                    int at = rng.Next(source.Length + 1);
                    text = source[..at] + alphabet[rng.Next(alphabet.Length)] + source[at..];
                    break;
                }
            }

            if (!ConnectionStringCodec.TryParse(text, out ConnectionStringData value))
            {
                continue;
            }

            Assert.True(text.Length <= ConnectionStringCodec.MaxStringLength);
            AssertInvariants(value);
            Assert.True(ConnectionString.TryParse(text, out _));
            Assert.Equal(text, ConnectionStringCodec.Encode(value));
        }
    }

    [Fact]
    public void NonCanonicalBodies_AreRejected()
    {
        byte[] a = Convert.FromHexString(GoldenAHex);
        byte[] b = Convert.FromHexString(GoldenBHex);
        byte[] c = Convert.FromHexString(GoldenCHex);
        byte[] d = Convert.FromHexString(GoldenDHex);
        byte[] e = Convert.FromHexString(GoldenEHex);
        byte[] f = Convert.FromHexString(GoldenFHex);
        Assert.True(ConnectionStringCodec.TryRead(a, out _, out _));
        Assert.True(ConnectionStringCodec.TryRead(b, out _, out _));
        Assert.True(ConnectionStringCodec.TryRead(c, out _, out _));
        Assert.True(ConnectionStringCodec.TryRead(d, out _, out _));
        Assert.True(ConnectionStringCodec.TryRead(e, out _, out _));
        Assert.True(ConnectionStringCodec.TryRead(f, out _, out _));

        Reject(Patch(a, 0, 0));
        Reject(Patch(a, 0, 4));
        Reject(Patch(a, 0, 5));
        Reject(Patch(a, 0, 0xFF));

        Reject(Patch(a, 1, 1));
        Reject(Patch(a, 1, 3));
        Reject(Patch(b, 1, 0));
        Reject(Patch(b, 1, 3));
        Reject(Patch(c, 1, 1));
        Reject(Patch(c, 1, 2));

        Reject(Patch(e, 1, 0));
        Reject(Patch(e, 1, 1));
        Reject(Patch(e, 1, 3));
        Reject(Patch(e, 1, 4));
        Reject(Patch(e, 1, 6));
        Reject(Patch(e, 1, 7));

        Reject(Patch(e, e.Length - 17, 0));
        Reject(Patch(e, e.Length - 17, 65));
        Reject([.. e, 0]);

        Reject(Patch(a, 10, 3));
        Reject(Patch(a, 10, 200));

        Reject(Patch(a, 11, 0));
        Reject(Patch(b, 11, 0));
        Reject(Patch(c, 11, 0));
        Reject(Patch(a, 11, 33));

        Reject(Patch(a, 12, 0));
        Reject(Patch(a, 12, 5));
        Reject(Patch(a, 12, 15));
        Reject(Patch(a, 12, 17));

        Reject(Patch(a, 19, 0));
        Reject(Patch(a, 19, 6));
        Reject(Patch(d, 19, 3));

        Reject([.. a, 0]);
        Reject([.. c, 0xFF]);

        Reject([.. b[..^1]]);
        Reject([.. b, 0]);
        Reject([.. c[..^1]]);
        Reject([.. c, 0]);

        foreach (byte[] body in new[] { a, b, c, d, e, f })
        {
            for (int keep = 0; keep < body.Length; keep++)
            {
                Reject(body[..keep]);
            }
        }

        byte[] twice = [.. a[..12], 2, .. a[12..], .. a[12..]];
        Reject(twice);

        Reject(RelayBody(65, 3));

        Reject(RelayBody(2, 3, highByte: true));

        Reject([.. c[..^33]]);

        Assert.True(ConnectionStringCodec.TryRead(IrohBody("https://x.example/k"), out _, out _));
        Assert.True(ConnectionStringCodec.TryRead(IrohBody("http://127.0.0.1:99/k"), out _, out _));
        Reject(IrohBody("http://relay.example/k"));
        Reject(IrohBody("https://x.example/?q=1"));
        Reject(IrohBody("https://x.example/#f"));
        Reject(IrohBody("https://user:pw@x.example/"));
        Reject(IrohBody("notaurl"));
    }

    [Fact]
    public void NonCanonicalTextForms_AreRejected()
    {
        Assert.True(ConnectionStringCodec.TryParse(GoldenAText, out _));
        Assert.True(ConnectionStringCodec.TryParse(GoldenDText, out _));

        string payload = GoldenAText["pinhole1:".Length..];
        string dPayload = GoldenDText["pinhole1:".Length..];
        foreach (string bad in new[]
                 {
                     "",
                     "pinhole1",
                     "pinhole1:",
                     "pinhole:",
                     "pinhole2:" + payload,
                     "PINHOLE1:" + payload,
                     " pinhole1:" + payload,
                     payload,
                     "pinhole1:" + payload + "!",
                     "pinhole1:+" + payload,
                     "pinhole1:" + payload + "+",
                     "pinhole1:" + payload + "====",
                     "pinhole1:AAAAA",
                     "pinhole1:" + dPayload + "Q",
                     "pinhole1:" + new string('A', 8000),
                 })
        {
            Assert.False(ConnectionStringCodec.TryParse(bad, out ConnectionStringData v), bad);
            Assert.Null(v.Candidates);
        }

        string mixed = Convert.ToBase64String([0xFB, 0xFF, 0xFE, 0xFB, 0xFF, 0xFE]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Assert.Contains('-', mixed);
        Assert.Contains('_', mixed);
        Assert.False(ConnectionStringCodec.TryDecodeBase64Url(mixed.Replace('-', '+'), new byte[8], out _));
        Assert.False(ConnectionStringCodec.TryDecodeBase64Url(mixed.Replace('_', '/'), new byte[8], out _));
        Assert.True(ConnectionStringCodec.TryDecodeBase64Url(mixed, new byte[8], out _));

        Assert.True(ConnectionString.TryParse(GoldenAText + "=", out _));
        Assert.False(ConnectionStringCodec.TryParse(GoldenAText + "=", out _));
        Assert.False(ConnectionString.TryParse(GoldenAText + "==", out _));
        Assert.False(ConnectionStringCodec.TryParse(GoldenAText + "==", out _));

        char[] bumped = payload.ToCharArray();
        bumped[^1] = NextBase64Char(bumped[^1]);
        Assert.True(ConnectionString.TryParse("pinhole1:" + new string(bumped), out _));
        Assert.False(ConnectionStringCodec.TryParse("pinhole1:" + new string(bumped), out _));

        Assert.False(ConnectionStringCodec.TryDecodeBase64Url("AB=C", new byte[3], out _));
        Assert.False(ConnectionStringCodec.TryDecodeBase64Url("=ABC", new byte[3], out _));
        Assert.False(ConnectionStringCodec.TryDecodeBase64Url("A B", new byte[3], out _));
        Assert.True(ConnectionStringCodec.TryDecodeBase64Url("ABB".Replace("B", "A"), new byte[3], out _));
    }

    [Fact]
    public void Base64UrlPrimitives_MatchConvert_AndRejectNonCanonicalSlack()
    {
        var rng = new Random(0x5EED5);
        for (int i = 0; i < 2_000; i++)
        {
            int len = rng.Next(0, 100);
            byte[] data = new byte[len];
            rng.NextBytes(data);
            string expected = Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

            char[] encoded = new char[expected.Length + 4];
            Assert.True(ConnectionStringCodec.TryEncodeBase64Url(data, encoded, out int charsWritten));
            Assert.Equal(expected, new string(encoded, 0, charsWritten));
            if (expected.Length > 0)
            {
                Assert.False(ConnectionStringCodec.TryEncodeBase64Url(data, encoded.AsSpan(0, expected.Length - 1), out int shortWritten));
                Assert.Equal(0, shortWritten);
            }

            byte[] decoded = new byte[len + 1];
            Assert.True(ConnectionStringCodec.TryDecodeBase64Url(expected, decoded, out int bytesWritten));
            Assert.Equal(len, bytesWritten);
            Assert.True(decoded.AsSpan(0, len).SequenceEqual(data));

            if (expected.Length % 4 is 2 or 3)
            {
                char[] slack = expected.ToCharArray();
                slack[^1] = NextBase64Char(slack[^1]);
                Assert.False(ConnectionStringCodec.TryDecodeBase64Url(slack, decoded, out _));

                string padded = new string(slack).Replace('-', '+').Replace('_', '/');
                padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
                Assert.True(decoded.AsSpan(0, len).SequenceEqual(Convert.FromBase64String(padded)));
            }
            else if (expected.Length > 0)
            {

                char[] bumped = expected.ToCharArray();
                bumped[0] = NextBase64Char(bumped[0]);
                Assert.True(ConnectionStringCodec.TryDecodeBase64Url(bumped, decoded, out _));
            }
        }

        Assert.False(ConnectionStringCodec.TryDecodeBase64Url(new string('A', 5), new byte[8], out _));

        Assert.True(ConnectionStringCodec.TryEncodeBase64Url([], new char[1], out int zero));
        Assert.Equal(0, zero);
        Assert.True(ConnectionStringCodec.TryDecodeBase64Url([], new byte[1], out int zeroBytes));
        Assert.Equal(0, zeroBytes);
    }

    [Fact]
    public void Differential_MyEncodedBytes_AreParsedIdenticallyByTheReference()
    {
        var rng = new Random(0xC0FFEE);
        for (int i = 0; i < 500; i++)
        {
            ConnectionStringData value = RandomValue(rng);
            string text = ConnectionStringCodec.Encode(value);
            Assert.True(text.Length <= ConnectionStringCodec.MaxStringLength);

            byte[] body = new byte[ConnectionStringCodec.MaxEncodedLength];
            int written = ConnectionStringCodec.Write(value, body);
            byte[] referenceBody = ReferenceDecode(text);
            Assert.True(body.AsSpan(0, written).SequenceEqual(referenceBody));

            Assert.True(ConnectionString.TryParse(text, out ConnectionString? reference), text);
            AssertMatchesReference(value, reference!);
            Assert.Equal(text, reference!.ToString());
        }
    }

    [Fact]
    public void Differential_ReferenceEncodedBytes_AreParsedIdenticallyByMyCodec()
    {
        var rng = new Random(0x5EED1);
        for (int i = 0; i < 500; i++)
        {
            ConnectionString reference = RandomReferenceValue(rng);
            string text = reference.ToString();
            byte[] body = ReferenceDecode(text);

            Assert.True(ConnectionStringCodec.TryRead(body, out ConnectionStringData mine, out int consumed));
            Assert.Equal(body.Length, consumed);
            AssertMatchesReference(mine, reference);

            Assert.True(ConnectionStringCodec.TryParse(text, out ConnectionStringData fromText));
            AssertMatchesReference(fromText, reference);
            Assert.Equal(text, ConnectionStringCodec.Encode(mine));
        }
    }

    private static ConnectionStringData GoldenA() => new(
        0x1122334455667788UL,
        WireNatHint.Unknown,
        [Direct(IPAddress.Loopback, 40000)],
        null, null);

    private static ConnectionStringData GoldenB() => new(
        0UL,
        WireNatHint.Cone,
        [Reflexive(IPAddress.IPv6Loopback, 53)],
        Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(),
        null);

    private static ConnectionStringData GoldenC() => new(
        ulong.MaxValue,
        WireNatHint.Symmetric,
        [
            new CandidateData(WireCandidateKind.Relay, Endpoint(IPAddress.Parse("8.8.8.8"), 3478),
                Endpoint(IPAddress.Parse("1.2.3.4"), 3479), "u", "pw9", null, null),
        ],
        Repeat(0x11, 32), Repeat(0x22, 32));

    private static ConnectionStringData GoldenD() => new(
        0x2A2A2A2A2A2A2A2AUL,
        WireNatHint.Unknown,
        [
            new CandidateData(WireCandidateKind.IrohRelay, Endpoint(IPAddress.Loopback, 1), null, null, null,
                "https://r.example/x", Repeat(0xCD, 32)),
        ],
        null, null);

    private static ConnectionStringData GoldenE() => new(
        0x1122334455667788UL,
        WireNatHint.Unknown,
        [Direct(IPAddress.Loopback, 40000)],
        Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(),
        null,
        Repeat(0xAB, 16));

    private static ConnectionStringData GoldenF() => new(
        0x1122334455667788UL,
        WireNatHint.Unknown,
        [Direct(IPAddress.Loopback, 40000)],
        Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(),
        Repeat(0x22, 32),
        Repeat(0xCD, 8));

    private static void CheckGolden(ConnectionStringData value, string hex, string text)
    {
        byte[] body = Convert.FromHexString(hex);

        Span<byte> buffer = stackalloc byte[ConnectionStringCodec.MaxEncodedLength];
        int written = ConnectionStringCodec.Write(value, buffer);
        Assert.Equal(body.Length, written);
        Assert.True(buffer[..written].SequenceEqual(body));

        Assert.True(ConnectionStringCodec.TryRead(body, out ConnectionStringData read, out int consumed));
        Assert.Equal(body.Length, consumed);
        AssertValuesEqual(value, read);

        Assert.Equal(text, ConnectionStringCodec.Encode(value));
        Assert.True(ConnectionStringCodec.TryParse(text, out ConnectionStringData fromText));
        AssertValuesEqual(value, fromText);

        var reference = ConnectionString.Parse(text);
        AssertMatchesReference(value, reference);
        Assert.Equal(text, reference.ToString());
    }

    private static IPEndPoint Endpoint(IPAddress address, int port) => new(address, port);

    private static CandidateData Direct(IPAddress address, int port)
        => new(WireCandidateKind.Direct, Endpoint(address, port), null, null, null, null, null);

    private static CandidateData Reflexive(IPAddress address, int port)
        => new(WireCandidateKind.Reflexive, Endpoint(address, port), null, null, null, null, null);

    private static byte[] Repeat(byte b, int n)
    {
        byte[] a = new byte[n];
        Array.Fill(a, b);
        return a;
    }

    private static ConnectionStringData AllFiveKinds()
    {
        byte[] key = Repeat(1, 32);
        return new ConnectionStringData(
            0x0123456789ABCDEFUL,
            WireNatHint.Cone,
            [
                Direct(IPAddress.Loopback, 1000),
                Reflexive(IPAddress.IPv6Loopback, 1001),
                new CandidateData(WireCandidateKind.Relay, Endpoint(IPAddress.Loopback, 1002),
                    Endpoint(IPAddress.Parse("1.2.3.4"), 1003), "user", "pw", null, null),
                new CandidateData(WireCandidateKind.IrohRelay, Endpoint(IPAddress.IPv6Loopback, 1004), null, null, null,
                    "https://iroh.example/k", key),
                new CandidateData(WireCandidateKind.DerpRelay, Endpoint(IPAddress.Loopback, 1005), null, null, null,
                    "http://127.0.0.1:1006/d", key),
            ],
            key, (byte[])[.. key]);
    }

    private static ConnectionStringData MaxBodyValue()
    {
        string filler = new('u', 64);
        var candidates = new CandidateData[ConnectionStringCodec.MaxCandidates];
        for (int i = 0; i < candidates.Length; i++)
        {
            int port = 1 + (int)((1024 + (ulong)i * 7919) % 65535);
            candidates[i] = new CandidateData(
                WireCandidateKind.Relay,
                Endpoint(new IPAddress(Enumerable.Range(0, 16).Select(j => (byte)(i ^ j)).ToArray()), port),
                Endpoint(IPAddress.IPv6Loopback, 65535 - i),
                filler, filler, null, null);
        }

        return new ConnectionStringData(ulong.MaxValue, WireNatHint.Symmetric, candidates, Repeat(3, 32), Repeat(4, 32),
            Repeat(5, ConnectionStringCodec.MaxKnockLength));
    }

    private static byte[] WriteValue(ConnectionStringData value)
    {
        byte[] buffer = new byte[ConnectionStringCodec.MaxEncodedLength];
        int written = ConnectionStringCodec.Write(value, buffer);
        return buffer[..written];
    }

    private static byte[] ReferenceDecode(string text)
    {
        string b64 = text[(text.IndexOf(':') + 1)..].Replace('-', '+').Replace('_', '/');
        while (b64.Length % 4 != 0)
        {
            b64 += "=";
        }

        return Convert.FromBase64String(b64);
    }

    private static byte[] Patch(byte[] source, int index, byte value)
    {
        byte[] copy = [.. source];
        copy[index] = value;
        return copy;
    }

    private static void Reject(byte[] body)
    {
        Assert.False(ConnectionStringCodec.TryRead(body, out ConnectionStringData value, out int consumed));
        Assert.Equal(0, consumed);
        Assert.Null(value.Candidates);
    }

    private static byte[] RelayBody(int usernameLength, int credentialLength, bool highByte = false)
    {
        var body = new List<byte> { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        AppendEndpoint(body, 127, 0, 0, 1, 5000);
        body.Add(3);
        AppendEndpoint(body, 10, 1, 2, 3, 5001);
        body.Add((byte)usernameLength);
        if (highByte)
        {
            body.Add(0xC3);
            body.Add(0x80);
        }
        else
        {
            body.AddRange(Enumerable.Repeat((byte)'u', usernameLength));
        }

        body.Add((byte)credentialLength);
        body.AddRange(Enumerable.Repeat((byte)'p', credentialLength));
        return [.. body];

        static void AppendEndpoint(List<byte> body, byte a, byte b, byte c, byte d, int port)
        {
            body.Add(4);
            body.Add(a);
            body.Add(b);
            body.Add(c);
            body.Add(d);
            body.Add((byte)(port >> 8));
            body.Add((byte)port);
        }
    }

    private static byte[] IrohBody(string url)
    {
        var body = new List<byte> { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        body.Add(4);
        body.AddRange(new byte[] { 127, 0, 0, 1 });
        body.Add(0);
        body.Add(1);
        body.Add(4);
        byte[] urlBytes = Encoding.ASCII.GetBytes(url);
        body.Add((byte)urlBytes.Length);
        body.AddRange(urlBytes);
        body.AddRange(Repeat(0xCD, 32));
        return [.. body];
    }

    private static char NextBase64Char(char c)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int index = alphabet.IndexOf(c);
        Assert.True(index >= 0, $"char {c} not in the base64url alphabet");
        return alphabet[(index + 1) % alphabet.Length];
    }

    private static ConnectionStringData RandomValue(Random rng)
    {
        int count = rng.Next(1, 7);
        var candidates = new CandidateData[count];
        int unique = 0;
        for (int i = 0; i < count; i++)
        {
            candidates[i] = RandomCandidate(rng, ref unique);
        }

        byte[]? staticKey = null;
        byte[]? endpointKey = null;
        byte[]? knock = null;
        switch (rng.Next(4))
        {
            case 1:
                staticKey = RandomBytes(rng, 32);
                break;
            case 2:
                staticKey = RandomBytes(rng, 32);
                endpointKey = RandomBytes(rng, 32);
                break;
            case 3:
                staticKey = RandomBytes(rng, 32);

                if (rng.Next(2) == 0)
                {
                    endpointKey = RandomBytes(rng, 32);
                }

                knock = RandomBytes(rng, rng.Next(1, 65));
                break;
        }

        return new ConnectionStringData((ulong)rng.NextInt64(), (WireNatHint)rng.Next(3), candidates, staticKey, endpointKey, knock);
    }

    private static CandidateData RandomCandidate(Random rng, ref int unique)
    {
        IPEndPoint address = UniqueEndpoint(rng, ref unique);
        switch (rng.Next(10))
        {
            case < 4:
                return new CandidateData(WireCandidateKind.Direct, address, null, null, null, null, null);
            case < 6:
                return new CandidateData(WireCandidateKind.Reflexive, address, null, null, null, null, null);
            case < 8:
                return new CandidateData(WireCandidateKind.Relay, address, UniqueEndpoint(rng, ref unique),
                    RandomAscii(rng, 64), RandomAscii(rng, 64), null, null);
            default:
                return new CandidateData(rng.Next(2) == 0 ? WireCandidateKind.IrohRelay : WireCandidateKind.DerpRelay,
                    address, null, null, null, RandomRelayUrl(rng, unique), RandomBytes(rng, 32));
        }
    }

    private static IPEndPoint UniqueEndpoint(Random rng, ref int unique)
    {
        int id = unique++;
        int port = 1 + (int)((1024UL + (ulong)id * 7919) % 65535);
        if (rng.Next(2) == 0)
        {
            return new IPEndPoint(IPAddress.Parse($"{10 + (id >> 8) % 245}.{(id >> 4) & 255}.{id & 255}.{rng.Next(1, 255)}"), port);
        }

        byte[] v6 = RandomBytes(rng, 16);
        v6[0] = 0x20;
        v6[1] = 1;
        v6[15] = (byte)id;
        return new IPEndPoint(new IPAddress(v6), port);
    }

    private static string RandomRelayUrl(Random rng, int unique)
    {
        string url = rng.Next(4) == 0
            ? $"http://127.0.0.1:{1 + unique % 60000}/path{rng.Next(100)}"
            : $"https://relay{unique}.example:{1 + unique % 60000}/k{rng.Next(1000)}";
        return new Uri(url).AbsoluteUri;
    }

    private static ConnectionString RandomReferenceValue(Random rng)
    {
        var candidates = new List<PinholeCandidate>();
        int unique = 0;
        int count = rng.Next(1, 7);
        for (int i = 0; i < count; i++)
        {
            IPEndPoint address = UniqueEndpoint(rng, ref unique);
            switch (rng.Next(10))
            {
                case < 4:
                    candidates.Add(new PinholeCandidate(CandidateKind.Direct, address));
                    break;
                case < 6:
                    candidates.Add(new PinholeCandidate(CandidateKind.Reflexive, address));
                    break;
                case < 8:
                    candidates.Add(new PinholeCandidate(CandidateKind.Relay, address, UniqueEndpoint(rng, ref unique),
                        RandomAscii(rng, 64), RandomAscii(rng, 64)));
                    break;
                default:
                    candidates.Add(new PinholeCandidate(
                        rng.Next(2) == 0 ? CandidateKind.IrohRelay : CandidateKind.DerpRelay,
                        address,
                        RelayUrl: new Uri(RandomRelayUrl(rng, unique)),
                        RelayKey: RandomBytes(rng, 32)));
                    break;
            }
        }

        byte[]? staticKey = null;
        byte[]? endpointKey = null;
        byte[]? knock = null;
        switch (rng.Next(4))
        {
            case 1:
                staticKey = RandomBytes(rng, 32);
                break;
            case 2:
                staticKey = RandomBytes(rng, 32);
                endpointKey = RandomBytes(rng, 32);
                break;
            case 3:
                staticKey = RandomBytes(rng, 32);
                if (rng.Next(2) == 0)
                {
                    endpointKey = RandomBytes(rng, 32);
                }

                knock = RandomBytes(rng, rng.Next(1, 65));
                break;
        }

        return new ConnectionString((ulong)rng.NextInt64(), candidates, (NatHint)rng.Next(3), staticKey, endpointKey, knock);
    }

    private static byte[] RandomBytes(Random rng, int length)
    {
        byte[] data = new byte[length];
        rng.NextBytes(data);
        return data;
    }

    private static string RandomAscii(Random rng, int maxLength)
    {
        int length = rng.Next(0, maxLength + 1);
        char[] chars = new char[length];
        for (int i = 0; i < length; i++)
        {
            chars[i] = (char)rng.Next(0x20, 0x7F);
        }

        return new string(chars);
    }

    private static void AssertInvariants(in ConnectionStringData value)
    {
        Assert.True(value.Candidates is { Length: >= 1 and <= ConnectionStringCodec.MaxCandidates });
        Assert.True(Enum.IsDefined(value.NatHint));
        if (value.StaticKey is null)
        {
            Assert.Null(value.EndpointKey);
            Assert.Null(value.Knock);
        }
        else
        {
            Assert.Equal(ConnectionStringCodec.StaticKeyLength, value.StaticKey.Length);
            if (value.EndpointKey is not null)
            {
                Assert.Equal(ConnectionStringCodec.EndpointKeyLength, value.EndpointKey.Length);
            }

            if (value.Knock is not null)
            {
                Assert.InRange(value.Knock.Length, 1, ConnectionStringCodec.MaxKnockLength);
            }
        }

        foreach (CandidateData candidate in value.Candidates!)
        {
            Assert.True(Enum.IsDefined(candidate.Kind));
            Assert.NotNull(candidate.Address);
            Assert.True(candidate.Address!.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6);
            Assert.InRange(candidate.Address.Port, 0, 65535);
            if (candidate.Kind == WireCandidateKind.Relay)
            {
                Assert.NotNull(candidate.RelayServer);
                Assert.NotNull(candidate.Username);
                Assert.InRange(candidate.Username!.Length, 0, ConnectionStringCodec.MaxShortTextBytes);
                Assert.NotNull(candidate.Credential);
                Assert.InRange(candidate.Credential!.Length, 0, ConnectionStringCodec.MaxShortTextBytes);
                Assert.Null(candidate.RelayUrl);
                Assert.Null(candidate.RelayKey);
            }
            else if (candidate.Kind is WireCandidateKind.IrohRelay or WireCandidateKind.DerpRelay)
            {
                Assert.NotNull(candidate.RelayUrl);
                Assert.InRange(candidate.RelayUrl!.Length, 0, ConnectionStringCodec.MaxShortTextBytes);
                Assert.Equal(ConnectionStringCodec.RelayKeyLength, candidate.RelayKey!.Length);
                Assert.Null(candidate.RelayServer);
                Assert.Null(candidate.Username);
                Assert.Null(candidate.Credential);
            }
            else
            {
                Assert.Null(candidate.RelayServer);
                Assert.Null(candidate.Username);
                Assert.Null(candidate.Credential);
                Assert.Null(candidate.RelayUrl);
                Assert.Null(candidate.RelayKey);
            }
        }
    }

    private static void AssertValuesEqual(in ConnectionStringData expected, in ConnectionStringData actual)
    {
        Assert.Equal(expected.PeerId, actual.PeerId);
        Assert.Equal(expected.NatHint, actual.NatHint);
        Assert.True(BytesEqual(expected.StaticKey, actual.StaticKey));
        Assert.True(BytesEqual(expected.EndpointKey, actual.EndpointKey));
        Assert.True(BytesEqual(expected.Knock, actual.Knock));
        Assert.Equal(expected.Candidates!.Length, actual.Candidates!.Length);
        for (int i = 0; i < expected.Candidates.Length; i++)
        {
            AssertCandidatesEqual(expected.Candidates[i], actual.Candidates[i]);
        }
    }

    private static void AssertCandidatesEqual(in CandidateData expected, in CandidateData actual)
    {
        Assert.Equal(expected.Kind, actual.Kind);
        AssertEndpointsEqual(expected.Address!, actual.Address!);
        if (expected.Kind == WireCandidateKind.Relay)
        {
            AssertEndpointsEqual(expected.RelayServer!, actual.RelayServer!);
            Assert.Equal(expected.Username, actual.Username);
            Assert.Equal(expected.Credential, actual.Credential);
        }
        else if (expected.Kind is WireCandidateKind.IrohRelay or WireCandidateKind.DerpRelay)
        {
            Assert.Equal(expected.RelayUrl, actual.RelayUrl);
            Assert.True(BytesEqual(expected.RelayKey, actual.RelayKey));
        }
    }

    private static void AssertMatchesReference(in ConnectionStringData mine, ConnectionString reference)
    {
        Assert.Equal(reference.PeerId, mine.PeerId);
        Assert.Equal((byte)reference.NatHint, (byte)mine.NatHint);
        Assert.True(BytesEqual(mine.StaticKey, reference.StaticKey));
        Assert.True(BytesEqual(mine.EndpointKey, reference.EndpointKey));
        Assert.True(BytesEqual(mine.Knock, reference.Knock));
        Assert.Equal(reference.Candidates.Count, mine.Candidates!.Length);
        for (int i = 0; i < reference.Candidates.Count; i++)
        {
            PinholeCandidate r = reference.Candidates[i];
            CandidateData m = mine.Candidates[i];
            Assert.Equal((byte)r.Kind, (byte)m.Kind);
            AssertEndpointsEqual(m.Address!, r.Address);
            if (r.Kind == CandidateKind.Relay)
            {
                AssertEndpointsEqual(m.RelayServer!, r.RelayServer!);
                Assert.Equal(r.Username, m.Username);
                Assert.Equal(r.Credential, m.Credential);
            }
            else if (r.Kind is CandidateKind.IrohRelay or CandidateKind.DerpRelay)
            {
                Assert.Equal(r.RelayUrl!.AbsoluteUri, m.RelayUrl);
                Assert.True(BytesEqual(m.RelayKey, r.RelayKey));
            }
        }
    }

    private static void AssertEndpointsEqual(IPEndPoint expected, IPEndPoint actual)
    {
        Assert.Equal(expected.AddressFamily, actual.AddressFamily);
        Assert.Equal(expected.Port, actual.Port);
        Assert.True(expected.Address.GetAddressBytes().AsSpan().SequenceEqual(actual.Address.GetAddressBytes()));
    }

    private static bool BytesEqual(byte[]? expected, byte[]? actual) =>
        expected is null || actual is null ? expected is null && actual is null : expected.AsSpan().SequenceEqual(actual);
}
