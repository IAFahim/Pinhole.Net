using Pinhole.Wire;
using Xunit;

namespace Pinhole.Tests.Wire;

// The PATTERN EXEMPLAR for every codec in Pinhole.Wire: three test shapes that all
// codec tests must provide —
//   1. RoundTrip_IsCanonicalAndExact: Write -> TryRead reproduces the value and
//      consumes exactly the written length; known fixed vectors pin the byte format.
//   2. TotalityFuzz_NeverThrows: dense seeded mutations of valid encodings plus raw
//      random bytes — TryRead must never throw and never produce out-of-range values.
//   3. Rejection properties: the specific non-canonical forms for this format
//      (here: padded varints, truncations, trailing bytes) return false.
public sealed class WirePrimitivesTests
{
    [Fact]
    public void Varint_Rfc9000Vectors_RoundTripExactly()
    {
        // RFC 9000 section 16 sample encodings
        AssertVec([0x25], 37);
        AssertVec([0x7B, 0xBD], 15_293);
        AssertVec([0x9D, 0x7F, 0x3E, 0x7D], 494_878_333);
        AssertVec([0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C], 151_288_809_941_952_652);

        static void AssertVec(byte[] wire, ulong value)
        {
            Assert.True(WirePrimitives.TryReadVarint(wire, out ulong read, out int length));
            Assert.Equal(value, read);
            Assert.Equal(wire.Length, length);
            Span<byte> buffer = stackalloc byte[8];
            Assert.Equal(wire.Length, WirePrimitives.WriteVarint(buffer, value));
            Assert.True(buffer[..wire.Length].SequenceEqual(wire));
        }
    }

    [Fact]
    public void Varint_RoundTrip_AtEveryBoundary()
    {
        ulong[] boundaries =
        [
            0, 1, 63, 64, 65, 16_383, 16_384, 16_385,
            (1UL << 30) - 1, 1UL << 30, (1UL << 30) + 1,
            WirePrimitives.VarintMax,
        ];
        Span<byte> buffer = stackalloc byte[8];
        foreach (ulong value in boundaries)
        {
            int written = WirePrimitives.WriteVarint(buffer, value);
            Assert.True(WirePrimitives.TryReadVarint(buffer[..written], out ulong read, out int length));
            Assert.Equal(value, read);
            Assert.Equal(written, length);
            Assert.Equal(written, WirePrimitives.VarintLength(value));
        }

        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            Span<byte> buffer = stackalloc byte[8];
            WirePrimitives.WriteVarint(buffer, WirePrimitives.VarintMax + 1);
        });
    }

    [Fact]
    public void Varint_PaddedEncodings_AreRejected()
    {
        // A value that fits one byte, padded into each longer form, is non-canonical.
        foreach ((int size, byte prefix) in new[] { (2, (byte)0x40), (4, (byte)0x80), (8, (byte)0xC0) })
        {
            byte[] padded = new byte[size];
            padded[0] = prefix; // 0x40/0x80/0xC0 prefix with zero low bits encodes 0
            Assert.False(WirePrimitives.TryReadVarint(padded, out ulong value, out _), $"size {size}");
            Assert.Equal(0UL, value);
        }
    }

    [Fact]
    public void Varint_TotalityFuzz_NeverThrows()
    {
        var rng = new Random(0xBEEF);
        byte[] buffer = new byte[8];
        byte[] scratch = new byte[9];
        for (int i = 0; i < 200_000; i++)
        {
            int kind = rng.Next(3);
            switch (kind)
            {
                case 0: // raw random bytes, lengths 0..8
                {
                    int len = rng.Next(0, 9);
                    rng.NextBytes(scratch.AsSpan(0, len));
                    Exercise(scratch.AsSpan(0, len));
                    break;
                }
                case 1: // valid encoding, then a bit flip
                {
                    ulong value = SampleValue(rng);
                    int written = WirePrimitives.WriteVarint(buffer, value);
                    buffer[..written].CopyTo(scratch);
                    Array.Clear(scratch, written, scratch.Length - written);
                    scratch[rng.Next(written)] ^= (byte)(1 << rng.Next(8));
                    Exercise(scratch.AsSpan(0, written));
                    break;
                }
                default: // valid encoding, truncated
                {
                    ulong value = SampleValue(rng);
                    int written = WirePrimitives.WriteVarint(buffer, value);
                    int keep = rng.Next(written);
                    Exercise(buffer.AsSpan(0, keep));
                    break;
                }
            }
        }

        static ulong SampleValue(Random rng) => (ulong)rng.NextInt64(0, (long)WirePrimitives.VarintMax + 1);

        static void Exercise(ReadOnlySpan<byte> input)
        {
            bool ok = WirePrimitives.TryReadVarint(input, out ulong value, out int length);
            if (ok)
            {
                Assert.InRange(value, 0UL, WirePrimitives.VarintMax);
                Assert.InRange(length, 1, input.Length);
                Assert.True(length <= input.Length);
            }
            else
            {
                Assert.Equal(0UL, value);
                Assert.Equal(0, length);
            }
        }
    }

    [Fact]
    public void FixedWidth_Readers_RejectShortInput_AndReadExact()
    {
        Assert.False(WirePrimitives.TryReadU16Be([], out _));
        Assert.False(WirePrimitives.TryReadU16Be([0x01], out _));
        Assert.True(WirePrimitives.TryReadU16Be([0x01, 0x02], out ushort be));
        Assert.Equal((ushort)0x0102, be);
        Assert.True(WirePrimitives.TryReadU16Le([0x01, 0x02], out ushort le));
        Assert.Equal((ushort)0x0201, le);
        Assert.True(WirePrimitives.TryReadU64Le(Convert.FromHexString("0102030405060708"), out ulong u64));
        Assert.Equal(0x0807060504030201UL, u64);
        Assert.True(WirePrimitives.TryReadU32Be(Convert.FromHexString("00010203"), out uint u32));
        Assert.Equal(0x00010203u, u32);
        Assert.True(WirePrimitives.TryReadU64Be(Convert.FromHexString("0102030405060708"), out ulong be64));
        Assert.Equal(0x0102030405060708UL, be64);

        Span<byte> buffer = stackalloc byte[8];
        Assert.Equal(2, WirePrimitives.WriteU16Be(buffer, 0x0102));
        Assert.True(buffer[..2].SequenceEqual(Convert.FromHexString("0102")));
        Assert.Equal(4, WirePrimitives.WriteU32Be(buffer, 0x01020304));
        Assert.Equal(8, WirePrimitives.WriteU64Le(buffer, 0x0807060504030201));
        Assert.Equal(8, WirePrimitives.WriteU64Be(buffer, 0x0102030405060708));
        static void ThrowCheck(Span<byte> tooSmall) => WirePrimitives.WriteU16Be(tooSmall, 1);
        var small = new byte[1];
        Assert.Throws<ArgumentException>(() => ThrowCheck(small));
    }
}
