using System.Net;
using System.Security.Cryptography;
using Pinhole.Blobs;
using Xunit;

namespace Pinhole.Tests;

public sealed class DecoderHardeningTests
{
    private static BlobTicket RealTicket()
    {
        var cs = new Pinhole.ConnectionString(0x1234567890ABCDEF,
            [new PinholeCandidate(Pinhole.CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 5000))]).ToString();
        return new BlobTicket
        {
            Kind = BlobKind.Directory,
            Root = RandomNumberGenerator.GetBytes(32),
            Name = "holiday-photos",
            ConnectionString = cs,
            PreSharedKey = RandomNumberGenerator.GetBytes(32),
        };
    }

    [Fact]
    public void BlobTicket_EveryBitFlip_IsRejectedOrSafe_NeverAnUnexpectedThrow()
    {
        string text = RealTicket().ToString();
        char[] chars = text.ToCharArray();
        var legal = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (int i = 0; i < chars.Length; i++)
        {
            char original = chars[i];
            foreach (char replacement in legal)
            {
                if (replacement == original)
                {
                    continue;
                }

                chars[i] = replacement;
                TryParseAndClassify(new string(chars));
            }

            chars[i] = original;
        }
    }

    [Fact]
    public void BlobTicket_EveryTruncation_IsRejected()
    {
        string text = RealTicket().ToString();

        for (int len = 0; len < text.Length; len++)
        {
            Assert.False(BlobTicket.TryParse(text[..len], out _), $"prefix of length {len} parsed");
        }
    }

    [Fact]
    public void BlobTicket_TryParse_Null_ReturnsFalse()
    {

        Assert.False(BlobTicket.TryParse(null, out BlobTicket? ticket));
        Assert.Null(ticket);
    }

    [Fact]
    public void BlobTicket_RandomBytes_NeverProduceAnUnexpectedThrow()
    {

        var rng = new Random(0xB10B);
        for (int i = 0; i < 2_000; i++)
        {
            int len = rng.Next(0, 200);
            var bytes = new byte[len];
            rng.NextBytes(bytes);
            string candidate = "pinholeblob1:" + Convert.ToBase64String(bytes)
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            TryParseAndClassify(candidate);
        }
    }

    private static void TryParseAndClassify(string candidate)
    {
        try
        {
            _ = BlobTicket.TryParse(candidate, out _);
        }
        catch (FormatException)
        {

        }
    }

    [Fact]
    public void BlobWire_EveryPerturbation_ParsesFalseOrBounded_NeverThrows()
    {
        ulong stream = 0x0102030405060708;
        byte[][] frames =
        [
            BlobWire.Hello(stream, RandomNumberGenerator.GetBytes(BlobWire.SessionIdLength)),
            BlobWire.Welcome(stream, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32),
                RandomNumberGenerator.GetBytes(49)),
            BlobWire.Head(stream, 123_456, 121),
            BlobWire.Request(stream, 7, 64),
            BlobWire.Chunk(stream, 9, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(1024)),
            BlobWire.Bye(stream),
        ];

        foreach (byte[] frame in frames)
        {
            for (int i = 0; i < frame.Length; i++)
            {
                frame[i] ^= 0xFF;
                ParseMustStayBounded(frame);
                frame[i] ^= 0xFF;
            }

            for (int len = 0; len < frame.Length; len++)
            {
                ParseMustStayBounded(frame.AsSpan(0, len).ToArray());
            }
        }
    }

    private static void ParseMustStayBounded(byte[] frame)
    {

        bool parsed = BlobWire.Frame.TryParse(frame, out BlobWire.Frame f);
        if (parsed)
        {
            Assert.InRange(f.ChunkData?.Length ?? 0, 0, BlobWire.MaxChunkData);
        }
    }

    [Fact]
    public void Manifest_PerturbedAndRandomBytes_OnlyEverFormatExceptionOrAResult()
    {
        byte[] honest = Manifest.Encode("photos",
        [
            new Manifest.Entry("a/b.jpg", 1_000, RandomNumberGenerator.GetBytes(32)),
            new Manifest.Entry("c.jpg", 5, RandomNumberGenerator.GetBytes(32)),
        ]);

        for (int i = 0; i < honest.Length; i++)
        {
            honest[i] ^= 0x5A;
            DecodeMustStayBounded(honest);
            honest[i] ^= 0x5A;
        }

        for (int len = 0; len < honest.Length; len++)
        {
            DecodeMustStayBounded(honest.AsSpan(0, len).ToArray());
        }

        var rng = new Random(0xF00D);
        for (int i = 0; i < 2_000; i++)
        {
            var bytes = new byte[rng.Next(0, 300)];
            rng.NextBytes(bytes);
            DecodeMustStayBounded(bytes);
        }
    }

    private static void DecodeMustStayBounded(byte[] bytes)
    {
        try
        {
            _ = Manifest.Decode(bytes);
        }
        catch (FormatException)
        {
        }
        catch (Exception ex)
        {
            Assert.Fail($"manifest decoder leaked a raw {ex.GetType().Name}: {ex.Message}");
        }
    }

    [Fact]
    public void Manifest_HugeDeclaredEntryCount_FailsFastInsteadOfPreAllocating()
    {

        var claimed = new byte[2 + 4];
        claimed[0] = 0;
        claimed[1] = 0;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(claimed.AsSpan(2), int.MaxValue);

        var ex = Assert.Throws<FormatException>(() => Manifest.Decode(claimed));
        Assert.Contains("malformed", ex.Message);
    }
}
