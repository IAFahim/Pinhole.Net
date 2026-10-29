using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using ChaChaPoly = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;
using Org.BouncyCastle.Crypto.Parameters;
using Pinhole.Blobs;
using Pinhole.Crypto;
using Xunit;

namespace Pinhole.Tests;

public sealed class BlobCipherAeadTests
{
    [Theory]
    [InlineData(BlobWire.ProtocolVersion, false)]
    [InlineData(BlobWire.ProtocolVersion, true)]
    [InlineData(BlobWire.CurrentVersion, false)]
    [InlineData(BlobWire.CurrentVersion, true)]
    public void Cipher_SealedBytes_MatchTheBouncyCastleReference(byte version, bool asProvider)
    {
        if (!Aead.ChaCha20Poly1305Supported)
        {
            return;
        }

        byte[] psk = RandomNumberGenerator.GetBytes(32);
        byte[] root = RandomNumberGenerator.GetBytes(32);
        byte[] sessionId = RandomNumberGenerator.GetBytes(BlobWire.SessionIdLength);
        byte[] providerNonce = RandomNumberGenerator.GetBytes(BlobWire.SessionIdLength);
        byte[] bcKey = BcDeriveKey(psk, [.. root, .. sessionId, .. providerNonce],
            Encoding.UTF8.GetBytes(InfoText(version)));
        var cipher = BlobWire.Cipher.For(psk, root, sessionId, providerNonce, version)!;

        byte[][] payloads =
        [
            [],
            BlobWire.Bye(7),
            BlobWire.Chunk(7, 3, RandomNumberGenerator.GetBytes(32),
                RandomNumberGenerator.GetBytes(BlobWire.MaxChunkData)),
        ];
        foreach (ulong counter in new[] { 0UL, 1UL, 1UL << 40 })
        {
            foreach (byte[] payload in payloads)
            {
                byte[] bcFrame = BcSeal(bcKey, asProvider, counter, payload);
                byte[] newFrame = cipher.Seal(asProvider, counter, payload);
                Assert.Equal(bcFrame, newFrame);

                if (counter > 0)
                {
                    ulong watermark = counter - 1;
                    Assert.True(cipher.TryOpen(asProvider, newFrame, ref watermark, out byte[] plain));
                    Assert.Equal(payload, plain);

                    ulong viaBcWatermark = counter - 1;
                    Assert.True(cipher.TryOpen(asProvider, bcFrame, ref viaBcWatermark, out byte[] viaBc));
                    Assert.Equal(payload, viaBc);
                }
            }
        }
    }

    [Fact]
    public void Cipher_TamperedTag_RejectedByBothImplementations_WithoutMovingTheWatermark()
    {
        if (!Aead.ChaCha20Poly1305Supported)
        {
            return;
        }

        byte[] psk = RandomNumberGenerator.GetBytes(32);
        byte[] root = RandomNumberGenerator.GetBytes(32);
        byte[] sessionId = RandomNumberGenerator.GetBytes(BlobWire.SessionIdLength);
        byte[] providerNonce = RandomNumberGenerator.GetBytes(BlobWire.SessionIdLength);
        byte[] bcKey = BcDeriveKey(psk, [.. root, .. sessionId, .. providerNonce], "pinhole-blobs-v4"u8.ToArray());
        var cipher = BlobWire.Cipher.For(psk, root, sessionId, providerNonce, BlobWire.CurrentVersion)!;

        foreach (bool role in new[] { false, true })
        {
            byte[] genuine = cipher.Seal(role, 7, BlobWire.Bye(1));
            byte[] tamperedTag = genuine.ToArray();
            tamperedTag[^1] ^= 1;

            Assert.True(BcTryOpen(bcKey, role, genuine, out byte[] opened));
            Assert.Equal(BlobWire.Bye(1), opened);
            Assert.False(BcTryOpen(bcKey, role, tamperedTag, out _));

            ulong watermark = 6;
            Assert.False(cipher.TryOpen(role, tamperedTag, ref watermark, out _));
            Assert.Equal(6UL, watermark);
        }
    }

    [Fact]
    public void Cipher_LegacyV1Derivation_SealsBouncyCastleBytes_AndRoundTrips()
    {
        if (!Aead.ChaCha20Poly1305Supported)
        {
            return;
        }

        byte[] psk = RandomNumberGenerator.GetBytes(32);
        byte[] root = RandomNumberGenerator.GetBytes(32);
        byte[] bcKey = BcDeriveKey(psk, root, "pinhole-blobs-v1"u8.ToArray());
        var emulation = BlobWire.Cipher.ForLegacyEmulation(psk, root);
        byte[] payload = BlobWire.Chunk(1, 0, RandomNumberGenerator.GetBytes(32),
            RandomNumberGenerator.GetBytes(BlobWire.MaxChunkData));

        Assert.Equal(BcSeal(bcKey, false, 0, payload), emulation.Seal(asProvider: false, 0, payload));
        Assert.Equal(BcSeal(bcKey, true, 1, payload), emulation.Seal(asProvider: true, 1, payload));

        var detector = BlobWire.Cipher.ForLegacy(psk, root);
        ulong watermark = 4;
        Assert.True(detector.TryOpen(fromProvider: true, emulation.Seal(asProvider: true, 5, payload),
            ref watermark, out byte[] plain));
        Assert.Equal(payload, plain);
        Assert.Equal(5UL, watermark);

        ulong opened = 0;
        Assert.True(emulation.TryOpen(fromProvider: false, BcSeal(bcKey, false, 1, payload),
            ref opened, out byte[] viaBc));
        Assert.Equal(payload, viaBc);
    }

    [Theory]
    [InlineData("pinhole-blobs-v3")]
    [InlineData("pinhole-blobs-v4")]
    [InlineData("pinhole-blobs-v1")]
    public void HkdfSha256_MatchesBouncyCastleKeyDerivation(string info)
    {
        byte[] psk = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(96);
        byte[] bc = BcDeriveKey(psk, salt, Encoding.UTF8.GetBytes(info));
        byte[] bcl = HKDF.DeriveKey(HashAlgorithmName.SHA256, psk, 32, salt, Encoding.UTF8.GetBytes(info));
        Assert.Equal(bc, bcl);
    }

    [Fact]
    public async Task Cipher_ConcurrentSealAndOpenOnOneSession_StaysSafe()
    {
        if (!Aead.ChaCha20Poly1305Supported)
        {
            return;
        }

        var cipher = BlobWire.Cipher.For(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32),
            BlobWire.Cipher.FreshSessionId(), BlobWire.Cipher.FreshSessionId())!;
        byte[] payload = RandomNumberGenerator.GetBytes(256);
        const int threads = 4, perThread = 1_000;
        var start = new TaskCompletionSource();

        Task[] workers = Enumerable.Range(0, threads).Select(t => Task.Run(async () =>
        {
            await start.Task;
            ulong watermark = (ulong)(t * perThread);
            for (int i = 0; i < perThread; i++)
            {
                ulong counter = watermark + 1 + (ulong)i;
                byte[] sealedFrame = cipher.Seal(asProvider: t % 2 == 0, counter, payload);
                Assert.True(cipher.TryOpen(fromProvider: t % 2 == 0, sealedFrame, ref watermark, out byte[] plain));
                Assert.Equal(payload, plain);
            }
        })).ToArray();
        start.SetResult();
        await Task.WhenAll(workers);
    }

    private static string InfoText(byte version) => version switch
    {
        BlobWire.ProtocolVersion => "pinhole-blobs-v3",
        BlobWire.CurrentVersion => "pinhole-blobs-v4",
        _ => throw new ArgumentOutOfRangeException(nameof(version), "blob protocol version must be 3 or 4"),
    };

    private static byte[] BcDeriveKey(byte[] psk, byte[] salt, byte[] info)
    {
        var hkdf = new HkdfBytesGenerator(new Sha256Digest());
        hkdf.Init(new HkdfParameters(psk, salt, info));
        var key = new byte[32];
        hkdf.GenerateBytes(key, 0, 32);
        return key;
    }

    private static byte[] BcSeal(byte[] key, bool asProvider, ulong counter, ReadOnlySpan<byte> plaintext)
    {
        var aead = new ChaChaPoly();
        Span<byte> nonce = stackalloc byte[12];
        BcNonce(nonce, asProvider, counter);
        aead.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce.ToArray()));
        byte[] input = plaintext.ToArray();
        byte[] output = new byte[8 + input.Length + 16];
        BinaryPrimitives.WriteUInt64LittleEndian(output, counter);
        int n = aead.ProcessBytes(input, 0, input.Length, output, 8);
        aead.DoFinal(output, 8 + n);
        return output;
    }

    private static bool BcTryOpen(byte[] key, bool fromProvider, ReadOnlySpan<byte> wire, out byte[] plaintext)
    {
        plaintext = Array.Empty<byte>();
        if (wire.Length < 8 + 16)
        {
            return false;
        }

        var aead = new ChaChaPoly();
        Span<byte> nonce = stackalloc byte[12];
        BcNonce(nonce, fromProvider, BinaryPrimitives.ReadUInt64LittleEndian(wire));
        aead.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce.ToArray()));
        byte[] input = wire.ToArray();
        byte[] buf = new byte[input.Length];
        try
        {
            int n = aead.ProcessBytes(input, 8, input.Length - 8, buf, 0);
            n += aead.DoFinal(buf, n);
            plaintext = buf[..n];
            return true;
        }
        catch (InvalidCipherTextException)
        {
            return false;
        }
    }

    private static void BcNonce(Span<byte> nonce, bool provider, ulong counter)
    {
        nonce[0] = provider ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[1..], counter);
        nonce[9..].Clear();
    }
}
