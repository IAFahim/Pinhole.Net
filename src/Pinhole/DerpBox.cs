using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Pinhole;

// DERP's authentication box is NaCl box: X25519 -> HSalsa20 ->
// XSalsa20/Poly1305. This is only the relay login; Pinhole's authenticated
// AES-GCM session continues to seal every application datagram.
internal static class DerpBox
{
    internal const int NonceSize = 24;
    internal const int TagSize = 16;

    internal static byte[] SharedKey(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        byte[] shared = NodeIdentity.X25519Agree(privateKey, publicKey);
        try
        {
            Span<uint> state = stackalloc uint[16];
            state.Clear();
            ReadOnlySpan<byte> constants = "expand 32-byte k"u8;
            for (int i = 0; i < 4; i++)
            {
                state[i * 5] = BinaryPrimitives.ReadUInt32LittleEndian(constants[(i * 4)..]);
                state[i + 1] = BinaryPrimitives.ReadUInt32LittleEndian(shared.AsSpan(i * 4));
                state[i + 11] = BinaryPrimitives.ReadUInt32LittleEndian(shared.AsSpan(16 + i * 4));
            }
            // HSalsa20 with an all-zero 16-byte input: ten column/row double
            // rounds, without Salsa20's final state addition.
            for (int i = 0; i < 10; i++)
            {
                QuarterRound(state, 0, 4, 8, 12); QuarterRound(state, 5, 9, 13, 1);
                QuarterRound(state, 10, 14, 2, 6); QuarterRound(state, 15, 3, 7, 11);
                QuarterRound(state, 0, 1, 2, 3); QuarterRound(state, 5, 6, 7, 4);
                QuarterRound(state, 10, 11, 8, 9); QuarterRound(state, 15, 12, 13, 14);
            }
            ReadOnlySpan<int> indices = [0, 5, 10, 15, 6, 7, 8, 9];
            byte[] key = new byte[32];
            for (int i = 0; i < indices.Length; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(key.AsSpan(i * 4), state[indices[i]]);
            state.Clear();
            return key;
        }
        finally { CryptographicOperations.ZeroMemory(shared); }
    }

    private static void QuarterRound(Span<uint> state, int a, int b, int c, int d)
    {
        unchecked
        {
            state[b] ^= BitOperations.RotateLeft(state[a] + state[d], 7);
            state[c] ^= BitOperations.RotateLeft(state[b] + state[a], 9);
            state[d] ^= BitOperations.RotateLeft(state[c] + state[b], 13);
            state[a] ^= BitOperations.RotateLeft(state[d] + state[c], 18);
        }
    }

    internal static byte[] Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, byte[]? nonce = null)
    {
        nonce ??= RandomNumberGenerator.GetBytes(NonceSize);
        if (nonce.Length != NonceSize) throw new ArgumentException("a NaCl nonce has 24 bytes", nameof(nonce));
        var cipher = new XSalsa20Engine();
        cipher.Init(true, new ParametersWithIV(new KeyParameter(key.ToArray()), nonce));
        byte[] macKey = new byte[32];
        cipher.ProcessBytes(new byte[32], 0, 32, macKey, 0);
        try
        {
            byte[] result = new byte[NonceSize + TagSize + plaintext.Length];
            nonce.CopyTo(result, 0);
            cipher.ProcessBytes(plaintext, result.AsSpan(NonceSize + TagSize));
            var mac = new Poly1305();
            mac.Init(new KeyParameter(macKey));
            mac.BlockUpdate(result.AsSpan(NonceSize + TagSize));
            mac.DoFinal(result.AsSpan(NonceSize, TagSize));
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(macKey); }
    }

    internal static byte[] Open(ReadOnlySpan<byte> key, ReadOnlySpan<byte> box)
    {
        if (box.Length < NonceSize + TagSize) throw new InvalidDataException("truncated DERP authentication box");
        var cipher = new XSalsa20Engine();
        cipher.Init(false, new ParametersWithIV(new KeyParameter(key.ToArray()), box[..NonceSize].ToArray()));
        byte[] macKey = new byte[32];
        cipher.ProcessBytes(new byte[32], 0, 32, macKey, 0);
        try
        {
            var mac = new Poly1305();
            mac.Init(new KeyParameter(macKey));
            mac.BlockUpdate(box[(NonceSize + TagSize)..]);
            Span<byte> tag = stackalloc byte[TagSize];
            mac.DoFinal(tag);
            if (!CryptographicOperations.FixedTimeEquals(tag, box.Slice(NonceSize, TagSize)))
                throw new InvalidDataException("DERP authentication box failed verification");
            byte[] plaintext = new byte[box.Length - NonceSize - TagSize];
            cipher.ProcessBytes(box[(NonceSize + TagSize)..], plaintext);
            return plaintext;
        }
        finally { CryptographicOperations.ZeroMemory(macKey); }
    }
}
