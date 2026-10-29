using Pinhole.Crypto;

namespace Pinhole;

internal static class HybridKem
{
    public const int PublicKeyLength = 1184;
    public const int CiphertextLength = 1088;
    public const int SharedSecretLength = 32;
    public const int PrivateSeedLength = 64;

    public const string SeedLabel = "pinhole-mlkem768-seed-v1";

    internal static ReadOnlySpan<byte> SeedLabelBytes => "pinhole-mlkem768-seed-v1"u8;

    public static byte[] DerivePrivateSeed(ReadOnlySpan<byte> identitySeed)
    {
        byte[] seed = new byte[PrivateSeedLength];
        Blake3.HashDeriveKey(SeedLabelBytes, identitySeed, seed);
        return seed;
    }

#if NET10_0
    internal static bool IsSupported => System.Security.Cryptography.MLKem.IsSupported;

    internal static byte[]? PublicKeyFromSeed(byte[] privateSeed)
    {
        if (!IsSupported)
        {
            return null;
        }

        using var kem = System.Security.Cryptography.MLKem.ImportPrivateSeed(
            System.Security.Cryptography.MLKemAlgorithm.MLKem768, privateSeed);
        return kem.ExportEncapsulationKey();
    }

    internal static (byte[] Ciphertext, byte[] SharedSecret)? Encapsulate(ReadOnlySpan<byte> publicKey)
    {
        if (!IsSupported || publicKey.Length != PublicKeyLength)
        {
            return null;
        }

        using var encap = System.Security.Cryptography.MLKem.ImportEncapsulationKey(
            System.Security.Cryptography.MLKemAlgorithm.MLKem768, publicKey.ToArray());
        encap.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret);
        return (ciphertext, sharedSecret);
    }

    internal static byte[]? Decapsulate(byte[] privateSeed, ReadOnlySpan<byte> ciphertext)
    {
        if (!IsSupported || ciphertext.Length != CiphertextLength)
        {
            return null;
        }

        using var kem = System.Security.Cryptography.MLKem.ImportPrivateSeed(
            System.Security.Cryptography.MLKemAlgorithm.MLKem768, privateSeed);
        return kem.Decapsulate(ciphertext.ToArray());
    }
#else
    internal static bool IsSupported => false;

    internal static byte[]? PublicKeyFromSeed(byte[] privateSeed) => null;

    internal static (byte[] Ciphertext, byte[] SharedSecret)? Encapsulate(ReadOnlySpan<byte> publicKey) => null;

    internal static byte[]? Decapsulate(byte[] privateSeed, ReadOnlySpan<byte> ciphertext) => null;
#endif
}
