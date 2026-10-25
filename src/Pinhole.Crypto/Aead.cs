using System.Security.Cryptography;

namespace Pinhole.Crypto;

// Span-only AEAD over the BCL ciphers: one instance wraps one key for the session's
// lifetime (cipher construction is the only allocation). Seal writes ciphertext
// followed by the 16-byte tag; TryOpen returns false on any authentication failure
// and never throws on wire-controlled input. Not thread-safe.
public sealed class Aead : IDisposable
{
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int KeySize = 32;

    private readonly AesGcm? _aes;
    private readonly ChaCha20Poly1305? _chacha;

    public static bool AesGcmSupported => AesGcm.IsSupported;

    public static bool ChaCha20Poly1305Supported => ChaCha20Poly1305.IsSupported;

    private Aead(AesGcm aes) => _aes = aes;

    private Aead(ChaCha20Poly1305 chacha) => _chacha = chacha;

    public static Aead CreateAesGcm(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (16 or 24 or 32))
        {
            throw new ArgumentException("AES-GCM keys are 16, 24, or 32 bytes");
        }

        return new Aead(new AesGcm(key, TagSize));
    }

    public static Aead CreateChaCha20Poly1305(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException("ChaCha20-Poly1305 keys are 32 bytes");
        }

        return new Aead(new ChaCha20Poly1305(key));
    }

    public void Seal(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertextAndTag)
    {
        ObjectDisposedException.ThrowIf(_aes is null && _chacha is null, this);
        if (nonce.Length != NonceSize) ThrowNonce();
        if (ciphertextAndTag.Length < plaintext.Length + TagSize) ThrowOutputTooSmall();
        Span<byte> ciphertext = ciphertextAndTag[..plaintext.Length];
        Span<byte> tag = ciphertextAndTag[plaintext.Length..];
        if (_aes is not null)
        {
            _aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }
        else
        {
            _chacha!.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }
    }

    public bool TryOpen(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertextAndTag, Span<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_aes is null && _chacha is null, this);
        if (nonce.Length != NonceSize || ciphertextAndTag.Length < TagSize
            || plaintext.Length < ciphertextAndTag.Length - TagSize)
        {
            return false;
        }

        ReadOnlySpan<byte> ciphertext = ciphertextAndTag[..^TagSize];
        ReadOnlySpan<byte> tag = ciphertextAndTag[^TagSize..];
        try
        {
            if (_aes is not null)
            {
                _aes.Decrypt(nonce, ciphertext, tag, plaintext[..ciphertext.Length], aad);
            }
            else
            {
                _chacha!.Decrypt(nonce, ciphertext, tag, plaintext[..ciphertext.Length], aad);
            }

            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        _aes?.Dispose();
        _chacha?.Dispose();
    }

    private static void ThrowNonce() => throw new ArgumentException("nonce must be 12 bytes");

    private static void ThrowOutputTooSmall() => throw new ArgumentException("output must hold ciphertext plus 16 tag bytes");
}
