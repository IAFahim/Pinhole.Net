using System.Security.Cryptography;
using System.Text;

namespace Pinhole.Turn;

public static class TurnRestCredentials
{
    public static (string Username, string Credential) Issue(
        ReadOnlySpan<byte> sharedSecret,
        DateTimeOffset? now,
        TimeSpan lifetime,
        ReadOnlySpan<byte> nonce)
    {
        if (nonce.Length < 8)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce), "use at least 8 bytes of cryptographic randomness");
        }

        long expiry = ((now ?? DateTimeOffset.UtcNow) + lifetime).ToUnixTimeSeconds();
        string username = $"{expiry}:{Convert.ToHexString(nonce).ToLowerInvariant()}";
        byte[] mac = HMACSHA1.HashData(sharedSecret, Encoding.ASCII.GetBytes(username));
        return (username, Convert.ToBase64String(mac));
    }
}
