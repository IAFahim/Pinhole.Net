using System.Security.Cryptography;
using System.Text;

namespace Pinhole.Turn;

/// <summary>Issues the REST-style ephemeral TURN credentials described by the coturn
/// <c>use-auth-secret</c> draft and used by Cloudflare Realtime TURN and other managed
/// providers: the username is <c>{unix-expiry}:{nonce}</c> and the credential is
/// base64(HMAC-SHA1(sharedSecret, username)). The shared secret never leaves the
/// operator's server — an SDK or game embeds only the short-lived pair it is handed,
/// which is why this helper lives with the operator's tooling, not in the client path.
/// Generate pairs server-side with a small lifetime and hand them to hosts/joiners
/// alongside the TURN URIs.</summary>
public static class TurnRestCredentials
{
    /// <summary>Issues one credential pair valid until <paramref name="lifetime"/> from
    /// now. <paramref name="nonce"/> should be at least 8 bytes of cryptographic
    /// randomness; it makes each issued username unique so pairs cannot be pooled or
    /// replayed across users beyond their common expiry.</summary>
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
