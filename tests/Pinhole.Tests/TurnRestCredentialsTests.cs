using System.Security.Cryptography;
using System.Text;
using Pinhole.Turn;
using Xunit;

namespace Pinhole.Tests;

public sealed class TurnRestCredentialsTests
{
    [Fact]
    public void Issue_MatchesTheRestScheme()
    {
        byte[] secret = "pinhole-test-secret"u8.ToArray();
        byte[] nonce = Convert.FromHexString("00112233445566778899aabb");
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

        (string username, string credential) = TurnRestCredentials.Issue(secret, now, TimeSpan.FromHours(2), nonce);

        long expectedExpiry = 1_700_000_000 + 2 * 3600;
        Assert.Equal($"{expectedExpiry}:00112233445566778899aabb", username);
        byte[] expectedMac = HMACSHA1.HashData(secret, Encoding.ASCII.GetBytes(username));
        Assert.Equal(Convert.ToBase64String(expectedMac), credential);
    }

    [Fact]
    public void Issue_DistinctNonces_DistinctUsernames()
    {
        byte[] secret = new byte[32];
        var now = DateTimeOffset.UtcNow;
        var a = TurnRestCredentials.Issue(secret, now, TimeSpan.FromMinutes(10), "aaaaaaaa"u8);
        var b = TurnRestCredentials.Issue(secret, now, TimeSpan.FromMinutes(10), "bbbbbbbb"u8);
        Assert.NotEqual(a.Username, b.Username);
        Assert.NotEqual(a.Credential, b.Credential);
    }

    [Fact]
    public void Issue_RejectsShortNonces()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => TurnRestCredentials.Issue("s"u8.ToArray(), DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1), "1234567"u8));
    }
}
