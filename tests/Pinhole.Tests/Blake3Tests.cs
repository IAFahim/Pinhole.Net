using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Pinhole.Blobs;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Our tree-exposing BLAKE3 must be bit-compatible with BouncyCastle's digest —
/// that oracle anchors every root we ever mint or verify, while the chunk CVs (which
/// BouncyCastle cannot produce) are validated through the tree structure itself.</summary>
public sealed class Blake3Tests
{
    public static IEnumerable<object[]> Sizes() =>
        new object[][]
        {
            [0], [1], [63], [64], [65], [127], [128], [1023], [1024], [1025],
            [2047], [2048], [2049], [3072], [4096], [5000], [65536], [100_003],
        };

    [Theory]
    [MemberData(nameof(Sizes))]
    public void Root_MatchesBouncyCastle(int size)
    {
        byte[] data = RandomNumberGenerator.GetBytes(size);

        var reference = new Blake3Digest();
        var expected = new byte[32];
        reference.BlockUpdate(data, 0, data.Length);
        reference.DoFinal(expected, 0);

        Assert.Equal(expected, Blake3.Hash(data));
    }

    [Fact]
    public void Root_MatchesAcrossChunkBoundaries_WhenFedPiecewise()
    {
        byte[] data = RandomNumberGenerator.GetBytes(10_000);
        var tree = new Blake3.Tree();
        int pos = 0;
        var rng = new Random(42);
        while (pos < data.Length)
        {
            int take = Math.Min(rng.Next(1, 700), data.Length - pos);
            tree.Update(data.AsSpan(pos, take));
            pos += take;
        }

        var reference = new Blake3Digest();
        var expected = new byte[32];
        reference.BlockUpdate(data, 0, data.Length);
        reference.DoFinal(expected, 0);
        Assert.Equal(expected, tree.RootHash());
        Assert.Equal(data.Length, tree.TotalBytes);
    }

    [Fact]
    public void KnownEmptyVector_Matches()
    {
        // af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262 — the published
        // BLAKE3 hash of the empty string.
        byte[] root = Blake3.Hash([]);
        Assert.Equal("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", Convert.ToHexString(root).ToLowerInvariant());
    }

    [Fact]
    public void ChunkCvs_RecomputeFromData_AndReceiverTreeReproducesRoot()
    {
        byte[] data = RandomNumberGenerator.GetBytes(5000); // 4 full chunks + 904
        var tree = new Blake3.Tree();
        tree.Update(data);
        byte[] root = tree.RootHash();
        IReadOnlyList<byte[]> cvs = tree.ChunkCvs;

        Assert.Equal(5, cvs.Count);
        for (int i = 0; i < cvs.Count; i++)
        {
            ReadOnlySpan<byte> chunk = data.AsSpan(i * Blake3.ChunkSize,
                Math.Min(Blake3.ChunkSize, data.Length - i * Blake3.ChunkSize));
            Assert.Equal(cvs[i], Blake3.ChunkCv(chunk, (ulong)i, root: false));
        }

        // The receiver's job: hash received bytes through its own tree while writing them
        // out, verify each chunk's CV on arrival, and require the root to match the ticket.
        var receiver = new Blake3.Tree();
        for (int i = 0; i < cvs.Count; i++)
        {
            ReadOnlySpan<byte> chunk = data.AsSpan(i * Blake3.ChunkSize,
                Math.Min(Blake3.ChunkSize, data.Length - i * Blake3.ChunkSize));
            receiver.Update(chunk);
        }

        Assert.Equal(root, receiver.RootHash());
        Assert.NotEqual(cvs[0], cvs[4]);
    }

    [Fact]
    public void DifferentData_ProducesDifferentRoots()
    {
        byte[] a = new byte[3000];
        byte[] b = new byte[3000];
        b[^1] = 1;
        Assert.NotEqual(Blake3.Hash(a), Blake3.Hash(b));
    }
}
