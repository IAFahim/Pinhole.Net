using Pinhole.Blobs;
using Xunit;

namespace Pinhole.Tests;

public sealed class RunVerifyTests
{
    private static byte[] MakeData(long bytes)
    {
        byte[] data = new byte[bytes];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)((i * 31 + 7) % 251);
        }

        return data;
    }

    public static IEnumerable<object[]> ChunkCounts() =>
        new object[][]
        {
            [2], [3], [4], [5], [63], [64], [65], [66], [96], [100], [127], [128],
            [129], [130], [192], [200], [255], [256], [257], [300], [511], [512],
            [513], [600], [1000], [1023], [1024], [1025], [2000], [4095], [4096],
            [4097], [5000],
        };

    // The streaming hasher's root is the oracle: for every chunk-count shape, every
    // run's proof must chain its leaf CVs back to exactly that root.
    [Theory]
    [MemberData(nameof(ChunkCounts))]
    public void RunProofs_ReproduceTheStreamingRoot_ForEveryRun(int chunkCount)
    {
        byte[] data = MakeData(chunkCount * 1024L);
        var tree = new Blake3.Tree();
        tree.Update(data);
        byte[] root = tree.RootHash();
        IReadOnlyList<byte[]> cvs = tree.ChunkCvs;
        Assert.Equal(chunkCount, cvs.Count);

        var runTree = new RunTree(cvs, chunkCount);
        long runs = RunVerify.RunCount(chunkCount);
        Assert.Equal((chunkCount + RunVerify.RunChunks - 1) / RunVerify.RunChunks, runs);

        byte[] proof = new byte[RunVerify.MaxSiblings * RunVerify.CvSize];
        byte[] leaves = new byte[RunVerify.RunChunks * RunVerify.CvSize];
        for (long r = 0; r < runs; r++)
        {
            int count = runTree.Proof(r, chunkCount, proof);
            Assert.True(count >= 0, $"run {r} proof failed to build");
            int len = RunVerify.RunLength(r, chunkCount);
            Assert.Equal((int)Math.Min(RunVerify.RunChunks, chunkCount - r * RunVerify.RunChunks), len);
            for (int c = 0; c < len; c++)
            {
                cvs[(int)(r * RunVerify.RunChunks + c)].CopyTo(leaves.AsSpan(c * RunVerify.CvSize, RunVerify.CvSize));
            }

            Assert.True(
                RunVerify.VerifyRun(leaves.AsSpan(0, len * RunVerify.CvSize), proof.AsSpan(0, count * RunVerify.CvSize), r, chunkCount, root),
                $"run {r} of {chunkCount} chunks failed to verify");
        }
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(31)]
    [InlineData(63)]
    [InlineData(64)]
    public void SingleRunFiles_VerifyWithAnEmptyProof(int chunkCount)
    {
        byte[] data = MakeData(chunkCount * 1024L);
        var tree = new Blake3.Tree();
        tree.Update(data);
        var runTree = new RunTree(tree.ChunkCvs, chunkCount);
        Assert.Equal(1, RunVerify.RunCount(chunkCount));
        byte[] proof = new byte[RunVerify.MaxSiblings * RunVerify.CvSize];
        Assert.Equal(0, runTree.Proof(0, chunkCount, proof));

        byte[] leaves = new byte[RunVerify.RunChunks * RunVerify.CvSize];
        for (int c = 0; c < chunkCount; c++)
        {
            tree.ChunkCvs[c].CopyTo(leaves.AsSpan(c * RunVerify.CvSize, RunVerify.CvSize));
        }

        Assert.True(RunVerify.VerifyRun(leaves.AsSpan(0, chunkCount * RunVerify.CvSize), [], 0, chunkCount, tree.RootHash()));
    }

    [Fact]
    public void SingleChunkFile_RootIsTheRootFlaggedChunkHash()
    {
        byte[] data = MakeData(1024);
        Assert.True(RunVerify.VerifySingleChunk(data, Blake3.Hash(data)));
        byte[] wrong = Blake3.Hash(data);
        wrong[0] ^= 1;
        Assert.False(RunVerify.VerifySingleChunk(data, wrong));
        // A 5-byte file is also a single chunk; its root is the plain hash.
        Assert.True(RunVerify.VerifySingleChunk(MakeData(5), Blake3.Hash(MakeData(5))));

        // No run exists for a one-chunk file; VerifyRun must not pretend otherwise.
        var tree = new Blake3.Tree();
        tree.Update(data);
        Assert.False(RunVerify.VerifyRun(tree.ChunkCvs[0], [], 0, 1, tree.RootHash()));
    }

    [Theory]
    [InlineData(200, 0)]
    [InlineData(200, 2)]
    [InlineData(200, 3)]
    [InlineData(1000, 7)]
    [InlineData(1025, 16)]
    public void ForgedProofs_AreRejected(int chunkCount, int runIndex)
    {
        byte[] data = MakeData(chunkCount * 1024L);
        var tree = new Blake3.Tree();
        tree.Update(data);
        byte[] root = tree.RootHash();
        var runTree = new RunTree(tree.ChunkCvs, chunkCount);
        byte[] proof = new byte[RunVerify.MaxSiblings * RunVerify.CvSize];
        int count = runTree.Proof(runIndex, chunkCount, proof);
        Assert.True(count >= 1);
        int len = RunVerify.RunLength(runIndex, chunkCount);
        byte[] leaves = new byte[len * RunVerify.CvSize];
        for (int c = 0; c < len; c++)
        {
            tree.ChunkCvs[(int)(runIndex * RunVerify.RunChunks + c)].CopyTo(leaves.AsSpan(c * RunVerify.CvSize, RunVerify.CvSize));
        }

        ReadOnlySpan<byte> honest = proof.AsSpan(0, count * RunVerify.CvSize);
        Assert.True(RunVerify.VerifyRun(leaves, honest, runIndex, chunkCount, root));

        // A bit flipped in any single sibling must break the chain to the root.
        for (int i = 0; i < count; i++)
        {
            byte[] forged = honest.ToArray();
            forged[i * RunVerify.CvSize + (i % RunVerify.CvSize)] ^= 0x80;
            Assert.False(RunVerify.VerifyRun(leaves, forged, runIndex, chunkCount, root), $"flip in sibling {i} accepted");
        }

        // A lying leaf CV (self-consistent chunk, wrong position claim) must fail.
        byte[] lyingLeaves = leaves.ToArray();
        lyingLeaves[0] ^= 1;
        Assert.False(RunVerify.VerifyRun(lyingLeaves, honest, runIndex, chunkCount, root));

        // Wrong run index, wrong root, wrong sibling count, and reversed siblings.
        if (runIndex + 1 < RunVerify.RunCount(chunkCount))
        {
            Assert.False(RunVerify.VerifyRun(leaves, honest, runIndex + 1, chunkCount, root));
        }

        byte[] wrongRoot = root.ToArray();
        wrongRoot[31] ^= 1;
        Assert.False(RunVerify.VerifyRun(leaves, honest, runIndex, chunkCount, wrongRoot));
        if (count >= 2)
        {
            byte[] reversed = new byte[count * RunVerify.CvSize];
            for (int i = 0; i < count; i++)
            {
                honest.Slice((count - 1 - i) * RunVerify.CvSize, RunVerify.CvSize).CopyTo(reversed.AsSpan(i * RunVerify.CvSize));
            }

            Assert.False(RunVerify.VerifyRun(leaves, reversed, runIndex, chunkCount, root));
        }

        Assert.False(RunVerify.VerifyRun(leaves, honest[..(RunVerify.CvSize * Math.Max(0, count - 1))], runIndex, chunkCount, root));
        Assert.False(RunVerify.VerifyRun(leaves, honest, runIndex, chunkCount, root[..31]));
        Assert.False(RunVerify.VerifyRun(leaves, honest, -1, chunkCount, root));
        Assert.False(RunVerify.VerifyRun(leaves, honest, RunVerify.RunCount(chunkCount), chunkCount, root));
    }

    [Theory]
    [InlineData(65)]
    [InlineData(100)]
    [InlineData(200)]
    [InlineData(1000)]
    [InlineData(1025)]
    [InlineData(5000)]
    public void FoldRunsToRoot_MatchesTheStreamingRoot(int chunkCount)
    {
        byte[] data = MakeData(chunkCount * 1024L);
        var tree = new Blake3.Tree();
        tree.Update(data);
        var runTree = new RunTree(tree.ChunkCvs, chunkCount);
        long runs = RunVerify.RunCount(chunkCount);
        byte[] runCvs = new byte[runs * RunVerify.CvSize];
        for (long r = 0; r < runs; r++)
        {
            runTree.RunCv(r).CopyTo(runCvs.AsSpan((int)(r * RunVerify.CvSize), RunVerify.CvSize));
        }

        byte[] folded = new byte[32];
        Assert.True(RunVerify.FoldRunsToRoot(runCvs, chunkCount, folded));
        Assert.Equal(tree.RootHash(), folded);
    }

    [Fact]
    public void SiblingPath_IsLogarithmic_AndSiblingsAreRunAligned()
    {
        // 512 MiB + ragged tail: 8193 runs.
        const int chunks = 512 * 1024 + 37;
        Assert.Equal(8193, RunVerify.RunCount(chunks));
        Span<RunVerify.Step> path = stackalloc RunVerify.Step[RunVerify.MaxSiblings];

        foreach (long r in new long[] { 0, 1, 4096, 8191, 8192 })
        {
            int count = RunVerify.SiblingPath(r, chunks, path);
            Assert.True(count > 0);
            Assert.True(count <= 24, $"run {r} needs {count} siblings");
            for (int i = 0; i < count; i++)
            {
                // Siblings are always 64-aligned; the only short ones are ragged
                // suffixes that run to the end of the file.
                Assert.Equal(0, path[i].SibStart % RunVerify.RunChunks);
                Assert.True(path[i].SibLen >= RunVerify.RunChunks || path[i].SibStart + path[i].SibLen == chunks);
            }
        }

        Assert.Equal(-1, RunVerify.SiblingPath(-1, chunks, path));
        Assert.Equal(-1, RunVerify.SiblingPath(RunVerify.RunCount(chunks), chunks, path));
    }

    [Fact]
    public void HalfGiB_EveryHundredthRun_Verifies()
    {
        const int chunks = 512 * 1024 + 37;
        byte[] data = MakeData(chunks * 1024L);
        var tree = new Blake3.Tree();
        tree.Update(data);
        byte[] root = tree.RootHash();
        IReadOnlyList<byte[]> cvs = tree.ChunkCvs;
        Assert.Equal(chunks, cvs.Count);
        var runTree = new RunTree(cvs, chunks);

        byte[] proof = new byte[RunVerify.MaxSiblings * RunVerify.CvSize];
        byte[] leaves = new byte[RunVerify.RunChunks * RunVerify.CvSize];
        for (long r = 0; r < RunVerify.RunCount(chunks); r += 97)
        {
            int count = runTree.Proof(r, chunks, proof);
            int len = RunVerify.RunLength(r, chunks);
            for (int c = 0; c < len; c++)
            {
                cvs[(int)(r * RunVerify.RunChunks + c)].CopyTo(leaves.AsSpan(c * RunVerify.CvSize, RunVerify.CvSize));
            }

            Assert.True(RunVerify.VerifyRun(leaves.AsSpan(0, len * RunVerify.CvSize), proof.AsSpan(0, count * RunVerify.CvSize), r, chunks, root), $"run {r} failed");
        }
    }
}
