using System.Buffers.Binary;

namespace Pinhole.Blobs;

// R2 verified runs. A run is an aligned 64-chunk subtree of the file's canonical
// left-complete BLAKE3 tree; the ragged tail is one run. Chunk frames carry leaf CVs;
// the Proof frame carries the sibling CVs from the run's node up to the file root.
// VerifyRun folds the leaf CVs, folds the sibling chain with the ROOT flag on the fold
// that completes the file, and compares the digest to the ticket root. Nothing may
// reach the disk before that comparison passes.
internal static class RunVerify
{
    internal const int RunChunks = 64;
    internal const int MaxSiblings = 64; // also bounds the fold-stack depth below
    internal const int CvSize = 32;

    // Supports chunk counts to 2^32 (files to 2^42 bytes); beyond that the sibling
    // path outgrows MaxSiblings and every entry point returns false / -1.
    internal static long RunCount(long totalChunks) =>
        totalChunks <= 0 ? 0 : (totalChunks + RunChunks - 1) / RunChunks;

    internal static long RunFirstChunk(long runIndex) => runIndex * RunChunks;

    internal static int RunLength(long runIndex, long totalChunks)
    {
        long len = totalChunks - runIndex * RunChunks;
        return (int)Math.Min(RunChunks, Math.Max(0, len));
    }

    // A single-chunk file has no folds; its root is the chunk hashed with the ROOT
    // flag, so the receiver needs the bytes (not a CV) to check it.
    internal static bool VerifySingleChunk(ReadOnlySpan<byte> chunkData, ReadOnlySpan<byte> expectedRoot)
    {
        if (chunkData.Length is < 0 or > Blake3.ChunkSize || expectedRoot.Length != CvSize)
        {
            return false;
        }

        Span<uint> words = stackalloc uint[8];
        Crypto.Blake3.HashChunk(chunkData, 0, root: true, words);
        Span<byte> digest = stackalloc byte[CvSize];
        WordsToBytes(words, digest);
        return digest.SequenceEqual(expectedRoot);
    }

    // Folds every run CV (run order) into the file root: the same stack discipline
    // the streaming hasher uses, with ROOT on the final spine fold. This is the
    // receiver's Complete()-time root check when runs were verified on arrival —
    // the second hashing pass over the data disappears. Single-run files verify
    // through VerifyRun's empty-proof branch (or VerifySingleChunk) instead.
    internal static bool FoldRunsToRoot(ReadOnlySpan<byte> runCvs, long totalChunks, Span<byte> root32)
    {
        long runs = RunCount(totalChunks);
        if (totalChunks <= RunChunks || runCvs.Length != runs * CvSize || root32.Length < CvSize)
        {
            return false;
        }

        // Push every run but the last, then fold the last run's CV up the spine
        // smallest-first with ROOT on the final fold — the exact shape of the
        // streaming hasher's finish, so a power-of-two run count never merges its
        // top pair without the ROOT flag.
        Span<uint> stack = stackalloc uint[8 * MaxSiblings];
        Span<long> stackCounts = stackalloc long[MaxSiblings];
        int depth = 0;
        Span<uint> cv = stackalloc uint[8];
        for (long r = 0; r < runs - 1; r++)
        {
            LoadCv(runCvs.Slice((int)(r * CvSize), CvSize), cv);
            Crypto.Blake3.PushCv(cv, 1, stack, stackCounts, ref depth, Crypto.Blake3.IvWords, 0);
        }

        LoadCv(runCvs.Slice((int)((runs - 1) * CvSize), CvSize), cv);
        Span<uint> acc = stackalloc uint[8];
        cv.CopyTo(acc);
        Span<uint> parent = stackalloc uint[8];
        for (int i = depth - 1; i >= 0; i--)
        {
            Crypto.Blake3.ParentWords(stack.Slice(8 * i, 8), acc, Crypto.Blake3.IvWords, 0, root: i == 0, parent);
            parent.CopyTo(acc);
        }

        WordsToBytes(acc, root32);
        return true;
    }

    internal readonly struct Step
    {
        public Step(long sibStart, long sibLen, bool nodeIsLeft)
        {
            SibStart = sibStart;
            SibLen = sibLen;
            NodeIsLeft = nodeIsLeft;
        }

        public long SibStart { get; }
        public long SibLen { get; }
        public bool NodeIsLeft { get; }
    }

    // The sibling chain from the run's node to the file root, bottom-up. Every aligned
    // run is a node of the canonical tree, so the chain is a function of (runIndex,
    // totalChunks) alone; the proof only supplies CV bytes. Each sibling is either a
    // power-of-two range (>= 64 chunks, 64-aligned) or a fold-chain suffix [o, n), so
    // the run-level tree can answer every lookup. Returns the step count, or -1.
    internal static int SiblingPath(long runIndex, long totalChunks, Span<Step> path)
    {
        if (totalChunks < 2 || runIndex < 0 || runIndex >= RunCount(totalChunks))
        {
            return -1;
        }

        long s = runIndex * RunChunks;
        long m = Math.Min(RunChunks, totalChunks - s);
        int count = 0;
        while (!(s == 0 && m == totalChunks))
        {
            if (count == path.Length || !TryClassify(s, m, totalChunks, out Step step, out long parentStart, out long parentLen))
            {
                return -1;
            }

            path[count++] = step;
            s = parentStart;
            m = parentLen;
        }

        return count;
    }

    // Verifies one run. leafCvs holds the run's leaf CVs (RunLength * 32 bytes), in
    // chunk order; siblings holds the Proof frame's CVs bottom-up (count * 32). The
    // final fold carries ROOT; the digest must equal expectedRoot. Total: false on any
    // shape mismatch. totalChunks == 1 has no run — use VerifySingleChunk.
    internal static bool VerifyRun(
        ReadOnlySpan<byte> leafCvs,
        ReadOnlySpan<byte> siblings,
        long runIndex,
        long totalChunks,
        ReadOnlySpan<byte> expectedRoot)
    {
        if (expectedRoot.Length != CvSize)
        {
            return false;
        }

        int leafCount = RunLength(runIndex, totalChunks);
        if (totalChunks < 2 || leafCount < 1 || leafCvs.Length != leafCount * CvSize)
        {
            return false;
        }

        Span<Step> path = stackalloc Step[MaxSiblings];
        int steps = SiblingPath(runIndex, totalChunks, path);
        if (steps < 0 || siblings.Length != steps * CvSize)
        {
            return false;
        }

        // A single-run file folds its own top pair with ROOT; otherwise ROOT lands on
        // the chain fold that completes the file (always the last step).
        if (steps == 0)
        {
            Span<byte> digest = stackalloc byte[CvSize];
            if (!FoldRun(leafCvs, leafCount, rootOnFinal: true, digest))
            {
                return false;
            }

            return digest.SequenceEqual(expectedRoot);
        }

        Span<uint> cur = stackalloc uint[8];
        if (!FoldRunWords(leafCvs, leafCount, cur))
        {
            return false;
        }

        Span<uint> sib = stackalloc uint[8];
        Span<uint> parent = stackalloc uint[8];
        for (int i = 0; i < steps; i++)
        {
            LoadCv(siblings.Slice(i * CvSize, CvSize), sib);
            // The walker exits at [0, n), so ROOT belongs to the last fold.
            bool isLast = i == steps - 1;
            Crypto.Blake3.ParentWords(
                path[i].NodeIsLeft ? cur : sib,
                path[i].NodeIsLeft ? sib : cur,
                Crypto.Blake3.IvWords, 0, root: isLast, parent);
            parent.CopyTo(cur);
        }

        Span<byte> digest2 = stackalloc byte[CvSize];
        WordsToBytes(cur, digest2);
        return digest2.SequenceEqual(expectedRoot);
    }

    // Folds a run's leaf CVs into the run node CV: the canonical left-complete subtree
    // for the run's length, exactly the shape the streaming hasher produces. rootOnFinal
    // places ROOT on the final fold (single-run files); run CVs for larger files use
    // false, since the chain above them supplies ROOT.
    internal static bool FoldRun(ReadOnlySpan<byte> leafCvs, int leafCount, bool rootOnFinal, Span<byte> cv32)
    {
        if (cv32.Length < CvSize || leafCount < 1 || leafCvs.Length != leafCount * CvSize)
        {
            return false;
        }

        if (leafCount == 1)
        {
            // No fold exists to carry ROOT; callers handle single-chunk files directly.
            if (rootOnFinal)
            {
                return false;
            }

            leafCvs[..CvSize].CopyTo(cv32);
            return true;
        }

        Span<uint> scratch = stackalloc uint[8 * RunChunks];
        LoadCvWords(leafCvs, leafCount, scratch);
        int nodes = leafCount;
        while (nodes > 2)
        {
            nodes = Crypto.Blake3.ReduceLevel(scratch, nodes);
        }

        if (rootOnFinal)
        {
            Crypto.Blake3.RootFromTopPair(scratch[..8], scratch.Slice(8, 8), cv32);
        }
        else
        {
            Span<uint> cv = stackalloc uint[8];
            Crypto.Blake3.ParentWords(scratch[..8], scratch.Slice(8, 8), Crypto.Blake3.IvWords, 0, root: false, cv);
            WordsToBytes(cv, cv32);
        }

        return true;
    }

    private static bool FoldRunWords(ReadOnlySpan<byte> leafCvs, int leafCount, Span<uint> cv8)
    {
        Span<byte> scratch = stackalloc byte[CvSize];
        if (!FoldRun(leafCvs, leafCount, rootOnFinal: false, scratch))
        {
            return false;
        }

        LoadCv(scratch, cv8);
        return true;
    }

    // Classifies the node [s, s+m) inside the tree over n chunks: which sibling sits
    // beside it, on which side, and the parent's range. A node is one of: a top-level
    // part of n's binary decomposition, a fold-chain suffix [o_i, n), or an aligned
    // power-of-two strictly inside a part's perfect subtree.
    private static bool TryClassify(long s, long m, long n, out Step step, out long parentStart, out long parentLen)
    {
        step = default;
        parentStart = 0;
        parentLen = 0;
        long o = 0;
        long prevOffset = -1, prevSize = 0;
        for (long size = HighestPower(n); size >= 1; size >>= 1)
        {
            if ((n & size) == 0)
            {
                continue;
            }

            if (s > o && s + m <= o + size)
            {
                return TryClassifyInsidePerfect(s, m, o, out step, out parentStart, out parentLen);
            }

            if (s == o)
            {
                if (s + m == n && prevOffset >= 0)
                {
                    // Fold-chain suffix: the accumulated right side; the previous part
                    // is its sibling and the parent is the suffix above it.
                    step = new Step(prevOffset, prevSize, nodeIsLeft: false);
                    parentStart = prevOffset;
                    parentLen = n - prevOffset;
                    return true;
                }

                if (m == size && s + m < n)
                {
                    // A part folds against everything after it.
                    step = new Step(o + size, n - o - size, nodeIsLeft: true);
                    parentStart = o;
                    parentLen = n - o;
                    return true;
                }

                if (m < size)
                {
                    return TryClassifyInsidePerfect(s, m, o, out step, out parentStart, out parentLen);
                }

                return false;
            }

            prevOffset = o;
            prevSize = size;
            o += size;
        }

        return false;
    }

    private static bool TryClassifyInsidePerfect(long s, long m, long partOffset, out Step step, out long parentStart, out long parentLen)
    {
        step = default;
        parentStart = 0;
        parentLen = 0;
        if (m < 1 || (m & (m - 1)) != 0)
        {
            return false;
        }

        long ls = s - partOffset;
        if (ls % (2 * m) == 0)
        {
            step = new Step(s + m, m, nodeIsLeft: true);
            parentStart = s;
            parentLen = 2 * m;
            return true;
        }

        if (ls % (2 * m) == m)
        {
            step = new Step(s - m, m, nodeIsLeft: false);
            parentStart = s - m;
            parentLen = 2 * m;
            return true;
        }

        return false;
    }

    private static long HighestPower(long n)
    {
        long p = 1;
        while (p * 2 <= n)
        {
            p *= 2;
        }

        return p;
    }

    internal static void LoadCv(ReadOnlySpan<byte> cv32, Span<uint> words8)
    {
        for (int i = 0; i < 8; i++)
        {
            words8[i] = BinaryPrimitives.ReadUInt32LittleEndian(cv32.Slice(4 * i));
        }
    }

    internal static void WordsToBytes(ReadOnlySpan<uint> words8, Span<byte> cv32)
    {
        for (int i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(cv32.Slice(4 * i), words8[i]);
        }
    }

    private static void LoadCvWords(ReadOnlySpan<byte> leafCvs, int leafCount, Span<uint> scratch)
    {
        for (int i = 0; i < leafCount; i++)
        {
            LoadCv(leafCvs.Slice(i * CvSize, CvSize), scratch.Slice(8 * i, 8));
        }
    }
}

// The provider side: the left-complete tree over run CVs with every internal node
// retained, so a proof costs O(depth) lookups instead of re-folding sibling ranges.
// Build once per served file from its per-chunk leaf CVs.
internal sealed class RunTree
{
    private readonly byte[][] _runCvs;
    private readonly Dictionary<long, byte[]> _nodes = new();

    public RunTree(IReadOnlyList<byte[]> chunkCvs, long totalChunks)
    {
        long runs = RunVerify.RunCount(totalChunks);
        _runCvs = new byte[runs][];
        Span<byte> leaves = stackalloc byte[RunVerify.RunChunks * RunVerify.CvSize];
        for (long r = 0; r < runs; r++)
        {
            int len = RunVerify.RunLength(r, totalChunks);
            for (int c = 0; c < len; c++)
            {
                chunkCvs[(int)(r * RunVerify.RunChunks + c)].CopyTo(leaves.Slice(c * RunVerify.CvSize, RunVerify.CvSize));
            }

            byte[] cv = new byte[RunVerify.CvSize];
            if (!RunVerify.FoldRun(leaves[..(len * RunVerify.CvSize)], len, rootOnFinal: false, cv))
            {
                throw new InvalidOperationException("run fold rejected its input");
            }

            _runCvs[r] = cv;
        }

        if (runs > 1)
        {
            BuildNode(0, runs);
        }
    }

    public byte[] RunCv(long runIndex) => _runCvs[runIndex];

    // Writes the proof for runIndex (sibling CVs, bottom-up) into siblingsOut and
    // returns the sibling count, or -1 on invalid input.
    public int Proof(long runIndex, long totalChunks, Span<byte> siblingsOut)
    {
        if (siblingsOut.Length < RunVerify.MaxSiblings * RunVerify.CvSize)
        {
            return -1;
        }

        Span<RunVerify.Step> path = stackalloc RunVerify.Step[RunVerify.MaxSiblings];
        int steps = RunVerify.SiblingPath(runIndex, totalChunks, path);
        if (steps < 0)
        {
            return -1;
        }

        for (int i = 0; i < steps; i++)
        {
            byte[]? cv = Lookup(path[i].SibStart, path[i].SibLen);
            if (cv is null)
            {
                return -1;
            }

            cv.CopyTo(siblingsOut.Slice(i * RunVerify.CvSize, RunVerify.CvSize));
        }

        return steps;
    }

    private byte[] BuildNode(long start, long count)
    {
        if (count == 1)
        {
            return _runCvs[start];
        }

        long left = LeftSplit(count);
        byte[] l = BuildNode(start, left);
        byte[] r = BuildNode(start + left, count - left);
        byte[] cv = new byte[RunVerify.CvSize];
        Span<uint> lw = stackalloc uint[8];
        Span<uint> rw = stackalloc uint[8];
        RunVerify.LoadCv(l, lw);
        RunVerify.LoadCv(r, rw);
        Span<uint> pw = stackalloc uint[8];
        Crypto.Blake3.ParentWords(lw, rw, Crypto.Blake3.IvWords, 0, root: false, pw);
        RunVerify.WordsToBytes(pw, cv);
        _nodes[(start << 32) | count] = cv;
        return cv;
    }

    private byte[]? Lookup(long chunkStart, long chunkLen)
    {
        // Every sibling of a run node is 64-aligned with a length that is either a
        // power of two >= 64 or the ragged suffix ending at the file root; both map
        // onto run ranges by dividing and rounding up.
        long start = chunkStart / RunVerify.RunChunks;
        long count = (chunkStart + chunkLen + RunVerify.RunChunks - 1) / RunVerify.RunChunks - start;
        return count == 1 ? _runCvs[start] : _nodes.GetValueOrDefault((start << 32) | count);
    }

    private static long LeftSplit(long count)
    {
        long p = 1;
        while (p * 2 <= count)
        {
            p *= 2;
        }

        // A perfect count splits in half; a ragged one keeps the left side the largest
        // power of two below it, matching the streaming hasher's stack discipline.
        return p == count ? count / 2 : p;
    }
}
