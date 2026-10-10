using System.Buffers.Binary;
using System.Numerics;

namespace Pinhole.Blobs;

/// <summary>Pure-C# BLAKE3 (the tree hashing parts iroh-blobs builds on) exposing what
/// verified streaming needs and <c>Blake3Digest</c> cannot: the per-chunk chaining values
/// that form the tree's leaves. The root is bit-compatible with BouncyCastle's
/// <c>Blake3Digest</c> (cross-checked in the test suite), so hashes interoperate while the
/// chunk CVs stay our outboard format.
///
/// Tree shape is the spec's left-deep binary tree, built with the usual counter-carry
/// stack: chunk CVs merge pairwise when their subtree sizes match; the ROOT flag lands on
/// exactly one final compress.</summary>
public static class Blake3
{
    /// <summary>The chunk size every BLAKE3 implementation agrees on: the tree's leaves
    /// are 1 KiB chunks, and blob frames carry exactly one chunk each.</summary>
    public const int ChunkSize = 1024;

    /// <summary>The compression block size, exposed for callers sizing buffers.</summary>
    public const int BlockSize = 64;

    private static readonly uint[] Iv =
    [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    private const uint ChunkStart = 1 << 0;
    private const uint ChunkEnd = 1 << 1;
    private const uint Parent = 1 << 2;
    private const uint Root = 1 << 3;

    private static readonly int[] Permutation = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    /// <summary>Streaming builder: feed bytes, read the root and the chunk-CV outboard.</summary>
    public sealed class Tree
    {
        private readonly bool _retainOutboard;

        /// <summary>Builds a hash and retains the chunk-CV outboard for serving.</summary>
        public Tree() : this(retainOutboard: true) { }

        internal Tree(bool retainOutboard) => _retainOutboard = retainOutboard;

        private readonly List<byte[]> _chunkCvs = new();
        private readonly List<(uint[] Cv, long Chunks, TreeEntry? L, TreeEntry? R)> _stack = new();
        private readonly byte[] _pending = new byte[ChunkSize];
        private int _pendingLen;
        private long _chunkCounter;
        private long _totalBytes;
        private byte[]? _root;

        /// <summary>Total bytes fed so far.</summary>
        public long TotalBytes => _totalBytes;

        /// <summary>Chunk count the current input covers, including the not-yet-closed
        /// final chunk (empty input counts as one chunk, per the spec).</summary>
        public int ChunkCount => checked((int)_chunkCounter + (_pendingLen > 0 || _totalBytes == 0 ? 1 : 0));

        /// <summary>The outboard so far: one 32-byte chaining value per closed chunk plus
        /// the pending chunk's, in order — exactly what a provider sends alongside data
        /// and what a receiver re-checks per chunk.</summary>
        public IReadOnlyList<byte[]> ChunkCvs
        {
            get
            {
                if (!_retainOutboard) throw new InvalidOperationException("this hash does not retain an outboard");
                byte[][] cvs = new byte[_chunkCvs.Count + (_pendingLen > 0 ? 1 : 0)][];
                for (int i = 0; i < _chunkCvs.Count; i++)
                {
                    cvs[i] = _chunkCvs[i];
                }

                if (_pendingLen > 0)
                {
                    cvs[^1] = ChunkCv(_pending.AsSpan(0, _pendingLen), (ulong)_chunkCounter, root: false);
                }

                return cvs;
            }
        }

        /// <summary>Feeds bytes in any chunking; call repeatedly for streaming input.
        /// Throws once <see cref="RootHash"/> has finalized the tree.</summary>
        public void Update(ReadOnlySpan<byte> data)
        {
            if (_root is not null)
            {
                throw new InvalidOperationException("the tree is already finalized");
            }

            while (data.Length > 0)
            {
                int take = Math.Min(data.Length, ChunkSize - _pendingLen);
                data[..take].CopyTo(_pending.AsSpan(_pendingLen));
                _pendingLen += take;
                data = data[take..];
                _totalBytes += take;

                // A full buffer only closes the chunk once the NEXT byte arrives: the very
                // last chunk's final compress is where the ROOT flag could belong, and that
                // is unknowable until the input ends.
                if (_pendingLen == ChunkSize && data.Length > 0)
                {
                    FlushPendingChunk();
                }
            }
        }

        /// <summary>Finalizes and returns the 32-byte root; idempotent (later calls return
        /// the same buffer) and freezes the tree against further <see cref="Update"/>.</summary>
        public byte[] RootHash()
        {
            if (_root is not null)
            {
                return _root;
            }

            if (_stack.Count == 0)
            {
                // Whole input is one chunk (possibly empty): the root is that chunk's final
                // compress with the ROOT flag.
                uint[] words = ChunkCvWords(_pending.AsSpan(0, _pendingLen), 0, root: true);
                return _root = WordsToHash(words);
            }

            FlushPendingChunk();
            while (_stack.Count >= 2)
            {
                var r = _stack[^1];
                var l = _stack[^2];
                _stack.RemoveRange(_stack.Count - 2, 2);
                _stack.Add((ParentCv(l.Cv, r.Cv, root: false), l.Chunks + r.Chunks, ToEntry(l), ToEntry(r)));
            }

            var top = _stack[0];
            uint[] rootWords = top.L is { } left && top.R is { } right
                ? ParentCv(left.Cv, right.Cv, root: true)
                : top.Cv; // unreachable defensive branch: a lone chunk was handled above
            return _root = WordsToHash(rootWords);
        }

        private void FlushPendingChunk()
        {
            uint[] cv = ChunkCvWords(_pending.AsSpan(0, _pendingLen), (ulong)_chunkCounter, root: false);
            if (_retainOutboard) _chunkCvs.Add(WordsToHash(cv));
            _stack.Add((cv, 1, null, null));
            _pendingLen = 0;
            _chunkCounter++;

            while (_stack.Count >= 2 && _stack[^1].Chunks == _stack[^2].Chunks)
            {
                var r = _stack[^1];
                var l = _stack[^2];
                _stack.RemoveRange(_stack.Count - 2, 2);
                _stack.Add((ParentCv(l.Cv, r.Cv, root: false), l.Chunks + r.Chunks, ToEntry(l), ToEntry(r)));
            }
        }

        private TreeEntry ToEntry((uint[] Cv, long Chunks, TreeEntry? L, TreeEntry? R) e) =>
            new(e.Cv, _retainOutboard ? e.L : null, _retainOutboard ? e.R : null);

        private sealed record TreeEntry(uint[] Cv, TreeEntry? L, TreeEntry? R);
    }

    /// <summary>One-shot hash of the whole input — bit-compatible with BouncyCastle's
    /// <c>Blake3Digest</c> over the same bytes.</summary>
    public static byte[] Hash(ReadOnlySpan<byte> data)
    {
        var tree = new Tree(retainOutboard: false);
        tree.Update(data);
        return tree.RootHash();
    }

    /// <summary>The chunk's chaining value (leaf of the verification tree): what the sender
    /// ships in the outboard and what the receiver recomputes from chunk bytes to detect
    /// corruption before the transfer ends.</summary>
    public static byte[] ChunkCv(ReadOnlySpan<byte> chunk, ulong index, bool root) => WordsToHash(ChunkCvWords(chunk, index, root));

    private static uint[] ChunkCvWords(ReadOnlySpan<byte> chunk, ulong index, bool root)
    {
        uint[] cv = Iv;
        int pos = 0;
        long blocks = 0;
        if (chunk.Length == 0)
        {
            Span<uint> block = stackalloc uint[16];
            return First8(Compress(cv, block, index, 0, ChunkStart | ChunkEnd | (root ? Root : 0)));
        }

        Span<uint> words = stackalloc uint[16];
        while (pos < chunk.Length)
        {
            int take = Math.Min(BlockSize, chunk.Length - pos);
            words.Clear();
            LoadWords(chunk.Slice(pos, take), words);
            bool last = pos + take == chunk.Length;
            uint flags = blocks == 0 ? ChunkStart : 0;
            if (last)
            {
                flags |= ChunkEnd | (root ? Root : 0);
            }

            cv = First8(Compress(cv, words, index, (uint)take, flags));
            pos += take;
            blocks++;
        }

        return cv;
    }

    private static uint[] ParentCv(uint[] left, uint[] right, bool root)
    {
        Span<uint> block = stackalloc uint[16];
        left.AsSpan().CopyTo(block);
        right.AsSpan().CopyTo(block[8..]);
        return First8(Compress(Iv, block, 0, BlockSize, Parent | (root ? Root : 0)));
    }

    private static uint[] First8(uint[] state) => state[..8];

    private static void LoadWords(ReadOnlySpan<byte> src, Span<uint> dst)
    {
        dst.Clear();
        int full = src.Length >> 2;
        for (int i = 0; i < full; i++)
        {
            dst[i] = BinaryPrimitives.ReadUInt32LittleEndian(src.Slice(4 * i, 4));
        }

        int rem = src.Length & 3;
        if (rem > 0)
        {
            // Sub-word tail: the block is zero-padded; assemble the little-endian remainder
            // by hand because the primitive reader demands a full four bytes.
            uint v = 0;
            ReadOnlySpan<byte> tail = src.Slice(4 * full, rem);
            for (int i = 0; i < rem; i++)
            {
                v |= (uint)tail[i] << (8 * i);
            }

            dst[full] = v;
        }
    }

    private static byte[] WordsToHash(uint[] words)
    {
        byte[] hash = new byte[32];
        for (int i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(hash.AsSpan(4 * i), words[i]);
        }

        return hash;
    }

    /// <summary>The BLAKE3 compression function. State layout per the reference: cv, IV[0..4],
    /// 64-bit counter, block length, flags; seven rounds over the permuted message schedule;
    /// final half-word XOR fold against both cv and IV.</summary>
    private static uint[] Compress(uint[] cv, ReadOnlySpan<uint> block, ulong counter, uint blockLen, uint flags)
    {
        var state = new uint[16];
        cv.AsSpan().CopyTo(state.AsSpan(0, 8));
        state[8] = Iv[0];
        state[9] = Iv[1];
        state[10] = Iv[2];
        state[11] = Iv[3];
        state[12] = (uint)counter;
        state[13] = (uint)(counter >> 32);
        state[14] = blockLen;
        state[15] = flags;

        var m = block.ToArray();
        for (int round = 0; round < 7; round++)
        {
            Round(state, m);
            var permuted = new uint[16];
            for (int i = 0; i < 16; i++)
            {
                permuted[i] = m[Permutation[i]];
            }

            m = permuted;
        }

        for (int i = 0; i < 8; i++)
        {
            state[i] ^= state[i + 8];
            state[i + 8] ^= cv[i];
        }

        return state;
    }

    private static void Round(uint[] s, uint[] m)
    {
        G(s, 0, 4, 8, 12, m[0], m[1]);
        G(s, 1, 5, 9, 13, m[2], m[3]);
        G(s, 2, 6, 10, 14, m[4], m[5]);
        G(s, 3, 7, 11, 15, m[6], m[7]);
        G(s, 0, 5, 10, 15, m[8], m[9]);
        G(s, 1, 6, 11, 12, m[10], m[11]);
        G(s, 2, 7, 8, 13, m[12], m[13]);
        G(s, 3, 4, 9, 14, m[14], m[15]);
    }

    private static void G(uint[] s, int a, int b, int c, int d, uint mx, uint my)
    {
        s[a] = s[a] + s[b] + mx;
        s[d] = BitOperations.RotateRight(s[d] ^ s[a], 16);
        s[c] = s[c] + s[d];
        s[b] = BitOperations.RotateRight(s[b] ^ s[c], 12);
        s[a] = s[a] + s[b] + my;
        s[d] = BitOperations.RotateRight(s[d] ^ s[a], 8);
        s[c] = s[c] + s[d];
        s[b] = BitOperations.RotateRight(s[b] ^ s[c], 7);
    }
}
