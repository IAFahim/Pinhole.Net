using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Pinhole.Crypto;

public static class Blake3
{
    public const int ChunkSize = 1024;
    public const int BlockSize = 64;
    public const int DigestLength = 32;

    internal const uint ChunkStart = 1u << 0;
    internal const uint ChunkEnd = 1u << 1;
    internal const uint Parent = 1u << 2;
    internal const uint Root = 1u << 3;
    internal const uint KeyedHash = 1u << 4;
    internal const uint DeriveKeyContext = 1u << 5;
    internal const uint DeriveKeyMaterial = 1u << 6;

    internal const int MaxStackDepth = 64;

    internal const int BatchChunks = 512;

    private static readonly int[] BatchSizes = [512, 256, 128, 64, 32, 16, 8];

    [ThreadStatic]
    internal static bool SimdBypass;

    internal static ReadOnlySpan<uint> IvWords => Iv.AsSpan();

    internal static void KeyToWords(ReadOnlySpan<byte> key32, Span<uint> words) => LoadWords(key32, words);

    internal static void ContextKey(ReadOnlySpan<byte> context, Span<byte> contextKey)
    {
        Span<uint> stack = stackalloc uint[8 * MaxStackDepth];
        RunStreaming(context, Iv, DeriveKeyContext, contextKey, ref stack);
    }

    private static readonly uint[] Iv =
    [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    private static readonly byte[] Permutation = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    public static byte[] Hash(ReadOnlySpan<byte> data)
    {
        byte[] digest = new byte[DigestLength];
        Hash(data, digest);
        return digest;
    }

    public static void Hash(ReadOnlySpan<byte> data, Span<byte> digest)
    {
        if (digest.Length < DigestLength) ThrowDigestTooSmall();
        Span<uint> stack = stackalloc uint[8 * MaxStackDepth];
        RunStreaming(data, Iv, 0, digest, ref stack);
    }

    public static byte[] HashKeyed(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        byte[] digest = new byte[DigestLength];
        HashKeyed(key, data, digest);
        return digest;
    }

    public static void HashKeyed(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> digest)
    {
        if (digest.Length < DigestLength) ThrowDigestTooSmall();
        if (key.Length != DigestLength) ThrowKeySize();
        Span<uint> keyWords = stackalloc uint[8];
        LoadWords(key, keyWords);
        Span<uint> stack = stackalloc uint[8 * MaxStackDepth];
        RunStreaming(data, keyWords, KeyedHash, digest, ref stack);
    }

    public static byte[] HashDeriveKey(ReadOnlySpan<byte> context, ReadOnlySpan<byte> material)
    {
        byte[] digest = new byte[DigestLength];
        HashDeriveKey(context, material, digest);
        return digest;
    }

    public static void HashDeriveKey(ReadOnlySpan<byte> context, ReadOnlySpan<byte> material, Span<byte> digest)
    {
        if (digest.Length < DigestLength) ThrowDigestTooSmall();
        Span<uint> stack = stackalloc uint[8 * MaxStackDepth];
        Span<byte> contextKey = stackalloc byte[DigestLength];
        ContextKey(context, contextKey);
        Span<uint> contextWords = stackalloc uint[8];
        LoadWords(contextKey, contextWords);
        RunStreaming(material, contextWords, DeriveKeyMaterial, digest, ref stack);
    }

    public static int HashChunks(ReadOnlySpan<byte> data, ulong firstChunkIndex, Span<uint> chunkCvs)
    {
        return HashBatch(data, firstChunkIndex, chunkCvs.Length / 8, Iv, 0, chunkCvs);
    }

    public static void HashChunk(ReadOnlySpan<byte> chunk, ulong chunkIndex, bool root, Span<uint> cvOut)
    {
        if (chunk.Length > ChunkSize) ThrowChunkTooBig();
        if (cvOut.Length < 8) ThrowCvTooSmall();
        HashChunkWords(chunk, chunkIndex, Iv, 0, root, cvOut);
    }

    public static int ReduceLevel(Span<uint> cvs, int nodeCount)
    {
        return ReduceLevelInto(cvs, nodeCount, Iv, 0);
    }

    public static void RootFromTopPair(ReadOnlySpan<uint> left, ReadOnlySpan<uint> right, Span<byte> digest)
    {
        if (digest.Length < DigestLength) ThrowDigestTooSmall();
        Span<uint> rootCv = stackalloc uint[8];
        ParentWords(left, right, Iv, 0, root: true, rootCv);
        WordsToBytes(rootCv, digest);
    }

    public static void Compress(ReadOnlySpan<uint> cv, ReadOnlySpan<uint> blockWords, ulong counter, uint blockLength, uint flags, Span<uint> output)
    {
        if (cv.Length < 8 || blockWords.Length < 16 || output.Length < 16) ThrowCompressShapes();
        Span<uint> s = stackalloc uint[16];
        cv[..8].CopyTo(s);
        s[8] = Iv[0];
        s[9] = Iv[1];
        s[10] = Iv[2];
        s[11] = Iv[3];
        s[12] = unchecked((uint)counter);
        s[13] = unchecked((uint)(counter >> 32));
        s[14] = blockLength;
        s[15] = flags;
        Span<uint> m = stackalloc uint[16];
        blockWords[..16].CopyTo(m);
        Span<uint> t = stackalloc uint[16];
        for (int round = 0; round < 7; round++)
        {
            Round(s, m);
            if (round < 6)
            {
                for (int i = 0; i < 16; i++)
                {
                    t[i] = m[Permutation[i]];
                }

                t.CopyTo(m);
            }
        }

        for (int i = 0; i < 8; i++)
        {
            s[i] ^= s[i + 8];
            s[i + 8] ^= cv[i];
        }

        s.CopyTo(output);
    }

    internal static void HashChunkWords(ReadOnlySpan<byte> chunk, ulong chunkIndex, ReadOnlySpan<uint> cvInit, uint baseFlags, bool root, Span<uint> cvOut)
    {
        Span<uint> cv = stackalloc uint[8];
        cvInit[..8].CopyTo(cv);
        Span<uint> m = stackalloc uint[16];
        Span<uint> s = stackalloc uint[16];
        if (chunk.Length == 0)
        {
            m.Clear();
            Compress(cv, m, chunkIndex, 0, baseFlags | ChunkStart | ChunkEnd | (root ? Root : 0), s);
            s[..8].CopyTo(cvOut);
            return;
        }

        int pos = 0;
        uint carried = baseFlags | ChunkStart;
        while (pos < chunk.Length)
        {
            int take = Math.Min(BlockSize, chunk.Length - pos);
            LoadWords(chunk.Slice(pos, take), m);
            bool last = pos + take == chunk.Length;
            uint flags = carried | (last ? ChunkEnd | (root ? Root : 0) : 0);
            Compress(cv, m, chunkIndex, (uint)take, flags, s);
            s[..8].CopyTo(cv);
            pos += take;
            carried = baseFlags;
        }

        cv.CopyTo(cvOut);
    }

    internal static void ParentWords(ReadOnlySpan<uint> left, ReadOnlySpan<uint> right, ReadOnlySpan<uint> cvInit, uint baseFlags, bool root, Span<uint> out8)
    {
        Span<uint> block = stackalloc uint[16];
        left[..8].CopyTo(block[..8]);
        right[..8].CopyTo(block[8..]);
        Span<uint> s = stackalloc uint[16];
        Compress(cvInit, block, 0, BlockSize, baseFlags | Parent | (root ? Root : 0), s);
        s[..8].CopyTo(out8);
    }

    internal static int ReduceLevelInto(Span<uint> cvs, int nodeCount, ReadOnlySpan<uint> cvInit, uint baseFlags)
    {
        if (nodeCount < 2)
        {
            return nodeCount;
        }

        int parents = nodeCount / 2;
        int vectorPairs = Vector256.IsHardwareAccelerated && !SimdBypass ? (parents / 8) * 8 : 0;
        for (int p = 0; p < vectorPairs; p += 8)
        {
            ParentColumn256(cvs, p, cvs, 8 * p, cvInit, baseFlags);
        }

        for (int p = vectorPairs; p < parents; p++)
        {
            ParentWords(cvs.Slice(16 * p, 8), cvs.Slice((16 * p) + 8, 8), cvInit, baseFlags, root: false, cvs.Slice(8 * p, 8));
        }

        if ((nodeCount & 1) != 0)
        {
            cvs.Slice(8 * (nodeCount - 1), 8).CopyTo(cvs.Slice(8 * parents, 8));
            parents++;
        }

        return parents;
    }

    private static void ParentColumn256(ReadOnlySpan<uint> src, int firstPair, Span<uint> dst, int firstParent,
        ReadOnlySpan<uint> cvInit, uint baseFlags)
    {
        Vector256<uint> s0 = Vector256.Create(cvInit[0]);
        Vector256<uint> s1 = Vector256.Create(cvInit[1]);
        Vector256<uint> s2 = Vector256.Create(cvInit[2]);
        Vector256<uint> s3 = Vector256.Create(cvInit[3]);
        Vector256<uint> s4 = Vector256.Create(cvInit[4]);
        Vector256<uint> s5 = Vector256.Create(cvInit[5]);
        Vector256<uint> s6 = Vector256.Create(cvInit[6]);
        Vector256<uint> s7 = Vector256.Create(cvInit[7]);
        Vector256<uint> m0 = default, m1 = default, m2 = default, m3 = default,
            m4 = default, m5 = default, m6 = default, m7 = default,
            m8 = default, m9 = default, m10 = default, m11 = default,
            m12 = default, m13 = default, m14 = default, m15 = default;
        ref uint r = ref MemoryMarshal.GetReference(src);
        r = ref Unsafe.Add(ref r, firstPair * 16);
        nint laneStride = 16 * 4;

        LoadMessage256(ref Unsafe.As<uint, byte>(ref r), 0, laneStride,
            ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
            ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);

        Vector256<uint> s8 = Vector256.Create(Iv[0]);
        Vector256<uint> s9 = Vector256.Create(Iv[1]);
        Vector256<uint> s10 = Vector256.Create(Iv[2]);
        Vector256<uint> s11 = Vector256.Create(Iv[3]);
        Vector256<uint> s12 = Vector256.Create(0u);
        Vector256<uint> s13 = Vector256.Create(0u);
        Vector256<uint> s14 = Vector256.Create((uint)BlockSize);
        Vector256<uint> s15 = Vector256.Create(baseFlags | Parent);

        for (int round = 0; round < 7; round++)
        {
            G256(ref s0, ref s4, ref s8, ref s12, m0, m1);
            G256(ref s1, ref s5, ref s9, ref s13, m2, m3);
            G256(ref s2, ref s6, ref s10, ref s14, m4, m5);
            G256(ref s3, ref s7, ref s11, ref s15, m6, m7);
            G256(ref s0, ref s5, ref s10, ref s15, m8, m9);
            G256(ref s1, ref s6, ref s11, ref s12, m10, m11);
            G256(ref s2, ref s7, ref s8, ref s13, m12, m13);
            G256(ref s3, ref s4, ref s9, ref s14, m14, m15);
            if (round < 6)
            {
                Vector256<uint> t0 = m2, t1 = m6, t2 = m3, t3 = m10, t4 = m7, t5 = m0, t6 = m4, t7 = m13,
                    t8 = m1, t9 = m11, t10 = m12, t11 = m5, t12 = m9, t13 = m14, t14 = m15, t15 = m8;
                m0 = t0; m1 = t1; m2 = t2; m3 = t3; m4 = t4; m5 = t5; m6 = t6; m7 = t7;
                m8 = t8; m9 = t9; m10 = t10; m11 = t11; m12 = t12; m13 = t13; m14 = t14; m15 = t15;
            }
        }

        s0 ^= s8;
        s1 ^= s9;
        s2 ^= s10;
        s3 ^= s11;
        s4 ^= s12;
        s5 ^= s13;
        s6 ^= s14;
        s7 ^= s15;
        StoreLanes256(dst, firstParent, s0, s1, s2, s3, s4, s5, s6, s7);
    }

    internal static int HashBatch(ReadOnlySpan<byte> data, ulong firstIndex, int maxChunks, ReadOnlySpan<uint> cvInit, uint baseFlags, Span<uint> cvs)
    {
        int total = Math.Min(data.Length / ChunkSize, maxChunks);
        int done = 0;
        if (!SimdBypass)
        {
            if (Vector256.IsHardwareAccelerated)
            {
                while (total - done >= 8)
                {
                    HashChunkColumn256(data.Slice(done * ChunkSize, 8 * ChunkSize), firstIndex + (ulong)done, cvInit, baseFlags, cvs.Slice(done * 8, 64));
                    done += 8;
                }
            }
            else if (Vector128.IsHardwareAccelerated)
            {
                while (total - done >= 4)
                {
                    HashChunkColumn128(data.Slice(done * ChunkSize, 4 * ChunkSize), firstIndex + (ulong)done, cvInit, baseFlags, cvs.Slice(done * 8, 32));
                    done += 4;
                }
            }
        }

        for (; done < total; done++)
        {
            HashChunkWords(data.Slice(done * ChunkSize, ChunkSize), firstIndex + (ulong)done, cvInit, baseFlags, root: false, cvs.Slice(done * 8, 8));
        }

        return total;
    }

    internal static void UpdateChunks(ReadOnlySpan<byte> data, ReadOnlySpan<uint> cvInit, uint baseFlags,
        Span<byte> pending, ref int pendingLen, ref ulong chunkCounter, ref long totalBytes,
        Span<uint> stack, Span<long> stackChunks, ref int stackCount)
    {
        totalBytes += data.Length;

        if (!SimdBypass && pendingLen == 0)
        {
            Span<uint> group = stackalloc uint[8 * BatchChunks];
            foreach (int size in BatchSizes)
            {
                while (chunkCounter % (ulong)size == 0 && data.Length >= (size + 1) * ChunkSize)
                {
                    HashBatch(data, chunkCounter, size, cvInit, baseFlags, group);
                    int nodes = size;
                    while (nodes > 1)
                    {
                        nodes = ReduceLevelInto(group, nodes, cvInit, baseFlags);
                    }

                    PushCv(group, size, stack, stackChunks, ref stackCount, cvInit, baseFlags);
                    data = data[(size * ChunkSize)..];
                    chunkCounter += (ulong)size;
                }
            }
        }

        Span<uint> chunkCv = stackalloc uint[8];
        while (data.Length > 0)
        {
            int take = Math.Min(data.Length, ChunkSize - pendingLen);
            data[..take].CopyTo(pending.Slice(pendingLen, take));
            pendingLen += take;
            data = data[take..];

            if (pendingLen == ChunkSize && data.Length > 0)
            {
                HashChunkWords(pending, chunkCounter, cvInit, baseFlags, root: false, chunkCv);
                PushCv(chunkCv, 1, stack, stackChunks, ref stackCount, cvInit, baseFlags);
                pendingLen = 0;
                chunkCounter++;
            }
        }
    }

    internal static void FinishChunks(Span<byte> digest, ReadOnlySpan<uint> cvInit, uint baseFlags,
        Span<byte> pending, int pendingLen, ulong chunkCounter, Span<uint> stack, int stackCount)
    {
        Span<uint> acc = stackalloc uint[8];
        if (stackCount == 0)
        {

            HashChunkWords(pending[..pendingLen], 0, cvInit, baseFlags, root: true, acc);
            WordsToBytes(acc, digest);
            return;
        }

        if (pendingLen == 0)
        {

            throw new InvalidOperationException("finish called with an open stack but no pending chunk");
        }

        HashChunkWords(pending[..pendingLen], chunkCounter, cvInit, baseFlags, root: false, acc);
        Span<uint> parent = stackalloc uint[8];
        for (int i = stackCount - 1; i >= 0; i--)
        {
            ParentWords(stack.Slice(8 * i, 8), acc, cvInit, baseFlags, root: i == 0, parent);
            parent.CopyTo(acc);
        }

        WordsToBytes(acc, digest);
    }

    internal static void PushCv(ReadOnlySpan<uint> cv, long chunks,
        Span<uint> stack, Span<long> stackChunks, ref int stackCount, ReadOnlySpan<uint> cvInit, uint baseFlags)
    {
        cv[..8].CopyTo(stack.Slice(8 * stackCount, 8));
        stackChunks[stackCount] = chunks;
        stackCount++;
        Span<uint> merged = stackalloc uint[8];
        while (stackCount >= 2 && stackChunks[stackCount - 1] == stackChunks[stackCount - 2])
        {
            ParentWords(stack.Slice(8 * (stackCount - 2), 8), stack.Slice(8 * (stackCount - 1), 8), cvInit, baseFlags, root: false, merged);
            merged.CopyTo(stack.Slice(8 * (stackCount - 2), 8));
            stackChunks[stackCount - 2] += stackChunks[stackCount - 1];
            stackCount--;
        }
    }

    private static void RunStreaming(ReadOnlySpan<byte> data, ReadOnlySpan<uint> cvInit, uint baseFlags, Span<byte> digest, ref Span<uint> stack)
    {
        Span<byte> pending = stackalloc byte[ChunkSize];
        Span<long> stackChunks = stackalloc long[MaxStackDepth];
        int pendingLen = 0;
        ulong chunkCounter = 0;
        long totalBytes = 0;
        int stackCount = 0;
        UpdateChunks(data, cvInit, baseFlags, pending, ref pendingLen, ref chunkCounter, ref totalBytes,
            stack, stackChunks, ref stackCount);
        FinishChunks(digest, cvInit, baseFlags, pending, pendingLen, chunkCounter, stack, stackCount);
    }

    private static void Round(Span<uint> s, ReadOnlySpan<uint> m)
    {
        G(ref s[0], ref s[4], ref s[8], ref s[12], m[0], m[1]);
        G(ref s[1], ref s[5], ref s[9], ref s[13], m[2], m[3]);
        G(ref s[2], ref s[6], ref s[10], ref s[14], m[4], m[5]);
        G(ref s[3], ref s[7], ref s[11], ref s[15], m[6], m[7]);
        G(ref s[0], ref s[5], ref s[10], ref s[15], m[8], m[9]);
        G(ref s[1], ref s[6], ref s[11], ref s[12], m[10], m[11]);
        G(ref s[2], ref s[7], ref s[8], ref s[13], m[12], m[13]);
        G(ref s[3], ref s[4], ref s[9], ref s[14], m[14], m[15]);
    }

    private static void G(ref uint a, ref uint b, ref uint c, ref uint d, uint mx, uint my)
    {
        a += b + mx;
        d = BitOperations.RotateRight(d ^ a, 16);
        c += d;
        b = BitOperations.RotateRight(b ^ c, 12);
        a += b + my;
        d = BitOperations.RotateRight(d ^ a, 8);
        c += d;
        b = BitOperations.RotateRight(b ^ c, 7);
    }

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

            uint v = 0;
            ReadOnlySpan<byte> tail = src.Slice(4 * full, rem);
            for (int i = 0; i < rem; i++)
            {
                v |= (uint)tail[i] << (8 * i);
            }

            dst[full] = v;
        }
    }

    private static void WordsToBytes(ReadOnlySpan<uint> words, Span<byte> digest)
    {
        for (int i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(digest.Slice(4 * i), words[i]);
        }
    }

    private static void HashChunkColumn256(ReadOnlySpan<byte> data, ulong firstIndex, ReadOnlySpan<uint> cvInit, uint baseFlags, Span<uint> cvs)
    {

        Vector256<uint> s0 = Vector256.Create(cvInit[0]);
        Vector256<uint> s1 = Vector256.Create(cvInit[1]);
        Vector256<uint> s2 = Vector256.Create(cvInit[2]);
        Vector256<uint> s3 = Vector256.Create(cvInit[3]);
        Vector256<uint> s4 = Vector256.Create(cvInit[4]);
        Vector256<uint> s5 = Vector256.Create(cvInit[5]);
        Vector256<uint> s6 = Vector256.Create(cvInit[6]);
        Vector256<uint> s7 = Vector256.Create(cvInit[7]);
        Vector256<uint> m0 = default, m1 = default, m2 = default, m3 = default,
            m4 = default, m5 = default, m6 = default, m7 = default,
            m8 = default, m9 = default, m10 = default, m11 = default,
            m12 = default, m13 = default, m14 = default, m15 = default;
        ref byte b = ref MemoryMarshal.GetReference(data);
        nint laneStride = ChunkSize;

        for (int block = 0; block < ChunkSize / BlockSize; block++)
        {
            nint offset = block * BlockSize;
            LoadMessage256(ref b, offset, laneStride,
                ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
                ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);

            Vector256<uint> s8 = Vector256.Create(Iv[0]);
            Vector256<uint> s9 = Vector256.Create(Iv[1]);
            Vector256<uint> s10 = Vector256.Create(Iv[2]);
            Vector256<uint> s11 = Vector256.Create(Iv[3]);
            Vector256<uint> s12 = Vector256.Create(
                unchecked((uint)(firstIndex + 0)), unchecked((uint)(firstIndex + 1)), unchecked((uint)(firstIndex + 2)), unchecked((uint)(firstIndex + 3)),
                unchecked((uint)(firstIndex + 4)), unchecked((uint)(firstIndex + 5)), unchecked((uint)(firstIndex + 6)), unchecked((uint)(firstIndex + 7)));
            Vector256<uint> s13 = Vector256.Create(
                unchecked((uint)((firstIndex + 0) >> 32)), unchecked((uint)((firstIndex + 1) >> 32)), unchecked((uint)((firstIndex + 2) >> 32)), unchecked((uint)((firstIndex + 3) >> 32)),
                unchecked((uint)((firstIndex + 4) >> 32)), unchecked((uint)((firstIndex + 5) >> 32)), unchecked((uint)((firstIndex + 6) >> 32)), unchecked((uint)((firstIndex + 7) >> 32)));
            Vector256<uint> s14 = Vector256.Create((uint)BlockSize);
            Vector256<uint> s15 = Vector256.Create(baseFlags | ChunkStartOrEndFlags(block));

            for (int round = 0; round < 7; round++)
            {
                G256(ref s0, ref s4, ref s8, ref s12, m0, m1);
                G256(ref s1, ref s5, ref s9, ref s13, m2, m3);
                G256(ref s2, ref s6, ref s10, ref s14, m4, m5);
                G256(ref s3, ref s7, ref s11, ref s15, m6, m7);
                G256(ref s0, ref s5, ref s10, ref s15, m8, m9);
                G256(ref s1, ref s6, ref s11, ref s12, m10, m11);
                G256(ref s2, ref s7, ref s8, ref s13, m12, m13);
                G256(ref s3, ref s4, ref s9, ref s14, m14, m15);
                if (round < 6)
                {
                    Vector256<uint> t0 = m2, t1 = m6, t2 = m3, t3 = m10, t4 = m7, t5 = m0, t6 = m4, t7 = m13,
                        t8 = m1, t9 = m11, t10 = m12, t11 = m5, t12 = m9, t13 = m14, t14 = m15, t15 = m8;
                    m0 = t0; m1 = t1; m2 = t2; m3 = t3; m4 = t4; m5 = t5; m6 = t6; m7 = t7;
                    m8 = t8; m9 = t9; m10 = t10; m11 = t11; m12 = t12; m13 = t13; m14 = t14; m15 = t15;
                }
            }

            s0 ^= s8;
            s1 ^= s9;
            s2 ^= s10;
            s3 ^= s11;
            s4 ^= s12;
            s5 ^= s13;
            s6 ^= s14;
            s7 ^= s15;
        }

        StoreLanes256(cvs, 0, s0, s1, s2, s3, s4, s5, s6, s7);
    }

    private static void LoadMessage256(ref byte baseRef, nint blockOffset, nint laneStride,
        ref Vector256<uint> m0, ref Vector256<uint> m1, ref Vector256<uint> m2, ref Vector256<uint> m3,
        ref Vector256<uint> m4, ref Vector256<uint> m5, ref Vector256<uint> m6, ref Vector256<uint> m7,
        ref Vector256<uint> m8, ref Vector256<uint> m9, ref Vector256<uint> m10, ref Vector256<uint> m11,
        ref Vector256<uint> m12, ref Vector256<uint> m13, ref Vector256<uint> m14, ref Vector256<uint> m15)
    {
        Transpose8(ref baseRef, blockOffset, laneStride, 0,
            ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7);
        Transpose8(ref baseRef, blockOffset, laneStride, 32,
            ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);
    }

    private static void Transpose8(ref byte baseRef, nint blockOffset, nint laneStride, nint wordByte,
        ref Vector256<uint> m0, ref Vector256<uint> m1, ref Vector256<uint> m2, ref Vector256<uint> m3,
        ref Vector256<uint> m4, ref Vector256<uint> m5, ref Vector256<uint> m6, ref Vector256<uint> m7)
    {
        Transpose4(ref baseRef, blockOffset + wordByte, laneStride, 0, 0, out Vector128<uint> a0, out Vector128<uint> a1, out Vector128<uint> a2, out Vector128<uint> a3);
        Transpose4(ref baseRef, blockOffset + wordByte, laneStride, 0, 16, out Vector128<uint> b0, out Vector128<uint> b1, out Vector128<uint> b2, out Vector128<uint> b3);
        Transpose4(ref baseRef, blockOffset + wordByte, laneStride, 4, 0, out Vector128<uint> c0, out Vector128<uint> c1, out Vector128<uint> c2, out Vector128<uint> c3);
        Transpose4(ref baseRef, blockOffset + wordByte, laneStride, 4, 16, out Vector128<uint> d0, out Vector128<uint> d1, out Vector128<uint> d2, out Vector128<uint> d3);
        m0 = Vector256.Create(a0, c0);
        m1 = Vector256.Create(a1, c1);
        m2 = Vector256.Create(a2, c2);
        m3 = Vector256.Create(a3, c3);
        m4 = Vector256.Create(b0, d0);
        m5 = Vector256.Create(b1, d1);
        m6 = Vector256.Create(b2, d2);
        m7 = Vector256.Create(b3, d3);
    }

    private static void Transpose4(ref byte baseRef, nint byteOffset, nint laneStride, int laneBase, nint wordByte,
        out Vector128<uint> r0, out Vector128<uint> r1, out Vector128<uint> r2, out Vector128<uint> r3)
    {
        Vector128<uint> x0 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref baseRef, byteOffset + wordByte + (laneBase + 0) * laneStride));
        Vector128<uint> x1 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref baseRef, byteOffset + wordByte + (laneBase + 1) * laneStride));
        Vector128<uint> x2 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref baseRef, byteOffset + wordByte + (laneBase + 2) * laneStride));
        Vector128<uint> x3 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref baseRef, byteOffset + wordByte + (laneBase + 3) * laneStride));
        Vector128<uint> lo01 = Sse2.UnpackLow(x0, x1);
        Vector128<uint> hi01 = Sse2.UnpackHigh(x0, x1);
        Vector128<uint> lo23 = Sse2.UnpackLow(x2, x3);
        Vector128<uint> hi23 = Sse2.UnpackHigh(x2, x3);
        Vector128<ulong> p0 = Sse2.UnpackLow(lo01.AsUInt64(), lo23.AsUInt64());
        Vector128<ulong> p1 = Sse2.UnpackHigh(lo01.AsUInt64(), lo23.AsUInt64());
        Vector128<ulong> p2 = Sse2.UnpackLow(hi01.AsUInt64(), hi23.AsUInt64());
        Vector128<ulong> p3 = Sse2.UnpackHigh(hi01.AsUInt64(), hi23.AsUInt64());
        r0 = p0.AsUInt32();
        r1 = p1.AsUInt32();
        r2 = p2.AsUInt32();
        r3 = p3.AsUInt32();
    }

    private static void StoreLanes256(Span<uint> cvs, int baseIndex,
        Vector256<uint> s0, Vector256<uint> s1, Vector256<uint> s2, Vector256<uint> s3,
        Vector256<uint> s4, Vector256<uint> s5, Vector256<uint> s6, Vector256<uint> s7)
    {
        for (int lane = 0; lane < 8; lane++)
        {
            cvs[baseIndex + (lane * 8) + 0] = s0.GetElement(lane);
            cvs[baseIndex + (lane * 8) + 1] = s1.GetElement(lane);
            cvs[baseIndex + (lane * 8) + 2] = s2.GetElement(lane);
            cvs[baseIndex + (lane * 8) + 3] = s3.GetElement(lane);
            cvs[baseIndex + (lane * 8) + 4] = s4.GetElement(lane);
            cvs[baseIndex + (lane * 8) + 5] = s5.GetElement(lane);
            cvs[baseIndex + (lane * 8) + 6] = s6.GetElement(lane);
            cvs[baseIndex + (lane * 8) + 7] = s7.GetElement(lane);
        }
    }

    private static void G256(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d,
        Vector256<uint> mx, Vector256<uint> my)
    {
        a = a + b + mx;
        Vector256<uint> x = d ^ a;
        d = (x >>> 16) | (x << 16);
        c = c + d;
        x = b ^ c;
        b = (x >>> 12) | (x << 20);
        a = a + b + my;
        x = d ^ a;
        d = (x >>> 8) | (x << 24);
        c = c + d;
        x = b ^ c;
        b = (x >>> 7) | (x << 25);
    }

    private static void HashChunkColumn128(ReadOnlySpan<byte> data, ulong firstIndex, ReadOnlySpan<uint> cvInit, uint baseFlags, Span<uint> cvs)
    {
        Span<Vector128<uint>> s = stackalloc Vector128<uint>[16];
        Span<Vector128<uint>> m = stackalloc Vector128<uint>[16];
        Span<Vector128<uint>> t = stackalloc Vector128<uint>[16];
        for (int i = 0; i < 8; i++)
        {
            s[i] = Vector128.Create(cvInit[i]);
        }

        for (int block = 0; block < ChunkSize / BlockSize; block++)
        {
            int offset = block * (BlockSize / 4);
            for (int w = 0; w < 16; w++)
            {
                m[w] = Vector128.Create(
                    Word(data, 0, offset + w), Word(data, 1, offset + w), Word(data, 2, offset + w), Word(data, 3, offset + w));
            }

            s[8] = Vector128.Create(Iv[0]);
            s[9] = Vector128.Create(Iv[1]);
            s[10] = Vector128.Create(Iv[2]);
            s[11] = Vector128.Create(Iv[3]);
            s[12] = Vector128.Create(
                unchecked((uint)(firstIndex + 0)), unchecked((uint)(firstIndex + 1)),
                unchecked((uint)(firstIndex + 2)), unchecked((uint)(firstIndex + 3)));
            s[13] = Vector128.Create(
                unchecked((uint)((firstIndex + 0) >> 32)), unchecked((uint)((firstIndex + 1) >> 32)),
                unchecked((uint)((firstIndex + 2) >> 32)), unchecked((uint)((firstIndex + 3) >> 32)));
            s[14] = Vector128.Create((uint)BlockSize);
            s[15] = Vector128.Create(baseFlags | ChunkStartOrEndFlags(block));

            for (int round = 0; round < 7; round++)
            {
                Round128(s, m);
                if (round < 6)
                {
                    for (int i = 0; i < 16; i++)
                    {
                        t[i] = m[Permutation[i]];
                    }

                    t.CopyTo(m);
                }
            }

            for (int i = 0; i < 8; i++)
            {
                s[i] = Vector128.Xor(s[i], s[i + 8]);
            }
        }

        for (int lane = 0; lane < 4; lane++)
        {
            for (int w = 0; w < 8; w++)
            {
                cvs[(lane * 8) + w] = s[w].GetElement(lane);
            }
        }
    }

    private static void Round128(Span<Vector128<uint>> s, ReadOnlySpan<Vector128<uint>> m)
    {
        G128(ref s[0], ref s[4], ref s[8], ref s[12], m[0], m[1]);
        G128(ref s[1], ref s[5], ref s[9], ref s[13], m[2], m[3]);
        G128(ref s[2], ref s[6], ref s[10], ref s[14], m[4], m[5]);
        G128(ref s[3], ref s[7], ref s[11], ref s[15], m[6], m[7]);
        G128(ref s[0], ref s[5], ref s[10], ref s[15], m[8], m[9]);
        G128(ref s[1], ref s[6], ref s[11], ref s[12], m[10], m[11]);
        G128(ref s[2], ref s[7], ref s[8], ref s[13], m[12], m[13]);
        G128(ref s[3], ref s[4], ref s[9], ref s[14], m[14], m[15]);
    }

    private static void G128(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d,
        Vector128<uint> mx, Vector128<uint> my)
    {
        a = a + b + mx;
        Vector128<uint> x = d ^ a;
        d = (x >>> 16) | (x << 16);
        c = c + d;
        x = b ^ c;
        b = (x >>> 12) | (x << 20);
        a = a + b + my;
        x = d ^ a;
        d = (x >>> 8) | (x << 24);
        c = c + d;
        x = b ^ c;
        b = (x >>> 7) | (x << 25);
    }

    private static uint ChunkStartOrEndFlags(int block)
    {
        uint flags = 0;
        if (block == 0)
        {
            flags |= ChunkStart;
        }

        if (block == ChunkSize / BlockSize - 1)
        {
            flags |= ChunkEnd;
        }

        return flags;
    }

    private static uint Word(ReadOnlySpan<byte> data, int lane, int wordIndex)
        => BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((lane * ChunkSize) + (4 * wordIndex), 4));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ReadWord(ref byte baseRef, nint blockOffset, int lane, int word, nint laneStride)
        => Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref baseRef, blockOffset + (lane * laneStride) + (4 * (nint)word)));

    private static void ThrowDigestTooSmall() => throw new ArgumentException("digest must be at least 32 bytes");

    private static void ThrowKeySize() => throw new ArgumentException("key must be 32 bytes");

    private static void ThrowChunkTooBig() => throw new ArgumentException("chunk exceeds 1024 bytes");

    private static void ThrowCvTooSmall() => throw new ArgumentException("cv output must hold 8 words");

    private static void ThrowCompressShapes() => throw new ArgumentException("Compress needs cv[8], blockWords[16], output[16]");
}
