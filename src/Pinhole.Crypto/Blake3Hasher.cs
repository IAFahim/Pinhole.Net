namespace Pinhole.Crypto;

// Incremental BLAKE3 over the three modes. Construction allocates the fixed working
// buffers once; Update and Finish are allocation-free. Not thread-safe.
public sealed class Blake3Hasher
{
    private readonly uint[] _cvInit = new uint[8];
    private readonly uint _baseFlags;
    private readonly uint[] _stack = new uint[8 * Blake3.MaxStackDepth];
    private readonly long[] _stackChunks = new long[Blake3.MaxStackDepth];
    private readonly byte[] _pending = new byte[Blake3.ChunkSize];
    private int _pendingLen;
    private ulong _chunkCounter;
    private long _totalBytes;
    private int _stackCount;

    public Blake3Hasher()
    {
        Blake3.IvWords.CopyTo(_cvInit);
    }

    public Blake3Hasher(ReadOnlySpan<byte> key)
    {
        if (key.Length != Blake3.DigestLength)
        {
            throw new ArgumentException("key must be 32 bytes");
        }

        Blake3.KeyToWords(key, _cvInit);
        _baseFlags = Blake3.KeyedHash;
    }

    private Blake3Hasher(ReadOnlySpan<uint> cvInit, uint baseFlags)
    {
        cvInit.CopyTo(_cvInit);
        _baseFlags = baseFlags;
    }

    public static Blake3Hasher ForDeriveKey(ReadOnlySpan<byte> context)
    {
        Span<byte> contextKey = stackalloc byte[Blake3.DigestLength];
        Blake3.ContextKey(context, contextKey);
        Span<uint> words = stackalloc uint[8];
        Blake3.KeyToWords(contextKey, words);
        return new Blake3Hasher(words, Blake3.DeriveKeyMaterial);
    }

    public long TotalBytes => _totalBytes;

    public void Update(ReadOnlySpan<byte> data)
    {
        Blake3.UpdateChunks(data, _cvInit, _baseFlags, _pending, ref _pendingLen, ref _chunkCounter,
            ref _totalBytes, _stack, _stackChunks, ref _stackCount);
    }

    public byte[] Finish()
    {
        byte[] digest = new byte[Blake3.DigestLength];
        Finish(digest);
        return digest;
    }

    public void Finish(Span<byte> digest)
    {
        Blake3.FinishChunks(digest, _cvInit, _baseFlags, _pending, _pendingLen, _chunkCounter, _stack, _stackCount);
    }
}
