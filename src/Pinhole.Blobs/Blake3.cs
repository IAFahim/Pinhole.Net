using System.Buffers.Binary;

namespace Pinhole.Blobs;

// Facade over Pinhole.Crypto's zero-allocation BLAKE3. The public surface is the
// shipped blob-layer contract; every member now delegates to the shared core.
public static class Blake3
{
    public const int ChunkSize = Crypto.Blake3.ChunkSize;

    public const int BlockSize = Crypto.Blake3.BlockSize;

    public static byte[] Hash(ReadOnlySpan<byte> data) => Crypto.Blake3.Hash(data);

    public static byte[] ChunkCv(ReadOnlySpan<byte> chunk, ulong index, bool root)
    {
        Span<uint> words = stackalloc uint[8];
        Crypto.Blake3.HashChunk(chunk, index, root, words);
        byte[] cv = new byte[32];
        for (int i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(cv.AsSpan(4 * i), words[i]);
        }

        return cv;
    }

    public sealed class Tree
    {
        private readonly bool _retainOutboard;

        public Tree() : this(retainOutboard: true) { }

        internal Tree(bool retainOutboard) => _retainOutboard = retainOutboard;

        private readonly List<byte[]> _chunkCvs = new();
        private readonly uint[] _stack = new uint[8 * Crypto.Blake3.MaxStackDepth];
        private readonly long[] _stackChunks = new long[Crypto.Blake3.MaxStackDepth];
        private readonly byte[] _pending = new byte[ChunkSize];
        private int _pendingLen;
        private ulong _chunkCounter;
        private long _totalBytes;
        private int _stackCount;
        private byte[]? _root;

        public long TotalBytes => _totalBytes;

        public int ChunkCount => checked((int)_chunkCounter) + (_pendingLen > 0 || _totalBytes == 0 ? 1 : 0);

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
                    cvs[^1] = ChunkCv(_pending.AsSpan(0, _pendingLen), _chunkCounter, root: false);
                }

                return cvs;
            }
        }

        public void Update(ReadOnlySpan<byte> data)
        {
            if (_root is not null)
            {
                throw new InvalidOperationException("the tree is already finalized");
            }

            if (_retainOutboard)
            {
                // Per-chunk feeding so every completed chunk's CV lands in the outboard;
                // the shared core handles the no-outboard fast path with vectorized batches.
                Span<uint> chunkCv = stackalloc uint[8];
                while (data.Length > 0)
                {
                    int take = Math.Min(data.Length, ChunkSize - _pendingLen);
                    data[..take].CopyTo(_pending.AsSpan(_pendingLen, take));
                    _pendingLen += take;
                    data = data[take..];
                    _totalBytes += take;
                    if (_pendingLen == ChunkSize && data.Length > 0)
                    {
                        Crypto.Blake3.HashChunkWords(_pending, _chunkCounter, Crypto.Blake3.IvWords, 0, root: false, chunkCv);
                        _chunkCvs.Add(WordsToBytes(chunkCv));
                        Crypto.Blake3.PushCv(chunkCv, 1, _stack, _stackChunks, ref _stackCount, Crypto.Blake3.IvWords, 0);
                        _pendingLen = 0;
                        _chunkCounter++;
                    }
                }

                return;
            }

            Crypto.Blake3.UpdateChunks(data, Crypto.Blake3.IvWords, 0, _pending, ref _pendingLen, ref _chunkCounter,
                ref _totalBytes, _stack, _stackChunks, ref _stackCount);
        }

        public byte[] RootHash()
        {
            if (_root is not null)
            {
                return _root;
            }

            byte[] digest = new byte[32];
            Crypto.Blake3.FinishChunks(digest, Crypto.Blake3.IvWords, 0, _pending, _pendingLen, _chunkCounter, _stack, _stackCount);
            return _root = digest;
        }

        private static byte[] WordsToBytes(ReadOnlySpan<uint> words)
        {
            byte[] cv = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(cv.AsSpan(4 * i), words[i]);
            }

            return cv;
        }
    }
}
