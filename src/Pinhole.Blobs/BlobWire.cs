using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using ChaChaPoly = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;
using Org.BouncyCastle.Crypto.Parameters;

namespace Pinhole.Blobs;

/// <summary>The blob-layer wire protocol: small frames tunneled inside Pinhole Data
/// datagrams, optionally wrapped in ChaCha20-Poly1305 so the public relays forward nothing
/// but ciphertext. One blob stream per BLAKE3 root (its first 8 bytes, big endian, are the
/// stream id); the downloader drives with range requests, the provider answers with
/// self-describing verified chunks. Frame sizes are tuned so the largest (a 1 KiB chunk)
/// stays under the connection's 1200-byte datagram budget, encrypted included.</summary>
internal static class BlobWire
{
    internal const byte TypeHello = 1;
    internal const byte TypeHead = 2;
    internal const byte TypeReq = 3;
    internal const byte TypeChunk = 4;
    internal const byte TypeBye = 5;

    public const int MaxChunkData = Blake3.ChunkSize; // 1024
    public const int MaxRequestCount = 64;

    /// <summary>A fresh per-connection session id: 32 random bytes the downloader puts in
    /// its first Hello. Both sides derive the connection's cipher from it, so two
    /// connections sharing one ticket never share a key — and therefore never reuse a
    /// ChaCha20-Poly1305 (key, nonce) pair across connections.</summary>
    public const int SessionIdLength = 32;

    public static ulong StreamId(byte[] root) => BinaryPrimitives.ReadUInt64BigEndian(root.AsSpan(0, 8));

    private delegate void BodyWriter(Span<byte> body);

    private static byte[] Build(byte type, ulong stream, int bodyLength, BodyWriter write)
    {
        byte[] frame = new byte[9 + bodyLength];
        frame[0] = type;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
        write(frame.AsSpan(9));
        return frame;
    }

    // Built without the shared BodyWriter helper, like Chunk: spans cannot be captured
    // in the lambda.
    public static byte[] Hello(ulong stream, ReadOnlySpan<byte> sessionId)
    {
        byte[] frame = new byte[9 + sessionId.Length];
        frame[0] = TypeHello;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
        sessionId.CopyTo(frame.AsSpan(9));
        return frame;
    }

    public static byte[] Bye(ulong stream) => Build(TypeBye, stream, 0, static _ => { });

    public static byte[] Head(ulong stream, long totalBytes, long totalChunks) =>
        Build(TypeHead, stream, 16, body =>
        {
            BinaryPrimitives.WriteInt64LittleEndian(body, totalBytes);
            BinaryPrimitives.WriteInt64LittleEndian(body[8..], totalChunks);
        });

    public static byte[] Request(ulong stream, long startChunk, int count) =>
        Build(TypeReq, stream, 10, body =>
        {
            BinaryPrimitives.WriteInt64LittleEndian(body, startChunk);
            BinaryPrimitives.WriteUInt16LittleEndian(body[8..], (ushort)count);
        });

    // Built without the shared BodyWriter helper: spans cannot be captured in the lambda.
    public static byte[] Chunk(ulong stream, long index, ReadOnlySpan<byte> cv, ReadOnlySpan<byte> data)
    {
        byte[] frame = new byte[9 + 8 + 32 + data.Length];
        frame[0] = TypeChunk;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
        BinaryPrimitives.WriteInt64LittleEndian(frame.AsSpan(9), index);
        cv.CopyTo(frame.AsSpan(17));
        data.CopyTo(frame.AsSpan(49));
        return frame;
    }

    /// <summary>Parsed view over one plaintext blob frame. Copies the chunk payload (and
    /// only it): frames are short-lived, chunks live until applied to the sink.</summary>
    public readonly record struct Frame
    {
        public byte Type { get; init; }
        public ulong Stream { get; init; }
        public long TotalBytes { get; init; }
        public long TotalChunks { get; init; }
        public long StartChunk { get; init; }
        public int Count { get; init; }
        public long Index { get; init; }
        public byte[]? ChunkCv { get; init; }
        public byte[]? ChunkData { get; init; }

        /// <summary>The Hello's session id (32 bytes) — null on a legacy empty-body Hello,
        /// the pre-2.0 wire an encrypting provider must refuse.</summary>
        public byte[]? SessionId { get; init; }

        public static bool TryParse(ReadOnlySpan<byte> frame, out Frame f)
        {
            f = default;
            if (frame.Length < 9)
            {
                return false;
            }

            byte type = frame[0];
            ulong stream = BinaryPrimitives.ReadUInt64BigEndian(frame[1..]);
            ReadOnlySpan<byte> body = frame[9..];
            switch (type)
            {
                case TypeHello:
                    if (body.Length is not (0 or SessionIdLength))
                    {
                        return false;
                    }

                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        SessionId = body.IsEmpty ? null : body.ToArray(),
                    };
                    return true;
                case TypeBye:
                    if (!body.IsEmpty)
                    {
                        return false;
                    }

                    f = new Frame { Type = type, Stream = stream };
                    return true;
                case TypeHead:
                    if (body.Length != 16)
                    {
                        return false;
                    }

                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        TotalBytes = BinaryPrimitives.ReadInt64LittleEndian(body),
                        TotalChunks = BinaryPrimitives.ReadInt64LittleEndian(body[8..]),
                    };
                    return f.TotalBytes >= 0 && f.TotalChunks >= 0; // (0,0) is the empty blob
                case TypeReq:
                    if (body.Length != 10)
                    {
                        return false;
                    }

                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        StartChunk = BinaryPrimitives.ReadInt64LittleEndian(body),
                        Count = BinaryPrimitives.ReadUInt16LittleEndian(body[8..]),
                    };
                    return f.StartChunk >= 0 && f.Count is >= 1 and <= MaxRequestCount;
                case TypeChunk:
                    if (body.Length is < 41 or > 8 + 32 + MaxChunkData)
                    {
                        return false;
                    }

                    var cv = new byte[32];
                    body.Slice(8, 32).CopyTo(cv);
                    var data = body[40..].ToArray();
                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        Index = BinaryPrimitives.ReadInt64LittleEndian(body),
                        ChunkCv = cv,
                        ChunkData = data,
                    };
                    return f.Index >= 0 && data.Length > 0;
                default:
                    return false;
            }
        }
    }

    /// <summary>Per-direction frame encryption. The key is HKDF-SHA256 over the ticket's
    /// pre-shared key, salted with the content root, the downloader's session id, and the
    /// connection's transport binding — the two engine tokens, freshness contributed by
    /// BOTH endpoints — so two tickets never share a stream cipher even when a caller
    /// reuses a key, and two connections sharing one ticket never share a cipher either:
    /// a downloader that repeats its session id still gets a different key, because the
    /// server's token is fresh in every connection. That is what makes per-connection
    /// counters restarting at 1 safe. Nonces are (role, 64-bit frame counter); the
    /// counter rides in the clear ahead of the ciphertext and receivers reject replayed
    /// or regressed counters — a replayer can at most duplicate a frame the ARQ layer
    /// already de-duplicates.</summary>
    internal sealed class Cipher
    {
        private const byte DownloaderRole = 0;
        private const byte ProviderRole = 1;
        private readonly KeyParameter _key;

        private Cipher(KeyParameter key) => _key = key;

        /// <summary>The connection cipher: bound to the downloader's session id and to
        /// the connection's transport binding, so every connection — simultaneous,
        /// reconnected, resumed, or a hostile repeat of an earlier session id — seals
        /// under its own key. Null when the ticket carries no PSK (plaintext mode).</summary>
        public static Cipher? For(byte[]? psk, byte[] root, ReadOnlySpan<byte> sessionId, TransportBinding transport)
        {
            if (psk is null)
            {
                return null;
            }

            var salt = new byte[root.Length + sessionId.Length + 8];
            root.CopyTo(salt, 0);
            sessionId.CopyTo(salt.AsSpan(root.Length));
            BinaryPrimitives.WriteUInt32LittleEndian(salt.AsSpan(root.Length + sessionId.Length), transport.Lo);
            BinaryPrimitives.WriteUInt32LittleEndian(salt.AsSpan(root.Length + sessionId.Length + 4), transport.Hi);
            return Derive(psk, salt, "pinhole-blobs-v2");
        }

        /// <summary>The pre-v2 fixed per-ticket key, wrapped so it can only ever OPEN
        /// frames: it exists to recognize a pre-2.0 downloader and refuse it. Sealing
        /// under it is unrepresentable on purpose — that key re-used (key, nonce) pairs
        /// across connections, and the refusal path must not repeat the sin.</summary>
        public static LegacyDetector ForLegacy(byte[] psk, byte[] root) => new(psk, root);

        /// <summary>Emulation seam for tests that need to <em>be</em> a pre-2.0 downloader
        /// (which seals under the old key). Production code gets only
        /// <see cref="ForLegacy"/>, which cannot seal.</summary>
        internal static Cipher ForLegacyEmulation(byte[] psk, byte[] root) => Derive(psk, root, "pinhole-blobs-v1");

        private static Cipher Derive(byte[] psk, byte[] salt, string info)
        {
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(psk, salt, Encoding.UTF8.GetBytes(info)));
            var key = new byte[32];
            hkdf.GenerateBytes(key, 0, 32);
            return new Cipher(new KeyParameter(key));
        }

        public static byte[] FreshKey() => RandomNumberGenerator.GetBytes(32);

        /// <summary>A fresh connection session id for the downloader's first Hello.</summary>
        public static byte[] FreshSessionId() => RandomNumberGenerator.GetBytes(SessionIdLength);

        public byte[] Seal(bool asProvider, ulong counter, ReadOnlySpan<byte> plaintext)
        {
            var aead = new ChaChaPoly();
            Span<byte> nonce = stackalloc byte[12];
            BuildNonce(nonce, asProvider, counter);
            aead.Init(true, new AeadParameters(_key, 128, nonce.ToArray()));
            byte[] input = plaintext.ToArray();
            byte[] output = new byte[8 + input.Length + 16];
            BinaryPrimitives.WriteUInt64LittleEndian(output, counter);
            int n = aead.ProcessBytes(input, 0, input.Length, output, 8);
            aead.DoFinal(output, 8 + n);
            return output;
        }

        /// <summary>Tries to open one wire frame. <paramref name="watermark"/> is the
        /// highest counter this direction has authenticated, and it moves ONLY when a
        /// frame authenticates: a forged counter — however far into the future — and a
        /// replayed or regressed old counter both leave it exactly where it was. A
        /// rejected frame can neither starve the frames behind it (the pre-2.1 bug, the
        /// same unauthenticated-watermark class as the session layer's replay window)
        /// nor re-admit the frames before it.</summary>
        public bool TryOpen(bool fromProvider, ReadOnlySpan<byte> wire, ref ulong watermark, out byte[] plaintext)
        {
            plaintext = Array.Empty<byte>();
            if (wire.Length < 8 + 16)
            {
                return false;
            }

            ulong candidate = BinaryPrimitives.ReadUInt64LittleEndian(wire);
            if (candidate <= watermark)
            {
                return false; // replay or regression; the ARQ layer tolerates loss, not lies
            }

            var aead = new ChaChaPoly();
            Span<byte> nonce = stackalloc byte[12];
            BuildNonce(nonce, fromProvider, candidate);
            aead.Init(false, new AeadParameters(_key, 128, nonce.ToArray()));
            byte[] input = wire.ToArray();
            byte[] buf = new byte[input.Length];
            try
            {
                int n = aead.ProcessBytes(input, 8, input.Length - 8, buf, 0);
                n += aead.DoFinal(buf, n);
                plaintext = buf[..n];
                watermark = candidate; // committed only after the tag verifies
                return true;
            }
            catch (InvalidCipherTextException)
            {
                return false; // forged or corrupted in flight: the watermark does not move
            }
        }

        private static void BuildNonce(Span<byte> nonce, bool provider, ulong counter)
        {
            nonce[0] = provider ? ProviderRole : DownloaderRole;
            BinaryPrimitives.WriteUInt64LittleEndian(nonce[1..], counter);
            nonce[9..].Clear();
        }

        /// <summary>Open-only view over the pre-v2 per-ticket key. See
        /// <see cref="ForLegacy"/>.</summary>
        internal sealed class LegacyDetector
        {
            private readonly Cipher _inner;

            internal LegacyDetector(byte[] psk, byte[] root) => _inner = Derive(psk, root, "pinhole-blobs-v1");

            public bool TryOpen(bool fromProvider, ReadOnlySpan<byte> wire, ref ulong watermark, out byte[] plaintext) =>
                _inner.TryOpen(fromProvider, wire, ref watermark, out plaintext);
        }
    }
}
