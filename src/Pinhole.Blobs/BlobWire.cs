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
    internal const byte TypeWelcome = 6;
    internal const byte ProtocolVersion = 3;

    public const int MaxChunkData = Blake3.ChunkSize; // 1024
    public const int MaxRequestCount = 64;

    /// <summary>The length of each endpoint's random per-connection nonce. The downloader
    /// sends its nonce in Hello; the provider contributes an independent nonce in Welcome.</summary>
    public const int SessionIdLength = 32;
    private const int SealedHeadLength = 8 + 25 + 16;

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
        if (sessionId.Length != SessionIdLength)
        {
            throw new ArgumentException("session id must be 32 bytes", nameof(sessionId));
        }

        byte[] frame = new byte[10 + SessionIdLength];
        frame[0] = TypeHello;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
        frame[9] = ProtocolVersion;
        sessionId.CopyTo(frame.AsSpan(10));
        return frame;
    }

    public static byte[] Welcome(ulong stream, ReadOnlySpan<byte> sessionId, ReadOnlySpan<byte> providerNonce,
        ReadOnlySpan<byte> sealedHead)
    {
        if (sessionId.Length != SessionIdLength || providerNonce.Length != SessionIdLength
            || sealedHead.Length != SealedHeadLength)
        {
            throw new ArgumentException("Welcome requires two 32-byte nonces and a sealed Head");
        }

        byte[] frame = new byte[10 + 2 * SessionIdLength + SealedHeadLength];
        frame[0] = TypeWelcome;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
        frame[9] = ProtocolVersion;
        sessionId.CopyTo(frame.AsSpan(10));
        providerNonce.CopyTo(frame.AsSpan(10 + SessionIdLength));
        sealedHead.CopyTo(frame.AsSpan(10 + 2 * SessionIdLength));
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

        /// <summary>The downloader's 32-byte nonce, or null for a v1 Hello.</summary>
        public byte[]? SessionId { get; init; }
        public byte Version { get; init; }
        public byte[]? ProviderNonce { get; init; }
        public byte[]? SealedHead { get; init; }

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
                    if (body.Length is not (0 or SessionIdLength)
                        && (body.Length != 1 + SessionIdLength || body[0] != ProtocolVersion))
                    {
                        return false;
                    }

                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        Version = body.IsEmpty ? (byte)1 : body.Length == SessionIdLength ? (byte)2 : ProtocolVersion,
                        SessionId = body.IsEmpty ? null : body.Length == SessionIdLength ? body.ToArray() : body[1..].ToArray(),
                    };
                    return true;
                case TypeWelcome:
                    if (body.Length != 1 + 2 * SessionIdLength + SealedHeadLength || body[0] != ProtocolVersion)
                    {
                        return false;
                    }

                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        Version = ProtocolVersion,
                        SessionId = body.Slice(1, SessionIdLength).ToArray(),
                        ProviderNonce = body.Slice(1 + SessionIdLength, SessionIdLength).ToArray(),
                        SealedHead = body[(1 + 2 * SessionIdLength)..].ToArray(),
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

    /// <summary>Ticket-authenticated download state shared by all streams on a connection.
    /// A Welcome's provider nonce is adopted only after its sealed Head authenticates.
    /// The receive watermark is shared across directory streams, just like the send counter.</summary>
    internal sealed class DownloadSession
    {
        private readonly byte[]? _psk;
        private readonly byte[] _root;
        private Cipher? _cipher;
        private byte[]? _providerNonce;
        private ulong _watermark;

        public byte[] SessionId { get; }

        public DownloadSession(byte[]? psk, byte[] root, byte[]? sessionId = null)
        {
            _psk = psk?.ToArray();
            _root = root.ToArray();
            SessionId = (sessionId ?? Cipher.FreshSessionId()).ToArray();
        }

        public byte[] Seal(ulong counter, byte[] plain)
        {
            if (_psk is null)
            {
                return plain;
            }

            return (_cipher ?? throw new InvalidOperationException("the provider has not authenticated a Welcome"))
                .Seal(asProvider: false, counter, plain);
        }

        public bool TryOpen(ReadOnlySpan<byte> payload, ulong stream, out Frame frame)
        {
            frame = default;
            if (_psk is null)
            {
                return Frame.TryParse(payload, out frame) && frame.Stream == stream;
            }

            // Try ordinary ciphertext first after negotiation. A failed open never changes
            // the watermark, so an unsealed Welcome can safely be checked afterwards.
            if (_cipher is not null && _cipher.TryOpen(fromProvider: true, payload, ref _watermark, out byte[] plain))
            {
                return Frame.TryParse(plain, out frame) && frame.Stream == stream;
            }

            if (!Frame.TryParse(payload, out Frame welcome) || welcome.Type != TypeWelcome || welcome.Stream != stream
                || !welcome.SessionId.AsSpan().SequenceEqual(SessionId)
                || (_providerNonce is not null && !_providerNonce.AsSpan().SequenceEqual(welcome.ProviderNonce)))
            {
                Telemetry.FrameRejected("blob", "welcome-unverified");
                return false;
            }

            Cipher candidate = _cipher ?? Cipher.For(_psk, _root, SessionId, welcome.ProviderNonce!)!;
            ulong candidateWatermark = _watermark;
            if (!candidate.TryOpen(fromProvider: true, welcome.SealedHead!, ref candidateWatermark, out byte[] head)
                || !Frame.TryParse(head, out frame) || frame.Type != TypeHead || frame.Stream != stream)
            {
                Telemetry.FrameRejected("blob", "welcome-unverified");
                return false;
            }

            _cipher = candidate;
            _providerNonce ??= welcome.ProviderNonce;
            _watermark = candidateWatermark;
            WelcomeNonceSeen?.Invoke(SessionId, welcome.ProviderNonce!);
            return true;
        }
    }

    /// <summary>Test/diagnostic seam: invoked with (downloader session id, provider nonce)
    /// for every Welcome a session adopts — including repeats, since the provider re-offers
    /// the same nonce to each retried Hello on one connection. Recovery tests assert the
    /// nonce is stable within a session and distinct across sessions — a fresh two-sided
    /// key every re-dial, never a continued counter.</summary>
    internal static Action<byte[], byte[]>? WelcomeNonceSeen;

    /// <summary>ChaCha20-Poly1305 frames with a key derived from the ticket PSK, content
    /// root, and independent 256-bit nonces from the downloader and provider. Routing
    /// tokens do not participate in key derivation. Direction and counter form the nonce.</summary>
    internal sealed class Cipher
    {
        private const byte DownloaderRole = 0;
        private const byte ProviderRole = 1;
        private readonly KeyParameter _key;

        private Cipher(KeyParameter key) => _key = key;

        /// <summary>The connection cipher, derived from both endpoints' nonces. Null for
        /// a plaintext ticket. The provider generates its nonce once per connection.</summary>
        public static Cipher? For(byte[]? psk, byte[] root, ReadOnlySpan<byte> sessionId, ReadOnlySpan<byte> providerNonce)
        {
            if (psk is null)
            {
                return null;
            }

            if (psk.Length != 32 || root.Length != 32 || sessionId.Length != SessionIdLength
                || providerNonce.Length != SessionIdLength)
            {
                throw new ArgumentException("PSK, root, and each session nonce must be 32 bytes");
            }

            var salt = new byte[root.Length + 2 * SessionIdLength];
            root.CopyTo(salt, 0);
            sessionId.CopyTo(salt.AsSpan(root.Length));
            providerNonce.CopyTo(salt.AsSpan(root.Length + SessionIdLength));
            return Derive(psk, salt, "pinhole-blobs-v3");
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

    // ------------------------------------------------------------------ send-path transition tolerance

    /// <summary>How long a blob pump waits out a pathless connection before giving up:
    /// longer than the engine's worst relay-reconnect backoff, shorter than the
    /// downloader's 30 s stall clock, so an unhealable path surfaces as an honest stall
    /// instead of a zombie pump.</summary>
    internal static readonly TimeSpan RideOutBudget = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan RideOutPace = TimeSpan.FromMilliseconds(50);

    /// <summary>Sends one wire frame, riding out the connection's transient states: a
    /// mid-transfer roam flips Open→Punching and back on the roaming side, and a relay
    /// outage parks a relay-only session until the reconnect lands. Reliability is the
    /// blob layer's job, so bounded pathlessness is a wait, not a death — the frame goes
    /// out the moment a path exists again. Only a Closed connection (the peer is gone) or
    /// an expired <see cref="RideOutBudget"/> rethrows.</summary>
    internal static async ValueTask SendRidingOutPathlessnessAsync(Pinhole.PinholeConnection conn, byte[] wire, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                conn.Send(wire);
                return;
            }
            catch (InvalidOperationException) when (conn.State != Pinhole.PinholeConnectionState.Closed && sw.Elapsed < RideOutBudget)
            {
                await Task.Delay(RideOutPace, ct).ConfigureAwait(false);
            }
        }
    }
}
