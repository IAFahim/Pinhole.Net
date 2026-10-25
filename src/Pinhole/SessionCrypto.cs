using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

namespace Pinhole;

public enum PinholeEncryption
{
    Required = 0,

    Optional = 1,

    Disabled = 2,
}

internal static class CryptoWire
{
    public const int HeaderLength = 9;   // type byte + sender peer id (u64 LE)
    public const int TokenLength = 4;
    public const int EphemeralLength = 32;
    public const int StaticKeyLength = 32;
    public const int ConfirmLength = 16;
    public const int CounterLength = 8;
    public const int TagLength = 16;
    public const int SealedOverhead = CounterLength + TagLength;

    public const int PuncLegacyBody = TokenLength;                                  // 4  → frame 13
    public const int PuncCryptoBody = TokenLength + EphemeralLength + StaticKeyLength; // 68 → frame 77
    public const int PackLegacyBody = 2 * TokenLength;                              // 8  → frame 17
    public const int PackCryptoBody = 2 * TokenLength + EphemeralLength + StaticKeyLength + ConfirmLength; // 88 → frame 97
    public const int HsckBody = TokenLength + ConfirmLength;                        // 20 → frame 29
}

internal sealed class NodeIdentity
{
    public const int KeyLength = 32;

    private readonly byte[] _private;
    public byte[] PublicKey { get; }

    public NodeIdentity(byte[]? seed = null)
    {
        _private = (seed ?? RandomNumberGenerator.GetBytes(KeyLength)).ToArray();
        if (_private.Length != KeyLength)
        {
            throw new ArgumentException($"identity seed must be {KeyLength} bytes", nameof(seed));
        }

        PublicKey = new X25519PrivateKeyParameters(_private, 0).GeneratePublicKey().GetEncoded();
    }

    internal byte[] ExportPrivateSeed() => (byte[])_private.Clone();

    public static (byte[] Private, byte[] Public) NewEphemeral()
    {
        byte[] priv = RandomNumberGenerator.GetBytes(KeyLength);
        return (priv, new X25519PrivateKeyParameters(priv, 0).GeneratePublicKey().GetEncoded());
    }

    internal static byte[] X25519Agree(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublic)
    {
        var agreement = new X25519Agreement();
        agreement.Init(new X25519PrivateKeyParameters(privateKey.ToArray(), 0));
        byte[] shared = new byte[KeyLength];
        try
        {
            agreement.CalculateAgreement(new X25519PublicKeyParameters(peerPublic.ToArray(), 0), shared, 0);
        }
        catch (InvalidOperationException ex)
        {
            // BouncyCastle rejects small-subgroup (all-zero) agreements itself
            throw new CryptographicException("peer public key is a low-order point", ex);
        }

        return shared.AsSpan().IndexOfAnyExcept((byte)0) >= 0
            ? shared
            : throw new CryptographicException("peer public key is a low-order point");
    }
}

internal sealed class SessionKeys
{
    public required byte[] TranscriptHash { get; init; }  // 32
    public required byte[] LoToHiKey { get; init; }       // 32, AES-256 key, lo→hi direction
    public required byte[] HiToLoKey { get; init; }       // 32, hi→lo direction
    public required byte[] LoToHiSalt { get; init; }      // 4, nonce salt, lo→hi
    public required byte[] HiToLoSalt { get; init; }      // 4, hi→lo
    public required byte[] LoConfirm { get; init; }       // 16, lo's handshake MAC
    public required byte[] HiConfirm { get; init; }       // 16, hi's handshake MAC
}

internal static class KeySchedule
{
    public const string TranscriptLabel = "pinhole-hs1";
    public const string Info = "pinhole-session-v1";
    public const string RekeyInfo = "pinhole-rekey-v1";

    public static SessionKeys Derive(
        ulong myPeerId,
        ReadOnlySpan<byte> myEphPrivate,
        ReadOnlySpan<byte> myStaticPrivate,
        ulong peerPeerId,
        ReadOnlySpan<byte> peerEphPublic,
        ReadOnlySpan<byte> peerStaticPublic)
    {
        bool iAmLo = myPeerId < peerPeerId;
        byte[] ee = NodeIdentity.X25519Agree(myEphPrivate, peerEphPublic);
        // (s_lo, e_hi) and (e_lo, s_hi) swap perspective with the role; X25519 agreement is
        // symmetric, so each side computes both with the halves it holds.
        byte[] se = iAmLo
            ? NodeIdentity.X25519Agree(myStaticPrivate, peerEphPublic)
            : NodeIdentity.X25519Agree(myEphPrivate, peerStaticPublic);
        byte[] es = iAmLo
            ? NodeIdentity.X25519Agree(myEphPrivate, peerStaticPublic)
            : NodeIdentity.X25519Agree(myStaticPrivate, peerEphPublic);

        var ikm = new byte[3 * NodeIdentity.KeyLength];
        ee.CopyTo(ikm, 0);
        se.CopyTo(ikm, NodeIdentity.KeyLength);
        es.CopyTo(ikm, 2 * NodeIdentity.KeyLength);

        byte[] myEphPublic = new X25519PrivateKeyParameters(myEphPrivate.ToArray(), 0).GeneratePublicKey().GetEncoded();
        byte[] myStaticPublic = new X25519PrivateKeyParameters(myStaticPrivate.ToArray(), 0).GeneratePublicKey().GetEncoded();
        byte[] th = TranscriptHash(
            iAmLo ? myPeerId : peerPeerId,
            iAmLo ? peerPeerId : myPeerId,
            iAmLo ? myEphPublic : peerEphPublic.ToArray(),
            iAmLo ? myStaticPublic : peerStaticPublic.ToArray(),
            iAmLo ? peerEphPublic.ToArray() : myEphPublic,
            iAmLo ? peerStaticPublic.ToArray() : myStaticPublic);

        byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 136, th, System.Text.Encoding.ASCII.GetBytes(Info));
        return new SessionKeys
        {
            TranscriptHash = th,
            // Direction-absolute: lo→hi is lo→hi for both sides; the role-relative choice
            // (which key I send with) happens in FrameSealer's constructor.
            LoToHiKey = okm[..32],
            HiToLoKey = okm[32..64],
            LoToHiSalt = okm[128..132],
            HiToLoSalt = okm[132..136],
            LoConfirm = ConfirmMac(okm[64..96], th),
            HiConfirm = ConfirmMac(okm[96..128], th),
        };
    }

    public static byte[] TranscriptHash(ulong loPeerId, ulong hiPeerId, ReadOnlySpan<byte> loEph, ReadOnlySpan<byte> loStatic, ReadOnlySpan<byte> hiEph, ReadOnlySpan<byte> hiStatic)
    {
        var buf = new byte[TranscriptLabel.Length + 8 + 8 + 4 * NodeIdentity.KeyLength];
        int pos = System.Text.Encoding.ASCII.GetBytes(TranscriptLabel, buf);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(pos), loPeerId);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(pos + 8), hiPeerId);
        loEph.CopyTo(buf.AsSpan(pos + 16));
        loStatic.CopyTo(buf.AsSpan(pos + 16 + NodeIdentity.KeyLength));
        hiEph.CopyTo(buf.AsSpan(pos + 16 + 2 * NodeIdentity.KeyLength));
        hiStatic.CopyTo(buf.AsSpan(pos + 16 + 3 * NodeIdentity.KeyLength));
        return SHA256.HashData(buf);
    }

    public static byte[] Rekey(ReadOnlySpan<byte> currentKey, ReadOnlySpan<byte> transcriptHash)
    {
        byte[] next = GC.AllocateUninitializedArray<byte>(32);
        HKDF.DeriveKey(HashAlgorithmName.SHA256, currentKey, next, transcriptHash, System.Text.Encoding.ASCII.GetBytes(RekeyInfo));
        return next;
    }

    private static byte[] ConfirmMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> transcript) =>
        HMACSHA256.HashData(key, transcript)[..CryptoWire.ConfirmLength];
}

internal sealed class FrameSealer : IDisposable
{
    private const int DefaultEpochFrames = 1 << 28;
    private const int Window = 64;

    private readonly byte[] _transcriptHash;
    private readonly byte[] _nonceSalt;
    private readonly int _epochFrames;
    private readonly object _gate = new();

    private byte[] _key;
    private AesGcm? _aes;
    private AesGcm? _prevAes; // the previous epoch's cipher: stragglers still inside the replay window
    private uint _epoch;
    private bool _disposed;

    // Send side: the next counter to seal with. Receive side: the highest accepted and its
    // 64-frame window bitmap. A sealer is one direction only, so the halves never mix.
    private ulong _nextCounter = 1;
    private ulong _highest;
    private ulong _bitmap;

    public FrameSealer(SessionKeys keys, bool iAmLo, bool sending, int epochFrames = DefaultEpochFrames)
    {
        _transcriptHash = keys.TranscriptHash;
        _epochFrames = epochFrames;
        bool loToHi = sending == iAmLo; // the lo side sends with the lo→hi key, hi with hi→lo
        _nonceSalt = loToHi ? keys.LoToHiSalt : keys.HiToLoSalt;
        _key = loToHi ? keys.LoToHiKey : keys.HiToLoKey;
    }

    public int Seal(Span<byte> destination, ReadOnlySpan<byte> headerAndToken, ReadOnlySpan<byte> plaintext)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(FrameSealer));
            }

            ulong counter = _nextCounter++;
            uint epoch = (uint)((counter - 1) / (ulong)_epochFrames);
            if (_aes is null)
            {
                _aes = new AesGcm(_key, CryptoWire.TagLength);
            }
            else if (epoch != _epoch)
            {
                // Epochs advance one at a time (the counter does), so this is one HKDF step
                // per 2^28 frames — automatic key rotation with no wire negotiation.
                while (_epoch < epoch)
                {
                    _key = KeySchedule.Rekey(_key, _transcriptHash);
                    _epoch++;
                }

                _aes.Dispose();
                _aes = new AesGcm(_key, CryptoWire.TagLength);
            }

            Span<byte> nonce = stackalloc byte[12];
            _nonceSalt.CopyTo(nonce);
            BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
            BinaryPrimitives.WriteUInt64LittleEndian(destination, counter);
            Span<byte> ct = destination.Slice(CryptoWire.CounterLength, plaintext.Length);
            Span<byte> tag = destination.Slice(CryptoWire.CounterLength + plaintext.Length, CryptoWire.TagLength);
            Span<byte> aad = stackalloc byte[CryptoWire.HeaderLength + CryptoWire.TokenLength + CryptoWire.CounterLength];
            headerAndToken.CopyTo(aad);
            BinaryPrimitives.WriteUInt64LittleEndian(aad[(CryptoWire.HeaderLength + CryptoWire.TokenLength)..], counter);
            _aes.Encrypt(nonce, plaintext, ct, tag, aad);
            return CryptoWire.CounterLength + plaintext.Length + CryptoWire.TagLength;
        }
    }

    public bool Open(ReadOnlySpan<byte> frame, Span<byte> plaintext, out int plaintextLength)
    {
        plaintextLength = 0;
        ReadOnlySpan<byte> sealedBody = frame[(CryptoWire.HeaderLength + CryptoWire.TokenLength)..];
        if (sealedBody.Length < CryptoWire.CounterLength + CryptoWire.TagLength)
        {
            return false; // not a sealed frame at all
        }

        ulong counter = BinaryPrimitives.ReadUInt64LittleEndian(sealedBody);
        if (counter == 0)
        {
            return false; // counters start at 1
        }

        uint epoch = (uint)((counter - 1) / (ulong)_epochFrames);
        lock (_gate)
        {
            if (_disposed)
            {
                return false;
            }

            if (!ReplayEligible(counter))
            {
                return false; // stale replay or duplicate: no authentication needed to see that
            }

            // Pick the candidate cipher without committing anything: the current epoch's,
            // the previous epoch's (a legitimately reordered straggler inside the window),
            // or a derived candidate for the next epoch — adopted only if it authenticates.
            // Anything further away is unreachable: the 64-frame window cannot straddle
            // more than two adjacent epochs.
            AesGcm aes;
            byte[]? candidateKey = null;
            if (epoch == _epoch)
            {
                _aes ??= new AesGcm(_key, CryptoWire.TagLength);
                aes = _aes;
            }
            else if (epoch == _epoch + 1)
            {
                candidateKey = KeySchedule.Rekey(_key, _transcriptHash);
                aes = new AesGcm(candidateKey, CryptoWire.TagLength);
            }
            else if (epoch + 1 == _epoch && _prevAes is not null)
            {
                aes = _prevAes;
            }
            else
            {
                return false;
            }

            ReadOnlySpan<byte> ciphertext = sealedBody[CryptoWire.CounterLength..];
            int plainLen = ciphertext.Length - CryptoWire.TagLength;
            if (plaintext.Length < plainLen)
            {
                if (candidateKey is not null)
                {
                    aes.Dispose();
                }

                return false; // caller-provided destination cannot hold this frame
            }

            Span<byte> nonce = stackalloc byte[12];
            _nonceSalt.CopyTo(nonce);
            BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
            bool opened;
            try
            {
                aes.Decrypt(nonce, ciphertext[..^CryptoWire.TagLength], ciphertext[^CryptoWire.TagLength..], plaintext[..plainLen],
                    frame[..(CryptoWire.HeaderLength + CryptoWire.TokenLength + CryptoWire.CounterLength)]);
                opened = true;
            }
            catch (CryptographicException)
            {
                opened = false; // forged or corrupted in flight: no counter burned, no key adopted
            }

            if (!opened)
            {
                if (candidateKey is not null)
                {
                    aes.Dispose(); // the unadopted next-epoch candidate dies with the frame
                }

                return false;
            }

            // Authenticated: now, and only now, the frame's state may commit.
            CommitReplay(counter);
            if (candidateKey is not null)
            {
                _prevAes?.Dispose();
                _prevAes = _aes; // retained until the window can no longer reach the old epoch
                _aes = aes;
                _key = candidateKey;
                _epoch = epoch;
            }

            plaintextLength = plainLen;
            return true;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _aes?.Dispose();
            _prevAes?.Dispose();
        }
    }

    private bool ReplayEligible(ulong counter)
    {
        if (counter > _highest)
        {
            return true;
        }

        ulong delta = _highest - counter;
        return delta < Window && (_bitmap >> (int)delta & 1) == 0;
    }

    private void CommitReplay(ulong counter)
    {
        if (counter > _highest)
        {
            ulong shift = counter - _highest;
            _bitmap = shift >= Window ? 1 : (_bitmap << (int)shift) | 1;
            _highest = counter;
        }
        else
        {
            _bitmap |= 1UL << (int)(_highest - counter);
        }
    }
}

internal sealed class ConnectionCrypto
{
    private readonly byte[] _ephPrivate;
    private readonly byte[] _staticPrivate;

    public required ulong MyPeerId { get; init; }
    public required ulong PeerPeerId { get; init; }
    public byte[] MyEphPublic { get; }
    public byte[] MyStaticPublic { get; }

    public byte[]? PeerEphPublic { get; private set; }     // connection gate
    public byte[]? PeerStaticPublic { get; private set; }  // connection gate
    public SessionKeys? Keys { get; private set; }         // connection gate; set once
    public FrameSealer? Send { get; private set; }
    public FrameSealer? Recv { get; private set; }
    public bool PeerConfirmed { get; private set; }
    public long Rejected; // Interlocked: tampered, replayed, or downgraded frames dropped

    [System.Diagnostics.CodeAnalysis.SetsRequiredMembers]
    private ConnectionCrypto(byte[] ephPrivate, byte[] ephPublic, byte[] staticPrivate, byte[] staticPublic, ulong myPeerId, ulong peerPeerId)
    {
        _ephPrivate = ephPrivate;
        MyEphPublic = ephPublic;
        _staticPrivate = staticPrivate;
        MyStaticPublic = staticPublic;
        MyPeerId = myPeerId;
        PeerPeerId = peerPeerId;
    }

    public static ConnectionCrypto New(NodeIdentity identity, ulong myPeerId, ulong peerPeerId)
    {
        (byte[] ephPrivate, byte[] ephPublic) = NodeIdentity.NewEphemeral();
        return new ConnectionCrypto(ephPrivate, ephPublic, identity.ExportPrivateSeed(), identity.PublicKey, myPeerId, peerPeerId);
    }

    public bool Established => Keys is not null;

    public bool TryPeerKeys(ReadOnlySpan<byte> eph, ReadOnlySpan<byte> stat)
    {
        if (Keys is not null)
        {
            return PeerEphPublic.AsSpan().SequenceEqual(eph) && PeerStaticPublic.AsSpan().SequenceEqual(stat);
        }

        if (PeerEphPublic is not null)
        {
            return false; // a second, different handshake: stale or hostile
        }

        try
        {
            SessionKeys keys = KeySchedule.Derive(MyPeerId, _ephPrivate, _staticPrivate, PeerPeerId, eph, stat);
            PeerEphPublic = eph.ToArray();
            PeerStaticPublic = stat.ToArray();
            Keys = keys;
            bool iAmLo = MyPeerId < PeerPeerId;
            Send = new FrameSealer(keys, iAmLo, sending: true);
            Recv = new FrameSealer(keys, iAmLo, sending: false);
            return true;
        }
        catch (CryptographicException)
        {
            return false; // low-order point probe: refuse the keys; a later honest retry still works
        }
    }

    public bool TrySupersedeUnconfirmed(ReadOnlySpan<byte> eph, ReadOnlySpan<byte> stat, ReadOnlySpan<byte> confirm,
        bool allowUnexposedIncoming = false)
    {
        // An explicit dial may adopt a late incoming PUNC/HSCK from the peer's
        // closed connection. That state has neither authenticated traffic nor an
        // exposed application connection. A trial PACK still needs a valid MAC
        // under the requested static key; active sessions never take this path.
        if (PeerConfirmed && !allowUnexposedIncoming || Keys is null)
        {
            return false; // nothing stale to replace, or too late to replace it
        }

        try
        {
            SessionKeys trial = KeySchedule.Derive(MyPeerId, _ephPrivate, _staticPrivate, PeerPeerId, eph, stat);
            ReadOnlySpan<byte> expected = MyPeerId < PeerPeerId ? trial.HiConfirm : trial.LoConfirm;
            if (!CryptographicOperations.FixedTimeEquals(confirm, expected))
            {
                return false;
            }

            PeerEphPublic = eph.ToArray();
            PeerStaticPublic = stat.ToArray();
            Keys = trial;
            bool iAmLo = MyPeerId < PeerPeerId;
            Send?.Dispose();
            Recv?.Dispose();
            Send = new FrameSealer(trial, iAmLo, sending: true);
            Recv = new FrameSealer(trial, iAmLo, sending: false);
            Interlocked.Increment(ref SupersededLatches);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public long SupersededLatches; // Interlocked

    public byte[] MyConfirm() => MyPeerId < PeerPeerId ? Keys!.LoConfirm : Keys!.HiConfirm;

    public byte[]? ExpectedPeerConfirm() => Keys is null ? null : MyPeerId < PeerPeerId ? Keys.HiConfirm : Keys.LoConfirm;

    public bool VerifyPeerConfirm(ReadOnlySpan<byte> confirm) =>
        ExpectedPeerConfirm() is { } expected && confirm.SequenceEqual(expected);

    public void MarkPeerConfirmed() => PeerConfirmed = true;

    public void CountRejected()
    {
        Interlocked.Increment(ref Rejected);
        Telemetry.FrameRejected("session", "unverified");
    }

    // Key-agreement forensics: at the FIRST reject, remember whether a session was already
    // derived and the leading bytes of the stored, arriving, and own ephemeral keys. Cross-
    // referencing the three names whose handshake the stale latch belongs to.
    private long _keyRejectCaptured; // Interlocked: first reject wins
    private volatile string _keyRejectDetail = "";

    public string KeyRejectSummary => _keyRejectDetail;

    public string MyEphPrefix => HexPrefix(MyEphPublic);

    public void NoteKeyReject(ReadOnlySpan<byte> arrivingEph)
    {
        if (Interlocked.Exchange(ref _keyRejectCaptured, 1) == 1) return;
        _keyRejectDetail = $"[{(Keys is not null ? "derived" : "underived")}"
            + $" stored-eph={HexPrefix(PeerEphPublic)}"
            + $" arriving-eph={HexPrefix(arrivingEph)}"
            + $" my-eph={HexPrefix(MyEphPublic)}]";
    }

    private static string HexPrefix(ReadOnlySpan<byte> key) =>
        key.IsEmpty ? "-" : Convert.ToHexString(key[..4]).ToLowerInvariant();
}
