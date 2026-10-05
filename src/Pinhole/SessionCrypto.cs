using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

namespace Pinhole;

/// <summary>How a node treats encryption on the wire.
/// <see cref="Required"/> (default) refuses plaintext peers entirely; <see cref="Optional"/>
/// still speaks crypto with current peers but accepts pre-1.6 plaintext ones; <see cref="Disabled"/>
/// reproduces the pre-1.6 wire (and never embeds a static key in connection strings).</summary>
public enum PinholeEncryption
{
    /// <summary>Encrypt and authenticate every session; a peer that will not is refused.</summary>
    Required = 0,

    /// <summary>Encrypt with current peers; accept pre-1.6 plaintext peers when they cannot.</summary>
    Optional = 1,

    /// <summary>No encryption — the documented pre-1.6 behavior. Traffic is readable and peer
    /// identity unauthenticated; connection strings carry no static key.</summary>
    Disabled = 2,
}

/// <summary>Wire-layout constants the handshake and sealed frames share with the engine.</summary>
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

/// <summary>The node's long-term X25519 identity: the public half is embedded in every
/// connection string (v2) and pins the far end of each handshake against man-in-the-middle
/// substitution. Generate once and persist via <see cref="PinholeOptions.IdentityKeySeed"/>
/// if peer identity should survive restarts.</summary>
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

    /// <summary>A fresh ephemeral keypair for one connection's handshake.</summary>
    public static (byte[] Private, byte[] Public) NewEphemeral()
    {
        byte[] priv = RandomNumberGenerator.GetBytes(KeyLength);
        return (priv, new X25519PrivateKeyParameters(priv, 0).GeneratePublicKey().GetEncoded());
    }

    /// <summary>Raw X25519. An all-zero shared secret means the peer public key was a
    /// low-order point (a small-subgroup probe), which we refuse rather than negotiate with.</summary>
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

/// <summary>The session keys one handshake produced. Role names are canonical — "lo" is the
/// side with the smaller peer ID — so both endpoints derive identical keys no matter who
/// dialed, and simultaneous dials converge instead of colliding.</summary>
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

/// <summary>Key schedule for the v2 handshake: a triple-DH (Noise-style, signatures not
/// needed) over one ephemeral and one static X25519 key per side, folded through HKDF-SHA256
/// with the transcript hash as salt. Pure function of its inputs — oracle-tested against an
/// independent implementation.</summary>
internal static class KeySchedule
{
    public const string TranscriptLabel = "pinhole-hs1";
    public const string Info = "pinhole-session-v1";
    public const string RekeyInfo = "pinhole-rekey-v1";

    /// <summary>One side's derivation. Inputs are that side's private halves and the peer's
    /// public halves; the peer-id ordering makes the result identical on both ends.</summary>
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

/// <summary>One direction of an established session: a strictly-increasing frame counter
/// (so AES-GCM nonces never repeat), an epoch ratchet that chains the key forward every
/// 2^28 frames, and — on the receive side — an IPsec-style replay window. Thread-safe:
/// sends may come from any app thread, receives from any transport thread.</summary>
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
    private uint _epoch;

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

    /// <summary>Seals one frame body. <paramref name="headerAndToken"/> is the 13-byte frame
    /// prefix (type + sender peer id + token); the associated data is that prefix plus the
    /// frame counter, so type, sender, token, and ordering are all tamper-evident. The
    /// destination receives [counter][ciphertext||tag]. The whole operation runs under the
    /// direction lock: the counter assignment, the epoch key, and the cipher must move together.</summary>
    public int Seal(Span<byte> destination, ReadOnlySpan<byte> headerAndToken, ReadOnlySpan<byte> plaintext)
    {
        lock (_gate)
        {
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

    /// <summary>Opens one sealed frame. <paramref name="frame"/> is the full wire frame
    /// ([header][token][counter][ciphertext||tag]); the plaintext is written to
    /// <paramref name="plaintext"/> and its length returned. Returns false on tampering,
    /// replay, or an epoch too far ahead — each costs the frame, nothing more.</summary>
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
        AesGcm aes;
        lock (_gate)
        {
            if (!ReplayAccept(counter))
            {
                return false;
            }

            // The 64-deep replay window cannot straddle more than two adjacent epochs, so a
            // frame from anything beyond _epoch+1 is bogus regardless of its tag.
            if (epoch == _epoch)
            {
                _aes ??= new AesGcm(_key, CryptoWire.TagLength);
                aes = _aes;
            }
            else if (epoch == _epoch + 1)
            {
                _key = KeySchedule.Rekey(_key, _transcriptHash);
                _epoch = epoch;
                _aes?.Dispose();
                aes = _aes = new AesGcm(_key, CryptoWire.TagLength);
            }
            else
            {
                return false;
            }
        }

        ReadOnlySpan<byte> ciphertext = sealedBody[CryptoWire.CounterLength..];
        int plainLen = ciphertext.Length - CryptoWire.TagLength;
        if (plaintext.Length < plainLen)
        {
            return false; // caller-provided destination cannot hold this frame
        }

        Span<byte> nonce = stackalloc byte[12];
        _nonceSalt.CopyTo(nonce);
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
        try
        {
            aes.Decrypt(nonce, ciphertext[..^CryptoWire.TagLength], ciphertext[^CryptoWire.TagLength..], plaintext[..plainLen],
                frame[..(CryptoWire.HeaderLength + CryptoWire.TokenLength + CryptoWire.CounterLength)]);
        }
        catch (CryptographicException)
        {
            return false; // tag mismatch: forged or corrupted in flight
        }

        plaintextLength = plainLen;
        return true;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _aes?.Dispose();
        }
    }

    private bool ReplayAccept(ulong counter)
    {
        if (counter > _highest)
        {
            ulong shift = counter - _highest;
            _bitmap = shift >= Window ? 1 : (_bitmap << (int)shift) | 1;
            _highest = counter;
            return true;
        }

        ulong delta = _highest - counter;
        if (delta >= Window)
        {
            return false; // older than the window: a stale replay
        }

        if ((_bitmap >> (int)delta & 1) != 0)
        {
            return false; // already seen
        }

        _bitmap |= 1UL << (int)delta;
        return true;
    }
}

/// <summary>Per-connection crypto state: the pending handshake until the triple-DH
/// completes, then the two sealers. Handshake fields are guarded by the connection's gate;
/// the sealers are internally thread-safe.</summary>
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
    /// <summary>A confirm MAC from the peer verified — the far end holds the static key the
    /// handshake named, so the session is authenticated.</summary>
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

    /// <summary>Records the peer's handshake keys (first frame wins; a mismatched retry is a
    /// stale or substituted handshake and is refused) and derives the session when both
    /// halves are present. False means: ignore this frame, the handshake state is unchanged.</summary>
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

    /// <summary>This side's confirm MAC — carried in the PACK/Hsck reply, verified by the peer.</summary>
    public byte[] MyConfirm() => MyPeerId < PeerPeerId ? Keys!.LoConfirm : Keys!.HiConfirm;

    /// <summary>The confirm value the peer must produce; null before derivation.</summary>
    public byte[]? ExpectedPeerConfirm() => Keys is null ? null : MyPeerId < PeerPeerId ? Keys.HiConfirm : Keys.LoConfirm;

    public bool VerifyPeerConfirm(ReadOnlySpan<byte> confirm) =>
        ExpectedPeerConfirm() is { } expected && confirm.SequenceEqual(expected);

    public void MarkPeerConfirmed() => PeerConfirmed = true;

    public void CountRejected() => Interlocked.Increment(ref Rejected);
}
