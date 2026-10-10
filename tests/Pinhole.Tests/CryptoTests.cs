using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Pinhole.Tests;

// The crypto layer, oracle-tested: every constant that is not an RFC vector was produced by
// an independent python implementation (cryptography + hashlib, RFC 5869 HKDF) of the same
// schedule, so a C# mistake cannot silently agree with itself.
public class CryptoTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(8);

    private static PinholeOptions Opts(Func<PinholeOptions, PinholeOptions>? tweak = null)
    {
        var o = new PinholeOptions
        {
            StunServers = [],
            IrohRelayUrls = [],
            EnablePortMapping = false,
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false,
            EnablePathValidation = false,
            StunRefreshInterval = TimeSpan.Zero,
        };
        return tweak is null ? o : tweak(o);
    }

    // ---------------------------------------------------------------- oracle: X25519

    [Fact]
    public void X25519_Rfc7748Vectors()
    {
        // RFC 7748 §5.2, scalar-mult test vector
        Assert.Equal(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
            Convert.ToHexString(NodeIdentity.X25519Agree(
                Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
                Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))).ToLowerInvariant());

        // RFC 7748 §6.1, Diffie-Hellman: both orders of the same exchange agree
        string shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        Assert.Equal(shared, Convert.ToHexString(NodeIdentity.X25519Agree(
            Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
            Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))).ToLowerInvariant());
        Assert.Equal(shared, Convert.ToHexString(NodeIdentity.X25519Agree(
            Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
            Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))).ToLowerInvariant());
    }

    [Fact]
    public void X25519_LowOrderPoint_IsRefused()
    {
        // The all-zero public key is the classic small-subgroup probe; the agreement must
        // refuse rather than negotiate on top of the all-zero shared secret.
        Assert.Throws<CryptographicException>(() => NodeIdentity.X25519Agree(new byte[32], new byte[32]));
    }

    // ---------------------------------------------------------------- oracle: key schedule

    // A fixed handshake: roles, keys, and every derived artifact come from the independent
    // python derivation. Both sides must land on exactly these values.
    private static SessionKeys FixtureKeys() => new()
    {
        TranscriptHash = Convert.FromHexString("e970527b014fbba3d0f9ded3f8180b4264490842119f67da3f91875e1948a1a2"),
        LoToHiKey = Convert.FromHexString("333901cc7a951e999bdb28fd115c251c7c75cc47b54735a32dccad332f19cff1"),
        HiToLoKey = Convert.FromHexString("222accda171cc5129b53a6db38cd52fad4d914479577165a071bec9a7ee43474"),
        LoToHiSalt = Convert.FromHexString("35c98125"),
        HiToLoSalt = Convert.FromHexString("a8856dfe"),
        LoConfirm = Convert.FromHexString("da8fd71b96b455038cb86978c2bc089a"),
        HiConfirm = Convert.FromHexString("abf53ca1473abdc50641de16a1027c80"),
    };

    [Fact]
    public void KeySchedule_MatchesTheIndependentDerivation_FromBothSides()
    {
        byte[] ephLoPriv = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] ephHiPriv = Convert.FromHexString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        byte[] stLoPriv = Convert.FromHexString("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] stHiPriv = Convert.FromHexString("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f");
        byte[] ephLoPub = Convert.FromHexString("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
        byte[] ephHiPub = Convert.FromHexString("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254");
        // The fixture's peer ids are the numbers 0x0102030405060708 / 0x0a0b0c0d0e0f1011;
        // these byte strings are their little-endian encodings.
        ulong lo = BinaryPrimitives.ReadUInt64LittleEndian(Convert.FromHexString("0807060504030201"));
        ulong hi = BinaryPrimitives.ReadUInt64LittleEndian(Convert.FromHexString("11100f0e0d0c0b0a"));

        SessionKeys loSide = KeySchedule.Derive(lo, ephLoPriv, stLoPriv, hi, ephHiPub, Convert.FromHexString("675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f"));
        SessionKeys hiSide = KeySchedule.Derive(hi, ephHiPriv, stHiPriv, lo, ephLoPub, Convert.FromHexString("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"));

        SessionKeys oracle = FixtureKeys();
        foreach ((string name, byte[] fromLo, byte[] fromHi, byte[] want) in new[]
        {
            ("transcript", loSide.TranscriptHash, hiSide.TranscriptHash, oracle.TranscriptHash),
            ("lo2hi key", loSide.LoToHiKey, hiSide.LoToHiKey, oracle.LoToHiKey),
            ("hi2lo key", loSide.HiToLoKey, hiSide.HiToLoKey, oracle.HiToLoKey),
            ("lo2hi salt", loSide.LoToHiSalt, hiSide.LoToHiSalt, oracle.LoToHiSalt),
            ("hi2lo salt", loSide.HiToLoSalt, hiSide.HiToLoSalt, oracle.HiToLoSalt),
            ("lo confirm", loSide.LoConfirm, hiSide.LoConfirm, oracle.LoConfirm),
            ("hi confirm", loSide.HiConfirm, hiSide.HiConfirm, oracle.HiConfirm),
        })
        {
            Assert.Equal(want, fromLo);
            Assert.Equal(want, fromHi);
            Assert.True(fromLo.SequenceEqual(fromHi), $"{name}: both sides must derive identical keys");
        }
    }

    [Fact]
    public void Rekey_ChainMatchesTheIndependentDerivation()
    {
        byte[] th = Convert.FromHexString("e970527b014fbba3d0f9ded3f8180b4264490842119f67da3f91875e1948a1a2");
        byte[] k0 = Convert.FromHexString("333901cc7a951e999bdb28fd115c251c7c75cc47b54735a32dccad332f19cff1");
        byte[] epoch1 = KeySchedule.Rekey(k0, th);
        byte[] epoch2 = KeySchedule.Rekey(epoch1, th);
        Assert.Equal("5a20cdfb7dff6347f568cf53f9c063d7a35e5cbeb16d89fe027b01c24f90f76d", Convert.ToHexString(epoch1).ToLowerInvariant());
        Assert.Equal("18a45df662eecfff9118f1f7185d8b2a82dcf70a31b99ee424548f287deb9969", Convert.ToHexString(epoch2).ToLowerInvariant());
    }

    // ---------------------------------------------------------------- oracle: frame sealing

    [Fact]
    public void FrameSealer_ProducesTheOracleCiphertext_AtCounterSeven()
    {
        // The python oracle sealed "through the wire" with the lo→hi key, salt, counter 7,
        // and aad [0x52][peer id lo LE][token AABBCCDD][counter 7 LE] — the engine's exact
        // frame shape for its 7th sealed frame.
        byte[] aad = Convert.FromHexString("520807060504030201aabbccdd0700000000000000");
        byte[] oracleCt = Convert.FromHexString("9515322e31d9186736e476c2e111b047133b7d13e056ed4cf6716d473ccd15fb");

        var sender = new FrameSealer(FixtureKeys(), iAmLo: true, sending: true);
        byte[] frame = new byte[13 + 8 + 16 + 16];
        aad[..13].CopyTo(frame);
        for (int i = 0; i < 7; i++)
        {
            sender.Seal(frame.AsSpan(13), frame.AsSpan(0, 13), "through the wire"u8);
        }

        Assert.Equal(oracleCt, frame.AsSpan(21, 32).ToArray());

        // and the receiver opens it back to the plaintext
        var receiver = new FrameSealer(FixtureKeys(), iAmLo: false, sending: false);
        byte[] plain = new byte[16];
        Assert.True(receiver.Open(frame, plain, out int len));
        Assert.Equal(16, len);
        Assert.Equal("through the wire"u8.ToArray(), plain);
    }

    [Fact]
    public void FrameSealer_TamperReplayAndReorder()
    {
        var sender = new FrameSealer(FixtureKeys(), iAmLo: true, sending: true);
        var receiver = new FrameSealer(FixtureKeys(), iAmLo: false, sending: false);

        byte[] Frame(int i)
        {
            var f = new byte[13 + 8 + 4 + 16];
            f[0] = 0x52;
            sender.Seal(f.AsSpan(13), f.AsSpan(0, 13), [(byte)i, 1, 2, 3]);
            return f;
        }

        byte[] scratch = new byte[64];

        byte[] f1 = Frame(1), f2 = Frame(2), f3 = Frame(3);
        Assert.True(receiver.Open(f1, scratch, out int n1));
        Assert.Equal(4, n1);
        Assert.True(receiver.Open(f3, scratch, out _)); // reordering inside the window is fine
        Assert.True(receiver.Open(f2, scratch, out _));
        Assert.False(receiver.Open(f2, scratch, out _)); // replayed: refused

        byte[] f4 = Frame(4);
        f4[^3] ^= 1; // tamper: one flipped ciphertext bit
        Assert.False(receiver.Open(f4, scratch, out _));

        byte[] f5 = Frame(5);
        BinaryPrimitives.WriteUInt64LittleEndian(f5.AsSpan(13), (1UL << 40) + 99); // far-future epoch
        Assert.False(receiver.Open(f5, scratch, out _));
    }

    [Fact]
    public void FrameSealer_EpochRatchet_RotatesKeysWithoutNegotiation()
    {
        var keys = new SessionKeys
        {
            TranscriptHash = new byte[32],
            LoToHiKey = RandomNumberGenerator.GetBytes(32),
            HiToLoKey = RandomNumberGenerator.GetBytes(32),
            LoToHiSalt = new byte[4],
            HiToLoSalt = new byte[4],
            LoConfirm = new byte[16],
            HiConfirm = new byte[16],
        };

        // epoch length 4: counters 1-4 use epoch 0, 5-8 epoch 1, ... — 12 frames cross three epochs
        var sender = new FrameSealer(keys, iAmLo: true, sending: true, epochFrames: 4);
        var receiver = new FrameSealer(keys, iAmLo: false, sending: false, epochFrames: 4);

        var frames = new List<byte[]>();
        for (int i = 0; i < 12; i++)
        {
            var f = new byte[13 + 8 + 4 + 16];
            f[0] = 0x52;
            sender.Seal(f.AsSpan(13), f.AsSpan(0, 13), [(byte)i, 0, 0, 0]);
            frames.Add(f);
        }

        byte[] scratch = new byte[64];
        foreach (byte[] f in frames)
        {
            Assert.True(receiver.Open(f, scratch, out _),
                $"counter {BinaryPrimitives.ReadUInt64LittleEndian(f.AsSpan(13))} must open after the ratchet");
        }

        Assert.False(receiver.Open(frames[0], scratch, out _)); // replayed counter, refused
    }

    [Fact]
    public void FrameSealer_ForgedFarFutureCounter_IsRejectedWithoutPoisoningTheWindow()
    {
        // The token rides in the clear, so an on-path forger can shape frames with any
        // counter it likes. A forged far-future counter must die on authentication
        // alone: the replay window may advance only when a frame authenticates
        // (RFC 4303 §3.4.3), or one forged packet starves every legitimate frame
        // behind it for the rest of the epoch.
        var sender = new FrameSealer(FixtureKeys(), iAmLo: true, sending: true);
        var receiver = new FrameSealer(FixtureKeys(), iAmLo: false, sending: false);

        byte[] Frame()
        {
            var f = new byte[13 + 8 + 4 + 16];
            f[0] = 0x52;
            sender.Seal(f.AsSpan(13), f.AsSpan(0, 13), [1, 2, 3, 4]);
            return f;
        }

        byte[] scratch = new byte[64];
        Assert.True(receiver.Open(Frame(), scratch, out _)); // counter 1

        byte[] forged = Frame(); // counter 2 on the wire, claimed as 100
        BinaryPrimitives.WriteUInt64LittleEndian(forged.AsSpan(13), 100);
        Assert.False(receiver.Open(forged, scratch, out _));

        Assert.True(receiver.Open(Frame(), scratch, out _), "a rejected forged counter must not starve the frames behind it");
        Assert.True(receiver.Open(Frame(), scratch, out _));
    }

    [Fact]
    public void FrameSealer_ForgedNextEpochCounter_IsRejectedWithoutRatchetingTheKey()
    {
        // The same forger one epoch ahead: the epoch ratchet may adopt the next epoch's
        // key only when a frame sealed under it authenticates. Committing the ratchet
        // on a forged counter would strand every legitimate frame still sealed under
        // the previous epoch's key — a one-packet kill of the receive direction.
        var keys = new SessionKeys
        {
            TranscriptHash = new byte[32],
            LoToHiKey = RandomNumberGenerator.GetBytes(32),
            HiToLoKey = RandomNumberGenerator.GetBytes(32),
            LoToHiSalt = new byte[4],
            HiToLoSalt = new byte[4],
            LoConfirm = new byte[16],
            HiConfirm = new byte[16],
        };
        var sender = new FrameSealer(keys, iAmLo: true, sending: true, epochFrames: 8);
        var receiver = new FrameSealer(keys, iAmLo: false, sending: false, epochFrames: 8);

        byte[] Frame()
        {
            var f = new byte[13 + 8 + 4 + 16];
            f[0] = 0x52;
            sender.Seal(f.AsSpan(13), f.AsSpan(0, 13), [1, 2, 3, 4]);
            return f;
        }

        byte[] scratch = new byte[64];
        for (int i = 0; i < 4; i++)
        {
            Assert.True(receiver.Open(Frame(), scratch, out _)); // counters 1..4, epoch 0
        }

        byte[] forged = Frame(); // counter 5 on the wire, claimed as 9 = epoch 1
        BinaryPrimitives.WriteUInt64LittleEndian(forged.AsSpan(13), 9);
        Assert.False(receiver.Open(forged, scratch, out _));

        // Genuine epoch-0 frames still open: the key was not ratcheted by the forgery.
        for (int i = 0; i < 4; i++)
        {
            Assert.True(receiver.Open(Frame(), scratch, out _), $"counter {5 + i} must open after the forged epoch jump");
        }

        // And the genuine epoch transition still ratchets, on an authenticated frame.
        Assert.True(receiver.Open(Frame(), scratch, out _)); // counter 9, epoch 1
        Assert.True(receiver.Open(Frame(), scratch, out _)); // counter 10
    }

    [Fact]
    public void FrameSealer_ReorderAcrossEpochBoundary_StragglerStillOpens()
    {
        // UDP legitimately reorders. When the window crosses an epoch boundary, a
        // straggler from the previous epoch is still inside the replay window and must
        // open under the retained previous-epoch key.
        var keys = new SessionKeys
        {
            TranscriptHash = new byte[32],
            LoToHiKey = RandomNumberGenerator.GetBytes(32),
            HiToLoKey = RandomNumberGenerator.GetBytes(32),
            LoToHiSalt = new byte[4],
            HiToLoSalt = new byte[4],
            LoConfirm = new byte[16],
            HiConfirm = new byte[16],
        };
        var sender = new FrameSealer(keys, iAmLo: true, sending: true, epochFrames: 8);
        var receiver = new FrameSealer(keys, iAmLo: false, sending: false, epochFrames: 8);

        var frames = new List<byte[]>();
        for (int i = 0; i < 10; i++)
        {
            var f = new byte[13 + 8 + 4 + 16];
            f[0] = 0x52;
            sender.Seal(f.AsSpan(13), f.AsSpan(0, 13), [(byte)i, 0, 0, 0]);
            frames.Add(f);
        }

        byte[] scratch = new byte[64];
        Assert.True(receiver.Open(frames[0], scratch, out _)); // epoch 0
        Assert.True(receiver.Open(frames[1], scratch, out _));
        Assert.True(receiver.Open(frames[8], scratch, out _)); // epoch 1: ratchet commits
        Assert.True(receiver.Open(frames[9], scratch, out _));
        for (int i = 2; i < 8; i++)
        {
            Assert.True(receiver.Open(frames[i], scratch, out _),
                $"straggler counter {i + 1} from the previous epoch must open under the retained key");
        }
    }

    [Fact]
    public async Task FrameSealer_DisposeDuringOpens_RefusesQuietlyNeverThrows()
    {
        var sender = new FrameSealer(FixtureKeys(), iAmLo: true, sending: true);
        var receiver = new FrameSealer(FixtureKeys(), iAmLo: false, sending: false);

        var frames = new List<byte[]>();
        for (int i = 0; i < 500; i++)
        {
            var f = new byte[13 + 8 + 4 + 16];
            f[0] = 0x52;
            sender.Seal(f.AsSpan(13), f.AsSpan(0, 13), [1, 2, 3, 4]);
            frames.Add(f);
        }

        var tasks = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            byte[] scratch = new byte[64];
            foreach (byte[] f in frames)
            {
                receiver.Open(f, scratch, out _);
            }
        })).ToArray();
        receiver.Dispose(); // races the opens; nothing may throw
        await Task.WhenAll(tasks);

        Assert.False(receiver.Open(frames[0], new byte[64], out _)); // refused, not thrown
    }

    [Theory]
    [InlineData(1UL, 2UL)]
    [InlineData(2UL, 1UL)]
    public void UnconfirmedLatch_VerifiedFreshHandshakeReplacesStaleKeys(ulong mine, ulong theirs)
    {
        var identity = new NodeIdentity();
        var peerIdentity = new NodeIdentity();
        ConnectionCrypto local = ConnectionCrypto.New(identity, mine, theirs);
        ConnectionCrypto stale = ConnectionCrypto.New(peerIdentity, theirs, mine);
        ConnectionCrypto current = ConnectionCrypto.New(peerIdentity, theirs, mine);
        Assert.True(local.TryPeerKeys(stale.MyEphPublic, stale.MyStaticPublic));
        Assert.True(current.TryPeerKeys(local.MyEphPublic, local.MyStaticPublic));
        Assert.False(local.VerifyPeerConfirm(current.MyConfirm()));

        Assert.True(local.TrySupersedeUnconfirmed(current.MyEphPublic, current.MyStaticPublic, current.MyConfirm()));
        Assert.True(local.VerifyPeerConfirm(current.MyConfirm()));
        Assert.True(current.VerifyPeerConfirm(local.MyConfirm()));
        Assert.Equal(current.MyEphPublic, local.PeerEphPublic);
        Assert.Equal(1, local.SupersededLatches);
    }

    [Theory]
    [InlineData(1UL, 2UL)]
    [InlineData(2UL, 1UL)]
    public void UnconfirmedLatch_FailedProofAndLowOrderKeysLeaveStateUntouched(ulong mine, ulong theirs)
    {
        var identity = new NodeIdentity();
        var peerIdentity = new NodeIdentity();
        ConnectionCrypto local = ConnectionCrypto.New(identity, mine, theirs);
        ConnectionCrypto stale = ConnectionCrypto.New(peerIdentity, theirs, mine);
        ConnectionCrypto current = ConnectionCrypto.New(peerIdentity, theirs, mine);
        Assert.True(local.TryPeerKeys(stale.MyEphPublic, stale.MyStaticPublic));
        Assert.True(current.TryPeerKeys(local.MyEphPublic, local.MyStaticPublic));
        SessionKeys? keys = local.Keys;
        FrameSealer? send = local.Send;
        FrameSealer? recv = local.Recv;
        byte[] invalidConfirm = current.MyConfirm().ToArray();
        invalidConfirm[0] ^= 1;

        Assert.False(local.TrySupersedeUnconfirmed(current.MyEphPublic, current.MyStaticPublic, invalidConfirm));
        Assert.False(local.TrySupersedeUnconfirmed(new byte[32], current.MyStaticPublic, current.MyConfirm()));
        Assert.Same(keys, local.Keys);
        Assert.Same(send, local.Send);
        Assert.Same(recv, local.Recv);
        Assert.Equal(stale.MyEphPublic, local.PeerEphPublic);
        Assert.Equal(0, local.SupersededLatches);
    }

    [Theory]
    [InlineData(1UL, 2UL)]
    [InlineData(2UL, 1UL)]
    public void ConfirmedLatch_CannotBeReplacedEvenByAValidFreshHandshake(ulong mine, ulong theirs)
    {
        var identity = new NodeIdentity();
        var peerIdentity = new NodeIdentity();
        ConnectionCrypto local = ConnectionCrypto.New(identity, mine, theirs);
        ConnectionCrypto original = ConnectionCrypto.New(peerIdentity, theirs, mine);
        ConnectionCrypto successor = ConnectionCrypto.New(peerIdentity, theirs, mine);
        Assert.True(local.TryPeerKeys(original.MyEphPublic, original.MyStaticPublic));
        Assert.True(original.TryPeerKeys(local.MyEphPublic, local.MyStaticPublic));
        Assert.True(local.VerifyPeerConfirm(original.MyConfirm()));
        local.MarkPeerConfirmed();
        Assert.True(successor.TryPeerKeys(local.MyEphPublic, local.MyStaticPublic));
        SessionKeys? keys = local.Keys;

        Assert.False(local.TrySupersedeUnconfirmed(successor.MyEphPublic, successor.MyStaticPublic, successor.MyConfirm()));
        Assert.Same(keys, local.Keys);
        Assert.Equal(original.MyEphPublic, local.PeerEphPublic);
        Assert.True(local.VerifyPeerConfirm(original.MyConfirm()));
        Assert.Equal(0, local.SupersededLatches);
    }

    // ---------------------------------------------------------------- end to end

    [Fact]
    public async Task EncryptedByDefault_DataFlows_BothSidesAuthenticated()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());

        PinholeConnection atA = await a.ConnectAsync(b.ConnectionString);
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atA.Received += p => got.TrySetResult(p.ToArray());
        await using PinholeConnection atB = await b.AcceptAsync();

        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (!got.Task.IsCompleted && sw.Elapsed < Timeout)
        {
            atB.Send("secret"u8);
            await Task.Delay(100);
        }

        Assert.Equal("secret"u8.ToArray(), await got.Task.WaitAsync(TimeSpan.FromSeconds(1)));
        Assert.True(atA.IsEncrypted);
        Assert.True(atB.IsEncrypted);
        Assert.Equal(b.StaticPublicKey, atA.RemoteStaticKey);
        Assert.Equal(a.StaticPublicKey, atB.RemoteStaticKey);
        Assert.Equal(0, atA.FramesRejected);
        Assert.Equal(0, atB.FramesRejected);
    }

    [Fact]
    public async Task IdentitySeed_StableIdentity_AcrossBinds()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        await using PinholeNode a = await PinholeNode.BindAsync(Opts(o => o with { IdentityKeySeed = seed }));
        await using PinholeNode b = await PinholeNode.BindAsync(Opts(o => o with { IdentityKeySeed = seed }));
        Assert.Equal(a.StaticPublicKey, b.StaticPublicKey);

        await using PinholeNode c = await PinholeNode.BindAsync(Opts(o => o with { Encryption = PinholeEncryption.Disabled }));
        Assert.Null(c.StaticPublicKey);
    }

    [Fact]
    public async Task ConnectionString_V2_RoundTripsTheStaticKey()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        ConnectionString cs = Pinhole.ConnectionString.Parse(a.ConnectionString);
        Assert.NotNull(cs.StaticKey);
        Assert.Equal(a.StaticPublicKey, cs.StaticKey);

        // a v2 payload without the trailing key, or with a wrong-length one, is malformed
        await using PinholeNode b = await PinholeNode.BindAsync(Opts(o => o with { Encryption = PinholeEncryption.Disabled }));
        ConnectionString legacy = Pinhole.ConnectionString.Parse(b.ConnectionString);
        Assert.Null(legacy.StaticKey);
        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(1, [], NatHint.Unknown, new byte[31]));
    }

    [Fact]
    public async Task SimultaneousDials_ConvergeOnOneEncryptedSession()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());

        Task<PinholeConnection> dialA = a.ConnectAsync(b.ConnectionString);
        Task<PinholeConnection> dialB = b.ConnectAsync(a.ConnectionString);
        PinholeConnection atA = await dialA;
        PinholeConnection atB = await dialB;

        Assert.True(atA.IsEncrypted);
        Assert.True(atB.IsEncrypted);

        var gotB = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atB.Received += p => gotB.TrySetResult(p.ToArray());
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (!gotB.Task.IsCompleted && sw.Elapsed < Timeout)
        {
            atA.Send("both dialed"u8);
            await Task.Delay(100);
        }

        Assert.Equal("both dialed"u8.ToArray(), await gotB.Task.WaitAsync(TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public async Task Mitm_StaticKeySubstitution_KillsTheDial()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts(o => o with { ConnectTimeout = TimeSpan.FromSeconds(5) }));

        // A "machine in the middle" re-issues the victim's string with its own key
        // substituted. No real attacker is present — the honest peer's PACK simply fails the
        // pin, which is exactly what a machine in the middle cannot forge.
        await using PinholeNode honest = await PinholeNode.BindAsync(Opts());
        ConnectionString honestString = Pinhole.ConnectionString.Parse(honest.ConnectionString);
        var tampered = new ConnectionString(
            honestString.PeerId, honestString.Candidates, honestString.NatHint,
            staticKey: new NodeIdentity().PublicKey);

        var ex = await Assert.ThrowsAnyAsync<Exception>(() => a.ConnectAsync(tampered.ToString()));
        Assert.True(ex is InvalidOperationException or TimeoutException, $"unexpected {ex}");
    }

    [Fact]
    public async Task Downgrade_PlaintextPack_AgainstACryptoDial_KillsTheConnection()
    {
        // A raw socket pretending to be the peer of a v2 string: it answers the crypto PUNC
        // with a legacy plaintext PACK — the striptease a machine in the middle would perform.
        await using PinholeNode a = await PinholeNode.BindAsync(Opts(o => o with { ConnectTimeout = TimeSpan.FromSeconds(5) }));
        using var fake = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        fake.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        var cs = new ConnectionString(0xdeadbeefdeadbeef,
            [new PinholeCandidate(CandidateKind.Direct, (IPEndPoint)fake.LocalEndPoint!)],
            NatHint.Unknown,
            staticKey: new NodeIdentity().PublicKey);

        _ = Task.Run(() =>
        {
            byte[] buf = new byte[2048];
            EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            int n = fake.ReceiveFrom(buf, ref any);
            byte[] pack = new byte[17];
            pack[0] = 0x51;
            BinaryPrimitives.WriteUInt64LittleEndian(pack.AsSpan(1), 0xdeadbeefdeadbeef); // the fake's own id
            Buffer.BlockCopy(buf, 9, pack, 9, 4);  // echo the dialer's token
            fake.SendTo(pack, any);
        });

        var ex = await Assert.ThrowsAnyAsync<Exception>(() => a.ConnectAsync(cs.ToString()));
        Assert.True(ex is InvalidOperationException or TimeoutException, $"unexpected {ex}");
    }

    [Fact]
    public async Task RequiredNode_TurnsAwayV1Strings_AndPlaintextStrangers()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());

        var v1 = new ConnectionString(0x1234, [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 65000))]);
        PinholeConnectResult result = await a.TryConnectAsync(v1.ToString());
        Assert.Equal(PinholeConnectFailure.PeerIncompatible, result.Failure);

        using var stranger = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        stranger.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        byte[] punc = new byte[13];
        punc[0] = 0x50;
        BinaryPrimitives.WriteUInt64LittleEndian(punc.AsSpan(1), 0xcafebabecafebabe);
        BinaryPrimitives.WriteUInt32LittleEndian(punc.AsSpan(9), 0x01020304);
        for (int i = 0; i < 50; i++)
        {
            stranger.SendTo(punc, new IPEndPoint(IPAddress.Loopback, a.LocalPort));
        }

        await Task.Delay(300);
        Assert.Empty(a.Connections);
    }

    [Fact]
    public async Task OptionalNode_TalksToALegacyV1Peer_InPlaintext()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts(o => o with { Encryption = PinholeEncryption.Optional, ConnectTimeout = TimeSpan.FromSeconds(5) }));
        using var fakePeer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        fakePeer.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        uint token = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
        const ulong fakePeerId = 0xfeedfacefeedface;
        var cs = new ConnectionString(fakePeerId, [new PinholeCandidate(CandidateKind.Direct, (IPEndPoint)fakePeer.LocalEndPoint!)]);

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        _ = Task.Run(() =>
        {
            byte[] buf = new byte[2048];
            while (!got.Task.IsCompleted)
            {
                EndPoint any = new IPEndPoint(IPAddress.Any, 0);
                int n;
                try { n = fakePeer.ReceiveFrom(buf, ref any); }
                catch (SocketException) { return; }
                if (n >= 13 && buf[0] == 0x50)
                {
                    byte[] pack = new byte[17];
                    pack[0] = 0x51;
                    BinaryPrimitives.WriteUInt64LittleEndian(pack.AsSpan(1), fakePeerId);
                    Buffer.BlockCopy(buf, 9, pack, 9, 4);
                    BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(13), token);
                    fakePeer.SendTo(pack, any);

                    // Keep the data coming until the test has seen it: on a slow runner the
                    // whole burst can be delivered before the post-dial subscription attaches.
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    while (!got.Task.IsCompleted && sw.Elapsed < TimeSpan.FromSeconds(6))
                    {
                        byte[] data = new byte[13 + 5];
                        data[0] = 0x52;
                        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(1), fakePeerId);
                        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(9), token);
                        Encoding.ASCII.GetBytes("plain").CopyTo(data, 13);
                        fakePeer.SendTo(data, any);
                        Thread.Sleep(25);
                    }
                }
            }
        });

        PinholeConnection conn = await a.ConnectAsync(cs.ToString());
        conn.Received += p => got.TrySetResult(p.ToArray());
        Assert.Equal("plain"u8.ToArray(), await got.Task.WaitAsync(Timeout));
        Assert.False(conn.IsEncrypted);
        Assert.Null(conn.RemoteStaticKey);
    }

    // ---------------------------------------------------------------- wire-level oracle peer

    /// <summary>Speaks the real wire protocol with a real handshake: proves the node's frames
    /// are sealed on the wire, byte for byte, and that forged/replayed frames die at the
    /// receiver.</summary>
    private sealed class OraclePeer : IDisposable
    {
        public readonly Socket Sock = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        public readonly ulong PeerId = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        public readonly NodeIdentity Identity = new();
        public const uint Token = 0x11223344;
        private ConnectionCrypto? _crypto;
        public byte[] HandshakePack { get; private set; } = [];

        public IPEndPoint Ep => (IPEndPoint)Sock.LocalEndPoint!;

        public ConnectionString StringPointingAt(IPEndPoint ep) => new(
            PeerId, [new PinholeCandidate(CandidateKind.Direct, ep)], NatHint.Unknown, Identity.PublicKey);

        public byte[] CurrentPunch()
        {
            byte[] punc = new byte[77]; punc[0] = 0x50;
            BinaryPrimitives.WriteUInt64LittleEndian(punc.AsSpan(1), PeerId);
            BinaryPrimitives.WriteUInt32LittleEndian(punc.AsSpan(9), Token);
            _crypto!.MyEphPublic.CopyTo(punc, 13); _crypto.MyStaticPublic.CopyTo(punc, 45);
            return punc;
        }

        public async Task SendUnfinishedIncomingHandshakeAsync(PinholeNode node, bool confirm, NodeIdentity? identity = null)
        {
            var crypto = ConnectionCrypto.New(identity ?? Identity, PeerId, node.PeerId);
            var target = new IPEndPoint(IPAddress.Loopback, node.LocalPort);
            byte[] punc = new byte[77]; punc[0] = 0x50;
            BinaryPrimitives.WriteUInt64LittleEndian(punc.AsSpan(1), PeerId);
            BinaryPrimitives.WriteUInt32LittleEndian(punc.AsSpan(9), Token);
            crypto.MyEphPublic.CopyTo(punc, 13); crypto.MyStaticPublic.CopyTo(punc, 45);
            await Sock.SendToAsync(punc, target);
            using var deadline = new CancellationTokenSource(Timeout);
            var reply = new byte[8192];
            while (true)
            {
                var received = await Sock.ReceiveFromAsync(reply, new IPEndPoint(IPAddress.Any, 0), deadline.Token);
                if (received.ReceivedBytes != 97 || reply[0] != 0x51) continue;
                Assert.True(crypto.TryPeerKeys(reply.AsSpan(17, 32), reply.AsSpan(49, 32)));
                Assert.True(crypto.VerifyPeerConfirm(reply.AsSpan(81, 16)));
                break;
            }
            if (confirm)
            {
                byte[] hsck = new byte[29]; hsck[0] = 0x57;
                BinaryPrimitives.WriteUInt64LittleEndian(hsck.AsSpan(1), PeerId);
                BinaryPrimitives.WriteUInt32LittleEndian(hsck.AsSpan(9), Token);
                crypto.MyConfirm().CopyTo(hsck, 13);
                await Sock.SendToAsync(hsck, target);
                await TestPoll.UntilAsync(Timeout, () => node.Engine.Lookup(PeerId)?.Crypto?.PeerConfirmed == true);
            }
        }

        /// <summary>Waits for the node's crypto PUNC, derives the same keys, answers PACK.
        /// The node must already be dialing this peer.</summary>
        public async Task ShakeHandsAsync(PinholeNode node, CancellationToken ct = default, uint? advertisedToken = null)
        {
            var nodeEp = new IPEndPoint(IPAddress.Loopback, node.LocalPort);
            _crypto = ConnectionCrypto.New(Identity, PeerId, node.PeerId);
            byte[] buf = new byte[2048];
            EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            while (true)
            {
                SocketReceiveFromResult r = await Sock.ReceiveFromAsync(buf, any, ct);
                // The PUNC carries no recipient field — the header's peer id is the sender,
                // which for a dial we initiated is always the node we dialed.
                if (r.ReceivedBytes == 9 + CryptoWire.PuncCryptoBody && buf[0] == 0x50
                    && BinaryPrimitives.ReadUInt64LittleEndian(buf.AsSpan(1)) == node.PeerId)
                {
                    break;
                }
            }

            uint dialerToken = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(9));
            if (!_crypto.TryPeerKeys(buf.AsSpan(13, 32), buf.AsSpan(45, 32)))
            {
                throw new InvalidOperationException("oracle peer could not derive the node's keys");
            }

            byte[] pack = new byte[9 + CryptoWire.PackCryptoBody];
            pack[0] = 0x51;
            BinaryPrimitives.WriteUInt64LittleEndian(pack.AsSpan(1), PeerId);
            BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(9), dialerToken);
            BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(13), advertisedToken ?? Token);
            _crypto.MyEphPublic.CopyTo(pack.AsSpan(17));
            _crypto.MyStaticPublic.CopyTo(pack.AsSpan(49));
            _crypto.MyConfirm().CopyTo(pack.AsSpan(81));
            HandshakePack = pack;
            await Sock.SendToAsync(pack, nodeEp, ct);
            // A plaintext handshake does not prove its source route. Supply fresh sealed
            // traffic so the node can adopt the oracle's UDP path and complete its dial.
            await Sock.SendToAsync(SealFrame(0x53, new byte[8]), nodeEp, ct);
        }

        /// <summary>Builds one sealed frame exactly the way the engine does.</summary>
        public byte[] SealFrame(byte type, ReadOnlySpan<byte> body)
        {
            var f = new byte[9 + 4 + CryptoWire.SealedOverhead + body.Length];
            f[0] = type;
            BinaryPrimitives.WriteUInt64LittleEndian(f.AsSpan(1), PeerId);
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(9), Token);
            _crypto!.Send!.Seal(f.AsSpan(13), f.AsSpan(0, 13), body);
            return f;
        }

        /// <summary>Receives until a sealed frame from the node opens under the session keys.</summary>
        public async Task<(byte Type, byte[] Body)?> ReceiveSealedAsync(TimeSpan timeout, byte? wantType = null)
        {
            using var cts = new CancellationTokenSource(timeout);
            byte[] buf = new byte[8192];
            byte[] plain = new byte[8192];
            EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    SocketReceiveFromResult r = await Sock.ReceiveFromAsync(buf, any, cts.Token);
                    if (r.ReceivedBytes < 13 || buf[0] is 0x50 or 0x51 or 0x57)
                    {
                        continue; // handshake frames are plaintext by design
                    }

                    if (_crypto!.Recv!.Open(buf.AsSpan(0, r.ReceivedBytes), plain, out int len))
                    {
                        if (wantType is { } t && buf[0] != t)
                        {
                            continue;
                        }

                        return (buf[0], plain.AsSpan(0, len).ToArray());
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }

            return null;
        }

        public void Dispose() => Sock.Dispose();
    }

    [Fact]
    public async Task WireOracle_SealedFramesFlow_ForgedAndReplayedOnesDie()
    {
        await using PinholeNode node = await PinholeNode.BindAsync(Opts(o => o with { ConnectTimeout = TimeSpan.FromSeconds(5) }));
        using var oracle = new OraclePeer();
        oracle.Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        // The node dials the oracle; the oracle completes a genuine handshake.
        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString());
        await oracle.ShakeHandsAsync(node);
        PinholeConnection conn = await dial;
        Assert.True(conn.IsEncrypted);

        // The genuine frame is delivered exactly once. Its exact replay is refused by the
        // replay window, and a fresh frame whose tag was corrupted in flight is refused by
        // authentication — and only refused: a corrupted tag consumes nothing, so the
        // ordering here (genuine first) is just determinism, not a workaround. The
        // corrupted-clone-before-genuine order is covered by
        // WireOracle_CorruptedCloneDoesNotBurnTheCounter.
        byte[] real = oracle.SealFrame(0x52, "genuine"u8);
        byte[] replay = (byte[])real.Clone();
        byte[] forged = oracle.SealFrame(0x52, "forged"u8);
        forged[^1] ^= 0xFF;

        // Subscribe before sending: on a fast machine the genuine frame can be delivered
        // before a subscription added after the sends would attach.
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.Received += p => got.TrySetResult(p.ToArray());

        var nodeEp = new IPEndPoint(IPAddress.Loopback, node.LocalPort);
        oracle.Sock.SendTo(real, nodeEp);
        oracle.Sock.SendTo(replay, nodeEp);
        oracle.Sock.SendTo(forged, nodeEp);

        Assert.Equal("genuine"u8.ToArray(), await got.Task.WaitAsync(Timeout));

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => conn.FramesRejected >= 2);
        Assert.Equal(1, conn.Stats.DatagramsReceived); // the replay did not double-deliver
    }

    [Fact]
    public async Task WireOracle_EditedInitialPackTokenIsHealedOnlyByAuthenticatedTraffic()
    {
        await using PinholeNode node = await PinholeNode.BindAsync(Opts());
        using var oracle = new OraclePeer();
        oracle.Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString());
        await oracle.ShakeHandsAsync(node, advertisedToken: OraclePeer.Token + 1);
        PinholeConnection conn = await dial.WaitAsync(Timeout);
        ConnState state = node.Engine.Lookup(oracle.PeerId)!;
        Assert.True(state.RemoteTokenAuthenticated);
        Assert.Equal(OraclePeer.Token, state.RemoteToken);
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.Received += p => got.TrySetResult(p.ToArray());
        await oracle.Sock.SendToAsync(oracle.SealFrame(0x52, "real token"u8),
            new IPEndPoint(IPAddress.Loopback, node.LocalPort));
        Assert.Equal("real token"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WireOracle_ExplicitDialAdoptsAnUnfinishedIncomingHandshakeAndFreshPeerKeys(bool confirmOldKeys)
    {
        await using var node = await PinholeNode.BindAsync(Opts());
        using var oracle = new OraclePeer();
        oracle.Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        await oracle.SendUnfinishedIncomingHandshakeAsync(node, confirmOldKeys);
        ConnState incoming = node.Engine.Lookup(oracle.PeerId)!;
        Assert.True(incoming.IsIncoming);
        Assert.False(incoming.RemoteTokenAuthenticated);
        Assert.False(incoming.Connected.Task.IsCompleted);

        using var deadline = new CancellationTokenSource(Timeout);
        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString(), deadline.Token);
        await oracle.ShakeHandsAsync(node, deadline.Token); // the peer's new connection has new ephemeral keys
        await using var connected = await dial.WaitAsync(Timeout);
        Assert.Same(incoming.Public, connected);
        Assert.Equal(oracle.Identity.PublicKey, incoming.PinnedStaticKey);
        Assert.True(incoming.RemoteTokenAuthenticated);
        Assert.True(connected.IsEncrypted);
    }

    [Fact]
    public async Task WireOracle_IdempotentDialStillChecksTheRequestedStaticKey()
    {
        await using var node = await PinholeNode.BindAsync(Opts());
        using var oracle = new OraclePeer();
        oracle.Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString());
        await oracle.ShakeHandsAsync(node);
        await using var connected = await dial.WaitAsync(Timeout);
        string wrongPin = new ConnectionString(oracle.PeerId,
            [new PinholeCandidate(CandidateKind.Direct, oracle.Ep)], staticKey: new NodeIdentity().PublicKey).ToString();
        await Assert.ThrowsAsync<InvalidOperationException>(() => node.ConnectAsync(wrongPin));
        Assert.Equal(PinholeConnectionState.Open, connected.State);
        Assert.Same(connected, await node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString()));
    }

    [Fact]
    public async Task WireOracle_UnprovedIncomingKeyCannotBlockAPinnedDial()
    {
        await using var node = await PinholeNode.BindAsync(Opts());
        using var oracle = new OraclePeer();
        oracle.Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        await oracle.SendUnfinishedIncomingHandshakeAsync(node, confirm: true, identity: new NodeIdentity());
        ConnState stranger = node.Engine.Lookup(oracle.PeerId)!;
        using var deadline = new CancellationTokenSource(Timeout);
        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString(), deadline.Token);
        await oracle.ShakeHandsAsync(node, deadline.Token);
        await using var connected = await dial.WaitAsync(Timeout);
        Assert.NotSame(stranger.Public, connected);
        Assert.Equal(PinholeConnectionState.Closed, stranger.State);
        Assert.Equal(oracle.Identity.PublicKey, connected.RemoteStaticKey);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WireOracle_LatePunchCannotRecreateAClosedAuthenticatedSession(bool remoteClose)
    {
        await using var node = await PinholeNode.BindAsync(Opts());
        using var oracle = new OraclePeer();
        oracle.Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString());
        await oracle.ShakeHandsAsync(node);
        await using var connected = await dial.WaitAsync(Timeout);
        byte[] latePunch = oracle.CurrentPunch();
        var target = new IPEndPoint(IPAddress.Loopback, node.LocalPort);
        if (remoteClose) await oracle.Sock.SendToAsync(oracle.SealFrame(0x56, []), target);
        else await connected.CloseAsync();
        await TestPoll.UntilAsync(Timeout, () => connected.State == PinholeConnectionState.Closed);
        await oracle.Sock.SendToAsync(latePunch, target);
        await TestPoll.UntilAsync(Timeout, () => Volatile.Read(ref node.Engine.StaleHandshakeDrops) > 0);
        Assert.Null(node.Engine.Lookup(oracle.PeerId));

        using var deadline = new CancellationTokenSource(Timeout);
        Task<PinholeConnection> redial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString(), deadline.Token);
        await oracle.ShakeHandsAsync(node, deadline.Token);
        await using var fresh = await redial.WaitAsync(Timeout);
        Assert.NotSame(connected, fresh);
        Assert.True(fresh.IsEncrypted);
    }

    [Theory]
    [InlineData("confirmation")]
    [InlineData("static-key")]
    [InlineData("ephemeral-key")]
    [InlineData("peer-token")]
    [InlineData("downgrade")]
    [InlineData("replay-from-another-address")]
    public async Task WireOracle_HandshakeRetriesCannotKillOrRedirectAConfirmedSession(string attack)
    {
        await using PinholeNode node = await PinholeNode.BindAsync(Opts());
        using var oracle = new OraclePeer();
        oracle.Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString());
        await oracle.ShakeHandsAsync(node);
        PinholeConnection conn = await dial.WaitAsync(Timeout);
        ConnState state = node.Engine.Lookup(oracle.PeerId)!;
        IPEndPoint? originalRemote = conn.Path.Remote;
        byte[] frame = oracle.HandshakePack.ToArray();
        switch (attack)
        {
            case "confirmation": frame[81] ^= 1; break;
            case "static-key": new NodeIdentity().PublicKey.CopyTo(frame.AsSpan(49)); break;
            case "ephemeral-key": NodeIdentity.NewEphemeral().Public.CopyTo(frame.AsSpan(17)); break;
            case "peer-token": BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(13), OraclePeer.Token + 1); break;
            case "downgrade": frame = frame[..17]; break;
        }

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        long rejects = conn.FramesRejected;
        long packs = Volatile.Read(ref state.PacksReceived);
        await attacker.SendToAsync(frame, new IPEndPoint(IPAddress.Loopback, node.LocalPort));
        await TestPoll.UntilAsync(Timeout, () => attack == "replay-from-another-address"
            ? Volatile.Read(ref state.PacksReceived) > packs : conn.FramesRejected > rejects);

        Assert.Equal(PinholeConnectionState.Open, conn.State);
        Assert.Equal(originalRemote, conn.Path.Remote);
        Assert.Equal(OraclePeer.Token, state.RemoteToken);
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.Received += p => got.TrySetResult(p.ToArray());
        await oracle.Sock.SendToAsync(oracle.SealFrame(0x52, "still authenticated"u8),
            new IPEndPoint(IPAddress.Loopback, node.LocalPort));
        Assert.Equal("still authenticated"u8.ToArray(), await got.Task.WaitAsync(Timeout));
        conn.Send("reply"u8);
        var reply = await oracle.ReceiveSealedAsync(Timeout, wantType: 0x52);
        Assert.NotNull(reply);
        Assert.Equal("reply"u8.ToArray(), reply.Value.Body);
    }

    [Fact]
    public async Task WireOracle_CorruptedCloneDoesNotBurnTheCounter()
    {
        // A frame corrupted in flight carries the genuine counter. The receiver must
        // refuse the corrupted clone on its tag and still deliver the genuine frame
        // that follows: the replay window advances only on authenticated frames
        // (RFC 4303 §3.4.3), so the clone consumes nothing.
        await using PinholeNode node = await PinholeNode.BindAsync(Opts(o => o with { ConnectTimeout = TimeSpan.FromSeconds(5) }));
        using var oracle = new OraclePeer();
        oracle.Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString());
        await oracle.ShakeHandsAsync(node);
        PinholeConnection conn = await dial;

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.Received += p => got.TrySetResult(p.ToArray());

        var nodeEp = new IPEndPoint(IPAddress.Loopback, node.LocalPort);
        byte[] genuine = oracle.SealFrame(0x52, "genuine"u8);
        byte[] corrupted = (byte[])genuine.Clone();
        corrupted[^1] ^= 0xFF;
        oracle.Sock.SendTo(corrupted, nodeEp); // the clone lands first
        oracle.Sock.SendTo(genuine, nodeEp);

        Assert.Equal("genuine"u8.ToArray(), await got.Task.WaitAsync(Timeout));
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => conn.FramesRejected >= 1);
        Assert.Equal(1, conn.Stats.DatagramsReceived); // delivered once, the clone refused
    }

    [Fact]
    public async Task WireOracle_NodeFramesAreSealedOnTheWire()
    {
        await using PinholeNode node = await PinholeNode.BindAsync(Opts(o => o with { ConnectTimeout = TimeSpan.FromSeconds(5) }));
        using var oracle = new OraclePeer();
        oracle.Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString());
        await oracle.ShakeHandsAsync(node);
        PinholeConnection conn = await dial;
        conn.Ping();

        // Everything the node sends after the handshake must open under the session keys —
        // and only under them.
        (byte type, byte[] body)? frame = await oracle.ReceiveSealedAsync(TimeSpan.FromSeconds(5), wantType: 0x53);
        Assert.NotNull(frame);
        // Caller pings carry the 8-byte timestamp first and are padded to the guaranteed
        // wire floor behind it: peers size their path MTU from inbound Ping frames, and a
        // sub-floor ping would shrink a legacy peer's payload budget below zero.
        Assert.True(frame!.Value.body.Length >= 8, $"ping body lost its timestamp: {frame.Value.body.Length} bytes");
        Assert.InRange(frame.Value.body.Length, 8, 1300);
    }
}
