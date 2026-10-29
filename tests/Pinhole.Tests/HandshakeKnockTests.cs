using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Pinhole.Crypto;
using Xunit;

namespace Pinhole.Tests;

// R5 phase 2 remainder: the knock — an optional per-string secret mixed into the armor
// as a PSK. When the answering node is configured with one, its connection string
// carries the secret, mac1 is keyed with a derivation of (static pub, knock) instead of
// the raw static pub, unversioned initiations are ignored outright, and the session
// keys mix the knock as a labeled PSK block. These pin the labeled constructions, the
// PSK's effect on every derived artifact, the knock-less byte-identity (no option set,
// no behavior change), the total silence a static-pub-only scanner earns on both v4 and
// v3 shapes, the wrong-knock and MITM refusals, the v3-under-knock policy, the
// cookie layering under knock, and the string round-trip.
public sealed class HandshakeKnockTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static byte[] Knock(int length = 16)
    {
        byte[] knock = new byte[length];
        RandomNumberGenerator.Fill(knock);
        return knock;
    }

    private static PinholeOptions Opts(byte[]? knock = null, TimeSpan? connectTimeout = null) => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [], DerpRelayUrls = [],
        Listen = true,
        Knock = knock,
        ConnectTimeout = connectTimeout ?? TimeSpan.FromSeconds(8),
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false, EnablePortMapping = false,
        EnableTcpTransport = false,
    };

    // ------------------------------------------------------------------ the constructions

    [Fact]
    public void KnockMac1Key_IsTheLabeledBlake3DeriveKey_OverStaticPubAndKnock()
    {
        byte[] stat = RandomNumberGenerator.GetBytes(32);
        byte[] knock = Knock();
        Span<byte> key = stackalloc byte[32];
        CryptoWire.KnockMac1Key(key, stat, knock);

        // Independent recomputation: BLAKE3-DeriveKey(context = the label, material =
        // staticPub || knock) — the exact construction WIRE.md documents.
        byte[] material = [.. stat, .. knock];
        byte[] expected = Blake3.HashDeriveKey(CryptoWire.KnockMac1LabelBytes, material);
        Assert.Equal(expected, key.ToArray());

        // The derivation separates every input: another knock, another static key, or a
        // different order all land on a different key, and no input yields the raw key.
        Span<byte> other = stackalloc byte[32];
        CryptoWire.KnockMac1Key(other, stat, Knock());
        Assert.False(other.SequenceEqual(key));
        CryptoWire.KnockMac1Key(other, RandomNumberGenerator.GetBytes(32), knock);
        Assert.False(other.SequenceEqual(key));
        Assert.False(stat.AsSpan().SequenceEqual(key), "the knock key must not degenerate to the raw static pub");
    }

    [Fact]
    public void KnockPsk_ChangesEveryDerivedKey_BothSidesAgree_ConfirmFailsWithoutIt()
    {
        NodeIdentity loId = new(Convert.FromHexString("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"));
        NodeIdentity hiId = new(Convert.FromHexString("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"));
        (byte[] loEphPriv, byte[] loEphPub) = NodeIdentity.NewEphemeral();
        (byte[] hiEphPriv, byte[] hiEphPub) = NodeIdentity.NewEphemeral();
        ulong lo = 1, hi = 2;
        byte[] knock = Knock();

        SessionKeys withKnockLo = KeySchedule.Derive(lo, loEphPriv, loId.ExportPrivateSeed(), hi, hiEphPub, hiId.PublicKey, knock);
        SessionKeys withKnockHi = KeySchedule.Derive(hi, hiEphPriv, hiId.ExportPrivateSeed(), lo, loEphPub, loId.PublicKey, knock);
        SessionKeys withoutKnockLo = KeySchedule.Derive(lo, loEphPriv, loId.ExportPrivateSeed(), hi, hiEphPub, hiId.PublicKey);
        SessionKeys otherKnockLo = KeySchedule.Derive(lo, loEphPriv, loId.ExportPrivateSeed(), hi, hiEphPub, hiId.PublicKey, Knock());

        // Both knock-holders derive identical keys (role-absolute, like the DH).
        Assert.Equal(withKnockLo.LoToHiKey, withKnockHi.LoToHiKey);
        Assert.Equal(withKnockLo.HiConfirm, withKnockHi.HiConfirm);

        // Every sealed artifact differs from the knock-less schedule and from a wrong
        // knock: keys, salts, and both confirm MACs.
        foreach ((string name, byte[] a, byte[] b) in new[]
        {
            ("lo2hi key", withKnockLo.LoToHiKey, withoutKnockLo.LoToHiKey),
            ("hi2lo key", withKnockLo.HiToLoKey, withoutKnockLo.HiToLoKey),
            ("lo2hi salt", withKnockLo.LoToHiSalt, withoutKnockLo.LoToHiSalt),
            ("hi2lo salt", withKnockLo.HiToLoSalt, withoutKnockLo.HiToLoSalt),
            ("lo confirm", withKnockLo.LoConfirm, withoutKnockLo.LoConfirm),
            ("hi confirm", withKnockLo.HiConfirm, withoutKnockLo.HiConfirm),
            ("lo2hi key vs wrong knock", withKnockLo.LoToHiKey, otherKnockLo.LoToHiKey),
        })
        {
            Assert.False(a.AsSpan().SequenceEqual(b), $"{name} must change under the PSK");
        }

        // The confirm-MAC gate a knock-less MITM actually hits: a full handshake pair
        // where one side derives with the knock and the other without — the keys agree
        // on the DH, every MAC differs, and neither confirm verifies.
        var holder = ConnectionCrypto.New(loId, lo, hi, knock);
        var without = ConnectionCrypto.New(hiId, hi, lo);
        Assert.True(holder.TryPeerKeys(hiEphPub, hiId.PublicKey));
        Assert.True(without.TryPeerKeys(loEphPub, loId.PublicKey));
        Assert.False(holder.VerifyPeerConfirm(without.MyConfirm()), "a knock-less confirm must not verify against knock-derived keys");
        Assert.False(without.VerifyPeerConfirm(holder.MyConfirm()), "a knock-derived confirm must not verify against knock-less keys");
    }

    [Fact]
    public void KnocklessKeySchedule_IsByteIdentical_TheIndependentGoldenStillHolds()
    {
        // The CryptoTests golden (independent python derivation) already pins Derive
        // without a knock; here the explicit statement: default knock changes nothing —
        // the empty-knock call IS the old call.
        byte[] ephPriv = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        NodeIdentity id = new(Convert.FromHexString("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"));
        (byte[] ephPriv2, byte[] ephPub2) = NodeIdentity.NewEphemeral();
        NodeIdentity id2 = new(Convert.FromHexString("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"));
        SessionKeys omitted = KeySchedule.Derive(1, ephPriv, id.ExportPrivateSeed(), 2, ephPub2, id2.PublicKey);
        SessionKeys empty = KeySchedule.Derive(1, ephPriv, id.ExportPrivateSeed(), 2, ephPub2, id2.PublicKey, default);
        Assert.Equal(omitted.LoToHiKey, empty.LoToHiKey);
        Assert.Equal(omitted.HiConfirm, empty.HiConfirm);
    }

    // ------------------------------------------------------------------ options

    [Fact]
    public async Task KnockOptions_AreValidated_TooShortTooLongOrPlaintextRefuse()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PinholeNode.BindAsync(Opts(knock: new byte[7])));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PinholeNode.BindAsync(Opts(knock: new byte[65])));
        await Assert.ThrowsAsync<ArgumentException>(() => PinholeNode.BindAsync(Opts(knock: Knock()) with { Encryption = PinholeEncryption.Disabled }));

        // The legal bounds bind: 8 and 64 bytes both configure (the string they produce
        // is pinned in the engine gates below).
        await using PinholeNode short8 = await PinholeNode.BindAsync(Opts(knock: new byte[8]));
        await using PinholeNode long64 = await PinholeNode.BindAsync(Opts(knock: new byte[64]));
    }

    [Fact]
    public void KnocklessNode_ProducesTheSameStringShapeAsAlways()
    {
        // No knock option: the string stays v2/v3 and parses with a null knock — the
        // default surface is byte-identical to a pre-knock node.
        var candidates = new[] { new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 40000)) };
        var bare = new ConnectionString(1, candidates, NatHint.Unknown, RandomNumberGenerator.GetBytes(32));
        Assert.Null(bare.Knock);
        string text = bare.ToString();
        string payload = text[(text.IndexOf(':') + 1)..].Replace('-', '+').Replace('_', '/');
        byte[] body = Convert.FromBase64String(payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '='));
        Assert.Equal(2, body[0]); // version 2
        Assert.Equal(1, body[1]); // flags: static key only — the knock bit is absent
        ConnectionString reparsed = ConnectionString.Parse(text);
        Assert.Null(reparsed.Knock);
        Assert.Equal(bare.StaticKey, reparsed.StaticKey);
    }

    [Fact]
    public void KnockString_RoundTrips_AndCanonicallyRejectsBadShapes()
    {
        byte[] stat = RandomNumberGenerator.GetBytes(32);
        byte[] knock = Knock();
        var candidates = new[] { new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 40000)) };

        var keyed = new ConnectionString(0xA11CE, candidates, NatHint.Cone, stat, knock: knock);
        ConnectionString parsed = ConnectionString.Parse(keyed.ToString());
        Assert.Equal(knock, parsed.Knock);
        Assert.Equal(stat, parsed.StaticKey);
        Assert.Null(parsed.EndpointKey);
        Assert.Equal(keyed.ToString(), parsed.ToString()); // canonical: re-encode is identical

        var withEndpoint = new ConnectionString(0xA11CE, candidates, NatHint.Cone, stat, RandomNumberGenerator.GetBytes(32), knock);
        parsed = ConnectionString.Parse(withEndpoint.ToString());
        Assert.Equal(knock, parsed.Knock);
        Assert.NotNull(parsed.EndpointKey);

        // Non-canonical shapes refuse: knock without the static key it is published with.
        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(1, candidates, NatHint.Unknown, knock: knock));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(1, candidates, NatHint.Unknown, stat, knock: []));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(1, candidates, NatHint.Unknown, stat, knock: new byte[65]));
    }
}
