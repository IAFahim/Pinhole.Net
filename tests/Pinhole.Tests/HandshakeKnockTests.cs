using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Pinhole.Crypto;
using Xunit;

namespace Pinhole.Tests;

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

    [Fact]
    public void KnockMac1Key_IsTheLabeledBlake3DeriveKey_OverStaticPubAndKnock()
    {
        byte[] stat = RandomNumberGenerator.GetBytes(32);
        byte[] knock = Knock();
        Span<byte> key = stackalloc byte[32];
        CryptoWire.KnockMac1Key(key, stat, knock);

        byte[] material = [.. stat, .. knock];
        byte[] expected = Blake3.HashDeriveKey(CryptoWire.KnockMac1LabelBytes, material);
        Assert.Equal(expected, key.ToArray());

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

        Assert.Equal(withKnockLo.LoToHiKey, withKnockHi.LoToHiKey);
        Assert.Equal(withKnockLo.HiConfirm, withKnockHi.HiConfirm);

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

        byte[] ephPriv = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        NodeIdentity id = new(Convert.FromHexString("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"));
        (byte[] ephPriv2, byte[] ephPub2) = NodeIdentity.NewEphemeral();
        NodeIdentity id2 = new(Convert.FromHexString("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"));
        SessionKeys omitted = KeySchedule.Derive(1, ephPriv, id.ExportPrivateSeed(), 2, ephPub2, id2.PublicKey);
        SessionKeys empty = KeySchedule.Derive(1, ephPriv, id.ExportPrivateSeed(), 2, ephPub2, id2.PublicKey, default);
        Assert.Equal(omitted.LoToHiKey, empty.LoToHiKey);
        Assert.Equal(omitted.HiConfirm, empty.HiConfirm);
    }

    [Fact]
    public async Task KnockOptions_AreValidated_TooShortTooLongOrPlaintextRefuse()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PinholeNode.BindAsync(Opts(knock: new byte[7])));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PinholeNode.BindAsync(Opts(knock: new byte[65])));
        await Assert.ThrowsAsync<ArgumentException>(() => PinholeNode.BindAsync(Opts(knock: Knock()) with { Encryption = PinholeEncryption.Disabled }));

        await using PinholeNode short8 = await PinholeNode.BindAsync(Opts(knock: new byte[8]));
        await using PinholeNode long64 = await PinholeNode.BindAsync(Opts(knock: new byte[64]));
    }

    [Fact]
    public void KnocklessNode_ProducesTheSameStringShapeAsAlways()
    {

        var candidates = new[] { new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 40000)) };
        var bare = new ConnectionString(1, candidates, NatHint.Unknown, RandomNumberGenerator.GetBytes(32));
        Assert.Null(bare.Knock);
        string text = bare.ToString();
        string payload = text[(text.IndexOf(':') + 1)..].Replace('-', '+').Replace('_', '/');
        byte[] body = Convert.FromBase64String(payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '='));
        Assert.Equal(2, body[0]);
        Assert.Equal(1, body[1]);
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
        Assert.Equal(keyed.ToString(), parsed.ToString());

        var withEndpoint = new ConnectionString(0xA11CE, candidates, NatHint.Cone, stat, RandomNumberGenerator.GetBytes(32), knock);
        parsed = ConnectionString.Parse(withEndpoint.ToString());
        Assert.Equal(knock, parsed.Knock);
        Assert.NotNull(parsed.EndpointKey);

        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(1, candidates, NatHint.Unknown, knock: knock));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(1, candidates, NatHint.Unknown, stat, knock: []));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(1, candidates, NatHint.Unknown, stat, knock: new byte[65]));
    }

    private static byte[] V4Punc(ulong sender, uint token, ReadOnlySpan<byte> eph, ReadOnlySpan<byte> stat,
        ReadOnlySpan<byte> mac1Key, bool goodMac1 = true)
    {
        byte[] frame = new byte[9 + CryptoWire.PuncCryptoBodyV4];
        frame[0] = 0x50;
        BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(1), sender);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(9), token);
        eph.CopyTo(frame.AsSpan(13));
        stat.CopyTo(frame.AsSpan(45));
        CryptoWire.WriteMac1Ext(frame, mac1Key);
        if (!goodMac1)
        {
            frame[^1] ^= 0xFF;
        }

        return frame;
    }

    private static byte[] KnockMac1KeyBytes(byte[] staticPub, byte[] knock)
    {
        Span<byte> key = stackalloc byte[32];
        CryptoWire.KnockMac1Key(key, staticPub, knock);
        return key.ToArray();
    }

    [Fact]
    public async Task ScannerWithStaticPubOnly_EarnsTotalSilence_V4RefusedV3Ignored()
    {
        byte[] knock = Knock();
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts(knock));
        var listenerWire = new IPEndPoint(IPAddress.Loopback, listener.LocalPort);
        ConnectionString cs = ConnectionString.Parse(listener.ConnectionString);
        byte[] listenerKey = cs.StaticKey!;

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        byte[] wrongKnockKey = KnockMac1KeyBytes(listenerKey, Knock());
        const int perShape = 8;
        for (int i = 0; i < perShape; i++)
        {
            attacker.SendTo(V4Punc(0x5CA11_0000 + (ulong)i, 0x1234_5678, RandomNumberGenerator.GetBytes(32),
                RandomNumberGenerator.GetBytes(32), listenerKey), SocketFlags.None, listenerWire);
            attacker.SendTo(V4Punc(0x5CA22_0000 + (ulong)i, 0x1234_5679, RandomNumberGenerator.GetBytes(32),
                RandomNumberGenerator.GetBytes(32), wrongKnockKey), SocketFlags.None, listenerWire);
            byte[] v3Crypto = V4Punc(0x5CA33_0000 + (ulong)i, 0x1234_567A, RandomNumberGenerator.GetBytes(32),
                RandomNumberGenerator.GetBytes(32), listenerKey)[..(9 + CryptoWire.PuncCryptoBody)];
            attacker.SendTo(v3Crypto, SocketFlags.None, listenerWire);
            byte[] v3Legacy = new byte[9 + CryptoWire.PuncLegacyBody];
            v3Legacy[0] = 0x50;
            BinaryPrimitives.WriteUInt64LittleEndian(v3Legacy.AsSpan(1), 0x5CA44_0000 + (ulong)i);
            BinaryPrimitives.WriteUInt32LittleEndian(v3Legacy.AsSpan(9), 0x1234_567B);
            attacker.SendTo(v3Legacy, SocketFlags.None, listenerWire);
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => listener.Engine.Mac1Refused >= 2 * perShape);
        Assert.Equal(2 * perShape, listener.Engine.Mac1Refused);
        Assert.Equal(0, listener.Engine.HandshakeKeyAgreements);
        Assert.Empty(listener.Connections);
        Assert.True(listener.Engine.CookieDemanded == 0, "ignored v3 shapes never even arm the cookie gate");

        Assert.False(attacker.Poll(500_000, SelectMode.SelectRead), "responder emitted bytes to a knock-less scanner");
    }

    [Fact]
    public async Task KnockHolderDialsKnockResponder_SealsEndToEnd()
    {
        byte[] knock = Knock();
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts(knock));

        ConnectionString cs = ConnectionString.Parse(listener.ConnectionString);
        Assert.Equal(knock, cs.Knock);
        Assert.NotNull(cs.StaticKey);

        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts());
        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        PinholeConnection atListener = await accept.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);

        ConnState state = dialer.Engine.Lookup(listener.PeerId)!;
        Assert.True(state.PuncFrameV4);
        Assert.False(state.PuncFrameDowngraded, "a knock dial never falls back to unversioned retries");
        Assert.True(CryptoWire.VerifyMac1(state.PuncFrame, KnockMac1KeyBytes(cs.StaticKey!, knock)), "the PUNC's mac1 is knock-keyed");
        Assert.False(CryptoWire.VerifyMac1(state.PuncFrame, cs.StaticKey!), "the raw static pub must not verify");

        var gotAtListener = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var gotAtDialer = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atListener.Received += p => gotAtListener.TrySetResult(p.ToArray());
        conn.Received += p => gotAtDialer.TrySetResult(p.ToArray());
        conn.Send("knock knock"u8);
        Assert.Equal("knock knock"u8.ToArray(), await gotAtListener.Task.WaitAsync(Timeout));
        atListener.Send("who's there"u8);
        Assert.Equal("who's there"u8.ToArray(), await gotAtDialer.Task.WaitAsync(Timeout));
        Assert.Equal(0, listener.Engine.Mac1Refused);
    }

    [Fact]
    public async Task WrongKnockDialer_TimesOut_ResponderCountsOnlyTheRefusals()
    {
        byte[] knock = Knock();
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts(knock));
        ConnectionString real = ConnectionString.Parse(listener.ConnectionString);

        var wrongString = new ConnectionString(real.PeerId, real.Candidates, real.NatHint, real.StaticKey, real.EndpointKey, Knock());
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts(connectTimeout: TimeSpan.FromSeconds(3)));
        await Assert.ThrowsAsync<TimeoutException>(() => dialer.ConnectAsync(wrongString.ToString()).WaitAsync(Timeout));

        Assert.True(listener.Engine.Mac1Refused >= 1, "the wrong-knock PUNCs were refused");
        Assert.Equal(0, listener.Engine.HandshakeKeyAgreements);
        Assert.Empty(listener.Connections);
    }

    [Fact]
    public async Task KnocklessImpostor_CannotCompleteAKnockDial_BothPackShapesRefused()
    {

        byte[] knock = Knock();
        await using PinholeNode target = await PinholeNode.BindAsync(Opts(knock));
        ConnectionString real = ConnectionString.Parse(target.ConnectionString);

        using var impostor = new KnockImpostor(real.PeerId, real.StaticKey!);
        var impostorString = new ConnectionString(real.PeerId,
            [new PinholeCandidate(CandidateKind.Direct, impostor.Ep)], real.NatHint, real.StaticKey, real.EndpointKey, knock);

        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts(connectTimeout: TimeSpan.FromSeconds(4)));
        Task dial = dialer.ConnectAsync(impostorString.ToString());

        byte[] punc = await impostor.AwaitV4PuncAsync(dialer.PeerId);
        uint dialerToken = BinaryPrimitives.ReadUInt32LittleEndian(punc.AsSpan(9));
        impostor.Derive(dialer.PeerId, punc.AsSpan(13, 32), punc.AsSpan(45, 32));
        await impostor.SendRawKeyedPackAsync(dialerToken);
        await impostor.SendTruncatedPackAsync(dialerToken);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => dialer.Engine.Mac1Refused >= 2);

        await Assert.ThrowsAsync<TimeoutException>(() => dial.WaitAsync(Timeout));
        Assert.Equal(0, dialer.Engine.HandshakeKeyAgreements);
    }

    [Fact]
    public async Task V3DialerAgainstKnockResponder_IsIgnored_NotEvenCookied()
    {

        byte[] knock = Knock();
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts(knock));
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts(connectTimeout: TimeSpan.FromSeconds(3)));
        dialer.Engine.LegacyHandshakeV3Only = true;

        await Assert.ThrowsAsync<TimeoutException>(() => dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout));

        Assert.Equal(0, listener.Engine.Mac1Refused);
        Assert.Equal(0, listener.Engine.CookieDemanded);
        Assert.Equal(0, listener.Engine.HandshakeKeyAgreements);
        Assert.Empty(listener.Connections);
    }

    [Fact]
    public async Task KnockResponder_DialsV3OnlyPeer_StillCompletes()
    {

        byte[] knock = Knock();
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts(knock));
        await using PinholeNode peer = await PinholeNode.BindAsync(Opts());
        peer.Engine.LegacyHandshakeV3Only = true;

        Task<PinholeConnection> accept = peer.AcceptAsync();
        PinholeConnection conn = await listener.ConnectAsync(peer.ConnectionString).WaitAsync(Timeout);
        PinholeConnection atPeer = await accept.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.Received += p => got.TrySetResult(p.ToArray());
        atPeer.Send("outbound window intact"u8);
        Assert.Equal("outbound window intact"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task KnockDialerUnderCookieLoad_CompletesWithTheMac2RoundTrip()
    {

        byte[] knock = Knock();
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts(knock));
        var listenerWire = new IPEndPoint(IPAddress.Loopback, listener.LocalPort);
        ConnectionString cs = ConnectionString.Parse(listener.ConnectionString);
        byte[] knockKey = KnockMac1KeyBytes(cs.StaticKey!, knock);

        using (var stranger = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            stranger.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            byte[] eph = RandomNumberGenerator.GetBytes(32);
            byte[] stat = RandomNumberGenerator.GetBytes(32);
            for (int i = 0; i < CookieArmor.GlobalThreshold + 64; i++)
            {
                stranger.SendTo(V4Punc(0xF100D_0001, 0x1234_5678, eph, stat, cs.StaticKey!), SocketFlags.None, listenerWire);
            }
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3),
            () => listener.Engine.Mac1Refused >= CookieArmor.GlobalThreshold + 64);
        Assert.Equal(0, listener.Engine.CookieDemanded);
        Assert.Equal(0, listener.Engine.CookieLoadSources);

        using (var horde = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            horde.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            byte[] eph = RandomNumberGenerator.GetBytes(32);
            byte[] stat = RandomNumberGenerator.GetBytes(32);
            for (int i = 0; i < CookieArmor.GlobalThreshold + 2 * CookieArmor.PerSourceThreshold + 32; i++)
            {
                horde.SendTo(V4Punc(0xDEAD_BEEF_DEAD_BEEF, 0x77AA_5500, eph, stat, knockKey), SocketFlags.None, listenerWire);
            }

            await TestPoll.UntilAsync(TimeSpan.FromSeconds(3),
                () => listener.Engine.CookieDemanded >= CookieArmor.GlobalThreshold + 8);
        }

        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts());
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);
        ConnState dialerState = dialer.Engine.Lookup(listener.PeerId)!;
        Assert.Equal(9 + CryptoWire.PuncCryptoBodyV4Mac2, dialerState.PuncFrame.Length);
        Assert.True(listener.Engine.CookieAccepted >= 1, "the knock dialer's mac2 was accepted");
        Assert.True(listener.Engine.HandshakeKeyAgreements >= 1);

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.Received += p => got.TrySetResult(p.ToArray());
        listener.Connections.First(l => l.PeerId == dialer.PeerId).Send("through the knock wall"u8);
        Assert.Equal("through the knock wall"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    private sealed class KnockOracle : IDisposable
    {
        public readonly Socket Sock = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        public readonly ulong PeerId = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        public readonly NodeIdentity Identity = new();
        public readonly byte[] Knock;
        public const uint Token = 0x1357_9BDF;
        private ConnectionCrypto? _crypto;
        private IPEndPoint? _node;

        public KnockOracle(byte[] knock)
        {
            Knock = knock;
            Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        }

        public IPEndPoint Ep => (IPEndPoint)Sock.LocalEndPoint!;

        public ConnectionString StringPointingAt(IPEndPoint ep) => new(
            PeerId, [new PinholeCandidate(CandidateKind.Direct, ep)], NatHint.Unknown, Identity.PublicKey, knock: Knock);

        public async Task<byte[]> AwaitV4PuncAsync(ulong nodePeerId)
        {
            byte[] buf = new byte[2048];
            EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            using var deadline = new CancellationTokenSource(Timeout);
            while (true)
            {
                SocketReceiveFromResult r = await Sock.ReceiveFromAsync(buf, any, deadline.Token);
                if (r.ReceivedBytes == 9 + CryptoWire.PuncCryptoBodyV4 && buf[0] == 0x50
                    && BinaryPrimitives.ReadUInt64LittleEndian(buf.AsSpan(1)) == nodePeerId)
                {
                    _node = (IPEndPoint)r.RemoteEndPoint!;
                    return buf[..r.ReceivedBytes];
                }
            }
        }

        public bool TryPeerKeys(ulong nodePeerId, ReadOnlySpan<byte> eph, ReadOnlySpan<byte> stat)
        {
            _crypto ??= ConnectionCrypto.New(Identity, PeerId, nodePeerId, Knock);
            return _crypto.TryPeerKeys(eph, stat);
        }

        public async Task SendSealedFrameAsync(byte type, byte[] body)
        {
            var f = new byte[9 + 4 + CryptoWire.SealedOverhead + body.Length];
            f[0] = type;
            BinaryPrimitives.WriteUInt64LittleEndian(f.AsSpan(1), PeerId);
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(9), Token);
            _crypto!.Send!.Seal(f.AsSpan(13), f.AsSpan(0, 13), body);
            await Sock.SendToAsync(f, _node!);
        }

        public async Task SendPackAsync(uint dialerToken)
        {
            byte[] pack = new byte[9 + CryptoWire.PackCryptoBodyV4];
            pack[0] = 0x51;
            BinaryPrimitives.WriteUInt64LittleEndian(pack.AsSpan(1), PeerId);
            BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(9), dialerToken);
            BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(13), Token);
            _crypto!.MyEphPublic.CopyTo(pack, 17);
            _crypto.MyStaticPublic.CopyTo(pack, 49);
            _crypto.MyConfirm().CopyTo(pack, 81);
            CryptoWire.WriteMac1Ext(pack, KnockMac1KeyBytes(Identity.PublicKey, Knock));
            await Sock.SendToAsync(pack, _node!);
        }

        public void Dispose() => Sock.Dispose();
    }

    [Fact]
    public async Task V4PuncTowardAKnockResponder_VerifiesUnderTheKnockKey_OracleHandshakeSeals()
    {

        byte[] knock = Knock();
        using var oracle = new KnockOracle(knock);
        await using PinholeNode node = await PinholeNode.BindAsync(Opts());

        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString());
        byte[] punc = await oracle.AwaitV4PuncAsync(node.PeerId);

        Assert.Equal(9 + CryptoWire.PuncCryptoBodyV4, punc.Length);
        Assert.Equal(CryptoWire.HandshakeV4Marker, punc[^CryptoWire.Mac1ExtLength]);
        Assert.True(CryptoWire.VerifyMac1(punc, KnockMac1KeyBytes(oracle.Identity.PublicKey, knock)));
        Assert.False(CryptoWire.VerifyMac1(punc, oracle.Identity.PublicKey), "raw-static mac1 must not verify under knock");

        uint dialerToken = BinaryPrimitives.ReadUInt32LittleEndian(punc.AsSpan(9));
        Assert.True(oracle.TryPeerKeys(node.PeerId, punc.AsSpan(13, 32), punc.AsSpan(45, 32)));
        await oracle.SendPackAsync(dialerToken);
        await oracle.SendSealedFrameAsync(0x53, new byte[8]);
        PinholeConnection conn = await dial.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);
        Assert.Equal(0, node.Engine.Mac1Refused);
    }

    private sealed class KnockImpostor : IDisposable
    {
        public readonly Socket Sock = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        private readonly ulong _targetPeerId;
        private readonly byte[] _targetStatic;
        private readonly byte[] _ephPriv = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _staticPriv = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _ephPub = new byte[32];
        private SessionKeys? _keys;
        private ulong _dialerPeerId;
        private IPEndPoint? _dialer;

        public KnockImpostor(ulong targetPeerId, byte[] targetStatic)
        {
            _targetPeerId = targetPeerId;
            _targetStatic = targetStatic;
            _ephPub = new X25519PrivateKeyParameters(_ephPriv, 0).GeneratePublicKey().GetEncoded();
            Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        }

        public IPEndPoint Ep => (IPEndPoint)Sock.LocalEndPoint!;

        public async Task<byte[]> AwaitV4PuncAsync(ulong dialerPeerId)
        {
            byte[] buf = new byte[2048];
            EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            using var deadline = new CancellationTokenSource(Timeout);
            while (true)
            {
                SocketReceiveFromResult r = await Sock.ReceiveFromAsync(buf, any, deadline.Token);
                if (r.ReceivedBytes == 9 + CryptoWire.PuncCryptoBodyV4 && buf[0] == 0x50
                    && BinaryPrimitives.ReadUInt64LittleEndian(buf.AsSpan(1)) == dialerPeerId)
                {
                    _dialer = (IPEndPoint)r.RemoteEndPoint!;
                    return buf[..r.ReceivedBytes];
                }
            }
        }

        public void Derive(ulong dialerPeerId, ReadOnlySpan<byte> dialerEph, ReadOnlySpan<byte> dialerStatic)
        {

            _dialerPeerId = dialerPeerId;
            _keys = KeySchedule.Derive(_targetPeerId, _ephPriv, _staticPriv, dialerPeerId, dialerEph, dialerStatic);
        }

        public async Task SendRawKeyedPackAsync(uint dialerToken)
        {
            byte[] pack = Pack(dialerToken, v4: true);
            CryptoWire.WriteMac1Ext(pack, _targetStatic);
            await Sock.SendToAsync(pack, _dialer!);
        }

        public async Task SendTruncatedPackAsync(uint dialerToken)
        {
            byte[] pack = Pack(dialerToken, v4: false);
            await Sock.SendToAsync(pack, _dialer!);
        }

        private byte[] Pack(uint dialerToken, bool v4)
        {
            byte[] pack = new byte[9 + CryptoWire.PackCryptoBody + (v4 ? CryptoWire.Mac1ExtLength : 0)];
            pack[0] = 0x51;
            BinaryPrimitives.WriteUInt64LittleEndian(pack.AsSpan(1), _targetPeerId);
            BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(9), dialerToken);
            BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(13), 0x0BAD_F00D);
            _ephPub.CopyTo(pack, 17);
            _targetStatic.CopyTo(pack, 49);

            SessionKeys keys = _keys!;
            (_targetPeerId < _dialerPeerId ? keys.LoConfirm : keys.HiConfirm).CopyTo(pack, 81);
            return pack;
        }

        public void Dispose() => Sock.Dispose();
    }
}
