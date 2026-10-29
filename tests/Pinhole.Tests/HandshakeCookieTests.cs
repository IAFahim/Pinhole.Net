using System.Buffers.Binary;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Pinhole.Core;
using Pinhole.Crypto;
using Xunit;

namespace Pinhole.Tests;

public sealed class HandshakeCookieTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Opts(TimeSpan? connectTimeout = null) => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [], DerpRelayUrls = [],
        Listen = true,
        ConnectTimeout = connectTimeout ?? TimeSpan.FromSeconds(8),
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false, EnablePortMapping = false,
        EnableTcpTransport = false,
    };

    private static byte[] V4Punc(ulong sender, uint token, ReadOnlySpan<byte> eph, ReadOnlySpan<byte> stat,
        ReadOnlySpan<byte> mac1Key, bool goodMac1 = true, ReadOnlySpan<byte> mac2Key = default)
    {
        bool mac2 = !mac2Key.IsEmpty;
        byte[] frame = new byte[9 + CryptoWire.PuncCryptoBodyV4 + (mac2 ? CryptoWire.Mac2ExtLength : 0)];
        frame[0] = 0x50;
        BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(1), sender);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(9), token);
        eph.CopyTo(frame.AsSpan(13));
        stat.CopyTo(frame.AsSpan(45));
        if (mac2)
        {
            CryptoWire.WriteMac1Ext(frame.AsSpan()[..^CryptoWire.Mac2ExtLength], mac1Key);
            CryptoWire.WriteMac2Ext(frame, mac2Key);
        }
        else
        {
            CryptoWire.WriteMac1Ext(frame, mac1Key);
        }

        if (!goodMac1)
        {

            frame[frame.Length - (mac2 ? CryptoWire.Mac2ExtLength + CryptoWire.Mac1Length : CryptoWire.Mac1Length)] ^= 0xFF;
        }

        return frame;
    }

    private static byte[] SourceKey(int tag) => [0xAA, 0xBB, (byte)(tag >> 8), (byte)tag];

    private static byte[] Mac2Frame(CookieArmor armor, ReadOnlySpan<byte> sourceKey)
    {
        Span<byte> cookie = stackalloc byte[CryptoWire.CookieLength];
        armor.Mint(cookie, sourceKey);
        return V4Punc(0xF100D_0001, 0x0C0C_0C0C, RandomNumberGenerator.GetBytes(32),
            RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), mac2Key: cookie.ToArray());
    }

    [Fact]
    public void Mac2_IsKeyedBlake3OverTheWholeFrameMinusTheMac2_Mac1Untouched()
    {
        byte[] mac1Key = RandomNumberGenerator.GetBytes(32);
        byte[] cookie = RandomNumberGenerator.GetBytes(16);
        byte[] frame = V4Punc(0xA11CE_0002, 0x0BAD_C0DE, RandomNumberGenerator.GetBytes(32),
            RandomNumberGenerator.GetBytes(32), mac1Key, mac2Key: cookie);

        Assert.Equal(111, frame.Length);
        Assert.Equal(CryptoWire.Mac2Marker, frame[^CryptoWire.Mac2ExtLength]);

        byte[] key32 = new byte[CryptoWire.CookieKeyLength];
        cookie.CopyTo(key32, 0);
        byte[] expected = Blake3.HashKeyed(key32, frame.AsSpan(0, frame.Length - CryptoWire.Mac2Length));
        Assert.Equal(expected[..16], frame[^CryptoWire.Mac2Length..].ToArray());

        Assert.True(CryptoWire.VerifyMac2(frame, cookie));
        Assert.False(CryptoWire.VerifyMac2(frame, RandomNumberGenerator.GetBytes(16)), "wrong cookie");
        frame[20] ^= 0x01;
        Assert.False(CryptoWire.VerifyMac2(frame, cookie), "edited body");
        frame[20] ^= 0x01;

        Assert.True(CryptoWire.HasMac2(frame));
        Assert.False(CryptoWire.HasMac2(V4Punc(1, 2, new byte[32], new byte[32], mac1Key)));
        Assert.False(CryptoWire.VerifyMac2(V4Punc(1, 2, new byte[32], new byte[32], mac1Key), cookie));
        Assert.Equal(9 + CryptoWire.PuncCryptoBodyV4, CryptoWire.Mac1View(frame).Length);
        Assert.True(CryptoWire.VerifyMac1(CryptoWire.Mac1View(frame), mac1Key));
        frame[^CryptoWire.Mac2ExtLength] = 0x03;
        Assert.False(CryptoWire.HasMac2(frame));
        Assert.False(CryptoWire.VerifyMac2(frame, cookie), "foreign marker");
    }

    [Fact]
    public void MachineCookieGate_RepliesCookieBeforeEveryOtherCheck_AndIgnoresMac2WhenNotLoaded()
    {
        HandshakeState s = HandshakeState.Create(0x1111_1111, offeredCrypto: true);
        Effect[] effects = new Effect[2];

        HandshakeInput input = default;
        input.Kind = HandshakeInputKind.PuncBegin;
        input.CryptoBody = true;
        input.PinMatches = false;
        input.Mac1Present = true;
        input.Mac1Ok = true;
        input.CookieRequired = true;
        input.CookieOk = false;
        input.FrameToken = 0x2222_2222;
        int n = HandshakeMachine.Step(ref s, in input, new Tick(0), effects);
        Assert.Single(effects[..n]);
        Assert.Equal(EffectKind.Transmit, effects[0].Kind);
        Assert.Equal(HandshakeMachine.ReplyCookie, effects[0].Value);
        Assert.False(s.RemoteTokenKnown, "the cookie demand latched no token");

        HandshakeState honest = HandshakeState.Create(0x1111_1111, offeredCrypto: true);
        input.PinMatches = true;
        input.CookieOk = true;
        n = HandshakeMachine.Step(ref honest, in input, new Tick(0), effects);
        Assert.Equal(HandshakeMachine.NeedKeys, effects[0].Value);

        HandshakeState calm = HandshakeState.Create(0x1111_1111, offeredCrypto: true);
        input.CookieRequired = false;
        input.CookieOk = false;
        n = HandshakeMachine.Step(ref calm, in input, new Tick(0), effects);
        Assert.Equal(HandshakeMachine.NeedKeys, effects[0].Value);

        HandshakeState forged = HandshakeState.Create(0x1111_1111, offeredCrypto: true);
        input.Mac1Ok = false;
        n = HandshakeMachine.Step(ref forged, in input, new Tick(0), effects);
        Assert.Equal(EffectKind.Notify, effects[0].Kind);
        Assert.Equal(HandshakeMachine.RejectMac1, effects[0].Value);
    }

    [Fact]
    public void CookieJar_KeepsThePreviousEpoch_RefusesTwoAgo_AndBindsToTheSource()
    {
        long now = 5 * CookieArmor.EpochMs + 1_000;
        var armor = new CookieArmor(() => now);
        byte[] source = SourceKey(1);

        byte[] frame = Mac2Frame(armor, source);
        Assert.True(armor.VerifyMac2(frame, source));
        now += CookieArmor.EpochMs;
        Assert.True(armor.VerifyMac2(frame, source), "epoch N-1 cookie must stay valid in epoch N");
        now += CookieArmor.EpochMs;
        Assert.False(armor.VerifyMac2(frame, source), "epoch N-2 cookie must be refused");

        long later = 20 * CookieArmor.EpochMs;
        var fresh = new CookieArmor(() => later);
        byte[] forA = Mac2Frame(fresh, SourceKey(1));
        Assert.False(fresh.VerifyMac2(forA, SourceKey(2)), "foreign-source cookie");
        Assert.True(fresh.VerifyMac2(forA, SourceKey(1)));
    }

    [Fact]
    public void LoadTable_ArmsPerSourceAt64_AndGloballyForSpoofedUniqueSources_MemoryStaysBounded()
    {
        long now = 1_000_000;
        var armor = new CookieArmor(() => now);
        byte[] source = SourceKey(7);

        for (int i = 0; i < CookieArmor.PerSourceThreshold - 1; i++)
        {
            Assert.False(armor.NotePuncAndCheckLoad(source, now), "below the per-source threshold");
        }

        Assert.True(armor.NotePuncAndCheckLoad(source, now), "the threshold-crossing PUNC trips for itself");
        Assert.Equal(1, armor.TrackedSources);

        for (int i = 0; i < CookieArmor.GlobalThreshold; i++)
        {
            armor.NotePuncAndCheckLoad(SourceKey(0x1000 + i), now);
            Assert.True(armor.TrackedSources <= CookieArmor.MaxSources, "the source table must stay bounded");
        }

        Assert.True(armor.NotePuncAndCheckLoad(SourceKey(0x9999), now), "the global arm catches a fresh spoofed source");
        Assert.Equal(CookieArmor.MaxSources, armor.TrackedSources);

        now += CookieArmor.LoadWindowMs + 1;
        Assert.False(armor.NotePuncAndCheckLoad(SourceKey(0x9999), now), "the load window expired");
    }

    private const ulong FakePeer = 0xDEAD_BEEF_DEAD_BEEF;

    private static async Task ArmGlobalLoadAsync(PinholeNode listener, IPEndPoint listenerWire, byte[] listenerKey)
    {
        using var horde = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        horde.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        byte[] eph = RandomNumberGenerator.GetBytes(32);
        byte[] stat = RandomNumberGenerator.GetBytes(32);
        int hordeCount = CookieArmor.GlobalThreshold + 2 * CookieArmor.PerSourceThreshold + 32;
        for (int i = 0; i < hordeCount; i++)
        {
            horde.SendTo(V4Punc(FakePeer, 0x1234_5678, eph, stat, listenerKey), SocketFlags.None, listenerWire);
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3),
            () => listener.Engine.CookieDemanded >= CookieArmor.GlobalThreshold + 8);
    }

    private static int Drain(Socket sock, Func<byte[], int, bool> classify, TimeSpan budget)
    {
        byte[] buf = new byte[2048];
        EndPoint any = new IPEndPoint(IPAddress.Any, 0);
        int matches = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        sock.ReceiveTimeout = 100;
        while (sw.Elapsed < budget)
        {
            int n;
            try
            {
                n = sock.ReceiveFrom(buf, ref any);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
            {
                break;
            }

            if (classify(buf, n))
            {
                matches++;
            }
        }

        return matches;
    }

    [Fact]
    public async Task SpoofedSourceFloodUnderLoad_EarnsOnlyCookieReplies_ZeroPacksZeroStateZeroAgreements()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        var listenerWire = new IPEndPoint(IPAddress.Loopback, listener.LocalPort);
        byte[] listenerKey = ConnectionString.Parse(listener.ConnectionString).StaticKey!;

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        byte[] eph = RandomNumberGenerator.GetBytes(32);
        byte[] stat = RandomNumberGenerator.GetBytes(32);

        for (int i = 0; i < CookieArmor.PerSourceThreshold + 16; i++)
        {
            attacker.SendTo(V4Punc(FakePeer, 0x1234_5678, eph, stat, listenerKey), SocketFlags.None, listenerWire);
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => listener.Engine.CookieDemanded >= 8);

        Drain(attacker, static (_, _) => false, TimeSpan.FromMilliseconds(400));

        long agreements = listener.Engine.HandshakeKeyAgreements;
        long refused = listener.Engine.Mac1Refused;
        int conns = listener.Connections.Count;
        for (int i = 0; i < 32; i++)
        {
            attacker.SendTo(V4Punc(FakePeer, 0x1234_5678, eph, stat, listenerKey), SocketFlags.None, listenerWire);
        }

        int others = Drain(attacker, (buf, n) => !(n == CryptoWire.CookieFrameLength && buf[0] == 0x59),
            TimeSpan.FromMilliseconds(800));
        Assert.Equal(0, others);

        Assert.Equal(agreements, listener.Engine.HandshakeKeyAgreements);
        Assert.Equal(refused, listener.Engine.Mac1Refused);
        Assert.Equal(conns, listener.Connections.Count);

        await ArmGlobalLoadAsync(listener, listenerWire, listenerKey);
        Assert.True(listener.Engine.CookieLoadSources <= CookieArmor.MaxSources);
        Assert.Equal(conns, listener.Connections.Count);

        long armed = listener.Engine.HandshakeKeyAgreements;
        long demanded = listener.Engine.CookieDemanded;
        using var spoofed = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        spoofed.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        for (int i = 0; i < 32; i++)
        {
            spoofed.SendTo(V4Punc(FakePeer, 0x77AA_5500, eph, stat, listenerKey), SocketFlags.None, listenerWire);
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => listener.Engine.CookieDemanded >= demanded + 32);
        Assert.Equal(armed, listener.Engine.HandshakeKeyAgreements);
        Assert.Equal(conns, listener.Connections.Count);
        Assert.True(listener.Engine.CookieLoadSources <= CookieArmor.MaxSources);
    }

    [Fact]
    public async Task HonestDialerUnderLoad_CompletesOnTheSameAttempt_WithTheMac2RoundTrip()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        var listenerWire = new IPEndPoint(IPAddress.Loopback, listener.LocalPort);
        byte[] listenerKey = ConnectionString.Parse(listener.ConnectionString).StaticKey!;
        await ArmGlobalLoadAsync(listener, listenerWire, listenerKey);
        long agreementsBeforeDial = listener.Engine.HandshakeKeyAgreements;

        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts());
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);

        await TestPoll.UntilAsync(Timeout,
            () => listener.Connections.Any(l => l.PeerId == dialer.PeerId && l.IsEncrypted));
        PinholeConnection atListener = listener.Connections.First(l => l.PeerId == dialer.PeerId);

        ConnState dialerState = dialer.Engine.Lookup(listener.PeerId)!;
        Assert.True(dialerState.PuncFrameV4);
        Assert.False(dialerState.PuncFrameDowngraded, "the cookie exchange must not bounce the dial into the v3 fallback");
        Assert.Equal(9 + CryptoWire.PuncCryptoBodyV4Mac2, dialerState.PuncFrame.Length);
        Assert.NotNull(dialerState.Cookie);

        Assert.True(listener.Engine.CookieAccepted >= 1, "the honest dialer's mac2 was accepted");
        Assert.True(listener.Engine.HandshakeKeyAgreements - agreementsBeforeDial >= 1,
            "the honest dial did agree keys");

        var gotAtListener = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var gotAtDialer = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atListener.Received += p => gotAtListener.TrySetResult(p.ToArray());
        conn.Received += p => gotAtDialer.TrySetResult(p.ToArray());
        conn.Send("through the cookie wall"u8);
        Assert.Equal("through the cookie wall"u8.ToArray(), await gotAtListener.Task.WaitAsync(Timeout));
        atListener.Send("and back"u8);
        Assert.Equal("and back"u8.ToArray(), await gotAtDialer.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task V3Dialer_V4ResponderUnderLoad_GetsOnlyCookieReplies_AndCannotComplete()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        var listenerWire = new IPEndPoint(IPAddress.Loopback, listener.LocalPort);
        byte[] listenerKey = ConnectionString.Parse(listener.ConnectionString).StaticKey!;
        await ArmGlobalLoadAsync(listener, listenerWire, listenerKey);
        long agreements = listener.Engine.HandshakeKeyAgreements;
        long demanded = listener.Engine.CookieDemanded;
        int conns = listener.Connections.Count;

        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts(connectTimeout: TimeSpan.FromSeconds(3)));
        dialer.Engine.LegacyHandshakeV3Only = true;
        await Assert.ThrowsAsync<TimeoutException>(() => dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout));

        Assert.True(listener.Engine.CookieDemanded > demanded, "the v3 PUNCs earned cookie demands");
        Assert.Equal(agreements, listener.Engine.HandshakeKeyAgreements);
        Assert.Equal(conns, listener.Connections.Count);
        Assert.Equal(0, listener.Engine.Mac1Refused);
    }
}
