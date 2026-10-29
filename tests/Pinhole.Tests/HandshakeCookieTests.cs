using System.Buffers.Binary;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Pinhole.Core;
using Pinhole.Crypto;
using Xunit;

namespace Pinhole.Tests;

// R5 phase 2 armor: the mac2/cookie exchange. Under initiation load a responder stops
// answering PUNCs with PACK and demands a cookie bound to the PUNC's source address
// instead; a spoofed-source flood never sees the cookie it would have to echo, so it can
// extract neither PACK output nor key agreements nor connection state. These pin the wire
// shapes (111-byte PUNC, 30-byte COOKIE frame, marker 0x05, the MAC inputs), the
// two-epoch rotation window, the per-source and global load arms with their bounded
// table, the spoofed-flood behavior under load, the honest dialer completing the extra
// round trip on the SAME attempt, and the documented cost to a v3 dialer under load.
public sealed class HandshakeCookieTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    // TCP is disabled in these tests on purpose: a TCP arrival cannot spoof its source
    // (a three-way handshake completed), so the cookie gate exempts TCP by design — and
    // an exempt path must not rescue a dial that the UDP armor is busy proving something
    // about. The mac2 exchange itself is UDP-direct-only armor.
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
            // The last mac1 byte: just before the mac1 ext tail, or just before mac2's.
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

    // ------------------------------------------------------------------ the mac2/cookie codec

    [Fact]
    public void Mac2_IsKeyedBlake3OverTheWholeFrameMinusTheMac2_Mac1Untouched()
    {
        byte[] mac1Key = RandomNumberGenerator.GetBytes(32);
        byte[] cookie = RandomNumberGenerator.GetBytes(16);
        byte[] frame = V4Punc(0xA11CE_0002, 0x0BAD_C0DE, RandomNumberGenerator.GetBytes(32),
            RandomNumberGenerator.GetBytes(32), mac1Key, mac2Key: cookie);

        Assert.Equal(111, frame.Length); // 9 + PuncCryptoBodyV4Mac2, outside every v3/v4-mac1 length class
        Assert.Equal(CryptoWire.Mac2Marker, frame[^CryptoWire.Mac2ExtLength]);
        // Independent recomputation: keyed BLAKE3 (the 16-byte cookie zero-extended to
        // the 32-byte key size) over everything but the 16 mac2 bytes — which includes
        // mac1 and both markers.
        byte[] key32 = new byte[CryptoWire.CookieKeyLength];
        cookie.CopyTo(key32, 0);
        byte[] expected = Blake3.HashKeyed(key32, frame.AsSpan(0, frame.Length - CryptoWire.Mac2Length));
        Assert.Equal(expected[..16], frame[^CryptoWire.Mac2Length..].ToArray());

        Assert.True(CryptoWire.VerifyMac2(frame, cookie));
        Assert.False(CryptoWire.VerifyMac2(frame, RandomNumberGenerator.GetBytes(16)), "wrong cookie");
        frame[20] ^= 0x01;
        Assert.False(CryptoWire.VerifyMac2(frame, cookie), "edited body");
        frame[20] ^= 0x01;

        // mac1 still covers exactly the bytes it always did: the frame through the mac1
        // extension, with mac2 sliced off the view — and mac2's marker is what makes the
        // view; destroy it and mac2 stops parsing (a foreign marker is not a mac2).
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

        // Under load with no valid mac2: the ONLY effect is the COOKIE reply — the pin
        // mismatch, stale token, and mixed-mode checks never run, so nothing about the
        // responder's state leaks into the demand.
        HandshakeInput input = default;
        input.Kind = HandshakeInputKind.PuncBegin;
        input.CryptoBody = true;
        input.PinMatches = false;      // would be RejectPin without the load gate
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

        // mac2 verified (or not demanded): the normal path resumes — pin and keys sequenced.
        HandshakeState honest = HandshakeState.Create(0x1111_1111, offeredCrypto: true);
        input.PinMatches = true;
        input.CookieOk = true;
        n = HandshakeMachine.Step(ref honest, in input, new Tick(0), effects);
        Assert.Equal(HandshakeMachine.NeedKeys, effects[0].Value);

        // Not under load: a frame that carries mac2 without proving it is NOT punished —
        // mac2 is ignored entirely when the responder is not demanding it.
        HandshakeState calm = HandshakeState.Create(0x1111_1111, offeredCrypto: true);
        input.CookieRequired = false;
        input.CookieOk = false;
        n = HandshakeMachine.Step(ref calm, in input, new Tick(0), effects);
        Assert.Equal(HandshakeMachine.NeedKeys, effects[0].Value);

        // And the mac1 gate still comes first: a failed mac1 is silence even under load.
        HandshakeState forged = HandshakeState.Create(0x1111_1111, offeredCrypto: true);
        input.Mac1Ok = false;
        n = HandshakeMachine.Step(ref forged, in input, new Tick(0), effects);
        Assert.Equal(EffectKind.Notify, effects[0].Kind);
        Assert.Equal(HandshakeMachine.RejectMac1, effects[0].Value);
    }

    // ------------------------------------------------------------------ the jar and the load table

    [Fact]
    public void CookieJar_KeepsThePreviousEpoch_RefusesTwoAgo_AndBindsToTheSource()
    {
        long now = 5 * CookieArmor.EpochMs + 1_000; // mid epoch 5
        var armor = new CookieArmor(() => now);
        byte[] source = SourceKey(1);

        // Minted in epoch 5; valid in epoch 5 and epoch 6 (the previous secret), refused
        // in epoch 7 — pure epoch arithmetic, no clock sleeps.
        byte[] frame = Mac2Frame(armor, source);
        Assert.True(armor.VerifyMac2(frame, source));
        now += CookieArmor.EpochMs;
        Assert.True(armor.VerifyMac2(frame, source), "epoch N-1 cookie must stay valid in epoch N");
        now += CookieArmor.EpochMs;
        Assert.False(armor.VerifyMac2(frame, source), "epoch N-2 cookie must be refused");

        // The binding is the source address: a cookie minted for source A never
        // validates a frame from source B, in either live epoch.
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

        // A spoofed-source flood: every PUNC from a fresh address, so no per-source count
        // can ever trip — the GLOBAL arm must. Memory stays at the fixed bound while
        // thousands of unique sources cycle through the table.
        for (int i = 0; i < CookieArmor.GlobalThreshold; i++)
        {
            armor.NotePuncAndCheckLoad(SourceKey(0x1000 + i), now);
            Assert.True(armor.TrackedSources <= CookieArmor.MaxSources, "the source table must stay bounded");
        }

        Assert.True(armor.NotePuncAndCheckLoad(SourceKey(0x9999), now), "the global arm catches a fresh spoofed source");
        Assert.Equal(CookieArmor.MaxSources, armor.TrackedSources);

        // The window cools by arithmetic, not by sleeps: one window past the last counted
        // PUNC and the same source is admitted again (the honest-dialer escape).
        now += CookieArmor.LoadWindowMs + 1;
        Assert.False(armor.NotePuncAndCheckLoad(SourceKey(0x9999), now), "the load window expired");
    }

    // ------------------------------------------------------------------ the spoofed flood under load

    private const ulong FakePeer = 0xDEAD_BEEF_DEAD_BEEF;

    // Enough mac1-valid forgeries from one horde socket (one fake peer id, so at most
    // one pre-load stranger husk exists) to trip BOTH the per-source window (64) and the
    // global window (512), then waits until the global arm is provably hot: cookie
    // demands only pass GlobalThreshold once the horde is essentially fully processed,
    // well past the 512th counted PUNC. Ordering, not wall-clock, is the sync point.
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

    // Reads from sock until it goes quiet (first timeout) or the budget ends; classify
    // sees each datagram, the count of matching datagrams comes back.
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

        // mac1-VALID forgeries under the listener's real public key, one source: the
        // first threshold-many PUNCs are admitted by design (the gate arms ON the
        // threshold — PUNC #1's stranger husk and the retransmission PACKs are the
        // pre-load behavior), everything after earns only cookies.
        for (int i = 0; i < CookieArmor.PerSourceThreshold + 16; i++)
        {
            attacker.SendTo(V4Punc(FakePeer, 0x1234_5678, eph, stat, listenerKey), SocketFlags.None, listenerWire);
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => listener.Engine.CookieDemanded >= 8);

        // Flush the admission window's leftovers (PACKs to the first 63) so the burst
        // below starts from an empty receive buffer.
        Drain(attacker, static (_, _) => false, TimeSpan.FromMilliseconds(400));

        long agreements = listener.Engine.HandshakeKeyAgreements;
        long refused = listener.Engine.Mac1Refused;
        int conns = listener.Connections.Count;
        for (int i = 0; i < 32; i++)
        {
            attacker.SendTo(V4Punc(FakePeer, 0x1234_5678, eph, stat, listenerKey), SocketFlags.None, listenerWire);
        }

        // From the trip instant on, every reply is a 30-byte COOKIE frame — never a
        // PACK, never an HSCK, nothing sealed.
        int others = Drain(attacker, (buf, n) => !(n == CryptoWire.CookieFrameLength && buf[0] == 0x59),
            TimeSpan.FromMilliseconds(800));
        Assert.Equal(0, others);

        // Zero key agreements, zero refusals, zero new connection state during the burst.
        Assert.Equal(agreements, listener.Engine.HandshakeKeyAgreements);
        Assert.Equal(refused, listener.Engine.Mac1Refused);
        Assert.Equal(conns, listener.Connections.Count);

        // The global arm and the bounded table: a fresh-source horde (a spoofed-source
        // flood, where per-source counting structurally cannot trip) arms the global
        // window — its own admission window (the first PerSourceThreshold PUNCs,
        // admitted by design) may still agree keys, exactly like the first flood's did.
        await ArmGlobalLoadAsync(listener, listenerWire, listenerKey);
        Assert.True(listener.Engine.CookieLoadSources <= CookieArmor.MaxSources);
        Assert.Equal(conns, listener.Connections.Count);

        // From the armed instant on: a spoofed-source burst earns cookies only — zero
        // key agreements, zero stranger state, table still at its bound.
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

    // ------------------------------------------------------------------ the honest dialer under load

    [Fact]
    public async Task HonestDialerUnderLoad_CompletesOnTheSameAttempt_WithTheMac2RoundTrip()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        var listenerWire = new IPEndPoint(IPAddress.Loopback, listener.LocalPort);
        byte[] listenerKey = ConnectionString.Parse(listener.ConnectionString).StaticKey!;
        await ArmGlobalLoadAsync(listener, listenerWire, listenerKey);
        long agreementsBeforeDial = listener.Engine.HandshakeKeyAgreements;

        // The honest dial: PUNC -> COOKIE -> PUNC+mac2 -> PACK -> HSCK, all inside ONE
        // ConnectAsync — no re-dial, no v3 fallback (a COOKIE reply proves the responder
        // speaks v4; the fallback clock restarts at the cookie).
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts());
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);

        await TestPoll.UntilAsync(Timeout,
            () => listener.Connections.Any(l => l.PeerId == dialer.PeerId && l.IsEncrypted));
        PinholeConnection atListener = listener.Connections.First(l => l.PeerId == dialer.PeerId);

        // The dialer really did the mac2 round trip on this attempt.
        ConnState dialerState = dialer.Engine.Lookup(listener.PeerId)!;
        Assert.True(dialerState.PuncFrameV4);
        Assert.False(dialerState.PuncFrameDowngraded, "the cookie exchange must not bounce the dial into the v3 fallback");
        Assert.Equal(9 + CryptoWire.PuncCryptoBodyV4Mac2, dialerState.PuncFrame.Length);
        Assert.NotNull(dialerState.Cookie);

        // The responder demanded a cookie, accepted the echoed mac2, and agreed keys for
        // the honest dial only (the horde's post-trip PUNCs earned zero; retries may
        // legitimately re-answer while the handshake is in flight).
        Assert.True(listener.Engine.CookieAccepted >= 1, "the honest dialer's mac2 was accepted");
        Assert.True(listener.Engine.HandshakeKeyAgreements - agreementsBeforeDial >= 1,
            "the honest dial did agree keys");

        // Sealed traffic flows under the keys the exchange agreed.
        var gotAtListener = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var gotAtDialer = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atListener.Received += p => gotAtListener.TrySetResult(p.ToArray());
        conn.Received += p => gotAtDialer.TrySetResult(p.ToArray());
        conn.Send("through the cookie wall"u8);
        Assert.Equal("through the cookie wall"u8.ToArray(), await gotAtListener.Task.WaitAsync(Timeout));
        atListener.Send("and back"u8);
        Assert.Equal("and back"u8.ToArray(), await gotAtDialer.Task.WaitAsync(Timeout));
    }

    // ------------------------------------------------------------------ the v3 cost under load

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

        // A v3-only dialer cannot produce mac2, so under load it cannot complete — the
        // documented cost of the armor until the support window closes. The responder's
        // heaviest output to it is the 30-byte COOKIE reply: never a key agreement, never
        // a stranger husk, never a mac1 refusal (v3 passes that gate vacuously).
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts(connectTimeout: TimeSpan.FromSeconds(3)));
        dialer.Engine.LegacyHandshakeV3Only = true;
        await Assert.ThrowsAsync<TimeoutException>(() => dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout));

        Assert.True(listener.Engine.CookieDemanded > demanded, "the v3 PUNCs earned cookie demands");
        Assert.Equal(agreements, listener.Engine.HandshakeKeyAgreements); // never a key agreement
        Assert.Equal(conns, listener.Connections.Count);                  // never a stranger husk
        Assert.Equal(0, listener.Engine.Mac1Refused);
    }
}
