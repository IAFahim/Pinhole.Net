using System.Buffers.Binary;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Pinhole.Core;
using Pinhole.Crypto;
using Xunit;

namespace Pinhole.Tests;

public sealed class HandshakeRendezvousTests
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
        ReadOnlySpan<byte> mac1Key)
    {
        byte[] frame = new byte[9 + CryptoWire.PuncCryptoBodyV4];
        frame[0] = 0x50;
        BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(1), sender);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(9), token);
        eph.CopyTo(frame.AsSpan(13));
        stat.CopyTo(frame.AsSpan(45));
        CryptoWire.WriteMac1Ext(frame, mac1Key);
        return frame;
    }

    private static byte[] V3Punc(ulong sender, uint token)
    {
        byte[] frame = new byte[9 + CryptoWire.PuncCryptoBody];
        frame[0] = 0x50;
        BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(1), sender);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(9), token);
        RandomNumberGenerator.GetBytes(32).CopyTo(frame.AsSpan(13));
        RandomNumberGenerator.GetBytes(32).CopyTo(frame.AsSpan(45));
        return frame;
    }

    private const ulong FakePeer = 0xDEAD_BEEF_DEAD_BEEF;

    [Fact]
    public void StrangerLedger_AdminsThreePerWindow_RollsWithTheWindow_AndResetsOnValidation()
    {
        long now = 500_000;
        var ledger = new StrangerLedger(() => now);
        byte[] source = [0x11, 0x22, 0x33, 0x44];

        Assert.True(ledger.TryCharge(source, now, token: 0x100));
        Assert.True(ledger.TryCharge(source, now, token: 0x200));
        Assert.True(ledger.TryCharge(source, now, token: 0x300));
        Assert.False(ledger.TryCharge(source, now, token: 0x400), "the fourth priced reply inside one window must be refused");
        Assert.False(ledger.TryCharge(source, now + StrangerLedger.WindowMs - 1, token: 0x500), "the window has not rolled");

        now += StrangerLedger.WindowMs + 1;
        Assert.True(ledger.TryCharge(source, now, token: 0x600), "a rolled window admits again");
        Assert.True(ledger.TryCharge(source, now, token: 0x700));
        Assert.True(ledger.TryCharge(source, now, token: 0x800));
        Assert.False(ledger.TryCharge(source, now, token: 0x900));

        ledger.NoteValidated(source, now);
        Assert.True(ledger.TryCharge(source, now, token: 0xA00), "validation resets the budget");
        Assert.True(ledger.TryCharge(source, now, token: 0xB00));
        Assert.True(ledger.TryCharge(source, now, token: 0xC00));
        Assert.False(ledger.TryCharge(source, now, token: 0xD00));
    }

    [Fact]
    public void StrangerLedger_RetransmittedPuncsOfTheSameHandshakeDrawNothing()
    {
        long now = 2_000_000;
        var ledger = new StrangerLedger(() => now);
        byte[] source = [0x55, 0x66];

        Assert.True(ledger.TryCharge(source, now, token: 0x4242_4242));
        for (int i = 0; i < 12; i++)
        {
            Assert.True(ledger.TryCharge(source, now + 100 + i, token: 0x4242_4242),
                "a retransmit of the same initiation is the same dialog, not a new bill");
        }

        Assert.True(ledger.TryCharge(source, now + 2_000, token: 0x5151_5151));
        Assert.True(ledger.TryCharge(source, now + 3_000, token: 0x6161_6161));
        Assert.False(ledger.TryCharge(source, now + 4_000, token: 0x7171_7171),
            "distinct initiations still spend the window budget");
        Assert.True(ledger.TryCharge(source, now + 5_000, token: 0x6161_6161),
            "the latest dialog's retransmit still rides free");
    }

    [Fact]
    public void StrangerLedger_KeysArePerSource_AndTheTableStaysBoundedUnderChurn()
    {
        long now = 1_000_000;
        var ledger = new StrangerLedger(() => now);
        byte[] a = [0x01];
        byte[] b = [0x02];

        for (int i = 0; i < StrangerLedger.PricedRepliesPerWindow; i++)
        {
            Assert.True(ledger.TryCharge(a, now, token: (uint)(0x10 + i)));
        }

        Assert.False(ledger.TryCharge(a, now, token: 0x99));
        Assert.True(ledger.TryCharge(b, now, token: 0x1), "a fresh source has its own budget");

        for (int i = 0; i < 4 * StrangerLedger.MaxSources; i++)
        {
            Span<byte> key = [0xC0, (byte)(i >> 8), (byte)i];
            ledger.TryCharge(key, now, token: (uint)i);
            Assert.True(ledger.TrackedSources <= StrangerLedger.MaxSources, "the source table must stay bounded");
        }
    }

    [Fact]
    public void MachinePricedReplyGate_SilencesThePack_KeepsTheCookieDemand_Mac1StaysFirst()
    {
        Effect[] effects = new Effect[2];

        HandshakeInput forged = default;
        forged.Kind = HandshakeInputKind.PuncBegin;
        forged.CryptoBody = true;
        forged.PinMatches = true;
        forged.Mac1Present = true;
        forged.Mac1Ok = false;
        forged.CookieRequired = true;
        forged.CookieOk = false;
        forged.PricedReplyBlocked = true;
        HandshakeState mac1First = HandshakeState.Create(1, offeredCrypto: true);
        int n = HandshakeMachine.Step(ref mac1First, in forged, new Tick(0), effects);
        Assert.Equal(HandshakeMachine.RejectMac1, effects[0].Value);

        HandshakeInput loaded = forged;
        loaded.Mac1Ok = true;
        HandshakeState cookieWins = HandshakeState.Create(1, offeredCrypto: true);
        n = HandshakeMachine.Step(ref cookieWins, in loaded, new Tick(0), effects);
        Assert.Single(effects[..n]);
        Assert.Equal(EffectKind.Transmit, effects[0].Kind);
        Assert.Equal(HandshakeMachine.ReplyCookie, effects[0].Value);

        HandshakeInput spent = loaded;
        spent.CookieRequired = false;
        spent.CookieOk = false;
        HandshakeState silenced = HandshakeState.Create(1, offeredCrypto: true);
        n = HandshakeMachine.Step(ref silenced, in spent, new Tick(0), effects);
        Assert.Single(effects[..n]);
        Assert.Equal(EffectKind.Notify, effects[0].Kind);
        Assert.Equal(HandshakeMachine.RejectPricedReply, effects[0].Value);
        Assert.False(silenced.RemoteTokenKnown, "the ledger refusal latched no token");

        HandshakeInput funded = spent;
        funded.PricedReplyBlocked = false;
        HandshakeState answering = HandshakeState.Create(1, offeredCrypto: true);
        n = HandshakeMachine.Step(ref answering, in funded, new Tick(0), effects);
        Assert.Equal(HandshakeMachine.NeedKeys, effects[0].Value);
    }

    [Fact]
    public async Task StrangerPuncBarrage_EarnsAtMostThreePricedReplies_NoAnnounceNoProbe_LedgerHoldsOneSource()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        var listenerWire = new IPEndPoint(IPAddress.Loopback, listener.LocalPort);
        byte[] listenerKey = ConnectionString.Parse(listener.ConnectionString).StaticKey!;

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        byte[] eph = RandomNumberGenerator.GetBytes(32);
        byte[] stat = RandomNumberGenerator.GetBytes(32);

        const int flood = 16;
        for (int i = 0; i < flood; i++)
        {
            attacker.SendTo(V4Punc(FakePeer, (uint)(0x1234_0000 + i), eph, stat, listenerKey), SocketFlags.None, listenerWire);
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => listener.Engine.StrangerLedgerRefused >= 1);

        var replies = new List<(int Length, byte Type)>();
        byte[] buf = new byte[2048];
        EndPoint any = new IPEndPoint(IPAddress.Any, 0);
        attacker.ReceiveTimeout = 100;
        long drainedAt = Environment.TickCount64;
        while (Environment.TickCount64 - drainedAt < 500)
        {
            int received;
            try
            {
                received = attacker.ReceiveFrom(buf, SocketFlags.None, ref any);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
            {
                break;
            }

            replies.Add((received, buf[0]));
        }

        Assert.True(replies.Count <= 3,
            $"the barrage of {flood} PUNCs earned {replies.Count} replies: {string.Join(",", replies.Select(r => $"{r.Length}B:{r.Type:x2}"))}");
        foreach ((int length, byte type) in replies)
        {
            Assert.Equal(0x51, type);
            Assert.Equal(9 + CryptoWire.PackCryptoBodyV4, length);
            Assert.True(length <= 3 * (9 + CryptoWire.PuncCryptoBodyV4), "each reply must stay priced by its request");
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => listener.Engine.HandshakeKeyAgreements == 3);
        Assert.True(listener.Engine.StrangerLedgerSources <= 1, "one barrage source is one ledger entry");
        Assert.True(listener.Connections.Count <= 1, "the barrage created at most one husk");

        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts());
        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        PinholeConnection atListener = await accept.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atListener.Received += p => got.TrySetResult(p.ToArray());
        conn.Send("through the spent ledger"u8);
        Assert.Equal("through the spent ledger"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task V3StrangerPuncs_DrawFromTheSameLedger_AsV4StrangerPuncs()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        var listenerWire = new IPEndPoint(IPAddress.Loopback, listener.LocalPort);

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        for (int i = 0; i < StrangerLedger.PricedRepliesPerWindow; i++)
        {
            attacker.SendTo(V4Punc(FakePeer, (uint)(0x100 + i), RandomNumberGenerator.GetBytes(32),
                RandomNumberGenerator.GetBytes(32), ConnectionString.Parse(listener.ConnectionString).StaticKey!),
                SocketFlags.None, listenerWire);
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3),
            () => listener.Engine.HandshakeKeyAgreements >= StrangerLedger.PricedRepliesPerWindow);

        byte[] scratch = new byte[2048];
        EndPoint drainFrom = new IPEndPoint(IPAddress.Any, 0);
        attacker.ReceiveTimeout = 100;
        try
        {
            while (true) _ = attacker.ReceiveFrom(scratch, SocketFlags.None, ref drainFrom);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
        {
        }

        attacker.SendTo(V3Punc(FakePeer + 1, 0x200), SocketFlags.None, listenerWire);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => listener.Engine.StrangerLedgerRefused >= 1);

        byte[] buf = new byte[2048];
        EndPoint any = new IPEndPoint(IPAddress.Any, 0);
        attacker.ReceiveTimeout = 300;
        Assert.Throws<SocketException>(() => attacker.ReceiveFrom(buf, SocketFlags.None, ref any));
        Assert.Equal(StrangerLedger.PricedRepliesPerWindow, listener.Engine.HandshakeKeyAgreements);
    }

    [Fact]
    public async Task ConfirmedPeer_RetransmittingPuncs_IsNotChargedByTheStrangerLedger()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts());

        Task<PinholeConnection> accept = listener.AcceptAsync();
        await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        await accept.WaitAsync(Timeout);
        long refusedBeforeReplays = listener.Engine.StrangerLedgerRefused;

        ConnState dialerState = dialer.Engine.Lookup(listener.PeerId)!;
        byte[] punc = dialerState.PuncFrame;
        var listenerWire = new IPEndPoint(IPAddress.Loopback, listener.LocalPort);
        using var replay = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        replay.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        const int retransmits = StrangerLedger.PricedRepliesPerWindow + 2;
        for (int i = 0; i < retransmits; i++)
        {
            replay.SendTo(punc, SocketFlags.None, listenerWire);
        }

        int packs = 0;
        byte[] buf = new byte[2048];
        EndPoint any = new IPEndPoint(IPAddress.Any, 0);
        replay.ReceiveTimeout = 100;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < TimeSpan.FromSeconds(2))
        {
            try
            {
                int n = replay.ReceiveFrom(buf, SocketFlags.None, ref any);
                if (buf[0] == 0x51 && n == 9 + CryptoWire.PackCryptoBodyV4) packs++;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
            {
                break;
            }
        }

        Assert.True(packs >= retransmits,
            $"a confirmed peer's {retransmits} retransmissions earned {packs} PACKs — retransmits must not be priced as strangers");
        Assert.Equal(refusedBeforeReplays, listener.Engine.StrangerLedgerRefused);
        Assert.True(listener.Engine.StrangerLedgerSources <= StrangerLedger.MaxSources,
            "the ledger stays bounded after a dial plus confirmed retransmits");
    }
}
