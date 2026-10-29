using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Pinhole.Crypto;
using Xunit;

namespace Pinhole.Tests;

public sealed class HybridKemTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static byte[] Knock(int length = 16)
    {
        byte[] knock = new byte[length];
        RandomNumberGenerator.Fill(knock);
        return knock;
    }

    private static PinholeOptions Opts(bool hybrid = false, byte[]? knock = null, TimeSpan? connectTimeout = null) => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [], DerpRelayUrls = [],
        Listen = true,
        Knock = knock,
        HybridKeyExchange = hybrid,
        ConnectTimeout = connectTimeout ?? TimeSpan.FromSeconds(8),
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false, EnablePortMapping = false,
        EnableTcpTransport = false,
    };

    private static byte[] MlKemSeed() => RandomNumberGenerator.GetBytes(HybridKem.PrivateSeedLength);

    private static byte[] MlKemPub() => HybridKem.PublicKeyFromSeed(MlKemSeed())!;

    private static byte[] MlKemBlob() => RandomNumberGenerator.GetBytes(HybridKem.PublicKeyLength);

    private static (PinholeConnection Conn, PinholeConnection AtListener, PinholeNode Dialer, PinholeNode Listener) Dial(
        PinholeOptions dialer, PinholeOptions listener)
    {
        PinholeNode listenerNode = PinholeNode.BindAsync(listener).GetAwaiter().GetResult();
        PinholeNode dialerNode = PinholeNode.BindAsync(dialer).GetAwaiter().GetResult();
        try
        {
            Task<PinholeConnection> accept = listenerNode.AcceptAsync();
            PinholeConnection conn = dialerNode.ConnectAsync(listenerNode.ConnectionString).WaitAsync(Timeout).GetAwaiter().GetResult();
            PinholeConnection atListener = accept.WaitAsync(Timeout).GetAwaiter().GetResult();
            return (conn, atListener, dialerNode, listenerNode);
        }
        catch
        {
            dialerNode.DisposeAsync().AsTask().GetAwaiter().GetResult();
            listenerNode.DisposeAsync().AsTask().GetAwaiter().GetResult();
            throw;
        }
    }

    [Fact]
    public void MlKemPskBlock_IsLabeledAndSeparate_HybridKeysDifferFromEveryClassicalOutput()
    {
        NodeIdentity loId = new(Convert.FromHexString("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"));
        NodeIdentity hiId = new(Convert.FromHexString("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"));
        (byte[] loEphPriv, byte[] loEphPub) = NodeIdentity.NewEphemeral();
        (byte[] hiEphPriv, byte[] hiEphPub) = NodeIdentity.NewEphemeral();
        ulong lo = 1, hi = 2;
        byte[] ss = RandomNumberGenerator.GetBytes(HybridKem.SharedSecretLength);
        byte[] knock = Knock();

        SessionKeys hybridLo = KeySchedule.Derive(lo, loEphPriv, loId.ExportPrivateSeed(), hi, hiEphPub, hiId.PublicKey, mlkemSecret: ss);
        SessionKeys hybridHi = KeySchedule.Derive(hi, hiEphPriv, hiId.ExportPrivateSeed(), lo, loEphPub, loId.PublicKey, mlkemSecret: ss);
        SessionKeys classical = KeySchedule.Derive(lo, loEphPriv, loId.ExportPrivateSeed(), hi, hiEphPub, hiId.PublicKey);
        SessionKeys otherSs = KeySchedule.Derive(lo, loEphPriv, loId.ExportPrivateSeed(), hi, hiEphPub, hiId.PublicKey,
            mlkemSecret: RandomNumberGenerator.GetBytes(HybridKem.SharedSecretLength));
        SessionKeys knockKeyed = KeySchedule.Derive(lo, loEphPriv, loId.ExportPrivateSeed(), hi, hiEphPub, hiId.PublicKey, knock);
        SessionKeys both = KeySchedule.Derive(lo, loEphPriv, loId.ExportPrivateSeed(), hi, hiEphPub, hiId.PublicKey, knock, ss);

        Assert.Equal(hybridLo.LoToHiKey, hybridHi.LoToHiKey);
        Assert.Equal(hybridLo.HiConfirm, hybridHi.HiConfirm);

        foreach ((string name, byte[] a, byte[] b) in new[]
        {
            ("lo2hi key", hybridLo.LoToHiKey, classical.LoToHiKey),
            ("hi2lo key", hybridLo.HiToLoKey, classical.HiToLoKey),
            ("lo2hi salt", hybridLo.LoToHiSalt, classical.LoToHiSalt),
            ("hi2lo salt", hybridLo.HiToLoSalt, classical.HiToLoSalt),
            ("lo confirm", hybridLo.LoConfirm, classical.LoConfirm),
            ("hi confirm", hybridLo.HiConfirm, classical.HiConfirm),
            ("lo2hi key vs other ss", hybridLo.LoToHiKey, otherSs.LoToHiKey),
            ("knock block vs mlkem block on equal material", knockKeyed.LoToHiKey, hybridLo.LoToHiKey),
            ("knock-only vs knock+kem", knockKeyed.LoToHiKey, both.LoToHiKey),
            ("hybrid vs knock+kem", hybridLo.LoToHiKey, both.LoToHiKey),
        })
        {
            Assert.False(a.AsSpan().SequenceEqual(b), $"{name} must differ under the ML-KEM PSK block");
        }
    }

    [Fact]
    public void HybridTicketV5_RoundTrips_AndCanonicallyRejectsBadShapes()
    {
        byte[] stat = RandomNumberGenerator.GetBytes(32);
        byte[] mlkem = MlKemBlob();
        var candidates = new[] { new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 40000)) };

        var bare = new ConnectionString(0xA11CE, candidates, NatHint.Cone, stat, mlKemKey: mlkem);
        string text = bare.ToString();
        string payload = text[(text.IndexOf(':') + 1)..].Replace('-', '+').Replace('_', '/');
        byte[] body = Convert.FromBase64String(payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '='));
        Assert.Equal(5, body[0]);
        Assert.Equal(9, body[1]);
        ConnectionString parsed = ConnectionString.Parse(text);
        Assert.Equal(mlkem, parsed.MlKemKey);
        Assert.Equal(stat, parsed.StaticKey);
        Assert.Null(parsed.EndpointKey);
        Assert.Null(parsed.Knock);
        Assert.Equal(text, parsed.ToString());

        byte[] knock = Knock();
        byte[] endpoint = RandomNumberGenerator.GetBytes(32);
        var full = new ConnectionString(0xA11CE, candidates, NatHint.Cone, stat, endpoint, knock, mlkem);
        parsed = ConnectionString.Parse(full.ToString());
        Assert.Equal(mlkem, parsed.MlKemKey);
        Assert.Equal(endpoint, parsed.EndpointKey);
        Assert.Equal(knock, parsed.Knock);
        Assert.Equal(full.ToString(), parsed.ToString());

        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(1, candidates, NatHint.Unknown,
            stat, mlKemKey: mlkem[..^1]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(1, candidates, NatHint.Unknown,
            stat, mlKemKey: [.. mlkem, 0]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(1, candidates, NatHint.Unknown,
            mlKemKey: mlkem));
        Assert.Throws<FormatException>(() => ConnectionString.Parse(StripKemFlag(text)));
        Assert.Throws<FormatException>(() => ConnectionString.Parse(Truncate(text, HybridKem.PublicKeyLength - 1)));
        Assert.Throws<FormatException>(() => ConnectionString.Parse(Truncate(text, 1)));
    }

    private static string StripKemFlag(string text)
    {
        string payload = text[(text.IndexOf(':') + 1)..].Replace('-', '+').Replace('_', '/');
        byte[] body = Convert.FromBase64String(payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '='));
        body[1] = (byte)(body[1] & ~8);
        return "pinhole1:" + Convert.ToBase64String(body).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string Truncate(string text, int removeBytes)
    {
        string payload = text[(text.IndexOf(':') + 1)..].Replace('-', '+').Replace('_', '/');
        byte[] body = Convert.FromBase64String(payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '='));
        return "pinhole1:" + Convert.ToBase64String(body[..^removeBytes]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    [Fact]
    public async Task HybridFlagNeedsAnEncryptedNode()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => PinholeNode.BindAsync(Opts(hybrid: true) with
        {
            Encryption = PinholeEncryption.Disabled,
        }));
    }

#if !NET10_0
    [Fact]
    public async Task OnRuntimesWithoutMlKem_TheFlagIsASafeNoOp_TheTicketStaysPreV5()
    {
        Assert.False(HybridKem.IsSupported);
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts(hybrid: true));
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts(hybrid: true));

        ConnectionString parsed = ConnectionString.Parse(listener.ConnectionString);
        Assert.Null(parsed.MlKemKey);
        byte version = VersionByte(listener.ConnectionString);
        Assert.InRange(version, (byte)1, (byte)4);

        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        await accept.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);
        Assert.Equal(0, dialer.Engine.HybridHandshakes);
        Assert.Equal(0, listener.Engine.HybridHandshakes);
        Assert.Null(dialer.Engine.Lookup(listener.PeerId)!.KemFrame);
    }

    private static byte VersionByte(string text)
    {
        string payload = text[(text.IndexOf(':') + 1)..].Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '='))[0];
    }
#endif

    [Fact]
    public async Task FlagOffBothSides_TheWireIsByteIdenticalToTheClassicalHandshake()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts());

        ConnectionString parsed = ConnectionString.Parse(listener.ConnectionString);
        Assert.Null(parsed.MlKemKey);
        Assert.InRange(VersionByteOf(listener.ConnectionString), (byte)1, (byte)4);

        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        await accept.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);

        ConnState state = dialer.Engine.Lookup(listener.PeerId)!;
        Assert.True(state.PuncFrameV4);
        Assert.Equal(9 + CryptoWire.PuncCryptoBodyV4, state.PuncFrame.Length);
        Assert.Null(state.KemFrame);
        Assert.Equal(0, dialer.Engine.HybridHandshakes);
        Assert.Equal(0, listener.Engine.HybridHandshakes);
    }

    private static byte VersionByteOf(string text)
    {
        string payload = text[(text.IndexOf(':') + 1)..].Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '='))[0];
    }

    [Fact]
    public async Task DialerFlagOn_ResponderTicketPreV5_CompletesClassicalSilently()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts(hybrid: true));
        Assert.Null(ConnectionString.Parse(listener.ConnectionString).MlKemKey);

        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        PinholeConnection atListener = await accept.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);

        Assert.Null(dialer.Engine.Lookup(listener.PeerId)!.KemFrame);
        Assert.Equal(0, dialer.Engine.HybridHandshakes);
        Assert.Equal(0, listener.Engine.HybridHandshakes);
        Assert.False(listener.Engine.Lookup(dialer.PeerId)!.Crypto!.HybridLatched);

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.Received += p => got.TrySetResult(p.ToArray());
        atListener.Send("classical because the ticket never offered a kem"u8);
        Assert.Equal("classical because the ticket never offered a kem"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task ResponderFlagOn_DialerFlagOff_CompletesClassicalSilently()
    {
        if (!HybridKem.IsSupported) return;
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts(hybrid: true));
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts());

        ConnectionString parsed = ConnectionString.Parse(listener.ConnectionString);
        Assert.NotNull(parsed.MlKemKey);
        Assert.Equal(HybridKem.PublicKeyLength, parsed.MlKemKey!.Length);

        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        PinholeConnection atListener = await accept.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);

        Assert.Null(dialer.Engine.Lookup(listener.PeerId)!.KemFrame);
        Assert.Equal(0, dialer.Engine.HybridHandshakes);
        Assert.Equal(0, listener.Engine.HybridHandshakes);
        Assert.False(listener.Engine.Lookup(dialer.PeerId)!.Crypto!.HybridLatched);
    }

    [Fact]
    public async Task BothFlagsOn_TheSessionGoesHybrid_ConfirmsAndTrafficCoverTheKem()
    {
        if (!HybridKem.IsSupported) return;
        (PinholeConnection conn, PinholeConnection atListener, PinholeNode dialer, PinholeNode listener) =
            Dial(Opts(hybrid: true), Opts(hybrid: true));
        await using (dialer)
        await using (listener)
        {
            Assert.True(conn.IsEncrypted);

            ConnState dialerState = dialer.Engine.Lookup(listener.PeerId)!;
            ConnState listenerState = listener.Engine.Lookup(dialer.PeerId)!;
            Assert.True(dialerState.PuncFrameV4);
            Assert.Equal(9 + CryptoWire.PuncCryptoBodyV4, dialerState.PuncFrame.Length);
            Assert.Equal(9 + CryptoWire.KemBody, dialerState.KemFrame!.Length);
            Assert.Equal((byte)FrameType.Kem, dialerState.KemFrame[0]);
            Assert.True(dialerState.Crypto!.HybridPending);
            Assert.True(listenerState.Crypto!.HybridLatched);
            Assert.Equal(1, dialer.Engine.HybridHandshakes);
            Assert.Equal(1, listener.Engine.HybridHandshakes);
            Assert.True(listenerState.KemsReceived >= 1);

            var gotAtListener = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            var gotAtDialer = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            atListener.Received += p => gotAtListener.TrySetResult(p.ToArray());
            conn.Received += p => gotAtDialer.TrySetResult(p.ToArray());
            conn.Send("hybrid sealed one way"u8);
            Assert.Equal("hybrid sealed one way"u8.ToArray(), await gotAtListener.Task.WaitAsync(Timeout));
            atListener.Send("hybrid sealed the other"u8);
            Assert.Equal("hybrid sealed the other"u8.ToArray(), await gotAtDialer.Task.WaitAsync(Timeout));
        }
    }

    [Fact]
    public async Task KnockAndHybrid_Compose_Mac1StaysKnockKeyed()
    {
        if (!HybridKem.IsSupported) return;
        byte[] knock = Knock();
        (PinholeConnection conn, _, PinholeNode dialer, PinholeNode listener) =
            Dial(Opts(hybrid: true), Opts(hybrid: true, knock: knock));
        await using (dialer)
        await using (listener)
        {
            Assert.True(conn.IsEncrypted);
            ConnectionString cs = ConnectionString.Parse(listener.ConnectionString);
            Assert.Equal(knock, cs.Knock);
            Assert.NotNull(cs.MlKemKey);

            ConnState dialerState = dialer.Engine.Lookup(listener.PeerId)!;
            Assert.True(dialerState.PuncFrameV4);
            Assert.False(dialerState.PuncFrameDowngraded);
            Span<byte> key = stackalloc byte[32];
            CryptoWire.KnockMac1Key(key, cs.StaticKey!, knock);
            Assert.True(CryptoWire.VerifyMac1(dialerState.PuncFrame, key));
            Assert.Equal(1, dialer.Engine.HybridHandshakes);
            Assert.Equal(1, listener.Engine.HybridHandshakes);
        }
    }

    [Fact]
    public async Task StrangerKemFrameBeforeAnyPunc_EarnsTotalSilence()
    {
        if (!HybridKem.IsSupported) return;
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts(hybrid: true));
        var listenerWire = new IPEndPoint(IPAddress.Loopback, listener.LocalPort);

        using var stranger = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        stranger.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        for (int i = 0; i < 8; i++)
        {
            byte[] kem = new byte[9 + CryptoWire.KemBody];
            kem[0] = (byte)FrameType.Kem;
            BinaryPrimitives.WriteUInt64LittleEndian(kem.AsSpan(1), 0x5CA11_0000 + (ulong)i);
            BinaryPrimitives.WriteUInt32LittleEndian(kem.AsSpan(9), 0x1234_5678);
            RandomNumberGenerator.Fill(kem.AsSpan(13));
            stranger.SendTo(kem, SocketFlags.None, listenerWire);
            byte[] wrongLength = kem[..(9 + CryptoWire.TokenLength + 64)];
            wrongLength[0] = (byte)FrameType.Kem;
            stranger.SendTo(wrongLength, SocketFlags.None, listenerWire);
        }

        await Task.Delay(500);
        Assert.False(stranger.Poll(500_000, SelectMode.SelectRead), "the responder emitted bytes to a Kem-frame stranger");
        Assert.Empty(listener.Connections);
        Assert.Equal(0, listener.Engine.HandshakeKeyAgreements);
        Assert.Equal(0, listener.Engine.Mac1Refused);
        Assert.Equal(0, listener.Engine.CookieDemanded);
        Assert.Equal(0, listener.Engine.HybridHandshakes);
    }

    private sealed class TamperProxy : IDisposable
    {
        public readonly Socket Sock = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        private readonly IPEndPoint _target;
        private readonly bool _tamper;
        private readonly byte[] _buf = new byte[8192];
        private IPEndPoint? _dialer;

        public TamperProxy(IPEndPoint target, bool tamper)
        {
            _target = target;
            _tamper = tamper;
            Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _ = RunAsync();
        }

        public IPEndPoint Ep => (IPEndPoint)Sock.LocalEndPoint!;

        private async Task RunAsync()
        {
            EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            try
            {
                while (true)
                {
                    SocketReceiveFromResult r = await Sock.ReceiveFromAsync(_buf, any);
                    var from = (IPEndPoint)r.RemoteEndPoint!;
                    bool towardListener = from.Port != _target.Port || !from.Address.Equals(_target.Address);
                    if (towardListener) _dialer = from;
                    if (_tamper && _buf[0] == (byte)FrameType.Kem && r.ReceivedBytes == 9 + CryptoWire.KemBody)
                    {
                        _buf[30] ^= 0x40;
                    }

                    await Sock.SendToAsync(_buf.AsMemory(0, r.ReceivedBytes),
                        towardListener ? _target : _dialer!);
                }
            }
            catch (ObjectDisposedException)
            {
            }
        }

        public void Dispose() => Sock.Dispose();
    }

    private static ConnectionString TicketThrough(ConnectionString real, IPEndPoint via) => new(
        real.PeerId,
        [new PinholeCandidate(CandidateKind.Direct, via)],
        real.NatHint,
        real.StaticKey,
        real.EndpointKey,
        real.Knock,
        real.MlKemKey);

    [Fact]
    public async Task TamperedKemFrame_BreaksTheHandshake_InsteadOfFallingBackClassical()
    {
        if (!HybridKem.IsSupported) return;
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts(hybrid: true));
        using var proxy = new TamperProxy(new IPEndPoint(IPAddress.Loopback, listener.LocalPort), tamper: true);
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts(hybrid: true,
            connectTimeout: TimeSpan.FromSeconds(4)));

        ConnectionString real = ConnectionString.Parse(listener.ConnectionString);
        await Assert.ThrowsAnyAsync<Exception>(() =>
            dialer.ConnectAsync(TicketThrough(real, proxy.Ep).ToString()).WaitAsync(Timeout));

        ConnState? listenerState = listener.Engine.Lookup(dialer.PeerId);
        if (listenerState is not null)
        {
            Assert.False(listenerState.Crypto?.PeerConfirmed ?? false,
                "the responder must not confirm a session whose kem ciphertext was tampered");
        }
    }

    [Fact]
    public async Task UntamperedKemThroughAProxy_CompletesHybrid()
    {
        if (!HybridKem.IsSupported) return;
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts(hybrid: true));
        using var proxy = new TamperProxy(new IPEndPoint(IPAddress.Loopback, listener.LocalPort), tamper: false);
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts(hybrid: true));

        ConnectionString real = ConnectionString.Parse(listener.ConnectionString);
        PinholeConnection conn = await dialer.ConnectAsync(TicketThrough(real, proxy.Ep).ToString()).WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);
        Assert.Equal(1, dialer.Engine.HybridHandshakes);
        Assert.Equal(1, listener.Engine.HybridHandshakes);
    }

    [Fact]
    public async Task StaleMlKemTicket_TimesOutVisibly_NoSilentClassicalCompletion()
    {
        if (!HybridKem.IsSupported) return;
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        ConnectionString real = ConnectionString.Parse(listener.ConnectionString);
        var stale = new ConnectionString(real.PeerId, real.Candidates, real.NatHint, real.StaticKey,
            real.EndpointKey, real.Knock, MlKemPub());

        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts(hybrid: true,
            connectTimeout: TimeSpan.FromSeconds(3)));
        await Assert.ThrowsAsync<TimeoutException>(() =>
            dialer.ConnectAsync(stale.ToString()).WaitAsync(Timeout));

        Assert.Equal(0, listener.Engine.HybridHandshakes);
        var listenerState = listener.Engine.Lookup(dialer.PeerId);
        Assert.NotNull(listenerState);
        Assert.True(listenerState.Crypto is { Established: true });
        Assert.False(listenerState.Crypto!.PeerConfirmed, "the responder must not confirm a session the dialer never hybrid-confirmed");
        Assert.True(listenerState.KemsReceived >= 1, "the stale kem frames arrived and were ignored by the flag-off responder");
    }
}
