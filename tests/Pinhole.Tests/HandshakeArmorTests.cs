using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Pinhole.Crypto;
using Xunit;

namespace Pinhole.Tests;

public sealed class HandshakeArmorTests
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
    };

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

    [Fact]
    public void Mac1_IsKeyedBlake3OverTheFrameMinusTheMac_TruncatedToWireGuardSize()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] frame = V4Punc(0xA11CE_0001, 0x0BAD_C0DE, RandomNumberGenerator.GetBytes(32),
            RandomNumberGenerator.GetBytes(32), key);

        Assert.Equal(94, frame.Length);
        Assert.Equal(CryptoWire.HandshakeV4Marker, frame[^CryptoWire.Mac1ExtLength]);
        Assert.Equal(16, CryptoWire.Mac1Length);

        byte[] expected = Blake3.HashKeyed(key, frame.AsSpan(0, frame.Length - CryptoWire.Mac1Length));
        Assert.Equal(expected[..16], frame[^CryptoWire.Mac1Length..].ToArray());

        Assert.True(CryptoWire.VerifyMac1(frame, key));
        Assert.False(CryptoWire.VerifyMac1(frame, RandomNumberGenerator.GetBytes(32)), "wrong key");
        frame[20] ^= 0x01;
        Assert.False(CryptoWire.VerifyMac1(frame, key), "edited body");
        frame[20] ^= 0x01;
        frame[^CryptoWire.Mac1ExtLength] = 0x03;
        Assert.False(CryptoWire.VerifyMac1(frame, key), "foreign marker");
        Assert.False(CryptoWire.VerifyMac1(new byte[9 + CryptoWire.PuncCryptoBody], key), "v3 shape has no extension");
    }

    [Fact]
    public async Task ForgedMac1Flood_EarnsSilenceZeroStateAndZeroKeyAgreements_WhileAV4DialStillCompletes()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        var listenerWire = new IPEndPoint(IPAddress.Loopback, listener.LocalPort);

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        byte[] wrongKey = RandomNumberGenerator.GetBytes(32);
        const int flood = 64;
        for (int i = 0; i < flood; i++)
        {
            byte[] frame = V4Punc(
                BinaryPrimitives.ReadUInt64LittleEndian(RandomNumberGenerator.GetBytes(8)),
                BinaryPrimitives.ReadUInt32LittleEndian(RandomNumberGenerator.GetBytes(4)),
                RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32),
                wrongKey, goodMac1: i % 2 == 0);
            attacker.SendTo(frame, SocketFlags.None, listenerWire);
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => listener.Engine.Mac1Refused >= flood);

        Assert.Equal(0, listener.Engine.HandshakeKeyAgreements);
        Assert.Empty(listener.Connections);

        Assert.False(attacker.Poll(500_000, SelectMode.SelectRead), "responder emitted bytes to a forged source");

        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts());
        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        PinholeConnection atListener = await accept.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);
        Assert.True(listener.Engine.HandshakeKeyAgreements >= 1, "the legitimate dial did agree keys");
        Assert.True(listener.Engine.Mac1Refused >= flood);

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atListener.Received += p => got.TrySetResult(p.ToArray());
        conn.Send("through the flood"u8);
        Assert.Equal("through the flood"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task V4Dialer_V4Responder_PuncCarriesMac1_AndTheHandshakeSealsEndToEnd()
    {
        await using PinholeNode node = await PinholeNode.BindAsync(Opts());
        using var oracle = new V4Oracle();
        var nodeEp = new IPEndPoint(IPAddress.Loopback, node.LocalPort);

        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString());
        byte[] punc = await oracle.AwaitV4PuncAsync(node);

        Assert.Equal(9 + CryptoWire.PuncCryptoBodyV4, punc.Length);
        Assert.Equal(CryptoWire.HandshakeV4Marker, punc[^CryptoWire.Mac1ExtLength]);
        Assert.True(CryptoWire.VerifyMac1(punc, oracle.Identity.PublicKey));

        uint dialerToken = BinaryPrimitives.ReadUInt32LittleEndian(punc.AsSpan(9));
        Assert.True(oracle.TryPeerKeys(node.PeerId, punc.AsSpan(13, 32), punc.AsSpan(45, 32)));
        await oracle.Sock.SendToAsync(oracle.Pack(dialerToken, v4: true), nodeEp);
        await oracle.Sock.SendToAsync(oracle.SealFrame(0x53, new byte[8]), nodeEp);

        PinholeConnection conn = await dial.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);
        Assert.Equal(0, node.Engine.Mac1Refused);

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.Received += p => got.TrySetResult(p.ToArray());
        await oracle.Sock.SendToAsync(oracle.SealFrame(0x52, "v4 sealed"u8), nodeEp);
        Assert.Equal("v4 sealed"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task ForgedV4Pack_IsSilentOnTheDialer_GoodPackStillCompletes()
    {
        await using PinholeNode node = await PinholeNode.BindAsync(Opts());
        using var oracle = new V4Oracle();
        var nodeEp = new IPEndPoint(IPAddress.Loopback, node.LocalPort);

        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString());
        byte[] punc = await oracle.AwaitV4PuncAsync(node);
        uint dialerToken = BinaryPrimitives.ReadUInt32LittleEndian(punc.AsSpan(9));
        Assert.True(oracle.TryPeerKeys(node.PeerId, punc.AsSpan(13, 32), punc.AsSpan(45, 32)));

        byte[] forged = oracle.Pack(dialerToken, v4: true);
        forged[^1] ^= 0xFF;
        await oracle.Sock.SendToAsync(forged, nodeEp);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => node.Engine.Mac1Refused >= 1);
        Assert.Equal(0, node.Engine.HandshakeKeyAgreements);
        byte[] scratch = new byte[2048];
        EndPoint any = new IPEndPoint(IPAddress.Any, 0);
        oracle.Sock.ReceiveTimeout = 200;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            while (sw.Elapsed < TimeSpan.FromMilliseconds(700))
            {
                int received = oracle.Sock.ReceiveFrom(scratch, ref any);
                Assert.True(scratch[0] == 0x50, $"dialer answered a forged PACK with frame type {scratch[0]:x2}");
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
        {
        }

        await oracle.Sock.SendToAsync(oracle.Pack(dialerToken, v4: true), nodeEp);
        await oracle.Sock.SendToAsync(oracle.SealFrame(0x53, new byte[8]), nodeEp);
        PinholeConnection conn = await dial.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);
        Assert.Equal(1, node.Engine.HandshakeKeyAgreements);
    }

    [Fact]
    public async Task V4PackMac1KeyedWithTheDialersOwnStaticKey_AlsoVerifies()
    {

        await using PinholeNode node = await PinholeNode.BindAsync(Opts());
        using var oracle = new V4Oracle();
        var nodeEp = new IPEndPoint(IPAddress.Loopback, node.LocalPort);

        Task<PinholeConnection> dial = node.ConnectAsync(oracle.StringPointingAt(oracle.Ep).ToString());
        byte[] punc = await oracle.AwaitV4PuncAsync(node);
        uint dialerToken = BinaryPrimitives.ReadUInt32LittleEndian(punc.AsSpan(9));
        Assert.True(oracle.TryPeerKeys(node.PeerId, punc.AsSpan(13, 32), punc.AsSpan(45, 32)));

        byte[] pack = oracle.Pack(dialerToken, v4: true, mac1Key: punc.AsSpan(45, 32).ToArray());
        await oracle.Sock.SendToAsync(pack, nodeEp);
        await oracle.Sock.SendToAsync(oracle.SealFrame(0x53, new byte[8]), nodeEp);
        PinholeConnection conn = await dial.WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);
    }

    [Fact]
    public async Task V4Dialer_LegacyV3Responder_FallsBackToUnversionedOnceAndCompletes()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        listener.Engine.LegacyHandshakeV3Only = true;
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts());

        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        PinholeConnection atListener = await accept.WaitAsync(Timeout);

        Assert.True(conn.IsEncrypted);
        ConnState state = dialer.Engine.Lookup(listener.PeerId)!;
        Assert.True(state.PuncFrameDowngraded, "the one-shot fallback fired");
        Assert.False(state.PuncFrameV4);
        Assert.Equal(9 + CryptoWire.PuncCryptoBody, state.PuncFrame.Length);
        Assert.Equal(0, listener.Engine.Mac1Refused);
        Assert.True(listener.Engine.HandshakeKeyAgreements >= 1, "the fallback handshake agreed keys");

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.Received += p => got.TrySetResult(p.ToArray());
        atListener.Send("after fallback"u8);
        Assert.Equal("after fallback"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task LegacyV3Dialer_V4Responder_IsUnchangedByTheSupportWindow()
    {
        await using PinholeNode listener = await PinholeNode.BindAsync(Opts());
        await using PinholeNode dialer = await PinholeNode.BindAsync(Opts());
        dialer.Engine.LegacyHandshakeV3Only = true;

        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        PinholeConnection atListener = await accept.WaitAsync(Timeout);

        Assert.True(conn.IsEncrypted);
        Assert.Equal(0, listener.Engine.Mac1Refused);
        Assert.True(listener.Engine.HandshakeKeyAgreements >= 1);
        Assert.False(dialer.Engine.Lookup(listener.PeerId)!.PuncFrameV4);

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.Received += p => got.TrySetResult(p.ToArray());
        atListener.Send("v3 bridge"u8);
        Assert.Equal("v3 bridge"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    private sealed class V4Oracle : IDisposable
    {
        public readonly Socket Sock = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        public readonly ulong PeerId = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        public readonly NodeIdentity Identity = new();
        public const uint Token = 0x2468_ACE0;
        private ConnectionCrypto? _crypto;

        public V4Oracle()
        {
            Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        }

        public IPEndPoint Ep => (IPEndPoint)Sock.LocalEndPoint!;

        public ConnectionString StringPointingAt(IPEndPoint ep) => new(
            PeerId, [new PinholeCandidate(CandidateKind.Direct, ep)], NatHint.Unknown, Identity.PublicKey);

        public bool TryPeerKeys(ulong nodePeerId, ReadOnlySpan<byte> eph, ReadOnlySpan<byte> stat)
        {
            _crypto ??= ConnectionCrypto.New(Identity, PeerId, nodePeerId);
            return _crypto.TryPeerKeys(eph, stat);
        }

        public async Task<byte[]> AwaitV4PuncAsync(PinholeNode node)
        {
            byte[] buf = new byte[2048];
            EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            using var deadline = new CancellationTokenSource(Timeout);
            while (true)
            {
                SocketReceiveFromResult r = await Sock.ReceiveFromAsync(buf, any, deadline.Token);
                if (r.ReceivedBytes == 9 + CryptoWire.PuncCryptoBodyV4 && buf[0] == 0x50
                    && BinaryPrimitives.ReadUInt64LittleEndian(buf.AsSpan(1)) == node.PeerId)
                {
                    return buf[..r.ReceivedBytes];
                }
            }
        }

        public byte[] Pack(uint dialerToken, bool v4, byte[]? mac1Key = null)
        {
            byte[] pack = new byte[9 + CryptoWire.PackCryptoBody + (v4 ? CryptoWire.Mac1ExtLength : 0)];
            pack[0] = 0x51;
            BinaryPrimitives.WriteUInt64LittleEndian(pack.AsSpan(1), PeerId);
            BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(9), dialerToken);
            BinaryPrimitives.WriteUInt32LittleEndian(pack.AsSpan(13), Token);
            _crypto!.MyEphPublic.CopyTo(pack, 17);
            _crypto.MyStaticPublic.CopyTo(pack, 49);
            _crypto.MyConfirm().CopyTo(pack, 81);
            if (v4)
            {
                CryptoWire.WriteMac1Ext(pack, mac1Key ?? Identity.PublicKey);
            }

            return pack;
        }

        public byte[] SealFrame(byte type, ReadOnlySpan<byte> body)
        {
            var f = new byte[9 + 4 + CryptoWire.SealedOverhead + body.Length];
            f[0] = type;
            BinaryPrimitives.WriteUInt64LittleEndian(f.AsSpan(1), PeerId);
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(9), Token);
            _crypto!.Send!.Seal(f.AsSpan(13), f.AsSpan(0, 13), body);
            return f;
        }

        public void Dispose() => Sock.Dispose();
    }
}
