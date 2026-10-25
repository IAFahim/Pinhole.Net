using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using Pinhole.Turn;
using Pinhole.Wire;
using Xunit;

namespace Pinhole.Tests.Wire;

// Differential oracles for the STUN/TURN codecs. Pinhole grants internals to
// this assembly, so StunBindingMessage is called directly. TurnClient's wire
// helpers are private static (not internal), so they are reached through
// delegates compiled from reflection — CreateDelegate rather than Invoke,
// because span parameters cannot be boxed. Everything here is seeded and
// socket-free: no network, no timing, no filesystem.
public sealed class StunTurnCodecTests
{
    private const uint Cookie = 0x2112A442;

    private static readonly byte[] Txid = Enumerable.Range(0, 12).Select(i => (byte)i).ToArray();

    private delegate byte[] XorAddressD(IPAddress ip, int port, ReadOnlySpan<byte> txid);
    private delegate IPEndPoint? DecodeAddressD(ReadOnlySpan<byte> value, ReadOnlySpan<byte> txid, bool xor);
    private delegate bool TryAddressD(ReadOnlySpan<byte> value, ReadOnlySpan<byte> transaction, bool xor, out IPEndPoint? endpoint);
    private delegate byte[] AttrD(ushort type, ReadOnlySpan<byte> value);
    private delegate byte[] MessageD(ushort type, byte[] txid, byte[] attrs);
    private delegate void HeaderD(byte[] msg, ushort type, int len, byte[] txid);
    private delegate List<(ushort Type, byte[] Value)> AttributesD(byte[] msg);

    private static T TurnMethod<T>(string name) where T : Delegate =>
        typeof(TurnClient).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static)!.CreateDelegate<T>();

    private static readonly XorAddressD TurnXorAddress = TurnMethod<XorAddressD>("XorAddress");
    private static readonly DecodeAddressD TurnDecodeAddress = TurnMethod<DecodeAddressD>("DecodeAddress");
    private static readonly AttrD TurnAttr = TurnMethod<AttrD>("Attr");
    private static readonly MessageD TurnBuildMessage = TurnMethod<MessageD>("Message");
    private static readonly HeaderD TurnHeader = TurnMethod<HeaderD>("Header");
    private static readonly AttributesD TurnAttributes = TurnMethod<AttributesD>("Attributes");
    private static readonly TryAddressD StunTryAddress =
        typeof(StunBindingMessage).GetMethod("TryAddress", BindingFlags.NonPublic | BindingFlags.Static)!.CreateDelegate<TryAddressD>();
    private static readonly MethodInfo TurnIsErrorMethod = typeof(TurnClient).GetMethod("IsError", BindingFlags.NonPublic | BindingFlags.Static)!;
    private static readonly MethodInfo TurnThrowIfErrorMethod = typeof(TurnClient).GetMethod("ThrowIfError", BindingFlags.NonPublic | BindingFlags.Static)!;
    private static readonly MethodInfo TurnTryAuthenticateMethod = typeof(TurnClient).GetMethod("TryAuthenticateResponse", BindingFlags.NonPublic | BindingFlags.Static)!;
    private static readonly Type TurnPendingRequestType = typeof(TurnClient).GetNestedType("PendingRequest", BindingFlags.NonPublic)!;

    private static bool TurnIsError(byte[] message, int code) => (bool)TurnIsErrorMethod.Invoke(null, [message, code])!;

    private static void TurnThrowIfError(byte[] message) => _ = TurnThrowIfErrorMethod.Invoke(null, [message]);

    private static object NewPendingRequest(ushort method, byte[]? integrityKey) =>
        Activator.CreateInstance(TurnPendingRequestType, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null, [method, integrityKey], null)!;

    private static bool TurnTryAuthenticate(byte[] response, object pending, out byte[]? accepted)
    {
        object?[] args = [response, pending, null];
        bool result = (bool)TurnTryAuthenticateMethod.Invoke(null, args)!;
        accepted = (byte[]?)args[2];
        return result;
    }

    // ---- STUN ----

    [Fact]
    public void Stun_BindingRequest_GoldenBytes_MirrorStunBindingMessageRequest()
    {
        byte[] golden0 = Convert.FromHexString("000100002112A442000102030405060708090A0B");
        byte[] golden2 = Convert.FromHexString("000100082112A442000102030405060708090A0B0003000400000002");
        byte[] golden6 = Convert.FromHexString("000100082112A442000102030405060708090A0B0003000400000006");
        byte[] buffer = new byte[28];
        Assert.Equal(20, StunCodec.WriteBindingRequest(buffer, Txid, 0));
        Assert.Equal(golden0, buffer[..20]);
        Assert.Equal(28, StunCodec.WriteBindingRequest(buffer, Txid, 2));
        Assert.Equal(golden2, buffer);
        Assert.Equal(28, StunCodec.WriteBindingRequest(buffer, Txid, 6));
        Assert.Equal(golden6, buffer);
        Assert.Throws<ArgumentOutOfRangeException>(() => StunCodec.WriteBindingRequest(buffer, Txid, 4));

        uint[] changes = [0, 2, 6];
        foreach (uint change in changes)
        {
            byte[] oracle = StunBindingMessage.Request(change);
            Assert.True(StunCodec.TryReadBindingRequest(oracle, out StunMessage? mine, out uint parsed));
            Assert.Equal(change, parsed);
            Assert.Equal(StunCodec.BindingRequest, mine!.MessageType);
            Assert.Equal(oracle.AsSpan(8, 12).ToArray(), mine.TransactionId);
            int n = StunCodec.WriteBindingRequest(buffer, mine.TransactionId, parsed);
            Assert.True(buffer[..n].SequenceEqual(oracle));
        }
    }

    [Fact]
    public void Stun_AddressGoldens_PinnedAgainstTheExistingEncoders()
    {
        IPEndPoint v4 = new(IPAddress.Parse("192.0.2.1"), 12345);
        IPEndPoint v6 = new(IPAddress.Parse("2001:db8::1"), 443);
        byte[] v4Xor = Convert.FromHexString("0001112BE112A643");
        byte[] v4Plain = Convert.FromHexString("00013039C0000201");
        byte[] v6Xor = Convert.FromHexString("000220A90113A9FA000102030405060708090A0A");

        byte[] buffer = new byte[20];
        int n = StunCodec.WriteAddress(buffer, v4, Txid, xor: true);
        Assert.Equal(8, n);
        Assert.Equal(v4Xor, buffer[..n]);
        n = StunCodec.WriteAddress(buffer, v4, Txid, xor: false);
        Assert.Equal(v4Plain, buffer[..n]);
        n = StunCodec.WriteAddress(buffer, v6, Txid, xor: true);
        Assert.Equal(20, n);
        Assert.Equal(v6Xor, buffer[..n]);

        // the pinned bytes are exactly what the existing encoders produce
        Assert.Equal(v4Xor, TurnXorAddress(v4.Address, v4.Port, Txid));
        Assert.Equal(v6Xor, TurnXorAddress(v6.Address, v6.Port, Txid));
        Assert.True(StunTryAddress(v4Xor, Txid, true, out IPEndPoint? viaStun));
        Assert.Equal(v4, viaStun);
        Assert.Equal(v6, TurnDecodeAddress(v6Xor, Txid, true));

        // full binding-response golden: one XOR-MAPPED-ADDRESS, the FakeStunServer shape
        byte[] responseGolden = Convert.FromHexString("0101000C2112A442000102030405060708090A0B002000080001112BE112A643");
        byte[] responseBuffer = new byte[64];
        int m = StunCodec.WriteBindingResponse(responseBuffer, Txid, v4);
        Assert.Equal(32, m);
        Assert.Equal(responseGolden, responseBuffer[..m]);
        Assert.True(StunBindingMessage.TryRead(responseGolden, new IPEndPoint(IPAddress.Parse("192.0.2.10"), 3478), out StunBindingReply? oracle));
        Assert.Equal(v4, oracle!.Mapped);
    }

    [Fact]
    public void Stun_BindingResponse_AcceptsExactlyWhatStunBindingMessageAccepts()
    {
        var rng = new Random(0x5104_0003);
        byte[] txid = new byte[12];
        byte[] buffer = new byte[256];
        IPEndPoint v4Origin = new(IPAddress.Parse("192.0.2.10"), 3478);
        IPEndPoint v6Origin = new(IPAddress.Parse("2001:db8::10"), 3478);
        for (int i = 0; i < 400; i++)
        {
            IPEndPoint origin = i % 5 == 0 ? v6Origin : v4Origin;
            rng.NextBytes(txid);
            IPEndPoint mapped = RandomUsableEndpoint(rng, origin.AddressFamily);
            IPEndPoint? replyOrigin = i % 3 == 0 ? null : origin;
            IPEndPoint? other = i % 2 == 0 ? RandomUsableEndpoint(rng, i % 7 == 0 ? AddressFamily.InterNetworkV6 : origin.AddressFamily) : null;
            int n = StunCodec.WriteBindingResponse(buffer, txid, mapped, replyOrigin, other);
            byte[] bytes = buffer[..n].ToArray();

            Assert.True(StunBindingMessage.TryRead(bytes, origin, out StunBindingReply? oracle), $"iteration {i}");
            Assert.Equal(mapped, oracle!.Mapped);
            Assert.Equal(replyOrigin, oracle.Origin);
            Assert.Equal(other, oracle.Other);

            Assert.True(StunCodec.TryReadBindingResponse(bytes, origin, out StunBindingResult? mine), $"iteration {i}");
            Assert.Equal(oracle.Mapped, mine!.Mapped);
            Assert.Equal(oracle.Origin, mine.Origin);
            Assert.Equal(oracle.Other, mine.Other);
        }

        // XOR-MAPPED wins over MAPPED, identically in both parsers
        IPEndPoint mappedPlain = new(IPAddress.Parse("203.0.113.20"), 1111);
        IPEndPoint mappedXor = new(IPAddress.Parse("203.0.113.21"), 2222);
        byte[] both = Build(StunCodec.BindingSuccessResponse, Txid, Concat(
            AttrBytes(StunCodec.AttrMappedAddress, AddressBytes(mappedPlain, xor: false)),
            AttrBytes(StunCodec.AttrXorMappedAddress, AddressBytes(mappedXor, xor: true))));
        Assert.True(StunBindingMessage.TryRead(both, v4Origin, out StunBindingReply? bothOracle));
        Assert.Equal(mappedXor, bothOracle!.Mapped);
        Assert.True(StunCodec.TryReadBindingResponse(both, v4Origin, out StunBindingResult? bothMine));
        Assert.Equal(mappedXor, bothMine!.Mapped);

        // a repeated attribute of one type must decode identically (SetOnce semantics)
        byte[] identicalDuplicate = Build(StunCodec.BindingSuccessResponse, Txid, Concat(
            AttrBytes(StunCodec.AttrXorMappedAddress, AddressBytes(mappedXor, xor: true)),
            AttrBytes(StunCodec.AttrXorMappedAddress, AddressBytes(mappedXor, xor: true))));
        Assert.True(StunCodec.TryReadBindingResponse(identicalDuplicate, v4Origin, out _));
    }

    [Fact]
    public void Stun_Message_RoundTripsWithPaddingAndUnknownAttributes()
    {
        var rng = new Random(0x5104_0004);
        byte[] buffer = new byte[512];
        byte[] txid = new byte[12];
        for (int i = 0; i < 200; i++)
        {
            rng.NextBytes(txid);
            int count = rng.Next(0, 6);
            StunAttribute[] attributes = new StunAttribute[count];
            for (int a = 0; a < count; a++)
            {
                attributes[a] = new StunAttribute((ushort)rng.Next(0, 0x10000), RandomBytes(rng, rng.Next(0, 25)));
            }

            ushort type = (ushort)rng.Next(0, 0x4000);
            int n = StunCodec.WriteMessage(buffer, type, txid, attributes);
            Assert.Equal(0, n % 4);
            Assert.True(StunCodec.TryReadMessage(buffer.AsSpan(0, n), out StunMessage? parsed));
            Assert.Equal(type, parsed!.MessageType);
            Assert.Equal(txid, parsed.TransactionId);
            Assert.Equal(count, parsed.Attributes.Length);
            for (int a = 0; a < count; a++)
            {
                Assert.Equal(attributes[a].Type, parsed.Attributes[a].Type);
                Assert.Equal(attributes[a].Value, parsed.Attributes[a].Value);
            }
        }
    }

    [Fact]
    public void Stun_RejectsNonCanonicalForms()
    {
        IPEndPoint origin = new(IPAddress.Parse("192.0.2.10"), 3478);
        IPEndPoint mapped = new(IPAddress.Parse("203.0.113.9"), 40000);
        IPEndPoint alternate = new(IPAddress.Parse("203.0.113.99"), 40001);
        byte[] buffer = new byte[128];
        int n = StunCodec.WriteBindingResponse(buffer, Txid, mapped, origin, null);
        byte[] good = buffer[..n].ToArray();
        Assert.True(StunCodec.TryReadBindingResponse(good, origin, out StunBindingResult? ok));
        Assert.Equal(mapped, ok!.Mapped);

        // header-level rejections
        Assert.False(StunCodec.TryReadMessage([], out _));
        Assert.False(StunCodec.TryReadMessage(good[..19], out _));
        byte[] badCookie = (byte[])good.Clone();
        badCookie[5] ^= 0xFF;
        Assert.False(StunCodec.TryReadMessage(badCookie, out _));
        byte[] trailing = [.. good, 0];
        Assert.False(StunCodec.TryReadMessage(trailing, out _));
        Assert.False(StunCodec.TryReadMessage(Build(0x0101, Txid, [0, 0]), out _));
        Assert.False(StunCodec.TryReadMessage(Build(0xC101, Txid, []), out _));

        // attribute-level rejections: declared length beyond the body, stray tail bytes
        Assert.False(StunCodec.TryReadMessage(Build(0x0101, Txid, Concat(AttrBytes(0x7FFF, new byte[8]), [0x00, 0x19, 0x00, 0x28])), out _));
        Assert.False(StunCodec.TryReadMessage(Build(0x0101, Txid, Concat(AttrBytes(0x7FFF, new byte[4]), [1, 2, 3])), out _));

        // non-zero padding is rejected here while the existing parser accepts it (pinned divergence)
        byte[] dirtyPadding = Build(0x0101, Txid, Concat(
            AttrBytes(StunCodec.AttrXorMappedAddress, AddressBytes(mapped, xor: true)),
            AttrBytes(0x7FFF, [1, 2, 3, 4, 5], paddingByte: 0xEE)));
        Assert.False(StunCodec.TryReadMessage(dirtyPadding, out _));
        Assert.True(StunBindingMessage.TryRead(dirtyPadding, origin, out StunBindingReply? lax));
        Assert.Equal(mapped, lax!.Mapped);

        // address-value rejections
        Assert.False(StunCodec.TryReadAddress([0, 1, 0x30, 0x39, 192, 0, 2, 1, 0], Txid, false, out _));
        Assert.False(StunCodec.TryReadAddress([1, 1, 0x30, 0x39, 192, 0, 2, 1], Txid, false, out _));
        Assert.False(StunCodec.TryReadAddress([0, 3, 0x30, 0x39, 192, 0, 2, 1], Txid, false, out _));
        Assert.False(StunCodec.TryReadAddress(AddressBytes(mapped, xor: true), Txid[..11], true, out _));

        // binding-response semantic rejections, all mirrored from StunBindingMessage
        Assert.False(StunCodec.TryReadBindingResponse(Response(Txid, alternate, otherOnly: true), origin, out _));
        Assert.False(StunCodec.TryReadBindingResponse(Response(Txid, new IPEndPoint(IPAddress.Parse("203.0.113.9"), 0)), origin, out _));
        Assert.False(StunCodec.TryReadBindingResponse(Response(Txid, new IPEndPoint(IPAddress.Any, 40000)), origin, out _));
        Assert.False(StunCodec.TryReadBindingResponse(Response(Txid, new IPEndPoint(IPAddress.Parse("224.0.0.1"), 40000)), origin, out _));
        Assert.False(StunCodec.TryReadBindingResponse(
            Response(Txid, new IPEndPoint(IPAddress.Parse("ff02::1"), 40000)), new IPEndPoint(IPAddress.Parse("2001:db8::10"), 3478), out _));
        Assert.False(StunCodec.TryReadBindingResponse(Response(Txid, mapped, new IPEndPoint(IPAddress.Parse("192.0.2.99"), 3478)), origin, out _));
        Assert.False(StunCodec.TryReadBindingResponse(Response(Txid, new IPEndPoint(IPAddress.Parse("2001:db8::1"), 40000)), origin, out _));
        byte[] conflictingDuplicate = Build(StunCodec.BindingSuccessResponse, Txid, Concat(
            AttrBytes(StunCodec.AttrXorMappedAddress, AddressBytes(mapped, xor: true)),
            AttrBytes(StunCodec.AttrXorMappedAddress, AddressBytes(alternate, xor: true))));
        Assert.False(StunCodec.TryReadBindingResponse(conflictingDuplicate, origin, out _));

        // binding-request shape rejections: only {}, {change=2}, {change=6} exist
        Assert.False(StunCodec.TryReadBindingRequest(Build(0x0001, Txid, AttrBytes(StunCodec.AttrChangeRequest, U32Bytes(0))), out _, out _));
        Assert.False(StunCodec.TryReadBindingRequest(Build(0x0001, Txid, AttrBytes(StunCodec.AttrChangeRequest, U32Bytes(4))), out _, out _));
        Assert.False(StunCodec.TryReadBindingRequest(Build(0x0001, Txid, AttrBytes(StunCodec.AttrChangeRequest, [0, 0])), out _, out _));
        Assert.False(StunCodec.TryReadBindingRequest(Build(0x0001, Txid, Concat(AttrBytes(StunCodec.AttrChangeRequest, U32Bytes(2)), AttrBytes(0x7FFF, []))), out _, out _));
        Assert.False(StunCodec.TryReadBindingRequest(Build(0x0101, Txid, []), out _, out _));
    }

    [Fact]
    public void Stun_TotalityFuzz_NeverThrows()
    {
        var rng = new Random(0x5104_0001);
        byte[] scratch = new byte[64];
        byte[] valid = new byte[512];
        byte[] txid = new byte[12];
        IPEndPoint origin = new(IPAddress.Parse("192.0.2.10"), 3478);
        for (int i = 0; i < 200_000; i++)
        {
            switch (rng.Next(4))
            {
                case 0:
                {
                    int length = rng.Next(0, 65);
                    rng.NextBytes(scratch.AsSpan(0, length));
                    ExerciseStun(scratch.AsSpan(0, length), origin);
                    break;
                }
                case 1:
                {
                    int n = GenerateStun(rng, valid, txid);
                    ExerciseStun(valid.AsSpan(0, n), origin, requireMessage: true);
                    break;
                }
                case 2:
                {
                    int n = GenerateStun(rng, valid, txid);
                    valid[rng.Next(n)] ^= (byte)(1 << rng.Next(8));
                    ExerciseStun(valid.AsSpan(0, n), origin);
                    break;
                }
                default:
                {
                    int n = GenerateStun(rng, valid, txid);
                    ExerciseStun(valid.AsSpan(0, rng.Next(n + 1)), origin);
                    break;
                }
            }
        }
    }

    private static void ExerciseStun(ReadOnlySpan<byte> input, IPEndPoint origin, bool requireMessage = false)
    {
        bool ok = StunCodec.TryReadMessage(input, out StunMessage? message);
        if (requireMessage) Assert.True(ok);
        if (ok)
        {
            Assert.Equal(12, message!.TransactionId.Length);
            int total = 20;
            foreach (StunAttribute attribute in message.Attributes)
            {
                total += 4 + attribute.Value.Length;
                Assert.True(total <= input.Length);
            }

            if (StunCodec.TryReadBindingRequest(input, out StunMessage? request, out uint change))
            {
                Assert.Equal(StunCodec.BindingRequest, request!.MessageType);
                Assert.True(change is 0 or 2 or 6);
            }
        }

        if (StunCodec.TryReadBindingResponse(input, origin, out StunBindingResult? reply))
        {
            Assert.NotNull(reply!.Mapped);
            Assert.True(reply.Mapped.Port > 0);
            Assert.Equal(origin.AddressFamily, reply.Mapped.AddressFamily);
            if (reply.Origin is not null) Assert.Equal(origin, reply.Origin);
        }

        if (StunCodec.TryReadAddress(input, Txid, true, out IPEndPoint? address))
        {
            Assert.NotNull(address);
        }
    }

    private static int GenerateStun(Random rng, Span<byte> buffer, byte[] txid)
    {
        rng.NextBytes(txid);
        ushort type = rng.Next(6) switch
        {
            0 => StunCodec.BindingRequest,
            1 => StunCodec.BindingSuccessResponse,
            2 => 0x0011,
            3 => 0x0111,
            _ => (ushort)rng.Next(0, 0x4000),
        };
        int count = rng.Next(0, 6);
        StunAttribute[] attributes = new StunAttribute[count];
        for (int i = 0; i < count; i++)
        {
            switch (rng.Next(7))
            {
                case 0: attributes[i] = new StunAttribute(StunCodec.AttrXorMappedAddress, RandomStunAddressValue(rng, txid, xor: true)); break;
                case 1: attributes[i] = new StunAttribute(StunCodec.AttrMappedAddress, RandomStunAddressValue(rng, txid, xor: false)); break;
                case 2: attributes[i] = new StunAttribute(StunCodec.AttrChangeRequest, U32Bytes((uint)rng.Next(8))); break;
                case 3: attributes[i] = new StunAttribute(StunCodec.AttrResponseOrigin, RandomStunAddressValue(rng, txid, xor: false)); break;
                case 4: attributes[i] = new StunAttribute(StunCodec.AttrOtherAddress, RandomStunAddressValue(rng, txid, xor: true)); break;
                case 5: attributes[i] = new StunAttribute(0x7FFF, RandomBytes(rng, rng.Next(0, 17))); break;
                default: attributes[i] = new StunAttribute((ushort)rng.Next(0, 0x10000), RandomBytes(rng, rng.Next(0, 21))); break;
            }
        }

        return StunCodec.WriteMessage(buffer, type, txid, attributes);
    }

    // ---- TURN ----

    [Fact]
    public void Turn_AllocateRequest_GoldenBytes_MatchTurnClientShapes()
    {
        byte[] golden = Convert.FromHexString("000300082112A442000102030405060708090A0B0019000411000000");
        byte[] buffer = new byte[28];
        Assert.Equal(28, TurnCodec.WriteAllocateRequest(buffer, Txid));
        Assert.Equal(golden, buffer);
        Assert.Equal(TurnCodec.MethodAllocate, BinaryPrimitives.ReadUInt16BigEndian(golden));
        Assert.True(TurnCodec.IsSuccessResponse((ushort)(TurnCodec.MethodAllocate | TurnCodec.ClassSuccess)));
        Assert.True(TurnCodec.IsErrorResponse((ushort)(TurnCodec.MethodAllocate | TurnCodec.ClassError)));
        Assert.False(TurnCodec.IsErrorResponse(BinaryPrimitives.ReadUInt16BigEndian(golden)));
        Assert.False(TurnCodec.IsSuccessResponse(TurnCodec.MethodDataIndication));

        Assert.True(TurnCodec.TryReadMessage(golden, out TurnMessage? message));
        Assert.Equal(TurnCodec.MethodAllocate, message!.MessageType);
        Assert.True(message.HasAttribute(TurnCodec.AttrRequestedTransport));
        Assert.True(message.TryGetAttribute(TurnCodec.AttrRequestedTransport, out TurnAttribute transport));
        Assert.True(TurnCodec.TryReadRequestedTransport(transport.Value, out byte protocol));
        Assert.Equal(TurnCodec.TransportUdp, protocol);

        List<(ushort Type, byte[] Value)> oracle = TurnAttributes(golden);
        Assert.Single(oracle);
        Assert.Equal(TurnCodec.AttrRequestedTransport, oracle[0].Type);
        Assert.Equal(new byte[] { 17, 0, 0, 0 }, oracle[0].Value);
    }

    [Fact]
    public void Turn_Indications_GoldenBytes_MirrorTurnClientComposer()
    {
        IPEndPoint peer = new(IPAddress.Parse("198.51.100.7"), 5000);
        byte[] sendGolden = Convert.FromHexString("001600142112A442000102030405060708090A0B001200080001329AE721C0450013000268690000");
        byte[] dataGolden = Convert.FromHexString("001700142112A442000102030405060708090A0B001200080001329AE721C0450013000268690000");
        byte[] buffer = new byte[40];
        Assert.Equal(40, TurnCodec.WriteSendIndication(buffer, Txid, peer, "hi"u8));
        Assert.Equal(sendGolden, buffer);
        Assert.Equal(40, TurnCodec.WriteDataIndication(buffer, Txid, peer, "hi"u8));
        Assert.Equal(dataGolden, buffer);

        // byte-exact against the production composer: Message + Attr + XorAddress
        byte[] oracle = TurnBuildMessage(TurnCodec.MethodSendIndication, Txid, Concat(
            TurnAttr(TurnCodec.AttrXorPeerAddress, TurnXorAddress(peer.Address, peer.Port, Txid)),
            TurnAttr(TurnCodec.AttrData, "hi"u8)));
        Assert.Equal(oracle, sendGolden);

        // parse back through my codec, and the peer address through both decoders
        Assert.True(TurnCodec.TryReadDataIndication(dataGolden, out IPEndPoint? from, out byte[]? payload));
        Assert.Equal(peer, from);
        Assert.Equal("hi"u8.ToArray(), payload);
        Assert.True(TurnCodec.TryReadMessage(sendGolden, out TurnMessage? message));
        Assert.Equal(TurnCodec.MethodSendIndication, message!.MessageType);
        Assert.True(message.TryGetAttribute(TurnCodec.AttrXorPeerAddress, out TurnAttribute xorPeer));
        Assert.True(TurnCodec.TryReadAddress(xorPeer.Value, message.TransactionId, true, out IPEndPoint? decoded));
        Assert.Equal(peer, decoded);
        Assert.Equal(peer, TurnDecodeAddress(xorPeer.Value, message.TransactionId, true));
    }

    [Fact]
    public void Turn_Header_MatchesTurnClientHeaderWriter()
    {
        byte[] oracle = new byte[36];
        TurnHeader(oracle, TurnCodec.MethodAllocate, 16, Txid);
        byte[] mine = new byte[36];
        int n = TurnCodec.WriteMessage(mine, TurnCodec.MethodAllocate, Txid, [new TurnAttribute(0x7FFF, new byte[12])]);
        Assert.Equal(36, n);
        Assert.Equal(oracle[..20], mine[..20]);
    }

    [Fact]
    public void Turn_Message_IsByteExactWithTurnClientBuilder_AndRoundTrips()
    {
        var rng = new Random(0x704A_0001);
        byte[] buffer = new byte[1024];
        byte[] txid = new byte[12];
        for (int i = 0; i < 300; i++)
        {
            rng.NextBytes(txid);
            ushort type = rng.Next(5) switch
            {
                0 => TurnCodec.MethodAllocate,
                1 => (ushort)(TurnCodec.MethodRefresh | TurnCodec.ClassSuccess),
                2 => (ushort)(TurnCodec.MethodCreatePermission | TurnCodec.ClassError),
                3 => TurnCodec.MethodSendIndication,
                _ => TurnCodec.MethodDataIndication,
            };
            int count = rng.Next(0, 5);
            byte[][] oracleParts = new byte[count][];
            TurnAttribute[] attributes = new TurnAttribute[count];
            for (int a = 0; a < count; a++)
            {
                ushort attrType = rng.Next(5) switch
                {
                    0 => TurnCodec.AttrRealm,
                    1 => TurnCodec.AttrNonce,
                    2 => TurnCodec.AttrData,
                    3 => TurnCodec.AttrUsername,
                    _ => (ushort)rng.Next(0, 0x10000),
                };
                byte[] value = RandomBytes(rng, rng.Next(0, 21));
                if (attrType == TurnCodec.AttrMessageIntegrity && value.Length != 20)
                {
                    attrType = 0x7FFF; // the canonical writer pins MESSAGE-INTEGRITY to 20 bytes
                }

                oracleParts[a] = TurnAttr(attrType, value);
                attributes[a] = new TurnAttribute(attrType, value);
            }

            byte[] oracle = TurnBuildMessage(type, txid, Concat(oracleParts));
            int n = TurnCodec.WriteMessage(buffer, type, txid, attributes);
            Assert.Equal(oracle.Length, n);
            Assert.True(buffer[..n].SequenceEqual(oracle));

            List<(ushort Type, byte[] Value)> walked = TurnAttributes(oracle);
            Assert.Equal(count, walked.Count);
            for (int a = 0; a < count; a++)
            {
                Assert.Equal(attributes[a].Type, walked[a].Type);
                Assert.Equal(attributes[a].Value, walked[a].Value);
            }

            Assert.True(TurnCodec.TryReadMessage(oracle, out TurnMessage? parsed));
            Assert.Equal(type, parsed!.MessageType);
            Assert.Equal(txid, parsed.TransactionId);
            Assert.Equal(count, parsed.Attributes.Length);
            for (int a = 0; a < count; a++)
            {
                Assert.Equal(attributes[a].Type, parsed.Attributes[a].Type);
                Assert.Equal(attributes[a].Value, parsed.Attributes[a].Value);
            }
        }
    }

    [Fact]
    public void Turn_AddressCodec_IsByteExactWithTurnClientBothWays()
    {
        var rng = new Random(0x704A_0002);
        byte[] txid = new byte[12];
        byte[] buffer = new byte[20];
        for (int i = 0; i < 400; i++)
        {
            rng.NextBytes(txid);
            IPEndPoint endpoint = RandomAnyEndpoint(rng);
            byte[] oracle = TurnXorAddress(endpoint.Address, endpoint.Port, txid);
            int n = TurnCodec.WriteAddress(buffer, endpoint, txid, xor: true);
            Assert.Equal(oracle.Length, n);
            Assert.True(buffer[..n].SequenceEqual(oracle));

            Assert.True(TurnCodec.TryReadAddress(oracle, txid, true, out IPEndPoint? mine));
            Assert.Equal(endpoint, mine);
            Assert.True(StunCodec.TryReadAddress(oracle, txid, true, out IPEndPoint? viaStun));
            Assert.Equal(endpoint, viaStun);
            Assert.True(StunTryAddress(oracle, txid, true, out IPEndPoint? viaStunOracle));
            Assert.Equal(endpoint, viaStunOracle);
            Assert.Equal(endpoint, TurnDecodeAddress(oracle, txid, true));
        }
    }

    [Fact]
    public void Turn_AuthenticatedRequest_MirrorsRequestLayout_AndPassesTryAuthenticateResponse()
    {
        byte[] key = MD5.HashData("user:pinhole-test:pass"u8);
        TurnAttribute[] attributes =
        [
            new TurnAttribute(TurnCodec.AttrUsername, "user"u8.ToArray()),
            new TurnAttribute(TurnCodec.AttrRealm, "pinhole-test"u8.ToArray()),
            new TurnAttribute(TurnCodec.AttrNonce, "n1"u8.ToArray()),
        ];
        byte[] buffer = new byte[600];
        int placeholderLength = TurnCodec.WriteAuthenticatedRequest(buffer, TurnCodec.MethodAllocate, Txid, attributes, new byte[20]);
        byte[] placeholder = buffer[..placeholderLength].ToArray();
        int integrityOffset = placeholder.Length - 24;
        byte[] hmac = HMACSHA1.HashData(key, placeholder.AsSpan(0, integrityOffset));
        int n = TurnCodec.WriteAuthenticatedRequest(buffer, TurnCodec.MethodAllocate, Txid, attributes, hmac);
        byte[] signed = buffer[..n].ToArray();

        // framing mirrors TurnClient.Request: integrity last, header length covers it
        Assert.Equal(TurnCodec.AttrMessageIntegrity, BinaryPrimitives.ReadUInt16BigEndian(signed.AsSpan(integrityOffset)));
        Assert.Equal(20, BinaryPrimitives.ReadUInt16BigEndian(signed.AsSpan(integrityOffset + 2)));
        Assert.Equal(signed.Length - 20, BinaryPrimitives.ReadUInt16BigEndian(signed.AsSpan(2)));
        Assert.Equal(0, signed.Length % 4);

        // the production authenticator accepts my bytes and rejects a wrong key
        object pending = NewPendingRequest(TurnCodec.MethodAllocate, key);
        Assert.True(TurnTryAuthenticate(signed, pending, out byte[]? accepted));
        Assert.Equal(signed, accepted);
        Assert.False(TurnTryAuthenticate(signed, NewPendingRequest(TurnCodec.MethodAllocate, MD5.HashData("wrong"u8)), out byte[]? rejected));
        Assert.Null(rejected);
        Assert.Throws<ArgumentException>(() => TurnCodec.WriteAuthenticatedRequest(buffer, TurnCodec.MethodAllocate, Txid, attributes, new byte[18]));
    }

    [Fact]
    public void Turn_ErrorResponses_AgreeWithTurnClientErrorParsers()
    {
        byte[] signedError = Build((ushort)(TurnCodec.MethodRefresh | TurnCodec.ClassError), Txid, Concat(
            AttrBytes(TurnCodec.AttrErrorCode, ErrorCodeValue(437, "Allocation Mismatch"u8)),
            AttrBytes(TurnCodec.AttrRealm, "pinhole-test"u8),
            AttrBytes(TurnCodec.AttrNonce, "n1"u8),
            AttrBytes(TurnCodec.AttrMessageIntegrity, new byte[20])));

        Assert.True(TurnCodec.TryReadMessage(signedError, out TurnMessage? message));
        Assert.True(TurnCodec.IsErrorResponse(message!.MessageType));
        Assert.True(message.HasAttribute(TurnCodec.AttrMessageIntegrity));
        Assert.True(message.TryGetAttribute(TurnCodec.AttrErrorCode, out TurnAttribute errorAttribute));
        Assert.True(TurnCodec.TryReadErrorCode(errorAttribute.Value, out int code, out string reason));
        Assert.Equal(437, code);
        Assert.Equal("Allocation Mismatch", reason);

        Assert.True(TurnIsError(signedError, 437));
        Assert.False(TurnIsError(signedError, 401));
        TargetInvocationException wrapped = Assert.Throws<TargetInvocationException>(() => TurnThrowIfError(signedError));
        TurnRejectException reject = Assert.IsType<TurnRejectException>(wrapped.InnerException);
        Assert.Equal(437, reject.Code);

        // unsigned 401 challenge flows through the challenge path, identically
        byte[] challenge = Build((ushort)(TurnCodec.MethodAllocate | TurnCodec.ClassError), Txid, Concat(
            AttrBytes(TurnCodec.AttrErrorCode, ErrorCodeValue(401, "Unauthorized"u8)),
            AttrBytes(TurnCodec.AttrRealm, "pinhole-test"u8),
            AttrBytes(TurnCodec.AttrNonce, "n1"u8)));
        Assert.True(TurnIsError(challenge, 401));
        TargetInvocationException challengeThrow = Assert.Throws<TargetInvocationException>(() => TurnThrowIfError(challenge));
        InvalidOperationException challengeException = Assert.IsType<InvalidOperationException>(challengeThrow.InnerException);
        Assert.Contains("401", challengeException.Message);

        // odd-length reason phrases exercise attribute padding
        byte[] paddedError = Build((ushort)(TurnCodec.MethodRefresh | TurnCodec.ClassError), Txid,
            AttrBytes(TurnCodec.AttrErrorCode, ErrorCodeValue(401, "denied"u8)));
        Assert.True(TurnCodec.TryReadMessage(paddedError, out TurnMessage? padded));
        Assert.True(padded!.TryGetAttribute(TurnCodec.AttrErrorCode, out TurnAttribute paddedAttribute));
        Assert.True(TurnCodec.TryReadErrorCode(paddedAttribute.Value, out int paddedCode, out string paddedReason));
        Assert.Equal(401, paddedCode);
        Assert.Equal("denied", paddedReason);
    }

    [Fact]
    public void Turn_RejectsNonCanonicalForms_AndPinsExistingParserLeniency()
    {
        byte[] buffer = new byte[64];
        int n = TurnCodec.WriteAllocateRequest(buffer, Txid);
        byte[] allocateRequest = buffer[..n].ToArray();
        Assert.True(TurnCodec.TryReadMessage(allocateRequest, out _));

        // header-level rejections
        Assert.False(TurnCodec.TryReadMessage([], out _));
        Assert.False(TurnCodec.TryReadMessage(allocateRequest[..19], out _));
        byte[] badCookie = (byte[])allocateRequest.Clone();
        badCookie[4] ^= 1;
        Assert.False(TurnCodec.TryReadMessage(badCookie, out _));
        byte[] trailing = [.. allocateRequest, 0, 0, 0, 0];
        Assert.False(TurnCodec.TryReadMessage(trailing, out _));
        Assert.False(TurnCodec.TryReadMessage(Build(0x0003, Txid, [0, 0]), out _));
        Assert.False(TurnCodec.TryReadMessage(Build(0x8003, Txid, []), out _));
        Assert.False(TurnCodec.TryReadMessage(Build(0x0003, Txid, Concat(AttrBytes(0x7FFF, new byte[4]), [1, 2, 3])), out _));
        Assert.False(TurnCodec.TryReadMessage(Build(0x0003, Txid, AttrBytes(TurnCodec.AttrMessageIntegrity, new byte[18])), out _));

        // non-zero padding is rejected here; TurnClient's walker ignores it (pinned divergence)
        byte[] dirtyPadding = Build(0x0003, Txid, AttrBytes(TurnCodec.AttrRealm, [1, 2, 3, 4, 5], paddingByte: 0xFF));
        Assert.False(TurnCodec.TryReadMessage(dirtyPadding, out _));
        List<(ushort Type, byte[] Value)> dirtyWalked = TurnAttributes(dirtyPadding);
        Assert.Single(dirtyWalked);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, dirtyWalked[0].Value);

        // an attribute claiming more bytes than the body carries is rejected here;
        // TurnClient's walker clamps to whatever is available (pinned divergence)
        byte[] clamped = Build(0x0003, Txid, [0x00, 0x19, 0x00, 0x06, 17, 0, 0, 0]);
        Assert.False(TurnCodec.TryReadMessage(clamped, out _));
        List<(ushort Type, byte[] Value)> clampedWalked = TurnAttributes(clamped);
        Assert.Single(clampedWalked);
        Assert.Equal(new byte[] { 17, 0, 0, 0 }, clampedWalked[0].Value);

        // typed-attribute rejections
        Assert.False(TurnCodec.TryReadRequestedTransport([17, 0, 0, 0, 0], out _));
        Assert.False(TurnCodec.TryReadRequestedTransport([17, 1, 0, 0], out _));
        Assert.True(TurnCodec.TryReadRequestedTransport([17, 0, 0, 0], out byte protocol));
        Assert.Equal(TurnCodec.TransportUdp, protocol);
        Assert.False(TurnCodec.TryReadErrorCode([0, 0, 4], out _, out _));
        Assert.False(TurnCodec.TryReadErrorCode([0, 1, 4, 37], out _, out _));
        Assert.True(TurnCodec.TryReadErrorCode([0, 0, 4, 37], out int code, out string reason));
        Assert.Equal(437, code);
        Assert.Equal("", reason);
        Assert.False(TurnCodec.TryReadLifetime([0, 0, 0x02, 0x58, 0], out _));
        Assert.True(TurnCodec.TryReadLifetime([0, 0, 0x02, 0x58], out uint lifetime));
        Assert.Equal(600u, lifetime);

        // address rejections: trailing bytes, unknown family, reserved byte;
        // TurnClient.DecodeAddress tolerates the trailing bytes (pinned divergence)
        byte[] longAddress = [0, 1, 0x30, 0x39, 198, 51, 100, 7, 0];
        Assert.False(TurnCodec.TryReadAddress(longAddress, Txid, true, out _));
        Assert.NotNull(TurnDecodeAddress(longAddress, Txid, true));
        Assert.False(TurnCodec.TryReadAddress([0, 7, 0, 0, 1, 2, 3, 4], Txid, true, out _));
        Assert.False(TurnCodec.TryReadAddress([1, 1, 0x30, 0x39, 198, 51, 100, 7], Txid, true, out _));

        // data-indication shape rejections
        IPEndPoint peer = new(IPAddress.Parse("198.51.100.7"), 5000);
        Assert.False(TurnCodec.TryReadDataIndication(Build(TurnCodec.MethodDataIndication, Txid, AttrBytes(TurnCodec.AttrXorPeerAddress, TurnPeerAddressBytes(peer))), out _, out _));
        Assert.False(TurnCodec.TryReadDataIndication(Build(TurnCodec.MethodDataIndication, Txid, AttrBytes(TurnCodec.AttrData, "x"u8)), out _, out _));
        Assert.False(TurnCodec.TryReadDataIndication(Build(TurnCodec.MethodDataIndication, Txid, AttrBytes(TurnCodec.AttrXorPeerAddress, [0, 7, 0, 0, 1, 2, 3, 4])), out _, out _));
        Assert.False(TurnCodec.TryReadDataIndication(Build(TurnCodec.MethodSendIndication, Txid, Concat(AttrBytes(TurnCodec.AttrXorPeerAddress, TurnPeerAddressBytes(peer)), AttrBytes(TurnCodec.AttrData, "x"u8))), out _, out _));

        // an empty DATA attribute is present, not absent — mirrors the receive loop
        byte[] emptyData = Build(TurnCodec.MethodDataIndication, Txid, Concat(AttrBytes(TurnCodec.AttrXorPeerAddress, TurnPeerAddressBytes(peer)), AttrBytes(TurnCodec.AttrData, [])));
        Assert.True(TurnCodec.TryReadDataIndication(emptyData, out IPEndPoint? from, out byte[]? payload));
        Assert.Equal(peer, from);
        Assert.Empty(payload!);

        // the last XOR-PEER-ADDRESS wins, mirroring the receive loop's foreach
        IPEndPoint lastPeer = new(IPAddress.Parse("198.51.100.8"), 5001);
        byte[] duplicated = Build(TurnCodec.MethodDataIndication, Txid, Concat(
            AttrBytes(TurnCodec.AttrXorPeerAddress, TurnPeerAddressBytes(peer)),
            AttrBytes(TurnCodec.AttrXorPeerAddress, TurnPeerAddressBytes(lastPeer)),
            AttrBytes(TurnCodec.AttrData, "x"u8)));
        Assert.True(TurnCodec.TryReadDataIndication(duplicated, out IPEndPoint? winner, out _));
        Assert.Equal(lastPeer, winner);
    }

    [Fact]
    public void Turn_TotalityFuzz_NeverThrows()
    {
        var rng = new Random(0x704A_0003);
        byte[] scratch = new byte[80];
        byte[] valid = new byte[512];
        byte[] txid = new byte[12];
        for (int i = 0; i < 200_000; i++)
        {
            switch (rng.Next(4))
            {
                case 0:
                {
                    int length = rng.Next(0, 81);
                    rng.NextBytes(scratch.AsSpan(0, length));
                    ExerciseTurn(scratch.AsSpan(0, length));
                    break;
                }
                case 1:
                {
                    int n = GenerateTurn(rng, valid, txid);
                    ExerciseTurn(valid.AsSpan(0, n), requireMessage: true);
                    break;
                }
                case 2:
                {
                    int n = GenerateTurn(rng, valid, txid);
                    valid[rng.Next(n)] ^= (byte)(1 << rng.Next(8));
                    ExerciseTurn(valid.AsSpan(0, n));
                    break;
                }
                default:
                {
                    int n = GenerateTurn(rng, valid, txid);
                    ExerciseTurn(valid.AsSpan(0, rng.Next(n + 1)));
                    break;
                }
            }
        }
    }

    private static void ExerciseTurn(ReadOnlySpan<byte> input, bool requireMessage = false)
    {
        bool ok = TurnCodec.TryReadMessage(input, out TurnMessage? message);
        if (requireMessage) Assert.True(ok);
        if (ok)
        {
            Assert.Equal(12, message!.TransactionId.Length);
            int total = 20;
            foreach (TurnAttribute attribute in message.Attributes)
            {
                total += 4 + attribute.Value.Length;
                Assert.True(total <= input.Length);
            }
        }

        if (TurnCodec.TryReadDataIndication(input, out IPEndPoint? peer, out byte[]? payload))
        {
            Assert.NotNull(peer);
            Assert.NotNull(payload);
        }

        if (TurnCodec.TryReadAddress(input, Txid, true, out IPEndPoint? address))
        {
            Assert.NotNull(address);
        }
    }

    private static int GenerateTurn(Random rng, Span<byte> buffer, byte[] txid)
    {
        rng.NextBytes(txid);
        ushort type = rng.Next(6) switch
        {
            0 => TurnCodec.MethodAllocate,
            1 => (ushort)(TurnCodec.MethodAllocate | TurnCodec.ClassSuccess),
            2 => (ushort)(TurnCodec.MethodRefresh | TurnCodec.ClassError),
            3 => TurnCodec.MethodCreatePermission,
            4 => TurnCodec.MethodSendIndication,
            _ => TurnCodec.MethodDataIndication,
        };
        int count = rng.Next(0, 6);
        TurnAttribute[] attributes = new TurnAttribute[count];
        for (int i = 0; i < count; i++)
        {
            switch (rng.Next(9))
            {
                case 0: attributes[i] = new TurnAttribute(TurnCodec.AttrXorPeerAddress, RandomTurnAddressValue(rng, txid, xor: true)); break;
                case 1: attributes[i] = new TurnAttribute(TurnCodec.AttrXorRelayedAddress, RandomTurnAddressValue(rng, txid, xor: true)); break;
                case 2: attributes[i] = new TurnAttribute(TurnCodec.AttrXorMappedAddress, RandomTurnAddressValue(rng, txid, xor: true)); break;
                case 3: attributes[i] = new TurnAttribute(TurnCodec.AttrMappedAddress, RandomTurnAddressValue(rng, txid, xor: false)); break;
                case 4: attributes[i] = new TurnAttribute(TurnCodec.AttrData, RandomBytes(rng, rng.Next(0, 49))); break;
                case 5: attributes[i] = new TurnAttribute(TurnCodec.AttrUsername, RandomBytes(rng, rng.Next(0, 13))); break;
                case 6: attributes[i] = new TurnAttribute(TurnCodec.AttrLifetime, U32Bytes((uint)rng.Next(int.MaxValue))); break;
                case 7: attributes[i] = new TurnAttribute(TurnCodec.AttrMessageIntegrity, new byte[20]); break;
                default:
                {
                    ushort randomType = (ushort)rng.Next(0, 0x10000);
                    byte[] randomValue = RandomBytes(rng, rng.Next(0, 17));
                    if (randomType == TurnCodec.AttrMessageIntegrity && randomValue.Length != 20)
                    {
                        randomType = 0x7FFF; // the canonical writer pins MESSAGE-INTEGRITY to 20 bytes
                    }

                    attributes[i] = new TurnAttribute(randomType, randomValue);
                    break;
                }
            }
        }

        return TurnCodec.WriteMessage(buffer, type, txid, attributes);
    }

    // ---- shared fixtures ----

    private static byte[] Build(ushort type, ReadOnlySpan<byte> txid, ReadOnlySpan<byte> body)
    {
        byte[] message = new byte[20 + body.Length];
        BinaryPrimitives.WriteUInt16BigEndian(message, type);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), (ushort)body.Length);
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(4), Cookie);
        txid.CopyTo(message.AsSpan(8));
        body.CopyTo(message.AsSpan(20));
        return message;
    }

    private static byte[] AttrBytes(ushort type, ReadOnlySpan<byte> value, byte paddingByte = 0)
    {
        int padded = (value.Length + 3) & ~3;
        byte[] attribute = new byte[4 + padded];
        BinaryPrimitives.WriteUInt16BigEndian(attribute, type);
        BinaryPrimitives.WriteUInt16BigEndian(attribute.AsSpan(2), (ushort)value.Length);
        value.CopyTo(attribute.AsSpan(4));
        if (paddingByte != 0 && padded > value.Length)
        {
            attribute.AsSpan(4 + value.Length, padded - value.Length).Fill(paddingByte);
        }

        return attribute;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int length = 0;
        foreach (byte[] part in parts)
        {
            length += part.Length;
        }

        byte[] result = new byte[length];
        int position = 0;
        foreach (byte[] part in parts)
        {
            part.CopyTo(result, position);
            position += part.Length;
        }

        return result;
    }

    private static byte[] RandomBytes(Random rng, int length)
    {
        byte[] bytes = new byte[length];
        rng.NextBytes(bytes);
        return bytes;
    }

    private static byte[] U32Bytes(uint value)
    {
        byte[] bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }

    private static IPEndPoint RandomAnyEndpoint(Random rng)
    {
        byte[] raw = new byte[rng.Next(2) == 0 ? 4 : 16];
        rng.NextBytes(raw);
        return new IPEndPoint(new IPAddress(raw), rng.Next(65536));
    }

    private static IPEndPoint RandomUsableEndpoint(Random rng, AddressFamily family)
    {
        if (family == AddressFamily.InterNetworkV6)
        {
            byte[] raw = new byte[16];
            rng.NextBytes(raw);
            raw[0] = (byte)rng.Next(1, 255); // never the unspecified address, never multicast
            return new IPEndPoint(new IPAddress(raw), rng.Next(1, 65536));
        }

        byte[] v4 = new byte[4];
        v4[0] = (byte)rng.Next(1, 224); // unicast IPv4 first octet, matching StunBindingMessage.Usable
        rng.NextBytes(v4.AsSpan(1));
        return new IPEndPoint(new IPAddress(v4), rng.Next(1, 65536));
    }

    private static byte[] AddressBytes(IPEndPoint endpoint, bool xor)
    {
        byte[] value = new byte[20];
        int n = StunCodec.WriteAddress(value, endpoint, Txid, xor);
        return value[..n];
    }

    private static byte[] TurnPeerAddressBytes(IPEndPoint peer) => AddressBytes(peer, xor: true);

    private static byte[] RandomStunAddressValue(Random rng, ReadOnlySpan<byte> txid, bool xor)
    {
        byte[] value = new byte[20];
        int n = StunCodec.WriteAddress(value, RandomAnyEndpoint(rng), txid, xor);
        return value[..n];
    }

    private static byte[] RandomTurnAddressValue(Random rng, ReadOnlySpan<byte> txid, bool xor)
    {
        byte[] value = new byte[20];
        int n = TurnCodec.WriteAddress(value, RandomAnyEndpoint(rng), txid, xor);
        return value[..n];
    }

    private static byte[] ErrorCodeValue(int code, ReadOnlySpan<byte> reasonUtf8)
    {
        byte[] value = new byte[4 + reasonUtf8.Length];
        int n = TurnCodec.WriteErrorCode(value, code, reasonUtf8);
        return value[..n];
    }

    private static byte[] Response(byte[] txid, IPEndPoint mapped, IPEndPoint? origin = null, bool otherOnly = false)
    {
        byte[] mappedAttribute = AttrBytes(StunCodec.AttrXorMappedAddress, AddressBytes(mapped, xor: true));
        if (otherOnly)
        {
            return Build(StunCodec.BindingSuccessResponse, txid, AttrBytes(StunCodec.AttrOtherAddress, AddressBytes(mapped, xor: false)));
        }

        if (origin is null)
        {
            return Build(StunCodec.BindingSuccessResponse, txid, mappedAttribute);
        }

        return Build(StunCodec.BindingSuccessResponse, txid, Concat(
            mappedAttribute, AttrBytes(StunCodec.AttrResponseOrigin, AddressBytes(origin, xor: false))));
    }
}
