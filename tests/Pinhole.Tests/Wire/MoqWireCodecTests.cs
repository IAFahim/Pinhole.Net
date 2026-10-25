// Pinhole.Moq builds with EnablePreviewFeatures on net8.0, so its internal
// MoqWriter/MoqReader/MoqStreamWire carry RequiresPreviewFeatures; this test
// file is the opted-in consumer for the differential oracle.
#pragma warning disable CA2252

using Pinhole.Moq;
using Pinhole.Wire;
using Xunit;

namespace Pinhole.Tests.Wire;

// Three shapes per the WirePrimitives exemplar, plus the differential oracle
// against Pinhole.Moq's internal MoqWriter/MoqReader/MoqStreamWire (reachable
// through InternalsVisibleTo):
//   1. golden byte vectors + Write -> TryRead round trips for every form,
//   2. a >= 200k seeded totality fuzz (bit flips, truncations, raw bytes) that
//      also checks the read-then-write identity on accepted inputs,
//   3. explicit non-canonical rejections (padded varints, bad UTF-8, oversized
//      counts, trailing bytes, invalid stream-type bits),
//   4. differentials: byte-exact and value-exact agreement both directions,
//      and the documented non-minimal-varint acceptance divergence.
public sealed class MoqWireCodecTests
{
    private const ulong BigId = 151_288_809_941_952_652UL; // RFC 9000 8-byte sample

    // ---------- golden vectors + round trips ----------

    [Fact]
    public void ControlFrame_GoldenBytes()
    {
        // varint type + fixed two-byte big-endian length + payload
        byte[] framed = [0x0a, 0x00, 0x01, 0x2a];
        Assert.True(MoqWireCodec.TryReadControlFrame(framed, out var frame));
        Assert.Equal(MoqControlTypes.Unsubscribe, frame.Type);
        Assert.Equal(1, frame.PayloadLength);
        Assert.Equal(4, frame.Consumed);
        Assert.True(frame.Payload(framed).SequenceEqual((ReadOnlySpan<byte>)[0x2a]));

        // empty payload, multi-byte type varint, and concatenated frames
        Span<byte> buffer = new byte[16];
        Assert.Equal(3, MoqWireCodec.WriteControlFrame(buffer, MoqControlTypes.Unsubscribe, []));
        Assert.True(buffer[..3].SequenceEqual((ReadOnlySpan<byte>)[0x0a, 0x00, 0x00]));
        Assert.Equal(7, MoqWireCodec.WriteControlFrame(buffer, 0x4000, [0xaa])); // 4-byte type varint
        Assert.True(MoqWireCodec.TryReadControlFrame(buffer[..7], out frame));
        Assert.Equal(0x4000UL, frame.Type);
        Assert.Equal(1, frame.PayloadLength);

        int first = MoqWireCodec.WriteControlFrame(buffer, 0x0a, [0x2a]);
        int second = MoqWireCodec.WriteControlFrame(buffer[first..], 0x15, [0x41, 0x2c]);
        Assert.True(MoqWireCodec.TryReadControlFrame(buffer[..(first + second)], out frame));
        Assert.Equal(4, frame.Consumed);
        Assert.True(MoqWireCodec.TryReadControlFrame(buffer[frame.Consumed..], out frame));
        Assert.Equal(MoqControlTypes.MaxRequestId, frame.Type);
    }

    [Fact]
    public void Unsubscribe_GoldenRoundTrip()
    {
        byte[] golden = [0x0a, 0x00, 0x01, 0x2a];
        Assert.True(MoqWireCodec.TryReadUnsubscribe(golden, out var message, out int consumed));
        Assert.Equal(42UL, message.RequestId);
        Assert.Equal(4, consumed);
        Span<byte> buffer = new byte[16];
        Assert.Equal(4, MoqWireCodec.WriteUnsubscribe(buffer, new MoqUnsubscribe(42)));
        Assert.True(buffer[..4].SequenceEqual(golden));

        byte[] big = [0x0a, 0x00, 0x08, 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        Assert.True(MoqWireCodec.TryReadUnsubscribe(big, out message, out consumed));
        Assert.Equal(BigId, message.RequestId);
        Assert.Equal(11, consumed);
        Assert.Equal(11, MoqWireCodec.WriteUnsubscribe(buffer, new MoqUnsubscribe(BigId)));
        Assert.True(buffer[..11].SequenceEqual(big));
    }

    [Fact]
    public void MaxRequestId_GoldenRoundTrip()
    {
        byte[] golden = [0x15, 0x00, 0x02, 0x41, 0x2c]; // 300 as a 2-byte varint
        Assert.True(MoqWireCodec.TryReadMaxRequestId(golden, out var message, out int consumed));
        Assert.Equal(300UL, message.Maximum);
        Assert.Equal(5, consumed);
        Span<byte> buffer = new byte[16];
        Assert.Equal(5, MoqWireCodec.WriteMaxRequestId(buffer, new MoqMaxRequestId(300)));
        Assert.True(buffer[..5].SequenceEqual(golden));
    }

    [Fact]
    public void GoAway_GoldenRoundTrip()
    {
        byte[] golden = [0x10, 0x00, 0x08, 0x07, 0x73, 0x74, 0x61, 0x67, 0x69, 0x6e, 0x67];
        Assert.True(MoqWireCodec.TryReadGoAway(golden, out var message, out int consumed));
        Assert.Equal("staging", message.Reason);
        Assert.Equal(11, consumed);
        Span<byte> buffer = new byte[32];
        Assert.Equal(11, MoqWireCodec.WriteGoAway(buffer, new MoqGoAway("staging")));
        Assert.True(buffer[..11].SequenceEqual(golden));
    }

    [Fact]
    public void Subscribe_GoldenRoundTrip()
    {
        byte[] golden =
        [
            0x03, 0x00, 0x13,
            0x05,                             // request id 5
            0x01, 0x02, 0x6e, 0x73,           // namespace: one element "ns"
            0x04, 0x64, 0x65, 0x6d, 0x6f,     // track name "demo"
            0x03,                             // 3 parameters
            0x20, 0x40, 0x80,                 // key 0x20 (number) = 128
            0x01, 0x01, 0x02,                 // key 0x21 (blob) = [0x02]
            0x01, 0x01,                       // key 0x22 (number) = 1
        ];
        Assert.True(MoqWireCodec.TryReadSubscribe(golden, out var message, out int consumed));
        Assert.Equal(5UL, message.RequestId);
        Assert.Equal("ns", message.TrackNamespace);
        Assert.Equal("demo", message.TrackName);
        Assert.Equal(3, message.Parameters.Length);
        Assert.Equal(0x20UL, message.Parameters[0].Key);
        Assert.False(message.Parameters[0].IsBlob);
        Assert.Equal(128UL, message.Parameters[0].Number);
        Assert.Equal(0x21UL, message.Parameters[1].Key);
        Assert.True(message.Parameters[1].IsBlob);
        Assert.True(message.Parameters[1].Blob!.SequenceEqual((ReadOnlySpan<byte>)[0x02]));
        Assert.Equal(0x22UL, message.Parameters[2].Key);
        Assert.Equal(1UL, message.Parameters[2].Number);
        Assert.Equal(golden.Length, consumed);

        var rewritten = new MoqSubscribe(5, "ns", "demo",
            [new MoqParameter(0x20, 128UL), new MoqParameter(0x21, new byte[] { 0x02 }), new MoqParameter(0x22, 1UL)]);
        Span<byte> buffer = new byte[64];
        Assert.Equal(golden.Length, MoqWireCodec.WriteSubscribe(buffer, rewritten));
        Assert.True(buffer[..golden.Length].SequenceEqual(golden));
    }

    [Fact]
    public void SubscribeOk_GoldenRoundTrip_WithAndWithoutExtensions()
    {
        byte[] plain = [0x04, 0x00, 0x03, 0x09, 0x11, 0x00];
        Assert.True(MoqWireCodec.TryReadSubscribeOk(plain, out var message, out int consumed));
        Assert.Equal(9UL, message.RequestId);
        Assert.Equal(0x11UL, message.TrackAlias);
        Assert.Empty(message.Parameters);
        Assert.Empty(message.Extensions);
        Assert.Equal(6, consumed);

        byte[] withExtensions = [0x04, 0x00, 0x06, 0x09, 0x11, 0x00, 0x03, 0x01, 0xaa];
        Assert.True(MoqWireCodec.TryReadSubscribeOk(withExtensions, out message, out consumed));
        Assert.Single(message.Extensions);
        Assert.Equal(3UL, message.Extensions[0].Key);
        Assert.True(message.Extensions[0].Blob!.SequenceEqual((ReadOnlySpan<byte>)[0xaa]));
        Assert.Equal(9, consumed);

        Span<byte> buffer = new byte[32];
        Assert.Equal(6, MoqWireCodec.WriteSubscribeOk(buffer, new MoqSubscribeOk(9, 0x11, [], [])));
        Assert.True(buffer[..6].SequenceEqual(plain));
        Assert.Equal(9, MoqWireCodec.WriteSubscribeOk(buffer,
            new MoqSubscribeOk(9, 0x11, [], [new MoqParameter(3, new byte[] { 0xaa })])));
        Assert.True(buffer[..9].SequenceEqual(withExtensions));
    }

    [Fact]
    public void SubscribeError_GoldenRoundTrip()
    {
        byte[] golden = [0x05, 0x00, 0x06, 0x09, 0x10, 0x00, 0x02, 0x6e, 0x6f];
        Assert.True(MoqWireCodec.TryReadSubscribeError(golden, out var message, out int consumed));
        Assert.Equal(9UL, message.RequestId);
        Assert.Equal(0x10UL, message.ErrorCode);
        Assert.Equal(0UL, message.TrackAlias);
        Assert.Equal("no", message.Reason);
        Assert.Equal(9, consumed);
        Span<byte> buffer = new byte[32];
        Assert.Equal(9, MoqWireCodec.WriteSubscribeError(buffer, new MoqSubscribeError(9, 0x10, 0, "no")));
        Assert.True(buffer[..9].SequenceEqual(golden));
    }

    [Fact]
    public void SubscribeDone_GoldenRoundTrip()
    {
        byte[] golden = [0x0b, 0x00, 0x04, 0x09, 0x00, 0x00, 0x00];
        Assert.True(MoqWireCodec.TryReadSubscribeDone(golden, out var message, out int consumed));
        Assert.Equal(9UL, message.RequestId);
        Assert.Equal(0UL, message.Status);
        Assert.Equal(string.Empty, message.Reason);
        Assert.Equal(7, consumed);
        Span<byte> buffer = new byte[16];
        Assert.Equal(7, MoqWireCodec.WriteSubscribeDone(buffer, new MoqSubscribeDone(9, 0, 0, "")));
        Assert.True(buffer[..7].SequenceEqual(golden));
    }

    [Fact]
    public void SubscribeUpdate_GoldenRoundTrip()
    {
        byte[] golden = [0x02, 0x00, 0x03, 0x04, 0x07, 0x00];
        Assert.True(MoqWireCodec.TryReadSubscribeUpdate(golden, out var message, out int consumed));
        Assert.Equal(4UL, message.RequestId);
        Assert.Equal(7UL, message.ExistingRequestId);
        Assert.Empty(message.Parameters);
        Assert.Equal(6, consumed);
        Span<byte> buffer = new byte[16];
        Assert.Equal(6, MoqWireCodec.WriteSubscribeUpdate(buffer, new MoqSubscribeUpdate(4, 7, [])));
        Assert.True(buffer[..6].SequenceEqual(golden));
    }

    [Fact]
    public void Announce_GoldenRoundTrip()
    {
        byte[] golden = [0x06, 0x00, 0x06, 0x01, 0x01, 0x02, 0x6e, 0x73, 0x00];
        Assert.True(MoqWireCodec.TryReadAnnounce(golden, out var message, out int consumed));
        Assert.Equal(1UL, message.RequestId);
        Assert.Equal("ns", message.TrackNamespace);
        Assert.Empty(message.Parameters);
        Assert.Equal(9, consumed);
        Span<byte> buffer = new byte[16];
        Assert.Equal(9, MoqWireCodec.WriteAnnounce(buffer, new MoqAnnounce(1, "ns", [])));
        Assert.True(buffer[..9].SequenceEqual(golden));
    }

    [Fact]
    public void AnnounceOk_GoldenRoundTrip()
    {
        byte[] golden = [0x07, 0x00, 0x02, 0x2a, 0x00];
        Assert.True(MoqWireCodec.TryReadAnnounceOk(golden, out var message, out int consumed));
        Assert.Equal(42UL, message.RequestId);
        Assert.Empty(message.Parameters);
        Assert.Equal(5, consumed);
        Span<byte> buffer = new byte[16];
        Assert.Equal(5, MoqWireCodec.WriteAnnounceOk(buffer, new MoqAnnounceOk(42, [])));
        Assert.True(buffer[..5].SequenceEqual(golden));
    }

    [Fact]
    public void Publish_GoldenRoundTrip()
    {
        byte[] golden = [0x1d, 0x00, 0x0c, 0x01, 0x01, 0x02, 0x6e, 0x73, 0x04, 0x64, 0x65, 0x6d, 0x6f, 0x03, 0x00];
        Assert.True(MoqWireCodec.TryReadPublish(golden, out var message, out int consumed));
        Assert.Equal(1UL, message.RequestId);
        Assert.Equal("ns", message.TrackNamespace);
        Assert.Equal("demo", message.TrackName);
        Assert.Equal(3UL, message.TrackAlias);
        Assert.Empty(message.Parameters);
        Assert.Equal(15, consumed);
        Span<byte> buffer = new byte[32];
        Assert.Equal(15, MoqWireCodec.WritePublish(buffer, new MoqPublish(1, "ns", "demo", 3, [])));
        Assert.True(buffer[..15].SequenceEqual(golden));
    }

    [Fact]
    public void PublishOk_GoldenRoundTrip()
    {
        byte[] golden = [0x1e, 0x00, 0x02, 0x2a, 0x00];
        Assert.True(MoqWireCodec.TryReadPublishOk(golden, out var message, out int consumed));
        Assert.Equal(42UL, message.RequestId);
        Assert.Equal(5, consumed);
        Span<byte> buffer = new byte[16];
        Assert.Equal(5, MoqWireCodec.WritePublishOk(buffer, new MoqPublishOk(42, [])));
        Assert.True(buffer[..5].SequenceEqual(golden));
    }

    [Fact]
    public void Setup_GoldenRoundTrip_ClientAndServer()
    {
        byte[] client = [0x20, 0x00, 0x08, 0x02, 0x02, 0x41, 0x00, 0x03, 0x02, 0x63, 0x66];
        Assert.True(MoqWireCodec.TryReadSetup(client, out var message, out int consumed));
        Assert.Equal(MoqControlTypes.ClientSetup, message.Type);
        Assert.Equal(2, message.Parameters.Length);
        Assert.Equal(2UL, message.Parameters[0].Key);
        Assert.Equal(256UL, message.Parameters[0].Number);
        Assert.Equal(5UL, message.Parameters[1].Key);
        Assert.True(message.Parameters[1].Blob!.SequenceEqual("cf"u8.ToArray()));
        Assert.Equal(11, consumed);

        byte[] server = [0x21, 0x00, 0x04, 0x01, 0x02, 0x41, 0x00];
        Assert.True(MoqWireCodec.TryReadSetup(server, out message, out _));
        Assert.Equal(MoqControlTypes.ServerSetup, message.Type);
        Assert.Single(message.Parameters);

        Span<byte> buffer = new byte[32];
        Assert.Equal(11, MoqWireCodec.WriteSetup(buffer,
            new MoqSetup(MoqControlTypes.ClientSetup, [new MoqParameter(2, 256UL), new MoqParameter(5, "cf"u8.ToArray())])));
        Assert.True(buffer[..11].SequenceEqual(client));
        Assert.Equal(7, MoqWireCodec.WriteSetup(buffer, new MoqSetup(MoqControlTypes.ServerSetup, [new MoqParameter(2, 256UL)])));
        Assert.True(buffer[..7].SequenceEqual(server));
    }

    [Fact]
    public void Helpers_GoldenRoundTrip()
    {
        Assert.True(MoqWireCodec.TryReadTrackName([0x04, 0x64, 0x65, 0x6d, 0x6f], out string name, out int consumed));
        Assert.Equal("demo", name);
        Assert.Equal(5, consumed);

        Assert.True(MoqWireCodec.TryReadNamespace([0x01, 0x02, 0x6e, 0x73], out string trackNamespace, out consumed));
        Assert.Equal("ns", trackNamespace);
        Assert.Equal(4, consumed);

        byte[] parameters = [0x02, 0x02, 0x41, 0x00, 0x03, 0x02, 0x63, 0x66];
        Assert.True(MoqWireCodec.TryReadParameters(parameters, out var read, out consumed));
        Assert.Equal(2, read.Length);
        Assert.Equal(consumed, parameters.Length);

        Assert.True(MoqWireCodec.TryReadExtensionBlock([0x03, 0x01, 0xaa], out var extensions, out consumed));
        Assert.Single(extensions);
        Assert.Equal(3, consumed);

        Span<byte> buffer = new byte[32];
        Assert.Equal(5, MoqWireCodec.WriteTrackName(buffer, "demo"));
        Assert.True(buffer[..5].SequenceEqual((ReadOnlySpan<byte>)[0x04, 0x64, 0x65, 0x6d, 0x6f]));
        Assert.Equal(4, MoqWireCodec.WriteNamespace(buffer, "ns"));
        Assert.True(buffer[..4].SequenceEqual((ReadOnlySpan<byte>)[0x01, 0x02, 0x6e, 0x73]));
        Assert.Equal(8, MoqWireCodec.WriteParameters(buffer,
            [new MoqParameter(2, 256UL), new MoqParameter(5, "cf"u8.ToArray())]));
        Assert.True(buffer[..8].SequenceEqual(parameters));
        Assert.Equal(3, MoqWireCodec.WriteExtensionBlock(buffer, [new MoqParameter(3, new byte[] { 0xaa })]));
        Assert.True(buffer[..3].SequenceEqual((ReadOnlySpan<byte>)[0x03, 0x01, 0xaa]));

        // multibyte UTF-8 survives with byte-exact re-encoding
        Assert.True(MoqWireCodec.TryReadTrackName([0x03, 0xe4, 0xb8, 0xad], out name, out _));
        Assert.Equal("\u4e2d", name);
        Assert.Equal(4, MoqWireCodec.WriteTrackName(buffer, "\u4e2d"));
        Assert.True(buffer[..4].SequenceEqual((ReadOnlySpan<byte>)[0x03, 0xe4, 0xb8, 0xad]));
    }

    [Fact]
    public void StreamHeader_GoldenRoundTrip()
    {
        // the exact header shape the SessionPumpTests fixture and
        // CloudflareMoqClient.SendObjectAsync use: 0x18 = object stream,
        // no subgroup id, priority byte present
        byte[] plain = [0x18, 0x01, 0x07, 0x80];
        Assert.True(MoqWireCodec.TryReadStreamHeader(plain, out var header, out int consumed));
        Assert.Equal(0x18UL, header.StreamType);
        Assert.Equal(1UL, header.TrackAlias);
        Assert.Equal(7UL, header.GroupId);
        Assert.False(header.HasSubgroupId);
        Assert.True(header.HasPriority);
        Assert.Equal(0x80, header.Priority);
        Assert.Equal(4, consumed);

        byte[] subgroup = [0x14, 0x01, 0x02, 0x03, 0x80]; // (type & 0x6) == 4 -> subgroup id
        Assert.True(MoqWireCodec.TryReadStreamHeader(subgroup, out header, out consumed));
        Assert.True(header.HasSubgroupId);
        Assert.Equal(3UL, header.SubgroupId);
        Assert.True(header.HasPriority);
        Assert.Equal(5, consumed);

        byte[] noPriority = [0x38, 0x05, 0x06]; // (type & 0x20) != 0 -> no priority byte
        Assert.True(MoqWireCodec.TryReadStreamHeader(noPriority, out header, out consumed));
        Assert.False(header.HasPriority);
        Assert.Equal(3, consumed);

        Span<byte> buffer = new byte[16];
        Assert.Equal(4, MoqWireCodec.WriteStreamHeader(buffer, new MoqStreamHeader(0x18, 1, 7, 0, 0x80)));
        Assert.True(buffer[..4].SequenceEqual(plain));
        Assert.Equal(5, MoqWireCodec.WriteStreamHeader(buffer, new MoqStreamHeader(0x14, 1, 2, 3, 0x80)));
        Assert.True(buffer[..5].SequenceEqual(subgroup));
        Assert.Equal(3, MoqWireCodec.WriteStreamHeader(buffer, new MoqStreamHeader(0x38, 5, 6, 0, 0)));
        Assert.True(buffer[..3].SequenceEqual(noPriority));
    }

    [Fact]
    public void ObjectHeader_GoldenRoundTrip()
    {
        byte[] plain = [0x00, 0x01];
        Assert.True(MoqWireCodec.TryReadObjectHeader(plain, extensionsPresent: false, out var header, out int consumed));
        Assert.Equal(0UL, header.ObjectId);
        Assert.Null(header.ExtensionBytes);
        Assert.Equal(1UL, header.PayloadLength);
        Assert.False(header.HasStatus);
        Assert.Equal(2, consumed);

        byte[] withExtensions = [0x00, 0x03, 0x01, 0x01, 0xaa, 0x01];
        Assert.True(MoqWireCodec.TryReadObjectHeader(withExtensions, extensionsPresent: true, out header, out consumed));
        Assert.True(header.ExtensionBytes!.SequenceEqual((ReadOnlySpan<byte>)[0x01, 0x01, 0xaa]));
        Assert.Equal(1UL, header.PayloadLength);
        Assert.Equal(6, consumed);

        byte[] emptyWithStatus = [0x00, 0x00, 0x00];
        Assert.True(MoqWireCodec.TryReadObjectHeader(emptyWithStatus, extensionsPresent: false, out header, out consumed));
        Assert.Equal(0UL, header.PayloadLength);
        Assert.True(header.HasStatus);
        Assert.Equal(0UL, header.Status);
        Assert.Equal(3, consumed);

        byte[] endMarker = [0x05, 0x00, 0x03]; // nonzero status: the pump skips these objects
        Assert.True(MoqWireCodec.TryReadObjectHeader(endMarker, extensionsPresent: false, out header, out consumed));
        Assert.Equal(3UL, header.Status);
        Assert.Equal(3, consumed);

        Span<byte> buffer = new byte[16];
        Assert.Equal(2, MoqWireCodec.WriteObjectHeader(buffer, new MoqObjectHeader(0, null, 1, 0), extensionsPresent: false));
        Assert.True(buffer[..2].SequenceEqual(plain));
        Assert.Equal(6, MoqWireCodec.WriteObjectHeader(buffer,
            new MoqObjectHeader(0, [0x01, 0x01, 0xaa], 1, 0), extensionsPresent: true));
        Assert.True(buffer[..6].SequenceEqual(withExtensions));
        Assert.Equal(3, MoqWireCodec.WriteObjectHeader(buffer, new MoqObjectHeader(5, null, 0, 3), extensionsPresent: false));
        Assert.True(buffer[..3].SequenceEqual(endMarker));
    }

    // ---------- non-canonical rejections ----------

    [Fact]
    public void NonMinimalVarints_RejectedInEveryFieldPosition()
    {
        // padded type varint
        Assert.False(MoqWireCodec.TryReadControlFrame([0x40, 0x0a, 0x00, 0x01, 0x2a], out _));
        Assert.False(MoqWireCodec.TryReadUnsubscribe([0x40, 0x0a, 0x00, 0x01, 0x2a], out _, out _));
        // padded request id inside the payload
        Assert.False(MoqWireCodec.TryReadUnsubscribe([0x0a, 0x00, 0x02, 0x40, 0x2a], out _, out _));
        // padded track-name length
        Assert.False(MoqWireCodec.TryReadTrackName([0x40, 0x01, 0x61], out _, out _));
        // padded namespace count
        Assert.False(MoqWireCodec.TryReadNamespace([0x40, 0x01, 0x00], out _, out _));
        // padded parameter count
        Assert.False(MoqWireCodec.TryReadParameters([0x40, 0x00], out _, out _));
        // padded stream type
        Assert.False(MoqWireCodec.TryReadStreamHeader([0x40, 0x40, 0x01, 0x02, 0x80], out _, out _));
        // padded object id
        Assert.False(MoqWireCodec.TryReadObjectHeader([0x40, 0x00, 0x01], false, out _, out _));
        // padded payload-length varint inside an object header
        Assert.False(MoqWireCodec.TryReadObjectHeader([0x00, 0x40, 0x01], false, out _, out _));
    }

    [Fact]
    public void TrackName_InvalidUtf8_OrOversized_Rejected()
    {
        Assert.False(MoqWireCodec.TryReadTrackName([0x01, 0xff], out _, out _)); // stray continuation
        Assert.False(MoqWireCodec.TryReadTrackName([0x02, 0xc0, 0x80], out _, out _)); // overlong 2-byte
        Assert.False(MoqWireCodec.TryReadTrackName([0x03, 0xe0, 0x80, 0x80], out _, out _)); // overlong 3-byte
        Assert.False(MoqWireCodec.TryReadTrackName([0x03, 0xed, 0xa0, 0x80], out _, out _)); // lone surrogate
        Assert.False(MoqWireCodec.TryReadTrackName([0x04, 0xf4, 0x90, 0x80, 0x80], out _, out _)); // > U+10FFFF
        Assert.False(MoqWireCodec.TryReadTrackName([0x02, 0xc3, 0x28], out _, out _)); // bad continuation
        Assert.False(MoqWireCodec.TryReadTrackName([0x02, 0xe2, 0x82], out _, out _)); // truncated sequence
        Assert.False(MoqWireCodec.TryReadTrackName([0x05, 0x61], out _, out _)); // length beyond remaining
    }

    [Fact]
    public void TrackName_MaxLengthBoundary()
    {
        var valid = new byte[2 + 4096];
        valid[0] = 0x50; // varint 4096 = [0x50, 0x00]
        valid[1] = 0x00;
        valid.AsSpan(2).Fill(0x61);
        Assert.True(MoqWireCodec.TryReadTrackName(valid, out string name, out int consumed));
        Assert.Equal(4096, name.Length);
        Assert.Equal(valid.Length, consumed);

        var tooLong = new byte[2 + 4097];
        tooLong[0] = 0x50; // varint 4097 = [0x50, 0x01]
        tooLong[1] = 0x01;
        tooLong.AsSpan(2).Fill(0x61);
        Assert.False(MoqWireCodec.TryReadTrackName(tooLong, out _, out _));
    }

    [Fact]
    public void Namespace_CountNotOne_Rejected()
    {
        Assert.False(MoqWireCodec.TryReadNamespace([0x00, 0x01, 0x61], out _, out _));
        Assert.False(MoqWireCodec.TryReadNamespace([0x02, 0x01, 0x61, 0x01, 0x62], out _, out _));
    }

    [Fact]
    public void ControlFrame_TruncatedLengthOrOversizedPayload_Rejected()
    {
        Assert.False(MoqWireCodec.TryReadControlFrame([], out _)); // no type varint
        Assert.False(MoqWireCodec.TryReadControlFrame([0x40], out _)); // truncated type varint
        Assert.False(MoqWireCodec.TryReadControlFrame([0x0a, 0x00], out _)); // truncated u16 length
        Assert.False(MoqWireCodec.TryReadControlFrame([0x0a, 0x00, 0x05, 0x2a], out _)); // payload shorter than declared
        Assert.False(MoqWireCodec.TryReadControlFrame([0x0a, 0x40, 0x00, 0x01, 0x2a], out _)); // padded type
    }

    [Fact]
    public void UnknownType_NotParseableAsAMessage()
    {
        // Framing tolerates any type (callers slice with it), but the client's
        // reader throws "Unsupported MoQ control type" — so no known-message
        // TryRead accepts one, and IsKnown reports false.
        byte[] unknown = [0x0f, 0x00, 0x01, 0x2a];
        Assert.True(MoqWireCodec.TryReadControlFrame(unknown, out var frame));
        Assert.Equal(0x0fUL, frame.Type);
        Assert.False(MoqControlTypes.IsKnown(0x0f));
        Assert.False(MoqWireCodec.TryReadSetup(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadSubscribe(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadSubscribeUpdate(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadSubscribeOk(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadSubscribeError(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadSubscribeDone(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadAnnounce(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadAnnounceOk(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadPublish(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadPublishOk(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadUnsubscribe(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadMaxRequestId(unknown, out _, out _));
        Assert.False(MoqWireCodec.TryReadGoAway(unknown, out _, out _));

        // a known type in the wrong message slot is equally rejected
        Assert.False(MoqWireCodec.TryReadUnsubscribe([0x0b, 0x00, 0x04, 0x09, 0x00, 0x00, 0x00], out _, out _));
    }

    [Fact]
    public void StrictMessages_RejectTrailingBytes()
    {
        // trailing byte inside the payload (the client calls MoqReader.End())
        Assert.False(MoqWireCodec.TryReadUnsubscribe([0x0a, 0x00, 0x02, 0x2a, 0x00], out _, out _));
        Assert.False(MoqWireCodec.TryReadAnnounceOk([0x07, 0x00, 0x02, 0x2a, 0x03], out _, out _));
        Assert.False(MoqWireCodec.TryReadMaxRequestId([0x15, 0x00, 0x03, 0x41, 0x2c, 0x00], out _, out _));
        Assert.False(MoqWireCodec.TryReadGoAway([0x10, 0x00, 0x02, 0x01, 0x61, 0x00], out _, out _));
        // a whole second frame after the first (slice with TryReadControlFrame instead)
        Assert.False(MoqWireCodec.TryReadUnsubscribe([0x0a, 0x00, 0x01, 0x2a, 0x0a, 0x00, 0x01, 0x2a], out _, out _));
    }

    [Fact]
    public void SubscribeOk_ExtensionBlockRules()
    {
        // well-formed extensions after the parameters are accepted (unique to SUBSCRIBE_OK)
        Assert.True(MoqWireCodec.TryReadSubscribeOk([0x04, 0x00, 0x06, 0x09, 0x11, 0x00, 0x03, 0x01, 0xaa], out _, out _));
        // malformed extension pairs in the tail are rejected
        Assert.False(MoqWireCodec.TryReadSubscribeOk([0x04, 0x00, 0x05, 0x09, 0x11, 0x00, 0x03, 0x01], out _, out _));
        Assert.False(MoqWireCodec.TryReadSubscribeOk([0x04, 0x00, 0x04, 0x09, 0x11, 0x00, 0xff], out _, out _));
    }

    [Fact]
    public void Parameters_NonCanonicalForms_Rejected()
    {
        // count above 128 ([0x40, 0x81] is the minimal encoding of 129)
        Assert.False(MoqWireCodec.TryReadParameters([0x40, 0x81], out _, out _));
        // duplicate keys (delta 0 after the first)
        Assert.False(MoqWireCodec.TryReadParameters([0x02, 0x04, 0x00, 0x00, 0x00], out _, out _));
        // odd key whose blob length is beyond the remaining bytes
        Assert.False(MoqWireCodec.TryReadParameters([0x01, 0x03, 0x05, 0x61], out _, out _));
        // cumulative key above the varint range (delta VarintMax then +1)
        Span<byte> huge = new byte[16];
        int w = WirePrimitives.WriteVarint(huge, 2);
        w += WirePrimitives.WriteVarint(huge[w..], WirePrimitives.VarintMax);
        w += WirePrimitives.WriteVarint(huge[w..], 0); // even key -> number value
        w += WirePrimitives.WriteVarint(huge[w..], 1);
        Assert.False(MoqWireCodec.TryReadParameters(huge[..w], out _, out _));

        // exactly 128 pairs is the accepted maximum
        Span<byte> buffer = new byte[1024];
        var maximum = new MoqParameter[128];
        for (int i = 0; i < 128; i++)
        {
            maximum[i] = (i % 2 == 0)
                ? new MoqParameter((ulong)(2 * i + 1), Array.Empty<byte>())
                : new MoqParameter((ulong)(2 * i + 2), (ulong)(i + 1));
        }

        int written = MoqWireCodec.WriteParameters(buffer, maximum);
        Assert.True(MoqWireCodec.TryReadParameters(buffer[..written], out var parsed, out _));
        Assert.Equal(128, parsed.Length);
    }

    [Fact]
    public void ExtensionBlock_NonCanonicalForms_Rejected()
    {
        // dangling key delta with no value
        Assert.False(MoqWireCodec.TryReadExtensionBlock([0x03], out _, out _));
        // blob length beyond the block
        Assert.False(MoqWireCodec.TryReadExtensionBlock([0x03, 0x02, 0xaa], out _, out _));
        // duplicate keys (1 then delta 0)
        Assert.False(MoqWireCodec.TryReadExtensionBlock([0x01, 0x00, 0x00, 0x00], out _, out _));
        // truncated 4-byte sequence
        Assert.False(MoqWireCodec.TryReadExtensionBlock([0x80, 0x00], out _, out _));
        // empty block is fine
        Assert.True(MoqWireCodec.TryReadExtensionBlock([], out var empty, out int consumed));
        Assert.Empty(empty);
        Assert.Equal(0, consumed);
    }

    [Fact]
    public void StreamHeader_TypeBitRules()
    {
        // type >= 0x40 (0x40 0x40 is the minimal encoding of 64)
        Assert.False(MoqWireCodec.TryReadStreamHeader([0x40, 0x40, 0x01, 0x02, 0x80], out _, out _));
        // marker bit 0x10 missing
        Assert.False(MoqWireCodec.TryReadStreamHeader([0x08, 0x01, 0x02, 0x80], out _, out _));
        // both bits of 0x6 set
        Assert.False(MoqWireCodec.TryReadStreamHeader([0x16, 0x01, 0x02, 0x80], out _, out _));
        // subgroup id required ((type & 0x6) == 4) but truncated
        Assert.False(MoqWireCodec.TryReadStreamHeader([0x14, 0x01, 0x02], out _, out _));
        // priority byte required ((type & 0x20) == 0) but missing
        Assert.False(MoqWireCodec.TryReadStreamHeader([0x18, 0x01, 0x02], out _, out _));
        Assert.False(MoqWireCodec.TryReadStreamHeader([], out _, out _));
    }

    [Fact]
    public void ObjectHeader_NonCanonicalForms_Rejected()
    {
        // extension length above 65535 (the pump's ushort cap)
        Assert.False(MoqWireCodec.TryReadObjectHeader([0x00, 0x80, 0x01, 0x00, 0x00], true, out _, out _));
        // extension length beyond the remaining bytes
        Assert.False(MoqWireCodec.TryReadObjectHeader([0x00, 0x64], true, out _, out _));
        // malformed extension block (dangling delta)
        Assert.False(MoqWireCodec.TryReadObjectHeader([0x00, 0x01, 0x01, 0x01], true, out _, out _));
        // payload length above 65536 (CloudflareMoqClient.MaximumObjectBytes)
        Assert.False(MoqWireCodec.TryReadObjectHeader([0x00, 0x80, 0x01, 0x00, 0x01], false, out _, out _));
        Assert.True(MoqWireCodec.TryReadObjectHeader([0x00, 0x80, 0x01, 0x00, 0x00], false, out _, out _)); // 65536 exactly
        // zero payload length requires a status varint
        Assert.False(MoqWireCodec.TryReadObjectHeader([0x00, 0x00], false, out _, out _));
        // truncated object id
        Assert.False(MoqWireCodec.TryReadObjectHeader([0x80], false, out _, out _));
    }

    // ---------- write-side validation ----------

    [Fact]
    public void Write_ArgumentValidation()
    {
        var tiny = new byte[2];
        Assert.Throws<ArgumentException>(() => MoqWireCodec.WriteUnsubscribe(tiny, new MoqUnsubscribe(42)));

        var buffer = new byte[80_000];
        Assert.Throws<ArgumentOutOfRangeException>(() => MoqWireCodec.WriteTrackName(buffer, new string('a', 4097)));
        Assert.Throws<ArgumentOutOfRangeException>(() => MoqWireCodec.WriteParameters(buffer, TooManyParameters()));
        Assert.Throws<ArgumentException>(() => MoqWireCodec.WriteParameters(buffer, [new MoqParameter(5, 1UL), new MoqParameter(4, 1UL)]));
        Assert.Throws<ArgumentException>(() => MoqWireCodec.WriteParameters(buffer, [new MoqParameter(2, new byte[] { 1 })]));
        Assert.Throws<ArgumentException>(() => MoqWireCodec.WriteParameters(buffer, [new MoqParameter(3, null!)]));
        Assert.Throws<ArgumentOutOfRangeException>(() => MoqWireCodec.WriteControlFrame(buffer, WirePrimitives.VarintMax + 1, []));
        Assert.Throws<ArgumentOutOfRangeException>(() => MoqWireCodec.WriteControlFrame(buffer, 0x0a, new byte[65_536]));
        Assert.Throws<ArgumentOutOfRangeException>(() => MoqWireCodec.WriteSetup(buffer, new MoqSetup(0x99, [])));
        Assert.Throws<ArgumentOutOfRangeException>(() => MoqWireCodec.WriteStreamHeader(buffer, new MoqStreamHeader(0x16, 1, 2, 0, 0)));
        Assert.Throws<ArgumentOutOfRangeException>(() => MoqWireCodec.WriteObjectHeader(buffer, new MoqObjectHeader(0, null, 65_537, 0), false));
        Assert.Throws<ArgumentException>(() => MoqWireCodec.WriteObjectHeader(buffer, new MoqObjectHeader(0, null, 1, 0), true));
        Assert.Throws<ArgumentException>(() => MoqWireCodec.WriteObjectHeader(buffer, new MoqObjectHeader(0, [0x01], 1, 0), false));
        Assert.Throws<ArgumentException>(() => MoqWireCodec.WriteObjectHeader(buffer, new MoqObjectHeader(0, [0x01], 1, 0), true));

        // a message whose payload exceeds the u16 frame length (FinishControlMessage cap)
        var blobs = new MoqParameter[12];
        var body = new byte[6000];
        for (int i = 0; i < blobs.Length; i++)
        {
            blobs[i] = new MoqParameter((ulong)(2 * i + 1), (byte[])body.Clone());
        }

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            MoqWireCodec.WriteSubscribe(buffer, new MoqSubscribe(1, "ns", "demo", blobs)));
    }

    private static MoqParameter[] TooManyParameters()
    {
        var result = new MoqParameter[129];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = new MoqParameter((ulong)i, 0UL);
        }

        return result;
    }

    // ---------- totality fuzz ----------

    [Fact]
    public void TotalityFuzz_NeverThrows_NeverOutOfRange()
    {
        var rng = new Random(20261025);
        byte[][] samples = BuildSamples();
        var mutated = new byte[64];
        var scratch = new byte[256];
        for (int i = 0; i < 220_000; i++)
        {
            byte[] sample = samples[rng.Next(samples.Length)];
            int len;
            switch (rng.Next(4))
            {
                case 0: // raw random bytes
                    len = rng.Next(0, 41);
                    rng.NextBytes(mutated.AsSpan(0, len));
                    break;
                case 1: // one to three bit flips over the sample
                    len = sample.Length;
                    sample.AsSpan().CopyTo(mutated.AsSpan(0, len));
                    for (int f = 0, flips = 1 + rng.Next(3); f < flips && len > 0; f++)
                    {
                        mutated[rng.Next(len)] ^= (byte)(1 << rng.Next(8));
                    }

                    break;
                case 2: // truncation at a random point
                    len = rng.Next(sample.Length + 1);
                    sample.AsSpan(0, len).CopyTo(mutated.AsSpan(0, len));
                    break;
                default: // random byte spliced in
                    len = sample.Length;
                    sample.AsSpan().CopyTo(mutated.AsSpan(0, len));
                    if (len > 0)
                    {
                        mutated[rng.Next(len)] = (byte)rng.Next(256);
                    }

                    break;
            }

            ExerciseAllTryReads(mutated.AsSpan(0, len), scratch);
        }
    }

    private static void ExerciseAllTryReads(ReadOnlySpan<byte> input, byte[] scratch)
    {
        if (MoqWireCodec.TryReadControlFrame(input, out var frame))
        {
            Assert.InRange(frame.Consumed, 1, input.Length);
            Assert.InRange(frame.PayloadLength, 0, input.Length);
            Assert.True(frame.PayloadStart + frame.PayloadLength <= input.Length);
        }

        if (MoqWireCodec.TryReadSetup(input, out var setup, out int consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WriteSetup(scratch, in setup), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadSubscribe(input, out var subscribe, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WriteSubscribe(scratch, in subscribe), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadSubscribeUpdate(input, out var update, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WriteSubscribeUpdate(scratch, in update), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadSubscribeOk(input, out var ok, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WriteSubscribeOk(scratch, in ok), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadSubscribeError(input, out var error, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WriteSubscribeError(scratch, in error), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadSubscribeDone(input, out var done, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WriteSubscribeDone(scratch, in done), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadAnnounce(input, out var announce, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WriteAnnounce(scratch, in announce), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadAnnounceOk(input, out var announceOk, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WriteAnnounceOk(scratch, in announceOk), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadPublish(input, out var publish, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WritePublish(scratch, in publish), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadPublishOk(input, out var publishOk, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WritePublishOk(scratch, in publishOk), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadUnsubscribe(input, out var unsubscribe, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WriteUnsubscribe(scratch, in unsubscribe), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadMaxRequestId(input, out var maxRequestId, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WriteMaxRequestId(scratch, in maxRequestId), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadGoAway(input, out var goAway, out consumed))
        {
            AssertRewritten(input, scratch, MoqWireCodec.WriteGoAway(scratch, in goAway), consumed);
        }
        else
        {
            Assert.Equal(0, consumed);
        }

        if (MoqWireCodec.TryReadStreamHeader(input, out var streamHeader, out int headerConsumed))
        {
            Assert.InRange(headerConsumed, 1, input.Length);
            int rewritten = MoqWireCodec.WriteStreamHeader(scratch, in streamHeader);
            Assert.Equal(headerConsumed, rewritten);
            Assert.True(input[..rewritten].SequenceEqual(scratch.AsSpan(0, rewritten)));
        }
        else
        {
            Assert.Equal(0, headerConsumed);
        }

        if (MoqWireCodec.TryReadObjectHeader(input, false, out var objectHeader, out int objectConsumed))
        {
            Assert.InRange(objectConsumed, 1, input.Length);
            Assert.True(objectHeader.PayloadLength <= 65_536UL);
            Assert.True(objectHeader.ExtensionBytes is null);
            int rewritten = MoqWireCodec.WriteObjectHeader(scratch, in objectHeader, false);
            Assert.Equal(objectConsumed, rewritten);
            Assert.True(input[..rewritten].SequenceEqual(scratch.AsSpan(0, rewritten)));
        }

        if (MoqWireCodec.TryReadObjectHeader(input, true, out objectHeader, out objectConsumed))
        {
            Assert.InRange(objectConsumed, 1, input.Length);
            Assert.True(objectHeader.PayloadLength <= 65_536UL);
            Assert.True((objectHeader.ExtensionBytes?.Length ?? 0) <= 65_535);
            int rewritten = MoqWireCodec.WriteObjectHeader(scratch, in objectHeader, true);
            Assert.Equal(objectConsumed, rewritten);
            Assert.True(input[..rewritten].SequenceEqual(scratch.AsSpan(0, rewritten)));
        }

        if (MoqWireCodec.TryReadTrackName(input, out string _, out int nameConsumed))
        {
            Assert.Equal(input.Length, nameConsumed);
        }

        if (MoqWireCodec.TryReadNamespace(input, out string _, out int nsConsumed))
        {
            Assert.Equal(input.Length, nsConsumed);
        }

        if (MoqWireCodec.TryReadParameters(input, out var parameters, out int parametersConsumed))
        {
            Assert.Equal(input.Length, parametersConsumed);
            Assert.True(parameters.Length <= 128);
        }

        if (MoqWireCodec.TryReadExtensionBlock(input, out var extensions, out int extensionsConsumed))
        {
            Assert.Equal(input.Length, extensionsConsumed); // 0 only when the input itself is empty
            Assert.True(extensions.Length <= 128);
        }
    }

    // On success the message must re-encode to exactly the consumed bytes:
    // read-then-write is the identity on canonical inputs. Callers only invoke
    // the Write after a successful TryRead (a default struct would throw).
    private static void AssertRewritten(ReadOnlySpan<byte> input, byte[] scratch, int written, int consumed)
    {
        Assert.InRange(consumed, 1, input.Length);
        Assert.Equal(input.Length, consumed); // message TryReads take exactly one frame
        Assert.Equal(consumed, written);
        Assert.True(input[..written].SequenceEqual(scratch.AsSpan(0, written)));
    }

    private static byte[][] BuildSamples() =>
    [
        [0x0a, 0x00, 0x01, 0x2a],
        [0x0a, 0x00, 0x08, 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
        [0x0a, 0x00, 0x00],
        [0x15, 0x00, 0x02, 0x41, 0x2c],
        [0x10, 0x00, 0x08, 0x07, 0x73, 0x74, 0x61, 0x67, 0x69, 0x6e, 0x67],
        [0x03, 0x00, 0x13, 0x05, 0x01, 0x02, 0x6e, 0x73, 0x04, 0x64, 0x65, 0x6d, 0x6f, 0x03, 0x20, 0x40, 0x80, 0x01, 0x01, 0x02, 0x01, 0x01],
        [0x03, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00],
        [0x04, 0x00, 0x03, 0x09, 0x11, 0x00],
        [0x04, 0x00, 0x06, 0x09, 0x11, 0x00, 0x03, 0x01, 0xaa],
        [0x05, 0x00, 0x06, 0x09, 0x10, 0x00, 0x02, 0x6e, 0x6f],
        [0x0b, 0x00, 0x04, 0x09, 0x00, 0x00, 0x00],
        [0x02, 0x00, 0x03, 0x04, 0x07, 0x00],
        [0x06, 0x00, 0x06, 0x01, 0x01, 0x02, 0x6e, 0x73, 0x00],
        [0x07, 0x00, 0x02, 0x2a, 0x00],
        [0x1d, 0x00, 0x0c, 0x01, 0x01, 0x02, 0x6e, 0x73, 0x04, 0x64, 0x65, 0x6d, 0x6f, 0x03, 0x00],
        [0x1e, 0x00, 0x02, 0x2a, 0x00],
        [0x20, 0x00, 0x08, 0x02, 0x02, 0x41, 0x00, 0x03, 0x02, 0x63, 0x66],
        [0x21, 0x00, 0x04, 0x01, 0x02, 0x41, 0x00],
        [0x18, 0x01, 0x07, 0x80],
        [0x14, 0x01, 0x02, 0x03, 0x80],
        [0x38, 0x05, 0x06],
        [0x19, 0x05, 0x06, 0x80],
        [0x18, 0x01, 0x07, 0x80, 0x00, 0x01, 0xff],
        [0x00, 0x01],
        [0x00, 0x03, 0x01, 0x01, 0xaa, 0x01],
        [0x00, 0x00, 0x00],
        [0x00, 0x00, 0x03],
        [0x02, 0x02, 0x41, 0x00, 0x03, 0x02, 0x63, 0x66],
        [0x01, 0x02, 0x6e, 0x73],
        [0x04, 0x64, 0x65, 0x6d, 0x6f],
        [0x03, 0x01, 0xaa],
        [0x0f, 0x00, 0x01, 0x2a],
    ];

    // ---------- differential oracle against Pinhole.Moq ----------

    [Fact]
    public void Differential_ControlMessages_Match_MoqWriterExactly_BothWays()
    {
        var rng = new Random(0xD1FFE5);
        var buffer = new byte[8192];
        for (int i = 0; i < 4_000; i++)
        {
            (MoqParameter[] mine, (ulong Key, object Value)[] theirs) = RandomParameters(rng);
            switch (rng.Next(13))
            {
                case 0: // SUBSCRIBE
                {
                    ulong id = RandomVarint(rng);
                    string ns = RandomText(rng);
                    string name = RandomText(rng);
                    var message = new MoqSubscribe(id, ns, name, mine);
                    int n = MoqWireCodec.WriteSubscribe(buffer, in message);
                    var writer = new MoqWriter();
                    writer.Integer(id);
                    writer.Namespace(ns);
                    writer.Text(name);
                    writer.Parameters(theirs);
                    AssertTrueAndCompare(writer, MoqControlTypes.Subscribe, buffer, n);
                    Assert.True(MoqWireCodec.TryReadSubscribe(buffer.AsSpan(0, n), out var read, out int used));
                    Assert.Equal(n, used);
                    Assert.Equal(id, read.RequestId);
                    Assert.Equal(ns, read.TrackNamespace);
                    Assert.Equal(name, read.TrackName);
                    AssertParametersEqual(mine, read.Parameters);
                    var reader = PayloadReader(buffer, n);
                    Assert.Equal(id, reader.Integer());
                    Assert.Equal(ns, reader.Namespace());
                    Assert.Equal(name, reader.Text());
                    AssertSameParameters(mine, reader.Parameters());
                    reader.End();
                    break;
                }

                case 1: // SUBSCRIBE_OK (with random extensions where present)
                {
                    ulong id = RandomVarint(rng);
                    ulong alias = RandomVarint(rng);
                    (MoqParameter[] extMine, (ulong Key, object Value)[] extTheirs) = RandomParameters(rng);
                    var message = new MoqSubscribeOk(id, alias, mine, extMine);
                    int n = MoqWireCodec.WriteSubscribeOk(buffer, in message);
                    var writer = new MoqWriter();
                    writer.Integer(id);
                    writer.Integer(alias);
                    writer.Parameters(theirs);
                    WriteRawPairs(writer, extTheirs);
                    AssertTrueAndCompare(writer, MoqControlTypes.SubscribeOk, buffer, n);
                    Assert.True(MoqWireCodec.TryReadSubscribeOk(buffer.AsSpan(0, n), out var read, out _));
                    Assert.Equal(alias, read.TrackAlias);
                    AssertParametersEqual(extMine, read.Extensions);
                    var reader = PayloadReader(buffer, n);
                    Assert.Equal(id, reader.Integer());
                    Assert.Equal(alias, reader.Integer());
                    AssertSameParameters(mine, reader.Parameters());
                    AssertSameParameters(extMine, reader.Extensions());
                    reader.End();
                    break;
                }

                case 2: // ANNOUNCE
                {
                    ulong id = RandomVarint(rng);
                    string ns = RandomText(rng);
                    var message = new MoqAnnounce(id, ns, mine);
                    int n = MoqWireCodec.WriteAnnounce(buffer, in message);
                    var writer = new MoqWriter();
                    writer.Integer(id);
                    writer.Namespace(ns);
                    writer.Parameters(theirs);
                    AssertTrueAndCompare(writer, MoqControlTypes.Announce, buffer, n);
                    var reader = PayloadReader(buffer, n);
                    Assert.Equal(id, reader.Integer());
                    Assert.Equal(ns, reader.Namespace());
                    AssertSameParameters(mine, reader.Parameters());
                    reader.End();
                    break;
                }

                case 3: // PUBLISH
                {
                    ulong id = RandomVarint(rng);
                    string ns = RandomText(rng);
                    string name = RandomText(rng);
                    ulong alias = RandomVarint(rng);
                    var message = new MoqPublish(id, ns, name, alias, mine);
                    int n = MoqWireCodec.WritePublish(buffer, in message);
                    var writer = new MoqWriter();
                    writer.Integer(id);
                    writer.Namespace(ns);
                    writer.Text(name);
                    writer.Integer(alias);
                    writer.Parameters(theirs);
                    AssertTrueAndCompare(writer, MoqControlTypes.Publish, buffer, n);
                    var reader = PayloadReader(buffer, n);
                    Assert.Equal(id, reader.Integer());
                    Assert.Equal(ns, reader.Namespace());
                    Assert.Equal(name, reader.Text());
                    Assert.Equal(alias, reader.Integer());
                    AssertSameParameters(mine, reader.Parameters());
                    reader.End();
                    break;
                }

                case 4: // ANNOUNCE_OK / PUBLISH_OK share the id+params shape
                case 5:
                {
                    ulong id = RandomVarint(rng);
                    bool announce = rng.Next(2) == 0;
                    int n;
                    if (announce)
                    {
                        var ok = new MoqAnnounceOk(id, mine);
                        n = MoqWireCodec.WriteAnnounceOk(buffer, in ok);
                    }
                    else
                    {
                        var ok = new MoqPublishOk(id, mine);
                        n = MoqWireCodec.WritePublishOk(buffer, in ok);
                    }

                    var writer = new MoqWriter();
                    writer.Integer(id);
                    writer.Parameters(theirs);
                    AssertTrueAndCompare(writer, announce ? MoqControlTypes.AnnounceOk : MoqControlTypes.PublishOk, buffer, n);
                    var reader = PayloadReader(buffer, n);
                    Assert.Equal(id, reader.Integer());
                    AssertSameParameters(mine, reader.Parameters());
                    reader.End();
                    break;
                }

                case 6: // SUBSCRIBE_ERROR / SUBSCRIBE_DONE share the shape
                case 7:
                {
                    ulong id = RandomVarint(rng);
                    ulong code = RandomVarint(rng);
                    ulong alias = RandomVarint(rng);
                    string reason = RandomText(rng);
                    bool isError = rng.Next(2) == 0;
                    int n = isError
                        ? MoqWireCodec.WriteSubscribeError(buffer, new MoqSubscribeError(id, code, alias, reason))
                        : MoqWireCodec.WriteSubscribeDone(buffer, new MoqSubscribeDone(id, code, alias, reason));
                    var writer = new MoqWriter();
                    writer.Integer(id);
                    writer.Integer(code);
                    writer.Integer(alias);
                    writer.Text(reason);
                    AssertTrueAndCompare(writer, isError ? MoqControlTypes.SubscribeError : MoqControlTypes.SubscribeDone, buffer, n);
                    var reader = PayloadReader(buffer, n);
                    Assert.Equal(id, reader.Integer());
                    Assert.Equal(code, reader.Integer());
                    Assert.Equal(alias, reader.Integer());
                    Assert.Equal(reason, reader.Text());
                    reader.End();
                    break;
                }

                case 8: // SUBSCRIBE_UPDATE
                {
                    var message = new MoqSubscribeUpdate(RandomVarint(rng), RandomVarint(rng), mine);
                    int n = MoqWireCodec.WriteSubscribeUpdate(buffer, in message);
                    var writer = new MoqWriter();
                    writer.Integer(message.RequestId);
                    writer.Integer(message.ExistingRequestId);
                    writer.Parameters(theirs);
                    AssertTrueAndCompare(writer, MoqControlTypes.SubscribeUpdate, buffer, n);
                    var reader = PayloadReader(buffer, n);
                    Assert.Equal(message.RequestId, reader.Integer());
                    Assert.Equal(message.ExistingRequestId, reader.Integer());
                    AssertSameParameters(mine, reader.Parameters());
                    reader.End();
                    break;
                }

                case 9: // UNSUBSCRIBE
                {
                    ulong id = RandomVarint(rng);
                    int n = MoqWireCodec.WriteUnsubscribe(buffer, new MoqUnsubscribe(id));
                    var writer = new MoqWriter();
                    writer.Integer(id);
                    AssertTrueAndCompare(writer, MoqControlTypes.Unsubscribe, buffer, n);
                    Assert.Equal(id, PayloadReader(buffer, n).Integer());
                    break;
                }

                case 10: // MAX_REQUEST_ID
                {
                    ulong maximum = RandomVarint(rng);
                    int n = MoqWireCodec.WriteMaxRequestId(buffer, new MoqMaxRequestId(maximum));
                    var writer = new MoqWriter();
                    writer.Integer(maximum);
                    AssertTrueAndCompare(writer, MoqControlTypes.MaxRequestId, buffer, n);
                    Assert.Equal(maximum, PayloadReader(buffer, n).Integer());
                    break;
                }

                case 11: // GOAWAY
                {
                    string reason = RandomText(rng);
                    int n = MoqWireCodec.WriteGoAway(buffer, new MoqGoAway(reason));
                    var writer = new MoqWriter();
                    writer.Text(reason);
                    AssertTrueAndCompare(writer, MoqControlTypes.GoAway, buffer, n);
                    Assert.Equal(reason, PayloadReader(buffer, n).Text());
                    break;
                }

                default: // CLIENT_SETUP / SERVER_SETUP
                {
                    ulong type = rng.Next(2) == 0 ? MoqControlTypes.ClientSetup : MoqControlTypes.ServerSetup;
                    var message = new MoqSetup(type, mine);
                    int n = MoqWireCodec.WriteSetup(buffer, in message);
                    var writer = new MoqWriter();
                    writer.Parameters(theirs);
                    AssertTrueAndCompare(writer, type, buffer, n);
                    var reader = PayloadReader(buffer, n);
                    AssertSameParameters(mine, reader.Parameters());
                    reader.End();
                    break;
                }
            }
        }
    }

    [Fact]
    public async Task Differential_MoqStreamWire_FramesAndIntegers_Agree()
    {
        var rng = new Random(0x5EA1);
        var buffer = new byte[512];
        for (int i = 0; i < 2_000; i++)
        {
            ulong type = RandomVarint(rng) % 64;
            int payloadLength = rng.Next(0, 60);
            var payload = new byte[payloadLength];
            rng.NextBytes(payload);
            int n = MoqWireCodec.WriteControlFrame(buffer, type, payload);
            var (readType, readPayload) = await MoqStreamWire.ReadMessageAsync(
                new MemoryStream(buffer[..n].ToArray()), CancellationToken.None);
            Assert.Equal(type, readType);
            Assert.True(readPayload.SequenceEqual(payload));
        }
    }

    [Fact]
    public void Differential_TrackName_AgreesWith_MoqReaderText()
    {
        var rng = new Random(0xDA7A5);
        var raw = new byte[12];
        var candidate = new byte[16];
        for (int i = 0; i < 50_000; i++)
        {
            int len = rng.Next(0, 13);
            rng.NextBytes(raw.AsSpan(0, len));
            int w = WirePrimitives.WriteVarint(candidate, (ulong)len);
            raw.AsSpan(0, len).CopyTo(candidate.AsSpan(w));
            int total = w + len;
            bool mine = MoqWireCodec.TryReadTrackName(candidate.AsSpan(0, total), out string name, out int consumed);
            try
            {
                string theirs = new MoqReader(candidate[..total]).Text();
                Assert.True(mine, $"mine rejected valid text {Convert.ToHexString(candidate[..total])}");
                Assert.Equal(theirs, name);
                Assert.Equal(total, consumed);
            }
            catch (Exception error) when (error is MoqProtocolException or ArgumentException)
            {
                Assert.False(mine, $"mine accepted invalid text {Convert.ToHexString(candidate[..total])}");
            }
        }
    }

    [Fact]
    public void Differential_MoqReaderInteger_AgreesWithCanonicalVarints()
    {
        var rng = new Random(0xC0FFEE);
        var buf = new byte[10];
        for (int i = 0; i < 100_000; i++)
        {
            int len = RandomVarintBuffer(rng, buf);
            var slice = buf.AsSpan(0, len);
            bool canonical = WirePrimitives.TryReadVarint(slice, out ulong value, out int length);
            ulong moqValue;
            int moqRemaining;
            try
            {
                var reader = new MoqReader(buf[..len]);
                moqValue = reader.Integer();
                moqRemaining = reader.Remaining;
            }
            catch (MoqProtocolException)
            {
                Assert.False(canonical, "canonical reader rejected a truncated buffer that WirePrimitives accepted");
                continue;
            }

            if (canonical)
            {
                Assert.Equal(value, moqValue);
                Assert.Equal(len - length, moqRemaining);
            }
            else
            {
                // MoqReader accepted a form WirePrimitives rejects: it must
                // still be the naive (non-minimal-tolerant) decoding.
                Assert.Equal(NaiveDecode(slice, out int naiveLength), moqValue);
                Assert.Equal(len - naiveLength, moqRemaining);
            }
        }
    }

    [Fact]
    public async Task Differential_MoqStreamWireInteger_AgreesWithCanonicalVarints()
    {
        var rng = new Random(0x57EAB);
        var buf = new byte[10];
        for (int i = 0; i < 25_000; i++)
        {
            int len = RandomVarintBuffer(rng, buf);
            var slice = buf[..len];
            bool canonical = WirePrimitives.TryReadVarint(slice, out ulong value, out int length);
            var stream = new MemoryStream(slice);
            ulong? streamValue;
            try
            {
                streamValue = await MoqStreamWire.ReadIntegerAsync(stream, CancellationToken.None);
            }
            catch (IOException)
            {
                Assert.False(canonical, "stream reader rejected a truncated buffer that WirePrimitives accepted");
                continue;
            }

            if (streamValue is null)
            {
                Assert.False(canonical);
                continue;
            }

            if (canonical)
            {
                Assert.Equal(value, streamValue.Value);
                Assert.Equal((long)length, stream.Position);
            }
            else
            {
                Assert.Equal(NaiveDecode(slice, out int naiveLength), streamValue.Value);
                Assert.Equal((long)naiveLength, stream.Position);
            }
        }
    }

    [Fact]
    public async Task Discrepancy_NonMinimalVarints_MoqAcceptsWhileCanonicalCodecRejects()
    {
        // MoqReader.Integer and MoqStreamWire.ReadIntegerAsync accept padded
        // varints; WirePrimitives (and therefore every MoqWireCodec TryRead)
        // rejects them. Documented divergence: this codec stays RFC 9000
        // canonical.
        Assert.Equal(42UL, new MoqReader([0x40, 0x2a]).Integer());
        Assert.False(WirePrimitives.TryReadVarint([0x40, 0x2a], out _, out _));
        Assert.Equal(42UL, await MoqStreamWire.ReadIntegerAsync(new MemoryStream([0x80, 0x00, 0x00, 0x2a]), CancellationToken.None));
        Assert.False(WirePrimitives.TryReadVarint([0x80, 0x00, 0x00, 0x2a], out _, out _));

        byte[] framed = [0x0a, 0x00, 0x02, 0x40, 0x2a];
        Assert.False(MoqWireCodec.TryReadUnsubscribe(framed, out _, out _));
        Assert.True(MoqWireCodec.TryReadControlFrame(framed, out _)); // framing only sees a canonical type varint
    }

    // ---------- random generators and differential helpers ----------

    private static void AssertTrueAndCompare(MoqWriter writer, ulong type, byte[] buffer, int n)
    {
        byte[] theirs = writer.Message(type);
        Assert.Equal(n, theirs.Length);
        Assert.True(buffer.AsSpan(0, n).SequenceEqual(theirs),
            $"byte mismatch for type {type}: mine {Convert.ToHexString(buffer, 0, n)} vs MoqWriter {Convert.ToHexString(theirs)}");
    }

    private static MoqReader PayloadReader(byte[] buffer, int n) => new(buffer[3..n]);

    // MoqWriter has no extension API; emit the count-free pair list manually,
    // delta-encoded like MoqWireCodec.WriteExtensionBlock does.
    private static void WriteRawPairs(MoqWriter writer, (ulong Key, object Value)[] pairs)
    {
        ulong previous = 0;
        foreach (var pair in pairs.OrderBy(p => p.Key))
        {
            writer.Integer(pair.Key - previous);
            previous = pair.Key;
            if ((pair.Key & 1) == 0)
            {
                writer.Integer((ulong)pair.Value);
            }
            else
            {
                writer.Blob((byte[])pair.Value);
            }
        }
    }

    private static void AssertParametersEqual(MoqParameter[] expected, MoqParameter[] actual)
    {
        Assert.Equal(expected.Length, actual.Length);
        for (int i = 0; i < expected.Length; i++)
        {
            Assert.Equal(expected[i].Key, actual[i].Key);
            Assert.Equal(expected[i].IsBlob, actual[i].IsBlob);
            if (expected[i].IsBlob)
            {
                Assert.True(expected[i].Blob!.SequenceEqual(actual[i].Blob!), $"blob mismatch at key {expected[i].Key}");
            }
            else
            {
                Assert.Equal(expected[i].Number, actual[i].Number);
            }
        }
    }

    private static void AssertSameParameters(MoqParameter[] mine, Dictionary<ulong, object> theirs)
    {
        Assert.Equal(mine.Length, theirs.Count);
        foreach (MoqParameter p in mine)
        {
            Assert.True(theirs.TryGetValue(p.Key, out object? value), $"MoqReader lacks key {p.Key}");
            if (p.IsBlob)
            {
                Assert.True(p.Blob!.SequenceEqual((byte[])value!), $"blob mismatch at key {p.Key}");
            }
            else
            {
                Assert.Equal(p.Number, (ulong)value);
            }
        }
    }

    private static ulong NaiveDecode(ReadOnlySpan<byte> b, out int length)
    {
        length = 1 << (b[0] >> 6);
        ulong value = b[0] & 0x3FUL;
        for (int i = 1; i < length; i++)
        {
            value = (value << 8) | b[i];
        }

        return value;
    }

    private static int RandomVarintBuffer(Random rng, byte[] buf)
    {
        if (rng.Next(2) == 0)
        {
            ulong value = RandomVarint(rng);
            int len = WirePrimitives.WriteVarint(buf, value);
            if (rng.Next(4) == 0)
            {
                // re-encode with the next larger form: well-formed but non-minimal
                len = PadVarint(buf, value);
            }

            return len;
        }

        int len2 = rng.Next(0, 10);
        rng.NextBytes(buf.AsSpan(0, len2));
        return len2;
    }

    private static int PadVarint(byte[] buf, ulong value)
    {
        int size = WirePrimitives.VarintLength(value) switch { 1 => 2, 2 => 4, _ => 8 };
        byte prefix = size switch { 2 => 0x40, 4 => 0x80, _ => 0xC0 };
        int shift = (size - 1) * 8;
        for (int i = 0; i < size; i++, shift -= 8)
        {
            buf[i] = i == 0 ? (byte)(prefix | (value >> shift)) : (byte)(value >> shift);
        }

        return size;
    }

    private static ulong RandomVarint(Random rng) => rng.Next(7) switch
    {
        0 => (ulong)rng.Next(0, 64),
        1 => (ulong)rng.Next(64, 16_384),
        2 => (ulong)rng.NextInt64(16_384, 1L << 30),
        3 => 63UL,
        4 => 16_383UL,
        5 => (1UL << 30) - 1,
        _ => (ulong)rng.NextInt64(0, (long)WirePrimitives.VarintMax + 1),
    };

    private static string RandomText(Random rng)
    {
        int length = rng.Next(0, 17);
        var chars = new char[length];
        for (int i = 0; i < length; i++)
        {
            chars[i] = rng.Next(4) switch
            {
                0 => (char)('a' + rng.Next(26)),
                1 => (char)('A' + rng.Next(26)),
                2 => (char)('0' + rng.Next(10)),
                _ => rng.Next(2) == 0 ? '\u00e9' : '\u4e2d',
            };
        }

        return new string(chars);
    }

    private static (MoqParameter[] Mine, (ulong Key, object Value)[] Theirs) RandomParameters(Random rng)
    {
        int count = rng.Next(0, 6);
        var mine = new MoqParameter[count];
        var theirs = new (ulong Key, object Value)[count];
        ulong key = 0;
        for (int i = 0; i < count; i++)
        {
            key += (ulong)rng.Next(1, 40); // strictly ascending, mixed parity
            if ((key & 1) == 0)
            {
                ulong number = RandomVarint(rng);
                mine[i] = new MoqParameter(key, number);
                theirs[i] = (key, number);
            }
            else
            {
                var blob = new byte[rng.Next(0, 8)];
                rng.NextBytes(blob);
                mine[i] = new MoqParameter(key, blob);
                theirs[i] = (key, blob);
            }
        }

        return (mine, theirs);
    }
}
