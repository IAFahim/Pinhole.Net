using System.Text;

namespace Pinhole.Wire;

public static class MoqControlTypes
{
    public const ulong SubscribeUpdate = 0x02;
    public const ulong Subscribe = 0x03;
    public const ulong SubscribeOk = 0x04;
    public const ulong SubscribeError = 0x05;
    public const ulong Announce = 0x06;
    public const ulong AnnounceOk = 0x07;
    public const ulong Unsubscribe = 0x0a;
    public const ulong SubscribeDone = 0x0b;
    public const ulong GoAway = 0x10;
    public const ulong MaxRequestId = 0x15;
    public const ulong Publish = 0x1d;
    public const ulong PublishOk = 0x1e;
    public const ulong ClientSetup = 0x20;
    public const ulong ServerSetup = 0x21;

    public static bool IsKnown(ulong type) => type is SubscribeUpdate or Subscribe or SubscribeOk or SubscribeError
        or Announce or AnnounceOk or Unsubscribe or SubscribeDone or GoAway or MaxRequestId or Publish or PublishOk
        or ClientSetup or ServerSetup;
}

public readonly struct MoqParameter
{
    public ulong Key { get; }
    public bool IsBlob { get; }
    public ulong Number { get; }
    public byte[]? Blob { get; }

    public MoqParameter(ulong key, ulong number)
    {
        Key = key;
        IsBlob = false;
        Number = number;
        Blob = null;
    }

    public MoqParameter(ulong key, byte[] blob)
    {
        Key = key;
        IsBlob = true;
        Number = 0;
        Blob = blob;
    }
}

public readonly struct MoqControlFrame(ulong type, int payloadStart, int payloadLength, int consumed)
{
    public ulong Type => type;
    public int PayloadStart => payloadStart;
    public int PayloadLength => payloadLength;
    public int Consumed => consumed;

    public ReadOnlySpan<byte> Payload(ReadOnlySpan<byte> buffer) => buffer.Slice(payloadStart, payloadLength);
}

public readonly struct MoqSetup(ulong type, MoqParameter[] parameters)
{
    public ulong Type => type;
    public MoqParameter[] Parameters => parameters;
}

public readonly struct MoqSubscribe(ulong requestId, string trackNamespace, string trackName, MoqParameter[] parameters)
{
    public ulong RequestId => requestId;
    public string TrackNamespace => trackNamespace;
    public string TrackName => trackName;
    public MoqParameter[] Parameters => parameters;
}

public readonly struct MoqSubscribeUpdate(ulong requestId, ulong existingRequestId, MoqParameter[] parameters)
{
    public ulong RequestId => requestId;
    public ulong ExistingRequestId => existingRequestId;
    public MoqParameter[] Parameters => parameters;
}

public readonly struct MoqSubscribeOk(ulong requestId, ulong trackAlias, MoqParameter[] parameters, MoqParameter[] extensions)
{
    public ulong RequestId => requestId;
    public ulong TrackAlias => trackAlias;
    public MoqParameter[] Parameters => parameters;
    public MoqParameter[] Extensions => extensions;
}

public readonly struct MoqSubscribeError(ulong requestId, ulong errorCode, ulong trackAlias, string reason)
{
    public ulong RequestId => requestId;
    public ulong ErrorCode => errorCode;
    public ulong TrackAlias => trackAlias;
    public string Reason => reason;
}

public readonly struct MoqSubscribeDone(ulong requestId, ulong status, ulong trackAlias, string reason)
{
    public ulong RequestId => requestId;
    public ulong Status => status;
    public ulong TrackAlias => trackAlias;
    public string Reason => reason;
}

public readonly struct MoqAnnounce(ulong requestId, string trackNamespace, MoqParameter[] parameters)
{
    public ulong RequestId => requestId;
    public string TrackNamespace => trackNamespace;
    public MoqParameter[] Parameters => parameters;
}

public readonly struct MoqAnnounceOk(ulong requestId, MoqParameter[] parameters)
{
    public ulong RequestId => requestId;
    public MoqParameter[] Parameters => parameters;
}

public readonly struct MoqPublish(ulong requestId, string trackNamespace, string trackName, ulong trackAlias, MoqParameter[] parameters)
{
    public ulong RequestId => requestId;
    public string TrackNamespace => trackNamespace;
    public string TrackName => trackName;
    public ulong TrackAlias => trackAlias;
    public MoqParameter[] Parameters => parameters;
}

public readonly struct MoqPublishOk(ulong requestId, MoqParameter[] parameters)
{
    public ulong RequestId => requestId;
    public MoqParameter[] Parameters => parameters;
}

public readonly struct MoqUnsubscribe(ulong requestId)
{
    public ulong RequestId => requestId;
}

public readonly struct MoqMaxRequestId(ulong maximum)
{
    public ulong Maximum => maximum;
}

public readonly struct MoqGoAway(string reason)
{
    public string Reason => reason;
}

public readonly struct MoqStreamHeader(ulong streamType, ulong trackAlias, ulong groupId, ulong subgroupId, byte priority)
{
    public ulong StreamType => streamType;
    public ulong TrackAlias => trackAlias;
    public ulong GroupId => groupId;
    public bool HasSubgroupId => (streamType & 0x6) == 4;
    public ulong SubgroupId => subgroupId;
    public bool HasPriority => (streamType & 0x20) == 0;
    public byte Priority => priority;
}

public readonly struct MoqObjectHeader(ulong objectId, byte[]? extensionBytes, ulong payloadLength, ulong status)
{
    public ulong ObjectId => objectId;
    public byte[]? ExtensionBytes => extensionBytes;
    public ulong PayloadLength => payloadLength;
    public bool HasStatus => payloadLength == 0;
    public ulong Status => status;
}

public static class MoqWireCodec
{
    public const int MaxTextBytes = 4096;
    public const int MaxParameterPairs = 128;
    public const int MaxParameterBlobBytes = ushort.MaxValue;
    public const int MaxObjectPayloadBytes = 65536;
    public const int MaxControlPayloadBytes = ushort.MaxValue;

    public static bool TryReadControlFrame(ReadOnlySpan<byte> b, out MoqControlFrame frame)
    {
        frame = default;
        if (!WirePrimitives.TryReadVarint(b, out ulong type, out int typeLength))
        {
            return false;
        }

        if (!WirePrimitives.TryReadU16Be(b[typeLength..], out ushort payloadLength))
        {
            return false;
        }

        int payloadStart = typeLength + 2;
        if (b.Length - payloadStart < payloadLength)
        {
            return false;
        }

        frame = new MoqControlFrame(type, payloadStart, payloadLength, payloadStart + payloadLength);
        return true;
    }

    public static int WriteControlFrame(Span<byte> b, ulong type, ReadOnlySpan<byte> payload)
    {
        if (type > WirePrimitives.VarintMax)
        {
            ThrowVarintRange();
        }

        if (payload.Length > MaxControlPayloadBytes)
        {
            ThrowControlPayloadTooLarge();
        }

        int typeLength = WirePrimitives.VarintLength(type);
        if (b.Length < typeLength + 2 + payload.Length)
        {
            ThrowTooSmall();
        }

        int w = WirePrimitives.WriteVarint(b, type);
        w += WirePrimitives.WriteU16Be(b[w..], (ushort)payload.Length);
        payload.CopyTo(b[w..]);
        return w + payload.Length;
    }

    public static bool TryReadTrackName(ReadOnlySpan<byte> b, out string name, out int consumed)
    {
        name = "";
        consumed = 0;
        var reader = new MoqSpanReader(b);
        if (!reader.TryReadText(out name) || !reader.AtEnd)
        {
            name = "";
            return false;
        }

        consumed = b.Length;
        return true;
    }

    public static int WriteTrackName(Span<byte> b, string name) => WriteText(b, name);

    public static bool TryReadNamespace(ReadOnlySpan<byte> b, out string trackNamespace, out int consumed)
    {
        trackNamespace = "";
        consumed = 0;
        var reader = new MoqSpanReader(b);
        if (!reader.TryReadNamespace(out trackNamespace) || !reader.AtEnd)
        {
            trackNamespace = "";
            return false;
        }

        consumed = b.Length;
        return true;
    }

    public static int WriteNamespace(Span<byte> b, string trackNamespace)
    {
        ArgumentNullException.ThrowIfNull(trackNamespace);
        int w = WirePrimitives.WriteVarint(b, 1);
        return w + WriteText(b[w..], trackNamespace);
    }

    public static bool TryReadParameters(ReadOnlySpan<byte> b, out MoqParameter[] parameters, out int consumed)
    {
        parameters = [];
        consumed = 0;
        var reader = new MoqSpanReader(b);
        if (!reader.TryReadParameters(out parameters) || !reader.AtEnd)
        {
            parameters = [];
            return false;
        }

        consumed = b.Length;
        return true;
    }

    public static int WriteParameters(Span<byte> b, ReadOnlySpan<MoqParameter> parameters)
    {
        int w = WriteCount(b, parameters.Length);
        return w + WritePairs(b[w..], parameters);
    }

    public static bool TryReadExtensionBlock(ReadOnlySpan<byte> b, out MoqParameter[] extensions, out int consumed)
    {
        extensions = [];
        consumed = 0;
        var reader = new MoqSpanReader(b);
        if (!reader.TryReadExtensionPairs(out extensions) || !reader.AtEnd)
        {
            extensions = [];
            return false;
        }

        consumed = b.Length;
        return true;
    }

    public static int WriteExtensionBlock(Span<byte> b, ReadOnlySpan<MoqParameter> extensions) => WritePairs(b, extensions);

    public static bool TryReadSetup(ReadOnlySpan<byte> b, out MoqSetup message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame)
            || (frame.Type != MoqControlTypes.ClientSetup && frame.Type != MoqControlTypes.ServerSetup))
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadParameters(out var parameters) || !reader.AtEnd || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqSetup(frame.Type, parameters);
        consumed = frame.Consumed;
        return true;
    }

    public static int WriteSetup(Span<byte> b, in MoqSetup message)
    {
        if (message.Type != MoqControlTypes.ClientSetup && message.Type != MoqControlTypes.ServerSetup)
        {
            ThrowSetupType();
        }

        StartControlMessage(b, message.Type, out int body);
        int w = WriteParameters(b[body..], message.Parameters);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadSubscribe(ReadOnlySpan<byte> b, out MoqSubscribe message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.Subscribe)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadVarint(out ulong requestId)
            || !reader.TryReadNamespace(out string trackNamespace)
            || !reader.TryReadText(out string trackName)
            || !reader.TryReadParameters(out var parameters)
            || !reader.AtEnd
            || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqSubscribe(requestId, trackNamespace, trackName, parameters);
        consumed = frame.Consumed;
        return true;
    }

    public static int WriteSubscribe(Span<byte> b, in MoqSubscribe message)
    {
        StartControlMessage(b, MoqControlTypes.Subscribe, out int body);
        int w = WirePrimitives.WriteVarint(b[body..], message.RequestId);
        w += WriteNamespace(b[(body + w)..], message.TrackNamespace);
        w += WriteText(b[(body + w)..], message.TrackName);
        w += WriteParameters(b[(body + w)..], message.Parameters);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadSubscribeUpdate(ReadOnlySpan<byte> b, out MoqSubscribeUpdate message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.SubscribeUpdate)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadVarint(out ulong requestId)
            || !reader.TryReadVarint(out ulong existing)
            || !reader.TryReadParameters(out var parameters)
            || !reader.AtEnd
            || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqSubscribeUpdate(requestId, existing, parameters);
        consumed = frame.Consumed;
        return true;
    }

    public static int WriteSubscribeUpdate(Span<byte> b, in MoqSubscribeUpdate message)
    {
        StartControlMessage(b, MoqControlTypes.SubscribeUpdate, out int body);
        int w = WirePrimitives.WriteVarint(b[body..], message.RequestId);
        w += WirePrimitives.WriteVarint(b[(body + w)..], message.ExistingRequestId);
        w += WriteParameters(b[(body + w)..], message.Parameters);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadSubscribeOk(ReadOnlySpan<byte> b, out MoqSubscribeOk message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.SubscribeOk)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadVarint(out ulong requestId)
            || !reader.TryReadVarint(out ulong trackAlias)
            || !reader.TryReadParameters(out var parameters)
            || !reader.TryReadExtensionPairs(out var extensions)
            || !reader.AtEnd
            || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqSubscribeOk(requestId, trackAlias, parameters, extensions);
        consumed = frame.Consumed;
        return true;
    }

    public static int WriteSubscribeOk(Span<byte> b, in MoqSubscribeOk message)
    {
        StartControlMessage(b, MoqControlTypes.SubscribeOk, out int body);
        int w = WirePrimitives.WriteVarint(b[body..], message.RequestId);
        w += WirePrimitives.WriteVarint(b[(body + w)..], message.TrackAlias);
        w += WriteParameters(b[(body + w)..], message.Parameters);
        w += WriteExtensionBlock(b[(body + w)..], message.Extensions);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadSubscribeError(ReadOnlySpan<byte> b, out MoqSubscribeError message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.SubscribeError)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadVarint(out ulong requestId)
            || !reader.TryReadVarint(out ulong errorCode)
            || !reader.TryReadVarint(out ulong trackAlias)
            || !reader.TryReadText(out string reason)
            || !reader.AtEnd
            || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqSubscribeError(requestId, errorCode, trackAlias, reason);
        consumed = frame.Consumed;
        return true;
    }

    public static int WriteSubscribeError(Span<byte> b, in MoqSubscribeError message)
    {
        StartControlMessage(b, MoqControlTypes.SubscribeError, out int body);
        int w = WirePrimitives.WriteVarint(b[body..], message.RequestId);
        w += WirePrimitives.WriteVarint(b[(body + w)..], message.ErrorCode);
        w += WirePrimitives.WriteVarint(b[(body + w)..], message.TrackAlias);
        w += WriteText(b[(body + w)..], message.Reason);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadSubscribeDone(ReadOnlySpan<byte> b, out MoqSubscribeDone message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.SubscribeDone)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadVarint(out ulong requestId)
            || !reader.TryReadVarint(out ulong status)
            || !reader.TryReadVarint(out ulong trackAlias)
            || !reader.TryReadText(out string reason)
            || !reader.AtEnd
            || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqSubscribeDone(requestId, status, trackAlias, reason);
        consumed = frame.Consumed;
        return true;
    }

    public static int WriteSubscribeDone(Span<byte> b, in MoqSubscribeDone message)
    {
        StartControlMessage(b, MoqControlTypes.SubscribeDone, out int body);
        int w = WirePrimitives.WriteVarint(b[body..], message.RequestId);
        w += WirePrimitives.WriteVarint(b[(body + w)..], message.Status);
        w += WirePrimitives.WriteVarint(b[(body + w)..], message.TrackAlias);
        w += WriteText(b[(body + w)..], message.Reason);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadAnnounce(ReadOnlySpan<byte> b, out MoqAnnounce message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.Announce)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadVarint(out ulong requestId)
            || !reader.TryReadNamespace(out string trackNamespace)
            || !reader.TryReadParameters(out var parameters)
            || !reader.AtEnd
            || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqAnnounce(requestId, trackNamespace, parameters);
        consumed = frame.Consumed;
        return true;
    }

    public static int WriteAnnounce(Span<byte> b, in MoqAnnounce message)
    {
        StartControlMessage(b, MoqControlTypes.Announce, out int body);
        int w = WirePrimitives.WriteVarint(b[body..], message.RequestId);
        w += WriteNamespace(b[(body + w)..], message.TrackNamespace);
        w += WriteParameters(b[(body + w)..], message.Parameters);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadAnnounceOk(ReadOnlySpan<byte> b, out MoqAnnounceOk message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.AnnounceOk)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadVarint(out ulong requestId)
            || !reader.TryReadParameters(out var parameters)
            || !reader.AtEnd
            || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqAnnounceOk(requestId, parameters);
        consumed = frame.Consumed;
        return true;
    }

    public static int WriteAnnounceOk(Span<byte> b, in MoqAnnounceOk message)
    {
        StartControlMessage(b, MoqControlTypes.AnnounceOk, out int body);
        int w = WirePrimitives.WriteVarint(b[body..], message.RequestId);
        w += WriteParameters(b[(body + w)..], message.Parameters);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadPublish(ReadOnlySpan<byte> b, out MoqPublish message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.Publish)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadVarint(out ulong requestId)
            || !reader.TryReadNamespace(out string trackNamespace)
            || !reader.TryReadText(out string trackName)
            || !reader.TryReadVarint(out ulong trackAlias)
            || !reader.TryReadParameters(out var parameters)
            || !reader.AtEnd
            || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqPublish(requestId, trackNamespace, trackName, trackAlias, parameters);
        consumed = frame.Consumed;
        return true;
    }

    public static int WritePublish(Span<byte> b, in MoqPublish message)
    {
        StartControlMessage(b, MoqControlTypes.Publish, out int body);
        int w = WirePrimitives.WriteVarint(b[body..], message.RequestId);
        w += WriteNamespace(b[(body + w)..], message.TrackNamespace);
        w += WriteText(b[(body + w)..], message.TrackName);
        w += WirePrimitives.WriteVarint(b[(body + w)..], message.TrackAlias);
        w += WriteParameters(b[(body + w)..], message.Parameters);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadPublishOk(ReadOnlySpan<byte> b, out MoqPublishOk message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.PublishOk)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadVarint(out ulong requestId)
            || !reader.TryReadParameters(out var parameters)
            || !reader.AtEnd
            || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqPublishOk(requestId, parameters);
        consumed = frame.Consumed;
        return true;
    }

    public static int WritePublishOk(Span<byte> b, in MoqPublishOk message)
    {
        StartControlMessage(b, MoqControlTypes.PublishOk, out int body);
        int w = WirePrimitives.WriteVarint(b[body..], message.RequestId);
        w += WriteParameters(b[(body + w)..], message.Parameters);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadUnsubscribe(ReadOnlySpan<byte> b, out MoqUnsubscribe message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.Unsubscribe)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadVarint(out ulong requestId) || !reader.AtEnd || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqUnsubscribe(requestId);
        consumed = frame.Consumed;
        return true;
    }

    public static int WriteUnsubscribe(Span<byte> b, in MoqUnsubscribe message)
    {
        StartControlMessage(b, MoqControlTypes.Unsubscribe, out int body);
        int w = WirePrimitives.WriteVarint(b[body..], message.RequestId);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadMaxRequestId(ReadOnlySpan<byte> b, out MoqMaxRequestId message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.MaxRequestId)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadVarint(out ulong maximum) || !reader.AtEnd || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqMaxRequestId(maximum);
        consumed = frame.Consumed;
        return true;
    }

    public static int WriteMaxRequestId(Span<byte> b, in MoqMaxRequestId message)
    {
        StartControlMessage(b, MoqControlTypes.MaxRequestId, out int body);
        int w = WirePrimitives.WriteVarint(b[body..], message.Maximum);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadGoAway(ReadOnlySpan<byte> b, out MoqGoAway message, out int consumed)
    {
        message = default;
        consumed = 0;
        if (!TryReadControlFrame(b, out var frame) || frame.Type != MoqControlTypes.GoAway)
        {
            return false;
        }

        var reader = new MoqSpanReader(frame.Payload(b));
        if (!reader.TryReadText(out string reason) || !reader.AtEnd || frame.Consumed != b.Length)
        {
            return false;
        }

        message = new MoqGoAway(reason);
        consumed = frame.Consumed;
        return true;
    }

    public static int WriteGoAway(Span<byte> b, in MoqGoAway message)
    {
        StartControlMessage(b, MoqControlTypes.GoAway, out int body);
        int w = WriteText(b[body..], message.Reason);
        return FinishControlMessage(b, body, w);
    }

    public static bool TryReadStreamHeader(ReadOnlySpan<byte> b, out MoqStreamHeader header, out int consumed)
    {
        header = default;
        consumed = 0;
        var reader = new MoqSpanReader(b);
        if (!reader.TryReadVarint(out ulong streamType) || !ValidStreamType(streamType))
        {
            return false;
        }

        if (!reader.TryReadVarint(out ulong trackAlias) || !reader.TryReadVarint(out ulong groupId))
        {
            return false;
        }

        ulong subgroupId = 0;
        if ((streamType & 0x6) == 4 && !reader.TryReadVarint(out subgroupId))
        {
            return false;
        }

        byte priority = 0;
        if ((streamType & 0x20) == 0 && !reader.TryReadByte(out priority))
        {
            return false;
        }

        header = new MoqStreamHeader(streamType, trackAlias, groupId, subgroupId, priority);
        consumed = b.Length - reader.Remaining;
        return true;
    }

    public static int WriteStreamHeader(Span<byte> b, in MoqStreamHeader header)
    {
        if (!ValidStreamType(header.StreamType))
        {
            ThrowStreamType();
        }

        if (header.HasSubgroupId != ((header.StreamType & 0x6) == 4) || header.HasPriority != ((header.StreamType & 0x20) == 0))
        {
            ThrowStreamType();
        }

        int w = WirePrimitives.WriteVarint(b, header.StreamType);
        w += WirePrimitives.WriteVarint(b[w..], header.TrackAlias);
        w += WirePrimitives.WriteVarint(b[w..], header.GroupId);
        if (header.HasSubgroupId)
        {
            w += WirePrimitives.WriteVarint(b[w..], header.SubgroupId);
        }

        if (header.HasPriority)
        {
            if (b.Length < w + 1)
            {
                ThrowTooSmall();
            }

            b[w] = header.Priority;
            w++;
        }

        return w;
    }

    public static bool TryReadObjectHeader(ReadOnlySpan<byte> b, bool extensionsPresent, out MoqObjectHeader header, out int consumed)
    {
        header = default;
        consumed = 0;
        var reader = new MoqSpanReader(b);
        if (!reader.TryReadVarint(out ulong objectId))
        {
            return false;
        }

        byte[]? extensions = null;
        if (extensionsPresent)
        {
            if (!reader.TryReadVarint(out ulong extensionLength)
                || extensionLength > (ulong)MaxParameterBlobBytes
                || extensionLength > (ulong)reader.Remaining)
            {
                return false;
            }

            ReadOnlySpan<byte> block = reader.Rest[..(int)extensionLength];
            if (!TryReadExtensionBlock(block, out var pairs, out _))
            {
                return false;
            }

            extensions = block.ToArray();
            reader.Skip((int)extensionLength);
        }

        if (!reader.TryReadVarint(out ulong payloadLength) || payloadLength > (ulong)MaxObjectPayloadBytes)
        {
            return false;
        }

        ulong status = 0;
        if (payloadLength == 0 && !reader.TryReadVarint(out status))
        {
            return false;
        }

        header = new MoqObjectHeader(objectId, extensions, payloadLength, status);
        consumed = b.Length - reader.Remaining;
        return true;
    }

    public static int WriteObjectHeader(Span<byte> b, in MoqObjectHeader header, bool extensionsPresent)
    {
        if (header.PayloadLength > (ulong)MaxObjectPayloadBytes)
        {
            ThrowObjectPayloadTooLarge();
        }

        if (extensionsPresent != (header.ExtensionBytes is not null))
        {
            ThrowExtensionPresence();
        }

        int w = WirePrimitives.WriteVarint(b, header.ObjectId);
        if (extensionsPresent)
        {
            if (!TryReadExtensionBlock(header.ExtensionBytes, out _, out _))
            {
                ThrowMalformedExtensions();
            }

            w += WriteParameterBlob(b[w..], header.ExtensionBytes);
        }

        w += WirePrimitives.WriteVarint(b[w..], header.PayloadLength);
        if (header.PayloadLength == 0)
        {
            w += WirePrimitives.WriteVarint(b[w..], header.Status);
        }

        return w;
    }

    private static void StartControlMessage(Span<byte> b, ulong type, out int body)
    {

        if (WirePrimitives.VarintLength(type) != 1 || b.Length < 3)
        {
            ThrowTooSmall();
        }

        b[0] = (byte)type;
        body = 3;
    }

    private static int FinishControlMessage(Span<byte> b, int body, int written)
    {
        if (written > MaxControlPayloadBytes)
        {
            ThrowControlPayloadTooLarge();
        }

        WirePrimitives.WriteU16Be(b[1..], (ushort)written);
        return body + written;
    }

    private static int WriteText(Span<byte> b, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        int byteCount = Encoding.UTF8.GetByteCount(value);
        if (byteCount > MaxTextBytes)
        {
            ThrowTextTooLarge();
        }

        if (b.Length < WirePrimitives.VarintLength((ulong)byteCount) + byteCount)
        {
            ThrowTooSmall();
        }

        int w = WirePrimitives.WriteVarint(b, (ulong)byteCount);
        return w + Encoding.UTF8.GetBytes(value.AsSpan(), b[w..]);
    }

    private static int WriteCount(Span<byte> b, int count)
    {
        if (count > MaxParameterPairs)
        {
            ThrowTooManyParameters();
        }

        return WirePrimitives.WriteVarint(b, (ulong)count);
    }

    private static int WritePairs(Span<byte> b, ReadOnlySpan<MoqParameter> parameters)
    {
        int w = 0;
        ulong previous = 0;
        for (int i = 0; i < parameters.Length; i++)
        {
            MoqParameter p = parameters[i];
            if (i > 0 && p.Key <= previous)
            {
                ThrowParameterKeys();
            }

            if (p.Key > WirePrimitives.VarintMax)
            {
                ThrowVarintRange();
            }

            bool blobForm = (p.Key & 1) != 0;
            if (blobForm != p.IsBlob || (blobForm && p.Blob is null))
            {
                ThrowParameterParity();
            }

            w += WirePrimitives.WriteVarint(b[w..], p.Key - previous);
            previous = p.Key;
            w += blobForm ? WriteParameterBlob(b[w..], p.Blob!) : WirePrimitives.WriteVarint(b[w..], p.Number);
        }

        return w;
    }

    private static int WriteParameterBlob(Span<byte> b, ReadOnlySpan<byte> value)
    {
        if (value.Length > MaxParameterBlobBytes)
        {
            ThrowBlobTooLarge();
        }

        if (b.Length < WirePrimitives.VarintLength((ulong)value.Length) + value.Length)
        {
            ThrowTooSmall();
        }

        int w = WirePrimitives.WriteVarint(b, (ulong)value.Length);
        value.CopyTo(b[w..]);
        return w + value.Length;
    }

    private static bool ValidStreamType(ulong type) =>
        (type & ~0x3fUL) == 0 && (type & 0x10) != 0 && (type & 0x6) != 0x6;

    private static bool ValidUtf8(ReadOnlySpan<byte> b)
    {
        int i = 0;
        while (i < b.Length)
        {
            byte first = b[i];
            if (first < 0x80)
            {
                i++;
                continue;
            }

            int extra;
            if (first >= 0xC2 && first <= 0xDF)
            {
                extra = 1;
            }
            else if (first >= 0xE0 && first <= 0xEF)
            {
                extra = 2;
            }
            else if (first >= 0xF0 && first <= 0xF4)
            {
                extra = 3;
            }
            else
            {
                return false;
            }

            if (b.Length - i - 1 < extra)
            {
                return false;
            }

            byte second = b[i + 1];
            if ((second & 0xC0) != 0x80)
            {
                return false;
            }

            if (extra == 2)
            {
                if ((b[i + 2] & 0xC0) != 0x80)
                {
                    return false;
                }

                if (first == 0xE0 && second < 0xA0)
                {
                    return false;
                }

                if (first == 0xED && second >= 0xA0)
                {
                    return false;
                }
            }
            else if (extra == 3)
            {
                if ((b[i + 2] & 0xC0) != 0x80 || (b[i + 3] & 0xC0) != 0x80)
                {
                    return false;
                }

                if (first == 0xF0 && second < 0x90)
                {
                    return false;
                }

                if (first == 0xF4 && second > 0x8F)
                {
                    return false;
                }
            }

            i += extra + 1;
        }

        return true;
    }

    private ref struct MoqSpanReader(ReadOnlySpan<byte> data)
    {
        private ReadOnlySpan<byte> _data = data;
        private int _offset;

        public readonly int Remaining => _data.Length - _offset;
        public readonly bool AtEnd => _offset == _data.Length;
        public readonly ReadOnlySpan<byte> Rest => _data[_offset..];

        public void Skip(int count) => _offset += count;

        public bool TryReadVarint(out ulong value)
        {
            if (WirePrimitives.TryReadVarint(_data[_offset..], out value, out int length))
            {
                _offset += length;
                return true;
            }

            return false;
        }

        public bool TryReadByte(out byte value)
        {
            if (AtEnd)
            {
                value = 0;
                return false;
            }

            value = _data[_offset];
            _offset++;
            return true;
        }

        public bool TryReadNamespace(out string value)
        {
            value = "";
            return TryReadVarint(out ulong count) && count == 1 && TryReadText(out value);
        }

        public bool TryReadText(out string value)
        {
            value = "";
            if (!TryReadVarint(out ulong length)
                || length > (ulong)MaxTextBytes
                || length > (ulong)Remaining)
            {
                return false;
            }

            ReadOnlySpan<byte> span = _data.Slice(_offset, (int)length);
            if (!ValidUtf8(span))
            {
                return false;
            }

            value = Encoding.UTF8.GetString(span);
            _offset += (int)length;
            return true;
        }

        public bool TryReadParameters(out MoqParameter[] values)
        {
            values = [];
            if (!TryReadVarint(out ulong count) || count > (ulong)MaxParameterPairs)
            {
                return false;
            }

            return TryReadPairList((int)count, out values);
        }

        public bool TryReadExtensionPairs(out MoqParameter[] values)
        {
            values = [];
            int start = _offset;
            int count = 0;
            ulong key = 0;
            while (!AtEnd)
            {
                if (!TryReadVarint(out ulong delta))
                {
                    return false;
                }

                ulong sum = key + delta;
                if (sum > WirePrimitives.VarintMax || (count > 0 && sum <= key))
                {
                    return false;
                }

                key = sum;
                if ((key & 1) == 0)
                {
                    if (!TryReadVarint(out _))
                    {
                        return false;
                    }
                }
                else
                {
                    if (!TryReadVarint(out ulong length)
                        || length > (ulong)MaxParameterBlobBytes
                        || length > (ulong)Remaining)
                    {
                        return false;
                    }

                    Skip((int)length);
                }

                count++;
                if (count > MaxParameterPairs)
                {
                    return false;
                }
            }

            _offset = start;
            return TryReadPairList(count, out values);
        }

        private bool TryReadPairList(int count, out MoqParameter[] values)
        {
            var result = new MoqParameter[count];
            ulong key = 0;
            for (int i = 0; i < count; i++)
            {
                if (!TryReadVarint(out ulong delta))
                {
                    values = [];
                    return false;
                }

                ulong sum = key + delta;

                if (sum > WirePrimitives.VarintMax || (i > 0 && sum <= key))
                {
                    values = [];
                    return false;
                }

                key = sum;
                if ((key & 1) == 0)
                {
                    if (!TryReadVarint(out ulong number))
                    {
                        values = [];
                        return false;
                    }

                    result[i] = new MoqParameter(key, number);
                }
                else if (!TryReadParameterBlob(out byte[] blob))
                {
                    values = [];
                    return false;
                }
                else
                {
                    result[i] = new MoqParameter(key, blob);
                }
            }

            values = result;
            return true;
        }

        public bool TryReadParameterBlob(out byte[] value)
        {
            value = [];
            if (!TryReadVarint(out ulong length)
                || length > (ulong)MaxParameterBlobBytes
                || length > (ulong)Remaining)
            {
                return false;
            }

            value = _data.Slice(_offset, (int)length).ToArray();
            _offset += (int)length;
            return true;
        }
    }

    private static void ThrowTooSmall() => throw new ArgumentException("destination span too small");

    private static void ThrowVarintRange() => throw new ArgumentOutOfRangeException("value", "varint values are at most 62 bits");

    private static void ThrowTextTooLarge() => throw new ArgumentOutOfRangeException("name", "text fields are at most 4096 UTF-8 bytes");

    private static void ThrowBlobTooLarge() => throw new ArgumentOutOfRangeException("value", "parameter blobs are at most 65535 bytes");

    private static void ThrowControlPayloadTooLarge() => throw new ArgumentOutOfRangeException("payload", "control payload is at most 65535 bytes");

    private static void ThrowObjectPayloadTooLarge() => throw new ArgumentOutOfRangeException("payloadLength", "object payloads are at most 65536 bytes");

    private static void ThrowTooManyParameters() => throw new ArgumentOutOfRangeException("parameters", "at most 128 parameter pairs");

    private static void ThrowParameterKeys() => throw new ArgumentException("parameter keys must be strictly ascending");

    private static void ThrowParameterParity() => throw new ArgumentException("even keys carry numbers, odd keys carry blobs");

    private static void ThrowStreamType() => throw new ArgumentOutOfRangeException("streamType", "invalid MoQ subgroup stream type bits");

    private static void ThrowExtensionPresence() => throw new ArgumentException("extension bytes must be present exactly when the stream type's extension bit is set");

    private static void ThrowMalformedExtensions() => throw new ArgumentException("extension block is not a well-formed pair list");

    private static void ThrowSetupType() => throw new ArgumentOutOfRangeException("type", "setup type must be CLIENT_SETUP or SERVER_SETUP");
}
