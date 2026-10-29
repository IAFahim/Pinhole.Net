using System.Net;
using System.Net.Sockets;

namespace Pinhole.Wire;

public readonly record struct StunAttribute(ushort Type, byte[] Value);

public sealed record StunMessage(ushort MessageType, byte[] TransactionId, StunAttribute[] Attributes)
{
    public bool TryGetAttribute(ushort type, out StunAttribute attribute)
    {
        foreach (StunAttribute candidate in Attributes)
        {
            if (candidate.Type == type)
            {
                attribute = candidate;
                return true;
            }
        }

        attribute = default;
        return false;
    }
}

public sealed record StunBindingResult(IPEndPoint Mapped, IPEndPoint? Origin, IPEndPoint? Other);

public static class StunCodec
{
    public const uint Cookie = 0x2112A442;
    public const ushort BindingRequest = 0x0001;
    public const ushort BindingSuccessResponse = 0x0101;
    public const ushort AttrMappedAddress = 0x0001;
    public const ushort AttrChangeRequest = 0x0003;
    public const ushort AttrXorMappedAddress = 0x0020;
    public const ushort AttrResponseOrigin = 0x802B;
    public const ushort AttrOtherAddress = 0x802C;

    public static bool TryReadMessage(ReadOnlySpan<byte> source, out StunMessage? message)
    {
        message = null;
        if (source.Length < 20
            || !WirePrimitives.TryReadU16Be(source, out ushort messageType)
            || !WirePrimitives.TryReadU16Be(source[2..], out ushort length)
            || !WirePrimitives.TryReadU32Be(source[4..], out uint cookie)
            || messageType >= 0x4000
            || (length & 3) != 0
            || cookie != Cookie
            || source.Length != 20 + length)
        {
            return false;
        }

        ReadOnlySpan<byte> body = source[20..];
        if (!TryWalkAttributes(body, null, out int count))
        {
            return false;
        }

        StunAttribute[] attributes = new StunAttribute[count];
        if (count > 0 && !TryWalkAttributes(body, attributes, out _))
        {
            return false;
        }

        message = new StunMessage(messageType, source.Slice(8, 12).ToArray(), attributes);
        return true;
    }

    public static int WriteMessage(Span<byte> destination, ushort messageType, ReadOnlySpan<byte> transactionId, ReadOnlySpan<StunAttribute> attributes)
    {
        if (transactionId.Length != 12) ThrowTransactionIdLength();
        if (messageType >= 0x4000) ThrowMessageType();
        int bodyLength = 0;
        for (int i = 0; i < attributes.Length; i++)
        {
            if (attributes[i].Value is null) ThrowNullValue();
            bodyLength += 4 + ((attributes[i].Value.Length + 3) & ~3);
        }

        if (bodyLength > ushort.MaxValue) ThrowBodyTooLarge();
        if (destination.Length < 20 + bodyLength) ThrowTooSmall();

        Span<byte> cursor = destination;
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, messageType)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, (ushort)bodyLength)..];
        cursor = cursor[WirePrimitives.WriteU32Be(cursor, Cookie)..];
        transactionId.CopyTo(cursor);
        cursor = cursor[12..];
        for (int i = 0; i < attributes.Length; i++)
        {
            cursor = cursor[WriteAttribute(cursor, attributes[i].Type, attributes[i].Value)..];
        }

        return 20 + bodyLength;
    }

    public static int WriteAttribute(Span<byte> destination, ushort type, ReadOnlySpan<byte> value)
    {
        if (value.Length > ushort.MaxValue) ThrowValueTooLarge();
        int padded = (value.Length + 3) & ~3;
        if (destination.Length < 4 + padded) ThrowTooSmall();
        Span<byte> cursor = destination;
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, type)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, (ushort)value.Length)..];
        value.CopyTo(cursor);
        cursor[value.Length..padded].Clear();
        return 4 + padded;
    }

    public static bool TryReadAddress(ReadOnlySpan<byte> value, ReadOnlySpan<byte> transactionId, bool xor, out IPEndPoint? endpoint)
    {
        endpoint = null;
        if (value.Length < 4 || value[0] != 0) return false;
        if (xor && transactionId.Length != 12) return false;
        int addressBytes = value[1] switch { 1 => 4, 2 => 16, _ => 0 };
        if (addressBytes == 0 || value.Length != 4 + addressBytes) return false;
        if (!WirePrimitives.TryReadU16Be(value[2..], out ushort port)) return false;
        Span<byte> address = stackalloc byte[16];
        value.Slice(4, addressBytes).CopyTo(address);
        if (xor)
        {
            port ^= (ushort)(Cookie >> 16);
            Span<byte> mask = stackalloc byte[16];
            Span<byte> maskCursor = mask;
            maskCursor = maskCursor[WirePrimitives.WriteU32Be(maskCursor, Cookie)..];
            transactionId.CopyTo(maskCursor);
            for (int i = 0; i < addressBytes; i++)
            {
                address[i] ^= mask[i];
            }
        }

        endpoint = new IPEndPoint(new IPAddress(address[..addressBytes]), port);
        return true;
    }

    public static int WriteAddress(Span<byte> destination, IPEndPoint endpoint, ReadOnlySpan<byte> transactionId, bool xor)
    {
        if (xor && transactionId.Length != 12) ThrowTransactionIdLength();
        byte[] raw = endpoint.Address.GetAddressBytes();
        if (raw.Length is not (4 or 16)) ThrowAddressFamily();
        if (destination.Length < 4 + raw.Length) ThrowTooSmall();
        destination[0] = 0;
        destination[1] = (byte)(raw.Length == 4 ? 1 : 2);
        ushort port = (ushort)endpoint.Port;
        if (xor)
        {
            port ^= (ushort)(Cookie >> 16);
        }

        Span<byte> cursor = destination[2..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, port)..];
        if (xor)
        {
            Span<byte> mask = stackalloc byte[16];
            Span<byte> maskCursor = mask;
            maskCursor = maskCursor[WirePrimitives.WriteU32Be(maskCursor, Cookie)..];
            transactionId.CopyTo(maskCursor);
            for (int i = 0; i < raw.Length; i++)
            {
                destination[4 + i] = (byte)(raw[i] ^ mask[i]);
            }
        }
        else
        {
            raw.AsSpan().CopyTo(destination[4..]);
        }

        return 4 + raw.Length;
    }

    public static int WriteBindingRequest(Span<byte> destination, ReadOnlySpan<byte> transactionId, uint change = 0)
    {
        if (change is not (0 or 2 or 6)) throw new ArgumentOutOfRangeException(nameof(change), "change flags are 0, 2 or 6");
        if (transactionId.Length != 12) ThrowTransactionIdLength();
        int total = change == 0 ? 20 : 28;
        if (destination.Length < total) ThrowTooSmall();
        Span<byte> cursor = destination;
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, BindingRequest)..];
        cursor = cursor[WirePrimitives.WriteU16Be(cursor, (ushort)(total - 20))..];
        cursor = cursor[WirePrimitives.WriteU32Be(cursor, Cookie)..];
        transactionId.CopyTo(cursor);
        if (change != 0)
        {
            cursor = cursor[12..];
            cursor = cursor[WirePrimitives.WriteU16Be(cursor, AttrChangeRequest)..];
            cursor = cursor[WirePrimitives.WriteU16Be(cursor, 4)..];
            cursor = cursor[WirePrimitives.WriteU32Be(cursor, change)..];
        }

        return total;
    }

    public static bool TryReadBindingRequest(ReadOnlySpan<byte> source, out StunMessage? message, out uint change)
    {
        message = null;
        change = 0;
        if (!TryReadMessage(source, out StunMessage? parsed) || parsed!.MessageType != BindingRequest) return false;
        if (parsed.Attributes.Length == 0)
        {
            message = parsed;
            return true;
        }

        if (parsed.Attributes.Length != 1
            || parsed.Attributes[0].Type != AttrChangeRequest
            || parsed.Attributes[0].Value.Length != 4
            || !WirePrimitives.TryReadU32Be(parsed.Attributes[0].Value, out uint value)
            || value is not (2 or 6))
        {
            return false;
        }

        message = parsed;
        change = value;
        return true;
    }

    public static int WriteBindingResponse(Span<byte> destination, ReadOnlySpan<byte> transactionId, IPEndPoint mapped, IPEndPoint? origin = null, IPEndPoint? other = null)
    {
        if (transactionId.Length != 12) ThrowTransactionIdLength();
        Span<byte> value = stackalloc byte[20];
        int mappedLength = WriteAddress(value, mapped, transactionId, xor: true);
        StunAttribute[] attributes = new StunAttribute[1 + (origin is null ? 0 : 1) + (other is null ? 0 : 1)];
        attributes[0] = new StunAttribute(AttrXorMappedAddress, value[..mappedLength].ToArray());
        int next = 1;
        if (origin is not null)
        {
            int originLength = WriteAddress(value, origin, transactionId, xor: false);
            attributes[next++] = new StunAttribute(AttrResponseOrigin, value[..originLength].ToArray());
        }

        if (other is not null)
        {
            int otherLength = WriteAddress(value, other, transactionId, xor: false);
            attributes[next] = new StunAttribute(AttrOtherAddress, value[..otherLength].ToArray());
        }

        return WriteMessage(destination, BindingSuccessResponse, transactionId, attributes);
    }

    public static bool TryReadBindingResponse(ReadOnlySpan<byte> source, IPEndPoint expectedOrigin, out StunBindingResult? reply)
    {
        reply = null;
        if (!TryReadMessage(source, out StunMessage? message) || message!.MessageType != BindingSuccessResponse) return false;
        IPEndPoint? mapped = null, xorMapped = null, origin = null, other = null;
        foreach (StunAttribute attribute in message.Attributes)
        {
            if (attribute.Type is not (AttrMappedAddress or AttrXorMappedAddress or AttrResponseOrigin or AttrOtherAddress)) continue;
            bool xor = attribute.Type == AttrXorMappedAddress;
            if (!TryReadAddress(attribute.Value, message.TransactionId, xor, out IPEndPoint? endpoint) || !IsUsable(endpoint!)) return false;
            switch (attribute.Type)
            {
                case AttrMappedAddress:
                    if (!SetOnce(ref mapped, endpoint!)) return false;
                    break;
                case AttrXorMappedAddress:
                    if (!SetOnce(ref xorMapped, endpoint!)) return false;
                    break;
                case AttrResponseOrigin:
                    if (!SetOnce(ref origin, endpoint!)) return false;
                    break;
                default:
                    if (!SetOnce(ref other, endpoint!)) return false;
                    break;
            }
        }

        if (origin is not null && !origin.Equals(expectedOrigin)
            || (xorMapped ?? mapped) is not { } observed
            || observed.AddressFamily != expectedOrigin.AddressFamily)
        {
            return false;
        }

        reply = new StunBindingResult(observed, origin, other);
        return true;
    }

    public static bool IsUsable(IPEndPoint endpoint) => endpoint.Port > 0
        && !endpoint.Address.Equals(IPAddress.Any)
        && !endpoint.Address.Equals(IPAddress.IPv6Any)
        && !endpoint.Address.IsIPv6Multicast
        && (endpoint.AddressFamily != AddressFamily.InterNetwork || endpoint.Address.GetAddressBytes()[0] is > 0 and < 224);

    private static bool SetOnce(ref IPEndPoint? slot, IPEndPoint next)
    {
        if (slot is not null) return slot.Equals(next);
        slot = next;
        return true;
    }

    private static bool TryWalkAttributes(ReadOnlySpan<byte> body, StunAttribute[]? attributes, out int count)
    {
        count = 0;
        int position = 0;
        while (position < body.Length)
        {
            if (position + 4 > body.Length
                || !WirePrimitives.TryReadU16Be(body[position..], out ushort type)
                || !WirePrimitives.TryReadU16Be(body[(position + 2)..], out ushort length))
            {
                return false;
            }

            int padded = (length + 3) & ~3;
            if (position + 4 + padded > body.Length) return false;
            for (int i = length; i < padded; i++)
            {
                if (body[position + 4 + i] != 0) return false;
            }

            if (attributes is not null)
            {
                attributes[count] = new StunAttribute(type, body.Slice(position + 4, length).ToArray());
            }

            count++;
            position += 4 + padded;
        }

        return true;
    }

    private static void ThrowTooSmall() => throw new ArgumentException("destination span too small");

    private static void ThrowTransactionIdLength() => throw new ArgumentException("transaction id must be 12 bytes");

    private static void ThrowMessageType() => throw new ArgumentOutOfRangeException("messageType", "STUN message types are below 0x4000");

    private static void ThrowBodyTooLarge() => throw new ArgumentException("attributes exceed the STUN length field");

    private static void ThrowValueTooLarge() => throw new ArgumentException("attribute value exceeds 65535 bytes");

    private static void ThrowNullValue() => throw new ArgumentException("attribute value is null");

    private static void ThrowAddressFamily() => throw new ArgumentException("endpoint address must be IPv4 or IPv6");
}
