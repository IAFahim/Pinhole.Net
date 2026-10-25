using System.Net;
using System.Text;

namespace Pinhole.Wire;

public readonly record struct TurnAttribute(ushort Type, byte[] Value);

public sealed record TurnMessage(ushort MessageType, byte[] TransactionId, TurnAttribute[] Attributes)
{
    public bool HasAttribute(ushort type) => TryGetAttribute(type, out _);

    public bool TryGetAttribute(ushort type, out TurnAttribute attribute)
    {
        foreach (TurnAttribute candidate in Attributes)
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

// Canonical TURN codec (RFC 5766 over RFC 5389 framing) covering exactly the
// framing Pinhole.Turn.TurnClient produces and consumes — no crypto: integrity
// values are opaque 20-byte blobs. Total: TryRead never throws on
// wire-controlled bytes and returns false on every non-canonical form; Write
// throws only on programmer error. Canonical rules, all enforced by TryRead:
//   1. the span is at least 20 bytes, so the 12-byte transaction id is complete;
//   2. the message type is below 0x4000 (the two top bits of a STUN type are
//      zero; TurnClient never checks this, it just never sees such types);
//   3. the magic cookie at offset 4 is exactly 0x2112A442 (checked by
//      TurnClient's receive loop);
//   4. the header length field equals span length - 20: datagram exact, no
//      trailing bytes (checked by the receive loop);
//   5. the whole datagram — hence the header length — is a multiple of 4
//      (checked explicitly by the receive loop via (n & 3) != 0);
//   6. every attribute's 4-byte header and padded extent (4 + align4(length))
//      lie inside the body, and the walk ends exactly at the body end.
//      TurnClient.Attributes clamps overflowing attribute lengths and drops
//      stray tail bytes instead; the canonical codec rejects both;
//   7. attribute padding bytes are zero (the canonical form every encoder here
//      writes; TurnClient's walkers ignore padding bytes);
//   8. a MESSAGE-INTEGRITY attribute carries exactly 20 bytes —
//      TurnClient.TryAuthenticateResponse rejects any other length outright;
//   9. REQUESTED-TRANSPORT is 4 bytes: the protocol number then three zero
//      RFFU bytes (TurnClient writes [17,0,0,0] and never parses it back);
//  10. ERROR-CODE is at least 4 bytes with zero reserved bytes, class/number
//      in bytes [2]/[3], UTF-8 reason phrase after (TurnClient reads the same
//      layout but does not check the reserved bytes);
//  11. LIFETIME is exactly 4 big-endian bytes (TurnClient accepts any value of
//      at least 4 bytes and ignores the rest — the canonical form is exact);
//  12. address attributes (XOR-PEER, XOR-RELAYED, XOR-MAPPED, MAPPED) decode
//      with reserved byte 0, family 1 or 2, exact value length 8 or 20, and
//      the cookie||transaction-id XOR mask; the transaction id must be the full
//      12 bytes for the XOR form. TurnClient.DecodeAddress accepts values
//      longer than the address and ignores trailing bytes, and the receive loop
//      only requires >= 8 — the canonical codec rejects both;
//  13. data indications (0x0017) carry XOR-PEER-ADDRESS and DATA, and the last
//      occurrence of each wins, mirroring the receive loop's parse (an empty
//      DATA attribute is present, not absent — same as the receive loop).
public static class TurnCodec
{
    public const uint Cookie = 0x2112A442;
    public const ushort MethodAllocate = 0x0003;
    public const ushort MethodRefresh = 0x0004;
    public const ushort MethodCreatePermission = 0x0008;
    public const ushort MethodSendIndication = 0x0016;
    public const ushort MethodDataIndication = 0x0017;
    public const ushort ClassSuccess = 0x0100;
    public const ushort ClassError = 0x0110;
    public const byte TransportUdp = 17;

    public const ushort AttrMappedAddress = 0x0001;
    public const ushort AttrUsername = 0x0006;
    public const ushort AttrMessageIntegrity = 0x0008;
    public const ushort AttrErrorCode = 0x0009;
    public const ushort AttrLifetime = 0x000D;
    public const ushort AttrXorPeerAddress = 0x0012;
    public const ushort AttrData = 0x0013;
    public const ushort AttrRealm = 0x0014;
    public const ushort AttrNonce = 0x0015;
    public const ushort AttrXorRelayedAddress = 0x0016;
    public const ushort AttrRequestedTransport = 0x0019;
    public const ushort AttrXorMappedAddress = 0x0020;

    public static bool IsErrorResponse(ushort messageType) => (messageType & ClassError) == ClassError;

    public static bool IsSuccessResponse(ushort messageType) => (messageType & ClassError) == ClassSuccess;

    public static bool TryReadMessage(ReadOnlySpan<byte> source, out TurnMessage? message)
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

        TurnAttribute[] attributes = new TurnAttribute[count];
        if (count > 0 && !TryWalkAttributes(body, attributes, out _))
        {
            return false;
        }

        message = new TurnMessage(messageType, source.Slice(8, 12).ToArray(), attributes);
        return true;
    }

    public static int WriteMessage(Span<byte> destination, ushort messageType, ReadOnlySpan<byte> transactionId, ReadOnlySpan<TurnAttribute> attributes)
    {
        if (transactionId.Length != 12) ThrowTransactionIdLength();
        if (messageType >= 0x4000) ThrowMessageType();
        int bodyLength = 0;
        for (int i = 0; i < attributes.Length; i++)
        {
            if (attributes[i].Value is null) ThrowNullValue();
            if (attributes[i].Type == AttrMessageIntegrity && attributes[i].Value.Length != 20) ThrowIntegrityLength();
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

    public static bool TryReadErrorCode(ReadOnlySpan<byte> value, out int code, out string reason)
    {
        code = 0;
        reason = "";
        if (value.Length < 4 || value[0] != 0 || value[1] != 0) return false;
        code = value[2] * 100 + value[3];
        reason = Encoding.UTF8.GetString(value[4..]);
        return true;
    }

    public static int WriteErrorCode(Span<byte> destination, int code, ReadOnlySpan<byte> reasonUtf8)
    {
        if (code is < 300 or > 699) throw new ArgumentOutOfRangeException(nameof(code), "TURN error codes are 300..699");
        if (reasonUtf8.Length > ushort.MaxValue - 4) ThrowValueTooLarge();
        if (destination.Length < 4 + reasonUtf8.Length) ThrowTooSmall();
        destination[0] = 0;
        destination[1] = 0;
        destination[2] = (byte)(code / 100);
        destination[3] = (byte)(code % 100);
        reasonUtf8.CopyTo(destination[4..]);
        return 4 + reasonUtf8.Length;
    }

    public static bool TryReadLifetime(ReadOnlySpan<byte> value, out uint seconds)
    {
        seconds = 0;
        return value.Length == 4 && WirePrimitives.TryReadU32Be(value, out seconds);
    }

    public static int WriteLifetime(Span<byte> destination, uint seconds)
    {
        if (destination.Length < 4) ThrowTooSmall();
        Span<byte> cursor = destination;
        cursor = cursor[WirePrimitives.WriteU32Be(cursor, seconds)..];
        return 4;
    }

    public static bool TryReadRequestedTransport(ReadOnlySpan<byte> value, out byte protocol)
    {
        protocol = 0;
        if (value.Length != 4 || value[1] != 0 || value[2] != 0 || value[3] != 0) return false;
        protocol = value[0];
        return true;
    }

    public static int WriteRequestedTransport(Span<byte> destination, byte protocol)
    {
        if (destination.Length < 4) ThrowTooSmall();
        destination[0] = protocol;
        destination[1] = 0;
        destination[2] = 0;
        destination[3] = 0;
        return 4;
    }

    // Byte-identical to TurnClient.Request: attributes in the given order, then
    // MESSAGE-INTEGRITY last, with the header length field covering the
    // attribute bytes plus the 24-byte integrity attribute.
    public static int WriteAuthenticatedRequest(Span<byte> destination, ushort messageType, ReadOnlySpan<byte> transactionId, ReadOnlySpan<TurnAttribute> attributes, ReadOnlySpan<byte> messageIntegrity)
    {
        if (messageIntegrity.Length != 20) ThrowIntegrityLength();
        TurnAttribute[] all = new TurnAttribute[attributes.Length + 1];
        for (int i = 0; i < attributes.Length; i++)
        {
            if (attributes[i].Type == AttrMessageIntegrity) ThrowIntegrityPresent();
            all[i] = attributes[i];
        }

        all[attributes.Length] = new TurnAttribute(AttrMessageIntegrity, messageIntegrity.ToArray());
        return WriteMessage(destination, messageType, transactionId, all);
    }

    // The unauthenticated first allocate request TurnClient sends: one
    // REQUESTED-TRANSPORT attribute for UDP.
    public static int WriteAllocateRequest(Span<byte> destination, ReadOnlySpan<byte> transactionId)
    {
        TurnAttribute[] attributes = [new TurnAttribute(AttrRequestedTransport, [TransportUdp, 0, 0, 0])];
        return WriteMessage(destination, MethodAllocate, transactionId, attributes);
    }

    public static int WriteSendIndication(Span<byte> destination, ReadOnlySpan<byte> transactionId, IPEndPoint peer, ReadOnlySpan<byte> payload) =>
        WriteIndication(destination, MethodSendIndication, transactionId, peer, payload);

    public static int WriteDataIndication(Span<byte> destination, ReadOnlySpan<byte> transactionId, IPEndPoint peer, ReadOnlySpan<byte> payload) =>
        WriteIndication(destination, MethodDataIndication, transactionId, peer, payload);

    public static bool TryReadDataIndication(ReadOnlySpan<byte> source, out IPEndPoint? peer, out byte[]? payload)
    {
        peer = null;
        payload = null;
        if (!TryReadMessage(source, out TurnMessage? message) || message!.MessageType != MethodDataIndication) return false;
        foreach (TurnAttribute attribute in message.Attributes)
        {
            if (attribute.Type == AttrXorPeerAddress)
            {
                if (!TryReadAddress(attribute.Value, message.TransactionId, xor: true, out IPEndPoint? endpoint)) return false;
                peer = endpoint;
            }
            else if (attribute.Type == AttrData)
            {
                payload = attribute.Value;
            }
        }

        return peer is not null && payload is not null;
    }

    private static int WriteIndication(Span<byte> destination, ushort messageType, ReadOnlySpan<byte> transactionId, IPEndPoint peer, ReadOnlySpan<byte> payload)
    {
        Span<byte> address = stackalloc byte[20];
        int addressLength = WriteAddress(address, peer, transactionId, xor: true);
        TurnAttribute[] attributes =
        [
            new TurnAttribute(AttrXorPeerAddress, address[..addressLength].ToArray()),
            new TurnAttribute(AttrData, payload.ToArray()),
        ];
        return WriteMessage(destination, messageType, transactionId, attributes);
    }

    private static bool TryWalkAttributes(ReadOnlySpan<byte> body, TurnAttribute[]? attributes, out int count)
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
            if (type == AttrMessageIntegrity && length != 20) return false;
            for (int i = length; i < padded; i++)
            {
                if (body[position + 4 + i] != 0) return false;
            }

            if (attributes is not null)
            {
                attributes[count] = new TurnAttribute(type, body.Slice(position + 4, length).ToArray());
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

    private static void ThrowIntegrityLength() => throw new ArgumentException("message integrity is a 20-byte HMAC-SHA1");

    private static void ThrowIntegrityPresent() => throw new ArgumentException("attributes must not already contain MESSAGE-INTEGRITY");
}
