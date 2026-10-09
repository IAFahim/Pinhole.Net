using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Pinhole;

internal sealed record StunBindingReply(IPEndPoint Mapped, IPEndPoint? Origin, IPEndPoint? Other);

/// <summary>RFC 8489 binding messages and RFC 5780 behavior attributes. Source,
/// local socket and all transaction bytes are checked by the receiving engine.</summary>
internal static class StunBindingMessage
{
    internal const uint Cookie = 0x2112A442;

    internal static byte[] Request(uint change = 0)
    {
        if (change is not (0 or 2 or 6)) throw new ArgumentOutOfRangeException(nameof(change));
        byte[] request = new byte[change == 0 ? 20 : 28];
        BinaryPrimitives.WriteUInt16BigEndian(request, 1);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), (ushort)(request.Length - 20));
        BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4), Cookie);
        RandomNumberGenerator.Fill(request.AsSpan(8, 12));
        if (change != 0)
        {
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(20), 3);
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(22), 4);
            BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(24), change);
        }
        return request;
    }

    internal static bool TryRead(ReadOnlySpan<byte> message, IPEndPoint expectedOrigin, out StunBindingReply? reply)
    {
        reply = null;
        if (message.Length < 20 || BinaryPrimitives.ReadUInt16BigEndian(message) != 0x0101
            || BinaryPrimitives.ReadUInt32BigEndian(message[4..]) != Cookie
            || message.Length != 20 + BinaryPrimitives.ReadUInt16BigEndian(message[2..])) return false;
        IPEndPoint? mapped = null, xorMapped = null, origin = null, other = null;
        int position = 20;
        while (position < message.Length)
        {
            if (position + 4 > message.Length) return false;
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(message[position..]);
            int length = BinaryPrimitives.ReadUInt16BigEndian(message[(position + 2)..]);
            int padded = (length + 3) & ~3;
            if (position + 4 + padded > message.Length) return false;
            if (type is 0x0001 or 0x0020 or 0x802b or 0x802c)
            {
                if (!TryAddress(message.Slice(position + 4, length), message.Slice(8, 12), type == 0x0020, out IPEndPoint? endpoint)
                    || !Usable(endpoint!)) return false;
                switch (type)
                {
                    case 0x0001: if (!SetOnce(ref mapped, endpoint!)) return false; break;
                    case 0x0020: if (!SetOnce(ref xorMapped, endpoint!)) return false; break;
                    case 0x802b: if (!SetOnce(ref origin, endpoint!)) return false; break;
                    case 0x802c: if (!SetOnce(ref other, endpoint!)) return false; break;
                }
            }
            position += 4 + padded;
        }
        if (origin is not null && !origin.Equals(expectedOrigin) || (xorMapped ?? mapped) is not { } observed
            || observed.AddressFamily != expectedOrigin.AddressFamily) return false;
        reply = new(observed, origin, other);
        return true;
    }

    private static bool SetOnce(ref IPEndPoint? value, IPEndPoint next)
    {
        if (value is not null) return value.Equals(next);
        value = next;
        return true;
    }

    internal static bool Usable(IPEndPoint endpoint) => endpoint.Port > 0
        && !endpoint.Address.Equals(IPAddress.Any) && !endpoint.Address.Equals(IPAddress.IPv6Any)
        && !endpoint.Address.IsIPv6Multicast
        && (endpoint.AddressFamily != AddressFamily.InterNetwork || endpoint.Address.GetAddressBytes()[0] is > 0 and < 224);

    private static bool TryAddress(ReadOnlySpan<byte> value, ReadOnlySpan<byte> transaction, bool xor, out IPEndPoint? endpoint)
    {
        endpoint = null;
        if (value.Length < 4 || value[0] != 0) return false;
        int bytes = value[1] switch { 1 => 4, 2 => 16, _ => 0 };
        if (bytes == 0 || value.Length != 4 + bytes) return false;
        int port = BinaryPrimitives.ReadUInt16BigEndian(value[2..]);
        Span<byte> address = stackalloc byte[bytes];
        value[4..].CopyTo(address);
        if (xor)
        {
            port ^= (int)(Cookie >> 16);
            Span<byte> mask = stackalloc byte[16];
            BinaryPrimitives.WriteUInt32BigEndian(mask, Cookie);
            transaction.CopyTo(mask[4..]);
            for (int i = 0; i < bytes; i++) address[i] ^= mask[i];
        }
        endpoint = new(new IPAddress(address), port);
        return true;
    }
}
