using System.Net;
using System.Net.Sockets;

namespace Pinhole.Wire;

// Canonical codec for the Pinhole address record (differential oracle: Pinhole.AddressRecord).
// The signed-body byte layout is a compatibility contract — Ed25519 signatures cover these
// exact bytes, so readers and the writer must reproduce them byte-for-byte:
//
//   version   u8       1 = direct endpoints only; 2 = a relayed endpoint list is appended
//   peerId    u64 LE
//   key       32 raw bytes (Ed25519 public key)
//   sequence  u64 LE
//   expiry    i64 LE   raw Unix seconds; returned as a plain long — never routed through
//                     DateTimeOffset on wire values (audit C-06), so no bit pattern can
//                     throw; range/expiry policy belongs to the verifying caller
//   direct endpoints:   count u8, then per endpoint family u8 (4|16) + address + port u16 BE
//   relayed endpoints:  same list encoding, present only in version 2
//
// The full signed record is body || 64-byte Ed25519 signature; the signature bytes are
// opaque to this codec (verification needs the key and is the caller's job).
//
// Canonical rules the readers enforce (documented; violations return false, never throw):
//   1. the version byte is exactly 1 or 2 — unknown versions or stray high bits fail;
//   2. bodies shorter than the fixed header (58 bytes) fail;
//   3. endpoint family is 4 or 16 and the address and port bytes must all be present;
//   4. at most 16 direct endpoints and 4 relayed endpoints;
//   5. version 1 carries no relayed list; version 2 carries at least one relayed endpoint —
//      the legacy encoder emits v2 only when relayed endpoints exist, so an empty v2 list is
//      non-canonical (the legacy parser is more lenient and accepts it; see the tests);
//   6. trailing bytes after the last endpoint fail — a body must consume its input exactly,
//      which is what makes accept => WriteBody(TryReadBody(x)) == x hold;
//   7. expiry is surfaced as the raw 64-bit integer regardless of bit pattern.
//
// WriteBody throws only on programmer error: wrong key length or endpoint counts over the
// caps throw InvalidOperationException (same conditions and messages as AddressRecord.Encode);
// a destination span smaller than the encoding throws ArgumentException.
public static class AddressRecordCodec
{
    public const int EndpointKeyLength = 32;

    public const int SignatureLength = 64;

    public const int MaxDirectEndpoints = 16;

    public const int MaxRelayedEndpoints = 4;

    public const int MaxEndpointEncoding = 1 + 16 + 2; // family + longest address + port

    // version + peerId + key + sequence + expiry + direct endpoint count
    public const int MinimumBodyLength = 1 + 8 + EndpointKeyLength + 8 + 8 + 1;

    public const int MaxEncodedLength =
        MinimumBodyLength
        + MaxDirectEndpoints * MaxEndpointEncoding
        + 1 + MaxRelayedEndpoints * MaxEndpointEncoding;

    private const byte WireVersion1 = 1;

    private const byte WireVersion2 = 2;

    public static bool TryReadBody(ReadOnlySpan<byte> wire, out AddressRecordBody body, out int consumed)
    {
        body = new AddressRecordBody(0, [], 0, 0, [], []);
        consumed = 0;
        if (wire.Length < MinimumBodyLength)
        {
            return false;
        }

        byte version = wire[0];
        if (version is not (WireVersion1 or WireVersion2))
        {
            return false;
        }

        if (!WirePrimitives.TryReadU64Le(wire[1..], out ulong peerId)
            || !WirePrimitives.TryReadU64Le(wire[41..], out ulong sequence)
            || !WirePrimitives.TryReadU64Le(wire[49..], out ulong expiryRaw))
        {
            return false;
        }

        int pos = 57;
        int directCount = wire[pos++];
        if (!TryReadEndpointList(wire, MaxDirectEndpoints, directCount, ref pos, out IPEndPoint[] endpoints))
        {
            return false;
        }

        IPEndPoint[] relayed = [];
        if (version == WireVersion2)
        {
            if (pos >= wire.Length)
            {
                return false; // the relayed count byte is missing
            }

            int relayedCount = wire[pos++];
            if (relayedCount == 0)
            {
                return false; // non-canonical: v2 exists only to carry relayed endpoints
            }

            if (!TryReadEndpointList(wire, MaxRelayedEndpoints, relayedCount, ref pos, out relayed))
            {
                return false;
            }
        }

        if (pos != wire.Length)
        {
            return false; // trailing bytes: the record would not cover exactly what was parsed
        }

        body = new AddressRecordBody(
            peerId,
            wire.Slice(9, EndpointKeyLength).ToArray(),
            sequence,
            unchecked((long)expiryRaw), // raw Unix seconds; no DateTimeOffset conversion on wire data (C-06)
            endpoints,
            relayed);
        consumed = pos;
        return true;
    }

    public static bool TryReadSigned(ReadOnlySpan<byte> wire, out SignedAddressRecord record, out int consumed)
    {
        record = new SignedAddressRecord(new AddressRecordBody(0, [], 0, 0, [], []), []);
        consumed = 0;
        if (wire.Length < MinimumBodyLength + SignatureLength)
        {
            return false;
        }

        if (!TryReadBody(wire[..^SignatureLength], out AddressRecordBody body, out int bodyLength))
        {
            return false;
        }

        record = new SignedAddressRecord(body, wire[^SignatureLength..].ToArray());
        consumed = bodyLength + SignatureLength;
        return true;
    }

    public static int WriteBody(in AddressRecordBody body, Span<byte> destination)
    {
        if (body.EndpointKey is not { Length: EndpointKeyLength })
        {
            throw new InvalidOperationException($"endpoint keys are {EndpointKeyLength} bytes");
        }

        if (body.Endpoints.Length > MaxDirectEndpoints)
        {
            throw new InvalidOperationException($"records carry at most {MaxDirectEndpoints} endpoints");
        }

        if (body.RelayedEndpoints.Length > MaxRelayedEndpoints)
        {
            throw new InvalidOperationException($"records carry at most {MaxRelayedEndpoints} relayed endpoints");
        }

        // MinimumBodyLength already contains the direct count byte, so the direct list
        // contributes only its endpoint bytes here; a relayed list adds count + endpoints.
        int needed = MinimumBodyLength + EndpointBytesSize(body.Endpoints)
            + (body.RelayedEndpoints.Length > 0 ? 1 + EndpointBytesSize(body.RelayedEndpoints) : 0);
        if (destination.Length < needed)
        {
            ThrowTooSmall();
        }

        bool hasRelayed = body.RelayedEndpoints.Length > 0;
        destination[0] = hasRelayed ? WireVersion2 : WireVersion1;
        int pos = 1;
        pos += WirePrimitives.WriteU64Le(destination[pos..], body.PeerId);
        body.EndpointKey.AsSpan().CopyTo(destination[pos..]);
        pos += EndpointKeyLength;
        pos += WirePrimitives.WriteU64Le(destination[pos..], body.Sequence);
        pos += WirePrimitives.WriteU64Le(destination[pos..], unchecked((ulong)body.ExpiresAtUnixSeconds));
        destination[pos++] = (byte)body.Endpoints.Length;
        WriteEndpointList(body.Endpoints, destination, ref pos);
        if (hasRelayed)
        {
            destination[pos++] = (byte)body.RelayedEndpoints.Length;
            WriteEndpointList(body.RelayedEndpoints, destination, ref pos);
        }

        return pos;
    }

    private static bool TryReadEndpointList(
        ReadOnlySpan<byte> wire,
        int cap,
        int count,
        ref int pos,
        out IPEndPoint[] endpoints)
    {
        endpoints = [];
        if (count > cap)
        {
            return false;
        }

        var parsed = new IPEndPoint[count];
        for (int i = 0; i < count; i++)
        {
            if (pos >= wire.Length)
            {
                return false;
            }

            int family = wire[pos++];
            if (family is not 4 and not 16 || pos + family + 2 > wire.Length)
            {
                return false;
            }

            if (!WirePrimitives.TryReadU16Be(wire.Slice(pos + family), out ushort port))
            {
                return false;
            }

            // family is 4 or 16 and the slice length matches, so this ctor cannot throw
            parsed[i] = new IPEndPoint(new IPAddress(wire.Slice(pos, family)), port);
            pos += family + 2;
        }

        endpoints = parsed;
        return true;
    }

    private static void WriteEndpointList(IPEndPoint[] endpoints, Span<byte> destination, ref int pos)
    {
        foreach (IPEndPoint endpoint in endpoints)
        {
            byte[] raw = endpoint.Address.GetAddressBytes();
            destination[pos++] = (byte)raw.Length;
            raw.AsSpan().CopyTo(destination[pos..]);
            pos += raw.Length;
            pos += WirePrimitives.WriteU16Be(destination[pos..], (ushort)endpoint.Port);
        }
    }

    private static int EndpointBytesSize(IPEndPoint[] endpoints)
    {
        int size = 0;
        foreach (IPEndPoint endpoint in endpoints)
        {
            size += 1 + AddressSize(endpoint) + 2;
        }

        return size;
    }

    private static int AddressSize(IPEndPoint endpoint) =>
        endpoint.Address.AddressFamily == AddressFamily.InterNetworkV6 ? 16 : 4;

    private static void ThrowTooSmall() => throw new ArgumentException("destination span too small");
}

// The unsigned fields that the Ed25519 signature covers. ExpiresAtUnixSeconds is the raw
// wire integer; converting to DateTimeOffset is the caller's decision after verification.
// Array members participate in record equality by reference — compare via WriteBody bytes.
public readonly record struct AddressRecordBody(
    ulong PeerId,
    byte[] EndpointKey,
    ulong Sequence,
    long ExpiresAtUnixSeconds,
    IPEndPoint[] Endpoints,
    IPEndPoint[] RelayedEndpoints);

// The full signed record: body plus the detached 64-byte signature.
public readonly record struct SignedAddressRecord(AddressRecordBody Body, byte[] Signature);
