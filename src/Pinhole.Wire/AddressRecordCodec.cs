using System.Net;
using System.Net.Sockets;

namespace Pinhole.Wire;

public static class AddressRecordCodec
{
    public const int EndpointKeyLength = 32;

    public const int SignatureLength = 64;

    public const int MaxDirectEndpoints = 16;

    public const int MaxRelayedEndpoints = 4;

    public const int MaxEndpointEncoding = 1 + 16 + 2;

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
                return false;
            }

            int relayedCount = wire[pos++];
            if (relayedCount == 0)
            {
                return false;
            }

            if (!TryReadEndpointList(wire, MaxRelayedEndpoints, relayedCount, ref pos, out relayed))
            {
                return false;
            }
        }

        if (pos != wire.Length)
        {
            return false;
        }

        body = new AddressRecordBody(
            peerId,
            wire.Slice(9, EndpointKeyLength).ToArray(),
            sequence,
            unchecked((long)expiryRaw),
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

public readonly record struct AddressRecordBody(
    ulong PeerId,
    byte[] EndpointKey,
    ulong Sequence,
    long ExpiresAtUnixSeconds,
    IPEndPoint[] Endpoints,
    IPEndPoint[] RelayedEndpoints);

public readonly record struct SignedAddressRecord(AddressRecordBody Body, byte[] Signature);
