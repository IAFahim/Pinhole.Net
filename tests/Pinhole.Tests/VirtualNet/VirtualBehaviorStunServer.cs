using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Pinhole.Tests;

/// <summary>Independent four-address RFC 5780 responder. It actually sends changed
/// responses from another virtual socket, so NAT inbound filters decide delivery.</summary>
internal sealed class VirtualBehaviorStunServer : IDisposable
{
    private readonly VirtualUdpSocket[] _sockets;
    private volatile bool _running = true;
    internal bool IncludeAlternates = true;
    internal bool IgnoreChange;
    internal readonly ConcurrentQueue<(IPEndPoint Destination, uint Change)> Requests = new();
    internal IPEndPoint Primary => _sockets[0].LocalEndPoint;
    internal IPEndPoint Other => _sockets[3].LocalEndPoint;

    internal VirtualBehaviorStunServer(VirtualNetwork network, bool ipv6 = false)
    {
        IPAddress a = IPAddress.Parse(ipv6 ? "2001:db8::90" : "192.0.2.90");
        IPAddress b = IPAddress.Parse(ipv6 ? "2001:db8::91" : "192.0.2.91");
        _sockets = [network.CreateHost(new(a, 3478)), network.CreateHost(new(a, 3479)),
            network.CreateHost(new(b, 3478)), network.CreateHost(new(b, 3479))];
        for (int i = 0; i < _sockets.Length; i++)
        {
            int index = i;
            new Thread(() => Receive(index)) { IsBackground = true, Name = "behavior-stun" }.Start();
        }
    }

    private void Receive(int index)
    {
        byte[] buffer = new byte[128]; var source = new SocketAddress(AddressFamily.InterNetworkV6);
        while (_running)
        {
            int count;
            try { count = _sockets[index].ReceiveFrom(buffer, source); }
            catch (SocketException) { continue; }
            catch (ObjectDisposedException) { return; }
            if (count < 20 || BinaryPrimitives.ReadUInt16BigEndian(buffer) != 1
                || BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(4)) != 0x2112a442) continue;
            uint change = count == 28 && BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(20)) == 3
                ? BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(24)) : 0;
            Requests.Enqueue((_sockets[index].LocalEndPoint, change));
            if (IgnoreChange && change != 0) continue;
            int senderIndex = index ^ (int)(change & 2) / 2 ^ (int)(change & 4) / 2;
            var observed = (IPEndPoint)new IPEndPoint(IPAddress.IPv6Any, 0).Create(source);
            if (observed.Address.IsIPv4MappedToIPv6) observed = new(observed.Address.MapToIPv4(), observed.Port);
            byte[] response = Response(buffer.AsSpan(8, 12), observed, _sockets[senderIndex].LocalEndPoint,
                IncludeAlternates ? _sockets[senderIndex ^ 3].LocalEndPoint : null);
            try { _sockets[senderIndex].SendTo(response, source); }
            catch (ObjectDisposedException) { return; }
        }
    }

    // The fixture encoder deliberately does not use the production message codec.
    internal static byte[] Response(ReadOnlySpan<byte> transaction, IPEndPoint mapped, IPEndPoint origin, IPEndPoint? other)
    {
        int valueLength = mapped.AddressFamily == AddressFamily.InterNetwork ? 8 : 20;
        byte[] message = new byte[20 + (valueLength + 4) * (other is null ? 2 : 3)];
        BinaryPrimitives.WriteUInt16BigEndian(message, 0x0101);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), (ushort)(message.Length - 20));
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(4), 0x2112a442);
        transaction.CopyTo(message.AsSpan(8));
        Write(message.AsSpan(20), 0x0020, mapped, transaction, xor: true);
        Write(message.AsSpan(24 + valueLength), 0x802b, origin, transaction, xor: false);
        if (other is not null) Write(message.AsSpan(28 + 2 * valueLength), 0x802c, other, transaction, xor: false);
        return message;
    }

    private static void Write(Span<byte> attribute, ushort type, IPEndPoint endpoint, ReadOnlySpan<byte> transaction, bool xor)
    {
        byte[] address = endpoint.Address.GetAddressBytes();
        BinaryPrimitives.WriteUInt16BigEndian(attribute, type);
        BinaryPrimitives.WriteUInt16BigEndian(attribute[2..], (ushort)(4 + address.Length));
        attribute[5] = (byte)(address.Length == 4 ? 1 : 2);
        BinaryPrimitives.WriteUInt16BigEndian(attribute[6..], (ushort)(endpoint.Port ^ (xor ? 0x2112 : 0)));
        ReadOnlySpan<byte> cookie = [0x21, 0x12, 0xa4, 0x42];
        for (int i = 0; i < address.Length; i++)
            attribute[8 + i] = (byte)(address[i] ^ (xor ? i < 4 ? cookie[i] : transaction[i - 4] : 0));
    }

    public void Dispose() { _running = false; foreach (var socket in _sockets) socket.Dispose(); }
}
