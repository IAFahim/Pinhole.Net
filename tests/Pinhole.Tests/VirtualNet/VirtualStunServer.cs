using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Pinhole.Tests;

/// <summary>An RFC 5389 STUN responder attached to a <see cref="VirtualNetwork"/> address.
/// It reports the source it observes — which, behind a virtual NAT, is the NAT's public
/// mapping, so the engine's reflexive discovery and its symmetric-NAT detection (two
/// servers, divergent mappings) run against real address translation physics.</summary>
internal sealed class VirtualStunServer : IDisposable
{
    private const uint Cookie = 0x2112A442;

    private readonly VirtualUdpSocket _socket;
    private readonly byte[] _buf = new byte[1500];
    private volatile bool _running = true;

    public VirtualStunServer(VirtualNetwork net, IPEndPoint address)
    {
        _socket = net.CreateHost(address);
        new Thread(Run) { IsBackground = true, Name = "virtual-stun" }.Start();
    }

    public IPEndPoint LocalEndPoint => _socket.Address;

    private void Run()
    {
        var remote = new SocketAddress(AddressFamily.InterNetworkV6);
        while (_running)
        {
            int n;
            try
            {
                n = _socket.ReceiveFrom(_buf, remote);
            }
            catch (SocketException)
            {
                continue; // the 200 ms poll wake
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            if (n < 20 || BinaryPrimitives.ReadUInt32BigEndian(_buf.AsSpan(4)) != Cookie)
            {
                continue;
            }

            IPEndPoint observed = (IPEndPoint)new IPEndPoint(IPAddress.IPv6Any, 0).Create(remote);
            if (observed.Address.IsIPv4MappedToIPv6)
            {
                observed = new IPEndPoint(observed.Address.MapToIPv4(), observed.Port);
            }

            _socket.SendTo(BuildResponse(_buf[8..20], observed), remote);
        }
    }

    private static byte[] BuildResponse(byte[] txid, IPEndPoint observed)
    {
        // XOR-MAPPED-ADDRESS (0x0020): reserved(0) + family + port^cookie>>16 + addr^mask
        byte[] raw = observed.Address.GetAddressBytes();
        bool v4 = raw.Length == 4;
        byte[] value = new byte[4 + raw.Length];
        value[1] = (byte)(v4 ? 0x01 : 0x02);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2), (ushort)(observed.Port ^ (Cookie >> 16)));
        for (int i = 0; i < raw.Length; i++)
        {
            byte mask = i < 4 ? (byte)(Cookie >> (24 - i * 8)) : txid[i - 4];
            value[4 + i] = (byte)(raw[i] ^ mask);
        }

        int padded = (value.Length + 3) & ~3;
        byte[] msg = new byte[20 + 4 + padded];
        BinaryPrimitives.WriteUInt16BigEndian(msg, 0x0101); // binding success
        BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(2), (ushort)(4 + padded));
        BinaryPrimitives.WriteUInt32BigEndian(msg.AsSpan(4), Cookie);
        txid.CopyTo(msg, 8);
        BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(20), 0x0020);
        BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(22), (ushort)value.Length);
        value.CopyTo(msg, 24);
        return msg;
    }

    public void Dispose()
    {
        _running = false;
        _socket.Dispose();
    }
}
