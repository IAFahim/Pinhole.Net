using System.Net;
using System.Net.Sockets;
using System.Buffers.Binary;

namespace Pinhole;

internal interface IUdpSocket : IDisposable
{
    IPEndPoint LocalEndPoint { get; }

    void SendTo(ReadOnlySpan<byte> frame, SocketAddress to);

    int ReceiveFrom(Span<byte> buffer, SocketAddress from);
}

internal delegate IUdpSocket UdpSocketFactory(IPEndPoint? bind);

internal sealed class SystemUdpSocket : IUdpSocket
{
    private static readonly SocketAddress MappedIPv4Template = new IPEndPoint(IPAddress.Any.MapToIPv6(), 0).Serialize();
    private readonly Socket _udp;

    private SystemUdpSocket(Socket udp) => _udp = udp;

    public static IUdpSocket Create(IPEndPoint? bind) => CreateCore(bind, 4 * 1024 * 1024);

    internal static IUdpSocket CreateForInterface(IPEndPoint? bind) => CreateCore(bind, 512 * 1024);

    private static IUdpSocket CreateCore(IPEndPoint? bind, int bufferBytes)
    {
        var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        try
        {

            udp.ReceiveTimeout = 200;
            udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, bufferBytes);
            udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, bufferBytes);
            if (OperatingSystem.IsWindows())
            {
                const int sioUdpConnreset = -1744830452;
                udp.IOControl(sioUdpConnreset, new byte[] { 0 }, null);
            }

            IPEndPoint? bindV6 = bind is { Address.AddressFamily: AddressFamily.InterNetwork }
                ? new IPEndPoint(bind.Address.MapToIPv6(), bind.Port)
                : bind;
            udp.Bind(bindV6 ?? new IPEndPoint(IPAddress.IPv6Any, 0));
            return new SystemUdpSocket(udp);
        }
        catch { udp.Dispose(); throw; }
    }

    public IPEndPoint LocalEndPoint => (IPEndPoint)_udp.LocalEndPoint!;

    public void SendTo(ReadOnlySpan<byte> frame, SocketAddress to) => _udp.SendTo(frame, SocketFlags.None, to);

    public int ReceiveFrom(Span<byte> buffer, SocketAddress from)
    {
        int n = _udp.ReceiveFrom(buffer, SocketFlags.None, from);
        NormalizeReceivedAddress(from);
        return n;
    }

    internal static void NormalizeReceivedAddress(SocketAddress from)
    {
        if (from.Family != AddressFamily.InterNetwork || from.Size < 16) return;
        Span<byte> bytes = from.Buffer.Span;
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
        uint address = BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]);
        MappedIPv4Template.Buffer.Span.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes[2..], port);
        BinaryPrimitives.WriteUInt32BigEndian(bytes[20..], address);
        from.Size = MappedIPv4Template.Size;
    }

    public void Dispose() => _udp.Dispose();
}
