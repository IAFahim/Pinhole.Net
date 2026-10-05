using System.Net;
using System.Net.Sockets;

namespace Pinhole;

/// <summary>The engine's whole view of a UDP socket: bind, local endpoint, datagram send,
/// datagram receive, dispose. Production uses the OS-backed implementation; tests may
/// substitute an in-process network (<see cref="PinholeOptions.UdpSocketFactory"/>) that
/// routes datagrams between nodes with injected drop, delay, and NAT behavior.</summary>
internal interface IUdpSocket : IDisposable
{
    /// <summary>The locally bound endpoint. Polled for the advertised port; changes only
    /// with a rebind.</summary>
    IPEndPoint LocalEndPoint { get; }

    /// <summary>Sends one datagram. Unroutable destinations are the network's problem, not
    /// the caller's: the OS silently drops, and so must any substitute.</summary>
    void SendTo(ReadOnlySpan<byte> frame, SocketAddress to);

    /// <summary>Receives one datagram into <paramref name="buffer"/>, writing the sender's
    /// address into <paramref name="from"/>. Blocks up to a short poll interval and then
    /// throws <see cref="SocketException"/> (TimedOut) — the receive loop relies on the
    /// periodic wake to observe shutdown; throws <see cref="ObjectDisposedException"/>
    /// after dispose.</summary>
    int ReceiveFrom(Span<byte> buffer, SocketAddress from);
}

/// <summary>Creates the node's UDP socket: called once at bind and again on every rebind
/// (interface loss, roam-now, dead-network recovery). The bind hint is the caller's
/// <see cref="PinholeOptions.Bind"/>; substitutes may ignore it and assign addresses of
/// their own — only the returned endpoint is consulted.</summary>
internal delegate IUdpSocket UdpSocketFactory(IPEndPoint? bind);

/// <summary>The production socket: one dual-mode IPv6 UDP socket, v4-mapped dialing,
/// bounded receive wakes for clean disposal.</summary>
internal sealed class SystemUdpSocket : IUdpSocket
{
    private readonly Socket _udp;

    private SystemUdpSocket(Socket udp) => _udp = udp;

    /// <summary>Creates and binds the socket exactly as the engine always did.</summary>
    public static IUdpSocket Create(IPEndPoint? bind)
    {
        var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        // Blocked receives must wake up periodically: closing a socket while a sync receive
        // holds it spins forever in SafeSocketHandle.CloseAsIs on macOS, so disposal needs the
        // receive loop to come back and observe the disposed state.
        udp.ReceiveTimeout = 200;
        udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, 4 * 1024 * 1024);
        udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, 4 * 1024 * 1024);
        if (OperatingSystem.IsWindows())
        {
            const int sioUdpConnreset = -1744830452;
            udp.IOControl(sioUdpConnreset, new byte[] { 0 }, null);
        }

        // A dual-mode socket cannot bind a bare IPv4 address; map it so a caller's
        // IPAddress.Loopback/Any bind option works instead of throwing.
        IPEndPoint? bindV6 = bind is { Address.AddressFamily: AddressFamily.InterNetwork }
            ? new IPEndPoint(bind.Address.MapToIPv6(), bind.Port)
            : bind;
        udp.Bind(bindV6 ?? new IPEndPoint(IPAddress.IPv6Any, 0));
        return new SystemUdpSocket(udp);
    }

    public IPEndPoint LocalEndPoint => (IPEndPoint)_udp.LocalEndPoint!;

    public void SendTo(ReadOnlySpan<byte> frame, SocketAddress to) => _udp.SendTo(frame, SocketFlags.None, to);

    public int ReceiveFrom(Span<byte> buffer, SocketAddress from) => _udp.ReceiveFrom(buffer, SocketFlags.None, from);

    public void Dispose() => _udp.Dispose();
}
