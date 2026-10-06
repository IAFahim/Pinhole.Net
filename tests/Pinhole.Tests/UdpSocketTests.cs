using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Pinhole.Tests;

public sealed class UdpSocketTests
{
    [Fact]
    public void NativeIPv4Source_IsMappedWithoutLosingItsPortOrAddress()
    {
        var source = new IPEndPoint(IPAddress.Parse("127.0.0.17"), 61007);
        SocketAddress native = source.Serialize();
        var scratch = new SocketAddress(AddressFamily.InterNetworkV6);
        native.Buffer.Span.CopyTo(scratch.Buffer.Span);
        scratch.Size = native.Size;

        SystemUdpSocket.NormalizeReceivedAddress(scratch);

        var mapped = (IPEndPoint)new IPEndPoint(IPAddress.IPv6Any, 0).Create(scratch);
        Assert.Equal(AddressFamily.InterNetworkV6, scratch.Family);
        Assert.True(mapped.Address.IsIPv4MappedToIPv6);
        Assert.Equal(source.Address, mapped.Address.MapToIPv4());
        Assert.Equal(source.Port, mapped.Port);
    }

    [Fact]
    public void IPv4BoundDualSocket_ReceivesAndRepliesUsingTheReturnedSource()
    {
        using IUdpSocket receiver = SystemUdpSocket.Create(new IPEndPoint(IPAddress.Loopback, 0));
        using var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
        {
            ReceiveTimeout = 3000,
        };
        sender.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        byte[] payload = "reply on the address returned by receive"u8.ToArray();
        sender.SendTo(payload, new IPEndPoint(IPAddress.Loopback, receiver.LocalEndPoint.Port));

        byte[] buffer = new byte[128];
        var from = new SocketAddress(AddressFamily.InterNetworkV6);
        int n = receiver.ReceiveFrom(buffer, from);
        Assert.Equal(payload, buffer[..n]);
        Assert.Equal(AddressFamily.InterNetworkV6, from.Family);
        receiver.SendTo(buffer.AsSpan(0, n), from);

        EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
        Assert.Equal(payload, buffer[..sender.ReceiveFrom(buffer, ref remote)]);
        Assert.Equal(receiver.LocalEndPoint.Port, ((IPEndPoint)remote).Port);
    }
}
