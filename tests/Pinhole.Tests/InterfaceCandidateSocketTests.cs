using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Actual source binding and reply sockets; separate from the virtual
/// interface fixtures and pending in a socket-denying execution profile.</summary>
public sealed class InterfaceCandidateSocketTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public async Task SourceBoundSocket_ReceivesAndRepliesUsingItsOwnPort(string literal)
    {
        IPAddress address = IPAddress.Parse(literal);
        using IUdpSocket source = SystemUdpSocket.CreateForInterface(new(address, 0));
        using IUdpSocket peer = SystemUdpSocket.Create(new(address, 0));
        var origin = new SocketAddress(AddressFamily.InterNetworkV6);
        byte[] buffer = new byte[128];
        source.SendTo([1, 2, 3], peer.LocalEndPoint.Serialize());
        Assert.Equal(3, await Task.Run(() => peer.ReceiveFrom(buffer, origin)).WaitAsync(TimeSpan.FromSeconds(4)));
        var observed = (IPEndPoint)new IPEndPoint(IPAddress.IPv6Any, 0).Create(origin);
        Assert.Equal(source.LocalEndPoint.Port, observed.Port);
        Assert.Equal(address, observed.Address.IsIPv4MappedToIPv6 ? observed.Address.MapToIPv4() : observed.Address);
        peer.SendTo([4, 5, 6], origin);
        var replyFrom = new SocketAddress(AddressFamily.InterNetworkV6);
        Assert.Equal(3, await Task.Run(() => source.ReceiveFrom(buffer, replyFrom)).WaitAsync(TimeSpan.FromSeconds(4)));
        Assert.Equal(new byte[] { 4, 5, 6 }, buffer[..3]);
    }
}
