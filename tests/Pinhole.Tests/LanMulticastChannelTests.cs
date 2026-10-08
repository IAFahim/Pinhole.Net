using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Pinhole;
using Xunit;

namespace Pinhole.Tests;

public sealed class LanMulticastChannelTests
{
    [Fact]
    public void ProductionReceivePath_ReadsIpv4AndIpv6WithInterfaceInformation()
    {
        Assert.True(Socket.OSSupportsIPv6);
        using var channel = new MulticastLanChannel(() => [], MulticastLanChannel.GroupV4, MulticastLanChannel.GroupV6, bindPort: 0);
        Assert.NotNull(channel.LocalV4);
        Assert.NotNull(channel.LocalV6);
        using var v4 = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using var v6 = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        byte[] buffer = new byte[1500];
        v4.SendTo(new byte[] { 4 }, new IPEndPoint(IPAddress.Loopback, channel.LocalV4!.Port));
        Assert.True(channel.TryReceive(buffer, out int length, out var from, 2000));
        Assert.Equal(1, length);
        Assert.Equal(4, buffer[0]);
        Assert.Equal(AddressFamily.InterNetwork, from.AddressFamily);
        v6.SendTo(new byte[] { 6 }, new IPEndPoint(IPAddress.IPv6Loopback, channel.LocalV6!.Port));
        Assert.True(channel.TryReceive(buffer, out length, out from, 2000));
        Assert.Equal(1, length);
        Assert.Equal(6, buffer[0]);
        Assert.Equal(AddressFamily.InterNetworkV6, from.AddressFamily);
        Assert.True(channel.LastReceiveIpv6Scope > 0);
        Assert.False(channel.TryReceive(buffer, out _, out _, 1));
    }

    [Theory]
    [InlineData(AddressFamily.InterNetwork)]
    [InlineData(AddressFamily.InterNetworkV6)]
    public void UnavailableFamily_DoesNotDisableTheOther(AddressFamily blockedFamily)
    {
        using var blocked = new Socket(blockedFamily, SocketType.Dgram, ProtocolType.Udp) { ExclusiveAddressUse = true };
        if (blockedFamily == AddressFamily.InterNetworkV6) blocked.DualMode = false;
        blocked.Bind(new IPEndPoint(blockedFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0));
        int port = ((IPEndPoint)blocked.LocalEndPoint!).Port;
        using var channel = new MulticastLanChannel(() => [], MulticastLanChannel.GroupV4, MulticastLanChannel.GroupV6, port);
        AddressFamily available = blockedFamily == AddressFamily.InterNetwork ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        Assert.Null(blockedFamily == AddressFamily.InterNetwork ? channel.LocalV4 : channel.LocalV6);
        using var sender = new Socket(available, SocketType.Dgram, ProtocolType.Udp);
        sender.SendTo(new byte[] { 77 }, new IPEndPoint(available == AddressFamily.InterNetwork ? IPAddress.Loopback : IPAddress.IPv6Loopback, port));
        Assert.True(channel.TryReceive(new byte[100], out int count, out var from, 2000));
        Assert.Equal(1, count);
        Assert.Equal(available, from.AddressFamily);
    }

    [Fact]
    public void FailedMembership_DoesNotSuppressOtherInterfaces_AndRefreshRemovesOldLinks()
    {
        using var sink = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sink.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var loopback = NetworkInterface.GetAllNetworkInterfaces().First(n => n.NetworkInterfaceType == NetworkInterfaceType.Loopback).GetIPProperties();
        int v4Index = loopback.GetIPv4Properties()!.Index;
        int v6Index = loopback.GetIPv6Properties()!.Index;
        MulticastLanChannel.Interface[] interfaces =
        [new(IPAddress.Parse("192.0.2.255"), int.MaxValue, int.MaxValue), new(IPAddress.Loopback, v4Index, v6Index)];
        using var channel = new MulticastLanChannel(() => interfaces, (IPEndPoint)sink.LocalEndPoint!, MulticastLanChannel.GroupV6, bindPort: 0);
        channel.Send(new byte[] { 22 }, null);
        Assert.True(sink.Poll(2_000_000, SelectMode.SelectRead));
        Assert.Equal(1, sink.Receive(new byte[100]));
        // An IPv4 packet must give browsers the corresponding LOCAL IPv6 scope.
        sink.SendTo(new byte[] { 33 }, new IPEndPoint(IPAddress.Loopback, channel.LocalV4!.Port));
        Assert.True(channel.TryReceive(new byte[100], out _, out _, 2000));
        Assert.Equal(v6Index, channel.LastReceiveIpv6Scope);
        interfaces = [];
        channel.RefreshInterfaces(force: true);
        channel.Send(new byte[] { 44 }, null);
        Assert.False(sink.Poll(100_000, SelectMode.SelectRead));
        channel.Dispose();
        Assert.Throws<ObjectDisposedException>(() => channel.Send(new byte[] { 55 }, null));
    }
}
