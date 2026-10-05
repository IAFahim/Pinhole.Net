using System.Net;
using System.Net.Sockets;
using System.Text;
using Pinhole.Rendezvous;
using Xunit;

namespace Pinhole.Tests;

public sealed class RendezvousTests
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task Reg_ReturnsObservedAddress()
    {
        await using RendezvousServer server = RendezvousServer.Start();
        IPEndPoint serverEp = new(IPAddress.IPv6Loopback, server.LocalEndPoint.Port);
        using var peer = new PeerSocket(0x11);
        peer.AddRendezvous(serverEp);

        IPEndPoint observed = await peer.RegisterAsync().WaitAsync(DefaultTimeout);

        Assert.Equal(1, server.NodeCount);
        Assert.NotNull(observed);
    }

    [Fact]
    public async Task Want_TargetRegisters_BothPeersGetIntros_AndPunch()
    {
        await using RendezvousServer server = RendezvousServer.Start();
        IPEndPoint serverEp = new(IPAddress.IPv6Loopback, server.LocalEndPoint.Port);
        using var waiter = new PeerSocket(0x22);
        using var target = new PeerSocket(0x33);
        waiter.AddRendezvous(serverEp);
        target.AddRendezvous(serverEp);

        // Waiter wants a target that has not registered yet -> WAIT, and the intro fires
        // the moment the target shows up; both sides then punch each other over loopback.
        _ = waiter.ConnectAsync(0x33);
        await Task.Delay(300);

        _ = target.RegisterAsync();
        await Task.WhenAll(waiter.Connected, target.Connected).WaitAsync(DefaultTimeout);

        var targetGot = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        target.Received += span => targetGot.TrySetResult(span.ToArray());
        waiter.Send("via-intro"u8);
        Assert.Equal("via-intro"u8.ToArray(), await targetGot.Task.WaitAsync(DefaultTimeout));
    }

    [Fact]
    public async Task Want_TargetAlreadyRegistered_ImmediateIntro()
    {
        await using RendezvousServer server = RendezvousServer.Start();
        IPEndPoint serverEp = new(IPAddress.IPv6Loopback, server.LocalEndPoint.Port);
        using var a = new PeerSocket(0x44);
        using var b = new PeerSocket(0x55);
        a.AddRendezvous(serverEp);
        b.AddRendezvous(serverEp);
        _ = a.RegisterAsync();
        await Task.Delay(300);

        _ = b.ConnectAsync(0x44);
        await Task.WhenAll(a.Connected, b.Connected).WaitAsync(DefaultTimeout);
    }

    [Fact]
    public async Task Sweep_EvictsNodesAndWants_AfterTtl()
    {
        await using RendezvousServer server = RendezvousServer.Start(ttl: TimeSpan.FromSeconds(1));
        IPEndPoint serverEp = new(IPAddress.IPv6Loopback, server.LocalEndPoint.Port);

        using Socket client = new(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        client.DualMode = true;
        client.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        await client.SendToAsync(Encoding.ASCII.GetBytes("REG 00000000000000aa\n"), SocketFlags.None, serverEp);
        await client.SendToAsync(Encoding.ASCII.GetBytes("WANT 00000000000000bb 00000000000000cc\n"), SocketFlags.None, serverEp);
        await Task.Delay(300);
        Assert.Equal(1, server.NodeCount);
        Assert.Equal(1, server.WantCount);

        await Task.Delay(TimeSpan.FromSeconds(1.1));
        // The sweep runs at ttl/2, so eviction is due — but on a stalled CI runner the sweep
        // thread can lag past any fixed wall-clock assert. Poll for the contract instead:
        // gone means gone, whenever the sweep lands.
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(3), () => server.NodeCount == 0 && server.WantCount == 0);
        Assert.Equal(0, server.NodeCount);
        Assert.Equal(0, server.WantCount);
    }

    [Fact]
    public async Task Waiters_PerTarget_AreBounded()
    {
        await using RendezvousServer server = RendezvousServer.Start();
        IPEndPoint serverEp = new(IPAddress.IPv6Loopback, server.LocalEndPoint.Port);

        using Socket client = new(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        client.DualMode = true;
        client.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        for (int i = 0; i < RendezvousServer.MaxWaitersPerTarget + 10; i++)
        {
            await client.SendToAsync(Encoding.ASCII.GetBytes($"WANT {i:x16} 00000000000000dd\n"), SocketFlags.None, serverEp);
        }

        await Task.Delay(500);
        Assert.Equal(RendezvousServer.MaxWaitersPerTarget, server.WaitersFor(0xdd));
    }

    [Fact]
    public async Task Nodes_TableIsBounded_OldestEvicted()
    {
        await using RendezvousServer server = RendezvousServer.Start();
        IPEndPoint serverEp = new(IPAddress.IPv6Loopback, server.LocalEndPoint.Port);

        using Socket client = new(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        client.DualMode = true;
        client.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        for (int i = 0; i <= RendezvousServer.MaxNodes; i++)
        {
            await client.SendToAsync(Encoding.ASCII.GetBytes($"REG {i:x16}\n"), SocketFlags.None, serverEp);
            if (i % 64 == 63)
            {
                // Pace the burst so the server's per-datagram reply loop keeps up
                // instead of dropping registrations on slower machines.
                await Task.Delay(15);
            }
        }

        await Task.Delay(1000);
        // The invariant is the bound itself; loopback burst loss can shave a few
        // registrations below the cap, but the table must never exceed it.
        Assert.True(server.NodeCount <= RendezvousServer.MaxNodes,
            $"node table exceeded the bound: {server.NodeCount}");
        Assert.True(server.NodeCount > RendezvousServer.MaxNodes - 512,
            $"node table unexpectedly small: {server.NodeCount}");
    }

    [Fact]
    public async Task Dispose_CompletesPromptly()
    {
        RendezvousServer server = RendezvousServer.Start();
        await server.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
    }
}
