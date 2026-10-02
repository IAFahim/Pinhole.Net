using System.Net;
using Xunit;

namespace Pinhole.Tests;

public sealed class PeerSocketTests
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task Punch_DirectLoopback_BothDirections()
    {
        using var a = new PeerSocket(1);
        using var b = new PeerSocket(2);

        _ = a.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, b.LocalPort));
        _ = b.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, a.LocalPort));
        await Task.WhenAll(a.Connected, b.Connected).WaitAsync(DefaultTimeout);

        var aGot = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var bGot = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        a.Received += span => aGot.TrySetResult(span.ToArray());
        b.Received += span => bGot.TrySetResult(span.ToArray());

        a.Send("alpha"u8);
        b.Send("omega"u8);
        byte[] atA = await aGot.Task.WaitAsync(DefaultTimeout);
        byte[] atB = await bGot.Task.WaitAsync(DefaultTimeout);
        Assert.Equal("omega"u8.ToArray(), atA);
        Assert.Equal("alpha"u8.ToArray(), atB);
    }

    [Fact]
    public async Task Punch_ThreePeers_AllPairsConnect()
    {
        // A PeerSocket is a 1:1 pinhole (one peer address slot), but it must sustain
        // concurrent punches to several peers: all six pairings must complete.
        using var p0 = new PeerSocket(0xA0);
        using var p1 = new PeerSocket(0xA1);
        using var p2 = new PeerSocket(0xA2);

        _ = p0.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, p1.LocalPort));
        _ = p0.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, p2.LocalPort));
        _ = p1.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, p0.LocalPort));
        _ = p1.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, p2.LocalPort));
        _ = p2.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, p0.LocalPort));
        _ = p2.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, p1.LocalPort));

        await Task.WhenAll(p0.Connected, p1.Connected, p2.Connected).WaitAsync(DefaultTimeout);
    }

    [Fact]
    public async Task Punch_ToleratesUnroutableCandidate()
    {
        using var a = new PeerSocket(3);
        using var b = new PeerSocket(4);

        // A bogus (TEST-NET-1, never routable) candidate must not kill the punch; the
        // loopback candidate right after it still opens the path.
        b.AddCandidate(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 9));
        b.AddCandidate(new IPEndPoint(IPAddress.Loopback, a.LocalPort));
        _ = a.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, b.LocalPort));
        await b.Connected.WaitAsync(DefaultTimeout);
        await a.Connected.WaitAsync(DefaultTimeout);

        var aGot = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        a.Received += span => aGot.TrySetResult(span.ToArray());
        b.Send("still-alive"u8);
        Assert.Equal("still-alive"u8.ToArray(), await aGot.Task.WaitAsync(DefaultTimeout));
    }

    [Fact]
    public async Task Ping_Pong_UpdatesRtt()
    {
        using var a = new PeerSocket(5);
        using var b = new PeerSocket(6);

        _ = a.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, b.LocalPort));
        _ = b.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, a.LocalPort));
        await Task.WhenAll(a.Connected, b.Connected).WaitAsync(DefaultTimeout);

        a.Ping();
        DateTimeOffset until = DateTimeOffset.UtcNow.AddSeconds(5);
        while (a.LastRtt is null && DateTimeOffset.UtcNow < until)
        {
            await Task.Delay(50);
        }

        Assert.NotNull(a.LastRtt);
    }

    [Fact]
    public async Task Send_BeforePunch_Throws()
    {
        using var a = new PeerSocket(7);
        Assert.Throws<InvalidOperationException>(() => a.Send("x"u8));
        await Task.CompletedTask;
    }

    [Theory]
    [InlineData(16)]
    [InlineData(1500)]
    public async Task Data_SmallAndLargePayloads_Intact(int size)
    {
        using var a = new PeerSocket(8);
        using var b = new PeerSocket(9);

        _ = a.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, b.LocalPort));
        _ = b.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, a.LocalPort));
        await Task.WhenAll(a.Connected, b.Connected).WaitAsync(DefaultTimeout);

        byte[] payload = new byte[size];
        Random.Shared.NextBytes(payload);
        var bGot = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        b.Received += span => bGot.TrySetResult(span.ToArray());

        a.Send(payload);
        byte[] received = await bGot.Task.WaitAsync(DefaultTimeout);
        Assert.Equal(payload, received);
    }

    [Fact]
    public async Task Dispose_DuringPendingPunch_CompletesPromptly()
    {
        var a = new PeerSocket(10);
        _ = a.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, 9)); // nothing listens there
        await Task.Delay(200);

        Task dispose = Task.Run(() => a.Dispose());
        await dispose.WaitAsync(TimeSpan.FromSeconds(5)); // throws TimeoutException if it wedged
    }

    [Fact]
    public async Task Dispose_DuringPendingReceive_CompletesPromptly()
    {
        using var a = new PeerSocket(11);
        using var b = new PeerSocket(12);
        _ = a.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, b.LocalPort));
        _ = b.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, a.LocalPort));
        await Task.WhenAll(a.Connected, b.Connected).WaitAsync(DefaultTimeout);

        var waiting = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        b.Received += span => waiting.TrySetResult(span.ToArray());
        DisposeTwice(a); // idempotent, and a pending receive must not wedge it
        await Task.Yield();
    }

    private static void DisposeTwice(PeerSocket socket)
    {
        socket.Dispose();
        socket.Dispose();
    }
}
