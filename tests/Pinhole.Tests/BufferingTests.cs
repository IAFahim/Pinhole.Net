using System.Text;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Issue #13: opt-in buffered receiving closes the accept/subscribe race — a
/// datagram that arrived before the app first reads is delivered by the first read. All
/// semantics here are local queueing over the same unreliable transport; nothing about
/// network reliability changes.</summary>
public sealed class BufferingTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Opts(int capacity) => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [],
        ReceiveBufferCapacity = capacity,
        EnableNetworkWatch = false, EnablePortMapping = false,
        ConnectTimeout = TimeSpan.FromSeconds(8),
    };

    private static async Task<(PinholeConnection Dialer, Task<PinholeConnection> Accept)> PairAsync(
        PinholeNode listener, PinholeNode dialer)
    {
        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection dialerSide = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        return (dialerSide, accept);
    }

    [Fact]
    public async Task PreAcceptPayload_IsAvailableToTheFirstBufferedRead()
    {
        await using var listener = await PinholeNode.BindAsync(Opts(64));
        await using var dialer = await PinholeNode.BindAsync(Opts(0));
        (PinholeConnection atDialer, Task<PinholeConnection> accept) = await PairAsync(listener, dialer);

        // The datagram crosses before the app ever touches the accepted connection — the
        // exact window where the Received event would have dropped it.
        atDialer.Send("before you subscribed"u8);
        await Task.Delay(200);

        await using PinholeConnection atListener = await accept.WaitAsync(Timeout);
        ReadOnlyMemory<byte>? first = await atListener.ReceiveAsync().AsTask().WaitAsync(Timeout);
        Assert.NotNull(first);
        Assert.Equal("before you subscribed"u8.ToArray(), first.Value.ToArray());
    }

    [Fact]
    public async Task ReturnedMemory_StaysValidAcrossLaterReads()
    {
        await using var listener = await PinholeNode.BindAsync(Opts(4));
        await using var dialer = await PinholeNode.BindAsync(Opts(0));
        (PinholeConnection atDialer, Task<PinholeConnection> accept) = await PairAsync(listener, dialer);
        await using PinholeConnection atListener = await accept.WaitAsync(Timeout);

        byte[] firstSent = Encoding.UTF8.GetBytes("first payload, kept alive");
        atDialer.Send(firstSent);
        ReadOnlyMemory<byte> first = (await atListener.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value;

        for (int i = 0; i < 10; i++)
        {
            atDialer.Send("later traffic forcing buffer churn"u8);
            _ = await atListener.ReceiveAsync().AsTask().WaitAsync(Timeout);
        }

        Assert.Equal(firstSent, first.ToArray()); // ownership moved to the reader, no reuse
    }

    [Fact]
    public async Task FullQueue_DropsOldest_NeverBlocks_AndCountsHonestly()
    {
        await using var listener = await PinholeNode.BindAsync(Opts(2));
        await using var dialer = await PinholeNode.BindAsync(Opts(0));
        (PinholeConnection atDialer, Task<PinholeConnection> accept) = await PairAsync(listener, dialer);
        await using PinholeConnection atListener = await accept.WaitAsync(Timeout);

        for (int i = 0; i < 5; i++)
        {
            atDialer.Send([(byte)('0' + i)]); // the sender is never blocked by a full queue
        }

        await Task.Delay(300); // let all five cross
        Assert.True(atListener.DroppedDatagrams >= 3, $"dropped {atListener.DroppedDatagrams}, expected the three oldest");

        // The newest datagrams are what a reader finds; the queue kept flowing.
        byte[] third = (await atListener.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value.ToArray();
        byte[] fourth = (await atListener.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value.ToArray();
        Assert.Equal("3"u8.ToArray(), third);
        Assert.Equal("4"u8.ToArray(), fourth);
    }

    [Fact]
    public async Task Close_DrainsBufferedDatagrams_BeforeEof()
    {
        await using var listener = await PinholeNode.BindAsync(Opts(8));
        await using var dialer = await PinholeNode.BindAsync(Opts(0));
        (PinholeConnection atDialer, Task<PinholeConnection> accept) = await PairAsync(listener, dialer);
        await using PinholeConnection atListener = await accept.WaitAsync(Timeout);

        atDialer.Send("one"u8);
        atDialer.Send("two"u8);
        atDialer.Send("three"u8);
        await Task.Delay(200);
        await atDialer.CloseAsync();
        await atListener.Closed.WaitAsync(Timeout);

        // EOF only after the buffered three come out.
        Assert.Equal("one"u8.ToArray(), (await atListener.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value.ToArray());
        Assert.Equal("two"u8.ToArray(), (await atListener.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value.ToArray());
        Assert.Equal("three"u8.ToArray(), (await atListener.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value.ToArray());
        Assert.Null(await atListener.ReceiveAsync().AsTask().WaitAsync(Timeout));

        int yielded = 0;
        await foreach (ReadOnlyMemory<byte> _ in atListener.ReadAllAsync()) { yielded++; }
        Assert.Equal(0, yielded); // drained: the enumeration ends immediately
    }

    [Fact]
    public async Task Cancellation_EndsThePendingRead_WithoutClosingTheConnection()
    {
        await using var listener = await PinholeNode.BindAsync(Opts(4));
        await using var dialer = await PinholeNode.BindAsync(Opts(0));
        (PinholeConnection atDialer, Task<PinholeConnection> accept) = await PairAsync(listener, dialer);
        await using PinholeConnection atListener = await accept.WaitAsync(Timeout);

        using var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => atListener.ReceiveAsync(stop.Token).AsTask().WaitAsync(Timeout));
        Assert.Equal(PinholeConnectionState.Open, atListener.State);

        atDialer.Send("still readable after a cancelled receive"u8);
        byte[] got = (await atListener.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value.ToArray();
        Assert.Equal("still readable after a cancelled receive"u8.ToArray(), got);
    }

    [Fact]
    public async Task Roaming_Rebind_DoesNotEndTheStream()
    {
        await using var listener = await PinholeNode.BindAsync(Opts(4));
        await using var dialer = await PinholeNode.BindAsync(Opts(0));
        (PinholeConnection atDialer, Task<PinholeConnection> accept) = await PairAsync(listener, dialer);
        await using PinholeConnection atListener = await accept.WaitAsync(Timeout);

        Task<ReadOnlyMemory<byte>?> pending = atListener.ReceiveAsync().AsTask();
        await dialer.Engine.SimulateInterfaceLossAsync().WaitAsync(Timeout); // the sender's whole network changed

        await TestPoll.UntilAsync(Timeout, () =>
        {
            try
            {
                atDialer.Send("after the roam"u8);
            }
            catch (InvalidOperationException)
            {
                return false; // mid-recovery; the engine re-punches on its own
            }

            return pending.IsCompleted;
        });

        byte[] got = (await pending.WaitAsync(Timeout))!.Value.ToArray();
        Assert.Equal("after the roam"u8.ToArray(), got);
        Assert.Equal(PinholeConnectionState.Open, atListener.State);
    }

    [Fact]
    public async Task BufferingDisabled_ReceiveAsync_Throws_AndCallbackModeIsUnchanged()
    {
        await using var listener = await PinholeNode.BindAsync(Opts(0));
        await using var dialer = await PinholeNode.BindAsync(Opts(0));
        (PinholeConnection atDialer, Task<PinholeConnection> accept) = await PairAsync(listener, dialer);
        await using PinholeConnection atListener = await accept.WaitAsync(Timeout);

        await Assert.ThrowsAsync<InvalidOperationException>(() => atListener.ReceiveAsync().AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await foreach (ReadOnlyMemory<byte> _ in atListener.ReadAllAsync()) { }
        });
        Assert.Equal(0, atListener.DroppedDatagrams);

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atListener.Received += s => got.TrySetResult(s.ToArray());
        atDialer.Send("callback mode untouched"u8);
        Assert.Equal("callback mode untouched"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task ConcurrentReceives_AreRejected_SingleReaderOnly()
    {
        await using var listener = await PinholeNode.BindAsync(Opts(4));
        await using var dialer = await PinholeNode.BindAsync(Opts(0));
        (PinholeConnection atDialer, Task<PinholeConnection> accept) = await PairAsync(listener, dialer);
        await using PinholeConnection atListener = await accept.WaitAsync(Timeout);

        ValueTask<ReadOnlyMemory<byte>?> first = atListener.ReceiveAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => atListener.ReceiveAsync().AsTask());
        Assert.False(first.IsCompleted); // the first receive is still pending, untouched

        atDialer.Send("first reader wins"u8);
        byte[] got = (await first.AsTask().WaitAsync(Timeout))!.Value.ToArray();
        Assert.Equal("first reader wins"u8.ToArray(), got);
    }
}
