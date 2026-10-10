using System.Threading.Channels;

namespace Pinhole;

/// <summary>The opt-in bounded receive queue behind
/// <see cref="PinholeConnection.ReceiveAsync"/>. It exists from the moment the engine
/// materializes the connection — before the handshake completes — so a datagram that
/// arrives before the app first reads is queued instead of dropped. A full queue drops
/// the oldest datagram and never blocks the engine's receive path; completing the channel
/// lets readers drain what is left before EOF. No reliability of any kind is added: this
/// is local queueing over the same unreliable transport.</summary>
internal sealed class DatagramBuffer
{
    private readonly Channel<byte[]> _channel;
    private long _dropped;

    public DatagramBuffer(int capacity)
    {
        _channel = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        }, _ => Interlocked.Increment(ref _dropped));
    }

    public long Dropped => Interlocked.Read(ref _dropped);

    /// <summary>Called on the engine's receive threads; copies the payload to an owned
    /// array (buffered mode pays one allocation per datagram by design) and drops the
    /// oldest entry when full.</summary>
    public void Enqueue(ReadOnlySpan<byte> payload)
    {
        // Count actual evictions through the channel's callback. Queue length is
        // unchanged when a waiting reader takes a new item directly, and a concurrent
        // reader can change it between snapshots without any overflow at all.
        _channel.Writer.TryWrite(payload.ToArray());
    }

    /// <summary>Next buffered datagram, or null once the queue is drained and completed.
    /// Cancellation ends this read only; the queue and the connection are untouched.</summary>
    public async ValueTask<byte[]?> ReadAsync(CancellationToken ct)
    {
        try
        {
            return await _channel.Reader.ReadAsync(ct).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            return null; // EOF comes only after every buffered datagram was drained
        }
    }

    /// <summary>EOF after drain; idempotent and safe from any thread.</summary>
    public void Complete() => _channel.Writer.TryComplete();
}
