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
    private readonly object _gate = new();
    private long _dropped;

    public DatagramBuffer(int capacity)
    {
        _channel = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });
    }

    public long Dropped => Interlocked.Read(ref _dropped);

    /// <summary>Called on the engine's receive threads; copies the payload to an owned
    /// array (buffered mode pays one allocation per datagram by design) and drops the
    /// oldest entry when full.</summary>
    public void Enqueue(ReadOnlySpan<byte> payload)
    {
        lock (_gate)
        {
            int before = _channel.Reader.Count;
            _channel.Writer.TryWrite(payload.ToArray());
            if (_channel.Reader.Count == before)
            {
                _dropped++; // DropOldest kept the count at capacity: one old datagram went away
            }
        }
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
