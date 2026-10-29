using System.Threading.Channels;

namespace Pinhole;

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

    public void Enqueue(ReadOnlySpan<byte> payload)
    {

        _channel.Writer.TryWrite(payload.ToArray());
    }

    public async ValueTask<byte[]?> ReadAsync(CancellationToken ct)
    {
        try
        {
            return await _channel.Reader.ReadAsync(ct).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            return null;
        }
    }

    public void Complete() => _channel.Writer.TryComplete();
}
