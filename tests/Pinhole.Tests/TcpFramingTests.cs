using System.Text;
using System.Threading.Channels;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Independent TCP-envelope fixtures over fragmented/blocked streams. These
/// exercise the production codec without an OS socket or the production encoder.</summary>
public sealed class TcpFramingTests
{
    private sealed class Duplex : Stream
    {
        private readonly Channel<byte> _input = Channel.CreateUnbounded<byte>();
        private readonly MemoryStream _output = new();
        public byte[] Written => _output.ToArray();
        public void Feed(ReadOnlySpan<byte> bytes) { foreach (byte b in bytes) _input.Writer.TryWrite(b); }
        public void Finish() => _input.Writer.TryComplete();
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => _output.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken ct = default) => _output.WriteAsync(bytes, ct);
        public override async ValueTask<int> ReadAsync(Memory<byte> bytes, CancellationToken ct = default)
        {
            if (bytes.IsEmpty) return 0;
            try
            {
                byte value = await _input.Reader.ReadAsync(ct);
                bytes.Span[0] = value;
                return 1;
            }
            catch (ChannelClosedException) { return 0; }
        }
    }

    [Fact]
    public void Encoder_WritesNetworkByteOrderAndPreservesTheOriginalFrame()
    {
        byte[] frame = Enumerable.Range(0, 257).Select(i => (byte)i).ToArray();
        byte[] packet = TcpFrameCodec.Encode(frame);
        Assert.Equal(new byte[] { 1, 1 }, packet[..2]);
        Assert.Equal(frame, packet[2..]);
        frame[0] = 99;
        Assert.Equal(0, packet[2]); // the queued writer owns a snapshot
        Assert.Throws<ArgumentOutOfRangeException>(() => TcpFrameCodec.Encode(new byte[12]));
        Assert.Throws<ArgumentOutOfRangeException>(() => TcpFrameCodec.Encode(new byte[8193]));
        Assert.Equal(new byte[] { 32, 0 }, TcpFrameCodec.Encode(new byte[8192])[..2]);
    }

    [Fact]
    public async Task Reader_HandlesOneByteFragmentsAndConsecutiveIndependentFrames()
    {
        using var stream = new Duplex();
        byte[] first = Enumerable.Range(0, 13).Select(i => (byte)(i + 40)).ToArray();
        byte[] second = Enumerable.Range(0, 257).Select(i => (byte)(i * 3)).ToArray();
        stream.Feed(new byte[] { 0, 13 }); stream.Feed(first);
        stream.Feed(new byte[] { 1, 1 }); stream.Feed(second);
        stream.Finish();
        byte[] scratch = new byte[8192], header = new byte[2];
        int count = await TcpFrameCodec.ReadAsync(stream, header, scratch, TimeSpan.FromSeconds(1), default);
        Assert.Equal(first, scratch[..count]);
        count = await TcpFrameCodec.ReadAsync(stream, header, scratch, TimeSpan.FromSeconds(1), default);
        Assert.Equal(second, scratch[..count]);
        await Assert.ThrowsAsync<EndOfStreamException>(() => TcpFrameCodec.ReadAsync(stream, header, scratch, TimeSpan.FromSeconds(1), default).AsTask());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(12)]
    [InlineData(8193)]
    [InlineData(65535)]
    public async Task Reader_RejectsInvalidSizesBeforeReadingTheBody(int size)
    {
        using var stream = new Duplex();
        stream.Feed(new byte[] { (byte)(size >> 8), (byte)size });
        await Assert.ThrowsAsync<IOException>(() => TcpFrameCodec.ReadAsync(stream, new byte[2], new byte[8192], TimeSpan.FromSeconds(1), default).AsTask());
    }

    [Fact]
    public async Task Reader_RefusesTruncatedAndTooLargeForDestinationFrames()
    {
        using var stream = new Duplex();
        stream.Feed(new byte[] { 0, 13, 80, 1, 2 });
        stream.Finish();
        await Assert.ThrowsAsync<EndOfStreamException>(() => TcpFrameCodec.ReadAsync(stream, new byte[2], new byte[8192], TimeSpan.FromSeconds(1), default).AsTask());
        using var small = new Duplex();
        small.Feed(new byte[] { 0, 13 });
        await Assert.ThrowsAsync<IOException>(() => TcpFrameCodec.ReadAsync(small, new byte[2], new byte[12], TimeSpan.FromSeconds(1), default).AsTask());
    }

    [Fact]
    public async Task Reader_AllowsIdleButBoundsAnIncompleteHeaderAndBody()
    {
        using var idle = new Duplex();
        Task<int> pending = TcpFrameCodec.ReadAsync(idle, new byte[2], new byte[8192], TimeSpan.FromMilliseconds(50), default).AsTask();
        await Task.Delay(120);
        Assert.False(pending.IsCompleted); // an empty, idle session has no body deadline
        idle.Feed(new byte[] { 0 });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(2)));
        using var body = new Duplex();
        body.Feed(new byte[] { 0, 13, 80 });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => TcpFrameCodec.ReadAsync(body, new byte[2], new byte[8192], TimeSpan.FromMilliseconds(50), default).AsTask());
    }

    [Fact]
    public async Task Reader_CancellationEndsAnIdleRead()
    {
        using var idle = new Duplex();
        using var ct = new CancellationTokenSource();
        Task<int> pending = TcpFrameCodec.ReadAsync(idle, new byte[2], new byte[8192], TimeSpan.FromSeconds(1), ct.Token).AsTask();
        ct.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Preface_NegotiatesTheExactProtocolInEitherDirection(bool initiator)
    {
        using var stream = new Duplex();
        stream.Feed(Encoding.ASCII.GetBytes("PHNTCP1\n"));
        await TcpFrameCodec.NegotiateAsync(stream, initiator, default);
        Assert.Equal(Encoding.ASCII.GetBytes("PHNTCP1\n"), stream.Written);
    }

    [Theory]
    [InlineData("PHNTCP2\n")]
    [InlineData("HTTP/1.1")]
    [InlineData("PHNTCP0\n")]
    public async Task Preface_UnknownVersionsAndOtherProtocolsGetNoServerAnswer(string hello)
    {
        using var stream = new Duplex();
        stream.Feed(Encoding.ASCII.GetBytes(hello));
        await Assert.ThrowsAsync<IOException>(() => TcpFrameCodec.NegotiateAsync(stream, initiator: false, default));
        Assert.Empty(stream.Written);
    }
}
