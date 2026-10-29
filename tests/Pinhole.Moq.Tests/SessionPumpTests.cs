using Pinhole.Moq;
using Xunit;

namespace Pinhole.Moq.Tests;

public sealed class SessionPumpTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static byte[] SubgroupHeader(ulong alias, ulong group) =>
    [
        0x18,
        (byte)alias,
        (byte)group,
        0x80,
    ];

    private static byte[] Object(ulong delta, byte payload) =>
    [
        (byte)delta,
        (byte)1,
        payload,
    ];

    private sealed class DripStream : Stream
    {
        private readonly List<(int DelayMs, byte[] Bytes)> _parts;
        private int _part;
        private int _offset;

        public DripStream(params (int DelayMs, byte[] Bytes)[] parts) => _parts = [.. parts];

        public void Add((int DelayMs, byte[] Bytes) part) => _parts.Add(part);

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            if (_part >= _parts.Count)
            {
                return 0;
            }

            (int delayMs, byte[] bytes) = _parts[_part];
            if (_offset == 0 && delayMs > 0)
            {
                await Task.Delay(delayMs, cancellationToken);
            }

            int n = Math.Min(buffer.Length, bytes.Length - _offset);
            bytes.AsSpan(_offset, n).CopyTo(buffer.Span);
            _offset += n;
            if (_offset == bytes.Length)
            {
                _part++;
                _offset = 0;
            }

            return n;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task SubgroupStream_OlderThanAnyIdleBudget_SurvivesWhileDataFlows()
    {

        var subscription = new MoqSubscription(null!, "ns", "slow-and-steady");
        var parts = new List<(int, byte[])> { (0, SubgroupHeader(alias: 1, group: 7)) };
        for (uint i = 0; i < 8; i++)
        {

            parts.Add((150, Object(i == 0 ? 0UL : 1UL, (byte)(0xa0 + i))));
        }

        await MoqSessionPump.ProcessSubgroupStreamAsync(
            new DripStream([.. parts]), (_, _) => Task.FromResult(subscription), CancellationToken.None, TimeSpan.FromMilliseconds(900)).WaitAsync(Timeout);

        for (uint i = 0; i < 8; i++)
        {
            MoqObject delivered = await subscription.ReadAsync().AsTask().WaitAsync(Timeout);
            Assert.Equal((byte)(0xa0 + i), delivered.Payload.Span[0]);
        }
    }

    [Fact]
    public async Task SubgroupStream_StalledPastTheIdleBudget_RetiresAlone()
    {

        var subscription = new MoqSubscription(null!, "ns", "stalled");
        var stream = new DripStream(
            (0, SubgroupHeader(alias: 1, group: 7)),
            (0, Object(0, 0x11)),
            (600, new byte[] { 0x01 }));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            MoqSessionPump.ProcessSubgroupStreamAsync(
                stream, (_, _) => Task.FromResult(subscription), CancellationToken.None, TimeSpan.FromMilliseconds(200)).WaitAsync(Timeout));

        MoqObject delivered = await subscription.ReadAsync().AsTask().WaitAsync(Timeout);
        Assert.Equal(0x11, delivered.Payload.Span[0]);
    }

    [Fact]
    public async Task FullSubscriberQueue_StallsItsOwnStream_NotTheOthers()
    {

        var slow = new MoqSubscription(null!, "ns", "slow-reader");
        var fast = new MoqSubscription(null!, "ns", "fast-reader");

        var slowStream = new DripStream((0, SubgroupHeader(alias: 1, group: 1)));
        for (ulong i = 0; i < 20; i++)
        {
            slowStream.Add((0, Object(i == 0 ? 0UL : 1UL, 0xe0)));
        }

        var fastStream = new DripStream(
            (0, SubgroupHeader(alias: 2, group: 2)),
            (0, Object(0, 0x42)),
            (0, Object(1, 0x42)),
            (0, Object(1, 0x42)));

        Task slowPump = MoqSessionPump.ProcessSubgroupStreamAsync(
            slowStream, (_, _) => Task.FromResult(slow), CancellationToken.None, Timeout);
        await Task.Delay(300);

        await MoqSessionPump.ProcessSubgroupStreamAsync(
            fastStream, (_, _) => Task.FromResult(fast), CancellationToken.None, Timeout).WaitAsync(Timeout);
        for (int i = 0; i < 3; i++)
        {
            await fast.ReadAsync().AsTask().WaitAsync(Timeout);
        }

        for (int i = 0; i < 20; i++)
        {
            await slow.ReadAsync().AsTask().WaitAsync(Timeout);
        }

        await slowPump.WaitAsync(Timeout);
    }

    [Fact]
    public void PeerRequestGate_AdmitsTwoHundredRelayRequests_ByGrowingTheGrant()
    {

        var gate = new MoqPeerRequestIds(256);
        int extensions = 0;
        for (int i = 0; i < 200; i++)
        {
            gate.Admit((ulong)(2 * i + 1));
            if (gate.ExtensionDue() is { } grant)
            {
                Assert.True(grant > (ulong)(2 * i + 3), "the new grant must cover future relay requests");
                extensions++;
            }
        }

        Assert.True(extensions >= 1, "the grant was never raised; the session dies at request 128");
        Assert.Equal(401UL, gate.NextExpected);
    }

    [Fact]
    public void PeerRequestGate_RejectsGapsRepeatsAndOvershoots()
    {
        var gate = new MoqPeerRequestIds(256);
        Assert.Throws<MoqProtocolException>(() => gate.Admit(3));
        gate.Admit(1);
        Assert.Throws<MoqProtocolException>(() => gate.Admit(1));
        gate.Admit(3);
        Assert.Throws<MoqProtocolException>(() => gate.Admit(5 + 2_000));
    }
}
