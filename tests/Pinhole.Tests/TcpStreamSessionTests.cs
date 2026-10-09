using System.Collections.Concurrent;
using System.Net;
using System.Threading.Channels;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Production TCP framing, crypto dispatcher and datagram API over bounded,
/// fragmented memory streams. This verifies session behavior; OS sockets and Internet
/// reachability are separately covered by TcpSessionTests, not by this fixture.</summary>
public sealed class TcpStreamSessionTests
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(5);
    private sealed class Endpoint(Channel<byte[]> incoming, Channel<byte[]> outgoing) : Stream
    {
        private byte[]? _pending;
        private int _offset, _disposed;
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> bytes, CancellationToken ct = default)
        {
            if (bytes.IsEmpty) return 0;
            if (_pending is null)
            {
                try { _pending = await incoming.Reader.ReadAsync(ct); _offset = 0; }
                catch (ChannelClosedException) { return 0; }
            }
            int count = Math.Min(7, Math.Min(bytes.Length, _pending.Length - _offset));
            _pending.AsMemory(_offset, count).CopyTo(bytes);
            _offset += count;
            if (_offset == _pending.Length) _pending = null;
            return count;
        }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken ct = default)
        {
            if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(Endpoint));
            try { await outgoing.Writer.WriteAsync(bytes.ToArray(), ct); }
            catch (ChannelClosedException ex) { throw new IOException("peer closed the stream", ex); }
        }
        protected override void Dispose(bool disposing)
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                incoming.Writer.TryComplete(); outgoing.Writer.TryComplete();
            }
            base.Dispose(disposing);
        }
    }

    private sealed class Pair : IAsyncDisposable
    {
        internal TcpLink A { get; }
        internal TcpLink B { get; }
        internal ConcurrentQueue<byte[]> AtA { get; } = new();
        internal ConcurrentQueue<byte[]> AtB { get; } = new();
        private readonly Task _aRun, _bRun;
        private Pair(NodeEngine? a, NodeEngine? b, bool aInitiates, int tag)
        {
            var aInput = Channel.CreateBounded<byte[]>(64); var bInput = Channel.CreateBounded<byte[]>(64);
            var aEp = new IPEndPoint(IPAddress.Parse("192.0.2.10"), 61000 + tag);
            var bEp = new IPEndPoint(IPAddress.Parse("192.0.2.20"), 62000 + tag);
            A = new TcpLink(tag * 2, new Endpoint(aInput, bInput), bEp, aInitiates ? bEp : null, default,
                (link, frame) => { a?.OnTcpFrame(link, frame); AtA.Enqueue(frame.ToArray()); }, link => a?.OnTcpClosed(link));
            B = new TcpLink(tag * 2 + 1, new Endpoint(bInput, aInput), aEp, aInitiates ? null : aEp, default,
                (link, frame) => { b?.OnTcpFrame(link, frame); AtB.Enqueue(frame.ToArray()); }, link => b?.OnTcpClosed(link));
            _aRun = A.RunAsync(aInitiates); _bRun = B.RunAsync(!aInitiates);
        }
        internal static async Task<Pair> Open(NodeEngine? a, NodeEngine? b, bool aInitiates = true, int tag = 1)
        {
            var pair = new Pair(a, b, aInitiates, tag);
            await Task.WhenAll(pair.A.Ready, pair.B.Ready).WaitAsync(Budget);
            return pair;
        }
        public async ValueTask DisposeAsync()
        {
            A.Dispose(); B.Dispose();
            await Task.WhenAll(_aRun, _bRun).WaitAsync(Budget);
        }
    }

    private static Func<PinholeOptions, PinholeOptions> TcpOnly => o => o with
    { EnableDirectUdp = false, StunServers = [], StunRefreshInterval = TimeSpan.Zero,
        ReceiveBufferCapacity = 16, ConnectTimeout = TimeSpan.FromSeconds(8) };
    private static Task<PinholeNode> Node(VirtualLab lab, string address) =>
        lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse(address), 0), tweak: TcpOnly);
    private static Task<PinholeNode> UdpNode(VirtualLab lab, string address) =>
        lab.BindNodeAsync(hostAddress: new IPEndPoint(IPAddress.Parse(address), 0),
            tweak: o => TcpOnly(o) with { EnableDirectUdp = true, StunServers = lab.StunServers });
    private static Task Until(Func<bool> condition) => TestPoll.UntilAsync(Budget, condition);

    private static async Task<ConnState> StartDial(PinholeNode dialer, PinholeNode listener, Task<PinholeConnection> dial)
    {
        await Until(() => dialer.Engine.Lookup(listener.PeerId) is not null);
        Assert.False(dial.IsCompleted);
        return dialer.Engine.Lookup(listener.PeerId)!;
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task FramedSession_AuthenticatesExchangesAndClosesInEitherStreamDirection(bool aInitiates)
    {
        using var lab = new VirtualLab();
        await using var a = await Node(lab, "192.0.2.10");
        await using var b = await Node(lab, "192.0.2.20");
        Task<PinholeConnection> accept = b.AcceptAsync();
        Task<PinholeConnection> dial = a.ConnectAsync(b.ConnectionString);
        ConnState state = await StartDial(a, b, dial);
        await using var pair = await Pair.Open(a.Engine, b.Engine, aInitiates);
        Assert.True(pair.A.BindPeer(b.PeerId));
        Assert.True(pair.A.Send(state.PuncFrame));
        await using var outgoing = await dial.WaitAsync(Budget);
        await using var incoming = await accept.WaitAsync(Budget);
        Assert.True(outgoing.IsEncrypted); Assert.True(incoming.IsEncrypted);
        Assert.Equal(b.StaticPublicKey, outgoing.RemoteStaticKey);
        Assert.Equal(a.StaticPublicKey, incoming.RemoteStaticKey);
        Assert.Equal(DirectTransport.Tcp, outgoing.Path.Transport);
        Assert.Equal(DirectTransport.Tcp, incoming.Path.Transport);
        Assert.Equal(b.PeerId, pair.A.AuthenticatedPeer);
        Assert.Equal(a.PeerId, pair.B.AuthenticatedPeer);
        Assert.Equal(0, outgoing.Stats.PingsSent); Assert.Equal(0, outgoing.Stats.PongsReceived);
        foreach (int size in new[] { 1, 60, 1200 })
        {
            byte[] data = Enumerable.Range(0, size).Select(i => (byte)(i * 11)).ToArray();
            outgoing.Send(data);
            Assert.Equal(data, (await incoming.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
            incoming.Send(data);
            Assert.Equal(data, (await outgoing.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
        }
        Assert.Equal(0, lab.Net.Delivered); // no direct UDP frame slipped through the policy
        await outgoing.CloseAsync();
        await incoming.Closed.WaitAsync(Budget);
        Assert.Equal(PinholeConnectionState.Closed, incoming.State);
    }

    [Fact]
    public async Task ReplayedHandshakeOnAnotherStream_CannotMoveTheExistingPath()
    {
        using var lab = new VirtualLab();
        await using var a = await Node(lab, "192.0.2.10");
        await using var b = await Node(lab, "192.0.2.20");
        Task<PinholeConnection> accept = b.AcceptAsync();
        Task<PinholeConnection> dial = a.ConnectAsync(b.ConnectionString);
        ConnState state = await StartDial(a, b, dial);
        await using var pair = await Pair.Open(a.Engine, b.Engine);
        Assert.True(pair.A.BindPeer(b.PeerId)); Assert.True(pair.A.Send(state.PuncFrame));
        await using var outgoing = await dial.WaitAsync(Budget);
        await using var incoming = await accept.WaitAsync(Budget);
        ConnState serverState = b.Engine.Lookup(a.PeerId)!;
        await using var attacker = await Pair.Open(null, b.Engine, tag: 2);
        byte[] punc = pair.AtB.First(frame => frame[0] == 0x50);
        Assert.True(attacker.A.Send(punc));
        await Until(() => attacker.AtA.Any(frame => frame[0] == 0x53)); // new encrypted challenge was issued
        byte[] confirm = pair.AtB.First(frame => frame[0] == 0x57);
        Assert.True(attacker.A.Send(confirm));
        byte[] oldPong = pair.AtB.First(frame => frame[0] == 0x54);
        Assert.True(attacker.A.Send(oldPong));
        await Until(() => attacker.AtB.Any(frame => frame[0] == 0x54));
        Assert.Equal(0ul, attacker.B.AuthenticatedPeer);
        Assert.Same(pair.B, serverState.DirectTcp);
        Assert.Single(b.Connections);
        outgoing.Send([9, 8, 7]);
        Assert.Equal(new byte[] { 9, 8, 7 }, (await incoming.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
    }

    [Fact]
    public async Task ParallelStreams_ConvergeOnOnePairAndContinueFlowing()
    {
        using var lab = new VirtualLab();
        await using var a = await Node(lab, "192.0.2.10");
        await using var b = await Node(lab, "192.0.2.20");
        Task<PinholeConnection> accept = b.AcceptAsync();
        Task<PinholeConnection> dial = a.ConnectAsync(b.ConnectionString);
        ConnState state = await StartDial(a, b, dial);
        await using var first = await Pair.Open(a.Engine, b.Engine, aInitiates: a.PeerId > b.PeerId);
        Assert.True(first.A.BindPeer(b.PeerId)); Assert.True(first.A.Send(state.PuncFrame));
        await using var outgoing = await dial.WaitAsync(Budget);
        await using var incoming = await accept.WaitAsync(Budget);
        await using var preferred = await Pair.Open(a.Engine, b.Engine, aInitiates: a.PeerId < b.PeerId, tag: 2);
        Assert.True(preferred.A.BindPeer(b.PeerId)); Assert.True(preferred.A.Send(state.PuncFrame));
        await Until(() => ReferenceEquals(preferred.A, state.DirectTcp)
            && ReferenceEquals(preferred.B, b.Engine.Lookup(a.PeerId)?.DirectTcp));
        outgoing.Send([6, 5]);
        Assert.Equal(new byte[] { 6, 5 }, (await incoming.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
        Assert.Single(a.Connections); Assert.Single(b.Connections);
    }

    [Fact]
    public async Task HealthyUdp_KeepsItsPathWhenAnAuthenticatedTcpStreamArrives()
    {
        using var lab = new VirtualLab();
        await using var a = await UdpNode(lab, "192.0.2.10");
        await using var b = await UdpNode(lab, "192.0.2.20");
        Task<PinholeConnection> accept = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(b.ConnectionString).WaitAsync(Budget);
        await using var incoming = await accept.WaitAsync(Budget);
        Assert.Equal(DirectTransport.Udp, outgoing.Path.Transport);
        await using var pair = await Pair.Open(a.Engine, b.Engine);
        Assert.True(pair.A.BindPeer(b.PeerId)); Assert.True(pair.A.Send(a.Engine.Lookup(b.PeerId)!.PuncFrame));
        await Until(() => !pair.A.IsReady && !pair.B.IsReady);
        Assert.Equal(DirectTransport.Udp, outgoing.Path.Transport);
        Assert.Equal(DirectTransport.Udp, incoming.Path.Transport);
        outgoing.Send([3, 2, 1]);
        Assert.Equal(new byte[] { 3, 2, 1 }, (await incoming.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
    }

    [Fact]
    public async Task RestoredUdp_ReplacesTcpWithoutReplacingTheSession()
    {
        using var lab = new VirtualLab();
        var aSide = Subnet.Parse("192.0.2.10/32"); var bSide = Subnet.Parse("192.0.2.20/32");
        var blockA = LinkRule.Directional(aSide, bSide, dropAll: true);
        var blockB = LinkRule.Directional(bSide, aSide, dropAll: true);
        lab.Net.AddRule(blockA); lab.Net.AddRule(blockB);
        await using var a = await UdpNode(lab, "192.0.2.10");
        await using var b = await UdpNode(lab, "192.0.2.20");
        Task<PinholeConnection> accept = b.AcceptAsync(); Task<PinholeConnection> dial = a.ConnectAsync(b.ConnectionString);
        ConnState state = await StartDial(a, b, dial);
        await using var pair = await Pair.Open(a.Engine, b.Engine);
        Assert.True(pair.A.BindPeer(b.PeerId)); Assert.True(pair.A.Send(state.PuncFrame));
        await using var outgoing = await dial.WaitAsync(Budget);
        await using var incoming = await accept.WaitAsync(Budget);
        Assert.Equal(DirectTransport.Tcp, outgoing.Path.Transport);
        lab.Net.RemoveRule(blockA); lab.Net.RemoveRule(blockB);
        await Until(() => outgoing.Path.Transport == DirectTransport.Udp && incoming.Path.Transport == DirectTransport.Udp);
        Assert.Same(outgoing, a.Connections.Single());
        Assert.Same(incoming, b.Connections.Single());
        outgoing.Send([1, 3, 5]);
        Assert.Equal(new byte[] { 1, 3, 5 }, (await incoming.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
        incoming.Send([2, 4, 6]);
        Assert.Equal(new byte[] { 2, 4, 6 }, (await outgoing.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
    }

    [Fact]
    public async Task SimultaneousDials_AuthenticateTheSameEncryptedStreamSession()
    {
        using var lab = new VirtualLab();
        await using var a = await Node(lab, "192.0.2.10");
        await using var b = await Node(lab, "192.0.2.20");
        Task<PinholeConnection> aDial = a.ConnectAsync(b.ConnectionString);
        Task<PinholeConnection> bDial = b.ConnectAsync(a.ConnectionString);
        ConnState aState = await StartDial(a, b, aDial);
        ConnState bState = await StartDial(b, a, bDial);
        await using var pair = await Pair.Open(a.Engine, b.Engine);
        Assert.True(pair.A.BindPeer(b.PeerId)); Assert.True(pair.B.BindPeer(a.PeerId));
        Assert.True(pair.A.Send(aState.PuncFrame)); Assert.True(pair.B.Send(bState.PuncFrame));
        await using var aConnection = await aDial.WaitAsync(Budget);
        await using var bConnection = await bDial.WaitAsync(Budget);
        Assert.Equal(DirectTransport.Tcp, aConnection.Path.Transport);
        Assert.Equal(DirectTransport.Tcp, bConnection.Path.Transport);
        Assert.Single(a.Connections); Assert.Single(b.Connections);
        aConnection.Send([7, 9]);
        Assert.Equal(new byte[] { 7, 9 }, (await bConnection.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
    }
}
