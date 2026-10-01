using System.Net;
using System.Text;
using Pinhole;
using Pinhole.Turn;
using Xunit;

namespace Pinhole.Tests;

public sealed class ConnectionStringTests
{
    [Fact]
    public void RoundTrip_AllCandidateKinds_AndNatHint()
    {
        ulong peerId = 0x1122334455667788;
        var candidates = new List<PinholeCandidate>
        {
            new(CandidateKind.Direct, new IPEndPoint(IPAddress.Parse("192.168.1.4"), 42123)),
            new(CandidateKind.Direct, new IPEndPoint(IPAddress.Parse("2001:db8::1"), 42123)),
            new(CandidateKind.Reflexive, new IPEndPoint(IPAddress.Parse("203.0.113.9"), 51000)),
            new(CandidateKind.Relay, new IPEndPoint(IPAddress.Parse("198.51.100.7"), 60001),
                new IPEndPoint(IPAddress.Parse("198.51.100.7"), 3478), "openrelayproject", "openrelayproject"),
        };

        string encoded = new ConnectionString(peerId, candidates, NatHint.Symmetric).ToString();
        Assert.StartsWith("pinhole1:", encoded);

        ConnectionString parsed = ConnectionString.Parse(encoded);
        Assert.Equal(peerId, parsed.PeerId);
        Assert.Equal(NatHint.Symmetric, parsed.NatHint);
        Assert.Equal(4, parsed.Candidates.Count);
        Assert.Equal(candidates, parsed.Candidates);
    }

    [Fact]
    public void Parse_RejectsForeignAndCorruptStrings()
    {
        Assert.Throws<FormatException>(() => ConnectionString.Parse("iroh1:AAAA"));
        Assert.Throws<FormatException>(() => ConnectionString.Parse("pinhole1:!!!!"));
        ConnectionString cs = new(1, [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 5))]);
        string encoded = cs.ToString();
        string b64 = encoded["pinhole1:".Length..].Replace('-', '+').Replace('_', '/');
        b64 += new string('=', (4 - b64.Length % 4) % 4);
        byte[] payload = Convert.FromBase64String(b64);
        payload[0] = 9; // wrong version
        string bad = "pinhole1:" + Convert.ToBase64String(payload).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Assert.Throws<FormatException>(() => ConnectionString.Parse(bad));
        Assert.False(ConnectionString.TryParse("pinhole1:AAAA", out _));
        Assert.True(ConnectionString.TryParse(encoded, out ConnectionString? good));
        Assert.Equal(1UL, good!.PeerId);
    }

    [Fact]
    public void Constructor_CapsCandidateCount()
    {
        var tooMany = Enumerable.Range(0, ConnectionString.MaxCandidates + 1)
            .Select(i => new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, i)))
            .ToList();
        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(1, tooMany));
    }
}

public sealed class NodeConnectionTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Opts(bool listen = true, IReadOnlyList<TurnServerConfig>? relays = null, TimeSpan? connectTimeout = null) => new()
    {
        StunServers = [],
        Relays = relays ?? [],
        Listen = listen,
        ConnectTimeout = connectTimeout ?? TimeSpan.FromSeconds(8),
        BindProbeBudget = TimeSpan.FromSeconds(5),
        EnableNetworkWatch = false,
    };

    private static async Task<(PinholeConnection Dialer, PinholeConnection Listener)> ConnectPairAsync(PinholeNode listener, PinholeNode dialer)
    {
        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection dialerSide = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        PinholeConnection listenerSide = await accept.WaitAsync(Timeout);
        Assert.Equal(listener.PeerId, dialerSide.PeerId);   // dialer holds a conn TO the listener
        Assert.Equal(dialer.PeerId, listenerSide.PeerId);   // listener holds a conn TO the dialer
        return (dialerSide, listenerSide);
    }

    [Fact]
    public async Task Connect_DirectLoopback_DataFlowsBothWays()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());

        (PinholeConnection conn, PinholeConnection atA) = await ConnectPairAsync(a, b);
        Assert.Equal(PinholeConnectionState.Open, conn.State);
        Assert.Equal(PathKind.Direct, conn.Path.Kind);
        Assert.Equal(a.PeerId, conn.PeerId);

        var aGot = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var bGot = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atA.Received += s => aGot.TrySetResult(s.ToArray());
        conn.Received += s => bGot.TrySetResult(s.ToArray());

        conn.Send("hello from B"u8);
        atA.Send("hello from A"u8);

        Assert.Equal("hello from B"u8.ToArray(), await aGot.Task.WaitAsync(Timeout));
        Assert.Equal("hello from A"u8.ToArray(), await bGot.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task Connect_IsIdempotent_SecondDialReturnsLiveConnection()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        _ = a.AcceptAsync();

        PinholeConnection first = await b.ConnectAsync(a.ConnectionString).WaitAsync(Timeout);
        PinholeConnection second = await b.ConnectAsync(a.ConnectionString).WaitAsync(Timeout);
        Assert.Same(first, second);
    }

    [Fact]
    public async Task ThreePeers_EveryPairConnects_LateJoinDoesNotDisturb()
    {
        await using PinholeNode n0 = await PinholeNode.BindAsync(Opts());
        await using PinholeNode n1 = await PinholeNode.BindAsync(Opts());
        await using PinholeNode n2 = await PinholeNode.BindAsync(Opts());

        List<Task<PinholeConnection>> accepts =
        [
            n0.AcceptAsync(), n0.AcceptAsync(), // from 1 and 2
            n1.AcceptAsync(),                   // from 2
        ];
        PinholeConnection c01 = await n1.ConnectAsync(n0.ConnectionString).WaitAsync(Timeout);
        PinholeConnection c02 = await n2.ConnectAsync(n0.ConnectionString).WaitAsync(Timeout);
        PinholeConnection c12 = await n2.ConnectAsync(n1.ConnectionString).WaitAsync(Timeout);
        await Task.WhenAll(accepts).WaitAsync(Timeout);

        // Every pair proves itself with an exchange.
        await ExchangeAsync(n1, c01, n0);
        await ExchangeAsync(n2, c02, n0);
        await ExchangeAsync(n2, c12, n1);

        // A late fourth peer joins; the existing pairings keep flowing.
        await using PinholeNode n3 = await PinholeNode.BindAsync(Opts());
        Task<PinholeConnection> lateAccept = n0.AcceptAsync();
        PinholeConnection c03 = await n3.ConnectAsync(n0.ConnectionString).WaitAsync(Timeout);
        await lateAccept.WaitAsync(Timeout);
        await ExchangeAsync(n3, c03, n0);
        await ExchangeAsync(n1, c01, n0); // unaffected by the join
    }

    /// <summary>Sends a marker on the dialer-side connection and expects it on the peer node.</summary>
    private static async Task ExchangeAsync(PinholeNode from, PinholeConnection conn, PinholeNode peer)
    {
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        PinholeConnection peerSide = peer.Connections.Single(c => c.PeerId == from.PeerId);
        peerSide.Received += s => got.TrySetResult(s.ToArray());
        string marker = $"ping-{Guid.NewGuid():N}";
        conn.Send(Encoding.UTF8.GetBytes(marker));
        byte[] answer = await got.Task.WaitAsync(Timeout);
        Assert.Equal(marker, Encoding.UTF8.GetString(answer));
    }

    [Fact]
    public async Task ForcedPunchFailure_StillConnects_OnRelay()
    {
        using FakeTurnServer turn = new();
        var relay = new TurnServerConfig(turn.Control, "user", "pass");
        await using PinholeNode a = await PinholeNode.BindAsync(Opts(relays: [relay]));
        await using PinholeNode b = await PinholeNode.BindAsync(Opts(relays: [relay]));

        // A connection string with the direct candidates withheld: the punch has nothing to
        // try, so the connection can only live on the relay — and must still exist.
        string relayOnlyString = new ConnectionString(a.PeerId, RelayCandidatesOf(a)).ToString();
        Assert.True(ConnectionString.Parse(relayOnlyString).Candidates.All(c => c.Kind == CandidateKind.Relay));

        Task<PinholeConnection> accept = a.AcceptAsync();
        PinholeConnection conn = await b.ConnectAsync(relayOnlyString).WaitAsync(Timeout);

        Assert.Equal(PinholeConnectionState.Degraded, conn.State);
        Assert.Equal(PathKind.Relay, conn.Path.Kind);

        PinholeConnection atA = await accept.WaitAsync(Timeout);
        var aGot = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var bGot = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atA.Received += s => aGot.TrySetResult(s.ToArray());
        conn.Received += s => bGot.TrySetResult(s.ToArray());

        conn.Send("via relay"u8);
        atA.Send("relay reply"u8);
        Assert.Equal("via relay"u8.ToArray(), await aGot.Task.WaitAsync(Timeout));
        Assert.Equal("relay reply"u8.ToArray(), await bGot.Task.WaitAsync(Timeout));
    }

    private static IReadOnlyList<PinholeCandidate> RelayCandidatesOf(PinholeNode node) =>
        ConnectionString.Parse(node.ConnectionString).Candidates.Where(c => c.Kind == CandidateKind.Relay).ToList();

    [Fact]
    public async Task MaxPayload_Guards_InsteadOfDyingInTheNetwork()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        (PinholeConnection conn, PinholeConnection atA) = await ConnectPairAsync(a, b);

        Assert.Equal(1200, PinholeConnection.MaxPayload);
        Assert.Throws<ArgumentOutOfRangeException>(() => conn.Send(new byte[PinholeConnection.MaxPayload + 1]));

        var got = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        atA.Received += s => got.TrySetResult(s.Length);
        conn.Send(new byte[PinholeConnection.MaxPayload]);
        Assert.Equal(PinholeConnection.MaxPayload, await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task Send_BeforeOpen_Throws()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());

        string deadString = new ConnectionString(
            a.PeerId,
            [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Parse("192.0.2.1"), 9))]).ToString();
        Task<PinholeConnection> dial = b.ConnectAsync(deadString).WaitAsync(TimeSpan.FromSeconds(15));

        // While the doomed dial is in flight, sending on it is a clear error, not a mystery.
        PinholeConnection? unopened = b.Connections.FirstOrDefault();
        if (unopened is { } eager)
        {
            Assert.ThrowsAny<InvalidOperationException>(() => eager.Send("x"u8));
        }

        await Assert.ThrowsAsync<TimeoutException>(() => dial);
    }

    [Fact]
    public async Task CloseAsync_FiresClosed_PeerLearnsViaBye()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        _ = a.AcceptAsync();
        PinholeConnection conn = await b.ConnectAsync(a.ConnectionString).WaitAsync(Timeout);
        PinholeConnection atA = a.Connections.Single(c => c.PeerId == b.PeerId);

        await conn.CloseAsync();
        Assert.Equal(PinholeConnectionState.Closed, conn.State);
        await conn.Closed.WaitAsync(Timeout);
        await atA.Closed.WaitAsync(Timeout);
        Assert.Equal(PinholeConnectionState.Closed, atA.State);
        Assert.Throws<ObjectDisposedException>(() => conn.Send("after close"u8));
    }

    [Fact]
    public async Task SelfDial_Throws_AndNonListeningNode_RefusesStrangers()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await Assert.ThrowsAsync<ArgumentException>(() => a.ConnectAsync(a.ConnectionString));

        await using PinholeNode silent = await PinholeNode.BindAsync(Opts(listen: false));
        await Assert.ThrowsAsync<InvalidOperationException>(() => silent.AcceptAsync());

        string silentString = silent.ConnectionString;
        await using PinholeNode stranger = await PinholeNode.BindAsync(Opts());
        await Assert.ThrowsAsync<TimeoutException>(() => stranger.ConnectAsync(silentString).WaitAsync(TimeSpan.FromSeconds(15)));
    }
}
