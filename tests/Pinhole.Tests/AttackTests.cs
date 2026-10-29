using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Pinhole.Providers;
using Pinhole.Rendezvous;
using Xunit;

namespace Pinhole.Tests;

public sealed class AttackTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Opts() => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [], DerpRelayUrls = [],
        Listen = true,
        ConnectTimeout = TimeSpan.FromSeconds(8),
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false, EnablePortMapping = false,
    };

    private static async Task<(PinholeConnection AtDialer, PinholeConnection AtListener)> ConnectPairAsync(
        PinholeNode listener, PinholeNode dialer, string? listenerString = null)
    {
        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection dialerSide = await dialer.ConnectAsync(listenerString ?? listener.ConnectionString).WaitAsync(Timeout);
        PinholeConnection listenerSide = await accept.WaitAsync(Timeout);
        return (dialerSide, listenerSide);
    }

    private static string LoopbackString(PinholeNode listener) => new ConnectionString(
        listener.PeerId,
        [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, listener.LocalPort))],
        staticKey: listener.StaticPublicKey).ToString();

    private static byte[] Frame(byte type, ulong sender, uint token, ReadOnlySpan<byte> payload = default)
    {
        byte[] frame = new byte[9 + 4 + payload.Length];
        frame[0] = type;
        BitConverter.TryWriteBytes(frame.AsSpan(1), sender);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(9), token);
        payload.CopyTo(frame.AsSpan(13));
        return frame;
    }

    [Fact]
    public async Task MalformedStunResponse_DoesNotDeafenPeerSocket()
    {
        (var evil, var evilEp, byte[] request) = await BindEvilServerAsync();
        Task evilResponder = RespondEvilStunAsync(evil, request, 0x0020);

        using var victim = new PeerSocket(0xA11CE);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(800));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => victim.ProbeStunAsync(evilEp, cts.Token));
        await evilResponder.WaitAsync(Timeout);
        evil.Dispose();

        using var peer = new PeerSocket(0xB0B);
        _ = peer.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, victim.LocalPort));
        _ = victim.ConnectDirectAsync(new IPEndPoint(IPAddress.Loopback, peer.LocalPort));
        await Task.WhenAll(peer.Connected, victim.Connected).WaitAsync(Timeout);
    }

    [Fact]
    public async Task MalformedStunResponse_DoesNotDeafenNode()
    {
        await using PinholeNode node = await PinholeNode.BindAsync(Opts());

        (var evil, var evilEp, byte[] request) = await BindEvilServerAsync();
        Task evilResponder = RespondEvilStunAsync(evil, request, 0x0001);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(800));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => node.Engine.ProbeStunAsync(evilEp, cts.Token));
        await evilResponder.WaitAsync(Timeout);
        evil.Dispose();

        await using PinholeNode other = await PinholeNode.BindAsync(Opts());
        (PinholeConnection dialer, PinholeConnection atNode) = await ConnectPairAsync(node, other);
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atNode.Received += p => got.TrySetResult(p.ToArray());
        dialer.Send("after attack"u8);
        Assert.Equal("after attack"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task SpoofedBye_WithoutTheConnectionToken_CannotCloseASession()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        (PinholeConnection atB, PinholeConnection atA) = await ConnectPairAsync(a, b, LoopbackString(a));
        Assert.Equal(PinholeConnectionState.Open, atB.State);

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        IPEndPoint bWire = new(IPAddress.Loopback, b.LocalPort);

        attacker.SendTo(Frame(0x56, a.PeerId, 0), SocketFlags.None, bWire);
        attacker.SendTo(Frame(0x56, a.PeerId, 0xDEADBEEF), SocketFlags.None, bWire);
        await Task.Delay(500);

        Assert.Equal(PinholeConnectionState.Open, atB.State);
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atB.Received += p => got.TrySetResult(p.ToArray());
        atA.Send("still here"u8);
        Assert.Equal("still here"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task SpoofedData_WithoutTheConnectionToken_CannotStealThePathOrInject()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());

        (PinholeConnection atB, PinholeConnection atA) = await ConnectPairAsync(a, b, LoopbackString(a));
        IPEndPoint realRemote = atB.Path.Remote!;
        Assert.Equal(IPAddress.Loopback, realRemote.Address);

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        bool injected = false;
        atB.Received += _ => injected = true;
        attacker.SendTo(Frame(0x52, a.PeerId, 0x01020304, "injected"u8), SocketFlags.None,
            new IPEndPoint(IPAddress.Loopback, b.LocalPort));
        await Task.Delay(600);

        Assert.False(injected);
        Assert.Equal(realRemote, atB.Path.Remote);
        Assert.Equal(PinholeConnectionState.Open, atB.State);

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atB.Received += p => got.TrySetResult(p.ToArray());
        atA.Send("genuine"u8);
        Assert.Equal("genuine"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task PuncFlood_FromStrangers_ConnectionTableStaysBounded()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        (PinholeConnection atB, PinholeConnection atA) = await ConnectPairAsync(a, b);

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        IPEndPoint aWire = new(IPAddress.Loopback, a.LocalPort);
        byte[] punc = new byte[13];
        punc[0] = 0x50;
        for (int i = 0; i < 3000; i++)
        {
            RandomNumberGenerator.Fill(punc.AsSpan(1, 8));
            attacker.SendTo(punc, SocketFlags.None, aWire);
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(5), () => a.Connections.Count > 0);
        Assert.True(a.Connections.Count <= NodeEngine.MaxConnections,
            $"stranger flood materialized {a.Connections.Count} connections");

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atA.Received += p => got.TrySetResult(p.ToArray());
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (!got.Task.IsCompleted && sw.Elapsed < Timeout)
        {
            atB.Send("through the flood"u8);
            await Task.Delay(200);
        }

        Assert.Equal("through the flood"u8.ToArray(), await got.Task.WaitAsync(TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public async Task StrangerHusks_AreReapedAfterConnectTimeout_AllowingRealPeersIn()
    {
        const int cap = 8;
        await using PinholeNode listener = await PinholeNode.BindAsync(
            Opts() with { MaxConnectionsOverride = cap, ConnectTimeout = TimeSpan.FromSeconds(2) });

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        IPEndPoint listenerWire = new(IPAddress.Loopback, listener.LocalPort);

        byte[] punc = new byte[CryptoWire.HeaderLength + CryptoWire.PuncCryptoBody];
        punc[0] = 0x50;
        for (int i = 0; i < cap * 5; i++)
        {
            RandomNumberGenerator.Fill(punc.AsSpan(1));
            attacker.SendTo(punc, SocketFlags.None, listenerWire);
        }

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(5), () => listener.Connections.Count == cap);

        await TestPoll.UntilAsync(TimeSpan.FromSeconds(10), () => listener.Connections.Count == 0);

        await using PinholeNode real = await PinholeNode.BindAsync(Opts() with { ConnectTimeout = TimeSpan.FromSeconds(5) });
        await using PinholeConnection conn = await real.ConnectAsync(LoopbackString(listener)).WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);
    }

    [Fact]
    public async Task MaxConnectionsFlood_RealHandshakes_RefusesOverflowAndRecovers()
    {
        const int cap = 4;
        const int strangers = 6;
        await using PinholeNode listener = await PinholeNode.BindAsync(
            Opts() with { MaxConnectionsOverride = cap });
        string cs = LoopbackString(listener);
        PinholeOptions dialerOpts = Opts() with { ConnectTimeout = TimeSpan.FromSeconds(3) };

        var nodes = new List<PinholeNode>();
        var dials = new List<Task<PinholeConnection>>();
        try
        {
            for (int i = 0; i < strangers; i++)
            {
                nodes.Add(await PinholeNode.BindAsync(dialerOpts));
                dials.Add(nodes[i].ConnectAsync(cs));
            }

            var results = await Task.WhenAll(dials.Select(d => RecordAsync(d)));
            Assert.Equal(cap, results.Count(r => r is not null));
            Assert.Equal(strangers - cap, results.Count(r => r is null));
            Assert.True(listener.Connections.Count <= cap,
                $"cap exceeded: {listener.Connections.Count} materialized");

            await results.First(r => r is not null)!.DisposeAsync();
            await TestPoll.UntilAsync(TimeSpan.FromSeconds(5), () => listener.Connections.Count == cap - 1);

            await using PinholeNode late = await PinholeNode.BindAsync(dialerOpts);
            await using PinholeConnection recovered = await late.ConnectAsync(cs).WaitAsync(Timeout);
        }
        finally
        {
            foreach (PinholeNode n in nodes)
            {
                await n.DisposeAsync();
            }
        }

        static async Task<PinholeConnection?> RecordAsync(Task<PinholeConnection> dial)
        {
            try
            {
                return await dial;
            }
            catch (TimeoutException)
            {
                return null;
            }
        }
    }

    [Fact]
    public async Task ConcurrentDials_ToSameTarget_ShareOneConnectionObject()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        Task<PinholeConnection> accept = a.AcceptAsync();

        string cs = a.ConnectionString;
        Task<PinholeConnection>[] dials =
        [
            b.ConnectAsync(cs),
            b.ConnectAsync(cs),
            b.ConnectAsync(cs),
        ];
        PinholeConnection[] conns = await Task.WhenAll(dials).WaitAsync(Timeout);
        PinholeConnection atA = await accept.WaitAsync(Timeout);

        Assert.All(conns, c => Assert.Same(conns[0], c));
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atA.Received += p => got.TrySetResult(p.ToArray());
        conns[0].Send("one object, one session"u8);
        Assert.Equal("one object, one session"u8.ToArray(), await got.Task.WaitAsync(Timeout));
    }

    [Fact]
    public async Task Send_EnforcesPayloadBoundaries()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        (PinholeConnection atB, PinholeConnection atA) = await ConnectPairAsync(a, b);

        Assert.Throws<ArgumentOutOfRangeException>(() => atB.Send(ReadOnlySpan<byte>.Empty));

        Assert.Throws<ArgumentOutOfRangeException>(() => atB.Send(new byte[66_000]));

        byte[] max = new byte[PinholeConnection.MaxPayload];
        max.AsSpan().Fill(0xAB);
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atA.Received += p => got.TrySetResult(p.ToArray());
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (!got.Task.IsCompleted && sw.Elapsed < Timeout)
        {
            atB.Send(max);
            await Task.Delay(100);
        }

        Assert.Equal(max, await got.Task.WaitAsync(TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public async Task Send_AfterClose_ThrowsCleanly_AndDoubleDisposeIsHarmless()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        (PinholeConnection atB, PinholeConnection _) = await ConnectPairAsync(a, b);

        await atB.CloseAsync();
        Exception thrown = Assert.ThrowsAny<Exception>(() => atB.Send("late"u8));
        Assert.True(thrown is ObjectDisposedException or InvalidOperationException,
            $"Send after close threw {thrown.GetType().Name}: {thrown.Message}");

        await atB.DisposeAsync();
        await atB.DisposeAsync();
        atB.Dispose();
        await DisposeThreeTimesAsync(b);
    }

    private static async Task DisposeThreeTimesAsync(PinholeNode node)
    {
        node.Dispose();
        node.Dispose();
        await node.DisposeAsync();
    }

    [Fact]
    public async Task AcceptAfterDispose_ThrowsObjectDisposed()
    {
        PinholeNode node = await PinholeNode.BindAsync(Opts());
        Task<PinholeConnection> accept = node.AcceptAsync();
        await node.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => accept);
    }

    [Fact]
    public async Task PingStorm_NeverThrows_AndCountsHonestly()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        (PinholeConnection atB, _) = await ConnectPairAsync(a, b);

        for (int i = 0; i < 300; i++)
        {
            atB.Ping();
        }

        Assert.Equal(300, atB.Stats.PingsSent);
        await TestPoll.UntilAsync(Timeout, () => atB.LastRtt is not null);
        Assert.True(atB.Stats.PingsLost <= 300);

        await atB.CloseAsync();
        atB.Ping();
    }

    [Fact]
    public async Task Rebind_WithUnreachableRelayCandidates_DoesNotThrowAndRecoversDirect()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        var withDeadRelay = new ConnectionString(a.PeerId,
        [
            new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, a.LocalPort)),
            new PinholeCandidate(CandidateKind.Relay, new IPEndPoint(IPAddress.Parse("203.0.113.1"), 40000),
                new IPEndPoint(IPAddress.Parse("203.0.113.1"), 3478), "ghost", "ghost"),
        ],
        staticKey: a.StaticPublicKey);
        PinholeConnection atB = await b.ConnectAsync(withDeadRelay.ToString()).WaitAsync(Timeout);
        Task<PinholeConnection> accept = a.AcceptAsync();
        PinholeConnection atA = await accept.WaitAsync(Timeout);

        await b.Engine.SimulateInterfaceLossAsync();

        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atA.Received += p => got.TrySetResult(p.ToArray());
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (!got.Task.IsCompleted && sw.Elapsed < Timeout)
        {
            try
            {
                atB.Send("after rebind"u8);
            }
            catch (InvalidOperationException)
            {

            }

            await Task.Delay(200);
        }

        Assert.Equal("after rebind"u8.ToArray(), await got.Task.WaitAsync(TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public void ConnectionString_EveryTruncationAndCorruption_HasExactlyTwoOutcomes()
    {
        ulong peerId = 0x0011223344556677;
        var candidates = new List<PinholeCandidate>
        {
            new(CandidateKind.Direct, new IPEndPoint(IPAddress.Parse("192.168.1.9"), 41000)),
            new(CandidateKind.Direct, new IPEndPoint(IPAddress.Parse("2001:db8::9"), 41000)),
            new(CandidateKind.Reflexive, new IPEndPoint(IPAddress.Parse("203.0.113.99"), 51000)),
            new(CandidateKind.Relay, new IPEndPoint(IPAddress.Parse("198.51.100.3"), 60001),
                new IPEndPoint(IPAddress.Parse("198.51.100.3"), 3478), "user", "pass"),
        };
        string encoded = new ConnectionString(peerId, candidates, NatHint.Cone).ToString();

        for (int len = 0; len <= encoded.Length; len++)
        {
            string prefix = encoded[..len];
            bool ok = ConnectionString.TryParse(prefix, out ConnectionString? _);
            Assert.True(!ok || len == encoded.Length, "a truncated string must never parse");
        }

        char[] chars = encoded.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char original = chars[i];
            chars[i] = '\xFF';
            ConnectionString.TryParse(new string(chars), out _);
            chars[i] = original;
        }

        ConnectionString full = ConnectionString.Parse(encoded);
        Assert.Equal(peerId, full.PeerId);
        Assert.Equal(NatHint.Cone, full.NatHint);
        Assert.Equal(candidates, full.Candidates);
    }

    [Fact]
    public void ConnectionString_MaxRelayCandidateString_RoundTripsUnderItsOwnCap()
    {
        var fat = new List<PinholeCandidate>();
        for (int i = 0; i < ConnectionString.MaxCandidates; i++)
        {
            fat.Add(new PinholeCandidate(CandidateKind.Relay, new IPEndPoint(IPAddress.Parse("198.51.100.7"), 6000 + i),
                new IPEndPoint(IPAddress.Parse("198.51.100.7"), 3478),
                new string('u', 64), new string('p', 64)));
        }

        string encoded = new ConnectionString(0xABCDEF, fat, NatHint.Symmetric).ToString();
        Assert.True(encoded.Length <= ConnectionString.MaxEncodedLength,
            $"worst legal string is {encoded.Length} chars but Parse caps at {ConnectionString.MaxEncodedLength}");
        ConnectionString parsed = ConnectionString.Parse(encoded);
        Assert.Equal(fat, parsed.Candidates);
        Assert.Throws<FormatException>(
            () => ConnectionString.Parse("pinhole1:" + new string('A', ConnectionString.MaxEncodedLength)));
    }

    [Fact]
    public void Parse_RejectsWhitespaceAndGarbage()
    {
        Assert.Throws<FormatException>(() => ConnectionString.Parse("pinhole1:AA AA"));
        Assert.Throws<FormatException>(() => ConnectionString.Parse("pinhole1:===="));
        Assert.Throws<FormatException>(() => ConnectionString.Parse("pinhole1:"));
        Assert.Throws<FormatException>(() => ConnectionString.Parse("pinhole1"));
        Assert.Throws<FormatException>(() => ConnectionString.Parse(""));
        Assert.Throws<ArgumentNullException>(() => ConnectionString.Parse(null!));
    }

    [Fact]
    public async Task Bind_ToSpecificIPv4Port_IsHonored()
    {
        int port;
        using (var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            port = ((IPEndPoint)probe.LocalEndPoint!).Port;
        }

        await using PinholeNode node = await PinholeNode.BindAsync(new PinholeOptions
        {
            Bind = new IPEndPoint(IPAddress.Loopback, port),
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [], DerpRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
        });
        Assert.Equal(port, node.LocalPort);
    }

    [Fact]
    public async Task TurnServerThatGrantsNothing_FailsAllocationWithCleanError()
    {
        using var liar = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        liar.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        Task respond = RespondEmptyTurnAsync(liar);

        IPEndPoint server = (IPEndPoint)liar.LocalEndPoint!;
        InvalidOperationException ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Turn.TurnClient.AllocateAsync(server, "u", "p"));
        await respond.WaitAsync(Timeout);
        liar.Dispose();
        Assert.Contains("relayed address", ex.Message);
    }

    [Fact]
    public async Task Rendezvous_GarbageBarrage_StillIntroducesPeers()
    {
        await using RendezvousServer rd = RendezvousServer.Start();

        using var attacker = NewLoopbackSocket();
        using var client = NewLoopbackSocket();
        IPEndPoint rdEp = new(IPAddress.IPv6Loopback, rd.LocalEndPoint.Port);
        string[] garbage =
        [
            "", "REG", "REG zz", "REG deadbeef extra", "WANT", "WANT nothex 1234",
            "WANT 1 2", "INTRO forged 1.2.3.4:9", new string('x', 2000),
        ];
        byte[][] binary = [new byte[] { 0, 1, 2, 3 }, new byte[600]];
        foreach (string line in garbage)
        {
            attacker.SendTo(Encoding.ASCII.GetBytes(line + "\n"), SocketFlags.None, rdEp);
        }

        foreach (byte[] junk in binary)
        {
            attacker.SendTo(junk, SocketFlags.None, rdEp);
        }

        client.ReceiveTimeout = 3000;
        client.SendTo(Encoding.ASCII.GetBytes("REG aabbccdd\n"), SocketFlags.None, rdEp);
        byte[] resp = new byte[256];
        EndPoint from = new IPEndPoint(IPAddress.IPv6Any, 0);
        int n = client.ReceiveFrom(resp, SocketFlags.None, ref from);
        Assert.StartsWith("OBS ", Encoding.ASCII.GetString(resp, 0, n));
    }

    private static Socket NewLoopbackSocket() =>
        new(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };

    private static Task RespondEvilStunAsync(Socket evil, byte[] request, ushort attributeType) =>
        Task.Run(() =>
        {
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            _ = evil.ReceiveFrom(request, SocketFlags.None, ref from);
            var resp = new byte[20 + 8];
            BinaryPrimitives.WriteUInt16BigEndian(resp, 0x0101);
            BinaryPrimitives.WriteUInt16BigEndian(resp.AsSpan(2), 0xFFFF);
            BinaryPrimitives.WriteUInt32BigEndian(resp.AsSpan(4), 0x2112A442);
            request.AsSpan(8, 12).CopyTo(resp.AsSpan(8));
            BinaryPrimitives.WriteUInt16BigEndian(resp.AsSpan(20), attributeType);
            BinaryPrimitives.WriteUInt16BigEndian(resp.AsSpan(22), 0xFFFF);
            evil.SendTo(resp, SocketFlags.None, from);
        });

    private static async Task<(Socket Evil, IPEndPoint Endpoint, byte[] Request)> BindEvilServerAsync()
    {
        var evil = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        evil.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return (evil, (IPEndPoint)evil.LocalEndPoint!, new byte[64]);
    }

    private static Task RespondEmptyTurnAsync(Socket liar) =>
        Task.Run(async () =>
        {
            byte[] buf = new byte[1500];
            for (int round = 0; round < 2; round++)
            {
                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                SocketReceiveFromResult result = await liar.ReceiveFromAsync(buf, SocketFlags.None, from).ConfigureAwait(false);

                byte[] challenge =
                [
                    0x00, 0x09, 0x00, 0x04, 0, 0, 4, 1,
                    0x00, 0x14, 0x00, 0x05, (byte)'e', (byte)'m', (byte)'p', (byte)'t', (byte)'y', 0, 0, 0,
                    0x00, 0x15, 0x00, 0x01, (byte)'n', 0, 0, 0,
                ];
                var resp = new byte[20 + (round == 0 ? challenge.Length : 24)];
                BinaryPrimitives.WriteUInt16BigEndian(resp, round == 0 ? (ushort)0x0113 : (ushort)0x0103);
                BinaryPrimitives.WriteUInt16BigEndian(resp.AsSpan(2), (ushort)(resp.Length - 20));
                BinaryPrimitives.WriteUInt32BigEndian(resp.AsSpan(4), 0x2112A442);
                buf.AsSpan(8, 12).CopyTo(resp.AsSpan(8));
                if (round == 0) challenge.CopyTo(resp, 20);
                else
                {
                    BinaryPrimitives.WriteUInt16BigEndian(resp.AsSpan(20), 0x0008);
                    BinaryPrimitives.WriteUInt16BigEndian(resp.AsSpan(22), 20);
                    byte[] key = MD5.HashData("u:empty:p"u8);
                    HMACSHA1.HashData(key, resp.AsSpan(0, 20)).CopyTo(resp, 24);
                }
                await liar.SendToAsync(resp, SocketFlags.None, result.RemoteEndPoint).ConfigureAwait(false);
            }
        });

    [Fact]
    public void ProviderCatalog_OpenRelayCarriesPublishedCredentials()
    {
        TurnServer openRelay = TurnServers.OpenRelay;
        Assert.Equal("openrelayproject", openRelay.Username);
        Assert.Equal("openrelayproject", openRelay.Credential);
        Assert.Equal(80, openRelay.Port);
    }
}
