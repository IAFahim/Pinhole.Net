using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Pinhole.Tests;

public sealed class InterfaceCandidateTests
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(6);
    private static Task Until(Func<bool> condition) => TestPoll.UntilAsync(Budget, condition);

    private sealed class Sources(VirtualNetwork network) : IDisposable
    {
        private readonly object _gate = new();
        private readonly Dictionary<IPAddress, VirtualUdpSocket> _available = [];
        private UdpInterfaceSource[] _selected = [];
        private readonly HashSet<VirtualUdpSocket> _bound = [];
        private static int _nextFreshPort = 45000;
        internal int Created;
        internal VirtualUdpSocket Add(string address, int port, int index)
        {
            var socket = network.CreateHost(new(IPAddress.Parse(address), port));
            lock (_gate)
            {
                _available[socket.LocalEndPoint.Address] = socket;
                _selected = [.. _selected, new(socket.LocalEndPoint.Address, index)];
            }
            return socket;
        }
        internal VirtualUdpSocket AddNat(VirtualNat nat, int index)
        {
            var socket = network.CreateBehindNat(nat);
            lock (_gate)
            {
                _available[socket.LocalEndPoint.Address] = socket;
                _selected = [.. _selected, new(socket.LocalEndPoint.Address, index)];
            }
            return socket;
        }
        internal IReadOnlyList<UdpInterfaceSource> Selected() { lock (_gate) return _selected; }
        internal void Only(IPAddress address) { lock (_gate) _selected = _selected.Where(s => s.Address.Equals(address)).ToArray(); }
        internal IUdpSocket Bind(IPEndPoint? bind)
        {
            Assert.NotNull(bind); Assert.Equal(0, bind.Port);
            lock (_gate)
            {
                Interlocked.Increment(ref Created);
                VirtualUdpSocket socket = _available[bind.Address];
                if (!_bound.Add(socket))
                {
                    socket = network.CreateHost(new(bind.Address, Interlocked.Increment(ref _nextFreshPort)));
                    _available[bind.Address] = socket; _bound.Add(socket);
                }
                return socket;
            }
        }
        public void Dispose() { lock (_gate) foreach (var socket in _available.Values) socket.Dispose(); }
    }

    private static Task<PinholeNode> Node(VirtualLab lab, Sources sources, string address, double timeout = 8) =>
        lab.BindNodeAsync(hostAddress: new(IPAddress.Parse(address), 0), tweak: o => o with
        {
            InterfaceSourceProvider = sources.Selected, InterfaceUdpSocketFactory = sources.Bind,
            ReceiveBufferCapacity = 8, ConnectTimeout = TimeSpan.FromSeconds(timeout), BindProbeBudget = TimeSpan.FromMilliseconds(500),
            PathValidationIdle = TimeSpan.FromMilliseconds(150), PathValidationProbeInterval = TimeSpan.FromMilliseconds(80),
            PathValidationMaxUnansweredProbes = 2,
        });

    [Fact]
    public async Task AlternateInterface_ConnectsWhenTheDefaultSourceCannotReachThePeer()
    {
        using var lab = new VirtualLab(); using var sources = new Sources(lab.Net);
        sources.Add("198.51.100.10", 40110, 10);
        lab.Net.AddRule(new LinkRule { DropAll = true, Match = (s, _) => s.Address.Equals(IPAddress.Parse("192.0.2.10")) });
        await using var a = await Node(lab, sources, "192.0.2.10");
        await using var b = await lab.BindNodeAsync(hostAddress: new(IPAddress.Parse("192.0.2.20"), 0), tweak: o => o with { ReceiveBufferCapacity = 8 });
        await Until(() => a.InterfaceCandidates.Count == 1 && a.InterfaceCandidates[0].ReflexiveEndpoints.Count == 1);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 40110), a.InterfaceCandidates[0].LocalEndpoint);
        Assert.Equal(NatHint.Cone, a.InterfaceCandidates[0].MappingHint); // two servers, same source socket
        var ticket = ConnectionString.Parse(a.ConnectionString);
        Assert.Contains(ticket.Candidates, c => c.Kind == CandidateKind.Reflexive && c.Address.Port == 40110);
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(b.ConnectionString).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        Assert.Equal(PathKind.Direct, outgoing.Path.Kind);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("198.51.100.10"), 40110), incoming.Path.Remote);
        Assert.NotNull(a.Engine.Lookup(b.PeerId)!.DirectUdpSocket);
        outgoing.Send([1, 2, 3]);
        Assert.Equal(new byte[] { 1, 2, 3 }, (await incoming.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
        incoming.Send([4, 5, 6]);
        Assert.Equal(new byte[] { 4, 5, 6 }, (await outgoing.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
    }

    [Fact]
    public async Task SourceRemoval_WithdrawsItsCandidatesAndRecoversThroughTheRemainingInterface()
    {
        using var lab = new VirtualLab(); using var sources = new Sources(lab.Net);
        sources.Add("198.51.100.10", 40210, 10);
        sources.Add("198.51.100.11", 40211, 11);
        lab.Net.AddRule(new LinkRule { DropAll = true, Match = (s, _) => s.Address.Equals(IPAddress.Parse("192.0.2.10")) });
        await using var a = await Node(lab, sources, "192.0.2.10");
        await using var b = await lab.BindNodeAsync(hostAddress: new(IPAddress.Parse("192.0.2.20"), 0), tweak: o => o with
        { ReceiveBufferCapacity = 8, PathValidationIdle = TimeSpan.FromMilliseconds(150), PathValidationProbeInterval = TimeSpan.FromMilliseconds(80), PathValidationMaxUnansweredProbes = 2 });
        await Until(() => a.InterfaceCandidates.Count == 2 && a.InterfaceCandidates.All(s => s.ReflexiveEndpoints.Count == 1));
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(b.ConnectionString).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        IPAddress original = incoming.Path.Remote!.Address;
        IPAddress remaining = original.Equals(IPAddress.Parse("198.51.100.10")) ? IPAddress.Parse("198.51.100.11") : IPAddress.Parse("198.51.100.10");
        sources.Only(remaining);
        await a.RoamNowAsync();
        Assert.Equal(remaining, Assert.Single(a.InterfaceCandidates).LocalEndpoint.Address);
        Assert.DoesNotContain(ConnectionString.Parse(a.ConnectionString).Candidates, c => c.Address.Address.Equals(original));
        await Until(() => incoming.Path.Remote?.Address.Equals(remaining) == true && outgoing.State == PinholeConnectionState.Open
            && a.Engine.Lookup(b.PeerId)?.DirectUdpSocket?.LocalEndPoint.Address.Equals(remaining) == true);
        Assert.Same(outgoing, Assert.Single(a.Connections)); Assert.Same(incoming, Assert.Single(b.Connections));
        outgoing.Send([7]); Assert.Equal(new byte[] { 7 }, (await incoming.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
    }

    [Fact]
    public async Task Ipv6Source_IsKeptForRepliesAndApplicationTraffic()
    {
        using var lab = new VirtualLab(withV6Stun: true); using var sources = new Sources(lab.Net);
        sources.Add("2001:db8::10", 40310, 10);
        lab.Net.AddRule(new LinkRule { DropAll = true, Match = (s, _) => s.Address.Equals(IPAddress.Parse("192.0.2.10")) });
        await using var a = await Node(lab, sources, "192.0.2.10");
        await using var b = await lab.BindNodeAsync(hostAddress: new(IPAddress.Parse("2001:db8::20"), 0), tweak: o => o with { ReceiveBufferCapacity = 8 });
        await Until(() => a.InterfaceCandidates.Count == 1 && a.InterfaceCandidates[0].ReflexiveEndpoints.Count == 1);
        var v6 = ConnectionString.Parse(b.ConnectionString);
        string ticket = new ConnectionString(v6.PeerId, v6.Candidates.Where(c => c.Address.AddressFamily == AddressFamily.InterNetworkV6).ToArray(),
            v6.NatHint, v6.StaticKey, v6.EndpointKey).ToString();
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(ticket).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        Assert.Equal(IPAddress.Parse("2001:db8::10"), incoming.Path.Remote!.Address);
        outgoing.Send([9]); Assert.Equal(new byte[] { 9 }, (await incoming.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
    }

    [Fact]
    public async Task BoundPool_IsLimitedAndDisposedSourceSocketsDoNotRemainRegistered()
    {
        using var lab = new VirtualLab(); using var sources = new Sources(lab.Net);
        int baseline = lab.Net.LiveSockets;
        for (int i = 1; i <= 4; i++) sources.Add($"198.51.100.{i}", 41000 + i, i);
        await using (var node = await Node(lab, sources, "192.0.2.10"))
        {
            await Until(() => node.InterfaceCandidates.Count == 4);
            Assert.Equal(4, sources.Created);
            Assert.Equal(baseline + 5, lab.Net.LiveSockets);
        }
        await Until(() => lab.Net.LiveSockets == baseline);
    }

    [Fact]
    public async Task OptOut_DoesNotConstructAnyAdditionalSockets()
    {
        using var lab = new VirtualLab(); using var sources = new Sources(lab.Net);
        sources.Add("198.51.100.10", 40510, 10);
        await using var node = await lab.BindNodeAsync(hostAddress: new(IPAddress.Parse("192.0.2.10"), 0), tweak: o => o with
        { EnableInterfaceCandidates = false, InterfaceSourceProvider = sources.Selected, InterfaceUdpSocketFactory = sources.Bind });
        Assert.Empty(node.InterfaceCandidates); Assert.Equal(0, sources.Created);
    }

    [Fact]
    public void SourceSelection_IsBoundedAndExcludesWildcardMulticastLoopbackAndLinkLocal()
    {
        UdpInterfaceSource[] input = Enumerable.Range(1, 20).Select(i => new UdpInterfaceSource(IPAddress.Parse($"192.0.2.{i}"), i)).ToArray();
        Assert.Equal(4, InterfaceUdpTransport.Select(input).Count);
        foreach (string invalid in new[] { "0.0.0.0", "224.0.0.1", "255.255.255.255", "127.0.0.1", "::", "::1", "fe80::1%3", "ff02::1", "::ffff:192.0.2.1" })
            Assert.Empty(InterfaceUdpTransport.Select([new(IPAddress.Parse(invalid), 3)]));
        Assert.Empty(InterfaceUdpTransport.Gather(new(IPAddress.Loopback, 1234)));
    }

    [Fact]
    public void SourceSelection_ManyIpv4LinksAndPrivacyAddressesCannotCrowdOutIpv6()
    {
        UdpInterfaceSource[] input = [new(IPAddress.Parse("192.0.2.1"), 1), new(IPAddress.Parse("2001:db8::1"), 1),
            .. Enumerable.Range(2, 10).Select(i => new UdpInterfaceSource(IPAddress.Parse($"192.0.2.{i}"), i)),
            .. Enumerable.Range(2, 10).Select(i => new UdpInterfaceSource(IPAddress.Parse($"2001:db8::{i}"), 1))];
        var selected = InterfaceUdpTransport.Select(input);
        Assert.Equal(4, selected.Count);
        Assert.Contains(selected, s => s.Address.Equals(IPAddress.Parse("2001:db8::1")));
        Assert.Equal(3, selected.Select(s => s.Index).Distinct().Count());
    }

    [Fact]
    public async Task DifferentInterfaceMappings_AreClassifiedPerSocketInsteadOfCreatingAFalseSymmetricHint()
    {
        using var lab = new VirtualLab(); using var sources = new Sources(lab.Net);
        sources.AddNat(lab.Nat(VirtualNatKind.FullCone, "203.0.113.10", "172.31.10.0/24"), 10);
        sources.AddNat(lab.Nat(VirtualNatKind.Symmetric, "203.0.113.20", "172.31.20.0/24"), 20);
        await using var node = await Node(lab, sources, "192.0.2.10");
        await Until(() => node.InterfaceCandidates.Count == 2 && node.InterfaceCandidates.All(s => s.ReflexiveEndpoints.Count > 0));
        PinholeInterfaceCandidates cone = node.InterfaceCandidates.Single(s => s.InterfaceIndex == 10);
        PinholeInterfaceCandidates symmetric = node.InterfaceCandidates.Single(s => s.InterfaceIndex == 20);
        Assert.Equal(NatHint.Cone, cone.MappingHint); Assert.Single(cone.ReflexiveEndpoints);
        Assert.Equal(NatHint.Symmetric, symmetric.MappingHint); Assert.Equal(2, symmetric.ReflexiveEndpoints.Count);
        Assert.Equal(NatHint.Cone, node.NatHint); // the wildcard socket's own two-server observation
    }

    [Fact]
    public async Task StunReply_MustMatchAllTransactionBytesTheServerAndTheReceivingSocket()
    {
        using var lab = new VirtualLab(); using var sources = new Sources(lab.Net);
        VirtualUdpSocket source = sources.Add("198.51.100.10", 40810, 10);
        await using var node = await lab.BindNodeAsync(hostAddress: new(IPAddress.Parse("192.0.2.10"), 0), tweak: o => o with
        { StunServers = [], InterfaceSourceProvider = sources.Selected, InterfaceUdpSocketFactory = sources.Bind });
        using var server = lab.Net.CreateHost(new(IPAddress.Parse("192.0.2.99"), 3478));
        using var attacker = lab.Net.CreateHost(new(IPAddress.Parse("192.0.2.98"), 3478));
        using var deadline = new CancellationTokenSource(Budget);
        Task<IPEndPoint> probe = node.Engine.ProbeStunAsync(server.LocalEndPoint, deadline.Token);
        byte[] request = new byte[256]; var origin = new SocketAddress(AddressFamily.InterNetworkV6);
        Assert.Equal(20, await Task.Run(() => server.ReceiveFrom(request, origin)).WaitAsync(Budget));
        // Independent RFC response for 203.0.113.88:44444. Only the request's random
        // transaction bytes are copied; no production STUN encoder/decoder is used.
        byte[] response = Convert.FromHexString("0101000C2112A4420000000000000000000000000020000800018C8EEA12D51A");
        request.AsSpan(8, 12).CopyTo(response.AsSpan(8));
        attacker.SendTo(response, origin); // correct nonce, wrong sender
        server.SendTo(response, new IPEndPoint(source.LocalEndPoint.Address.MapToIPv6(), source.LocalEndPoint.Port).Serialize()); // correct nonce/server, wrong local socket
        byte[] wrongNonce = (byte[])response.Clone(); wrongNonce[19] ^= 1;
        server.SendTo(wrongNonce, origin); // same first 64 bits, changed last transaction byte
        byte[] wrongType = (byte[])response.Clone(); wrongType[0] = 0;
        server.SendTo(wrongType, origin);
        await Task.Delay(100); Assert.False(probe.IsCompleted);
        server.SendTo(response, origin);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.88"), 44444), await probe.WaitAsync(Budget));
    }

    [Fact]
    public async Task EncryptedIncomingHandshake_DoesNotExposeASessionBeforeThePeerProvesItsKeys()
    {
        using var lab = new VirtualLab();
        await using var listener = await lab.BindNodeAsync(hostAddress: new(IPAddress.Parse("192.0.2.20"), 0));
        using var attacker = lab.Net.CreateHost(new(IPAddress.Parse("192.0.2.66"), 40966));
        var identity = new NodeIdentity(); var ephemeral = NodeIdentity.NewEphemeral();
        byte[] punc = new byte[77]; punc[0] = 0x50;
        BinaryPrimitives.WriteUInt64LittleEndian(punc.AsSpan(1), 123456789);
        BinaryPrimitives.WriteUInt32LittleEndian(punc.AsSpan(9), 123456);
        ephemeral.Public.CopyTo(punc, 13); identity.PublicKey.CopyTo(punc, 45);
        attacker.SendTo(punc, new IPEndPoint(IPAddress.Parse("192.0.2.20").MapToIPv6(), listener.LocalPort).Serialize());
        byte[] reply = new byte[8192]; var from = new SocketAddress(AddressFamily.InterNetworkV6);
        Assert.Equal(97, await Task.Run(() => attacker.ReceiveFrom(reply, from)).WaitAsync(Budget));
        ConnState state = listener.Engine.Lookup(123456789)!;
        Assert.False(state.Connected.Task.IsCompleted); Assert.False(state.IncomingQueued);
        Assert.Equal(PinholeConnectionState.Punching, state.State);
        Assert.Throws<InvalidOperationException>(() => state.Public!.Send([1]));
    }
}
