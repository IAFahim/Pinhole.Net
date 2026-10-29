using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Pinhole.Rendezvous;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

public sealed class RediscoveryTests
{
    private readonly ITestOutputHelper _output;

    public RediscoveryTests(ITestOutputHelper output) => _output = output;

    private static readonly TimeSpan DialTimeout = TimeSpan.FromSeconds(5);

    private RendezvousServer StartRendezvous() => RendezvousServer.Start();

    private static IPEndPoint Loopback(RendezvousServer server) =>
        new(IPAddress.IPv6Loopback, server.LocalEndPoint.Port);

    private static byte[] NewSeed() => RandomNumberGenerator.GetBytes(32);

    private static PinholeOptions Options(
        byte[]? seed = null,
        IReadOnlyList<IPEndPoint>? rendezvous = null,
        IReadOnlyList<IPinholeLookupProvider>? providers = null,
        TimeSpan? connectTimeout = null) => new()
    {
        IdentityKeySeed = seed,
        RendezvousEndpoints = rendezvous ?? [],
        LookupProviders = providers,
        StunServers = [],
        IrohRelayUrls = [], DerpRelayUrls = [],
        PublishIrohAddress = false,
        EnableNetworkWatch = false,
        EnablePortMapping = false,
        EnableLanDiscovery = false,
        ConnectTimeout = connectTimeout ?? DialTimeout,
    };

    private static async Task<PinholeNode> BindOnFreshPortAsync(PinholeOptions options, int oldPort, ITestOutputHelper output)
    {
        for (int attempt = 0; attempt < 5; attempt++)
        {
            PinholeNode node = await PinholeNode.BindAsync(options);
            if (node.LocalPort != oldPort)
            {
                return node;
            }

            output.WriteLine($"port {oldPort} was reused on attempt {attempt}; rebinding");
            node.Dispose();
        }

        throw new InvalidOperationException("could not escape the old port");
    }

    [Fact]
    public async Task SameSeed_FullIdentityStableAcrossRestart()
    {
        byte[] seed = NewSeed();
        await using PinholeNode a = await PinholeNode.BindAsync(Options(seed));
        await using PinholeNode b = await PinholeNode.BindAsync(Options(seed));
        await using PinholeNode c = await PinholeNode.BindAsync(Options(NewSeed()));

        Assert.Equal(a.PeerId, b.PeerId);
        Assert.Equal(a.StaticPublicKey, b.StaticPublicKey);
        Assert.Equal(a.EndpointPublicKey, b.EndpointPublicKey);
        Assert.NotEqual(a.PeerId, c.PeerId);
        Assert.NotEqual(a.StaticPublicKey, c.StaticPublicKey);
        Assert.NotEqual(a.EndpointPublicKey, c.EndpointPublicKey);

        Assert.NotEqual(a.StaticPublicKey, a.EndpointPublicKey);

        ConnectionString parsed = Pinhole.ConnectionString.Parse(a.ConnectionString);
        Assert.NotNull(parsed.StaticKey);
        Assert.NotNull(parsed.EndpointKey);
        Assert.Equal(a.EndpointPublicKey, parsed.EndpointKey);

        string body = a.ConnectionString.Split(':', 2)[1];
        byte[] truncated = Base64Url.Decode(body)[..^1];
        Assert.Throws<FormatException>(() => Pinhole.ConnectionString.Parse(
            Pinhole.ConnectionString.Scheme + ":" + Base64Url.Encode(truncated)));
    }

    [Fact]
    public void EndpointKeyWithoutStaticKey_Refused()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ConnectionString(
            1, [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 1))],
            staticKey: null, endpointKey: new byte[32]));
    }

    private static (byte[] Wire, RelayIdentity Signer, ulong PeerId) SignedRecord(
        byte[] seed, ulong peerId, DateTimeOffset expires, params IPEndPoint[] endpoints)
    {
        RelayIdentity identity = new(EndpointIdentity.DeriveEndpointSeed(seed));
        byte[] wire = new AddressRecord
        {
            PeerId = peerId,
            EndpointKey = identity.PublicKey,
            Sequence = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            ExpiresAtUtc = expires,
            Endpoints = endpoints,
        }.EncodeSigned(identity);
        return (wire, identity, peerId);
    }

    [Fact]
    public void RecordVerification_AcceptsGoodRecordOnly()
    {
        byte[] seed = NewSeed();
        RelayIdentity victim = new(EndpointIdentity.DeriveEndpointSeed(seed));
        IPEndPoint ep = new(IPAddress.Loopback, 4711);
        AddressRecord record = new()
        {
            PeerId = 0xABCD,
            EndpointKey = victim.PublicKey,
            Sequence = 1000,
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5),
            Endpoints = [ep],
        };
        byte[] wire = record.EncodeSigned(victim);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        Assert.True(AddressRecord.TryParseVerified(wire, 0xABCD, victim.PublicKey, now, out AddressRecord? good));
        Assert.Equal(ep, good!.Endpoints.Single());

        Assert.False(AddressRecord.TryParseVerified(wire, 0xABCD, new RelayIdentity().PublicKey, now, out _));
        Assert.False(AddressRecord.TryParseVerified(wire, 0xABCE, victim.PublicKey, now, out _));

        foreach (int flip in new[] { 2, 12, 45, 58, 62 })
        {
            byte[] tampered = (byte[])wire.Clone();
            tampered[flip] ^= 0xFF;
            Assert.False(AddressRecord.TryParseVerified(tampered, 0xABCD, victim.PublicKey, now, out _), $"flip at {flip}");
        }

        AddressRecord expired = new()
        {
            PeerId = record.PeerId,
            EndpointKey = record.EndpointKey,
            Sequence = record.Sequence,
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5),
            Endpoints = record.Endpoints,
        };
        byte[] expiredWire = expired.EncodeSigned(victim);
        Assert.False(AddressRecord.TryParseVerified(expiredWire, 0xABCD, victim.PublicKey,
            DateTimeOffset.UtcNow.AddMinutes(10), out _));

        Assert.False(AddressRecord.TryParseVerified(wire[..^65], 0xABCD, victim.PublicKey, now, out _));
    }

    [Fact]
    public void RecordVerification_HostileExpiryTimestamp_ReturnsFalseInsteadOfThrowing()
    {
        byte[] seed = NewSeed();
        RelayIdentity victim = new(EndpointIdentity.DeriveEndpointSeed(seed));
        byte[] wire = new AddressRecord
        {
            PeerId = 0xABCD,
            EndpointKey = victim.PublicKey,
            Sequence = 1000,
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5),
            Endpoints = [new IPEndPoint(IPAddress.Loopback, 4711)],
        }.EncodeSigned(victim);

        byte[] hostile = (byte[])wire.Clone();
        BinaryPrimitives.WriteInt64LittleEndian(hostile.AsSpan(49, 8), long.MaxValue);
        Assert.False(AddressRecord.TryParseVerified(hostile, 0xABCD, victim.PublicKey,
            DateTimeOffset.UtcNow, out _));

        BinaryPrimitives.WriteInt64LittleEndian(hostile.AsSpan(49, 8), long.MinValue);
        Assert.False(AddressRecord.TryParseVerified(hostile, 0xABCD, victim.PublicKey,
            DateTimeOffset.UtcNow, out _));
    }

    [Fact]
    public async Task RecordRollback_RejectedBySequenceCache()
    {
        await using PinholeNode node = await PinholeNode.BindAsync(Options());
        NodeEngine engine = node.Engine;

        Assert.True(engine.AcceptRecordSequence(7, 100));
        Assert.True(engine.AcceptRecordSequence(7, 100));
        Assert.False(engine.AcceptRecordSequence(7, 99));
        Assert.True(engine.AcceptRecordSequence(7, 101));
        Assert.True(engine.AcceptRecordSequence(8, 1));
    }

    [Fact]
    public async Task RendezvousServer_PassesRecordsThroughAndStaysLegacyCompatible()
    {
        await using RendezvousServer server = StartRendezvous();
        using Socket a = TalkSocket();
        using Socket b = TalkSocket();

        const string record = "cGluaG9sZS1zaG91bGQtYmUtdmVyaWZpZWQ";
        ulong registeredId = 0x1234;
        await SendAsync(a, $"REG {registeredId:x16} {record}", server);
        Assert.StartsWith("OBS", await RecvAsync(a), StringComparison.Ordinal);
        await SendAsync(b, $"WANT 5678 {registeredId:x16}", server);
        Assert.Equal($"INTRO {registeredId:x16} {record}", await RecvAsync(b));

        ulong legacyId = 0x9ABC;
        using Socket c = TalkSocket();
        await SendAsync(c, $"REG {legacyId:x16}", server);
        Assert.StartsWith("OBS", await RecvAsync(c), StringComparison.Ordinal);
        await SendAsync(b, $"WANT 5678 {legacyId:x16}", server);
        string intro = await RecvAsync(b);
        Assert.StartsWith($"INTRO {legacyId:x16} ", intro, StringComparison.Ordinal);
        Assert.DoesNotContain(record, intro);

        using Socket d = TalkSocket();
        await SendAsync(d, "REG dead not-base64!!", server);
        await Task.Delay(100);
        await SendAsync(b, "WANT 5678 dead", server);
        Assert.StartsWith("WAIT", await RecvAsync(b), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReconnectAfterRestart_NoNewTicket()
    {
        await using RendezvousServer server = StartRendezvous();
        byte[] seed = NewSeed();

        await using PinholeNode listener = await PinholeNode.BindAsync(Options(seed, [Loopback(server)]));
        await using PinholeNode dialer = await PinholeNode.BindAsync(Options(NewSeed(), [Loopback(server)]));

        string ticket = listener.ConnectionString;
        int oldPort = listener.LocalPort;
        await using PinholeConnection first = await dialer.ConnectAsync(ticket);
        await using PinholeConnection accepted = await listener.AcceptAsync();
        await ExchangeAsync(first, accepted, "before the restart");
        first.Dispose();
        accepted.Dispose();
        listener.Dispose();

        await using PinholeNode revived = await BindOnFreshPortAsync(Options(seed, [Loopback(server)]), oldPort, _output);
        Assert.Equal(listener.PeerId, revived.PeerId);
        Assert.Equal(listener.StaticPublicKey, revived.StaticPublicKey);
        Assert.Equal(listener.EndpointPublicKey, revived.EndpointPublicKey);

        await using PinholeConnection second = await dialer.ConnectAsync(ticket);
        await using PinholeConnection reaccepted = await revived.AcceptAsync();
        await ExchangeAsync(second, reaccepted, "after the restart, old ticket");
        Assert.Equal(revived.PeerId, second.PeerId);
    }

    [Fact]
    public async Task BothPeersRoamSimultaneously_EitherDirectionReconnects()
    {
        await using RendezvousServer server = StartRendezvous();
        byte[] seedA = NewSeed();
        byte[] seedB = NewSeed();
        await using PinholeNode a1 = await PinholeNode.BindAsync(Options(seedA, [Loopback(server)]));
        await using PinholeNode b1 = await PinholeNode.BindAsync(Options(seedB, [Loopback(server)]));

        string ticketA = a1.ConnectionString;
        string ticketB = b1.ConnectionString;
        int portA = a1.LocalPort;
        int portB = b1.LocalPort;

        a1.Dispose();
        b1.Dispose();

        TimeSpan healBudget = TimeSpan.FromSeconds(15);
        await using PinholeNode a2 = await BindOnFreshPortAsync(Options(seedA, [Loopback(server)], connectTimeout: healBudget), portA, _output);
        await using PinholeNode b2 = await BindOnFreshPortAsync(Options(seedB, [Loopback(server)], connectTimeout: healBudget), portB, _output);
        await UntilRecordServedAsync(server, a2.PeerId);
        await UntilRecordServedAsync(server, b2.PeerId);

        try
        {
            await using (PinholeConnection atB = await a2.ConnectAsync(ticketB))
            await using (PinholeConnection acceptAtB = await b2.AcceptAsync())
            {
                await ExchangeAsync(atB, acceptAtB, "A dials B's stale ticket");
            }
        }
        catch (Exception ex)
        {

            _output.WriteLine($"direction-one failed: {ex.Message}");
            _output.WriteLine($"rendezvous nodes={server.NodeCount} wants={server.WantCount}");
            _output.WriteLine($"a2 conns: {string.Join(",", a2.Connections.Select(c => $"{c.State}/{c.Path.Kind}@{c.Path.Remote}"))}");
            _output.WriteLine($"b2 conns: {string.Join(",", b2.Connections.Select(c => $"{c.State}/{c.Path.Kind}@{c.Path.Remote}"))}");
            _output.WriteLine($"handshake a2-side: {a2.Engine.HandshakeSummary(b2.PeerId)}");
            _output.WriteLine($"handshake b2-side: {b2.Engine.HandshakeSummary(a2.PeerId)}");
            _output.WriteLine($"recv a2: {a2.Engine.RecvDiagnostics()}");
            _output.WriteLine($"recv b2: {b2.Engine.RecvDiagnostics()}");
            throw;
        }

        try
        {
            await using PinholeConnection atA = await b2.ConnectAsync(ticketA);
            await using PinholeConnection acceptAtA = await a2.AcceptAsync();
            await ExchangeAsync(atA, acceptAtA, "B dials A's stale ticket");
        }
        catch (Exception ex)
        {
            _output.WriteLine($"direction-two failed: {ex.Message}");
            _output.WriteLine($"rendezvous nodes={server.NodeCount} wants={server.WantCount}");
            _output.WriteLine($"a2 conns: {string.Join(",", a2.Connections.Select(c => $"{c.State}/{c.Path.Kind}@{c.Path.Remote}"))}");
            _output.WriteLine($"b2 conns: {string.Join(",", b2.Connections.Select(c => $"{c.State}/{c.Path.Kind}@{c.Path.Remote}"))}");
            _output.WriteLine($"handshake a2-side: {a2.Engine.HandshakeSummary(b2.PeerId)}");
            _output.WriteLine($"handshake b2-side: {b2.Engine.HandshakeSummary(a2.PeerId)}");
            _output.WriteLine($"recv a2: {a2.Engine.RecvDiagnostics()}");
            _output.WriteLine($"recv b2: {b2.Engine.RecvDiagnostics()}");
            throw;
        }
    }

    [Fact]
    public async Task AllCachedAddressesDead_RediscoveredRecordCarriesTheDial()
    {
        await using RendezvousServer server = StartRendezvous();
        byte[] seed = NewSeed();

        string ticket;
        int oldPort;
        await using (PinholeNode victim = await PinholeNode.BindAsync(Options(seed, [Loopback(server)])))
        {
            ticket = victim.ConnectionString;
            oldPort = victim.LocalPort;
        }

        await using PinholeNode dialer = await PinholeNode.BindAsync(Options(NewSeed(), [Loopback(server)]));

        await using PinholeNode moved = await BindOnFreshPortAsync(Options(seed, [Loopback(server)]), oldPort, _output);
        await UntilRecordServesPortAsync(server, moved.PeerId, moved.EndpointPublicKey!, moved.LocalPort);

        await using PinholeConnection conn = await dialer.ConnectAsync(ticket);
        Assert.Equal(moved.PeerId, conn.PeerId);
        Assert.Contains(dialer.Engine.PeerCandidatesSnapshot(moved.PeerId),
            c => c.Address.Port == moved.LocalPort);
        _output.WriteLine($"healed onto port {moved.LocalPort} (dead ticket port was {oldPort})");
    }

    private sealed class PoisonProvider : IPinholeLookupProvider
    {
        public byte[]? Served { get; set; }
        public bool ThrowOnResolve { get; set; }
        public int Resolves { get; private set; }

        public Task PublishAsync(ReadOnlyMemory<byte> signedRecord, CancellationToken ct) => Task.CompletedTask;

        public Task<byte[]?> ResolveAsync(ulong peerId, CancellationToken ct)
        {
            Resolves++;
            if (ThrowOnResolve)
            {
                throw new InvalidOperationException("provider is down");
            }

            return Task.FromResult(Served);
        }
    }

    [Fact]
    public async Task PoisonedRecord_CannotImpersonate_OnlyDeniesAvailability()
    {
        byte[] victimSeed = NewSeed();
        await using PinholeNode victim = await PinholeNode.BindAsync(Options(victimSeed));
        string ticket = victim.ConnectionString;
        int victimPort = victim.LocalPort;
        ulong victimId = victim.PeerId;
        victim.Dispose();

        byte[] attackerSeed = NewSeed();
        await using PinholeNode attacker = await PinholeNode.BindAsync(Options(attackerSeed));
        IPEndPoint attackerEp = new(IPAddress.Loopback, attacker.LocalPort);
        RelayIdentity attackerIdentity = new(EndpointIdentity.DeriveEndpointSeed(attackerSeed));
        var poison = new PoisonProvider
        {
            Served = new AddressRecord
            {
                PeerId = victimId,
                EndpointKey = attackerIdentity.PublicKey,
                Sequence = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 1_000_000,
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                Endpoints = [attackerEp],
            }.EncodeSigned(attackerIdentity),
        };

        Assert.False(AddressRecord.TryParseVerified(poison.Served!, victimId, victim.EndpointPublicKey!,
            DateTimeOffset.UtcNow, out _));

        byte[] forgedSignature = new AddressRecord
        {
            PeerId = victimId,
            EndpointKey = victim.EndpointPublicKey!,
            Sequence = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 2_000_000,
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(10),
            Endpoints = [attackerEp],
        }.Encode().Concat(new byte[64]).ToArray();
        Assert.False(AddressRecord.TryParseVerified(forgedSignature, victimId, victim.EndpointPublicKey!,
            DateTimeOffset.UtcNow, out _));

        await using PinholeNode dialer = await PinholeNode.BindAsync(Options(NewSeed(), providers: [poison]));
        await Assert.ThrowsAsync<TimeoutException>(() => dialer.ConnectAsync(ticket));

        Assert.Empty(attacker.Connections);
        Assert.True(poison.Resolves > 0, "the poison was actually served and refused");
        _output.WriteLine($"attacker at {attackerEp} stayed untouched; victim port {victimPort} is dead");
    }

    [Fact]
    public async Task StaleRecord_DeadEndpoints_TimesOutWithoutImpersonating()
    {
        byte[] victimSeed = NewSeed();
        await using PinholeNode victim = await PinholeNode.BindAsync(Options(victimSeed));
        string ticket = victim.ConnectionString;
        ulong victimId = victim.PeerId;
        byte[] victimEndpointKey = victim.EndpointPublicKey!;
        int deadPort = victim.LocalPort;
        victim.Dispose();

        var stale = new PoisonProvider
        {
            Served = SignedRecord(
                victimSeed, victimId,
                DateTimeOffset.UtcNow.AddMinutes(10),
                new IPEndPoint(IPAddress.Loopback, deadPort)).Wire,
        };
        Assert.True(AddressRecord.TryParseVerified(stale.Served!, victimId, victimEndpointKey,
            DateTimeOffset.UtcNow, out _));

        await using PinholeNode dialer = await PinholeNode.BindAsync(Options(NewSeed(), providers: [stale]));
        await Assert.ThrowsAsync<TimeoutException>(() => dialer.ConnectAsync(ticket));
        Assert.True(stale.Resolves > 0);
    }

    [Fact]
    public async Task ProviderOutage_AllProvidersDown_DialFailsCleanlyAndBounded()
    {

        int deadPort = FreePort();
        var throwing = new PoisonProvider { ThrowOnResolve = true };
        await using PinholeNode dialer = await PinholeNode.BindAsync(Options(NewSeed(),
            rendezvous: [new IPEndPoint(IPAddress.IPv6Loopback, deadPort)],
            providers: [throwing],
            connectTimeout: TimeSpan.FromSeconds(3)));

        string unreachableTicket = await UnreachableTicketAsync();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(() => dialer.ConnectAsync(unreachableTicket));
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(8), $"dial hung for {sw.Elapsed} past its timeout");
        _output.WriteLine($"all providers down: honest timeout in {sw.Elapsed.TotalMilliseconds:F0} ms");
    }

    [Fact]
    public async Task MultipleProviders_DeadFirst_LiveSecondStillHeals()
    {
        await using RendezvousServer server = StartRendezvous();
        byte[] seed = NewSeed();
        await using PinholeNode victim = await PinholeNode.BindAsync(Options(seed, [Loopback(server)]));
        string ticket = victim.ConnectionString;
        int oldPort = victim.LocalPort;
        victim.Dispose();

        await using PinholeNode moved = await BindOnFreshPortAsync(Options(seed, [Loopback(server)]), oldPort, _output);
        await UntilRecordServedAsync(server, moved.PeerId);

        int deadPort = FreePort();
        await using PinholeNode dialer = await PinholeNode.BindAsync(Options(NewSeed(),
            rendezvous: [new IPEndPoint(IPAddress.IPv6Loopback, deadPort), Loopback(server)]));
        await using PinholeConnection conn = await dialer.ConnectAsync(ticket);
        Assert.Equal(moved.PeerId, conn.PeerId);
    }

    private static async Task ExchangeAsync(PinholeConnection from, PinholeConnection to, string marker)
    {
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        to.Received += payload => got.TrySetResult(payload.ToArray());
        from.Send(Encoding.UTF8.GetBytes(marker));
        byte[] answer = await got.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(marker, Encoding.UTF8.GetString(answer));
    }

    private static async Task<string> UnreachableTicketAsync()
    {
        await using PinholeNode stranger = await PinholeNode.BindAsync(Options());
        return stranger.ConnectionString;
    }

    private static async Task UntilRecordServedAsync(RendezvousServer server, ulong peerId)
    {
        using Socket probe = TalkSocket();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < TimeSpan.FromSeconds(10))
        {
            await SendAsync(probe, $"WANT 0 {peerId:x16}", server);
            string reply = await RecvAsync(probe, TimeSpan.FromSeconds(1));
            if (reply.StartsWith("INTRO", StringComparison.Ordinal) && reply.Split(' ').Length == 3
                && !reply.Contains(':'))
            {
                return;
            }

            await Task.Delay(100);
        }

        throw new TimeoutException($"no record published for peer {peerId:x16}");
    }

    private static async Task UntilRecordServesPortAsync(
        RendezvousServer server, ulong peerId, byte[] endpointKey, int port)
    {
        using Socket probe = TalkSocket();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < TimeSpan.FromSeconds(10))
        {
            await SendAsync(probe, $"WANT 0 {peerId:x16}", server);
            string reply = await RecvAsync(probe, TimeSpan.FromSeconds(1));
            if (reply.StartsWith("INTRO", StringComparison.Ordinal) && reply.Split(' ').Length == 3
                && !reply.Contains(':')
                && AddressRecord.TryParseVerified(Base64Url.Decode(reply.Split(' ')[2]), peerId, endpointKey,
                    DateTimeOffset.UtcNow, out AddressRecord? record)
                && record!.Endpoints.Any(e => e.Port == port))
            {
                return;
            }

            await Task.Delay(100);
        }

        throw new TimeoutException($"served record for peer {peerId:x16} never carried port {port}");
    }

    private static Socket TalkSocket()
    {
        var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        udp.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        return udp;
    }

    private static Task SendAsync(Socket s, string line, RendezvousServer server) =>
        s.SendToAsync(Encoding.ASCII.GetBytes(line), SocketFlags.None, Loopback(server));

    private static async Task<string> RecvAsync(Socket s, TimeSpan? budget = null)
    {
        byte[] buffer = new byte[2048];
        using var timeout = new CancellationTokenSource(budget ?? TimeSpan.FromSeconds(5));
        try
        {
            SocketReceiveFromResult res = await s.ReceiveFromAsync(buffer, SocketFlags.None,
                new IPEndPoint(IPAddress.IPv6Any, 0), timeout.Token);
            return Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim();
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException("no reply from the rendezvous server");
        }
    }

    private static int FreePort()
    {
        using Socket s = TalkSocket();
        return ((IPEndPoint)s.LocalEndPoint!).Port;
    }
}
