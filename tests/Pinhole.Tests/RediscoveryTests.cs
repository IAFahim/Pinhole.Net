using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Pinhole.Rendezvous;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

/// <summary>#29 — persistent full-key identity and authenticated peer-address rediscovery.
/// The trust model under test: lookup providers (rendezvous introducers, app callbacks) are
/// untrusted stores; only records that verify against the endpoint key pinned in a v3
/// connection string are adopted, and a malicious or stale record can deny availability
/// but never impersonate the peer.</summary>
public sealed class RediscoveryTests
{
    private readonly ITestOutputHelper _output;

    public RediscoveryTests(ITestOutputHelper output) => _output = output;

    private static readonly TimeSpan DialTimeout = TimeSpan.FromSeconds(5);

    private RendezvousServer StartRendezvous() => RendezvousServer.Start();

    private static IPEndPoint Loopback(RendezvousServer server) =>
        new(IPAddress.IPv6Loopback, server.LocalEndPoint.Port);

    private static byte[] NewSeed() => RandomNumberGenerator.GetBytes(32);

    /// <summary>Offline options: no STUN, no relays, no LAN, no OS watch — a pure loopback
    /// node whose only infrastructure is the rendezvous/provider list the test arranges.</summary>
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
        IrohRelayUrls = [],
        PublishIrohAddress = false,
        EnableNetworkWatch = false,
        EnablePortMapping = false,
        EnableLanDiscovery = false,
        ConnectTimeout = connectTimeout ?? DialTimeout,
    };

    /// <summary>Binds until the node's port differs from a previous one, so a test can prove
    /// a reconnect came from rediscovery rather than OS port reuse.</summary>
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

    // ------------------------------------------------------------------ identity persistence

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

        // The seed is the root of both key domains: an endpoint private key can never be
        // recomputed from the X25519 seed's own public half (HKDF one-wayness) — spot-check
        // the domains at least differ.
        Assert.NotEqual(a.StaticPublicKey, a.EndpointPublicKey);

        ConnectionString parsed = Pinhole.ConnectionString.Parse(a.ConnectionString);
        Assert.NotNull(parsed.StaticKey);
        Assert.NotNull(parsed.EndpointKey);
        Assert.Equal(a.EndpointPublicKey, parsed.EndpointKey);

        // Malformed v3 payloads are rejected, not mis-parsed: chop a byte off the key tail.
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

    // ------------------------------------------------------------------ record authentication

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

        // Wrong pinned key (the impostor's own consistently-signed record), wrong peer id,
        // and a different honest key are all refused.
        Assert.False(AddressRecord.TryParseVerified(wire, 0xABCD, new RelayIdentity().PublicKey, now, out _));
        Assert.False(AddressRecord.TryParseVerified(wire, 0xABCE, victim.PublicKey, now, out _));

        // Any tampered field breaks the signature.
        foreach (int flip in new[] { 2, 12, 45, 58, 62 })
        {
            byte[] tampered = (byte[])wire.Clone();
            tampered[flip] ^= 0xFF;
            Assert.False(AddressRecord.TryParseVerified(tampered, 0xABCD, victim.PublicKey, now, out _), $"flip at {flip}");
        }

        // Expired records are stale even with a perfect signature.
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

        // Truncated wires never parse.
        Assert.False(AddressRecord.TryParseVerified(wire[..^65], 0xABCD, victim.PublicKey, now, out _));
    }

    [Fact]
    public async Task RecordRollback_RejectedBySequenceCache()
    {
        await using PinholeNode node = await PinholeNode.BindAsync(Options());
        NodeEngine engine = node.Engine;

        Assert.True(engine.AcceptRecordSequence(7, 100));
        Assert.True(engine.AcceptRecordSequence(7, 100)); // idempotent re-adoption of the same record
        Assert.False(engine.AcceptRecordSequence(7, 99)); // strictly older: rollback
        Assert.True(engine.AcceptRecordSequence(7, 101));
        Assert.True(engine.AcceptRecordSequence(8, 1));   // per-peer cache, independent rows
    }

    // ------------------------------------------------------------------ rendezvous wire

    [Fact]
    public async Task RendezvousServer_PassesRecordsThroughAndStaysLegacyCompatible()
    {
        await using RendezvousServer server = StartRendezvous();
        using Socket a = TalkSocket();
        using Socket b = TalkSocket();

        // A record-bearing registration is served back verbatim to a second node's WANT.
        const string record = "cGluaG9sZS1zaG91bGQtYmUtdmVyaWZpZWQ";
        ulong registeredId = 0x1234;
        await SendAsync(a, $"REG {registeredId:x16} {record}", server);
        Assert.StartsWith("OBS", await RecvAsync(a), StringComparison.Ordinal);
        await SendAsync(b, $"WANT 5678 {registeredId:x16}", server);
        Assert.Equal($"INTRO {registeredId:x16} {record}", await RecvAsync(b));

        // A bare registration keeps the legacy endpoint form — no record, no surprise.
        ulong legacyId = 0x9ABC;
        using Socket c = TalkSocket();
        await SendAsync(c, $"REG {legacyId:x16}", server);
        Assert.StartsWith("OBS", await RecvAsync(c), StringComparison.Ordinal);
        await SendAsync(b, $"WANT 5678 {legacyId:x16}", server);
        string intro = await RecvAsync(b);
        Assert.StartsWith($"INTRO {legacyId:x16} ", intro, StringComparison.Ordinal);
        Assert.DoesNotContain(record, intro);

        // Hostile payloads (space smuggling, oversize) are ignored entirely.
        using Socket d = TalkSocket();
        await SendAsync(d, "REG dead not-base64!!", server);
        await Task.Delay(100);
        await SendAsync(b, "WANT 5678 dead", server);
        Assert.StartsWith("WAIT", await RecvAsync(b), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ the acceptance scenarios

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

        // Same seed, fresh process-equivalent: same full identity, new address.
        await using PinholeNode revived = await BindOnFreshPortAsync(Options(seed, [Loopback(server)]), oldPort, _output);
        Assert.Equal(listener.PeerId, revived.PeerId);
        Assert.Equal(listener.StaticPublicKey, revived.StaticPublicKey);
        Assert.Equal(listener.EndpointPublicKey, revived.EndpointPublicKey);

        // The old ticket's own candidates point at the dead port; only rediscovery can land.
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

        // Both sides drop and rebind (a simultaneous roam): both publish fresh records.
        a1.Dispose();
        b1.Dispose();
        // The stale-ticket dials below assert rediscovery healing, not dial latency: on a
        // saturated CI runner the heal chain (dead-candidate punch → lookup → adopt →
        // crypto handshake) stretches well past the 5 s production default the rest of
        // this suite uses, so these two dials carry their own load-tolerant budget.
        TimeSpan healBudget = TimeSpan.FromSeconds(15);
        await using PinholeNode a2 = await BindOnFreshPortAsync(Options(seedA, [Loopback(server)], connectTimeout: healBudget), portA, _output);
        await using PinholeNode b2 = await BindOnFreshPortAsync(Options(seedB, [Loopback(server)], connectTimeout: healBudget), portB, _output);
        await UntilRecordServedAsync(server, a2.PeerId);
        await UntilRecordServedAsync(server, b2.PeerId);

        // Direction one: A's stale ticket heals onto B's new address.
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
            // Parallel-suite forensics: the handshake-flight counters name the dead stage
            // (punches sent vs answered vs processed) without needing tracing enabled.
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

        // Direction two, after the first pair closed: B's stale ticket heals onto A's new
        // address. (Dialing while the first connection lives would reuse it — that is the
        // engine's idempotent-dial rule, not a new path.)
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

    /// <summary>The exact acceptance criterion of #29: when a ticket's candidates are all
    /// dead, the dial heals through the lookup route. Here the revived peer moved ports and
    /// we assert the fresh record's endpoint was actually adopted by the dial.</summary>
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

        // The victim "roams" without notice: same identity, new address, fresh record. Its
        // old socket is gone — the ticket's only endpoint is dead, so the record is the
        // only route. (The victim must actually be disposed here: a live node keeps
        // republishing its own record under the same peer id, and the last writer wins.)
        await using PinholeNode moved = await BindOnFreshPortAsync(Options(seed, [Loopback(server)]), oldPort, _output);
        await UntilRecordServesPortAsync(server, moved.PeerId, moved.EndpointPublicKey!, moved.LocalPort);

        // The ticket only knows the dead port; the connection can only exist via the record.
        await using PinholeConnection conn = await dialer.ConnectAsync(ticket);
        Assert.Equal(moved.PeerId, conn.PeerId);
        Assert.Contains(dialer.Engine.PeerCandidatesSnapshot(moved.PeerId),
            c => c.Address.Port == moved.LocalPort);
        _output.WriteLine($"healed onto port {moved.LocalPort} (dead ticket port was {oldPort})");
    }

    // ------------------------------------------------------------------ adversarial providers

    /// <summary>A lookup provider the test fully controls: serves whatever bytes it is told
    /// to, exactly like a hostile or compromised directory would.</summary>
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

        // The attacker is a real, live pinhole node with its own honest keys — but its
        // record claims to be the victim and lists the attacker's own address. Fully
        // self-consistent: signed by exactly the key it carries.
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
        // Consistent, fresh, correctly signed — and still never adoptable, because the
        // pinned key is the victim's, not the attacker's.
        Assert.False(AddressRecord.TryParseVerified(poison.Served!, victimId, victim.EndpointPublicKey!,
            DateTimeOffset.UtcNow, out _));

        // Second poison: claims the victim's own endpoint key but is signed by the attacker.
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

        // Availability was denied; nobody was impersonated: the attacker never saw a session.
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

        // A perfectly authentic record — signed by the victim's own derived key — whose
        // endpoints are the victim's now-dead address. Verified, adopted, and useless.
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
        // A rendezvous endpoint nothing listens on, plus an app provider that throws.
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

        // First provider unreachable, second live: first-verified-wins still finds the record.
        int deadPort = FreePort();
        await using PinholeNode dialer = await PinholeNode.BindAsync(Options(NewSeed(),
            rendezvous: [new IPEndPoint(IPAddress.IPv6Loopback, deadPort), Loopback(server)]));
        await using PinholeConnection conn = await dialer.ConnectAsync(ticket);
        Assert.Equal(moved.PeerId, conn.PeerId);
    }

    // ------------------------------------------------------------------ helpers

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

    /// <summary>Polls the introducer until a raw WANT for the peer yields a record-bearing
    /// INTRO — the observable proof the peer's publish landed.</summary>
    private static async Task UntilRecordServedAsync(RendezvousServer server, ulong peerId)
    {
        using Socket probe = TalkSocket();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < TimeSpan.FromSeconds(10))
        {
            await SendAsync(probe, $"WANT 0 {peerId:x16}", server);
            string reply = await RecvAsync(probe, TimeSpan.FromSeconds(1));
            if (reply.StartsWith("INTRO", StringComparison.Ordinal) && reply.Split(' ').Length == 3
                && !reply.Contains(':')) // records are base64url; endpoints contain colons
            {
                return;
            }

            await Task.Delay(100);
        }

        throw new TimeoutException($"no record published for peer {peerId:x16}");
    }

    /// <summary>Waits until the record the server currently serves is the fresh one — the
    /// decoded, verified record carries the expected port. Any earlier record under the
    /// same peer id (a disposed predecessor's) must not satisfy this wait.</summary>
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
