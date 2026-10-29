using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Pinhole.Rendezvous;
using Xunit;

namespace Pinhole.Tests;

public sealed class HostJoinTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);
    private static PinholeOptions OfflineNode() => new()
    {
        Bind = new IPEndPoint(IPAddress.Loopback, 0),
        StunServers = [], Relays = [], IrohRelayUrls = [], DerpRelayUrls = [],
        PublishIrohAddress = false, EnableNetworkWatch = false, EnablePortMapping = false,
        EnableLanDiscovery = false, ReceiveBufferCapacity = 16,
        ConnectTimeout = TimeSpan.FromSeconds(8),
    };

    private static PinholeHostSettings HostSettings(RendezvousServer server) => new()
    {
        RendezvousEndpoints = [server.LocalEndPoint],
        NodeOptions = OfflineNode(),
    };

    private static PinholeJoinSettings JoinSettings(RendezvousServer server) => new()
    {
        RendezvousEndpoints = [server.LocalEndPoint],
        NodeOptions = OfflineNode(),
        WaitTimeout = TimeSpan.FromSeconds(10),
        PollInterval = TimeSpan.FromMilliseconds(200),
    };

    [Fact]
    public async Task BothDefaultRelayFleets_HostAndJoinByCode_WithAnInvitationLargerThanTheOldDirectoryLimit()
    {
        await using var server = RendezvousServer.Start();
        var iroh = PinholeOptions.PublicIrohRelays.ToDictionary(url => url.Host, _ => new InMemoryIrohRelay());
        var derp = PinholeOptions.PublicDerpRelays.ToDictionary(url => url.Host, url => new InMemoryDerpRelay(url.Host));
        try
        {
            PinholeOptions options = OfflineNode() with
            {
                IrohRelayUrls = null, DerpRelayUrls = null,
                IrohWebSocketFactory = (uri, ct) => iroh[uri.Host].ConnectAsync(new Uri("wss://relay.example.test/relay"), ct),
                DerpWebSocketFactory = (uri, ct) => derp[uri.Host].ConnectAsync(uri, ct),
                EnableDirectUdp = false, EnableTcpTransport = false,
            };
            await using var host = await PinholeSession.HostAsync(HostSettings(server) with { NodeOptions = options }).WaitAsync(Timeout);
            string invitation = host.FullInvitation;
            Assert.True(Base64Url.Encode(Encoding.UTF8.GetBytes(invitation)).Length > RendezvousServer.MaxRecordLength);
            var candidates = ConnectionString.Parse(invitation).Candidates;
            Assert.Equal(4, candidates.Count(c => c.Kind == CandidateKind.IrohRelay));
            Assert.Equal(4, candidates.Count(c => c.Kind == CandidateKind.DerpRelay));
            Task<PinholeConnection> accepting = host.AcceptAsync();
            await using var joined = await PinholeSession.JoinAsync(host.Code, JoinSettings(server) with { NodeOptions = options }).WaitAsync(Timeout);
            await using var accepted = await accepting.WaitAsync(Timeout);
            Assert.True(joined.IsEncrypted && accepted.IsEncrypted);
            Assert.Equal(PathKind.Relay, joined.Path.Kind);
            joined.Send("both default relay fleets fit invitation codes"u8);
            Assert.Equal("both default relay fleets fit invitation codes"u8.ToArray(),
                (await accepted.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value.ToArray());
        }
        finally
        {
            foreach (var relay in iroh.Values) relay.Dispose();
            foreach (var relay in derp.Values) relay.Dispose();
        }
    }

    [Fact]
    public async Task HostAndJoinByCode_ExchangesDatagramsBothWays()
    {
        await using var server = RendezvousServer.Start();
        await using var host = await PinholeSession.HostAsync(HostSettings(server)).WaitAsync(Timeout);
        Task<PinholeConnection> accepted = host.AcceptAsync();
        await using var joined = await PinholeSession.JoinAsync(host.Code, JoinSettings(server)).WaitAsync(Timeout);
        await using var hosting = await accepted.WaitAsync(Timeout);

        Assert.True(joined.IsEncrypted);
        Assert.True(hosting.IsEncrypted);
        byte[] payload = RandomNumberGenerator.GetBytes(64);
        joined.Send(payload);
        ReadOnlyMemory<byte>? received = await hosting.ReceiveAsync().AsTask().WaitAsync(Timeout);
        Assert.NotNull(received);
        Assert.Equal(payload, received.Value.ToArray());
        hosting.Send([7, 7, 7]);
        received = await joined.ReceiveAsync().AsTask().WaitAsync(Timeout);
        Assert.NotNull(received);
        Assert.Equal(new byte[] { 7, 7, 7 }, received.Value.ToArray());

        Assert.Equal(host.ConfirmationCode, joined.RemoteConfirmationCode);
    }

    [Fact]
    public async Task ConfirmationCode_IsIdentityOnly_AndSurvivesCandidateChurn()
    {
        await using var server = RendezvousServer.Start();
        await using var host = await PinholeSession.HostAsync(HostSettings(server)).WaitAsync(Timeout);
        Task<PinholeConnection> accepted = host.AcceptAsync();
        await using var joined = await PinholeSession.JoinAsync(host.Code, JoinSettings(server)).WaitAsync(Timeout);
        await using var hosting = await accepted.WaitAsync(Timeout);

        Assert.Equal(host.ConfirmationCode, joined.RemoteConfirmationCode);
        Assert.NotNull(hosting.RemoteConfirmationCode);
        Assert.NotEqual(host.ConfirmationCode, hosting.RemoteConfirmationCode);

        ConnectionString before = ConnectionString.Parse(host.FullInvitation);
        var roamed = new ConnectionString(
            before.PeerId,
            [.. before.Candidates, new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 65001))],
            before.NatHint, before.StaticKey, before.EndpointKey);
        Assert.Equal(
            host.ConfirmationCode,
            PinholeHost.FormatConfirmation(PinholeHost.ConfirmationFingerprint(roamed.PeerId, roamed.StaticKey, roamed.EndpointKey)));

        Assert.NotEqual(
            host.ConfirmationCode,
            PinholeHost.FormatConfirmation(PinholeHost.ConfirmationFingerprint(before.PeerId + 1, before.StaticKey, before.EndpointKey)));
    }

    [Fact]
    public async Task CodesAreRandomBase32_AndDistinctAcrossHosts()
    {
        await using var server = RendezvousServer.Start();
        var hosts = new List<PinholeHost>();
        try
        {
            for (int i = 0; i < 4; i++)
            {
                hosts.Add(await PinholeSession.HostAsync(HostSettings(server)).WaitAsync(Timeout));
            }

            foreach (PinholeHost host in hosts)
            {
                Assert.Equal(9, host.Code.Length);
                foreach (char c in host.Code)
                {
                    Assert.Contains(c, "0123456789ABCDEFGHJKMNPQRSTVWXYZ");
                }
            }

            Assert.Equal(hosts.Count, hosts.Select(h => h.Code).Distinct().Count());
            Assert.Equal(hosts.Count, hosts.Select(h => h.ConfirmationCode).Distinct().Count());
            Assert.Matches("^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$", hosts[0].ConfirmationCode);
        }
        finally
        {
            foreach (PinholeHost host in hosts)
            {
                await host.DisposeAsync();
            }
        }
    }

    [Fact]
    public async Task UnknownCode_TimesOutWithCleanError()
    {
        await using var server = RendezvousServer.Start();
        var settings = JoinSettings(server) with { WaitTimeout = TimeSpan.FromSeconds(2), PollInterval = TimeSpan.FromMilliseconds(200) };
        await Assert.ThrowsAsync<TimeoutException>(
            () => PinholeSession.JoinAsync("ZZZZZZZZZ", settings).WaitAsync(Timeout));
    }

    [Fact]
    public async Task DisposalDeletesTheCode_JoinersAfterwardsFindNothing()
    {
        await using var server = RendezvousServer.Start();
        string code;
        await using (var host = await PinholeSession.HostAsync(HostSettings(server)).WaitAsync(Timeout))
        {
            code = host.Code;
            Assert.Equal(1, server.CodeCount);
        }

        Assert.Equal(0, server.CodeCount);
        var settings = JoinSettings(server) with { WaitTimeout = TimeSpan.FromSeconds(1), PollInterval = TimeSpan.FromMilliseconds(150) };
        await Assert.ThrowsAsync<TimeoutException>(
            () => PinholeSession.JoinAsync(code, settings).WaitAsync(Timeout));
    }

    [Fact]
    public async Task LiveCode_CannotBeReplacedWithoutItsToken()
    {
        await using var server = RendezvousServer.Start();
        await using var host = await PinholeSession.HostAsync(HostSettings(server)).WaitAsync(Timeout);

        using var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        udp.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        var target = new IPEndPoint(IPAddress.Loopback, server.LocalEndPoint.Port);
        byte[] stranger = Encoding.ASCII.GetBytes($"PUTC {host.Code} {Convert.ToBase64String(Encoding.UTF8.GetBytes("evil"))}");
        await udp.SendToAsync(stranger, SocketFlags.None, target);
        byte[] buffer = new byte[256];
        IPEndPoint any = new(IPAddress.IPv6Any, 0);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        SocketReceiveFromResult res = await udp.ReceiveFromAsync(buffer, SocketFlags.None, any, cts.Token);
        Assert.Equal("TokB", Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim());
        Assert.Equal(1, server.CodeCount);

        var settings = JoinSettings(server);
        await using var joined = await PinholeSession.JoinAsync(host.Code, settings).WaitAsync(Timeout);
        Assert.True(joined.IsEncrypted);
    }

    [Fact]
    public async Task Keepalive_RefreshesPastTheDirectoryTtl()
    {

        await using var server = RendezvousServer.Start(ttl: TimeSpan.FromSeconds(2));
        var hostSettings = HostSettings(server) with { RefreshInterval = TimeSpan.FromMilliseconds(500) };
        await using var host = await PinholeSession.HostAsync(hostSettings).WaitAsync(Timeout);
        await Task.Delay(TimeSpan.FromSeconds(5));
        Assert.Equal(1, server.CodeCount);

        var settings = JoinSettings(server);
        await using var joined = await PinholeSession.JoinAsync(host.Code, settings).WaitAsync(Timeout);
        Assert.True(joined.IsEncrypted);
    }

    [Fact]
    public async Task DirectoryBounds_RejectOversizedRecordsAndBadCodes()
    {
        await using var server = RendezvousServer.Start();
        var directory = new CodeDirectory([new(IPAddress.Loopback, server.LocalEndPoint.Port)]);
        await Assert.ThrowsAsync<ArgumentException>(() => directory.PutAsync("ABCDEFG",
            new string('A', ConnectionString.MaxEncodedLength), CancellationToken.None));
        using var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        udp.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        var target = new IPEndPoint(IPAddress.Loopback, server.LocalEndPoint.Port);
        byte[] buffer = new byte[4096];
        IPEndPoint any = new(IPAddress.IPv6Any, 0);

        async Task<string> Roundtrip(string message)
        {
            await udp.SendToAsync(Encoding.ASCII.GetBytes(message), SocketFlags.None, target);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            try
            {
                SocketReceiveFromResult res = await udp.ReceiveFromAsync(buffer, SocketFlags.None, any, cts.Token);
                return Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim();
            }
            catch (OperationCanceledException)
            {
                return "";
            }
        }

        string huge = new string('A', RendezvousServer.MaxCodeRecordLength + 1);
        Assert.Equal(string.Empty, await Roundtrip($"PUTC ABCDEFG {huge}"));
        Assert.Equal(string.Empty, await Roundtrip("PUTC has space and invalid {A}"));
        Assert.StartsWith("OKCG ", await Roundtrip("PUTC ABCDEFG AAAAAAAA"));

        string challenge = await Roundtrip("GETC ABCDEFG");
        Assert.StartsWith("CHAL ABCDEFG ", challenge);
        Assert.StartsWith("OKCC ", await Roundtrip($"GETC ABCDEFG {challenge.Split(' ')[^1]}"));
        Assert.Equal("WAITC", await Roundtrip("GETC NOSUCHCODE"));
        Assert.Equal("TokB", await Roundtrip("DELC ABCDEFG wrong-token"));
    }

    [Fact]
    public async Task ClaimToken_IsExactly22Base64UrlCharacters_AndDrivesRefreshAndDelete()
    {
        await using var server = RendezvousServer.Start();
        using var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        udp.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        var target = new IPEndPoint(IPAddress.Loopback, server.LocalEndPoint.Port);
        byte[] buffer = new byte[4096];
        IPEndPoint any = new(IPAddress.IPv6Any, 0);

        async Task<string> Roundtrip(string message)
        {
            await udp.SendToAsync(Encoding.ASCII.GetBytes(message), SocketFlags.None, target);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            SocketReceiveFromResult res = await udp.ReceiveFromAsync(buffer, SocketFlags.None, any, cts.Token);
            return Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim();
        }

        string reply = await Roundtrip("PUTC TOKEN01 AAAAAAAA");
        Assert.StartsWith("OKCG ", reply);
        string token = reply["OKCG ".Length..];

        Assert.Equal(22, token.Length);
        Assert.All(token, c => Assert.True(
            c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_',
            $"unexpected token character '{c}' (0x{(short)c:X4})"));

        Assert.StartsWith("OKCG", await Roundtrip($"PUTC TOKEN01 BBBBBBBB {token}"));
        Assert.Equal("OKCD", await Roundtrip($"DELC TOKEN01 {token}"));
    }

    [Fact]
    public async Task RefreshOfAnAbsentCode_IsNOCODE_NotTokB()
    {
        await using var server = RendezvousServer.Start();
        using var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        udp.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        var target = new IPEndPoint(IPAddress.Loopback, server.LocalEndPoint.Port);
        byte[] buffer = new byte[4096];
        IPEndPoint any = new(IPAddress.IPv6Any, 0);

        async Task<string> Roundtrip(string message)
        {
            await udp.SendToAsync(Encoding.ASCII.GetBytes(message), SocketFlags.None, target);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            SocketReceiveFromResult res = await udp.ReceiveFromAsync(buffer, SocketFlags.None, any, cts.Token);
            return Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim();
        }

        Assert.Equal("NOCODE", await Roundtrip("PUTC GONECOD AAAAAAAA stalenonce"));
        Assert.Equal("NOCODE", await Roundtrip("DELC GONECOD stalenonce"));

        Assert.StartsWith("OKCG", await Roundtrip("PUTC LIVECODE AAAAAAAA"));
        Assert.Equal("TokB", await Roundtrip("PUTC LIVECODE BBBBBBBB wrong-token"));
        Assert.Equal("TokB", await Roundtrip("DELC LIVECODE wrong-token"));
    }

    [Fact]
    public async Task ForgedDirectoryReply_FromAnUnconfiguredSource_IsIgnored()
    {

        using var fakeDirectory = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        fakeDirectory.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
        using var spoofer = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        spoofer.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));

        var directory = new CodeDirectory([(IPEndPoint)fakeDirectory.LocalEndPoint!]);
        byte[] forged = Encoding.ASCII.GetBytes("OKCC " + Base64Url.Encode(Encoding.UTF8.GetBytes("pinhole1:AAAAFORGED")));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Task<string?> resolve = directory.ResolveAsync("ABCDEFG", TimeSpan.FromSeconds(3), TimeSpan.FromMilliseconds(300), cts.Token);

        byte[] buffer = new byte[2048];
        var anySource = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (!resolve.IsCompleted)
        {
            using var wait = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            SocketReceiveFromResult res;
            try
            {
                res = await fakeDirectory.ReceiveFromAsync(buffer, SocketFlags.None, anySource, wait.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            await spoofer.SendToAsync(forged, SocketFlags.None, res.RemoteEndPoint!);
        }

        Assert.Null(await resolve.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task DirectoryRestart_KeepaliveReClaimsTheCode()
    {

        int port;
        using (var probe = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true })
        {
            probe.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
            port = ((IPEndPoint)probe.LocalEndPoint!).Port;
        }

        var endpoint = new IPEndPoint(IPAddress.IPv6Loopback, port);

        var settings = new PinholeHostSettings
        {
            RendezvousEndpoints = [endpoint],
            NodeOptions = OfflineNode(),
            RefreshInterval = TimeSpan.FromSeconds(1),
        };

        await using var server = RendezvousServer.Start(port);
        await using var host = await PinholeSession.HostAsync(settings).WaitAsync(Timeout);
        Assert.Equal(1, server.CodeCount);
        string code = host.Code;

        await server.DisposeAsync();
        await using var restarted = RendezvousServer.Start(port);
        Assert.Equal(0, restarted.CodeCount);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (restarted.CodeCount == 0 && sw.Elapsed < TimeSpan.FromSeconds(8))
        {
            await Task.Delay(100);
        }

        Assert.Equal(1, restarted.CodeCount);

        var joiner = new CodeDirectory([restarted.LocalEndPoint]);
        string? invitation = await joiner.ResolveAsync(code, TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(200),
            CancellationToken.None).WaitAsync(Timeout);
        Assert.NotNull(invitation);
        Assert.True(Pinhole.ConnectionString.TryParse(invitation, out _), "re-claimed record is a live connection string");
    }
}
