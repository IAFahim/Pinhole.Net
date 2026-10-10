using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Pinhole.Rendezvous;
using Xunit;

namespace Pinhole.Tests;

/// <summary>#45 M2: the minimal host/join-by-code API over the real in-process rendezvous
/// code directory and the real engine. All cases run on loopback with offline node options;
/// the transport beneath is the unchanged UDP/TCP/relay engine.</summary>
public sealed class HostJoinTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);
    private static PinholeOptions OfflineNode() => new()
    {
        Bind = new IPEndPoint(IPAddress.Loopback, 0),
        StunServers = [], Relays = [], IrohRelayUrls = [],
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

        // The joiner can verify out of band what the host displays.
        string joinerView = PinholeHost.Fingerprint(Encoding.UTF8.GetBytes(host.FullInvitation));
        Assert.Equal(host.ConfirmationCode.Replace("-", ""), joinerView);
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
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        SocketReceiveFromResult res = await udp.ReceiveFromAsync(buffer, SocketFlags.None, any, cts.Token);
        Assert.Equal("TokB", Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim());
        Assert.Equal(1, server.CodeCount); // unchanged, not replaced by the stranger

        // The real invitation still resolves: the host's keepalive path is untouched.
        var settings = JoinSettings(server);
        await using var joined = await PinholeSession.JoinAsync(host.Code, settings).WaitAsync(Timeout);
        Assert.True(joined.IsEncrypted);
    }

    [Fact]
    public async Task Keepalive_RefreshesPastTheDirectoryTtl()
    {
        // A short TTL proves the refresh loop is what keeps the code alive: without it
        // the entry would be swept at 2s and the join would time out.
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
                return ""; // no reply at all: the server ignored an invalid command
            }
        }

        string huge = new string('A', RendezvousServer.MaxRecordLength + 1);
        Assert.Equal(string.Empty, await Roundtrip($"PUTC ABCDEFG {huge}")); // ignored, no reply
        Assert.Equal(string.Empty, await Roundtrip("PUTC has space and invalid {A}"));
        Assert.StartsWith("OKCG ", await Roundtrip("PUTC ABCDEFG AAAAAAAA"));
        Assert.StartsWith("OKCC ", await Roundtrip("GETC ABCDEFG"));
        Assert.Equal("WAITC", await Roundtrip("GETC NOSUCHCODE"));
        Assert.Equal("TokB", await Roundtrip("DELC ABCDEFG wrong-token"));
    }
}
