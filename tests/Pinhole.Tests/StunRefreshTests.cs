using System.Diagnostics;
using System.Net;
using System.Text;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Periodic reflexive refresh — the re-discovery iroh also performs on a timer:
/// NAT mappings move with no OS network event, so the node re-probes STUN, replaces a moved
/// mapping, and re-advertises its candidates without disturbing paths that already work.</summary>
public sealed class StunRefreshTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static IPEndPoint Mapping(int port) => new(IPAddress.Parse("198.51.100.7"), port);

    private static async Task<PinholeNode> BindAsync(FakeStunServer stun, TimeSpan refresh)
    {
        return await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [stun.LocalEndPoint],
            Relays = [],
            IrohRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
            EnablePathValidation = false, // isolate this suite: refresh, not probe, behavior
            StunRefreshInterval = refresh,
        }).WaitAsync(Timeout);
    }

    private static async Task<PinholeNode> BindOfflineAsync()
    {
        return await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
            EnablePathValidation = false,
        }).WaitAsync(Timeout);
    }

    [Fact]
    public async Task MovedMapping_IsRefreshedAndReplaced()
    {
        using FakeStunServer stun = new() { ReportMappedOverride = Mapping(40000) };
        await using PinholeNode node = await BindAsync(stun, TimeSpan.FromMilliseconds(250));

        Assert.Contains(node.PublicEndpoints, ep => ep.Port == 40000);

        stun.ReportMappedOverride = Mapping(41000);

        // Poll on the artifact the test ultimately asserts (the regenerated string), so the
        // pass condition and the assertions below can never observe different generations.
        await TestPoll.UntilAsync(Timeout, () =>
        {
            if (!Pinhole.ConnectionString.TryParse(node.ConnectionString, out Pinhole.ConnectionString? cs))
            {
                return false;
            }

            IReadOnlyList<PinholeCandidate> reflexive = cs.Candidates.Where(c => c.Kind == CandidateKind.Reflexive).ToList();
            return reflexive.Any(c => c.Address.Port == 41000) && reflexive.All(c => c.Address.Port != 40000);
        });

        Assert.Contains(node.PublicEndpoints, ep => ep.Port == 41000);
        Assert.DoesNotContain(node.PublicEndpoints, ep => ep.Port == 40000); // replaced, not accumulated
    }

    [Fact]
    public async Task Refresh_KeepsWorkingDirectPaths_AndTeachesPeersTheNewCandidates()
    {
        using FakeStunServer stun = new() { ReportMappedOverride = Mapping(42000) };
        await using PinholeNode a = await BindAsync(stun, TimeSpan.FromMilliseconds(250));
        await using PinholeNode b = await BindOfflineAsync();

        Task<PinholeConnection> accept = b.AcceptAsync();
        PinholeConnection atA = await a.ConnectAsync(b.ConnectionString).WaitAsync(Timeout);
        PinholeConnection atB = await accept.WaitAsync(Timeout);
        await TestPoll.UntilAsync(Timeout, () => atA.Path.Kind == PathKind.Direct && atB.Path.Kind == PathKind.Direct);

        stun.ReportMappedOverride = Mapping(42100);

        // The peer's candidate table is refreshed by the announce the refresh triggered.
        await TestPoll.UntilAsync(Timeout, () =>
            b.Engine.PeerCandidatesSnapshot(a.PeerId).Any(c => c.Kind == CandidateKind.Reflexive && c.Address.Port == 42100));

        // The refresh only re-advertised: the live direct path was never demoted or reset.
        Assert.Equal(PinholeConnectionState.Open, atA.State);
        Assert.Equal(PathKind.Direct, atA.Path.Kind);

        // And it still carries traffic after the mapping moved.
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Handler(ReadOnlySpan<byte> body) => got.TrySetResult(body.ToArray());
        atB.Received += Handler;
        try
        {
            var sw = Stopwatch.StartNew();
            while (!got.Task.IsCompleted && sw.Elapsed < Timeout)
            {
                atA.Send(Encoding.UTF8.GetBytes("still-here"));
                await Task.Delay(50);
            }

            Assert.Equal("still-here", Encoding.UTF8.GetString(await got.Task.WaitAsync(TimeSpan.FromSeconds(1))));
        }
        finally
        {
            atB.Received -= Handler;
        }
    }

    [Fact]
    public async Task ZeroInterval_DisablesTheRefresh()
    {
        using FakeStunServer stun = new() { ReportMappedOverride = Mapping(43000) };
        await using PinholeNode node = await BindAsync(stun, TimeSpan.Zero);

        Assert.Contains(node.PublicEndpoints, ep => ep.Port == 43000);

        stun.ReportMappedOverride = Mapping(43100);

        await Task.Delay(800); // several refresh periods would have passed at test cadence
        Assert.DoesNotContain(node.PublicEndpoints, ep => ep.Port == 43100);
    }

    [Fact]
    public async Task SubHundredMillisecondInterval_IsRejected()
    {
        using FakeStunServer stun = new();
        await Assert.ThrowsAnyAsync<ArgumentOutOfRangeException>(() => PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [stun.LocalEndPoint],
            Relays = [],
            IrohRelayUrls = [],
            StunRefreshInterval = TimeSpan.FromMilliseconds(50),
        }));
    }
}
