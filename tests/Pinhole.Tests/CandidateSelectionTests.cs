using System.Net;
using Xunit;

namespace Pinhole.Tests;

public sealed class CandidateSelectionTests
{
    private static IPEndPoint Endpoint(string address, int port) => new(IPAddress.Parse(address), port);

    [Fact]
    public void OversizedSourceMappings_CannotEvictIntroductionsRouterGrantsOrBothFamilies()
    {
        var mapped = Endpoint("203.0.113.200", 42000); var tcp = Endpoint("203.0.113.200", 42001);
        PinholeInterfaceCandidates[] sources = Enumerable.Range(1, 4).Select(i => new PinholeInterfaceCandidates(
            Endpoint($"172.31.{i}.2", 40002), Enumerable.Range(0, 8).Select(p => Endpoint($"203.0.113.{i}", 49000 + p)).ToArray())).ToArray();
        List<PinholeCandidate> input = [new(CandidateKind.Direct, Endpoint("127.0.0.1", 40000)),
            new(CandidateKind.Direct, Endpoint("192.0.2.20", 40000)), new(CandidateKind.Direct, Endpoint("2001:db8::20", 40000))];
        foreach (var source in sources)
        {
            input.Add(new(CandidateKind.Direct, source.LocalEndpoint));
            input.AddRange(source.ReflexiveEndpoints.Select(e => new PinholeCandidate(CandidateKind.Reflexive, e)));
        }
        input.Add(new(CandidateKind.Reflexive, mapped)); input.Add(new(CandidateKind.Reflexive, tcp));
        input.Add(new(CandidateKind.Direct, Endpoint("fe80::20", 40000)));
        for (int i = 0; i < 10; i++) input.Add(new(CandidateKind.Relay, Endpoint($"198.51.100.{i + 1}", 50000), Endpoint($"198.51.100.{i + 1}", 3478), "user", "password"));
        var iroh = new PinholeCandidate(CandidateKind.IrohRelay, new(IPAddress.None, 0), RelayUrl: new("https://relay.example.test/"), RelayKey: new byte[32]);
        input.Add(iroh);
        var selected = CandidateSelection.Published(input, mapped, tcp, sources);
        Assert.Equal(32, selected.Length);
        Assert.Contains(iroh, selected); Assert.Contains(selected, c => c.Kind == CandidateKind.Relay);
        Assert.Contains(selected, c => c.Kind == CandidateKind.Reflexive && c.Address.Equals(mapped));
        Assert.Contains(selected, c => c.Kind == CandidateKind.Reflexive && c.Address.Equals(tcp));
        Assert.Contains(selected, c => c.Address.Address.Equals(IPAddress.Parse("2001:db8::20")));
        Assert.Contains(selected, c => c.Address.Address.IsIPv6LinkLocal);
        foreach (var source in sources)
        {
            Assert.Contains(selected, c => c.Address.Equals(source.LocalEndpoint));
            Assert.Contains(selected, c => c.Address.Equals(source.ReflexiveEndpoints[0]));
        }
        string ticket = new ConnectionString(42, selected).ToString();
        Assert.Equal(32, ConnectionString.Parse(ticket).Candidates.Count);
    }

    [Fact]
    public void OrdinaryLists_PreserveTheirOriginalMembershipAndOrder()
    {
        PinholeCandidate[] candidates = [new(CandidateKind.Direct, Endpoint("127.0.0.1", 40000)), new(CandidateKind.Reflexive, Endpoint("203.0.113.1", 49000))];
        Assert.Equal(candidates, CandidateSelection.Published(candidates, null, null, []));
    }
}
