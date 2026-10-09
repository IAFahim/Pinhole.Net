using System.Net;

namespace Pinhole;

/// <summary>Keep introductions, router grants and source diversity when a bounded
/// interface pool would otherwise fill the ticket with STUN mappings.</summary>
internal static class CandidateSelection
{
    internal static PinholeCandidate[] Published(IReadOnlyList<PinholeCandidate> candidates,
        IPEndPoint? mapped, IPEndPoint? tcpMapped, IReadOnlyList<PinholeInterfaceCandidates> sources)
    {
        if (candidates.Count <= ConnectionString.MaxCandidates) return candidates.ToArray();
        var chosen = new HashSet<PinholeCandidate>();
        void Keep(PinholeCandidate? candidate)
        {
            if (candidate is not null && chosen.Count < ConnectionString.MaxCandidates) chosen.Add(candidate);
        }
        void Endpoint(CandidateKind kind, IPEndPoint? endpoint)
        {
            if (endpoint is not null) Keep(candidates.FirstOrDefault(c => c.Kind == kind && c.Address.Equals(endpoint)));
        }
        Endpoint(CandidateKind.Reflexive, mapped); Endpoint(CandidateKind.Reflexive, tcpMapped);
        PinholeCandidate[] turn = candidates.Where(c => c.Kind == CandidateKind.Relay).ToArray();
        PinholeCandidate[] iroh = candidates.Where(c => c.Kind == CandidateKind.IrohRelay).ToArray();
        // Keep both provider types even when one has many configured allocations.
        Keep(turn.FirstOrDefault()); Keep(iroh.FirstOrDefault());
        foreach (PinholeCandidate candidate in iroh.Skip(1).Concat(turn.Skip(1)).Take(Math.Max(0, 8 - chosen.Count(c => c.Kind is CandidateKind.Relay or CandidateKind.IrohRelay))))
            Keep(candidate);
        foreach (PinholeCandidate candidate in candidates.Where(c => c.Kind == CandidateKind.Direct && !IPAddress.IsLoopback(c.Address.Address)
            && !c.Address.Address.IsIPv6LinkLocal).DistinctBy(c => c.Address.AddressFamily)) Keep(candidate);
        foreach (PinholeCandidate candidate in candidates.Where(c => c.Kind == CandidateKind.Direct && c.Address.Address.IsIPv6LinkLocal).Take(2)) Keep(candidate);
        foreach (PinholeInterfaceCandidates source in sources.Take(InterfaceUdpTransport.MaxSources))
        {
            Endpoint(CandidateKind.Direct, source.LocalEndpoint);
            Endpoint(CandidateKind.Reflexive, source.ReflexiveEndpoints.FirstOrDefault());
        }
        foreach (PinholeCandidate candidate in candidates.Where(c => c.Kind == CandidateKind.Reflexive).DistinctBy(c => c.Address.AddressFamily)) Keep(candidate);
        foreach (PinholeCandidate candidate in candidates) Keep(candidate);
        // Preserve probe ordering; priority only determines membership of the bound.
        return candidates.Where(chosen.Contains).Distinct().Take(ConnectionString.MaxCandidates).ToArray();
    }
}
