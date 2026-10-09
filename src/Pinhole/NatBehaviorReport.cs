using System.Net;
using System.Net.Sockets;

namespace Pinhole;

/// <summary>Mapping behavior observed with one socket and cooperating alternate STUN endpoints.</summary>
public enum NatMappingBehavior
{
    /// <summary>The required observations are unavailable.</summary>
    Unknown,
    /// <summary>The primary and alternate addresses observed the same mapped endpoint.</summary>
    EndpointIndependent,
    /// <summary>The alternate address changed the mapping, but changing its port did not.</summary>
    AddressDependent,
    /// <summary>Changing the alternate address's port changed the mapping again.</summary>
    AddressAndPortDependent,
}

/// <summary>Positive filtering evidence on a fresh diagnostic socket. Silence is unknown.</summary>
public enum NatFilteringBehavior
{
    /// <summary>No alternate response establishes filtering behavior; loss and unsupported servers remain possible.</summary>
    Unknown,
    /// <summary>A response arrived from an address and port the socket had not contacted.</summary>
    EndpointIndependent,
    /// <summary>After unanswered different-address tests, a response arrived from another port of the contacted address.</summary>
    AddressDependent,
}

/// <summary>A bounded RFC 5780 diagnostic pass, for the reported socket and instant only.
/// It is not the application socket and does not predict another peer's reachability.</summary>
public sealed class NatBehaviorReport
{
    internal NatBehaviorReport(IPEndPoint local, NatMappingBehavior mapping, NatFilteringBehavior filtering,
        IReadOnlyList<IPEndPoint> observations, bool supportsAlternates, bool alternateRepliesMissing, int probes, TimeSpan elapsed)
    {
        LocalEndpoint = new(local.Address, local.Port);
        Mapping = mapping; Filtering = filtering;
        MappingObservations = Array.AsReadOnly(observations.Select(e => new IPEndPoint(e.Address, e.Port)).ToArray());
        SupportsAlternates = supportsAlternates; AlternateRepliesMissing = alternateRepliesMissing;
        ProbesSent = probes; Elapsed = elapsed; MeasuredAtUtc = DateTimeOffset.UtcNow;
    }

    /// <summary>The actual local diagnostic socket endpoint; wildcard addresses mean OS-selected routing.</summary>
    public IPEndPoint LocalEndpoint { get; }
    /// <summary>Observed destination dependence of mappings.</summary>
    public NatMappingBehavior Mapping { get; }
    /// <summary>Positive alternate-source response evidence; unknown does not mean blocked.</summary>
    public NatFilteringBehavior Filtering { get; }
    /// <summary>Primary, alternate-address/same-port, and (when needed) alternate-address/alternate-port mappings, in order.</summary>
    public IReadOnlyList<IPEndPoint> MappingObservations { get; }
    /// <summary>The primary reply advertised a consistent response origin and distinct alternate address/port.</summary>
    public bool SupportsAlternates { get; }
    /// <summary>Both alternate filtering tests remained unanswered after bounded retries. This is not proof of filtering.</summary>
    public bool AlternateRepliesMissing { get; }
    /// <summary>Total binding requests, including filtering retries.</summary>
    public int ProbesSent { get; }
    /// <summary>Total measurement time.</summary>
    public TimeSpan Elapsed { get; }
    /// <summary>UTC completion time; behavior can change immediately afterward.</summary>
    public DateTimeOffset MeasuredAtUtc { get; }
}

internal static class NatBehaviorMeasurement
{
    internal static async Task<NatBehaviorReport> InspectAsync(IPEndPoint local, IPEndPoint server,
        Func<IPEndPoint, IPEndPoint, uint, CancellationToken, Task<StunBindingReply>> probe, CancellationToken ct)
    {
        long started = Environment.TickCount64;
        int probes = 0;
        List<IPEndPoint> observations = [];
        NatMappingBehavior mapping = NatMappingBehavior.Unknown;
        NatFilteringBehavior filtering = NatFilteringBehavior.Unknown;
        bool supported = false, missing = false;
        async Task<StunBindingReply?> Try(IPEndPoint destination, IPEndPoint expected, uint change)
        {
            ct.ThrowIfCancellationRequested();
            probes++;
            try { return await probe(destination, expected, change, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is TimeoutException or SocketException) { return null; }
        }
        NatBehaviorReport Report() => new(local, mapping, filtering, observations, supported, missing, probes,
            TimeSpan.FromMilliseconds(Environment.TickCount64 - started));

        StunBindingReply? primary = await Try(server, server, 0).ConfigureAwait(false);
        if (primary is null) return Report();
        observations.Add(primary.Mapped);
        if (primary.Origin?.Equals(server) != true || primary.Other is not { } other
            || !StunBindingMessage.Usable(other) || other.AddressFamily != server.AddressFamily
            || other.Address.Equals(server.Address) || other.Port == server.Port) return Report();
        supported = true;

        // Filtering MUST precede contact with any alternate destination, or those
        // contacts would open the very filter being measured (RFC 5780 section 4.5).
        for (int attempt = 0; attempt < 2; attempt++)
        {
            if (await Try(server, other, 6).ConfigureAwait(false) is { Origin: { } origin } && origin.Equals(other))
            { filtering = NatFilteringBehavior.EndpointIndependent; break; }
        }
        if (filtering == NatFilteringBehavior.Unknown)
        {
            var differentPort = new IPEndPoint(server.Address, other.Port);
            for (int attempt = 0; attempt < 2; attempt++)
            {
                if (await Try(server, differentPort, 2).ConfigureAwait(false) is { Origin: { } origin } && origin.Equals(differentPort))
                { filtering = NatFilteringBehavior.AddressDependent; break; }
            }
            missing = filtering == NatFilteringBehavior.Unknown;
        }

        StunBindingReply? second = await Try(new(other.Address, server.Port), new(other.Address, server.Port), 0).ConfigureAwait(false);
        if (second is null) return Report();
        observations.Add(second.Mapped);
        if (primary.Mapped.Equals(second.Mapped)) mapping = NatMappingBehavior.EndpointIndependent;
        else
        {
            StunBindingReply? third = await Try(other, other, 0).ConfigureAwait(false);
            if (third is null) return Report();
            observations.Add(third.Mapped);
            mapping = second.Mapped.Equals(third.Mapped) ? NatMappingBehavior.AddressDependent : NatMappingBehavior.AddressAndPortDependent;
        }
        return Report();
    }
}
