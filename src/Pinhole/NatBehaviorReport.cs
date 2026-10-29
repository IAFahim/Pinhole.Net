using System.Net;
using System.Net.Sockets;

namespace Pinhole;

public enum NatMappingBehavior
{
    Unknown,
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

public enum NatFilteringBehavior
{
    Unknown,
    EndpointIndependent,
    AddressDependent,
}

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

    public IPEndPoint LocalEndpoint { get; }
    public NatMappingBehavior Mapping { get; }
    public NatFilteringBehavior Filtering { get; }
    public IReadOnlyList<IPEndPoint> MappingObservations { get; }
    public bool SupportsAlternates { get; }
    public bool AlternateRepliesMissing { get; }
    public int ProbesSent { get; }
    public TimeSpan Elapsed { get; }
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
