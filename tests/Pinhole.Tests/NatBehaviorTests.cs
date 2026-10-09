using System.Buffers.Binary;
using System.Net;
using Xunit;

namespace Pinhole.Tests;

public sealed class NatBehaviorTests
{
    private static readonly IPEndPoint Local = new(IPAddress.Parse("172.30.0.2"), 40002);
    private static readonly IPEndPoint Primary = new(IPAddress.Parse("192.0.2.90"), 3478);
    private static readonly IPEndPoint Other = new(IPAddress.Parse("192.0.2.91"), 3479);
    private static IPEndPoint Mapping(int port) => new(IPAddress.Parse("203.0.113.20"), port);

    private static async Task<StunBindingReply> Probe(NodeEngine engine, IPEndPoint destination, IPEndPoint expected, uint change, CancellationToken ct)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromMilliseconds(300));
        try { return await engine.ProbeBindingAsync(destination, expected, change, budget.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new TimeoutException(); }
    }

    private static PinholeOptions Fresh(PinholeOptions options) => options with
    {
        StunServers = [], EnableTcpTransport = false, EnableInterfaceCandidates = false,
        EnablePathValidation = false, EnablePmtud = false, StunRefreshInterval = TimeSpan.Zero, Listen = false,
    };

    [Theory]
    [InlineData(VirtualNatKind.FullCone, NatMappingBehavior.EndpointIndependent, NatFilteringBehavior.EndpointIndependent)]
    [InlineData(VirtualNatKind.RestrictedCone, NatMappingBehavior.EndpointIndependent, NatFilteringBehavior.AddressDependent)]
    [InlineData(VirtualNatKind.PortRestricted, NatMappingBehavior.EndpointIndependent, NatFilteringBehavior.Unknown)]
    [InlineData(VirtualNatKind.Symmetric, NatMappingBehavior.AddressAndPortDependent, NatFilteringBehavior.Unknown)]
    public async Task AlternateResponses_ExerciseTheActualInboundFilter(VirtualNatKind kind, NatMappingBehavior mapping, NatFilteringBehavior filtering)
    {
        using var lab = new VirtualLab(); using var server = new VirtualBehaviorStunServer(lab.Net);
        using var nat = lab.Nat(kind, "203.0.113.20", "172.30.0.0/24");
        await using var node = await lab.BindNodeAsync(nat, tweak: Fresh);
        NatBehaviorReport report = await NatBehaviorMeasurement.InspectAsync(node.Engine.DiagnosticLocalEndpoint, server.Primary,
            (d, e, f, ct) => Probe(node.Engine, d, e, f, ct), CancellationToken.None);
        Assert.True(report.SupportsAlternates); Assert.Equal(mapping, report.Mapping); Assert.Equal(filtering, report.Filtering);
        Assert.InRange(report.ProbesSent, 3, 7);
        Assert.Equal(filtering == NatFilteringBehavior.Unknown, report.AlternateRepliesMissing);
        Assert.Equal(node.LocalPort, report.LocalEndpoint.Port);
        var requests = server.Requests.ToArray();
        int alternateContact = Array.FindIndex(requests, r => !r.Destination.Address.Equals(server.Primary.Address));
        Assert.True(alternateContact > 0);
        Assert.All(requests.Skip(alternateContact), r => Assert.Equal(0u, r.Change));
        Assert.NotEqual(DateTimeOffset.MinValue, report.MeasuredAtUtc);
    }

    [Fact]
    public async Task Ipv6Behavior_UsesTheSameFullTransactionAndAlternateSourceChecks()
    {
        using var lab = new VirtualLab(); using var server = new VirtualBehaviorStunServer(lab.Net, ipv6: true);
        await using var node = await lab.BindNodeAsync(hostAddress: new(IPAddress.Parse("2001:db8::20"), 40002), tweak: Fresh);
        NatBehaviorReport report = await NatBehaviorMeasurement.InspectAsync(node.Engine.DiagnosticLocalEndpoint, server.Primary,
            (d, e, f, ct) => Probe(node.Engine, d, e, f, ct), CancellationToken.None);
        Assert.Equal(NatMappingBehavior.EndpointIndependent, report.Mapping);
        Assert.Equal(NatFilteringBehavior.EndpointIndependent, report.Filtering);
        Assert.Equal(3, report.ProbesSent);
        Assert.Equal(IPAddress.Parse("2001:db8::20"), report.MappingObservations[0].Address);
    }

    [Fact]
    public async Task MissingAlternateCapability_DoesNotInventMappingOrFilteringKnowledge()
    {
        using var lab = new VirtualLab(); using var server = new VirtualBehaviorStunServer(lab.Net) { IncludeAlternates = false };
        await using var node = await lab.BindNodeAsync(hostAddress: new(IPAddress.Parse("192.0.2.20"), 40002), tweak: Fresh);
        NatBehaviorReport report = await NatBehaviorMeasurement.InspectAsync(node.Engine.DiagnosticLocalEndpoint, server.Primary,
            (d, e, f, ct) => Probe(node.Engine, d, e, f, ct), CancellationToken.None);
        Assert.False(report.SupportsAlternates); Assert.Equal(1, report.ProbesSent);
        Assert.Equal(NatMappingBehavior.Unknown, report.Mapping); Assert.Equal(NatFilteringBehavior.Unknown, report.Filtering);
        Assert.False(report.AlternateRepliesMissing);
    }

    [Fact]
    public async Task ServerIgnoringChangeRequests_ProducesUnknownFilteringEvenWithoutANat()
    {
        using var lab = new VirtualLab(); using var server = new VirtualBehaviorStunServer(lab.Net) { IgnoreChange = true };
        await using var node = await lab.BindNodeAsync(hostAddress: new(IPAddress.Parse("192.0.2.20"), 40002), tweak: Fresh);
        NatBehaviorReport report = await NatBehaviorMeasurement.InspectAsync(node.Engine.DiagnosticLocalEndpoint, server.Primary,
            (d, e, f, ct) => Probe(node.Engine, d, e, f, ct), CancellationToken.None);
        Assert.True(report.SupportsAlternates); Assert.True(report.AlternateRepliesMissing);
        Assert.Equal(NatFilteringBehavior.Unknown, report.Filtering); Assert.Equal(NatMappingBehavior.EndpointIndependent, report.Mapping);
        Assert.Equal(6, report.ProbesSent);
    }

    [Fact]
    public async Task AddressDependentMapping_IsDistinctFromPortDependentMapping()
    {
        List<(IPEndPoint Destination, uint Change)> requests = [];
        Task<StunBindingReply> ProbeScript(IPEndPoint destination, IPEndPoint expected, uint change, CancellationToken ct)
        {
            requests.Add((destination, change));
            return Task.FromResult(new StunBindingReply(Mapping(destination.Address.Equals(Primary.Address) ? 41000 : 41001), expected, Other));
        }
        var report = await NatBehaviorMeasurement.InspectAsync(Local, Primary, ProbeScript, CancellationToken.None);
        Assert.Equal(NatMappingBehavior.AddressDependent, report.Mapping);
        Assert.Equal(new[] { 41000, 41001, 41001 }, report.MappingObservations.Select(o => o.Port));
        Assert.Equal(new uint[] { 0, 6, 0, 0 }, requests.Select(r => r.Change));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingResponseOrCancellation_PreservesAnHonestOutcome(bool cancel)
    {
        using var cts = new CancellationTokenSource();
        Task<StunBindingReply> ProbeScript(IPEndPoint d, IPEndPoint e, uint f, CancellationToken ct)
        {
            if (cancel) { cts.Cancel(); return Task.FromCanceled<StunBindingReply>(cts.Token); }
            return Task.FromException<StunBindingReply>(new TimeoutException());
        }
        if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NatBehaviorMeasurement.InspectAsync(Local, Primary, ProbeScript, cts.Token));
        else
        {
            var report = await NatBehaviorMeasurement.InspectAsync(Local, Primary, ProbeScript, cts.Token);
            Assert.Equal(NatMappingBehavior.Unknown, report.Mapping); Assert.Equal(NatFilteringBehavior.Unknown, report.Filtering);
            Assert.Empty(report.MappingObservations); Assert.Equal(1, report.ProbesSent);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MessageCodec_DecodesIndependentAlternateAttributesInBothFamilies(bool ipv6)
    {
        IPEndPoint server = ipv6 ? new(IPAddress.Parse("2001:db8::90"), 3478) : Primary;
        IPEndPoint other = ipv6 ? new(IPAddress.Parse("2001:db8::91"), 3479) : Other;
        IPEndPoint mapping = ipv6 ? new(IPAddress.Parse("2001:db8::20"), 41000) : Mapping(41000);
        byte[] transaction = Convert.FromHexString("A1A2A3A4A5A6A7A8A9AAABAC");
        byte[] wire = VirtualBehaviorStunServer.Response(transaction, mapping, server, other);
        Assert.True(StunBindingMessage.TryRead(wire, server, out StunBindingReply? reply));
        Assert.Equal(mapping, reply!.Mapped); Assert.Equal(server, reply.Origin); Assert.Equal(other, reply.Other);
        Assert.False(StunBindingMessage.TryRead(wire, other, out _));
    }

    [Theory]
    [InlineData(0)] // short known address
    [InlineData(1)] // truncated tail
    [InlineData(2)] // invalid reserved byte
    [InlineData(3)] // zero mapped port
    [InlineData(4)] // multicast mapped address
    [InlineData(5)] // message length mismatch
    public void MessageCodec_RejectsMalformedOrUnusableEvidence(int variant)
    {
        byte[] wire = VirtualBehaviorStunServer.Response(new byte[12], Mapping(41000), Primary, Other);
        switch (variant)
        {
            case 0: BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(22), 4); break;
            case 1: wire = wire[..^1]; break;
            case 2: wire[24] = 1; break;
            case 3: BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(26), 0x2112); break;
            case 4: wire[28] = 0xe0 ^ 0x21; break;
            case 5: wire[3] ^= 1; break;
        }
        Assert.False(StunBindingMessage.TryRead(wire, Primary, out _));
    }

    [Fact]
    public void ChangeRequest_ContainsOnlyTheRequestedRfcFlagsAndFreshTransactions()
    {
        byte[] request = StunBindingMessage.Request(6);
        Assert.Equal(28, request.Length); Assert.Equal(8, BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(2)));
        Assert.Equal(3, BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(20)));
        Assert.Equal(4, BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(22)));
        Assert.Equal(6u, BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(24)));
        Assert.NotEqual(request.AsSpan(8, 12).ToArray(), StunBindingMessage.Request(6).AsSpan(8, 12).ToArray());
        Assert.Throws<ArgumentOutOfRangeException>(() => StunBindingMessage.Request(4));
    }
}
