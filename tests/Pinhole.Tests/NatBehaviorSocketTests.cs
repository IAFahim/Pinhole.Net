using Xunit;

namespace Pinhole.Tests;

public sealed class NatBehaviorSocketTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PublicDiagnostic_UsesARealFreshSocketAndReportsMissingAlternateCapability(bool ipv6)
    {
        using var server = new FakeStunServer(ipv6);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        NatBehaviorReport report = await NatDetector.InspectAsync(server.LocalEndPoint, deadline.Token);
        Assert.InRange(report.LocalEndpoint.Port, 1, ushort.MaxValue);
        Assert.Equal(report.LocalEndpoint.Port, Assert.Single(report.MappingObservations).Port);
        Assert.False(report.SupportsAlternates);
        Assert.Equal(NatMappingBehavior.Unknown, report.Mapping);
        Assert.Equal(NatFilteringBehavior.Unknown, report.Filtering);
        Assert.Equal(1, report.ProbesSent);
    }
}
