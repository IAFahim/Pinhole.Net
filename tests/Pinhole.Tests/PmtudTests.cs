using System.Net;
using Pinhole;
using Xunit;

namespace Pinhole.Tests;

public sealed class PmtudTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Opts() => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [], DerpRelayUrls = [],
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false,
        EnablePortMapping = false,
        EnablePathValidation = false,
        PathValidationProbeInterval = TimeSpan.FromMilliseconds(100),
        ConnectTimeout = TimeSpan.FromSeconds(8),
    };

    private static string LoopbackString(PinholeNode listener) => new ConnectionString(
        listener.PeerId,
        [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, listener.LocalPort))],
        staticKey: listener.StaticPublicKey).ToString();

    [Theory]
    [InlineData(false, PinholeEncryption.Required)]
    [InlineData(true, PinholeEncryption.Required)]
    [InlineData(false, PinholeEncryption.Disabled)]
    [InlineData(true, PinholeEncryption.Disabled)]
    public async Task SmallInboundPing_NeverShrinksTheGuaranteedPayloadFloor(bool pmtud, PinholeEncryption encryption)
    {
        var options = Opts() with { EnablePmtud = pmtud, Encryption = encryption, ReceiveBufferCapacity = 8 };
        await using var a = await PinholeNode.BindAsync(options);
        await using var b = await PinholeNode.BindAsync(options);
        Task<PinholeConnection> accept = a.AcceptAsync();
        using var atB = await b.ConnectAsync(LoopbackString(a)).WaitAsync(Timeout);
        using var atA = await accept.WaitAsync(Timeout);
        atB.Ping();
        await TestPoll.UntilAsync(Timeout, () => atB.Stats.PongsReceived > 0);
        Assert.True(atA.PathMtu >= NodeEngine.PmtuBaseWire);
        byte[] payload = new byte[PinholeConnection.MaxPayload];
        atA.Send(payload);
        Assert.Equal(payload, (await atB.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value.ToArray());
    }

    [Fact]
    public async Task Probes_ClimbToTheCeiling_AndRaiseThePayloadLimit()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        _ = a.AcceptAsync();
        PinholeConnection atB = await b.ConnectAsync(LoopbackString(a)).WaitAsync(Timeout);
        PinholeConnection atA = a.Connections.Single(c => c.PeerId == b.PeerId);

        Assert.InRange(atB.PathMtu, NodeEngine.PmtuBaseWire, 1472);

        await TestPoll.UntilAsync(Timeout, () => atB.PathMtu >= 1472 && atA.PathMtu >= 1472);
        Assert.True(b.Engine.Lookup(a.PeerId)!.PmtuProbesSent > 0, "the climb was actively probed");

        var got = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        atA.Received += p => got.TrySetResult(p.Length);
        atB.Send(new byte[1472 - NodeEngine.PmtuOverhead]);
        Assert.Equal(1435, await got.Task.WaitAsync(Timeout));
        Assert.Throws<ArgumentOutOfRangeException>(() => atB.Send(new byte[1472 - NodeEngine.PmtuOverhead + 1]));
    }

    [Fact]
    public async Task OversizeBlackhole_KeepsTheFloor_SmallTrafficUnaffected()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        _ = a.AcceptAsync();
        PinholeConnection atB = await b.ConnectAsync(LoopbackString(a)).WaitAsync(Timeout);
        PinholeConnection atA = a.Connections.Single(c => c.PeerId == b.PeerId);

        a.Engine.Lookup(b.PeerId)!.DropAboveBytes = 1300;
        b.Engine.Lookup(a.PeerId)!.DropAboveBytes = 1300;

        await TestPoll.UntilAsync(Timeout, () =>
            a.Engine.Lookup(b.PeerId)!.PmtuProbesSent >= 3 && b.Engine.Lookup(a.PeerId)!.PmtuProbesSent >= 3);
        await Task.Delay(700);

        Assert.Equal(NodeEngine.PmtuBaseWire, atB.PathMtu);
        Assert.Equal(NodeEngine.PmtuBaseWire, atA.PathMtu);

        Assert.Throws<ArgumentOutOfRangeException>(() => atB.Send(new byte[1250]));
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atA.Received += p => got.TrySetResult(p.ToArray());
        atB.Send(new byte[1200]);
        Assert.Equal(1200, (await got.Task.WaitAsync(Timeout)).Length);
    }
}
