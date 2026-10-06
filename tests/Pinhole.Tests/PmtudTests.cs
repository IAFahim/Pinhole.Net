using System.Net;
using Pinhole;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Path MTU discovery (RFC 8899-style): padded token-checked pings climb from the
/// 1237-byte wire floor, a pong confirms a size, and an over-MTU black hole keeps the
/// floor while normal payloads keep flowing.</summary>
public sealed class PmtudTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Opts() => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [],
        EnableNetworkWatch = false,
        EnablePortMapping = false,
        EnablePathValidation = false, // PMTUD has its own probes; these tests measure only those
        PathValidationProbeInterval = TimeSpan.FromMilliseconds(100), // paces PMTUD attempts too
        ConnectTimeout = TimeSpan.FromSeconds(8),
    };

    /// <summary>A v4-loopback-only dial string (with the node's static key): the path, and
    /// therefore the probe ceiling, is deterministic.</summary>
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

        // Discovery runs concurrently with the dial continuation: a probe may already
        // have completed by the time ConnectAsync returns, but the floor is guaranteed.
        Assert.InRange(atB.PathMtu, NodeEngine.PmtuBaseWire, 1472);

        // Loopback carries everything: the ladder should reach the Ethernet IPv4 plateau.
        await TestPoll.UntilAsync(Timeout, () => atB.PathMtu >= 1472 && atA.PathMtu >= 1472);
        Assert.True(b.Engine.Lookup(a.PeerId)!.PmtuProbesSent > 0, "the climb was actively probed");

        // The confirmed ceiling lifts Send beyond the API floor — and one byte past it still refuses.
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

        // A network that silently drops anything above 1300 wire bytes: every ladder step
        // (1365+) vanishes in both directions, three attempts each, then the cooldown.
        a.Engine.Lookup(b.PeerId)!.DropAboveBytes = 1300;
        b.Engine.Lookup(a.PeerId)!.DropAboveBytes = 1300;

        // The attempts run and give up (three tries per size, ~100 ms apart, plus tick slop).
        await TestPoll.UntilAsync(Timeout, () =>
            a.Engine.Lookup(b.PeerId)!.PmtuProbesSent >= 3 && b.Engine.Lookup(a.PeerId)!.PmtuProbesSent >= 3);
        await Task.Delay(700); // let a would-be confirmation window pass — none can arrive

        Assert.Equal(NodeEngine.PmtuBaseWire, atB.PathMtu);
        Assert.Equal(NodeEngine.PmtuBaseWire, atA.PathMtu);

        // The unproven sizes stay refused; the guaranteed floor keeps flowing under the cap.
        Assert.Throws<ArgumentOutOfRangeException>(() => atB.Send(new byte[1250]));
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atA.Received += p => got.TrySetResult(p.ToArray());
        atB.Send(new byte[1200]);
        Assert.Equal(1200, (await got.Task.WaitAsync(Timeout)).Length);
    }
}
