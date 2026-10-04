using Xunit;

namespace Pinhole.Tests;

public sealed class ConsumerApiTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Options(bool listen = true) => new()
    {
        StunServers = [], Relays = [], IrohRelayUrls = [],
        Listen = listen, EnableNetworkWatch = false, EnablePortMapping = false,
        ConnectTimeout = TimeSpan.FromMilliseconds(300),
    };

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task Connect_NormalizesPastedCodes_AndDeliversDatagrams(bool omitPrefix, bool useResult)
    {
        await using var listener = await PinholeNode.BindAsync(Options() with { ConnectTimeout = Timeout });
        await using var dialer = await PinholeNode.BindAsync(Options() with { ConnectTimeout = Timeout });
        string code = listener.ConnectionString;
        if (omitPrefix) code = code[(ConnectionString.Scheme.Length + 1)..];
        code = " \r\n\t" + code + "\r\n ";
        Task<PinholeConnection> accept = listener.AcceptAsync();

        PinholeConnection connected;
        if (useResult)
        {
            PinholeConnectResult result = await dialer.TryConnectAsync(code).WaitAsync(Timeout);
            Assert.True(result.IsSuccess);
            Assert.Equal(PinholeConnectFailure.None, result.Failure);
            Assert.Null(result.ErrorMessage);
            connected = result.Connection;
        }
        else connected = await dialer.ConnectAsync(code).WaitAsync(Timeout);

        await using var peer = connected;
        await using var atListener = await accept.WaitAsync(Timeout);
        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        atListener.Received += data => received.TrySetResult(data.ToArray());
        peer.Send("normalized code"u8);
        Assert.Equal("normalized code"u8.ToArray(), await received.Task.WaitAsync(Timeout));
        Assert.False(dialer.HasRelay);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" \r\n\t ")]
    [InlineData("invalid")]
    [InlineData("iroh1:AAAA")]
    public async Task InvalidCode_ReturnsFailure_WithoutCreatingAConnection(string? code)
    {
        await using var node = await PinholeNode.BindAsync(Options());
        PinholeConnectResult result = await node.TryConnectAsync(code);
        Assert.False(result.IsSuccess);
        Assert.Null(result.Connection);
        Assert.Equal(PinholeConnectFailure.InvalidConnectionString, result.Failure);
        Assert.Contains("Invalid connection string", result.ErrorMessage);
        Assert.Empty(node.Connections);

        if (code is null) await Assert.ThrowsAsync<ArgumentNullException>(() => node.ConnectAsync(code!));
        else await Assert.ThrowsAsync<FormatException>(() => node.ConnectAsync(code));
    }

    [Fact]
    public async Task OwnCode_ReturnsSelfConnection_WithoutCreatingAConnection()
    {
        await using var node = await PinholeNode.BindAsync(Options());
        string ownCode = " " + node.ConnectionString[(ConnectionString.Scheme.Length + 1)..] + " ";
        PinholeConnectResult result = await node.TryConnectAsync(ownCode);
        Assert.Equal(PinholeConnectFailure.SelfConnection, result.Failure);
        Assert.Null(result.Connection);
        Assert.Contains("own connection string", result.ErrorMessage);
        Assert.Empty(node.Connections);
        await Assert.ThrowsAsync<ArgumentException>(() => node.ConnectAsync(ownCode));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Timeout_ExplainsWhetherThePeerAdvertisesARelay_AndCleansUp(bool useRelay)
    {
        await using var server = new FakeIrohRelay();
        PinholeOptions options = Options() with { IrohRelayUrls = useRelay ? [server.Url] : [] };
        await using var silent = await PinholeNode.BindAsync(options with { Listen = false });
        await using var dialer = await PinholeNode.BindAsync(options);
        Assert.Equal(useRelay, dialer.HasRelay);

        PinholeConnectResult result = await dialer.TryConnectAsync(silent.ConnectionString).WaitAsync(Timeout);
        Assert.False(result.IsSuccess);
        Assert.Null(result.Connection);
        Assert.Equal(useRelay ? PinholeConnectFailure.TimedOut : PinholeConnectFailure.NoRelayFallback, result.Failure);
        Assert.Contains(useRelay ? "peer may be offline" : "no relay fallback", result.ErrorMessage);
        Assert.Empty(dialer.Connections);
    }

    [Fact]
    public async Task Cancellation_StillThrows_AndCleansUpTheAttempt()
    {
        await using var silent = await PinholeNode.BindAsync(Options(listen: false));
        await using var node = await PinholeNode.BindAsync(Options() with { ConnectTimeout = Timeout });
        using var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => node.TryConnectAsync(silent.ConnectionString, stop.Token));
        Assert.Empty(node.Connections);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => node.TryConnectAsync("invalid", stop.Token));
        Assert.Empty(node.Connections);
    }

    [Fact]
    public async Task DisposedNode_IsNotReportedAsAnOrdinaryConnectionFailure()
    {
        await using var peer = await PinholeNode.BindAsync(Options());
        await using var node = await PinholeNode.BindAsync(Options());
        node.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => node.TryConnectAsync(peer.ConnectionString));
        Assert.False(node.HasRelay);
        Assert.Empty(node.Connections);
    }

    [Fact]
    public async Task HasRelay_RecognizesTurn_AndBecomesFalseOnDisposal()
    {
        using var server = new FakeTurnServer();
        await using var node = await PinholeNode.BindAsync(Options() with
        {
            Relays = [new TurnServerConfig(server.Control, "user", "pass")],
        });
        Assert.True(node.HasRelay);
        node.Dispose();
        Assert.False(node.HasRelay);
    }
}
