using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Pinhole;
using Xunit;

namespace Pinhole.Tests;

/// <summary>#25: connection attempts, recovery, and failure causes are measured through
/// .NET's own diagnostics stack (System.Diagnostics.Metrics, meter "Pinhole.Net") — the
/// same surface OpenTelemetry, dotnet-counters, and MeterListener see. These tests attach
/// a listener and assert the instruments a real consumer would observe. Counters are
/// process-global, so every assertion is a before/after delta: parallel tests may add
/// their own measurements, but they can never mask ours.</summary>
public sealed class TelemetryTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Opts(TimeSpan? connectTimeout = null) => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [],
        ConnectTimeout = connectTimeout ?? TimeSpan.FromSeconds(8),
        BindProbeBudget = TimeSpan.FromSeconds(5),
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false,
        EnablePortMapping = false,
    };

    /// <summary>Collects every measurement from the Pinhole.Net meter published while it
    /// is alive. Counters accumulate; histograms keep their raw recordings.</summary>
    private sealed class MeterSnapshot : IDisposable
    {
        private readonly MeterListener _listener;
        private readonly ConcurrentBag<(string Instrument, string? FirstTag, long LongValue, double DoubleValue)> _rows = new();

        public MeterSnapshot()
        {
            _listener = new MeterListener
            {
                InstrumentPublished = (instrument, listener) =>
                {
                    if (instrument.Meter.Name == Telemetry.MeterName)
                    {
                        listener.EnableMeasurementEvents(instrument);
                    }
                },
            };
            _listener.SetMeasurementEventCallback<long>((inst, value, tags, _) =>
                _rows.Add((inst.Name, FirstTag(tags), value, 0)));
            _listener.SetMeasurementEventCallback<double>((inst, value, tags, _) =>
                _rows.Add((inst.Name, FirstTag(tags), 0, value)));
            _listener.Start();
        }

        private static string? FirstTag(ReadOnlySpan<KeyValuePair<string, object?>> tags) =>
            tags.IsEmpty ? null : tags[0].Value?.ToString();

        public int Count(string instrument, string? firstTag = null) => _rows.Count(r =>
            r.Instrument == instrument && (firstTag is null || r.FirstTag == firstTag));

        public int Recordings(string instrument) => _rows.Count(r => r.Instrument == instrument);

        public void Dispose() => _listener.Dispose();
    }

    [Fact]
    public async Task Dial_AttemptOutcomeAndEstablishDurationAreMeasured()
    {
        using var meter = new MeterSnapshot();
        int dialBefore = meter.Count("pinhole.connection.attempts", Telemetry.OutcomeDialEstablished);
        int acceptBefore = meter.Count("pinhole.connection.attempts", Telemetry.OutcomeAcceptEstablished);
        int durationsBefore = meter.Recordings("pinhole.connection.establish_duration");

        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());

        _ = a.AcceptAsync();
        await using PinholeConnection conn = await b.ConnectAsync(a.ConnectionString).WaitAsync(Timeout);

        Assert.True(meter.Count("pinhole.connection.attempts", Telemetry.OutcomeDialEstablished) > dialBefore,
            "the dial's established outcome was measured");
        Assert.True(meter.Count("pinhole.connection.attempts", Telemetry.OutcomeAcceptEstablished) > acceptBefore,
            " the accept's established outcome was measured");
        Assert.True(meter.Recordings("pinhole.connection.establish_duration") > durationsBefore,
            "establish duration recorded");
    }

    [Fact]
    public async Task DialTimeout_AttemptOutcomeIsMeasured()
    {
        using var meter = new MeterSnapshot();
        await using PinholeNode b = await PinholeNode.BindAsync(Opts(connectTimeout: TimeSpan.FromMilliseconds(700)));

        // A string pointing at a socket that never answers: the attempt lands as a timeout.
        using var silent = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        silent.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var cs = new ConnectionString(0xfeedfacefeedface,
            [new PinholeCandidate(CandidateKind.Direct, (IPEndPoint)silent.LocalEndPoint!)],
            NatHint.Unknown,
            staticKey: new NodeIdentity().PublicKey);

        int timeoutsBefore = meter.Count("pinhole.connection.attempts", Telemetry.OutcomeDialTimeout);
        await Assert.ThrowsAsync<TimeoutException>(() => b.ConnectAsync(cs.ToString()));
        Assert.True(meter.Count("pinhole.connection.attempts", Telemetry.OutcomeDialTimeout) > timeoutsBefore,
            "the timed-out dial was measured");
    }

    [Fact]
    public async Task HandshakeFailure_TheCauseIsMeasured()
    {
        using var meter = new MeterSnapshot();
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());

        // The pinning mismatch from CryptoTests.Mitm_StaticKeySubstitution_KillsTheDial:
        // the honest peer's PACK fails the substituted static key, and the refusal must
        // land on pinhole.connection.failures dimensioned by its fixed sentence.
        await using PinholeNode honest = await PinholeNode.BindAsync(Opts());
        ConnectionString honestString = Pinhole.ConnectionString.Parse(honest.ConnectionString);
        var tampered = new ConnectionString(
            honestString.PeerId, honestString.Candidates, honestString.NatHint,
            staticKey: new NodeIdentity().PublicKey);

        int refusalsBefore = meter.Count("pinhole.connection.failures");
        int faultedBefore = meter.Count("pinhole.connection.attempts", Telemetry.OutcomeDialFaulted);
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => a.ConnectAsync(tampered.ToString()));
        Assert.True(ex is InvalidOperationException or TimeoutException, $"unexpected {ex}");
        Assert.True(meter.Count("pinhole.connection.failures") > refusalsBefore,
            "the handshake refusal is counted with its cause");
        if (ex is InvalidOperationException)
        {
            Assert.True(meter.Count("pinhole.connection.attempts", Telemetry.OutcomeDialFaulted) > faultedBefore,
                "a refused dial is not a silent timeout");
        }
    }

    [Fact]
    public void RejectedFrames_SessionLayerCounterMoves()
    {
        using var meter = new MeterSnapshot();

        // The connection-level counter is what #25 measures: ConnectionCrypto.CountRejected
        // mirrors every engine-side rejection into the meter. Parallel tests may reject
        // frames of their own — ours must be additive on top.
        int rejectedBefore = meter.Count("pinhole.frames.rejected");
        var crypto = ConnectionCrypto.New(new NodeIdentity(), 1, 2);
        crypto.CountRejected();
        crypto.CountRejected();
        Assert.True(meter.Count("pinhole.frames.rejected") >= rejectedBefore + 2,
            "each rejected frame is measured on the session layer");
    }
}
