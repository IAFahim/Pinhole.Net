using System.Diagnostics.Metrics;

namespace Pinhole;

/// <summary>All engine and blob-layer instrumentation, on one
/// <see cref="System.Diagnostics.Metrics"/> meter named <c>Pinhole.Net</c>. Counters and
/// histograms are the .NET-native OpenTelemetry surface: attach a <c>MeterListener</c>, an
/// OTel <c>AddMeter("Pinhole.Net")</c>, or <c>dotnet-counters</c> to observe connection
/// attempts and their outcomes, recovery maneuvers, failure causes, and rejected frames in
/// real time. Every instrument is disabled-by-default and cheap; nothing is buffered
/// in-process, so telemetry can never bound or unbound the engine's own memory.</summary>
internal static class Telemetry
{
    public const string MeterName = "Pinhole.Net";

    private static readonly Meter Meter = new(MeterName, typeof(Telemetry).Assembly.GetName().Version?.ToString() ?? "1.0.0");

    private static readonly Counter<long> Attempts = Meter.CreateCounter<long>("pinhole.connection.attempts");
    private static readonly Counter<long> Failures = Meter.CreateCounter<long>("pinhole.connection.failures");
    private static readonly Histogram<double> EstablishDurationHistogram =
        Meter.CreateHistogram<double>("pinhole.connection.establish_duration", unit: "ms");
    private static readonly Counter<long> RecoveryEvents = Meter.CreateCounter<long>("pinhole.recovery.events");
    private static readonly Counter<long> FramesRejected = Meter.CreateCounter<long>("pinhole.frames.rejected");

    /// <summary>Outcome names on <c>pinhole.connection.attempts</c>, dimension <c>outcome</c>.</summary>
    public const string OutcomeDialEstablished = "dial-established";
    public const string OutcomeDialTimeout = "dial-timeout";
    public const string OutcomeDialCancelled = "dial-cancelled";
    public const string OutcomeDialFaulted = "dial-faulted";
    public const string OutcomeAcceptEstablished = "accept-established";

    /// <summary>A dial or accept finished — the terminal outcome of one connection attempt.</summary>
    public static void AttemptOutcome(string outcome, string? path = null)
    {
        if (Attempts.Enabled)
        {
            Attempts.Add(1, new KeyValuePair<string, object?>("outcome", outcome),
                new KeyValuePair<string, object?>("path", path ?? "unknown"));
        }
    }

    /// <summary>Milliseconds from dial/accept to a connected session, dimensioned by the
    /// path that carried it.</summary>
    public static void EstablishDuration(double milliseconds, string path)
    {
        if (EstablishDurationHistogram.Enabled)
        {
            EstablishDurationHistogram.Record(milliseconds, new KeyValuePair<string, object?>("path", path));
        }
    }

    /// <summary>The engine refused an establishing connection — the cause strings are the
    /// engine's fixed handshake-failure sentences (pinning mismatch, refused encryption,
    /// failed confirmation), so <c>pinhole.connection.failures</c> is the failure-cause
    /// breakdown #25 asks for.</summary>
    public static void ConnectionRefused(string cause)
    {
        if (Failures.Enabled)
        {
            Failures.Add(1, new KeyValuePair<string, object?>("cause", cause));
        }
    }

    /// <summary>One recovery maneuver started or landed: path-suspect, rebind,
    /// relay-retire, relay-reallocate, relay-heal.</summary>
    public static void Recovery(string kind)
    {
        if (RecoveryEvents.Enabled)
        {
            RecoveryEvents.Add(1, new KeyValuePair<string, object?>("kind", kind));
        }
    }

    /// <summary>A frame was dropped as replayed, tampered, or otherwise unverified —
    /// the per-layer tamper/replay rate.</summary>
    public static void FrameRejected(string layer, string cause)
    {
        if (FramesRejected.Enabled)
        {
            FramesRejected.Add(1, new KeyValuePair<string, object?>("layer", layer),
                new KeyValuePair<string, object?>("cause", cause));
        }
    }
}
