using System.Diagnostics.Metrics;

namespace Pinhole;

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

    public const string OutcomeDialEstablished = "dial-established";
    public const string OutcomeDialTimeout = "dial-timeout";
    public const string OutcomeDialCancelled = "dial-cancelled";
    public const string OutcomeDialFaulted = "dial-faulted";
    public const string OutcomeAcceptEstablished = "accept-established";

    public static void AttemptOutcome(string outcome, string? path = null)
    {
        if (Attempts.Enabled)
        {
            Attempts.Add(1, new KeyValuePair<string, object?>("outcome", outcome),
                new KeyValuePair<string, object?>("path", path ?? "unknown"));
        }
    }

    public static void EstablishDuration(double milliseconds, string path)
    {
        if (EstablishDurationHistogram.Enabled)
        {
            EstablishDurationHistogram.Record(milliseconds, new KeyValuePair<string, object?>("path", path));
        }
    }

    public static void ConnectionRefused(string cause)
    {
        if (Failures.Enabled)
        {
            Failures.Add(1, new KeyValuePair<string, object?>("cause", cause));
        }
    }

    public static void Recovery(string kind)
    {
        if (RecoveryEvents.Enabled)
        {
            RecoveryEvents.Add(1, new KeyValuePair<string, object?>("kind", kind));
        }
    }

    public static void FrameRejected(string layer, string cause)
    {
        if (FramesRejected.Enabled)
        {
            FramesRejected.Add(1, new KeyValuePair<string, object?>("layer", layer),
                new KeyValuePair<string, object?>("cause", cause));
        }
    }
}
