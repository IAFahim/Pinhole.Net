using System.Diagnostics.CodeAnalysis;

namespace Pinhole;

public enum PinholeConnectFailure
{
    None = 0,
    InvalidConnectionString = 1,
    SelfConnection = 2,
    NoRelayFallback = 3,
    TimedOut = 4,
    PeerIncompatible = 5,
}

public sealed class PinholeConnectResult
{
    private PinholeConnectResult(PinholeConnection? connection, PinholeConnectFailure failure, string? errorMessage)
    {
        Connection = connection;
        Failure = failure;
        ErrorMessage = errorMessage;
    }

    [MemberNotNullWhen(true, nameof(Connection))]
    public bool IsSuccess => Connection is not null;

    public PinholeConnection? Connection { get; }

    public PinholeConnectFailure Failure { get; }

    public string? ErrorMessage { get; }

    internal static PinholeConnectResult Connected(PinholeConnection connection) =>
        new(connection, PinholeConnectFailure.None, null);

    internal static PinholeConnectResult Failed(PinholeConnectFailure failure, string message) =>
        new(null, failure, message);
}
