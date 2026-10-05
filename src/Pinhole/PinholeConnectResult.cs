using System.Diagnostics.CodeAnalysis;

namespace Pinhole;

/// <summary>Why a connection attempt did not establish a path.</summary>
public enum PinholeConnectFailure
{
    /// <summary>The connection succeeded.</summary>
    None = 0,
    /// <summary>The supplied code is empty or malformed.</summary>
    InvalidConnectionString = 1,
    /// <summary>The supplied code belongs to this node.</summary>
    SelfConnection = 2,
    /// <summary>The direct attempt timed out and the peer's code contains no relay candidate.</summary>
    NoRelayFallback = 3,
    /// <summary>No path was established before the timeout, despite advertised relay candidates.</summary>
    TimedOut = 4,
    /// <summary>The peer's connection string predates encryption and this node requires it
    /// (regenerate the string on a current node, or set <see cref="PinholeOptions.Encryption"/>
    /// to <see cref="PinholeEncryption.Optional"/>).</summary>
    PeerIncompatible = 5,
}

/// <summary>The outcome of <see cref="PinholeNode.TryConnectAsync"/>.
/// A successful connection belongs to the caller and should be disposed when finished.</summary>
public sealed class PinholeConnectResult
{
    private PinholeConnectResult(PinholeConnection? connection, PinholeConnectFailure failure, string? errorMessage)
    {
        Connection = connection;
        Failure = failure;
        ErrorMessage = errorMessage;
    }

    /// <summary>True when the attempt established a connection.</summary>
    [MemberNotNullWhen(true, nameof(Connection))]
    public bool IsSuccess => Connection is not null;

    /// <summary>The established connection, or null when the attempt failed.</summary>
    public PinholeConnection? Connection { get; }

    /// <summary>The failure reason, or None when connected.</summary>
    public PinholeConnectFailure Failure { get; }

    /// <summary>An actionable failure description, or null when connected.</summary>
    public string? ErrorMessage { get; }

    internal static PinholeConnectResult Connected(PinholeConnection connection) =>
        new(connection, PinholeConnectFailure.None, null);

    internal static PinholeConnectResult Failed(PinholeConnectFailure failure, string message) =>
        new(null, failure, message);
}
