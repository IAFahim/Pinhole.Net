using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Pinhole;

/// <summary>Per-stream proof state. Confirm must be called only after a sealed PONG
/// was authenticated by the session dispatcher; a reusable handshake is not proof
/// that this stream reaches the key holder. One stream can name only one peer.</summary>
internal sealed class TcpPeerProof
{
    private readonly long _challenge = BinaryPrimitives.ReadInt64LittleEndian(RandomNumberGenerator.GetBytes(8)) & 0x3fff_ffff_ffff_ffff;
    private long _peerId;
    private long _remoteChallenge = -1;
    private int _started;
    private int _confirmed;
    internal ulong BoundPeer => unchecked((ulong)Volatile.Read(ref _peerId));
    internal ulong AuthenticatedPeer => Volatile.Read(ref _confirmed) == 0 ? 0 : BoundPeer;

    internal bool Bind(ulong peerId)
    {
        if (peerId == 0) return false;
        long value = unchecked((long)peerId);
        long previous = Interlocked.CompareExchange(ref _peerId, value, 0);
        return previous == 0 || previous == value;
    }

    internal bool Begin(out long challenge)
    {
        challenge = _challenge;
        return BoundPeer != 0 && Interlocked.CompareExchange(ref _started, 1, 0) == 0;
    }

    internal bool Confirm(ulong peerId, long echoed)
    {
        if (peerId == 0 || peerId != BoundPeer || Volatile.Read(ref _started) == 0 || echoed != _challenge) return false;
        Volatile.Write(ref _confirmed, 1);
        return true;
    }

    internal void ObserveChallenge(long challenge)
    {
        if (challenge is >= 0 and <= 0x3fff_ffff_ffff_ffff)
            Interlocked.CompareExchange(ref _remoteChallenge, challenge, -1);
    }

    internal int CompareTo(TcpPeerProof other)
    {
        // Both ends see the same sorted pair, so parallel streams converge on the
        // same winner instead of each end closing the other's preferred stream.
        long remote = Volatile.Read(ref _remoteChallenge), otherRemote = Volatile.Read(ref other._remoteChallenge);
        var key = (Math.Min(_challenge, remote), Math.Max(_challenge, remote));
        var otherKey = (Math.Min(other._challenge, otherRemote), Math.Max(other._challenge, otherRemote));
        return key.CompareTo(otherKey);
    }
}
