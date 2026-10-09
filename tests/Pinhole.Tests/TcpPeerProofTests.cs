using Xunit;

namespace Pinhole.Tests;

public sealed class TcpPeerProofTests
{
    [Fact]
    public void StreamCannotBeReassignedOrConfirmedBeforeItsOwnChallenge()
    {
        var proof = new TcpPeerProof();
        Assert.False(proof.Bind(0));
        Assert.False(proof.Begin(out _));
        Assert.True(proof.Bind(0xffff_ffff_ffff_ffff));
        Assert.True(proof.Bind(0xffff_ffff_ffff_ffff));
        Assert.False(proof.Bind(7));
        Assert.Equal(0xffff_ffff_ffff_ffff, proof.BoundPeer);
        Assert.False(proof.Confirm(proof.BoundPeer, 0));
        Assert.Equal(0ul, proof.AuthenticatedPeer);
        Assert.True(proof.Begin(out long challenge));
        Assert.InRange(challenge, 0, 0x3fff_ffff_ffff_ffff);
        Assert.False(proof.Begin(out _));
        Assert.False(proof.Confirm(7, challenge));
        Assert.False(proof.Confirm(proof.BoundPeer, challenge ^ 1));
        Assert.Equal(0ul, proof.AuthenticatedPeer);
        Assert.True(proof.Confirm(proof.BoundPeer, challenge));
        Assert.Equal(proof.BoundPeer, proof.AuthenticatedPeer);
    }

    [Fact]
    public void ParallelStreamsHaveTheSameSelectionOrderAtBothEnds()
    {
        var a1 = new TcpPeerProof(); var b1 = new TcpPeerProof();
        var a2 = new TcpPeerProof(); var b2 = new TcpPeerProof();
        foreach (TcpPeerProof proof in new[] { a1, b1, a2, b2 }) Assert.True(proof.Bind(11));
        Assert.True(a1.Begin(out long aFirst)); Assert.True(b1.Begin(out long bFirst));
        Assert.True(a2.Begin(out long aSecond)); Assert.True(b2.Begin(out long bSecond));
        a1.ObserveChallenge(bFirst); b1.ObserveChallenge(aFirst);
        a2.ObserveChallenge(bSecond); b2.ObserveChallenge(aSecond);
        Assert.Equal(0, a1.CompareTo(b1));
        Assert.Equal(0, a2.CompareTo(b2));
        Assert.Equal(Math.Sign(a1.CompareTo(a2)), Math.Sign(b1.CompareTo(b2)));
        a1.ObserveChallenge(0); // later application pings cannot change selection order
        Assert.Equal(0, a1.CompareTo(b1));
        Assert.False(a1.Confirm(11, aSecond)); // proof from another stream has no authority here
        Assert.True(a1.Confirm(11, aFirst));
    }
}
