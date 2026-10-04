using Xunit;

namespace Pinhole.Tests;

/// <summary>Reconnect pacing, iroh's practice for the same problem: a relay outage must not
/// synchronize every client into a retry storm, and brief blips must still heal fast.</summary>
public sealed class BackoffTests
{
    [Fact]
    public void RetryDelay_FirstRetryStaysNearOneSecond()
    {
        for (int i = 0; i < 50; i++)
        {
            Assert.InRange(IrohRelay.RetryDelay(0).TotalMilliseconds, 900, 1100);
        }
    }

    [Fact]
    public void RetryDelay_DoublesPerFailure_AndCapsAtThirtySeconds()
    {
        for (int i = 0; i < 50; i++)
        {
            // 8 s ±10% versus 2 s ±10%: the ranges cannot overlap, so the ladder strictly climbs.
            Assert.True(IrohRelay.RetryDelay(3) > IrohRelay.RetryDelay(1));
            Assert.InRange(IrohRelay.RetryDelay(50).TotalSeconds, 27, 33);
        }
    }
}
