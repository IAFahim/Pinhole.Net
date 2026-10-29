using Xunit;

namespace Pinhole.Tests;

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

            Assert.True(IrohRelay.RetryDelay(3) > IrohRelay.RetryDelay(1));
            Assert.InRange(IrohRelay.RetryDelay(50).TotalSeconds, 27, 33);
        }
    }
}
