using Xunit;

namespace Pinhole.Tests;

internal static class TestBudget
{
    public static readonly TimeSpan Bind = TimeSpan.FromSeconds(10);

    public static readonly TimeSpan Handshake = TimeSpan.FromSeconds(15);

    public static readonly TimeSpan Io = TimeSpan.FromSeconds(10);

    public static readonly TimeSpan Teardown = TimeSpan.FromSeconds(20);

    public static readonly TimeSpan Scenario = TimeSpan.FromSeconds(30);
}

internal static class TestDispose
{
    public static async Task BoundedAsync(IAsyncDisposable disposable, string what)
    {
        try
        {
            await disposable.DisposeAsync().AsTask().WaitAsync(TestBudget.Teardown);
        }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            Assert.Fail($"disposing {what} did not finish within {TestBudget.Teardown.TotalSeconds:0}s: {ex.Message}");
        }
        catch
        {

        }
    }

    public static byte[] Pattern(long length, byte seed)
    {
        var result = new byte[length];
        for (long i = 0; i < length; i++)
        {
            result[i] = unchecked((byte)(i * 31 + seed));
        }

        return result;
    }
}
