using Xunit;

namespace Pinhole.Tests;

/// <summary>Named timeout budgets, the iroh-net-bindings pattern: every category of wait
/// in the suite gets a name and a ceiling so a contract violation fails a test with a
/// clear timeout instead of hanging the run — and a stuck TEARDOWN surfaces as a test
/// failure rather than an infinite CI job. New tests should use these instead of
/// ad-hoc <c>TimeSpan.FromSeconds</c> values.</summary>
internal static class TestBudget
{
    /// <summary>Node bind + STUN/relay registration in offline setups.</summary>
    public static readonly TimeSpan Bind = TimeSpan.FromSeconds(10);

    /// <summary>Connect/accept handshakes, including a relay-first path.</summary>
    public static readonly TimeSpan Handshake = TimeSpan.FromSeconds(15);

    /// <summary>A single exchange (one request/response round) once connected.</summary>
    public static readonly TimeSpan Io = TimeSpan.FromSeconds(10);

    /// <summary>Disposal of nodes/servers — teardown must be bounded and observable.</summary>
    public static readonly TimeSpan Teardown = TimeSpan.FromSeconds(20);

    /// <summary>Whole-test ceiling for end-to-end scenarios with healing in the loop.</summary>
    public static readonly TimeSpan Scenario = TimeSpan.FromSeconds(30);
}

internal static class TestDispose
{
    /// <summary>Disposes with a budget so a stuck teardown fails the test instead of
    /// hanging the run; cleanup failures are swallowed — they must never mask the
    /// actual assertion that got us here.</summary>
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
            // The dispose itself threw a real error (not a timeout): still not worth
            // replacing the test's own result — but a stuck one above is worth failing.
        }
    }

    /// <summary>Deterministic non-uniform filler, the sendme-style triage payload: any
    /// failure can be reproduced byte-for-byte from (length, seed) with no stored state.</summary>
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
