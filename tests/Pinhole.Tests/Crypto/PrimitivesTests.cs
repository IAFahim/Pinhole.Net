using Pinhole.Crypto;
using Xunit;

namespace Pinhole.Tests.Crypto;

// R1 gates for the bookkeeping primitives: the replay window against a set model,
// ledger conservation under random operation sequences, and Tick ordering.
public sealed class PrimitivesTests
{
    [Fact]
    public void ReplayWindow_MatchesTheSetModel_UnderRandomTraffic()
    {
        var rng = new Random(0xC0FFEE);
        for (int trial = 0; trial < 200; trial++)
        {
            ReplayWindow window = default;
            ulong highest = 0; // Highest is a watermark; the default value has marked nothing
            var seen = new HashSet<ulong>();
            for (int step = 0; step < 400; step++)
            {
                ulong counter = (ulong)(rng.NextInt64(0, (long)highest + 80));
                bool expectedAdmit = counter > highest || (highest - counter < 64 && !seen.Contains(counter));
                Assert.Equal(expectedAdmit, window.Admits(counter));

                if (expectedAdmit)
                {
                    window = window.Mark(counter);
                    seen.Add(counter);
                    if (counter > highest)
                    {
                        highest = counter;
                    }
                }
            }
        }
    }

    [Fact]
    public void ReplayWindow_BoundarySemantics()
    {
        ReplayWindow w = default;
        Assert.True(w.Admits(1));
        Assert.True(w.Admits(0)); // the watermark with an empty bitmap has marked nothing

        w = w.Mark(1);
        Assert.False(w.Admits(1));
        Assert.True(w.Admits(0)); // never marked; still inside the window

        // jump far: the old window clears; only the new Highest is marked
        w = w.Mark(200);
        Assert.False(w.Admits(200));
        Assert.True(w.Admits(137)); // top of the window (200-63), bit clear
        Assert.False(w.Admits(136)); // below the window: rejected as too old, seen or not
        Assert.True(w.Admits(201));

        // gap fill inside the window
        w = w.Mark(195);
        Assert.False(w.Admits(195));
        Assert.True(w.Admits(196));
        Assert.True(w.Admits(150));
        w = w.Mark(196);
        Assert.False(w.Admits(196));

        // marking below the window is a no-op, not corruption
        ReplayWindow before = w;
        w = w.Mark(3);
        Assert.Equal(before, w);
    }

    [Fact]
    public void ReplayWindow_DuplicateSuppression_CoversAMigrationBurst()
    {
        // The R6 multipath trick: the same sealed frame arrives on two paths; the
        // second copy is a replay by definition.
        ReplayWindow w = default;
        for (ulong counter = 1; counter <= 40; counter++)
        {
            Assert.True(w.Admits(counter));
            w = w.Mark(counter);
            Assert.False(w.Admits(counter));
        }

        for (ulong counter = 1; counter <= 40; counter++)
        {
            Assert.False(w.Admits(counter));
        }

        Assert.True(w.Admits(41));
    }

    [Fact]
    public void Ledger_ConservesCredit_UnderRandomSequences()
    {
        var rng = new Random(7);
        for (int trial = 0; trial < 100; trial++)
        {
            long capacity = rng.Next(1, 10_000);
            var ledger = new Ledger(capacity);
            var live = new List<(int Handle, long Amount)>();
            int nextHandle = 0;
            long outstanding = 0;

            for (int step = 0; step < 300; step++)
            {
                if (live.Count > 0 && rng.Next(3) == 0)
                {
                    int idx = rng.Next(live.Count);
                    (int handle, long amount) = live[idx];
                    live.RemoveAt(idx);
                    ledger.Release(amount);
                    outstanding -= amount;
                }
                else
                {
                    long amount = rng.Next(1, 500);
                    bool shouldSucceed = amount <= capacity - outstanding;
                    Assert.Equal(shouldSucceed, ledger.TryReserve(amount));
                    if (shouldSucceed)
                    {
                        live.Add((nextHandle++, amount));
                        outstanding += amount;
                    }
                }

                Assert.Equal(outstanding, ledger.Outstanding);
                Assert.Equal(capacity - outstanding, ledger.Available);
            }

            foreach ((_, long amount) in live)
            {
                ledger.Release(amount);
            }

            Assert.Equal(0, ledger.Outstanding); // quiescence: everything borrowed came back
        }
    }

    [Fact]
    public void Ledger_RejectsContractViolations()
    {
        var ledger = new Ledger(100);
        Assert.True(ledger.TryReserve(100));
        Assert.False(ledger.TryReserve(1));
        ledger.Release(100);
        Assert.True(ledger.TryReserve(1));
        Assert.Throws<InvalidOperationException>(() => ledger.Release(2));
        Assert.Throws<ArgumentOutOfRangeException>(() => ledger.TryReserve(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Ledger(-1));
    }

    [Fact]
    public void Tick_OrdersAndMeasuresDeltas()
    {
        var a = new Tick(1_000);
        var b = Tick.FromMilliseconds(1_500);
        Assert.True(a < b);
        Assert.Equal(500, b.MillisecondsSince(a));
        Assert.Equal(-500, a.MillisecondsSince(b));
        Assert.Equal(new TimeSpan(0, 0, 1), TimeSpan.FromMilliseconds(Tick.FromTimeSpan(TimeSpan.FromSeconds(1)).Milliseconds));
        Assert.NotEqual(a, b);
    }
}
