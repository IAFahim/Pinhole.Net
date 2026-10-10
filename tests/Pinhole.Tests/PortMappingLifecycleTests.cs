using System.Collections.Concurrent;
using System.Net;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Lease lifecycle contracts, with delayed protocol completions and an
/// independent recording lease. No OS sockets or production mapping codec is used.</summary>
public sealed class PortMappingLifecycleTests
{
    // The choreography here runs on sub-second lease lifetimes; the budget only needs to
    // absorb a steal-heavy runner's scheduler stalls. 20 s: one mac CI run starved the
    // worker's post-cancellation continuation past a full 10 s without any lease fault.
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(20);
    private sealed class Lease(int port, ConcurrentQueue<string> trace) : IPortMapLease
    {
        public IPEndPoint External { get; } = new(IPAddress.Parse("203.0.113.10"), port);
        public TimeSpan Lifetime { get; set; } = TimeSpan.FromSeconds(10);
        public Func<CancellationToken, Task<bool>> Renew { get; set; } = _ => Task.FromResult(true);
        public Func<CancellationToken, Task> Release { get; set; } = _ => Task.CompletedTask;
        public int Releases, Disposals;
        public Task<bool> RenewAsync(CancellationToken ct) { trace.Enqueue($"renew:{port}"); return Renew(ct); }
        public async Task ReleaseAsync(CancellationToken ct)
        {
            trace.Enqueue($"release:{port}"); Interlocked.Increment(ref Releases);
            await Release(ct);
        }
        public void Dispose() { trace.Enqueue($"dispose:{port}"); Interlocked.Increment(ref Disposals); }
    }

    private static TaskCompletionSource<T> Signal<T>() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static Task Until(Func<bool> condition) => TestPoll.UntilAsync(Budget, condition);

    [Fact]
    public async Task ShutdownDuringDiscovery_ReleasesTheLateLeaseWithoutPublishingIt()
    {
        var started = Signal<bool>(); var reply = Signal<IPortMapLease?>();
        var trace = new ConcurrentQueue<string>(); var published = new ConcurrentQueue<IPEndPoint?>();
        var lease = new Lease(50001, trace);
        int calls = 0;
        using var service = new PortMappingService(new(), published.Enqueue, discover: (_, _) =>
        { Interlocked.Increment(ref calls); started.TrySetResult(true); return reply.Task; });
        service.Ensure(20001);
        await started.Task.WaitAsync(Budget);
        service.Shutdown();
        reply.SetResult(lease); // model a response already arriving when cancellation happened
        await service.Completed.WaitAsync(Budget);
        service.Ensure(20002); service.Rebind(20003); service.Tick(Environment.TickCount64);
        Assert.Empty(published);
        Assert.Null(service.Current);
        Assert.Equal(1, calls);
        Assert.Equal(1, lease.Releases);
        Assert.Equal(1, lease.Disposals);
    }

    [Fact]
    public async Task RebindDuringDiscovery_CoalescesToTheLatestPortAndReleasesBeforeReplacement()
    {
        var started = Signal<bool>(); var reply = Signal<IPortMapLease?>();
        var trace = new ConcurrentQueue<string>(); var published = new ConcurrentQueue<IPEndPoint?>();
        var old = new Lease(50001, trace); var fresh = new Lease(50003, trace);
        using var service = new PortMappingService(new(), published.Enqueue, discover: (port, _) =>
        {
            trace.Enqueue($"map:{port}");
            if (port == 20001) { started.TrySetResult(true); return reply.Task; }
            Assert.Equal(20003, port);
            return Task.FromResult<IPortMapLease?>(fresh);
        });
        service.Ensure(20001); await started.Task.WaitAsync(Budget);
        service.Rebind(20002); service.Rebind(20003);
        reply.SetResult(old);
        await Until(() => Equals(service.Current, fresh.External) && Equals(published.LastOrDefault(), fresh.External));
        Assert.Equal(new[] { "map:20001", "release:50001", "dispose:50001", "map:20003" }, trace.ToArray());
        Assert.Equal(new[] { fresh.External }, published.ToArray());
        service.Shutdown(); await service.Completed.WaitAsync(Budget);
        Assert.Equal(1, fresh.Releases);
    }

    [Fact]
    public async Task SamePortOnNewNetwork_WithdrawsAndFinishesReleaseBeforeRemapping()
    {
        var releaseStarted = Signal<bool>(); var releaseDone = Signal<bool>();
        var trace = new ConcurrentQueue<string>(); var published = new ConcurrentQueue<IPEndPoint?>();
        var old = new Lease(50001, trace) { Release = async ct => { releaseStarted.TrySetResult(true); await releaseDone.Task.WaitAsync(ct); } };
        var fresh = new Lease(50002, trace);
        int calls = 0;
        using var service = new PortMappingService(new(), published.Enqueue,
            discover: (_, _) => Task.FromResult<IPortMapLease?>(Interlocked.Increment(ref calls) == 1 ? old : fresh));
        service.Ensure(20001); await Until(() => Equals(service.Current, old.External) && published.Contains(old.External));
        service.Rebind(20001);
        await releaseStarted.Task.WaitAsync(Budget);
        Assert.Null(service.Current);
        await Until(() => published.Last() is null);
        await Task.Delay(50);
        Assert.Equal(1, calls);
        releaseDone.TrySetResult(true);
        await Until(() => Equals(service.Current, fresh.External) && Equals(published.LastOrDefault(), fresh.External));
        Assert.Equal(new IPEndPoint?[] { old.External, null, fresh.External }, published.ToArray());
        service.Shutdown(); await service.Completed.WaitAsync(Budget);
    }

    [Fact]
    public async Task PublicationCallback_CannotHoldRebindOrShutdownUnderTheLeaseLock()
    {
        var entered = Signal<bool>(); var resume = Signal<bool>();
        var trace = new ConcurrentQueue<string>(); var published = new ConcurrentQueue<IPEndPoint?>();
        var old = new Lease(50001, trace); var fresh = new Lease(50002, trace);
        using var service = new PortMappingService(new(), endpoint =>
        {
            if (Equals(endpoint, old.External)) { entered.TrySetResult(true); resume.Task.GetAwaiter().GetResult(); }
            published.Enqueue(endpoint);
        }, discover: (port, _) => Task.FromResult<IPortMapLease?>(port == 20001 ? old : fresh));
        try
        {
            service.Ensure(20001); await entered.Task.WaitAsync(Budget);
            await Task.Run(() => service.Rebind(20002)).WaitAsync(Budget);
            await Until(() => Equals(service.Current, fresh.External));
            await Task.Run(service.Shutdown).WaitAsync(Budget);
        }
        finally { resume.TrySetResult(true); }
        await service.Completed.WaitAsync(Budget);
        Assert.Null(service.Current);
        Assert.Null(published.Last());
        Assert.Equal(1, old.Releases); Assert.Equal(1, fresh.Releases);
    }

    [Fact]
    public async Task PendingRenewal_CannotKeepAnExpiredCandidateAlive()
    {
        var renewStarted = Signal<bool>();
        var trace = new ConcurrentQueue<string>(); var published = new ConcurrentQueue<IPEndPoint?>();
        var lease = new Lease(50001, trace)
        {
            Lifetime = TimeSpan.FromMilliseconds(300),
            Renew = async ct => { renewStarted.TrySetResult(true); await Task.Delay(Timeout.Infinite, ct); return true; },
        };
        using var service = new PortMappingService(new(), published.Enqueue,
            discover: (_, _) => Task.FromResult<IPortMapLease?>(lease));
        service.Ensure(20001);
        await renewStarted.Task.WaitAsync(Budget);
        await Until(() => service.Current is null);
        await Until(() => lease.Disposals == 1);
        await Until(() => published.LastOrDefault() is null);
        Assert.Equal(new IPEndPoint?[] { lease.External, null }, published.ToArray());
        Assert.Equal(1, lease.Releases);
        service.Shutdown(); await service.Completed.WaitAsync(Budget);
    }

    [Fact]
    public async Task StaleFailedRenewal_CannotWithdrawTheReplacementLease()
    {
        var renewStarted = Signal<bool>(); var renewal = Signal<bool>();
        var trace = new ConcurrentQueue<string>(); var published = new ConcurrentQueue<IPEndPoint?>();
        var old = new Lease(50001, trace)
        {
            Lifetime = TimeSpan.FromMilliseconds(200),
            Renew = _ => { renewStarted.TrySetResult(true); return renewal.Task; },
        };
        var fresh = new Lease(50002, trace);
        using var service = new PortMappingService(new(), published.Enqueue,
            discover: (port, _) => Task.FromResult<IPortMapLease?>(port == 20001 ? old : fresh));
        service.Ensure(20001); await Until(() => published.Contains(old.External));
        await renewStarted.Task.WaitAsync(Budget);
        service.Rebind(20002); renewal.SetResult(false);
        await Until(() => Equals(service.Current, fresh.External) && Equals(published.LastOrDefault(), fresh.External));
        Assert.Equal(new IPEndPoint?[] { old.External, null, fresh.External }, published.ToArray());
        Assert.Equal(1, old.Releases);
        Assert.Equal(1, old.Disposals);
        service.Shutdown(); await service.Completed.WaitAsync(Budget);
    }
}
