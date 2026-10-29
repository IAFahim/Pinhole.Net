using System.Net;
using System.Net.Sockets;

namespace Pinhole.Providers;

public static class Resolver
{
    private static readonly TimeSpan CatalogBudget = TimeSpan.FromSeconds(5);

    public static async Task<IPEndPoint[]> FreeStunAsync(CancellationToken ct = default)
    {
        (string host, int port)[] sources =
        [
            ("stun.l.google.com", 19302),
            ("stun.cloudflare.com", 3478),
            ("openrelay.metered.ca", 80),
            ("stun.relay.metered.ca", 80),
            ("global.stun.twilio.com", 3478),
        ];

        return await ResolveWithinBudgetAsync(sources, ct).ConfigureAwait(false);
    }

    public static async Task<IPEndPoint[]> FreeRelayServersAsync(CancellationToken ct = default)
    {
        (string host, int port)[] sources =
        [
            ("openrelay.metered.ca", 80),
            ("turn.relay.metered.ca", 80),
            ("turn.cloudflare.com", 3478),
            ("global.turn.twilio.com", 3478),
        ];

        return await ResolveWithinBudgetAsync(sources, ct).ConfigureAwait(false);
    }

    private static async Task<IPEndPoint[]> ResolveWithinBudgetAsync((string Host, int Port)[] sources, CancellationToken ct)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(CatalogBudget);
        Task<IPEndPoint[]>[] tasks = sources.Select(s => TryResolve(s.Host, s.Port, budget.Token)).ToArray();
        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {

        }

        var resolved = new List<IPEndPoint>();
        foreach (Task<IPEndPoint[]> task in tasks)
        {
            if (task.IsCompletedSuccessfully)
            {
                resolved.AddRange(task.Result);
            }
        }

        return resolved.ToArray();
    }

    private static async Task<IPEndPoint[]> TryResolve(string host, int port, CancellationToken ct)
    {
        try
        {
            IPAddress[] addrs = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            return addrs.Select(ip => new IPEndPoint(ip, port)).ToArray();
        }
        catch (SocketException)
        {
            return Array.Empty<IPEndPoint>();
        }

    }
}
