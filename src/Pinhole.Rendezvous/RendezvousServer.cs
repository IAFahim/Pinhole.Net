using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pinhole.Rendezvous;

/// <summary>A tiny UDP introducer: nodes REGister, waiters WANT a target, and both sides receive
/// an INTRO when the target registers. A registration may attach a signed address record
/// (base64url, ≤1 KB) which INTROs then carry verbatim — the introducer stores and forwards
/// records but never validates them; adopters verify signatures against their pinned keys.
/// Entries are TTL-swept and bounded so memory stays flat.
///
/// Host/join code directory (#45): hosts PUTC a short invitation code mapped to a
/// connection-string record; joiners GETC it. Codes are capabilities — the introducer still
/// never validates records — and a registration can only be deleted by presenting the
/// token the server issued at PUT time, so a joiner who knows the code cannot tear down
/// the host's registration.</summary>
public sealed class RendezvousServer : IAsyncDisposable
{
    public const int MaxNodes = 4096;
    public const int MaxWaitersPerTarget = 64;
    public const int MaxRecordLength = 1024;
    public const int MaxCodes = 4096;
    public const int MaxCodeLength = 16;

    private readonly Socket _udp;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _run;
    private readonly ConcurrentDictionary<ulong, (IPEndPoint Ep, DateTimeOffset Seen, string? Record)> _nodes = new();
    private readonly ConcurrentDictionary<ulong, List<(ulong Id, IPEndPoint Ep, DateTimeOffset At)>> _wants = new();
    private readonly ConcurrentDictionary<string, (string Record, string Token, DateTimeOffset Seen)> _codes = new();

    private RendezvousServer(Socket udp, TimeSpan ttl)
    {
        _udp = udp;
        _ttl = ttl;
        LocalEndPoint = (IPEndPoint)udp.LocalEndPoint!;
        _run = Task.WhenAll(ReceiveLoop(), SweepLoop());
    }

    public IPEndPoint LocalEndPoint { get; }

    private TimeSpan _ttl;

    public static RendezvousServer Start(int port = 0, TimeSpan? ttl = null)
    {
        var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        // An introducer receives registration bursts; the default buffer drops them.
        udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, 4 * 1024 * 1024);
        udp.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
        return new RendezvousServer(udp, ttl ?? TimeSpan.FromSeconds(120));
    }

    public int NodeCount => _nodes.Count;

    public int WantCount => _wants.Count;

    public int CodeCount => _codes.Count;

    internal int WaitersFor(ulong target)
    {
        if (!_wants.TryGetValue(target, out List<(ulong, IPEndPoint, DateTimeOffset)>? list))
        {
            return 0;
        }

        lock (list)
        {
            return list.Count;
        }
    }

    private async Task ReceiveLoop()
    {
        byte[] buffer = new byte[2048];
        IPEndPoint any = new(IPAddress.IPv6Any, 0);
        while (!_shutdown.IsCancellationRequested)
        {
            SocketReceiveFromResult res;
            try
            {
                res = await _udp.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, any).ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException) when (_shutdown.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException)
            {
                continue;
            }

            if (res.ReceivedBytes == 0)
            {
                continue;
            }

            IPEndPoint remote = (IPEndPoint)res.RemoteEndPoint;
            try
            {
                await HandleDatagram(remote, buffer, res.ReceivedBytes).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                if (_shutdown.IsCancellationRequested)
                {
                    return;
                }

                // One undeliverable reply must not stop the introducer for everyone else.
            }
        }
    }

    private async Task HandleDatagram(IPEndPoint remote, byte[] buffer, int n)
    {
        string[] parts = Encoding.ASCII.GetString(buffer, 0, n).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        switch (parts)
        {
            case ["REG", ..] when parts.Length is 2 or 3
                && (parts.Length == 2 || ValidRecord(parts[2]))
                && ulong.TryParse(parts[1], NumberStyles.HexNumber, null, out ulong id):
                _nodes[id] = (remote, DateTimeOffset.UtcNow, parts.Length == 3 ? parts[2] : null);
                if (_nodes.Count > MaxNodes)
                {
                    EvictOldestNode();
                }

                await Say(remote, $"OBS {remote}").ConfigureAwait(false);
                if (_wants.TryRemove(id, out List<(ulong Id, IPEndPoint Ep, DateTimeOffset At)>? waiters))
                {
                    foreach ((ulong waiterId, IPEndPoint waiterEp, _) in waiters)
                    {
                        await IntroTo(waiterEp, id, _nodes[id]).ConfigureAwait(false);
                        await IntroTo(remote, waiterId, _nodes.TryGetValue(waiterId, out var waiterEntry)
                            ? waiterEntry
                            : (waiterEp, DateTimeOffset.UtcNow, null)).ConfigureAwait(false);
                    }
                }

                break;
            case ["WANT", var meText, var targetText]
                when ulong.TryParse(meText, NumberStyles.HexNumber, null, out ulong me)
                     && ulong.TryParse(targetText, NumberStyles.HexNumber, null, out ulong target):
                if (_nodes.TryGetValue(target, out (IPEndPoint Ep, DateTimeOffset Seen, string? Record) entry)
                    && entry.Seen > DateTimeOffset.UtcNow - _ttl)
                {
                    await IntroTo(remote, target, entry).ConfigureAwait(false);
                    await IntroTo(entry.Ep, me, (remote, DateTimeOffset.UtcNow, null)).ConfigureAwait(false);
                }
                else
                {
                    _wants.AddOrUpdate(target,
                        _ => new List<(ulong, IPEndPoint, DateTimeOffset)> { (me, remote, DateTimeOffset.UtcNow) },
                        (_, list) =>
                        {
                            lock (list)
                            {
                                if (list.Count >= MaxWaitersPerTarget)
                                {
                                    list.RemoveAt(0);
                                }

                                list.Add((me, remote, DateTimeOffset.UtcNow));
                            }

                            return list;
                        });
                    await Say(remote, $"WAIT {target:x16}").ConfigureAwait(false);
                }

                break;
            case ["PUTC", var code, var record] when ValidCode(code) && ValidRecord(record):
                // First registration claims the code and issues its delete/replace token.
                if (_codes.TryGetValue(code, out _))
                {
                    // A live code belongs to whoever claimed it: only the token holder
                    // may replace the record, so a code holder cannot hijack a host.
                    await Say(remote, "TokB").ConfigureAwait(false);
                    break;
                }

                string token = Token.New();
                _codes[code] = (record, token, DateTimeOffset.UtcNow);
                if (_codes.Count > MaxCodes)
                {
                    EvictOldestCode();
                }

                await Say(remote, $"OKCG {token}").ConfigureAwait(false);
                break;
            case ["PUTC", var code, var record, var oldToken] when ValidCode(code) && ValidRecord(record):
                if (!_codes.TryGetValue(code, out (string Record, string Token, DateTimeOffset Seen) held)
                    || held.Token != oldToken)
                {
                    await Say(remote, "TokB").ConfigureAwait(false);
                    break;
                }

                _codes[code] = (record, oldToken, DateTimeOffset.UtcNow); // refresh keeps the token
                await Say(remote, $"OKCG {oldToken}").ConfigureAwait(false);
                break;
            case ["GETC", var code] when ValidCode(code):
                if (_codes.TryGetValue(code, out (string Record, string Token, DateTimeOffset Seen) entry2)
                    && entry2.Seen > DateTimeOffset.UtcNow - _ttl)
                {
                    await Say(remote, $"OKCC {entry2.Record}").ConfigureAwait(false);
                }
                else
                {
                    await Say(remote, "WAITC").ConfigureAwait(false);
                }

                break;
            case ["DELC", var delCode, var delToken] when ValidCode(delCode!):
                if (_codes.TryGetValue(delCode, out (string Record, string Token, DateTimeOffset Seen) current)
                    && current.Token == delToken)
                {
                    _codes.TryRemove(delCode, out _);
                    await Say(remote, "OKCD").ConfigureAwait(false);
                }
                else
                {
                    await Say(remote, "TokB").ConfigureAwait(false);
                }

                break;
        }
    }

    private async Task SweepLoop()
    {
        while (!_shutdown.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_ttl / 2, _shutdown.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            DateTimeOffset cutoff = DateTimeOffset.UtcNow - _ttl;
            foreach (var (id, (_, seen, _)) in _nodes)
            {
                if (seen < cutoff)
                {
                    _nodes.TryRemove(id, out _);
                }
            }

            foreach (var (target, list) in _wants)
            {
                bool empty;
                lock (list)
                {
                    list.RemoveAll(w => w.At < cutoff);
                    empty = list.Count == 0;
                }

                if (empty)
                {
                    _wants.TryRemove(target, out _);
                }
            }

            foreach (var (code, (_, _, seen)) in _codes)
            {
                if (seen < cutoff)
                {
                    _codes.TryRemove(code, out _);
                }
            }
        }
    }

    private void EvictOldestCode()
    {
        string? oldest = null;
        DateTimeOffset oldestSeen = DateTimeOffset.MaxValue;
        foreach (var (code, (_, _, seen)) in _codes)
        {
            if (seen < oldestSeen)
            {
                (oldest, oldestSeen) = (code, seen);
            }
        }

        if (oldest is { } evicted)
        {
            _codes.TryRemove(evicted, out _);
        }
    }

    /// <summary>Codes are ASCII, bounded, and space-free — they key a dictionary and ride
    /// the space-framed wire. Content is the host's choice; the SDK generates base32.</summary>
    private static bool ValidCode(string code)
    {
        if (code.Length is < 4 or > MaxCodeLength)
        {
            return false;
        }

        foreach (char c in code)
        {
            if (!(c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-'))
            {
                return false;
            }
        }

        return true;
    }

    private static class Token
    {
        public static string New()
        {
            Span<byte> raw = stackalloc byte[16];
            System.Security.Cryptography.RandomNumberGenerator.Fill(raw);
            System.Span<char> chars = stackalloc char[26];
            Base64UrlEncode(raw, chars);
            return new string(chars[..26].TrimEnd('='));
        }

        private static void Base64UrlEncode(ReadOnlySpan<byte> bytes, Span<char> output)
        {
            string s = Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_');
            s.AsSpan().CopyTo(output);
        }
    }

    private void EvictOldestNode()
    {
        ulong? oldest = null;
        DateTimeOffset oldestSeen = DateTimeOffset.MaxValue;
        foreach (var (key, (_, seen, _)) in _nodes)
        {
            if (seen < oldestSeen)
            {
                (oldest, oldestSeen) = (key, seen);
            }
        }

        if (oldest is { } id)
        {
            _nodes.TryRemove(id, out _);
        }
    }

    private Task Say(IPEndPoint to, string line) =>
        _udp.SendToAsync(new ArraySegment<byte>(Encoding.ASCII.GetBytes(line + '\n')), SocketFlags.None, to);

    /// <summary>Introduces a subject to a waiter: the subject's signed record verbatim when
    /// one is registered, else the legacy bare-endpoint form for pre-record clients.</summary>
    private Task IntroTo(IPEndPoint to, ulong subject, (IPEndPoint Ep, DateTimeOffset Seen, string? Record) entry) =>
        Say(to, entry.Record is { } record ? $"INTRO {subject:x16} {record}" : $"INTRO {subject:x16} {entry.Ep}");

    /// <summary>Records are opaque here, but not arbitrary: base64url of bounded length, so a
    /// hostile registration cannot bloat memory or smuggle spaces into the ASCII framing.</summary>
    private static bool ValidRecord(string record)
    {
        if (record.Length is < 1 or > MaxRecordLength)
        {
            return false;
        }

        foreach (char c in record)
        {
            if (!(c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_' or '='))
            {
                return false;
            }
        }

        return true;
    }

    public async ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        _udp.Dispose();
        try
        {
            await _run.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The loops end on socket disposal; a faulted loop is irrelevant at shutdown.
        }
    }
}
