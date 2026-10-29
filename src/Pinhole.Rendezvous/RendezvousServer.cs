using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Pinhole.Rendezvous;

public sealed class RendezvousServer : IAsyncDisposable
{
    public const int MaxNodes = 4096;
    public const int MaxWaitersPerTarget = 64;
    public const int MaxRecordLength = 1024;

    public const int MaxCodeRecordLength = 8 * 1024;
    public const int MaxCodes = 4096;
    public const int MaxCodeLength = 16;

    public const int MaxValidatedSources = 1024;

    private readonly Socket _udp;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _run;
    private readonly ConcurrentDictionary<ulong, (IPEndPoint Ep, DateTimeOffset Seen, string? Record)> _nodes = new();
    private readonly ConcurrentDictionary<ulong, List<(ulong Id, IPEndPoint Ep, DateTimeOffset At, bool Validated)>> _wants = new();
    private readonly ConcurrentDictionary<string, (string Record, string Token, DateTimeOffset Seen)> _codes = new();
    private readonly ConcurrentDictionary<IPEndPoint, DateTimeOffset> _validated = new();
    private readonly byte[] _cookieKey = RandomNumberGenerator.GetBytes(32);
    private long _datagramFaults;

    internal Action? OnWaiterIntro;

    public long DatagramFaults => Interlocked.Read(ref _datagramFaults);

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

        udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, 4 * 1024 * 1024);
        udp.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
        return new RendezvousServer(udp, ttl ?? TimeSpan.FromSeconds(120));
    }

    public int NodeCount => _nodes.Count;

    public int WantCount => _wants.Count;

    public int CodeCount => _codes.Count;

    internal int WaitersFor(ulong target)
    {
        if (!_wants.TryGetValue(target, out List<(ulong, IPEndPoint, DateTimeOffset, bool)>? list))
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
        byte[] buffer = new byte[MaxCodeRecordLength + 128];
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

            }
            catch (Exception)
            {

                Interlocked.Increment(ref _datagramFaults);
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
                if (_wants.TryRemove(id, out List<(ulong Id, IPEndPoint Ep, DateTimeOffset At, bool Validated)>? waiters))
                {

                    (ulong Id, IPEndPoint Ep, DateTimeOffset At, bool Validated)[] matched;
                    lock (waiters)
                    {
                        matched = waiters.ToArray();
                    }

                    if (!_nodes.TryGetValue(id, out (IPEndPoint Ep, DateTimeOffset Seen, string? Record) self))
                    {
                        self = (remote, DateTimeOffset.UtcNow, null);
                    }

                    bool registrantValidated = _validated.ContainsKey(remote);
                    foreach ((ulong waiterId, IPEndPoint waiterEp, _, bool waiterValidated) in matched)
                    {
                        OnWaiterIntro?.Invoke();
                        await IntroTo(waiterEp, id, waiterValidated ? self : StripRecord(self)).ConfigureAwait(false);
                        (IPEndPoint Ep, DateTimeOffset Seen, string? Record) waiterEntry = _nodes.TryGetValue(waiterId, out var registered)
                            ? registered
                            : (waiterEp, DateTimeOffset.UtcNow, null);
                        await IntroTo(remote, waiterId, registrantValidated ? waiterEntry : StripRecord(waiterEntry)).ConfigureAwait(false);
                    }
                }

                break;
            case ["WANT", var meText, var targetText]
                when ulong.TryParse(meText, NumberStyles.HexNumber, null, out ulong me)
                     && ulong.TryParse(targetText, NumberStyles.HexNumber, null, out ulong target):
                await HandleWantAsync(remote, me, target, null).ConfigureAwait(false);
                break;
            case ["WANT", var meText, var targetText, var cookie]
                when ulong.TryParse(meText, NumberStyles.HexNumber, null, out ulong me)
                     && ulong.TryParse(targetText, NumberStyles.HexNumber, null, out ulong target):
                await HandleWantAsync(remote, me, target, cookie).ConfigureAwait(false);
                break;
            case ["PUTC", var code, var record] when ValidCode(code) && ValidRecord(record, MaxCodeRecordLength):

                if (_codes.TryGetValue(code, out _))
                {

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
            case ["PUTC", var code, var record, var oldToken] when ValidCode(code) && ValidRecord(record, MaxCodeRecordLength):
                if (!_codes.TryGetValue(code, out (string Record, string Token, DateTimeOffset Seen) held))
                {

                    await Say(remote, "NOCODE").ConfigureAwait(false);
                    break;
                }

                if (!Token.Matches(held.Token, oldToken))
                {
                    await Say(remote, "TokB").ConfigureAwait(false);
                    break;
                }

                _codes[code] = (record, oldToken, DateTimeOffset.UtcNow);
                await Say(remote, $"OKCG {oldToken}").ConfigureAwait(false);
                break;
            case ["GETC", var code] when ValidCode(code):
                if (_codes.TryGetValue(code, out (string Record, string Token, DateTimeOffset Seen) entry2)
                    && entry2.Seen > DateTimeOffset.UtcNow - _ttl)
                {

                    await Say(remote, $"CHAL {code} {ChallengeCookie(remote, code)}").ConfigureAwait(false);
                }
                else
                {
                    await Say(remote, "WAITC").ConfigureAwait(false);
                }

                break;
            case ["GETC", var code, var cookie] when ValidCode(code):
                if (!ValidCookie(remote, code, cookie))
                {
                    await Say(remote, $"CHAL {code} {ChallengeCookie(remote, code)}").ConfigureAwait(false);
                    break;
                }

                if (_codes.TryGetValue(code, out (string Record, string Token, DateTimeOffset Seen) entry3)
                    && entry3.Seen > DateTimeOffset.UtcNow - _ttl)
                {
                    await Say(remote, $"OKCC {entry3.Record}").ConfigureAwait(false);
                }
                else
                {
                    await Say(remote, "WAITC").ConfigureAwait(false);
                }

                break;
            case ["DELC", var delCode, var delToken] when ValidCode(delCode!):
                if (!_codes.TryGetValue(delCode, out (string Record, string Token, DateTimeOffset Seen) current))
                {
                    await Say(remote, "NOCODE").ConfigureAwait(false);
                }
                else if (Token.Matches(current.Token, delToken))
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

    private async Task HandleWantAsync(IPEndPoint remote, ulong me, ulong target, string? cookie)
    {
        string subject = target.ToString("x16");
        if (cookie is not null)
        {
            if (!ValidCookie(remote, subject, cookie, "pinhole-want"))
            {
                await Say(remote, $"CHAL {subject} {ChallengeCookie(remote, subject, "pinhole-want")}").ConfigureAwait(false);
                return;
            }

            NoteValidatedSource(remote);
        }

        if (_nodes.TryGetValue(target, out (IPEndPoint Ep, DateTimeOffset Seen, string? Record) entry)
            && entry.Seen > DateTimeOffset.UtcNow - _ttl)
        {
            if (_validated.ContainsKey(remote))
            {
                await IntroTo(remote, target, entry).ConfigureAwait(false);
            }
            else
            {
                await Say(remote, $"CHAL {subject} {ChallengeCookie(remote, subject, "pinhole-want")}").ConfigureAwait(false);
                await IntroTo(remote, target, StripRecord(entry)).ConfigureAwait(false);
            }

            await IntroTo(entry.Ep, me, (remote, DateTimeOffset.UtcNow, null)).ConfigureAwait(false);
            return;
        }

        bool waiterValidated = cookie is not null || _validated.ContainsKey(remote);
        _wants.AddOrUpdate(target,
            _ => new List<(ulong Id, IPEndPoint Ep, DateTimeOffset At, bool Validated)>
            {
                (me, remote, DateTimeOffset.UtcNow, waiterValidated),
            },
            (_, list) =>
            {
                lock (list)
                {
                    if (list.Count >= MaxWaitersPerTarget)
                    {
                        list.RemoveAt(0);
                    }

                    list.Add((me, remote, DateTimeOffset.UtcNow, waiterValidated));
                }

                return list;
            });
        await Say(remote, $"WAIT {subject}").ConfigureAwait(false);
        if (!waiterValidated)
        {
            await Say(remote, $"CHAL {subject} {ChallengeCookie(remote, subject, "pinhole-want")}").ConfigureAwait(false);
        }
    }

    private static (IPEndPoint Ep, DateTimeOffset Seen, string? Record) StripRecord(
        (IPEndPoint Ep, DateTimeOffset Seen, string? Record) entry) => (entry.Ep, entry.Seen, null);

    private void NoteValidatedSource(IPEndPoint source)
    {
        _validated[source] = DateTimeOffset.UtcNow;
        if (_validated.Count > MaxValidatedSources)
        {
            EvictOldestValidated();
        }
    }

    private void EvictOldestValidated()
    {
        IPEndPoint? oldest = null;
        DateTimeOffset oldestSeen = DateTimeOffset.MaxValue;
        foreach (var (source, seen) in _validated)
        {
            if (seen < oldestSeen)
            {
                (oldest, oldestSeen) = (source, seen);
            }
        }

        if (oldest is { } evicted)
        {
            _validated.TryRemove(evicted, out _);
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

            foreach (var (source, seen) in _validated)
            {
                if (seen < cutoff)
                {
                    _validated.TryRemove(source, out _);
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

    private string ChallengeCookie(IPEndPoint src, string code, string label = "pinhole-chal")
    {
        long minute = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_cookieKey, Encoding.ASCII.GetBytes($"{label}|{src}|{code}|{minute}"), mac);
        return Convert.ToBase64String(mac[..12]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private bool ValidCookie(IPEndPoint src, string code, string presented, string label = "pinhole-chal")
    {
        if (presented.Length != 16)
        {
            return false;
        }

        long minute = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;
        Span<byte> given = stackalloc byte[16];
        Span<byte> mac = stackalloc byte[32];
        Span<byte> expected = stackalloc byte[16];
        Encoding.ASCII.GetBytes(presented, given);
        for (long m = minute - 1; m <= minute; m++)
        {
            HMACSHA256.HashData(_cookieKey, Encoding.ASCII.GetBytes($"{label}|{src}|{code}|{m}"), mac);
            Encoding.ASCII.GetBytes(Convert.ToBase64String(mac[..12]).TrimEnd('=').Replace('+', '-').Replace('/', '_'), expected);
            if (CryptographicOperations.FixedTimeEquals(expected, given))
            {
                return true;
            }
        }

        return false;
    }

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
            return Convert.ToBase64String(raw).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }

        public static bool Matches(string expected, string presented)
        {
            if (expected.Length != presented.Length || expected.Length > 128)
            {
                return false;
            }

            Span<byte> a = stackalloc byte[expected.Length];
            Span<byte> b = stackalloc byte[presented.Length];
            Encoding.ASCII.GetBytes(expected, a);
            Encoding.ASCII.GetBytes(presented, b);
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b);
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

    private Task IntroTo(IPEndPoint to, ulong subject, (IPEndPoint Ep, DateTimeOffset Seen, string? Record) entry) =>
        Say(to, entry.Record is { } record ? $"INTRO {subject:x16} {record}" : $"INTRO {subject:x16} {entry.Ep}");

    private static bool ValidRecord(string record, int maxLength = MaxRecordLength)
    {
        if (record.Length < 1 || record.Length > maxLength)
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

        }
    }
}
