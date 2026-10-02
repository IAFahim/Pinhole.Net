using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Pinhole;

/// <summary>Receives one datagram payload from the peer. The span points into the receive
/// buffer and is only valid for the duration of the call — copy anything you keep.</summary>
public delegate void PinholeDatagramHandler(ReadOnlySpan<byte> payload);

/// <summary>The raw 1:1 punch engine beneath the session API: one UDP socket, hole punching
/// to a single peer via rendezvous signalling or STUN, then bare datagrams. No relays, no
/// roaming — see <see cref="PinholeNode"/> for the open-forever layer.</summary>
public sealed class PeerSocket : IDisposable
{
    private readonly PeerState _s;

    /// <summary>Binds a dual-mode IPv6 UDP socket (OS-assigned port unless <paramref name="bind"/>
    /// says otherwise) and starts the receive loop.</summary>
    public PeerSocket(ulong nodeId, IPEndPoint? bind = null)
    {
        _s = PeerEngine.CreateState(nodeId, bind);
        PeerEngine.Start(_s);
    }

    /// <summary>Adds a rendezvous server this socket registers with, so peers can discover it and be introduced to it.</summary>
    public void AddRendezvous(IPEndPoint endpoint) => PeerEngine.AddRendezvous(_s, endpoint);

    /// <summary>The bound UDP port.</summary>
    public int LocalPort => ((IPEndPoint)_s.Udp.LocalEndPoint!).Port;

    /// <summary>The public endpoint as last observed — by a STUN probe or reported back by a rendezvous server. Null until either happens.</summary>
    public IPEndPoint? PublicAddress => _s.PublicAddress;

    /// <summary>The peer's endpoint once the pinhole is open; null before that.</summary>
    public IPEndPoint? Peer => _s.PeerSa is { } sa ? (IPEndPoint)new IPEndPoint(IPAddress.IPv6Any, 0).Create(sa) : null;

    /// <summary>Round-trip time of the most recent answered <see cref="Ping"/>, if any.</summary>
    public TimeSpan? LastRtt => _s.LastRtt;

    /// <summary>Completes when the punch lands (a peer's reply matched this socket's magic).</summary>
    public Task Connected => _s.Punched.Task;

    /// <summary>Datagrams received from the peer; the payload span is valid only during the call.</summary>
    public event PinholeDatagramHandler? Received
    {
        add => _s.Received += value;
        remove => _s.Received -= value;
    }

    /// <summary>Announces this socket to every rendezvous; completes when one reports back the
    /// public endpoint it observed. Throws if no rendezvous is configured; times out after 10 s.</summary>
    public Task<IPEndPoint> RegisterAsync(CancellationToken ct = default) => PeerEngine.Register(_s, ct);

    /// <summary>Sends one STUN binding request and completes with the reflexive address.
    /// Concurrent probes are serialized on shared state — the later one waits for the earlier.</summary>
    public Task<IPEndPoint> ProbeStunAsync(IPEndPoint stunServer, CancellationToken ct = default) => PeerEngine.ProbeStun(_s, stunServer, ct);

    /// <summary>Adds a candidate endpoint and starts (or feeds) the punch loop, which probes
    /// every candidate until one replies. Add candidates as you learn them.</summary>
    public void AddCandidate(IPEndPoint endpoint) => PeerEngine.AddCandidate(_s, endpoint);

    /// <summary>Asks the rendezvous servers to introduce the target peer, then punches; completes
    /// when the pinhole opens. Fails after a 10 s punch timeout.</summary>
    public Task ConnectAsync(ulong targetNodeId, CancellationToken ct = default) => PeerEngine.Connect(_s, targetNodeId, ct);

    /// <summary>Punches straight at a known endpoint — no rendezvous involved. Completes when
    /// the pinhole opens; unlike <see cref="ConnectAsync(ulong, CancellationToken)"/> there is no built-in timeout.</summary>
    public Task ConnectDirectAsync(IPEndPoint endpoint) => PeerEngine.ConnectDirect(_s, endpoint);

    /// <summary>Sends one unreliable datagram through the open pinhole; throws if it is not open.</summary>
    public void Send(ReadOnlySpan<byte> payload) => PeerEngine.SendData(_s, payload);

    /// <summary>Sends a round-trip probe to the peer; a no-op before the pinhole is open. The answer updates <see cref="LastRtt"/>.</summary>
    public void Ping() => PeerEngine.Ping(_s);

    /// <summary>Releases the socket; this layer has no bye frame, so the peer simply sees silence.</summary>
    public void Dispose() => PeerEngine.Shutdown(_s);
}

internal sealed class PeerState
{
    public required Socket Udp;
    public required ulong NodeId;
    public required ulong Magic;
    public readonly CancellationTokenSource Shutdown = new();
    public readonly List<SocketAddress> Rendezvous = new();
    public readonly List<SocketAddress> Candidates = new();
    public SocketAddress? PeerSa;
    public IPEndPoint? PublicAddress;
    public readonly TaskCompletionSource<IPEndPoint> Observed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource Punched = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public PinholeDatagramHandler? Received;
    public TimeSpan? LastRtt;
    public int Punching;
    public readonly SemaphoreSlim StunGate = new(1, 1);
    public byte[]? StunTxid;
    public TaskCompletionSource<IPEndPoint>? StunResult;
}

internal static class PeerEngine
{
    private const byte FrameStun = 0x01;
    private const byte FramePunc = 0x05;
    private const byte FramePack = 0x06;
    private const byte FrameData = 0x10;
    private const byte FramePing = 0x11;
    private const byte FramePong = 0x12;
    private const int MaxStackFrame = 512;
    private const uint StunCookie = 0x2112A442;

    private static readonly TimeSpan PunchInterval = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan PunchTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan SignalTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan RegisterRefresh = TimeSpan.FromSeconds(30);

    private delegate void FrameHandler(PeerState s, SocketAddress remote, ReadOnlySpan<byte> frame);

    private static readonly FrameHandler?[] FrameTable = BuildTable();

    private static FrameHandler?[] BuildTable()
    {
        var table = new FrameHandler?[0x20];
        table[FrameStun] = OnStun;
        table[FramePunc] = OnPunc;
        table[FramePack] = OnPack;
        table[FrameData] = OnData;
        table[FramePing] = OnPing;
        table[FramePong] = OnPong;
        return table;
    }

    public static PeerState CreateState(ulong nodeId, IPEndPoint? bind)
    {
        var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        // Blocked receives must wake up periodically: closing a socket while a sync
        // receive holds it spins forever in SafeSocketHandle.CloseAsIs on macOS, so
        // disposal needs the receive loop to come back and observe the shutdown flag.
        udp.ReceiveTimeout = 200;
        udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, 4 * 1024 * 1024);
        udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, 4 * 1024 * 1024);
        if (OperatingSystem.IsWindows())
        {
            const int sioUdpConnreset = -1744830452;
            udp.IOControl(sioUdpConnreset, new byte[] { 0 }, null);
        }

        udp.Bind(bind is null
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : bind.Address.AddressFamily == AddressFamily.InterNetwork
                ? new IPEndPoint(bind.Address.MapToIPv6(), bind.Port) // dual-mode cannot bind a bare IPv4 address
                : bind);
        return new PeerState { Udp = udp, NodeId = nodeId, Magic = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8)) };
    }

    public static void Start(PeerState s)
    {
        new Thread(() => RecvLoop(s)) { IsBackground = true, Name = "pinhole-recv" }.Start();
        _ = RefreshLoop(s);
    }

    public static void Shutdown(PeerState s)
    {
        s.Shutdown.Cancel();
        s.Udp.Dispose();
        // The CTS is deliberately not disposed: the refresh loop may still be
        // registering on its token, and a timer-less CTS is reclaimed by the GC.
    }

    public static void AddRendezvous(PeerState s, IPEndPoint endpoint)
    {
        lock (s.Rendezvous)
        {
            s.Rendezvous.Add(ToWire(endpoint));
        }
    }

    public static async Task<IPEndPoint> Register(PeerState s, CancellationToken ct)
    {
        lock (s.Rendezvous)
        {
            if (s.Rendezvous.Count == 0)
            {
                throw new InvalidOperationException("no rendezvous added");
            }
        }

        SignalAll(s, $"REG {s.NodeId:x16}");
        return await s.Observed.Task.WaitAsync(SignalTimeout, ct).ConfigureAwait(false);
    }

    public static async Task Connect(PeerState s, ulong targetNodeId, CancellationToken ct)
    {
        SignalAll(s, $"WANT {s.NodeId:x16} {targetNodeId:x16}");
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, s.Shutdown.Token);
        deadline.CancelAfter(PunchTimeout);
        await s.Punched.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
    }

    public static Task ConnectDirect(PeerState s, IPEndPoint endpoint)
    {
        AddCandidate(s, endpoint);
        return s.Punched.Task;
    }

    public static void AddCandidate(PeerState s, IPEndPoint ep)
    {
        lock (s.Candidates)
        {
            s.Candidates.Add(ToWire(ep));
        }

        if (Interlocked.CompareExchange(ref s.Punching, 1, 0) == 0)
        {
            _ = PunchLoop(s);
        }
    }

    private static SocketAddress ToWire(IPEndPoint ep)
    {
        // The socket is dual-mode IPv6: IPv4 targets must be v4-mapped or Windows
        // sendto rejects the address family outright; the unspecified v6 address is
        // not a valid destination anywhere but Linux tolerates it, so map it to loopback.
        if (ep.Address.AddressFamily == AddressFamily.InterNetwork || ep.Address.Equals(IPAddress.IPv6Any))
        {
            IPAddress mapped = ep.Address.Equals(IPAddress.IPv6Any) ? IPAddress.IPv6Loopback : ep.Address.MapToIPv6();
            ep = new IPEndPoint(mapped, ep.Port);
        }

        return ep.Serialize();
    }

    public static void SendData(PeerState s, ReadOnlySpan<byte> payload)
    {
        SocketAddress peer = s.PeerSa ?? throw new InvalidOperationException("pinhole not open");
        if (!s.Punched.Task.IsCompleted)
        {
            throw new InvalidOperationException("pinhole not open");
        }

        int n = payload.Length + 1;
        if (n <= MaxStackFrame)
        {
            Span<byte> frame = stackalloc byte[n];
            frame[0] = FrameData;
            payload.CopyTo(frame[1..]);
            s.Udp.SendTo(frame, SocketFlags.None, peer);
            return;
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(n);
        try
        {
            rented[0] = FrameData;
            payload.CopyTo(rented.AsSpan(1));
            s.Udp.SendTo(rented.AsSpan(0, n), SocketFlags.None, peer);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    public static void Ping(PeerState s)
    {
        if (s.PeerSa is not { } peer)
        {
            return;
        }

        Span<byte> frame = stackalloc byte[9];
        frame[0] = FramePing;
        BitConverter.TryWriteBytes(frame[1..], Environment.TickCount64);
        s.Udp.SendTo(frame, SocketFlags.None, peer);
    }

    public static async Task<IPEndPoint> ProbeStun(PeerState s, IPEndPoint server, CancellationToken ct)
    {
        // ProbeStun shares StunTxid/StunResult on the state, so concurrent probes are
        // serialized; the later probe simply runs once the earlier one settles.
        await s.StunGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            byte[] req = new byte[20];
            BinaryPrimitives.WriteUInt16BigEndian(req, 0x0001);
            BinaryPrimitives.WriteUInt32BigEndian(req.AsSpan(4), StunCookie);
            RandomNumberGenerator.Fill(req.AsSpan(8));
            s.StunTxid = req.AsSpan(8).ToArray();
            s.StunResult = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
            s.Udp.SendTo(req, SocketFlags.None, ToWire(server));
            return await s.StunResult.Task.WaitAsync(SignalTimeout, ct).ConfigureAwait(false);
        }
        finally
        {
            s.StunGate.Release();
        }
    }

    private static void OnStun(PeerState s, SocketAddress remote, ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 20
            || BinaryPrimitives.ReadUInt32BigEndian(frame[4..]) != StunCookie
            || s.StunTxid is not { } txid
            || !frame.Slice(8, 12).SequenceEqual(txid))
        {
            return;
        }

        int end = Math.Min(frame.Length, 20 + BinaryPrimitives.ReadUInt16BigEndian(frame[2..]));
        int pos = 20;
        while (pos + 4 <= end)
        {
            ushort attrType = BinaryPrimitives.ReadUInt16BigEndian(frame[pos..]);
            int attrLen = BinaryPrimitives.ReadUInt16BigEndian(frame[(pos + 2)..]);
            if (pos + 4 + attrLen > end)
            {
                return; // a hostile or broken server claims an attribute past the message end
            }

            if ((attrType is 0x0020 or 0x0001) && attrLen >= 8)
            {
                if (TryDecodeAddress(frame.Slice(pos + 4, attrLen), txid, attrType == 0x0020, out IPEndPoint? ep))
                {
                    s.PublicAddress = ep;
                    s.StunResult?.TrySetResult(ep!);
                }

                return;
            }

            pos += 4 + ((attrLen + 3) & ~3);
        }
    }

    private static bool TryDecodeAddress(ReadOnlySpan<byte> value, ReadOnlySpan<byte> txid, bool xor, out IPEndPoint? ep)
    {
        ep = null;
        byte family = value[1];
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(value[2..]);
        if (xor)
        {
            port ^= (ushort)(StunCookie >> 16);
        }

        if (family == 0x01 && value.Length >= 8)
        {
            Span<byte> raw = stackalloc byte[4];
            value.Slice(4, 4).CopyTo(raw);
            if (xor)
            {
                raw[0] ^= 0x21;
                raw[1] ^= 0x12;
                raw[2] ^= 0xA4;
                raw[3] ^= 0x42;
            }

            ep = new IPEndPoint(new IPAddress(raw), port);
            return true;
        }

        if (family == 0x02 && value.Length >= 20)
        {
            Span<byte> raw = stackalloc byte[16];
            value.Slice(4, 16).CopyTo(raw);
            if (xor)
            {
                Span<byte> mask = stackalloc byte[16];
                BinaryPrimitives.WriteUInt32BigEndian(mask, StunCookie);
                txid.CopyTo(mask[4..]);
                for (int i = 0; i < 16; i++)
                {
                    raw[i] ^= mask[i];
                }
            }

            ep = new IPEndPoint(new IPAddress(raw), port);
            return true;
        }

        return false;
    }

    private static void RecvLoop(PeerState s)
    {
        byte[] buf = new byte[2048];
        var remote = new SocketAddress(AddressFamily.InterNetworkV6);
        while (!s.Shutdown.IsCancellationRequested)
        {
            int n;
            try
            {
                n = s.Udp.ReceiveFrom(buf, SocketFlags.None, remote);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException) when (s.Shutdown.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException)
            {
                continue;
            }

            if (n == 0)
            {
                continue;
            }

            if (buf[0] < 0x20)
            {
                try
                {
                    // Frame handlers send replies on this receive thread; one failed
                    // send (unreachable peer, interface flap) must not deafen the socket.
                    DispatchFrame(s, remote, buf.AsSpan(0, n));
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                }
            }
            else
            {
                OnSignal(s, buf.AsSpan(0, n));
            }
        }
    }

    private static void DispatchFrame(PeerState s, SocketAddress remote, ReadOnlySpan<byte> frame) =>
        FrameTable[frame[0]]?.Invoke(s, remote, frame);

    private static void OnPunc(PeerState s, SocketAddress remote, ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 9)
        {
            return;
        }

        Span<byte> pack = stackalloc byte[9];
        pack[0] = FramePack;
        frame[1..9].CopyTo(pack[1..]);
        s.Udp.SendTo(pack, SocketFlags.None, remote);
    }

    private static void OnPack(PeerState s, SocketAddress remote, ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 9 || BitConverter.ToUInt64(frame[1..]) != s.Magic)
        {
            return;
        }

        s.PeerSa = Clone(remote);
        s.Punched.TrySetResult();
    }

    private static void OnData(PeerState s, SocketAddress remote, ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 2 || s.Received is not { } handler)
        {
            return;
        }

        handler(frame[1..]);
    }

    private static void OnPing(PeerState s, SocketAddress remote, ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 9)
        {
            return;
        }

        Span<byte> pong = stackalloc byte[9];
        pong[0] = FramePong;
        frame[1..9].CopyTo(pong[1..]);
        s.Udp.SendTo(pong, SocketFlags.None, remote);
    }

    private static void OnPong(PeerState s, SocketAddress remote, ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 9)
        {
            return;
        }

        s.LastRtt = TimeSpan.FromMilliseconds(Environment.TickCount64 - BitConverter.ToInt64(frame[1..]));
    }

    private static void OnSignal(PeerState s, ReadOnlySpan<byte> line)
    {
        line = line.TrimEnd("\r\n"u8);
        int space = line.IndexOf((byte)' ');
        if (space <= 0)
        {
            return;
        }

        ReadOnlySpan<byte> arg = line[(space + 1)..];
        switch (line[0])
        {
            case (byte)'O':
                OnObserved(s, arg);
                break;
            case (byte)'I':
                OnIntro(s, arg);
                break;
        }
    }

    private static void OnObserved(PeerState s, ReadOnlySpan<byte> arg)
    {
        if (TryParseEndpoint(arg, out IPEndPoint? ep))
        {
            s.PublicAddress = ep;
            s.Observed.TrySetResult(ep!);
        }
    }

    private static void OnIntro(PeerState s, ReadOnlySpan<byte> arg)
    {
        int space = arg.LastIndexOf((byte)' ');
        if (space < 0 || !TryParseEndpoint(arg[(space + 1)..], out IPEndPoint? ep))
        {
            return;
        }

        AddCandidate(s, ep!);
    }

    private static async Task PunchLoop(PeerState s)
    {
        byte[] probe = new byte[9];
        probe[0] = FramePunc;
        BitConverter.TryWriteBytes(probe.AsSpan(1), s.Magic);
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(s.Shutdown.Token);
        deadline.CancelAfter(PunchTimeout);
        try
        {
            while (!s.Punched.Task.IsCompleted)
            {
                lock (s.Candidates)
                {
                    foreach (SocketAddress sa in s.Candidates)
                    {
                        try
                        {
                            s.Udp.SendTo(probe, SocketFlags.None, sa);
                        }
                        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                        {
                            // One unroutable candidate (or a brief interface flap) must
                            // not kill the punch; the pacing delay below bounds retries.
                        }
                    }
                }

                await Task.Delay(PunchInterval, deadline.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static async Task RefreshLoop(PeerState s)
    {
        while (!s.Shutdown.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(RegisterRefresh, s.Shutdown.Token).ConfigureAwait(false);
                if (s.Observed.Task.IsCompleted)
                {
                    SignalAll(s, $"REG {s.NodeId:x16}");
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                // The rendezvous send failed (network flap); retry on the next tick
                // so the registration does not quietly expire.
            }
        }
    }

    private static void SignalAll(PeerState s, ReadOnlySpan<char> line)
    {
        Span<byte> buf = stackalloc byte[line.Length + 1];
        int n = Encoding.ASCII.GetBytes(line, buf);
        buf[n] = (byte)'\n';
        ReadOnlySpan<byte> frame = buf[..(n + 1)];
        lock (s.Rendezvous)
        {
            foreach (SocketAddress sa in s.Rendezvous)
            {
                s.Udp.SendTo(frame, SocketFlags.None, sa);
            }
        }
    }

    private static bool TryParseEndpoint(ReadOnlySpan<byte> ascii, out IPEndPoint? ep)
    {
        ep = null;
        if (ascii.Length == 0 || ascii.Length > 64)
        {
            return false;
        }

        Span<char> chars = stackalloc char[ascii.Length];
        int n = Encoding.ASCII.GetChars(ascii, chars);
        return IPEndPoint.TryParse(chars[..n], out ep);
    }

    private static SocketAddress Clone(SocketAddress src)
    {
        var dst = new SocketAddress(src.Family, src.Size);
        for (int i = 0; i < src.Size; i++)
        {
            dst[i] = src[i];
        }

        return dst;
    }
}
