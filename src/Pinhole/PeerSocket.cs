using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Pinhole;

/// <summary>
/// A peer's own UDP socket: registers with a rendezvous server (which sees our public
/// mapped address, doubling as STUN), then punches a NAT pinhole to another peer.
/// One socket carries signaling and data so the observed mapping is the punched mapping.
///
/// Wire format — signaling to the rendezvous is ASCII lines; peer frames are binary with
/// a leading type byte &lt; 0x20:
///   PUNC (0x05) + u64 magic   — punch probe; opens our outbound mapping
///   PACK (0x06) + u64 magic   — punch ack; carrying OUR magic proves the pinhole opened
///   DATA (0x10) + payload     — a datagram on the established pinhole
///   PING (0x11) + i64 ticks   — keepalive / latency probe
///   PONG (0x12) + i64 ticks   — echoes PING
/// </summary>
public sealed class PeerSocket : IDisposable
{
    private static readonly TimeSpan PunchInterval = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan PunchTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan SignalTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan RegisterRefresh = TimeSpan.FromSeconds(30);

    private const byte FramePunc = 0x05;
    private const byte FramePack = 0x06;
    private const byte FrameData = 0x10;
    private const byte FramePing = 0x11;
    private const byte FramePong = 0x12;

    private readonly Socket _udp;
    private readonly IPEndPoint _rendezvous;
    private readonly ulong _nodeId;
    private readonly ulong _magic;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TaskCompletionSource<IPEndPoint> _observed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _punched = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _intro = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private IPEndPoint? _peer;
    private int _punching;

    /// <summary>Creates a peer socket that will signal through <paramref name="rendezvous"/> as <paramref name="nodeId"/>.</summary>
    public PeerSocket(IPEndPoint rendezvous, ulong nodeId)
    {
        _rendezvous = rendezvous;
        _nodeId = nodeId;
        _magic = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        _udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        _udp.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        _ = Task.Run(RecvLoop);
        _ = Task.Run(RegisterRefreshLoop);
    }

    /// <summary>This socket's public mapped endpoint as observed by the rendezvous; set after <see cref="RegisterAsync"/>.</summary>
    public IPEndPoint? PublicAddress { get; private set; }

    /// <summary>The punched peer endpoint once connected; null before.</summary>
    public IPEndPoint? Peer => _peer;

    /// <summary>Round-trip time of the last PING/PONG on the pinhole, or null before any pong.</summary>
    public TimeSpan? LastRtt { get; private set; }

    /// <summary>Completes when the pinhole is confirmed open (a PACK carrying our magic arrived).</summary>
    public Task Connected => _punched.Task;

    /// <summary>Raised for each DATA datagram received on the pinhole.</summary>
    public event Action<byte[]>? Received;

    /// <summary>Registers with the rendezvous and returns this socket's observed public endpoint.</summary>
    public async Task<IPEndPoint> RegisterAsync(CancellationToken ct = default)
    {
        await SignalAsync($"REG {_nodeId:x16}", ct).ConfigureAwait(false);
        return await _observed.Task.WaitAsync(SignalTimeout, ct).ConfigureAwait(false);
    }

    /// <summary>Asks the rendezvous to introduce <paramref name="targetNodeId"/>, then punches until the pinhole opens.</summary>
    public async Task ConnectAsync(ulong targetNodeId, CancellationToken ct = default)
    {
        if (!_observed.Task.IsCompleted)
        {
            throw new InvalidOperationException("RegisterAsync must complete before connecting.");
        }

        await SignalAsync($"WANT {_nodeId:x16} {targetNodeId:x16}", ct).ConfigureAwait(false);
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(PunchTimeout);
        await _punched.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
    }

    /// <summary>Sends a datagram to the punched peer. Throws if not connected.</summary>
    public void Send(ReadOnlySpan<byte> payload)
    {
        if (_peer is null || !_punched.Task.IsCompleted)
        {
            throw new InvalidOperationException("The pinhole is not open yet.");
        }

        byte[] frame = new byte[payload.Length + 1];
        frame[0] = FrameData;
        payload.CopyTo(frame.AsSpan(1));
        _udp.SendTo(frame, SocketFlags.None, _peer);
    }

    /// <summary>Sends a keepalive PING; the peer's PONG updates <see cref="LastRtt"/>.</summary>
    public void Ping()
    {
        if (_peer is null)
        {
            return;
        }

        byte[] frame = new byte[9];
        frame[0] = FramePing;
        BitConverter.TryWriteBytes(frame.AsSpan(1), Environment.TickCount64);
        _udp.SendTo(frame, SocketFlags.None, _peer);
    }

    public void Dispose()
    {
        _shutdown.Cancel();
        _udp.Dispose();
    }

    private Task SignalAsync(string line, CancellationToken ct) =>
        _udp.SendToAsync(new ArraySegment<byte>(Encoding.ASCII.GetBytes(line + '\n')), SocketFlags.None, _rendezvous, ct).AsTask();

    private async Task RecvLoop()
    {
        byte[] buffer = new byte[2048];
        while (!_shutdown.IsCancellationRequested)
        {
            SocketReceiveFromResult res;
            try
            {
                res = await _udp.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, new IPEndPoint(IPAddress.IPv6Any, 0)).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            if (res.ReceivedBytes == 0)
            {
                continue;
            }

            if (buffer[0] < 0x20)
            {
                PeerFrame((IPEndPoint)res.RemoteEndPoint, buffer, res.ReceivedBytes);
            }
            else
            {
                ServerLine(Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim());
            }
        }
    }

    private void ServerLine(string line)
    {
        string[] parts = line.Split(' ');
        switch (parts)
        {
            case ["OBS", var observed] when IPEndPoint.TryParse(observed, out IPEndPoint? ep):
                PublicAddress = ep;
                _observed.TrySetResult(ep);
                break;
            case ["INTRO", _, var addr] when IPEndPoint.TryParse(addr, out IPEndPoint? peer):
                OnIntro(peer);
                break;
        }
    }

    private void OnIntro(IPEndPoint peer)
    {
        _peer ??= peer;
        _intro.TrySetResult();
        if (Interlocked.CompareExchange(ref _punching, 1, 0) == 0)
        {
            _ = Task.Run(PunchLoop);
        }
    }

    private async Task PunchLoop()
    {
        byte[] probe = new byte[9];
        probe[0] = FramePunc;
        BitConverter.TryWriteBytes(probe.AsSpan(1), _magic);
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token);
        deadline.CancelAfter(PunchTimeout);
        try
        {
            while (!_punched.Task.IsCompleted)
            {
                if (_peer is not null)
                {
                    _udp.SendTo(probe, SocketFlags.None, _peer);
                }

                await Task.Delay(PunchInterval, deadline.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void PeerFrame(IPEndPoint remote, byte[] buffer, int length)
    {
        switch (buffer[0])
        {
            case FramePunc when length == 9:
                // Their probe got in — ack it so THEIR pinhole registers as open.
                byte[] pack = new byte[9];
                pack[0] = FramePack;
                buffer.AsSpan(1, 8).CopyTo(pack.AsSpan(1));
                _udp.SendTo(pack, SocketFlags.None, remote);
                break;
            case FramePack when length == 9 && BitConverter.ToUInt64(buffer, 1) == _magic:
                _peer ??= remote; // the addr that answered our probe is the live pinhole
                _punched.TrySetResult();
                break;
            case FrameData when length > 1:
                Received?.Invoke(buffer[1..length]);
                break;
            case FramePing when length == 9:
                byte[] pong = new byte[9];
                pong[0] = FramePong;
                buffer.AsSpan(1, 8).CopyTo(pong.AsSpan(1));
                _udp.SendTo(pong, SocketFlags.None, remote);
                break;
            case FramePong when length == 9:
                LastRtt = TimeSpan.FromMilliseconds(Environment.TickCount64 - BitConverter.ToInt64(buffer, 1));
                break;
        }
    }

    private async Task RegisterRefreshLoop()
    {
        while (!_shutdown.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(RegisterRefresh, _shutdown.Token).ConfigureAwait(false);
                if (_observed.Task.IsCompleted)
                {
                    await SignalAsync($"REG {_nodeId:x16}", _shutdown.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}
