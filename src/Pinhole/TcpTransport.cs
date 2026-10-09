using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Pinhole;

/// <summary>Bounded managed TCP sidecar. Framing negotiates the transport only: the
/// session dispatcher must independently authenticate the peer before selecting it.</summary>
internal sealed class TcpTransport : IDisposable
{
    internal static ReadOnlySpan<byte> Preface => "PHNTCP1\n"u8;
    internal const int MaxFrame = 8192;
    internal const int MaxLinks = 32;
    private readonly object _gate = new();
    private readonly Action<TcpLink, ReadOnlyMemory<byte>> _receive;
    private readonly Action<TcpLink> _closed;
    private readonly CancellationTokenSource _stop = new();
    private readonly Dictionary<long, TcpLink> _links = [];
    private readonly Dictionary<string, long> _attempts = [];
    private readonly HashSet<string> _dialing = [];
    private Socket? _listener;
    private long _nextId;
    private bool _disposed;

    internal TcpTransport(IPEndPoint listen, Action<TcpLink, ReadOnlyMemory<byte>> receive, Action<TcpLink> closed)
    {
        _receive = receive;
        _closed = closed;
        Rebind(listen);
    }

    internal int? ListeningPort { get { lock (_gate) return ((IPEndPoint?)_listener?.LocalEndPoint)?.Port; } }
    internal int LiveLinks { get { lock (_gate) return _links.Count + _dialing.Count; } }

    internal void Rebind(IPEndPoint endpoint)
    {
        lock (_gate)
        {
            if (_disposed || _listener?.LocalEndPoint?.Equals(endpoint) == true) return;
        }
        Socket? listener = null;
        try
        {
            listener = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            if (endpoint.AddressFamily == AddressFamily.InterNetworkV6) listener.DualMode = true;
            if (OperatingSystem.IsWindows()) listener.ExclusiveAddressUse = true;
            else listener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            listener.Bind(endpoint);
            listener.Listen(MaxLinks);
        }
        catch (Exception ex) when (ex is SocketException or NotSupportedException)
        {
            listener?.Dispose();
            listener = null; // TCP bind failure does not prevent UDP or active TCP use
        }
        lock (_gate)
        {
            if (_disposed) { listener?.Dispose(); return; }
            _listener?.Dispose();
            _listener = listener;
            if (listener is not null) _ = AcceptAsync(listener);
        }
    }

    private async Task AcceptAsync(Socket listener)
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket socket;
            try { socket = await listener.AcceptAsync(_stop.Token).ConfigureAwait(false); }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException) { return; }
            TcpLink? link = null;
            try
            {
                lock (_gate) link = _disposed || _links.Count + _dialing.Count >= MaxLinks ? null : AddLink(socket);
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException) { }
            if (link is null) socket.Dispose();
            else _ = link.RunAsync(initiator: false);
        }
    }

    internal async Task<TcpLink?> ConnectAsync(IPEndPoint endpoint, CancellationToken ct)
    {
        if (endpoint.Port == 0 || endpoint.Address.Equals(IPAddress.Any) || endpoint.Address.Equals(IPAddress.IPv6Any)
            || endpoint.Address.IsIPv6Multicast || endpoint.Address.AddressFamily == AddressFamily.InterNetwork && endpoint.Address.GetAddressBytes()[0] >= 224) return null;
        string key = endpoint.ToString();
        lock (_gate)
        {
            if (_disposed) return null;
            TcpLink? existing = _links.Values.FirstOrDefault(link => link.OutgoingTarget?.Equals(endpoint) == true && link.IsReady);
            if (existing is not null) return existing;
            long now = Environment.TickCount64;
            if (_links.Count + _dialing.Count >= MaxLinks || _dialing.Contains(key)
                || _attempts.TryGetValue(key, out long last) && now - last < 5_000) return null;
            if (_attempts.Count >= 128) _attempts.Remove(_attempts.MinBy(p => p.Value).Key);
            _attempts[key] = now;
            _dialing.Add(key);
        }
        Socket? socket = null;
        TcpLink? connected = null;
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, _stop.Token);
            deadline.CancelAfter(TimeSpan.FromSeconds(3));
            socket = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(endpoint, deadline.Token).ConfigureAwait(false);
            lock (_gate)
            {
                _dialing.Remove(key);
                if (_disposed) return null;
                connected = AddLink(socket, endpoint);
                socket = null; // link now owns it
            }
            _ = connected.RunAsync(initiator: true);
            await connected.Ready.WaitAsync(deadline.Token).ConfigureAwait(false);
            return connected;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException or IOException)
        {
            connected?.Dispose();
            return null;
        }
        finally
        {
            socket?.Dispose();
            lock (_gate) _dialing.Remove(key);
        }
    }

    private TcpLink AddLink(Socket socket, IPEndPoint? target = null)
    {
        try
        {
            var link = new TcpLink(Interlocked.Increment(ref _nextId), socket, target, _stop.Token, _receive, Closed);
            _links.Add(link.Id, link);
            return link;
        }
        catch { socket.Dispose(); throw; }
    }

    private void Closed(TcpLink link)
    {
        lock (_gate) _links.Remove(link.Id);
        try { _closed(link); } catch (Exception) { } // user/session callbacks cannot strand the transport
    }

    internal void ClosePeer(ulong peerId, TcpLink? graceful)
    {
        TcpLink[] owned;
        lock (_gate) owned = _links.Values.Where(link => link.BoundPeer == peerId).ToArray();
        foreach (TcpLink link in owned)
            if (ReferenceEquals(link, graceful)) link.CloseGracefully(); else link.Dispose();
    }

    public void Dispose()
    {
        TcpLink[] links;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _stop.Cancel();
            _listener?.Dispose();
            _listener = null;
            links = _links.Values.ToArray();
            _attempts.Clear();
        }
        foreach (TcpLink link in links) link.Dispose();
        _stop.Dispose();
    }
}

/// <summary>One framed stream, with a short unauthenticated lifetime, a bounded
/// writer queue and one receiving loop. All frame buffers belong to this link.</summary>
internal sealed class TcpLink : IDisposable
{
    private readonly Stream _stream;
    private readonly CancellationTokenSource _stop;
    private readonly Action<TcpLink, ReadOnlyMemory<byte>> _receive;
    private readonly Action<TcpLink> _closed;
    private readonly Channel<byte[]> _outgoing = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(32)
    {
        FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = false,
    });
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Timer _authenticationDeadline;
    private readonly TcpPeerProof _proof = new();
    private int _disposed;
    internal long Id { get; }
    internal IPEndPoint Remote { get; }
    internal IPEndPoint? OutgoingTarget { get; }
    internal Task Ready => _ready.Task;
    internal bool IsReady => _ready.Task.IsCompletedSuccessfully && Volatile.Read(ref _disposed) == 0;
    internal ulong AuthenticatedPeer => _proof.AuthenticatedPeer;
    internal ulong BoundPeer => _proof.BoundPeer;
    internal bool Initiator => OutgoingTarget is not null;

    internal TcpLink(long id, Socket socket, IPEndPoint? target, CancellationToken stop,
        Action<TcpLink, ReadOnlyMemory<byte>> receive, Action<TcpLink> closed)
        : this(id, CreateStream(socket), target, stop, receive, closed) { }

    // Stream injection lets protocol/lifecycle tests exercise the production link
    // without pretending a memory stream validates OS connect/listen behavior.
    internal TcpLink(long id, Stream stream, IPEndPoint remote, IPEndPoint? target, CancellationToken stop,
        Action<TcpLink, ReadOnlyMemory<byte>> receive, Action<TcpLink> closed)
        : this(id, (stream, remote), target, stop, receive, closed) { }

    private TcpLink(long id, (Stream Stream, IPEndPoint Remote) connection, IPEndPoint? target, CancellationToken stop,
        Action<TcpLink, ReadOnlyMemory<byte>> receive, Action<TcpLink> closed)
    {
        Id = id;
        _stream = connection.Stream;
        var remote = connection.Remote;
        Remote = remote.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(remote.Address.MapToIPv4(), remote.Port) : remote;
        OutgoingTarget = target;
        _receive = receive;
        _closed = closed;
        _stop = CancellationTokenSource.CreateLinkedTokenSource(stop);
        _authenticationDeadline = new Timer(_ => Dispose(), null, TimeSpan.FromSeconds(10), Timeout.InfiniteTimeSpan);
    }

    private static (Stream, IPEndPoint) CreateStream(Socket socket)
    {
        var remote = (IPEndPoint)socket.RemoteEndPoint!;
        socket.NoDelay = true;
        socket.SendBufferSize = 64 * 1024;
        socket.ReceiveBufferSize = 64 * 1024;
        return (new NetworkStream(socket, ownsSocket: true), remote);
    }

    /// <summary>Even before authentication, one stream may name only one peer. A
    /// stranger cannot populate the session table with many IDs on a single stream.</summary>
    internal bool BindPeer(ulong peerId)
    {
        return Volatile.Read(ref _disposed) == 0 && _proof.Bind(peerId);
    }

    internal bool BeginProof(out long challenge)
    {
        challenge = 0;
        return IsReady && _proof.Begin(out challenge);
    }

    internal bool ConfirmProof(ulong peerId, long echoed)
    {
        if (!IsReady || !_proof.Confirm(peerId, echoed)) return false;
        try { _authenticationDeadline.Change(Timeout.Infinite, Timeout.Infinite); }
        catch (ObjectDisposedException) { return false; }
        return IsReady;
    }

    internal void ObserveChallenge(long challenge) => _proof.ObserveChallenge(challenge);
    internal bool PreferredTo(TcpLink other, bool preferInitiator)
    {
        if (Initiator != other.Initiator) return Initiator == preferInitiator;
        return _proof.CompareTo(other._proof) < 0;
    }

    internal bool Send(ReadOnlySpan<byte> frame)
    {
        if (!IsReady || frame.Length is < 13 or > TcpTransport.MaxFrame) return false;
        byte[] packet = TcpFrameCodec.Encode(frame);
        return _outgoing.Writer.TryWrite(packet);
    }

    internal async Task RunAsync(bool initiator)
    {
        Task? writer = null;
        try
        {
            using (var negotiation = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token))
            {
                negotiation.CancelAfter(TimeSpan.FromSeconds(3));
                await TcpFrameCodec.NegotiateAsync(_stream, initiator, negotiation.Token).ConfigureAwait(false);
            }
            _ready.TrySetResult();
            writer = WriteAsync();
            byte[] size = new byte[2];
            byte[] buffer = new byte[TcpTransport.MaxFrame];
            while (!_stop.IsCancellationRequested)
            {
                int length = await TcpFrameCodec.ReadAsync(_stream, size, buffer, TimeSpan.FromSeconds(5), _stop.Token).ConfigureAwait(false);
                try { _receive(this, buffer.AsMemory(0, length)); } catch (Exception) { } // malformed frame costs one frame
            }
        }
        catch (Exception ex) when (ex is SocketException or IOException or ObjectDisposedException or OperationCanceledException)
        {
            // Accepted streams have no waiter. A canceled negotiation does not leave
            // an unobserved fault behind; active dials treat it as a failed attempt.
            _ready.TrySetCanceled();
        }
        finally
        {
            Dispose();
            if (writer is not null) await writer.ConfigureAwait(false);
            _stop.Dispose();
        }
    }

    private async Task WriteAsync()
    {
        try
        {
            await foreach (byte[] packet in _outgoing.Reader.ReadAllAsync(_stop.Token).ConfigureAwait(false))
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                deadline.CancelAfter(TimeSpan.FromSeconds(2));
                await _stream.WriteAsync(packet, deadline.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is SocketException or IOException or ObjectDisposedException or OperationCanceledException) { }
        finally { Dispose(); }
    }

    internal void CloseGracefully() => _outgoing.Writer.TryComplete();

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _authenticationDeadline.Dispose();
        _outgoing.Writer.TryComplete();
        _stop.Cancel();
        _stream.Dispose();
        _closed(this);
    }
}
