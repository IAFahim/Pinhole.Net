using System.Net;
using System.Net.Sockets;
using Pinhole;

namespace Pinhole.Tests;

/// <summary>A UDP socket attached to a <see cref="VirtualNetwork"/> — the test double the
/// engine's <see cref="IUdpSocket"/> seam consumes. Address semantics mirror a dual-mode OS
/// socket exactly: v4 peers appear as v4-mapped IPv6 sockaddrs on receive, and v4-mapped
/// destinations are unwrapped on send, so the engine's address comparisons behave as they
/// do against a real network.</summary>
internal sealed class VirtualUdpSocket : IUdpSocket
{
    private readonly VirtualNetwork _net;
    private readonly object _gate = new();
    private readonly Queue<(byte[] Payload, IPEndPoint From)> _inbox = new();
    private readonly AutoResetEvent _signal = new(false);
    private bool _disposed;

    internal VirtualUdpSocket(VirtualNetwork net, IPEndPoint address, VirtualNat? nat)
    {
        _net = net;
        Address = address;
        Nat = nat;
    }

    /// <summary>The address this socket lives at: public when internet-attached, private
    /// (behind <see cref="Nat"/>) otherwise.</summary>
    internal IPEndPoint Address { get; }

    internal VirtualNat? Nat { get; }

    public IPEndPoint LocalEndPoint => Address;

    public void SendTo(ReadOnlySpan<byte> frame, SocketAddress to) =>
        _net.RouteFrom(this, ToEndPoint(to), frame.ToArray());

    public int ReceiveFrom(Span<byte> buffer, SocketAddress from)
    {
        while (true)
        {
            lock (_gate)
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(VirtualUdpSocket));
                }

                if (_inbox.Count > 0)
                {
                    (byte[] payload, IPEndPoint source) = _inbox.Dequeue();
                    payload.CopyTo(buffer);
                    WriteAddress(from, source);
                    return payload.Length;
                }
            }

            if (!_signal.WaitOne(200))
            {
                throw new SocketException((int)SocketError.TimedOut); // the engine's periodic wake
            }
        }
    }

    internal void Enqueue(IPEndPoint source, byte[] payload)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _inbox.Enqueue((payload, source));
        }

        _signal.Set();
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
        }

        _signal.Set();
    }

    private static IPEndPoint ToEndPoint(SocketAddress address)
    {
        var ep = (IPEndPoint)new IPEndPoint(IPAddress.IPv6Any, 0).Create(address);
        return ep.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(ep.Address.MapToIPv4(), ep.Port) : ep;
    }

    private static void WriteAddress(SocketAddress target, IPEndPoint source)
    {
        IPEndPoint mapped = source.Address.AddressFamily == AddressFamily.InterNetwork
            ? new IPEndPoint(source.Address.MapToIPv6(), source.Port)
            : source;
        SocketAddress serialized = mapped.Serialize();
        for (int i = 0; i < serialized.Size; i++)
        {
            target[i] = serialized[i];
        }
    }
}
