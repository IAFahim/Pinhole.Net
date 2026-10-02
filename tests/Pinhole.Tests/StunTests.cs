using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Pinhole.Tests;

/// <summary>An in-process STUN responder that builds RFC 5389 wire bytes by hand, so the
/// client's XOR decoding (v4 and v6) is exercised against exact recorded-style vectors.</summary>
public sealed class FakeStunServer : IDisposable
{
    private const uint Cookie = 0x2112A442;

    private readonly Socket _udp;
    private readonly byte[] _buf = new byte[1500];
    private volatile bool _running = true;
    public FakeStunServer(bool ipv6 = false)
    {
        _udp = new Socket(ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _udp.Bind(new IPEndPoint(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, 0));
        LocalEndPoint = (IPEndPoint)_udp.LocalEndPoint!;
        _ = Task.Run(RunAsync);
    }

    public IPEndPoint LocalEndPoint { get; }

    /// <summary>When set, a response with a random (never-matching) transaction id is sent
    /// before the real reply, exercising the client's txid mismatch rejection.</summary>
    public bool SendDecoyFirst { get; set; }

    /// <summary>When set, the server claims THIS endpoint is the client's mapped address
    /// instead of the observed one — simulating a NAT that assigns a mapping per
    /// destination (what NatDetector must call Symmetric).</summary>
    public IPEndPoint? ReportMappedOverride { get; set; }

    private async Task RunAsync()
    {
        IPEndPoint any = new(_udp.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        while (_running)
        {
            SocketReceiveFromResult res;
            try
            {
                res = await _udp.ReceiveFromAsync(_buf, SocketFlags.None, any).ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            if (res.ReceivedBytes < 20 || BinaryPrimitives.ReadUInt32BigEndian(_buf.AsSpan(4)) != Cookie)
            {
                continue;
            }

            IPEndPoint remote = (IPEndPoint)res.RemoteEndPoint;
            IPEndPoint mapped = ReportMappedOverride ?? remote;
            byte[] txid = _buf[8..20];
            if (SendDecoyFirst)
            {
                byte[] decoyTxid = new byte[12];
                Random.Shared.NextBytes(decoyTxid);
                await _udp.SendToAsync(BuildResponse(decoyTxid, mapped), SocketFlags.None, remote).ConfigureAwait(false);
            }

            await _udp.SendToAsync(BuildResponse(txid, mapped), SocketFlags.None, remote).ConfigureAwait(false);
        }

        static byte[] BuildResponse(byte[] txid, IPEndPoint observed)
        {
            // XOR-MAPPED-ADDRESS (0x0020) value: reserved(0) + family + port^cookie>>16 + addr^mask
            byte[] raw = observed.Address.GetAddressBytes();
            bool v4 = raw.Length == 4;
            byte[] value = new byte[4 + raw.Length];
            value[1] = (byte)(v4 ? 0x01 : 0x02);
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2), (ushort)(observed.Port ^ (Cookie >> 16)));
            for (int i = 0; i < raw.Length; i++)
            {
                byte mask = i < 4 ? (byte)(Cookie >> (24 - i * 8)) : txid[i - 4];
                value[4 + i] = (byte)(raw[i] ^ mask);
            }

            int padded = (value.Length + 3) & ~3;
            byte[] msg = new byte[20 + 4 + padded];
            BinaryPrimitives.WriteUInt16BigEndian(msg, 0x0101); // binding success
            BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(2), (ushort)(4 + padded));
            BinaryPrimitives.WriteUInt32BigEndian(msg.AsSpan(4), Cookie);
            txid.CopyTo(msg, 8);
            BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(20), 0x0020);
            BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(22), (ushort)value.Length);
            value.CopyTo(msg, 24);
            return msg;
        }
    }

    public void Dispose()
    {
        _running = false;
        _udp.Dispose();
    }
}

public sealed class StunTests
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task Probe_ResolvesMappedAddress_V4()
    {
        using FakeStunServer server = new();
        using var peer = new PeerSocket(0x51);

        IPEndPoint mapped = await peer.ProbeStunAsync(server.LocalEndPoint).WaitAsync(DefaultTimeout);

        // The fake reports whatever endpoint it observed — the client's own loopback address and port.
        Assert.Equal(IPAddress.Loopback, mapped.Address);
        Assert.Equal(peer.LocalPort, mapped.Port);
        Assert.Equal(mapped, peer.PublicAddress);
    }

    [Fact]
    public async Task Probe_ResolvesMappedAddress_V6()
    {
        using FakeStunServer server = new(ipv6: true);
        using var peer = new PeerSocket(0x52);

        IPEndPoint mapped = await peer.ProbeStunAsync(server.LocalEndPoint).WaitAsync(DefaultTimeout);

        Assert.Equal(IPAddress.IPv6Loopback, mapped.Address);
        Assert.Equal(peer.LocalPort, mapped.Port);
    }

    [Fact]
    public async Task Probe_IgnoresMismatchedTransactionId()
    {
        using FakeStunServer server = new() { SendDecoyFirst = true };
        using var peer = new PeerSocket(0x53);

        IPEndPoint mapped = await peer.ProbeStunAsync(server.LocalEndPoint).WaitAsync(DefaultTimeout);
        Assert.Equal(peer.LocalPort, mapped.Port);
    }

    [Fact]
    public async Task Probe_ConcurrentCalls_AllResolveAndAgree()
    {
        using FakeStunServer server = new();
        using var peer = new PeerSocket(0x54);

        Task<IPEndPoint>[] probes =
        [
            peer.ProbeStunAsync(server.LocalEndPoint),
            peer.ProbeStunAsync(server.LocalEndPoint),
            peer.ProbeStunAsync(server.LocalEndPoint),
            peer.ProbeStunAsync(server.LocalEndPoint),
        ];

        IPEndPoint[] results = await Task.WhenAll(probes).WaitAsync(DefaultTimeout);
        Assert.All(results, r => Assert.Equal(peer.LocalPort, r.Port));
        Assert.Single(results.Select(r => r.ToString()).Distinct());
    }
}
