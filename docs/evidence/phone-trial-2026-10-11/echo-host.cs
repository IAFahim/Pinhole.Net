using Pinhole;

// Online echo peer for the Android device-test harness: binds with production
// defaults (STUN, iroh relays, mDNS, port mapping, network watch), prints its
// connection string, accepts one peer, and echoes every datagram back.
await using var node = await PinholeNode.BindAsync(new PinholeOptions { ReceiveBufferCapacity = 256, EnableDirectUdp = false, EnablePortMapping = false });
Console.WriteLine("TICKET " + node.ConnectionString);
await using var peer = await node.AcceptAsync();
Console.WriteLine($"PEER encrypted={peer.IsEncrypted} kind={peer.Path.Kind} remote={peer.Path.Remote}");
long echoes = 0;
while (true)
{
    ReadOnlyMemory<byte>? received = await peer.ReceiveAsync();
    if (received is { } payload)
    {
        var kindBefore = peer.Path.Kind;
        peer.Send(payload.Span);
        if (++echoes <= 5 || echoes % 50 == 0)
            Console.WriteLine($"echo {echoes} rxpath={kindBefore} txpath={peer.Path.Kind}");
    }
}
