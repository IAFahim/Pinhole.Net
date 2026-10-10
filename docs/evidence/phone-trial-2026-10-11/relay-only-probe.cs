using System.Diagnostics;
using Pinhole;

// Two nodes on this machine, direct UDP disabled on both: the only possible
// path is the iroh relay. Establishes the session and round-trips datagrams,
// printing which stage stalls.
var options = new PinholeOptions
{
    EnableDirectUdp = false, EnablePortMapping = false, EnableLanDiscovery = false,
    EnableNetworkWatch = false, ReceiveBufferCapacity = 16,
};
await using var listener = await PinholeNode.BindAsync(options);
var echoLoop = Task.Run(async () =>
{
    await using var peer = await listener.AcceptAsync();
    Console.WriteLine($"listener accepted kind={peer.Path.Kind} encrypted={peer.IsEncrypted}");
    while (true)
    {
        ReadOnlyMemory<byte>? received = await peer.ReceiveAsync();
        if (received is { } payload) peer.Send(payload.Span);
    }
});
await using var dialer = await PinholeNode.BindAsync(options);
var sw = Stopwatch.StartNew();
await using var conn = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(TimeSpan.FromSeconds(30));
Console.WriteLine($"connect ok in {sw.ElapsedMilliseconds}ms kind={conn.Path.Kind} encrypted={conn.IsEncrypted}");
for (int i = 0; i < 5; i++)
{
    conn.Send(new byte[64]);
    try
    {
        ReadOnlyMemory<byte>? echo = await conn.ReceiveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(8));
        Console.WriteLine($"echo {i}: {(echo is null ? "NULL" : echo.Value.Length.ToString() + " bytes")} kind={conn.Path.Kind} t={sw.ElapsedMilliseconds}ms");
    }
    catch (TimeoutException)
    {
        Console.WriteLine($"echo {i}: TIMEOUT kind={conn.Path.Kind} t={sw.ElapsedMilliseconds}ms");
        break;
    }
}
Console.WriteLine("done");
