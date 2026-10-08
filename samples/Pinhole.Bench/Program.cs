using System.Diagnostics;
using Pinhole;

// Non-interactive throughput/allocation canary for the direct UDP path. Two nodes on
// loopback, no stdin, no public infrastructure, no STUN, no relays — deterministic on
// every OS and CI runner. Usage: dotnet run -c Release [-- <datagrams> <payloadBytes>]
//   default: 300000 datagrams of 64 bytes. Output (parsed by .github/workflows/ci.yml):
//   "<dps> dps, <bytes> B/dgram (<count> datagrams x <payload> B, <delivered> delivered)"

int count = args.Length > 0 && int.TryParse(args[0], out int n) ? n : 300_000;
int payloadSize = args.Length > 1 && int.TryParse(args[1], out int p) ? p : 64;
payloadSize = Math.Clamp(payloadSize, 1, PinholeConnection.MaxPayload);

// Path validation is transport maintenance for live connections; a one-way firehose has
// nothing to validate, so it is opted out here to keep the numbers about sending.
PinholeOptions options = new()
{
    StunServers = [],
    Relays = [],
    IrohRelayUrls = [],
    PublishIrohAddress = false,
    EnableLanDiscovery = false,
    EnableNetworkWatch = false,
    EnablePathValidation = false,
    EnablePortMapping = false, // no router on loopback; keep the allocation counters pure
};

await using PinholeNode receiver = await PinholeNode.BindAsync(options);
await using PinholeNode sender = await PinholeNode.BindAsync(options);

Task<PinholeConnection> accept = receiver.AcceptAsync();
await using PinholeConnection sendSide = await sender.ConnectAsync(receiver.ConnectionString).WaitAsync(TimeSpan.FromSeconds(10));
await using PinholeConnection recvSide = await accept.WaitAsync(TimeSpan.FromSeconds(10));

long delivered = 0;
recvSide.Received += _ => Interlocked.Increment(ref delivered);

byte[] payload = new byte[payloadSize];
payload.AsSpan().Fill(0xB7);

// Warm up: JIT, socket buffers, and the NAT-less loopback path before any measurement.
const int Warmup = 20_000;
for (int i = 0; i < Warmup; i++)
{
    sendSide.Send(payload);
}

var warmupDrain = Stopwatch.StartNew();
while (Volatile.Read(ref delivered) < Warmup && warmupDrain.Elapsed < TimeSpan.FromSeconds(5))
{
    await Task.Delay(10); // let the warmup datagrams land before measuring
}

// Measure allocations on the sending thread: the loop below is fully synchronous, so the
// delta around it is exactly what one datagram's Send costs (stack only, by contract). The
// process-wide counter adds the receive path: the engine's recv thread and any GC work it
// triggers, which the sender-thread number alone cannot see.
long allocStart = GC.GetAllocatedBytesForCurrentThread();
long totalAllocStart = GC.GetTotalAllocatedBytes(precise: true);
var sw = Stopwatch.StartNew();
for (int i = 0; i < count; i++)
{
    sendSide.Send(payload);
}

sw.Stop();
long allocDelta = GC.GetAllocatedBytesForCurrentThread() - allocStart;

// Give late loopback datagrams a moment to land before closing the window. Thread.Sleep,
// not Task.Delay: the whole-process counter below must not count async machinery.
var drain = Stopwatch.StartNew();
while (Volatile.Read(ref delivered) < count && drain.Elapsed < TimeSpan.FromSeconds(2))
{
    Thread.Sleep(20);
}

long totalAllocDelta = GC.GetTotalAllocatedBytes(precise: true) - totalAllocStart;

double dps = count / sw.Elapsed.TotalSeconds;
double bytesPerDatagram = (double)allocDelta / count;
double totalPerDatagram = (double)totalAllocDelta / count;
Console.WriteLine($"{dps:0} dps, {bytesPerDatagram:0.000} B/dgram ({count} datagrams x {payloadSize} B, {Volatile.Read(ref delivered)} delivered)");
// Phrased to avoid the strings CI's canary greps for: this line reports the whole process
// (sending thread + receive thread + GC), the line above only the sending thread.
Console.WriteLine($"whole-process allocations: {totalAllocDelta} bytes total ({totalPerDatagram:0.000} bytes per datagram sent and received)");
