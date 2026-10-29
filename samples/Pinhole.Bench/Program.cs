using System.Diagnostics;
using Pinhole;

int count = args.Length > 0 && int.TryParse(args[0], out int n) ? n : 300_000;
int payloadSize = args.Length > 1 && int.TryParse(args[1], out int p) ? p : 64;
payloadSize = Math.Clamp(payloadSize, 1, PinholeConnection.MaxPayload);

PinholeOptions options = new()
{
    StunServers = [],
    Relays = [],
    IrohRelayUrls = [], DerpRelayUrls = [],
    PublishIrohAddress = false,
    EnableLanDiscovery = false,
    EnableNetworkWatch = false,
    EnablePathValidation = false,
    EnablePortMapping = false,
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

const int Warmup = 20_000;
for (int i = 0; i < Warmup; i++)
{
    sendSide.Send(payload);
}

var warmupDrain = Stopwatch.StartNew();
while (Volatile.Read(ref delivered) < Warmup && warmupDrain.Elapsed < TimeSpan.FromSeconds(5))
{
    await Task.Delay(10);
}

long allocStart = GC.GetAllocatedBytesForCurrentThread();
long totalAllocStart = GC.GetTotalAllocatedBytes(precise: true);
var sw = Stopwatch.StartNew();
for (int i = 0; i < count; i++)
{
    sendSide.Send(payload);
}

sw.Stop();
long allocDelta = GC.GetAllocatedBytesForCurrentThread() - allocStart;

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

Console.WriteLine($"whole-process allocations: {totalAllocDelta} bytes total ({totalPerDatagram:0.000} bytes per datagram sent and received)");
