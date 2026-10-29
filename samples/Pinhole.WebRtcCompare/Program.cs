using System.Diagnostics;
using System.Net;
using Pinhole;
using SIPSorcery.Net;

const int RttRounds = 500;
const int TputMessages = 10_000;
const int TputPayload = 1200;
const int RttPayload = 32;
TimeSpan Budget = TimeSpan.FromSeconds(180);

Console.WriteLine("sipsorcery_version=10.0.17");
await RunWebRtcAsync(reliable: true, tag: "webrtc_reliable");
await RunWebRtcAsync(reliable: false, tag: "webrtc_unreliable");
await RunPinholeAsync(tag: "pinhole_udp");
return 0;

async Task RunWebRtcAsync(bool reliable, string tag)
{
    long allocBefore = GC.GetTotalAllocatedBytes(precise: true);
    var sw = Stopwatch.StartNew();

    var config = new RTCConfiguration { iceServers = [] };
    using var server = new RTCPeerConnection(config);
    using var client = new RTCPeerConnection(config);

    var echoReady = new TaskCompletionSource<RTCDataChannel>(TaskCreationOptions.RunContinuationsAsynchronously);
    var opens = new List<Task>();
    var serverOpen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    client.ondatachannel += ch =>
    {
        if (ch.IsOpened) serverOpen.TrySetResult();
        else ch.onopen += () => serverOpen.TrySetResult();
        echoReady.TrySetResult(ch);
    };

    var channelInit = reliable
        ? new RTCDataChannelInit()
        : new RTCDataChannelInit { ordered = false, maxRetransmits = 0 };
    RTCDataChannel hostChannel = await server.createDataChannel("pinhole-probe", channelInit);

    var offer = server.createOffer();
    await server.setLocalDescription(offer);
    client.setRemoteDescription(offer);
    var answer = client.createAnswer();
    server.setRemoteDescription(answer);
    await client.setLocalDescription(answer);

    var stateDump = Task.Run(async () =>
    {
        for (int i = 0; i < 12; i++)
        {
            await Task.Delay(500);
            Console.Error.WriteLine($"[t+{i * 0.5:F1}s] conn={server.connectionState} ice={server.iceConnectionState} gathering={server.iceGatheringState} chopen={hostChannel.IsOpened} ready={echoReady.Task.IsCompleted}");
        }
    });
    RTCDataChannel echoChannel = await echoReady.Task.WaitAsync(Budget);
    await serverOpen.Task.WaitAsync(Budget);

    TaskCompletionSource gate = NewGate();
    echoChannel.onmessage += OnMessage;
    void OnMessage(RTCDataChannel _, DataChannelPayloadProtocols __, byte[] ___) => gate.TrySetResult();

    byte[] hello = new byte[RttPayload];
    hostChannel.send(hello);
    await gate.Task.WaitAsync(Budget);
    double connectMs = sw.Elapsed.TotalMilliseconds;

    byte[] ping = new byte[RttPayload];
    var rtts = new long[RttRounds];
    for (int i = 0; i < RttRounds; i++)
    {
        var single = Stopwatch.StartNew();
        hostChannel.send(ping);
        await gate.Task.WaitAsync(Budget);
        gate = NewGate();
        rtts[i] = single.ElapsedTicks;
    }
    double p50Us = Sorted(rtts, 0.50), p95Us = Sorted(rtts, 0.95);

    long drained = 0;
    var done = NewGate();
    echoChannel.onmessage -= OnMessage;
    void Count(RTCDataChannel _, DataChannelPayloadProtocols __, byte[] ___)
    {
        if (Interlocked.Increment(ref drained) >= TputMessages) done.TrySetResult();
    }
    echoChannel.onmessage += Count;
    byte[] payload = new byte[TputPayload];
    var tput = Stopwatch.StartNew();
    long backpressureYields = 0;
    for (int i = 0; i < TputMessages; i++)
    {

        if (hostChannel.bufferedAmount > 4 * 1024 * 1024)
        {
            backpressureYields++;
            await Task.Delay(1);
        }
        hostChannel.send(payload);
    }
    var watch = Task.Run(async () =>
    {
        for (int i = 0; i < 30; i++)
        {
            await Task.Delay(1000);
            Console.Error.WriteLine($"[drain t+{i}s] drained={Volatile.Read(ref drained)}/{TputMessages}");
        }
    });
    await done.Task.WaitAsync(Budget);
    tput.Stop();

    long allocMb = (GC.GetTotalAllocatedBytes(precise: true) - allocBefore) / (1024 * 1024);
    Report(tag, connectMs, p50Us, p95Us, TputMessages, TputMessages * (long)TputPayload, tput.Elapsed.TotalSeconds, allocMb);
    Console.WriteLine($"{tag}: backpressure_yields={backpressureYields} buffered_amount_end={hostChannel.bufferedAmount}");
    server.close();
    client.close();

    static TaskCompletionSource NewGate() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

async Task RunPinholeAsync(string tag)
{
    long allocBefore = GC.GetTotalAllocatedBytes(precise: true);
    var sw = Stopwatch.StartNew();

    var options = new PinholeOptions
    {
        Bind = new IPEndPoint(IPAddress.Loopback, 0),
        StunServers = [], Relays = [], IrohRelayUrls = [], DerpRelayUrls = [],
        PublishIrohAddress = false, EnableNetworkWatch = false, EnablePortMapping = false,
        EnableLanDiscovery = false, EnablePathValidation = false, ReceiveBufferCapacity = 4096,
    };
    await using var listener = await PinholeNode.BindAsync(options);
    await using var dialer = await PinholeNode.BindAsync(options);

    Task<PinholeConnection> accepted = listener.AcceptAsync();
    await using var outgoing = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Budget);
    await using var incoming = await accepted.WaitAsync(Budget);

    TaskCompletionSource gate = NewGate();
    incoming.Received += OnReceived;
    void OnReceived(ReadOnlySpan<byte> _) => gate.TrySetResult();

    byte[] hello = new byte[RttPayload];
    outgoing.Send(hello);
    await gate.Task.WaitAsync(Budget);
    double connectMs = sw.Elapsed.TotalMilliseconds;

    byte[] ping = new byte[RttPayload];
    var rtts = new long[RttRounds];
    for (int i = 0; i < RttRounds; i++)
    {
        var single = Stopwatch.StartNew();
        outgoing.Send(ping);
        await gate.Task.WaitAsync(Budget);
        gate = NewGate();
        rtts[i] = single.ElapsedTicks;
    }
    double p50Us = Sorted(rtts, 0.50), p95Us = Sorted(rtts, 0.95);

    long drained = 0;
    var done = NewGate();
    incoming.Received -= OnReceived;
    incoming.Received += (ReadOnlySpan<byte> _) => { if (Interlocked.Increment(ref drained) >= TputMessages) done.TrySetResult(); };
    byte[] payload = new byte[TputPayload];
    var tput = Stopwatch.StartNew();
    for (int i = 0; i < TputMessages; i++) outgoing.Send(payload);
    var watch = Task.Run(async () =>
    {
        for (int i = 0; i < 30; i++)
        {
            await Task.Delay(1000);
            Console.Error.WriteLine($"[drain t+{i}s] drained={Volatile.Read(ref drained)}/{TputMessages}");
        }
    });
    await done.Task.WaitAsync(Budget);
    tput.Stop();

    long allocMb = (GC.GetTotalAllocatedBytes(precise: true) - allocBefore) / (1024 * 1024);
    Report(tag, connectMs, p50Us, p95Us, TputMessages, TputMessages * (long)TputPayload, tput.Elapsed.TotalSeconds, allocMb);

    static TaskCompletionSource NewGate() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

static double Sorted(long[] ticks, double q)
{
    Array.Sort(ticks);
    return ticks[(int)(ticks.Length * q)] * 1_000_000.0 / Stopwatch.Frequency;
}

static void Report(string tag, double connectMs, double p50Us, double p95Us,
    long messages, long bytes, double seconds, long allocMb) =>
    Console.WriteLine(
        $"{tag}: connect_ms={connectMs:F1} rtt_p50_us={p50Us:F0} rtt_p95_us={p95Us:F0} " +
        $"tput_msg_s={messages / seconds:F0} tput_bytes_s={bytes / seconds:F0} " +
        $"alloc_mb={allocMb} workingset_mb={Environment.WorkingSet / (1024 * 1024)}");
