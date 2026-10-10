using System.Diagnostics;
using System.Net.Quic;
using System.Security.Cryptography;
using System.Text.Json;
using Pinhole.Moq;

if (args.Length != 2 || args[0] != "--credentials")
{
    Console.WriteLine("Usage: Pinhole.MoqProbe --credentials /private/file.json"); return 2;
}
var stage = "credentials";
var watch = Stopwatch.StartNew();
try
{
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
    using var secrets = JsonDocument.Parse(await File.ReadAllTextAsync(args[1], timeout.Token));
    var publishToken = secrets.RootElement.GetProperty("publishSubscribeToken").GetString() ?? throw new InvalidOperationException();
    var subscribeToken = secrets.RootElement.GetProperty("subscribeToken").GetString() ?? throw new InvalidOperationException();
    var topic = "pinhole-test-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
    stage = "connect_a";
    await using var a = await CloudflareMoqClient.ConnectAsync(publishToken, timeout.Token);
    stage = "connect_b";
    await using var b = await CloudflareMoqClient.ConnectAsync(publishToken, timeout.Token);
    stage = "connect_observer";
    await using var observer = await CloudflareMoqClient.ConnectAsync(subscribeToken, timeout.Token);
    var connectedMs = watch.Elapsed.TotalMilliseconds;
    stage = "publish_a";
    var outgoingA = await a.CreatePublisherAsync(topic + "-a", "messages", timeout.Token);
    stage = "publish_b";
    var outgoingB = await b.CreatePublisherAsync(topic + "-b", "messages", timeout.Token);
    stage = "subscribe_a";
    await using var incomingA = await a.SubscribeAsync(topic + "-b", "messages", timeout.Token);
    stage = "subscribe_b";
    await using var incomingB = await b.SubscribeAsync(topic + "-a", "messages", timeout.Token);
    stage = "subscribe_observer";
    await using var observed = await observer.SubscribeAsync(topic + "-a", "messages", timeout.Token);
    stage = "messages";
    var rtts = new List<double>();
    using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    for (var sequence = 0; sequence < 48; sequence++)
    {
        var payload = new byte[256]; RandomNumberGenerator.Fill(payload); BitConverter.TryWriteBytes(payload.AsSpan(), sequence);
        var echoWatch = Stopwatch.StartNew();
        await outgoingA.PublishAsync(payload, timeout.Token);
        var atB = await incomingB.ReadAsync(timeout.Token);
        var atObserver = await observed.ReadAsync(timeout.Token);
        if (!payload.AsSpan().SequenceEqual(atB.Payload.Span) || !payload.AsSpan().SequenceEqual(atObserver.Payload.Span))
            throw new InvalidDataException("Object mismatch");
        await outgoingB.PublishAsync(atB.Payload, timeout.Token);
        var atA = await incomingA.ReadAsync(timeout.Token);
        if (!payload.AsSpan().SequenceEqual(atA.Payload.Span)) throw new InvalidDataException("Echo mismatch");
        rtts.Add(echoWatch.Elapsed.TotalMilliseconds); digest.AppendData(payload);
    }
    stage = "object_size_boundaries";
    foreach (var size in new[] { 0, CloudflareMoqClient.MaximumObjectBytes })
    {
        var payload = RandomNumberGenerator.GetBytes(size);
        await outgoingA.PublishAsync(payload, timeout.Token);
        var atB = await incomingB.ReadAsync(timeout.Token);
        var atObserver = await observed.ReadAsync(timeout.Token);
        if (!payload.AsSpan().SequenceEqual(atB.Payload.Span) || !payload.AsSpan().SequenceEqual(atObserver.Payload.Span))
            throw new InvalidDataException("Boundary object mismatch");
        await outgoingB.PublishAsync(atB.Payload, timeout.Token);
        var atA = await incomingA.ReadAsync(timeout.Token);
        if (!payload.AsSpan().SequenceEqual(atA.Payload.Span)) throw new InvalidDataException("Boundary echo mismatch");
        digest.AppendData(payload);
    }
    var overLimitRejected = false;
    try { await outgoingA.PublishAsync(new byte[CloudflareMoqClient.MaximumObjectBytes + 1], timeout.Token); }
    catch (ArgumentOutOfRangeException) { overLimitRejected = true; }
    if (!overLimitRejected) throw new InvalidDataException("Object limit not enforced");
    stage = "subscribe_only_publish_rejection";
    var subscribeOnlyRejected = false;
    ulong subscribeOnlyError = 0;
    try { await observer.CreatePublisherAsync(topic + "-negative", "forbidden", timeout.Token); }
    catch (MoqRequestException error) when (error.ErrorCode is 1 or 32) { subscribeOnlyRejected = true; subscribeOnlyError = error.ErrorCode; }
    if (!subscribeOnlyRejected) throw new InvalidDataException("Subscribe-only publication was not rejected");
    stage = "same_target_publish_positive_control";
    var positiveControl = await a.CreatePublisherAsync(topic + "-negative", "forbidden", timeout.Token);
    stage = "invalid_signature_rejection";
    var segments = publishToken.Split('.'); var signature = segments[2].ToCharArray(); signature[0] = signature[0] == 'A' ? 'B' : 'A';
    var badToken = segments[0] + "." + segments[1] + "." + new string(signature);
    var invalidSignatureRejected = false;
    long? invalidSignatureError = null;
    ulong? invalidSignatureRequestError = null;
    try
    {
        await using var invalid = await CloudflareMoqClient.ConnectAsync(badToken, timeout.Token);
        await using var forbidden = await invalid.SubscribeAsync(topic + "-a", "messages", timeout.Token);
    }
    catch (QuicException error) when (error.QuicError == QuicError.ConnectionAborted && error.ApplicationErrorCode is 2 or 3)
    { invalidSignatureRejected = true; invalidSignatureError = error.ApplicationErrorCode; }
    catch (MoqRequestException error) when (error.ErrorCode is 1 or 32)
    { invalidSignatureRejected = true; invalidSignatureRequestError = error.ErrorCode; }
    if (!invalidSignatureRejected) throw new InvalidDataException("Invalid token was not rejected");
    stage = "cleanup";
    await observed.DisposeAsync(); await incomingB.DisposeAsync(); await incomingA.DisposeAsync();
    await observer.DisposeAsync(); await b.DisposeAsync(); await a.DisposeAsync();
    stage = "complete";
    rtts.Sort();
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        status = "PASS", stage, service = "Cloudflare MoQ", draft = 16, transport = "native QUIC reliable subgroup streams",
        tlsCertificateValidated = true, relayVerified = true, messagesEachDirection = 50, observerMessages = 50, regularObjectBytes = 256, boundaryObjectBytes = new[] { 0, CloudflareMoqClient.MaximumObjectBytes }, overLimitRejected, cleanupCompleted = true,
        connectedMs = Math.Round(connectedMs, 2), elapsedMs = Math.Round(watch.Elapsed.TotalMilliseconds, 2),
        rttP50Ms = Math.Round(rtts[24], 2), rttP95Ms = Math.Round(rtts[45], 2),
        subscribeOnlyPublishRejected = subscribeOnlyRejected, subscribeOnlyError, sameTargetPublishPositiveControl = true, invalidSignatureRejected, invalidSignatureError, invalidSignatureRequestError,
        payloadDigest = Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant(),
        runtime = Environment.Version.ToString()
    }));
    return 0;
}
catch (Exception error)
{
    Console.WriteLine(JsonSerializer.Serialize(new { status = "FAIL", stage, exception = error.GetType().Name,
        quicError = error is QuicException q ? q.QuicError.ToString() : null,
        applicationError = error is QuicException a ? a.ApplicationErrorCode : null,
        requestError = error is MoqRequestException r ? (ulong?)r.ErrorCode : null,
        elapsedMs = Math.Round(watch.Elapsed.TotalMilliseconds, 2) }));
    return 1;
}
