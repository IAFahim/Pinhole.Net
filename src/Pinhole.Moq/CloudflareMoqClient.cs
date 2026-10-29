using System.Collections.Concurrent;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Text;
using System.Threading.Channels;

namespace Pinhole.Moq;

public sealed class CloudflareMoqClient : IAsyncDisposable
{
    public const string EndpointHost = "draft-16.cloudflare.mediaoverquic.com";
    public const int MaximumObjectBytes = 65536;
    private const int MaximumTracks = 32;
    private readonly QuicConnection _connection;
    private readonly QuicStream _control;
    private readonly CancellationTokenSource _stop = new();
    private readonly SemaphoreSlim _send = new(1, 1);
    private readonly ConcurrentDictionary<ulong, PendingRequest> _pending = new();
    private readonly ConcurrentDictionary<ulong, MoqSubscription> _subscriptions = new();
    private readonly ConcurrentDictionary<ulong, MoqSubscription> _aliases = new();
    private readonly ConcurrentDictionary<ulong, MoqPublisher> _publishRequests = new();
    private readonly ConcurrentDictionary<string, MoqPublisher> _publishers = new(StringComparer.Ordinal);
    private readonly HashSet<string> _namespaces = [];
    private readonly SemaphoreSlim _registration = new(1, 1);
    private readonly Task _controlTask;
    private readonly Task _dataTask;
    private TaskCompletionSource _aliasChanged = NewSignal();
    private readonly MoqRequestIds _requestIds;
    private readonly MoqPeerRequestIds _peerRequestIds;
    private ulong _nextAlias;
    private int _disposed;
    private int _subscriptionReservations;
    private Exception? _failure;

    private CloudflareMoqClient(QuicConnection connection, QuicStream control, ulong maxRequestId)
    {
        _connection = connection; _control = control; _requestIds = new(maxRequestId);
        _peerRequestIds = new MoqPeerRequestIds(256);
        _controlTask = ReadControlAsync(); _dataTask = ReadDataAsync();
    }

    public static async Task<CloudflareMoqClient> ConnectAsync(string token, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        if (token.Length > 4096 || token.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')))
            throw new ArgumentException("Expected a MoQ bearer token", nameof(token));
        if (!QuicConnection.IsSupported) throw new PlatformNotSupportedException("System.Net.Quic requires platform QUIC support");
        using var deadline = Deadline(cancellationToken);
        var connection = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
        {
            RemoteEndPoint = new DnsEndPoint(EndpointHost, 443),
            DefaultCloseErrorCode = 0, DefaultStreamErrorCode = 0,
            MaxInboundUnidirectionalStreams = 16, MaxInboundBidirectionalStreams = 0,
            IdleTimeout = TimeSpan.FromSeconds(60),
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                TargetHost = EndpointHost,
                ApplicationProtocols = [new SslApplicationProtocol("moqt-16")]
            }
        }, deadline.Token);
        QuicStream? control = null;
        try
        {
            control = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, deadline.Token);
            var writer = new MoqWriter();
            writer.Parameters((1, Encoding.UTF8.GetBytes("/" + token)), (2, 256UL), (5, Encoding.UTF8.GetBytes(EndpointHost)),
                (7, Encoding.UTF8.GetBytes("Pinhole.Moq experimental Draft16")));
            var setup = writer.Message(0x20);
            try { await control.WriteAsync(setup, deadline.Token); }
            finally { Array.Clear(setup); }
            var message = await MoqStreamWire.ReadMessageAsync(control, deadline.Token);
            if (message.Type != 0x21) throw new MoqProtocolException("Expected SERVER_SETUP");
            var reader = new MoqReader(message.Payload); var parameters = reader.Parameters(); reader.End();
            if (parameters.ContainsKey(1) || parameters.ContainsKey(5)) throw new MoqProtocolException("Server sent client-only setup parameters");
            return new CloudflareMoqClient(connection, control, parameters.TryGetValue(2, out var value) ? (ulong)value : 0);
        }
        catch
        {
            if (control is not null) await control.DisposeAsync();
            await connection.DisposeAsync(); throw;
        }
    }

    public async Task<MoqPublisher> CreatePublisherAsync(string trackNamespace, string trackName, CancellationToken cancellationToken = default)
    {
        ValidateName(trackNamespace, trackName);
        using var deadline = Deadline(cancellationToken, _stop.Token);
        await _registration.WaitAsync(deadline.Token);
        try
        {
            ThrowIfStopped();
            if (_namespaces.Count >= MaximumTracks && !_namespaces.Contains(trackNamespace)) throw new InvalidOperationException("MoQ namespace limit reached");
            if (_publishers.Count >= MaximumTracks) throw new InvalidOperationException("MoQ track limit reached");
            var key = TrackKey(trackNamespace, trackName);
            var publisher = new MoqPublisher(this, trackNamespace, trackName, _nextAlias++);
            if (!_publishers.TryAdd(key, publisher)) throw new InvalidOperationException("Track already published");
            try
            {
                if (!_namespaces.Contains(trackNamespace))
                {
                    await RequestAsync(0x6, writer => { writer.Namespace(trackNamespace); writer.Parameters(); }, null, deadline.Token);
                    _namespaces.Add(trackNamespace);
                }
                var response = await RequestAsync(0x1d, writer =>
                {
                    writer.Namespace(trackNamespace); writer.Text(trackName); writer.Integer(publisher.Alias); writer.Parameters();
                }, publisher, deadline.Token);
                if (response.Type != 0x1e) throw new MoqProtocolException("Expected PUBLISH_OK");
                return publisher;
            }
            catch { _publishers.TryRemove(key, out _); throw; }
        }
        finally { _registration.Release(); }
    }

    public async Task<MoqSubscription> SubscribeAsync(string trackNamespace, string trackName, CancellationToken cancellationToken = default)
    {
        ValidateName(trackNamespace, trackName);
        using var deadline = Deadline(cancellationToken, _stop.Token);
        var subscription = new MoqSubscription(this, trackNamespace, trackName);
        var response = await RequestAsync(0x3, writer =>
        {
            writer.Namespace(trackNamespace); writer.Text(trackName);

            writer.Parameters((0x20, 128UL), (0x21, new byte[] { 2 }), (0x22, 1UL));
        }, subscription, deadline.Token);
        if (response.Type != 0x4) throw new MoqProtocolException("Expected SUBSCRIBE_OK");
        return subscription;
    }

    internal async Task SendObjectAsync(MoqPublisher publisher, ulong groupId, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (payload.Length > MaximumObjectBytes) throw new ArgumentOutOfRangeException(nameof(payload));
        using var deadline = Deadline(cancellationToken, _stop.Token);
        ThrowIfStopped();
        await publisher.WaitForForwardAsync(deadline.Token);
        await using var stream = await _connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, deadline.Token);
        var writer = new MoqWriter();
        writer.Integer(0x18); writer.Integer(publisher.Alias); writer.Integer(groupId); writer.Byte(128);
        writer.Integer(0); writer.Integer((ulong)payload.Length);
        if (payload.Length == 0) writer.Integer(0);
        await stream.WriteAsync(writer.ToArray(), deadline.Token);
        await stream.WriteAsync(payload, completeWrites: true, deadline.Token);
        await stream.WritesClosed.WaitAsync(deadline.Token);
    }

    internal async Task UnsubscribeAsync(MoqSubscription subscription)
    {
        if (Interlocked.Exchange(ref subscription.Disposed, 1) != 0) return;
        _subscriptions.TryRemove(subscription.RequestId, out _);

        subscription.Complete(null);
        if (_stop.IsCancellationRequested) return;
        using var deadline = Deadline(_stop.Token);
        var writer = new MoqWriter(); writer.Integer(subscription.RequestId);
        try { await SendControlAsync(writer.Message(0xa), deadline.Token); }
        catch (Exception error) when (error is OperationCanceledException or IOException) { }
    }

    private async Task<Response> RequestAsync(ulong type, Action<MoqWriter> body, object? owner, CancellationToken cancellationToken)
    {
        var completion = new TaskCompletionSource<Response>(TaskCreationOptions.RunContinuationsAsynchronously);
        ulong id;
        await _send.WaitAsync(cancellationToken);
        try
        {
            ThrowIfStopped();
            if (_pending.Count >= 128) throw new InvalidOperationException("MoQ pending request limit reached");
            if (owner is MoqSubscription && _subscriptionReservations >= MaximumTracks)
                throw new InvalidOperationException("MoQ track limit reached");

            id = _requestIds.Allocate();
            if (owner is MoqPublisher publisher) _publishRequests[id] = publisher;
            if (owner is MoqSubscription subscription)
            {
                _subscriptionReservations++;
                subscription.RequestId = id;
                if (!_subscriptions.TryAdd(id, subscription)) throw new MoqProtocolException("Duplicate request ID");
            }
            _pending[id] = new PendingRequest(type, completion, owner);
            var writer = new MoqWriter(); writer.Integer(id); body(writer);
            var message = writer.Message(type);
            try { await _control.WriteAsync(message, cancellationToken); }
            catch (Exception error) { Fail(error); throw; }
        }
        finally { _send.Release(); }
        try { return await completion.Task.WaitAsync(cancellationToken); }
        catch
        {
            _pending.TryRemove(id, out _);
            if (owner is MoqPublisher) _publishRequests.TryRemove(id, out _);
            if (owner is MoqSubscription subscription)
            {
                _subscriptions.TryRemove(id, out _); subscription.Complete(new OperationCanceledException());
            }
            throw;
        }
    }

    private async Task SendControlAsync(byte[] message, CancellationToken cancellationToken)
    {
        await _send.WaitAsync(cancellationToken);
        try { ThrowIfStopped(); await _control.WriteAsync(message, cancellationToken); }
        finally { _send.Release(); }
    }

    private async Task ReadControlAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var message = await MoqStreamWire.ReadMessageAsync(_control, _stop.Token);
                var reader = new MoqReader(message.Payload);
                switch (message.Type)
                {
                    case 0x4: case 0x7: case 0x1e:
                    {
                        var id = reader.Integer();
                        if (!_pending.TryGetValue(id, out var request)) throw new MoqProtocolException("Response for unknown request");
                        var expected = request.Type == 0x3 ? 0x4UL : request.Type == 0x1d ? 0x1eUL : 0x7UL;
                        if (message.Type != expected) throw new MoqProtocolException("Unexpected MoQ response type");
                        if (request.Owner is MoqSubscription subscription && message.Type == 0x4)
                        {
                            var alias = reader.Integer(); subscription.Alias = alias;
                            reader.Parameters(); reader.Extensions(); reader.End();
                            if (!_aliases.TryAdd(alias, subscription)) throw new MoqProtocolException("Duplicate track alias");
                            var previous = Interlocked.Exchange(ref _aliasChanged, NewSignal()); previous.TrySetResult();
                        }
                        else
                        {
                            var parameters = reader.Parameters(); reader.End();
                            if (request.Owner is MoqPublisher publisher)
                            {
                                var forward = parameters.TryGetValue(0x10, out var state) ? (ulong)state : 1UL;
                                if (forward > 1) throw new MoqProtocolException("Invalid forward state");
                                publisher.SetForward(forward == 1);
                            }
                        }
                        _pending.TryRemove(id, out _);
                        request.Completion.TrySetResult(new Response(message.Type, message.Payload)); break;
                    }
                    case 0x5:
                    {
                        var id = reader.Integer(); var error = reader.Integer(); reader.Integer(); reader.Text(); reader.End();
                        if (!_pending.TryRemove(id, out var request)) throw new MoqProtocolException("Error for unknown request");
                        request.Completion.TrySetException(new MoqRequestException(error)); break;
                    }
                    case 0x15:
                    {
                        var maximum = reader.Integer(); reader.End();
                        _requestIds.Extend(maximum); break;
                    }
                    case 0x2:
                    {
                        var id = reader.Integer(); await CheckPeerRequestAsync(id);
                        var existing = reader.Integer(); var parameters = reader.Parameters(); reader.End();
                        if (!_publishRequests.TryGetValue(existing, out var publisher)) throw new MoqProtocolException("Update for unknown publish");
                        if (parameters.TryGetValue(0x10, out var forward))
                        {
                            if ((ulong)forward > 1) throw new MoqProtocolException("Invalid forward state");
                            publisher.SetForward((ulong)forward == 1);
                        }
                        var writer = new MoqWriter(); writer.Integer(id); writer.Parameters();
                        await SendControlAsync(writer.Message(0x7), _stop.Token); break;
                    }
                    case 0x3:
                    {
                        var id = reader.Integer(); await CheckPeerRequestAsync(id);
                        var ns = reader.Namespace(); var name = reader.Text(); reader.Parameters(); reader.End();
                        if (!_publishers.TryGetValue(TrackKey(ns, name), out var publisher))
                        {
                            var failure = new MoqWriter(); failure.Integer(id); failure.Integer(0x10); failure.Integer(0); failure.Text("Unknown track");
                            await SendControlAsync(failure.Message(0x5), _stop.Token); break;
                        }
                        _publishRequests[id] = publisher; publisher.SetForward(true);
                        var writer = new MoqWriter(); writer.Integer(id); writer.Integer(publisher.Alias); writer.Parameters();
                        await SendControlAsync(writer.Message(0x4), _stop.Token); break;
                    }
                    case 0xa:
                    {
                        var id = reader.Integer(); reader.End();
                        if (_publishRequests.TryRemove(id, out var publisher)) publisher.SetForward(false);
                        break;
                    }
                    case 0xb:
                    {
                        var id = reader.Integer(); var status = reader.Integer(); reader.Integer(); reader.Text(); reader.End();
                        if (_subscriptions.TryRemove(id, out var subscription)) subscription.Complete(new MoqRequestException(status));
                        break;
                    }
                    case 0x10:
                        reader.Text(); reader.End(); throw new IOException("MoQ relay requested migration");
                    default: throw new MoqProtocolException($"Unsupported MoQ control type {message.Type}");
                }
            }
        }
        catch (Exception error) { if (!_stop.IsCancellationRequested) Fail(error); }
    }

    private async Task CheckPeerRequestAsync(ulong id)
    {
        _peerRequestIds.Admit(id);

        if (_peerRequestIds.ExtensionDue() is { } grant)
        {
            var writer = new MoqWriter(); writer.Integer(grant);
            try { await SendControlAsync(writer.Message(0x15), _stop.Token); }
            catch (Exception error) when (error is OperationCanceledException or IOException) { }
        }
    }

    private async Task ReadDataAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var stream = await _connection.AcceptInboundStreamAsync(_stop.Token);
                if (stream.Type != QuicStreamType.Unidirectional) throw new MoqProtocolException("Unexpected bidirectional stream");

                _ = PumpStreamAsync(stream);
            }
        }
        catch (Exception error) { if (!_stop.IsCancellationRequested) Fail(error); }
    }

    private static readonly TimeSpan SubgroupIdleTimeout = TimeSpan.FromSeconds(15);

    private async Task PumpStreamAsync(QuicStream stream)
    {
        try
        {
            await using (stream)
            {
                await MoqSessionPump.ProcessSubgroupStreamAsync(stream, WaitAliasAsync, _stop.Token, SubgroupIdleTimeout);
            }
        }
        catch (OperationCanceledException) when (!_stop.IsCancellationRequested)
        {

        }
        catch (OperationCanceledException)
        {

        }
        catch (Exception error) { if (!_stop.IsCancellationRequested) Fail(error); }
    }

    private async Task<MoqSubscription> WaitAliasAsync(ulong alias, CancellationToken ct)
    {
        using var bound = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bound.CancelAfter(TimeSpan.FromSeconds(5));
        while (true)
        {
            var changed = Volatile.Read(ref _aliasChanged);
            if (_aliases.TryGetValue(alias, out MoqSubscription? subscription)) return subscription;
            await changed.Task.WaitAsync(bound.Token);
        }
    }

    private void Fail(Exception error)
    {
        if (Interlocked.CompareExchange(ref _failure, error, null) is not null) return;
        foreach (var request in _pending.Values) request.Completion.TrySetException(error);
        foreach (var subscription in _subscriptions.Values) subscription.Complete(error);
        foreach (var publisher in _publishers.Values) publisher.Stop(error);
        _stop.Cancel();
    }
    private void ThrowIfStopped()
    {
        if (_failure is not null) throw new IOException("MoQ session failed", _failure);
        if (_stop.IsCancellationRequested) throw new ObjectDisposedException(nameof(CloudflareMoqClient));
    }
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _stop.Cancel();
        foreach (var request in _pending.Values) request.Completion.TrySetCanceled();
        foreach (var subscription in _subscriptions.Values) subscription.Complete(null);
        foreach (var publisher in _publishers.Values) publisher.Stop(new ObjectDisposedException(nameof(CloudflareMoqClient)));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try { await _connection.CloseAsync(0, deadline.Token); }
        catch (Exception error) when (error is OperationCanceledException or QuicException) { }
        await _control.DisposeAsync(); await _connection.DisposeAsync();
        await Task.WhenAll(_controlTask, _dataTask);

    }
    private static CancellationTokenSource Deadline(CancellationToken token, CancellationToken second = default)
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(token, second); source.CancelAfter(TimeSpan.FromSeconds(15)); return source;
    }
    private static void ValidateName(string trackNamespace, string trackName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trackNamespace); ArgumentException.ThrowIfNullOrWhiteSpace(trackName);
        if (trackNamespace.Contains('\0') || trackName.Contains('\0')) throw new ArgumentException("Track names cannot contain NUL");
        var utf8 = new UTF8Encoding(false, true);
        if (utf8.GetByteCount(trackNamespace) + utf8.GetByteCount(trackName) > 4096)
            throw new ArgumentOutOfRangeException(nameof(trackName));
    }
    private static string TrackKey(string ns, string name) => ns + "\0" + name;
    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private sealed record PendingRequest(ulong Type, TaskCompletionSource<Response> Completion, object? Owner);
    private sealed record Response(ulong Type, byte[] Payload);
}

public sealed record MoqObject(ulong GroupId, ulong ObjectId, ReadOnlyMemory<byte> Payload);

public sealed class MoqPublisher
{
    private readonly CloudflareMoqClient _client;
    private readonly SemaphoreSlim _send = new(1, 1);
    private readonly object _gate = new();
    private TaskCompletionSource _forward = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private ulong _nextGroup;
    internal ulong Alias { get; }
    public string TrackNamespace { get; }
    public string TrackName { get; }
    internal MoqPublisher(CloudflareMoqClient client, string trackNamespace, string trackName, ulong alias)
    { _client = client; TrackNamespace = trackNamespace; TrackName = trackName; Alias = alias; }
    public async Task PublishAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        if (payload.Length > CloudflareMoqClient.MaximumObjectBytes) throw new ArgumentOutOfRangeException(nameof(payload));
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        await _send.WaitAsync(deadline.Token);
        try { await _client.SendObjectAsync(this, _nextGroup++, payload, deadline.Token); }
        finally { _send.Release(); }
    }
    internal void SetForward(bool value)
    {
        lock (_gate)
        {
            if (value) _forward.TrySetResult();
            else if (_forward.Task.IsCompletedSuccessfully) _forward = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }
    internal Task WaitForForwardAsync(CancellationToken token) { lock (_gate) return _forward.Task.WaitAsync(token); }
    internal void Stop(Exception error) { lock (_gate) _forward.TrySetException(error); }
}

public sealed class MoqSubscription : IAsyncDisposable
{
    private readonly CloudflareMoqClient _client;
    private readonly Channel<MoqObject> _objects = Channel.CreateBounded<MoqObject>(new BoundedChannelOptions(16)
    { SingleWriter = true, SingleReader = false, FullMode = BoundedChannelFullMode.Wait });
    internal ulong RequestId;
    internal ulong Alias;
    internal int Disposed;
    public string TrackNamespace { get; }
    public string TrackName { get; }
    internal MoqSubscription(CloudflareMoqClient client, string trackNamespace, string trackName)
    { _client = client; TrackNamespace = trackNamespace; TrackName = trackName; }
    public ValueTask<MoqObject> ReadAsync(CancellationToken cancellationToken = default) => _objects.Reader.ReadAsync(cancellationToken);
    public IAsyncEnumerable<MoqObject> ReadAllAsync(CancellationToken cancellationToken = default) => _objects.Reader.ReadAllAsync(cancellationToken);
    internal ValueTask EnqueueAsync(MoqObject message, CancellationToken cancellationToken) =>
        _objects.Writer.WriteAsync(message, cancellationToken);
    internal void Complete(Exception? error) => _objects.Writer.TryComplete(error);
    public ValueTask DisposeAsync() => new(_client.UnsubscribeAsync(this));
}
