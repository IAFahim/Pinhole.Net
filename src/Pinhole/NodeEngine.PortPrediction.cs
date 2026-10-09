using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Pinhole;

internal sealed partial class NodeEngine
{
    private readonly object _predictionGate = new();
    private IUdpSocket? _predictionTrackedSource, _predictionMeasuredSource;
    private readonly HashSet<IPEndPoint> _predictionContactedServers = [];
    private int _predictionMeasuring, _predictionRounds;

    private IPEndPoint[] ReservedPredictionServers()
    {
        if (!_options.EnablePortPrediction || !_options.EnableDirectUdp || _rawReceive is not null
            || _options.Encryption != PinholeEncryption.Required) return [];
        IPEndPoint[] servers = ResolvedStun().Where(s => s.AddressFamily == AddressFamily.InterNetwork && StunBindingMessage.Usable(s)).Distinct().ToArray();
        return servers.Length < 6 ? [] : servers[^PortPrediction.SampleCount..];
    }

    private IReadOnlyList<IPEndPoint> BasicStunServers()
    {
        IPEndPoint[] reserved = ReservedPredictionServers();
        return reserved.Length == 0 ? ResolvedStun() : ResolvedStun().Where(s => !reserved.Contains(s)).ToArray();
    }

    private void TrackPredictionContact(IUdpSocket source, IPEndPoint server)
    {
        if (!_options.EnablePortPrediction || !ReferenceEquals(source, _udp)) return;
        lock (_predictionGate)
        {
            if (!ReferenceEquals(_predictionTrackedSource, source))
            {
                _predictionTrackedSource = source; _predictionContactedServers.Clear(); _predictionRounds = 0;
            }
            if (_predictionContactedServers.Count < 64) _predictionContactedServers.Add(server);
        }
    }

    private bool PredictionAllowed(ConnState c) => _options.EnablePortPrediction && _options.EnableDirectUdp
        && _rawReceive is null && _options.Encryption == PinholeEncryption.Required
        && c.Crypto is { PeerConfirmed: true } && c.PeerCandidatesReceived
        && c.State is PinholeConnectionState.Punching or PinholeConnectionState.Degraded
        && !c.Connected.Task.IsFaulted && !c.Connected.Task.IsCanceled
        && (c.Iroh is { IsAlive: true } && c.IrohConfirmed || c.RelayReady);

    private void MaybeStartPortPrediction(ConnState c)
    {
        if (!PredictionAllowed(c) || (!c.SymmetricHint && ObservedNatHint != NatHint.Symmetric)
            || Environment.TickCount64 - c.LastKickTicks < 1500) return;
        StartPortPrediction(c);
    }

    private void StartPortPrediction(ConnState c)
    {
        lock (c.Gate)
        {
            if (c.Prediction is not null || !PredictionAllowed(c)) return;
            lock (_predictionGate)
            {
                if (_predictionRounds >= 4) return; // cumulative per primary source, including failed negotiations
                _predictionRounds++;
            }
            c.Prediction = new(_udp);
        }
        _ = PortPredictionLoopAsync(c, c.Prediction);
    }

    private void SendPredictionControl(ConnState c, ReadOnlySpan<byte> body)
    {
        if (c.Crypto is not { PeerConfirmed: true }) return;
        Span<byte> frame = stackalloc byte[128];
        int length = BuildFrame(c, FrameType.Predict, body, frame);
        try
        {
            // Coordination must not create additional primary-socket destination
            // mappings after sampling. It stays on an already authenticated relay leg.
            if (c.Iroh is { IsAlive: true } relay && c.IrohConfirmed && c.IrohPeerKey is { } key)
                SendOnArrival(new Arrival(relay, key), frame[..length]);
            else if (c.RelayReady && c.RelayRemote is { } remote)
                SendOnArrival(new Arrival(remote), frame[..length]);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException) { }
    }

    private async Task PortPredictionLoopAsync(ConnState c, PortPredictionState state)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token, c.Dead.Token);
        stop.CancelAfter(TimeSpan.FromSeconds(8));
        try
        {
            byte[] hello = new byte[11]; hello[0] = 1; hello[1] = 0;
            BinaryPrimitives.WriteUInt64LittleEndian(hello.AsSpan(2), state.LocalId);
            hello[10] = (byte)(ObservedNatHint == NatHint.Symmetric || c.SymmetricHint ? 1 : 0);
            for (int attempt = 0; attempt < 4 && !state.PeerCapable; attempt++)
            {
                SendPredictionControl(c, hello);
                await Task.Delay(300, stop.Token).ConfigureAwait(false);
            }
            if (!state.PeerCapable || !PredictionAllowed(c)) return;
            IPEndPoint[]? local = await MeasurePredictionTargetsAsync(state.Source, stop.Token).ConfigureAwait(false);
            if (local is null || local.Length == 0 || !ReferenceEquals(_udp, state.Source)) return;
            lock (c.Gate) state.LocalTargets = local;
            byte[] offer = PortPrediction.Offer(state.LocalId, local);
            for (int attempt = 0; attempt < 30 && !state.Started && PredictionAllowed(c); attempt++)
            {
                SendPredictionControl(c, offer);
                bool ready; lock (c.Gate) ready = state.PeerTargets is not null;
                if (ready && _peerId < c.PeerId) SendPredictionStart(c, state, acknowledgement: false);
                await Task.Delay(150, stop.Token).ConfigureAwait(false);
            }
            if (!state.Started || state.PeerTargets is not { } targets) return;
            for (int round = 0; round < PortPrediction.ProbeRounds && PredictionAllowed(c); round++)
            {
                if (!ReferenceEquals(_udp, state.Source)) return;
                foreach (IPEndPoint target in targets)
                {
                    stop.Token.ThrowIfCancellationRequested();
                    try
                    {
                        state.Source.SendTo(c.PuncFrame, ToWire(target));
                        Interlocked.Increment(ref c.PortPredictionProbesSent);
                    }
                    catch (Exception ex) when (ex is SocketException or ObjectDisposedException) { }
                }
                await Task.Delay(200, stop.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException or TimeoutException) { }
        finally { lock (c.Gate) state.Finished = true; }
    }

    private async Task<IPEndPoint[]?> MeasurePredictionTargetsAsync(IUdpSocket source, CancellationToken ct)
    {
        if (Interlocked.CompareExchange(ref _predictionMeasuring, 1, 0) != 0) return null;
        try
        {
            if (!ReferenceEquals(_udp, source)) return null;
            if (ObservedNatHint == NatHint.Cone)
            {
                IPEndPoint[] servers = BasicStunServers().Where(s => s.AddressFamily == AddressFamily.InterNetwork).Distinct().Take(2).ToArray();
                if (servers.Length != 2) return null;
                IPEndPoint a = await ProbeStunFromAsync(source, servers[0], ct).ConfigureAwait(false);
                IPEndPoint b = await ProbeStunFromAsync(source, servers[1], ct).ConfigureAwait(false);
                return a.Equals(b) && PortPrediction.Eligible(a) ? [a] : null;
            }
            IPEndPoint[] fresh = ReservedPredictionServers();
            lock (_predictionGate)
            {
                if (ReferenceEquals(_predictionMeasuredSource, source) || fresh.Length != PortPrediction.SampleCount
                    || fresh.Any(s => _predictionContactedServers.Contains(s)) || fresh.Select(s => s.Address).Distinct().Count() < 3) return null;
                _predictionMeasuredSource = source; // even a failed measurement consumes its fresh destinations
            }
            List<IPEndPoint> observations = [];
            foreach (IPEndPoint server in fresh) observations.Add(await ProbeStunFromAsync(source, server, ct).ConfigureAwait(false));
            return ReferenceEquals(_udp, source) ? PortPrediction.Predict(observations) : null;
        }
        finally { Volatile.Write(ref _predictionMeasuring, 0); }
    }

    private void SendPredictionStart(ConnState c, PortPredictionState state, bool acknowledgement)
    {
        Span<byte> body = stackalloc byte[18]; body[0] = 1; body[1] = (byte)(acknowledgement ? 4 : 3);
        BinaryPrimitives.WriteUInt64LittleEndian(body[2..], state.LocalId);
        BinaryPrimitives.WriteUInt64LittleEndian(body[10..], state.PeerId);
        SendPredictionControl(c, body);
    }

    private void OnPrediction(ConnState c, ReadOnlySpan<byte> frame, in Arrival arrival)
    {
        if (!arrival.ViaRelay || !PredictionAllowed(c)) return;
        ReadOnlySpan<byte> body = frame[(HeaderSize + CryptoWire.TokenLength)..];
        if (body.Length < 10 || body[0] != 1 || body[1] > 4) return;
        ulong peerRound = BinaryPrimitives.ReadUInt64LittleEndian(body[2..]);
        if (peerRound == 0) return;
        if (body[1] == 0 && body.Length == 11 && body[10] <= 1
            && (body[10] == 1 || c.SymmetricHint || ObservedNatHint == NatHint.Symmetric)) StartPortPrediction(c);
        PortPredictionState? state = c.Prediction;
        if (state is null || state.Finished || !ReferenceEquals(state.Source, _udp)) return;
        IPAddress[] advertised;
        lock (_gate) advertised = c.PeerCandidates.Where(p => p.Kind == CandidateKind.Reflexive).Select(p => p.Address.Address).Distinct().ToArray();
        lock (c.Gate)
        {
            if (state.PeerId != 0 && state.PeerId != peerRound) return;
            if (body[1] is 0 or 1)
            {
                if (body.Length != 11 || body[10] > 1) return;
                state.PeerId = peerRound; state.PeerCapable = true;
            }
            else if (!state.PeerCapable || state.PeerId != peerRound) return;
            if (body[1] == 2)
            {
                IPEndPoint[]? targets = PortPrediction.ReadOffer(body, advertised);
                if (targets is null || state.PeerTargets is not null && !state.PeerTargets.SequenceEqual(targets)) return;
                state.PeerTargets = targets;
            }
            if (body[1] is 3 or 4)
            {
                if (body.Length != 18 || state.LocalTargets is null || state.PeerTargets is null
                    || BinaryPrimitives.ReadUInt64LittleEndian(body[10..]) != state.LocalId) return;
                if (body[1] == 3 && _peerId < c.PeerId || body[1] == 4 && _peerId > c.PeerId) return;
                state.Started = true;
            }
        }
        if (body[1] == 0)
        {
            Span<byte> ack = stackalloc byte[11]; ack[0] = 1; ack[1] = 1;
            BinaryPrimitives.WriteUInt64LittleEndian(ack[2..], state.LocalId); ack[10] = 0;
            SendPredictionControl(c, ack);
        }
        if (body[1] == 3) SendPredictionStart(c, state, acknowledgement: true);
    }
}
