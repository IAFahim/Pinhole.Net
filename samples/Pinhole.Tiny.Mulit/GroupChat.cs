using System.Collections.Concurrent;
using System.Text.Json;
using Pinhole;

internal sealed class GroupChat(PinholeNode node)
{
    private readonly ConcurrentDictionary<ulong, PinholeConnection> _peers = new();
    private readonly ConcurrentDictionary<Task, byte> _readers = new();
    private readonly HashSet<Guid> _seen = [];
    private readonly Queue<Guid> _recent = new();

    internal async Task RunAsync(string[] invitations, CancellationToken ct)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Console.WriteLine("Pinhole.Tiny.Mulit group chat");
        PrintInvitation();
        Console.WriteLine($"You: {node.PeerId:x16}");
        Console.WriteLine("Paste an invitation to add a friend, or type a message to everyone connected.");
        Console.WriteLine("/join INVITATION, /invite, /peers, /quit. Leave this app open for more friends.");
        Task accepting = AcceptAsync(stop.Token);
        try
        {
            foreach (string invitation in invitations) await JoinAsync(invitation, stop.Token);
            while (!stop.IsCancellationRequested)
            {
                string? line = await Task.Run(Console.ReadLine).WaitAsync(stop.Token);
                if (line is null or "/quit") break;
                line = line.Trim();
                if (line.Length == 0) continue;
                if (line == "/invite") { PrintInvitation(); continue; }
                if (line == "/peers")
                {
                    Console.WriteLine($"Connected friends: {_peers.Count}");
                    foreach (var peer in _peers.Values)
                    {
                        var stats = peer.Stats;
                        Console.WriteLine($"  {peer.PeerId:x16}: {peer.State}, {peer.Path.Kind} {peer.Path.Transport}; sent={stats.DatagramsSent}, received={stats.DatagramsReceived}, send-errors={stats.DatagramsSendFailed}, rejected={peer.FramesRejected}");
                    }
                    continue;
                }
                if (line.StartsWith("/join ", StringComparison.Ordinal))
                { await JoinAsync(line[6..], stop.Token); continue; }
                if (line.Trim('"', '\'', '`').StartsWith("pinhole1:", StringComparison.Ordinal))
                { await JoinAsync(line, stop.Token); continue; }
                if (line.StartsWith('/')) { Console.WriteLine("Commands: /join INVITATION, /invite, /peers, /quit."); continue; }
                if (_peers.IsEmpty) { Console.WriteLine("No friends connected yet. Paste an invitation or share yours."); continue; }
                var sent = new Message(Guid.NewGuid(), $"{node.PeerId:x16}", line);
                byte[] data = JsonSerializer.SerializeToUtf8Bytes(sent);
                if (data.Length > PinholeConnection.MaxPayload)
                { Console.WriteLine($"Message too long: encoded message must fit {PinholeConnection.MaxPayload} bytes, including its sender and ID."); continue; }
                Remember(sent.Id);
                int queued = Broadcast(data);
                Console.WriteLine($"Message queued for {queued} directly connected friend(s).");
            }
        }
        finally
        {
            stop.Cancel();
            await accepting;
            await Task.WhenAll(_readers.Keys);
        }
    }

    private void PrintInvitation() => Console.WriteLine(
        $"Share this invitation: {SampleNetwork.ShareInvitation(node.ConnectionString)}");

    private async Task JoinAsync(string invitation, CancellationToken ct)
    {
        string code = SampleNetwork.NormalizeInvitation(invitation);
        if (!ConnectionString.TryParse(code, out _))
        { Console.WriteLine("Invalid invitation: copy the full fresh pinhole1: string as plain text. Still listening."); return; }
        try { Attach(await node.ConnectAsync(code, ct), ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception e) { Console.WriteLine($"Could not join: {e.Message} Still listening."); }
    }

    private async Task AcceptAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { Attach(await node.AcceptAsync(ct), ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception e)
            {
                Console.WriteLine($"Incoming connection failed: {e.Message} Still listening.");
                try { await Task.Delay(250, ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            }
        }
    }

    private void Attach(PinholeConnection peer, CancellationToken ct)
    {
        while (!_peers.TryAdd(peer.PeerId, peer))
        {
            if (!_peers.TryGetValue(peer.PeerId, out var existing)) continue;
            if (!ReferenceEquals(existing, peer))
            {
                if (_peers.TryUpdate(peer.PeerId, peer, existing))
                {
                    existing.Dispose();
                    break;
                }
                continue;
            }
            Console.WriteLine($"Already connected: {peer.PeerId:x16}");
            return;
        }
        Console.WriteLine($"Connected {peer.PeerId:x16}: {SampleNetwork.Describe(peer)}, encrypted={peer.IsEncrypted}, friends={_peers.Count}");
        Task reader = Task.Run(() => ReceiveAsync(peer, ct));
        _readers.TryAdd(reader, 0);
        _ = reader.ContinueWith(completed => _readers.TryRemove(completed, out _),
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private async Task ReceiveAsync(PinholeConnection peer, CancellationToken ct)
    {
        bool reportedFormatError = false;
        try
        {
            await foreach (var data in peer.ReadAllAsync(ct))
            {
                if (data.Length > PinholeConnection.MaxPayload) continue;
                Message? message;
                try { message = JsonSerializer.Deserialize<Message>(data.Span); }
                catch (JsonException) { ReportFormatError(); continue; }
                if (message is not { From: not null, Text: not null } || message.Id == Guid.Empty)
                { ReportFormatError(); continue; }
                if (!Remember(message.Id)) continue;
                Console.WriteLine($"[{message.From}] {message.Text}");
                Broadcast(data.Span, peer.PeerId);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception e) { Console.WriteLine($"Peer {peer.PeerId:x16}: {e.Message}"); }
        finally
        {
            _peers.TryRemove(new KeyValuePair<ulong, PinholeConnection>(peer.PeerId, peer));
            try { await peer.DisposeAsync(); }
            catch (Exception e) { Console.WriteLine($"Closing {peer.PeerId:x16}: {e.Message}"); }
            Console.WriteLine($"Disconnected {peer.PeerId:x16}; friends={_peers.Count}."
                + (ct.IsCancellationRequested ? "" : " Still listening."));
        }

        void ReportFormatError()
        {
            if (reportedFormatError) return;
            reportedFormatError = true;
            Console.WriteLine($"Unsupported chat format from {peer.PeerId:x16}. Check that every PC runs the current Pinhole.Tiny.Mulit sample.");
        }
    }

    private int Broadcast(ReadOnlySpan<byte> data, ulong? except = null)
    {
        int queued = 0;
        foreach (var peer in _peers.Values)
        {
            if (peer.PeerId == except) continue;
            try { peer.Send(data); queued++; }
            catch (Exception e) { Console.WriteLine($"Send to {peer.PeerId:x16} failed: {e.Message}"); }
        }
        return queued;
    }

    private bool Remember(Guid id)
    {
        lock (_seen)
        {
            if (!_seen.Add(id)) return false;
            _recent.Enqueue(id);
            if (_recent.Count > 2048) _seen.Remove(_recent.Dequeue());
            return true;
        }
    }

    private sealed record Message(Guid Id, string From, string Text);
}
