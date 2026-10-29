using Pinhole;

internal static class InvitationChat
{
    internal static async Task RunAsync(PinholeNode node, string? invitation, CancellationToken ct)
    {
        Console.WriteLine($"Share this invitation: {SampleNetwork.ShareInvitation(node.ConnectionString)}");
        Console.WriteLine("Paste your friend's full pinhole1: invitation and press Enter, or leave this window open for them to join. /quit exits.");
        if (!node.HasRelay)
            Console.WriteLine("No relay connected yet. On different networks, both PCs may need to paste each other's fresh invitations.");

        using var accepting = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var dialing = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task<PinholeConnection> incoming = node.AcceptAsync(accepting.Token);
        Task<PinholeConnectResult>? outgoing = invitation is null ? null : Dial(invitation);
        Task<string?> pendingInput = Task.Run(Console.ReadLine);
        PinholeConnection? chosen = null;
        try
        {
            while (chosen is null)
            {
                Task ready = await Task.WhenAny(outgoing is null
                    ? [incoming, pendingInput] : new Task[] { incoming, pendingInput, outgoing }).WaitAsync(ct);
                if (ready == incoming) chosen = await incoming;
                else if (ready == outgoing)
                {
                    PinholeConnectResult result = await outgoing!;
                    outgoing = null;
                    if (result.IsSuccess) chosen = result.Connection;
                    else Console.WriteLine($"Could not connect: {result.ErrorMessage} Still listening; paste a fresh invitation to retry.");
                }
                else
                {
                    string? line = await pendingInput;
                    if (line is null or "/quit") return;
                    if (line.Trim().Length != 0)
                    {
                        if (outgoing is null) outgoing = Dial(line);
                        else Console.WriteLine("A connection attempt is running. /quit exits; you can retry after it finishes.");
                    }
                    pendingInput = Task.Run(Console.ReadLine);
                }
            }
            accepting.Cancel();
            dialing.Cancel();
            await using (chosen) await ChatConsole.RunAsync(chosen, ct, pendingInput);
        }
        finally
        {
            accepting.Cancel();
            dialing.Cancel();
            try
            {
                PinholeConnection unused = await incoming;
                if (!ReferenceEquals(unused, chosen)) await unused.DisposeAsync();
            }
            catch (OperationCanceledException) when (accepting.IsCancellationRequested) { }
            if (outgoing is not null)
            {
                try
                {
                    PinholeConnectResult result = await outgoing;
                    if (result.IsSuccess && !ReferenceEquals(result.Connection, chosen))
                        await result.Connection.DisposeAsync();
                }
                catch (OperationCanceledException) when (dialing.IsCancellationRequested) { }
            }
        }

        Task<PinholeConnectResult>? Dial(string text)
        {
            string normalized = SampleNetwork.NormalizeInvitation(text);
            if (!ConnectionString.TryParse(normalized, out _))
            {
                Console.WriteLine("Invalid invitation: copy the entire pinhole1: string as plain text. Check that both PCs run the current build. Still listening.");
                return null;
            }
            Console.WriteLine("Connecting to your friend...");
            return node.TryConnectAsync(normalized, dialing.Token);
        }
    }
}
