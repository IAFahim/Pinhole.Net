# Two PCs, plain Pinhole

This sample uses Google STUN and Pinhole's public iroh HTTPS relays. It needs no
Cloudflare Worker, Cloudflare TURN app, API token, player account or VM. Direct
UDP/TCP and public relay fallback are handled by Pinhole.

Install the [.NET 10 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/10.0),
then clone/pull this repository on both PCs. Run commands from the repository root.

**PC A — host:**

```sh
dotnet run --project samples/Pinhole.Tiny -c Release
```

Copy the entire `pinhole1:...` invitation it prints and send it privately to your
friend. Leave this process running.

**PC B — join:**

```sh
dotnet run --project samples/Pinhole.Tiny -c Release -- "PASTE_THE_FULL_INVITATION"
```

Wait for both terminals to show `Connected`, then type messages and press Enter
on either PC. `/quit` or Ctrl+C closes the session. Empty lines are ignored;
messages can contain up to 1,200 UTF-8 bytes. Receives are buffered so messages
sent immediately after connection are not lost while the console starts.

`Program.cs` contains the connection setup. The shared
[ChatConsole.cs](../ChatConsole.cs) contains the concurrent `Send` and `ReadAllAsync`
loops. This is a small datagram chat example: it adds no application-level
delivery acknowledgements or retransmission.

This accepts one friend per process. For the next friend, start a fresh host and
share its new invitation. Keep both hosts running while exchanging invitations;
a ticket from a stopped process cannot connect.

For a nine-character code and your Cloudflare relay instead, use
[Pinhole.CloudflareChat](../Pinhole.CloudflareChat/README.md).
