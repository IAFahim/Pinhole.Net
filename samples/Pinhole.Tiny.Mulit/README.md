# Pinhole.Tiny.Mulit — several friends, one running app

Run this sample on **every PC**. It accepts multiple friends concurrently and
keeps listening when someone disconnects. No Cloudflare account is needed: each
connection uses Pinhole's direct UDP/TCP or public iroh relay fallback.

From the repository root, with the .NET 10 SDK installed:

```sh
dotnet run --project samples/Pinhole.Tiny.Mulit -c Release
```

For the simplest group, PC A shares its invitation with everyone. PCs B, C, D,
and so on paste **A's same invitation** into their running apps and press Enter.
Keep A running. Everyone can now type messages; A forwards them to the other
friends. Only one app needs to be the shared host, and it accepts more friends
without restarting or making a new invitation after each join.

You can also pass one or more invitations at startup:

```sh
dotnet run --project samples/Pinhole.Tiny.Mulit -c Release -- "INVITATION_FROM_A"
```

While running:

- Paste a full `pinhole1:...` invitation, or `/join INVITATION`, to add a connection.
- Type a message and press Enter to send it to the group.
- `/peers` shows connected friends, paths, and sent/received/error counters.
- `/invite` prints your current invitation again.
- `/quit` or Ctrl+C closes your app and its connections.

An invalid invitation or failed join leaves the app running. Invitations use the
same copy-safe spelling as the updated Tiny sample. A stopped app's invitation
expires; after restarting it, share its new invitation.

All participants must run **Mulit**: it uses a small JSON chat envelope to carry
the sender label and message ID. Messages are forwarded between connected peers;
IDs prevent duplicate display and loops when the group also has direct links.
Each link is encrypted; forwarding participants receive the chat contents.
Sender labels are chat metadata, rather than a group identity protocol.
The encoded envelope must fit 1,200 bytes. This demo uses datagrams and adds no
delivery acknowledgements or retransmission.

After you send, `Message queued for N directly connected friend(s)` confirms
the app handed the message to those connections; it does not confirm delivery.
If someone can receive but their replies never arrive, have that person and
the person whose invitation they joined run `/peers`, send `test123`, then run
`/peers` again. Compare the corresponding peer's `sent`, `received`,
`send-errors`, and `rejected` counters. Include any `Send ... failed` or
`Unsupported chat format` lines when reporting the problem; omit invitations.

`Program.cs` creates one node; `GroupChat.cs` calls `AcceptAsync` repeatedly,
tracks each connection, and runs one receive loop per peer.

To give Windows x64 friends a self-contained executable without a .NET install:

```sh
dotnet publish samples/Pinhole.Tiny.Mulit -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o artifacts/chat/windows/mulit
```

Everyone launches `Pinhole.Tiny.Mulit.exe`, then pastes the shared host's
invitation into its prompt. Use `linux-x64` or a macOS runtime ID when publishing
for another platform.
