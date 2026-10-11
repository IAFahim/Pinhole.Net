# Two PCs, Pinhole + Cloudflare

Same chat API as [Pinhole.Tiny](../Pinhole.Tiny/README.md), with a nine-character
join code. The configured Cloudflare Worker exchanges both invitations and issues
temporary TURN credentials. Pinhole handles encrypted direct UDP/TCP or Cloudflare
TURN fallback. Players need no Cloudflare login or API token.

Install the [.NET 10 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/10.0),
then clone/pull this repository on both PCs. Run commands from the repository root.

**PC A — host:**

```sh
dotnet run --project samples/Pinhole.CloudflareChat -c Release
```

Share the code it prints, and leave the host running.

**PC B — join:**

```sh
dotnet run --project samples/Pinhole.CloudflareChat -c Release -- CODE_FROM_PC_A
```

Wait for `Connected`, then type on either PC and press Enter. `/quit` or Ctrl+C
exits. The status shows the selected path and whether encryption is active.
Messages are limited to 1,200 UTF-8 bytes and use the same datagram semantics as
the plain sample.

The sample defaults to the owner's deployed development coordinator:
`https://pinhole-coordinator.fahimmanowarj5.workers.dev`. To use another deployment,
set `PINHOLE_COORDINATOR` on both PCs:

```powershell
# PowerShell
$env:PINHOLE_COORDINATOR = "https://YOUR-WORKER.workers.dev"
```

```sh
# Linux/macOS
export PINHOLE_COORDINATOR=https://YOUR-WORKER.workers.dev
```

The development coordinator permits 200 room-creation attempts/day and 40,000
room requests/day. Start a fresh host for each friend; one code admits one joiner.
An unmatched room stays alive while its host runs, for up to 24 hours. Relay
credentials also expire after 24 hours. Current TURN access uses UDP, so this
mode does not promise relay connectivity where all UDP is blocked. See
[Worker setup and limits](../../infra/cloudflare-worker/README.md).

## Give friends an executable instead

Publish a self-contained Windows x64 executable from the repository root:

```sh
dotnet publish samples/Pinhole.CloudflareChat -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o artifacts/chat/windows/cloudflare
```

Your friends can run the published file without installing .NET or cloning the
repo. From PowerShell in that folder:

```powershell
# Host
.\Pinhole.CloudflareChat.exe
# Friend
.\Pinhole.CloudflareChat.exe CODE_FROM_HOST
```

Replace the project with `samples/Pinhole.Tiny` to publish the plain example.
For Linux or macOS, use the corresponding runtime ID (`linux-x64`, `osx-x64`
or `osx-arm64`) and run `./Pinhole.CloudflareChat [code]`.
