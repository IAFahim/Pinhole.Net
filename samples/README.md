# Running and verifying the samples

Build the current checkout on **every participating PC**. Rebuild any published
executables too. Start a fresh running host and share its full current invitation;
invitations from stopped processes cannot connect. Both peers must support the
new DERP candidate format. Use the same sample for group chat: Tiny.Mulit uses a
group envelope, while Tiny, Demo and CloudflareChat exchange plain chat messages.
Tiny and Demo can talk to each other.

| Sample | How a friend joins | Host lifetime |
| --- | --- | --- |
| [Tiny](Pinhole.Tiny/README.md) / Demo | Paste the full invitation, or pass it as the only argument | One friend; restart for the next session |
| [Tiny.Mulit](Pinhole.Tiny.Mulit/README.md) | Everyone pastes the same host invitation | Several friends; keeps accepting after a disconnect |
| [CloudflareChat](Pinhole.CloudflareChat/README.md) | Pass the nine-character code | One joiner per code |
| CodeShare | `host <directory-or-worker>` / `join <same-address> <code>` | Exchanges one greeting each way and exits |
| Send | `send <path>` / `recv "<ticket>" <destination>` | Sender keeps serving until Ctrl+C |

Tiny, Demo, Tiny.Mulit and Send use the SDK's free STUN, iroh and Tailcat defaults.
CloudflareChat uses the configured coordinator, its TURN credentials and Tailcat
fallback. Every chat reports its selected path and encryption status. Invalid
invitations and timed-out joins leave Tiny/Demo listening so you can retry.

## Repeatable process checks

From the repository root, with .NET 10 and Python installed:

```sh
python3 samples/verify.py --output artifacts/samples/loopback.json
```

This builds the solution and runs the real executables with isolated loopback
options. It checks invitation pasting and argument-based joins, Tiny/Demo
interoperability, retry after a stopped host, three-person group forwarding,
rejoining the same group host, file/directory integrity, repeated downloads,
UDP-directory codes, three mesh rounds and a live guest. It also checks clean
failure for a missing file. CI runs these checks on Linux, Windows and macOS;
the Worker job additionally runs both coordinator console samples against a
local Worker with public networking disabled.

Opt into small checks through the actual public services:

```sh
python3 samples/verify.py --no-build --network iroh --output artifacts/samples/iroh.json
python3 samples/verify.py --no-build --network derp --output artifacts/samples/derp.json
python3 samples/verify.py --no-build --network auto --worker https://YOUR-WORKER.workers.dev
```

These use separate processes on your PC. They verify real relay traffic, but
cannot establish that two physical PCs or a particular pair of NATs can connect.
The **Sample network** workflow runs the actual programs on three independent
Linux, Windows and macOS runners. It checks bidirectional Tiny/Demo messages,
group forwarding/rejoining, and a byte-verified file across machines with
default, iroh-only and DERP-only options. It also checks the owner's development
Cloudflare coordinator. Trigger it manually, or push a `verify/*` review branch.
Reports contain invitation hashes, paths and delivery results. Live signaling
records are encrypted; the temporary signal branch and per-run key artifact are
deleted afterwards. Public services are best effort, so this workflow is separate
from the deterministic CI suite.

## Diagnosing a transport

The runnable samples recognize `PINHOLE_SAMPLE_NETWORK`:

| Value | Enabled paths |
| --- | --- |
| `auto` (default) | Normal SDK or coordinator defaults |
| `iroh` | Public iroh HTTPS relays only; direct UDP/TCP disabled |
| `derp` | Public Tailcat DERP HTTPS relays only; direct UDP/TCP disabled |
| `tcp` | Direct TCP only; no STUN, relay or discovery services |
| `loopback` | Local UDP/TCP only; no external networking |

Set the same mode on both peers. For example, in PowerShell:

```powershell
$env:PINHOLE_SAMPLE_NETWORK = "derp"
.\Pinhole.Tiny.Mulit.exe
```

On Linux/macOS: `PINHOLE_SAMPLE_NETWORK=derp dotnet run --project samples/Pinhole.Tiny.Mulit -c Release`.
Remove the variable to return to automatic selection. Free relays are rate-limited;
extra paths increase options without guaranteeing universal connectivity or delivery.
The chat samples use datagrams and add no message retransmission. Send implements
verified file-transfer recovery above that transport.

For a LAN listener that needs a specific allowed port, set `PINHOLE_SAMPLE_BIND`
to its local endpoint, for example `192.168.68.113:53317`, before starting it.
The dialing peer can keep its OS-assigned port. The `loopback` test mode always
binds `127.0.0.1` and an OS-assigned port.
