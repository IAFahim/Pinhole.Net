# Live Cloudflare Worker host/join evidence — 2026-10-11

The deployed coordinator at
**https://pinhole-coordinator.fahimmanowarj5.workers.dev** pairs two .NET Pinhole
nodes by a fresh short code and issues separate temporary Cloudflare TURN
credentials. No account API token is supplied to either client. The long-term
TURN key lives in Worker secrets.

Every report requires one pinned, encrypted session and 48 byte-exact round trips
in **each** direction (256-byte payloads). All eight runs passed with 192 sends
each: no application retry was needed. The reports omit codes, full invitations,
management tokens and relay credentials; invitation hashes identify the runs.

| Runtime | Requested mode | Actual route | Host ready | Join + handshake | Echo RTT p50 |
|---|---|---|---:|---:|---:|
| .NET 8 | Automatic | Direct UDP | 1,395 ms | 947 ms | 0.013 ms |
| .NET 8 | UDP only | Direct UDP | 1,113 ms | 292 ms | 0.028 ms |
| .NET 8 | TCP only | Direct TCP | 1,784 ms | 1,981 ms | 0.021 ms |
| .NET 8 | Relay only | Cloudflare TURN/UDP | 1,082 ms | 1,003 ms | 3.818 ms |
| .NET 10 | Automatic | Direct UDP | 1,363 ms | 521 ms | 0.013 ms |
| .NET 10 | UDP only | Direct UDP | 1,325 ms | 1,080 ms | 0.014 ms |
| .NET 10 | TCP only | Direct TCP | 1,649 ms | 1,728 ms | 0.024 ms |
| .NET 10 | Relay only | Cloudflare TURN/UDP | 1,091 ms | 1,148 ms | 3.804 ms |

Host-ready time includes room creation, credential issuance, candidate gathering
and invitation publication. Join time includes claim, its credential issuance,
local bind, mutual signaling and the pinned handshake. Echo RTT excludes setup.
The direct modes use loopback addresses; automatic mode uses two nodes on this
same computer; the relay-only mode disables both direct transports and routes
through the real Cloudflare service. These are **not** WAN NAT, separate-machine,
phone or network-handoff measurements. Existing phone evidence remains separate.

The local actual Worker also passes on both runtimes with its WebSocket upgrade
confirmed in workerd's HTTP log, plus 48 echoes per direction. The C# fixture
tests separately cover HTTP polling when WebSocket upgrades are refused and a
strict TURN server with different allocation data IPs. Node tests cover room
ownership, single-joiner admission, expiry, budgets, bounded metadata, distinct
cached credentials, sanitized failures and refusal to follow upstream redirects.

An initial live deployment rejected credential generation because Cloudflare's
edge runtime does not implement fetch redirect mode `error`. The production
request now uses `manual` and rejects every non-success response, preserving the
rule that an API secret must never follow a redirect. The passing live runs use
Worker version **852104f8-8e6a-4096-945d-b1210a1cd247**.

## Reproduce

```sh
dotnet run --project samples/Pinhole.CloudflareProbe -c Release -f net10.0 -- --worker https://pinhole-coordinator.fahimmanowarj5.workers.dev
dotnet run --project samples/Pinhole.CloudflareProbe -c Release -f net10.0 -- --worker https://pinhole-coordinator.fahimmanowarj5.workers.dev --direct
dotnet run --project samples/Pinhole.CloudflareProbe -c Release -f net10.0 -- --worker https://pinhole-coordinator.fahimmanowarj5.workers.dev --tcp
dotnet run --project samples/Pinhole.CloudflareProbe -c Release -f net10.0 -- --worker https://pinhole-coordinator.fahimmanowarj5.workers.dev --relay
```

Repeat with `-f net8.0`. The independent local runtime check is
`python3 infra/cloudflare-worker/verify-local.py` after `npm ci` in that directory.

The coordinator has daily room/request budgets and expiring records. TURN
credentials have a 24-hour lifetime without in-session rotation; TCP/TLS access
to TURN is not implemented by this adapter. See [setup and limits](../../../infra/cloudflare-worker/README.md).

`manifest.json` records the Worker source/config/lockfile and probe/core assembly
hashes used by these runs. The implementation is unreleased source on main.
