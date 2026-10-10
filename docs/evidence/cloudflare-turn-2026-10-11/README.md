# Cloudflare TURN live verification — 2026-10-11

**PASS on .NET 8 and .NET 10.** API-issued credentials, authenticated allocations
and encrypted Pinhole datagrams were tested against the real Cloudflare UDP TURN
service. Both C# peers ran on this computer.

| Framework | Raw TURN round trips | Encrypted Pinhole round trips | Send attempts | Whole probe |
|---|---:|---:|---:|---:|
| .NET 10 | 4/4 | 48/48 in each direction | 200, no retries | 798 ms |
| .NET 8 | 4/4 | 48/48 in each direction | 200, no retries | 585 ms |

These durations cover the entire probe, including credential issuance, DNS,
allocations and all exchanges; they are not handshake or RTT figures. Direct
UDP/TCP and iroh were disabled, both paths remained `Relay`, and both peers
required Pinhole encryption. Both tickets retained their pinned static keys.
Sanitized results and tested assembly hashes are in [live.json](live.json).
The supplied TURN app was retained; only short-lived user credentials were issued.
No Worker or VM was deployed and no account plan was changed.

## Address discovery and receive permissions

The first authenticated run passed raw TURN exchanges but timed out during the
Pinhole handshake. Cloudflare's control IP differed from its allocated data IP;
the engine had only bootstrapped receive permissions for the control IP. Adding
the allocation's own data IP fixed the shared-data-IP case. A deterministic
strict-permission regression failed before this change and passed afterward.

A second run assigned the peers different data IPs. A listener with only its own
ticket cannot know the dialer's data IP before permitting incoming packets. The
probe now exchanges both peers' tickets before concurrent pinned dials, matching
TURN's requirement to learn each peer's address through signaling. The final
.NET 8 run proves this works when the Pinhole allocations have different data IPs.
A second regression covers this case with distinct modeled addresses.

The bootstrap change permits a known allocation address, not all peers. A real
application still needs the mutual signaling exchange for arbitrary allocations.
See [RFC 8656 section 2.1](https://www.rfc-editor.org/rfc/rfc8656.html#section-2.1).

## Regression verification

The 36 targeted TURN/client/failover/signaling tests passed on each framework.
The full Pinhole suite, including both new bootstrap regressions, then passed on
.NET 8 and .NET 10: **624 passed, 3 skipped, 0 failed** per framework. These are
local results; no CI result is claimed for the uncommitted changes. Sanitized
summaries are in [validation.json](validation.json).

## Scope and reproduction

This proves the existing C# TURN client and Pinhole encryption work with Cloudflare
using proper candidate exchange. It does not establish a Cloudflare-hosted short
code service, phone interoperability, TCP/TLS connections to TURN, or resilience
across different physical networks. Those need their own integration/tests.
The sample's reproduction commands are in its
[README](../../../samples/Pinhole.CloudflareProbe/README.md).

For an existing Cloudflare TURN app, save its ID and API token in a private local
JSON file with `keyId` and `keyToken` fields, then run:

```sh
dotnet run --project samples/Pinhole.CloudflareProbe -f net10.0 -- --turn-key /tmp/cloudflare-turn-key.json
dotnet run --project samples/Pinhole.CloudflareProbe -f net8.0 -- --turn-key /tmp/cloudflare-turn-key.json
```

A live pass requires `status=PASS`, `stage=encrypted_relay` and `relayTested=true`:
four raw TURN round trips, then 48 encrypted Pinhole round trips in each direction.
Owned temporary key cleanup must succeed; a caller-owned key is retained. Auth-only
and credential-validation commands report `relayTested=false`.

## Earlier attempts

[attempts.json](attempts.json) preserves the earlier observations and subsequent
successful runs; those blockers have been resolved for the live checks above.

The initial agent executor denied UDP socket creation (native error 13) and could
not refresh Wrangler's expired OAuth token. This was an executor restriction,
not evidence that the desktop, phone or Cloudflare were offline. After unrestricted
network access was enabled, Wrangler reached the account but TURN key creation
returned HTTP 403: its Workers OAuth scopes omitted `Calls Write`. The browser
route redirected to login. The user then created the TURN app and supplied the
credentials used for the live runs. The probe did not create or modify that app.

Before authenticated credentials were available, an unauthenticated Allocate to
`turn.cloudflare.com:3478` returned the expected 401 with matching transaction ID,
realm and nonce. This was service reachability evidence, not a relay pass.

The sample built without warnings/errors on both frameworks. Twelve offline
configuration/privacy cases passed (fixture data only), covering documented ICE
schemas, UDP port 443, rejection of TCP-only/other-provider URLs, missing passwords,
malformed schemas/JSON and sanitized CLI failures. Additional malformed key-file
cases failed before HTTP requests and exposed no secret values.

The credential guidance in `docs/HOST_JOIN.md` and the coturn helper's XML comments
was corrected: Cloudflare credentials come from its
[generate-ice-servers API](https://developers.cloudflare.com/realtime/turn/generate-credentials/).
Cloudflare's TURN API token is not a coturn `use-auth-secret` shared secret.
