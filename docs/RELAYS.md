# Operating relays (issue #30)

Pinhole's fallback paths ride infrastructure you do not control by default: the free
public n0 iroh relays, or TURN servers you configure yourself. This page is about what
that means operationally — failure domains, self-hosting, and what the library does when
relays misbehave.

## What the engine already does (and what it costs you)

| Failure | Behavior |
|---|---|
| One TURN relay of several dies | Relay traffic re-routes to a surviving allocation on the same server the peer uses; sessions keep flowing without application action. |
| The only relay of a relay-only session dies and restarts | Both peers reallocate (new relayed addresses), re-announce, and — with a persisted identity and a lookup route (#29) — re-find each other's new addresses through verified signed records. The same session object comes back. |
| Every relay is down | Sessions enter an explained pending state (`Punching`/`Degraded`, sends refused with "no usable path") and recover on their own when infrastructure returns — subject to the backoff ladder below. |
| Relay refuses allocations (quota 429, revoked credentials 401) | The slot retries on a doubling ladder (30 s → 5 min, ±20% jitter): bounded retries, never a reconnect storm. Recovery is immediate once the server accepts again. |
| Allocation expires / allocation mismatch (437) | The client retires and reallocates; a stale nonce (438) is retried in place. |
| iroh relay unreachable (DNS, TLS, restart) | The WebSocket client reconnects with capped exponential backoff (1 s → 30 s, ±10% jitter) per configured URL; other URLs keep serving. |
| An *unused* relay dies | Nothing: direct sessions never touch relay allocations. |

Diagnostics: `pinhole.recovery.events` on the `Pinhole.Net` meter counts every
`relay-retire` / `relay-reallocate` / `relay-heal` / `path-suspect` maneuver
(docs/METRICS.md), and the failover tests in `tests/Pinhole.Tests/RelayFailoverTests.cs`
assert each row of this table under an RFC-accurate fake TURN server — including the
receive-side permission gate real servers enforce.

## Self-hosting

**TURN (coturn)** — the standard choice, and what the library's TURN client speaks
(RFC 5766; long-term credentials; no channel bindings required):

```
turnserver -n --lt-cred-mech -u myapp:s3cret -p 3478 --no-tls --no-dtls
```

Configure it on every peer: `new PinholeOptions { Relays = [new TurnServerConfig(ep, "myapp", "s3cret")] }`.
 TURN servers are configured by IP:port by design — add `stale-nonce` and quota options
(`--stale-nonce`, `--total-quota`, `--user-quota`) to taste; the client adopts rotated
nonces. UDP 3478 must be open, and the relay port range (default 49152–65535) must be
open *inbound* for relayed traffic — that range is how peers reach each other.

**iroh-relay** — for the HTTPS/WebSocket fallback path: `cargo install iroh-relay` and
point `IrohRelayUrls` at it. Each URL is tried independently; the first that
authenticates serves the node.

**Rendezvous introducer** — for the #29 lookup route: run `Pinhole.Rendezvous` (in this
repository, ~200 lines, no storage) anywhere both peers can reach, and list it in
`RendezvousEndpoints`. It is deliberately dumb — store-and-forward of signed records —
so it needs no credentials and holds nothing sensitive.

## Failure domains

- **Independent relays are the point.** Two TURN entries + one iroh URL, run by different
  operators on different networks, make "the relay is down" someone else's scheduled
  maintenance. Configure at least two when relay reachability matters: one shared relay
  between two peers is a single failure domain for them (the multi-relay rendezvous and
  failover machinery only helps if a second usable relay exists).
- **Peers needn't share relay lists.** A relays=[X,Y] and B relays=[Y,Z] meet through Y;
  sends are routed through the allocation on the *same server* as the peer's relayed
  address whenever one exists, which is also the only route strict servers permit.
- **Cross-server cold boot is the one honest limit.** Two peers whose ONLY common route
  is "A on X, B on Y" (no shared relay, no direct path, no exchanged ticket) cannot
  bootstrap: each side's TURN server drops the other's first frames until a permission
  exists, and permissions can only be learned from a frame that arrives. Bootstrap needs
  any one working path first — a shared relay, a direct path, or a ticket. After that,
  announces install the permissions and cross-server legs work.
- **Credentials are per-deployment secrets.** They travel in tickets (relay candidates)
  but never in signed address records, which carry only public relayed *addresses*.

## Capacity, health, and honesty about SLAs

- The default relay lists are the **free public n0 iroh relays and public STUN**: no
  credentials, no capacity promises, no SLA — treat them as best-effort discovery, and
  pin your own relays when transfers must complete. Nothing in this library claims
  otherwise.
- Size a self-hosted TURN server for ~1 allocation per online peer (refreshed at
  lifetime/3) plus permission churn (a few datagrams per peer per minute). The fake
  server in the test suite handles the whole matrix in-process; real coturn sizing is
  your capacity planning, not ours to promise.
- Health checks: `node.HasRelay` says whether *any* configured relay is currently alive
  client-side. It is a liveness hint for UI, not a guarantee that a particular peer is
  reachable through it.

## What a relay operator learns

For TURN: peers' IP:port pairs, their allocation times, and the addresses they send to
(relayed addresses of their peers). For the rendezvous introducer: peer IDs, public
keys, current addresses, and who asked about whom. For iroh relays: whatever the relay
operator's own logs say. None of them can read session traffic (AES-256-GCM end to end)
or forge a peer (static-key pinning).
