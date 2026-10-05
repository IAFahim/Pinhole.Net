# Reachability rediscovery (issue #29)

Two peers that once connected hold each other's *ticket* (the `pinhole1:` connection
string). Tickets carry addresses, and addresses die — reboots, DHCP, NAT re-mappings,
trips between networks. Until 1.10 the answer was "a human shares a fresh ticket".
With a persisted identity and signed address records, the answer is now "the old ticket
keeps working, as long as the peers share a lookup route".

This follows [iroh's address-lookup design](https://docs.rs/iroh/latest/iroh/index.html#address-lookup):
reachability is published under the node's authenticated identity (an Ed25519 endpoint
key, exactly as iroh uses its node key), and lookups are verified against a key pinned
out-of-band before anything is adopted.

## The identity

One persisted 32-byte seed (`PinholeOptions.IdentityKeySeed`) restores the full key set:

| Key | Kind | Derived as | Used for |
|---|---|---|---|
| Static key | X25519 | the seed itself | session handshakes; pinned in tickets since v2 |
| Endpoint key | Ed25519 | HKDF-SHA256(seed, info=`pinhole-endpoint-ed25519-v1`) | signs address records; carried in v3 tickets |
| Peer ID | u64 | SHA-256(endpoint key)[0..8] | locator only — it never authorizes a peer |

The two key domains are separated by HKDF: neither private key can be computed from the
other's material. A node without a seed (and without iroh relays, which need the Ed25519
key for their handshake) has no endpoint identity and keeps its per-bind random ID.

**Rotation**: replacing the seed is a *new identity* — new peer ID, new keys. Old tickets
never silently connect to the wrong peer: a lookup for the old ID no longer resolves, and
if a record does arrive it fails the endpoint-key pin. Rotation means re-sharing a ticket;
there is no in-place migration, on purpose.

## Records

An `AddressRecord` is the peer's signed statement of where it is reachable **now**:

- peer ID, Ed25519 endpoint key, monotonic sequence (unix-time ms), expiry (90 s),
  and up to 16 direct/reflexive endpoints,
- Ed25519-signed over a canonical body, transported as opaque bytes.

Verification (`AddressRecord.TryParseVerified`) requires the *expected* peer ID **and**
the *pinned* endpoint key to match, the record to be unexpired, and the signature to
verify. A record is only ever adopted by that function; there is no code path that dials
a provider-supplied address on the provider's word. The engine additionally keeps the
highest adopted sequence per peer (bounded at 1024 peers): strictly-older records are
rollbacks, same-sequence re-adoption is an idempotent retry.

**Threat model**: a malicious or compromised provider — or the introducer itself — can
serve stale, forged, or poisoned records. Every one of those outcomes only *denies
availability*: the forged ones fail the pin, the stale ones point at dead addresses, and
even a perfectly authentic record contains nothing that impersonates the peer, because
impersonation requires the X25519 session handshake to pass the static-key pin too.
Records also never carry secrets: no session keys, no pre-shared keys, no TURN
credentials — relay reachability is deliberately *not* in records (TURN candidates embed
passwords; iroh relay URLs are locator configuration), because a public directory must
never hold ticket secrets.

## Providers

Lookup is a plug-in seam, `IPinholeLookupProvider`, with two operations over opaque
signed-record bytes: `PublishAsync` and `ResolveAsync`. Configure:

- `PinholeOptions.RendezvousEndpoints` — the built-in provider: a `Pinhole.Rendezvous`
  UDP introducer (`RendezvousServer.Start()`), which stores and forwards records without
  ever validating them. REG may now carry the publisher's record; INTRO carries it back.
  A bare-endpoint INTRO (legacy client) is ignored by adopters — an unsigned address is
  exactly the redirection abuse signatures exist to prevent.
- `PinholeOptions.LookupProviders` — your own implementation, fronting signed DNS, pkarr,
  or an iroh-style lookup service over whatever transport they speak.

All providers run in parallel; the **first record that verifies against the pin wins**.
When every provider is unreachable, dialing an out-of-date ticket simply times out
inside its normal `ConnectTimeout` — a provider is an availability dependency, not a
guarantee, and one is never on the critical path of a healthy ticket.

*Reuse note (the honest version)*: pkarr and signed-DNS lookups were evaluated first, as
the issue requires. No maintained, managed-C# (no native bindings) pkarr or signed-DNS
client library exists that fits this project's constraints, and publishing reachability
to *public* infrastructure is a privacy decision an application must make, not a library
default. The seam is the compromise: the wire format and verification are done, and an
adapter to an external system is a small class, not a fork.

## When things republish

The engine signs and publishes a record:

- once at bind (process restart), the moment its first candidate set exists,
- after every rebind, STUN-observed mapping change, or router port-mapping change
  (all route changes funnel through one refresh hook),
- on a 30 s heartbeat with ±2 s jitter, so a record never approaches its 90 s expiry,
- with exponential backoff (up to 5 minutes) while every provider is silent, reset on
  the first acknowledgment — bounded provider access even when everything is down.

Event-triggered publishes are debounced and rate-limited to one burst per 5 s so
candidate churn never becomes a provider flood. Publishing requires `Listen=true` and an
endpoint identity; a dial-only node has no address worth serving.

Dialing: when a ticket carries a pinned endpoint key (v3), the lookup races alongside the
punch loop. If the ticket's own candidates answer first, the lookup result is discarded;
if they are dead, the verified record's endpoints join the punch and the dial heals.

## Privacy

A provider operator learns: the publisher's peer ID and endpoint public key (both also
in any ticket the app shares), its current direct/reflexive IP:port list, and — for UDP
introducers — the IP:port of whoever resolves it. Records say nothing about sessions,
payload, or who the peer talks to. If that metadata matters to your application, run the
introducer yourself (`RendezvousServer` is ~200 lines, in-process, no storage) or front
a provider you trust, and keep `RendezvousEndpoints` pointed at it.

## Safe identity storage

The seed *is* the peer's identity. Treat it like a private key, because it is one:

- OS secret storage where available (DPAPI / Keychain / libsecret), or a file with `0600`
  permissions owned by the service user,
- never in source control, logs, or the ticket (tickets carry only public halves),
- generate with a cryptographic random source (`RandomNumberGenerator.GetBytes(32)`) —
  the tests' `NewSeed()` is the pattern.

## Limits (tested, see `RediscoveryTests.cs`)

- Reconnect through a lookup route requires both sides to run a provider and the
  publisher to have an endpoint identity (a persisted seed). Without one, old tickets
  keep their pre-1.10 behavior: dead candidates, honest timeout.
- A dialer's resolve is one bounded attempt per dial (3 s budget); an offline peer that
  registers a moment later needs a redial. The 30 s heartbeat keeps registered records
  fresh, not live forever — introducer TTL (default 120 s) sweeps silent publishers.
- The rendezvous introducer is unauthenticated store-and-forward by design; it can deny
  availability to anyone, and that is its whole power.
