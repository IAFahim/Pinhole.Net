# Tailcat DERP relays

`PinholeNode.BindAsync()` now connects to Tailcat's dedicated public DERP fleet
alongside n0's iroh relays. Both can introduce peers, carry encrypted Pinhole
datagrams when direct paths fail, and reconnect after an outage. The first
authenticated relay path remains selected while its connection is healthy;
direct UDP/TCP paths can replace it as before.

Tailcat makes its [public relays available without an account](https://github.com/tailscale/tailcat).
They are rate-limited, carry no SLA or throughput promise, and the operator can
[revoke access](https://github.com/tailscale/tailcat#stability). Extra providers
improve fallback choices; they do not guarantee faster traffic or successful
direct traversal on every network.

## Configuration

```csharp
// Defaults: STUN + iroh + Tailcat DERP.
await using var node = await PinholeNode.BindAsync();

// Keep iroh, disable Tailcat DERP.
await using var withoutDerp = await PinholeNode.BindAsync(new PinholeOptions
{
    DerpRelayUrls = [],
});

// Replace the public DERP fleet with an owned DERP server.
await using var custom = await PinholeNode.BindAsync(new PinholeOptions
{
    DerpRelayUrls = [new Uri("https://derp.example.com/")],
});
```

`null` uses the built-in fleet; `[]` disables this provider; explicit URLs
replace it. URLs use HTTPS, with HTTP permitted only on loopback for testing,
and must fit the candidate format's 64 ASCII bytes. The four default URLs come
from [Tailcat's DERP map](https://tailcat.dev/derpmap.json), verified 2026-10-12:
Tokyo, Frankfurt, New York, and San Francisco. They are built into the catalog;
bind does not fetch the map. Changing operators' endpoints requires updating
the catalog or supplying explicit URLs.

`Path.RelayUrl` identifies the active relay. `HasRelay` includes iroh, DERP,
and TURN. DERP uses encrypted sessions only; plaintext nodes do not connect
to it. `RelaySignalingOnly = true` still permits introductions and candidate
exchange but prohibits application traffic over either HTTPS relay provider.
Native `IrohTransport` retains its iroh-only raw connectivity API. The
Cloudflare Worker host/join facade also retains the DERP defaults alongside
its coordinator-supplied infrastructure; `DerpRelayUrls = []` disables them
in its network options.

## Protocol and compatibility

The adapter speaks [DERP v2](https://github.com/tailscale/tailscale/blob/main/derp/derp.go)
over the official `derp` WebSocket subprotocol at `/derp`. Relay login uses
X25519/XSalsa20/Poly1305; application traffic retains Pinhole's triple-DH
handshake and AES-GCM encryption. A received DERP source must match the
peer's Pinhole static key. The relay's advertised token bucket limits
application datagrams without declaring a healthy path dead when a packet
is rate-limited. Pinhole remains an unreliable datagram transport.

`CandidateKind.DerpRelay = 5` carries an HTTPS URL and a 32-byte X25519 key.
Connection strings and authenticated announcements share this encoding.
Signed pkarr publication adds `pinhole-derp=<URL>` TXT
values alongside the existing Pinhole static-key binding, allowing
`ConnectIrohAsync` to obtain authenticated DERP paths by endpoint ID. Native
iroh ticket encoding remains unchanged.

Both Pinhole peers need the new candidate support. Older .NET releases and
Kotlin clients whose parsers reject kind `5` must be updated, or the .NET node
must use `DerpRelayUrls = []` before sharing tickets with them. This is DERP
relay support for Pinhole's wire protocol; it is not compatibility with Tailcat
`tc...` addresses, WireGuard tunnels, or Tailscale's magicsock traversal engine.

Self-hosted UDP invitation-code directories must also be upgraded: the code
record bound is now 12 KiB, allowing the full invitation with both relay fleets.
Peer-ID lookup records retain their existing 1 KiB bound.

## Validation

Local tests cover the independent libsodium NaCl-box vector, fragmented and
coalesced WebSocket framing, authentication rejection, ping/pong, rate limits,
oversized frames, peer-ID spoof rejection, encrypted two-way traffic, different
home relays, signed endpoint-ID discovery, direct UDP upgrades, signaling-only
application restrictions, and failover between iroh and DERP on the same
encrypted connection. Host/join tests cover both relay fleets in UDP invitation
codes and default DERP fallback through the Worker coordinator.

The [small public-service probe](../samples/Pinhole.TailcatProbe/README.md)
checks three encrypted 32-byte echoes per relay with direct UDP/TCP and all
other infrastructure disabled. [Recorded results](evidence/tailcat-2026-10-12/README.md)
cover all four public relays on .NET 8 and .NET 10. Both peers run on the desktop;
these results do not establish mobile compatibility, physical NAT traversal,
or a throughput guarantee.
