# Pinhole.Net wire protocol

This document specifies what Pinhole.Net puts on the network, precisely enough to
re-implement either side — the same courtesy iroh extends with its protocol documents.
Everything here is pure C# in this repository; no part of it interoperates with iroh
application endpoints (we adopt iroh's *practices*, and its relay wire format, not its
QUIC transport).

Design rule throughout: **holding a connection string lets a stranger dial you, but
never forge, hijack, or kill an established session** — every frame is authenticated
with a per-connection token that never appears in the string.

## Transports

| Path | What carries it | When it is used |
|---|---|---|
| Direct UDP | One dual-mode (IPv6 + v4-mapped) socket per node | The goal — hole-punched, zero-alloc, MTU-sized datagrams |
| iroh HTTPS relay | WebSocket speaking the [iroh relay v1/v2 framing](#iroh-relay-transport) | Introduction + standing fallback; reconnects with capped exponential backoff |
| TURN relay | RFC 5766 allocate/permission/send+data indications | Optional fallback when credentials are supplied |

All three carry the same frame format below; only the encapsulation differs.

## Frame format

Every datagram (direct UDP payload, TURN `DATA` attribute, or relayed datagram body) is
one frame:

```
 0                   1                   2                   3
+-------+-------------------------------------------------+---------------+
| type  |            sender peer ID (8 bytes, LE)         | body...       |
+-------+-------------------------------------------------+---------------+
```

- Header size: **9 bytes**. Maximum payload: **1200 bytes** (fits typical MTUs without
  fragmentation; the socket is dual-mode so IPv4 targets are v4-mapped).
- The first 4 body bytes of every frame are the **sender's per-connection token**
  (u32 LE, random per connection). The remainder is frame-type-specific.

| Type | Byte | Body after token | Meaning |
|---|---|---|---|
| `Punc` | `0x50` | token (u32 LE) | Punch probe; body *is* the dialer's handshake token |
| `Pack` | `0x51` | echo (u32 LE) + responder token (u32 LE) | Punch ack; proves the PUNC was seen and delivers the responder's token |
| `Data` | `0x52` | payload (1–1200 bytes) | Application datagram |
| `Ping` | `0x53` | timestamp (i64 LE) | Path probe / RTT measurement |
| `Pong` | `0x54` | echoed timestamp (i64 LE) | Reply to Ping, value copied verbatim |
| `Announce` | `0x55` | count (u8) + candidate TLV stream | Sender's current reachable addresses |
| `Bye` | `0x56` | — | Clean close |

### Token authentication

The token is random per connection and travels only inside frames, never in the
connection string. `Punc` teaches the responder the dialer's token; `Pack` echoes it
and delivers the responder's own. From then on the receiver drops any frame whose
token does not match the one it learned — a forged `Data` or `Bye` from a third party
costs nothing. Stale tokens from an earlier connection to the same peer ID are
filtered the same way.

### Ping/Pong and maintenance probes

The timestamp field is the sender's `Environment.TickCount64` (monotonic, i64). The
**high bit marks maintenance probes**: engine path-validation probes set it, caller
`Ping()` calls do not, so RTT statistics and monitoring counters never mix. A probe's
`Pong` certifies the direct path only when it echoes the outstanding probe's nonce
*and* arrives from the endpoint the probe was sent to.

## Connection lifecycle

1. **Punch.** The dialer sends `Punc` to every candidate (direct, reflexive, relay)
   every 200 ms. A symmetric-NAT hint in the connection string suppresses the
   hopeless direct candidates. Both sides doing this simultaneously is the
   hole-punch: each NAT sees a permitted outbound flow before the inbound packet.
2. **Handshake.** The responder answers `Pack`; each side now holds the other's
   token. Either path confirms: direct ⇒ `Open`, relayed ⇒ `Degraded` (relay works,
   direct upgrade continues at 1 s pacing for up to 120 attempts, then passively).
3. **Traffic.** `Data` frames flow on the current path. Any valid frame received
   also updates the sender's address (last-wins by peer ID — that is roaming).
4. **Keepalive/validation.** One scheduler per node probes direct paths that have
   received nothing for the idle window (default 5 s); three unanswered probes
   (default) mark the path suspect → relay fallback or honest `Dead`.
5. **Re-discovery.** STUN is re-probed on a timer (default 60 s, the periodic
   refresh iroh also performs). A moved NAT mapping replaces the reflexive set and
   is re-advertised to every peer with `Announce` — working direct paths are never
   torn down by a refresh.
6. **Close.** `Bye`, both sides `Closed`; buffered readers drain then see EOF.

### Announce and candidate TLVs

`Announce` bodies and connection strings share one candidate encoding. Each
candidate is: endpoint (address-length byte `4`/`16`, raw address bytes, port u16
BE), kind byte (`1` direct, `2` reflexive, `3` TURN relay, `4` iroh relay), then per
kind: TURN adds relay-server endpoint + two length-prefixed ASCII strings (username,
credential, ≤64 bytes each); iroh adds a length-prefixed ASCII URL (HTTPS, ≤64
bytes) + a 32-byte Ed25519 public relay identity key.

Kind `2` (reflexive) covers both truths that make a public endpoint reachable:
STUN-observed mappings and endpoints granted by [router port mapping](#router-port-mapping).
A peer punches them identically; no wire semantics differ.

## Connection string

`pinhole1:<base64url>` (unpadded). The payload:

```
version:u8 (=1)  flags:u8 (=0)  peerId:u64 LE  natHint:u8 (0 unknown, 1 cone, 2 symmetric)
candidateCount:u8  candidate TLVs...
```

At most 32 candidates, at most 8192 encoded characters; parsers reject trailing
bytes, unknown kinds, and non-strict base64url.

`natHint` is derived automatically (a manual `SetNatHint` override wins): when two
or more configured STUN servers answer, identical observed mappings classify a cone
NAT (endpoint-independent mapping — the reflexive candidate is punchable) and
divergent ones a symmetric NAT (per-destination mapping — dialers skip the punch and
go straight to relay). A pass where fewer than two servers answer never overwrites
an earlier, better-informed classification.

## Router port mapping

The same strategy iroh's portmapper uses, spoken from pure C#. At bind (and after
every rebind) the node asks the network's gateway for an explicit UDP mapping to its
socket, in order: **PCP** (RFC 6887), **NAT-PMP** (RFC 6886) — both UDP to the
default gateway on port 5351, discovered from the OS routing table — then **UPnP
IGD** (SSDP M-SEARCH multicast to 239.255.255.250:1900, device-description XML, and
SOAP `AddAnyPortMapping` with `AddPortMapping` fallback, IGDv1/v2, on the control
URL the device advertises). The first protocol that grants a mapping wins; a granted
mapping is advertised as a reflexive candidate, renewed at half its granted lifetime
(default lease 2 h), released with a zero-lifetime request / `DeletePortMapping` on
close or rebind, and retried once a minute if a previously-working mapping dies.
Everything is background and best-effort: a network with none of these protocols
contributes no mapping, silently.

PCP MAP requests carry a per-mapping random nonce; renewals reuse it so the gateway
updates the existing mapping instead of allocating a second one. Responses are
accepted only when the nonce is echoed, the result code is success, and the external
address is IPv4 (or v4-mapped) — the candidate vocabulary is IPv4/IPv6 endpoints.

## STUN usage

RFC 5389 binding request/response subset: magic cookie `0x2112A442`, XOR-MAPPED-
ADDRESS (v4 and v6) decoded from the response. Probes ride the node's own socket;
all configured servers are probed in parallel, bounded by the bind budget, and any
server's failure costs only its candidate. `MAPPED-ADDRESS` is also accepted.
STUN traffic shares the receive loop with frames: the cookie at offset 4
demultiplexes it.

## iroh relay transport

Managed client for the iroh relay v1/v2 WebSocket protocol (relay transport only,
not iroh QUIC):

1. `GET wss://<relay>/relay` negotiating subprotocol `iroh-relay-v2` or `iroh-relay-v1`.
2. The relay sends a frame: `[0x00][16-byte challenge]`.
3. The client answers `[0x01][32-byte Ed25519 public key][64][64-byte signature]`
   where the signature covers the BLAKE3 hash of the challenge keyed with the
   context string `"iroh-relay handshake v1 challenge signature"`.
4. The relay confirms with `[0x02]`; failure is any other byte.

After that: `0x04` = client→relay datagram (`[dest 32B key][ECN u8][frame]`),
`0x06`/`0x07` = relay→client datagrams (source key + frame), `0x09`/`0x0A` =
protocol ping/pong (answered automatically), `0x0C` = relay-requested reconnect.
The node's peer ID is the first 8 bytes (LE) of the SHA-256 of its public key.

WebSocket keepalives run at 15 s. A dropped connection reconnects forever with
capped exponential backoff: ~1 s first, doubling per consecutive failure to 30 s,
±10% jitter, reset on the first successful authentication — an outage never turns
into a synchronized retry storm. TURN allocation retries follow the same idea
(30 s ±20%).

## Constants

| Constant | Value |
|---|---|
| Header size | 9 B |
| Max payload | 1200 B |
| Punch pace | 200 ms |
| Direct-upgrade pace | 1 s, ≤120 attempts |
| Path-validation defaults | 5 s idle, 1 s interval, 3 unanswered |
| STUN refresh | 60 s (0 = off) |
| Relay reconnect backoff | 1 s → ×2 → 30 s cap, ±10% jitter |
| Port-mapping lease | 2 h, renewed at half-life; discovery retries 60 s after a lost mapping |
| PCP / NAT-PMP gateway port | UDP 5351, retries 0/250/500 ms |
| SSDP | UDP 1900 multicast, M-SEARCH window 1 s, IGDv1+IGDv2 targets |
| STRANGER flood bound | 1024 connections materialized by unknown PUNCs |
| Frame receive buffer | 8192 B (fits 32 fat relay candidates of announce) |
