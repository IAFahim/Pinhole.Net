# Pinhole.Net wire protocol

This document specifies what Pinhole.Net puts on the network, precisely enough to
re-implement either side — the same courtesy iroh extends with its protocol documents.
Everything here is pure C# in this repository. The session protocol specified here
does not interoperate with iroh application endpoints. The separate
[IrohTransport API](IROH_CONNECTIVITY.md) supplies native endpoint tickets, signed
discovery, and unchanged network packets to a protocol engine above it; those packets
do not use the session frames below.

Design rule throughout: **holding a connection string lets a stranger dial you, but
never forge, hijack, or kill an established session** — every frame is authenticated
with a per-connection token that never appears in the string, and since wire v1.6
every session is additionally encrypted and peer-authenticated (below).

## Transports

| Path | What carries it | When it is used |
|---|---|---|
| Direct UDP | Primary dual-mode socket plus up to four source-bound interface sockets (local draft) | The goal — hole-punched, zero-alloc, MTU-sized datagrams |
| Direct TCP (local draft, #43) | A bounded, version-negotiated TCP sidecar with fresh encrypted stream proof | When UDP has not opened and a candidate accepts TCP; [release gate](DIRECT_TCP.md) remains pending |
| iroh HTTPS relay | WebSocket speaking the [iroh relay v1/v2 framing](#iroh-relay-transport) | Introduction + standing fallback; reconnects with capped exponential backoff |
| TURN relay | RFC 5766 allocate/permission/send+data indications | Optional fallback when credentials are supplied |

All transports carry the same frame format below; only the encapsulation differs.
TCP uses the [length envelope and per-stream challenge](DIRECT_TCP.md#framing-and-fresh-stream-authentication).

## Frame format

Every datagram (direct UDP payload, TURN `DATA` attribute, or relayed datagram body) is
one frame:

```
 0                   1                   2                   3
+-------+-------------------------------------------------+---------------+
| type  |            sender peer ID (8 bytes, LE)         | body...       |
+-------+-------------------------------------------------+---------------+
```

- Header size: **9 bytes**. Maximum payload: **1200 bytes guaranteed** (QUIC's
  conservative initial); path-MTU discovery may lift the per-connection ceiling above
  it on paths that prove they can carry more.
- The first 4 body bytes of every frame are the **sender's per-connection token**
  (u32 LE, random per connection). The remainder is frame-type-specific.
- On encrypted sessions every frame type after the handshake is **sealed** — the body
  shown below becomes `[counter u64 LE][ciphertext ‖ GCM tag]`; see
  [Encryption](#encryption-wire-v16).

| Type | Byte | Body after token | Meaning |
|---|---|---|---|
| `Punc` | `0x50` | token (u32 LE) | Punch probe; body *is* the dialer's handshake token |
| `Punc`+ | `0x50` | token + ephemeral (32) + static (32) — 77 B frame | Crypto punch: the dialer's half of the handshake (length discriminates from legacy 13 B) |
| `Pack` | `0x51` | echo (u32 LE) + responder token (u32 LE) | Punch ack; proves the PUNC was seen and delivers the responder's token |
| `Pack`+ | `0x51` | echo + token + ephemeral (32) + static (32) + confirm (16) — 97 B frame | Crypto punch ack: the responder's half plus its confirm MAC |
| `Hsck` | `0x57` | token + confirm (16) — 29 B frame, always plaintext | Third flight: the dialer's confirm MAC; also triggers the responder to re-announce |
| `Data` | `0x52` | payload (1–1200+ bytes) | Application datagram |
| `Ping` | `0x53` | nonce (i64 LE) [+ zero padding] | Path probe / RTT / (padded) PMTU probe |
| `Pong` | `0x54` | echoed nonce (i64 LE) | Reply to Ping, value copied verbatim |
| `Announce` | `0x55` | count (u8) + candidate TLV stream | Sender's current reachable addresses |
| `Bye` | `0x56` | — | Clean close |
| `Predict` (local draft) | `0x58` | Version, kind, round IDs and bounded offers | Authenticated relay-only prediction control; [exact layout](PORT_PREDICTION.md) |

### Token authentication

The token is random per connection and travels only inside frames, never in the
connection string. `Punc` teaches the responder the dialer's token; `Pack` echoes it
and delivers the responder's own. From then on the receiver drops any frame whose
token does not match the one it learned — a forged `Data` or `Bye` from a third party
costs nothing. Stale tokens from an earlier connection to the same peer ID are
filtered the same way.

### Ping/Pong and maintenance probes

The nonce field is the sender's `Environment.TickCount64` (monotonic, i64) with a
**class marker in the top bits**: bit 63 (value negative) marks engine
path-validation probes, bit 62 marks PMTU probes, and neither set is a caller
`Ping()` — so RTT statistics and monitoring counters never mix. A probe's `Pong`
certifies the direct path only when it echoes the outstanding probe's nonce *and*
arrives from the endpoint the probe was sent to.

## Encryption (wire v1.6)

Every session encrypts and authenticates by default: AES-256-GCM per frame over a
triple-DH X25519 handshake, with the answering key pinned to the connection string.
No signatures, no certificates, no RNG at MAC time.

### Handshake

The dialer uses crypto precisely when the connection string carries a static key
(payload v2). Roles are canonical — **lo** is the side with the smaller peer ID —
so both endpoints derive identical roles no matter who dialed, and simultaneous
dials converge on one session instead of colliding.

1. The dialer's `Punc` carries its ephemeral and static X25519 public keys (77 B
   frame). The responder derives the same secrets, and answers `Pack` with its own
   ephemeral/static keys plus its **confirm MAC** (97 B frame).
2. The dialer verifies the responder's static key against the string's pinned key —
   a substitution kills the connection as a MITM, it never negotiates — and the
   confirm MAC, then sends `Hsck` carrying *its* confirm MAC (29 B frame, the third
   flight). `Hsck` also asks the responder to re-announce (its first sealed announce
   may have lost the race against the PACK that delivered its keys).

Key schedule, all sides identical: transcript = SHA-256 of
`"pinhole-hs1" ‖ loId LE ‖ hiId LE ‖ eLo ‖ sLo ‖ eHi ‖ sHi`; secret input =
`DH(e,e) ‖ DH(s_lo,e_hi) ‖ DH(e_lo,s_hi)`; 136 B of HKDF-SHA256
(salt = transcript, info = `"pinhole-session-v1"`) expand to the lo→hi key,
hi→lo key, both 4-byte nonce salts, and both 16-byte confirm MACs
(HMAC of the transcript, truncated).

### Sealed frames

After the handshake every frame type (Data, Ping, Pong, Announce, Bye) is:

```
[header 9][token 4][counter u64 LE][ciphertext ‖ 16-byte GCM tag]
```

- Nonce = direction's salt (4 B) ‖ counter (8 B). Counters start at 1 and strictly
  increase, so nonces never repeat. AAD = header + token + counter (21 B) — frame
  type, sender, token, and ordering are all tamper-evident.
- The receiver keeps a 64-frame IPsec-style replay window — but a sequence number is
  marked only after the frame authenticates (RFC 4303 §3.4.3), so a forged frame with
  any counter it likes (the token rides the wire in the clear) starves nothing behind
  it. The same rule guards the epoch ratchet: the next epoch's key is derived as a
  candidate and adopted only when a frame sealed under it authenticates, and the
  previous epoch's cipher is retained for the window, so a frame reordered across an
  epoch boundary still opens. Replays and in-flight bit flips die without side effects.
- Key ratchet: every 2^28 frames per direction the key chains forward through
  HKDF-SHA256 (info `"pinhole-rekey-v1"`, salt = transcript). Both sides step
  identically with no wire negotiation.

### Policy and downgrade resistance

`Required` (default), `Optional`, `Disabled`. There is no negotiation window to
strip: a plaintext `Pack` answering a crypto dial fails the connection; a crypto
`Punc` on a plaintext session is dropped; a stranger's 13 B vs 77 B Punc is
length-discriminated and policy-filtered before any connection state exists.
`Optional` exists solely for pre-1.6 peers — it still speaks crypto with anyone
whose string pins a key.

## Path MTU discovery

RFC 8899-style, direct paths only (relays tunnel whatever they are handed). Padded
`Ping`s — nonce in front, zero padding behind, sized so the whole sealed frame hits
the probe size — climb from the 1237 B floor in 128 B steps toward the remote
family's Ethernet plateau (1472 B IPv4 / 1452 B IPv6; the dual-mode socket reports
v4 peers as v4-mapped v6, so the mapped-back endpoint decides). A matching `Pong`
confirms a size; three unanswered probes abandon it for a five-minute cooldown; the
ladder re-climbs a settled path every five minutes. An inbound frame of a new size
is adopted as evidence directly — if a datagram arrived, the path carries it.
Leaving the direct path forgets the climb: a relay hop or rebind may have a smaller
MTU than the last path proved.

## LAN discovery (mDNS)

Nodes may announce on the local link as `<peer-id-hex>._pinhole._udp.local`
(RFC 6762/6763 subset): PTR + SRV + TXT + A/AAAA records in one response, the RFC's 3×
startup burst plus a 120 s heartbeat, unicast answers to legacy queriers, and a
TTL-0 goodbye on shutdown. TXT carries `id` (16 hex), `hint` (0/1/2), and `key`
(64 hex = the static public key) — so a discovered peer is immediately dialable
with key-pinned encryption. Announcements are unsigned; a handshake proves key
possession rather than a previously trusted device identity. Record TTLs are 120 s
with the cache-flush bit on unique records. IPv4 224.0.0.251 and IPv6 ff02::fb are
joined on active multicast interfaces. Memberships refresh after network changes;
new host addresses trigger an announcement. AAAA link-local results are scoped to
the receiving interface, never to the announcing device's interface index.

## Connection lifecycle

1. **Punch.** The dialer sends `Punc` to every candidate (direct, reflexive, relay)
   every 200 ms. A symmetric-NAT hint in the connection string demotes direct
   candidates to a one-second trickle (relay candidates keep full pace): LAN peers
   and router-mapped endpoints remain directly punchable, while the per-destination
   mappings that make public reflexives hopeless cost one datagram per second. Both
   sides doing this simultaneously is the hole-punch: each NAT sees a permitted
   outbound flow before the inbound packet.
2. **Handshake.** The responder answers `Pack`; each side now holds the other's
   token. Either path confirms: direct ⇒ `Open`, relayed ⇒ `Degraded` (relay works,
   direct upgrade continues at 1 s pacing for up to 120 attempts, then passively).
3. **Traffic.** `Data` frames flow on the current path. Any valid frame received
   also updates the sender's address (last-wins by peer ID — that is roaming).
4. **Keepalive/validation.** One scheduler per node probes direct paths that have
   received nothing for the idle window (default 5 s); three unanswered probes
   (default) mark the path suspect → relay fallback or honest `Dead`. Separately,
   an app may set `KeepaliveInterval` to send a caller `Ping` at a fixed cadence —
   a heartbeat that refreshes NAT mappings both ways; off by default.
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

## Connection lifecycle across outages

The five connection states and their full transition set:

| State | Meaning | Leaves via |
|---|---|---|
| `Punching` | dialing / no usable path yet (also the wounded-pending state after path loss) | → `Open` (direct frame), → `Degraded` (relay leg), → `Dead` (punch budget, monotonic clock) |
| `Open` | authenticated traffic flowing on the direct path | → `Degraded` (path suspect + relay leg exists), → `Punching` (path suspect, no leg; rebind) |
| `Degraded` | traffic flowing, but relay-carried | → `Open` (direct revival), → `Punching` (relay leg condemned), → `Dead` |
| `Dead` | honest "no usable path"; **the same object can return** | → `Open`/`Degraded` (authenticated frame from the peer; bounded 1/s beacons for 5 min after dying keep telling the peer where we are) |
| `Closed` | terminal, only ever reached by closing | nothing — late frames create a NEW authenticated connection, never a resurrection |

`Send` throws during `Punching`/`Dead` (pathlessness is visible, never silently queued at
the datagram layer; the blobs layer rides such windows out with its own bounded budget).

**Suspend**: a suspended process exchanges no traffic until it can run again. On wake, the
engine's single scheduler compares absolute monotonic deadlines, so each maintenance chore
runs once — no replayed timer backlog — and no cryptographic state resets: session keys,
counters, and the replay window survive the pause untouched. A `Punching` connection's
budget is monotonic for exactly this reason: the wall clock jumping across a sleep cannot
condemn it before a post-wake probe has had its chance.

**Process restart** is a different event from roaming: no connection object survives it.
Restart recovery is the #29 redial: a persisted identity seed plus signed address records
lets the peer reconnect you without a new ticket — an authenticated fresh handshake, never
object preservation.

## Connection string

`pinhole1:<base64url>` (unpadded). Three payload versions share the envelope:

```
version:u8 (=1)  flags:u8 (=0)  peerId:u64 LE  natHint:u8 (0 unknown, 1 cone, 2 symmetric)
candidateCount:u8  candidate TLVs...  [v2: staticKey (32 B)]  [v3: endpointKey (32 B)]
```

Version 2 sets flags = 1 and ends with the announcer's 32-byte X25519 static public
key — the pin that makes every dial man-in-the-middle proof. Version 3 sets flags = 3
and appends the 32-byte Ed25519 endpoint public key on top: the pin that lets dialers
adopt [rediscovered addresses](REDISCOVERY.md) without trusting the lookup provider.
v1 parses as legacy (`StaticKey` null); a default node refuses to *dial* one. At most
32 candidates, at most 8192 encoded characters; parsers reject trailing bytes, unknown
kinds, and non-strict base64url.

`natHint` is derived automatically (a manual `SetNatHint` override wins): when two
or more configured STUN servers answer, identical observed mappings classify a cone
NAT (endpoint-independent mapping across the tested destinations; filtering is separate) and
divergent ones a symmetric NAT (per-destination mapping — dialers go relay-first with
a direct trickle and
go straight to relay). A pass where fewer than two servers answer never overwrites
an earlier, better-informed classification.

## Router port mapping

The same strategy iroh's portmapper uses, spoken from pure C#. At bind (and after
every rebind) the node asks the network's gateway for an explicit UDP mapping to its
socket and, in the TCP draft, a separate TCP lease for its listening sidecar, in
order: **PCP** (RFC 6887), **NAT-PMP** (RFC 6886) — both UDP to the
default gateway on port 5351, discovered from the OS routing table — then **UPnP
IGD** (SSDP M-SEARCH multicast to 239.255.255.250:1900, device-description XML, and
SOAP `AddAnyPortMapping` with `AddPortMapping` fallback, IGDv1/v2, on the control
URL the device advertises). The first protocol that grants a mapping wins; a granted
mapping is advertised as a reflexive candidate, renewed at half its granted lifetime
(default lease 2 h), released with a zero-lifetime request / `DeletePortMapping` on
close or rebind, and retried once a minute if a previously-working mapping dies.
Everything is background and best-effort: a network with none of these protocols
contributes no mapping, silently.

PCP MAP requests use the RFC 6887 24-byte common header and 36-byte MAP body. The
header carries the socket's actual source address; IPv4 addresses use IPv4-mapped
IPv6 encoding. IPv4 and IPv6 gateways are eligible, including scoped link-local
IPv6 gateways. NAT-PMP remains IPv4-only.

Requests carry a per-mapping random nonce. Renewals and deletion reuse it and suggest
the previously assigned external endpoint so a restarted gateway can restore the
mapping. The UDP socket is connected to the gateway, excluding replies from other
sources. A successful response must echo the nonce, requested protocol (UDP 17 or
TCP 6), and internal port,
and report a valid external IPv4 or IPv6 endpoint. A renewal that changes either
external IP or port invalidates the old advertised mapping and triggers rediscovery.
NAT-PMP's requested protocol is opcode 1 (UDP) or 2 (TCP); its replies must match
the gateway and internal port. Lease invalidation/expiry and bounded UPnP renewal
are described in the [TCP draft's lease section](DIRECT_TCP.md#resource-and-lease-bounds).

The local [IPv6 firewall-control draft](IPV6_FIREWALL.md) uses the separate
`WANIPv6FirewallControl:1` service, IPv6 SSDP on the selected LAN interface and
HTTP bound to the requested global `InternalClient`. After `GetFirewallStatus`
allows it, `AddPinhole` requests a protocol/port-specific lease and returns the
16-bit `UniqueID` used by `UpdatePinhole` and `DeletePinhole`. These are filter
permissions for an existing host candidate, not translated reflexive addresses.
Real socket/router and Kotlin release checks remain pending.

## STUN usage

The [local interface-candidate draft](INTERFACE_CANDIDATES.md) additionally binds
up to four source sockets. Each socket gathers its own host/reflexive endpoints,
validates full STUN transaction/server/socket correlation, and can carry direct
frames. Authenticated direct arrivals preserve their local socket for replies,
application traffic and maintenance probes. These additions use the same candidate
and session layouts; actual socket/platform and Kotlin checks remain pending.

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
| Max payload (guaranteed floor) | 1200 B (+37 B frame overhead = 1237 B wire) |
| Sealed-frame overhead | counter 8 B + GCM tag 16 B |
| Replay window / epoch | 64 frames / rekey every 2^28 frames |
| Crypto handshake frames | Punc 77 B, Pack 97 B, Hsck 29 B |
| PMTU ladder | 1237 B floor, +128 B steps, 1472 B (v4) / 1452 B (v6) ceiling, 3 tries/size, 5 min cooldown |
| mDNS | `_pinhole._udp.local` on 224.0.0.251 / ff02::fb port 5353, TTL 120 s, heartbeat 120 s |
| Punch pace | 200 ms |
| Direct-upgrade pace | 1 s, ≤120 attempts |
| Path-validation defaults | 5 s idle, 1 s interval, 3 unanswered |
| Keepalive option | off by default; ≥100 ms when set |
| STUN refresh | 60 s (0 = off) |
| Relay reconnect backoff | 1 s → ×2 → 30 s cap, ±10% jitter |
| Port-mapping lease | 2 h, renewed at half-life; discovery retries 60 s after a lost mapping |
| PCP / NAT-PMP gateway port | UDP 5351, retries 0/250/500 ms |
| SSDP | UDP 1900 multicast, M-SEARCH window 1 s, IGDv1+IGDv2 targets |
| STRANGER flood bound | 1024 connections materialized by unknown PUNCs |
| Frame receive buffer | 8192 B (fits 32 fat relay candidates of announce) |

## Bounded prediction control (local draft)

The optional, default-enabled prediction draft adds sealed relay-control frame
`0x58`. Its versioned Hello/Offer/Start exchange and exact layouts are specified
in [PORT_PREDICTION.md](PORT_PREDICTION.md). Older peers ignore the unknown frame;
only positively negotiated peers can authorize sampling/speculative punches.
Guessed endpoints never enter candidate TLVs or signed address publication.
[NAT_BEHAVIOR.md](NAT_BEHAVIOR.md) describes the separate fresh-socket RFC 5780
diagnostic API and stricter ordinary STUN reply validation.
