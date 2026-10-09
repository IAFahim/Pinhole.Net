# Coordinated bounded UDP prediction — local .NET draft

Parent: [#40](https://github.com/IAFahim/Pinhole.Net/issues/40).
The child issue body is [prepared locally](issues/nat-measurement-prediction.md).
This implementation has modeled evidence. Real sockets/carriers/routers,
performance/resource checks, .NET/Kotlin interop and Kotlin implementation remain
pending; it does not guarantee direct connectivity.

`EnablePortPrediction` defaults to `true`. Only required-encryption sessions with
an authenticated relay introduction and an authenticated candidate list can
negotiate it. A symmetric mapping hint causes an attempt after ordinary UDP has
had 1.5 seconds. Healthy direct sessions do not start a prediction round.
Opt-out/old peers do not acknowledge the new control frame, so no speculative
punches or measurement pass are authorized by them.

When at least six distinct IPv4 STUN endpoints are configured, the primary socket
reserves the last four from ordinary bind/refresh probes. At least two remain for
ordinary discovery. The prediction pass requires at least three distinct server
IPs and verifies none of its four destinations has already been contacted from
that socket. It probes them sequentially and consumes them even if the measurement
fails. A symmetric source gets at most one fresh sampling pass per socket;
concurrent sampling is refused. Source-bound interface sockets retain their own
ordinary probes and are not prediction sources in this draft.

All four observations must have the same usable IPv4 address and a constant
positive port step of 1–16. The eight next ports must fit without wrapping.
Random/constant/decreasing/inconsistent sequences, changing public addresses,
unresolved private/shared-carrier mapped addresses and missing evidence are
refused. A cone source can instead recheck two ordinary STUN destinations and
offer its single stable mapping. A public address does not reveal how many NAT
layers exist; consistent measurements cannot guarantee future allocation.

Peers exchange offers through the established encrypted relay control leg. The
lower peer ID coordinates start; the other acknowledges the two fresh round IDs.
Neither starts speculative punches before both offers and the start exchange.
Each offered IP must already be in that peer's authenticated reflexive candidates.
Offers contain a single stable endpoint or exactly eight uniformly ascending
ports, with no duplicates or arbitrary port lists.

Each side sends normal PUNC frames to at most eight proposed ports, at 200 ms
intervals for at most six rounds: **48 speculative datagrams per peer**. A round
has an eight-second total budget, bounded negotiation retries and at most four
negotiation rounds per primary source across the node. Cancellation, disposal,
source replacement or establishment of a working direct path stops work. Guesses
never enter tickets or published reflexive candidates. Normal encrypted peer
proof is required before selecting any resulting direct path.

Ordinary pending UDP punches pause during measurement/negotiation to avoid
polluting allocation order; relay application traffic and independent TCP
attempts remain available. The existing connect timeout is not extended. After
the bounded attempt finishes, ordinary UDP attempts resume. Another process or
other active traffic can alter allocation despite four consistent observations.
The draft does not retry prediction on the same connection after roaming, predict
TCP ports or perform TCP simultaneous-open.

## Control wire

Frame `0x58` (`Predict`) uses the existing session header/token and AES-GCM seal.
It is processed only from an authenticated relay leg. Older implementations
ignore the unknown frame and keep their existing application transport.
The decrypted control body starts with version `1`, kind and the sender's
nonzero little-endian 64-bit round ID:

| Kind | Body |
|---|---|
| 0: Hello | Version, kind, sender round ID, one-byte symmetric scheduling hint (0/1) |
| 1: Hello acknowledgement | Same layout; advertises support and the receiver's own round ID |
| 2: Offer | Version, kind, sender round ID, count, count × (IPv4 address:4 + port:2 big-endian) |
| 3: Start | Version, kind, sender round ID, expected receiver round ID |
| 4: Start acknowledgement | Same layout with the sender/receiver roles reversed |

All lists and lengths are exact. AES-GCM provides authentication and replay
rejection; round IDs prevent substituting controls from another active round.
`PortPredictionProbesSent` counts speculative punches separately from application
datagrams and ordinary path probes. A failed/refused attempt contributes no claim
of direct success; the path label remains relay/pending as appropriate.

Evidence: 22 socket-free checks cover bounded derivation, malformed/unadvertised
offers, private/shared addresses, random allocation, consumed sample destinations,
opt-out peers, initial control-message loss and two independently modeled symmetric
NATs reaching encrypted direct communication. A separate signaling-only case
requires direct completion and sends no application data through the relay.
These cases validate the actual node engine with modeled networks and an
independently authenticated in-memory iroh relay, not a real TLS relay or carrier.
