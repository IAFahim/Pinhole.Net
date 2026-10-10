# Direct TCP work — issue #43

This is a local implementation in progress, tracked in
[#43](https://github.com/IAFahim/Pinhole.Net/issues/43). It has not been released.
The real-socket suites now execute and pass on Linux (588 checks including the
IPv4/IPv6 TCP sessions, hardening cases, and 1.9.0 datagram interop in both
dial directions); the macOS/Windows matrix runs in platform CI. Kotlin dialer
parity ships in OpusVoice draft PR #4 with device evidence; its listener
parity and cross-machine production validation remain open. The full
connection-techniques checklist in [#40](https://github.com/IAFahim/Pinhole.Net/issues/40)
remains open.

## Behavior in the draft

`EnableTcpTransport` defaults to true for encrypted .NET sessions. The node tries
a TCP listener on the UDP socket's numeric port. Failure to bind TCP leaves UDP,
relays, and outbound TCP attempts available. Raw `PeerSocket` and native
`IrohTransport` packet APIs do not acquire a Pinhole TCP sidecar.

After UDP has had 1.2 seconds to open, the dialer can try TCP at known direct and
reflexive candidate tuples. Attempts are limited to eight tuples per round, one
round per five seconds, with three-second connect/negotiation deadlines. Both
ends can initiate after learning authenticated candidates. This is active/reverse
initiation; it is not TCP simultaneous-open or an ICE implementation.

Existing ticket envelopes and candidate-origin values are unchanged. A
host/reflexive tuple can be attempted over UDP and negotiated TCP. Separately
granted TCP router mappings add reflexive tuples. Older peers can still parse the
ticket and attempt UDP. They do not gain TCP support from the new ticket.

Healthy UDP remains preferred. A TCP session makes bounded UDP upgrade attempts
and returns to UDP when a validated route arrives, preserving the connection
object and session keys. A new authenticated candidate update restarts attempts.
TCP loss uses the existing suspect-path recovery and relay fallback.

`EnableDirectUdp = false` disables direct UDP **session frames**, while retaining
the socket for discovery/STUN. Explicitly configured TURN providers can still use
UDP. Empty `IrohRelayUrls` and `Relays` lists disable data relay and introduction;
there is not yet a separate signaling-only policy.

```csharp
await using var node = await PinholeNode.BindAsync(new PinholeOptions
{
    IrohRelayUrls = [], Relays = [],
    EnableDirectUdp = false, // useful for TCP-only integration checks
});
Console.WriteLine(node.TcpListeningPort);     // null if unavailable
Console.WriteLine(node.TcpPortMappedEndpoint); // a live router lease, or null
// After a peer connects:
// connection.Path.Kind == PathKind.Direct
// connection.Path.Transport == DirectTransport.Tcp
```

The addresses must still be reachable and the host firewall must permit TCP.
Neither a listening socket nor a router-granted mapping establishes reachability.
Two arbitrary NATs, carrier restrictions, or an administrator's firewall may
prevent direct TCP just as they may prevent UDP. No Internet-wide success rate is
established by this change.

## Framing and fresh stream authentication

The initiator writes the eight ASCII bytes `PHNTCP1\n`. The acceptor reads and
validates them before replying with the same bytes. Unknown versions receive no
protocol reply. Negotiation has a three-second deadline.

Each subsequent record is `length:u16 big-endian` followed by one unchanged
Pinhole frame. Valid frame lengths are 13–8192 bytes. Idle reads may wait; once
the first length byte arrives, the remaining header and body have five seconds
to complete. EOF and invalid/truncated lengths close the stream.

The existing pinned X25519 handshake and AES-GCM frames are reused. In addition,
each stream creates a cryptographically random 62-bit nonce, sends it in a sealed
`Ping`, and requires a sealed `Pong` echoing **that stream's** nonce. The two high
bits remain clear to avoid the maintenance and PMTU marker space. Handshake
confirmation alone cannot select a TCP path: replaying a previous `Punc`, `Pack`,
or `Hsck` does not prove the stream reaches the key holder.

Before fresh proof succeeds, only handshake and challenge frames are eligible;
application data, announcements, and close frames are refused. One stream may
name only one peer. Pending incoming sessions are not returned by `AcceptAsync`
before proof. Parallel streams select the same winner at both ends, preferring
initiation by the lower peer ID and then the shared, sorted nonce pair.

## Resource and lease bounds

The sidecar admits at most 32 live links plus pending dials. Each link has a
32-frame writer queue; enqueue failure is reported through the existing send
failure behavior. Writes have a two-second deadline, and an unproven link closes
after ten seconds. Closing a session drains its queued goodbye and releases its
owned streams. UDP's zero-allocation contract is unchanged; TCP copies queued
frames and can introduce head-of-line latency. The datagram API retains its
delivery/recovery contract across transport changes.

UDP and TCP router leases run independently through PCP → NAT-PMP → UPnP:

- PCP uses IP protocol 17 for UDP and 6 for TCP, with the same nonce/source checks.
- NAT-PMP uses opcode 1 for UDP and 2 for TCP, validates the gateway and internal
  port, tracks the granted lifetime, and deletes with suggested external port zero.
- UPnP uses `UDP`/`TCP`, renews the exact granted external port, preserves a
  permanent-only lease request, and detects changes in the WAN address. A lease
  owns its HTTP client so disposal of discovery does not break renewal/release.

Mapping work is serialized per transport. Network changes invalidate pending
results; stale leases are released before requesting replacements. Expired leases
are withdrawn, including during a pending renewal. Discovery uses an eight-second
budget, renewal at most two seconds or the remaining lease time, and release at
most one second. Unsupported routers contribute no candidate.

SSDP descriptions are pinned to a local responder. Control URLs must stay on
that responder's host, redirects/proxies are disabled, and XML responses are
bounded to 64 KiB with DTD/entities refused. Protocol fixtures follow
[PCP](https://www.rfc-editor.org/rfc/rfc6887.html),
[NAT-PMP](https://www.rfc-editor.org/rfc/rfc6886.html), and
[UPnP WANIPConnection](https://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf).

## Validation and release gate

The socket-free fixtures cover fragmented framing, malformed records, deadlines,
existing crypto oracles, lease expiry/cancellation/rebind races, independent
router byte/SOAP layouts, replayed handshakes on another stream, parallel stream
selection, bidirectional encrypted data, close, UDP preference and TCP-to-UDP
recovery. The virtual NAT checks cover hairpin, mapping expiry, and
IPv4-to-IPv6 roaming.

Executed on real sockets (2026-10-10, Linux, net8.0/net10.0 Release):

- The full suite passed 588 checks, including the IPv4/IPv6 TCP-only session
  tests over `127.0.0.1` and `::1`.
- `TcpSocketHardeningTests`: oversized length headers (8193, 65535) close the
  stream with no session; a substituted ticket key over TCP-only fails with the
  explicit man-in-the-middle error, never downgrades and never reaches
  `AcceptAsync`; close/rebind on the same port admits a fresh session after
  teardown.
- `TcpSimultaneousOpenTests`: source-bound sockets on `127.0.0.2`/`127.0.0.3`
  crossed SYNs and carried data both directions with no listener (first
  crossing after 11 jittered attempts on this host). This records the Linux OS
  primitive and its retry economics only — macOS needs the CI loopback alias
  prep, and no NAT-wide simultaneous-open claim is made.
- Previous-version interop: current↔1.9.0 exchanges encrypted direct UDP
  datagrams in both dial directions (interop harness `echo`/`dial` modes).
  Cross-version payload ceiling is 1176 bytes: a 1.9.0 peer's send API refuses
  more, even though its wire carries the current tree's 1200-byte frames
  inbound. The current 1200-byte guarantee is a same-version property.
- Throughput floor: `Pinhole.Bench` measured 463,863 dps of 64-byte datagrams
  at 0.014 B allocated per datagram — 18.5x the 25,000 dps CI canary floor.

Still pending before ship: the Linux/macOS/Windows CI matrix on these suites
(running on push), Kotlin listener parity beyond OpusVoice PR #4's dialer,
.NET↔Kotlin TCP interop on devices, physical firewall/Internet NAT success
rates, and repeat phone LTE/Wi-Fi tests. Do not close #43 or #40 until their
remaining acceptance criteria are satisfied.
