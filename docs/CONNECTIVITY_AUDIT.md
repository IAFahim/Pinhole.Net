# Direct connectivity audit — 2026-10-08

This audit distinguishes the .NET core from OpusVoice's Kotlin dialer. Having a
method in the core does not mean the phone implements it, and passing a virtual
NAT test does not establish an Internet-wide connection success rate.

The core was reviewed from `0ce33ae`; the Kotlin implementation was reviewed from
OpusVoice `d804a58`. The PCP correction described below is part of this audit.
The defaults below include the subsequent discovery-default change tracked in
[#39](https://github.com/IAFahim/Pinhole.Net/issues/39), phone router mapping
[#2](https://github.com/IAFahim/OpusVoice/issues/2), and dual-family LAN discovery
[#41](https://github.com/IAFahim/Pinhole.Net/issues/41).

## Implemented methods and their defaults

| Method | .NET core | OpusVoice Kotlin dialer |
|---|---|---|
| Local IPv4 and global IPv6 addresses | Advertised and probed automatically | Discovered, advertised after session establishment, and probed automatically |
| IPv6 link-local addresses | Enabled by default; bounded LAN interface scopes | Enabled on Wi-Fi/Ethernet scopes; omitted on mobile-only links |
| Same-socket STUN against several servers | Enabled by default; refresh every minute | Enabled by default; refresh every minute and after host address changes |
| Simultaneous UDP attempts and observed peer addresses | Authenticated handshake replies and direct path confirmation | Initial probes, reverse punch replies, and authenticated path confirmation |
| Automatic PCP / NAT-PMP / UPnP mapping | Enabled by default; PCP corrected during this audit | Enabled by default with Android OS-route gateways; lease renewal/release and authenticated candidate updates |
| Introduction through iroh HTTPS relay | Enabled by default; direct upgrade attempts continue after a relayed session starts | Supported when the peer supplies relay addresses; direct probes continue while relayed |
| Candidate updates and direct recovery | Announcements, STUN refresh, network watch, lookup hooks, and path validation | Announcements, host/STUN refresh, keepalive, and path recovery; fewer roaming capabilities than the core |
| LAN discovery without ticket exchange | IPv4/IPv6 mDNS on active multicast interfaces, enabled by default; explicit opt-out available | Not integrated |
| Stable identity and signed address lookup | Native publishing and direct-address publishing enabled by default; persist a seed for restart identity | Resolves signed native IDs/tickets; no equivalent general listener/publisher API |
| Configured TURN relay | Supported with operator credentials; no TURN default | TURN candidates are not supported |
| Direct TCP transport | Not implemented | Not implemented |

Core references: [options](../src/Pinhole/PinholeOptions.cs),
[engine](../src/Pinhole/NodeEngine.cs), [node](../src/Pinhole/PinholeNode.cs),
[port mapping](../src/Pinhole/PortMappingService.cs).
Phone reference: [PinholeDialer.kt with automatic router mapping](https://github.com/IAFahim/OpusVoice/blob/affd577e7d013a824116e2a9d2f1e755c0cb87af/pinhole/src/main/kotlin/pinhole/PinholeDialer.kt).

LAN discovery makes nearby peers discoverable; it does not traverse Internet NAT.
Keepalive and PMTU discovery preserve and tune an existing path. They do not create
an otherwise blocked route. QUIC runs over UDP and would not, by itself, provide
the missing TCP route.

## Defect corrected during the audit: PCP

The previous PCP implementation sent a 44-byte request instead of the RFC 6887
60-byte MAP message. It omitted the common header's client IP address and decoded
the nonce, result code, and port fields at incorrect offsets. The old fake gateway
implemented the same incorrect layout, hiding the defect.

The corrected client uses the 24-byte common header and 36-byte MAP body, inserts
the actual source IP selected by a connected UDP socket, and validates replies
from that gateway against the nonce, UDP protocol, and internal port. It supports
native IPv6 mappings and scoped IPv6 gateways as well as IPv4. Renewal suggests
the previous external endpoint and detects both address and port changes.

The existing advertisement test fails against the corrected fake gateway with the
old client: it falls through to NAT-PMP rather than obtaining a PCP mapping. The
fixed client passes that test. Additional tests use independently hand-encoded
RFC layouts, actual loopback UDP for retries and source rejection, and IPv6
mapping/lease lifecycle checks. This establishes protocol handling, not that the
user's router supports PCP or that its host firewall permits the mapped port.

Protocol reference: [RFC 6887 sections 7, 11 and 16.4](https://www.rfc-editor.org/rfc/rfc6887.html).
Test reference: [PcpClientTests](../tests/Pinhole.Tests/PcpClientTests.cs).

## Highest-priority gaps

1. **Desktop application firewall setup and a persistent listening port.** The
   measured LTE path reached the PC but UFW blocked its ephemeral UDP port. The
   successful test deliberately used the already permitted port 53317. The
   receiver now accepts `--port`, but neither the core nor the audited apps have
   automatic firewall integration. An installer/app should obtain the platform's
   normal firewall permission for its executable or chosen listening port and
   report blocked reachability clearly. Router mapping does not grant host
   firewall permission. Port 53317 is evidence from this machine, not a universal
   library default.
2. **Router mapping in the Kotlin implementation: implemented.** PCP, NAT-PMP,
   and UPnP now run in the background using Android OS routes and the audio socket's
   port, with renewal, expiry withdrawal, network-change handling, and release.
   The interop case checks the authenticated candidate at the .NET peer. A mobile
   carrier may expose none of these services; refusal or silence contributes no
   mapping and never prevents session establishment. See
   [OpusVoice #2](https://github.com/IAFahim/OpusVoice/issues/2).
3. **Add direct TCP candidates and reverse initiation.** Try TCP as an additional
   authenticated route where UDP is blocked but a peer can accept TCP. More
   advanced simultaneous-open can be considered after platform testing. This
   requires transport framing, capability negotiation, TCP router mappings, and
   tests on both implementations; it is not an existing flag that can be enabled.
   [RFC 6544](https://www.rfc-editor.org/rfc/rfc6544.html) describes TCP candidate
   types and their limitations.
4. **Gather and check candidates per active interface.** Both implementations
   principally use one wildcard UDP socket and the OS route choice. Advertising
   all interface addresses is not equivalent to proving a public path through
   each Wi-Fi, Ethernet, VPN, and cellular interface. Source-bound probes and
   prioritized local/remote candidate checks would expand multi-interface
   coverage. [ICE](https://www.rfc-editor.org/rfc/rfc8445.html) provides a model;
   Pinhole is not a full ICE implementation.
5. **Exchange both peers' current candidates before a no-relay dial.** With one
   shared ticket, the listener has no phone public candidates until a packet
   arrives or introduction establishes a session. The phone's announcements
   currently follow establishment. A two-way ticket or authenticated signaling
   exchange can give both sides targets before the first punch. Existing relay
   introduction already solves part of this; control signaling need not carry
   application data. The Kotlin API does not currently expose its own dialable
   ticket or a signaling-only connection policy.

These are implementation priorities, not promises that every one increases the
success rate on every network. TCP does not solve every NAT pairing, and IPv6
still has firewalls.

## Further conditional techniques

- **NAT behavior diagnostics:** the current multi-server STUN hint detects mapping
  differences. It does not fully characterize filtering or allocation behavior.
  [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780.html) describes richer discovery
  and requires servers that implement those tests.
- **Bounded port prediction:** absent today. It can sometimes help NATs with
  predictable allocation, but requires measurements and coordinated peer
  attempts. Random allocation and multiple NAT layers limit it; see
  [RFC 5128 section 3.5](https://www.rfc-editor.org/rfc/rfc5128.html#section-3.5).
  It should be evaluated after the ordinary mapping, signaling, and transport gaps.
- **UPnP IPv6 firewall pinholes:** the current UPnP client implements IPv4
  WANIP/WANPPP port mapping, not the separate IPv6 firewall-control service. The
  corrected PCP client supplies an IPv6 option only where a gateway supports PCP.
- **Additional relay transports/providers:** useful for connection availability,
  but they must be measured and reported as relayed, not direct.

## Evidence needed for deployment at scale

The virtual lab exercises 16 classical NAT pairings; it is not a survey of modern
routers or carriers. The live LTE demonstration proves a specific phone/PC pair
with a permitted host port. Neither establishes an Internet-wide direct success
rate.

Before claiming broad automatic direct connectivity, measure fresh installs with
normal firewall prompts and unmodified defaults across home routers, double NAT,
different carriers, IPv6-only access, VPNs, and networks that block UDP. Record
direct/relay/failure separately, time to connect and upgrade, and mapping and
firewall outcomes. Include .NET-to-.NET and Kotlin-to-.NET runs, as their
capabilities differ. See [existing reliability evidence](RELIABILITY.md).
