# Source-bound interface candidates — local draft

This addresses the per-interface gathering/checking requirement in
[#40](https://github.com/IAFahim/Pinhole.Net/issues/40). It is a .NET local draft;
real socket/platform/route-change validation and Kotlin parity remain pending.

`EnableInterfaceCandidates` defaults to `true`. The node retains its existing
wildcard socket and can additionally bind up to four active IPv4/IPv6 source
addresses. Wi-Fi/Ethernet links rank first, followed by other active interfaces,
including available VPN/cellular routes. Gathering keeps both available address
families first, then distinct interfaces, then extra addresses on one interface. Loopback, wildcard,
multicast, IPv6 link-local and Teredo addresses are excluded from this pool;
existing bounded link-local probing remains a separate LAN technique.

Each additional socket uses an OS-selected port and stays listening. Its exact
local endpoint and same-socket STUN observations become candidates. Different
source sockets can have different NAT mappings, so mapping classifications are
kept per source instead of comparing ports across unrelated sockets. The original
wildcard socket's NAT hint remains based on that socket's own observations.

Initial direct attempts use the wildcard socket and the bounded compatible-source
pool. Replies use the socket that actually received the frame. Once encrypted
traffic confirms a direct path, application datagrams use that selected source
socket alone. Path-validation/PMTU probe matching also retains the local source;
responses on another socket cannot complete those pending probes. A failed default
send does not suppress the other interface attempts.

`PinholeNode.InterfaceCandidates` reports each local endpoint, its interface index,
its reflexive endpoints and its per-socket mapping hint. These are observations,
not a reachability guarantee. Global IPv6 and LAN-local candidates can work without
STUN; STUN silence cannot prove that a source interface is unreachable.

STUN replies must match the complete 12-byte transaction ID, the configured server,
the receiving local socket, the binding-success type and the message length.
Source probes use compatible configured server families, at most eight per socket.
They run in the background and use the bind budget; they do not delay the public
bind beyond the existing main-socket infrastructure stage. Regular STUN refresh
updates mappings. Failed refreshes do not immediately erase prior observations;
stale observations expire after two refresh intervals, with a two-minute minimum.
When STUN refresh is explicitly disabled, existing observations remain until the
source is invalidated or removed.

Interface/address changes withdraw old sockets/candidates and cancel their pending
probes. Rebind/network-change recovery can invalidate otherwise identical source
addresses so new sockets learn the new network. Removed/failed sockets make their
direct paths suspect and permit recovery through another source or the configured
fallback policy. Refresh is serialized; four sources are active, with at most four
retiring sockets during one replacement pass. Each extra socket requests 512 KiB
send/receive buffers and has one bounded-wake receive worker. Disposal closes the
pool. Individual source bind failures do not fail the node.

Explicit single-address binds keep their chosen socket and do not auto-expand this
pool. Raw iroh transport also retains its existing socket contract. Virtual test
networks must explicitly supply an interface factory/source provider; ordinary
virtual node tests never create hidden OS sockets.

The global TCP sidecar and PCP/NAT-PMP/UPnP mapped ports retain their existing
listening-socket ownership; this draft does not create per-interface TCP listeners
or claim that source-specific UDP ports have explicit router firewall grants.
Outbound punching and received encrypted proof establish those UDP paths. Host
firewall and installer integration still belong to the broader roadmap.

Ten virtual checks cover failed-default/working-alternate routing, IPv6 source retention,
source removal/recovery, socket disposal, family diversity/bounds/opt-out, per-source NAT mapping
classification, wrong-server/wrong-socket/full-transaction STUN rejection and
encrypted incoming handshake completion. Separate socket tests cover actual IPv4
and IPv6 source-bound receive/reply behavior; platform and real network/VPN/carrier
checks are still required.

When the gathered list exceeds the 32-candidate ticket/announcement bound, selection
preserves router grants, both relay provider types, IPv4/IPv6 host coverage, bounded
link-local fallbacks and each selected source's local/first reflexive endpoint before
filling remaining slots. A large symmetric-STUN list must not evict introductions.
Lists already within the bound retain their original ordering/membership.
