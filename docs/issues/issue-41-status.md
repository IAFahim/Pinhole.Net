The default LAN channel currently binds only IPv4 mDNS and the node only announces IPv4 hosts. An IPv6-only LAN, or a LAN where only IPv6 passes between Wi-Fi and Ethernet, cannot use ticket-free discovery despite the encrypted UDP transport supporting IPv6.

This is a concrete part of #40, created before implementation.

Acceptance:
- [x] Browse and announce over IPv4 224.0.0.251 and IPv6 ff02::fb on each suitable active multicast interface.
- [x] Publish A and AAAA addresses with bounded packet size and preserve receiving-interface scope for link-local IPv6 targets.
- [x] Keep one family/interface working when another cannot bind or join; support explicit discovery opt-out and prompt disposal.
- [x] Refresh interface membership/address advertisements after network changes.
- [x] Exercise real IPv6 sockets, dual-family peer merging, malformed packets, link-local scope, and disposal without requiring multicast in CI.
- [x] Document the trust boundary: discovery metadata alone does not verify a human/device identity; the encrypted handshake proves possession of the discovered key.
- [ ] Run the .NET platform matrix and push the implementation.

RFC 6762: https://www.rfc-editor.org/rfc/rfc6762.html


## Implementation status — 2026-10-09

Implemented in core commit `5f4f2b0`: dual-family multicast channels on active interfaces, A/AAAA publication, receiving-interface link-local scopes, independent family/interface failure handling, interface/address refresh, opt-out and disposal. The associated independent multicast receive and LAN parser/browse tests are present. The CI failure recorded in #42 explicitly reports that the new discovery tests passed on Linux/macOS/Windows; it failed an unrelated process-heap assertion.

Android browsing/receiver selection shipped in OpusVoice `169fd9d`; [OpusVoice #3](https://github.com/IAFahim/OpusVoice/issues/3) is closed. Browsing does not make the phone dialer a general listening server. Discovery metadata establishes no human/device trust; session authentication proves possession of the discovered static key.

Remaining closure gate: verify the completed core Linux/macOS/Windows matrix after the #42 resource-isolation and #44 initial-path test fixes. Current source contains these changes, but this audit could not retrieve the Actions results. Keep this issue open until that evidence is attached; no additional LAN feature is claimed missing merely because the overall matrix has not been verified.

