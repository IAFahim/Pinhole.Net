Parent: https://github.com/IAFahim/Pinhole.Net/issues/40 (initial two-way candidate exchange and signaling-only policy, created before implementation).

Implement a managed .NET opt-in relay-signaling-only policy. Establish pinned crypto and exchange current candidates through a configured relay before completing a direct application connection. Relays may carry handshake, candidate updates, probes and close, but never application datagrams. Preserve the default data-and-signaling fallback behavior and accurate public path reporting.

- [ ] Required crypto; no plaintext downgrade in the signaling-only policy.
- [ ] Both endpoints exchange candidates before the direct application connection is exposed; retry bounded control announcements without resetting the overall initial dial budget.
- [ ] Direct-only completion/acceptance, explicit timeout reasons, ongoing signaling during direct loss, and enforced application-data rejection on relay send/receive paths.
- [ ] Keep connection objects during direct recovery; no misleading Degraded/relay application path in signaling-only mode.
- [ ] Independent in-memory WebSocket relay carrying real iroh handshake/datagram protocol and real Pinhole crypto; negative, loss, cancellation, migration, and default regression checks.
- [ ] Real relay/socket/platform and Kotlin interop checks, documentation and release validation.

This child issue is a local draft for publication; GitHub network access remains denied to the current tool sandbox. The parent issue already tracks this work. Tests using a modeled relay are not physical NAT/firewall success evidence. The user will handle commits/pushes/network-dependent checks.
