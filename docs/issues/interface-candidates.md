Parent: https://github.com/IAFahim/Pinhole.Net/issues/40 (per-interface IPv4/IPv6 gathering and connectivity checks, created before implementation).

Implement a bounded managed UDP interface pool in addition to the existing wildcard socket. Source-bind each selected IPv4/IPv6 interface, keep its ephemeral listening port alive, probe STUN on that same socket and advertise only endpoints actually bound/probed. Preserve the receiving local socket when selecting a direct path, so replies and application traffic use the validated source instead of the default route. Refresh after interface/route changes and withdraw disposed/stale candidates. Keep explicit single-address binds and raw iroh transport scoped to their chosen socket.

- [ ] At most four additional interface sockets/receive workers; explicit opt-out and nonfatal source bind failures.
- [ ] Fair IPv4/IPv6 gathering across active Wi-Fi/Ethernet and alternative routes; no comparison of NAT mappings between different local sockets.
- [ ] Same-source STUN, full transaction/server/local-socket validation, lease-free reflexive refresh/withdrawal.
- [ ] Bounded direct connectivity attempts across candidate/source combinations and replies on the actual receiving socket.
- [ ] Local source retained for authenticated direct data/path validation; no silent relay label changes.
- [ ] Address/route churn, rebind, disposal and readable per-source diagnostic snapshots.
- [ ] Independent virtual multi-interface/NAT checks and real IPv4/IPv6 source-bound socket/platform tests.
- [ ] Kotlin parity, documentation and final release checks.

Local draft for the user's later issue publication. The remote parent issue already tracks this requirement. Socket/platform tests remain pending the current sandbox restrictions; no physical reachability rate is claimed.
