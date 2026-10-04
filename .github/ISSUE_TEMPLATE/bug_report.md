---
name: Bug report
about: Something does not connect, drops, or misbehaves — tell us what you saw
title: ''
labels: bug
assignees: ''
---

**What happened?** A short description of the misbehavior — what you expected, what happened instead.

**How were you connected?** Direct (same LAN / internet), relayed (`conn.Path.Kind`), or TURN? Paste the relevant `PinholeConnection` diagnostics if you have them (path kind, state transitions, `node.HasRelay`).

**Which side moved?** Did either machine change network mid-session (WiFi→mobile, VPN up/down, sleep/wake)? Does it recover if you re-dial?

**Versions and platforms:**
- Pinhole.Net / Pinhole.Blobs package versions:
- .NET runtime:
- OS on each side (and NAT environment if known: home router, CGNAT, mobile carrier, corporate firewall):

**Connection string(s) involved** — both sides' if possible (they carry no secrets by design; redact TURN credentials if you embedded any):

**Reproduction:** the smallest snippet or command sequence that shows it. If it involves `Pinhole.Blobs`, include the ticket format you used and whether the transfer was fresh or resumed.

**Anything in the logs?** If you can run with your own logging wired to `conn.Closed` / path-change events, paste the lines around the failure moment.
