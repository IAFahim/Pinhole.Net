# Open-issue completion audit — 2026-10-10

The goal is to complete every open issue, including cross-repository work and
release evidence. Implementation, passing focused tests, a completed platform
matrix, physical-network results, and release approval are separate requirements.
An issue closes only when its own requirements are proved.

## Completed issues

| Issue | Evidence |
|---|---|
| #18: port-mapping coordination | `eb19c61` and its follow-ups are ancestors of main; the issue already records completed implementation and validation. No remaining implementation request. Closed on 2026-10-10. |
| #38: protocol specification | `docs/PROTOCOL.md` covers all requested frames, handshake flow/admission, canonical DH/HKDF labels and exact OKM offsets, nonce/AAD/replay/epoch rules, tickets and candidate encoding. Independent crypto vectors and real C#↔Kotlin interop verify the layouts. Closed on 2026-10-10. |

## Remaining scope

This table identifies the next missing evidence or implementation; it does not
replace the full acceptance checklist in each GitHub issue.

| Issue | Remaining requirements |
|---|---|
| #14: blobs | Complete extended file/directory/loss/recovery/security matrix, throughput canary and per-chunk allocation evidence. |
| #15: connection-power audit | Measure and decide the optional latency-based relay selection; update historical claims for current identity, encryption and PMTU behavior. |
| #17: testing discipline | Finish per-test trace files and changelog automation; attach evidence for topology/API/capacity gates. Warnings-as-errors is now the solution default. |
| #20: component selection and congestion control | Document maintained managed-component evaluation, then complete sustained/mixed-RTT/TCP-competition and response-byte/aggregate-budget evidence. |
| #23: reliability roadmap | Remains open until all named child issues and release gates are complete. |
| #24: independent security/recovery review | Record and fix all material findings, verify fixes, and complete independent review on the final candidate. The separate AI review stopped before completion; it is not a completed human audit or safety certification. |
| #25: diagnostics | Complete cause-specific events, reproducible JSON reports, latency distributions/cohorts, redaction and opt-in collection guidance. |
| #26: real network topology | Run pinned Patchbay/kernel configurations and actual HTTPS/TURN servers, including UDP blocking, failure capture and cleanup. Portable simulation is additional evidence. |
| #27: bottleneck baselines | Investigate the macOS clean-link collapse without lowering its floor; complete sustained seed distributions, asymmetry/reorder/burst cases and actual TCP competition. |
| #28: candidate racing | Verify bounded shared-deadline racing, actual HTTPS/proxy/TLS negative cases, cancellation and authenticated upgrade/fallback. |
| #29: identity and rediscovery | Audit complete full-key/freshness/provider/privacy/restart requirements against current tests and real infrastructure. Both-direction roaming regression is fixed. |
| #30: relay failover | Finish independent provider/domain, DNS/TLS/proxy, allocation-change and long-outage evidence; only authenticated definitive TURN errors may condemn allocations. |
| #31: logical connection recovery | Complete all stated route/family/MTU/suspend/outage cases and platform evidence with the same connection object and bounded retry work. |
| #32: automatic verified resume | Verify every handshake interruption, directory/counter/checkpoint invariant, prolonged outage, restart, tamper and cancellation case. Recovery allowance now has deterministic clock checks and a shaped restart scenario. |
| #33: desktop/mobile matrix | Declare and test supported runtime/AOT/device combinations and physical network/lifecycle transitions. OPPO Android 16 LTE transport checks now pass; audio, suspend, Wi-Fi/VPN handoff and other devices remain. |
| #34: bounded resources and soaks | Complete 24-hour and 72-hour runs with declared budgets, varied seeds, all required workloads and resource ledgers. Existing short tests and a harness do not prove long-run completion. |
| #35: release gate | Consolidate exact-candidate compatibility/security/platform/performance/soak evidence, correct reliability claims, verify package contents, and prepare a canary/rollback. Owner approval remains required for a release. |
| #40: all connection techniques | Finish Kotlin TCP/interface/signaling/IPv6-pinhole/NAT-prediction/TURN parity, receiver firewall/listener integration, physical network tests and release evidence. The full parent checklist remains authoritative. |
| #41: IPv6 LAN discovery | Attach the completed platform matrix after validation follow-ups. |
| #42: isolated heap measurements | Preserve eight cycles, 512 KiB threshold and exact ledgers; attach focused and completed platform results. |
| #43: direct TCP | Complete Kotlin transport/path labels/scoped IPv6, real interop/security/socket checks, prior-version compatibility/performance, source-bound OS simultaneous-open evaluation and final platform evidence. |
| #44: same-endpoint UDP restoration | Initial and restored paths explicitly require UDP, including TCP enabled/disabled cases; same endpoints, object identity and data assertions remain. Attach the completed platform matrix. |

## Current implementation and validation

- `ebf8937` prevents confirmed-session PACK retries from killing a session,
  editing its token or promoting an unproved source route; adds both-role latch
  regressions and actual UDP negative cases.
- `1914a88` authenticates a provisional token only through sealed-frame AAD,
  keeps opening/confirmation under the connection lock, and prevents malformed
  PUNCs from installing tokens. A sealed first-frame regression covers an edited
  initial PACK; blob wire fixtures now supply sealed route proof.
- `ed7bed9` verifies TURN response integrity, complete transaction ID and method,
  uses the request's captured key, and ignores attributes after integrity.
  Unsigned bootstrap/stale-nonce challenges remain bounded transient results.
- Focused local results: 55/55 crypto/rediscovery/path checks; 36/36 crypto/blob
  wire-oracle checks; 13/13 TURN/empty-grant/clean-link checks on .NET 8.
- An isolated OpusVoice worktree at `/tmp/pinhole-opusvoice-parity` fixes the same
  first-PACK token issue in Kotlin. All ten C#↔Kotlin interop cases pass, including
  lost flights, token editing, native discovery, real reference-relay traffic and
  relay-to-direct upgrade. This is JVM/loopback evidence, not a physical-phone pass.
- Hygiene passed at `378031c`. The platform matrix at `1914a88` failed the macOS
  throughput floors. `ef23281` finished 19/20, with only the macOS .NET 8
  clean-link floor failing: zero network drops, 58 retransmissions, 59,392 duplicate
  bytes and four window reductions. Buffered-response ordering reproduces a
  spurious retry locally when the verifier pauses. The downloader now consumes
  queued responses before timer decisions, bounds its frame queue to 256, measures
  RTT at pump arrival and records accepted request sends. All 24 focused congestion,
  bottleneck and recovery checks pass on .NET 8; final platform verification remains.
- Physical OPPO CPH2819 / Android 16 / API 36 / ARM64: Wi-Fi off, active cellular
  network checked before and after both runs. Automatic routing and forced relay
  each passed 48 byte-exact encrypted echoes (1–1200 bytes), with 48 sends each.
  Both used the Singapore HTTPS iroh relay. Automatic routing: connect 1383 ms,
  echo RTT p50 177 ms / p95 213 ms / max 295 ms. Forced relay: connect 1399 ms,
  p50 179 ms / p95 251 ms / max 298 ms. Closing retired the connection. This does
  not prove carrier-direct UDP/TCP, audio or lifecycle recovery.

Use `.github/scripts/verify-connectivity-drafts.sh` for the warning-free solution
build and both frameworks' separate interop, functional, resource and performance
processes. Required CI does not silently retry, skip or weaken failed gates.
