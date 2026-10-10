# Open-issue completion audit — 2026-10-10

The goal is to complete every open issue, including cross-repository work and
release evidence. Implementation, passing focused tests, a completed platform
matrix, physical-network results, and release approval are separate requirements.
An issue closes only when its own requirements are proved.

## Completed issues

| Issue | Evidence |
|---|---|
| #18: port-mapping coordination | `eb19c61` and its follow-ups are ancestors of main; the issue already records completed implementation and validation. No remaining implementation request. Closed on 2026-10-10. |
| #41: IPv6 LAN discovery | Implemented and pushed; all functional/resource/performance jobs passed on Linux/macOS/Windows and .NET 8/10 at `543b52e`, [run 38034044891](https://github.com/IAFahim/Pinhole.Net/actions/runs/38034044891). Closed on 2026-10-10. |
| #42: isolated heap measurements | All six fresh-process resource jobs passed in the same full green matrix. Eight cycles, 512 KiB threshold and exact ledgers remain. Closed on 2026-10-10. |
| #44: same-endpoint UDP restoration | Both TCP-enabled/disabled real-socket variants passed in all six functional jobs. Initial/restored UDP, endpoints, object identity and data assertions remain. Closed on 2026-10-10. |
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
| #27: bottleneck baselines | The per-chunk worker dispatch and stale-path retry state are fixed; all six performance jobs pass in subsequent matrices without lowering floors. Complete sustained seed distributions, asymmetry/reorder/burst cases and actual TCP competition. |
| #28: candidate racing | Verify bounded shared-deadline racing, actual HTTPS/proxy/TLS negative cases, cancellation and authenticated upgrade/fallback. |
| #29: identity and rediscovery | Audit complete full-key/freshness/provider/privacy/restart requirements against current tests and real infrastructure. Both-direction roaming regression is fixed. |
| #30: relay failover | Finish independent provider/domain, DNS/TLS/proxy, allocation-change and long-outage evidence; only authenticated definitive TURN errors may condemn allocations. |
| #31: logical connection recovery | Complete all stated route/family/MTU/suspend/outage cases and platform evidence with the same connection object and bounded retry work. |
| #32: automatic verified resume | Verify every handshake interruption, directory/counter/checkpoint invariant, prolonged outage, restart, tamper and cancellation case. Recovery allowance now has deterministic clock checks and a shaped restart scenario. |
| #33: desktop/mobile matrix | Declare and test supported runtime/AOT/device combinations and physical network/lifecycle transitions. OPPO Android 16 LTE and same-session Wi-Fi/LTE/VPN transport checks pass; audio, suspend and other devices remain. |
| #34: bounded resources and soaks | Complete 24-hour and 72-hour runs with declared budgets, varied seeds, all required workloads and resource ledgers. Existing short tests and a harness do not prove long-run completion. |
| #35: release gate | Consolidate exact-candidate compatibility/security/platform/performance/soak evidence, correct reliability claims, verify package contents, and prepare a canary/rollback. Owner approval remains required for a release. |
| #40: all connection techniques | Kotlin outgoing TCP fallback, path labels and scoped IPv6 are in draft PR #4 with interop/device evidence. Finish interface/signaling/IPv6-pinhole/NAT-prediction/TURN parity, receiver firewall/listener integration, remaining physical network tests and release evidence. The full parent checklist remains authoritative. |
| #43: direct TCP | Kotlin outgoing transport/path labels/scoped IPv6 pass local socket and interop checks. Complete prior-version compatibility/performance, source-bound OS simultaneous-open evaluation and final phone CI evidence. |

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
- [OpusVoice draft PR #4](https://github.com/IAFahim/OpusVoice/pull/4) fixes the same
  first-PACK token issue and adds authenticated outgoing TCP fallback in Kotlin.
  All seventeen C#↔Kotlin interop cases pass against core `543b52e`, including
  TCP IPv4/IPv6, blocked receiver UDP, healthy UDP preference, stable selection
  across two reference relays, lost flights, token editing, native discovery and
  relay-to-direct upgrade. Nine socket tests cover framing, deadlines, bounded
  attempts, connection generations and refusal of unproved stream traffic.
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

The complete local verification script passed both frameworks at `76b593d`.
Its CI matrix (`38032055722`) passed every performance and resource job but failed
three functional jobs: a late PUNC recreated a closed session before the reverse
dial, signaling cancellation left a similar retry husk, and a queued local STUN
fixture missed the probe deadline. The follow-up remembers up to 1024 closed
handshakes, ignores exact authenticated-session PUNC retries for 60 seconds, and
arms an unfinished incoming connection with an explicit dial's pins, candidates,
lookup and punch work. A verified PACK may replace old keys only while that
adopted connection has no authenticated traffic and has never completed its
application connection. Idempotent dials also check the caller's static key.
Six new actual UDP regressions cover those cases; 76 focused .NET 10 checks and
86 .NET 8 checks pass. The local STUN fixture now starts receiving immediately.

The follow-up matrix at `543b52e` finished **20/20 green**, including all six
functional, six resource and six throughput jobs, mesh smoke and the canary.
The phone also passed Wi-Fi → LTE → Wi-Fi (direct UDP → Singapore relay → direct
UDP) and Proton VPN → Wi-Fi → Proton VPN (forced relay) on the same dialer
instance in each run: 48/48 byte-exact echoes per sequence. LTE recovery took
8.25 s; VPN removal/restoration took 2.14/3.35 s. These are foreground transport
checks with a temporary CPU wake lock; they do not prove audio or suspend behavior.
The [redacted handoff report](https://github.com/IAFahim/OpusVoice/blob/0ea8d00/docs/validation/2026-10-10-oppo-handoffs.json)
pins Kotlin `358a25e`, the actual core `76b593d` handoff assembly and both APKs.
Recovery measurements start with the first request after Android reports the new
network; they exclude the network transition and the initial connect.

The subsequent local blob audit reproduced publication of data before its final
root check and acceptance of a truncated checkpoint. Completion now verifies the
root before replacing the destination, checkpoint state follows flushed data,
and file hashing/deduplication retain bounded metadata. HEAD totals must agree.
The real encrypted UDP regressions, independent hash oracle, parser properties,
fresh-process resource checks and unchanged throughput gates pass locally.
The independent final-candidate security review and long soaks remain open.
