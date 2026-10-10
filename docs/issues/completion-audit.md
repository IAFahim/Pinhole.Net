# Open-issue completion audit — 2026-10-10

The current product roadmap is [#45](https://github.com/IAFahim/Pinhole.Net/issues/45),
mirrored in the [minimal SDK plan](minimal-sdk-roadmap.md): a small host/join API,
reuse first, direct UDP/TCP, NAT punching and automatic routing. The original
all-open-issues audit is retained below, with superseded planning mandates
distinguished from completed implementation. Existing code is not deprecated.
Implementation, focused checks, platform CI, physical networks and release
approval remain distinct evidence; a planning closure proves none of them.

## Completed issues

| Issue | Evidence |
|---|---|
| #18: port-mapping coordination | `eb19c61` and its follow-ups are ancestors of main; the issue already records completed implementation and validation. No remaining implementation request. Closed on 2026-10-10. |
| #41: IPv6 LAN discovery | Implemented and pushed; all functional/resource/performance jobs passed on Linux/macOS/Windows and .NET 8/10 at `543b52e`, [run 38034044891](https://github.com/IAFahim/Pinhole.Net/actions/runs/38034044891). Closed on 2026-10-10. |
| #42: isolated heap measurements | All six fresh-process resource jobs passed in the same full green matrix. Eight cycles, 512 KiB threshold and exact ledgers remain. Closed on 2026-10-10. |
| #44: same-endpoint UDP restoration | Both TCP-enabled/disabled real-socket variants passed in all six functional jobs. Initial/restored UDP, endpoints, object identity and data assertions remain. Closed on 2026-10-10. |
| #38: protocol specification | `docs/PROTOCOL.md` covers all requested frames, handshake flow/admission, canonical DH/HKDF labels and exact OKM offsets, nonce/AAD/replay/epoch rules, tickets and candidate encoding. Independent crypto vectors and real C#↔Kotlin interop verify the layouts. Closed on 2026-10-10. |

## Superseded planning scope

| Issue | Disposition |
|---|---|
| #15: connection-power audit | Closed as superseded/not planned. Its measured relay-selection question moves to #28/#27; historical plaintext, identity, discovery and PMTU claims are outdated. |
| #23: reliability roadmap | Closed as superseded/not planned. #45 controls product scope; its security, compatibility, recovery, managed C# and release obligations remain in the retained issues. |
| #40: every technique across core/phone | Closed as superseded/not planned. Direct UDP/TCP stays required; manual parity/prediction/gateway work is conditional on measured gaps. Candidate/recovery/platform needs move to #28/#31/#33/#43. |

These three closures are not implementation completions. The nineteen original
open issues were audited individually; sixteen remain open, plus the new #45.
OpusVoice and `YouAnd-I/OpusVoice.Receiver` had no open issues at this audit.
Phone draft PR #4 remains open; the planning change does not merge or close it.

## Remaining scope under #45

This table identifies the next missing evidence or implementation; it does not
replace the full acceptance checklist in each GitHub issue.

| Issue | Remaining requirements |
|---|---|
| #14: blobs | Optional application layer outside the first SDK MVP; complete its extended transfer matrix, throughput canary and allocation evidence before a blob release. |
| #17: testing discipline | Finish per-test trace files and changelog automation; attach evidence for topology/API/capacity gates. Warnings-as-errors is now the solution default. |
| #20: component selection and congestion control | Compare maintained managed SDK components against the current backend. Custom blob control remains conditional/optional; retain applicable wire-load/fairness evidence. |
| #24: independent security/recovery review | Record and fix all material findings, verify fixes, and complete independent review on the final candidate. The separate AI review stopped before completion; it is not a completed human audit or safety certification. |
| #25: diagnostics | Complete cause-specific events, reproducible JSON reports, latency distributions/cohorts, redaction and opt-in collection guidance. |
| #26: real network topology | Run pinned Patchbay/kernel configurations and actual HTTPS/TURN servers, including UDP blocking, failure capture and cleanup. Portable simulation is additional evidence. |
| #27: bottleneck baselines | The per-chunk worker dispatch and stale-path retry state are fixed; all six performance jobs pass in subsequent matrices without lowering floors. Complete sustained seed distributions, asymmetry/reorder/burst cases and actual TCP competition. |
| #28: candidate racing | Add SDK backend agreement to bounded UDP/TCP/relay racing, authenticated completion, cancellation and measured route improvement; retain real HTTPS/proxy/TLS checks. |
| #29: identity and rediscovery | Add account-free code lookup and authenticated signaling/key binding to full-key/freshness/provider/privacy/restart requirements. Both-direction roaming regression is fixed. |
| #30: relay failover | Finish independent provider/domain, DNS/TLS/proxy, allocation-change and long-outage evidence; only authenticated definitive TURN errors may condemn allocations. |
| #31: logical connection recovery | Complete all stated route/family/MTU/suspend/outage cases and platform evidence with the same connection object and bounded retry work. |
| #32: automatic verified resume | Optional application layer; retain checkpoint/crypto/durable-resume requirements for blob releases. Reliable channels alone do not supply verified resume. |
| #33: desktop/mobile matrix | Declare and test supported runtime/AOT/device combinations and physical network/lifecycle transitions. OPPO Android 16 LTE and same-session Wi-Fi/LTE/VPN transport checks pass; audio, suspend and other devices remain. |
| #34: bounded resources and soaks | Complete 24-hour and 72-hour runs with declared budgets, varied seeds, all required workloads and resource ledgers. Existing short tests and a harness do not prove long-run completion. |
| #35: release gate | Apply exact-candidate compatibility/security/platform/performance/soak and managed/license evidence to shipped packages; keep canary/rollback and owner approval. Optional blob work blocks blob releases, not the connection-only MVP by association. |
| #43: direct TCP | Required capability. Current core/phone tests and CI pass; finish source-bound OS simultaneous-open evaluation and supported integration evidence. TURN/TCP is not direct peer TCP. |

The current core baseline `4f3caea` passed **20/20** jobs in
[run 38040052589](https://github.com/IAFahim/Pinhole.Net/actions/runs/38040052589).
The running frozen-candidate 24h soak and queued 72h stage cover two concurrent
file transfers, verified cancel/resume and short blackouts. They remain useful
baseline observations; they do not validate a new WebRTC/signaling implementation
or all #34 roaming, relay restart and prolonged-outage workloads.

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

The `1f5fad2` matrix passed all twelve resource/throughput jobs, but two macOS
functional jobs failed: signaling cancellation left a retry husk, and the loss
curve inverted after earlier functional workloads. A new actual UDP regression
reproduced closing after a valid key confirmation but before token authentication.
The closed-handshake cache now remembers confirmed keys in that window; an
unproved handshake still cannot reserve its keys. The loss curve now runs in the
fresh performance process with its existing assertions unchanged. The complete
local verification script passes both frameworks: per framework, three interop,
588 functional, seven resource and three performance cases pass, with three
explicit environment-gated skips.

The revised soak warms and samples two concurrent downloaders, actually verifies
cancelled checkpoints on resume, deletes each output, and records candidate hashes,
seed, declared budgets and leak slopes before measurement. Short smokes pass on
.NET 10 (two minutes, 98 completed files, 19 resumes) and .NET 8 (one minute,
46 files, 10 resumes). Socket, connection, serving-worker and flow-budget ledgers
return to baseline every cycle. These validate the harness; they do not complete
the required 24h/72h or relay/roaming/long-outage workloads.
