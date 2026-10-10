# CI flake investigation — Windows TCP hardening family — 2026-10-11

Branch `fix/ci-tcp-hardening-races`. Investigation of the recurring
`TcpSocketHardeningTests` / `TcpSessionTests` CI failures (Windows runners,
retry-clean), with captured logs, local reproductions, and cause fixes that
preserve every assertion. Work done in a separate checkout; the main working
copy was untouched.

## Captured failures

- **Run [38089918978](https://github.com/IAFahim/Pinhole.Net/actions/runs/38089918978)
  attempt 2, `test-windows-latest`:** all three hardening cases at once —
  - `OversizedFrameHeader_ClosesTheStreamWithoutASession(8193)` and `(65535)`:
    `Assert.NotNull` failure on `Nullable<int>` at `TcpSocketHardeningTests.cs:48`
    → `node.TcpListeningPort` was null, ~1 s duration.
  - `WrongStaticKey_TcpOnlyDial_FailsCleanlyWithoutDowngrade`: expected
    `InvalidOperationException` (pinned-key mismatch), got `TimeoutException`
    from `PinholeNode.ConnectPeerAsync` after the 8 s budget, 9 s duration.
- **Earlier recurrences:** run 38067401382 (all three cases again), 38064620863
  (one oversized case), 38024541744 (`TcpSessionTests.MalformedLength…` both
  cases, same null-port signature at line 87, 27–36 ms; plus
  `TcpOnly_Authenticates…(::1)` with the same 8 s connect timeout).
- Sibling `TcpRouterIntegrationTests.DefaultTcpSidecar…` failed twice more
  (38068940865, 38068038598) in its 45 s port-mapping poll; that test already
  documents serialized mapping passes over 20 s under suite load and is a
  separate budget domain — not addressed here.

## Frequency context (last 60 CI runs, 42 with ≥1 failure)

TCP socket family: 4 runs, 10 case-failures. The wider flake population is
dominated by bandwidth/budget tests (`BottleneckTests.FiniteBandwidth…` ×7,
`BlobResumeTests.ProviderRestart…` ×4, plus ~25 singletons), which are
runner-performance-sensitive by construction. The TCP family is the part with
identifiable, fixable races and is what this branch fixes.

## Root causes

### 1. Null sidecar port — Windows excluded TCP ranges, blind retries

`TcpTransport.Rebind` deliberately swallows TCP bind failure ("does not
prevent UDP"), leaving `TcpListeningPort` null. On Windows, Hyper-V/WSL
reserve large excluded port blocks; a UDP-chosen ephemeral port repeatedly
lands in them, and the tests' blind 8-attempt ephemeral retry exhausted (both
oversized cases + `MalformedLength`'s `TcpListeningPort!.Value` dereference).

**Fix (tests, assertions preserved):** `SidecarSockets` probes a port that
**both** UDP and TCP accept before binding the node (`ProbeDualStackEndpoint`),
replacing blind retries; bind collisions still retry; callers still assert
`TcpListeningPort`. Linux/macOS behavior is unchanged.

### 2. Connect-budget exhaustion — failed TCP dial frozen out by two stacked 5 s throttles

Dial sequence: 1.2 s UDP-first window → `TryTcpPathsAsync` →
`TcpTransport.ConnectAsync`. Both layers recorded a 5 s gate, and the
transport recorded its per-endpoint entry **before** dialing, leaving it in
place on failure. One transiently failed round under runner load (3 s
negotiation deadline against a slow greeting) froze every retry until
t+5 s; with an 8 s `ConnectTimeout` the single remaining round could not
finish → `TimeoutException` instead of the fast pinned-key
`InvalidOperationException`. This explains the wrong-key timeout and the
`::1` TCP-only timeout identically.

**Reproduction (before the fix, this machine):**
`TcpDialRetryTests.FailedDial_DoesNotFreezeTheEndpointForTheSuccessThrottle`
— a silent acceptor fails the first dial at its 3 s negotiation deadline;
the immediate retry to a real listener on the same port returns **null
without attempting** (throttle hit). Failed on unmodified `main`; passes
after the fix.

**Fixes (product, semantics preserved):**
- `TcpTransport.ConnectAsync`: a dial that produced no link removes its
  `_attempts` entry on failure; successful dials keep it. Concurrent dials
  remain impossible (`_dialing`).
- `NodeEngine.TryTcpPathsAsync`: the single 5 s `LastTcpAttempt` gate is
  split — a wholly failed batch backs off 1 s (batches serialize via
  `TcpDialing`; punch pace is 200 ms), while a batch that **established a
  link** still gates 5 s (`LastTcpLinkTicks`) so live handshakes are not
  churned. Stranger-flood protections (per-stream peer binding, 10 s
  authentication deadline, MaxLinks) are untouched.

## Verification

- New regression `TcpDialRetryTests`: fails on unmodified code (NotNull
  failure, instant null), passes after the fix.
- TCP family (hardening + session + retry, 12 tests): 10/10 iterations ×
  both frameworks pinned to 2 cores with competing CPU load — 20/20 green.
- Full suite net10.0/net8.0 in this checkout: green (see PR checks for CI).
- Assertions unchanged everywhere: `Assert.NotNull(TcpListeningPort)`, the
  exact-exception pinned-key asserts, oversized-frame close/EOF asserts.

## Not addressed (documented for triage)

- `TcpRouterIntegrationTests` port-mapping poll (serialized PCP passes under
  load; separate budget).
- Bandwidth/budget flake population (`BottleneckTests`, `BlobResume…`,
  singletons) — runner-performance sensitive; needs its own pass.
