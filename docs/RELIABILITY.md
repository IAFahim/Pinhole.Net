# Compatibility, recovery limits, and measured reliability

This is the release-evidence document (#35): what is guaranteed, what has been
measured, where the measurement lives, and what is explicitly not supported.
Every claim below links to the test or artifact that backs it — none of them are
aspirations. Where evidence does not exist yet, the item is listed under
[Known limitations](#known-limitations), not smoothed over.

## Supported platform matrix

| Surface | Status | Evidence |
|---|---|---|
| .NET 8 / .NET 10, Linux (x64) | CI-tested every push/PR | `.github/workflows/ci.yml` — full suite on `ubuntu-latest` |
| .NET 8 / .NET 10, macOS | CI-tested every push/PR | same job on `macos-latest` |
| .NET 8 / .NET 10, Windows | CI-tested every push/PR | same job on `windows-latest` |
| Mobile (Xamarin/MAUI targets) | Not validated | no harness yet — see limitations |
| Trimming / AOT | Not validated | ILLink.Tasks is auto-referenced but no `IsAotCompatible` claims or trimming tests exist |

The suite is self-contained on every OS: STUN and TURN run against in-process
fakes, and the virtual network makes the NAT/loss matrix portable — no scenario
is skipped on Windows or macOS. What the lab cannot reproduce (kernel NAT
behavior, real NICs) is covered by the env-gated real-infrastructure tests
(`docs/TESTING.md` § #26) and the scheduled mesh canary (`mesh.yml`), both of
which run real OS sockets on GitHub runners.

## Compatibility

### Core wire and session crypto

Wire encryption has been stable since v1.6: triple-DH X25519 handshake over a
canonical transcript, AES-256-GCM per frame, 64-frame replay window, HKDF epoch
ratchet every 2^28 frames. There is no downgrade path: a stripped or tampered
handshake fails, `PinholeEncryption.Required` (the default) refuses plaintext
peers outright, `Optional` speaks plaintext only with pre-1.6 peers, and
`Disabled` reproduces the old wire exactly for interop testing.

### Connection strings / tickets

`pinhole1:` envelope, three payload versions (`docs/PROTOCOL.md` § connection
strings):

| Version | Carries | Decoded by | Dialed by |
|---|---|---|---|
| v1 | peer id, candidates, NAT hint | all versions | refused by default nodes (no identity to pin against) |
| v2 | + static public key | all ≥1.6 | all ≥1.6 |
| v3 | + endpoint key (identity pin) | all ≥1.10 | all ≥1.10 |

Truncated v3 strings are refused; unknown versions fail explicitly.

### Blob wire

v3 since 1.10: Hello/Welcome carry explicit versions, Welcome mints the provider
nonce, keys derive from ticket PSK + content root + fresh two-sided session
nonces, and every re-dialed session derives fresh keys — a recovery never
continues old counters under recreated keys. A v3 provider recognizes a pre-3.0
downloader's Hello and refuses without serving ciphertext under an old key; the
legacy derivation is open-only for that refusal. Ticket format is unchanged —
a resumed download requests a shorter tail from any v3 provider.

### Stored state (checkpoints)

`<target>.pinhole-part/` directories carry magic `PBPART01`, the content root,
total size, and the applied-prefix count. A checkpoint whose root or size
disagrees with the ticket is ignored; a data file shorter than the recorded
prefix is treated as absent. Checkpoints are not a compatibility surface for
older releases — they were introduced in 1.10 — and are safe to delete at any
time (the download simply restarts from zero).

## Recovery contract — what is automatic and what is not

**Automatic** (ridden, never surfaced while any budget remains):

- Silent route loss mid-transfer: the engine's path validation marks the path
  suspect; the blob layer pauses its stall clock and request growth while no
  usable path exists and resumes when one returns — byte-exact, one call.
- Connection death: the same `DownloadAsync` call re-dials the pinned provider
  through the ticket (authenticated rediscovery when the peer has moved),
  doubling 500 ms → 5 s, resuming on the wire from the checkpointed prefix's
  first gap. Verified bytes never cross the network twice.
- Roaming, relay failover, provider restart: one call rides through them;
  directory manifests and completed roots carry across re-dials.

**Not automatic** (verdicts — surfaced immediately, never retried):

- Provider `Bye` (it cancelled the stream), a chunk failing BLAKE3
  verification, a root mismatch, a refused handshake (dial-stage
  `InvalidOperationException` — e.g. an incompatible legacy peer), and caller
  cancellation (honored promptly even mid-blackout).

**The budget**: `BlobDownloadOptions.RecoveryTimeout` (default **10 min** —
chosen so a five-minute outage is survivable) bounds the whole recovery regime:
pathlessness, per-attempt stalls, and re-dial backoff all ride down the same
deadline. Exhaustion throws `TimeoutException` saying the transfer "could not
be re-established within Ns". `TimeSpan.Zero` disables recovery: the first
transport failure surfaces as `TimeoutException` naming the dead attempt.
Negative values are rejected. When no route is available and none returns
within the budget, that is the answer the application gets — the call never
hangs and never silently degrades.

Longer-lived knobs underneath it (details in `docs/BLOBS.md`): 30 s stall
clock, first-Head timeout, `PmtuReprobeInterval` 5 min, dead-peer beacons 1/s
for 5 min, relay slot ladder 30 s → 5 min.

## Measured evidence

All numbers are produced by committed tests with fixed seeds and shaped virtual
links — reproducible by re-running them, not by trusting this page. They are
single-runner, small-sample measurements: they demonstrate mechanism and
relative ordering, and they are *not* percentage-of-nines claims.

| Evidence | Where | What it shows |
|---|---|---|
| Unit + loopback suite | `ci.yml`, 3 OS × every push/PR | 310+ tests: API, crypto oracles, roaming, relay failover, blob roundtrips, recovery scenarios, bounded-resource ledgers |
| NAT pairing matrix | `TopologyLabTests` (`docs/TESTING.md`) | all 16 NAT pairings reproduce the classical hole-punching table: 13 direct, 3 relay-only |
| Loss ladder / baselines | `LossLadderTests`, `docs/BASELINES.md` | fixed-window and controller goodput curves; measured controller gains 1.5–11× on degraded links, 0.89× on a clean fat pipe (the honest cost) |
| Recovery scenarios | `BlobResumeTests` (`docs/TESTING.md` § #32) | 30 s blackout, direct→relay cut, provider rebind/restart, refusal, tamper, cancellation, nonce freshness — same call, byte-exact |
| Resource boundedness | `BoundedResourceTests` (§ #34) | budget drains to zero after cancel/churn, socket ledger flat, 30 failed dials leave no connection-table husks, hostile barrage draws no amplification |
| Soak harness | `MixedWorkloadSoak` + `SustainedSize_ThroughTailDrop` (§ #34) | env-gated (`PINHOLE_SOAK_MINUTES`); per-minute CSV of heap/threads/handles/sockets/budget — the format scheduled 24 h/72 h runs will attach |
| Throughput canary | `ci.yml` bench job | ≥ 25k datagrams/s on shared CI vCPUs, < 0.1 B/dgram allocation — a regression tripwire, not a peak claim |
| Live internet | `mesh.yml` weekly canary | three unknown GitHub runners discover each other via connection strings, exchange secrets 3 rounds; `force_relay` variant proves relay-only |

### What "measured" does not mean here

We do not publish connect-success percentages or nines. The suite's coverage
is scenario-explicit: each claim names the test that proves it under stated
conditions. A 24 h/72 h soak and the real-OS support matrix (#33) are the
evidence expansion scheduled before release — until their CSVs are attached,
durability claims stay scoped to what has actually run.

## Diagnostics

Runtime instrumentation is emitted on the .NET diagnostics meter
`Pinhole.Net` — connection attempts, recovery events, failure causes — and is
safe to collect by construction: counters and state transitions only, never
payloads, keys, or peer contents. `BlobTransferStats` exposes per-transfer
verified/duplicate bytes, retransmits, loss events, RTT, and window. Details in
`docs/METRICS.md`.

## Dependency verification

The published packages are fully managed C# — verified, not asserted:

```
dotnet list <project> package --include-transitive
```

- `Pinhole.Net` → `BouncyCastle.Cryptography` 2.7.0 + `Pinhole.Turn` +
  `Pinhole.Providers` (both zero external deps)
- `Pinhole.Blobs` → `BouncyCastle.Cryptography` 2.7.0 + `Pinhole.Net`
- `BouncyCastle.Cryptography` ships managed assemblies only (net461, net6.0,
  netstandard2.0 — no `runtimes/` native assets in the nupkg)
- `Microsoft.NET.ILLink.Tasks` appears in the graph as an *auto-referenced
  build-time* package; it is not a runtime dependency

No project in the shipping closure P/Invokes, loads a native library, or
depends on a package that does.

## API compatibility

Every shipped project's public surface is checked in as a Roslyn PublicAPI
listing (`PublicAPI.Shipped.txt` / `PublicAPI.Unshipped.txt`, nullable
annotations recorded, `Microsoft.CodeAnalysis.PublicApiAnalyzers` 5.6.0 as a
build-time-only reference). Adding or mutating public API without updating the
listing is a build **error** (RS0016), and removing or changing existing API —
a binary-breaking change — is a build error outright (RS0017). To intentionally
change surface: `dotnet format analyzers src/<project>/<project>.csproj
--diagnostics RS0016` regenerates the listing; the diff is reviewable in the
PR. The .NET/runtime/AOT test matrix is the CI table above.

## Known limitations

Collected in one place so nothing relies on tribal knowledge:

- **Single-relay restart in place** — a TURN-relayed session whose only relay
  restarts cannot heal: both peers' relayed addresses die with the server.
  Documented since 1.9.0 (`docs/TESTING.md`); fresh-ticket redial heals in
  ~9 s. iroh-URL relays are not affected (identity-dialed, re-reached through
  the same URL).
- **Both-sides-dead rebind while STUN is dark** — beacons flow but PACK replies
  do not return; the single-side variants heal, this corner is recorded in
  `docs/TESTING.md` § #31 rather than claimed.
- **Wrong-identity responder at the provider's address** — a node with a
  different PeerId occupying the provider's address drops our datagrams
  pre-handshake, which is indistinguishable from the provider being down: the
  transfer rides the full `RecoveryTimeout` rather than failing fast. Inherent
  to authenticated dials — a stranger cannot prove it is not the provider
  without the keys.
- **Duplicate flood under sustained tail-drop** — FIXED: the flood was requests
  outrunning the sink's reorder horizon (floor-dropped arrivals consumed their
  reservations), not racing re-requests. The request horizon is now capped at
  `applied + reorderSpan`; measured duplicate bytes are zero at unit and
  sustained scale (#36, `docs/BASELINES.md`).
- **`BlobProgress.FilesDone`** — counts only fully root-verified files; the
  in-flight file's ordinal is `min(FilesDone + 1, FilesTotal)` for progress
  displays. Fixed while still unshipped (#37).
- **`NodeEngine.MaxConnections` flood** — covered: an internal
  `MaxConnectionsOverride` test seam shrinks the cap, and the flood test proves
  admission refusal and slot recovery with real handshakes.
- **Byte-level wire fuzzing** — covered: FsCheck property tests fuzz the frame,
  manifest, ticket, and connection-string parsers (never-throw contracts,
  encode/decode round-trips, decoded-value invariants). One defect found and
  fixed already: negative manifest entry sizes are now rejected.
- **Mobile and AOT/trimming** — untested; no claims are made for them.
- **24 h / 72 h soak evidence** — harness ready (`PINHOLE_SOAK_MINUTES`); the
  long runs are pending before release.
- **Independent security/recovery review** (#24) — outstanding; findings gate
  the release.
- **Previous-version interop runs** — wire-compatibility tests against the last
  published package are specified above but not yet automated. Open under #35.

## Release mechanics: canary and rollback

Releases ride the existing tag-push pipeline (`nuget.yml`): `dotnet pack` on
the tag builds all packages with symbols, uploads them as workflow artifacts,
and pushes to nuget.org only when `NUGET_API_KEY` is set — a missing key skips
the push rather than half-publishing. `--skip-duplicate` makes a re-run of the
same tag idempotent.

Canary plan for the first 1.10 release: publish `1.10.0-rc.1` (NuGet prerelease
tags are opt-in by construction — clients on stable ranges never see it), hold
for opt-in field runs plus the soak evidence above, then promote to stable by
pushing the release tag of the same commit. Rollback is NuGet's only honest
shape: unlisting hides a bad build but never deletes it — the recovery lever is
a fast-follow patch release, so the canary exists to keep that from ever being
needed. Merges and releases require owner approval; nothing in this repository
publishes itself.
