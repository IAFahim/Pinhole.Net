# Measured baselines (#27)

The numbers any blob congestion-control work (#20) is judged against. Everything here is
produced by committed tests with fixed seeds and fixed link parameters, so a before/after
comparison on one machine is meaningful; absolute numbers vary with hardware — re-run on
the same machine when comparing.

Reproduce:

```sh
dotnet test -c Release --filter "FullyQualifiedName~BottleneckTests|FullyQualifiedName~LossLadderTests" --logger "console;verbosity=detailed"
```

Environment of the recorded run: linux x64 (net10.0, Release), 2026-10-05, Pinhole 1.9.x.

## The bottleneck link model

`VirtualNet` shapes a real queue: one shared FIFO per rule, drained at a fixed bit rate,
tail-dropped when full; the rule's delay/jitter is propagation applied on dequeue. Queue
delay is emergent (a deep queue becomes bufferbloat, a thin one becomes loss), so these
rungs exercise the same regimes a real constrained uplink does.

## Recorded rungs (512 KiB file, BLAKE3-verified, all completed)

| Rung | Link | Goodput | Notes |
|---|---|---|---|
| deep queue | 16 Mbit/s, 128–256 pkt queue, 40 ms RTT, clean | **~1110 KiB/s** (57% of the 1953 KiB/s ceiling) | the fixed 4×64 window + 250 ms pacing cannot saturate a clean fat pipe — headroom any CC work should claim |
| thin queue | 16 Mbit/s, **16 pkt** queue, 40 ms RTT | **~32 KiB/s**, 1850+ tail drops, 762 chunks served vs 512 floor | congestion collapse: every burst overflows the queue, healing only via 900 ms re-requests — the headline case for pacing/bounded bursts |
| steady state × 5 seeds | 16 Mbit/s, 128 pkt queue, 40 ms RTT, 5% iid loss | **28–45 KiB/s** (seeds 801–805) | seed-to-seed spread ≈ 1.6×; loss + queue loss compound |
| mixed RTT | one 16 Mbit/s / 128 pkt bottleneck, near flow 5 ms vs far flow 120 ms | both 512 KiB flows in **~3.3 s** | the far flow still completes against the thin-RTT competitor |

Loss ladder (no bandwidth limit, zero-delay links, from the #22 lab):
1% → 494 KiB/s, 5% → ~250 KiB/s, 20% → 82 KiB/s, Gilbert-Elliott 10% (burst 8) → 251 KiB/s.

## Controller vs fixed window — same machine, same day (2026-10-06, #20)

The receiver-side controller (`docs/BLOBS.md` § congestion controller) against the fixed
window, both modes re-measured in the same Release run on the machine that recorded the
table above (fixed-window numbers reproduce the #27 record within a few percent — the
harness is stable). Reproduce either mode: `dotnet test -c Release --filter
"FullyQualifiedName~BottleneckTests|FullyQualifiedName~LossLadderTests"`, adding
`PINHOLE_BLOB_FIXED_WINDOW=1` for the baseline mode.

| Rung | Fixed window | Controller | Ratio |
|---|---|---|---|
| deep queue | 1102 KiB/s | 986 KiB/s | 0.89× |
| thin queue (16 pkt) | 31 KiB/s | 194–353 KiB/s | 6–11× |
| 5% loss × 5 seeds | 31–43 KiB/s | 98–227 KiB/s | 3–7× |
| mixed RTT (both flows) | 2.8 s | 0.7–0.8 s | ~3.7× faster |
| ladder 1% | 566 KiB/s | 1992 KiB/s | 3.5× |
| ladder 5% | 464 KiB/s | 691 KiB/s | 1.5× |
| ladder 20% | 69 KiB/s | 195 KiB/s | 2.8× |
| ladder GE 10% (burst 8) | 221 KiB/s | 474 KiB/s | 2.1× |

The one deficit is the clean-fat-pipe rung, and it is the documented trade, not a
surprise: the controller starts at a 32 KiB window and climbs (~100 ms on this rung)
instead of flooding 256 KiB instantly, and the 512 KiB test file is only ~6.5 BDPs — on
transfers large relative to the path's BDP the flow-phase rates are identical (the gap is
entirely the climb). The compensation is in the counters: the controller's shaper queue
stays at depth ≤ 3 the whole run where the fixed window bufferbloated 128–256 packets.
An IW ≥ 96 KiB matches the fixed window's deep-queue number (1092–1097) but measurably
hurts every lossy rung (the opening burst overflows thin queues deterministically) — 32
KiB was chosen because the thin-queue collapse is the scenario the controller exists for.

## What the baselines already forced out

- **A real lab bug**: the virtual scheduler delivered each 5 ms batch of delayed packets
  newest-first, which tripped the engine's strictly-increasing replay window — under any
  link delay the blob ARQ crawled at ~1 chunk per scheduler tick (~4 KiB/s). No prior test
  used delay, so it had never fired. Fixed before any CC tuning; a delay-only rung now
  pins it (`FiniteBandwidth_DeepQueue…` asserts real goodput under 40 ms RTT).

## Explicit gaps (documented, not hidden)

- **TCP competition** needs a real TCP sender sharing a kernel queue — in-process lab
  traffic only. It belongs to the root-gated real-network harness (#26's namespace
  matrix), not this file. The controller's claim is correspondingly narrow: AIMD-shaped
  backoff and burst bounds against the fixed window, measured in the lab — not
  "TCP-friendly" as a network claim, which only a real TCP competitor could establish.
- Fairness between two *similar* Pinhole flows is observable in the mixed-RTT rung's
  counters (both complete, far flow no longer starved: 0.7–0.8 s vs 2.8 s) but not yet
  asserted as a bandwidth ratio.
