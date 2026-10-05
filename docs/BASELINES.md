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

## What the baselines already forced out

- **A real lab bug**: the virtual scheduler delivered each 5 ms batch of delayed packets
  newest-first, which tripped the engine's strictly-increasing replay window — under any
  link delay the blob ARQ crawled at ~1 chunk per scheduler tick (~4 KiB/s). No prior test
  used delay, so it had never fired. Fixed before any CC tuning; a delay-only rung now
  pins it (`FiniteBandwidth_DeepQueue…` asserts real goodput under 40 ms RTT).

## Explicit gaps (documented, not hidden)

- **TCP competition** needs a real TCP sender sharing a kernel queue — in-process lab
  traffic only. It belongs to the root-gated real-network harness (#26's namespace
  matrix), not this file.
- Fairness between two *similar* Pinhole flows is observable in the mixed-RTT rung's
  counters but not yet asserted as a ratio; that comparison becomes meaningful when a
  controller exists to compare against this fixed-window baseline.
