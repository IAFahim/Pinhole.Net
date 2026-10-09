The IPv6 discovery change passed every new test on Linux, macOS, and Windows, but macOS CI failed the existing RepeatedCancelResume_ReturnsEveryReservation process-heap slope assertion: median cycle delta 1153 KiB while the total heap moved only 10.1 → 11.0 MiB, and all deterministic socket/budget ledgers returned to baseline.

That test currently samples the shared process GC heap while other xUnit collections allocate concurrently. A median does not isolate those allocations from the measured transfer. Preserve the 512 KiB threshold and the eight cancellation/resume cycles; run process-wide resource measurements in a nonparallel test collection, then verify both the focused resource tests and complete platform CI.

Evidence: https://github.com/IAFahim/Pinhole.Net/actions/runs/37807703384
This is a validation follow-up to #41 and #40, not a claim that a failed test can be ignored.


## Implementation status — 2026-10-09

Implemented in `828b7d4` and `b0e1c8c`: resource tests are in a nonparallel collection, and CI executes the resource suite in a dedicated fresh test process on each of Linux, macOS and Windows, separate from functional and throughput suites. Heap samples are logged. The eight cancellation/resume cycles, 512 KiB median-growth threshold, and deterministic socket/budget debt checks remain intact; the gate was not relaxed.

The macOS run cited by #44 passed the fresh-process resource gates and instead failed the independent initial-UDP-path assertion. That assertion was subsequently changed in `50e0389`.

- [x] Implement nonparallel collection isolation.
- [x] Run the resource suite separately in fresh platform test processes and log heap samples.
- [x] Preserve the existing heap threshold, cycle count and exact resource ledgers.
- [ ] Attach the focused resource and completed Linux/macOS/Windows matrix results after the follow-up fix, then close this issue. This audit could not retrieve current Actions results; the reported macOS pass alone is not verification of the whole platform matrix.

