macOS CI at b0e1c8c passed all fresh-process resource gates, but RestoredUdp_UpgradesTheSameConnectionBackToDirect captured a null original UDP endpoint and later compared it with the actual restored endpoint.

The initial relay/direct race may return a connected session before both sides have selected UDP. This scenario specifically claims to restore the original UDP path, so it must wait for confirmed direct paths on both sides before recording their endpoints and injecting UDP loss. Preserve the later endpoint, object-identity and data-exchange assertions and existing deadlines.

Evidence: https://github.com/IAFahim/Pinhole.Net/actions/runs/37810958121/job/113427357496


## Implementation status — 2026-10-09

The original null-endpoint capture race was changed in commit `50e0389`. Before recording either endpoint or injecting loss, the test polls until both connection objects report Open, Direct and a non-null remote endpoint, within the original test deadline. The restored-endpoint equality, same-connection-object and bidirectional data assertions remain.

- [x] Implement the initial confirmed-path wait before capturing endpoints or injecting loss.
- [x] Preserve recovery assertions, connection identity, exchanged data and the original deadline.
- [ ] Verify the focused real-socket recovery test and complete platform CI after the fix, including that the initial path is UDP with the newer TCP sidecar enabled. The current draft build passes; the 154 socket-free cases do not execute this real-socket test. This audit could not retrieve current Actions results.

Keep this issue open until the regression/platform evidence is attached. The code change is recorded; closure is not being inferred from compilation or unrelated model tests.

