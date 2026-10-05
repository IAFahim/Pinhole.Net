# Metrics (issue #25)

Pinhole instruments itself through .NET's own diagnostics stack,
`System.Diagnostics.Metrics`, on a meter named **`Pinhole.Net`**. Nothing is buffered
in-process: attach any standard consumer and the instruments appear.

- **OpenTelemetry**: `builder.Services.AddOpenTelemetry().WithMetrics(m => m.AddMeter("Pinhole.Net"))`
- **dotnet-counters / dotnet-monitor**: `dotnet-counters monitor --process-id <pid> Pinhole.Net`
- **In a test or tool**: a `MeterListener` filtered to `Pinhole.Net` (see
  `tests/Pinhole.Tests/TelemetryTests.cs` for a working collector).

Every instrument is disabled-by-default and allocation-light; when no listener is
attached, each call is a guarded no-op.

## Instruments

| Instrument | Kind | Dimensions | Meaning |
|---|---|---|---|
| `pinhole.connection.attempts` | counter | `outcome`, `path` | One dial or accept finished. Outcomes: `dial-established`, `dial-timeout`, `dial-cancelled`, `dial-faulted`, `accept-established`. `path` is `direct` or `relay` for established attempts. |
| `pinhole.connection.establish_duration` | histogram (ms) | `path` | Wall time from dial to a connected session, by the path that carried it. |
| `pinhole.connection.failures` | counter | `cause` | The engine refused an establishing connection; the cause is the engine's fixed handshake-failure sentence (static-key pin mismatch, refused encryption, failed confirmation). This is the failure-cause breakdown. |
| `pinhole.recovery.events` | counter | `kind` | One recovery maneuver: `path-suspect` (path validation condemned a path), `rebind` (socket rebound after network loss), `relay-retire` (a TURN client was retired on definitive refusal), `relay-reallocate` (a fresh allocation was made), `relay-heal` (a relay leg was re-confirmed usable). |
| `pinhole.frames.rejected` | counter | `layer`, `cause` | A frame was dropped as replayed, tampered, or unverified. Layers: `session` (engine crypto), `blob` (ticket cipher — `undecryptable` server-side garbage, `welcome-unverified` failed Welcome adoption). |

## What to compute from them

- **Connection success rate**: `attempts{outcome=dial-established}` ÷ total `attempts`;
  the complement split by `dial-timeout` vs `dial-faulted` is "unreachable" vs "refused".
- **Refusal causes**: the `cause` breakdown on `connection.failures` distinguishes
  man-in-the-middle pin failures from version/encryption mismatches.
- **Recovery health**: `recovery.events` rate per connection; a `relay-retire` followed by
  `relay-reallocate` and then `relay-heal` is a full ghost-allocation recovery cycle
  (the #22 fix), while `relay-retire` with no subsequent heal means the relay stayed gone.
- **Tamper exposure**: `frames.rejected` is passive-adversary noise plus active attacks;
  it should be ~0 on healthy paths.
