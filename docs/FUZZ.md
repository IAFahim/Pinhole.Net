# Fuzzing

`src/Pinhole.Fuzz` is a deterministic, coverage-lite mutation fuzzer for every
Pinhole.Net surface that parses untrusted bytes or text. It has no NuGet
dependencies, targets `net8.0;net10.0`, and doubles as a library: the smoke
tests in `tests/Pinhole.Tests/FuzzSmokeTests.cs` drive the same engine through
the same registry, so a console finding and a test finding mean the same thing.

## How it works

- A per-target xorshift128+ stream (seed stamped with the target name, splitmix
  finalized) drives every random choice. Same `--seed`, same target, same
  sequence of inputs — on any machine, any .NET version of the same major.
- Each iteration clones a seed-corpus entry and applies 1–4 mutation
  operations, recording the full lineage (`corpus#2 > flip@9:0x80 > splice@4<-pool[7..12)`).
  Operators: single-bit flips, interesting-byte spills, chunk splice from the
  corpus pool, slice duplicate, slice delete, boundary-value inserts
  (0x00/0x01/0x3F/0x40/0x7F/0x80/0xBF/0xC0/0xFE/0xFF…), random inserts, and
  truncation.
- Every input runs on the thread pool under a per-input timeout (2 s default)
  and a size clamp (16 KiB default): an input that hangs or balloons is itself
  a finding, as is any exception outside the target's documented family.
- Seed corpora are built with the library's own writers (`WriteHello`,
  `Encode`, `WriteBindingResponse`, `CreatePayload`, …), never hand-assembled
  bytes, so a corpus entry is valid by construction.

## Targets and oracles

The oracle per target is: malformed input is answered by a boolean `false`
return or by the parser's documented exception family — anything else (index
errors, `NullReferenceException`, `OperationCanceledException`, timeouts, a
successful parse that throws when re-encoded) is a finding.

| Target | Entry point | Malformed input is |
|---|---|---|
| `connection-string` | `Pinhole.ConnectionString.Parse` | `FormatException` |
| `wire-connection-string` | `ConnectionStringCodec.TryRead` | `false` |
| `blob-ticket` | `Pinhole.Blobs.BlobTicket.Parse` | `FormatException` |
| `blob-ticket-wire` | `BlobTicketCodec.TryRead` (+ `Write` re-encode on success) | `false` |
| `blob-manifest` | `ManifestCodec.TryRead` (+ `Write` re-encode on success) | `false` |
| `blob-frame` | `BlobFrameCodec.TryParse` (+ full `BlobFrameView` accessor sweep on success) | `false` |
| `dns-message` | `DnsWireCodec.TryReadMessage`, `AsksForService`, `TryReadPtrTarget`, `TryReadSrv`, `TryReadTxtEntries`, `TryReadTxtText` | `false` |
| `stun-binding` | `StunCodec.TryReadBindingRequest`, `TryReadBindingResponse`, `TryReadAddress` | `false` |
| `address-record` | `AddressRecordCodec.TryReadBody`, `TryReadSigned` (+ `WriteBody` re-encode on success) | `false` |
| `iroh-discovery` | `IrohDiscovery.ParsePayload` | `InvalidDataException` |
| `tcp-frame` | `TcpFrameCodec.ReadAsync` over a `MemoryStream` | `IOException` family |

`iroh-discovery` and `tcp-frame` parse internal types, so they are registered
by the test assembly (which holds `InternalsVisibleTo`), not by the console
binary; `--target all` in the console covers the other nine. The smoke test
covers all eleven. Registering them in the console would require adding
`Pinhole.Fuzz` to `InternalsVisibleTo` of engine projects — an engine edit this
harness deliberately avoids.

## Running campaigns

```
dotnet run --project src/Pinhole.Fuzz -f net10.0 -- --list
dotnet run --project src/Pinhole.Fuzz -f net10.0 -- --target all --iterations 5000000 --seconds 60 --seed 20261029
dotnet run --project src/Pinhole.Fuzz -f net10.0 -- --target dns-message --iterations 100000 --seed 7
```

Defaults: every target, seed 0, 50 000 iterations, no time budget. `--seconds
N` caps each target at N seconds (whichever limit hits first stops the target),
`--max-input N` clamps mutated input size. Exit code is `0` when clean and
`1` when any target reports a finding, so campaigns slot into scripts and CI.
The smoke test (`dotnet test tests/Pinhole.Tests -f net10.0 --filter
FullyQualifiedName~FuzzSmoke`) runs every registered target for 3 000
fixed-seed iterations in well under a second.

## Reproducing a finding

A finding prints everything needed to replay it byte for byte:

```
FINDING target=blob-frame seed=20261029 iteration=40213
  lineage=corpus#5 > flip@9:0x04 > del@30+2
  input=010700000000000000042B0101010101...
  detail=System.IndexOutOfRangeException: ...
```

Replay the exact offending bytes with the hex line:

```
dotnet run --project src/Pinhole.Fuzz -f net10.0 -- \
  --target blob-frame --hex 010700000000000000042B0101010101...
```

The replay exits `1` if the input still offends. The `seed` plus `lineage`
reproduce how the harness derived the input (`FuzzRunner.Run` with the same
seed regenerates it at the same iteration); the hex is authoritative and the
fastest path into a minimized xunit reproduction test. A regression test
embeds the hex via `FuzzRunner.Replay` (see
`FuzzSmokeTests.PlantedCrash_IsDetected_AndReproducesFromPrintedHex` for the
pattern) and is named after the defect it pins.

## Adding a target

Register a `FuzzTarget` in `BuiltinTargets.RegisterAll` (console-visible
parsers) or next to the smoke tests (internal parsers):

```csharp
FuzzRegistry.Register(new FuzzTarget(
    "my-codec",
    () => [MyCodec.Write(validValue)],
    input => MyCodec.TryRead(input, out _),
    ex => ex is FormatException));
```

Keep the corpus honest — build every entry with the codec's own writer. State
the oracle's tolerated-exception family explicitly, and only for parsers whose
contract is throwing (for `TryRead`-style codecs malformed input must be a
plain `false`, and the lambda is omitted). The target shows up in `--list`,
in `--target all`, and in the smoke-test theory automatically.
