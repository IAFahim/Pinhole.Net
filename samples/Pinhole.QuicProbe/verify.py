#!/usr/bin/env python3
"""Run the isolated QUIC fixtures; unsupported networking is never a passing test."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def verify(case, exit_code, report):
    expected = "EXPECTED_REJECTION" if case == "wrong_server_pin" else "PASS"
    if exit_code != 0 or report.get("Status") != expected:
        return False
    measurements = report.get("Measurements")
    if case == "wrong_server_pin":
        return measurements is None
    return (isinstance(measurements, dict)
            and measurements.get("VerifiedEchoes") == 101
            and measurements.get("PayloadBytes") == 64)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework", choices=("net8.0", "net10.0"), required=True)
    parser.add_argument("--configuration", choices=("Debug", "Release"), default="Release")
    parser.add_argument("--rust-server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sample = Path(__file__).resolve().parent
    assembly = sample / "bin" / args.configuration / args.framework / "Pinhole.QuicProbe.dll"
    peer = args.rust_server.resolve()
    if not assembly.is_file() or not peer.is_file():
        parser.error("Build the C# probe and Rust fixture before running verification.")
    if args.output.exists():
        parser.error("Choose a fresh output file; existing evidence is preserved.")
    evidence = {
        "status": "FAIL", "framework": args.framework,
        "assemblySha256": hashlib.sha256(assembly.read_bytes()).hexdigest(),
        "rustPeerSha256": hashlib.sha256(peer.read_bytes()).hexdigest(),
        "cargoLockSha256": hashlib.sha256((sample / "rust-peer" / "Cargo.lock").read_bytes()).hexdigest(),
        "cases": [],
    }
    cases = {
        "csharp_loopback": [],
        "csharp_rust": ["--rust-server", str(peer)],
        "wrong_server_pin": ["--rust-server", str(peer), "--wrong-server-pin"],
    }
    for case, arguments in cases.items():
        record = {"case": case, "verified": False}
        try:
            run = subprocess.run(["dotnet", str(assembly), *arguments],
                                 capture_output=True, text=True, timeout=30)
            record.update(exitCode=run.returncode, stderr=run.stderr)
            report = json.loads(run.stdout)
            record["report"] = report
            record["verified"] = verify(case, run.returncode, report)
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            record["error"] = f"{type(error).__name__}: {error}"
        evidence["cases"].append(record)
        print(f"{case}: {'PASS' if record['verified'] else record.get('report', {}).get('Status', 'FAIL')}")
        # A shared prerequisite failure prevents all network fixtures; do not retry it.
        if record.get("report", {}).get("Status") == "BLOCKED":
            evidence["status"] = "BLOCKED"
            break
    if len(evidence["cases"]) == len(cases) and all(record["verified"] for record in evidence["cases"]):
        evidence["status"] = "PASS"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"Evidence: {args.output}")
    return 0 if evidence["status"] == "PASS" else 2 if evidence["status"] == "BLOCKED" else 1


if __name__ == "__main__":
    sys.exit(main())
