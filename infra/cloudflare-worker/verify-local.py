"""Run the real local Worker and the C# Host/Join API without account secrets."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.request

root = Path(__file__).resolve().parents[2]
worker = Path(__file__).resolve().parent
frameworks = ["net8.0", "net10.0"]
with tempfile.TemporaryFile(mode="w+") as log:
    process = subprocess.Popen(
        [str(worker / "node_modules/.bin/wrangler"), "dev", "--port", "8788",
         "--var", "TURN_REQUIRED:false"], cwd=worker, stdout=log,
        stderr=subprocess.STDOUT, start_new_session=True)
    try:
        deadline = time.monotonic() + 45
        while True:
            if process.poll() is not None:
                raise RuntimeError("Local Worker exited before readiness")
            try:
                with urllib.request.urlopen("http://127.0.0.1:8788/health", timeout=1) as response:
                    health = json.load(response)
                    if health["version"] == 1 and health["turnConfigured"] is False:
                        break
            except (OSError, ValueError):
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError("Local Worker did not become ready")
            time.sleep(0.2)
        for framework in frameworks:
            subprocess.run(["dotnet", "build", "samples/Pinhole.CloudflareProbe",
                            "-c", "Release", "-f", framework], cwd=root, check=True)
            result = subprocess.run([
                "dotnet", str(root / f"samples/Pinhole.CloudflareProbe/bin/Release/{framework}/Pinhole.CloudflareProbe.dll"),
                "--worker", "http://127.0.0.1:8788", "--direct"],
                cwd=root, check=True, capture_output=True, text=True, timeout=90)
            report = json.loads(result.stdout)
            if report["status"] != "PASS" or not report["encrypted"] or report["path"] != "Direct" \
                    or report["roundTripsEachDirection"] != 48:
                raise AssertionError("Local Worker did not carry the expected encrypted session")
            print(framework, result.stdout.strip(), flush=True)
        time.sleep(0.2)
        log.seek(0)
        if log.read().count("101 Switching Protocols") < len(frameworks):
            raise AssertionError("Both runs must use the actual Worker WebSocket upgrade")
        print("PASS: actual Worker WebSocket signaling on both runtimes", flush=True)
    except BaseException:
        log.seek(0)
        print(log.read()[-4000:], flush=True)
        raise
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
