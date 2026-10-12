"""Drive the actual samples on three independent Actions runners, using encrypted
GitHub records only for signaling. Run via the Sample network workflow.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from verify import Checks, Peer, ROOT, redacted


class Signals:
    def __init__(self):
        self.repo = os.environ["GITHUB_REPOSITORY"]
        self.branch = os.environ["SAMPLE_SIGNAL_BRANCH"]
        self.token = os.environ["GITHUB_TOKEN"]
        self.cipher = ROOT / ".github/scripts/SignalCipher/bin/Release/net10.0/SignalCipher.dll"
        self.cached = {}

    def request(self, path, method="GET", body=None):
        request = urllib.request.Request("https://api.github.com/repos/" + self.repo + "/" + path,
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                     "Content-Type": "application/json", "User-Agent": "pinhole-sample-check"})
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)

    def crypt(self, mode, path, data):
        operation = subprocess.run(["dotnet", str(self.cipher), mode, path], input=data,
            capture_output=True, text=True, timeout=10)
        if operation.returncode:
            raise RuntimeError("Signal encryption/authentication failed")
        return operation.stdout

    def put(self, path, value):
        sealed = self.crypt("seal", path, json.dumps(value))
        for attempt in range(10):
            try:
                self.request("contents/signals/" + path + ".txt", "PUT", {
                    "message": "Encrypted sample signal " + path,
                    "branch": self.branch, "content": base64.b64encode(sealed.encode()).decode()})
                return
            except urllib.error.HTTPError as ex:
                # Independent runners can race an update of the branch head.
                if ex.code not in (403, 409, 422, 429, 502, 503) or attempt == 9:
                    raise
                time.sleep(min(10, 1 + attempt))
                existing = self.get(path)
                if existing == value:
                    return

    def get(self, path):
        if path in self.cached:
            return self.cached[path]
        try:
            record = self.request("contents/signals/" + path + ".txt?ref=" + urllib.parse.quote(self.branch, safe=""))
        except urllib.error.HTTPError as ex:
            if ex.code == 404:
                return None
            raise
        result = json.loads(self.crypt("open", path, base64.b64decode(record["content"]).decode()))
        self.cached[path] = result
        return result

    def wait(self, path, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = self.get(path)
            except urllib.error.HTTPError as ex:
                if ex.code not in (403, 429, 502, 503):
                    raise
                time.sleep(5)
                continue
            if value is not None:
                return value
            time.sleep(1.5)
        raise TimeoutError("Separate runner did not publish " + path)

    def barrier(self, phase, index):
        self.put(phase + "/" + str(index), {"ready": True})
        for remote in range(3):
            self.wait(phase + "/" + str(remote))


def connected(checks, peer, group=False):
    checks.connected(peer)
    return checks.paths[-1]


def chat(index, checks, signals, phase, project):
    if index == 0:
        host = checks.start(project)
        if project == "Pinhole.Tiny":
            invitation = checks.ticket(host)
        else:
            invitation = host.wait("Share this code: ").split(": ", 1)[1]
        signals.put(phase + "/invitation", {"value": invitation})
        connected(checks, host)
        host.wait(re.escape("Friend: " + phase + " from 1"), timeout=60)
        host.send(phase + " from 0")
        signals.wait(phase + "/read-by-1")
        host.quit()
    elif index == 1:
        invitation = signals.wait(phase + "/invitation")["value"]
        # Tiny and Demo must also talk to each other: both use the plain chat.
        joiner = checks.start("Pinhole.Demo" if project == "Pinhole.Tiny" else project, [invitation])
        connected(checks, joiner)
        joiner.send(phase + " from 1")
        joiner.wait(re.escape("Friend: " + phase + " from 0"), timeout=60)
        signals.put(phase + "/read-by-1", {"received": True})
        joiner.finish()


def group(index, checks, signals, phase):
    peer = checks.start("Pinhole.Tiny.Mulit")
    my_ticket = checks.ticket(peer)
    if index == 0:
        signals.put(phase + "/invitation", {"value": my_ticket})
    else:
        peer.send(signals.wait(phase + "/invitation")["value"])
    connected(checks, peer)
    if index == 0:
        peer.wait("friends=2", timeout=60)
    signals.barrier(phase + "/connected", index)
    for sender in range(3):
        text = phase + " from " + str(sender)
        if index == sender:
            peer.send(text)
            peer.wait("Message queued for ", timeout=20)
        else:
            peer.wait(r"^\[[0-9a-f]{16}\] " + re.escape(text) + "$", timeout=60)
        signals.barrier(phase + "/message-" + str(sender), index)
    if index == 1:
        peer.quit()
        peer = checks.start("Pinhole.Tiny.Mulit", [signals.wait(phase + "/invitation")["value"]])
        connected(checks, peer)
    signals.barrier(phase + "/rejoined", index)
    text = phase + " after rejoin"
    if index == 1:
        peer.send(text)
    else:
        peer.wait(r"^\[[0-9a-f]{16}\] " + re.escape(text) + "$", timeout=60)
    signals.barrier(phase + "/rejoin-delivery", index)
    peer.quit()


def send(index, checks, signals, phase):
    payload = hashlib.shake_256((phase + " verified file").encode()).digest(32768)
    with tempfile.TemporaryDirectory(prefix="pinhole-remote-file-") as temp:
        work = Path(temp)
        if index == 0:
            source = work / "sample payload.bin"
            source.write_bytes(payload)
            host = checks.start("Pinhole.Send", ["send", source])
            signals.put(phase + "/invitation", {"value": checks.ticket(host)})
            signals.wait(phase + "/verified")
            host.close()
        elif index == 1:
            invitation = signals.wait(phase + "/invitation")["value"]
            receiver = checks.start("Pinhole.Send", ["recv", invitation, work])
            receiver.wait("saved ", timeout=120)
            receiver.finish()
            if (work / "sample payload.bin").read_bytes() != payload:
                raise AssertionError("File differs between separate machines")
            signals.put(phase + "/verified", {"sha256": hashlib.sha256(payload).hexdigest()})


def code(index, checks, signals, phase, worker):
    if index == 0:
        host = checks.start("Pinhole.CodeShare", ["host", worker])
        code = host.wait("share this code: ").split(": ", 1)[1]
        signals.put(phase + "/invitation", {"value": code})
        host.wait("peer says: hello from the joiner", timeout=60)
        host.finish()
        checks.paths.append(host.wait("peer connected via "))
    elif index == 1:
        code = signals.wait(phase + "/invitation")["value"]
        peer = checks.start("Pinhole.CodeShare", ["join", worker, code])
        peer.wait("host says: hello from the host", timeout=60)
        peer.finish()
        checks.paths.append(peer.wait("connected via "))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=int, choices=[0, 1, 2], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    signals = Signals()
    index = args.index
    worker = "https://pinhole-coordinator.fahimmanowarj5.workers.dev"
    reports = []
    failure = False
    try:
        signals.barrier("ready", index)
        for network in ("auto", "iroh", "derp"):
            for case in ("chat", "group", "send"):
                phase = network + "/" + case
                checks = Checks(dict(os.environ, PINHOLE_SAMPLE_NETWORK=network), network, None)
                started = time.monotonic()
                try:
                    if case == "chat":
                        chat(index, checks, signals, phase, "Pinhole.Tiny")
                    elif case == "group":
                        group(index, checks, signals, phase)
                    else:
                        send(index, checks, signals, phase)
                    signals.barrier(phase + "/done", index)
                    report = {"case": case, "network": network, "status": "PASS",
                              "role": "host" if index == 0 else "peer" if case == "group" or index == 1 else "observer",
                              "connections": checks.paths, "invitationSha256": checks.hashes,
                              "seconds": round(time.monotonic() - started, 2)}
                    reports.append(report)
                    print(json.dumps(report), flush=True)
                finally:
                    checks.close()
        for case in ("cloudflare", "codeshare"):
            phase = "auto/" + case
            checks = Checks(dict(os.environ, PINHOLE_SAMPLE_NETWORK="auto", PINHOLE_COORDINATOR=worker), "auto", worker)
            try:
                if case == "cloudflare":
                    chat(index, checks, signals, phase, "Pinhole.CloudflareChat")
                else:
                    code(index, checks, signals, phase, worker)
                signals.barrier(phase + "/done", index)
                report = {"case": case, "network": "auto", "status": "PASS",
                          "role": "host" if index == 0 else "peer" if index == 1 else "observer", "connections": checks.paths}
                reports.append(report)
                print(json.dumps(report), flush=True)
            finally:
                checks.close()
    except Exception as ex:
        failure = True
        reports.append({"status": "FAIL", "error": redacted(str(ex))})
        print(json.dumps(reports[-1]), flush=True)
    finally:
        report = {"status": "FAIL" if failure else "PASS", "index": index, "os": platform.system(),
                  "commit": os.environ.get("GITHUB_SHA"),
                  "machineSha256": hashlib.sha256(platform.node().encode()).hexdigest(), "cases": reports}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 1 if failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
