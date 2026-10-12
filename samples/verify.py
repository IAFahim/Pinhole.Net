"""Exercise the runnable samples as real processes. No third-party Python packages.

Default: isolated loopback, suitable for CI. --network auto/iroh/derp opts into
public infrastructure; --worker URL additionally exercises the short-code chats.
Only invitation hashes enter the report; failure output redacts capabilities.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
NAMES = {"Pinhole.Demo": "pinhole-demo", "Pinhole.Mesh": "pinhole-mesh"}
CAPABILITY = re.compile(r"pinhole(?:blob)?1:[^\s\"'`]+")


def redacted(text):
    return CAPABILITY.sub("<invitation redacted>", text)


class Peer:
    def __init__(self, project, args=(), env=None, cwd=ROOT):
        self.project = project
        assembly = NAMES.get(project, project)
        binary = ROOT / "samples" / project / "bin/Release/net10.0" / (assembly + ".dll")
        if project == "Pinhole.Rendezvous":
            binary = ROOT / "src/Pinhole.Rendezvous/bin/Release/net10.0/pinhole-rendezvous.dll"
        if not binary.is_file():
            raise FileNotFoundError(f"Build {project} before using --no-build")
        self.process = subprocess.Popen(
            ["dotnet", str(binary), *map(str, args)], cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", bufsize=1, start_new_session=os.name != "nt")
        self.lines = []
        self.condition = threading.Condition()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            with self.condition:
                self.lines.append(line.rstrip())
                self.condition.notify_all()
        with self.condition:
            self.condition.notify_all()

    def mark(self):
        with self.condition:
            return len(self.lines)

    def wait(self, pattern, since=0, timeout=40):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                for line in self.lines[since:]:
                    if re.search(pattern, line):
                        return line
                if time.monotonic() >= deadline or (self.process.poll() is not None and not self.reader.is_alive()):
                    tail = redacted("\n".join(self.lines[-12:]))
                    raise AssertionError(f"{self.project}: missing {pattern!r} (exit={self.process.poll()})\n{tail}")
                self.condition.wait(timeout=0.1)

    def send(self, text):
        self.process.stdin.write(text + "\n")
        self.process.stdin.flush()

    def ticket(self):
        line = self.wait(r"pinhole(?:blob)?1:")
        return CAPABILITY.search(line).group(0)

    def connected(self):
        line = self.wait(r"^Connected(?: [0-9a-f]{16})?:")
        if "encrypted=True" not in line:
            raise AssertionError("Sample did not report an encrypted connection")
        return line

    def finish(self, timeout=20):
        code = self.process.wait(timeout=timeout)
        self.reader.join(timeout=2)
        if code != 0:
            raise AssertionError(f"{self.project} exited {code}\n" + redacted("\n".join(self.lines[-12:])))

    def quit(self):
        if self.process.poll() is None:
            self.send("/quit")
        self.finish()

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.process.stdin.close()
        self.process.stdout.close()


class Checks:
    def __init__(self, env, network, worker):
        self.env, self.network, self.worker = env, network, worker
        self.peers, self.hashes, self.paths = [], [], []

    def start(self, project, args=(), **kwargs):
        peer = Peer(project, args, env=self.env, **kwargs)
        self.peers.append(peer)
        return peer

    def ticket(self, peer):
        ticket = peer.ticket()
        self.hashes.append(hashlib.sha256(ticket.encode()).hexdigest())
        return ticket

    def connected(self, *peers):
        for peer in peers:
            line = peer.connected()
            expected = {"loopback": "Direct Udp", "tcp": "Direct Tcp",
                        "iroh": "Relay ", "derp": "Relay "}.get(self.network)
            if expected and expected not in line:
                raise AssertionError(f"Wrong path for {self.network}: {line}")
            if self.network == "iroh" and ".iroh.link" not in line:
                raise AssertionError("Forced iroh path used a different provider")
            if self.network == "derp" and ".ipn.dev" not in line:
                raise AssertionError("Forced DERP path used a different provider")
            self.paths.append(line)

    def exchange(self, a, b):
        # Each frame is sent once: verify the actual sample's send/receive loops.
        text = "first-message-" + os.urandom(6).hex()
        a.send(text)
        b.wait(re.escape("Friend: " + text))
        reply = "reply-" + os.urandom(6).hex()
        b.send(reply)
        a.wait(re.escape("Friend: " + reply))

    def tiny(self):
        host = self.start("Pinhole.Tiny")
        ticket = self.ticket(host)
        joiner = self.start("Pinhole.Tiny")
        self.ticket(joiner)
        joiner.send("pinhole1:broken")
        joiner.wait("Invalid invitation:")
        joiner.send('`' + ticket + '`')
        self.connected(host, joiner)
        self.exchange(host, joiner)
        host.quit()
        joiner.finish()
        # Argument-based joining and SDK base64url spelling work as well.
        host = self.start("Pinhole.Tiny")
        ticket = self.ticket(host).replace('+', '-').replace('/', '_')
        joiner = self.start("Pinhole.Tiny", [ticket])
        self.connected(host, joiner)
        self.exchange(host, joiner)
        joiner.quit()
        host.finish()

    def demo(self):
        host = self.start("Pinhole.Demo")
        ticket = self.ticket(host)
        joiner = self.start("Pinhole.Tiny")
        self.ticket(joiner)
        joiner.send('"' + ticket + '"')
        self.connected(host, joiner)
        self.exchange(joiner, host)
        joiner.quit()
        host.finish()

    def retry(self):
        stale = self.start("Pinhole.Tiny")
        old_ticket = self.ticket(stale)
        stale.quit()
        waiting = self.start("Pinhole.Tiny", [old_ticket])
        waiting.wait("Could not connect:.*Still listening", timeout=45)
        # Prove the listener survived a timed-out dial, without restarting it.
        current = self.start("Pinhole.Tiny", [self.ticket(waiting)])
        self.connected(waiting, current)
        self.exchange(waiting, current)
        current.quit()
        waiting.finish()

    def group(self):
        host = self.start("Pinhole.Tiny.Mulit")
        ticket = self.ticket(host)
        b = self.start("Pinhole.Tiny.Mulit", [ticket])
        self.connected(b)
        c = self.start("Pinhole.Tiny.Mulit", [ticket])
        self.connected(c)
        host.wait("friends=2")
        self.connected(host)
        for sender, receivers in [(b, [host, c]), (c, [host, b]), (host, [b, c])]:
            text = "group-" + os.urandom(6).hex()
            sender.send(text)
            sender.wait("Message queued for ")
            for receiver in receivers:
                receiver.wait(r"^\[[0-9a-f]{16}\] " + text + "$", timeout=20)
        b.quit()
        host.wait("Disconnected .*friends=1.*Still listening")
        mark = host.mark()
        d = self.start("Pinhole.Tiny.Mulit", [ticket])
        self.connected(d)
        host.wait("friends=2", since=mark)
        text = "after-rejoin-" + os.urandom(6).hex()
        d.send(text)
        host.wait(r"\] " + text + "$")
        c.wait(r"\] " + text + "$")
        reply = "to-new-peer-" + os.urandom(6).hex()
        host.send(reply)
        d.wait(r"\] " + reply + "$")
        c.wait(r"\] " + reply + "$")
        for peer in [host, c, d]:
            mark = peer.mark()
            peer.send("/peers")
            peer.wait("sent=[1-9][0-9]*, received=[1-9][0-9]*, send-errors=0, rejected=0", since=mark)
        host.quit()
        c.quit()
        d.quit()

    def send(self):
        with tempfile.TemporaryDirectory(prefix="pinhole-send-") as temp:
            work = Path(temp)
            source = work / "shared folder"
            source.mkdir()
            (source / "nested").mkdir()
            (source / "nested/empty.txt").write_bytes(b"")
            (source / "hello unicode.txt").write_text("hello π\n", encoding="utf-8")
            (source / "nested/random.bin").write_bytes(os.urandom(32 * 1024))
            for path in [source / "nested/random.bin", source]:
                host = self.start("Pinhole.Send", ["send", path])
                ticket = self.ticket(host)
                for attempt in range(2 if path.is_file() else 1):
                    destination = work / ("download-" + str(len(self.peers)))
                    receiver = self.start("Pinhole.Send", ["recv", '"' + ticket + '"', destination])
                    receiver.wait("saved ", timeout=90)
                    receiver.finish()
                    downloaded = destination / path.name
                    files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
                    for original in files:
                        target = downloaded if path.is_file() else downloaded / original.relative_to(path)
                        if target.read_bytes() != original.read_bytes():
                            raise AssertionError("Downloaded content differs from source")
                host.close()

    def codeshare(self):
        directory = self.start("Pinhole.Rendezvous", [0])
        line = directory.wait("listening on ")
        address = "127.0.0.1:" + line.rsplit(":", 1)[1]
        self.code_exchange(address)

    def code_exchange(self, address):
        host = self.start("Pinhole.CodeShare", ["host", address])
        code = host.wait("share this code: ").split(": ", 1)[1]
        joiner = self.start("Pinhole.CodeShare", ["join", address, code])
        host.wait("peer says: hello from the joiner")
        joiner.wait("host says: hello from the host")
        host.finish()
        joiner.finish()
        for peer in [host, joiner]:
            line = peer.wait("connected via ")
            if "encrypted=True" not in line:
                raise AssertionError("CodeShare connection was not encrypted")
            self.paths.append(line)

    def cloudflare(self):
        if not self.worker:
            raise ValueError("--worker is required for CloudflareChat")
        host = self.start("Pinhole.CloudflareChat")
        code = host.wait("Share this code: ").split(": ", 1)[1]
        joiner = self.start("Pinhole.CloudflareChat", [code])
        self.connected(host, joiner)
        self.exchange(host, joiner)
        host.quit()
        joiner.finish()

    def code_worker(self):
        if not self.worker:
            raise ValueError("--worker is required for CodeShare's coordinator mode")
        self.code_exchange(self.worker)

    def mesh(self):
        with tempfile.TemporaryDirectory(prefix="pinhole-mesh-") as temp:
            env = dict(self.env, MESH_SIGNAL_DIR=temp, MESH_DEADLINE_MS="90000", MESH_LINGER="")
            if self.network in ("iroh", "derp"):
                env["MESH_FORCE_RELAY"] = "1"
            else:
                env.pop("MESH_FORCE_RELAY", None)
            peers = [Peer("Pinhole.Mesh", ["node", i, 3], env=dict(env, MESH_LINGER="once" if i == 0 else ""), cwd=temp) for i in range(3)]
            self.peers.extend(peers)
            peers[0].wait(r"round 3: OK", timeout=90)
            guest = self.start("Pinhole.Mesh", ["guest", self.ticket(peers[0])], cwd=temp)
            guest.wait(r"\[guest\] mesh answered over ")
            guest.finish()
            line = guest.wait(r"\[guest\] connected via ")
            if "encrypted=True" not in line:
                raise AssertionError("Mesh guest was not encrypted")
            self.paths.append(line)
            for peer in peers:
                peer.wait("3/3 rounds verified", timeout=95)
                peer.finish()
            for round_index in (1, 2, 3):
                reports = [json.loads((Path(temp) / f"rounds/{round_index}/{i}.json").read_text()) for i in range(3)]
                for i, report in enumerate(reports):
                    if not report["ok"] or set(report["received"]) != {str(j) for j in range(3) if j != i}:
                        raise AssertionError("Mesh round missing a peer")
                    for remote, secret in report["received"].items():
                        if reports[int(remote)]["sent"] != secret:
                            raise AssertionError("Mesh exchanged the wrong secret")
                    if self.network in ("iroh", "derp") and any(report["udp"].values()):
                        raise AssertionError("Relay-only mesh secretly used a direct path")

    def errors(self):
        peer = self.start("Pinhole.Send", ["send", "/pinhole-smoke-missing-file"])
        peer.wait("Transfer failed:")
        if peer.process.wait(timeout=10) != 1:
            raise AssertionError("Missing file must produce a clean nonzero exit")

    def close(self):
        for peer in reversed(self.peers):
            peer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=["loopback", "tcp", "auto", "iroh", "derp"], default="loopback")
    parser.add_argument("--worker", help="Local or explicitly selected HTTPS coordinator")
    parser.add_argument("--only", nargs="+", choices=["tiny", "demo", "retry", "group", "send", "codeshare", "mesh", "cloudflare", "code-worker", "errors"])
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.no_build:
        built = subprocess.run(["dotnet", "build", "Pinhole.Net.slnx", "-c", "Release", "--disable-build-servers", "-warnaserror"],
                               cwd=ROOT, capture_output=True, text=True, timeout=180)
        if built.returncode:
            raise RuntimeError(redacted(built.stdout + built.stderr))
        print("PASS sample build", flush=True)
    cases = args.only or ["tiny", "demo", "retry", "group", "send", "codeshare", "mesh", "errors"]
    if args.worker and not args.only:
        cases += ["cloudflare", "code-worker"]
    env = dict(os.environ, PINHOLE_SAMPLE_NETWORK=args.network)
    if args.worker:
        env["PINHOLE_COORDINATOR"] = args.worker
    reports = []
    for case in cases:
        started = time.monotonic()
        checks = Checks(env, args.network, args.worker)
        report = {"case": case, "network": args.network}
        try:
            getattr(checks, case.replace("-", "_"))()
            report.update(status="PASS", invitationSha256=checks.hashes, connections=checks.paths)
        except Exception as ex:
            report.update(status="FAIL", error=redacted(str(ex)))
        finally:
            checks.close()
        report["seconds"] = round(time.monotonic() - started, 2)
        reports.append(report)
        print(json.dumps(report), flush=True)
    result = {"status": "PASS" if all(r["status"] == "PASS" for r in reports) else "FAIL", "cases": reports}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
