#!/usr/bin/env python3
"""Compare physical TCP tickets using fresh owned hosts and the installed Android test.

No radio, VPN, firewall or package changes. Raw tickets stay in private local logs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid


class TrialError(RuntimeError):
    pass


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def capture(process, destination, lines):
    with destination.open('x') as output:
        for line in process.stdout:
            output.write(line)
            output.flush()
            try:
                lines.put_nowait(line.rstrip())
            except queue.Full:
                pass


def call(command, destination, timeout=15):
    with destination.open('x') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise TrialError(f'Command exited {result.returncode}; see {destination.name}')
    return destination.read_text()


def readiness(process, lines, port, profile):
    header = None
    published_profile = None
    ticket = None
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise TrialError('Echo host exited before readiness; see host.log')
        try:
            line = lines.get(timeout=.2)
        except queue.Empty:
            continue
        if line.startswith('HOST_PID='):
            header = re.fullmatch(r'HOST_PID=(\d+) PORT=(\d+) TCP_PORT=(\d+) DIRECT_UDP=False PORT_MAPPING=False', line)
            if not header or tuple(map(int, header.groups())) != (process.pid, port, port):
                raise TrialError('Echo host PID/options/listening ports do not match this trial')
        elif line.startswith('TICKET_PROFILE='):
            published_profile = line.partition('=')[2]
        elif line.startswith('TICKET '):
            ticket = line.partition(' ')[2]
        if header and published_profile == profile and ticket:
            if process.poll() is not None:
                raise TrialError('Echo host exited after publishing its ticket')
            return ticket
    raise TrialError('Echo host did not publish verified readiness before its deadline')


def passes(instrumentation, events, host_log):
    return (re.search(r'^OK \(1 test\)\s*$', instrumentation, re.MULTILINE) is not None
            and not re.search(r'INSTRUMENTATION_STATUS_CODE: -(?:2|3|4)\b', instrumentation)
            and any('PASS ' in line and 'tcpOnly=true' in line and 'path=DirectTcp(' in line
                    and re.search(r'\bechoes=48\b', line) for line in events)
            and 'PEER encrypted=True kind=Direct transport=Tcp ' in host_log
            and re.search(r'^echo 48 rxpath=Direct rxtransport=Tcp txpath=Direct txtransport=Tcp$',
                          host_log, re.MULTILINE) is not None)


def trial(adb, host, directory, port, primary, timeout):
    directory.mkdir(mode=0o700)
    expected_profile = 'primary-ipv4-direct' if primary else 'full'
    environment = dict(os.environ, PINHOLE_TRACE_FILE=str(directory / 'engine.log'))
    command = ['dotnet', str(host), '--port', str(port), '--disable-direct-udp', '--disable-port-mapping']
    if primary:
        command.append('--primary-direct-only')
    peer = logcat = None
    readers = []
    started = time.monotonic()
    events = []
    result = {'profile': expected_profile, 'status': 'BLOCKED'}
    instrument_started = False
    try:
        call(adb + ['shell', 'am', 'force-stop', 'org.pinhole.devicetest'], directory / 'reset.log')
        peer = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=environment)
        host_lines = queue.Queue(maxsize=256)
        reader = threading.Thread(target=capture, args=(peer, directory / 'host.log', host_lines), daemon=True)
        reader.start()
        readers.append(reader)
        ticket = readiness(peer, host_lines, port, expected_profile)
        result['ticket_sha256'] = hashlib.sha256(ticket.encode()).hexdigest()
        device_lines = queue.Queue(maxsize=256)
        logcat = subprocess.Popen(adb + ['logcat', '-T', '1', '-v', 'brief',
            'PinholeDeviceTest:I', 'PinholeTcpTrial:I', '*:S'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        reader = threading.Thread(target=capture, args=(logcat, directory / 'device.log', device_lines), daemon=True)
        reader.start()
        readers.append(reader)
        marker = uuid.uuid4().hex
        call(adb + ['shell', 'log', '-p', 'i', '-t', 'PinholeTcpTrial', marker], directory / 'marker.log')
        deadline = time.monotonic() + 5
        marked = False
        while time.monotonic() < deadline and not marked:
            try:
                marked = marker in device_lines.get(timeout=.2)
            except queue.Empty:
                pass
        if not marked:
            raise TrialError('Could not verify the fresh device-log marker')
        result['status'] = 'FAIL'
        instrument_started = True
        instrumentation = call(adb + ['shell', 'am', 'instrument', '-w', '-r', '-e', 'class',
            'org.pinhole.devicetest.PhysicalPeerTest#encryptedRoundTripsAcrossThePhysicalNetwork',
            '-e', 'pinholeTicket', ticket, '-e', 'tcpOnly', 'true',
            'org.pinhole.devicetest.test/androidx.test.runner.AndroidJUnitRunner'],
            directory / 'instrumentation.log', timeout)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                line = device_lines.get(timeout=.2)
                events.append(line)
                if 'PASS ' in line and 'tcpOnly=true' in line:
                    break
            except queue.Empty:
                pass
        # Allow the host's last echo evidence to reach its own stdout reader.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if passes(instrumentation, events, (directory / 'host.log').read_text()):
                result['status'] = 'PASS'
                break
            time.sleep(.1)
        if result['status'] != 'PASS':
            result['reason'] = 'Missing successful assertion, fresh 48-echo TCP event, or encrypted TCP host evidence'
    except (TrialError, OSError, subprocess.TimeoutExpired) as error:
        result['reason'] = (str(error) if isinstance(error, TrialError) else type(error).__name__)
    finally:
        if instrument_started:
            try:
                call(adb + ['shell', 'am', 'force-stop', 'org.pinhole.devicetest'], directory / 'cleanup.log')
            except (TrialError, OSError, subprocess.TimeoutExpired):
                result['cleanup_failed'] = True
                result['status'] = 'FAIL'
        # Stop only processes owned by this trial; never search or kill by command text.
        stop(logcat)
        stop(peer)
        for reader in readers:
            reader.join(timeout=5)
        result['duration_seconds'] = round(time.monotonic() - started, 3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, required=True, help='An already permitted host TCP port')
    parser.add_argument('--adb', default=shutil.which('adb') or 'adb')
    parser.add_argument('--serial')
    parser.add_argument('--host', type=Path, default=Path(__file__).resolve().parent / 'bin/Debug/net10.0/EchoHost.dll')
    parser.add_argument('--output', type=Path, help='A new output directory; existing directories are refused')
    parser.add_argument('--profile', choices=['primary', 'full', 'both'], default='both')
    parser.add_argument('--timeout', type=int, default=90)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.timeout <= 600:
        parser.error('port must be 1..65535 and timeout must be 1..600 seconds')
    os.umask(0o077)
    output = args.output or Path(tempfile.mkdtemp(prefix='pinhole-physical-tcp-'))
    if args.output:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    adb = [args.adb] + (['-s', args.serial] if args.serial else [])
    report = {'status': 'BLOCKED', 'port': args.port, 'trials': [], 'network_changes': False}
    try:
        if not args.host.is_file():
            raise TrialError('Build EchoHost.csproj before running this trial')
        for name in ['EchoHost.dll', 'Pinhole.dll']:
            report[name + '_sha256'] = hashlib.sha256((args.host.parent / name).read_bytes()).hexdigest()
        if call(adb + ['get-state'], output / 'adb-access.log').strip() != 'device':
            raise TrialError('ADB did not confirm an authorized device')
        report['installed_apk_sha256'] = {}
        for package in ['org.pinhole.devicetest', 'org.pinhole.devicetest.test']:
            paths = call(adb + ['shell', 'pm', 'path', package], output / (package + '-paths.log'))
            paths = [line.removeprefix('package:').strip() for line in paths.splitlines() if line.startswith('package:')]
            if not paths or any(not re.fullmatch(r'/[A-Za-z0-9_./+=~-]+\.apk', path) for path in paths):
                raise TrialError('Cannot identify the installed device-test APKs')
            sums = call(adb + ['shell', 'sha256sum', *paths], output / (package + '-hashes.log'))
            hashes = re.findall(r'^([0-9a-f]{64})\s', sums, re.MULTILINE)
            if len(hashes) != len(paths):
                raise TrialError('Could not hash every installed device-test APK')
            report['installed_apk_sha256'][package] = hashes
        profiles = [True, False] if args.profile == 'both' else [args.profile == 'primary']
        for primary in profiles:
            result = trial(adb, args.host.resolve(), output / ('primary' if primary else 'full'),
                           args.port, primary, args.timeout)
            report['trials'].append(result)
            print(f"{result['profile']}: {result['status']}", flush=True)
        report['status'] = ('PASS' if all(item['status'] == 'PASS' for item in report['trials'])
                            else 'FAIL' if any(item['status'] == 'FAIL' for item in report['trials']) else 'BLOCKED')
    except (TrialError, OSError, subprocess.TimeoutExpired) as error:
        report['reason'] = (str(error) if isinstance(error, TrialError) else type(error).__name__)
    finally:
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f"Physical TCP: {report['status']}; report: {output / 'report.json'}", flush=True)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
