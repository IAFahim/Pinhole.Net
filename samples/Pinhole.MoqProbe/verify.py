#!/usr/bin/env python3
"""Run one fresh, bounded live Cloudflare MoQ check and retain secret-free evidence."""
import argparse
import hashlib
import json
import pathlib
import platform
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--framework', choices=['net8.0', 'net10.0'], required=True)
parser.add_argument('--credentials', type=pathlib.Path, required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
parser.add_argument('--dotnet', default='dotnet')
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[2]
assembly = root / 'samples/Pinhole.MoqProbe/bin/Release' / args.framework / 'Pinhole.MoqProbe.dll'
library = assembly.with_name('Pinhole.Moq.dll')
if args.output.exists():
    parser.error('Choose a fresh output file; previous evidence is never reused or overwritten')
if not assembly.is_file() or not library.is_file():
    parser.error('Build the Release probe before running the verifier')
try:
    process = subprocess.run([args.dotnet, str(assembly), '--credentials', str(args.credentials.resolve())],
                             capture_output=True, text=True, timeout=120)
    lines = [line for line in process.stdout.splitlines() if line.strip()]
    report = json.loads(lines[0]) if len(lines) == 1 else {'status': 'FAIL', 'stage': 'unexpected_output'}
except subprocess.TimeoutExpired:
    report = {'status': 'FAIL', 'stage': 'process_timeout'}
    process = None
except (ValueError, OSError):
    report = {'status': 'FAIL', 'stage': 'process_execution'}
    process = None
passed = process is not None and process.returncode == 0 and all([
    report.get('status') == 'PASS', report.get('relayVerified') is True,
    report.get('tlsCertificateValidated') is True, report.get('cleanupCompleted') is True,
    report.get('messagesEachDirection') == 50, report.get('observerMessages') == 50,
    report.get('boundaryObjectBytes') == [0, 65536], report.get('overLimitRejected') is True,
    report.get('subscribeOnlyPublishRejected') is True, report.get('sameTargetPublishPositiveControl') is True,
    report.get('invalidSignatureRejected') is True, report.get('draft') == 16,
])
# Only explicitly named safe report fields can enter an artifact, even after unexpected output.
safe_fields = {
    'status', 'stage', 'service', 'draft', 'transport', 'tlsCertificateValidated', 'relayVerified',
    'messagesEachDirection', 'observerMessages', 'regularObjectBytes', 'boundaryObjectBytes',
    'overLimitRejected', 'cleanupCompleted', 'connectedMs', 'elapsedMs', 'rttP50Ms', 'rttP95Ms',
    'subscribeOnlyPublishRejected', 'subscribeOnlyError', 'sameTargetPublishPositiveControl',
    'invalidSignatureRejected', 'invalidSignatureError', 'invalidSignatureRequestError', 'payloadDigest',
    'runtime', 'exception', 'quicError', 'applicationError', 'requestError',
}
report = {key: value for key, value in report.items() if key in safe_fields}
report['verifierPassed'] = passed
report['framework'] = args.framework
report['platform'] = platform.system() + ' ' + platform.machine()
report['probeAssemblySha256'] = hashlib.sha256(assembly.read_bytes()).hexdigest()
report['clientAssemblySha256'] = hashlib.sha256(library.read_bytes()).hexdigest()
args.output.parent.mkdir(parents=True, exist_ok=True)
with args.output.open('x') as output:
    json.dump(report, output, indent=2)
    output.write('\n')
print(json.dumps(report))
sys.exit(0 if passed else 1)
