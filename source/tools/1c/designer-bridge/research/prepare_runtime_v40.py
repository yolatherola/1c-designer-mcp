"""Prepare a fresh owned native runtime from exact local archive pins.

Runs only two disposable native fixture processes, never starts Gold. Preserve
the original SDK/research assets before cleaning the old recovered runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

PROJECT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PROJECT / 'tools/1c/designer-bridge/tests'))
from run_pipe_read import ARCHIVES, checked_extract, read_json
from pending_operation_inspector import contained
from process_identity import owned_process_gone
from run_command_session import verify_runtime
from stop_original_v40 import durable_new, GOLD, HOST

CACHE = PROJECT / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_cache():
    """Reuse only the saved, complete cache whose every asset is hash-bound."""
    contained(CACHE, PROJECT / 'artifacts/designer-bridge')
    owner = read_json(contained(CACHE / 'owner.json', CACHE))
    manifest = read_json(contained(CACHE / 'manifest.json', CACHE))
    if (owner.get('task') != 'DESIGNER-DIRECT-API/V40'
            or manifest.get('task') != owner['task']
            or owner.get('nonce') != manifest.get('nonce')
            or re.fullmatch('[a-f0-9]{32}', owner.get('nonce') or '') is None):
        raise ValueError('PREPARE_CACHE_OWNER_REJECTED')
    assets = manifest.get('assetSha256')
    if not isinstance(assets, dict) or not assets:
        raise ValueError('PREPARE_CACHE_ASSETS_MISSING')
    for relative, wanted in assets.items():
        if (not isinstance(relative, str) or Path(relative).is_absolute()
                or re.fullmatch('[a-f0-9]{64}', wanted or '') is None
                or sha(contained(CACHE / relative, CACHE)) != wanted):
            raise ValueError('PREPARE_CACHE_ASSET_CHANGED')
    for name, _, wanted in ARCHIVES:
        if (manifest.get('archiveSha256', {}).get(name) != wanted
                or assets.get(name, '').upper() != wanted):
            raise ValueError('PREPARE_CACHE_ARCHIVE_CHANGED')
    witness = contained(Path(manifest.get('originalRead1Witness', '')),
                        PROJECT / 'artifacts/designer-bridge')
    if (sha(witness) != manifest.get('originalRead1Sha256')
            or sha(witness) != '10ca83d12f609aaf832abadbf7bcaa4e229904442a3e6e3624b1442129c872c8'):
        raise ValueError('PREPARE_ORIGINAL_READ1_CHANGED')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    late = read_json(PROJECT / 'artifacts/designer-bridge/v40-original-late-recovery-20261011.json')
    if not late.get('leaseReleased') or not all(owned_process_gone(*x) for x in (GOLD, HOST)):
        raise ValueError('PREPARE_RECOVERY_REQUIRED')
    manifest = checked_cache()
    nonce = uuid.uuid4().hex
    build = PROJECT / 'build' / ('designer-v40-' + nonce)
    contained(build, PROJECT / 'build')
    build.mkdir()
    durable_new(build / 'runtime-owner.json', dict(task='DESIGNER-DIRECT-API/V40',
        createdBy='prepare_runtime_v40.py', runtimeNonce=nonce,
        cacheNonce=manifest['nonce']))
    for name, _, wanted in ARCHIVES:
        shutil.copyfile(CACHE / name, build / name)
        checked_extract(build / name, build / 'runtime')
    shell = Path(os.environ['WINDIR']) / 'SysWOW64/WindowsPowerShell/v1.0/powershell.exe'
    fixture = subprocess.run([str(shell), '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', str(PROJECT / 'tools/1c/designer-bridge/tests/Test-TargetedLoader.ps1'),
        '-BuildDirectory', str(build)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    host = (read_json(build / 'native-host-result.json')
            if (build / 'native-host-result.json').is_file() else {})
    if (fixture.returncode != 0 or host.get('targetCoreLoaded') is not True
            or host.get('controlProcessUnaffected') is not True
            or not all(owned_process_gone(host[prefix + 'ProcessId'],
                       host[prefix + 'CreationFileTimeUtc']) for prefix in ('target', 'control'))):
        failure = (read_json(build / 'native-host-failure.json')
                   if (build / 'native-host-failure.json').is_file() else {})
        proof = dict(stage='V40FreshNativeRuntimeFixtureFailed', passed=False,
                     runtimeDirectory=str(build), runtimeNonce=nonce,
                     goldStarted=False, nativeFailure=failure,
                     fixtureExitCode=fixture.returncode, runtimeRetained=True,
                     sourceSha256={str(p.relative_to(PROJECT)): sha(p) for p in
                         (Path(__file__), PROJECT / 'tools/1c/designer-bridge/TargetedLoader.cs',
                          PROJECT / 'tools/1c/designer-bridge/tests/Test-TargetedLoader.ps1')})
        target = PROJECT / 'artifacts/designer-bridge' / ('v40-fixture-failed-' + nonce + '.json')
        durable_new(target, proof)
        print(json.dumps(dict(passed=False, runtimeDirectory=str(build),
                             runtimeNonce=nonce, evidence=str(target), goldStarted=False,
                             hookError=failure.get('hookError'))))
        return 1
    pins = verify_runtime(build)
    proof = dict(stage='V40FreshNativeRuntimePrepared', passed=True,
                 runtimeDirectory=str(build), runtimeNonce=nonce,
                 fixtureProcessIdentities=[dict(processId=host[prefix + 'ProcessId'],
                    birth=host[prefix + 'CreationFileTimeUtc']) for prefix in ('target', 'control')],
                 fixtureOriginalsGone=True, goldStarted=False, wholeRouteLeaseCount=0,
                 nativeRuntimePins=pins, retainedCache=str(CACHE),
                 sourceSha256={str(Path(__file__).relative_to(PROJECT)): sha(Path(__file__))})
    target = PROJECT / 'artifacts/designer-bridge' / ('v40-prepared-runtime-' + nonce + '.json')
    durable_new(target, proof)
    print(json.dumps(dict(passed=True, runtimeDirectory=str(build), runtimeNonce=nonce,
                         evidence=str(target), goldStarted=False, fixtureOriginalsGone=True)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
