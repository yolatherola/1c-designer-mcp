"""Read exact Opros repository metadata/module and compare with live Gold.

No capture, configuration/database save, refresh/apply or repository mutation.
--check-guards additionally tests native policy inputs and wrong selection.
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
import time
import urllib.request
import uuid

from run_pipe_read import ARCHIVES, ROOT, TESTS, checked_extract, read_json
from process_identity import owned_process_gone
from run_repository_observe import lease_exists, sample_summary, SOURCES as OBSERVE_SOURCES
sys.path[:0] = [str(TESTS.parent), str(TESTS.parent / 'research')]
from native_source_codec import decode_module_packet
from repository_pe_probe import HASHES, PLATFORM

OBJECT = '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'
PROPERTY = 'a637f77f-3840-441d-a1c3-699c8c5cb7e0'
MODES = (
    ('CaptureStatusRepositorySourceOpros', 'none'),
    ('CaptureStatusRepositorySourceBufferDirtyOpros', 'buffer-dirty'),
    ('CaptureStatusRepositorySourceUnknownDirtyOpros', 'unknown-dirty'),
    ('CaptureStatusRepositorySourceWrongSelectionOpros', 'wrong-selection'),
)
SOURCES = OBSERVE_SOURCES + (
    TESTS / 'run_repository_source.py', TESTS / 'NativeRepositorySource.as',
    TESTS.parent / 'native_source_codec.py', TESTS / 'test_native_source_codec.py',
    TESTS / 'run_pipe_read.py', TESTS / 'Test-TargetedLoader.ps1',
    TESTS / 'process_identity.py', TESTS / 'test_process_identity.py',
)


def source_summary(sample):
    source = sample.get('sourceProbe') or {}
    fetch = source.get('fetch') or {}
    module = source.get('moduleSource') or {}
    scope = fetch.get('packetScope') or {}
    streams = scope.get('streams') or {}
    descriptor = source.get('moduleDescriptor') or {}
    return sample_summary(sample) | {
        'sourceWrites': source.get('sourceWriteCount'),
        'metadataRpcCount': source.get('metadataRpcCount'),
        'moduleRpcCount': source.get('moduleRpcCount'),
        'policySelfTest': source.get('policySelfTest'),
        'dirty': source.get('dirty'),
        'metadataFetch': {key: fetch.get(key) for key in (
            'attempted', 'error', 'packetReceived', 'bounded', 'elapsedMicroseconds',
            'requestedVersion', 'versionUnchanged', 'editorTextUnchanged', 'resultScopeVerified',
            'sourceApplied')},
        'packetScope': {key: scope.get(key) for key in ('verified', 'ids', 'cachedBefore', 'cachedAfter', 'itemPresent')},
        'metadataStream': {key: streams.get(key) for key in ('verified', 'mainFileBytes')},
        'moduleDescriptor': {key: descriptor.get(key) for key in ('verified', 'propertyId', 'fileNameRecognized', 'fileName')},
        'moduleFetch': {key: module.get(key) for key in (
            'attempted', 'error', 'fileReceived', 'bounded', 'elapsedMicroseconds',
            'fileBytes', 'temporaryReadComplete', 'versionUnchanged', 'editorTextUnchanged', 'sourceApplied')},
    }


def require_positive(sample):
    source = sample['sourceProbe']
    fetch = source.get('fetch') or {}
    module = source.get('moduleSource') or {}
    scope = fetch.get('packetScope') or {}
    descriptor = source.get('moduleDescriptor') or {}
    return (sample.get('selectionVerified') is True and source.get('sourceWriteCount') == 0
        and source.get('metadataRpcCount') == 1 and source.get('moduleRpcCount') == 1
        and source.get('policySelfTest') is True and source.get('dirty', {}).get('refreshAllowed') is True
        and all(fetch.get(key) is True for key in ('attempted', 'packetReceived', 'bounded',
            'versionUnchanged', 'editorTextUnchanged', 'resultScopeVerified'))
        and fetch.get('sourceApplied') is False and scope.get('verified') is True
        and [value.strip('{}').lower() for value in scope.get('ids', [])] == [OBJECT]
        and scope.get('itemPresent') is True and scope.get('streams', {}).get('verified') is True
        and descriptor.get('verified') is True and descriptor.get('fileNameRecognized') is True
        and descriptor.get('propertyId', '').strip('{}').lower() == PROPERTY
        and descriptor.get('fileName', '').lower() == OBJECT + '.0'
        and all(module.get(key) is True for key in ('attempted', 'fileReceived', 'bounded',
            'temporaryReadComplete', 'versionUnchanged', 'editorTextUnchanged'))
        and module.get('sourceApplied') is False and all(source.get('dirty', {}).get(key) is False
            for key in ('configurationModified', 'objectModified', 'bufferModified'))
        and source.get('dirty', {}).get('verified') is True
        and all(module.get('dirtyAfter', {}).get(key) is False
            for key in ('configurationModified', 'objectModified', 'bufferModified')))


def require_negative(sample, case):
    source = sample.get('sourceProbe') or {}
    return (source.get('sourceWriteCount') == 0 and source.get('metadataRpcCount') == 0
        and source.get('moduleRpcCount') == 0 and source.get('policySelfTest') is True
        and (source.get('fetch') or {}).get('attempted') is False
        and (source.get('moduleSource') or {}).get('attempted') is False
        and ((sample.get('selectionVerified') is False
              and sample.get('repositoryStatus', {}).get('queried') is False)
             if case == 'wrong-selection' else
             (source.get('dirty', {}).get('verified') is True
              and source.get('dirty', {}).get('nativeFlagsClean') is True
              and source.get('dirty', {}).get('refreshAllowed') is False
              and source.get('dirty', {}).get('policyInputCase') == case)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-cache', type=Path)
    parser.add_argument('--check-guards', action='store_true')
    args = parser.parse_args()
    if os.name != 'nt':
        raise SystemExit('WINDOWS_REQUIRED')
    run_id = time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    build_root = (ROOT / 'build').resolve()
    build = build_root / ('designer-source-' + run_id)
    build.mkdir(parents=True, exist_ok=False)
    proof_path = ROOT / 'artifacts/designer-bridge' / ('repository-source-' + run_id + '.json')
    proof_path.parent.mkdir(parents=True, exist_ok=True)
    proof = {'runId': run_id, 'target': 'Gold', 'objectId': OBJECT,
        'platform': '8.3.18.1208-x86', 'passed': False, 'configurationWrites': 0,
        'databaseUpdates': 0, 'repositoryMutations': 0, 'sourceApplied': False,
        'guardInputsSynthetic': True, 'trials': [], 'stage': 'prepare'}
    identity_before = {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCES}
    host = child = None
    cleanup_allowed = True
    identities = set()
    owners = []
    started = time.monotonic()
    exit_code = 1
    try:
        proof['platformSha256'] = {}
        for name, expected in HASHES.items():
            actual = hashlib.sha256((PLATFORM / name).read_bytes()).hexdigest().upper()
            if actual != expected:
                raise RuntimeError('PLATFORM_HASH_REJECTED')
            proof['platformSha256'][name] = actual
        proof['archives'] = {}
        for name, url, expected in ARCHIVES:
            dest = build / name
            if args.archive_cache:
                shutil.copyfile(args.archive_cache.resolve() / name, dest)
            else:
                with urllib.request.urlopen(url, timeout=30) as response, dest.open('wb') as output:
                    shutil.copyfileobj(response, output)
            actual = hashlib.sha256(dest.read_bytes()).hexdigest().upper()
            if actual != expected:
                raise RuntimeError('ARCHIVE_HASH_REJECTED')
            proof['archives'][name] = actual
            checked_extract(dest, build / 'runtime')
        powershell = Path(os.environ['WINDIR']) / 'SysWOW64/WindowsPowerShell/v1.0/powershell.exe'
        proof['stage'] = 'own-native-host'
        cleanup_allowed = False
        host = subprocess.Popen([str(powershell), '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', str(TESTS / 'Test-TargetedLoader.ps1'), '-BuildDirectory', str(build)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        host.wait(timeout=30)
        native_host = read_json(build / 'native-host-result.json')
        proof['host'] = native_host
        identities.update((native_host[prefix + 'ProcessId'], native_host.get(prefix + 'CreationFileTimeUtc'))
            for prefix in ('target', 'control'))
        cleanup_allowed = all(owned_process_gone(pid, created) for pid, created in identities)
        if host.returncode != 0 or not cleanup_allowed or not all(native_host.get(key) is True
                for key in ('targetCoreLoaded', 'controlProcessUnaffected')):
            raise RuntimeError('NATIVE_HOST_REJECTED')
        proof['stage'] = 'gold-read-only'
        for mode, case in MODES if args.check_guards else MODES[:1]:
            cleanup_allowed = False
            child = subprocess.Popen([sys.executable, '-B', str(TESTS / 'run_live_probe.py'), str(build), mode],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            output, _ = child.communicate(timeout=65)
            lease = next((json.loads(line) for line in reversed(output.splitlines())
                          if line.startswith('{') and '"leaseReleased"' in line), {})
            owner = lease.get('owner')
            if not isinstance(owner, str) or not re.fullmatch('[a-f0-9]{32}', owner):
                raise RuntimeError('SOURCE_LEASE_WITNESS_MISSING')
            owners.append(owner)
            result = read_json(build / 'gold-read-result.json')
            pid = result.get('processId')
            if not isinstance(pid, int):
                raise RuntimeError('SOURCE_PID_WITNESS_MISSING')
            created = result.get('processCreationFileTimeUtc')
            if not isinstance(created, str) or not re.fullmatch('[0-9a-f]{16}', created):
                raise RuntimeError('SOURCE_CREATION_WITNESS_MISSING')
            identities.add((pid, created))
            absent = owned_process_gone(pid, created)
            lease_absent = not lease_exists(owner)
            cleanup_allowed = absent and lease_absent and lease.get('leaseReleased') is True
            samples_path = max(build.glob('session-*/native-read-0.bsl'), key=lambda p: p.stat().st_mtime).parent
            samples = [read_json(samples_path / f'native-read-{i}.bsl') for i in range(result.get('readCount', 0))]
            record = {'case': case, 'processId': pid, 'processCreationFileTimeUtc': created, 'leaseOwner': owner,
                'processAbsentIndependently': absent, 'leaseAbsentIndependently': lease_absent,
                'startupMs': result.get('startupMs'), 'readRoundTripMs': result.get('readRoundTripMs'),
                'samples': [source_summary(sample) for sample in samples]}
            proof['trials'].append(record)
            common = result.get('readCount') == 5 and result.get('writeCount') == 0 and cleanup_allowed
            if case == 'none':
                record['verified'] = common and child.returncode == 0 and all(require_positive(s) for s in samples)
                if not record['verified']:
                    raise RuntimeError('SOURCE_READBACK_REJECTED')
                packet = (samples_path / 'repository-module.bin').read_bytes()
                live = (samples_path / 'live-module.bsl').read_bytes().decode('utf-8-sig')
                record['moduleComparison'] = decode_module_packet(packet).summary(live)
                record['refreshNeedsMerge'] = not record['moduleComparison']['normalizedLineEndingsEqual']
                record['metadataPacketSha256'] = hashlib.sha256((samples_path / 'repository-object.bin').read_bytes()).hexdigest()
            else:
                expected_exit = child.returncode != 0 and result.get('clientCode') == 'OBSERVE_SCOPE_REJECTED' if case == 'wrong-selection' else child.returncode == 0
                record['blockedBeforeSourceRpc'] = common and expected_exit and all(require_negative(s, case) for s in samples)
                if not record['blockedBeforeSourceRpc']:
                    raise RuntimeError('SOURCE_GUARD_REJECTED')
        proof['passed'] = True
        exit_code = 0
    except Exception as error:
        code = str(error)
        proof['failureCode'] = code if re.fullmatch('[A-Z][A-Z_0-9]{3,63}', code) else 'SOURCE_WRAPPER_FAILED'
        proof['errorType'] = type(error).__name__
    finally:
        proof['wrapperChildrenAbsent'] = all(p is None or p.poll() is not None for p in (host, child))
        proof['ownedProcessesAbsentIndependently'] = all(owned_process_gone(pid, created) for pid, created in identities)
        proof['ownedLeasesAbsentIndependently'] = all(not lease_exists(owner) for owner in owners)
        proof['ownedProcessIds'] = sorted({pid for pid, created in identities})
        proof['ownedProcessIdentities'] = [{'processId': pid, 'creationFileTimeUtc': created}
            for pid, created in sorted(identities)]
        identity_after = {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCES}
        proof['sourceSha256'] = identity_after
        proof['sourceIdentityUnchanged'] = identity_before == identity_after
        resolved = build.resolve()
        if (cleanup_allowed and proof['wrapperChildrenAbsent'] and proof['ownedProcessesAbsentIndependently']
                and proof['ownedLeasesAbsentIndependently'] and resolved.parent == build_root
                and resolved.name == 'designer-source-' + run_id):
            try:
                shutil.rmtree(resolved)
                proof['temporaryFilesRemoved'] = True
            except OSError:
                proof['temporaryFilesRemoved'] = False
        else:
            proof['temporaryFilesRemoved'] = False
        if not proof['temporaryFilesRemoved']:
            proof['retainedRuntime'] = str(build)
            proof['passed'] = False
            exit_code = 85
        if not proof['sourceIdentityUnchanged']:
            proof['failureCode'] = 'SOURCE_IDENTITY_CHANGED'
            proof['passed'] = False
            exit_code = 1
        proof['elapsedMs'] = round((time.monotonic() - started) * 1000, 1)
        proof_path.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'passed': proof['passed'], 'evidence': str(proof_path), 'verifiedTrials': len(proof['trials']),
            'temporaryFilesRemoved': proof['temporaryFilesRemoved'], 'failureCode': proof.get('failureCode')}, ensure_ascii=False), flush=True)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
