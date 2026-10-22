"""Fixed Gold metadata-selection research; never captures or cancels objects.

The agent runs three read-only scopes sequentially under the existing lease.
This proves selection, not repository ownership or a capture/cancel capability.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request
import uuid

from run_pipe_read import ARCHIVES, ROOT, TESTS, checked_extract, process_exists, read_json

sys.path.insert(0, str(TESTS.parent / 'research'))
from repository_pe_probe import HASHES, PLATFORM

SCOPES = (
    ('CaptureStatusRepositoryOpros', 'Document.Опрос',
     '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d', None),
    ('CaptureStatusRepositoryOprosManagedForm', 'Document.Опрос.Form.ФормаДокумента_Управляемая',
     '0ed914fb-2a1a-4b58-9fad-eaa103b47c9e', None),
    ('CaptureStatusRepositoryPatientTemplate', 'DataProcessor.ПоискПоПациенту.Template.ОбщийБегунокПациента',
     '8daef957-4ae2-48a1-bf6c-b88163a076f5', None),
    ('CaptureStatusRepositoryOprosWrongSelection', 'Negative:Опрос expects document but selects form',
     '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d', '0ed914fb-2a1a-4b58-9fad-eaa103b47c9e'),
)
SOURCES = (
    TESTS / 'run_repository_observe.py', TESTS / 'NativeRepositoryObserve.as',
    TESTS / 'run_repository_status.py',
    TESTS / 'NativeRepositoryObserve.v', TESTS / 'NativeCaptureStatusProbe.as',
    TESTS / 'NativeRepositoryPlan.as', TESTS / 'NativeRepositoryPlan.v',
    TESTS / 'Invoke-LiveReadProbe.ps1', TESTS / 'run_live_probe.py',
    TESTS.parent / 'TargetedLoader.cs', TESTS.parent / 'research/repository_pe_probe.py',
)


def sample_summary(sample: dict) -> dict:
    part = sample.get('treeContext', {}).get('metadataPart') or {}
    selection = part.get('selection') or {}
    statistic = sample.get('repositoryStatus') or {}
    revisor = statistic.get('revisorId', '').strip('{}').lower()
    status = {key: statistic.get(key) for key in (
        'queried', 'bounded', 'elapsedMicroseconds', 'versionNumber', 'revised',
        'ownerVerified', 'generationVerified', 'lockGenerationVerified', 'error'
    ) if key in statistic}
    if revisor:
        status['revisorPresent'] = revisor != '00000000-0000-0000-0000-000000000000'
        status['revisorSha256'] = hashlib.sha256(revisor.encode('ascii')).hexdigest()
    return {key: sample.get(key) for key in (
        'rootVerified', 'objectVerified', 'managerRootVerified', 'baseRootVerified',
        'selectionVerified', 'ownerVerified', 'generationVerified', 'repositoryBoundVerified',
        'nestedParentVerified', 'nestedTypeVerified'
    )} | {
        'current': selection.get('selected'),
        'selectedRows': selection.get('selectedRows'),
        'selectedRowsVerified': selection.get('selectionVerified'),
        'repositoryStatus': status,
    }


def lease_exists(owner: str) -> bool:
    state = Path(os.environ.get('AH1C_BRIDGE_STATE_DIR') or
                 (Path(os.environ['LOCALAPPDATA']) / 'AH_1C/bridge')) / 'state.db'
    with sqlite3.connect(state.resolve().as_uri() + '?mode=ro', uri=True) as connection:
        return connection.execute(
            'SELECT 1 FROM execution_leases WHERE resource=? AND owner_operation_id=?',
            ('ah1c-write', owner)
        ).fetchone() is not None


def main(repository_status: bool = False) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-cache', type=Path,
                        help='Optional read-only archive cache; exact SHA256 checks still apply.')
    args = parser.parse_args()
    if os.name != 'nt':
        raise SystemExit('WINDOWS_REQUIRED')
    run_id = time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    build_root = (ROOT / 'build').resolve()
    prefix = 'designer-status-' if repository_status else 'designer-observe-'
    build = build_root / (prefix + run_id)
    build.mkdir(parents=True, exist_ok=False)
    proof_dir = ROOT / 'artifacts/designer-bridge'
    proof_dir.mkdir(parents=True, exist_ok=True)
    proof_path = proof_dir / (('repository-status-' if repository_status else 'repository-selection-') + run_id + '.json')
    evidence = {'runId': run_id, 'passed': False, 'stage': 'prepare',
                'target': 'Gold', 'platform': '8.3.18.1208-x86',
                'configurationWrites': 0, 'repositoryMutations': 0,
                'ownershipVerified': False, 'captureCycleStatus': 'NOT_ATTEMPTED',
                'statusContractRequired': repository_status, 'lockGenerationVerified': False,
                'trials': []}
    started = time.monotonic()
    exit_code = 1
    try:
        evidence['platformSha256'] = {}
        for name, expected in HASHES.items():
            actual = hashlib.sha256((PLATFORM / name).read_bytes()).hexdigest().upper()
            if actual != expected:
                raise RuntimeError('PLATFORM_HASH_REJECTED')
            evidence['platformSha256'][name] = actual
        evidence['archives'] = {}
        for name, url, expected in ARCHIVES:
            destination = build / name
            if args.archive_cache:
                shutil.copyfile(args.archive_cache.resolve() / name, destination)
            else:
                with urllib.request.urlopen(url, timeout=30) as response, destination.open('wb') as output:
                    shutil.copyfileobj(response, output)
            actual = hashlib.sha256(destination.read_bytes()).hexdigest().upper()
            if actual != expected:
                raise RuntimeError('ARCHIVE_HASH_REJECTED')
            evidence['archives'][name] = actual
            checked_extract(destination, build / 'runtime')
        powershell = Path(os.environ['WINDIR']) / 'SysWOW64/WindowsPowerShell/v1.0/powershell.exe'
        evidence['stage'] = 'own-native-host'
        host = subprocess.run([str(powershell), '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', str(TESTS / 'Test-TargetedLoader.ps1'), '-BuildDirectory', str(build)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if host.returncode != 0:
            raise RuntimeError('NATIVE_HOST_FAILED')
        evidence['host'] = read_json(build / 'native-host-result.json')
        evidence['stage'] = 'gold-read-only'
        scopes = SCOPES
        if repository_status:
            scopes = SCOPES[:2] + (
                ('CaptureStatusRepositorySmsModule', 'CommonModule.УправлениеОтложеннымиДействиямиСервер',
                 'ca1bedb3-3d02-4924-a8a8-bc6b22b8eeb5', None),
            ) + SCOPES[2:]
        for probe, label, expected_id, wrong_selection_id in scopes:
            trial = subprocess.run([sys.executable, '-B', str(TESTS / 'run_live_probe.py'),
                str(build), probe], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            result = read_json(build / 'gold-read-result.json')
            lease_lines = [line for line in trial.stdout.splitlines() if '"leaseReleased"' in line]
            lease = json.loads(lease_lines[-1]) if lease_lines else {}
            samples = []
            if result.get('readCount', 0):
                samples_path = max(build.glob('session-*/native-read-0.bsl'), key=lambda f: f.stat().st_mtime).parent
                samples = [sample_summary(read_json(samples_path / ('native-read-' + str(i) + '.bsl')))
                           for i in range(result.get('readCount', 0))]
            record = {'scope': label, 'objectId': expected_id, 'samples': samples,
                      'processId': result.get('processId'), 'startupMs': result.get('startupMs'),
                      'readRoundTripMs': result.get('readRoundTripMs'),
                      'processStopped': result.get('processStopped'), 'lease': lease,
                      'failureCode': result.get('clientCode', result.get('failureCode'))}
            record['leaseAbsentIndependently'] = bool(lease.get('owner')) and not lease_exists(lease['owner'])
            record['processAbsentIndependently'] = bool(result.get('processId')) and not process_exists(result['processId'])
            evidence['trials'].append(record)
            if wrong_selection_id:
                record['wrongSelectionBlocked'] = (
                    trial.returncode != 0 and result.get('clientCode') == 'OBSERVE_SCOPE_REJECTED'
                    and result.get('readCount') == 5 and result.get('writeCount') == 0
                    and record['processAbsentIndependently'] and record['leaseAbsentIndependently']
                    and lease.get('leaseReleased') is True
                    and all(sample.get('selectionVerified') is False
                            and sample.get('rootVerified') is True
                            and sample.get('objectVerified') is True
                            and [value.strip('{}').lower() for value in sample['selectedRows']] == [wrong_selection_id]
                            for sample in samples)
                )
                if not record['wrongSelectionBlocked']:
                    raise RuntimeError('WRONG_SELECTION_NOT_BLOCKED')
                if repository_status and not all(
                        sample['repositoryStatus'].get('queried') is False
                        and sample['repositoryStatus'].get('error') == 'SCOPE_REJECTED'
                        for sample in samples):
                    raise RuntimeError('STATUS_QUERY_SCOPE_NOT_BLOCKED')
                continue
            if not (trial.returncode == 0 and result.get('selectionVerified') is True
                    and result.get('readCount') == 5 and result.get('writeCount') == 0
                    and record['processAbsentIndependently'] and record['leaseAbsentIndependently']
                    and lease.get('leaseReleased') is True
                    and all(sample.get('selectionVerified') is True
                            and sample.get('selectedRowsVerified') is True
                            and [value.strip('{}').lower() for value in sample['selectedRows']] == [expected_id]
                            for sample in samples)):
                raise RuntimeError('SELECTION_TRIAL_FAILED')
            if repository_status:
                if not all(sample.get('repositoryBoundVerified') is True for sample in samples):
                    raise RuntimeError('REPOSITORY_BINDING_FAILED')
                if probe == 'CaptureStatusRepositoryPatientTemplate':
                    record['statusUnsupportedSafely'] = all(
                        sample['repositoryStatus'].get('queried') is False
                        and sample['repositoryStatus'].get('error') == 'NEW_OBJECT_STATUS_UNSUPPORTED'
                        and sample.get('ownerVerified') is False
                        for sample in samples)
                    if not record['statusUnsupportedSafely']:
                        raise RuntimeError('UNSUPPORTED_STATUS_NOT_BLOCKED')
                    continue
                expected_revised = probe == 'CaptureStatusRepositorySmsModule'
                record['statusVerified'] = all(
                    sample.get('ownerVerified') is True and sample.get('generationVerified') is True
                    and sample['repositoryStatus'].get('queried') is True
                    and sample['repositoryStatus'].get('bounded') is True
                    and sample['repositoryStatus'].get('versionNumber', -1) >= 0
                    and sample['repositoryStatus'].get('revised') is expected_revised
                    and sample['repositoryStatus'].get('revisorPresent') is expected_revised
                    and sample['repositoryStatus'].get('elapsedMicroseconds', -1) >= 0
                    and sample['repositoryStatus'].get('lockGenerationVerified') is False
                    for sample in samples)
                if not record['statusVerified']:
                    raise RuntimeError('REPOSITORY_STATUS_FAILED')
                record['nativeStatusMedianMicroseconds'] = sorted(
                    sample['repositoryStatus']['elapsedMicroseconds'] for sample in samples)[len(samples)//2]
        evidence['ownershipVerified'] = repository_status and sum(
            trial.get('statusVerified', False) for trial in evidence['trials']) == 3
        evidence['passed'] = True
        exit_code = 0
    except Exception as error:
        code = str(error)
        evidence['failureCode'] = code if code.isascii() and code.isupper() and code.replace('_', '').isalnum() else 'OBSERVE_RUN_FAILED'
        evidence['errorType'] = type(error).__name__
    finally:
        stopped = True
        pid_file = build / 'owned-gold-pid'
        if pid_file.is_file():
            try:
                stopped = not process_exists(int(pid_file.read_text().strip()))
            except Exception:
                stopped = False
        evidence['ownedProcessStoppedIndependently'] = stopped
        resolved = build.resolve()
        # This invocation created exactly this directory; never remove a live
        # runtime or infer permission from another task's old status.
        if stopped and resolved.parent == build_root and resolved.name == prefix + run_id:
            shutil.rmtree(resolved)
            evidence['temporaryFilesRemoved'] = True
        else:
            evidence['temporaryFilesRemoved'] = False
            evidence['retainedRuntime'] = str(build)
            evidence['passed'] = False
            exit_code = 1
        evidence['elapsedMs'] = round((time.monotonic() - started) * 1000, 1)
        evidence['sourceSha256'] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in SOURCES}
        proof_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'passed': evidence['passed'], 'evidence': str(proof_path),
                          'verifiedScopes': sum(len(t['samples']) == 5 and 'wrongSelectionBlocked' not in t for t in evidence['trials']),
                          'wrongSelectionBlocked': any(t.get('wrongSelectionBlocked') for t in evidence['trials']),
                          'temporaryFilesRemoved': evidence['temporaryFilesRemoved'],
                          'captureCycleStatus': evidence['captureCycleStatus'],
                          'verifiedStatusScopes': sum(t.get('statusVerified', False) for t in evidence['trials']),
                          'failureCode': evidence.get('failureCode')}, ensure_ascii=False), flush=True)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
