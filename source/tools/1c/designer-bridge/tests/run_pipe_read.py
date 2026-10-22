"""Reproducible, fixed-scope Gold read trial; no config/repository mutations.

The agent runs this entry point. Only sanitized evidence survives cleanup.
Pinned archives are checked before extraction or execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import statistics
import subprocess
import sys
import time
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[4]
TESTS = Path(__file__).resolve().parent
ARCHIVES = (
    ('core.zip', 'https://github.com/infostart-hub/core_as_loader/releases/download/'
     'Alpha_1_0_2_4/core-as-1-0-2-04.zip',
     'FC5471B3D67A820E2B2F556904EE0CCEBC435EE9F973B8423282030461349D4B'),
    ('snegopat.zip', 'https://github.com/infostart-hub/snegopat_modul/releases/download/'
     'Alpha19/snegopat-Release-2022-03-03.zip',
     '464256EA84009D66F2D177CE92CB128479BA634DA6A493A93AEF579410710FDE'),
)


def checked_extract(archive: Path, runtime: Path) -> None:
    with zipfile.ZipFile(archive) as package:
        for member in package.infolist():
            name = member.filename.replace('\\', '/')
            target = (runtime / name).resolve()
            if (not target.is_relative_to(runtime.resolve()) or ':' in name
                    or stat.S_ISLNK(member.external_attr >> 16)):
                raise RuntimeError('ARCHIVE_PATH_REJECTED')
        package.extractall(runtime)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8-sig'))


def process_exists(pid: int) -> bool:
    # The handle query contains no command line, credentials or process output.
    import ctypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        # Invalid PID is the only absence proof; access-denied stays unknown.
        return ctypes.get_last_error() != 87
    try:
        code = ctypes.c_ulong()
        if not kernel.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code)):
            return True
        return code.value == 259
    finally:
        kernel.CloseHandle(ctypes.c_void_p(handle))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-cache', type=Path,
                        help='Optional read-only cache; both exact SHA256 values remain mandatory.')
    args = parser.parse_args()
    if os.name != 'nt':
        raise SystemExit('WINDOWS_REQUIRED')
    run_id = time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    build_root = (ROOT / 'build').resolve()
    build = build_root / ('designer-pipe-' + run_id)
    build.mkdir(parents=True, exist_ok=False)
    proof_dir = ROOT / 'artifacts/designer-bridge'
    proof_dir.mkdir(parents=True, exist_ok=True)
    proof_path = proof_dir / ('pipe-read-' + run_id + '.json')
    evidence = {'runId': run_id, 'passed': False, 'stage': 'prepare',
                'scope': 'CommonModule.УправлениеОтложеннымиДействиямиСервер.Module',
                'target': 'Gold', 'platform': '8.3.18.1208-x86',
                'configurationWrites': 0, 'repositoryMutations': 0}
    started = time.monotonic()
    exit_code = 1
    try:
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
        trial = subprocess.run([sys.executable, '-B', str(TESTS / 'run_live_probe.py'),
            str(build), 'PipeRead'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if (build / 'gold-read-result.json').is_file():
            evidence['trial'] = read_json(build / 'gold-read-result.json')
        # The child emits only sanitized JSON; recover its independently owned
        # lease result, without reading credentials or native logs.
        lease_lines = [line for line in trial.stdout.splitlines() if '"leaseReleased"' in line]
        if lease_lines:
            evidence['lease'] = json.loads(lease_lines[-1])
        if trial.returncode != 0:
            raise RuntimeError('PIPE_TRIAL_FAILED')
        result = evidence.get('trial', {})
        if not (result.get('processStopped') is True and result.get('readCount') == 20
                and result.get('writeCount') == 0 and result.get('pipe', {}).get('Passed') is True
                and evidence.get('lease', {}).get('leaseReleased') is True):
            raise RuntimeError('PIPE_EVIDENCE_INCOMPLETE')
        times = result['pipe']['RoundTripMs']
        evidence['timingMs'] = {'median': statistics.median(times), 'min': min(times), 'max': max(times)}
        evidence['passed'] = True
        exit_code = 0
    except Exception as error:
        code = str(error)
        # Never persist framework messages, URLs with tokens, paths or raw logs.
        evidence['failureCode'] = code if code.isascii() and code.isupper() and code.replace('_', '').isalnum() else 'PIPE_RUN_FAILED'
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
        # Never delete a pre-existing directory or a runtime of a live/unknown
        # process. This directory was created by this invocation with exist_ok=False.
        resolved = build.resolve()
        if stopped and resolved.parent == build_root and resolved.name == 'designer-pipe-' + run_id:
            shutil.rmtree(resolved)
            evidence['temporaryFilesRemoved'] = True
        else:
            evidence['temporaryFilesRemoved'] = False
            evidence['retainedRuntime'] = str(build)
            evidence['passed'] = False
            exit_code = 1
        evidence['elapsedMs'] = round((time.monotonic() - started) * 1000, 1)
        evidence['sourceSha256'] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path(__file__), TESTS / 'NativePipeReadProbe.as', TESTS / 'NativePipeIO.v',
                         TESTS / 'Invoke-LiveReadProbe.ps1', TESTS / 'run_live_probe.py',
                         TESTS.parent / 'LivePipeClient.cs', TESTS.parent / 'TargetedLoader.cs')}
        proof_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'passed': evidence['passed'], 'evidence': str(proof_path),
                          'timingMs': evidence.get('timingMs'),
                          'temporaryFilesRemoved': evidence['temporaryFilesRemoved'],
                          'failureCode': evidence.get('failureCode')}, ensure_ascii=False), flush=True)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
