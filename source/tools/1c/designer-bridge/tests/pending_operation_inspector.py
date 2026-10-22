"""Read-only inspection of an original UNKNOWN native capture operation.

This command cannot release a lease, cancel a capture or retry an operation.
Window diagnosis uses ownership-checked Win32 getters, never text or input.
"""
import argparse
from contextlib import closing
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from process_identity import query_process

OBJECT = '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'
PHASES = ('capture-dispatched', 'capture-verified', 'cancel-dispatched',
          'free-verified', 'cycle-result.json', 'retain-host')


def contained(path, boundary):
    """Reject traversal and every existing reparse component before reading."""
    path, boundary = Path(os.path.abspath(path)), Path(os.path.abspath(boundary))
    try:
        path.relative_to(boundary)
    except ValueError:
        raise ValueError('PATH_OUTSIDE_SCOPE') from None
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError('REPARSE_PATH_REJECTED')
        if item == boundary:
            break
    return path


def read_json(path, limit=4 * 1024 * 1024):
    if path.stat().st_size > limit:
        raise ValueError('EVIDENCE_SIZE_REJECTED')
    value = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(value, dict):
        raise ValueError('EVIDENCE_OBJECT_REQUIRED')
    return value


def original_identity(proof, prefix=''):
    pid_key = 'hostProcessId' if prefix else 'processId'
    birth_key = 'hostProcessCreationFileTimeUtc' if prefix else 'processCreationFileTimeUtc'
    pid, birth = proof.get(pid_key), proof.get(birth_key)
    if type(pid) is not int or not 0 < pid < 2**32:
        raise ValueError('ORIGINAL_PID_REJECTED')
    if not isinstance(birth, str) or not re.fullmatch('[0-9a-f]{16}', birth) or int(birth, 16) == 0:
        raise ValueError('ORIGINAL_BIRTH_REJECTED')
    return pid, birth


def bound_proof(evidence, project):
    project = Path(project).absolute()
    evidence = contained(evidence, project / 'artifacts/designer-bridge')
    proof = read_json(evidence)
    operation = proof.get('operationId')
    if not isinstance(operation, str) or not re.fullmatch('[0-9a-f]{32}', operation):
        raise ValueError('OPERATION_ID_REJECTED')
    if evidence.name != f'native-capture-{operation}.json' or proof.get('objectId') != OBJECT:
        raise ValueError('CAPTURE_SCOPE_REJECTED')
    if proof.get('decision') != {'terminal': 'UNKNOWN', 'release_lease': False, 'retain': True}:
        raise ValueError('ORIGINAL_UNKNOWN_REQUIRED')
    gold, host = original_identity(proof), original_identity(proof, 'host')
    runtime = contained(proof.get('runtimeDirectory', ''), project / 'build')
    native = proof.get('native')
    if not isinstance(native, dict) or native.get('operationId') != operation:
        raise ValueError('NATIVE_SCOPE_REJECTED')
    if original_identity(native) != gold or original_identity(native, 'host') != host:
        raise ValueError('NATIVE_IDENTITY_MISMATCH')
    session = contained(native.get('sessionDirectory', ''), runtime)
    if session != runtime / f'capture-session-{operation}':
        raise ValueError('SESSION_SCOPE_REJECTED')
    pins = proof.get('sourceSha256')
    if not isinstance(pins, dict) or not pins:
        raise ValueError('SOURCE_PINS_REQUIRED')
    sources = []
    for relative, digest in pins.items():
        if (not isinstance(relative, str) or Path(relative).is_absolute()
                or Path(relative).suffix.lower() not in {'.as', '.v', '.py', '.ps1', '.cs'}):
            raise ValueError('SOURCE_PATH_REJECTED')
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('SOURCE_HASH_REJECTED')
        sources.append((contained(project / relative, project / 'tools/1c/designer-bridge'), digest))
    return proof, operation, runtime, session, gold, host, sources


def route_state(state_file, operation):
    """Read counts only; no lease payloads, connection strings or DB writes."""
    with closing(sqlite3.connect(Path(state_file).resolve().as_uri() + '?mode=ro', uri=True)) as db:
        total = db.execute('SELECT count(*) FROM execution_leases WHERE resource=?',
                           ('ah1c-write',)).fetchone()[0]
        own = db.execute('SELECT count(*) FROM execution_leases WHERE resource=? AND owner_operation_id=?',
                         ('ah1c-write', operation)).fetchone()[0]
    return {'wholeRouteLeaseCount': total, 'originalOwnLeasePresent': own == 1}


def window_state(pid, thread):
    """Get classes and enable/visible bits of this process/thread only."""
    if os.name != 'nt' or type(thread) is not int or not 0 < thread < 2**32:
        return {'available': False, 'reason': 'ORIGINAL_GUI_THREAD_UNAVAILABLE'}
    u = ctypes.WinDLL('user32', use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_ssize_t)
    u.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    u.GetWindowThreadProcessId.restype = ctypes.c_uint32
    u.GetClassNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
    u.IsWindowEnabled.argtypes = [ctypes.c_void_p]
    u.IsWindowVisible.argtypes = [ctypes.c_void_p]
    u.EnumThreadWindows.argtypes = [ctypes.c_uint32, callback_type, ctypes.c_ssize_t]
    rows = []

    @callback_type
    def visit(hwnd, unused):
        owner = ctypes.c_uint32()
        owner_thread = u.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid or owner_thread != thread:
            return 1
        name = ctypes.create_unicode_buffer(256)
        if u.GetClassNameW(hwnd, name, 256) > 0:
            rows.append({'className': name.value,
                         'enabled': bool(u.IsWindowEnabled(hwnd)),
                         'visible': bool(u.IsWindowVisible(hwnd))})
        return 1

    ok = bool(u.EnumThreadWindows(thread, visit, 0))
    disabled_main = any(x['className'] == 'V8TopLevelFrame' and x['visible'] and not x['enabled'] for x in rows)
    enabled_dialog = any(x['className'] == 'V8NewLocalFrameBaseWnd' and x['visible'] and x['enabled'] for x in rows)
    return {'available': ok, 'ownedWindows': rows,
            'modalWindowObserved': ok and disabled_main and enabled_dialog,
            'modalCauseVerified': False, 'windowContentRead': False, 'inputSent': False}


def inspect(evidence, project, state_file, *, query=query_process, windows=None):
    proof, operation, runtime, session, gold, host, sources = bound_proof(evidence, project)
    observed = {}
    for name, (pid, birth) in [('gold', gold), ('host', host)]:
        state = query(pid)
        observed[name] = {'processId': pid, 'originalCreationFileTimeUtc': birth,
                          'queryStatus': state.status,
                          'sameOriginalLive': state.status == 'running' and state.creation_filetime == birth,
                          'pidReused': state.status == 'running' and state.creation_filetime != birth}
    phases = {name: contained(session / name, session).is_file() for name in PHASES}
    dispatch_identity = {}
    for name in ('capture-dispatched', 'cancel-dispatched'):
        file = session / name
        dispatch_identity[name] = (file.stat().st_size == 32 and file.read_text(encoding='ascii') == operation) if phases[name] else None
    source_current = all(file.is_file() and hashlib.sha256(file.read_bytes()).hexdigest() == digest for file, digest in sources)
    result = {'operationId': operation, 'objectId': OBJECT, 'readOnlyInspection': True,
              'originalDisposition': 'UNKNOWN', 'retryAllowed': False, 'releaseAllowed': False,
              'runtimeRetained': runtime.is_dir(), 'phases': phases,
              'dispatchOperationIdsMatch': dispatch_identity, 'sourcePinsCurrent': source_current,
              'originalIdentities': observed, 'terminalFileRequiresIndependentRecovery': phases['cycle-result.json'],
              'repositoryFreeVerifiedByInspector': False, 'databaseOrRepositoryCalls': 0}
    result.update(route_state(state_file, operation))
    if windows is not None and observed['gold']['sameOriginalLive']:
        result['gui'] = windows(gold[0], proof['native'].get('threadId'))
        after = query(gold[0])
        if after.status != 'running' or after.creation_filetime != gold[1]:
            result['gui'] = {'available': False, 'reason': 'ORIGINAL_CHANGED_DURING_QUERY'}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parents[4])
    parser.add_argument('--window-state', action='store_true')
    args = parser.parse_args()
    state = Path(os.environ.get('AH1C_BRIDGE_STATE_DIR') or Path(os.environ['LOCALAPPDATA']) / 'AH_1C/bridge') / 'state.db'
    result = inspect(args.evidence, args.project_root, state, windows=window_state if args.window_state else None)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
