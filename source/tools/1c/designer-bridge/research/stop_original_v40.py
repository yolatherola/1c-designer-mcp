"""One explicitly authorized stop of the fixed original diagnostic Gold.

This is original-operation recovery, not a general process killer. Compare the
creation FILETIME on the same retained handle used to terminate and wait. A
durable CreateNew intent must succeed before the single irreversible call.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PROJECT / 'tools/1c/designer-bridge/tests'))
from pending_operation_inspector import bound_proof, contained, inspect, read_json

OPERATION = '489fb7c97f1e4146a36660210484b403'
GOLD = (36568, '01dd58aca307f305')
HOST = (21688, '01dd58aca2bfbb6e')
EXIT_CODE = 86


def stop_exact(kernel, expected, write_intent):
    """Terminate one held, identity-checked handle; never retry a failed call.

    kernel is an adapter, allowing refusal/unknown cases to be tested locally.
    Only an observed WAIT_OBJECT_0 and non-active exit code prove termination.
    """
    handle = kernel.open(expected[0])
    if not handle:
        raise ValueError('CONTROLLED_STOP_OPEN_FAILED')
    try:
        if kernel.birth(handle) != expected[1] or kernel.exit_code(handle) != 259:
            raise ValueError('CONTROLLED_STOP_ORIGINAL_NOT_LIVE')
        write_intent()
        # Recheck on this held handle after the durable intent. PID lookup is
        # deliberately not repeated for the call; PID reuse cannot retarget it.
        if kernel.birth(handle) != expected[1] or kernel.exit_code(handle) != 259:
            raise ValueError('CONTROLLED_STOP_CHANGED_AFTER_INTENT')
        if not kernel.terminate(handle, EXIT_CODE):
            raise ValueError('CONTROLLED_STOP_TERMINATE_UNKNOWN')
        if kernel.wait(handle, 10000) != 0:
            raise ValueError('CONTROLLED_STOP_WAIT_UNKNOWN')
        code = kernel.exit_code(handle)
        if code == 259:
            raise ValueError('CONTROLLED_STOP_EXIT_UNKNOWN')
        return dict(heldOriginalHandleVerified=True, terminateCalls=1,
                    originalExited=True, exitCode=code)
    finally:
        kernel.close(handle)


class WindowsKernel:
    def __init__(self):
        if os.name != 'nt':
            raise ValueError('CONTROLLED_STOP_WINDOWS_REQUIRED')
        self.api = ctypes.WinDLL('kernel32', use_last_error=True)
        self.api.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self.api.OpenProcess.restype = ctypes.c_void_p
        self.api.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_uint64)] * 4
        self.api.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        self.api.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.api.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.api.WaitForSingleObject.restype = ctypes.c_uint32
        self.api.CloseHandle.argtypes = [ctypes.c_void_p]

    def open(self, pid):
        return self.api.OpenProcess(0x100000 | 0x1000 | 1, False, pid)

    def birth(self, handle):
        values = [ctypes.c_uint64() for _ in range(4)]
        if not self.api.GetProcessTimes(handle, *(ctypes.byref(x) for x in values)):
            raise ValueError('CONTROLLED_STOP_BIRTH_UNKNOWN')
        return f'{values[0].value:016x}'

    def exit_code(self, handle):
        code = ctypes.c_uint32()
        if not self.api.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise ValueError('CONTROLLED_STOP_STATE_UNKNOWN')
        return code.value

    def terminate(self, handle, code):
        return bool(self.api.TerminateProcess(handle, code))

    def wait(self, handle, millis):
        return self.api.WaitForSingleObject(handle, millis)

    def close(self, handle):
        self.api.CloseHandle(handle)


def durable_new(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-controlled-stop', action='store_true', required=True)
    args = parser.parse_args()
    evidence = PROJECT / f'artifacts/designer-bridge/native-capture-{OPERATION}.json'
    state = Path(os.environ.get('AH1C_BRIDGE_STATE_DIR',
        str(Path(os.environ['LOCALAPPDATA']) / 'AH_1C/bridge'))) / 'state.db'
    proof, operation, runtime, session, gold, host, sources = bound_proof(evidence, PROJECT)
    current = inspect(evidence, PROJECT, state)
    if (operation != OPERATION or gold != GOLD or host != HOST
            or current['sourcePinsCurrent'] is not True
            or current['wholeRouteLeaseCount'] != 1
            or current['originalOwnLeasePresent'] is not True
            or any(x['sameOriginalLive'] is not True for x in current['originalIdentities'].values())):
        raise ValueError('CONTROLLED_STOP_PREFLIGHT_REJECTED')
    cycle_file = contained(session / 'cycle-result.json', runtime)
    cycle = read_json(cycle_file)
    if (cycle.get('operationId') != OPERATION or cycle.get('status') != 'CYCLE_VERIFIED'
            or cycle.get('sourceWriteCount') != 0 or cycle.get('freeVerified') is not True):
        raise ValueError('CONTROLLED_STOP_CYCLE_REJECTED')
    target = contained(PROJECT / 'artifacts/designer-bridge/v40-controlled-original-stop-20261011.json',
                       PROJECT / 'artifacts/designer-bridge')
    intent = contained(PROJECT / 'artifacts/designer-bridge/v40-controlled-original-stop-intent-20261011.json',
                       PROJECT / 'artifacts/designer-bridge')
    if target.exists() or intent.exists():
        raise ValueError('CONTROLLED_STOP_ALREADY_DISPATCHED')
    base = dict(operationId=OPERATION, originalPid=GOLD[0], originalBirth=GOLD[1],
                explicitlyAuthorizedByHuman=True, authorizationDate='2026-10-11',
                cycleSha256=hashlib.sha256(cycle_file.read_bytes()).hexdigest(),
                sourceWrites=0, saveCalls=0, databaseUpdates=0, repositoryCalls=0,
                leaseReleased=False, runtimeDeleted=False,
                timestampUtc=datetime.now(timezone.utc).isoformat())
    result = stop_exact(WindowsKernel(), GOLD, lambda: durable_new(intent, base))
    durable_new(target, base | result)
    print(json.dumps(base | result))


if __name__ == '__main__':
    main()
