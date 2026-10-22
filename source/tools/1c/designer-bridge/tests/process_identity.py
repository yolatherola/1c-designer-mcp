"""Read-only Windows process identity; a PID alone can be reused.

No command lines or credentials are read. Unknown/access-denied queries keep
the owned runtime, rather than authorizing cleanup or termination.
"""
import ctypes
from dataclasses import dataclass
import os
import re


@dataclass(frozen=True)
class ProcessState:
    status: str  # absent, exited, running, unknown
    creation_filetime: str | None = None


def query_process(pid: int) -> ProcessState:
    if os.name != 'nt' or type(pid) is not int or not 0 < pid < 2**32:
        return ProcessState('unknown')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_uint64)] * 4
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return ProcessState('absent' if ctypes.get_last_error() == 87 else 'unknown')
    try:
        code = ctypes.c_uint32()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            return ProcessState('unknown')
        if code.value != 259:
            return ProcessState('exited')
        times = [ctypes.c_uint64() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
            return ProcessState('unknown')
        return ProcessState('running', f'{times[0].value:016x}')
    finally:
        kernel.CloseHandle(handle)


def identity_gone(state: ProcessState, expected_creation: str | None) -> bool:
    if state.status in ('absent', 'exited'):
        return True
    valid = lambda value: (isinstance(value, str)
        and re.fullmatch('[0-9a-f]{16}', value) is not None and int(value, 16) != 0)
    return (state.status == 'running' and valid(expected_creation)
        and valid(state.creation_filetime) and state.creation_filetime != expected_creation)


def owned_process_gone(pid: int, expected_creation: str | None) -> bool:
    return identity_gone(query_process(pid), expected_creation)
