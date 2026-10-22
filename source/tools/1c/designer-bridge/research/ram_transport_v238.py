"""RAM packet transport for a separately authorized, exact owned 1C process.

This library grants no process ownership, SDK dispatch or application mutation
authority. The root route must first validate its own session registry/lease.
Import is inert; payloads have no file/log/CLI API. Backend injection permits
offline tests. Receipts are observations, never capabilities for arbitrary free.
An UNKNOWN dispatch deliberately retains its allocation and handle. Recovering
it after interpreter loss needs a separately reviewed recovery implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Protocol

MAX_PACKET = 4 * 1024 * 1024
IMAGE_PATH = 'C:/Program Files (x86)/1cv8/8.3.18.1208/bin/1cv8.exe'
IMAGE_SHA256 = 'c49e36e4e1ca2f6db2c1b51228161297fd79b42d3d0c6dd046551e06d0a51e12'
_HEX16 = re.compile(r'[0-9a-f]{16}\Z')
_HEX32 = re.compile(r'[0-9a-f]{32}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """FILETIME creation value is sixteen lowercase hex digits, not wall time."""
    pid: int
    birth: str
    image_path: str
    image_sha256: str


@dataclass(frozen=True, slots=True)
class Receipt:
    """Technical metadata only; cannot be passed to cleanup as a capability."""
    operation_id: str
    pid: int
    birth: str
    address: int
    size: int
    sha256: str


class TransportError(RuntimeError):
    """Stable code and optional metadata only; backend errors are suppressed."""
    def __init__(self, code: str, receipt: Receipt | None = None):
        self.code = code
        self.receipt = receipt
        super().__init__('V238_' + code)


class Backend(Protocol):
    """All operations use one retained handle; allocate always creates new RAM."""
    def open(self, pid: int): ...
    def identity(self, handle) -> ProcessIdentity: ...
    def allocate(self, handle, size: int) -> int: ...
    def write(self, handle, address: int, payload: bytes) -> int: ...
    def read(self, handle, address: int, size: int) -> bytes: ...
    def free(self, handle, address: int) -> None: ...
    def close(self, handle) -> None: ...


def _path(value):
    return value.replace('\\', '/').casefold() if type(value) is str else None


def _target(value):
    if (type(value) is not ProcessIdentity or type(value.pid) is not int
            or not 0 < value.pid < 2**32 or type(value.birth) is not str
            or not _HEX16.fullmatch(value.birth) or int(value.birth, 16) == 0
            or _path(value.image_path) != _path(IMAGE_PATH)
            or value.image_sha256 != IMAGE_SHA256):
        raise TransportError('TARGET_IDENTITY')


class Lease:
    """Opaque, manager-owned capability. No payload is retained in Python here."""
    __slots__ = ('__owner', '__handle', '__receipt', '__identity', '__state',
                 '__readers_done')

    def __init__(self, owner, handle, receipt, identity):
        self.__owner, self.__handle = owner, handle
        self.__receipt, self.__identity = receipt, identity
        self.__state, self.__readers_done = 'ALLOCATED', False

    @property
    def receipt(self):
        return self.__receipt

    @property
    def state(self):
        return self.__state

    def __repr__(self):
        return f'Lease(state={self.__state!r}, receipt={self.__receipt!r})'


class RamTransport:
    """One serialized route's allocations; methods do not launch any code.

    Caller must serialize use, keep this manager alive through dispatch, and
    maintain the external persistent route lock. This object is not a process-
    wide/durable lock. No automatic finalizer frees retained remote memory.
    """
    def __init__(self, backend: Backend):
        self._backend = backend
        self._leases = {}
        self._seen = set()

    def _owned(self, lease):
        if (type(lease) is not Lease or lease._Lease__owner is not self
                or self._leases.get(lease.receipt.operation_id) is not lease):
            raise TransportError('FOREIGN_LEASE')
        return lease

    def _guard(self, handle, expected):
        try:
            found = self._backend.identity(handle)
        except Exception:
            raise TransportError('IDENTITY_UNAVAILABLE') from None
        if (type(found) is not ProcessIdentity or found.pid != expected.pid
                or found.birth != expected.birth
                or _path(found.image_path) != _path(expected.image_path)
                or found.image_sha256 != expected.image_sha256):
            raise TransportError('IDENTITY_CHANGED')

    def prepare(self, target: ProcessIdentity, operation_id: str, payload: bytes,
                *, expected_sha256: str) -> Lease:
        """Allocate, transfer and verify bytes only; does not dispatch a reader.

        SHA is supplied from the reviewed V237 packet proof. Any uncertain
        transfer before dispatch retains the allocation if identity cannot be
        freshly proved. TransportError.receipt identifies such retained RAM.
        """
        _target(target)
        if type(operation_id) is not str or not _HEX32.fullmatch(operation_id):
            raise TransportError('OPERATION_ID')
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_PACKET:
            raise TransportError('PAYLOAD_SIZE_TYPE')
        if (type(expected_sha256) is not str or not _HEX64.fullmatch(expected_sha256)
                or hashlib.sha256(payload).hexdigest() != expected_sha256):
            raise TransportError('PAYLOAD_SHA256')
        if operation_id in self._seen:
            raise TransportError('OPERATION_REPLAY')
        if any(item.state != 'RELEASED' and item._Lease__identity.pid == target.pid
               for item in self._leases.values()):
            raise TransportError('TARGET_RETAINED')
        # A failed attempt also consumes the operation id; retries require a new
        # reviewed operation and never overwrite a possibly retained buffer.
        self._seen.add(operation_id)
        handle = None
        lease = None
        try:
            handle = self._backend.open(target.pid)
            self._guard(handle, target)
            address = self._backend.allocate(handle, len(payload))
            if type(address) is not int or address <= 0:
                raise TransportError('ALLOCATION_ADDRESS')
            receipt = Receipt(operation_id, target.pid, target.birth, address,
                              len(payload), expected_sha256)
            lease = Lease(self, handle, receipt, target)
            self._leases[operation_id] = lease
            if address > 0xffffffff - len(payload):
                # A fresh backend-owned allocation is still ours to clean up;
                # its address must never be truncated into a 32-bit SDK field.
                raise TransportError('ALLOCATION_ADDRESS')
            # Recheck immediately before write, rather than relying only on the
            # pre-allocation check. The same retained kernel handle is used.
            self._guard(handle, target)
            written = self._backend.write(handle, address, payload)
            if type(written) is not int or written != len(payload):
                raise TransportError('PARTIAL_WRITE')
            readback = self._backend.read(handle, address, len(payload))
            if type(readback) is not bytes or len(readback) != len(payload):
                raise TransportError('PARTIAL_READ')
            if hashlib.sha256(readback).hexdigest() != expected_sha256:
                raise TransportError('READBACK_SHA256')
            self._guard(handle, target)
            lease._Lease__state = 'READY'
            return lease
        except Exception as exc:
            code = exc.code if type(exc) is TransportError else 'BACKEND_FAILURE'
            if lease is not None:
                try:
                    self._release(lease)
                except TransportError:
                    if lease.state == 'RELEASED':
                        raise TransportError(code + '_HANDLE_CLOSE_FAILED', lease.receipt) from None
                    lease._Lease__state = 'RETAINED_BEFORE_DISPATCH'
                    raise TransportError(code + '_RETAINED', lease.receipt) from None
            elif handle is not None:
                try:
                    self._backend.close(handle)
                except Exception:
                    pass
            raise TransportError(code) from None

    def mark_dispatched(self, lease: Lease) -> Receipt:
        """Call immediately BEFORE any native consumer might start reading.

        An admission marker is conservative: if the caller cannot prove that
        dispatch never started, it must mark_unknown and retain the allocation.
        """
        lease = self._owned(lease)
        if lease.state != 'READY':
            raise TransportError('DISPATCH_STATE', lease.receipt)
        self._guard(lease._Lease__handle, lease._Lease__identity)
        lease._Lease__state = 'DISPATCHED'
        return lease.receipt

    def mark_unknown(self, lease: Lease) -> Receipt:
        """Irreversible uncertainty: no free, redispatch or new target packet."""
        lease = self._owned(lease)
        if lease.state not in ('DISPATCHED', 'UNKNOWN'):
            raise TransportError('UNKNOWN_STATE', lease.receipt)
        lease._Lease__state = 'UNKNOWN'
        return lease.receipt

    def record_terminal(self, lease: Lease, *, no_readers: bool) -> None:
        """Root asserts a known terminal consumer result and reader release.

        A script's success code alone is insufficient: root must verify native
        context, hook workers and all consumers are released. UNKNOWN cannot
        be converted to terminal through this API.
        """
        lease = self._owned(lease)
        if lease.state != 'DISPATCHED' or type(no_readers) is not bool:
            raise TransportError('TERMINAL_STATE', lease.receipt)
        lease._Lease__readers_done = no_readers
        lease._Lease__state = 'TERMINAL'

    def release(self, lease: Lease) -> None:
        """Free only READY cancellation or known terminal with no readers."""
        lease = self._owned(lease)
        if not (lease.state == 'READY' or
                (lease.state == 'TERMINAL' and lease._Lease__readers_done)):
            raise TransportError('RELEASE_STATE', lease.receipt)
        self._release(lease)

    def _release(self, lease):
        self._guard(lease._Lease__handle, lease._Lease__identity)
        try:
            self._backend.free(lease._Lease__handle, lease.receipt.address)
        except Exception:
            lease._Lease__state = 'RETAINED_CLEANUP_FAILURE'
            raise TransportError('FREE_FAILED', lease.receipt) from None
        lease._Lease__state = 'RELEASED'
        try:
            self._backend.close(lease._Lease__handle)
        except Exception:
            # The allocation is already known freed. Never retry free because
            # handle cleanup failed; report only the technical cleanup problem.
            raise TransportError('HANDLE_CLOSE_FAILED', lease.receipt) from None


class WindowsBackend:
    """Explicit Win32 backend. Constructor binds functions but opens no process.

    The executable is hashed via a normal read-only file stream; module packet
    bytes are passed only to Write/ReadProcessMemory. No executable allocation,
    thread, hook, module load, VirtualProtectEx or platform memory patch exists.
    """
    PROCESS_RIGHTS = 0x1000 | 0x0008 | 0x0010 | 0x0020
    MEM_COMMIT_RESERVE = 0x1000 | 0x2000
    PAGE_READWRITE = 0x04
    MEM_RELEASE = 0x8000

    def __init__(self):
        import ctypes as ct
        import os
        from ctypes import wintypes as wt
        if os.name != 'nt':
            raise TransportError('WINDOWS_ONLY')
        self._ct, self._wt = ct, wt
        self._allocations = {}
        self._k = ct.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'OpenProcess': ([wt.DWORD, wt.BOOL, wt.DWORD], wt.HANDLE),
            'GetProcessId': ([wt.HANDLE], wt.DWORD),
            'GetProcessTimes': ([wt.HANDLE, ct.POINTER(wt.FILETIME), ct.POINTER(wt.FILETIME),
                                 ct.POINTER(wt.FILETIME), ct.POINTER(wt.FILETIME)], wt.BOOL),
            'GetExitCodeProcess': ([wt.HANDLE, ct.POINTER(wt.DWORD)], wt.BOOL),
            'QueryFullProcessImageNameW': ([wt.HANDLE, wt.DWORD, wt.LPWSTR,
                                          ct.POINTER(wt.DWORD)], wt.BOOL),
            'VirtualAllocEx': ([wt.HANDLE, ct.c_void_p, ct.c_size_t, wt.DWORD,
                                wt.DWORD], ct.c_void_p),
            'WriteProcessMemory': ([wt.HANDLE, ct.c_void_p, ct.c_void_p, ct.c_size_t,
                                    ct.POINTER(ct.c_size_t)], wt.BOOL),
            'ReadProcessMemory': ([wt.HANDLE, ct.c_void_p, ct.c_void_p, ct.c_size_t,
                                   ct.POINTER(ct.c_size_t)], wt.BOOL),
            'VirtualFreeEx': ([wt.HANDLE, ct.c_void_p, ct.c_size_t, wt.DWORD], wt.BOOL),
            'CloseHandle': ([wt.HANDLE], wt.BOOL),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self._k, name)
            fn.argtypes, fn.restype = args, result

    @staticmethod
    def _require(ok):
        if not ok:
            raise TransportError('WIN32_FAILURE')

    def open(self, pid):
        handle = self._k.OpenProcess(self.PROCESS_RIGHTS, False, pid)
        self._require(handle)
        return handle

    def identity(self, handle):
        ct, wt = self._ct, self._wt
        status = wt.DWORD()
        self._require(self._k.GetExitCodeProcess(handle, ct.byref(status)))
        self._require(status.value == 259)  # STILL_ACTIVE, retained handle only.
        times = [wt.FILETIME() for _ in range(4)]
        self._require(self._k.GetProcessTimes(handle, *[ct.byref(x) for x in times]))
        birth = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        path, length = ct.create_unicode_buffer(32768), wt.DWORD(32768)
        self._require(self._k.QueryFullProcessImageNameW(handle, 0, path, ct.byref(length)))
        pid = self._k.GetProcessId(handle)
        self._require(pid and length.value and length.value < 32768)
        self._require(_path(path.value) == _path(IMAGE_PATH))
        digest = hashlib.sha256()
        with open(path.value, 'rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        return ProcessIdentity(pid, f'{birth:016x}', path.value, digest.hexdigest())

    def allocate(self, handle, size):
        self._require(type(size) is int and 0 < size <= MAX_PACKET)
        address = self._k.VirtualAllocEx(handle, None, size,
                                        self.MEM_COMMIT_RESERVE, self.PAGE_READWRITE)
        self._require(address)
        self._allocations[(handle, address)] = size
        return address

    def write(self, handle, address, payload):
        self._require(type(payload) is bytes and
                      self._allocations.get((handle, address)) == len(payload))
        ct = self._ct
        buffer = ct.create_string_buffer(payload, len(payload))
        count = ct.c_size_t()
        self._require(self._k.WriteProcessMemory(handle, address, buffer,
                                                len(payload), ct.byref(count)))
        return count.value

    def read(self, handle, address, size):
        self._require(self._allocations.get((handle, address)) == size)
        ct = self._ct
        buffer, count = ct.create_string_buffer(size), ct.c_size_t()
        self._require(self._k.ReadProcessMemory(handle, address, buffer, size, ct.byref(count)))
        return buffer.raw[:count.value]

    def free(self, handle, address):
        self._require((handle, address) in self._allocations)
        self._require(self._k.VirtualFreeEx(handle, address, 0, self.MEM_RELEASE))
        del self._allocations[(handle, address)]

    def close(self, handle):
        self._require(self._k.CloseHandle(handle))
