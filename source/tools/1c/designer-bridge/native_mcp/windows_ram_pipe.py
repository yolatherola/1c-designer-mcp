"""One local, PID-bound, protected Windows pipe. Application bytes stay in RAM.

This is an inbox, not a native reader or attestation. A trusted launcher must
separately establish the native guard and the physical provenance of a receipt.
The caller owns returned bytes. No source, path or command is accepted from MCP.
"""
import ctypes
from ctypes import wintypes as W
import math
import os
import re
import struct
import threading
import time
import uuid

from .ram_wire import HEADER_BYTES, MAGIC, MAX_FRAME_BYTES, MAX_METADATA_BYTES, parse_frame
from .saved_source import MAX_BYTES


class NativePipeRefusal(ValueError):
    """Stable metadata-only failure; never forwards an OS or body diagnostic."""


def need(condition, code):
    if not condition:
        raise NativePipeRefusal('RAM_PIPE_' + code)


class _SA(ctypes.Structure):
    _fields_ = [('length', W.DWORD), ('descriptor', W.LPVOID), ('inherit', W.BOOL)]


class _AclSize(ctypes.Structure):
    _fields_ = [('ace_count', W.DWORD), ('in_use', W.DWORD), ('free', W.DWORD)]


class _Api:
    def __init__(self):
        need(os.name == 'nt', 'WINDOWS_REQUIRED')
        import _winapi
        self.w = _winapi
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        self.a = ctypes.WinDLL('advapi32', use_last_error=True)
        self._bind(self.k, 'GetCurrentProcess', W.HANDLE, [])
        self._bind(self.k, 'OpenProcess', W.HANDLE, [W.DWORD, W.BOOL, W.DWORD])
        self._bind(self.k, 'GetProcessTimes', W.BOOL, [W.HANDLE] + [ctypes.POINTER(W.FILETIME)] * 4)
        self._bind(self.k, 'LocalFree', W.HLOCAL, [W.HLOCAL])
        self._bind(self.k, 'CreateNamedPipeW', W.HANDLE,
                   [W.LPCWSTR, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD, ctypes.POINTER(_SA)])
        self._bind(self.k, 'GetNamedPipeClientProcessId', W.BOOL, [W.HANDLE, ctypes.POINTER(W.ULONG)])
        self._bind(self.a, 'OpenProcessToken', W.BOOL, [W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE)])
        self._bind(self.a, 'GetTokenInformation', W.BOOL,
                   [W.HANDLE, ctypes.c_int, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)])
        self._bind(self.a, 'ConvertSidToStringSidW', W.BOOL, [W.LPVOID, ctypes.POINTER(W.LPWSTR)])
        self._bind(self.a, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', W.BOOL,
                   [W.LPCWSTR, W.DWORD, ctypes.POINTER(W.LPVOID), ctypes.POINTER(W.DWORD)])
        self._bind(self.a, 'GetSecurityInfo', W.DWORD,
                   [W.HANDLE, ctypes.c_int, W.DWORD, W.LPVOID, W.LPVOID,
                    ctypes.POINTER(W.LPVOID), W.LPVOID, ctypes.POINTER(W.LPVOID)])
        self._bind(self.a, 'GetSecurityDescriptorControl', W.BOOL,
                   [W.LPVOID, ctypes.POINTER(W.WORD), ctypes.POINTER(W.DWORD)])
        self._bind(self.a, 'GetAclInformation', W.BOOL, [W.LPVOID, W.LPVOID, W.DWORD, ctypes.c_int])
        self._bind(self.a, 'GetAce', W.BOOL, [W.LPVOID, W.DWORD, ctypes.POINTER(W.LPVOID)])

    @staticmethod
    def _bind(dll, name, result, args):
        fn = getattr(dll, name)
        fn.restype, fn.argtypes = result, args

    def sid_string(self, address):
        value = W.LPWSTR()
        need(self.a.ConvertSidToStringSidW(address, ctypes.byref(value)), 'SID_CONVERT')
        try:
            return value.value
        finally:
            self.k.LocalFree(ctypes.cast(value, W.HLOCAL))

    def birth(self, handle):
        creation, exit_time, kernel, user = (W.FILETIME() for _ in range(4))
        need(self.k.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time),
                                    ctypes.byref(kernel), ctypes.byref(user)), 'PROCESS_TIMES')
        return format((creation.dwHighDateTime << 32) | creation.dwLowDateTime, '016x')

    def pin_process(self, pid, birth):
        handle = self.k.OpenProcess(0x101000, False, pid)
        need(handle, 'PROCESS_OPEN')
        try:
            self.live_process(handle, birth)
        except BaseException:
            self.w.CloseHandle(handle)
            raise
        return handle

    def live_process(self, handle, birth):
        need(self.w.WaitForSingleObject(handle, 0) == 258 and self.birth(handle) == birth, 'PROCESS_IDENTITY')

    def actor_sid(self):
        token, size = W.HANDLE(), W.DWORD()
        need(self.a.OpenProcessToken(self.k.GetCurrentProcess(), 8, ctypes.byref(token)), 'TOKEN')
        try:
            self.a.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            need(0 < size.value <= 65536, 'TOKEN_SIZE')
            data = ctypes.create_string_buffer(size.value)
            need(self.a.GetTokenInformation(token, 1, data, size, ctypes.byref(size)), 'TOKEN_USER')
            return self.sid_string(ctypes.cast(data, ctypes.POINTER(W.LPVOID)).contents.value)
        finally:
            self.w.CloseHandle(token.value)

    def verify_acl(self, handle, actor):
        descriptor, acl = W.LPVOID(), W.LPVOID()
        need(self.a.GetSecurityInfo(handle, 6, 4, None, None, ctypes.byref(acl), None,
                                    ctypes.byref(descriptor)) == 0, 'ACL_READ')
        try:
            control, revision = W.WORD(), W.DWORD()
            need(self.a.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision))
                 and control.value & 0x1000 and acl.value, 'ACL_PROTECTED')
            info = _AclSize()
            need(self.a.GetAclInformation(acl, ctypes.byref(info), ctypes.sizeof(info), 2), 'ACL_INFO')
            expected, observed = {actor, 'S-1-5-18'}, set()
            need(info.ace_count == len(expected), 'ACL_COUNT')
            for index in range(info.ace_count):
                ace = W.LPVOID()
                need(self.a.GetAce(acl, index, ctypes.byref(ace)) and ace.value, 'ACL_ACE')
                # ACCESS_ALLOWED_ACE: header4, accessmask4, then the SID.
                need(ctypes.c_ubyte.from_address(ace.value).value == 0
                     and ctypes.c_ubyte.from_address(ace.value + 1).value == 0, 'ACL_RULE')
                mask = W.DWORD.from_address(ace.value + 4).value
                need(mask & 0x1f01ff == 0x1f01ff, 'ACL_RIGHTS')
                observed.add(self.sid_string(ace.value + 8))
            need(observed == expected, 'ACL_IDENTITIES')
        finally:
            self.k.LocalFree(descriptor)

    def create(self, path):
        actor = self.actor_sid()
        descriptor, size = W.LPVOID(), W.DWORD()
        # No inherited/default/everyone/admin access. System may equal actor.
        actors = sorted({actor, 'S-1-5-18'})
        sddl = 'D:P' + ''.join('(A;;GA;;;' + value + ')' for value in actors)
        need(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)), 'ACL_CREATE')
        try:
            sa = _SA(ctypes.sizeof(_SA), descriptor, False)
            # OVERLAPPED | FIRST_PIPE_INSTANCE | PIPE_ACCESS_INBOUND.
            handle = self.k.CreateNamedPipeW(path, 0x40080001, 8, 1, 65536, 65536, 0, ctypes.byref(sa))
            need(handle not in (None, ctypes.c_void_p(-1).value), 'CREATE')
        finally:
            self.k.LocalFree(descriptor)
        try:
            self.verify_acl(handle, actor)
        except BaseException:
            self.w.CloseHandle(handle)
            raise
        return handle


class NativeRamInbox:
    """Create one strict inbox; receive once, then close in a with/finally block.

    timeout bounds the exchange, including connect; cleanup may outlast it.
    A held process handle plus birth/liveness checks bind the peer across reads.
    All operations and close belong to the constructing thread. Cancellation is drained by
    CPython's owned OVERLAPPED wrapper before its buffer or handle is released.
    The native sender must independently verify this server PID and its write
    completion. This object alone establishes neither native purity nor speed.
    """
    def __init__(self, expected_client_pid, *, expected_birth, timeout=5.0):
        need(type(expected_client_pid) is int and 0 < expected_client_pid < 2**32, 'PID')
        need(type(expected_birth) is str and re.fullmatch('[0-9a-f]{16}', expected_birth)
             and expected_birth != '0'*16, 'BIRTH')
        need(type(timeout) in (int, float) and math.isfinite(timeout) and .01 <= timeout <= 30, 'TIMEOUT')
        self._api = _Api()
        self._path = '\\\\.\\pipe\\AH1C-RAM-' + uuid.uuid4().hex
        self._pid = expected_client_pid
        self._birth = expected_birth
        self._timeout = timeout
        self._owner_thread = threading.get_ident()
        self._handle = None
        self._process = self._api.pin_process(self._pid, self._birth)
        try:
            self._handle = self._api.create(self._path)
        except BaseException:
            self.close()
            raise
        self._used = False
        self.peer_verified = False

    @property
    def path(self):
        return self._path

    @property
    def closed(self):
        return self._handle is None

    def __enter__(self):
        need(not self.closed, 'CLOSED')
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        need(threading.get_ident() == self._owner_thread, 'OWNER_THREAD')
        if self._handle is not None:
            handle, self._handle = self._handle, None
            self._api.w.CloseHandle(handle)
        if self._process is not None:
            process, self._process = self._process, None
            self._api.w.CloseHandle(process)

    def _complete(self, overlapped, deadline):
        try:
            remaining = max(0, math.ceil((deadline - time.monotonic()) * 1000))
            need(remaining > 0 and self._api.w.WaitForSingleObject(overlapped.event, remaining) == 0, 'DEADLINE')
        except BaseException:
            overlapped.cancel()
            # Match CPython multiprocessing's cancellation ownership pattern.
            overlapped.GetOverlappedResult(True)
            raise
        return overlapped.GetOverlappedResult(True)

    def _read(self, count, deadline):
        try:
            ov, error = self._api.w.ReadFile(self._handle, count, overlapped=True)
            _, error = self._complete(ov, deadline)
        except OSError as exc:
            if exc.winerror in (109, 232):
                return b''
            raise NativePipeRefusal('RAM_PIPE_READ') from None
        need(error in (0, 109, 232), 'READ_RESULT')
        return bytes(ov.getbuffer()) if error == 0 else b''

    def receive_frame(self):
        """Return one bounded frame in RAM; reject wrong PID before body reads."""
        need(threading.get_ident() == self._owner_thread, 'OWNER_THREAD')
        need(not self.closed and not self._used, 'ONE_SHOT')
        self._used = True
        deadline = time.monotonic() + self._timeout
        try:
            try:
                ov = self._api.w.ConnectNamedPipe(self._handle, overlapped=True)
            except OSError:
                raise NativePipeRefusal('RAM_PIPE_CONNECT') from None
            _, error = self._complete(ov, deadline)
            need(error == 0, 'CONNECT_RESULT')
            peer = W.ULONG()
            need(self._api.k.GetNamedPipeClientProcessId(self._handle, ctypes.byref(peer))
                 and peer.value == self._pid, 'PEER_PID')
            self._api.live_process(self._process, self._birth)
            self.peer_verified = True
            frame, wanted = bytearray(), HEADER_BYTES
            while len(frame) < wanted:
                chunk = self._read(min(65536, wanted - len(frame)), deadline)
                need(bool(chunk), 'TRUNCATED')
                frame.extend(chunk)
                if len(frame) == HEADER_BYTES and wanted == HEADER_BYTES:
                    need(bytes(frame[:8]) == MAGIC, 'MAGIC')
                    metadata, body = struct.unpack_from('<II', frame, 8)
                    need(0 < metadata <= MAX_METADATA_BYTES and body <= MAX_BYTES, 'FRAME_BOUND')
                    wanted = HEADER_BYTES + metadata + body
                    need(wanted <= MAX_FRAME_BYTES, 'FRAME_BOUND')
            need(not self._read(1, deadline), 'TRAILING')
            self._api.live_process(self._process, self._birth)
            return bytes(frame)
        except OSError:
            raise NativePipeRefusal('RAM_PIPE_IO') from None
        finally:
            self.close()

    def receive_snapshot(self, request, *, clock=time.monotonic):
        """Decode a bound snapshot; physical native claims need a separate proof."""
        from .saved_source import ReadRequest, SourceBinding
        need(type(request) is ReadRequest and type(request.binding) is SourceBinding
             and request.binding.process_id == self._pid and request.binding.birth == self._birth, 'REQUEST_PROCESS')
        frame = self.receive_frame()
        try:
            return parse_frame(frame, request, clock())
        finally:
            frame = None
