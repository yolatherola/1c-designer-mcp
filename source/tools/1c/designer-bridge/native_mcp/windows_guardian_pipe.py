"""Owner-thread Windows guardian link; no native commands or source files.

Kernel peer PID/birth and a separate 256-bit capability authenticate both ends.
The outer envelope binds sequence, deadline and connection nonce. Closing this
link never closes a HostSlot or cancels a native operation already accepted.
"""
import ctypes
from ctypes import wintypes as W
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import secrets
import struct
import threading
import time

from . import guardian_wire as wire
from .windows_ram_pipe import _Api, _SA

PREFIX = '\\\\.\\pipe\\AH1C_GUARDIAN_'
BASE_SHA = '54dd9a45064f34930a2dc6441c3c78cdaaeefbdf02138fcb2459830f1c57ec1e'
WIRE_SHA = '3ca907c8f4df783cba01f63fb002e86c9cb2a262f504b785f50a9276c938a456'
_CLIENT = struct.Struct('<8sIIQ16s16s32s')
_SERVER = struct.Struct('<8sIIQ16s16s16s32s')
_TX = struct.Struct('<8sII16s16sQdI')
_ACK = struct.Struct('<8sQ32s')
MAX_TICKETS = 4096


class GuardianPipeRefusal(ValueError):
    """Stable metadata-only refusal; never formats capabilities or payloads."""


def need(value, code):
    if not value:
        raise GuardianPipeRefusal('GUARDIAN_PIPE_' + code)


def _hex(value, length):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}', value) is not None and value != '0'*length


def _timeout(value):
    need(type(value) in (int, float) and math.isfinite(value) and .01 <= value <= 60, 'TIMEOUT')
    return float(value)


def validate_endpoint(row):
    need(type(row) is dict and set(row) == {'pipe_path', 'guardian_pid', 'guardian_birth', 'endpoint_id', 'capability'}, 'ENDPOINT')
    need(type(row['guardian_pid']) is int and 0 < row['guardian_pid'] < 2**32
         and _hex(row['guardian_birth'], 16) and _hex(row['endpoint_id'], 32)
         and row['pipe_path'] == PREFIX + row['endpoint_id']
         and type(row['capability']) is bytes and len(row['capability']) == 32
         and row['capability'] != bytes(32), 'ENDPOINT')


class _GuardianApi(_Api):
    def __init__(self):
        super().__init__()
        self._bind(self.k, 'GetNamedPipeServerProcessId', W.BOOL, [W.HANDLE, ctypes.POINTER(W.ULONG)])
        self._bind(self.k, 'CreateFileW', W.HANDLE,
                   [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE])
        self._bind(self.k, 'WaitNamedPipeW', W.BOOL, [W.LPCWSTR, W.DWORD])
        self._bind(self.k, 'DisconnectNamedPipe', W.BOOL, [W.HANDLE])

    def create_duplex(self, path):
        actor = self.actor_sid()
        descriptor, size = W.LPVOID(), W.DWORD()
        sddl = 'D:P' + ''.join('(A;;GA;;;' + value + ')' for value in sorted({actor, 'S-1-5-18'}))
        need(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1,
            ctypes.byref(descriptor), ctypes.byref(size)), 'ACL_CREATE')
        try:
            sa = _SA(ctypes.sizeof(_SA), descriptor, False)
            # DUPLEX | OVERLAPPED | FIRST_INSTANCE; byte mode + REJECT_REMOTE.
            handle = self.k.CreateNamedPipeW(path, 0x40080003, 8, 1, 65536, 65536, 0, ctypes.byref(sa))
            need(handle not in (None, ctypes.c_void_p(-1).value), 'CREATE')
        finally:
            self.k.LocalFree(descriptor)
        try:
            self.verify_acl(handle, actor)
        except BaseException:
            self.w.CloseHandle(handle)
            raise
        return handle


class _Link:
    def __init__(self, timeout):
        here = Path(__file__).resolve().parent
        need(hashlib.sha256((here/'windows_ram_pipe.py').read_bytes()).hexdigest() == BASE_SHA
             and hashlib.sha256((here/'guardian_wire.py').read_bytes()).hexdigest() == WIRE_SHA, 'SOURCE_PIN')
        self._timeout = _timeout(timeout)
        self._api = _GuardianApi()
        self._owner_thread = threading.get_ident()
        self._handle = self._peer = None
        self._peer_birth = None
        self._peer_pid = None
        self._connected = False
        self._session = None
        self._sequence = 0
        self._stop = threading.Event()
        self.peer_verified = False

    @property
    def closed(self):
        return self._handle is None

    def _owner(self):
        need(threading.get_ident() == self._owner_thread, 'OWNER_THREAD')

    def request_stop(self):
        """Signal only; the owner cancels/drains its own pending OVERLAPPED."""
        self._stop.set()

    def _live(self):
        if self._peer is not None:
            self._api.live_process(self._peer, self._peer_birth)
            observed = W.ULONG()
            getter = self._api.k.GetNamedPipeClientProcessId if self._server else self._api.k.GetNamedPipeServerProcessId
            need(getter(self._handle, ctypes.byref(observed)) and observed.value == self._peer_pid, 'PEER_PID')

    def _complete(self, ov, deadline):
        try:
            while True:
                need(not self._stop.is_set(), 'STOPPED')
                if deadline is None:
                    wait = 100
                else:
                    wait = min(100, max(0, math.ceil((deadline-time.monotonic())*1000)))
                    need(wait > 0, 'DEADLINE')
                state = self._api.w.WaitForSingleObject(ov.event, wait)
                if state == 0:
                    break
                need(state == 258, 'WAIT')
                self._live()
        except BaseException:
            ov.cancel()
            ov.GetOverlappedResult(True)
            raise
        return ov.GetOverlappedResult(True)

    def _read(self, count, deadline):
        result = bytearray()
        while len(result) < count:
            ov, _ = self._api.w.ReadFile(self._handle, min(65536, count-len(result)), overlapped=True)
            transferred, error = self._complete(ov, deadline)
            need(error == 0 and transferred > 0, 'READ')
            chunk = bytes(ov.getbuffer())
            need(len(chunk) == transferred and len(chunk) <= count-len(result), 'READ_LENGTH')
            result.extend(chunk)
        return bytes(result)

    def _write(self, raw, deadline):
        offset = 0
        while offset < len(raw):
            ov, _ = self._api.w.WriteFile(self._handle, raw[offset:offset+65536], overlapped=True)
            count, error = self._complete(ov, deadline)
            need(error == 0 and 0 < count <= min(65536, len(raw)-offset), 'WRITE')
            offset += count

    def _bind_peer(self, expected_pid=None, expected_birth=None):
        peer = W.ULONG()
        getter = self._api.k.GetNamedPipeClientProcessId if self._server else self._api.k.GetNamedPipeServerProcessId
        need(getter(self._handle, ctypes.byref(peer)) and peer.value > 0, 'PEER_PID')
        if expected_pid is not None:
            need(peer.value == expected_pid, 'PEER_PID')
        handle = self._api.k.OpenProcess(0x101000, False, peer.value)
        need(handle, 'PEER_OPEN')
        try:
            birth = self._api.birth(handle)
            if expected_birth is not None:
                need(birth == expected_birth, 'PEER_BIRTH')
            self._api.live_process(handle, birth)
        except BaseException:
            self._api.w.CloseHandle(handle)
            raise
        self._peer, self._peer_birth, self._peer_pid = handle, birth, peer.value

    def _close_peer(self):
        if self._peer is not None:
            handle, self._peer = self._peer, None
            self._api.w.CloseHandle(handle)
        self._peer_birth = self._peer_pid = None
        self._connected = self.peer_verified = False
        self._session = None

    def _tag(self, label, raw):
        return hmac.digest(self._capability, label+raw, 'sha256')

    def _header(self, direction, sequence, deadline, size):
        return _TX.pack(b'AH1CGTX1', 1, direction, self._endpoint, self._session, sequence, deadline, size)

    def _parse_header(self, raw, direction, sequence, deadline=None):
        magic, version, observed, endpoint, session, seq, limit, size = _TX.unpack(raw)
        maximum = wire.HEADER_BYTES + (wire.MAX_REQUEST_BYTES if direction == 1 else wire.MAX_RESPONSE_BYTES)
        now = time.monotonic()
        need(magic == b'AH1CGTX1' and version == 1 and observed == direction
             and endpoint == self._endpoint and session == self._session
             and seq == sequence and 1 <= seq <= MAX_TICKETS
             and math.isfinite(limit) and now < limit <= now+60
             and wire.HEADER_BYTES < size <= maximum, 'ENVELOPE')
        if deadline is not None:
            need(struct.pack('<d', limit) == struct.pack('<d', deadline), 'DEADLINE_JOIN')
        return limit, size


class GuardianPipeServer(_Link):
    """One protected instance, sequential authenticated client connections.

    Construct, accept, receive, send, disconnect and close on one owner thread.
    request_stop is the only cross-thread operation and never touches a handle.
    endpoint is confidential root metadata, not an MCP result or diagnostic.
    """
    def __init__(self, *, timeout=5.0, capability=None):
        super().__init__(timeout)
        self._server = True
        self._endpoint = secrets.token_bytes(16)
        self._capability = secrets.token_bytes(32) if capability is None else capability
        need(type(self._capability) is bytes and len(self._capability) == 32 and self._capability != bytes(32), 'CAPABILITY')
        self._path = PREFIX+self._endpoint.hex()
        self._nonces = set()
        self._request_ids = set()
        self._pending = None
        self._handle = self._api.create_duplex(self._path)

    @property
    def endpoint(self):
        return dict(pipe_path=self._path, guardian_pid=os.getpid(),
            guardian_birth=self._api.birth(self._api.k.GetCurrentProcess()),
            endpoint_id=self._endpoint.hex(), capability=self._capability)

    def accept(self):
        self._owner(); need(not self.closed and not self._connected, 'ACCEPT_PHASE')
        failed = False
        try:
            ov = self._api.w.ConnectNamedPipe(self._handle, overlapped=True)
            _, error = self._complete(ov, None)
            need(error == 0, 'CONNECT')
            self._bind_peer()
            deadline = time.monotonic()+self._timeout
            raw = self._read(_CLIENT.size, deadline)
            magic, version, pid, birth, endpoint, nonce, tag = _CLIENT.unpack(raw)
            need(magic == b'AH1CGH01' and version == 1 and pid == self._peer_pid
                 and f'{birth:016x}' == self._peer_birth and endpoint == self._endpoint
                 and nonce != bytes(16) and nonce not in self._nonces
                 and len(self._nonces) < MAX_TICKETS
                 and hmac.compare_digest(tag, self._tag(b'CLIENT\0', raw[:-32])), 'AUTH')
            self._nonces.add(nonce)
            self._session = secrets.token_bytes(16)
            own_birth = int(self._api.birth(self._api.k.GetCurrentProcess()), 16)
            hello = _SERVER.pack(b'AH1CGH02', 1, os.getpid(), own_birth, self._endpoint, nonce, self._session, bytes(32))
            hello = hello[:-32]+self._tag(b'SERVER\0'+raw, hello[:-32])
            self._write(hello, deadline)
            ack = self._read(32, deadline)
            need(hmac.compare_digest(ack, self._tag(b'ACK\0', raw+hello)), 'AUTH_ACK')
            self._live()
            self._connected = self.peer_verified = True
            self._sequence = 0
        except Exception:
            failed = True
            self.disconnect()
        if failed:
            raise GuardianPipeRefusal('GUARDIAN_PIPE_ACCEPT_UNPROVEN')

    def receive_request(self):
        self._owner(); need(self._connected and self._pending is None, 'RECEIVE_PHASE')
        failed = False
        try:
            self._live()
            # Idle wait is stoppable but has no request deadline. Once any byte
            # arrives, partial headers/body are bounded like all other I/O.
            first = self._read(1, None)
            header = first+self._read(_TX.size-1, time.monotonic()+self._timeout)
            deadline, size = self._parse_header(header, 1, self._sequence+1)
            inner_header = self._read(wire.HEADER_BYTES, deadline)
            payload_size = wire.parse_header(inner_header)
            need(size == wire.HEADER_BYTES+payload_size, 'INNER_LENGTH')
            frame = inner_header+self._read(payload_size, deadline)
            request = wire.parse_request(frame)
            request_id = request['request_id']
            need(request_id not in self._request_ids and len(self._request_ids) < MAX_TICKETS, 'REPLAY')
            self._request_ids.add(request_id)
            self._sequence += 1
            self._pending = (request_id, self._sequence, deadline)
            self._live()
            return frame
        except Exception:
            failed = True
            self.disconnect()
        if failed:
            raise GuardianPipeRefusal('GUARDIAN_PIPE_RECEIVE_UNPROVEN')

    def send_response(self, frame):
        self._owner(); need(self._connected and self._pending is not None, 'RESPONSE_PHASE')
        request_id, sequence, deadline = self._pending
        failed = False
        try:
            wire.parse_response(frame, request_id=request_id)
            self._live(); need(time.monotonic() < deadline, 'DEADLINE')
            header = self._header(2, sequence, deadline, len(frame))
            self._write(header+frame, deadline)
            magic, seq, tag = _ACK.unpack(self._read(_ACK.size, deadline))
            need(magic == b'AH1CGAK1' and seq == sequence
                 and hmac.compare_digest(tag, self._tag(b'RESPONSE_ACK\0', header+frame)), 'RESPONSE_ACK')
            # ACK confirms the validated frame was copied before we may recycle
            # the pipe. The receiver may legitimately close immediately after it.
            self._pending = None
        except Exception:
            failed = True
            self.disconnect()
        if failed:
            raise GuardianPipeRefusal('GUARDIAN_PIPE_RESPONSE_UNPROVEN')

    def disconnect(self):
        self._owner()
        try:
            if self._handle is not None:
                ctypes.set_last_error(0)
                success = self._api.k.DisconnectNamedPipe(self._handle)
                need(success or ctypes.get_last_error() in (109, 232, 233), 'DISCONNECT')
        finally:
            self._close_peer()
            self._pending = None

    def close(self):
        self._owner()
        try:
            self.disconnect()
        finally:
            if self._handle is not None:
                handle, self._handle = self._handle, None
                self._api.w.CloseHandle(handle)
            self._capability = None


class GuardianPipeClient(_Link):
    """Single authenticated connection; failed exchanges are never replayed."""
    def __init__(self, endpoint, *, timeout=10.0):
        validate_endpoint(endpoint)
        super().__init__(timeout)
        self._server = False
        self._endpoint = bytes.fromhex(endpoint['endpoint_id'])
        self._capability = endpoint['capability']
        self._path = endpoint['pipe_path']
        self._guardian_pid = endpoint['guardian_pid']
        self._guardian_birth = endpoint['guardian_birth']
        self._used = False
        self._request_ids = set()

    def connect(self):
        self._owner(); need(not self._used and self.closed, 'CONNECT_PHASE')
        self._used = True
        failed = False
        try:
            self._peer = self._api.pin_process(self._guardian_pid, self._guardian_birth)
            self._peer_pid, self._peer_birth = self._guardian_pid, self._guardian_birth
            deadline = time.monotonic()+self._timeout
            need(self._api.k.WaitNamedPipeW(self._path, int(self._timeout*1000)), 'PIPE_WAIT')
            handle = self._api.k.CreateFileW(self._path, 0xc0000000, 0, None, 3, 0x40000000, None)
            need(handle not in (None, ctypes.c_void_p(-1).value), 'PIPE_OPEN')
            self._handle = handle
            self._live()
            birth = int(self._api.birth(self._api.k.GetCurrentProcess()), 16)
            hello = _CLIENT.pack(b'AH1CGH01', 1, os.getpid(), birth, self._endpoint, secrets.token_bytes(16), bytes(32))
            hello = hello[:-32]+self._tag(b'CLIENT\0', hello[:-32])
            self._write(hello, deadline)
            reply = self._read(_SERVER.size, deadline)
            magic, version, pid, observed_birth, endpoint, nonce, session, tag = _SERVER.unpack(reply)
            need(magic == b'AH1CGH02' and version == 1 and pid == self._guardian_pid
                 and f'{observed_birth:016x}' == self._guardian_birth and endpoint == self._endpoint
                 and nonce == _CLIENT.unpack(hello)[5] and session != bytes(16)
                 and hmac.compare_digest(tag, self._tag(b'SERVER\0'+hello, reply[:-32])), 'AUTH')
            self._session = session
            self._write(self._tag(b'ACK\0', hello+reply), deadline)
            self._live()
            self._connected = self.peer_verified = True
        except Exception:
            failed = True
            self.close()
        if failed:
            raise GuardianPipeRefusal('GUARDIAN_PIPE_CONNECT_UNPROVEN')

    def exchange(self, frame):
        self._owner(); need(self._connected and not self.closed, 'EXCHANGE_PHASE')
        request = wire.parse_request(frame)
        need(request['request_id'] not in self._request_ids and self._sequence < MAX_TICKETS, 'REPLAY')
        failed = False
        try:
            self._request_ids.add(request['request_id'])
            sequence = self._sequence+1
            deadline = time.monotonic()+self._timeout
            self._live()
            self._write(self._header(1, sequence, deadline, len(frame))+frame, deadline)
            header = self._read(_TX.size, deadline)
            _, size = self._parse_header(header, 2, sequence, deadline)
            inner_header = self._read(wire.HEADER_BYTES, deadline)
            payload_size = wire.parse_header(inner_header, response=True)
            need(size == wire.HEADER_BYTES+payload_size, 'INNER_LENGTH')
            response = inner_header+self._read(payload_size, deadline)
            wire.parse_response(response, request_id=request['request_id'])
            self._live()
            self._write(_ACK.pack(b'AH1CGAK1', sequence,
                self._tag(b'RESPONSE_ACK\0', header+response)), deadline)
            self._sequence = sequence
            return response
        except Exception:
            failed = True
            self.close()
        if failed:
            raise GuardianPipeRefusal('GUARDIAN_PIPE_EXCHANGE_UNPROVEN')

    def close(self):
        self._owner()
        if self._handle is not None:
            handle, self._handle = self._handle, None
            self._api.w.CloseHandle(handle)
        self._close_peer()
        self._capability = None
