"""Authenticated, owner-thread persistent byte pipe; no native attestation.

One connection carries fixed commands and bounded responses. A response remains
pending until its caller validates semantic/native proofs and explicitly ACKs.
No reconnect, retry, endpoint transfer, process launch, or body files are used.
"""
import ctypes
from ctypes import wintypes as W
import hashlib
from pathlib import Path
import struct
import threading
import time

from . import windows_ready_ram_pipe as ready

READY_SHA256 = '1821d8603d72bab9dd836ff7ae4ee43ef78ea5dc19fd87eef7e8faf594325119'
need = ready.need
NativePipeRefusal = ready.NativePipeRefusal
MAX_FRAME = 16 + 16384 + 4194304


class NativeResidentPipe(ready.NativeReadyRamInbox):
    """One PID/birth-bound local client and at most 64 command tickets.

    All methods, including close, execute on the constructing thread. Bounded
    overlapped I/O is cancelled and drained by the pinned CPython owner before
    buffers/handles are released. A malformed or timed-out exchange poisons this
    channel; cleanup of remote SDK references is the resident worker's duty.
    """
    def __init__(self, expected_client_pid, *, install_nonce, expected_birth, timeout=5.0):
        need(hashlib.sha256(Path(ready.__file__).read_bytes()).hexdigest() == READY_SHA256,
             'RESIDENT_READY_PIN')
        super().__init__(expected_client_pid, request_id=install_nonce,
                         expected_birth=expected_birth, timeout=timeout)
        self._connected = False
        self._poisoned = False
        self._pending = None
        self._last_sequence = 0
        self._terminal_response = False

    def _owner(self):
        need(threading.get_ident() == self._owner_thread, 'OWNER_THREAD')

    def _live(self):
        self._api.live_process(self._process, self._birth)
        peer = W.ULONG()
        need(self._api.k.GetNamedPipeClientProcessId(self._handle, ctypes.byref(peer))
             and peer.value == self._pid, 'PEER_PID')

    def _write_exact(self, raw, deadline):
        offset = 0
        while offset < len(raw):
            ov, _ = self._api.w.WriteFile(self._handle, raw[offset:], overlapped=True)
            count, error = self._complete(ov, deadline)
            need(error == 0 and 0 < count <= len(raw)-offset, 'RESIDENT_WRITE')
            offset += count

    def _read_exact(self, count, deadline):
        value = bytearray()
        while len(value) < count:
            chunk = self._read(min(65536, count-len(value)), deadline)
            need(bool(chunk), 'RESIDENT_TRUNCATED')
            value.extend(chunk)
        return bytes(value)

    def connect(self):
        """Authenticate the client before releasing the installation READY."""
        self._owner()
        need(not self.closed and not self._connected and not self._used and not self._poisoned,
             'RESIDENT_CONNECT_PHASE')
        self._used = True
        deadline = time.monotonic()+self._timeout
        try:
            ov = self._api.w.ConnectNamedPipe(self._handle, overlapped=True)
            _, error = self._complete(ov, deadline)
            need(error == 0, 'CONNECT_RESULT')
            self._live()
            self.peer_verified = True
            self._ready_attempted = True
            self._write_exact(ready.READY_MAGIC+self.request_id.encode('ascii'), deadline)
            self.ready_sent = True
            self._connected = True
        except BaseException:
            self._poisoned = True
            self.close()
            raise

    def exchange(self, command):
        """Return one raw bounded response in RAM; semantic validation is separate.

        The caller must parse proofs/epoch/snapshot and acknowledge before the
        next command. No success or native source provenance follows from bytes.
        """
        self._owner()
        need(not self.closed and self._connected and not self._poisoned and self._pending is None
             and not self._terminal_response, 'RESIDENT_EXCHANGE_PHASE')
        need(type(command) is bytes and len(command) == 160 and command[:8] == b'AH1CCMD2',
             'RESIDENT_COMMAND')
        version, opcode, sequence = struct.unpack_from('<III', command, 8)
        need(version == 2 and opcode in (3, 4, 5) and sequence == self._last_sequence+1
             and 1 <= sequence <= 64 and (sequence < 64 or opcode == 5), 'RESIDENT_TICKET')
        deadline = time.monotonic()+self._timeout
        try:
            self._live()
            self._write_exact(command, deadline)
            header = self._read_exact(32, deadline)
            magic, seq, op, status, proof_bytes, epoch_bytes, frame_bytes = struct.unpack('<8sIIIIII', header)
            need(magic == b'AH1CRSP2' and seq == sequence and op == opcode and status in (0, 1, 2, 3, 4),
                 'RESIDENT_RESPONSE_JOIN')
            need(0 < proof_bytes <= 16384 and epoch_bytes <= 32768 and frame_bytes <= MAX_FRAME
                 and (status == 0 and opcode == 3 or frame_bytes == 0)
                 and (status != 4 or opcode == 5) and (opcode != 5 or status != 0),
                 'RESIDENT_RESPONSE_BOUND')
            value = header+self._read_exact(proof_bytes+epoch_bytes+frame_bytes, deadline)
            self._live()
            self._pending = (sequence, opcode, status)
            return value
        except BaseException:
            self._poisoned = True
            raise

    def acknowledge(self, accepted):
        """ACK validated bytes once; a rejected/unknown result seals the channel."""
        self._owner()
        need(type(accepted) is bool, 'RESIDENT_ACK_TYPE')
        need(not self.closed and not self._poisoned and self._pending is not None,
             'RESIDENT_ACK_PHASE')
        sequence, opcode, status = self._pending
        try:
            self._live()
            self._write_exact(struct.pack('<8sII', b'AH1CACK2', sequence, 0 if accepted else 1),
                              time.monotonic()+self._timeout)
            self._last_sequence = sequence
            self._pending = None
            self._terminal_response = opcode == 5 and status == 4
            self._poisoned = not accepted or status == 2
        except BaseException:
            self._poisoned = True
            raise

    def confirm_peer_closed(self):
        """After a validated CLOSE/ACK, require EOF before releasing local handles."""
        self._owner()
        need(not self.closed and self._terminal_response and self._pending is None and not self._poisoned,
             'RESIDENT_EOF_PHASE')
        try:
            need(not self._read(1, time.monotonic()+self._timeout), 'RESIDENT_TRAILING')
            self._api.live_process(self._process, self._birth)
        except BaseException:
            self._poisoned = True
            raise
        finally:
            self.close()
