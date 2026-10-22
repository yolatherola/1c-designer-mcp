"""Nonce READY for the frozen PID/birth-bound RAM inbox; no native reader.

Only synthetic/attested producers may use this transport. READY authenticates
the exchange phase, not application source provenance or snapshot freshness.
"""
import ctypes
from ctypes import wintypes as W
import hashlib
from pathlib import Path
import re
import time
from types import FunctionType
from . import windows_ram_pipe as _base
from .saved_source import ReadRequest

BASE_SHA256='54dd9a45064f34930a2dc6441c3c78cdaaeefbdf02138fcb2459830f1c57ec1e'
READY_MAGIC=b'AH1CRDY1'
READY_BYTES=40
NativePipeRefusal=_base.NativePipeRefusal
need=_base.need

class _DuplexApi(_base._Api):
    def create(self,path):
        actor=self.actor_sid();descriptor,size=W.LPVOID(),W.DWORD()
        actors=sorted({actor,'S-1-5-18'})
        sddl='D:P'+''.join('(A;;GA;;;'+value+')' for value in actors)
        need(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,1,ctypes.byref(descriptor),ctypes.byref(size)),'ACL_CREATE')
        try:
            sa=_base._SA(ctypes.sizeof(_base._SA),descriptor,False)
            # Only this access flag differs from the pinned base: DUPLEX3.
            handle=self.k.CreateNamedPipeW(path,0x40080003,8,1,65536,65536,0,ctypes.byref(sa))
            need(handle not in (None,ctypes.c_void_p(-1).value),'CREATE')
        finally:self.k.LocalFree(descriptor)
        try:self.verify_acl(handle,actor)
        except BaseException:
            self.w.CloseHandle(handle);raise
        return handle

# Clone only the constructor's globals. The original module/class and every
# existing NativeRamInbox keep their inbound-only API and function identity.
_original_init=_base.NativeRamInbox.__init__
_private_init=FunctionType(_original_init.__code__,dict(_original_init.__globals__,_Api=_DuplexApi),
                          _original_init.__name__,_original_init.__defaults__,_original_init.__closure__)
_private_init.__kwdefaults__=dict(_original_init.__kwdefaults__ or {})

class NativeReadyRamInbox(_base.NativeRamInbox):
    """One owner thread, one peer, one nonce ACK, then one bounded RAM frame.

    The sender must open with read/write access, verify server PID/birth, read
    exactly READY_BYTES and compare all bytes before writing/closing. The frozen
    receive method checks peer PID/birth before our first _read and closes both
    handles in finally. Cancellation drains owned OVERLAPPED operations; cleanup
    may outlast the exchange timeout. No retries or stream resynchronization.
    """
    def __init__(self,expected_client_pid,*,request_id,expected_birth,timeout=5.0):
        need(type(request_id) is str and re.fullmatch('[0-9a-f]{32}',request_id) is not None,'REQUEST_ID')
        try:source=Path(_base.__file__).read_bytes()
        except OSError:raise NativePipeRefusal('RAM_PIPE_BASE_PIN') from None
        need(hashlib.sha256(source).hexdigest()==BASE_SHA256,'BASE_PIN')
        self.request_id=request_id;self.ready_sent=False;self._ready_attempted=False
        _private_init(self,expected_client_pid,expected_birth=expected_birth,timeout=timeout)

    def receive_snapshot(self,request,*,clock=time.monotonic):
        need(type(request) is ReadRequest and request.request_id==self.request_id,'REQUEST_NONCE')
        return super().receive_snapshot(request,clock=clock)

    def _read(self,count,deadline):
        if not self._ready_attempted:
            need(self.peer_verified,'READY_PHASE')
            self._ready_attempted=True
            ready=READY_MAGIC+self.request_id.encode('ascii')
            try:
                ov,_=self._api.w.WriteFile(self._handle,ready,overlapped=True)
                count_written,error=self._complete(ov,deadline)
            except OSError:raise NativePipeRefusal('RAM_PIPE_READY_IO') from None
            need(error==0 and count_written==READY_BYTES,'READY_WRITE')
            self.ready_sent=True
        return super()._read(count,deadline)
