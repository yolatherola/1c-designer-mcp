"""Protected one-shot LIVE inbox, one handle owner, validation then ACK then EOF.

Construction reserves only. Deadlines start at explicit arm after RootRun. No
native source is read here; only a trusted physical verifier may accept a frame.
"""
import ctypes
from ctypes import wintypes as W
import hashlib
import inspect
import math
import os
from pathlib import Path
import queue
import threading
import time
from uuid import uuid4

WIRE_SHA='28dbc6053386099696415eb6dbc4fdf8abb9aca5790ebc91e45620d113b59ba2'
if hashlib.sha256(Path(__file__).with_name('live_wire.py').read_bytes()).hexdigest()!=WIRE_SHA:
    raise ValueError('LIVE_PIPE_WIRE_PIN')
from . import live_wire as wire

BASE_SHA='54dd9a45064f34930a2dc6441c3c78cdaaeefbdf02138fcb2459830f1c57ec1e'
READY_SHA='1821d8603d72bab9dd836ff7ae4ee43ef78ea5dc19fd87eef7e8faf594325119'
for _file,_pin in (('windows_ram_pipe.py',BASE_SHA),('windows_ready_ram_pipe.py',READY_SHA)):
    if hashlib.sha256(Path(__file__).with_name(_file).read_bytes()).hexdigest()!=_pin:
        raise ValueError('LIVE_PIPE_PRIMITIVE_PIN')
from . import windows_ram_pipe as base
from . import windows_ready_ram_pipe as ready


class LivePipeRefusal(RuntimeError):
    """Stable transport error; never reflects source, OS, peer or callback text."""


def _need(ok,code):
    if not ok:raise LivePipeRefusal('LIVE_PIPE_'+code)


class _Inbox(base.NativeRamInbox):
    # Reuse only pinned ACL/process/OVL cancellation primitives, never its
    # saved-domain receive_frame/EOF protocol or NativeReadyRamInbox._read.
    def __init__(self,pid,birth):
        self._api=ready._DuplexApi();self._owner_thread=threading.get_ident()
        self._pid,self._birth=pid,birth;self._handle=self._process=None
        self._path='\\\\.\\pipe\\AH1C-LIVE-'+uuid4().hex
        try:
            self._process=self._api.pin_process(pid,birth)
            self._handle=self._api.create(self._path)
        except BaseException:
            self.close();raise

    def identity(self,request_id):
        return dict(pipePath=self.path,serverPid=os.getpid(),
            serverBirth=self._api.birth(self._api.k.GetCurrentProcess()),requestId=request_id)

    def _live(self):
        self._api.live_process(self._process,self._birth);peer=W.ULONG()
        _need(self._api.k.GetNamedPipeClientProcessId(self._handle,ctypes.byref(peer))
              and peer.value==self._pid,'PEER_PID')

    def _read_exact(self,count,deadline):
        value=bytearray()
        while len(value)<count:
            raw=self._read(min(65536,count-len(value)),deadline)
            _need(bool(raw),'TRUNCATED');value.extend(raw)
        return bytes(value)

    def _write_exact(self,raw,deadline):
        offset=0
        while offset<len(raw):
            ov,_=self._api.w.WriteFile(self._handle,raw[offset:],overlapped=True)
            count,error=self._complete(ov,deadline)
            _need(error==0 and 0<count<=len(raw)-offset,'WRITE');offset+=count

    def receive(self,context,validator,deadline,abandoned):
        frame=None;snapshot=None;request=None;accepted=False
        try:
            ov=self._api.w.ConnectNamedPipe(self._handle,overlapped=True)
            _,error=self._complete(ov,deadline);_need(error==0,'CONNECT')
            self._live();_need(not abandoned(),'ABANDONED')
            self._write_exact(wire.ready_bytes(context),deadline)
            header=self._read_exact(wire.HEADER_BYTES,deadline)
            meta,body,_,_=wire.parse_header(header)
            raw=header+self._read_exact(meta+body,deadline);self._live()
            frame=wire.parse_frame(raw,context,now=time.monotonic());raw=None
            request=wire.expected_request(frame,context)
            _need(not abandoned(),'ABANDONED')
            snapshot=validator(frame,request)
            if inspect.isawaitable(snapshot):
                if inspect.iscoroutine(snapshot):snapshot.close()
                raise LivePipeRefusal('LIVE_PIPE_ASYNC_VALIDATOR')
            wire.validate_result(frame,snapshot,request,context,now=time.monotonic())
            self._live();_need(not abandoned() and time.monotonic()<=deadline,'ABANDONED')
            self._write_exact(wire.build_ack(context,frame.metadata['source_sha256'],accepted=True),deadline)
            accepted=True
            # Client reads ACK, closes its handle; only now may we wait for EOF.
            _need(not self._read(1,deadline),'TRAILING');self._live()
            _need(not abandoned(),'ABANDONED')
            return snapshot,request
        except BaseException:
            if not accepted and frame is not None:
                try:self._write_exact(wire.build_ack(context,frame.metadata['source_sha256'],accepted=False),deadline)
                except BaseException:pass
            snapshot=None;request=None;raise
        finally:
            frame=None;self.close()


class LiveRamReceiver:
    """Reserve, explicitly arm once, receive once on a dedicated handle owner.

    ``validator(frame, request)`` is a trusted synchronous physical-proof join,
    not a tool argument. ACK accepts private RAM only; final SDK worker/host
    cleanup remains the controller's gate before public MCP exposure.
    """
    def __init__(self,expected_client_pid,*,expected_birth,context,timeout=60.0):
        _need(type(context) is wire.LiveFrameContext,'CONTEXT');context.validate()
        _need(type(expected_client_pid) is int and expected_client_pid==context.process_id
              and type(expected_birth) is str and expected_birth==context.birth,'PEER_CONTEXT')
        _need(type(timeout) in (int,float) and math.isfinite(timeout) and .01<=timeout<=90,'TIMEOUT')
        self._context=context;self._timeout=float(timeout);self._lock=threading.Lock()
        self._queue=queue.Queue(maxsize=1);self._ready=threading.Event();self._done=threading.Event()
        self._exited=threading.Event();self._abandoned=False;self._armed=False
        self._result=None;self._error=None;self._identity=None;self._consumed=False;self._handles_closed=False
        self._thread=threading.Thread(target=self._owner,args=(expected_client_pid,expected_birth),
            name='AH1C LIVE RAM receiver owner',daemon=True)
        self._thread.start()
        if not self._ready.wait(5.0):
            with self._lock:self._abandoned=True
            self._queue.put_nowait(None)
            raise LivePipeRefusal('LIVE_PIPE_RESERVE_UNKNOWN')
        _need(self._identity is not None and self._error is None,'RESERVE')

    @property
    def identity(self):return dict(self._identity)
    @property
    def path(self):return self._identity['pipePath']
    @property
    def closed(self):return self._exited.is_set() and self._handles_closed
    @property
    def owner_thread_alive(self):return self._thread.is_alive()

    def _is_abandoned(self):
        with self._lock:return self._abandoned

    def _owner(self,pid,birth):
        pipe=None;job=None;result=None
        try:
            pipe=_Inbox(pid,birth)
            with self._lock:self._identity=pipe.identity(self._context.request_id)
            self._ready.set()
            job=self._queue.get()
            if job is None or self._is_abandoned():return
            result=pipe.receive(self._context,job,time.monotonic()+self._timeout,self._is_abandoned)
            with self._lock:
                if not self._abandoned:self._result=result;result=None
        except BaseException:
            with self._lock:self._error='LIVE_PIPE_RECEIVE_UNPROVEN';self._abandoned=True
        finally:
            result=None;job=None
            if pipe is not None:
                try:
                    pipe.close()
                    with self._lock:self._handles_closed=True
                except BaseException:
                    with self._lock:self._error='LIVE_PIPE_CLOSE_UNPROVEN';self._abandoned=True;self._result=None
            pipe=None;self._ready.set();self._done.set();self._exited.set()

    def arm(self,validator):
        _need(callable(validator) and not inspect.iscoroutinefunction(validator),'VALIDATOR')
        with self._lock:
            _need(not self._armed and not self._abandoned and not self.closed,'ARM_PHASE')
            self._armed=True;self._queue.put_nowait(validator)

    def receive(self,timeout=75.0):
        _need(type(timeout) in (int,float) and math.isfinite(timeout) and 0<=timeout<=120,'WAIT_TIMEOUT')
        with self._lock:_need(self._armed and not self._consumed,'RECEIVE_PHASE')
        if not self._done.wait(timeout):
            with self._lock:
                if not self._done.is_set():
                    self._abandoned=True;raise LivePipeRefusal('LIVE_PIPE_ACTIVE_UNKNOWN')
        with self._lock:
            self._consumed=True
            if self._error is not None or self._abandoned:
                self._result=None;raise LivePipeRefusal('LIVE_PIPE_RECEIVE_UNPROVEN')
            result=self._result;self._result=None
        _need(type(result) is tuple and len(result)==2,'RESULT');return result

    def abort_before_arm(self):
        with self._lock:
            if self.closed:return
            _need(not self._armed and not self._abandoned,'ABORT_PHASE')
            self._abandoned=True;self._queue.put_nowait(None)

    def wait_closed(self,timeout=5.0):
        _need(type(timeout) in (int,float) and math.isfinite(timeout) and 0<=timeout<=120,'WAIT_TIMEOUT')
        return self._exited.wait(timeout)
