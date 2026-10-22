"""One protected pipe owner for many LIVE jobs; no reconnect or source files.

Only the installation owner supplies callbacks. PRE-ACK accepts a capture;
JOB_RELEASED accepts its closed job. CLOSE/EOF closes local handles, while the
installer must still join the native worker and managed host independently.
"""
from dataclasses import dataclass,field
import hashlib
import inspect
from pathlib import Path
import queue
import threading
import time
from uuid import uuid4

WIRE_SHA='28cbe004e96cc8e330e102d281d7fa3af185d77745d0f6c9bae7e166c969d104'
PRIMITIVE_SHA='6bc066d3860bd3cda9b657459979f08e83a985c8e488c7b616d819e767564c1c'
SOURCE_SHA='49d2b0aa1b5a97a8a36164a408fe898fd6d7ef99618e26af0909c21a70267773'
from . import resident_live_wire as wire
from . import windows_live_ram_pipe as primitive


class ResidentLivePipeRefusal(RuntimeError):
    """Fixed metadata-only refusal; no body, callback, or OS error reflection."""


def _need(ok,code):
    if not ok:raise ResidentLivePipeRefusal('RESIDENT_LIVE_PIPE_'+code)


def _duration(value,maximum):
    return wire.source._finite(value) and .001<=value<=maximum


def _sync(value):
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value):value.close()
        raise ResidentLivePipeRefusal('RESIDENT_LIVE_PIPE_ASYNC_VALIDATOR')
    return value


class _Pipe(primitive._Inbox):
    # Inherit only pinned protected ACL/process/OVL primitives, not its receive.
    def __init__(self,pid,birth):
        self._api=primitive.ready._DuplexApi();self._owner_thread=threading.get_ident()
        self._pid,self._birth=pid,birth;self._handle=self._process=None
        self._path='\\\\.\\pipe\\AH1C-LIVE-RESIDENT-'+uuid4().hex
        try:
            self._process=self._api.pin_process(pid,birth)
            self._handle=self._api.create(self._path)
        except BaseException:
            self.close();raise

    def identity(self):
        row=super().identity('0'*32)
        return {key:row[key] for key in ('pipePath','serverPid','serverBirth')}

    def connect_live(self,context,deadline,abandoned):
        ov=self._api.w.ConnectNamedPipe(self._handle,overlapped=True)
        _,error=self._complete(ov,deadline);_need(error==0,'CONNECT')
        self._live();_need(not abandoned(),'ABANDONED')
        raw=self._read_exact(wire.READY_BYTES,deadline);self._live()
        _need(not abandoned(),'ABANDONED')
        return wire.parse_ready(raw,context=context,now=time.monotonic())

    def exchange_live(self,command_raw,command,binding,previous,validator,deadline,abandoned):
        capture=None;accepted=False;ack_sha=None
        args=dict(binding=binding,command=command,previous_sequence=previous)
        try:
            self._live();_need(not abandoned(),'ABANDONED')
            self._write_exact(command_raw,deadline)
            header=self._read_exact(wire.HEADER_BYTES,deadline)
            sizes=wire.parse_response_header(header,command=command)
            raw=header+self._read_exact(sizes.metadata_length+sizes.body_length,deadline)
            self._live();_need(not abandoned(),'ABANDONED')
            if command.opcode==wire.CLOSE:
                row=wire.parse_close_frame(raw,now=time.monotonic(),**args);raw=None
                ack_sha=wire.EMPTY_SHA256
                returned=_sync(validator(dict(row)))
                _need(type(returned) is dict and returned==row,'CLOSE_VALIDATOR')
                wire.build_close_frame(returned,now=time.monotonic(),**args)
                # Reparse after the callback: it may consume cleanup grace.
                wire.build_command(command,binding=binding,now=time.monotonic(),previous_sequence=previous)
                self._live();_need(not abandoned(),'ABANDONED')
                self._write_exact(wire.build_ack(command,wire.EMPTY_SHA256,accepted=True),deadline)
                accepted=True
                _need(not self._read(1,deadline),'TRAILING_CLOSE');self._live()
                _need(not abandoned(),'ABANDONED')
                return row
            capture=wire.parse_capture_frame(raw,now=time.monotonic(),**args);raw=None
            ack_sha=capture.receipt.source_sha256
            receipt=_sync(validator(capture,capture.request))
            wire.validate_receipt(capture,receipt,now=time.monotonic(),**args);receipt=None
            self._live();_need(not abandoned() and time.monotonic()<=deadline,'ABANDONED')
            self._write_exact(wire.build_ack(command,capture.receipt.source_sha256,accepted=True),deadline)
            accepted=True
            released=wire.parse_release(self._read_exact(wire.RELEASE_BYTES,deadline),
                capture=capture,now=time.monotonic(),**args)
            self._live();_need(not abandoned(),'ABANDONED')
            snapshot=wire.finish_capture(capture,released,now=time.monotonic(),**args)
            return snapshot,capture.request
        except BaseException:
            if not accepted and ack_sha is not None:
                try:self._write_exact(wire.build_ack(command,ack_sha,accepted=False),deadline)
                except BaseException:pass
            raise
        finally:
            capture=None


@dataclass(slots=True)
class _Job:
    kind:str
    raw:bytes|None=field(default=None,repr=False)
    validator:object=None
    done:threading.Event=field(default_factory=threading.Event,repr=False)
    result:object=field(default=None,repr=False)
    error:str|None=None
    abandoned:bool=False


class ResidentLiveChannel:
    """Reserve before stage; connect after RootRun; serialize READ and CLOSE.

    All handles belong to one dedicated thread. A caller timeout seals access;
    it does not close another thread's I/O or authorize another native attempt.
    """
    def __init__(self,expected_client_pid,*,expected_birth,context,timeout=60.0,wait_timeout=75.0):
        for module,pin in ((wire,WIRE_SHA),(primitive,PRIMITIVE_SHA),(wire.source,SOURCE_SHA)):
            _need(hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()==pin,'DEPENDENCY_PIN')
        _need(type(context) is wire.ResidentLiveContext,'CONTEXT');context.validate()
        _need(type(expected_client_pid) is int and expected_client_pid==context.process_id
              and type(expected_birth) is str and expected_birth==context.birth,'PEER_CONTEXT')
        _need(_duration(timeout,90) and _duration(wait_timeout,120),'TIMEOUT')
        self._context=context;self._timeout=float(timeout);self._wait_timeout=float(wait_timeout)
        self._lock=threading.Lock();self._queue=queue.Queue(maxsize=1)
        self._ready=threading.Event();self._exited=threading.Event();self._stop=threading.Event()
        self._identity=None;self._binding=None;self._last_sequence=0;self._nonces=set()
        self._busy=False;self._sealed=False;self._connect_submitted=False;self._handles_closed=False;self._startup_error=False
        self._thread=threading.Thread(target=self._owner,args=(expected_client_pid,expected_birth),
            name='AH1C resident LIVE pipe owner',daemon=True)
        try:
            self._thread.start()
            _need(self._ready.wait(5),'RESERVE_UNKNOWN')
            _need(self._identity is not None and not self._startup_error,'RESERVE')
        except BaseException:
            with self._lock:
                self._sealed=True;self._stop.set()
                try:self._queue.put_nowait(None)
                except queue.Full:pass
            raise

    @property
    def identity(self):return dict(self._identity)
    @property
    def path(self):return self._identity['pipePath']
    @property
    def sealed(self):
        with self._lock:return self._sealed
    @property
    def closed(self):return self._exited.is_set() and self._handles_closed
    @property
    def owner_thread_alive(self):return self._thread.is_alive()
    @property
    def last_sequence(self):
        with self._lock:return self._last_sequence

    def _abandoned(self,job):
        with self._lock:return job.abandoned or self._stop.is_set()

    def _abandon(self,job):
        with self._lock:
            job.abandoned=True;job.result=None;self._sealed=True;self._stop.set()
            # Also wake an owner that already delivered and returned to idle.
            # All I/O cancellation, drain and handle close remain on that owner.
            try:self._queue.put_nowait(None)
            except queue.Full:pass

    def _submit(self,job):
        queued=False
        try:
            with self._lock:
                _need(not self._sealed and not self._exited.is_set(),'SEALED')
                _need(not self._busy,'BUSY')
                if job.kind=='connect':
                    _need(not self._connect_submitted,'CONNECT_PHASE')
                    queued=True;self._connect_submitted=True
                else:
                    _need(self._binding is not None,'CONNECT_REQUIRED')
                    try:
                        command=wire.parse_command(job.raw,binding=self._binding,now=time.monotonic(),previous_sequence=self._last_sequence)
                    except Exception:raise ResidentLivePipeRefusal('RESIDENT_LIVE_PIPE_COMMAND') from None
                    _need(command.opcode==(wire.READ if job.kind=='read' else wire.CLOSE),'OPCODE')
                    _need(command.request_id not in self._nonces,'NONCE_REPLAY')
                queued=True;self._busy=True;self._queue.put_nowait(job)
            if not job.done.wait(self._wait_timeout):
                with self._lock:
                    _need(job.done.is_set(),'ACTIVE_UNKNOWN')
            if job.error is not None:raise ResidentLivePipeRefusal(job.error)
            with self._lock:result=job.result;job.result=None
            return result
        except BaseException:
            if queued:self._abandon(job)
            raise

    def connect(self):return self._submit(_Job('connect'))

    def read(self,command,validator):
        _need(type(command) is bytes and len(command)==wire.COMMAND_BYTES,'COMMAND')
        _need(callable(validator) and not inspect.iscoroutinefunction(validator),'VALIDATOR')
        return self._submit(_Job('read',command,validator))

    def close(self,command,validator):
        _need(type(command) is bytes and len(command)==wire.COMMAND_BYTES,'COMMAND')
        _need(callable(validator) and not inspect.iscoroutinefunction(validator),'VALIDATOR')
        result=self._submit(_Job('close',command,validator))
        _need(self.wait_closed(5) and self.closed,'LOCAL_CLOSE')
        return result

    def abort_before_connect(self):
        with self._lock:
            _need(not self._connect_submitted and not self._busy and not self._sealed,'ABORT_PHASE')
            self._sealed=True;self._stop.set();self._queue.put_nowait(None)

    def wait_closed(self,timeout=5.0):
        _need(wire.source._finite(timeout) and 0<=timeout<=120,'WAIT_TIMEOUT')
        _need(threading.get_ident()!=self._thread.ident,'OWNER_WAIT')
        return self._exited.wait(timeout)

    def _owner(self,pid,birth):
        pipe=None;job=None;result=None
        try:
            try:
                pipe=_Pipe(pid,birth)
                with self._lock:self._identity=pipe.identity()
            except BaseException:
                with self._lock:self._startup_error=True;self._sealed=True
                return
            finally:self._ready.set()
            while not self._stop.is_set():
                job=self._queue.get()
                if job is None:return
                terminal=False;result=None;error=None
                try:
                    _need(not self._abandoned(job),'ABANDONED')
                    deadline=time.monotonic()+self._timeout
                    if job.kind=='connect':
                        result=pipe.connect_live(self._context,deadline,lambda:self._abandoned(job))
                        _need(not self._abandoned(job),'ABANDONED')
                        with self._lock:self._binding=result
                    else:
                        command=wire.parse_command(job.raw,binding=self._binding,now=time.monotonic(),previous_sequence=self._last_sequence)
                        result=pipe.exchange_live(job.raw,command,self._binding,self._last_sequence,
                            job.validator,deadline,lambda:self._abandoned(job))
                        _need(not self._abandoned(job),'ABANDONED')
                        with self._lock:
                            self._nonces.add(command.request_id)
                            if job.kind=='read':self._last_sequence=command.sequence
                        terminal=job.kind=='close'
                except BaseException:
                    terminal=True;error='RESIDENT_LIVE_PIPE_TRANSACTION_UNPROVEN';result=None
                if terminal:
                    try:pipe.close();self._handles_closed=True
                    except BaseException:error='RESIDENT_LIVE_PIPE_LOCAL_CLOSE_UNPROVEN';result=None
                with self._lock:
                    terminal=terminal or job.abandoned or self._stop.is_set()
                    if terminal:self._sealed=True
                    job.result=None if job.abandoned or error else result
                    job.error='RESIDENT_LIVE_PIPE_ACTIVE_UNKNOWN' if job.abandoned else error
                    job.raw=None;job.validator=None;self._busy=False;job.done.set()
                job=None;result=None
                if terminal:return
        finally:
            result=None
            if pipe is not None:
                try:pipe.close();self._handles_closed=True
                except BaseException:self._handles_closed=False
            with self._lock:self._sealed=True
            self._ready.set();self._exited.set()
