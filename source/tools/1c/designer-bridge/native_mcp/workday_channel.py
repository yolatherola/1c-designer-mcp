"""v234 synchronous workday transport with one exclusive Windows handle owner.

Only a trusted host supplies validators. A validator returns a validated result
or raises; it is never a client tool argument. Local closure does not attest to
native SDK cleanup. Caller timeout seals the endpoint and does not abort an
already dispatched native command; its owner closes after I/O/validation returns.
"""
from dataclasses import dataclass,field
import hashlib
import inspect
import math
from pathlib import Path
import queue
import struct
import threading

from . import workday_pipe as transport

PIPE_SHA256='0d86fdc34b932c7a87b6286597308a44097447b3122a48be29966b7c3a2fe42f'
_PIPE_CLASS=transport.WorkdayResidentPipe


class ResidentChannelRefusal(RuntimeError):
    """Stable metadata-only channel refusal; no source or exception reflection."""


def _need(ok,code):
    if not ok:raise ResidentChannelRefusal('RESIDENT_CHANNEL_'+code)


@dataclass(slots=True)
class _Job:
    kind:str
    command:bytes|None=field(default=None,repr=False)
    validator:object=field(default=None,repr=False)
    done:threading.Event=field(default_factory=threading.Event,repr=False)
    result:object=field(default=None,repr=False)
    error:str|None=None
    abandoned:bool=False


class WorkdayResidentChannel:
    """One pipe and owner thread, no reconnect, retries, or queued waiters.

    Construct to publish ``path``, launch the managed peer, then call connect.
    wait_timeout bounds the calling thread's wait, not native execution lifetime.
    A timed-out owner may still be alive while draining its own Windows I/O.
    """
    def __init__(self,expected_client_pid,*,install_nonce,expected_birth,timeout=5.0,wait_timeout=None):
        _need(hashlib.sha256(Path(transport.__file__).read_bytes()).hexdigest()==PIPE_SHA256,'PIPE_PIN')
        _need(type(timeout) in (int,float) and math.isfinite(timeout) and .01<=timeout<=30,'TIMEOUT')
        wait_timeout=timeout+1 if wait_timeout is None else wait_timeout
        _need(type(wait_timeout) in (int,float) and math.isfinite(wait_timeout) and .01<=wait_timeout<=60,'WAIT_TIMEOUT')
        self._wait_timeout=float(wait_timeout)
        self._lock=threading.Lock()
        self._queue=queue.Queue(maxsize=1)
        self._ready=threading.Event()
        self._exited=threading.Event()
        self._stop=threading.Event()
        self._busy=False
        self._sealed=False
        self._connected=False
        self._connect_submitted=False
        self._path=None
        self._startup_error=None
        self._thread=threading.Thread(target=self._owner,args=(expected_client_pid,install_nonce,expected_birth,timeout),
                                      name='AH1C workday channel owner',daemon=True)
        self._thread.start()
        if not self._ready.wait(self._wait_timeout):
            with self._lock:
                self._sealed=True;self._stop.set()
                # Also wake an owner that passed its startup stop check just
                # before the waiting constructor reached its deadline.
                self._queue.put_nowait(None)
            raise ResidentChannelRefusal('RESIDENT_CHANNEL_STARTUP_UNKNOWN')
        if self._startup_error is not None:raise ResidentChannelRefusal(self._startup_error)
        _need(self._path is not None and not self._sealed,'STARTUP_UNKNOWN')

    @property
    def path(self):return self._path

    @property
    def sealed(self):
        with self._lock:return self._sealed

    @property
    def closed(self):return self._exited.is_set()

    @property
    def owner_thread_alive(self):return self._thread.is_alive()

    def wait_closed(self,timeout=5.0):
        """Observe local owner exit only; never closes handles on this thread."""
        _need(type(timeout) in (int,float) and math.isfinite(timeout) and 0<=timeout<=60,'WAIT_TIMEOUT')
        _need(threading.get_ident()!=self._thread.ident,'OWNER_WAIT')
        return self._exited.wait(timeout)

    def _submit(self,job):
        with self._lock:
            _need(not self._sealed and not self._exited.is_set(),'SEALED')
            _need(not self._busy,'BUSY')
            if job.kind=='connect':
                _need(not self._connect_submitted,'CONNECT_PHASE');self._connect_submitted=True
            else:_need(self._connected,'CONNECT_REQUIRED')
            self._busy=True
            self._queue.put_nowait(job)
        if not job.done.wait(self._wait_timeout):
            with self._lock:
                # A completed operation at the timeout boundary remains known.
                if not job.done.is_set():
                    job.abandoned=True;self._sealed=True;self._stop.set()
                    raise ResidentChannelRefusal('RESIDENT_CHANNEL_ACTIVE_UNKNOWN')
        if job.error is not None:raise ResidentChannelRefusal(job.error)
        result=job.result;job.result=None
        return result

    def connect(self):
        """Queue authentication after the peer has been launched; no host wait."""
        return self._submit(_Job('connect'))

    def exchange(self,command,validator):
        """Validate on owner, then explicitly ACK once; never caches source."""
        _need(type(command) is bytes and len(command)==160,'COMMAND')
        _need(callable(validator) and not inspect.iscoroutinefunction(validator),'VALIDATOR')
        return self._submit(_Job('exchange',command,validator))

    def abort_before_connect(self):
        """Dispose an unused endpoint, only before connect was submitted."""
        with self._lock:
            _need(not self._sealed and not self._connect_submitted and not self._busy
                  and not self._exited.is_set(),'ABORT_PHASE')
            self._sealed=True;self._stop.set();self._queue.put_nowait(None)

    def _abandoned(self,job):
        with self._lock:return job.abandoned or self._stop.is_set()

    def _work(self,pipe,job):
        if self._abandoned(job):return True,None,'RESIDENT_CHANNEL_ACTIVE_UNKNOWN'
        if job.kind=='connect':
            pipe.connect()
            if self._abandoned(job):return True,None,'RESIDENT_CHANNEL_ACTIVE_UNKNOWN'
            with self._lock:self._connected=True
            return False,None,None
        raw=pipe.exchange(job.command)
        if self._abandoned(job):return True,None,'RESIDENT_CHANNEL_ACTIVE_UNKNOWN'
        try:result=job.validator(raw)
        except BaseException:return True,None,'RESIDENT_CHANNEL_VALIDATION'
        if inspect.isawaitable(result):
            # Validation must finish synchronously before ACK. Dispose only an
            # actual coroutine created by our trusted callback; never execute
            # arbitrary awaitable protocols or schedule work on the owner.
            if inspect.iscoroutine(result):
                try:result.close()
                except BaseException:pass
            return True,None,'RESIDENT_CHANNEL_VALIDATION'
        if self._abandoned(job):return True,None,'RESIDENT_CHANNEL_ACTIVE_UNKNOWN'
        _,_,opcode,status,_,_,_=struct.unpack('<8sIIIIII',raw[:32])
        # UNKNOWN cannot be promoted to ACK0 by a permissive callback.
        if status==2 or (opcode==5 and status!=4):
            return True,None,'RESIDENT_CHANNEL_REMOTE_UNKNOWN'
        pipe.acknowledge(True)
        if opcode==5 and status==4:
            pipe.confirm_peer_closed()
            return True,result,None
        return False,result,None

    def _owner(self,pid,nonce,birth,timeout):
        pipe=None
        try:
            try:
                pipe=_PIPE_CLASS(pid,install_nonce=nonce,expected_birth=birth,timeout=timeout)
                with self._lock:
                    if not self._stop.is_set():self._path=pipe.path
            except BaseException:
                with self._lock:self._startup_error='RESIDENT_CHANNEL_STARTUP';self._sealed=True
                return
            finally:self._ready.set()
            if self._stop.is_set():return
            while True:
                job=self._queue.get()
                if job is None:return
                terminal=False;result=None;error=None
                try:terminal,result,error=self._work(pipe,job)
                except BaseException:terminal=True;error='RESIDENT_CHANNEL_IO_UNKNOWN'
                if terminal:
                    # Only owner can touch the pending ACK and local handles.
                    if pipe._pending is not None and not pipe._poisoned and not pipe.closed:
                        try:pipe.acknowledge(False)
                        except BaseException:pass
                    try:pipe.close()
                    except BaseException:error='RESIDENT_CHANNEL_LOCAL_CLOSE_UNKNOWN'
                with self._lock:
                    terminal=terminal or job.abandoned or self._stop.is_set()
                    if terminal:self._sealed=True
                    job.result=None if job.abandoned else result
                    job.error='RESIDENT_CHANNEL_ACTIVE_UNKNOWN' if job.abandoned else error
                    job.command=None;job.validator=None
                    self._busy=False;job.done.set()
                job=None;result=None
                if terminal:return
        finally:
            if pipe is not None:
                try:pipe.close()
                except BaseException:pass
            with self._lock:self._sealed=True
            self._ready.set();self._exited.set()
