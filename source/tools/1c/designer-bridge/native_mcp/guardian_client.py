"""One async guardian link with an exclusive synchronous Windows I/O owner.

Local close releases only this relay connection. It never closes HostSlot,
native SDK ownership, the guardian process, or a Gold lease.
"""
import asyncio
from dataclasses import dataclass, field
import inspect
import queue
import re
import threading
from uuid import uuid4

from . import guardian_wire as wire


class GuardianRpcRefusal(RuntimeError):
    """Stable protocol/link refusal; contains no peer diagnostic or source."""


def _need(ok, code):
    if not ok:
        raise GuardianRpcRefusal('GUARDIAN_RPC_'+code)


def _physical(endpoint):
    # Import/construct/connect happen only on the dedicated handle owner.
    from .windows_guardian_pipe import GuardianPipeClient
    return GuardianPipeClient(endpoint)


@dataclass(slots=True)
class _Job:
    frame: bytes = field(repr=False)
    request_id: str
    future: object = field(repr=False)
    abandoned: bool = False
    outcome: object = field(default=None, repr=False)


def _drop(outcome):
    if type(outcome) is tuple and len(outcome) == 2 and type(outcome[1]) is dict:
        outcome[1].clear()


class GuardianRpcClient:
    """One explicit connection, one in-flight request, no retry or reconnect.

    endpoint and transport_factory are trusted root Python inputs, never tools.
    Cancelling a caller seals the link; its owner finishes/drains and discards
    the abandoned response before closing its own handles.
    """
    def __init__(self, endpoint, *, transport_factory=None):
        _need(type(endpoint) is dict and endpoint.keys() == {'pipe_path', 'guardian_pid',
            'guardian_birth', 'endpoint_id', 'capability'}, 'ENDPOINT')
        _need(type(endpoint['pipe_path']) is str and endpoint['pipe_path'].startswith(
            '\\\\.\\pipe\\AH1C_GUARDIAN_') and len(endpoint['pipe_path']) <= 256
            and all(32 <= ord(c) <= 126 for c in endpoint['pipe_path']), 'ENDPOINT')
        _need(type(endpoint['guardian_pid']) is int and 0 < endpoint['guardian_pid'] < 2**32,
              'ENDPOINT')
        for key, size in (('guardian_birth', 16), ('endpoint_id', 32)):
            _need(type(endpoint[key]) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',
                  endpoint[key]) is not None and endpoint[key] != '0'*size, 'ENDPOINT')
        _need(type(endpoint['capability']) is bytes and len(endpoint['capability']) == 32
              and endpoint['capability'] != bytes(32), 'ENDPOINT')
        _need(transport_factory is None or callable(transport_factory)
              and not inspect.iscoroutinefunction(transport_factory), 'FACTORY')
        self._endpoint = dict(endpoint)
        self._factory = _physical if transport_factory is None else transport_factory
        self._loop = None
        self._lock = threading.Lock()
        self._queue = queue.Queue(maxsize=1)
        self._thread = None
        self._busy = False
        self._sealed = False
        self._exited = threading.Event()
        self._close_clean = False

    def _enter_loop(self):
        loop = asyncio.get_running_loop()
        _need(self._loop is None or loop is self._loop, 'EVENT_LOOP')
        self._loop = loop
        return loop

    def _stop(self):
        self._sealed = True
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass  # Already admitted job is first; owner sees the seal afterward.

    def _deliver(self, job):
        with self._lock:
            outcome, job.outcome = job.outcome, None
            if job.abandoned:
                _drop(outcome)
                outcome = ('FAILED', None)
            if not job.future.done():
                job.future.set_result(outcome)
            else:
                _drop(outcome)

    def _finish(self, job, outcome):
        with self._lock:
            if job.abandoned:
                _drop(outcome)
                outcome = ('FAILED', None)
            job.outcome = outcome
            job.frame = b''
        try:
            self._loop.call_soon_threadsafe(self._deliver, job)
        except RuntimeError:
            with self._lock:
                _drop(job.outcome)
                job.outcome = None
                self._stop()

    def _owner(self):
        pipe = None
        job = raw = response = outcome = None
        try:
            while True:
                job = self._queue.get()
                if job is None:
                    break
                outcome = ('FAILED', None)
                raw = response = None
                try:
                    with self._lock:
                        abandoned = job.abandoned
                    if not abandoned:
                        if pipe is None:
                            pipe = self._factory(dict(self._endpoint))
                            pipe.connect()
                        raw = pipe.exchange(job.frame)
                        response = wire.parse_response(raw, request_id=job.request_id)
                        if response['ok']:
                            outcome = ('OK', response['result'])
                        else:
                            outcome = (response['error'], None)
                            if response['error'] == 'UNKNOWN_RETAIN':
                                with self._lock:
                                    self._stop()
                except BaseException:
                    with self._lock:
                        self._stop()
                finally:
                    # Retain no raw frame/exception. Source is returned only as
                    # the validated caller-owned result, never a diagnostic.
                    raw = response = None
                    self._finish(job, outcome)
                    outcome = None
                with self._lock:
                    stop = self._sealed
                # A completed Future can own a returned source slice. Never
                # retain the prior job in an idle worker's stack frame.
                job = None
                if stop:
                    break
        finally:
            job = raw = response = outcome = None
            clean = False
            try:
                if pipe is not None:
                    pipe.close()
                clean = True
            except BaseException:
                pass
            finally:
                with self._lock:
                    self._sealed = True
                    self._close_clean = clean
                    self._endpoint.clear()
                self._exited.set()

    async def call(self, tool, args, *, binding_token=None):
        """Validate one allowlisted call, then dispatch once to the guardian."""
        loop = self._enter_loop()
        valid = True
        try:
            request_id = uuid4().hex
            frame = wire.build_request(dict(kind='CALL', request_id=request_id,
                tool=tool, args=args, binding_token=binding_token))
        except Exception:
            valid = False
        if not valid:
            raise GuardianRpcRefusal('GUARDIAN_RPC_REQUEST_REFUSED')
        with self._lock:
            _need(not self._sealed, 'SEALED')
            _need(not self._busy, 'BUSY')
            job = _Job(frame, request_id, loop.create_future())
            self._busy = True
            if self._thread is None:
                self._thread = threading.Thread(target=self._owner,
                    name='AH1C guardian relay owner', daemon=True)
                try:
                    self._thread.start()
                except Exception:
                    self._busy = False
                    self._sealed = True
                    self._close_clean = True
                    self._endpoint.clear()
                    self._exited.set()
                    raise GuardianRpcRefusal('GUARDIAN_RPC_OWNER_START') from None
            self._queue.put_nowait(job)
        try:
            outcome = await asyncio.shield(job.future)
        except asyncio.CancelledError:
            with self._lock:
                job.abandoned = True
                _drop(job.outcome)
                job.outcome = None
                if job.future.done() and not job.future.cancelled():
                    _drop(job.future.result())
                self._stop()
            raise
        finally:
            with self._lock:
                self._busy = False
        status, result = outcome
        if status != 'OK':
            # Fixed wire enum only, or our local FAILED. No raw exception text.
            raise GuardianRpcRefusal('GUARDIAN_RPC_'+status)
        return result

    async def close(self):
        """Drain and close the relay on its owner; never shuts down guardian."""
        self._enter_loop()
        with self._lock:
            self._stop()
            if self._thread is None:
                self._endpoint.clear()
                self._close_clean = True
                self._exited.set()
        await asyncio.shield(asyncio.to_thread(self._exited.wait))
        return self._close_clean
