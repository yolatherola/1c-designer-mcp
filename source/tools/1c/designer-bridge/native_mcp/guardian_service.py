"""Reusable protected link service; never owns HostSlot shutdown authority.

All Windows handles belong to one dedicated thread. Only the injected HostSlot
is dispatched on its original asyncio loop; accepted calls are never cancelled,
retried or replaced because their frontend disconnects or stop times out.
"""
import asyncio
from concurrent.futures import Future
import hashlib
import math
from pathlib import Path
import threading

from . import guardian_wire as wire
from .host_slot import HostSlot

PIPE_SHA = 'c0c7a7a6a03e43d59fd29965a3b227ff337b212a577702cc5db2c76cca25e8b3'
WIRE_SHA = '3ca907c8f4df783cba01f63fb002e86c9cb2a262f504b785f50a9276c938a456'


class GuardianServiceRefusal(RuntimeError):
    """Stable lifecycle failure, without capabilities, source or peer errors."""


def _need(ok, code):
    if not ok:
        raise GuardianServiceRefusal('GUARDIAN_SERVICE_' + code)


def _timeout(value):
    _need(type(value) in (int, float) and math.isfinite(value) and .01 <= value <= 60, 'TIMEOUT')
    return float(value)


def _make_pipe(timeout):
    here = Path(__file__).resolve().parent
    _need(hashlib.sha256((here/'windows_guardian_pipe.py').read_bytes()).hexdigest() == PIPE_SHA
          and hashlib.sha256((here/'guardian_wire.py').read_bytes()).hexdigest() == WIRE_SHA, 'SOURCE_PIN')
    from .windows_guardian_pipe import GuardianPipeServer
    return GuardianPipeServer(timeout=timeout)


class GuardianService:
    """Single-use service around an exact, externally managed HostSlot.

    start returns confidential endpoint metadata in RAM after pipe creation.
    stop closes only this service/link, never slot.shutdown. False means the
    thread still owns a constructor, accepted call or draining Windows I/O;
    retain this instance and its asyncio loop, then stop again after completion.
    A true local stop proves no native/HostSlot closure by itself.
    """
    def __init__(self, slot, *, pipe_timeout=5.0, startup_timeout=5.0):
        _need(type(slot) is HostSlot, 'HOST_SLOT')
        self._slot = slot
        self._pipe_timeout = _timeout(pipe_timeout)
        self._startup_timeout = _timeout(startup_timeout)
        self._loop = self._thread = self._server = None
        self._ready = Future()
        self._stop = threading.Event()
        self._exited = threading.Event()
        self._idle = threading.Event()
        self._accepted = threading.Event()
        self._lock = threading.Lock()
        self._accepted_calls = 0
        self._connections = 0
        self._close_clean = False
        self._started = False

    @property
    def accepted_calls(self):
        with self._lock:
            return self._accepted_calls

    @property
    def state(self):
        if self._exited.is_set():
            return 'STOPPED' if self._close_clean else 'UNKNOWN_RETAIN'
        if self._stop.is_set():
            return 'STOPPING_RETAIN'
        return 'RUNNING' if self._started else 'NEW'

    def _enter_loop(self):
        loop = asyncio.get_running_loop()
        _need(self._loop is None or self._loop is loop, 'OWNER_LOOP')
        self._loop = loop
        _need(self._slot._loop is None or self._slot._loop is loop, 'HOST_LOOP')
        return loop

    async def start(self):
        """Create the protected endpoint on its owner; no native bootstrap."""
        self._enter_loop()
        _need(not self._started and not self._stop.is_set(), 'START_PHASE')
        self._started = True
        outcome = None
        try:
            self._thread = threading.Thread(target=self._owner, name='AH1C guardian pipe owner', daemon=True)
            try:
                self._thread.start()
            except Exception:
                # No Win32 handle or accepted job exists when the stdlib
                # thread could not start. Keep this single-use instance closed.
                if self._thread.ident is None:
                    self._thread = None
                    self._close_clean = True
                    self._exited.set()
                    self._ready.set_result((False, None))
                raise
            # Shield the producer Future: a cancelled/expired start must not
            # cause late constructor publication or foreign-thread handle close.
            outcome = await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(self._ready)), self._startup_timeout)
            _need(type(outcome) is tuple and outcome[0] is True and not self._stop.is_set()
                  and not self._exited.is_set(), 'START_UNPROVEN')
            return dict(outcome[1])
        except BaseException:
            self._signal_stop()
            # Do not preserve an exception traceback or its arbitrary contents.
            failed = True
        finally:
            outcome = None
        if failed:
            raise GuardianServiceRefusal('GUARDIAN_SERVICE_START_UNPROVEN')

    def _signal_stop(self):
        self._stop.set()
        server = self._server
        if server is not None:
            server.request_stop()  # Signal only; never touches a Win32 handle.

    async def stop(self, *, timeout=5.0):
        """Boundedly join local cleanup; never cancel an adopted HostSlot call."""
        self._enter_loop()
        timeout = _timeout(timeout)
        self._signal_stop()
        if self._thread is None:
            self._close_clean = True
            self._exited.set()
            return True
        try:
            await asyncio.to_thread(self._thread.join, timeout)
        except RuntimeError:
            # A non-Exception interruption of Thread.start can precede Python's
            # started/ident publication even when the OS thread was spawned.
            # Do not turn an unjoinable-yet thread into known closure.
            return False
        return not self._thread.is_alive() and self._exited.is_set() and self._close_clean

    def _connection(self):
        raw = request = coroutine = future = result = response = None
        try:
            while not self._stop.is_set():
                # No completed Future/result/raw source survives into this wait.
                self._idle.set()
                raw = self._server.receive_request()
                self._idle.clear()
                request = wire.parse_request(raw)
                if self._stop.is_set():
                    break
                unknown = False
                try:
                    coroutine = self._slot.call(request['tool'], request['args'],
                        binding_token=request['binding_token'])
                    try:
                        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
                    except BaseException:
                        # stdlib scheduling failure occurs before adoption by
                        # the loop. Close only this unsubmitted coroutine, never
                        # a returned Future or an accepted HostSlot operation.
                        coroutine.close()
                        raise
                    finally:
                        coroutine = None
                    with self._lock:
                        self._accepted_calls += 1
                    self._accepted.set()
                    # No deadline/cancellation here. A native call already
                    # accepted belongs to HostSlot even after its link dies.
                    result = future.result()
                    if self._stop.is_set():
                        break
                    response = wire.build_response(dict(kind='RESULT', request_id=request['request_id'],
                        ok=True, result=result, error=None), request_id=request['request_id'])
                except BaseException:
                    # Do not classify arbitrary exceptions by their text. Even
                    # a known local refusal is conservatively sealed on the link.
                    unknown = True
                    response = wire.build_response(dict(kind='RESULT', request_id=request['request_id'],
                        ok=False, result=None, error='UNKNOWN_RETAIN'), request_id=request['request_id'])
                finally:
                    result = future = None
                self._server.send_response(response)
                raw = request = response = None
                self._accepted.clear()
                if unknown:
                    break
        finally:
            raw = request = coroutine = future = result = response = None
            self._accepted.clear()
            self._idle.clear()

    def _owner(self):
        clean = False
        try:
            self._server = _make_pipe(self._pipe_timeout)
            if self._stop.is_set():
                return
            self._ready.set_result((True, self._server.endpoint))
            while not self._stop.is_set():
                try:
                    self._server.accept()
                except Exception:
                    if self._stop.is_set():
                        break
                    continue
                with self._lock:
                    self._connections += 1
                try:
                    self._connection()
                except Exception:
                    pass  # Fixed transport failure; native slot is unchanged.
                finally:
                    self._server.disconnect()
        except BaseException:
            pass  # Never publish raw constructor/transport/source exceptions.
        finally:
            try:
                if self._server is not None:
                    self._server.close()
                clean = True
            except BaseException:
                pass
            self._close_clean = clean
            if not self._ready.done():
                self._ready.set_result((False, None))
            else:
                # start returned an independent copy. Do not retain the RAM
                # capability through this completed constructor Future.
                outcome = self._ready.result()
                if outcome[0] is True:
                    outcome[1].clear()
                outcome = None
            self._exited.set()
