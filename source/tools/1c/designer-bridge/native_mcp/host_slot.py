"""One persistent MCP owner with replaceable, explicitly admitted native slots.

Publication is an in-process root operation, never an MCP tool. Each native
installation gets a new external token; broker generations remain unchanged.
The inner client's entire async context belongs to one actor task, including
its exit. Source responses exist only until the waiting caller receives them.
"""
import asyncio
import inspect
import json
import re
import secrets

from mcp import Client
from .resident_server import create_resident_server
from .saved_source import SavedRefusal
from .session_lifecycle import SessionBroker

TOOLS = frozenset(('health', 'open_saved_session', 'observe_module', 'read_module_slice',
                   'search_symbols', 'get_context', 'refresh_observed', 'close_saved_session'))
DATA_TOOLS = TOOLS - {'health', 'open_saved_session'}
MAX_RESPONSE_BYTES = 131072


def need(value, code):
    if not value:
        raise SavedRefusal('SAVED_HOST_' + code)


class HostSlot:
    """Serialize a root-published broker and retain uncertain native ownership.

    No method installs native code or opens another 1C process. The synchronous
    finalizer must prove the root controller's complete managed/native closure.
    It runs once, only after the broker's own verified shutdown succeeded.
    """
    def __init__(self):
        self._lock = asyncio.Lock()
        self._loop = None
        self._task = self._queue = self._pending = None
        self._broker = self._finalize = None
        self._token = None
        self._used_tokens = set()
        self._state = 'DISCONNECTED'
        self._finalize_attempted = False
        self._shutdown_attempted = False
        self._abandoned = False

    def _enter_loop(self):
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        need(self._loop is loop, 'OWNER_LOOP')

    def _idle(self):
        need(not self._lock.locked(), 'BUSY')
        need(self._pending is None or self._pending.done(), 'BUSY')

    def _health(self):
        return dict(status=self._state, binding_token=self._token, generation=0,
                    source_domain='database_saved', native_binding_verified=False,
                    writer_authorized=False, source_read_performed=False,
                    transport_open_performed=False, body_retained=False)

    def _discard_abandoned(self, future):
        if self._abandoned and not future.cancelled():
            # Drop any legitimately returned slice from an abandoned request.
            # Do not stringify errors or retain its result in a status record.
            value = future.result()
            if type(value) is dict:
                value.clear()

    async def _wait(self, future):
        self._pending = future
        self._abandoned = False
        future.add_done_callback(self._discard_abandoned)
        try:
            return await asyncio.shield(future)
        except asyncio.CancelledError:
            self._abandoned = True
            if self._state != 'CLOSED':
                self._state = 'UNKNOWN_RETAIN'
            if future.done():
                self._discard_abandoned(future)
            raise
        finally:
            if future.done():
                self._pending = None

    async def publish(self, broker, finalize):
        """Publish one new, admitted broker; returns its unique external token.

        The root owns native readiness and cleanup if publication cannot finish.
        An uncertain prior slot blocks publication, even when its token was never
        returned to a caller. No private generation counters are reset or seeded.
        """
        self._enter_loop(); self._idle()
        async with self._lock:
            need(self._state in ('DISCONNECTED', 'CLOSED')
                 and (self._task is None or self._task.done()), 'REPLACEMENT_UNPROVEN')
            need(type(broker) is SessionBroker and broker.state == 'UNOPENED', 'BROKER')
            need(callable(finalize) and not inspect.iscoroutinefunction(finalize), 'FINALIZER')
            need(len(self._used_tokens) < 4096, 'TOKEN_BUDGET')
            token = secrets.token_hex(16)
            need(type(token) is str and re.fullmatch('[0-9a-f]{32}', token) is not None and token != '0'*32
                 and token not in self._used_tokens, 'TOKEN')
            self._used_tokens.add(token)
            self._broker, self._finalize = broker, finalize
            self._token = token
            self._state = 'CONNECTING'
            self._finalize_attempted = self._shutdown_attempted = False
            self._queue = asyncio.Queue(maxsize=1)
            ready = asyncio.get_running_loop().create_future()
            self._task = asyncio.create_task(self._owner(ready))
            result = await self._wait(ready)
            need(result.get('ok') is True and self._state == 'CONNECTING', 'PUBLICATION_UNPROVEN')
            self._state = 'READY'
            return token

    def _finish_native(self):
        need(self._broker.state == 'CLOSED' and not self._finalize_attempted, 'CLOSURE_UNPROVEN')
        self._finalize_attempted = True
        value = self._finalize()
        if inspect.isawaitable(value):
            if inspect.iscoroutine(value):
                value.close()
            raise SavedRefusal('SAVED_HOST_ASYNC_FINALIZER')
        need(type(value) is bool and value is True, 'FINALIZER_UNPROVEN')

    async def _owner(self, ready):
        """Keep Client enter/calls/exit in this exact task (AnyIO requirement)."""
        job = None
        terminal = None
        response = None
        value = outcome = arguments = future = None
        try:
            async with Client(create_resident_server(self._broker), raise_exceptions=True) as client:
                ready.set_result(dict(ok=True))
                while True:
                    job = await self._queue.get()
                    kind, name, arguments, future = job
                    outcome = None
                    finish = False
                    try:
                        if kind == 'shutdown':
                            self._shutdown_attempted = True
                            need(self._broker.close() == 'CLOSED', 'BROKER_CLOSURE')
                            self._finish_native()
                            outcome = dict(ok=True, value=dict(status='CLOSED'))
                            finish = True
                        else:
                            response = await client.call_tool(name, arguments)
                            if response.is_error:
                                if self._broker.state == 'UNKNOWN_RETAIN':
                                    self._state = 'UNKNOWN_RETAIN'
                                outcome = dict(ok=False, error='TOOL_REFUSED')
                            else:
                                value = response.structured_content
                                need(type(value) is dict, 'RESPONSE')
                                need(len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8'))
                                     <= MAX_RESPONSE_BYTES, 'RESPONSE_BOUND')
                                if name == 'close_saved_session':
                                    self._shutdown_attempted = True
                                    self._finish_native()
                                    finish = True
                                outcome = dict(ok=True, value=value)
                    except Exception:
                        self._state = 'UNKNOWN_RETAIN'
                        outcome = dict(ok=False, error='OPERATION_UNPROVEN')
                    finally:
                        response = None
                        value = None
                    if finish:
                        # Do not acknowledge host closure until Client exits in
                        # its owner task as well as the physical root finalizer.
                        terminal = (future, outcome)
                        job = None
                        break
                    if not future.done():
                        future.set_result(outcome)
                    job = outcome = arguments = future = None
            self._state = 'CLOSED'
            self._token = None
            if terminal is not None and not terminal[0].done():
                terminal[0].set_result(terminal[1])
        except BaseException:
            # Never propagate raw inner errors (which can contain source text)
            # into a task exception, health record, or caller traceback.
            self._state = 'UNKNOWN_RETAIN'
            if not ready.done():
                ready.set_result(dict(ok=False))
            future = terminal[0] if terminal is not None else (job[3] if job is not None else None)
            if future is not None and not future.done():
                future.set_result(dict(ok=False, error='OWNER_UNPROVEN'))
        finally:
            response = value = outcome = arguments = future = job = terminal = None

    async def call(self, name, arguments, *, binding_token=None):
        """Forward an allowlisted call, holding its slot/token through completion."""
        self._enter_loop(); self._idle()
        async with self._lock:
            need(type(name) is str and name in TOOLS and type(arguments) is dict, 'TOOL')
            need(arguments.get('nocache') is True and type(arguments.get('nocache')) is bool
                 and 'binding_token' not in arguments, 'ARGUMENTS')
            if name == 'health' and self._state != 'READY':
                return self._health()
            need(self._state == 'READY' and self._task is not None and not self._task.done(), 'DISCONNECTED_OR_UNKNOWN')
            if name in DATA_TOOLS:
                need(type(binding_token) is str and binding_token == self._token, 'STALE_TOKEN')
            else:
                need(binding_token is None, 'TOKEN_ARGUMENT')
            token = self._token
            future = asyncio.get_running_loop().create_future()
            self._queue.put_nowait(('call', name, dict(arguments), future))
            result = await self._wait(future)
            need(result.get('ok') is True, result.get('error', 'OPERATION_UNPROVEN'))
            value = result.pop('value')
            result.clear()
            return dict(value, binding_token=token, binding_retired=self._state == 'CLOSED')

    async def shutdown(self):
        """Close the owned slot once, or retain uncertainty without replacement."""
        self._enter_loop()
        if self._lock.locked() or (self._pending is not None and not self._pending.done()):
            return False
        async with self._lock:
            if self._state in ('DISCONNECTED', 'CLOSED'):
                return True
            if self._shutdown_attempted or self._task is None or self._task.done():
                return False
            self._pending = None
            future = asyncio.get_running_loop().create_future()
            self._queue.put_nowait(('shutdown', None, None, future))
            result = await self._wait(future)
            return result.get('ok') is True and self._state == 'CLOSED'
