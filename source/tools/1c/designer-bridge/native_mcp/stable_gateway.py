"""Stable eight-tool frontend routing to an explicitly published guardian.

No native owner is constructed here. Health never attaches; only explicit open
can select a new eligible publication. Data never rebinds/retries, and uncertainty
retains the old route. EOF closes only this frontend's relay connection.
"""
import asyncio
import hashlib
import inspect
import json
import math
import re
import time
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from . import guardian_wire as wire
from .resident_server import CLOSE_OWNED
from .saved_source import SavedRefusal, SourceBinding
from .server import (SavedServer, READ_ONLY, MAX_RESPONSE, Domain, Generation,
                     Identity, Flag, Offset, Count, Hash, Limit, Query, Method)

_PUBLICATION = frozenset(('publicationId', 'operationId', 'publicationSha256', 'validUntil', 'ownerPid', 'ownerBirth'))
_ENDPOINT = frozenset(('pipe_path', 'guardian_pid', 'guardian_birth', 'endpoint_id', 'capability'))
_BINDING = frozenset(('root_uuid', 'session_id', 'process_id', 'birth', 'generation', 'source_domain', 'valid_until'))
_DATA = wire.TOOLS - {'health', 'open_saved_session'}
BindingToken = Annotated[str, Field(strict=True, min_length=32, max_length=32, pattern=r'^[0-9a-f]{32}$')]
PUBLICATION_SHA = '9361cdce7f6fb74a5ff212510c68d6aa58999df72a42f6f7101502a3c83300cb'
CLIENT_SHA = 'a8b76c3a6c314c3bccbe07c9a56d90898d5bb01a9dd4f0839b219cd78e110ce9'


def _need(ok, code):
    if not ok: raise SavedRefusal('SAVED_STABLE_' + code)


def _hex(value, size):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None and value != '0'*size


def _resolve_active():
    # Import only on an explicit open or an already attached route check.
    _pin('active_publication.py', PUBLICATION_SHA)
    from .active_publication import resolve_active
    return resolve_active()


def _client(endpoint):
    _pin('guardian_client.py', CLIENT_SHA)
    from .guardian_client import GuardianRpcClient
    return GuardianRpcClient(endpoint)


def _pin(name, expected):
    _need(hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() == expected, 'DEPENDENCY_PIN')


class StableGateway:
    """Serialize route/check/RPC/close in the issuing event loop.

    Resolver and client_factory are trusted Python test seams, never tool args.
    A successful rebind requires a fresh eligible root publication and strictTrue
    old-relay closure; a failed/cancelled RPC seals the route until frontend EOF.
    No source result, frame or peer diagnostic is cached on this object.
    """
    def __init__(self, *, resolver=None, client_factory=None, clock=time.monotonic):
        resolver = _resolve_active if resolver is None else resolver
        client_factory = _client if client_factory is None else client_factory
        _need(all(callable(fn) and not inspect.iscoroutinefunction(fn) for fn in (resolver, client_factory, clock)), 'FACTORY')
        self._resolver = resolver; self._factory = client_factory; self._clock = clock
        self._loop = None; self._lock = asyncio.Lock()
        self._client = None; self._publication = None; self._token = None; self._last_token = None
        self._generation = 0; self._retired = False; self._unknown = False; self._closed = False

    def _enter(self):
        loop = asyncio.get_running_loop()
        _need(self._loop is None or self._loop is loop, 'EVENT_LOOP')
        self._loop = loop

    def _now(self):
        now = self._clock()
        _need(type(now) in (int, float) and math.isfinite(now) and now >= 0, 'CLOCK')
        return now

    def _health(self, status):
        return dict(status=status, generation=self._generation, source_domain='database_saved', binding_token=None,
                    binding_retired=self._retired, body_retained=False, source_read_performed=False,
                    transport_open_performed=False, native_binding_verified=False, writer_authorized=False,
                    native_install_performed=False)

    def _resolve(self):
        """Return detached public metadata plus owned secret dict, or inactive."""
        endpoint = None; failed = False; outcome = None
        try:
            value = self._resolver()
            if inspect.isawaitable(value):
                if inspect.iscoroutine(value): value.close()
                raise SavedRefusal('SAVED_STABLE_ASYNC_RESOLVER')
            if value is None: return None
            _need(type(value) is tuple and len(value) == 2, 'PUBLICATION')
            metadata, endpoint = value
            _need(type(metadata) is dict and metadata.keys() == _PUBLICATION
                  and all(_hex(metadata[k], n) for k, n in (('publicationId', 32), ('operationId', 32),
                                                            ('publicationSha256', 64), ('ownerBirth', 16)))
                  and type(metadata['validUntil']) is float and math.isfinite(metadata['validUntil'])
                  and type(metadata['ownerPid']) is int and 0 < metadata['ownerPid'] < 2**32, 'PUBLICATION')
            _need(type(endpoint) is dict and endpoint.keys() == _ENDPOINT
                  and type(endpoint['pipe_path']) is str and endpoint['pipe_path'].startswith('\\\\.\\pipe\\AH1C_GUARDIAN_')
                  and len(endpoint['pipe_path']) <= 256 and all(32 <= ord(c) <= 126 for c in endpoint['pipe_path'])
                  and type(endpoint['guardian_pid']) is int and endpoint['guardian_pid'] == metadata['ownerPid']
                  and type(endpoint['guardian_birth']) is str and endpoint['guardian_birth'] == metadata['ownerBirth']
                  and _hex(endpoint['endpoint_id'], 32)
                  and type(endpoint['capability']) is bytes and len(endpoint['capability']) == 32
                  and endpoint['capability'] != bytes(32), 'ENDPOINT')
            if metadata['validUntil'] > self._now(): outcome = (dict(metadata), endpoint)
        except Exception:
            failed = True
        if outcome is None and type(endpoint) is dict: endpoint.clear()
        if failed: raise SavedRefusal('SAVED_STABLE_PUBLICATION_UNPROVEN') from None
        return outcome

    def _current(self):
        resolved = self._resolve()
        if resolved is None: return False
        metadata, endpoint = resolved
        try: return metadata == self._publication
        finally: endpoint.clear()

    async def _rpc(self, name, arguments, token=None):
        result = None; failed = False
        try:
            result = await self._client.call(name, arguments, binding_token=token)
            _need(type(result) is dict, 'RESPONSE')
            wire._tree(result)
            _need(len(json.dumps(result, ensure_ascii=False, allow_nan=False).encode('utf-8')) <= MAX_RESPONSE, 'RESPONSE_BOUND')
            _need(result.get('native_install_performed', False) is False, 'INSTALL_CLAIM')
            result['native_install_performed'] = False
            if result.get('status') == 'UNKNOWN_RETAIN': self._unknown = True
        except asyncio.CancelledError:
            if type(result) is dict: result.clear()
            self._unknown = True
            raise
        except Exception:
            if type(result) is dict: result.clear()
            result = None; self._unknown = True; failed = True
        if failed: raise SavedRefusal('SAVED_STABLE_RPC_UNPROVEN') from None
        return result

    def _opened(self, result, *, same_publication):
        _need(result.get('status') == 'BINDING_OPEN' and _hex(result.get('binding_token'), 32)
              and result.get('binding_retired') is False and type(result.get('binding')) is dict
              and result['binding'].keys() == _BINDING, 'OPEN_RESPONSE')
        binding = SourceBinding(**result['binding']); binding.validate()
        _need(binding.source_domain == 'database_saved' and self._now() < binding.valid_until
              <= self._publication['validUntil'], 'OPEN_BINDING')
        token = result['binding_token']
        if same_publication:
            _need(self._token is None or token == self._token, 'TOKEN_CHANGED')
            _need(binding.generation >= self._generation, 'GENERATION_ROLLBACK')
        else:
            _need(self._last_token is None or token != self._last_token, 'TOKEN_REUSED')
        self._token = self._last_token = token
        self._generation = binding.generation; self._retired = False

    async def _open(self):
        try: resolved = self._resolve()
        except Exception:
            if self._client is not None: self._unknown = True
            raise
        _need(resolved is not None, 'DISCONNECTED')
        metadata, endpoint = resolved
        same = self._client is not None and metadata == self._publication
        result = None
        try:
            _need(not same or not self._retired, 'PUBLICATION_RETIRED')
            if not same:
                if self._client is not None:
                    # This only drains our relay. Root's publisher, not frontend,
                    # proves eligibility/closure of the predecessor installation.
                    try:
                        closed = await self._client.close()
                    except BaseException:
                        self._unknown = True
                        raise
                    if closed is not True:
                        self._unknown = True
                        raise SavedRefusal('SAVED_STABLE_RELAY_CLOSURE_UNPROVEN')
                    self._client = None; self._publication = None; self._token = None
                    self._generation = 0; self._retired = False
                _need(metadata['validUntil'] > self._now(), 'DISCONNECTED')
                candidate = self._factory(endpoint)
                if inspect.isawaitable(candidate):
                    if inspect.iscoroutine(candidate): candidate.close()
                    raise SavedRefusal('SAVED_STABLE_ASYNC_CLIENT_FACTORY')
                _need(all(callable(getattr(candidate, key, None)) and inspect.iscoroutinefunction(getattr(candidate, key))
                          for key in ('call', 'close')), 'CLIENT')
                self._client = candidate; self._publication = metadata
            endpoint.clear()
            result = await self._rpc('open_saved_session', dict(nocache=True))
            try: self._opened(result, same_publication=same)
            except Exception:
                result.clear(); result = None; self._unknown = True
                raise SavedRefusal('SAVED_STABLE_OPEN_UNPROVEN') from None
            return result
        finally:
            endpoint.clear()

    async def call(self, name, arguments, *, binding_token=None):
        """Forward one exact allowlisted request; no implicit route selection."""
        self._enter()
        valid = True
        try:
            wire.build_request(dict(kind='CALL', request_id=uuid4().hex, tool=name,
                                    args=arguments, binding_token=binding_token))
        except Exception: valid = False
        if not valid: raise SavedRefusal('SAVED_STABLE_REQUEST_REFUSED') from None
        async with self._lock:
            _need(not self._closed, 'FRONTEND_CLOSED')
            if self._unknown:
                if name == 'health': return self._health('UNKNOWN_RETAIN')
                raise SavedRefusal('SAVED_STABLE_UNKNOWN_RETAIN')
            if name == 'health' and self._client is None: return self._health('DISCONNECTED')
            if name == 'open_saved_session':
                failed = False
                try: opened = await self._open()
                except asyncio.CancelledError:
                    if self._client is not None: self._unknown = True
                    raise
                except Exception:
                    failed = True
                if failed: raise SavedRefusal('SAVED_STABLE_OPEN_REFUSED') from None
                return opened
            _need(self._client is not None, 'DISCONNECTED')
            if name in _DATA:
                _need(not self._retired and binding_token == self._token
                      and arguments['generation'] == self._generation, 'STALE_BINDING')
            failed = False
            try: current = self._current()
            except Exception:
                self._unknown = True; failed = True
            if failed: raise SavedRefusal('SAVED_STABLE_PUBLICATION_UNPROVEN') from None
            if not current:
                if name == 'health': return self._health('DISCONNECTED')
                raise SavedRefusal('SAVED_STABLE_PUBLICATION_CHANGED')
            if name == 'health' and self._retired: return self._health('CLOSED')
            result = await self._rpc(name, arguments, binding_token)
            if name == 'close_saved_session':
                if result.get('status') != 'CLOSED' or result.get('binding_retired') is not True:
                    result.clear(); self._unknown = True
                    raise SavedRefusal('SAVED_STABLE_CLOSE_UNPROVEN')
                self._retired = True; self._token = None
            return result

    async def close(self):
        """Drain only the frontend relay; never send a native close tool."""
        self._enter()
        async with self._lock:
            if self._closed: return True
            if self._client is not None:
                try: closed = await self._client.close()
                except asyncio.CancelledError:
                    self._unknown = True; raise
                except Exception: closed = False
                if closed is not True:
                    self._unknown = True; return False
            self._closed = True; self._token = None
            return True


def create_stable_guardian_server(gateway: StableGateway):
    """Always expose the same eight schemas, including while disconnected."""
    _need(type(gateway) is StableGateway, 'GATEWAY_TYPE')
    server = SavedServer('AH1C stable saved RAM gateway', version='1', log_level='WARNING',
        instructions='Health is safe while disconnected. Open explicitly attaches a root-published guardian. '
                     'Use its exact token/generation; reads never install, retry or switch native owners.')
    async def invoke(name, args, token=None):
        result = None; failed = False
        try:
            result = await gateway.call(name, args, binding_token=token)
        except Exception: failed = True
        if failed: raise ToolError('SAVED_REQUEST_REFUSED') from None
        return result

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def health(nocache: Flag=True) -> dict[str, Any]:
        """Inspect status without attaching an owner or opening a binding."""
        return await invoke('health', dict(nocache=nocache))

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def open_saved_session(nocache: Flag=True) -> dict[str, Any]:
        """Explicitly attach or renew the eligible root-published installation."""
        return await invoke('open_saved_session', dict(nocache=nocache))

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def observe_module(binding_token: BindingToken, source_domain: Domain, generation: Generation,
            object_uuid: Identity, property_uuid: Identity, nocache: Flag=True) -> dict[str, Any]:
        """Guard/read any authorized common module in the pinned installation."""
        return await invoke('observe_module', dict(source_domain=source_domain, generation=generation,
            object_uuid=object_uuid, property_uuid=property_uuid, nocache=nocache), binding_token)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def read_module_slice(binding_token: BindingToken, source_domain: Domain, generation: Generation,
            object_uuid: Identity, property_uuid: Identity, offset: Offset=0, count: Count=4096,
            expected_sha256: Hash|None=None, nocache: Flag=True) -> dict[str, Any]:
        """Return a verified bounded RAM slice without retaining its body."""
        return await invoke('read_module_slice', dict(source_domain=source_domain, generation=generation,
            object_uuid=object_uuid, property_uuid=property_uuid, offset=offset, count=count,
            expected_sha256=expected_sha256, nocache=nocache), binding_token)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def search_symbols(binding_token: BindingToken, source_domain: Domain, generation: Generation,
            query: Query='', include_stale: Flag=False, limit: Limit=25, offset: Offset=0,
            nocache: Flag=True) -> dict[str, Any]:
        """Search existing observed metadata; never attach or implicitly read."""
        return await invoke('search_symbols', dict(source_domain=source_domain, generation=generation,
            query=query, include_stale=include_stale, limit=limit, offset=offset, nocache=nocache), binding_token)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def get_context(binding_token: BindingToken, source_domain: Domain, generation: Generation,
            object_uuid: Identity, property_uuid: Identity, method_name: Method,
            include_stale: Flag=False, nocache: Flag=True) -> dict[str, Any]:
        """Return symbol context only for the current installation/generation."""
        return await invoke('get_context', dict(source_domain=source_domain, generation=generation,
            object_uuid=object_uuid, property_uuid=property_uuid, method_name=method_name,
            include_stale=include_stale, nocache=nocache), binding_token)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def refresh_observed(binding_token: BindingToken, source_domain: Domain, generation: Generation,
            nocache: Flag=True) -> dict[str, Any]:
        """Explicitly refresh observed modules without switching installations."""
        return await invoke('refresh_observed', dict(source_domain=source_domain, generation=generation,
            nocache=nocache), binding_token)

    @server.tool(annotations=CLOSE_OWNED, structured_output=True)
    async def close_saved_session(binding_token: BindingToken, source_domain: Domain, generation: Generation,
            nocache: Flag=True) -> dict[str, Any]:
        """Explicitly ask the current root to close this exact owned session."""
        return await invoke('close_saved_session', dict(source_domain=source_domain, generation=generation,
            nocache=nocache), binding_token)

    return server
