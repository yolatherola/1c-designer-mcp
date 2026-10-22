"""Stable LIVE MCP frontend: explicit attachment, RAM captures, no installer."""
import asyncio
import hashlib
import json
from pathlib import Path
import secrets
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError
from . import live_guardian_wire as wire
from .resident_live_server import (ResidentLiveServer, Capture, Identity, Domain,
    Flag, Offset, Count, Limit, Page, Hash, Query, Method, READ_ONLY)

SERVER_SHA = 'e52f53211b8fd8a0d8f7d878658e814cb9e445edf6894676a43ef2ad27237395'
if hashlib.sha256(Path(__file__).with_name('resident_live_server.py').read_bytes()).hexdigest() != SERVER_SHA:
    raise ValueError('LIVE_GATEWAY_SERVER_SOURCE_PIN')


class LiveGatewayRefusal(ValueError):
    """Fixed failure code, never source, capabilities or native diagnostics."""


def _need(ok, code):
    if not ok: raise LiveGatewayRefusal('LIVE_GATEWAY_' + code)


def _resolve():
    from .live_publication import resolve_active
    return resolve_active()


def _current(metadata):
    from .live_publication import current_publication
    return current_publication(metadata)


def _client(endpoint):
    from .live_guardian_transport import LiveRpcClient
    return LiveRpcClient(endpoint)


def _metadata(row):
    _need(type(row) is dict and row.keys() == {'publicationId', 'operationId',
        'publicationSha256', 'validUntil', 'ownerPid', 'ownerBirth', 'sourceDomain'}, 'PUBLICATION')
    _need(wire._token(row['publicationId']) and wire._token(row['operationId'])
        and wire._hex(row['publicationSha256'], 64) and wire._hex(row['ownerBirth'], 16)
        and type(row['ownerPid']) is int and 0 < row['ownerPid'] < 2**32
        and type(row['validUntil']) is float and 0 < row['validUntil'] < float('inf')
        and row['sourceDomain'] == 'editor_live_at_capture', 'PUBLICATION')
    return dict(row)


class LiveGateway:
    """One frontend relay, attached only by explicit open_live_session.

    Trusted Python dependencies are for Root/tests only, never MCP arguments.
    Changing publication requires another explicit open and proven relay drain.
    Data calls never select an owner, retry a read or fall back to saved code.
    """
    def __init__(self, *, resolver=None, current=None, client_factory=None):
        self._resolver = _resolve if resolver is None else resolver
        self._current = _current if current is None else current
        self._factory = _client if client_factory is None else client_factory
        _need(all(callable(x) for x in (self._resolver, self._current, self._factory)), 'DEPENDENCY')
        self._client = self._publication = self._token = None
        self._last_token = None
        self._loop = None
        self._lock = asyncio.Lock()
        self._unknown = self._retired = self._closed = False

    def __repr__(self): return '<LiveGateway binding=privateRAM>'

    def _enter_loop(self):
        loop = asyncio.get_running_loop()
        _need(self._loop is None or self._loop is loop, 'OWNER_LOOP')
        self._loop = loop

    def _health(self):
        status = 'CLOSED' if self._retired else 'UNKNOWN_RETAIN' if self._unknown else 'DISCONNECTED'
        return dict(status=status, source_domain='editor_live_at_capture',
            attached=self._client is not None, native_connection_closed=self._retired,
            writer_authorized=False, source_body_included=False, retry_authorized=False)

    def _validate(self, tool, args):
        token = None if tool in ('health', 'open_live_session') else self._token or '1' * 32
        wire.build_request(dict(kind='CALL', request_id='1' * 32, tool=tool, args=args, binding_token=token))

    async def _attach(self):
        selection = self._resolver()
        _need(type(selection) is tuple and len(selection) == 2, 'DISCONNECTED')
        metadata, endpoint = selection
        try:
            metadata = _metadata(metadata)
            _need(type(endpoint) is dict, 'ENDPOINT')
            if self._publication == metadata and self._client is not None:
                return
            _need(not self._unknown and not self._retired, 'RETAIN')
            if self._client is not None:
                _need(await self._client.close() is True, 'RELAY_CLOSURE')
                self._client = None
                self._last_token = self._token
                self._token = self._publication = None
            self._client = self._factory(endpoint)
            _need(self._client is not None, 'CLIENT')
            self._publication = metadata
        finally:
            if type(endpoint) is dict: endpoint.clear()
            selection = endpoint = None

    def _reply(self, tool, row):
        _need(type(row) is dict, 'RESULT')
        if row.get('status') == 'LIVE_REQUEST_REFUSED':
            if row.get('connection_status') == 'UNKNOWN_RETAIN': self._unknown = True
            raise LiveGatewayRefusal('LIVE_GATEWAY_REQUEST_REFUSED')
        _need(len(json.dumps(row, ensure_ascii=False, allow_nan=False).encode('utf8'))
            <= wire.MAX_RESPONSE_BYTES, 'RESULT_SIZE')
        if 'source_domain' in row:
            _need(row['source_domain'] == 'editor_live_at_capture', 'RESULT_DOMAIN')
        if 'operation_id' in row:
            _need(row['operation_id'] == self._publication['operationId'], 'RESULT_OPERATION')
        if tool == 'open_live_session':
            token = row.get('binding_token')
            _need(wire._token(token) and wire._token(row.get('capture_id'))
                and row.get('source_domain') == 'editor_live_at_capture'
                and row.get('operation_id') == self._publication['operationId'], 'OPEN_RESULT')
            _need(self._token is None or secrets.compare_digest(self._token, token), 'TOKEN_CHANGED')
            _need(self._last_token is None or not secrets.compare_digest(self._last_token, token), 'TOKEN_REUSED')
            self._token = token
        elif tool != 'health':
            _need(type(row.get('binding_token')) is str and self._token is not None
                and secrets.compare_digest(row['binding_token'], self._token), 'RESULT_BINDING')
        if tool == 'close_live_connection':
            _need(row.get('status') == 'LIVE_RESIDENT_RESOURCES_CLOSED'
                and row.get('knownTerminal') is True and row.get('resourcesClosed') is True
                and row.get('native_connection_closed') is True
                and row.get('workerResult') == 0 and type(row.get('workerResult')) is int
                and row.get('hostExitCode') == 0 and type(row.get('hostExitCode')) is int
                and row.get('binding_retired') is True, 'NATIVE_CLOSURE')
            self._retired = True
        if row.get('status') == 'UNKNOWN_RETAIN': self._unknown = True
        # Root token is relay authority, not part of an agent's capture handle.
        return {k: v for k, v in row.items() if k != 'binding_token'}

    async def call(self, tool, args):
        """Dispatch one validated call; only explicit open resolves a new owner."""
        self._enter_loop()
        async with self._lock:
            _need(not self._closed, 'FRONTEND_CLOSED')
            self._validate(tool, args)
            if tool == 'health' and (self._client is None or self._unknown or self._retired):
                return self._health()
            _need(not self._unknown and not self._retired, 'RETAIN')
            try:
                if tool == 'open_live_session': await self._attach()
                _need(self._client is not None and self._publication is not None, 'DISCONNECTED')
                _need(self._current(self._publication) is True, 'STALE_PUBLICATION')
                if tool not in ('health', 'open_live_session'):
                    _need(self._token is not None, 'OPEN_REQUIRED')
                token = None if tool in ('health', 'open_live_session') else self._token
                row = await self._client.call(tool, args, binding_token=token)
                try:
                    result = self._reply(tool, row)
                except LiveGatewayRefusal:
                    if type(row) is not dict or row.get('status') != 'LIVE_REQUEST_REFUSED': self._unknown = True
                    raise
                finally:
                    row = None
                return result
            except asyncio.CancelledError:
                self._unknown = True
                raise
            except LiveGatewayRefusal:
                raise
            except Exception:
                self._unknown = True
                raise LiveGatewayRefusal('LIVE_GATEWAY_UNKNOWN_RETAIN') from None

    async def close(self):
        """Drain this relay only. EOF never sends close_live_connection."""
        self._enter_loop()
        async with self._lock:
            self._closed = True
            if self._client is None: return True
            try: clean = await self._client.close()
            except Exception: clean = False
            if clean is not True:
                self._unknown = True
                return False
            self._client = self._publication = self._token = self._last_token = None
            return True


def create_live_guardian_server(gateway):
    """Expose resident capture tools and local syntax analysis through LIVE."""
    _need(type(gateway) is LiveGateway, 'TYPE')
    server = ResidentLiveServer('AH1C LIVE editor gateway', version='1', log_level='WARNING',
        instructions='Explicit attach to an existing Root-published LIVE owner. CommonModule captures '
        'are RAM snapshots and may be dirty or readonly. No saved fallback, writes, native install '
        'or automatic EOF shutdown. Use nocache=true; refresh explicitly for a fresh capture.')

    async def invoke(tool, args):
        try: return await gateway.call(tool, args)
        except Exception: raise ToolError('LIVE_GATEWAY_REQUEST_REFUSED') from None

    @server.tool(annotations=READ_ONLY)
    async def health(nocache:Flag=True)->dict[str,Any]:
        """Connection metadata only; never attach or reread native source."""
        return await invoke('health', dict(nocache=nocache))

    @server.tool(annotations=READ_ONLY)
    async def open_live_session(object_uuid:Identity,source_domain:Domain,nocache:Flag=True)->dict[str,Any]:
        """Explicitly attach and capture one CommonModule from the LIVE owner."""
        return await invoke('open_live_session', dict(object_uuid=object_uuid,source_domain=source_domain,nocache=nocache))

    @server.tool(annotations=READ_ONLY)
    async def refresh_observed(capture_id:Capture,source_domain:Domain,nocache:Flag=True)->dict[str,Any]:
        """Refresh this capture and retire its previous index and handle."""
        return await invoke('refresh_observed',dict(capture_id=capture_id,source_domain=source_domain,nocache=nocache))

    @server.tool(annotations=READ_ONLY)
    async def observe_module(capture_id:Capture,source_domain:Domain,object_uuid:Identity,
                             property_uuid:Identity,nocache:Flag=True)->dict[str,Any]:
        """Read capture metadata, without another native source read."""
        return await invoke('observe_module',dict(capture_id=capture_id,source_domain=source_domain,object_uuid=object_uuid,property_uuid=property_uuid,nocache=nocache))

    @server.tool(annotations=READ_ONLY)
    async def read_module_slice(capture_id:Capture,source_domain:Domain,object_uuid:Identity,
        property_uuid:Identity,offset:Offset=0,count:Count=4096,expected_sha256:Hash|None=None,
        nocache:Flag=True)->dict[str,Any]:
        """Read bounded captured source pages; later pages require capture SHA."""
        return await invoke('read_module_slice',dict(capture_id=capture_id,source_domain=source_domain,object_uuid=object_uuid,property_uuid=property_uuid,offset=offset,count=count,expected_sha256=expected_sha256,nocache=nocache))

    @server.tool(annotations=READ_ONLY)
    async def search_symbols(capture_id:Capture,source_domain:Domain,query:Query='',limit:Limit=25,
                             offset:Page=0,nocache:Flag=True)->dict[str,Any]:
        """Search the capture's RAM index; no reread or whole-configuration scan."""
        return await invoke('search_symbols',dict(capture_id=capture_id,source_domain=source_domain,query=query,limit=limit,offset=offset,nocache=nocache))

    @server.tool(annotations=READ_ONLY)
    async def get_context(capture_id:Capture,source_domain:Domain,object_uuid:Identity,
        property_uuid:Identity,method_name:Method,nocache:Flag=True)->dict[str,Any]:
        """Get method source, local callers/callees and unresolved calls in <=24KiB UTF-8.

        Uses this capture's RAM index; omitted content is explicit. Refresh the
        capture for new code. Cross-object resolution stays unverified.
        """
        return await invoke('get_context',dict(capture_id=capture_id,source_domain=source_domain,object_uuid=object_uuid,property_uuid=property_uuid,method_name=method_name,nocache=nocache))

    @server.tool(annotations=READ_ONLY)
    async def analyze_syntax(capture_id:Capture,source_domain:Domain,object_uuid:Identity,
        property_uuid:Identity,expected_sha256:Hash,nocache:Flag=True)->dict[str,Any]:
        """Syntax only for this captured SHA/revision, with UTF-16 ranges.

        No native refresh, current-editor attestation, semantics or execution.
        """
        return await invoke('analyze_syntax',dict(capture_id=capture_id,source_domain=source_domain,
            object_uuid=object_uuid,property_uuid=property_uuid,expected_sha256=expected_sha256,nocache=nocache))

    @server.tool(annotations=READ_ONLY)
    async def close_live_session(capture_id:Capture,source_domain:Domain,nocache:Flag=True)->dict[str,Any]:
        """Drop one capture's RAM body and index; preserve the native owner."""
        return await invoke('close_live_session',dict(capture_id=capture_id,source_domain=source_domain,nocache=nocache))

    @server.tool(annotations=READ_ONLY)
    async def close_live_connection(nocache:Flag=True)->dict[str,Any]:
        """Explicit native closure; requires known worker and host closure proof."""
        return await invoke('close_live_connection',dict(nocache=nocache))

    return server
