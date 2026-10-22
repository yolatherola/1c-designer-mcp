"""Guardian MCP relay; native ownership stays outside the stdio process.

The external installation token supplements the inner binding generation. This
factory never installs native code or renews a binding implicitly on a read.
"""
import json
from typing import Annotated, Any

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from .guardian_client import GuardianRpcClient
from .saved_source import need
from .resident_server import CLOSE_OWNED
from .server import (SavedServer, READ_ONLY, MAX_RESPONSE, Domain, Generation,
                     Identity, Flag, Offset, Count, Hash, Limit, Query, Method)

BindingToken = Annotated[str, Field(strict=True, min_length=32, max_length=32,
                                   pattern=r'^[0-9a-f]{32}$')]


def create_guardian_relay_server(client: GuardianRpcClient):
    """Create eight saved-source tools over an exact owner-thread guardian client.

    Publishing/replacing a native installation remains an explicit root action.
    Scoped calls require both its opaque token and the inner binding generation.
    """
    need(type(client) is GuardianRpcClient, 'GUARDIAN_CLIENT_TYPE')
    server = SavedServer('AH1C guardian saved RAM relay', version='1', log_level='WARNING',
        instructions='Root publishes bounded saved-source installations explicitly. '
                     'Use the returned binding_token and generation for scoped calls. '
                     'Health/open never install native code; no source paths, scripts, or metadata writes.')

    async def invoke(name, arguments, binding_token=None):
        failed = False
        try:
            need(type(arguments.get('nocache')) is bool and arguments['nocache'] is True,
                 'NOCACHE_REQUIRED')
            result = await client.call(name, arguments, binding_token=binding_token)
            need(type(result) is dict, 'RESPONSE_TYPE')
            need(len(json.dumps(result, ensure_ascii=False, allow_nan=False).encode('utf-8'))
                 <= MAX_RESPONSE, 'RESPONSE_BOUND')
        except Exception:
            # Do not transport inner ToolError details or retain a source-bearing
            # exception context on the stable public protocol error.
            failed = True
            result = None
        if failed:
            raise ToolError('SAVED_REQUEST_REFUSED')
        return result

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def health(nocache: Flag=True) -> dict[str, Any]:
        """Inspect current installation metadata without opening or reading it."""
        return await invoke('health', dict(nocache=nocache))

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def open_saved_session(nocache: Flag=True) -> dict[str, Any]:
        """Open/renew a binding in the already published installation only."""
        return await invoke('open_saved_session', dict(nocache=nocache))

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def observe_module(binding_token: BindingToken, source_domain: Domain,
            generation: Generation, object_uuid: Identity, property_uuid: Identity,
            nocache: Flag=True) -> dict[str, Any]:
        """Guard and index one saved module under an exact installation token."""
        return await invoke('observe_module', dict(source_domain=source_domain,
            generation=generation, object_uuid=object_uuid, property_uuid=property_uuid,
            nocache=nocache), binding_token)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def read_module_slice(binding_token: BindingToken, source_domain: Domain,
            generation: Generation, object_uuid: Identity, property_uuid: Identity,
            offset: Offset=0, count: Count=4096, expected_sha256: Hash|None=None,
            nocache: Flag=True) -> dict[str, Any]:
        """Read a bounded verified Unicode slice; continuation requires its SHA."""
        return await invoke('read_module_slice', dict(source_domain=source_domain,
            generation=generation, object_uuid=object_uuid, property_uuid=property_uuid,
            offset=offset, count=count, expected_sha256=expected_sha256,
            nocache=nocache), binding_token)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def search_symbols(binding_token: BindingToken, source_domain: Domain,
            generation: Generation, query: Query='', include_stale: Flag=False,
            limit: Limit=25, offset: Offset=0, nocache: Flag=True) -> dict[str, Any]:
        """Search observed metadata without implicit source reads."""
        return await invoke('search_symbols', dict(source_domain=source_domain,
            generation=generation, query=query, include_stale=include_stale,
            limit=limit, offset=offset, nocache=nocache), binding_token)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def get_context(binding_token: BindingToken, source_domain: Domain,
            generation: Generation, object_uuid: Identity, property_uuid: Identity,
            method_name: Method, include_stale: Flag=False,
            nocache: Flag=True) -> dict[str, Any]:
        """Read context from the exact installation's observed metadata."""
        return await invoke('get_context', dict(source_domain=source_domain,
            generation=generation, object_uuid=object_uuid, property_uuid=property_uuid,
            method_name=method_name, include_stale=include_stale,
            nocache=nocache), binding_token)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def refresh_observed(binding_token: BindingToken, source_domain: Domain,
            generation: Generation, nocache: Flag=True) -> dict[str, Any]:
        """Explicitly refresh at most four stale observations through guards."""
        return await invoke('refresh_observed', dict(source_domain=source_domain,
            generation=generation, nocache=nocache), binding_token)

    @server.tool(annotations=CLOSE_OWNED, structured_output=True)
    async def close_saved_session(binding_token: BindingToken, source_domain: Domain,
            generation: Generation, nocache: Flag=True) -> dict[str, Any]:
        """Close this installation; unknown cleanup seals its root-owned slot."""
        return await invoke('close_saved_session', dict(source_domain=source_domain,
            generation=generation, nocache=nocache), binding_token)

    return server
