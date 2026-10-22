"""Generation-aware saved-source MCP, disconnected until a launcher binds it.

The eight tools expose no paths, connection settings, scripts, or mutations of
1C metadata. Callback composition is not a proof of a native transport binding.
"""
import json
from typing import Any
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .saved_source import SavedRefusal, Target, need
from .session_lifecycle import SessionBroker
from .server import (SavedServer, READ_ONLY, MAX_RESPONSE, _wire, LiveIndexRefusal,
                     Domain, Generation, Identity, Flag, Offset, Count, Hash,
                     Limit, Query, Method)

CLOSE_OWNED = ToolAnnotations(read_only_hint=False, destructive_hint=False,
                            idempotent_hint=False, open_world_hint=False)


def create_resident_server(broker=None):
    """Create an unregistered MCP service over one owned transport broker."""
    need(broker is None or type(broker) is SessionBroker, 'LIFECYCLE_BROKER')
    server = SavedServer('AH1C resident saved RAM sources', version='1', log_level='WARNING',
        instructions='Explicit binding generations; saved source only. Open explicitly, then use returned generation. '
                     'No editor-buffer equivalence, source files, metadata writes, or native attestation.')

    def invoke(action, nocache):
        if broker is None:
            raise ToolError('SAVED_DISCONNECTED')
        try:
            need(type(nocache) is bool and nocache is True, 'NOCACHE_REQUIRED')
            result = _wire(action())
            result.update(writer_authorized=False, native_binding_verified=False,
                          source_domain=broker.identity.source_domain,
                          source_view=broker.identity.source_domain, generation=broker.generation,
                          editor_buffer_equivalence_verified=False)
            need(len(json.dumps(result, ensure_ascii=False, allow_nan=False).encode()) <= MAX_RESPONSE,
                 'RESPONSE_BOUND')
            return result
        except (SavedRefusal, LiveIndexRefusal):
            raise ToolError('SAVED_REQUEST_REFUSED') from None
        except Exception:
            raise ToolError('SAVED_REQUEST_FAILED') from None

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def health(nocache: Flag=True) -> dict[str, Any]:
        """Inspect service metadata without opening or refreshing a transport."""
        return invoke(lambda: broker.health(), nocache)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def open_saved_session(nocache: Flag=True) -> dict[str, Any]:
        """Explicitly acquire/renew one bounded binding; no source read."""
        return invoke(lambda: dict(status='BINDING_OPEN', binding=_wire(broker.open_generation())), nocache)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def observe_module(source_domain: Domain, generation: Generation, object_uuid: Identity,
                             property_uuid: Identity, nocache: Flag=True) -> dict[str, Any]:
        """Guard and read one saved module into a bounded metadata index."""
        return invoke(lambda: broker.run_selected(source_domain, generation,
            lambda session: session.observe(Target(object_uuid, property_uuid))), nocache)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def read_module_slice(source_domain: Domain, generation: Generation, object_uuid: Identity,
            property_uuid: Identity, offset: Offset=0, count: Count=4096,
            expected_sha256: Hash|None=None, nocache: Flag=True) -> dict[str, Any]:
        """Read a verified RAM slice; continued reads require the previous SHA."""
        return invoke(lambda: broker.run_selected(source_domain, generation,
            lambda session: session.read_slice(Target(object_uuid, property_uuid), offset, count, expected_sha256)), nocache)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def search_symbols(source_domain: Domain, generation: Generation, query: Query='',
            include_stale: Flag=False, limit: Limit=25, offset: Offset=0,
            nocache: Flag=True) -> dict[str, Any]:
        """Search observed symbol metadata without implicit native reads."""
        return invoke(lambda: broker.run_selected(source_domain, generation,
            lambda session: session.search(query, include_stale, limit, offset)), nocache)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def get_context(source_domain: Domain, generation: Generation, object_uuid: Identity,
            property_uuid: Identity, method_name: Method, include_stale: Flag=False,
            nocache: Flag=True) -> dict[str, Any]:
        """Read call/symbol context from already observed metadata only."""
        return invoke(lambda: broker.run_selected(source_domain, generation,
            lambda session: session.context(Target(object_uuid, property_uuid), method_name, include_stale)), nocache)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def refresh_observed(source_domain: Domain, generation: Generation,
                               nocache: Flag=True) -> dict[str, Any]:
        """Refresh at most four stale observations through guarded reads."""
        return invoke(lambda: broker.run_selected(source_domain, generation,
            lambda session: session.refresh()), nocache)

    @server.tool(annotations=CLOSE_OWNED, structured_output=True)
    async def close_saved_session(source_domain: Domain, generation: Generation,
                                  nocache: Flag=True) -> dict[str, Any]:
        """Close only this service's exact generation; refuse uncertain cleanup."""
        return invoke(lambda: dict(status=broker.close_selected(source_domain, generation)), nocache)

    return server
