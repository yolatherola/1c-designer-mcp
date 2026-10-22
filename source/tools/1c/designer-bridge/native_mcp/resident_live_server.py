"""MCP over one Root-owned resident LIVE connection; frontend EOF is inert."""
import hashlib
import json
from pathlib import Path
from typing import Annotated, Any, Literal
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

SESSION_SHA = 'a63decd08efa3a6e53c1e18b4a3f22aa3f2c1c8509d48464f39c46607c79f4fc'
if hashlib.sha256(Path(__file__).with_name('resident_live_session.py').read_bytes()).hexdigest()!=SESSION_SHA:
    raise ValueError('RESIDENT_LIVE_MCP_SESSION_PIN')
from .resident_live_session import ResidentLiveSession, source, MAX_RESPONSE

Capture=Annotated[str,Field(strict=True,min_length=32,max_length=32,pattern=r'^[0-9a-f]{32}$')]
Identity=Annotated[str,Field(strict=True,pattern=r'^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$')]
Domain=Literal['editor_live_at_capture']
Flag=Annotated[bool,Field(strict=True)]
Offset=Annotated[int,Field(strict=True,ge=0,le=131072)]
Count=Annotated[int,Field(strict=True,ge=1,le=16384)]
Limit=Annotated[int,Field(strict=True,ge=1,le=100)]
Page=Annotated[int,Field(strict=True,ge=0,le=100000)]
Hash=Annotated[str,Field(strict=True,pattern=r'^[0-9a-f]{64}$')]
Query=Annotated[str,Field(strict=True,max_length=256,pattern=r'^[^\x00-\x1f\x7f]*$')]
Method=Annotated[str,Field(strict=True,min_length=1,max_length=256,pattern=r'^[^\x00-\x1f\x7f]*$')]
READ_ONLY=ToolAnnotations(read_only_hint=True,destructive_hint=False,idempotent_hint=False,open_world_hint=False)


class ResidentLiveServer(MCPServer):
    async def list_tools(self):
        result=await super().list_tools()
        for tool in result:tool.input_schema=dict(tool.input_schema,additionalProperties=False)
        return result

    async def call_tool(self,name,arguments,context=None):
        failed=False;result=None;raw=None
        try:
            catalog={tool.name:tool for tool in await self.list_tools()}
            if type(name) is not str or name not in catalog or type(arguments) is not dict or set(arguments)-set(catalog[name].input_schema.get('properties',{})):
                raise ValueError()
            result=await super().call_tool(name,arguments,context)
        except Exception:failed=True
        if failed:raise ToolError('RESIDENT_LIVE_REQUEST_REFUSED') from None
        return result


def create_server(session:ResidentLiveSession):
    """Expose existing trusted ports; no provider install/paths/code from tools.

    READ/open/refresh is explicit. Local capture close only drops RAM references;
    connection close explicitly asks Root to prove native worker/host closure.
    """
    if type(session) is not ResidentLiveSession:raise ValueError('RESIDENT_LIVE_SESSION_TYPE')
    server=ResidentLiveServer('AH1C resident captured editor RAM',version='1',log_level='WARNING',
        instructions='Explicit fresh CommonModule LIVE captures via an existing owned connection. '
        'Captured state may be dirty or readonly and may subsequently change. '
        'No saved fallback, source writes, native install or automatic EOF shutdown.')

    def invoke(action,nocache):
        failed=False;result=None
        try:
            if type(nocache) is not bool or nocache is not True:raise ValueError()
            result=action()
            if type(result) is not dict:raise ValueError()
            raw=json.dumps(result,ensure_ascii=False,allow_nan=False).encode('utf8')
            if len(raw)>MAX_RESPONSE:raise ValueError()
        except Exception:failed=True
        if failed:
            result=None;raw=None
            raise ToolError('RESIDENT_LIVE_REQUEST_REFUSED') from None
        return result

    def target(object_uuid,property_uuid):
        value=source.ResidentLiveTarget(object_uuid,property_uuid);value.validate();return value

    @server.tool(annotations=READ_ONLY)
    async def health(nocache:Flag=True)->dict[str,Any]:
        """Cached capture/connection metadata only; no native read or renewal."""
        return invoke(session.health,nocache)

    @server.tool(annotations=READ_ONLY)
    async def open_live_session(object_uuid:Identity,source_domain:Domain,nocache:Flag=True)->dict[str,Any]:
        """Explicitly capture one CommonModule through the trusted native owner."""
        return invoke(lambda:session.open_live_session(object_uuid),nocache)

    @server.tool(annotations=READ_ONLY)
    async def refresh_observed(capture_id:Capture,source_domain:Domain,nocache:Flag=True)->dict[str,Any]:
        """Fresh read and replacement of this target's previous capture/index."""
        return invoke(lambda:session.refresh_observed(capture_id),nocache)

    @server.tool(annotations=READ_ONLY)
    async def observe_module(capture_id:Capture,source_domain:Domain,object_uuid:Identity,
                             property_uuid:Identity,nocache:Flag=True)->dict[str,Any]:
        """Observe cached capture metadata; does not reread the current editor."""
        return invoke(lambda:session.observe_module(capture_id,target(object_uuid,property_uuid)),nocache)

    @server.tool(annotations=READ_ONLY)
    async def read_module_slice(capture_id:Capture,source_domain:Domain,object_uuid:Identity,
        property_uuid:Identity,offset:Offset=0,count:Count=4096,expected_sha256:Hash|None=None,
        nocache:Flag=True)->dict[str,Any]:
        """Unicode-code-point pages of exact captured text; later pages bind SHA."""
        return invoke(lambda:session.read_module_slice(capture_id,target(object_uuid,property_uuid),offset,count,expected_sha256),nocache)

    @server.tool(annotations=READ_ONLY)
    async def search_symbols(capture_id:Capture,source_domain:Domain,query:Query='',limit:Limit=25,
                             offset:Page=0,nocache:Flag=True)->dict[str,Any]:
        """Search one captured lexical index, without native reads or body text."""
        return invoke(lambda:session.search_symbols(capture_id,query,limit,offset),nocache)

    @server.tool(annotations=READ_ONLY)
    async def get_context(capture_id:Capture,source_domain:Domain,object_uuid:Identity,
        property_uuid:Identity,method_name:Method,nocache:Flag=True)->dict[str,Any]:
        """Get method source, local callers/callees and unresolved calls in <=24KiB UTF-8.

        Uses this capture's RAM index; omitted content is explicit. Refresh the
        capture for new code. Cross-object resolution stays unverified.
        """
        return invoke(lambda:session.get_context(capture_id,target(object_uuid,property_uuid),method_name),nocache)

    @server.tool(annotations=READ_ONLY)
    async def analyze_syntax(capture_id:Capture,source_domain:Domain,object_uuid:Identity,
        property_uuid:Identity,expected_sha256:Hash,nocache:Flag=True)->dict[str,Any]:
        """Syntax only for the exact captured SHA/revision; no native refresh.

        Returns code/severity and zero-based UTF-16 ranges, without messages or
        source. Current editor state, semantics and runtime remain unverified.
        """
        return invoke(lambda:session.analyze_syntax(capture_id,target(object_uuid,property_uuid),expected_sha256),nocache)

    @server.tool(annotations=READ_ONLY)
    async def close_live_session(capture_id:Capture,source_domain:Domain,nocache:Flag=True)->dict[str,Any]:
        """Drop this capture's body/index references only; keep native owner."""
        return invoke(lambda:session.close_live_session(capture_id),nocache)

    @server.tool(annotations=READ_ONLY)
    async def close_live_connection(nocache:Flag=True)->dict[str,Any]:
        """Explicit native CLOSE; success requires Root's known worker/host0 proof."""
        return invoke(session.close_live_connection,nocache)

    return server
