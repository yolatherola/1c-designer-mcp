"""Six read-only MCP tools over one validated captured-editor RAM session.

No provider, native capture, file body, listener or runtime attachment is created.
Closing drops this session's RAM references; frontend EOF adds no native action.
"""
import hashlib
import json
from pathlib import Path
from typing import Annotated,Any,Literal

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

SESSION_SHA='a421f915d83e95bfc9f3c2dec5778160b232afb4d2aa251d09658cdb32427851'
if hashlib.sha256(Path(__file__).with_name('live_session.py').read_bytes()).hexdigest()!=SESSION_SHA:
    raise ValueError('LIVE_MCP_SESSION_PIN')
from .live_session import LiveSession,source,MAX_RESPONSE

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


class LiveServer(MCPServer):
    """Reject extras and sanitize framework validation/unknown-tool errors too."""
    async def list_tools(self):
        result=await super().list_tools()
        for tool in result:tool.input_schema=dict(tool.input_schema,additionalProperties=False)
        return result

    async def call_tool(self,name,arguments,context=None):
        failed=False;result=None
        try:
            tools={tool.name:tool for tool in await self.list_tools()}
            if name not in tools or type(arguments) is not dict or set(arguments)-set(tools[name].input_schema.get('properties',{})):
                raise ValueError('arguments')
            result=await super().call_tool(name,arguments,context)
        except Exception:failed=True
        if failed:raise ToolError('LIVE_REQUEST_REFUSED') from None
        return result


def create_server(session:LiveSession):
    """Expose this existing capture only; no opening, refresh or native reads.

    The caller owns session lifetime. ``close_live_session`` clears RAM; it does
    not close a native process or authorize a subsequent capture or write.
    """
    if type(session) is not LiveSession:raise ValueError('LIVE_SESSION_TYPE')
    server=LiveServer('AH1C captured editor RAM',version='1',log_level='WARNING',
        instructions='Read one previously verified editor_live_at_capture snapshot. '
        'It may contain unsaved code; it does not prove the editor is unchanged now. '
        'No native capture, refresh, saved-source fallback or writer is available.')

    def invoke(action,nocache):
        failed=False;result=None
        try:
            if type(nocache) is not bool or nocache is not True:raise ValueError('nocache')
            result=action()
            if type(result) is not dict:raise ValueError('result')
            raw=json.dumps(result,ensure_ascii=False,allow_nan=False).encode('utf-8')
            if len(raw)>MAX_RESPONSE:raise ValueError('bound')
        except Exception:failed=True
        if failed:raise ToolError('LIVE_REQUEST_REFUSED') from None
        return result

    def target(object_uuid,property_uuid):
        value=source.LiveTarget(object_uuid,property_uuid);value.validate();return value

    @server.tool(annotations=READ_ONLY)
    async def health(nocache:Flag=True)->dict[str,Any]:
        """Capture metadata only; never opens or refreshes a native source."""
        return invoke(session.health,nocache)

    @server.tool(annotations=READ_ONLY)
    async def observe_module(capture_id:Capture,source_domain:Domain,object_uuid:Identity,
                             property_uuid:Identity,nocache:Flag=True)->dict[str,Any]:
        """Metadata for the exact captured module, not a new native observation."""
        def action():
            target(object_uuid,property_uuid)
            return session.observe(capture_id)
        return invoke(action,nocache)

    @server.tool(annotations=READ_ONLY)
    async def read_module_slice(capture_id:Capture,source_domain:Domain,object_uuid:Identity,
        property_uuid:Identity,offset:Offset=0,count:Count=4096,expected_sha256:Hash|None=None,
        nocache:Flag=True)->dict[str,Any]:
        """Read Unicode code points from captured RAM; pages require its hash."""
        return invoke(lambda:session.read_slice(capture_id,target(object_uuid,property_uuid),offset,count,expected_sha256),nocache)

    @server.tool(annotations=READ_ONLY)
    async def search_symbols(capture_id:Capture,source_domain:Domain,query:Query='',limit:Limit=25,
                              offset:Page=0,nocache:Flag=True)->dict[str,Any]:
        """Search the capture's lexical index; no provider or current-editor read."""
        return invoke(lambda:session.search_symbols(capture_id,query,limit,offset),nocache)

    @server.tool(annotations=READ_ONLY)
    async def get_context(capture_id:Capture,source_domain:Domain,object_uuid:Identity,
        property_uuid:Identity,method_name:Method,nocache:Flag=True)->dict[str,Any]:
        """Return captured procedure ranges and lexical calls, without body text."""
        return invoke(lambda:session.get_context(capture_id,target(object_uuid,property_uuid),method_name),nocache)

    @server.tool(annotations=READ_ONLY)
    async def close_live_session(capture_id:Capture,source_domain:Domain,nocache:Flag=True)->dict[str,Any]:
        """Drop this capture's RAM only; no native shutdown, retry or recapture."""
        def action():
            if session.health()['capture_id']!=capture_id:raise ValueError('capture')
            return session.close()
        return invoke(action,nocache)

    return server
