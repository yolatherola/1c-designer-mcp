"""Saved-domain MCP over a trusted injected RAM provider, disconnected by default.

No native transport, registration, process/session attachment, source-file cache,
or legacy getter is imported or started here. An external root launcher must
supply and independently attest current_binding/guard/provider callbacks.
"""
from dataclasses import asdict,is_dataclass
from pathlib import Path
import hashlib
import inspect
import json
import sys
import threading
import time
from typing import Annotated,Any,Literal
from types import FunctionType
from uuid import uuid4
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field
from .saved_source import (SourceBinding,Target,GuardState,ReadRequest,SavedRefusal,
                          validate_snapshot,need,finite,integer,digest,MAX_BYTES,MAX_CHARS)

# Fixed repository-owned PURE parser/index dependencies, never a client path.
_RESEARCH=Path(__file__).resolve().parents[1]/'research'
for _name,_pin in {
 'live_symbol_index_v204.py':'e30e38eecc48544f6375ff4ffffa0f3620b9cdf19f65fd9acee31cac431693bf',
 'rlm_ram_parser_adapter_v204.py':'9140c7411b6ed36b2e8619939800b86ee149b214d39d853a1bb1f59e08683eaf',
}.items():
    need(hashlib.sha256((_RESEARCH/_name).read_bytes()).hexdigest()==_pin,'INDEX_PIN')
if str(_RESEARCH) not in sys.path:sys.path.insert(0,str(_RESEARCH))
from live_symbol_index_v204 import LiveSymbolIndex,SourceScope,ModuleTarget,VerifiedSnapshot,LiveIndexRefusal
from rlm_ram_parser_adapter_v204 import RlmRamParserAdapter,RamParserRefusal

MAX_TRACKED=32
MAX_REFRESH=4
MAX_RESPONSE=131072

def _saved_text_hash(text):
    """Match the receipt envelope without changing the frozen parser's limits."""
    if type(text) is not str:raise RamParserRefusal('TEXT_TYPE')
    try:raw=text.encode('utf-8')
    except UnicodeError:raise RamParserRefusal('TEXT_ENCODING') from None
    if len(raw)>MAX_BYTES or len(text)>MAX_CHARS or '\x00' in text:raise RamParserRefusal('TEXT_BOUND')
    return hashlib.sha256(raw).hexdigest()

def _private_hash_function(original):
    # Functions get an isolated globals dictionary; imported modules and other
    # sessions keep their original byte cap and exact public dataclass types.
    return FunctionType(original.__code__,dict(original.__globals__,text_hash=_saved_text_hash),
                        original.__name__,original.__defaults__,original.__closure__)

class _SavedIndex(LiveSymbolIndex):
    apply_snapshot=_private_hash_function(LiveSymbolIndex.apply_snapshot)

class _SavedRamParser:
    """Remove a transport BOM only for parsing, never for hashes or slicing.

    The frozen parser misses a first declaration immediately following a BOM.
    Dropping that single marker preserves all line numbers; the index still
    hashes/stores the original verified source and retains metadata only.
    """
    def __init__(self):
        self._parser=RlmRamParserAdapter();self._parse=_private_hash_function(RlmRamParserAdapter.parse)
    def parse(self,text):return self._parse(self._parser,text[1:] if text.startswith('\ufeff') else text)

class SavedSession:
    """One immutable binding/domain. No in-place generation or domain rebinding.

    Guard is evaluated before every dispatch. An expired binding invalidates all
    observations; create a distinct session for a new generation or domain.
    """
    def __init__(self,binding,provider,guard,current_binding,*,clock=time.monotonic,ttl=5.0):
        need(type(binding) is SourceBinding,'BINDING_TYPE');binding.validate()
        need(all(callable(x) and not inspect.iscoroutinefunction(x) for x in (provider,guard,current_binding,clock)),'CALLBACK')
        need(finite(ttl) and 0<ttl<=60,'TTL')
        self.binding=binding;self.provider=provider;self.guard=guard;self.current_binding=current_binding;self.clock=clock;self.ttl=ttl
        scope=SourceScope(binding.root_uuid,binding.session_id,binding.generation,'editable' if binding.source_domain=='main_saved' else 'database')
        self.index=_SavedIndex(scope,parser=_SavedRamParser());self.observed={};self.sequence=0;self.reads=0;self.closed=False
        self.last_error=None;self._body=None;self._lock=threading.Lock();self._last_now=None
    def _now(self):
        now=self.clock();need(finite(now) and now>=0,'CLOCK')
        if self._last_now is not None and now<self._last_now:
            self._invalidate_all();raise SavedRefusal('SAVED_CLOCK_ROLLBACK')
        self._last_now=now;return now
    def _invalidate_all(self):
        for target,state in self.observed.items():state['stale']=True;self.index.mark_invalidated(ModuleTarget(target.object_uuid,target.property_uuid))
    def _identity(self):
        need(not self.closed,'CLOSED');now=self._now()
        try:current=self.current_binding()
        except Exception:current=None
        if type(current) is not SourceBinding or current!=self.binding or now>self.binding.valid_until:
            self._invalidate_all();self.last_error='SAVED_BINDING_CHANGED_OR_EXPIRED';raise SavedRefusal(self.last_error)
        return now
    def select(self,source_domain,generation):
        if type(source_domain) is not str or source_domain!=self.binding.source_domain or type(generation) is not int or generation!=self.binding.generation:
            raise SavedRefusal('SAVED_REQUEST_SCOPE')
        self.expire()
    def expire(self):
        now=self._identity()
        for target,state in self.observed.items():
            if now-state['checked_at']>=self.ttl or now>state['valid_until']:
                state['stale']=True;self.index.mark_invalidated(ModuleTarget(target.object_uuid,target.property_uuid))
        return now
    def _metadata(self,target,receipt):
        return dict(object_uuid=target.object_uuid,property_uuid=target.property_uuid,source_domain=self.binding.source_domain,
                    generation=self.binding.generation,source_sha256=receipt.source_sha256,revision=receipt.revision,
                    byte_count=receipt.byte_count,bom_present=receipt.bom_present,crlf_count=receipt.crlf_count,
                    editor_buffer_equivalence_verified=False,source_view=self.binding.source_domain,
                    saved_resource_sha256=receipt.saved_resource_sha256,writer_authorized=False,body_retained=False)
    def _obtain(self,target):
        need(type(target) is Target,'TARGET_TYPE');target.validate();need(self._lock.acquire(blocking=False),'BUSY')
        try:
            now=self.expire()
            need(target in self.observed or len(self.observed)<MAX_TRACKED,'SELECTION_BOUND')
            self.observed[target]=dict(checked_at=now,valid_until=now,stale=True)
            self.index.mark_invalidated(ModuleTarget(target.object_uuid,target.property_uuid))
            # Unknown/dirty/expired selection stops before provider invocation.
            try:state=self.guard(self.binding,target)
            except Exception:raise SavedRefusal('SAVED_GUARD_UNAVAILABLE') from None
            need(type(state) is GuardState and state.binding==self.binding and type(state.binding) is SourceBinding
                 and state.target==target and type(state.target) is Target and state.identity_verified is True,'GUARD_BINDING')
            now=self._identity()
            need(type(state.dirty_state) is str and state.dirty_state=='clean','DIRTY_OR_UNKNOWN')
            need(finite(state.checked_at) and finite(state.valid_until) and self.observed[target]['checked_at']<=state.checked_at<=now<=state.valid_until<=self.binding.valid_until,'GUARD_EXPIRED')
            self.sequence+=1
            request=ReadRequest(self.binding,target,uuid4().hex,self.sequence,now,min(state.valid_until,self.binding.valid_until,now+self.ttl))
            self.reads+=1
            try:packet=self.provider(request)
            except Exception:raise SavedRefusal('SAVED_PROVIDER_FAILED') from None
            now=self._identity();text=validate_snapshot(packet,request,now);self._body=text
            try:
                result=self.index.apply_snapshot(VerifiedSnapshot(self.index.scope,ModuleTarget(target.object_uuid,target.property_uuid),
                    packet.receipt.source_sha256,request.revision,text,True,True,True))
            except LiveIndexRefusal as error:
                # A valid receipt remains readable when finite lexical limits
                # prevent indexing. Never expose an old index as current.
                allowed={'LINE_BOUND','SYMBOL_BOUND','CALL_BOUND','DIRECTIVE_BOUND','PARSER_REFUSED','PARSER_RANGE'}
                if str(error) not in allowed:raise
                self.observed[target]=dict(checked_at=now,valid_until=packet.receipt.valid_until,stale=True)
                self.last_error='SAVED_INDEX_UNINDEXABLE'
                return text,dict(self._metadata(target,packet.receipt),status='UNINDEXABLE',index_status='UNINDEXABLE',
                                 index_fresh=False,index_reason=str(error),read_verified=True)
            self.observed[target]=dict(checked_at=now,valid_until=packet.receipt.valid_until,stale=False)
            self.last_error=None
            return text,dict(self._metadata(target,packet.receipt),status=result['status'],index_status=result['status'],index_fresh=True,read_verified=True)
        except SavedRefusal as error:
            self.last_error=str(error);raise
        except Exception:
            self.last_error='SAVED_INDEX_OR_RECEIPT';raise SavedRefusal(self.last_error) from None
        finally:self._body=None;self._lock.release()
    def observe(self,target):
        text,metadata=self._obtain(target);del text;return metadata
    def read_slice(self,target,offset=0,count=4096,expected_sha256=None):
        need(integer(offset,0,1048576) and integer(count,1,16384) and (expected_sha256 is None or digest(expected_sha256))
             and (offset==0 or expected_sha256 is not None),'SLICE_BOUND')
        text,metadata=self._obtain(target)
        try:
            need(expected_sha256 is None or expected_sha256==metadata['source_sha256'],'SOURCE_CHANGED')
            need(offset<=len(text),'OFFSET_AFTER_END');end=min(offset+count,len(text))
            return dict(metadata,status='SOURCE_SLICE',text=text[offset:end],offset=offset,next_offset=end if end<len(text) else None,
                        total_code_points=len(text),position_unit='unicode_code_points',offset_base=0)
        finally:del text
    def refresh(self):
        self.expire();targets=[target for target,state in self.observed.items() if state['stale']][:MAX_REFRESH]
        refreshed=failed=unindexable=0
        for target in targets:
            try:
                result=self.observe(target)
                if result['index_fresh']:refreshed+=1
                else:unindexable+=1
            except SavedRefusal:failed+=1
        return dict(refreshed=refreshed,refused=failed,unindexable=unindexable,remaining_stale=sum(x['stale'] for x in self.observed.values()),refresh_budget=MAX_REFRESH)
    def search(self,query,include_stale=False,limit=25,offset=0):
        self.expire();need(integer(limit,1,100) and integer(offset,0,100000),'PAGE')
        rows=self.index.search_symbols(query,include_stale)
        return dict(matches=rows[offset:offset+limit],total=len(rows),coverage=self.index.coverage(),source_read_performed=False,freshness_policy='bounded_snapshot_ttl')
    def context(self,target,method,include_stale=False):
        self.expire();target.validate();return dict(self.index.get_context(ModuleTarget(target.object_uuid,target.property_uuid),method,include_stale),source_read_performed=False,freshness_policy='bounded_snapshot_ttl')
    def health(self):
        try:self.expire();status='READY'
        except SavedRefusal:status='CLOSED' if self.closed else 'STALE_BINDING'
        return dict(status=status,source_domain=self.binding.source_domain,generation=self.binding.generation,
                    observed_modules=len(self.observed),fresh_modules=sum(not row['stale'] for row in self.observed.values()),
                    body_retained=self._body is not None,provider_reads=self.reads,last_error=self.last_error,
                    provider_binding='trusted_callback_only',native_binding_verified=False,editor_live_available=False,
                    coverage='observed_modules_only',freshness_policy='bounded_snapshot_ttl',writer_authorized=False)
    def close(self):
        self.closed=True;self._invalidate_all();self._body=None

Domain=Literal['main_saved','database_saved']
Generation=Annotated[int,Field(strict=True,ge=1,le=2**53-1)]
Identity=Annotated[str,Field(strict=True,pattern=r'^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$')]
Flag=Annotated[bool,Field(strict=True)]
Offset=Annotated[int,Field(strict=True,ge=0,le=1048576)]
Count=Annotated[int,Field(strict=True,ge=1,le=16384)]
Limit=Annotated[int,Field(strict=True,ge=1,le=100)]
Query=Annotated[str,Field(strict=True,max_length=256,pattern=r'^[^\x00-\x1f\x7f]*$')]
Method=Annotated[str,Field(strict=True,min_length=1,max_length=256,pattern=r'^[^\x00-\x1f\x7f]*$')]
Hash=Annotated[str,Field(strict=True,pattern=r'^[0-9a-f]{64}$')]
READ_ONLY=ToolAnnotations(read_only_hint=True,destructive_hint=False,idempotent_hint=False,open_world_hint=False)

def _wire(value):
    if is_dataclass(value):return {k:_wire(v) for k,v in asdict(value).items()}
    if type(value) is dict:return {k:_wire(v) for k,v in value.items()}
    if type(value) in (list,tuple):return [_wire(x) for x in value]
    return value

class SavedServer(MCPServer):
    async def list_tools(self):
        result=await super().list_tools()
        for tool in result:tool.input_schema=dict(tool.input_schema,additionalProperties=False)
        return result
    async def call_tool(self,name,arguments,context=None):
        tools={x.name:x for x in await self.list_tools()}
        if name in tools and (type(arguments) is not dict or set(arguments)-set(tools[name].input_schema.get('properties',{}))):
            raise ToolError('SAVED_ARGUMENTS')
        return await super().call_tool(name,arguments,context)

def create_server(session=None):
    """Build disconnected or trusted-callback MCP; never registers/attaches 1C."""
    need(session is None or type(session) is SavedSession,'SESSION_TYPE')
    server=SavedServer('AH1C saved RAM sources',version='1',log_level='WARNING',
        instructions='Saved Main/DB source domains only. Bounded RAM observations; no editor-live equivalence or native binding attestation. No writes, commands or source paths.')
    def invoke(action,nocache,source_domain=None,generation=None):
        if session is None:raise ToolError('SAVED_DISCONNECTED')
        try:
            need(type(nocache) is bool and nocache is True,'NOCACHE_REQUIRED')
            if source_domain is not None:session.select(source_domain,generation)
            result=_wire(action());result.update(writer_authorized=False,native_binding_verified=False,
                source_domain=session.binding.source_domain,source_view=session.binding.source_domain,
                generation=session.binding.generation,editor_buffer_equivalence_verified=False)
            need(len(json.dumps(result,ensure_ascii=False,allow_nan=False).encode())<=MAX_RESPONSE,'RESPONSE_BOUND')
            return result
        except (SavedRefusal,LiveIndexRefusal):raise ToolError('SAVED_REQUEST_REFUSED') from None
        except Exception:raise ToolError('SAVED_REQUEST_FAILED') from None
    @server.tool(annotations=READ_ONLY,structured_output=True)
    async def health(nocache:Flag=True)->dict[str,Any]:
        """Report bounded observation state; never read source or refresh provider."""
        return invoke(lambda:session.health(),nocache)
    @server.tool(annotations=READ_ONLY,structured_output=True)
    async def observe_module(source_domain:Domain,generation:Generation,object_uuid:Identity,property_uuid:Identity,nocache:Flag=True)->dict[str,Any]:
        """Freshly observe one clean saved module; refuse unknown/dirty before dispatch."""
        return invoke(lambda:session.observe(Target(object_uuid,property_uuid)),nocache,source_domain,generation)
    @server.tool(annotations=READ_ONLY,structured_output=True)
    async def read_module_slice(source_domain:Domain,generation:Generation,object_uuid:Identity,property_uuid:Identity,offset:Offset=0,count:Count=4096,expected_sha256:Hash|None=None,nocache:Flag=True)->dict[str,Any]:
        """Fresh byte-verified RAM source slice; continuation requires prior SHA."""
        return invoke(lambda:session.read_slice(Target(object_uuid,property_uuid),offset,count,expected_sha256),nocache,source_domain,generation)
    @server.tool(annotations=READ_ONLY,structured_output=True)
    async def search_symbols(source_domain:Domain,generation:Generation,query:Query='',include_stale:Flag=False,limit:Limit=25,offset:Offset=0,nocache:Flag=True)->dict[str,Any]:
        """Search observed RAM symbols; expiry marks stale without automatic reads."""
        return invoke(lambda:session.search(query,include_stale,limit,offset),nocache,source_domain,generation)
    @server.tool(annotations=READ_ONLY,structured_output=True)
    async def get_context(source_domain:Domain,generation:Generation,object_uuid:Identity,property_uuid:Identity,method_name:Method,include_stale:Flag=False,nocache:Flag=True)->dict[str,Any]:
        """Return parsed symbol/call metadata only, with explicit bounded freshness."""
        return invoke(lambda:session.context(Target(object_uuid,property_uuid),method_name,include_stale),nocache,source_domain,generation)
    @server.tool(annotations=READ_ONLY,structured_output=True)
    async def refresh_observed(source_domain:Domain,generation:Generation,nocache:Flag=True)->dict[str,Any]:
        """Refresh at most four stale selections through the safe guarded provider."""
        return invoke(lambda:session.refresh(),nocache,source_domain,generation)
    return server
