"""One expiring editor-live capture in private RAM; no native or MCP transport.

The index describes captured text, never the current editor. Dirty/read-only
states remain observations. Caller-returned slices cannot be erased here.
"""
from dataclasses import asdict,is_dataclass
import hashlib
import json
from pathlib import Path
import sys
import threading
import time
from types import FunctionType

SOURCE_SHA='8b8c8dc805d7de3cff9aa0ff81189ea3cbff1f7d73095887cf4c3fa48b4ba0d3'
if hashlib.sha256(Path(__file__).with_name('live_source.py').read_bytes()).hexdigest()!=SOURCE_SHA:
    raise ValueError('LIVE_SESSION_SOURCE_PIN')
from . import live_source as source

_RESEARCH=Path(__file__).resolve().parents[1]/'research'
_PINS={
    'live_symbol_index_v204.py':'e30e38eecc48544f6375ff4ffffa0f3620b9cdf19f65fd9acee31cac431693bf',
    'rlm_ram_parser_adapter_v204.py':'9140c7411b6ed36b2e8619939800b86ee149b214d39d853a1bb1f59e08683eaf',
}
MAX_RESPONSE=131072


class LiveSessionRefusal(ValueError):
    """Fixed refusal code without source text, peer diagnostics or error bodies."""


def _need(ok,code):
    if not ok:raise LiveSessionRefusal('LIVE_SESSION_'+code)


def _int(value,low,high):return type(value) is int and low<=value<=high


def _dependencies():
    for name,pin in _PINS.items():
        _need(hashlib.sha256((_RESEARCH/name).read_bytes()).hexdigest()==pin,'INDEX_PIN')
    if str(_RESEARCH) not in sys.path:sys.path.insert(0,str(_RESEARCH))
    import live_symbol_index_v204 as index
    import rlm_ram_parser_adapter_v204 as parser
    return index,parser


def _text_hash(text):
    # This private derivative changes only the verified input byte bound.
    if type(text) is not str:raise LiveSessionRefusal('LIVE_SESSION_TEXT_TYPE')
    try:raw=text.encode('utf-8','strict')
    except UnicodeError:raise LiveSessionRefusal('LIVE_SESSION_TEXT_ENCODING') from None
    _need(len(raw)<=source.MAX_UTF8_BYTES and '\x00' not in text,'TEXT_BOUND')
    return hashlib.sha256(raw).hexdigest()


def _private(original):
    fn=FunctionType(original.__code__,dict(original.__globals__,text_hash=_text_hash),
                    original.__name__,original.__defaults__,original.__closure__)
    fn.__kwdefaults__=original.__kwdefaults__
    return fn


def _make_index(request,text):
    index,parser=_dependencies()
    class CaptureParser:
        def __init__(self):
            self._parser=parser.RlmRamParserAdapter()
            self._parse=_private(parser.RlmRamParserAdapter.parse)
        def parse(self,value):
            return self._parse(self._parser,value[1:] if value.startswith('\ufeff') else value)
    class CaptureIndex(index.LiveSymbolIndex):
        apply_snapshot=_private(index.LiveSymbolIndex.apply_snapshot)
    scope=index.SourceScope(request.binding.root_uuid,request.binding.operation_id,request.revision,'editable')
    target=index.ModuleTarget(request.target.object_uuid,request.target.property_uuid)
    value=CaptureIndex(scope,parser=CaptureParser())
    try:
        value.apply_snapshot(index.VerifiedSnapshot(scope,target,_text_hash(text),request.revision,text,True,True,True))
    except index.LiveIndexRefusal as error:
        # A lexical parser bound does not invalidate an authenticated capture.
        allowed={'LINE_BOUND','SYMBOL_BOUND','CALL_BOUND','DIRECTIVE_BOUND','PARSER_REFUSED','PARSER_RANGE'}
        _need(str(error) in allowed,'INDEX_UNPROVEN')
        return None,target,'UNINDEXABLE'
    return value,target,'INDEXED'


def _plain(value):
    if is_dataclass(value):return _plain(asdict(value))
    if type(value) is dict:return {key:_plain(item) for key,item in value.items()}
    if type(value) in (list,tuple):return [_plain(item) for item in value]
    return value


def _bounded(row):
    row=_plain(row)
    try:raw=json.dumps(row,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8')
    except (TypeError,ValueError,UnicodeError):raise LiveSessionRefusal('LIVE_SESSION_RESPONSE') from None
    _need(len(raw)<=MAX_RESPONSE,'RESPONSE_BOUND');return row


class LiveSession:
    """Capture-once session; construction validates bytes, queries never dispatch.

    ``capture_id`` and target arguments prevent accidental cross-capture joins.
    Expiry/close drop this instance's body/index references; Python and caller
    memory erasure is not claimed. No refresh, write or implicit recapture exists.
    """
    __slots__=('_request','_receipt','_body','_index','_index_target','_index_status',
               '_clock','_last_now','_state','_lock')

    def __init__(self,snapshot,expected_request,*,clock=time.monotonic):
        _need(callable(clock),'CLOCK')
        self._body=None;self._index=None;self._state='CLOSED';self._clock=clock
        self._last_now=None;self._lock=threading.RLock()
        now=self._now()
        try:text=source.validate_snapshot(snapshot,expected_request,expected_request.target,now)
        except Exception:raise LiveSessionRefusal('LIVE_SESSION_CAPTURE_UNPROVEN') from None
        self._request=expected_request;self._receipt=snapshot.receipt
        try:self._index,self._index_target,self._index_status=_make_index(expected_request,text)
        except Exception:raise LiveSessionRefusal('LIVE_SESSION_INDEX_UNPROVEN') from None
        self._body=text;self._state='READY'

    def __repr__(self):return '<LiveSession '+self._state+' body=privateRAM>'

    def _drop(self,state):
        self._body=None;self._index=None;self._state=state

    def _now(self):
        try:value=self._clock()
        except Exception:
            self._drop('UNKNOWN_RETAIN');raise LiveSessionRefusal('LIVE_SESSION_CLOCK') from None
        if type(value) not in (int,float) or not 0<=value<float('inf') or (self._last_now is not None and value<self._last_now):
            self._drop('UNKNOWN_RETAIN');raise LiveSessionRefusal('LIVE_SESSION_CLOCK')
        self._last_now=value;return value

    def _metadata(self):
        r=self._receipt
        return dict(source_domain='editor_live_at_capture',source_view='editor_live_at_capture',
            capture_id=r.request_id,capture_version=r.revision,captured_at=r.sampled_at,
            valid_until=r.valid_until,object_uuid=r.target.object_uuid,property_uuid=r.target.property_uuid,
            root_uuid=r.binding.root_uuid,process_id=r.binding.process_id,birth=r.binding.birth,
            operation_id=r.binding.operation_id,scope_sha256=r.binding.scope_sha256,
            source_sha256=r.source_sha256,byte_count=r.byte_count,utf16_units=r.utf16_units,
            bom_present=r.bom_present,crlf_count=r.crlf_count,ends_lf=r.ends_lf,
            document_modified_at_capture=bool(r.before_state[11]),document_readonly_at_capture=bool(r.before_state[12]),
            text_manager_modified_at_capture=bool(r.before_state[19]),undo_available_at_capture=bool(r.before_state[20]),
            capture_read_verified=True,state_preservation_verified=True,current_editor_unchanged_verified=False,
            native_attestation_performed=False,source_body_included=False,
            native_read_performed=False,writer_authorized=False,mcp_transport_integrated=False,
            body_retained=self._body is not None,index_status=self._index_status)

    def _usable(self,capture_id,target=None):
        _need(type(capture_id) is str and capture_id==self._request.request_id,'CAPTURE_ID')
        _need(target is None or (type(target) is source.LiveTarget and target==self._request.target),'TARGET')
        now=self._now()
        if now>self._receipt.valid_until:self._drop('EXPIRED')
        _need(self._state=='READY' and self._body is not None,'CLOSED_OR_EXPIRED')

    def observe(self,capture_id):
        with self._lock:
            self._usable(capture_id);return _bounded(dict(self._metadata(),status='CAPTURE_OBSERVED'))

    def health(self):
        with self._lock:
            now=self._now()
            if self._state=='READY' and now>self._receipt.valid_until:self._drop('EXPIRED')
            return _bounded(dict(self._metadata(),status=self._state))

    def read_slice(self,capture_id,target,offset=0,count=4096,expected_sha256=None):
        with self._lock:
            self._usable(capture_id,target)
            _need(_int(offset,0,131072) and _int(count,1,16384),'SLICE_BOUND')
            _need(expected_sha256 is None or (type(expected_sha256) is str and expected_sha256==self._receipt.source_sha256),'SOURCE_HASH')
            _need(offset==0 or expected_sha256==self._receipt.source_sha256,'PAGE_HASH')
            _need(offset<=len(self._body),'OFFSET_AFTER_END');end=min(offset+count,len(self._body))
            return _bounded(dict(self._metadata(),status='SOURCE_SLICE',source_body_included=True,text=self._body[offset:end],offset=offset,
                next_offset=end if end<len(self._body) else None,total_code_points=len(self._body),
                position_unit='unicode_code_points',offset_base=0))

    def search_symbols(self,capture_id,query='',limit=25,offset=0):
        with self._lock:
            self._usable(capture_id)
            _need(type(query) is str and len(query)<=256 and _int(limit,1,100) and _int(offset,0,100000),'QUERY_BOUND')
            _need(self._index is not None,'UNINDEXABLE')
            rows=self._index.search_symbols(query)
            return _bounded(dict(self._metadata(),status='SYMBOLS',matches=rows[offset:offset+limit],total=len(rows),
                                 coverage='captured_module_only'))

    def get_context(self,capture_id,target,method_name):
        with self._lock:
            self._usable(capture_id,target)
            _need(type(method_name) is str and 0<len(method_name)<=256,'METHOD_BOUND')
            _need(self._index is not None,'UNINDEXABLE')
            result=self._index.get_context(self._index_target,method_name)
            return _bounded(dict(self._metadata(),context=result,status=result['status']))

    def close(self):
        with self._lock:
            self._drop('CLOSED');return dict(status='CLOSED',body_retained=False,writer_authorized=False)
