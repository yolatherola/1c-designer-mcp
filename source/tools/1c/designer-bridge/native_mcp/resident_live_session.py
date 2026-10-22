"""Bounded RAM captures over an explicitly owned resident LIVE provider.

Callbacks are constructor-only trusted ports. This module does not attach a
process, install native code, infer current-editor state, or read saved sources.
"""
from dataclasses import dataclass, field
from collections import OrderedDict
import hashlib
import inspect
from pathlib import Path
import re
import threading
import time

SOURCE_SHA='49d2b0aa1b5a97a8a36164a408fe898fd6d7ef99618e26af0909c21a70267773'
HELPERS_SHA='a421f915d83e95bfc9f3c2dec5778160b232afb4d2aa251d09658cdb32427851'
METHOD_CONTEXT_SHA='1fb0370558a75cc7ef3b613f8a6bcc3020bc92535f9fb0bce76c0d6e61d258c4'
ANALYZER_SHA='82f72384fd47fe54861907bf4e74fe076dee7703f91ee8f76dd713de8c394334'
COMMAND_SHA = '844a3effbeecd275e1249b1207b76d905d23bca93ea8f99ea8030e40e7c6a8ee'
for _name,_sha in (('resident_live_source.py',SOURCE_SHA),('live_session.py',HELPERS_SHA),
                  ('method_context.py',METHOD_CONTEXT_SHA),('ram_bsl_analysis.py',ANALYZER_SHA),
                  ('editor_command.py',COMMAND_SHA)):
    if hashlib.sha256(Path(__file__).with_name(_name).read_bytes()).hexdigest()!=_sha:
        raise ValueError('RESIDENT_LIVE_SESSION_DEPENDENCY_PIN')
from . import resident_live_source as source
from .live_session import _make_index, _bounded, _plain
from .method_context import build_method_context
from . import ram_bsl_analysis as syntax

MAX_RESPONSE=131072
MAX_CAPTURES=8


class ResidentLiveSessionRefusal(ValueError):
    """Stable body-free refusal; never reflects a provider/decoder message."""


def _need(ok,code):
    if not ok:raise ResidentLiveSessionRefusal('RESIDENT_LIVE_SESSION_'+code)


@dataclass(slots=True)
class _Capture:
    request: source.ResidentLiveReadRequest
    receipt: source.ResidentLiveReceipt
    body: str|None=field(repr=False)
    index: object=field(repr=False)
    index_target: object
    index_status: str


class ResidentLiveSession:
    """Serialize trusted READs, cache <=8 targets, and close only explicitly.

    Expiry/local close removes this object's body/index references, not copies
    already returned to callers. Frontend EOF has no effect on this lifetime.
    """
    def __init__(self,binding,read_callback,close_callback,*,clock=time.monotonic,previous_sequence=0):
        _need(type(binding) is source.ResidentLiveBinding,'BINDING');binding.validate()
        _need(callable(read_callback) and callable(close_callback) and callable(clock)
              and not inspect.iscoroutinefunction(read_callback) and not inspect.iscoroutinefunction(close_callback),'PORTS')
        _need(source._int(previous_sequence,0,64),'PREVIOUS_SEQUENCE')
        self._binding=binding;self._read=read_callback;self._close=close_callback;self._clock=clock
        self._lock=threading.RLock();self._entries=OrderedDict();self._sequence=previous_sequence
        self._nonces=set();self._state='READY';self._last_now=None;self._inflight=False
        self._close_attempted=False;self._closed_result=None
        self._syntax_blocked=False
        with self._lock:self._now()

    def __repr__(self):return '<ResidentLiveSession '+self._state+' captures=privateRAM>'

    def _drop(self):
        for entry in self._entries.values():entry.body=None;entry.index=None
        self._entries.clear()

    def _seal(self):self._state='UNKNOWN_RETAIN';self._drop()

    def _now(self):
        value=None
        try:value=self._clock()
        except Exception:pass
        if not source._finite(value) or value<0 or (self._last_now is not None and value<self._last_now):
            self._seal();raise ResidentLiveSessionRefusal('RESIDENT_LIVE_SESSION_CLOCK')
        self._last_now=value
        for entry in self._entries.values():
            if value>entry.receipt.valid_until:entry.body=None;entry.index=None
        return value

    def _target(self,object_uuid,property_uuid=source.PROPERTY_UUID):
        target=source.ResidentLiveTarget(object_uuid,property_uuid);target.validate();return target

    def _entry(self,capture_id,target=None,*,metadata_only=False):
        _need(not self._inflight and self._state=='READY','PHASE')
        now=self._now()
        _need(source._hex(capture_id,32),'CAPTURE_ID')
        if target is not None:
            _need(type(target) is source.ResidentLiveTarget,'TARGET_TYPE');target.validate()
        entry=next((row for row in self._entries.values() if row.request.request_id==capture_id),None)
        _need(entry is not None and (target is None or target==entry.request.target),'CAPTURE_TARGET')
        if not metadata_only:_need(now<=entry.receipt.valid_until and entry.body is not None,'EXPIRED')
        return entry

    def _metadata(self,entry):
        r=entry.receipt
        return dict(source_domain=source.SOURCE_DOMAIN,capture_id=r.request_id,capture_version=r.revision,
            sequence=r.sequence,operation_id=r.binding.operation_id,scope_sha256=r.binding.scope_sha256,
            object_uuid=r.target.object_uuid,property_uuid=r.target.property_uuid,root_uuid=r.binding.root_uuid,
            class_uuid=r.native_class_uuid,process_id=r.binding.process_id,birth=r.binding.birth,
            captured_at=r.sampled_at,valid_until=r.valid_until,source_sha256=r.source_sha256,
            byte_count=r.byte_count,utf16_units=r.utf16_units,bom_present=r.bom_present,
            crlf_count=r.crlf_count,ends_lf=r.ends_lf,document_modified_at_capture=bool(r.before_state[11]),
            document_readonly_at_capture=bool(r.before_state[12]),text_manager_modified_at_capture=bool(r.before_state[19]),
            capture_read_verified=True,state_preservation_verified=True,job_resources_closed=True,
            current_editor_unchanged_verified=False,native_attestation_performed=False,writer_authorized=False,
            source_body_included=False,body_retained=entry.body is not None,index_status=entry.index_status,
            installation_remains_resident=self._state!='CLOSED')

    def _capture(self,target):
        now=self._now()
        _need(self._state=='READY' and not self._inflight,'PHASE')
        _need(self._binding.installed_at<=now<=self._binding.valid_until,'INSTALLATION_EXPIRED')
        _need(self._sequence<64,'READ_BUDGET')
        old=self._entries.get(target.object_uuid)
        self._inflight=True;failed=False;text=None
        result=snapshot=request=entry=index=index_target=None
        try:
            result=self._read(target.object_uuid)
            if inspect.iscoroutine(result):result.close()
            _need(not inspect.isawaitable(result),'ASYNC_PROVIDER')
            _need(type(result) is tuple and len(result)==2,'PROVIDER_RESULT')
            snapshot,request=result
            _need(type(request) is source.ResidentLiveReadRequest and type(request.binding) is source.ResidentLiveBinding
                  and request.binding==self._binding and request.target==target,'PROVIDER_JOIN')
            now=self._now()
            text=source.validate_snapshot(snapshot,request,target,now,previous_sequence=self._sequence)
            _need(request.request_id not in self._nonces,'NONCE_REPLAY')
            _need(old is None or request.revision>old.request.revision,'REVISION_REPLAY')
            self._sequence=request.sequence;self._nonces.add(request.request_id)
            index,index_target,index_status=_make_index(request,text)
            entry=_Capture(request,snapshot.receipt,text,index,index_target,index_status)
            if old is not None:old.body=None;old.index=None;self._entries.pop(target.object_uuid)
            if len(self._entries)>=MAX_CAPTURES:
                _,evicted=self._entries.popitem(last=False);evicted.body=None;evicted.index=None
            self._entries[target.object_uuid]=entry
            self._now()  # Index work may consume the remaining capture TTL.
            return _bounded(dict(self._metadata(entry),status='LIVE_CAPTURE_OBSERVED',native_read_performed=True))
        except BaseException:failed=True;self._seal()
        finally:self._inflight=False;text=None
        if failed:
            result=snapshot=request=entry=index=index_target=old=None
            raise ResidentLiveSessionRefusal('RESIDENT_LIVE_SESSION_PROVIDER_UNPROVEN') from None

    def health(self):
        with self._lock:
            now=self._now()
            status='BUSY' if self._inflight else self._state
            if status=='READY' and now>self._binding.valid_until:status='EXPIRED'
            elif status=='READY' and self._sequence>=64:status='BUDGET_EXHAUSTED'
            return _bounded(dict(status=status,source_domain=source.SOURCE_DOMAIN,
                operation_id=self._binding.operation_id,scope_sha256=self._binding.scope_sha256,
                installation_valid_until=self._binding.valid_until,last_sequence=self._sequence,
                captures=[self._metadata(entry) for entry in self._entries.values()],
                body_retained=any(x.body is not None for x in self._entries.values()),
                native_read_performed=False,writer_authorized=False,current_editor_unchanged_verified=False,
                native_connection_closed=self._state=='CLOSED',close_attempted=self._close_attempted,
                syntax_analysis_blocked=self._syntax_blocked))

    def open_live_session(self,object_uuid):
        with self._lock:return self._capture(self._target(object_uuid))

    def refresh_observed(self,capture_id):
        with self._lock:
            entry=self._entry(capture_id,metadata_only=True)
            return self._capture(entry.request.target)

    def observe_module(self,capture_id,target):
        with self._lock:return _bounded(dict(self._metadata(self._entry(capture_id,target)),status='CAPTURE_OBSERVED',native_read_performed=False))

    def read_module_slice(self,capture_id,target,offset=0,count=4096,expected_sha256=None):
        with self._lock:
            entry=self._entry(capture_id,target)
            _need(source._int(offset,0,131072) and source._int(count,1,16384),'SLICE_BOUND')
            _need(expected_sha256 is None or (type(expected_sha256) is str and expected_sha256==entry.receipt.source_sha256),'SOURCE_HASH')
            _need(offset==0 or expected_sha256==entry.receipt.source_sha256,'PAGE_HASH')
            _need(offset<=len(entry.body),'OFFSET_AFTER_END');end=min(offset+count,len(entry.body))
            return _bounded(dict(self._metadata(entry),status='SOURCE_SLICE',source_body_included=True,
                text=entry.body[offset:end],offset=offset,next_offset=end if end<len(entry.body) else None,
                total_code_points=len(entry.body),position_unit='unicode_code_points',offset_base=0,native_read_performed=False))

    def search_symbols(self,capture_id,query='',limit=25,offset=0):
        with self._lock:
            entry=self._entry(capture_id)
            _need(type(query) is str and len(query)<=256 and source._int(limit,1,100) and source._int(offset,0,100000),'QUERY_BOUND')
            _need(entry.index is not None,'UNINDEXABLE');rows=entry.index.search_symbols(query)
            return _bounded(dict(self._metadata(entry),status='SYMBOLS',matches=rows[offset:offset+limit],
                total=len(rows),coverage='captured_module_only',native_read_performed=False))

    def get_context(self,capture_id,target,method_name):
        with self._lock:
            entry=self._entry(capture_id,target)
            _need(type(method_name) is str and 0<len(method_name)<=256,'METHOD_BOUND')
            _need(entry.index is not None,'UNINDEXABLE')
            row=build_method_context(entry.index,entry.index_target,method_name,entry.body)
            return _bounded(dict(self._metadata(entry),status=row['status'],context=row,native_read_performed=False,
                source_body_included=row['body_included']))

    def analyze_syntax(self,capture_id,target,expected_sha256):
        """Syntax-check this exact RAM capture, never reread or attest the editor.

        Capture revision is an analyzer document version, not a repository or
        platform version. A failed local analyzer never seals native ownership.
        Unknown local cleanup blocks further analysis, while reads/close remain.
        """
        with self._lock:
            entry=body=module=result=checked=receipt=None;failed=False
            try:
                entry=self._entry(capture_id,target)
                _need(not self._syntax_blocked,'SYNTAX_BLOCKED')
                receipt=entry.receipt;body=entry.body
                _need(type(expected_sha256) is str and source._hex(expected_sha256,64)
                      and expected_sha256==receipt.source_sha256,'SOURCE_HASH')
                module=syntax.ModuleText.from_text(body)
                _need(module.sha256==expected_sha256,'SOURCE_HASH')
                self._inflight=True
                try:
                    result=syntax.analyze_syntax(module,version=receipt.revision)
                    _need(type(result) is syntax.RamSyntaxResult and type(result.source_sha256) is str
                          and result.source_sha256==expected_sha256
                          and type(result.version) is int and result.version==receipt.revision
                          and type(result.diagnostics) is tuple and len(result.diagnostics)<=syntax.MAX_DIAGNOSTICS,
                          'SYNTAX_RESULT')
                    rows=[]
                    for diagnostic in result.diagnostics:
                        _need(type(diagnostic) is syntax.SyntaxDiagnostic,'SYNTAX_RESULT')
                        rows.append(dict(code=diagnostic.code,severity=diagnostic.severity,range=dict(
                            start=dict(line=diagnostic.start_line,character=diagnostic.start_character),
                            end=dict(line=diagnostic.end_line,character=diagnostic.end_character))))
                    checked=syntax._diagnostics(dict(uri='captured_snapshot',version=receipt.revision,diagnostics=rows),
                        uri='captured_snapshot',source=module,version=receipt.revision)
                    _need(result==checked,'SYNTAX_RESULT')
                except syntax.RamBslRefusal as error:
                    if (not re.fullmatch(r'RAM_BSL_[A-Z_]+',str(error))
                            or str(error)=='RAM_BSL_PIPE_CLEANUP'):
                        self._syntax_blocked=True
                    raise
                except Exception:
                    self._syntax_blocked=True
                    raise
                finally:
                    self._inflight=False
                # Analysis can consume the remaining TTL. Recheck without a
                # native read, and never publish an expired/replaced capture.
                _need(self._entry(capture_id,target) is entry and entry.body is body
                      and entry.receipt is receipt,'SYNTAX_CAPTURE_CHANGED')
                return _bounded(dict(self._metadata(entry),status='CAPTURE_SYNTAX_ANALYZED',
                    analysis_basis='captured_snapshot',syntax_only=True,syntax_valid=not rows,
                    position_unit='utf16_code_units',position_base=0,diagnostics=rows,
                    native_read_performed=False,syntax_analysis_blocked=False))
            except Exception:
                failed=True
            if failed:
                entry=body=module=result=checked=receipt=None
                raise ResidentLiveSessionRefusal('RESIDENT_LIVE_SESSION_SYNTAX_REFUSED')

    def close_live_session(self,capture_id):
        with self._lock:
            entry=self._entry(capture_id,metadata_only=True)
            entry.body=None;entry.index=None;self._entries.pop(entry.request.target.object_uuid)
            return dict(status='LIVE_CAPTURE_CLOSED',capture_id=capture_id,body_retained=False,native_connection_closed=False)

    def close_live_connection(self):
        with self._lock:
            if self._state=='CLOSED':return dict(self._closed_result)
            _need(not self._inflight and not self._close_attempted,'CLOSE_PHASE')
            self._close_attempted=True;self._state='CLOSING';self._inflight=True
            self._drop();failed=False;row=None
            try:
                row=self._close()
                if inspect.iscoroutine(row):row.close()
                _need(not inspect.isawaitable(row),'ASYNC_CLOSE')
                _need(type(row) is dict and row.get('kind')=='LIVE_RESIDENT_RESULT'
                    and row.get('operationId')==self._binding.operation_id
                    and row.get('scopeSha256')==self._binding.scope_sha256
                    and row.get('actualSourceSha256')==self._binding.reader_source_sha256
                    and row.get('compiledSourceSha256')==self._binding.compiled_source_sha256
                    and row.get('sourceDomain')==source.SOURCE_DOMAIN
                    and row.get('status')=='LIVE_RESIDENT_RESOURCES_CLOSED'
                    and row.get('knownTerminal') is True and row.get('resourcesClosed') is True
                    and row.get('retryAuthorized') is False and row.get('sourceBodyPersisted') is False
                    and row.get('currentEditorUnchangedVerified') is False
                    and type(row.get('reads')) is int and row['reads']==self._sequence
                    and all(type(row.get(key)) is int and row[key]==0 for key in ('workerResult','hostExitCode')),'ROOT_CLOSURE')
            except BaseException:failed=True;self._seal()
            finally:self._inflight=False
            if failed:
                row=None
                raise ResidentLiveSessionRefusal('RESIDENT_LIVE_SESSION_CLOSE_UNPROVEN') from None
            self._state='CLOSED'
            self._closed_result=dict(status='LIVE_RESIDENT_RESOURCES_CLOSED',knownTerminal=True,resourcesClosed=True,
                operation_id=self._binding.operation_id,reads=self._sequence,workerResult=0,hostExitCode=0,
                body_retained=False,native_connection_closed=True,retry_authorized=False)
            return dict(self._closed_result)
