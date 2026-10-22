"""Workday v234 saved-database provider; protocol3, one 28800s carrier.

Root supplies the physical identity/lease gate and managed-host join. The channel
must run the synchronous validator before ACK. Only pinned pure classifier code
is loaded; no legacy getter, source path, native SDK call, or body cache is used.
"""
import ast
import hashlib
import inspect
from pathlib import Path
import re
import threading
import time
from types import MappingProxyType,SimpleNamespace
from uuid import uuid4

from . import workday_wire as wire,session_lifecycle
from .saved_source import (SourceBinding,Target,ReadRequest,GuardState,SavedRefusal,
                           finite,integer,digest)
from .session_lifecycle import BindingRequest,SessionIdentity,SessionPorts,ShutdownReceipt

ROOT_UUID='218b5d00-7e10-486f-874c-73c2368ed5da'
DATABASE_ROOT=1383504556
DATABASE_MANAGER=100051712
PINS={
    'workday_wire.py':'06945271bfa4f22a474e400587ba8d558c4e6a8be2821ad9c4592bdd14790f46',
    'session_lifecycle.py':'458ef6898abad4623ed96ad0a246929828df3c1a33b2d0be257c460945fc4b3e',
    'workday_ram_carrier.py':'ff59538b81fd2266e3e9f62912d79c20fb1f30b932c650a6659de0e1855f5f25',
    'persistent_ram_carrier.py':'5fede18cce44dd9a1f465907deccdcbeffd209c5d43f2dcc022cb54f82feaf04',
    'native_ram_carrier.py':'c75ca413a26e5cccb6f4ff68f9a3d4e88ae5b9b960560e408afa0b606cdf1301',
    'comparison_cpp_exception_type_epoch.py':'e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4',
}
_CONFIG_KEYS={'operationId','scopeSha256','sessionId','installNonce','serverPid','serverBirth','pipePath',
              'installedAt','sessionValidUntil','armPath','resultPath'}
_IDENTITY_KEYS={'processId','birth','guiThreadId','engineAddress','moduleAddress'}
_ZERO_SOURCE=('bodyBytes','codePoints','crlfCount','bomPresent','endsLf','passes','propertyReads',
              'fileOpens','adoptedFiles','storedBytes')
_HEADER_FIELDS=(*_ZERO_SOURCE,'nativeStatus','nativeReason','pendingReference','beforeClean','afterClean',
                'prefixPreserved','typedCleared','nativeException','databaseRoot','databaseManager')


def _need(ok,code):
    if not ok:raise SavedRefusal('SAVED_WORKDAY_'+code)


def _hex(value,length):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None and value!='0'*length


def _sync(callback,*args):
    value=callback(*args)
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value):value.close()
        raise SavedRefusal('SAVED_WORKDAY_ASYNC_CALLBACK')
    return value


def _classifier():
    """Reuse exact frozen function bodies in an isolated, pure namespace."""
    here=Path(__file__).resolve().parent;research=here.parent/'research'
    trees={}
    for name,pin in PINS.items():
        raw=((research if name in ('workday_ram_carrier.py','persistent_ram_carrier.py','native_ram_carrier.py',
                                    'comparison_cpp_exception_type_epoch.py') else here)/name).read_bytes()
        _need(hashlib.sha256(raw).hexdigest()==pin,'DEPENDENCY_PIN')
        if name.endswith('carrier.py') or name=='comparison_cpp_exception_type_epoch.py':trees[name]=ast.parse(raw)
    def functions(tree,names,namespace):
        nodes=[node for node in tree.body if type(node) is ast.FunctionDef and node.name in names]
        _need(len(nodes)==len(names),'CLASSIFIER_FUNCTIONS')
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pinned-resident-classifier>','exec'),namespace)
    helpers={'re':re}
    functions(trees['native_ram_carrier.py'],{'_hex','_uint'},helpers)
    assignments=[node.value for node in trees['comparison_cpp_exception_type_epoch.py'].body
                 if type(node) is ast.Assign and any(type(x) is ast.Name and x.id=='PROFILE' for x in node.targets)]
    _need(len(assignments)==1,'CLASSIFIER_PROFILE')
    profile=ast.literal_eval(assignments[0]);_need(type(profile) is str,'CLASSIFIER_PROFILE')
    namespace={'fixed':SimpleNamespace(_hex=helpers['_hex'],_uint=helpers['_uint'],epoch=SimpleNamespace(PROFILE=profile))}
    functions(trees['persistent_ram_carrier.py'],{'need','classify_epoch'},namespace)
    return namespace['classify_epoch']


class WorkdayResidentProvider:
    """One resident instance, generation-bound ports and one-use GUARD tickets.

    managed_join is called only after validated CLOSE/ACK/EOF and must return the
    root-composed host/SDK terminal dict. It does not run on channel owner. This
    adapter never fabricates physical identity from a receipt's boolean claims.
    """
    def __init__(self,channel,configuration,identity,*,fresh_identity_gate,managed_join,
                 clock=time.monotonic,command_ttl=5.0):
        self._classify_epoch=_classifier()
        _need(wire.MAX_SEQUENCE==4096,'WIRE_PROFILE')
        _need(type(configuration) is dict and configuration.keys()==_CONFIG_KEYS,'CONFIG_SCHEMA')
        _need(type(identity) is dict and identity.keys()==_IDENTITY_KEYS,'IDENTITY_SCHEMA')
        _need(all(_hex(configuration[k],n) for k,n in (('operationId',32),('scopeSha256',64),('sessionId',32),
                                                       ('installNonce',32),('serverBirth',16)))
              and integer(configuration['serverPid'],1,2**32-1),'CONFIG_IDENTITY')
        _need(all(integer(identity[k],1,2**32-1) for k in ('processId','guiThreadId','engineAddress','moduleAddress'))
              and identity['guiThreadId']==8292 and _hex(identity['birth'],16),'IDENTITY')
        _need(finite(configuration['installedAt']) and finite(configuration['sessionValidUntil'])
              and 0<=configuration['installedAt']<configuration['sessionValidUntil']<=configuration['installedAt']+28800,
              'INSTALL_TIME')
        _need(type(configuration['pipePath']) is str and channel.path==configuration['pipePath']
              and all(callable(getattr(channel,k,None)) for k in ('exchange','wait_closed')),'CHANNEL')
        _need(all(callable(c) and not inspect.iscoroutinefunction(c) for c in (fresh_identity_gate,managed_join,clock)),'CALLBACK')
        _need(finite(command_ttl) and 0<command_ttl<=5,'TTL')
        self.channel=channel
        self.configuration=MappingProxyType(dict(configuration));self.identity=MappingProxyType(dict(identity))
        self._expected=SessionIdentity(ROOT_UUID,configuration['sessionId'],identity['processId'],identity['birth'],'database_saved')
        self._expected.binding(1,1.0)
        self._fresh_identity_gate=fresh_identity_gate;self._managed_join=managed_join;self._clock=clock;self._ttl=command_ttl
        self._lock=threading.Lock();self._last_now=None;self._binding=None;self._generation=0
        self._sequence=0;self._contexts=0;self._worker=None;self._last_guard=None;self._close_attempted=False
        self._native_binding=None
        self.state='UNOPENED'

    def _enter(self):_need(self._lock.acquire(blocking=False),'BUSY')

    def _now(self):
        value=_sync(self._clock)
        _need(finite(value) and value>=0 and (self._last_now is None or value>=self._last_now),'CLOCK')
        self._last_now=value;return value

    def _fresh(self,*,allow_expired=False):
        value=_sync(self._fresh_identity_gate)
        _need(type(value) is SessionIdentity and value==self._expected,'FRESH_IDENTITY')
        now=self._now()
        if not allow_expired:
            _need(self.configuration['installedAt']<=now<self.configuration['sessionValidUntil'],'INSTALL_EXPIRED')
        return now

    def _usable(self):_need(self.state not in ('CLOSED','UNKNOWN_RETAIN'),'SEALED')

    def _unknown(self):self.state='UNKNOWN_RETAIN';self._last_guard=None

    def _binding_join(self,binding,*,allow_expired=False):
        _need(type(binding) is SourceBinding and binding==self._binding,'BINDING')
        now=self._fresh(allow_expired=allow_expired)
        if not allow_expired:_need(now<=binding.valid_until,'BINDING_EXPIRED')
        return now

    def make_ports(self,request):
        """Renew metadata only; no GUARD, body, storage, or channel dispatch."""
        self._enter()
        try:
            self._usable();now=self._now()
            _need(type(request) is BindingRequest and type(request.identity) is SessionIdentity
                  and request.identity==self._expected and _hex(request.request_id,32)
                  and integer(request.generation,1,2**53-1) and request.generation==self._generation+1
                  and finite(request.issued_at) and finite(request.valid_until)
                  and request.issued_at<=now<=request.valid_until<=request.issued_at+60,'OPEN_REQUEST')
            _need(self._binding is None or now>self._binding.valid_until,'GENERATION_ACTIVE')
            checked=self._fresh()
            valid_until=min(request.valid_until,self.configuration['sessionValidUntil'])
            _need(checked<=valid_until,'OPEN_EXPIRED')
            binding=self._expected.binding(request.generation,valid_until)
            self._binding=binding;self._generation=request.generation;self._last_guard=None
            if self.state!='BUDGET_EXHAUSTED':self.state='READY'
            return SessionPorts(request.request_id,binding,checked,self.provider,self.guard,lambda:self.current_binding(binding))
        except BaseException:
            self._unknown();raise SavedRefusal('SAVED_WORKDAY_OPEN_UNPROVEN') from None
        finally:self._lock.release()

    def current_binding(self,binding=None):
        """Fresh physical identity/lease gate only; never dispatch source."""
        self._enter()
        try:
            self._usable();self._binding_join(self._binding if binding is None else binding)
            return self._binding
        except BaseException:
            self._unknown();raise SavedRefusal('SAVED_WORKDAY_IDENTITY_UNPROVEN') from None
        finally:self._lock.release()

    def _native(self,response,command):
        p=response.proof;close=command.opcode==wire.CLOSE
        _need(response.status==(wire.CLOSED if close else wire.SUCCESS),'NATIVE_STATUS')
        _need(type(p.get('version')) is int and p['version']==3,'NATIVE_VERSION')
        _need(integer(self._sequence,0,4095) and integer(self._contexts,0,4095),'LOCAL_COUNTERS')
        _need(p['operationId']==self.configuration['operationId'] and p['scopeSha256']==self.configuration['scopeSha256']
              and p['installNonce']==self.configuration['installNonce'] and p['guiThreadId']==self.identity['guiThreadId']
              and integer(p['workerThreadId'],1,2**32-1) and p['workerThreadId']!=p['guiThreadId']
              and (self._worker is None or p['workerThreadId']==self._worker),'NATIVE_IDENTITY')
        contexts=self._contexts+(0 if close else 1)
        _need(p['compileCount']==(1 if contexts else 0) and p['contextCount']==contexts,'SDK_COUNTS')
        _need(all(p[k] is True for k in ('contextCleared','handlerRemoved','epochClean','peerVerified','readyVerified',
                                        'drainCompleted','dllSelfReferenceRetained'))
              and all(p[k] is False for k in ('pipeClosed','buffersFreed'))
              and p['hookRemoved'] is close and p['functionRetained'] is (not close)
              and p['sdkRc']==0 and p['terminalRc']==0,'NATIVE_CLOSURE')
        if close:
            _need(p['nativeEnvelopeValid'] is False and all(p[k]==0 for k in _HEADER_FIELDS)
                  and p['sourceSha256']==p['savedResourceSha256']=='' and p['guardState'] is None,'CLOSE_HEADER')
        else:
            _need(p['nativeEnvelopeValid'] is True and p['nativeStatus']==1 and p['nativeReason']==0
                  and p['nativeException']==0 and p['pendingReference']==0
                  and all(p[k]==1 for k in ('beforeClean','afterClean','prefixPreserved','typedCleared'))
                  and p['databaseRoot']==DATABASE_ROOT and p['databaseManager']==DATABASE_MANAGER,'NATIVE_ENVELOPE')
            if command.opcode==wire.GUARD:
                _need(all(p[k]==0 for k in _ZERO_SOURCE),'GUARD_SOURCE')
            else:
                _need(all(p[k]==2 for k in ('passes','propertyReads','fileOpens','adoptedFiles'))
                      and integer(p['storedBytes'],1,8*1048576)
                      and digest(p['sourceSha256']) and digest(p['savedResourceSha256']),'READ_REPEAT')
        self._classify_epoch(response.epoch,operation_id=self.configuration['operationId'],scope_sha256=self.configuration['scopeSha256'],
            process_id=self.identity['processId'],execute_thread_id=self.identity['guiThreadId'],opcode=command.opcode,
            callback_known=True,callback_sdk_rc=p['sdkRc'],target_identity_verified=True)
        return contexts,p['workerThreadId']

    def _exchange(self,command,*,guard=None,request=None):
        context=command.binding if command.opcode==wire.CLOSE else self._binding
        raw=wire.build_command(command,context=context,now=self._now(),previous_sequence=self._sequence,guard=guard,request=request)
        def validate(frame):
            response=wire.parse_response(frame,command,request=request,now=self._now())
            counts=self._native(response,command)
            after=self._fresh(allow_expired=command.opcode==wire.CLOSE)
            if command.opcode!=wire.CLOSE:_need(after<=command.valid_until,'RESPONSE_EXPIRED')
            return response,counts
        checked=_sync(self.channel.exchange,raw,validate)
        _need(type(checked) is tuple and len(checked)==2 and type(checked[0]) is wire.ResidentResponse,'CHANNEL_RESULT')
        response,(contexts,worker)=checked
        self._sequence=command.sequence;self._contexts=contexts;self._worker=worker
        self._native_binding=command.binding
        return response

    def guard(self,binding,target):
        """Fresh metadata-only GUARD; ticket consumed by exactly one next READ."""
        self._enter()
        try:
            self._usable();now=self._binding_join(binding)
            _need(self.state!='BUDGET_EXHAUSTED','COMMAND_BUDGET')
            _need(type(target) is Target,'TARGET');target.validate();_need(target.property_uuid==wire.MODULE_PROPERTY,'PROPERTY')
            if self._sequence>=4094:
                # Keep one complete GUARD/READ pair plus a final CLOSE ticket.
                # This is known pre-dispatch exhaustion, never SDK uncertainty.
                self.state='BUDGET_EXHAUSTED';self._last_guard=None
                raise SavedRefusal('SAVED_WORKDAY_COMMAND_BUDGET')
            command=wire.ResidentCommand(wire.GUARD,self._sequence+1,binding,target,uuid4().hex,0,now,min(now+self._ttl,binding.valid_until))
            self._last_guard=None
            response=self._exchange(command)
            state=response.proof['guardState'];value=GuardState(SourceBinding(**state['binding']),Target(**state['target']),
                state['dirty_state'],state['checked_at'],state['valid_until'],state['identity_verified'])
            self._last_guard=command
            return value
        except BaseException:
            if self.state!='BUDGET_EXHAUSTED':self._unknown()
            raise SavedRefusal('SAVED_WORKDAY_GUARD_UNPROVEN') from None
        finally:self._lock.release()

    def provider(self,request):
        """Read saved source only after matching fresh GUARD; no body cache."""
        self._enter()
        try:
            self._usable();_need(type(request) is ReadRequest,'REQUEST')
            _need(self.state!='BUDGET_EXHAUSTED','COMMAND_BUDGET')
            now=self._binding_join(request.binding);guard=self._last_guard;self._last_guard=None
            _need(type(guard) is wire.ResidentCommand and guard.target==request.target and guard.binding==request.binding
                  and guard.sequence==self._sequence and finite(request.valid_until)
                  and request.valid_until<=guard.valid_until and now<=guard.valid_until,'GUARD_TICKET')
            _need(self._sequence<4095,'COMMAND_BUDGET')
            command=wire.ResidentCommand(wire.READ,self._sequence+1,request.binding,request.target,request.request_id,request.revision,
                request.issued_at,request.valid_until,guard.sequence)
            return self._exchange(command,guard=guard,request=request).snapshot
        except BaseException:
            if self.state!='BUDGET_EXHAUSTED':self._unknown()
            raise SavedRefusal('SAVED_WORKDAY_READ_UNPROVEN') from None
        finally:self._lock.release()

    def close(self):
        """CLOSE once, then require local EOF and root's actual managed closure."""
        self._enter()
        try:
            if self.state=='CLOSED':return ShutdownReceipt(True,True,True,True)
            _need(not self._close_attempted,'CLOSE_ALREADY_ATTEMPTED');self._close_attempted=True
            self._usable()
            now=self._fresh(allow_expired=True) if self._binding is None else self._binding_join(self._binding,allow_expired=True)
            # Metadata-only make_ports may advance a host generation without
            # a native command. CLOSE must still match C's last accepted one.
            close_binding=self._native_binding or self._binding
            if close_binding is None:
                # Connected-but-unopened cleanup is metadata only. No ports,
                # GUARD, source, or hidden function compilation are introduced.
                close_binding=self._expected.binding(1,min(now+self._ttl,self.configuration['sessionValidUntil']))
            command=wire.ResidentCommand(wire.CLOSE,self._sequence+1,close_binding,None,uuid4().hex,0,now,now+self._ttl)
            self._last_guard=None;self._exchange(command)
            _need(_sync(self.channel.wait_closed,self._ttl) is True and self.channel.closed is True,'LOCAL_CLOSE')
            row=_sync(self._managed_join)
            keys={'kind','operationId','knownTerminal','sdkResult','threadId','hookWorkersReleased','writerAuthorized',
                  'processId','processExitCode','rawSdkResult'}
            _need(type(row) is dict and row.keys()==keys and row['kind']=='RESIDENT_MANAGED_TERMINAL'
                  and row['operationId']==self.configuration['operationId']
                  and all(row[k] is True for k in ('knownTerminal','hookWorkersReleased')) and row['writerAuthorized'] is False
                  and all(type(row[k]) is int and row[k]==0 for k in ('sdkResult','rawSdkResult','processExitCode'))
                  and type(row['processId']) is int and row['processId']==self.identity['processId']
                  and type(row['threadId']) is int and row['threadId']==self.identity['guiThreadId'],'MANAGED_CLOSE')
            self.state='CLOSED';return ShutdownReceipt(True,True,True,True)
        except BaseException:
            self._unknown();raise SavedRefusal('SAVED_WORKDAY_CLOSE_UNPROVEN') from None
        finally:self._lock.release()
