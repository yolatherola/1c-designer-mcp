"""Diagnostic successor with exact retained-failure admission and fresh checks.

Exact component pins are checked before preparation; missing pins refuse it.
No body is stored by this controller; a returned snapshot belongs to its caller.
Only Root may prepare/stage/start against the approved native process.
"""
from dataclasses import dataclass
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from types import FunctionType, SimpleNamespace
import uuid

import live_module_ram_operation as ram
import live_module_ram_closure as closed_ram

c,reader,base,workday=ram.c,ram.reader,ram.base,ram.workday
HERE,ROOT=ram.HERE,ram.ROOT
sys.path.insert(0,str(HERE.parent))
from native_mcp import resident_live_source as source

PROFILE='COMMON_MODULE_LIVE_RESIDENT_DIAGNOSTIC'
SCOPE_KIND='ROOT_LIVE_RESIDENT_DIAGNOSTIC_SCOPE'
RUN_KIND='ROOT_LIVE_RESIDENT_DIAGNOSTIC_RUN'
ORIGINAL_CONTROLLER_SHA='43be4e69b235e29bdfebd010441ef65c2de1e16d405533729b38013d8197daf5'
FAILED_OPERATION='06b6deb40ec745ba869f4bd5f6778b8c'
FAILED_PLAN_SHA='ef15ded21b88bfc197a93fea154f46415c370d3deff2a477cec4847474cecfa5'
FAILED_AUDIT_SHA='9aaf4244b6a5fe1b6cf1adcd1db1a3e11553e03b8c2969ffa4bba174f4edd8f2'
FAILED_WINDOWS_SHA='cbc8315d4ea08f5adc3a1b64543a2f724fa4ed75f1130cc0e4199755455ca477'
FAILED_CLASSIFICATION='FAILED_READ_QUIESCENT_METADATA_RETAINED'
SOURCE_NAME='NativeLiveCommonModuleRam.as'
SOURCE_SHA='ba8fa5ca3ed3b13502d0a08f43bffe460bdd1eb7d0c611c667b173ce9d05048d'
PREVIOUS_SHA='953263e96beb27d42b066e04389a8a891a3f487e960c18507d0f6d3fa5b43c4b'
CLOSURE_SHA='7da33bad38a70785c7bebbe081dccc28189dc38dc04a1416d2ee55964f10fbf4'
JOB_SHA='2c5aff430aafbc9d3ddec1cd73de23ebe8f5b6b3006262db90e8e574968d5223'
SOURCE_CONTRACT_SHA='49d2b0aa1b5a97a8a36164a408fe898fd6d7ef99618e26af0909c21a70267773'
CARRIER_SHA='bfcadd5894c49a5a9ff6dd8e297fbdd2101164e9892a761716a087fce7772fd0'
WIRE_SHA='28cbe004e96cc8e330e102d281d7fa3af185d77745d0f6c9bae7e166c969d104'
PIPE_SHA='1ee81e3433d09c39eabfcc4b9852accd1fe9b9525247f6fcf938e8c441c48f13'
SUCCESS_OPERATION='3ec23ead1a204330bbe0f9b396bda7fd'
SUCCESS_PLAN_SHA='762aa07b21602f68b5318b94aec3c894f69e93dc8cbda1213e34d29555e55882'
SUCCESS_HOST_PID=21588
SUCCESS_HOST_BIRTH='01dd5f21dc1b86f9'
ARM_FILE='live-resident-arm.bin'
WORKER_FILE='live-resident-worker-result.bin'
HOST_READY='live-resident-host-ready.json'
HOST_RESULT='live-resident-host-result.json'
TRUE_AUTH=ram.TRUE_AUTH+('arbitraryCommonModuleSelectionAuthorized',
    'sdkExceptionLineMetadataReadAuthorized','runtimeTerminalDiagnosticWriteAuthorized')
FALSE_AUTH=ram.FALSE_AUTH
_ISSUER=object();_SEAL_ISSUER=object();_SEALS={}


def need(ok,code):
    if not ok:raise ValueError('LIVE_RESIDENT_DIAGNOSTIC_OPERATION_'+code)


def limits():
    # Direct-save/state budgets apply to each fresh READ, not to installation.
    return dict(ram.limits(),maximumReads=64,maximumSessionSeconds=600)


def authority(row):
    return type(row) is dict and all(row.get(k) is True for k in TRUE_AUTH) \
        and all(row.get(k) is False for k in FALSE_AUTH) \
        and all(type(row.get(k)) is int and row[k]==v for k,v in limits().items())


def _module(name,pin):
    need(ram.previous._hex(pin,64),'DEPENDENCY_NOT_FROZEN')
    return ram._module(name,pin)


def _pins():
    need(c.digest(c.read(HERE/'live_resident_operation.py'))==ORIGINAL_CONTROLLER_SHA,'ORIGINAL_CONTROLLER_PIN')
    _module('live_resident_failed_read_audit',FAILED_AUDIT_SHA)
    _module('live_resident_failed_read_windows',FAILED_WINDOWS_SHA)
    need(c.digest(c.read(Path(ram.__file__)))==PREVIOUS_SHA
         and c.digest(c.read(Path(closed_ram.__file__)))==CLOSURE_SHA,'FROZEN_BASE_PIN')
    ram._pins()
    need(c.digest(c.read(HERE/SOURCE_NAME,32768))==SOURCE_SHA
         and c.digest(c.read(Path(source.__file__)))==SOURCE_CONTRACT_SHA,'SOURCE_PIN')
    _module('live_resident_job',JOB_SHA)
    _module('live_resident_diagnostic_carrier',CARRIER_SHA)
    _module('native_mcp.resident_live_wire',WIRE_SHA)
    _module('native_mcp.windows_resident_live_pipe',PIPE_SHA)


def validate_scope(row):
    need(type(row) is dict and row.get('kind')==SCOPE_KIND and row.get('profile')==PROFILE
         and row.get('passed') is True and row.get('oneInstallation') is True and authority(row)
         and row.get('sourceDomain')==source.SOURCE_DOMAIN and row.get('allowedReadClasses')==['CommonModule']
         and row.get('modulePropertyId')==source.PROPERTY_UUID and row.get('rootUuid')==source.ROOT_UUID
         and row.get('actualSourceSha256')==SOURCE_SHA
         and row.get('liveResidentControllerSha256')==c.digest(c.read(Path(__file__)))
         and row.get('liveResidentJobSha256')==JOB_SHA and row.get('liveRamClosureSha256')==CLOSURE_SHA
         and row.get('priorRamSuccessOperationId')==SUCCESS_OPERATION and row.get('priorRamSuccessPlanSha256')==SUCCESS_PLAN_SHA,'SCOPE')
    need(row.get('priorFailedReadOperationId')==FAILED_OPERATION
         and row.get('priorFailedReadPlanSha256')==FAILED_PLAN_SHA
         and ram.previous._hex(FAILED_AUDIT_SHA,64) and row.get('failedReadAuditSha256')==FAILED_AUDIT_SHA
         and ram.previous._hex(FAILED_WINDOWS_SHA,64) and row.get('failedReadWindowsSha256')==FAILED_WINDOWS_SHA,'FAILED_SCOPE')
    for key,pin in (('liveResidentCarrierSha256',CARRIER_SHA),('residentLiveWireSha256',WIRE_SHA),
                    ('residentLivePipeSha256',PIPE_SHA)):
        need(ram.previous._hex(pin,64) and row.get(key)==pin,'SCOPE_DEPENDENCY')
    need(all(workday._approved_prior_plans(row).get(k)==v for k,v in ram.previous.REQUIRED_PRIORS.items()),'WORKDAY_PRIORS')
    workday._admission_scope_pins(row)


def _success_host_terminal():
    fn=FunctionType(ram.previous._prior_host_terminal.__code__,dict(ram.previous._prior_host_terminal.__globals__,
        PRIOR_HOST_PID=SUCCESS_HOST_PID,PRIOR_HOST_BIRTH=SUCCESS_HOST_BIRTH),ram.previous._prior_host_terminal.__name__)
    return fn()


def _checked_success(prior):
    need(type(prior) is dict and prior.get('operationId')==SUCCESS_OPERATION
         and c.digest(c.canonical(prior))==SUCCESS_PLAN_SHA,'EXACT_RAM_PRIOR')
    row=closed_ram.audit_closed(prior)
    need(row.get('classification')==closed_ram.CLASSIFICATION and all(row.get(k) is True for k in
         ('nativeResourcesClosed','resourcesClosed','readBodyVerified','privateRamTransferVerified',
          'freshHostExitCheckRequired','currentTargetIdentityAndLeaseCheckRequired'))
         and type(row.get('priorHostProcessId')) is int and row['priorHostProcessId']==SUCCESS_HOST_PID
         and row.get('priorHostBirth')==SUCCESS_HOST_BIRTH and all(row.get(k) is False for k in
         ('currentIdentityVerified','currentLeaseVerified','rootOwnerExitVerified','retryAuthorized',
          'newDispatchAuthorized','unloadAuthorized','foreignUnknownWaived')),'RAM_CLOSURE')
    observed=_success_host_terminal()
    need(type(observed) is dict and observed.get('birth')==SUCCESS_HOST_BIRTH
         and all(type(observed.get(k)) is int and observed[k]==v for k,v in
                 dict(pid=SUCCESS_HOST_PID,waitZeroMilliseconds=0,exitCode=0).items()),'FRESH_RAM_HOST')
    return row


def _fresh_failed():
    row=_module('live_resident_failed_read_windows',FAILED_WINDOWS_SHA).query_failed_06b6()
    need(type(row) is dict and row.get('kind')=='LIVE_RESIDENT_FAILED_READ_WINDOWS'
         and row.get('operationId')==FAILED_OPERATION and type(row.get('processId')) is int
         and row['processId']==48936 and row.get('birth')=='01dd5d0180299126'
         and row.get('dllSha256')=='6d8c01fb3f5ae4e6d8de82944b1d0b2ebab4efb253506be26105601c989abee9'
         and all(row.get(k) is True for k in ('freshPhysicalFacts','jobRetained','queryHandlesClosed'))
         and all(row.get(k) is False for k in ('closure','resourcesClosed','retryAuthorized','newDispatchAuthorized',
             'unloadAuthorized','foreignUnknownWaived'))
         and all(type(row.get(k)) is int and row[k]==0 for k in
             ('sourceBodyBytesRead','memoryWrites','nativeCallsDispatched')),'FAILED_FRESH_FACTS')
    return row


def _checked_failed(prior):
    need(type(prior) is dict and prior.get('operationId')==FAILED_OPERATION
         and c.digest(c.canonical(prior))==FAILED_PLAN_SHA,'EXACT_FAILED_PRIOR')
    row=_module('live_resident_failed_read_audit',FAILED_AUDIT_SHA).audit_metadata(prior)
    need(type(row) is dict and row.get('classification')==FAILED_CLASSIFICATION
         and row.get('operationId')==FAILED_OPERATION and row.get('planSha256')==FAILED_PLAN_SHA
         and all(row.get(k) is False for k in ('nativeResourcesClosed','resourcesClosed','closure','bodyCaptured',
             'readSuccess','mcpAcceptanceVerified','currentIdentityVerified','currentLeaseVerified','retryAuthorized',
             'newDispatchAuthorized','unloadAuthorized','foreignUnknownWaived'))
         and all(row.get(k) is True for k in ('retainedJob','originalUnknownPreserved','metadataRetained',
             'freshQueryRequired','freshWorkerHookHostAndModuleCheckRequired','currentTargetIdentityAndLeaseCheckRequired')),'FAILED_AUDIT')
    _fresh_failed()
    _pins()  # Source/dependency checks occur after the fresh physical query too.
    return row


def _resident_factory(factory):
    # Rehome ALL helpers, not just the outer factory; preserve explicit validator.
    clone=ram.previous._private_factory(ram._ram_factory,validate_scope=validate_scope)
    factory=clone(factory);old_reader=factory.__globals__['reader'];old_inspect=factory.__globals__['inspect']
    def namespace(parent):
        ns=old_reader._namespace(parent)
        ns.update(__resident_ram_success=SUCCESS_OPERATION,__resident_ram_success_audit=_checked_success,
            __resident_failed_read=FAILED_OPERATION,__resident_failed_read_audit=_checked_failed)
        return ns
    def source_text(target):
        text=old_inspect.getsource(target)
        if target is c._no_pending:
            anchor='        if prior_identity!=identity: continue\n'
            need(text.count(anchor)==1,'PARENT_AUDIT_ANCHOR')
            text=text.replace(anchor,anchor+'        if operation==__resident_ram_success:\n            __resident_ram_success_audit(prior);continue\n',1)
            text=text.replace(anchor,anchor+'        if operation==__resident_failed_read:\n            __resident_failed_read_audit(prior);continue\n',1)
        return text
    r=SimpleNamespace(**dict(old_reader.__dict__));r._namespace=namespace
    i=SimpleNamespace(**dict(old_inspect.__dict__));i.getsource=source_text
    return ram.previous._private_factory(factory,reader=r,inspect=i,validate_scope=validate_scope)


def prepare_parent(path,pin):
    def composed(factory):return workday.admission._extra_factory(_resident_factory(factory))
    return ram.previous._private_factory(workday.admission._prepare_parent,
        validate_scope=validate_scope,_extra_factory=composed)(path,pin)


@dataclass(slots=True)
class LiveResidentOperation:
    issuer:object
    parent:object
    scope:dict
    scope_path:Path
    scope_sha256:str
    plan:dict
    plan_raw:bytes
    private:dict
    channel:object
    phase:str='PREPARED'
    host:object=None
    seal:object=None
    binding:object=None
    sequence:int=0
    join_attempted:bool=False
    inflight:bool=False


@dataclass(frozen=True,slots=True)
class _AdmissionSeal:
    issuer:object
    operation:object
    parent:object
    plan_raw:bytes
    scope_path:Path
    scope_raw:bytes
    scope_sha256:str
    parent_plan_raw:bytes
    parent_scope_raw:bytes
    parent_scope_path:Path
    parent_scope_sha256:str
    owner_pid:int
    owner_birth:str
    checkpoint_path:Path
    checkpoint_sha256:str
    reservation_path:Path
    reservation_raw:bytes
    claim_raw:bytes
    intent_raw:bytes
    foreign_markers:tuple
    wire:object
    channel:object
    channel_identity:bytes


def _claim_path(s):
    return ROOT/'artifacts/designer-bridge'/('live-resident-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='LIVE_RESIDENT_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
        controllerSha256=s.plan['liveResidentControllerSha256'],actualSourceSha256=SOURCE_SHA,
        parentWriterOperationId=q['operationId'],
        parentWriterIntentSha256=c.digest(c.canonical(q)),sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'])


def _intent(s,review_pin):
    return dict(kind='LIVE_RESIDENT_HOST_INTENT',operationId=s.plan['operationId'],
        planSha256=c.digest(s.plan_raw),rootRunSha256=review_pin,**_authority_result(s))


def _marker_snapshot(own_operation):
    rows=[];total=0
    for pattern in workday._MARKER_PATTERNS:
        prefix=pattern[:-1]
        for out in (ROOT/'build').glob(pattern):
            op=out.name.removeprefix(prefix)
            if not re.fullmatch('[0-9a-f]{32}',op) or not out.is_dir() or op==own_operation:continue
            out=c._plain(out,ROOT/'build')
            for name in ('intent.json','unknown.json'):
                path=out/name
                if path.exists():
                    raw=c.read(path,65536);total+=len(raw)
                    need(len(rows)<4096 and total<=16777216,'MARKER_BOUND')
                    rows.append((path.relative_to(ROOT/'build').as_posix(),c.digest(raw)))
    for path in (ROOT/'build').glob('designer-hot-v233-target-*.json'):
        path=c._plain(path,ROOT/'build');raw=c.read(path,8192);total+=len(raw)
        need(len(rows)<4096 and total<=16777216,'MARKER_BOUND')
        rows.append((path.relative_to(ROOT/'build').as_posix(),c.digest(raw)))
    return tuple(sorted(rows))


def _check(s):
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER,'ISSUED_OPERATION');_pins()
    p=s.plan;ctx=p['context']
    need(c.canonical(p)==s.plan_raw and p.get('version')==233 and authority(p)
         and p.get('liveResidentControllerSha256')==c.digest(c.read(Path(__file__)))
         and p.get('updatePreviewControllerSha256')==p['liveResidentControllerSha256']
         and p.get('actualSourceSha256')==SOURCE_SHA and p.get('updatePreviewProfile')==PROFILE
         and p.get('updatePreviewScopeSha256')==s.scope_sha256 and ctx==s.parent.plan['context'],'PLAN')
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256'))==
         (48936,'01dd5d0180299126',8292,ram.previous.MAIN_SHA),'NATIVE_IDENTITY')
    row=ram.previous._json(s.scope_path,s.scope_sha256);validate_scope(row);q=reader._check_owner(s.parent)
    need(row==s.scope and row.get('targets')==q['targets'] and row.get('readScopeSha256')==s.parent.review_sha256
         and Path(row.get('readScopePath','')).resolve()==s.parent.review_path.resolve()
         and (row.get('sessionNonce'),row.get('pid'),row.get('birth'),row.get('guiThreadId'),row.get('mainSha256'))==
         (ctx['heldNonce'],48936,ctx['birth'],8292,ram.previous.MAIN_SHA),'SCOPE_BINDING')
    workday._checked_prior(row);workday._audit_workday_pending(ctx,scope=row)
    for op,checker in ((ram.previous.closed_refusal.OP,ram.previous._checked_refusal),
        (ram.previous.BASELINE_OPERATION,ram.previous._checked_baseline),(ram.previous.PREOPEN_OPERATION,ram.previous._checked_preopen),
        (ram.SUCCESS_OPERATION,ram._checked_success),(SUCCESS_OPERATION,_checked_success)):
        checker(ram.previous._json(ROOT/'build'/('designer-hot-v233-'+op)/'plan.json'))
    _checked_failed(ram.previous._json(ROOT/'build'/('designer-hot-v233-'+FAILED_OPERATION)/'plan.json'))
    base._lease(SimpleNamespace(plan=p))
    need(s.channel.identity=={k:p['liveResidentConfiguration'][k] for k in ('pipePath','serverPid','serverBirth')},'CHANNEL_IDENTITY')
    if s.phase in ('PREPARED','STAGED'):need(not _claim_path(s).exists(),'ALREADY_CLAIMED')
    else:need(ram.previous._json(_claim_path(s))==_claim(s),'OWN_CLAIM')


def _seal_admission(s,review_pin):
    markers=_marker_snapshot(s.plan['operationId']);_check(s)
    need(s.phase=='STAGED' and s.seal is None and id(s) not in _SEALS,'ADMISSION_ONCE')
    s.private['_no_pending'](context=s.plan['context'])
    need(_marker_snapshot(s.plan['operationId'])==markers,'ADMISSION_MARKER_RACE')
    ps=s.parent.scope;op=ps['writerOperationId'];need(ram.previous._hex(op,32),'WRITER_ID')
    checkpoint=ROOT/'artifacts/designer-bridge'/('root-notify-actual-write-checkpoint-'+op+'.json')
    reservation=c._reservation(s.plan['context'])
    seal=_AdmissionSeal(_SEAL_ISSUER,s,s.parent,s.plan_raw,s.scope_path.resolve(),c.canonical(s.scope),s.scope_sha256,
        s.parent.plan_raw,c.canonical(ps),s.parent.review_path.resolve(),s.parent.review_sha256,ps['ownerPid'],ps['ownerBirth'],
        checkpoint,ps['checkpointSha256'],reservation,c.read(reservation,8192),c.canonical(_claim(s)),
        c.canonical(_intent(s,review_pin)),markers,s.private['_wire'],s.channel,c.canonical(s.channel.identity))
    need(c.digest(c.read(seal.parent_scope_path,32768))==seal.parent_scope_sha256
         and c.digest(c.read(checkpoint,32768))==seal.checkpoint_sha256
         and _marker_snapshot(s.plan['operationId'])==markers,'ADMISSION_FINAL_RACE')
    _SEALS[id(s)]=seal;s.seal=seal
    return seal


def _hot_check(s):
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER,'HOT_ISSUER')
    seal=s.seal
    need(type(seal) is _AdmissionSeal and seal.issuer is _SEAL_ISSUER and _SEALS.get(id(s)) is seal
         and seal.operation is s and seal.parent is s.parent and s.private.get('_wire') is seal.wire,'HOT_SEAL')
    need(s.channel is seal.channel and c.canonical(s.channel.identity)==seal.channel_identity,'HOT_CHANNEL')
    if s.phase=='READY':need(s.host is not None and s.host.poll() is None,'HOT_MANAGED_HOST')
    if s.phase=='CLOSING' and s.join_attempted:
        need(s.host is not None and type(s.host.returncode) is int and s.host.returncode==0,'HOT_CLOSED_HOST')
    need(s.phase in ('STARTING_RETAIN','READY','CLOSING') and c.canonical(s.plan)==s.plan_raw==seal.plan_raw
         and s.scope_path.resolve()==seal.scope_path and s.scope_sha256==seal.scope_sha256
         and c.canonical(s.scope)==seal.scope_raw and authority(s.plan),'HOT_PLAN_SCOPE')
    need(s.parent.plan_raw==seal.parent_plan_raw and c.canonical(s.parent.plan)==seal.parent_plan_raw
         and c.canonical(s.parent.scope)==seal.parent_scope_raw and s.parent.review_path.resolve()==seal.parent_scope_path
         and s.parent.review_sha256==seal.parent_scope_sha256,'HOT_PARENT')
    need(c.digest(c.read(seal.scope_path,65536))==seal.scope_sha256
         and c.digest(c.read(seal.parent_scope_path,32768))==seal.parent_scope_sha256,'HOT_SCOPE_FILES')
    base._lease(SimpleNamespace(plan=s.plan))
    need(reader._process(seal.owner_pid)==seal.owner_birth,'HOT_ORIGINAL_RAM_OWNER')
    need(c.digest(c.read(seal.checkpoint_path,32768))==seal.checkpoint_sha256
         and c.read(seal.reservation_path,8192)==seal.reservation_raw,'HOT_OWNER_MARKERS')
    out=Path(s.plan['outputDirectory'])
    need(not (out/'unknown.json').exists() and c.canonical(ram.previous._json(_claim_path(s)))==seal.claim_raw
         and c.canonical(ram.previous._json(out/'intent.json'))==seal.intent_raw,'HOT_OWN_MARKERS')
    need(_marker_snapshot(s.plan['operationId'])==seal.foreign_markers,'HOT_FOREIGN_MARKERS')
    _fresh_failed()


def _fresh_identity_gate(s):
    """No historical audit/source graph/SDK calls on this hot path."""
    try:
        _hot_check(s)
        api=workday._Api();handle=api.pin_process(48936,'01dd5d0180299126')
        try:
            api.live_process(handle,'01dd5d0180299126')
            main=Path(s.plan['context']['buildDirectory'])/'runtime/modules/snegopat/engine/main.as'
            need(c.digest(c.read(main))==ram.previous.MAIN_SHA,'HOT_NATIVE_MAIN')
        finally:api.w.CloseHandle(handle)
    except BaseException:
        if type(s) is LiveResidentOperation and s.issuer is _ISSUER:s.phase='UNKNOWN_RETAIN'
        raise


def _identity(s):return ram._identity(s)


def _admitted(s):
    return _module('live_resident_diagnostic_carrier',CARRIER_SHA).admit_source(c.read(HERE/SOURCE_NAME,32768),
        operation_id=s.plan['operationId'],scope_sha256=s.scope_sha256,
        own_dll_path=(Path(s.plan['outputDirectory'])/'Continuation.dll').as_posix(),scope_admitted=True)


def _managed_render(s):
    out=Path(s.plan['outputDirectory'])
    files=ram.managed.render(dict(operationId=s.plan['operationId'],armPath=str(out/'resident-arm.bin'),
        resultPath=str(out/'resident-sdk-result.bin')),_identity(s));answer={}
    replacements={'resident-arm.bin':ARM_FILE,'resident-sdk-result.bin':WORKER_FILE,
        'resident-host-ready.json':HOST_READY,'resident-host-result.json':HOST_RESULT,
        'RESIDENT_':'LIVE_RESIDENT_','JOIN_VERIFIED_CLOSE':'JOIN_VERIFIED_LIVE_RESIDENT'}
    for name,raw in files.items():
        text=raw.decode('utf-8-sig')
        for old,new in replacements.items():text=text.replace(old,new)
        if name=='run-resident.ps1':text=text.replace('sdkResult=$code;','workerResult=$code;');name='run-live-resident.ps1'
        answer[name]=text.encode('utf-8-sig')
    need(b'PostThreadMessage(tid,0x83d2' not in answer['OwnedSdkDiagnosisHook.cs'],'UNTAGGED_DISPATCH')
    return answer


def _render(s):
    _check(s);p=s.plan
    files=c.render(base._carrier_view(p),c.read(HERE/c._probe_spec(reader.PROBE)[0],32768))
    admitted=_admitted(s);header=files['sdk_probe_params.h'].decode()
    line=next(v for v in header.splitlines() if v.startswith('#define AH_SDK_FIXED_SOURCE '))
    files['sdk_probe_params.h']=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(admitted.decode(),ensure_ascii=False)).encode()
    carrier=_module('live_resident_diagnostic_carrier',CARRIER_SHA)
    files['Continuation.c']=carrier.render(admitted,configuration=p['liveResidentConfiguration'],identity=_identity(s))
    anchor=carrier.SECTION_ANCHOR.encode();need(files['Continuation.c'].count(anchor)==1,'SECTION_ANCHOR')
    files['Continuation.c']=files['Continuation.c'].replace(anchor,ram.section_identity.ANCHOR,1)
    files.pop('run-fixed.ps1');files.update(_managed_render(s))
    return ram.section_identity.with_section_identity(files,operation_kind='LIVE_RESIDENT',operation_id=p['operationId'])[0]


def abort_before_start(s):
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER,'ABORT_ISSUER')
    if s.phase in ('PREPARED','STAGED'):
        s.channel.abort_before_connect();need(s.channel.wait_closed(),'UNSTARTED_CHANNEL_CLOSE')
        s.phase='ABORTED_UNSTARTED'


def prepare_root(path,pin):
    _pins();path=c._plain(path,ROOT/'artifacts/designer-bridge');scope=ram.previous._json(path,pin);validate_scope(scope)
    workday._checked_prior(scope)
    _checked_success(ram.previous._json(ROOT/'build'/('designer-hot-v233-'+SUCCESS_OPERATION)/'plan.json'))
    _checked_failed(ram.previous._json(ROOT/'build'/('designer-hot-v233-'+FAILED_OPERATION)/'plan.json'))
    parent=prepare_parent(path,pin);p=dict(parent.plan);op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):p.pop(key)
    out=ROOT/'build'/('designer-hot-v233-'+op);controller=c.digest(c.read(Path(__file__)))
    p.pop('moduleObjectId',None)
    p.update(operationId=op,outputDirectory=str(out),updatePreviewProfile=PROFILE,updatePreviewControllerSha256=controller,
        liveResidentControllerSha256=controller,actualSourceSha256=SOURCE_SHA,updatePreviewScopeSha256=pin,
        readScopeSha256=parent.review_sha256,sourceDomain=source.SOURCE_DOMAIN,applicationWrites=0,
        modulePropertyId=source.PROPERTY_UUID,rootUuid=source.ROOT_UUID,allowedReadClasses=['CommonModule'],
        **limits(),**{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})
    p['goldLeaseOwner'],p['goldLeaseBootstrapSha256']=base.owner_base._lease_binding(p['context'])
    dummy=SimpleNamespace(plan=p,scope=scope,scope_sha256=pin);admitted=_admitted(dummy)
    wire=_module('native_mcp.resident_live_wire',WIRE_SHA);pipe=_module('native_mcp.windows_resident_live_pipe',PIPE_SHA)
    context=wire.ResidentLiveContext(source.ROOT_UUID,48936,p['context']['birth'],op,pin,SOURCE_SHA,c.digest(admitted))
    channel=pipe.ResidentLiveChannel(48936,expected_birth=p['context']['birth'],context=context,timeout=60.0)
    try:
        cfg=dict(operationId=op,scopeSha256=pin,**channel.identity,maximumSessionSeconds=600,maximumReads=64,
            maximumRequestTtlMilliseconds=60000,armPath=(out/ARM_FILE).as_posix(),resultPath=(out/WORKER_FILE).as_posix())
        p['liveResidentConfiguration']=cfg;p['compiledSourceSha256']=c.digest(admitted)
        s=LiveResidentOperation(_ISSUER,parent,scope,path,pin,p,c.canonical(p),{},channel);_check(s)
        ns=parent.private;ns['__pending_read_operation']=op
        def fresh(plan):
            need(plan==s.plan,'FRESH_PLAN')
            if s.seal is None:_check(s);c._fresh(base._carrier_view(plan))
            else:_fresh_identity_gate(s)
        def render(plan,_):need(plan==s.plan,'RENDER_PLAN');return _render(s)
        ns.update(_fresh=fresh,render=render,_wire=wire);s.private=ns;ns['_no_pending'](context=p['context'])
        return s
    except BaseException:
        channel.abort_before_connect();channel.wait_closed();raise


def stage_root(s):
    try:
        _check(s);need(s.phase=='PREPARED','STAGE_PHASE');s.private['FILES']=tuple(_render(s))
        row=s.private['stage_private'](s.plan,dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',rootAuthorized=True,planSha256=c.digest(s.plan_raw)))
        s.phase='STAGED';return row
    except BaseException:abort_before_start(s);raise


def _authority_result(s):
    return dict(profile=PROFILE,scopeSha256=s.scope_sha256,actualSourceSha256=SOURCE_SHA,
        compiledSourceSha256=s.plan['compiledSourceSha256'],liveResidentControllerSha256=s.plan['liveResidentControllerSha256'],
        liveResidentCarrierSha256=CARRIER_SHA,residentLiveWireSha256=WIRE_SHA,residentLivePipeSha256=PIPE_SHA,
        priorFailedReadOperationId=FAILED_OPERATION,priorFailedReadPlanSha256=FAILED_PLAN_SHA,
        failedReadAuditSha256=FAILED_AUDIT_SHA,failedReadWindowsSha256=FAILED_WINDOWS_SHA,
        sourceDomain=source.SOURCE_DOMAIN,currentEditorUnchangedVerified=False,sourceBodyPersisted=False,
        **limits(),**{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


DIAGNOSTIC_KEYS={'kind','version','operationId','scopeSha256','readerSourceSha256','compiledSourceSha256',
    'sequence','lastReadSequence','nativeWorkerRc','sdkRc','executeRc','exceptionLine','exceptionLineAttempted',
    'exceptionLinePinStatus','exceptionLineInRange','contextsCreated','contextsReleased','functionsCreated',
    'functionsReleased','contextLive','functionLive','cppEvents','otherEvents','firstOtherExceptionCode',
    'handlerLive','epochActive','gateDone','hookLive','ioDrained','jobPresent','jobMetadataObserved','jobState',
    'jobBorrowed','captureCalls','bodyCopiedBytes','sourceBodyIncluded','addressesIncluded'}
DIAGNOSTIC_BOOL={'exceptionLineAttempted','exceptionLineInRange','contextLive','functionLive','handlerLive',
    'epochActive','gateDone','hookLive','ioDrained','jobPresent','jobMetadataObserved','sourceBodyIncluded','addressesIncluded'}
DIAGNOSTIC_TEXT={'kind','operationId','scopeSha256','readerSourceSha256','compiledSourceSha256'}


def terminal_diagnostics(s):
    """Read one existing final metadata file; never poll, close or bless failure."""
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER
         and c.canonical(s.plan)==s.plan_raw,'DIAGNOSTIC_ISSUER_PLAN')
    cfg=s.plan['liveResidentConfiguration'];path=Path(cfg['resultPath']+'.diagnostics.json')
    need(path.parent==Path(s.plan['outputDirectory']) and cfg['operationId']==s.plan['operationId']
         and cfg['scopeSha256']==s.scope_sha256,'DIAGNOSTIC_PATH')
    if not path.exists():return None
    row=ram.previous._json(c._plain(path,ROOT/'build'),bound=8192)
    need(type(row) is dict and row.keys()==DIAGNOSTIC_KEYS
         and row['kind']=='LIVE_RESIDENT_FINAL_DIAGNOSTIC'
         and row['operationId']==s.plan['operationId'] and row['scopeSha256']==s.scope_sha256
         and row['readerSourceSha256']==SOURCE_SHA
         and row['compiledSourceSha256']==s.plan['compiledSourceSha256'],'DIAGNOSTIC_JOIN')
    need(all(type(row[k]) is bool for k in DIAGNOSTIC_BOOL)
         and all(type(row[k]) is int and -2147483648<=row[k]<=4294967295 for k in
             DIAGNOSTIC_KEYS-DIAGNOSTIC_BOOL-DIAGNOSTIC_TEXT)
         and row['version']==1 and row['sourceBodyIncluded'] is False and row['addressesIncluded'] is False,'DIAGNOSTIC_TYPES')
    for key,maximum in {'sequence':65,'lastReadSequence':64,'exceptionLinePinStatus':2,
        'contextsCreated':1,'contextsReleased':1,'functionsCreated':1,'functionsReleased':1,
        'jobState':6,'jobBorrowed':1,'captureCalls':1,'bodyCopiedBytes':262144}.items():
        need(0<=row[key]<=maximum,'DIAGNOSTIC_RANGE')
    need(0<=row['exceptionLine']<=len(c.read(HERE/SOURCE_NAME,32768).splitlines())
         and all(row[k]>=0 for k in ('nativeWorkerRc','sdkRc','cppEvents','otherEvents','firstOtherExceptionCode')),'DIAGNOSTIC_NUMBERS')
    if row['exceptionLineInRange']:
        need(row['exceptionLineAttempted'] and row['exceptionLinePinStatus']==1 and row['exceptionLine']>0,'DIAGNOSTIC_LINE')
    else:need(row['exceptionLine']==0,'DIAGNOSTIC_LINE_ZERO')
    if not row['exceptionLineAttempted']:need(row['exceptionLinePinStatus']==0,'DIAGNOSTIC_UNATTEMPTED')
    if not row['jobMetadataObserved']:
        need(all(row[k]==0 for k in ('jobState','jobBorrowed','captureCalls','bodyCopiedBytes')),'DIAGNOSTIC_UNOBSERVED')
    else:need(row['jobPresent'] and row['gateDone'],'DIAGNOSTIC_JOB_OBSERVED')
    return row


def _require_closed_diagnostics(s):
    row=terminal_diagnostics(s);need(row is not None,'DIAGNOSTIC_REQUIRED')
    ram._counts(row,dict(sequence=s.sequence+1,lastReadSequence=s.sequence,nativeWorkerRc=0,
        sdkRc=0 if s.sequence else 999,executeRc=0 if s.sequence else -2147483647,
        exceptionLine=0,exceptionLinePinStatus=0,contextsCreated=1 if s.sequence else 0,
        contextsReleased=1 if s.sequence else 0,functionsCreated=1 if s.sequence else 0,
        functionsReleased=1 if s.sequence else 0,cppEvents=0,otherEvents=0,firstOtherExceptionCode=0,
        jobState=0,jobBorrowed=0,captureCalls=0,bodyCopiedBytes=0),'DIAGNOSTIC_CLOSED_COUNTS')
    ram._flags(row,yes=('ioDrained',),no=('exceptionLineAttempted','exceptionLineInRange','contextLive',
        'functionLive','handlerLive','epochActive','hookLive','gateDone','jobPresent','jobMetadataObserved'),code='DIAGNOSTIC_CLOSED_FLAGS')
    return row


def _unknown(s,reason):
    s.phase='UNKNOWN_RETAIN'
    row=dict(kind='LIVE_RESIDENT_UNKNOWN',operationId=s.plan['operationId'],knownTerminal=False,
        retryAuthorized=False,reason=reason,sourceBodyPersisted=False,ownedBufferMayRemain=True)
    path=Path(s.plan['outputDirectory'])/'unknown.json'
    if not path.exists():c.write_new(path,row)
    return row


def start_root_once(s,review_path,review_pin):
    _check(s);need(s.phase=='STAGED','START_ONCE')
    review_path=c._plain(review_path,ROOT/'artifacts/designer-bridge');review=ram.previous._json(review_path,review_pin)
    need(review.get('kind')==RUN_KIND and review.get('operationId')==s.plan['operationId']
         and review.get('passed') is True and review.get('planSha256')==c.digest(s.plan_raw)
         and review.get('buildSha256')==c.digest(c.canonical(s.private['require_stage'](s.plan)))
         and authority(review) and review.get('scopeSha256')==s.scope_sha256
         and review.get('actualSourceSha256')==SOURCE_SHA and review.get('compiledSourceSha256')==s.plan['compiledSourceSha256']
         and review.get('liveResidentControllerSha256')==s.plan['liveResidentControllerSha256']
         and review.get('liveResidentCarrierSha256')==CARRIER_SHA and review.get('residentLiveWireSha256')==WIRE_SHA
         and review.get('residentLivePipeSha256')==PIPE_SHA,'ROOT_RUN')
    out=Path(s.plan['outputDirectory'])
    need(not any((out/n).exists() for n in ('intent.json','host-identity.json','result.json','unknown.json',
         HOST_READY,HOST_RESULT,ARM_FILE,WORKER_FILE)),'ONE_ATTEMPT')
    _seal_admission(s,review_pin);c.write_new(_claim_path(s),json.loads(s.seal.claim_raw))
    c.write_new(out/'intent.json',json.loads(s.seal.intent_raw));s.phase='STARTING_RETAIN'
    try:
        _fresh_identity_gate(s)
        s.host=subprocess.Popen([str(reader.writer.PS),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(out/'run-live-resident.ps1')],
            cwd=out,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        c.write_new(out/'host-identity.json',reader.writer._host_identity(s.host))
        s.binding=s.channel.connect()
        need(type(s.binding) is source.ResidentLiveBinding,'BINDING_TYPE');s.binding.validate()
        need((s.binding.operation_id,s.binding.scope_sha256,s.binding.reader_source_sha256,s.binding.compiled_source_sha256,
              s.binding.process_id,s.binding.birth)==(s.plan['operationId'],s.scope_sha256,SOURCE_SHA,
              s.plan['compiledSourceSha256'],48936,s.plan['context']['birth']),'READY_BINDING')
        _host_ready(s)
        s.phase='READY';_fresh_identity_gate(s);return s
    except Exception:return _unknown(s,'INSTALL_CLOSURE_UNPROVEN')


def read_snapshot(s,target_uuid):
    """One fresh GUI read; channel must validate capture before ACK and release."""
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER and s.phase=='READY'
         and not s.inflight and s.sequence<64,'READ_PHASE_BUDGET')
    target=source.ResidentLiveTarget(target_uuid,source.PROPERTY_UUID);target.validate()
    need(type(s.binding) is source.ResidentLiveBinding,'READ_BINDING')
    # This local refusal precedes any channel/SDK dispatch and must leave the
    # known installation available for its separate cleanup-only CLOSE grace.
    need(time.monotonic()<=s.binding.valid_until,'READ_EXPIRED_CLOSE_REQUIRED')
    s.inflight=True
    try:
        _fresh_identity_gate(s)
        wire=s.private['_wire']
        command_now=time.monotonic()
        need(command_now<=s.binding.valid_until,'READ_EXPIRED_CLOSE_REQUIRED')
        command=wire.ResidentLiveCommand(wire.READ,s.sequence+1,uuid.uuid4().hex,s.sequence+1,target)
        command=wire.build_command(command,binding=s.binding,now=command_now,previous_sequence=s.sequence)
    except BaseException:
        # No channel method was called. Fresh physical failures already seal
        # themselves; known local expiry must still permit cleanup-only CLOSE.
        s.inflight=False
        raise
    try:
        # Only this fixed physical callback may approve the private capture;
        # no generic caller supplies policy or a forged post-ACK release.
        snapshot,request=s.channel.read(command,lambda frame,request:_validate_capture(s,frame,request))
        _fresh_identity_gate(s)
        text=source.validate_snapshot(snapshot,request,target,time.monotonic(),previous_sequence=s.sequence);del text
        s.sequence=request.sequence
        return snapshot,request
    except BaseException:
        _unknown(s,'JOB_CLOSURE_UNPROVEN')
    finally:s.inflight=False
    # Do not retain a source snapshot in a newly raised exception's locals or
    # chain. The original exception has left its except scope above.
    snapshot=request=None
    raise ValueError('LIVE_RESIDENT_OPERATION_JOB_CLOSURE_UNPROVEN')


def _validate_capture(s,frame,request):
    """Fresh physical guard around the pinned producer's capture facts.

    The channel binds its held kernel peer to the actual producer. Deep source
    and stage proof were sealed once before launch. The frozen producer emits
    these facts only after real SDK releases/zero whole epoch, not AS booleans.
    """
    _fresh_identity_gate(s)
    wire=s.private['_wire']
    need(type(frame) is wire.ResidentLiveCapture and frame.request==request and request.binding==s.binding,'CAPTURE_REQUEST')
    command=wire.ResidentLiveCommand(wire.READ,request.sequence,request.request_id,request.revision,request.target)
    wire.validate_capture(frame,binding=s.binding,command=command,now=time.monotonic(),previous_sequence=s.sequence)
    return frame.receipt


def _join_host(s):
    need(not s.join_attempted and s.channel.closed and s.host is not None and s.host.poll() is None
         and s.host.stdin is not None,'HOST_JOIN_PHASE');s.join_attempted=True
    s.host.stdin.write(b'JOIN_VERIFIED_LIVE_RESIDENT\n');s.host.stdin.flush();s.host.stdin.close()
    out=Path(s.plan['outputDirectory']);deadline=time.monotonic()+25
    while time.monotonic()<deadline:
        if (out/HOST_RESULT).is_file():
            row=ram.previous._json(out/HOST_RESULT,bound=8192)
            need(row.get('kind')=='LIVE_RESIDENT_MANAGED_TERMINAL' and row.get('operationId')==s.plan['operationId'],'HOST_JOIN')
            ram._flags(row,yes=('knownTerminal','hookWorkersReleased'),no=('writerAuthorized',),code='HOST_CLOSURE')
            ram._counts(row,dict(workerResult=0,threadId=8292),'HOST_WORKER_RESULT')
            s.host.wait(timeout=5);need(type(s.host.returncode) is int and s.host.returncode==0,'HOST_EXIT')
            need(c.read(out/WORKER_FILE,8)==bytes(4),'RAW_WORKER_RESULT');return row
        if s.host.poll() is not None:break
        time.sleep(.02)
    raise ValueError('LIVE_RESIDENT_OPERATION_HOST_CLOSURE_UNKNOWN')


def _host_ready(s):
    out=Path(s.plan['outputDirectory']);deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        if (out/HOST_READY).is_file():
            row=ram.previous._json(out/HOST_READY,bound=8192)
            need(row.get('kind')=='LIVE_RESIDENT_MANAGED_READY' and row.get('operationId')==s.plan['operationId'],'HOST_READY')
            ram._flags(row,yes=('workerExpectedAlive',),no=('nativeSourceBindingVerified',),code='HOST_READY_FLAGS')
            ram._counts(row,dict(processId=48936,threadId=8292),'HOST_READY_IDENTITY');return row
        if s.host is None or s.host.poll() is not None:break
        time.sleep(.01)
    raise ValueError('LIVE_RESIDENT_OPERATION_HOST_READY_UNKNOWN')


def close_root(s):
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER and s.phase=='READY' and not s.inflight,'CLOSE_PHASE')
    s.inflight=True
    try:
        _fresh_identity_gate(s);s.phase='CLOSING'
        wire=s.private['_wire']
        command=wire.ResidentLiveCommand(wire.CLOSE,s.sequence+1,uuid.uuid4().hex,0,None)
        command=wire.build_command(command,binding=s.binding,now=time.monotonic(),previous_sequence=s.sequence)
        s.channel.close(command,lambda row:_validate_close(s,row))
        need(s.channel.wait_closed() and s.channel.closed,'CLOSE_CHANNEL')
        _join_host(s);_fresh_identity_gate(s);_require_closed_diagnostics(s);s.phase='CLOSED'
        row=dict(kind='LIVE_RESIDENT_RESULT',operationId=s.plan['operationId'],status='LIVE_RESIDENT_RESOURCES_CLOSED',
            knownTerminal=True,resourcesClosed=True,reads=s.sequence,workerResult=0,hostExitCode=0,
            retryAuthorized=False,**_authority_result(s))
        c.write_new(Path(s.plan['outputDirectory'])/'result.json',row);return row
    except Exception:return _unknown(s,'CLOSE_CLOSURE_UNPROVEN')
    finally:s.inflight=False


def _validate_close(s,row):
    _fresh_identity_gate(s)
    wire=s.private['_wire']
    need(type(row) is dict,'CLOSE_METADATA')
    command=wire.ResidentLiveCommand(wire.CLOSE,s.sequence+1,row.get('request_id'),0,None)
    wire.build_close_frame(row,binding=s.binding,command=command,now=time.monotonic(),previous_sequence=s.sequence)
    return row
