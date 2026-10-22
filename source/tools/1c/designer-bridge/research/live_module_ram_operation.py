"""One reviewed LIVE capture into private RAM; no application body files.

Prepare/stage are separate from Root's single authorized launch. A private ACK
requires physical GUI SDK closure; public access additionally requires worker
and managed-host closure. Unknown state retains ownership and never retries.
"""
from dataclasses import dataclass
import importlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
from types import FunctionType,SimpleNamespace
import uuid

import live_module_readonly_operation as previous
import live_module_readonly_closure as success
import resident_managed_carrier as managed
import native_ram_carrier as native
import sdk_compiler_section_identity as section_identity

c,reader,base,workday=previous.c,previous.reader,previous.base,previous.workday
HERE,ROOT=previous.HERE,previous.ROOT
sys.path.insert(0,str(HERE.parent))
from native_mcp import live_source

PROFILE='PRINT_COMMON_MODULE_LIVE_RAM_ONESHOT'
SCOPE_KIND='ROOT_LIVE_MODULE_RAM_SCOPE'
RUN_KIND='ROOT_LIVE_MODULE_RAM_RUN'
SOURCE_SHA='4610f385654d36cdb6673b12ed2a9206338d6535405de5782f1e3598688cf9a9'
PREVIOUS_SHA='177f76ae53fecbff383f3fcd90a9e972958c63fa854589d5146f18e0db39c2d4'
SUCCESS_SHA='dae69b5d1ea69ded64ccb495c4ab5336b5045f32a348c0a02095ed7f9d17b7f4'
CAPTURE_SHA='1bd0c8aba6851918a6db499054e6d4f08ca9460b38caa044ef9e2a451ef2d292'
MANAGED_SHA='df071e91f3e0fe2bea80b5a850e2407bd3bed4e29322bf9ba5027f122dbe44e8'
CARRIER_SHA='267957dde28d9696add680e44736746c6b2ed9d619c5add0b783ffb6cc145ab6'
WIRE_SHA='28dbc6053386099696415eb6dbc4fdf8abb9aca5790ebc91e45620d113b59ba2'
PIPE_SHA='6bc066d3860bd3cda9b657459979f08e83a985c8e488c7b616d819e767564c1c'
SOURCE_CONTRACT_SHA='8b8c8dc805d7de3cff9aa0ff81189ea3cbff1f7d73095887cf4c3fa48b4ba0d3'
SUCCESS_OPERATION='4201198748b14537aee94bd07d69b7eb'
SUCCESS_PLAN_SHA='8e4f279777273d6646aff6018f0dce3f851654eeea9dd0baeb734258e57191ce'
SUCCESS_HOST_PID=25708
SUCCESS_HOST_BIRTH='01dd5f18516765a3'
SOURCE_NAME='NativeLiveModuleRam.as'
NATIVE_FILE='live-module-ram-proof.json'
INTENT_FILE='live-module-ram-intent.json'
EPOCH_FILE='live-module-ram-sdk-chain-epoch.json'
TRANSFER_FILE='live-module-ram-transfer-proof.json'
FINAL_FILE='live-module-ram-carrier-proof.json'
WORKER_FILE='live-module-ram-worker-result.bin'
ARM_FILE='live-module-ram-arm.bin'
CALLBACK_FILE='live-module-ram-callback.bin'
HOST_READY='live-module-ram-host-ready.json'
HOST_RESULT='live-module-ram-host-result.json'
TRUE_AUTH=previous.TRUE_AUTH+('ownedRamCopyAuthorized','scopedRamPipeTransferAuthorized','ownedRamBufferReleaseAuthorized')
FALSE_AUTH=previous.FALSE_AUTH
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('LIVE_RAM_OPERATION_'+code)


def limits():
    return dict(previous.limits(),maximumCaptureCalls=1,maximumCommitCalls=1,maximumTransfers=1,
                maximumRequestTtlSeconds=60,maximumBodyBytes=524288)


def authority(row):
    return all(row.get(k) is True for k in TRUE_AUTH) and all(row.get(k) is False for k in FALSE_AUTH) \
        and all(type(row.get(k)) is int and row[k]==v for k,v in limits().items())


def _module(name,pin):
    need(previous._hex(pin,64),'DEPENDENCY_NOT_FROZEN')
    path=(HERE.parent/name.replace('.', '/')).with_suffix('.py') if name.startswith('native_mcp.') else HERE/(name+'.py')
    need(c.digest(c.read(path))==pin,'DEPENDENCY_PIN')
    return importlib.import_module(name)


def _pins():
    need(c.digest(c.read(Path(previous.__file__)))==PREVIOUS_SHA
         and c.digest(c.read(Path(success.__file__)))==SUCCESS_SHA
         and c.digest(c.read(Path(managed.__file__)))==MANAGED_SHA,'FROZEN_BASE_PIN')
    previous._pins()
    need(c.digest(c.read(Path(native.__file__)))=='c75ca413a26e5cccb6f4ff68f9a3d4e88ae5b9b960560e408afa0b606cdf1301',
         'NATIVE_CLASSIFIER_PIN')
    need(c.digest(c.read(Path(live_source.__file__)))==SOURCE_CONTRACT_SHA,'SOURCE_CONTRACT_PIN')
    _module('live_module_ram_capture',CAPTURE_SHA)
    _module('live_module_ram_carrier',CARRIER_SHA)
    _module('native_mcp.live_wire',WIRE_SHA)
    _module('native_mcp.windows_live_ram_pipe',PIPE_SHA)
    need(c.digest(c.read(HERE/SOURCE_NAME,32768))==SOURCE_SHA,'SOURCE_PIN')


def validate_scope(row):
    need(type(row) is dict and row.get('kind')==SCOPE_KIND and row.get('profile')==PROFILE
         and row.get('passed') is True and row.get('oneShot') is True and authority(row)
         and row.get('actualSourceSha256')==SOURCE_SHA
         and row.get('liveModuleRamControllerSha256')==c.digest(c.read(Path(__file__)))
         and row.get('liveRamCarrierSha256')==CARRIER_SHA and previous._hex(CARRIER_SHA,64)
         and row.get('liveWireSha256')==WIRE_SHA and previous._hex(WIRE_SHA,64)
         and row.get('liveRamPipeSha256')==PIPE_SHA and previous._hex(PIPE_SHA,64)
         and row.get('liveReadonlySuccessClosureSha256')==SUCCESS_SHA
         and row.get('priorReadSuccessOperationId')==SUCCESS_OPERATION
         and row.get('priorReadSuccessPlanSha256')==SUCCESS_PLAN_SHA
         and row.get('moduleObjectId')==previous.TARGET and row.get('modulePropertyId')==previous.PROPERTY
         and row.get('allowedReadClasses')==['CommonModule'] and row.get('sourceDomain')==live_source.SOURCE_DOMAIN
         and previous._hex(row.get('requestId'),32) and type(row.get('revision')) is int and row['revision']==1,'SCOPE')
    need(all(workday._approved_prior_plans(row).get(k)==v for k,v in previous.REQUIRED_PRIORS.items()),'WORKDAY_PRIORS')
    workday._admission_scope_pins(row)


def _success_host_terminal():
    fn=FunctionType(previous._prior_host_terminal.__code__,dict(previous._prior_host_terminal.__globals__,
        PRIOR_HOST_PID=SUCCESS_HOST_PID,PRIOR_HOST_BIRTH=SUCCESS_HOST_BIRTH),previous._prior_host_terminal.__name__)
    return fn()


def _checked_success(prior):
    need(type(prior) is dict and prior.get('operationId')==SUCCESS_OPERATION
         and c.digest(c.canonical(prior))==SUCCESS_PLAN_SHA,'EXACT_SUCCESS_PRIOR')
    row=success.audit_closed(prior)
    need(row.get('classification')==success.CLASSIFICATION and all(row.get(k) is True for k in
         ('resourcesClosed','readBodyVerified','normalSdkContextAndFunctionReleaseReturned','ownedTypedHandlesCleared',
          'freshHostExitCheckRequired','currentTargetIdentityAndLeaseCheckRequired'))
         and type(row.get('priorHostProcessId')) is int and row['priorHostProcessId']==SUCCESS_HOST_PID
         and row.get('priorHostBirth')==SUCCESS_HOST_BIRTH and all(row.get(k) is False for k in
         ('currentIdentityVerified','currentLeaseVerified','rootOwnerExitVerified','transportVerified',
          'retryAuthorized','newDispatchAuthorized','unloadAuthorized','foreignUnknownWaived')),'SUCCESS_CLOSURE')
    observed=_success_host_terminal()
    need(type(observed) is dict and observed.get('birth')==SUCCESS_HOST_BIRTH and all(type(observed.get(k)) is int
         and observed[k]==v for k,v in dict(pid=SUCCESS_HOST_PID,waitZeroMilliseconds=0,exitCode=0).items()),'FRESH_SUCCESS_HOST')
    return row


def _ram_factory(factory):
    # Reuse the correct frozen shared-helper clone, preserving its3historical
    # exact branches. Add one success branch in that same private namespace.
    fn=previous._private_factory(previous._baseline_factory,validate_scope=validate_scope)
    factory=fn(factory);old_reader=factory.__globals__['reader'];old_inspect=factory.__globals__['inspect']
    def namespace(parent):
        ns=old_reader._namespace(parent);ns.update(__live_read_success=SUCCESS_OPERATION,__live_read_success_audit=_checked_success);return ns
    def source(target):
        text=old_inspect.getsource(target)
        if target is c._no_pending:
            anchor='        if prior_identity!=identity: continue\n'
            need(text.count(anchor)==1,'PARENT_AUDIT_ANCHOR')
            text=text.replace(anchor,anchor+'        if operation==__live_read_success:\n            __live_read_success_audit(prior);continue\n',1)
        return text
    r=SimpleNamespace(**dict(old_reader.__dict__));r._namespace=namespace
    i=SimpleNamespace(**dict(old_inspect.__dict__));i.getsource=source
    return previous._private_factory(factory,reader=r,inspect=i,validate_scope=validate_scope)


def prepare_parent(path,pin):
    def composed(factory):return workday.admission._extra_factory(_ram_factory(factory))
    return previous._private_factory(workday.admission._prepare_parent,validate_scope=validate_scope,_extra_factory=composed)(path,pin)


@dataclass(slots=True)
class LiveModuleRamOperation:
    issuer: object
    parent: object
    scope: dict
    scope_path: Path
    scope_sha256: str
    plan: dict
    plan_raw: bytes
    private: dict
    receiver: object
    phase: str='PREPARED'
    host: object=None
    snapshot: object=None
    request: object=None
    join_attempted: bool=False


def _claim_path(s):return ROOT/'artifacts/designer-bridge'/('live-module-ram-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='LIVE_MODULE_RAM_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
        controllerSha256=s.plan['liveModuleRamControllerSha256'],actualSourceSha256=SOURCE_SHA,requestId=s.scope['requestId'],
        parentWriterOperationId=q['operationId'],parentWriterIntentSha256=c.digest(c.canonical(q)),
        sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'])


def _check(s):
    need(type(s) is LiveModuleRamOperation and s.issuer is _ISSUER,'ISSUED_OPERATION');_pins()
    p=s.plan;ctx=p['context'];need(c.canonical(p)==s.plan_raw and p.get('version')==233
        and p.get('liveModuleRamControllerSha256')==c.digest(c.read(Path(__file__)))
        and p.get('updatePreviewControllerSha256')==p['liveModuleRamControllerSha256']
        and p.get('actualSourceSha256')==SOURCE_SHA and p.get('updatePreviewProfile')==PROFILE
        and p.get('updatePreviewScopeSha256')==s.scope_sha256 and authority(p)
        and ctx==s.parent.plan['context'],'PLAN')
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256'))==
         (48936,'01dd5d0180299126',8292,previous.MAIN_SHA),'NATIVE_IDENTITY')
    scope=previous._json(s.scope_path,s.scope_sha256);validate_scope(scope);q=reader._check_owner(s.parent)
    need(scope==s.scope and scope.get('targets')==q['targets'] and scope.get('readScopeSha256')==s.parent.review_sha256
         and Path(scope.get('readScopePath','')).resolve()==s.parent.review_path.resolve()
         and (scope.get('sessionNonce'),scope.get('pid'),scope.get('birth'),scope.get('guiThreadId'),scope.get('mainSha256'))==
         (ctx['heldNonce'],48936,ctx['birth'],8292,previous.MAIN_SHA),'SCOPE_BINDING')
    workday._checked_prior(scope);workday._audit_workday_pending(ctx,scope=scope)
    for op,checker in ((previous.closed_refusal.OP,previous._checked_refusal),(previous.BASELINE_OPERATION,previous._checked_baseline),
                       (previous.PREOPEN_OPERATION,previous._checked_preopen),(SUCCESS_OPERATION,_checked_success)):
        checker(previous._json(ROOT/'build'/('designer-hot-v233-'+op)/'plan.json'))
    base._lease(SimpleNamespace(plan=p))
    if s.phase in ('PREPARED','STAGED'):need(not _claim_path(s).exists(),'ALREADY_CLAIMED')
    else:need(previous._json(_claim_path(s))==_claim(s),'OWN_CLAIM')
    identity=s.receiver.identity;cfg=p['liveRamConfiguration']
    need(identity=={k:cfg[k] for k in ('pipePath','serverPid','serverBirth','requestId')},'RECEIVER_IDENTITY')


def _identity(s):
    x=s.plan['sdkIdentity'];return dict(processId=48936,birth=s.plan['context']['birth'],guiThreadId=8292,
        engineAddress=x['engineAddress'],moduleAddress=x['moduleAddress'])


def _admitted(s):
    out=Path(s.plan['outputDirectory']);carrier=_module('live_module_ram_carrier',CARRIER_SHA)
    return carrier.admit_source(c.read(HERE/SOURCE_NAME,32768),operation_id=s.plan['operationId'],scope_sha256=s.scope_sha256,
        request_id=s.scope['requestId'],own_dll_path=(out/'Continuation.dll').as_posix(),
        intent_path=(out/INTENT_FILE).as_posix(),proof_path=(out/NATIVE_FILE).as_posix(),scope_admitted=True)


def _managed_render(s):
    out=Path(s.plan['outputDirectory']);cfg=s.plan['liveRamConfiguration']
    files=managed.render(dict(operationId=s.plan['operationId'],armPath=str(out/'resident-arm.bin'),
        resultPath=str(out/'resident-sdk-result.bin')),_identity(s))
    replacements={'resident-arm.bin':ARM_FILE,'resident-sdk-result.bin':WORKER_FILE,
        'resident-host-ready.json':HOST_READY,'resident-host-result.json':HOST_RESULT,
        'RESIDENT_':'LIVE_RAM_','JOIN_VERIFIED_CLOSE':'JOIN_VERIFIED_LIVE_RAM'}
    answer={}
    for name,raw in files.items():
        text=raw.decode('utf-8-sig')
        for old,new in replacements.items():text=text.replace(old,new)
        # The existing rawDWORD wait is a WORKER outcome, not GUI SDK result.
        if name=='run-resident.ps1':
            text=text.replace('sdkResult=$code;','workerResult=$code;')
            name='run-live-ram.ps1'
        answer[name]=text.encode('utf-8-sig')
    need(b'PostThreadMessage(tid,0x83d2' not in answer['OwnedSdkDiagnosisHook.cs'],'UNTAGGED_DISPATCH')
    return answer


def _render(s):
    _check(s);p=s.plan;files=c.render(base._carrier_view(p),c.read(HERE/c._probe_spec(reader.PROBE)[0],32768))
    admitted=_admitted(s);header=files['sdk_probe_params.h'].decode()
    line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
    files['sdk_probe_params.h']=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(admitted.decode(),ensure_ascii=False)).encode()
    carrier=_module('live_module_ram_carrier',CARRIER_SHA)
    files['Continuation.c']=carrier.render(admitted,configuration=p['liveRamConfiguration'],identity=_identity(s))
    anchor=carrier.SECTION_ANCHOR.encode();need(files['Continuation.c'].count(anchor)==1,'SECTION_ANCHOR')
    files['Continuation.c']=files['Continuation.c'].replace(anchor,section_identity.ANCHOR,1)
    files.pop('run-fixed.ps1');files.update(_managed_render(s))
    files,_=section_identity.with_section_identity(files,operation_kind='LIVE_MODULE_RAM',operation_id=p['operationId'])
    return files


def abort_before_start(s):
    need(type(s) is LiveModuleRamOperation and s.issuer is _ISSUER,'ABORT_ISSUER')
    if s.phase in ('PREPARED','STAGED'):
        if not s.receiver.closed:s.receiver.abort_before_arm()
        need(s.receiver.wait_closed(),'UNSTARTED_RECEIVER_CLOSE')


def prepare_root(path,pin):
    _pins();path=c._plain(path,ROOT/'artifacts/designer-bridge');scope=previous._json(path,pin);validate_scope(scope)
    workday._checked_prior(scope)
    # Do this before even the earliest historical private factory audit. The
    # old scanner may already regard a result file as terminal; our new grant
    # still requires full read replay and fresh exact-host kernel observation.
    _checked_success(previous._json(ROOT/'build'/('designer-hot-v233-'+SUCCESS_OPERATION)/'plan.json'))
    parent=prepare_parent(path,pin);p=dict(parent.plan);op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):p.pop(key)
    out=ROOT/'build'/('designer-hot-v233-'+op);controller=c.digest(c.read(Path(__file__)))
    p.update(operationId=op,outputDirectory=str(out),updatePreviewProfile=PROFILE,updatePreviewControllerSha256=controller,
        liveModuleRamControllerSha256=controller,actualSourceSha256=SOURCE_SHA,updatePreviewScopeSha256=pin,
        readScopeSha256=parent.review_sha256,requestId=scope['requestId'],revision=1,sourceDomain=live_source.SOURCE_DOMAIN,
        moduleObjectId=previous.TARGET,modulePropertyId=previous.PROPERTY,applicationWrites=0,
        **limits(),**{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})
    p['goldLeaseOwner'],p['goldLeaseBootstrapSha256']=base.owner_base._lease_binding(p['context'])
    wire=_module('native_mcp.live_wire',WIRE_SHA);pipe=_module('native_mcp.windows_live_ram_pipe',PIPE_SHA)
    dummy=SimpleNamespace(plan=p,scope=scope,scope_sha256=pin)
    admitted=_admitted(dummy)
    context=wire.LiveFrameContext(op,pin,scope['requestId'],1,c.digest(admitted),48936,p['context']['birth'])
    receiver=pipe.LiveRamReceiver(48936,expected_birth=p['context']['birth'],context=context,timeout=60.0)
    try:
        cfg=dict(operationId=op,scopeSha256=pin,revision=1,**receiver.identity)
        need(cfg['requestId']==scope['requestId'],'RECEIVER_REQUEST')
        cfg.update(epochPath=(out/EPOCH_FILE).as_posix(),resultPath=(out/WORKER_FILE).as_posix(),
            armPath=(out/ARM_FILE).as_posix(),callbackPath=(out/CALLBACK_FILE).as_posix(),
            transferProofPath=(out/TRANSFER_FILE).as_posix(),proofPath=(out/FINAL_FILE).as_posix())
        p['liveRamConfiguration']=cfg;p['compiledSourceSha256']=c.digest(admitted)
        s=LiveModuleRamOperation(_ISSUER,parent,scope,path,pin,p,c.canonical(p),{},receiver)
        _check(s);ns=parent.private;ns['__pending_read_operation']=op
        def fresh(plan):_check(s);need(plan==s.plan,'FRESH_PLAN');c._fresh(base._carrier_view(plan))
        def render(plan,_):need(plan==s.plan,'RENDER_PLAN');return _render(s)
        ns.update(_fresh=fresh,render=render);s.private=ns;ns['_no_pending'](context=p['context']);return s
    except BaseException:
        receiver.abort_before_arm();receiver.wait_closed();raise


def stage_root(s):
    try:
        _check(s);need(s.phase=='PREPARED','STAGE_PHASE');s.private['FILES']=tuple(_render(s))
        row=s.private['stage_private'](s.plan,dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',rootAuthorized=True,planSha256=c.digest(s.plan_raw)))
        s.phase='STAGED';return row
    except BaseException:abort_before_start(s);raise


def _unknown(s,reason):
    s.phase='UNKNOWN_RETAIN';s.snapshot=None;s.request=None
    row=dict(kind='LIVE_MODULE_RAM_UNKNOWN',operationId=s.plan['operationId'],status=s.phase,knownTerminal=False,
        retryAuthorized=False,reason=reason,sourceBodyPersisted=False,publicSnapshotReleased=False,retainedBufferPossible=True)
    path=Path(s.plan['outputDirectory'])/'unknown.json'
    if not path.exists():c.write_new(path,row)
    return row


def _counts(row,values,code):
    need(all(type(row.get(k)) is int and row[k]==v for k,v in values.items()),code)


def _flags(row,yes=(),no=(),code='FLAGS'):
    need(all(row.get(k) is True for k in yes) and all(row.get(k) is False for k in no),code)


def _native_read(s,proof,intent,epoch):
    for row,kind in ((proof,'LIVE_MODULE_RAM_NATIVE'),(intent,'LIVE_MODULE_RAM_INTENT')):
        need(type(row) is dict and row.get('kind')==kind and row.get('operationId')==s.plan['operationId']
             and row.get('scopeSha256')==s.scope_sha256 and row.get('nonce')==s.scope['requestId'],'AS_JOIN')
    native.classify_epoch(epoch,operation_id=s.plan['operationId'],scope_sha256=s.scope_sha256,process_id=48936,
        execute_thread_id=8292,callback_known=True,callback_sdk_rc=0,target_identity_verified=True)
    local_epoch=dict(epoch,kind=previous.EPOCH_KIND,epochCoverage=previous.EPOCH_COVERAGE,phase='EXECUTE_RETURNED')
    local=SimpleNamespace(plan=s.plan,scope_sha256=s.scope_sha256,scope={'readonlyNonce':s.scope['requestId']})
    previous._native_terminal(local,dict(proof,kind='LIVE_MODULE_READONLY_NATIVE'),
        dict(intent,kind='LIVE_MODULE_READONLY_INTENT'),local_epoch)
    _counts(proof,dict(captureCalls=1,commitCalls=1,capturedUtf16Units=proof['sourceUtf16Units']),'AS_CAPTURE')
    _counts(intent,dict(maximumCaptureCalls=1,maximumCommitCalls=1),'AS_CAPTURE_INTENT')
    _flags(proof,yes=('captureReturned','commitReturned','captureCandidateOnly'),no=('transportPublished',),code='AS_COMMIT')
    need(proof.get('snapshotSemantics')==live_source.SOURCE_DOMAIN,'SNAPSHOT_SEMANTICS')


def _carrier_proof(s,row,*,final,metadata=None):
    need(type(row) is dict and row.get('kind')==('LIVE_MODULE_RAM_CARRIER' if final else 'LIVE_MODULE_RAM_TRANSFER_READY')
         and row.get('operationId')==s.plan['operationId'] and row.get('scopeSha256')==s.scope_sha256
         and row.get('requestId')==s.scope['requestId'] and row.get('readerSourceSha256')==SOURCE_SHA
         and row.get('compiledSourceSha256')==s.plan['compiledSourceSha256'],'C_PROOF_JOIN')
    _counts(row,dict(revision=1,processId=48936,guiThreadId=8292,sdkRc=0,abiFault=0,contextsCreated=1,contextsReleased=1,
        functionsCreated=1,functionsReleased=1,captureCalls=1,commitCalls=1,terminalRc=0),'C_SDK_COUNTS')
    need(type(row.get('workerThreadId')) is int and 0<row['workerThreadId']<=0xFFFFFFFF and row['workerThreadId']!=8292,'C_WORKER')
    _flags(row,yes=('sdkChainEntered','sdkChainReturned','sdkChainComplete','epochClean','handlerRemoved',
        'contextCleared','functionCleared','peerVerified','readyVerified','hookRemoved','drainCompleted','dllRetainedUntilProcessExit'),
        no=('sourceBodyIncluded',),code='C_CLOSURE')
    _flags(row,yes=('ackVerified','pipeClosed','borrowReturned','buffersFreed','transferProofWritten') if final else ('retainedBuffer',),
        no=('retainedBuffer',) if final else ('ackVerified','pipeClosed','borrowReturned','buffersFreed','transferProofWritten'),code='C_PHASE')
    _counts(row,dict(captureState=5 if final else 7),'C_CAPTURE_STATE')
    need(type(row.get('utf16Units')) is int and 0<=row['utf16Units']<=131072
         and type(row.get('captureCopiedBytes')) is int and row['captureCopiedBytes']==row['utf16Units']*2
         and type(row.get('bodyBytes')) is int and 0<=row['bodyBytes']<=524288,'C_BODY_BOUNDS')
    need(previous._hex(row.get('sourceSha256'),64) and all(live_source.finite(row.get(k)) for k in ('issuedAt','validUntil','capturedAt'))
         and 0<=row['issuedAt']<=row['capturedAt']<=row['validUntil']<=row['issuedAt']+60,'C_RUNTIME_TIMES')
    if not final:_counts(row,dict(frameBytesWritten=0),'C_PREACK_COUNTERS')
    else:
        need(type(row.get('frameBytesWritten')) is int and row['bodyBytes']+32<row['frameBytesWritten']<=row['bodyBytes']+16416,'C_FRAME_COUNTER')
    if metadata is not None:
        pairs={'issuedAt':'issued_at','validUntil':'valid_until','capturedAt':'captured_at','sourceSha256':'source_sha256',
               'utf16Units':'utf16_units','bodyBytes':'byte_count'}
        need(all(row[k]==metadata[v] and type(row[k]) is type(metadata[v]) for k,v in pairs.items()),'C_FRAME_JOIN')
    return row


def _trusted_snapshot(s,frame,request):
    """Owner-thread preACK gate. Does NOT wait for final worker/host closure."""
    need(s.phase=='STARTING_RETAIN','ACK_PHASE');_check(s)
    s.private['_fresh'](s.plan)
    s.private['require_stage'](s.plan)  # Recheck immutable stage/source before ACK.
    out=Path(s.plan['outputDirectory']);proof=previous._json(out/NATIVE_FILE)
    intent=previous._json(out/INTENT_FILE);epoch=previous._json(out/EPOCH_FILE)
    _native_read(s,proof,intent,epoch)
    need(c.read(out/ARM_FILE,16)==bytes(8),'ARM_RESULT')
    callback=c.read(out/CALLBACK_FILE,32)
    need(len(callback)==24 and struct.unpack('<6I',callback)==(48936,8292,0,0x83d2,8292,1),'TAGGED_CALLBACK')
    ready=_carrier_proof(s,previous._json(out/TRANSFER_FILE),final=False,metadata=frame.metadata)
    need(proof['sourceUtf16Units']==ready['utf16Units'],'AS_C_LENGTH')
    receipt=live_source.LiveReceipt(request.binding,request.target,request.request_id,request.revision,
        frame.metadata['captured_at'],frame.metadata['valid_until'],frame.metadata['byte_count'],frame.metadata['source_sha256'],
        frame.metadata['utf16_units'],frame.metadata['bom_present'],frame.metadata['crlf_count'],frame.metadata['ends_lf'],
        tuple(proof['beforeState']),tuple(proof['afterState']),epoch['cppThrows'],epoch['otherExceptions'],ready['sdkRc'],ready['abiFault'],
        ready['contextCleared'],ready['functionCleared'],proof['ownedTypedHandlesCleared'],proof['readEqualityVerified'])
    snapshot=live_source.LiveSnapshot(receipt,frame.utf8)
    text=live_source.validate_snapshot(snapshot,request,request.target,time.monotonic());del text
    return snapshot


def _join_host(s):
    need(not s.join_attempted and s.receiver.closed and s.host is not None and s.host.poll() is None
         and s.host.stdin is not None,'HOST_JOIN_PHASE')
    s.join_attempted=True
    s.host.stdin.write(b'JOIN_VERIFIED_LIVE_RAM\n');s.host.stdin.flush();s.host.stdin.close()
    out=Path(s.plan['outputDirectory']);deadline=time.monotonic()+25
    while time.monotonic()<deadline:
        if (out/HOST_RESULT).is_file():
            row=previous._json(out/HOST_RESULT,bound=8192)
            need(row.get('kind')=='LIVE_RAM_MANAGED_TERMINAL' and row.get('operationId')==s.plan['operationId'],'HOST_JOIN')
            _flags(row,yes=('knownTerminal','hookWorkersReleased'),no=('writerAuthorized',),code='HOST_CLOSURE')
            _counts(row,dict(workerResult=0,threadId=8292),'HOST_WORKER_RESULT')
            s.host.wait(timeout=5);need(type(s.host.returncode) is int and s.host.returncode==0,'HOST_EXIT')
            need(c.read(out/WORKER_FILE,8)==bytes(4),'RAW_WORKER_RESULT')
            return row
        if s.host.poll() is not None:break
        time.sleep(.02)
    raise ValueError('LIVE_RAM_OPERATION_HOST_CLOSURE_UNKNOWN')


def _authority_result(s):
    return dict(profile=PROFILE,actualSourceSha256=SOURCE_SHA,compiledSourceSha256=s.plan['compiledSourceSha256'],
        scopeSha256=s.scope_sha256,sourceDomain=live_source.SOURCE_DOMAIN,requestId=s.scope['requestId'],revision=1,
        liveModuleRamControllerSha256=s.plan['liveModuleRamControllerSha256'],liveRamCarrierSha256=CARRIER_SHA,
        sourceBodyPersisted=False,currentEditorUnchangedVerified=False,editorLiveMcpIntegrated=False,
        **limits(),**{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


def run_root_once(s,review_path,review_pin):
    """Return (LiveSnapshot,LiveReadRequest) only after privateACK+all closure.

    Metadata result is persisted; source bytes never are. On uncertainty return
    stable UNKNOWN metadata and retain the issued operation/native ownership.
    """
    _check(s);need(s.phase=='STAGED','RUN_PHASE');p=s.plan;out=Path(p['outputDirectory'])
    build=s.private['require_stage'](p);review=previous._json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_pin)
    need(review.get('kind')==RUN_KIND and review.get('passed') is True and authority(review)
         and review.get('planSha256')==c.digest(s.plan_raw) and review.get('buildSha256')==c.digest(c.canonical(build))
         and review.get('scopeSha256')==s.scope_sha256 and review.get('actualSourceSha256')==SOURCE_SHA
         and review.get('compiledSourceSha256')==p['compiledSourceSha256'] and review.get('liveRamCarrierSha256')==CARRIER_SHA
         and review.get('liveWireSha256')==WIRE_SHA and review.get('liveRamPipeSha256')==PIPE_SHA,'ROOT_RUN')
    s.private['_no_pending'](context=p['context']);workday._audit_workday_pending(p['context'],scope=s.scope)
    need(not any((out/name).exists() for name in ('intent.json','host-identity.json','result.json','unknown.json',
        HOST_READY,HOST_RESULT,NATIVE_FILE,INTENT_FILE,EPOCH_FILE,TRANSFER_FILE,FINAL_FILE,WORKER_FILE,ARM_FILE,CALLBACK_FILE)),'ONE_ATTEMPT')
    c.write_new(_claim_path(s),_claim(s));s.phase='STARTING_RETAIN'
    c.write_new(out/'intent.json',dict(kind='LIVE_MODULE_RAM_HOST_INTENT',operationId=p['operationId'],
        planSha256=c.digest(s.plan_raw),rootRunSha256=review_pin,**_authority_result(s)))
    try:
        s.private['_fresh'](p)
        s.receiver.arm(lambda frame,request:_trusted_snapshot(s,frame,request))
        s.host=subprocess.Popen([str(reader.writer.PS),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(out/'run-live-ram.ps1')],
            cwd=out,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        c.write_new(out/'host-identity.json',reader.writer._host_identity(s.host))
        snapshot,request=s.receiver.receive(timeout=75)
        need(s.receiver.wait_closed() and s.receiver.closed,'RECEIVER_CLOSED')
        # EOF/acceptedRAM is still private: final nativebuffer closure first,
        # then managed WaitArm/Dispose/hostexit. No MCPsession is exposed here.
        deadline=time.monotonic()+10
        while not (out/FINAL_FILE).is_file() and time.monotonic()<deadline:time.sleep(.02)
        final=_carrier_proof(s,previous._json(out/FINAL_FILE),final=True)
        need(final['sourceSha256']==snapshot.receipt.source_sha256 and final['utf16Units']==snapshot.receipt.utf16_units
             and final['bodyBytes']==snapshot.receipt.byte_count,'FINAL_SNAPSHOT_JOIN')
        host=_join_host(s);s.private['_fresh'](p)
        text=live_source.validate_snapshot(snapshot,request,request.target,time.monotonic());del text
        # Transfer the sole controller-local source reference to the caller.
        # Retaining the opaque admission object must not create a hidden body
        # cache after the caller closes its expiring LiveSession.
        s.phase='KNOWN_TERMINAL_RETAIN_PARENT'
        c.write_new(out/'result.json',dict(kind='LIVE_MODULE_RAM_RESULT',operationId=p['operationId'],
            status='LIVE_RAM_SNAPSHOT_RESOURCES_CLOSED',knownTerminal=True,workerResult=0,hostExitCode=0,
            privateAckAccepted=True,resourcesClosed=True,publicSnapshotAvailableInRam=True,
            sourceSha256=snapshot.receipt.source_sha256,sourceUtf16Units=snapshot.receipt.utf16_units,
            retryAuthorized=False,**_authority_result(s)))
        return snapshot,request
    except Exception:
        return _unknown(s,'NATIVE_RAM_OR_HOST_CLOSURE_UNPROVEN')
