"""Resident LIVE lifecycle bound to a freshly verified bootstrap, not a PID.

Native source, wire, capture validation and per-job cleanup are reused. This
root-only module owns admission, current-process reservation and host lifetime.
No application source is persisted. Ambiguous native outcomes are never retried.
"""
from dataclasses import dataclass
import hashlib
import inspect
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
from types import FunctionType,SimpleNamespace
import uuid

import live_resident_bound_operation as legacy

_LEGACY_SHA='d316f3daa3add60880a85fc7a9083cbcfdced2c41ebce561072c33a6fe1b2085'
if hashlib.sha256(Path(legacy.__file__).read_bytes()).hexdigest()!=_LEGACY_SHA:
    raise ValueError('LIVE_CURRENT_LIFECYCLE_PIN')
for _name,_value in tuple(vars(legacy).items()):
    if _name.startswith('__'):continue
    if isinstance(_value,FunctionType) and _value.__globals__ is vars(legacy):
        _fn=FunctionType(_value.__code__,globals(),_name,_value.__defaults__,_value.__closure__)
        _fn.__kwdefaults__=_value.__kwdefaults__;globals()[_name]=_fn
    else:globals()[_name]=_value

CURRENT_SCOPE='ROOT_CURRENT_RESIDENT_LIVE_SCOPE'
CURRENT_RUN='ROOT_CURRENT_RESIDENT_LIVE_RUN'
_ISSUER=object();_SEALS={}
_BOOTSTRAP_CONTEXT=None


def need(ok,code):
    if not ok:raise ValueError('LIVE_CURRENT_'+code)


def _pins():
    need(c.digest(c.read(Path(legacy.__file__)))==_LEGACY_SHA,'LIFECYCLE_PIN')
    legacy._pins()


def _load_context(scope):
    nonce=scope.get('bootstrapNonce')
    need(ram.previous._hex(nonce,32),'BOOTSTRAP_NONCE')
    artifacts=ROOT/'artifacts/designer-bridge'
    path=artifacts/('current-native-context-'+nonce+'.json')
    row=ram.previous._json(path,scope.get('currentContextSha256'),bound=16384)
    need(row.get('kind')=='CURRENT_NATIVE_BOOTSTRAP_CONTEXT' and row.get('passed') is True
         and row.get('sourceBodyIncluded') is False and row.get('sdkWrites')==0,'CONTEXT_PROOF')
    bootstrap=artifacts/('sheet-notify-bootstrap-result-'+nonce+'.json')
    boot=ram.previous._json(bootstrap,row['bootstrapResultSha256'],bound=262144)
    ctx=row['context'];owned=boot['context'];build=ROOT/'build'/('designer-v43-'+nonce)
    need(boot.get('passed') is True and boot.get('bootstrapState')=='READY_HELD'
         and ctx['heldNonce']==nonce and Path(ctx['buildDirectory'])==build
         and (ctx['processId'],ctx['birth'],ctx['mainSha256'])==
             (owned['processId'],owned['processCreationFileTimeUtc'],boot['mainSha256'])
         and boot.get('applicationWrites')==0 and boot.get('configurationSaves')==0
         and boot.get('databaseUpdates')==0 and boot.get('repositoryMutations')==0,'BOOTSTRAP_JOIN')
    return row,owned


def validate_scope(row):
    need(type(row) is dict and row.get('kind')==CURRENT_SCOPE and row.get('passed') is True
         and row.get('liveResidentControllerSha256')==c.digest(c.read(Path(__file__)))
         and row.get('liveResidentCarrierSha256')==CARRIER_SHA and row.get('actualSourceSha256')==SOURCE_SHA
         and row.get('sourceDomain')==source.SOURCE_DOMAIN and row.get('rootUuid')==source.ROOT_UUID
         and row.get('modulePropertyId')==source.PROPERTY_UUID and row.get('allowedReadClasses')==['CommonModule']
         and authority(row),'SCOPE_AUTHORITY')
    need(type(row.get('bootstrapKeeperPid')) is int and row['bootstrapKeeperPid']>0
         and ram.previous._hex(row.get('bootstrapKeeperBirth'),16),'BOOTSTRAP_KEEPER')


def _physical(s):
    row,owned=_load_context(s.scope);ctx=s.plan['context']
    need(row['context']==ctx and row['sdkIdentity']==s.plan['sdkIdentity'],'CONTEXT_CHANGED')
    for pk,bk in (('processId','processCreationFileTimeUtc'),('hostProcessId','hostProcessCreationFileTimeUtc'),
                  ('launcherProcessId','launcherProcessCreationFileTimeUtc')):
        need(reader._process(owned[pk])==owned[bk],'BOOTSTRAP_PROCESS')
    need(reader._process(s.scope['bootstrapKeeperPid'])==s.scope['bootstrapKeeperBirth'],'KEEPER_PROCESS')
    need(c.digest(c.read(Path(ctx['buildDirectory'])/'runtime/modules/Snegopat/engine/main.as'))==ctx['mainSha256'],'MAIN_CHANGED')
    need(c.inspect_owned(ctx)==s.plan['sdkIdentity'],'HEALTHY_SDK_IDENTITY')
    state=Path(os.environ.get('AH1C_BRIDGE_STATE_DIR') or (Path(os.environ['LOCALAPPDATA'])/'AH_1C/bridge'))/'state.db'
    with sqlite3.connect(state.resolve().as_uri()+'?mode=ro',uri=True) as db:
        leases=db.execute("SELECT owner_operation_id FROM execution_leases WHERE resource='ah1c-write'").fetchall()
    need(leases==[(owned['leaseOwner'],)],'GOLD_LEASE')


def _identity(s):
    ctx=s.plan['context'];sdk=s.plan['sdkIdentity']
    return dict(processId=ctx['processId'],birth=ctx['birth'],guiThreadId=ctx['guiThreadId'],
                engineAddress=sdk['engineAddress'],moduleAddress=sdk['moduleAddress'])


def _reservation(s):return c._reservation(s.plan['context'])


def _markers(s):
    own=_reservation(s).relative_to(ROOT/'build').as_posix()
    return tuple(r for r in legacy._marker_snapshot(s.plan['operationId']) if r[0]!=own)


def _check(s):
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER,'ISSUED_OPERATION');_pins()
    need(c.canonical(s.plan)==s.plan_raw and authority(s.plan),'PLAN')
    scope=ram.previous._json(s.scope_path,s.scope_sha256,bound=65536);validate_scope(scope)
    need(scope==s.scope and s.plan['currentScopeSha256']==s.scope_sha256,'SCOPE_CHANGED')
    _physical(s)
    _no_pending(s)


def _audit_closed_idle(prior,out):
    """Account exactly the installed-before-READ readiness failure, no retry."""
    from process_identity import owned_process_gone
    op='f47da3507ba540759dd246d0a1d34c7d'
    need(prior.get('operationId')==op and authority(prior)
         and c.digest(c.canonical(prior))=='2f86d9a9e9d9ae9a9fce866744af95530b7b61fd65a43ad49ae15315c64a29cf','IDLE_PRIOR')
    closure_path=out/'no-read-closure.json'
    need(c.digest(c.read(closure_path,16384))=='f013f6d89c38762f1e4bd6b2b4397a854b8685a867108916f2a6b88f01646266','IDLE_ACCOUNTING_PIN')
    accounted=ram.previous._json(closure_path,bound=16384)
    need(accounted.get('kind')=='CURRENT_RESIDENT_NO_READ_CLOSURE' and accounted.get('operationId')==op
         and accounted.get('planSha256')==c.digest(c.canonical(prior))
         and accounted.get('scopeSha256')==prior['currentScopeSha256']
         and all(accounted.get(k) is True for k in ('rootOwnerGone','managedHostGone','nativeResourcesClosed','noSdkCalls','priorUnknownPreserved'))
         and all(accounted.get(k) is False for k in ('readSuccess','platformProcessStopped','retryAuthorized','sourceBodyPersisted'))
         and type(accounted.get('readCount')) is int and accounted['readCount']==0,'IDLE_CLOSURE')
    proof=ram.previous._json(out/'build-proof.json')
    need(accounted.get('buildSha256')==c.digest(c.canonical(proof))
         and c.digest(c.read(out/'Continuation.dll'))==accounted.get('dllSha256')==proof.get('librarySha256'),'IDLE_BUILD')
    diag_path=out/(WORKER_FILE+'.diagnostics.json');raw=c.read(diag_path,16384);diag=c.parse(raw)
    need(c.digest(raw)==accounted.get('diagnosticSha256') and diag.get('operationId')==op
         and diag.get('scopeSha256')==prior['currentScopeSha256']
         and diag.get('readerSourceSha256')==SOURCE_SHA and diag.get('compiledSourceSha256')==prior['compiledSourceSha256'],'IDLE_DIAGNOSTIC')
    ram._counts(diag,dict(sequence=0,lastReadSequence=0,nativeWorkerRc=702,sdkRc=999,executeRc=-2147483647,
        contextsCreated=0,contextsReleased=0,functionsCreated=0,functionsReleased=0,cppEvents=0,otherEvents=0,
        captureCalls=0,bodyCopiedBytes=0),'IDLE_COUNTS')
    ram._flags(diag,yes=('ioDrained',),no=('contextLive','functionLive','handlerLive','epochActive','hookLive',
        'jobPresent','jobMetadataObserved','sourceBodyIncluded','addressesIncluded'),code='IDLE_FLAGS')
    need(c.read(out/WORKER_FILE,8)==(702).to_bytes(4,'little'),'IDLE_NATIVE_RESULT')
    worker=accounted['worker'];need(worker['processId']==prior['context']['processId'] and worker['waitZeroMilliseconds']==0
         and worker['exitCode']==2 and int(worker['exitTime'],16)>int(worker['birth'],16),'IDLE_TERMINAL_THREAD')
    root=accounted['rootOwner'];host=accounted['managedHost'];cfg=prior['liveResidentConfiguration']
    saved_host=ram.previous._json(out/'host-identity.json')
    need((root['processId'],root['birth'])==(cfg['serverPid'],cfg['serverBirth'])
         and (host['processId'],host['birth'])==(saved_host['processId'],saved_host['birth'])
         and owned_process_gone(root['processId'],root['birth']) and owned_process_gone(host['processId'],host['birth']),'IDLE_FRESH_HOLDERS_GONE')


def _no_pending(s):
    # Exact audited no-READ failure only; every other standard route, writer,
    # reference and foreign UNKNOWN check remains in the unchanged function.
    text=inspect.getsource(c._no_pending);anchor='        if prior_identity!=identity: continue\n'
    need(text.count(anchor)==1,'PENDING_DERIVATION')
    text=text.replace(anchor,anchor+"        if operation=='f47da3507ba540759dd246d0a1d34c7d':\n            __closed_idle_audit(prior,out);continue\n",1)
    namespace=dict(vars(c),__closed_idle_audit=_audit_closed_idle)
    exec(compile(text,'<current-exact-idle-closure>','exec'),namespace)
    namespace['_no_pending'](allow_operation=s.plan['operationId'],context=s.plan['context'])


@dataclass(frozen=True)
class _CurrentSeal:
    operation:object
    plan_raw:bytes
    scope_raw:bytes
    markers:tuple
    reservation_raw:bytes
    intent_raw:bytes
    build:dict


def _fresh_identity_gate(s):
    try:
        need(type(s) is LiveResidentOperation and s.issuer is _ISSUER,'HOT_ISSUER')
        seal=s.seal
        need(type(seal) is _CurrentSeal and _SEALS.get(id(s)) is seal and seal.operation is s
             and c.canonical(s.plan)==s.plan_raw==seal.plan_raw
             and c.canonical(s.scope)==seal.scope_raw,'ADMISSION_SEAL')
        need(c.digest(c.read(s.scope_path,65536))==s.scope_sha256,'HOT_SCOPE')
        need(_markers(s)==seal.markers and c.read(_reservation(s),8192)==seal.reservation_raw
             and c.read(Path(s.plan['outputDirectory'])/'intent.json',65536)==seal.intent_raw,'HOT_MARKERS')
        need(not (Path(s.plan['outputDirectory'])/'unknown.json').exists(),'UNKNOWN_RETAIN')
        if s.phase in ('STARTING_RETAIN','READY','CLOSING') and s.host is not None:
            need(s.host.poll() is None or (s.phase=='CLOSING' and s.join_attempted and s.host.returncode==0),'HOST_LIFETIME')
        _physical(s)
    except BaseException:
        if type(s) is LiveResidentOperation and s.issuer is _ISSUER:s.phase='UNKNOWN_RETAIN'
        raise


def _managed_render(s):
    out=Path(s.plan['outputDirectory']);identity=_identity(s)
    files=ram.managed.render(dict(operationId=s.plan['operationId'],armPath=str(out/'resident-arm.bin'),
        resultPath=str(out/'resident-sdk-result.bin')),dict(identity,guiThreadId=8292));answer={}
    replacements={'resident-arm.bin':ARM_FILE,'resident-sdk-result.bin':WORKER_FILE,
        'resident-host-ready.json':HOST_READY,'resident-host-result.json':HOST_RESULT,
        'RESIDENT_':'LIVE_RESIDENT_','JOIN_VERIFIED_CLOSE':'JOIN_VERIFIED_LIVE_RESIDENT'}
    for name,raw in files.items():
        text=raw.decode('utf-8-sig')
        if name=='OwnedSdkDiagnosisHook.cs':
            text=ram.managed.replace_once(text,'Require(tid==8292U,"V233_GUI_THREAD");',
                'Require(tid=='+str(identity['guiThreadId'])+'U,"V233_GUI_THREAD");')
        for old,new in replacements.items():text=text.replace(old,new)
        if name=='run-resident.ps1':name='run-live-resident.ps1';text=text.replace('sdkResult=$code;','workerResult=$code;')
        answer[name]=text.encode('utf-8-sig')
    return answer


def _render(s):
    identity=_identity(s);birth=int(identity['birth'],16);carrier=_module('live_resident_bound_carrier',CARRIER_SHA)
    admitted=carrier.admit_source(c.read(HERE/SOURCE_NAME,32768),operation_id=s.plan['operationId'],
        scope_sha256=s.scope_sha256,scope_admitted=True,identity=identity)
    need(c.digest(admitted)==s.plan['compiledSourceSha256'],'ADMITTED_SOURCE')
    definitions=dict(AH_SDK_TARGET_PID=str(identity['processId'])+'u',AH_SDK_BIRTH_LOW=hex(birth&0xffffffff)+'u',
        AH_SDK_BIRTH_HIGH=hex(birth>>32)+'u',AH_SDK_ENGINE_ADDRESS=hex(identity['engineAddress'])+'u',
        AH_SDK_MODULE_ADDRESS=hex(identity['moduleAddress'])+'u',AH_SDK_MESSAGE='0x8065u')
    files=_managed_render(s)
    files['sdk_probe_params.h']=(''.join('#define '+k+' '+v+'\n' for k,v in definitions.items())).encode()
    files['Continuation.c']=carrier.render(admitted,configuration=s.plan['liveResidentConfiguration'],identity=identity)
    return files


def prepare_root(path,pin):
    _pins();path=c._plain(path,ROOT/'artifacts/designer-bridge');scope=ram.previous._json(path,pin,65536);validate_scope(scope)
    row,owned=_load_context(scope);op=uuid.uuid4().hex;out=ROOT/'build'/('designer-hot-v233-'+op)
    need(not out.exists(),'ONE_OPERATION')
    wire=_module('native_mcp.resident_live_wire',WIRE_SHA);pipe=_module('native_mcp.windows_resident_live_pipe',PIPE_SHA)
    identity=dict(processId=row['context']['processId'],birth=row['context']['birth'],guiThreadId=row['context']['guiThreadId'],
                  engineAddress=row['sdkIdentity']['engineAddress'],moduleAddress=row['sdkIdentity']['moduleAddress'])
    carrier=_module('live_resident_bound_carrier',CARRIER_SHA)
    admitted=carrier.admit_source(c.read(HERE/SOURCE_NAME,32768),operation_id=op,scope_sha256=pin,scope_admitted=True,identity=identity)
    context=wire.ResidentLiveContext(source.ROOT_UUID,identity['processId'],identity['birth'],op,pin,SOURCE_SHA,c.digest(admitted))
    channel=pipe.ResidentLiveChannel(identity['processId'],expected_birth=identity['birth'],context=context,timeout=60)
    try:
        cfg=dict(operationId=op,scopeSha256=pin,**channel.identity,maximumSessionSeconds=600,maximumReads=64,
            maximumRequestTtlMilliseconds=60000,armPath=(out/ARM_FILE).as_posix(),resultPath=(out/WORKER_FILE).as_posix())
        p=dict(version=233,probe=reader.PROBE,operationId=op,outputDirectory=str(out),context=row['context'],sdkIdentity=row['sdkIdentity'],
            currentScopeSha256=pin,actualSourceSha256=SOURCE_SHA,compiledSourceSha256=c.digest(admitted),liveResidentConfiguration=cfg,
            **limits(),**{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})
        s=LiveResidentOperation(_ISSUER,None,scope,path,pin,p,c.canonical(p),{},channel)
        _check(s);s.private['_wire']=wire;s.private['require_stage']=lambda plan:require_stage(s,plan)
        return s
    except BaseException:channel.abort_before_connect();channel.wait_closed();raise


def stage_root(s):
    try:
        _check(s);need(s.phase=='PREPARED','STAGE_ONCE');out=Path(s.plan['outputDirectory']);files=_render(s)
        out.mkdir();c.write_new(out/'plan.json',s.plan)
        for name,raw in files.items():
            with (out/name).open('xb') as f:f.write(raw)
        compiler=Path(s.plan['context']['buildDirectory'])/'compiler/tcc/tcc.exe';need(c.digest(c.read(compiler))==c.TCC_SHA,'COMPILER')
        need(c.digest(c.read(HERE/'NativeSdkCall.s'))==c.SOURCE_PINS['NativeSdkCall.s'],'ABI_SHIM')
        cs,cs_sha=c._carrier_compiler()
        for command in ([str(compiler),'-shared','-I'+str(out),str(out/'Continuation.c'),str(HERE/'NativeSdkCall.s'),'-lkernel32','-luser32','-o',str(out/'Continuation.dll')],
            [str(cs),'/nologo','/target:library','/platform:x86','/out:'+str(out/'OwnedCarrierPreflight.dll'),str(out/'OwnedSdkDiagnosisHook.cs'),str(out/'OwnedSdkReadonlyAttach.cs')]):
            result=subprocess.run(command,cwd=out,capture_output=True,timeout=30,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=16384,'COMPILE')
        proof=dict(kind='CURRENT_RESIDENT_BUILD',passed=True,planSha256=c.digest(s.plan_raw),
            derivedSha256={k:c.digest(v) for k,v in files.items()},librarySha256=c.digest(c.read(out/'Continuation.dll')),
            carrierAssemblySha256=c.digest(c.read(out/'OwnedCarrierPreflight.dll')),compilerSha256=c.TCC_SHA,
            carrierCompilerSha256=cs_sha,nativeInstallPerformed=False)
        c.write_new(out/'build-proof.json',proof);s.phase='STAGED';_check(s);return proof
    except BaseException:abort_before_start(s);raise


def require_stage(s,plan):
    need(plan==s.plan and c.canonical(plan)==s.plan_raw,'STAGE_PLAN');out=Path(plan['outputDirectory'])
    proof=ram.previous._json(out/'build-proof.json')
    need(proof.get('kind')=='CURRENT_RESIDENT_BUILD' and proof.get('passed') is True
         and proof.get('planSha256')==c.digest(s.plan_raw),'BUILD_PROOF')
    need(all(c.digest(c.read(out/n))==v for n,v in proof['derivedSha256'].items())
         and c.digest(c.read(out/'Continuation.dll'))==proof['librarySha256']
         and c.digest(c.read(out/'OwnedCarrierPreflight.dll'))==proof['carrierAssemblySha256'],'STAGE_FILES')
    return proof


def _host_ready(s):
    out=Path(s.plan['outputDirectory']);deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        if (out/HOST_READY).is_file():
            try:ready=ram.previous._json(out/HOST_READY,bound=8192)
            except (OSError,ValueError):
                # CREATE_NEW is visible before the managed writer flushes and
                # closes its handle. Retry only this bounded metadata read.
                need(s.host is not None and s.host.poll() is None,'READY_HOST_LIFETIME');time.sleep(.01);continue
            need(ready.get('kind')=='LIVE_RESIDENT_MANAGED_READY' and ready.get('operationId')==s.plan['operationId']
                 and ready.get('processId')==s.plan['context']['processId']
                 and ready.get('threadId')==s.plan['context']['guiThreadId']
                 and ready.get('workerExpectedAlive') is True and ready.get('nativeSourceBindingVerified') is False,'MANAGED_READY')
            return ready
        need(s.host is not None and s.host.poll() is None,'READY_HOST_LIFETIME');time.sleep(.01)
    raise ValueError('LIVE_CURRENT_MANAGED_READY_TIMEOUT')


def start_root_once(s,review_path,review_pin):
    _check(s);need(s.phase=='STAGED','START_ONCE');proof=require_stage(s,s.plan)
    review=ram.previous._json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_pin)
    need(review.get('kind')==CURRENT_RUN and review.get('passed') is True and review.get('operationId')==s.plan['operationId']
         and review.get('scopeSha256')==s.scope_sha256 and review.get('planSha256')==c.digest(s.plan_raw)
         and review.get('buildSha256')==c.digest(c.canonical(proof)) and authority(review),'ROOT_RUN')
    out=Path(s.plan['outputDirectory']);need(not any((out/n).exists() for n in ('intent.json','unknown.json',HOST_READY,WORKER_FILE)),'ONE_ATTEMPT')
    markers=_markers(s);_check(s);need(_markers(s)==markers,'ADMISSION_RACE')
    reservation=dict(version=233,nonce=s.plan['context']['heldNonce'],operationId=s.plan['operationId'],planSha256=c.digest(s.plan_raw))
    intent=dict(version=233,kind='CURRENT_RESIDENT_INTENT',operationId=s.plan['operationId'],planSha256=c.digest(s.plan_raw),rootRunSha256=review_pin)
    c.write_new(_reservation(s),reservation);c.write_new(out/'intent.json',intent)
    seal=_CurrentSeal(s,s.plan_raw,c.canonical(s.scope),markers,c.read(_reservation(s),8192),c.read(out/'intent.json',65536),proof)
    s.seal=seal;_SEALS[id(s)]=seal;s.phase='STARTING_RETAIN'
    try:
        _fresh_identity_gate(s)
        s.host=subprocess.Popen([str(reader.writer.PS),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(out/'run-live-resident.ps1')],
            cwd=out,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        c.write_new(out/'host-identity.json',reader.writer._host_identity(s.host));s.binding=s.channel.connect()
        s.binding.validate();need((s.binding.process_id,s.binding.birth,s.binding.operation_id,s.binding.scope_sha256,
            s.binding.reader_source_sha256,s.binding.compiled_source_sha256)==(s.plan['context']['processId'],s.plan['context']['birth'],
            s.plan['operationId'],s.scope_sha256,SOURCE_SHA,s.plan['compiledSourceSha256']),'READY_BINDING')
        _host_ready(s)
        s.phase='READY';_fresh_identity_gate(s);return s
    except BaseException:_unknown(s,'INSTALL_CLOSURE_UNPROVEN');raise


def _closed_receipt(s):
    """Describe verified native closure without claiming editor-focus preservation."""
    return dict(version=233,kind='LIVE_RESIDENT_RESULT',operationId=s.plan['operationId'],planSha256=c.digest(s.plan_raw),
        status='LIVE_RESIDENT_RESOURCES_CLOSED',knownTerminal=True,resourcesClosed=True,hookWorkersReleased=True,
        targetIdentityVerified=True,sdkAttempted=True,sdkResult=0,nativeInjectionPerformed=True,reads=s.sequence,
        workerResult=0,hostExitCode=0,retryAuthorized=False,scopeSha256=s.scope_sha256,actualSourceSha256=SOURCE_SHA,
        compiledSourceSha256=s.plan['compiledSourceSha256'],sourceDomain=source.SOURCE_DOMAIN,
        sourceBodyPersisted=False,currentEditorUnchangedVerified=False)


def close_root(s):
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER and s.phase=='READY' and not s.inflight,'CLOSE_PHASE')
    s.inflight=True
    try:
        _fresh_identity_gate(s);s.phase='CLOSING';wire=s.private['_wire']
        command=wire.ResidentLiveCommand(wire.CLOSE,s.sequence+1,uuid.uuid4().hex,0,None)
        s.channel.close(wire.build_command(command,binding=s.binding,now=time.monotonic(),previous_sequence=s.sequence),lambda row:_validate_close(s,row))
        need(s.channel.wait_closed() and s.channel.closed,'CHANNEL_CLOSED');s.join_attempted=True
        need(s.host is not None and s.host.poll() is None and s.host.stdin is not None,'HOST_JOIN')
        s.host.stdin.write(b'JOIN_VERIFIED_LIVE_RESIDENT\n');s.host.stdin.flush();s.host.stdin.close();s.host.wait(timeout=30)
        need(s.host.returncode==0,'HOST_EXIT');out=Path(s.plan['outputDirectory']);terminal=ram.previous._json(out/HOST_RESULT,bound=8192)
        need(terminal.get('kind')=='LIVE_RESIDENT_MANAGED_TERMINAL' and terminal.get('knownTerminal') is True
             and terminal.get('hookWorkersReleased') is True and terminal.get('workerResult')==0
             and terminal.get('threadId')==s.plan['context']['guiThreadId']
             and c.read(out/WORKER_FILE,8)==bytes(4),'MANAGED_TERMINAL')
        _fresh_identity_gate(s);_require_closed_diagnostics(s)
        result=_closed_receipt(s)
        need(c.read(_reservation(s),8192)==s.seal.reservation_raw,'OWN_RESERVATION');_reservation(s).unlink()
        c.write_new(out/'result.json',result)
        s.phase='CLOSED';return result
    except BaseException:return _unknown(s,'CLOSE_CLOSURE_UNPROVEN')
    finally:s.inflight=False
