"""Root-only fixed read of a known, retained partial writer; never Save/reapply.

The old writer and its original packet remain alive. This observer owns only a
readonly carrier. The parent's shared writer reservation is never replaced or
removed. A diagnostic UNKNOWN therefore remains visible in the233 namespace.
"""
from dataclasses import dataclass
from pathlib import Path
from types import FunctionType
import inspect
import json
import re
import subprocess
import sys
import time
import uuid
import live_sdk_continuation_v233 as c
import runner_writer_dispatch as writer
import sheet_notify_pending_editor_recipe as recipe
import sheet_notify_pending_resource_recipe as resource_recipe

ROOT=c.ROOT
HERE=c.HERE
PARENT_SHA='04569dda63f46c12956518cec3e474d714fc25c14fc683c17d79f13606a4d681'
SOURCE_SHA='d79157106535954e754052e862265f806c86ef63718ba82bc54b9be0cdbbff15'
WORKER_SHA='b345dd214b9cb4cfe5de866b6781da0b72e2e29932ac2278557bae2d9e8c3453'
RECIPE_SHA='73ff4c1a3123cddf699154cc59a634ee3dd3a5b147f82c2166ee511d355d0534'
CHECK_NAME='pending-editors-check-only-1aca231b3f8d4b43bd3f316a0531e257.json'
CHECK_SHA='b4b03e595d60ecf288db751a5c150f5bd8658c0cfb03bbe471e1ec606c862069'
PROBE='RUNNER_EDITORS_V247'  # Carrier identity; actual read source is separately pinned.
EDITOR_PROFILE='PENDING_COMMON_MODULE_EDITORS'
RESOURCE_PROFILE='PENDING_STORED_RESOURCES'
RESOURCE_SOURCE_SHA='84a8a00510f60fc5ed0620107147738e57b665b09dba2bc0699d4c145b5e0067'
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('PENDING_READ_'+code)


def _json(path,pin=None,bound=32768):
    raw=c.read(path,bound)
    if pin is not None:need(c._writer_hash(pin) and c.digest(raw)==pin,'PROOF_PIN')
    value=c.parse(raw);need(type(value) is dict,'PROOF_OBJECT');return value


def _process(pid):
    # Fixed read-only process query; no command lines or environment are read.
    from ctypes import wintypes as w
    ct=c.ct;k=ct.WinDLL('kernel32',use_last_error=True)
    k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
    k.GetProcessTimes.argtypes=[w.HANDLE]+[ct.POINTER(ct.c_uint64)]*4
    k.GetExitCodeProcess.argtypes=[w.HANDLE,ct.POINTER(w.DWORD)];k.CloseHandle.argtypes=[w.HANDLE]
    need(type(pid) is int and 0<pid<2**32,'OWNER_PID');handle=k.OpenProcess(0x1000,False,pid)
    need(bool(handle),'OWNER_PROCESS')
    try:
        code=w.DWORD();times=[ct.c_uint64() for _ in range(4)]
        need(k.GetExitCodeProcess(handle,ct.byref(code)) and code.value==259
            and k.GetProcessTimes(handle,*(ct.byref(v) for v in times)),'OWNER_RUNNING')
        return f'{times[0].value:016x}'
    finally:k.CloseHandle(handle)


def _profile(profile):
    need(profile in (EDITOR_PROFILE,RESOURCE_PROFILE),'FIXED_READ_PROFILE')
    if profile==EDITOR_PROFILE:
        return recipe,SOURCE_SHA,CHECK_NAME,CHECK_SHA,'sheet_notify_pending_editor_recipe.py',RECIPE_SHA
    return (resource_recipe,RESOURCE_SOURCE_SHA,'pending-stored-resources-check-only-4c89a9c8b93a42f095f5bf54f9a6b60b.json',
        '2ccd1c0393e2cc935f0ce2f3a2595c715db698c84e91505590a7a069b3ac6745',
        'sheet_notify_pending_resource_recipe.py','a26438d2af7e6bf54dad5ecc6a35c222151a1f019d492c7e156f10841cb9be3a')


def _pins(profile=EDITOR_PROFILE):
    selected,source_sha,check_name,check_sha,recipe_name,recipe_pin=_profile(profile)
    for name,pin in [('live_sdk_continuation_v233.py',PARENT_SHA),
            ('sheet_notify_writer_session.py',WORKER_SHA),(recipe_name,recipe_pin),
            ('runner_writer_dispatch.py','f50c65792026e3299cc4ab75dc5006fa0c2f57553ea1b03c1a9c9e9157d93aff')]:
        need(c.digest(c.read(HERE/name))==pin,'TOOL_PIN')
    need(c.digest(selected.derive_source())==source_sha,'OBSERVER_SOURCE')
    check=_json(ROOT/'artifacts/designer-bridge'/check_name,check_sha)
    need(check.get('sourceSha256')==source_sha and check.get('positive',{}).get('compileVerified') is True
         and check.get('positive',{}).get('exitCode')==0 and check.get('negativeCoverage') is True
         and check.get('ownRuntimeRemoved') is True and check.get('goldStarted') is False
         and check.get('scriptRunRequested') is False,'COLD_COMPILE')


@dataclass(slots=True)
class Read:
    _issuer:object
    review_path:Path
    review_sha256:str
    scope:dict
    plan:dict
    plan_raw:bytes
    private:dict
    phase:str='PREPARED'
    host:object=None


def _check_owner(r):
    need(type(r) is Read and r._issuer is _ISSUER,'ISSUED_READ')
    need(c.digest(c.read(Path(__file__)))==r.plan['pendingReadControllerSha256'],'CONTROLLER_DRIFT')
    profile=r.plan['pendingReadProfile'];_pins(profile)
    need(r.plan['actualReadSourceSha256']==_profile(profile)[1],'ACTUAL_READ_PROFILE')
    scope=_json(r.review_path,r.review_sha256)
    need(scope==r.scope and scope.get('kind')=='ROOT_PENDING_EDITOR_READ_SCOPE'
        and set(scope)==set(('kind passed readOnly sessionNonce writerOperationId pid birth ownerPid ownerBirth '
            'checkpointSha256 sourceWritesAuthorized configurationSavesAuthorized databaseUpdatesAuthorized '
            'repositoryMutationsAuthorized releaseResourcesAuthorized').split())
        and scope.get('passed') is True and scope.get('readOnly') is True
        and all(scope.get(k) is False for k in ('sourceWritesAuthorized','configurationSavesAuthorized',
            'databaseUpdatesAuthorized','repositoryMutationsAuthorized','releaseResourcesAuthorized')),'READ_SCOPE')
    ctx=r.plan['context'];op=scope['writerOperationId'];out=ROOT/'build'/('designer-writer-v263-'+op)
    need(type(op) is str and c.HEX32.fullmatch(op) and scope['sessionNonce']==ctx['heldNonce']
        and (scope['pid'],scope['birth'])==(ctx['processId'],ctx['birth']),'TARGET_SCOPE')
    need(_process(scope['ownerPid'])==scope['ownerBirth'],'OWNER_BIRTH')
    check=_json(ROOT/'artifacts/designer-bridge'/('root-notify-actual-write-checkpoint-'+op+'.json'),scope['checkpointSha256'])
    need(check.get('ownerPid')==scope['ownerPid'] and check.get('nativePid')==scope['pid']
        and check.get('nativeBirth')==scope['birth'] and check.get('state')=='UNSAVED_UNKNOWN_RETAIN'
        and check.get('packetRetained') is True and check.get('templateReferencesRetained')==2,'RETAINED_CHECKPOINT')
    proofs=check['proofs'];rows={name:_json(out/name,pin,262144) for name,pin in proofs.items()}
    intent=rows['intent.json'];native=rows['composite-proof.json'];sdk=rows['sdk-receipt.json'];stage=rows['stage-package.json']
    need(intent.get('operationId')==op and intent.get('route')=='RUNNER_SHEET_NOTIFY_WRITE'
        and intent.get('compositionProfile')=='SHEET_NOTIFY' and intent.get('writerAuthorized') is True
        and intent.get('mainSha256')==ctx['mainSha256']
        and (intent.get('pid'),intent.get('birth'),intent.get('sessionNonce'))==
            (ctx['processId'],ctx['birth'],ctx['heldNonce'])
        and intent.get('compositeSha256')=='307ea65c71871347cc63d3b305bc0c2ba057d3a5076a3b7cd04346f0022286bb'
        and not (out/'result.json').exists(),'EXACT_PARTIAL_WRITER')
    need(sdk.get('status')=='SDK_TERMINAL_UNSAVED_RETAIN'
        and sdk.get('intentSha256')==c.digest(c.canonical(intent)) and sdk.get('sdkResult')==0
        and type(sdk.get('sdkResult')) is int and all(sdk.get(k) is True for k in
            ('knownTerminal','hookWorkersReleased','targetIdentityVerified'))
        and (sdk.get('pid'),sdk.get('birth'),sdk.get('sessionNonce'),sdk.get('operationId'))==
            (ctx['processId'],ctx['birth'],ctx['heldNonce'],op),'SDK_TERMINAL')
    need(native.get('status')=='COMPOSITE_UNKNOWN_RETAIN' and native.get('reason')=='FINAL_METADATA'
        and native.get('operationId')==op and native.get('packetSha256')==intent['packetSha256']
        and native.get('moduleMetadataDirtyVerified') is False and native.get('sheetStatus')=='WROTE_VERIFIED'
        and native.get('moduleStatus')=='APPLIED_RAM' and all(native.get(k) is True for k in
            ('packetPreflightVerified','packetProofWritten','modulesPrepared','sheetVerified','sheetProofWritten',
             'selectionRestored','notifyPrepared','checkpointReferenceRetained','documentReferenceRetained'))
        and all(type(native.get(k)) is int and native[k]==v for k,v in
            [('modulesApplied',2),('moduleWriteCalls',2),('moduleActionBeginCalls',2),('moduleActionCloseCalls',2),
             ('sheetMergesCompleted',3),('sheetSettersCompleted',36),('nativeNotifyCalls',1),
             ('configurationSaves',0),('databaseUpdates',0),('repositoryMutations',0)]),'KNOWN_PARTIAL_STATE')
    need(stage.get('intentSha256')==c.digest(c.canonical(intent))
        and stage.get('compositionProfile')=='SHEET_NOTIFY'
        and stage.get('compositeSourceSha256')==intent['compositeSha256'],'STAGE_INTENT_JOIN')
    marker=dict(version=233,nonce=ctx['heldNonce'],operationId=op,planSha256=stage['bindingSha256'],
        processId=ctx['processId'],birth=ctx['birth'],writerPackageVersion=263,intentSha256=c.digest(c.canonical(intent)))
    need(_json(c._reservation(ctx))==marker,'PARENT_MARKER')
    need(c.canonical(r.plan)==r.plan_raw,'PLAN_DRIFT')
    return intent


def _namespace(r):
    """Private function globals; the loaded233 module is never patched."""
    ns=dict(c.__dict__)
    for name,value in c.__dict__.items():
        if isinstance(value,FunctionType) and value.__module__==c.__name__:
            ns[name]=FunctionType(value.__code__,ns,value.__name__,value.__defaults__,value.__closure__)
            ns[name].__kwdefaults__=value.__kwdefaults__
    source=inspect.getsource(c._audit_writer_pending)
    old='        if prior_identity!=identity:continue\n'
    need(source.count(old)==1,'AUDIT_ANCHOR')
    source=source.replace(old,old+"        if operation==__pending_writer_operation:\n            need(prior==__pending_owner_check(),'EXACT_OWN_PENDING_WRITER');continue\n",1)
    ns['__pending_writer_operation']=r.scope['writerOperationId'];ns['__pending_owner_check']=lambda:_check_owner(r)
    exec(compile(source,'<fixed-own-pending-writer-audit>','exec'),ns)
    source=inspect.getsource(c._no_pending)
    old='or operation==allow_operation:';need(source.count(old)==1,'READ_AUDIT_ANCHOR')
    source=source.replace(old,'or operation==allow_operation or operation==__pending_read_operation:',1)
    ns['__pending_read_operation']=r.plan['operationId']
    exec(compile(source,'<fixed-own-pending-read-audit>','exec'),ns)
    audit=ns['_no_pending']
    def no_pending(allow_operation=None,context=None):
        need(context==r.plan['context'] and allow_operation in (None,r.plan['operationId']),'AUDIT_SCOPE')
        _check_owner(r);return audit(allow_operation=r.scope['writerOperationId'],context=context)
    def fresh(plan):
        _check_owner(r);c._fresh(plan)
    def render(plan,raw):
        _check_owner(r);need(plan==r.plan,'RENDER_PLAN')
        files=c.render(plan,raw);header=files['sdk_probe_params.h'].decode()
        line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
        selected=_profile(plan['pendingReadProfile'])[0]
        source=selected.derive_source().decode().replace('__PROOF_PATH__',
            (Path(plan['outputDirectory'])/c._probe_spec(PROBE)[3]).as_posix())
        header=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(source,ensure_ascii=False))
        files['sdk_probe_params.h']=header.encode();return files
    ns.update(_no_pending=no_pending,_fresh=fresh,render=render)
    return ns


def prepare_root(review_path,review_sha256,*,profile=EDITOR_PROFILE):
    """Prepare only the fixed SHA-only observer for one root-reviewed owner."""
    _pins(profile);source_sha=_profile(profile)[1]
    path=c._plain(review_path,ROOT/'artifacts/designer-bridge');scope=_json(path,review_sha256)
    need(c.HEX32.fullmatch(scope['sessionNonce']) and c.HEX32.fullmatch(scope['writerOperationId']),'SCOPE_IDS')
    ctx=c._context(scope['sessionNonce']);sdk=c.inspect_owned(ctx);op=uuid.uuid4().hex;spec=c._probe_spec(PROBE)
    plan=dict(version=233,probe=PROBE,operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),
        context=ctx,sdkIdentity=sdk,probeSha256=spec[2],controllerSha256=PARENT_SHA,
        testSha256=c.digest(c.read(HERE.parent/'tests/test_live_sdk_continuation_v233.py')),nativeDriverPins=dict(c.SOURCE_PINS),
        writerAuthorized=False,captureAuthorized=False,applicationWrites=0,configurationExports=0,configurationImports=0,
        oneShot=True,loadedDllRequiresTargetExitBeforeCleanup=True,pendingReadProfile=profile,
        actualReadSourceSha256=source_sha,pendingReadControllerSha256=c.digest(c.read(Path(__file__))),
        pendingScopeSha256=review_sha256,parentWriterOperationId=scope['writerOperationId'])
    r=Read(_ISSUER,path,review_sha256,scope,plan,c.canonical(plan),{})
    _check_owner(r);r.private=_namespace(r);r.private['_no_pending'](context=ctx);return r


def stage_root(r):
    """Stage fixed readonly carrier; no SDK/native call or application write."""
    _check_owner(r);need(r.phase=='PREPARED','STAGE_ONCE')
    proof=r.private['stage_private'](r.plan,dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',
        rootAuthorized=True,planSha256=c.digest(r.plan_raw)))
    r.phase='STAGED';return proof


def run_root_once(r,review_path,review_sha256):
    """Execute one root-reviewed read, keeping the original writer reservation."""
    _check_owner(r);need(r.phase=='STAGED','RUN_PHASE')
    p=r.plan;ns=r.private;ctx=p['context'];out=Path(p['outputDirectory']);plan_sha=c.digest(r.plan_raw)
    build=ns['require_stage'](p);review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind')=='ROOT_PENDING_EDITOR_READ_RUN' and review.get('passed') is True
        and review.get('planSha256')==plan_sha and review.get('buildSha256')==c.digest(c.canonical(build))
        and review.get('actualReadSourceSha256')==p['actualReadSourceSha256'] and review.get('scopeSha256')==r.review_sha256
        and all(review.get(k) is False for k in ('sourceWritesAuthorized','configurationSavesAuthorized',
            'databaseUpdatesAuthorized','repositoryMutationsAuthorized','releaseResourcesAuthorized')),'RUN_REVIEW')
    ns['_no_pending'](context=ctx)
    need(not any((out/n).exists() for n in ('intent.json','host-identity.json','host-result.json','result.json',
        'unknown.json',c._probe_spec(PROBE)[3])),'ONE_ATTEMPT')
    intent=dict(version=233,planSha256=plan_sha,operationId=p['operationId'],probe=PROBE,
        profile=p['pendingReadProfile'],actualReadSourceSha256=p['actualReadSourceSha256'],rootReadReviewSha256=review_sha256,
        parentWriterOperationId=r.scope['writerOperationId'],readOnly=True,configurationSaves=0)
    # This standard233 namespace remains visible to every ordinary route.
    c.write_new(out/'intent.json',intent);r.phase='DISPATCHED_RETAIN'
    ns['_fresh'](p)
    r.host=subprocess.Popen([str(writer.PS),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(out/'run-fixed.ps1')],
        cwd=out,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    identity=writer._host_identity(r.host);c.write_new(out/'host-identity.json',identity)
    deadline=time.monotonic()+55
    while time.monotonic()<deadline:
        if (out/'host-result.json').is_file():
            try:result=_json(out/'host-result.json',bound=8192)
            except (OSError,ValueError):time.sleep(.05);continue
            if result.get('version')==233 and result.get('knownTerminal') is True and result.get('hookWorkersReleased') is True:
                try:r.host.wait(timeout=5)
                except subprocess.TimeoutExpired:break
                need(r.host.returncode==0 and result.get('threadId')==ctx['guiThreadId']
                     and type(result.get('sdkResult')) is int,'HOST_TERMINAL')
                ns['_fresh'](p)
                result.update(planSha256=plan_sha,targetIdentityVerified=True,probe=PROBE,policyProofPresent=False,
                    probeProofPresent=(out/c._probe_spec(PROBE)[3]).is_file(),nativeInjectionPerformed=True,
                    pendingReadProfile=p['pendingReadProfile'],actualReadSourceSha256=p['actualReadSourceSha256'],
                    parentWriterOperationId=r.scope['writerOperationId'],configurationSaves=0)
                c.write_new(out/'result.json',result);r.phase='SDK_TERMINAL_RETAIN_PARENT';return result
            break
        if r.host.poll() is not None:break
        time.sleep(.05)
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=p['operationId'],
        targetProcessId=ctx['processId'],hostProcessId=r.host.pid,retryAuthorized=False)
    c.write_new(out/'unknown.json',result);return result
