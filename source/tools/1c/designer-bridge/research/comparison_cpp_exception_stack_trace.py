"""One fixed rejected-comparison stack diagnostic; no configuration writes.

Diagnostic closure is independent of comparison reliability. Old rejected
observations stay UNKNOWN; only exact closed-runtime maintenance is admitted.
"""
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace, FunctionType
import inspect
import json
import subprocess
import time
import uuid
import repeatable_stock_comparison_type_epoch as repeatable
import comparison_cpp_exception_stack_epoch as epoch

c=repeatable.c
reader=repeatable.reader
ROOT=c.ROOT
HERE=c.HERE
REPEATABLE_SHA='7ec7d40e76f380dbf71a05ae9a7231b726f9d8fe225cf0afe1b4369b93693c57'
EPOCH_SHA='ab6413c1aa26bce55e61cd614302e6ea631cdab4def00eee9bbfd1dca5d2ae52'
EPOCH_C_SHA='b1617bce4d8745f4e33667eea2d30b5bf581888103cf493b4b707a0234441bc9'
EPOCH_CHECK_NAME='comparison-cpp-stack-epoch-compile-2f703938a92641dba3cec55c5b3750e1.json'
EPOCH_CHECK_SHA='4c4530b6d7ed95b27603027aeeed22fc633d3bde76fc0e9db4567ee1ac7ea382'
SOURCE_SHA=repeatable.SOURCE_SHA
MAIN_SHA=repeatable.MAIN_SHA
PROFILE='MATCHED_LISTSTREAM_PUBLIC_STACK_DIAGNOSTIC_ONLY'
NATIVE_FILE=repeatable.NATIVE_FILE
INTENT_FILE=repeatable.INTENT_FILE
EPOCH_FILE='cpp-exception-stack-epoch.json'
TRUE_AUTH=repeatable.TRUE_AUTH+('matchedTypeStackTraceAuthorized',)
FALSE_AUTH=repeatable.FALSE_AUTH+('rawStackAddressesOutputAuthorized',)
RETIRED='e3208d5d0f1e4bb2b2cf175a72804ee8'
RETIRED_PLAN_SHA='5fe8cc03b1bd351d512b98e788d62b34ef3284698ad6690371a4ea8e52f0baf6'
RETIRED_SCOPE_SHA='43aa0dc4dbd8896bc2523d4bba8e28310aa58040e0c11d831cd965439355f2b5'
RETIRED_PINS={
 'plan.json':'d18c5e4ae636ff3d5521d4c1255ec2553f8f3d9683d6d952aeef375b6396787b',
 NATIVE_FILE:'02d90ae4723a794a3971ca74290d670572571f61e4495c8f5836de0a29a5b0e3',
 repeatable.EPOCH_FILE:'83e1c106691cbaf7f67f04ea90318fdf9b6ce7136c3bf0834d2bea6ca83a048a',
 'sdk-receipt.json':'3bea1d1dd760622b18f847e7e0ff7d50a6d4cb327130257ed47fa98870b109c1',
 'unknown.json':'0cc1bb510b50e1242021635b36ab39389976cefce82fffaff0752e8dc40ed642',
 'intent.json':'3aa6ebcdd70034016d379efcda5028f13f891bb75ac51cee6c46159cb99ee044'}
RETIRED_CLAIM_SHA='e5f5a079e79ffade993babd86aa02b6bc01a81694d59486ff72bb1fd98cd8426'
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('COMPARISON_CPP_STACK_TRACE_'+code)


def _json(path,pin=None,bound=32768):return reader._json(path,pin,bound)


def _authority(row):
    return repeatable._authority(row) and all(row.get(k) is True for k in TRUE_AUTH) \
        and all(row.get(k) is False for k in FALSE_AUTH) \
        and all(type(row.get(k)) is int and row[k]==v for k,v in
            (('maximumStackFrames',64),('maximumRetainedFrntendRvas',16),('maximumStackEvents',32))) \
        and row.get('thirdRetiredObservationOperationId')==RETIRED


def _epoch_carrier_source():
    need(EPOCH_C_SHA!='0'*64,'C_SOURCE_NOT_FROZEN');raw=epoch.render()
    need(c.digest(raw)==EPOCH_C_SHA,'C_SOURCE_PIN');source=raw.decode()
    source=c._replace_once(source,'if(GetCurrentThreadId()!=sdkGuiThread)rc=110;',
        'if(GetCurrentThreadId()!=sdkGuiThread || sdkGuiThread!=AH_SDK_EXPECTED_GUI_THREAD)rc=110;')
    source=c._replace_once(source,'if(!valid && diagnostic[0]==0)',
        'if(thread!=AH_SDK_EXPECTED_GUI_THREAD)valid=FALSE;\n if(!valid && diagnostic[0]==0)')
    return source.encode()


def _pins():
    need(EPOCH_SHA!='0'*64 and EPOCH_CHECK_SHA!='0'*64,'STACK_PROOFS_NOT_FROZEN')
    for module,pin in ((repeatable,REPEATABLE_SHA),(epoch,EPOCH_SHA)):
        need(c.digest(c.read(Path(module.__file__)))==pin,'DEPENDENCY_PIN')
    repeatable._pins();_epoch_carrier_source()
    proof=_json(ROOT/'artifacts/designer-bridge'/EPOCH_CHECK_NAME,EPOCH_CHECK_SHA)
    need(proof.get('kind')=='COMPARISON_CPP_EXCEPTION_STACK_EPOCH_COMPILE_ONLY'
        and proof.get('generatorSha256')==EPOCH_SHA and proof.get('derivedCSourceSha256')==EPOCH_C_SHA
        and proof.get('baselineSha256')=='e22ea0a88316fdeca21e70c3e6509619624cbe3203c05d8315a7e241830d6d0c'
        and type(proof.get('positiveCompileExit')) is int and proof['positiveCompileExit']==0
        and type(proof.get('negativeMissingScopeMacroExit')) is int and proof['negativeMissingScopeMacroExit']!=0
        and proof.get('ownCompilerDirectoryRemoved') is True
        and all(proof.get(k) is False for k in ('goldStarted','libraryLoaded','sourceAdmitted'))
        and all(type(proof.get(k)) is int and proof[k]==0 for k in
            ('targetProcessId','nativeCalls','sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')),'STACK_COMPILE_PROOF')


def _retired_trace_predecessor_audit(plan):
    """Exact e320 reference closure; its known rejected comparison stays rejected."""
    need(c.digest(c.canonical(plan))==RETIRED_PLAN_SHA and plan.get('operationId')==RETIRED
        and plan.get('actualSourceSha256')==SOURCE_SHA and plan.get('repeatableStockComparisonControllerSha256')==REPEATABLE_SHA
        and (plan.get('context',{}).get('processId'),plan.get('context',{}).get('birth'),
             plan.get('context',{}).get('guiThreadId'),plan.get('context',{}).get('mainSha256'))==
            (48936,'01dd5d0180299126',8292,MAIN_SHA),'RETIRED_PLAN')
    out=ROOT/'build'/('designer-hot-v233-'+RETIRED);need(not (out/'result.json').exists(),'RETIRED_RESULT_MUST_REMAIN_ABSENT')
    rows={name:_json(out/name,pin) for name,pin in RETIRED_PINS.items()}
    need(rows['plan.json']==plan,'RETIRED_RAW_PLAN')
    native=rows[NATIVE_FILE];reserved=_json(out/INTENT_FILE,bound=4096)
    need(repeatable._native_terminal(SimpleNamespace(plan=plan,scope_sha256=RETIRED_SCOPE_SHA),native,reserved)==
        'REPEATABLE_COMPARE_OBSERVED_DRAINED_CLEAN'
        and [v['releasedSlots'] for v in native['enumerations']]==[56,57]
        and all((v['oldCountBefore'],v['oldCountDuring'],v['oldCountAfter'])==(10,11,10) for v in native['enumerations'])
        and native['selectedReferenceCountDuring']==7 and native['selectedReferenceCountAfter']==6,'RETIRED_RUNTIME_CLOSURE')
    ep=rows[repeatable.EPOCH_FILE]
    need(ep.get('kind')=='COMPARISON_CPP_EXCEPTION_TYPE_EPOCH' and ep.get('operationId')==RETIRED
        and ep.get('scopeSha256')==RETIRED_SCOPE_SHA and ep.get('phase')=='EXECUTE_RETURNED'
        and all(ep.get(k) is True for k in ('handlerRegistered','handlerRemoved','executeEntered','executeReturned',
            'selfReferenceRetained','dllMustRemainLoadedUntilProcessExit','typeMetadataOnly'))
        and all(type(ep.get(k)) is int and ep[k]==v for k,v in
            (('cppThrows',6),('cppThrowsExecuteThread',6),('decodedCppThrows',6),('unknownCppThrows',0),
             ('listStreamCompatibleThrows',2),('cppThrowsOtherThreads',0),('otherExceptions',0),('sdkExecuteRc',0))),
        'RETIRED_REJECTED_TYPE_EPOCH')
    sdk=rows['sdk-receipt.json'];intent=rows['intent.json'];unknown=rows['unknown.json']
    claim=_json(ROOT/'artifacts/designer-bridge'/('repeatable-stock-comparison-claim-'+RETIRED_SCOPE_SHA+'.json'),RETIRED_CLAIM_SHA)
    need(sdk.get('knownTerminal') is True and sdk.get('hookWorkersReleased') is True
        and type(sdk.get('sdkResult')) is int and sdk['sdkResult']==0
        and type(sdk.get('threadId')) is int and sdk['threadId']==8292
        and all(row.get('operationId')==RETIRED and row.get('scopeSha256')==RETIRED_SCOPE_SHA for row in (sdk,intent,unknown,claim))
        and all(row.get('planSha256')==RETIRED_PLAN_SHA for row in (sdk,intent))
        and all(row.get('actualSourceSha256')==SOURCE_SHA for row in (sdk,intent,unknown,claim))
        and all(sdk.get(k) is False for k in repeatable.FALSE_AUTH)
        and claim.get('kind')=='REPEATABLE_STOCK_COMPARISON_CLAIM' and claim.get('writerOperationId')==plan.get('parentWriterOperationId')
        and unknown.get('status')=='UNKNOWN_RETAIN' and unknown.get('knownTerminal') is False
        and unknown.get('retryAuthorized') is False and unknown.get('reason')=='CPP_EPOCH_NATIVE_OR_FRESH_CLOSURE_UNPROVEN',
        'RETIRED_SDK_UNKNOWN_INTENT_CLAIM')
    return 'LISTSTREAM_REJECTED_REFERENCE_CLOSED_DIAGNOSTICS_ONLY'


def _maintenance_namespace(parent):
    ns=reader._namespace(parent);source=inspect.getsource(c._no_pending)
    skip='or operation==allow_operation:';anchor='        if prior_identity!=identity: continue\n'
    need(source.count(skip)==1 and source.count(anchor)==1,'PRIVATE_AUDIT_ANCHORS')
    source=source.replace(skip,'or operation==allow_operation or operation==__pending_read_operation:',1)
    source=source.replace(anchor,anchor+
        '        if operation==__retained_reference_operation:\n'
        '            __retained_reference_audit(prior);continue\n'
        '        if operation==__retired_observation_operation:\n'
        '            __retired_observation_audit(prior);continue\n'
        '        if operation==__retired_trace_predecessor:\n'
        '            __retired_trace_predecessor_audit(prior);continue\n',1)
    ns.update(__retained_reference_operation=repeatable.base.RETIRED_OPERATION,
        __retained_reference_audit=repeatable.base._retained_reference_audit,
        __retired_observation_operation=repeatable.RETIRED_OBSERVATION,__retired_observation_audit=repeatable._retired_observation_audit,
        __retired_trace_predecessor=RETIRED,__retired_trace_predecessor_audit=_retired_trace_predecessor_audit)
    exec(compile(source,'<three-exact-closed-runtime-diagnostic-permits>','exec'),ns);audit=ns['_no_pending']
    def no_pending(allow_operation=None,context=None):
        need(context==parent.plan['context'] and allow_operation in
            (None,parent.plan['operationId'],ns['__pending_read_operation']),'MAINTENANCE_SCOPE')
        reader._check_owner(parent);return audit(allow_operation=parent.scope['writerOperationId'],context=context)
    ns['_no_pending']=no_pending;return ns


def _prepare_parent(path,pin):
    ns=dict(reader.__dict__);ns['_namespace']=_maintenance_namespace
    prepare=FunctionType(reader.prepare_root.__code__,ns,reader.prepare_root.__name__,reader.prepare_root.__defaults__,reader.prepare_root.__closure__)
    prepare.__kwdefaults__=reader.prepare_root.__kwdefaults__;return prepare(path,pin)


@dataclass(slots=True)
class StackTrace:
    _issuer:object
    parent:object
    scope:dict
    scope_path:Path
    scope_sha256:str
    plan:dict
    plan_raw:bytes
    private:dict
    phase:str='PREPARED'
    host:object=None


def _claim_path(s):return ROOT/'artifacts/designer-bridge'/('comparison-cpp-stack-trace-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='COMPARISON_CPP_STACK_TRACE_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
        actualSourceSha256=SOURCE_SHA,controllerSha256=s.plan['stackTraceControllerSha256'],
        writerOperationId=q['operationId'],writerIntentSha256=c.digest(c.canonical(q)),packetSha256=q['packetSha256'],
        sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'],matchedTypeStackTraceAuthorized=True)


def _check(s):
    need(type(s) is StackTrace and s._issuer is _ISSUER,'ISSUED_TRACE');_pins();p=s.plan;ctx=p['context']
    need(c.canonical(p)==s.plan_raw and p.get('stackTraceControllerSha256')==c.digest(c.read(Path(__file__)))
        and p.get('stackTraceProfile')==PROFILE and _authority(p)
        and p.get('actualSourceSha256')==SOURCE_SHA and p.get('cppEpochGeneratorSha256')==EPOCH_SHA
        and p.get('cppEpochCSourceSha256')==EPOCH_C_SHA and p.get('actualCarrierCSourceSha256')==c.digest(_epoch_carrier_source())
        and p.get('writerAuthorized') is True and p.get('captureAuthorized') is False
        and type(p.get('applicationWrites')) is int and p['applicationWrites']==0
        and p.get('traceScopeSha256')==s.scope_sha256 and p.get('readScopeSha256')==s.parent.review_sha256
        and ctx==s.parent.plan['context'],'PLAN_AUTHORITY')
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256'))==
        (48936,'01dd5d0180299126',8292,MAIN_SHA),'FIXED_NATIVE')
    q=reader._check_owner(s.parent);scope=_json(s.scope_path,s.scope_sha256)
    need(scope==s.scope and scope.get('kind')=='ROOT_COMPARISON_CPP_STACK_TRACE_SCOPE' and scope.get('passed') is True
        and _authority(scope) and scope.get('actualSourceSha256')==SOURCE_SHA and scope.get('targets')==q['targets']
        and scope.get('readScopeSha256')==s.parent.review_sha256
        and Path(scope.get('readScopePath','')).resolve()==s.parent.review_path.resolve()
        and (scope.get('sessionNonce'),scope.get('pid'),scope.get('birth'),scope.get('guiThreadId'),scope.get('mainSha256'))==
            (ctx['heldNonce'],ctx['processId'],ctx['birth'],8292,MAIN_SHA),'TRACE_SCOPE')
    repeatable.base._lease(SimpleNamespace(plan=p))
    if s.phase in ('PREPARED','STAGED'):need(not _claim_path(s).exists(),'ALREADY_CLAIMED')
    else:need(_json(_claim_path(s))==_claim(s),'OWN_CLAIM')
    return q


def _render(s):
    _check(s);p=s.plan;out=Path(p['outputDirectory'])
    files=c.render(repeatable.base._carrier_view(p),c.read(HERE/c._probe_spec(reader.PROBE)[0],32768));source=repeatable._source().decode()
    values={'__REPEATABLE_STOCK_COMPARE_SCOPE_ADMITTED__':'true','__OPERATION_ID__':p['operationId'],
        '__SCOPE_SHA256__':s.scope_sha256,'__PROOF_PATH__':(out/NATIVE_FILE).as_posix(),
        '__NATIVE_COMPARE_INTENT_PATH__':(out/INTENT_FILE).as_posix()}
    for token,value in values.items():need(source.count(token)==1,'ONE_TOKEN');source=source.replace(token,value,1)
    header=files['sdk_probe_params.h'].decode();line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
    header=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(source,ensure_ascii=False))
    header+='\n#define AH_CPP_EPOCH_OPERATION_ID '+json.dumps(p['operationId'])+'\n'
    header+='#define AH_CPP_EPOCH_SCOPE_SHA256 '+json.dumps(s.scope_sha256)+'\n'
    header+='#define AH_CPP_EPOCH_RECEIPT_FILE L'+json.dumps((out/EPOCH_FILE).as_posix())+'\n'
    files['sdk_probe_params.h']=header.encode();files['Continuation.c']=_epoch_carrier_source()
    ps=files['run-fixed.ps1'].decode('utf-8-sig');need(ps.count('version=233;')==2,'HOST_AUTHORITY_ANCHOR')
    auth='version=233;writerAuthorized=$true;'+''.join(k+'=$true;' for k in TRUE_AUTH)+''.join(k+'=$false;' for k in FALSE_AUTH)
    for key,value in _limits().items():auth+=key+'='+str(value)+';'
    auth+="stackTraceProfile='"+PROFILE+"';actualSourceSha256='"+SOURCE_SHA+"';cppEpochGeneratorSha256='"+EPOCH_SHA+"';dllRetentionUntilProcessExitRequired=$true;"
    files['run-fixed.ps1']=ps.replace('version=233;',auth).encode('utf-8-sig');return files


def _limits():
    return dict(maximumStockComparisons=1,maximumEnumerations=2,maximumOwnedSlotsPerVector=128,maximumPreexistingResults=128,
        maximumStackFrames=64,maximumRetainedFrntendRvas=16,maximumStackEvents=32)


def _authority_result(s):
    return dict(stackTraceProfile=PROFILE,stackTraceControllerSha256=s.plan['stackTraceControllerSha256'],
        actualSourceSha256=SOURCE_SHA,cppEpochGeneratorSha256=EPOCH_SHA,cppEpochCSourceSha256=EPOCH_C_SHA,
        actualCarrierCSourceSha256=c.digest(_epoch_carrier_source()),scopeSha256=s.scope_sha256,readScopeSha256=s.parent.review_sha256,
        writerAuthorized=True,retainedReferenceOperationId=repeatable.base.RETIRED_OPERATION,
        secondRetiredObservationOperationId=repeatable.RETIRED_OBSERVATION,thirdRetiredObservationOperationId=RETIRED,
        completionEpochVerified=False,comparisonCompletionVerified=False,fullUuidPropertyDeltaVerified=False,onlyOwnPendingVerified=False,
        allCppExceptionFree=False,databaseApplyAuthorized=False,dllRetentionUntilProcessExitRequired=True,
        **_limits(),**{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


def prepare_root(scope_path,scope_sha256):
    _pins();path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=_json(path,scope_sha256)
    need(scope.get('kind')=='ROOT_COMPARISON_CPP_STACK_TRACE_SCOPE' and scope.get('passed') is True and _authority(scope)
        and scope.get('actualSourceSha256')==SOURCE_SHA,'TRACE_SCOPE_BEFORE_OWNER')
    parent=_prepare_parent(scope['readScopePath'],scope['readScopeSha256']);p=dict(parent.plan);op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):p.pop(key)
    p.update(operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),stackTraceProfile=PROFILE,
        stackTraceControllerSha256=c.digest(c.read(Path(__file__))),actualSourceSha256=SOURCE_SHA,cppEpochGeneratorSha256=EPOCH_SHA,
        cppEpochCSourceSha256=EPOCH_C_SHA,actualCarrierCSourceSha256=c.digest(_epoch_carrier_source()),traceScopeSha256=scope_sha256,
        readScopeSha256=parent.review_sha256,retainedReferenceOperationId=repeatable.base.RETIRED_OPERATION,
        secondRetiredObservationOperationId=repeatable.RETIRED_OBSERVATION,thirdRetiredObservationOperationId=RETIRED,
        writerAuthorized=True,captureAuthorized=False,applicationWrites=0,**_limits(),**{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})
    p['goldLeaseOwner'],p['goldLeaseBootstrapSha256']=repeatable.base.owner_base._lease_binding(p['context'])
    s=StackTrace(_ISSUER,parent,scope,path,scope_sha256,p,c.canonical(p),{});_check(s)
    ns=parent.private;ns['__pending_read_operation']=op
    def fresh(plan):_check(s);need(plan==p,'FRESH_PLAN');c._fresh(repeatable.base._carrier_view(plan))
    def render(plan,raw):need(plan==p,'RENDER_PLAN');return _render(s)
    ns.update(_fresh=fresh,render=render);s.private=ns;ns['_no_pending'](context=p['context']);return s


def stage_root(s):
    _check(s);need(s.phase=='PREPARED','STAGE_PHASE')
    proof=s.private['stage_private'](s.plan,dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',rootAuthorized=True,planSha256=c.digest(s.plan_raw)))
    s.phase='STAGED';return proof


def _unknown(s,reason):
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=s.plan['operationId'],reason=reason,
        retryAuthorized=False,parentWriterOperationId=s.parent.scope['writerOperationId'],**_authority_result(s))
    c.write_new(Path(s.plan['outputDirectory'])/'unknown.json',result);return result


def run_root_once(s,review_path,review_sha256):
    _check(s);need(s.phase=='STAGED','RUN_PHASE');p=s.plan;ctx=p['context'];out=Path(p['outputDirectory']);ns=s.private
    build=ns['require_stage'](p);review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind')=='ROOT_COMPARISON_CPP_STACK_TRACE_RUN' and review.get('passed') is True and _authority(review)
        and review.get('planSha256')==c.digest(s.plan_raw) and review.get('buildSha256')==c.digest(c.canonical(build))
        and review.get('scopeSha256')==s.scope_sha256 and review.get('readScopeSha256')==s.parent.review_sha256
        and review.get('actualSourceSha256')==SOURCE_SHA,'ROOT_RUN')
    ns['_no_pending'](context=ctx)
    need(not any((out/n).exists() for n in ('intent.json','host-identity.json','host-result.json','result.json','unknown.json',
        'sdk-receipt.json',NATIVE_FILE,INTENT_FILE,EPOCH_FILE)),'ONE_ATTEMPT')
    claim=_claim(s);c.write_new(_claim_path(s),claim);s.phase='DISPATCHED_RETAIN'
    c.write_new(out/'intent.json',dict(version=233,operationId=p['operationId'],planSha256=c.digest(s.plan_raw),rootRunSha256=review_sha256,
        parentWriterOperationId=claim['writerOperationId'],**_authority_result(s)));ns['_fresh'](p)
    s.host=subprocess.Popen([str(reader.writer.PS),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(out/'run-fixed.ps1')],cwd=out,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    c.write_new(out/'host-identity.json',reader.writer._host_identity(s.host));deadline=time.monotonic()+55
    while time.monotonic()<deadline:
        if (out/'host-result.json').is_file():
            try:sdk=_json(out/'host-result.json',bound=8192)
            except (OSError,ValueError):time.sleep(.05);continue
            if sdk.get('version')==233 and sdk.get('knownTerminal') is True and sdk.get('hookWorkersReleased') is True:
                try:s.host.wait(timeout=5)
                except subprocess.TimeoutExpired:break
                c.write_new(out/'sdk-receipt.json',dict(sdk,operationId=p['operationId'],planSha256=c.digest(s.plan_raw),**_authority_result(s)))
                try:
                    need(s.host.returncode==0 and type(sdk.get('threadId')) is int and sdk['threadId']==ctx['guiThreadId']
                        and type(sdk.get('sdkResult')) is int and sdk['sdkResult']==0,'SDK_TERMINAL');ns['_fresh'](p)
                    native=_json(out/NATIVE_FILE,bound=8192);reserved=_json(out/INTENT_FILE,bound=4096)
                    native_status=repeatable._native_terminal(s,native,reserved)
                    need(native_status in ('REPEATABLE_COMPARE_OBSERVED_DRAINED_CLEAN','COMPARE_RETURNED_NO_FRESH_RESULT_CLEAN'),
                        'NATIVE_DIAGNOSTIC_CLOSURE')
                    ep=_json(out/EPOCH_FILE,bound=32768)
                    trace=epoch.classify_stack_epoch(ep,operation_id=p['operationId'],scope_sha256=s.scope_sha256,process_id=ctx['processId'],
                        execute_thread_id=ctx['guiThreadId'],callback_known=True,callback_sdk_rc=sdk['sdkResult'],target_identity_verified=True)
                except (OSError,ValueError):return _unknown(s,'STACK_EPOCH_OR_REFERENCE_CLOSURE_UNPROVEN')
                result=dict(version=233,status='TRACE_OBSERVED_COMPARISON_REJECTED',knownTerminal=True,operationId=p['operationId'],
                    planSha256=c.digest(s.plan_raw),comparisonReliability='REJECTED',listStreamPathExceptionFree=False,
                    referenceClosureVerified=True,nativeRuntimeStatus=native_status,sdkResult=0,hookWorkersReleased=True,
                    targetIdentityVerified=True,nativeInjectionPerformed=True,
                    nativeProofSha256=c.digest(c.read(out/NATIVE_FILE)),cppStackEpochProofSha256=c.digest(c.read(out/EPOCH_FILE)),
                    cppExceptionStackEpoch=trace,parentWriterOperationId=claim['writerOperationId'],retryAuthorized=False,
                    releasePacketAllowed=False,releaseRefsAllowed=False,**_authority_result(s))
                c.write_new(out/'result.json',result);s.phase='KNOWN_TERMINAL_RETAIN_PARENT';return result
            break
        if s.host.poll() is not None:break
        time.sleep(.05)
    return _unknown(s,'HOST_OR_SDK_TERMINAL_UNPROVEN')
