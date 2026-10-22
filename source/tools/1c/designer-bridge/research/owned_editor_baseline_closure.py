"""Historical closure for the exact frozen E68 three-getter diagnostic only.

No SDK/OS/process/lease call, fake issuer, dispatch, resource release, or UNKNOWN
waiver. Root must separately query the exact prior host and current target.
"""
import hashlib
import importlib
import json
from pathlib import Path
import re
from types import FunctionType,SimpleNamespace

ROOT=Path(__file__).resolve().parents[4]
HERE=Path(__file__).resolve().parent
CONTROLLER_SHA='e68f2c082f8ae9b31bc80fb42439cdd60d193c54b552956584e6104336314368'
SOURCE_SHA='259992ba3fe65939771499a98969c9535c564c3c93ffdc0770650993e06759ee'
PROFILE='OWNED_PROCESSING_EDITOR_BASELINE_ONLY'
CLASSIFICATION='OWNED_EDITOR_BASELINE_SDK_RESOURCES_CLOSED'
SOURCE_PINS={'owned_editor_baseline_operation.py':CONTROLLER_SHA,'NativeOwnedEditorBaseline.as':SOURCE_SHA,
 'comparison_cpp_exception_type_epoch.py':'e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4'}
RECEIPTS=('plan.json','build-proof.json','intent.json','result.json','host-identity.json',
 'host-result.json','sdk-receipt.json','owned-editor-baseline-intent.json',
 'owned-editor-baseline-proof.json','owned-editor-baseline-sdk-chain-epoch.json')
DERIVED=('Continuation.c','sdk_probe_params.h','OwnedSdkDiagnosisHook.cs','OwnedSdkReadonlyAttach.cs','run-fixed.ps1')


def need(ok,code):
    if not ok:raise ValueError('BASELINE_CLOSURE_'+code)


def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(row):return json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def hexstr(value,size):return type(value)is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None and value!='0'*size


def counts(row,expected,code):
    need(all(type(row.get(k))is int and row[k]==v for k,v in expected.items()),code)


def flags(row,yes=(),no=(),code='FLAGS'):
    need(all(row.get(k)is True for k in yes)and all(row.get(k)is False for k in no),code)


def _pairs(items):
    result={}
    for key,value in items:need(key not in result,'JSON_DUPLICATE');result[key]=value
    return result


def parse(raw):
    def reject(_):raise ValueError('BASELINE_CLOSURE_JSON_NONFINITE')
    row=json.loads(raw,object_pairs_hook=_pairs,parse_constant=reject)
    need(type(row)is dict,'JSON_OBJECT');return row


def read(path,bound=65536):
    need(path.is_file()and not path.is_symlink(),'FILE')
    raw=path.read_bytes();need(len(raw)<=bound,'FILE_BOUND');return raw


def _producer():
    for name,pin in SOURCE_PINS.items():need(digest(read(HERE/name))==pin,'REVISION_PIN')
    ctl=importlib.import_module('owned_editor_baseline_operation')
    need(Path(ctl.__file__).resolve()==(HERE/'owned_editor_baseline_operation.py').resolve()
         and ctl.SOURCE_SHA==SOURCE_SHA and ctl.PROFILE==PROFILE,'PRODUCER')
    ctl._pins()  # Pure source pins; no current identity/lease/issuer checks.
    return ctl


def _identity(prior):
    need(type(prior)is dict and hexstr(prior.get('operationId'),32)and hexstr(prior.get('baselineNonce'),32),'PLAN_IDS')
    op=prior['operationId'];folder=ROOT/'build'/('designer-hot-v233-'+op)
    need(Path(prior.get('outputDirectory','')).resolve()==folder.resolve(),'OUTPUT_PATH')
    need(type(prior.get('version'))is int and prior['version']==233 and prior.get('oneShot')is True
         and prior.get('updatePreviewProfile')==PROFILE and prior.get('actualSourceSha256')==SOURCE_SHA
         and prior.get('ownedEditorBaselineControllerSha256')==prior.get('updatePreviewControllerSha256')==CONTROLLER_SHA
         and hexstr(prior.get('updatePreviewScopeSha256'),64),'PROFILE')
    return op,prior['baselineNonce'],folder


def load_rows(prior):
    """Read bounded technical files at fixed operation/nonce-derived paths."""
    op,nonce,folder=_identity(prior);art=ROOT/'artifacts/designer-bridge'
    need(not(folder/'unknown.json').exists(),'UNKNOWN_FORBIDDEN')
    paths={name:folder/name for name in RECEIPTS}
    paths.update(scope=art/('owned-editor-baseline-scope-'+nonce+'.json'),
        run=art/('owned-editor-baseline-run-'+op+'.json'),
        claim=art/('owned-editor-baseline-claim-'+prior['updatePreviewScopeSha256']+'.json'),
        kernel=art/('owned-editor-baseline-host-terminal-'+op+'.json'))
    raw={name:read(path)for name,path in paths.items()}
    rows={name:parse(value)for name,value in raw.items()}
    rows.update(
        derived={name:read(folder/name)for name in DERIVED},rawSdk=read(folder/'sdk-result.bin',8),
        library=read(folder/'Continuation.dll',1048576),assembly=read(folder/'OwnedCarrierPreflight.dll',1048576))
    checkpoint=art/('owned-editor-baseline-checkpoint-'+op+'.json')
    if checkpoint.exists():raw['checkpoint']=read(checkpoint)
    rows['checkpoint']=parse(raw['checkpoint'])if'checkpoint'in raw else None
    rows['jsonRaw']=raw
    return rows


def validate_closed(rows,prior):
    """Pure receipt semantics + exact frozen render; no current authority."""
    ctl=_producer();op,nonce,folder=_identity(prior)
    need(prior.get('probe')==ctl.reader.PROBE and prior.get('controllerSha256')==ctl.reader.PARENT_SHA
         and prior.get('nativeDriverPins')==ctl.c.SOURCE_PINS,'CARRIER_SOURCE_BINDING')
    keys=set(RECEIPTS)|{'scope','run','claim','kernel','derived','rawSdk','library','assembly','checkpoint','jsonRaw'}
    need(type(rows)is dict and set(rows)==keys and all(type(rows[k])is dict for k in RECEIPTS),'ROWS')
    need(prior==rows['plan.json'],'PRIOR_PLAN')
    raw=rows['jsonRaw'];rawkeys=set(RECEIPTS)|{'scope','run','claim','kernel'}|({'checkpoint'}if rows['checkpoint']is not None else set())
    need(type(raw)is dict and set(raw)==rawkeys and all(type(value)is bytes and len(value)<=65536
         and parse(value)==rows[name]for name,value in raw.items()),'RAW_JSON_JOIN')
    plan_sha=digest(canonical(prior));scope=rows['scope'];run=rows['run'];build=rows['build-proof.json']
    result=rows['result.json'];intent=rows['intent.json'];sdk=rows['sdk-receipt.json'];host=rows['host-result.json']
    native=rows[ctl.NATIVE_FILE];native_intent=rows[ctl.INTENT_FILE];epoch=rows[ctl.EPOCH_FILE];claim=rows['claim']
    for value in (scope,run,claim,rows['kernel']):need(type(value)is dict,'METADATA_OBJECT')
    ctl.validate_scope(scope)
    scope_sha=prior['updatePreviewScopeSha256']
    need(digest(raw['scope'])==scope_sha,'SCOPE_HASH')
    ctx=prior.get('context',{});need(type(ctx)is dict and
        (ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256'))==
        (48936,'01dd5d0180299126',8292,ctl.MAIN_SHA),'TARGET_IDENTITY')
    need(scope.get('baselineNonce')==nonce and scope.get('readScopeSha256')==prior.get('readScopeSha256')
         and(scope.get('pid'),scope.get('birth'),scope.get('guiThreadId'),scope.get('mainSha256'),scope.get('sessionNonce'))==
            (ctx['processId'],ctx['birth'],ctx['guiThreadId'],ctx['mainSha256'],ctx.get('heldNonce')),'SCOPE_BINDING')
    need(prior.get('ownedProcessingId')==ctl.TARGET and prior.get('modulePropertyId')==ctl.PROPERTY
         and prior.get('sourceDomain')=='editor_metadata_only' and ctl.authority(prior),'PLAN_AUTHORITY')
    need(run.get('kind')==ctl.RUN_KIND and run.get('passed')is True and ctl.authority(run)
         and run.get('planSha256')==plan_sha and run.get('buildSha256')==digest(canonical(build))
         and run.get('scopeSha256')==scope_sha and run.get('actualSourceSha256')==SOURCE_SHA
         and run.get('readScopeSha256')==prior.get('readScopeSha256'),'RUN')
    need(intent.get('rootRunSha256')==digest(raw['run']),'ROOT_RUN_HASH')
    for row in(intent,result,sdk):
        need(row.get('operationId')==op and row.get('planSha256')==plan_sha
             and row.get('scopeSha256')==scope_sha and row.get('actualSourceSha256')==SOURCE_SHA
             and row.get('ownedEditorBaselineControllerSha256')==CONTROLLER_SHA and ctl.authority(row),'RECEIPT_JOIN')
    flags(result,yes=('knownTerminal','hookWorkersReleased','targetIdentityVerified','nativeInjectionPerformed',
        'editorBaselineDiagnosticOnly'),no=('retryAuthorized','editorLiveMcpIntegrated','releasePacketAllowed','releaseRefsAllowed'))
    counts(result,dict(version=233,sdkResult=0),'RESULT_COUNTS')
    need(result.get('status')=='OWNED_EDITOR_BASELINE_OBSERVED' and result.get('nativeProofSha256')==digest(raw[ctl.NATIVE_FILE]),'RESULT')
    for row in(host,sdk):
        counts(row,dict(version=233,sdkResult=0,threadId=8292),'SDK_ZERO')
        flags(row,yes=('knownTerminal','hookWorkersReleased'));need(ctl.authority(row),'HOST_AUTHORITY')
    need(rows['rawSdk']==bytes(4)and type(rows['rawSdk'])is bytes,'RAW_SDK')
    need(claim.get('kind')=='OWNED_EDITOR_BASELINE_CLAIM'and claim.get('operationId')==op
         and claim.get('scopeSha256')==scope_sha and claim.get('controllerSha256')==CONTROLLER_SHA
         and claim.get('actualSourceSha256')==SOURCE_SHA and claim.get('baselineNonce')==nonce
         and claim.get('parentWriterOperationId')==prior.get('parentWriterOperationId')
         and(claim.get('pid'),claim.get('birth'),claim.get('sessionNonce'))==(ctx['processId'],ctx['birth'],ctx['heldNonce']),'CLAIM')
    s=SimpleNamespace(plan=prior,scope=scope,scope_sha256=scope_sha)
    need(ctl._native_terminal(s,native,native_intent,epoch)=='OWNED_EDITOR_BASELINE_OBSERVED','NATIVE')
    counts(build,dict(version=233,compileExitCode=0,carrierCompileExitCode=0),'BUILD_COUNTS')
    flags(build,yes=('passed','carrierPreflightOnly'),no=('carrierAssemblyExecuted','goldStarted','nativeInjectionPerformed'))
    need(build.get('compilerSha256')==ctl.c.TCC_SHA and hexstr(build.get('carrierCompilerSha256'),64),'COMPILER_BINDING')
    need(build.get('planSha256')==plan_sha and type(rows['library'])is bytes and type(rows['assembly'])is bytes
         and digest(rows['library'])==build.get('librarySha256')
         and digest(rows['assembly'])==build.get('carrierAssemblySha256'),'BINARY_JOIN')
    # Fixed private pure derivative, not an issued operation or a live _check.
    render=FunctionType(ctl._render.__code__,dict(ctl._render.__globals__,_check=lambda _:None),
        ctl._render.__name__,ctl._render.__defaults__,ctl._render.__closure__)
    expected=render(s);need(set(expected)==set(DERIVED)and type(rows['derived'])is dict
        and set(rows['derived'])==set(DERIVED),'RENDER_KEYS')
    for name,expected_bytes in expected.items():
        need(type(rows['derived'][name])is bytes and rows['derived'][name]==expected_bytes
             and digest(expected_bytes)==build.get('derivedSha256',{}).get(name),'EXACT_RENDER')
    code=expected['Continuation.c'].decode();body=code[code.index('static int ahOwnedBaselineSdkChainBody('):code.index('static int execute(')]
    wrapper=code[code.index('static int execute('):code.index('#ifdef AH_SDK_TEST_HOST')]
    need('if(!ahSdkAbiFault){call(context,1,0,0);call(fn,2,0,0);}else rc=107;'in body
         and'if(ahSdkAbiFault && rc==0)rc=107;'in wrapper
         and wrapper.index('ahOwnedBaselineSdkChainBody')<wrapper.index('ahCppEpochEnd(rc)'),'SDK_RELEASE_PATH')
    identity=rows['host-identity.json'];pid=identity.get('processId');birth=identity.get('birth')
    need(type(pid)is int and pid>0 and hexstr(birth,16),'HOST_IDENTITY')
    kernel=rows['kernel'];need(kernel.get('kind')=='OWNED_EDITOR_BASELINE_HOST_KERNEL_TERMINAL'
         and kernel.get('operationId')==op,'KERNEL_JOIN')
    flags(kernel,yes=('hostExitZeroVerified','queryHandlesClosed','originalUnknownPreserved'))
    counts(kernel,dict(kills=0,unloads=0,nativeDispatches=0,sourceWrites=0),'KERNEL_READONLY')
    observations=kernel.get('observations');need(type(observations)is list and 1<=len(observations)<=8,'KERNEL_ROWS')
    matching=[row for row in observations if type(row)is dict and row.get('pid')==pid and row.get('birth')==birth]
    need(len(matching)==1,'HOST_KERNEL_IDENTITY');counts(matching[0],dict(pid=pid,waitZeroMilliseconds=0,exitCode=0),'HOST_TERMINAL')
    flags(matching[0],yes=('terminal',))
    checkpoint=rows['checkpoint']
    if checkpoint is not None:
        need(type(checkpoint)is dict and checkpoint.get('kind')=='OWNED_EDITOR_BASELINE_CHECKPOINT'
             and checkpoint.get('operationId')==op and checkpoint.get('canonicalPlanSha256')==plan_sha
             and checkpoint.get('canonicalBuildSha256')==digest(canonical(build))
             and checkpoint.get('rootRunSha256')==digest(raw['run'])
             and checkpoint.get('hostKernelProofSha256')==digest(raw['kernel']),'CHECKPOINT_JOIN')
        available={**{name:value for name,value in raw.items()if name in RECEIPTS},**rows['derived'],
            'sdk-result.bin':rows['rawSdk'],'Continuation.dll':rows['library'],'OwnedCarrierPreflight.dll':rows['assembly']}
        evidence=checkpoint.get('evidence')
        need(type(evidence)is dict and 1<=len(evidence)<=32 and all(name in available
            and hexstr(pin,64)and pin==digest(available[name])for name,pin in evidence.items()),'CHECKPOINT_EVIDENCE')
    return dict(classification=CLASSIFICATION,operationId=op,resourcesClosed=True,
        normalSdkContextAndFunctionReleaseReturned=True,ownedTypedHandlesCleared=True,
        diagnosticOnly=True,readBodyVerified=False,repositoryOwnerVerified=False,readonlyCauseVerified=False,
        hostPid=pid,hostBirth=birth,priorHostProcessId=pid,priorHostBirth=birth,
        freshHostExitCheckRequired=True,currentTargetIdentityAndLeaseCheckRequired=True,
        currentIdentityVerified=False,currentLeaseVerified=False,rootOwnerExitVerified=False,
        retryAuthorized=False,newDispatchAuthorized=False,unloadAuthorized=False,dllSelfReferenceKeep=True,
        originalUiMayRemainOpen=True,foreignUnknownWaived=False)


def audit_closed(prior):
    """Verify one closed exact-profile episode. Root must query its host anew."""
    return validate_closed(load_rows(prior),prior)
