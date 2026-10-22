"""Historical successful frozen177f/a683 reads; no native or freshness calls.

The caller trusts its prior plan, then separately proves host exit, current
identity and lease. Cross-joined files are evidence, not signed attestation.
No source body is read: the embedded AS is fixed technical reader code only.
"""
import hashlib
import importlib
import json
import math
from pathlib import Path
import re
import struct
from types import FunctionType, SimpleNamespace

ROOT=Path(__file__).resolve().parents[4]
HERE=Path(__file__).resolve().parent
CONTROLLER_SHA='177f76ae53fecbff383f3fcd90a9e972958c63fa854589d5146f18e0db39c2d4'
SOURCE_SHA='a68348932423dd1fc8850dd75353c873764f003ee61f06f5ade3c2f866dad117'
CLASSIFICATION='LIVE_MODULE_READONLY_SUCCESS_SDK_RESOURCES_CLOSED'
FILES=('Continuation.c','sdk_probe_params.h','OwnedSdkReadonlyAttach.cs','OwnedSdkDiagnosisHook.cs','run-fixed.ps1')
JSON_FILES=('plan.json','build-proof.json','result.json','host-result.json','host-identity.json',
            'sdk-receipt.json','intent.json','live-module-readonly-proof.json',
            'live-module-readonly-intent.json','live-module-readonly-sdk-chain-epoch.json')
BINARY_FILES=(*FILES,'Continuation.dll','OwnedCarrierPreflight.dll','sdk-result.bin','arm-result.bin','callback-observe.bin')


def need(ok,code):
    if not ok:raise ValueError('LIVE_READ_CLOSURE_'+code)


def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(row):return json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def _hex(value,size):return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None and value!='0'*size
def counts(row,values):need(all(type(row.get(k)) is int and row[k]==v for k,v in values.items()),'COUNTS')
def flags(row,yes=(),no=()):need(all(row.get(k) is True for k in yes) and all(row.get(k) is False for k in no),'FLAGS')


def _json(raw):
    def pairs(items):
        row={}
        for key,value in items:need(key not in row,'DUPLICATE_JSON');row[key]=value
        return row
    def bad(_):raise ValueError('LIVE_READ_CLOSURE_NONFINITE')
    def number(value):
        value=float(value);need(math.isfinite(value),'NONFINITE');return value
    row=json.loads(raw,object_pairs_hook=pairs,parse_constant=bad,parse_float=number)
    need(type(row) is dict,'JSON_OBJECT');return row


def _read(path,bound=1048576):
    need(path.resolve()==path.absolute() and path.is_file() and not path.is_symlink(),'FILE')
    with path.open('rb') as stream:raw=stream.read(bound+1)
    need(len(raw)<=bound,'FILE_BOUND');return raw


def _producer():
    need(digest(_read(HERE/'live_module_readonly_operation.py'))==CONTROLLER_SHA
         and digest(_read(HERE/'NativeLiveModuleReadOnly.as'))==SOURCE_SHA,'PRODUCER_PIN')
    producer=importlib.import_module('live_module_readonly_operation')
    need(Path(producer.__file__).resolve()==HERE/'live_module_readonly_operation.py','PRODUCER_MODULE')
    producer._pins()  # Fixed source dependencies only; no target/kernel freshness.
    return producer


def load_rows(prior):
    """Read only bounded technical files derived from one valid operation UUID."""
    need(type(prior) is dict and _hex(prior.get('operationId'),32),'OPERATION')
    op=prior['operationId'];folder=ROOT/'build'/('designer-hot-v233-'+op)
    need(not (folder/'unknown.json').exists(),'UNKNOWN')
    raw={name:_read(folder/name) for name in JSON_FILES}
    raw['run']=_read(ROOT/'artifacts/designer-bridge'/('live-module-readonly-run-'+op+'.json'))
    scope_pin=prior.get('updatePreviewScopeSha256');need(_hex(scope_pin,64),'SCOPE_PIN')
    raw['claim']=_read(ROOT/'artifacts/designer-bridge'/('live-module-readonly-claim-'+scope_pin+'.json'))
    rows={name:_json(value) for name,value in raw.items()};rows['_json_raw']=raw
    nonce=prior.get('readonlyNonce');need(_hex(nonce,32),'SCOPE_NONCE')
    rows['_scope_raw']=_read(ROOT/'artifacts/designer-bridge'/('live-module-readonly-scope-'+nonce+'.json'))
    rows['_blobs']={name:_read(folder/name,4194304) for name in BINARY_FILES}
    return rows


def _state(p,scope):
    return SimpleNamespace(plan=p,scope=scope,scope_sha256=p['updatePreviewScopeSha256'],
                          parent=SimpleNamespace(review_sha256=p['readScopeSha256']))


def _render(producer,state):
    # The producer and all its dependencies have been pinned before this sole
    # private override. It bypasses live issuer/freshness, never changes globals.
    fn=FunctionType(producer._render.__code__,dict(producer._render.__globals__,_check=lambda _:None),
                    producer._render.__name__,producer._render.__defaults__,producer._render.__closure__)
    return fn(state)


def _pe(raw):
    need(type(raw) is bytes and len(raw)>=256 and raw[:2]==b'MZ','PE')
    offset=struct.unpack_from('<I',raw,60)[0]
    need(offset+26<=len(raw) and raw[offset:offset+4]==b'PE\0\0'
         and struct.unpack_from('<H',raw,offset+4)[0]==0x14c
         and struct.unpack_from('<H',raw,offset+24)[0]==0x10b,'PE_X86')


def validate_closed(rows,prior):
    """Pure metadata/byte predicate; never grants new dispatch or current lease."""
    producer=_producer()
    need(type(rows) is dict and set(rows)==set(JSON_FILES)|{'run','claim','_scope_raw','_blobs','_json_raw'},'ROWS')
    raw=rows['_json_raw'];need(type(raw) is dict and set(raw)==set(JSON_FILES)|{'run','claim'},'JSON_FILES')
    need(all(type(value) is bytes and len(value)<=1048576 and _json(value)==rows[name] for name,value in raw.items()),'RAW_JSON')
    need(type(prior) is dict and _hex(prior.get('operationId'),32) and prior==rows['plan.json'],'PRIOR_PLAN')
    p=prior;op=p['operationId'];folder=ROOT/'build'/('designer-hot-v233-'+op)
    need(Path(p.get('outputDirectory','')).resolve()==folder and p.get('updatePreviewProfile')==producer.PROFILE
         and p.get('liveModuleReadonlyControllerSha256')==p.get('updatePreviewControllerSha256')==CONTROLLER_SHA
         and p.get('actualSourceSha256')==SOURCE_SHA and p.get('moduleObjectId')==producer.TARGET
         and p.get('modulePropertyId')==producer.PROPERTY and p.get('sourceDomain')=='editor_live','PROFILE')
    counts(p,dict(version=233,applicationWrites=0));need(producer.authority(p),'PLAN_AUTHORITY')
    context=p.get('context');need(type(context) is dict and context.get('birth')=='01dd5d0180299126'
         and context.get('mainSha256')==producer.MAIN_SHA,'CONTEXT')
    counts(context,dict(processId=48936,guiThreadId=8292))
    scope_raw=rows['_scope_raw'];need(type(scope_raw) is bytes and digest(scope_raw)==p['updatePreviewScopeSha256'],'SCOPE_RAW')
    scope=_json(scope_raw);producer.validate_scope(scope)
    need(scope.get('readonlyNonce')==p.get('readonlyNonce') and scope.get('readScopeSha256')==p['readScopeSha256'],'SCOPE_JOIN')
    need(scope.get('acceptanceNonce')==p['readonlyNonce'] and scope.get('sessionNonce')==context.get('heldNonce')
         and scope.get('birth')==context['birth'] and scope.get('mainSha256')==context['mainSha256'],'SCOPE_CONTEXT')
    counts(scope,dict(pid=48936,guiThreadId=8292))
    state=_state(p,scope);blobs=rows['_blobs'];need(type(blobs) is dict and set(blobs)==set(BINARY_FILES),'BLOBS')
    expected=_render(producer,state);need(set(expected)==set(FILES),'RENDER_FILES')
    build=rows['build-proof.json'];counts(build,dict(version=233,compileExitCode=0,carrierCompileExitCode=0))
    flags(build,yes=('passed','carrierPreflightOnly'),no=('goldStarted','nativeInjectionPerformed','carrierAssemblyExecuted'))
    need(build.get('compilerSha256')=='11b86934bb2833f57fa0453a605ca342aee9207e193faea9b973baa2b2b4c35b'
         and build.get('carrierCompilerSha256')=='012e8cd8adff0c439a90ffd22c0e33efeb6fbc8cf660d52b4858d310649382fa','COMPILER_PIN')
    need(build.get('planSha256')==digest(canonical(p)) and type(build.get('derivedSha256')) is dict
         and set(build['derivedSha256'])==set(FILES),'BUILD_JOIN')
    for name in FILES:need(blobs[name]==expected[name] and digest(blobs[name])==build['derivedSha256'][name],'DERIVED_BYTES')
    for name,key in (('Continuation.dll','librarySha256'),('OwnedCarrierPreflight.dll','carrierAssemblySha256')):
        _pe(blobs[name]);need(digest(blobs[name])==build.get(key),'BINARY_PIN')
    header=blobs['sdk_probe_params.h'].decode('utf-8');prefix='#define AH_SDK_FIXED_SOURCE '
    line=[x[len(prefix):] for x in header.splitlines() if x.startswith(prefix)]
    need(len(line)==1,'PAYLOAD_HEADER');payload=json.loads(line[0]).encode('utf-8')+b'\0'
    need(blobs['Continuation.dll'].count(payload)==1 and b'AhReadOwnedTextManagerStateV1\0' in blobs['Continuation.dll'],'BINARY_SOURCE')
    code=blobs['Continuation.c'].decode();need('call(context,1,0,0);call(fn,2,0,0)' in code
         and code.index('rc=ahOwnedLiveSdkChainBody(')<code.index('if(!ahCppEpochEnd(rc))'),'NORMAL_RELEASE')
    run=rows['run'];result=rows['result.json'];intent=rows['intent.json'];sdk=rows['sdk-receipt.json'];host=rows['host-result.json']
    need(run.get('kind')==producer.RUN_KIND and run.get('operationId')==op and producer.authority(run)
         and run.get('liveModuleReadonlyControllerSha256')==CONTROLLER_SHA
         and run.get('moduleObjectId')==producer.TARGET and run.get('modulePropertyId')==producer.PROPERTY
         and run.get('actualSourceSha256')==SOURCE_SHA and run.get('scopeSha256')==state.scope_sha256
         and run.get('readScopeSha256')==p['readScopeSha256'] and run.get('planSha256')==digest(canonical(p))
         and run.get('buildSha256')==digest(canonical(build)),'ROOT_RUN');flags(run,yes=('passed',))
    for row in (result,intent,sdk):
        need(row.get('operationId')==op and row.get('planSha256')==digest(canonical(p))
             and producer.authority(row) and row.get('actualSourceSha256')==SOURCE_SHA
             and row.get('scopeSha256')==state.scope_sha256,'TERMINAL_JOIN')
    need(intent.get('rootRunSha256')==digest(raw['run']),'INTENT_RUN')
    for row in (sdk,host):
        counts(row,dict(version=233,sdkResult=0,threadId=8292));flags(row,yes=('knownTerminal','hookWorkersReleased'))
        need(producer.authority(row),'HOST_AUTHORITY')
    need(blobs['sdk-result.bin']==bytes(4),'RAW_SDK')
    need(blobs['arm-result.bin']==bytes(8) and type(blobs['callback-observe.bin']) is bytes
         and len(blobs['callback-observe.bin'])==24,'HOOK_RECORD')
    callback=struct.unpack('<6I',blobs['callback-observe.bin'])
    need(callback[:3]==(48936,8292,0) and callback[4:]==(8292,1),'HOOK_IDENTITY')
    result_status=producer._native_terminal(state,rows[producer.NATIVE_FILE],rows[producer.INTENT_FILE],rows[producer.EPOCH_FILE])
    need(result_status==result.get('status')=='LIVE_MODULE_READONLY_STATE_PRESERVED'
         and result.get('nativeProofSha256')==digest(raw[producer.NATIVE_FILE]),'READ_SUCCESS')
    flags(result,yes=('knownTerminal','hookWorkersReleased','readSuccess','targetIdentityVerified','nativeInjectionPerformed'),
          no=('semanticRefusal','retryAuthorized','releaseRefsAllowed','releasePacketAllowed','editorLiveMcpIntegrated','sourceBodyPersisted','sourceMutationVerified'))
    counts(result,dict(version=233,sdkResult=0));need(result.get('refusalReason') is None,'SUCCESS_REASON')
    identity=rows['host-identity.json'];need(type(identity.get('processId')) is int and 0<identity['processId']<=0xFFFFFFFF
         and _hex(identity.get('birth'),16),'HOST_IDENTITY')
    claim=rows['claim'];need(claim.get('kind')=='LIVE_MODULE_READONLY_CLAIM' and claim.get('operationId')==op
         and claim.get('scopeSha256')==state.scope_sha256 and claim.get('controllerSha256')==CONTROLLER_SHA
         and claim.get('actualSourceSha256')==SOURCE_SHA and claim.get('readonlyNonce')==scope['readonlyNonce']
         and claim.get('sessionNonce')==context.get('heldNonce') and claim.get('birth')==context['birth'],'CLAIM')
    counts(claim,dict(pid=48936))
    return dict(classification=CLASSIFICATION,operationId=op,resourcesClosed=True,readBodyVerified=True,
        normalSdkContextAndFunctionReleaseReturned=True,ownedTypedHandlesCleared=True,priorHostProcessId=identity['processId'],
        priorHostBirth=identity['birth'],hostProcessId=identity['processId'],hostBirth=identity['birth'],
        freshHostExitCheckRequired=True,currentTargetIdentityAndLeaseCheckRequired=True,
        currentIdentityVerified=False,currentLeaseVerified=False,rootOwnerExitVerified=False,transportVerified=False,
        retryAuthorized=False,newDispatchAuthorized=False,unloadAuthorized=False,foreignUnknownWaived=False)


def audit_closed(prior):
    return validate_closed(load_rows(prior),prior)
