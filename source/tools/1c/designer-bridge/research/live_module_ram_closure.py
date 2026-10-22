"""Reusable closed native LIVE RAM episodes for exact frozen953/2679/4610.

Only technical history is read. MCP acceptance is a separate metadata outcome,
not a prerequisite for native resource closure or a replay of source/tool traffic.
Fresh host/kernel identity/lease and all future dispatch authority stay outside.
"""
import importlib
import json
from pathlib import Path
import struct
from types import FunctionType,SimpleNamespace
import live_module_readonly_closure as util

ROOT=util.ROOT;HERE=Path(__file__).resolve().parent
CONTROLLER_SHA='953263e96beb27d42b066e04389a8a891a3f487e960c18507d0f6d3fa5b43c4b'
UTIL_SHA='dae69b5d1ea69ded64ccb495c4ab5336b5045f32a348c0a02095ed7f9d17b7f4'
CLASSIFICATION='LIVE_MODULE_RAM_NATIVE_RESOURCES_CLOSED'
FILES=('Continuation.c','sdk_probe_params.h','OwnedSdkReadonlyAttach.cs','OwnedSdkDiagnosisHook.cs','run-live-ram.ps1')
JSON_FILES=('plan.json','build-proof.json','result.json','host-identity.json','intent.json',
    'live-module-ram-host-ready.json','live-module-ram-host-result.json','live-module-ram-proof.json',
    'live-module-ram-intent.json','live-module-ram-sdk-chain-epoch.json',
    'live-module-ram-transfer-proof.json','live-module-ram-carrier-proof.json')
BINARY_FILES=(*FILES,'Continuation.dll','OwnedCarrierPreflight.dll','live-module-ram-arm.bin',
    'live-module-ram-callback.bin','live-module-ram-worker-result.bin')
digest,canonical=util.digest,util.canonical


def need(ok,code):
    if not ok:raise ValueError('LIVE_RAM_CLOSURE_'+code)


def _producer():
    need(digest(util._read(Path(util.__file__)))==UTIL_SHA,'UTILITY_PIN')
    need(digest(util._read(HERE/'live_module_ram_operation.py'))==CONTROLLER_SHA,'PRODUCER_PIN')
    producer=importlib.import_module('live_module_ram_operation')
    need(Path(producer.__file__).resolve()==HERE/'live_module_ram_operation.py','PRODUCER_MODULE')
    producer._pins()  # Immutable source/dependency reads only; no live _check.
    return producer


def load_rows(prior):
    """Read bounded metadata/binaries from paths derived only from op/request."""
    need(type(prior) is dict and util._hex(prior.get('operationId'),32)
         and util._hex(prior.get('requestId'),32) and util._hex(prior.get('updatePreviewScopeSha256'),64),'PRIOR')
    op=prior['operationId'];out=ROOT/'build'/('designer-hot-v233-'+op)
    need(not(out/'unknown.json').exists(),'UNKNOWN_RETAIN')
    raw={name:util._read(out/name) for name in JSON_FILES}
    raw['run']=util._read(ROOT/'artifacts/designer-bridge'/('live-module-ram-root-run-'+op+'.json'))
    raw['claim']=util._read(ROOT/'artifacts/designer-bridge'/('live-module-ram-claim-'+prior['updatePreviewScopeSha256']+'.json'))
    rows={k:util._json(v) for k,v in raw.items()};rows['_json_raw']=raw
    rows['_scope_raw']=util._read(ROOT/'artifacts/designer-bridge'/('live-module-ram-scope-'+prior['requestId']+'.json'))
    rows['_blobs']={name:util._read(out/name,4194304) for name in BINARY_FILES}
    acceptance=out/'actual-live-mcp-acceptance.json'
    rows['mcp']=None
    if acceptance.is_file():
        try:rows['mcp']=util._json(util._read(acceptance,16384))
        except (OSError,ValueError,UnicodeError,RecursionError):rows['mcp']={'invalidMetadata':True}
    return rows


def _state(p,scope):
    return SimpleNamespace(plan=p,scope=scope,scope_sha256=p['updatePreviewScopeSha256'],
        parent=SimpleNamespace(review_sha256=p['readScopeSha256']))


def _render(producer,state):
    # Source graph pinned first. Bypass only issuer/live freshness for pure byte
    # comparison; do not mutate producer globals or call prepare/run/native.
    fn=FunctionType(producer._render.__code__,dict(producer._render.__globals__,_check=lambda _:None),
                    producer._render.__name__,producer._render.__defaults__,producer._render.__closure__)
    return fn(state)


def _mcp(row,op,final):
    """A damaged/failed optional MCP report cannot create native-close success."""
    if row is None:return 'NOT_RECORDED'
    if type(row) is not dict or row.get('kind')!='ROOT_ACTUAL_GOLD_LIVE_MCP_ACCEPTANCE' or row.get('operationId')!=op:
        return 'UNVERIFIED'
    if row.get('passed') is False:return 'FAILED'
    yes=('passed','closed','sessionBodyReleased')
    no=('applicationBodyPersisted','currentEditorUnchangedVerified','permanentMcpInstalled')
    counts={'toolCount':6,'bodyBytes':final['bodyBytes'],'utf16Units':final['utf16Units']}
    if not (all(row.get(k) is True for k in yes) and all(row.get(k) is False for k in no)
        and all(type(row.get(k)) is int and row[k]==v for k,v in counts.items())
        and all(type(row.get(k)) is int and 0<=row[k]<=131073 for k in ('pageCount','symbolCount','contextEntries'))
        and row.get('sourceDomain')=='editor_live_at_capture' and row.get('sourceSha256')==final['sourceSha256']):
        return 'UNVERIFIED'
    return 'VERIFIED'


def validate_closed(rows,prior):
    """Pure replay for an exact caller-trusted prior, never a dispatch grant."""
    producer=_producer()
    need(type(rows) is dict and set(rows)==set(JSON_FILES)|{'run','claim','_json_raw','_scope_raw','_blobs','mcp'},'ROWS')
    raw=rows['_json_raw'];need(type(raw) is dict and set(raw)==set(JSON_FILES)|{'run','claim'},'RAW_JSON_FILES')
    need(all(type(v) is bytes and len(v)<=1048576 and util._json(v)==rows[k] for k,v in raw.items()),'RAW_JSON')
    need(type(prior) is dict and util._hex(prior.get('operationId'),32) and prior==rows['plan.json'],'PRIOR_PLAN')
    p=prior;op=p['operationId'];out=ROOT/'build'/('designer-hot-v233-'+op);scope_raw=rows['_scope_raw']
    need(Path(p.get('outputDirectory','')).resolve()==out and p.get('liveModuleRamControllerSha256')==CONTROLLER_SHA
         and p.get('updatePreviewControllerSha256')==CONTROLLER_SHA and p.get('updatePreviewProfile')==producer.PROFILE
         and p.get('actualSourceSha256')==producer.SOURCE_SHA and p.get('sourceDomain')=='editor_live_at_capture'
         and producer.authority(p),'PROFILE')
    util.counts(p,dict(version=233,revision=1,applicationWrites=0,configurationExports=0,configurationImports=0))
    ctx=p.get('context');need(type(ctx) is dict and ctx.get('birth')=='01dd5d0180299126'
         and ctx.get('mainSha256')==producer.previous.MAIN_SHA,'NATIVE_CONTEXT');util.counts(ctx,dict(processId=48936,guiThreadId=8292))
    need(type(scope_raw) is bytes and digest(scope_raw)==p['updatePreviewScopeSha256'],'SCOPE_RAW')
    scope=util._json(scope_raw);producer.validate_scope(scope)
    need(scope.get('requestId')==p.get('requestId') and scope.get('readScopeSha256')==p.get('readScopeSha256')
         and scope.get('sessionNonce')==ctx.get('heldNonce') and scope.get('birth')==ctx['birth']
         and scope.get('mainSha256')==ctx['mainSha256'],'SCOPE_JOIN');util.counts(scope,dict(pid=48936,guiThreadId=8292))
    s=_state(p,scope);blobs=rows['_blobs'];need(type(blobs) is dict and set(blobs)==set(BINARY_FILES),'BLOBS')
    cfg=p.get('liveRamConfiguration');need(type(cfg) is dict and cfg.get('operationId')==op
         and cfg.get('scopeSha256')==s.scope_sha256 and cfg.get('requestId')==scope['requestId'],'CONFIG_JOIN')
    paths={'epochPath':producer.EPOCH_FILE,'resultPath':producer.WORKER_FILE,'armPath':producer.ARM_FILE,
        'callbackPath':producer.CALLBACK_FILE,'transferProofPath':producer.TRANSFER_FILE,'proofPath':producer.FINAL_FILE}
    need(all(Path(cfg.get(k,'')).resolve()==out/name for k,name in paths.items()),'CONFIG_PATHS')
    expected=_render(producer,s);need(set(expected)==set(FILES),'RENDER_FILES')
    build=rows['build-proof.json'];util.counts(build,dict(version=233,compileExitCode=0,carrierCompileExitCode=0))
    util.flags(build,yes=('passed','carrierPreflightOnly'),no=('carrierAssemblyExecuted','goldStarted','nativeInjectionPerformed'))
    need(build.get('compilerSha256')=='11b86934bb2833f57fa0453a605ca342aee9207e193faea9b973baa2b2b4c35b'
         and build.get('carrierCompilerSha256')=='012e8cd8adff0c439a90ffd22c0e33efeb6fbc8cf660d52b4858d310649382fa'
         and build.get('planSha256')==digest(canonical(p)) and type(build.get('derivedSha256')) is dict
         and set(build['derivedSha256'])==set(FILES),'BUILD_JOIN')
    for name in FILES:need(blobs[name]==expected[name] and digest(blobs[name])==build['derivedSha256'][name],'DERIVED_BYTES')
    for name,key in (('Continuation.dll','librarySha256'),('OwnedCarrierPreflight.dll','carrierAssemblySha256')):
        util._pe(blobs[name]);need(digest(blobs[name])==build.get(key),'BINARY_PIN')
    prefix='#define AH_SDK_FIXED_SOURCE ';lines=[v[len(prefix):] for v in blobs['sdk_probe_params.h'].decode().splitlines() if v.startswith(prefix)]
    need(len(lines)==1,'HEADER_SOURCE');source=json.loads(lines[0]).encode('utf-8')
    need(digest(source)==p.get('compiledSourceSha256') and blobs['Continuation.dll'].count(source+b'\0')==1,'COMPILED_SOURCE')
    for export in (b'AhCaptureLiveUtf16V1\0',b'AhCommitLiveUtf16V1\0',b'AhReadOwnedTextManagerStateV1\0'):
        need(export in blobs['Continuation.dll'],'EXPORT')
    run=rows['run'];intent=rows['intent.json'];result=rows['result.json'];claim=rows['claim']
    need(run.get('kind')==producer.RUN_KIND and run.get('operationId')==op and run.get('passed') is True
         and run.get('planSha256')==digest(canonical(p)) and run.get('buildSha256')==digest(canonical(build)),'ROOT_RUN')
    for row in (run,intent,result):
        need(row.get('operationId')==op and row.get('scopeSha256')==s.scope_sha256 and producer.authority(row)
             and row.get('actualSourceSha256')==producer.SOURCE_SHA and row.get('compiledSourceSha256')==p['compiledSourceSha256']
             and row.get('liveModuleRamControllerSha256')==CONTROLLER_SHA and row.get('liveRamCarrierSha256')==producer.CARRIER_SHA,'AUTHORITY_JOIN')
    need(run.get('liveWireSha256')==producer.WIRE_SHA and run.get('liveRamPipeSha256')==producer.PIPE_SHA
         and intent.get('kind')=='LIVE_MODULE_RAM_HOST_INTENT' and intent.get('planSha256')==digest(canonical(p))
         and intent.get('rootRunSha256')==digest(raw['run']),'INTENT_RUN')
    need(claim.get('kind')=='LIVE_MODULE_RAM_CLAIM' and claim.get('operationId')==op
         and claim.get('scopeSha256')==s.scope_sha256 and claim.get('controllerSha256')==CONTROLLER_SHA
         and claim.get('actualSourceSha256')==producer.SOURCE_SHA and claim.get('requestId')==scope['requestId']
         and claim.get('sessionNonce')==ctx.get('heldNonce') and claim.get('birth')==ctx['birth'],'CLAIM');util.counts(claim,dict(pid=48936))
    producer._native_read(s,rows[producer.NATIVE_FILE],rows[producer.INTENT_FILE],rows[producer.EPOCH_FILE])
    before=producer._carrier_proof(s,rows[producer.TRANSFER_FILE],final=False)
    final=producer._carrier_proof(s,rows[producer.FINAL_FILE],final=True)
    changed={'kind','captureState','ackVerified','pipeClosed','borrowReturned','buffersFreed','retainedBuffer','transferProofWritten','frameBytesWritten'}
    need(set(before)==set(final) and all(before[k]==final[k] and type(before[k]) is type(final[k]) for k in before.keys()-changed),'PRE_POST_JOIN')
    need(rows[producer.NATIVE_FILE]['sourceUtf16Units']==final['utf16Units'],'AS_C_LENGTH')
    need(blobs[producer.WORKER_FILE]==bytes(4) and blobs[producer.ARM_FILE]==bytes(8)
         and type(blobs[producer.CALLBACK_FILE]) is bytes and len(blobs[producer.CALLBACK_FILE])==24
         and struct.unpack('<6I',blobs[producer.CALLBACK_FILE])==(48936,8292,0,0x83d2,8292,1),'RAW_RESULTS')
    host=rows[producer.HOST_RESULT];ready=rows[producer.HOST_READY];identity=rows['host-identity.json']
    need(host.get('kind')=='LIVE_RAM_MANAGED_TERMINAL' and host.get('operationId')==op,'HOST_TERMINAL')
    util.flags(host,yes=('knownTerminal','hookWorkersReleased'),no=('writerAuthorized',));util.counts(host,dict(workerResult=0,threadId=8292))
    need(ready.get('kind')=='LIVE_RAM_MANAGED_READY' and ready.get('operationId')==op,'HOST_READY')
    util.flags(ready,yes=('workerExpectedAlive',),no=('nativeSourceBindingVerified',));util.counts(ready,dict(processId=48936,threadId=8292))
    need(type(identity.get('processId')) is int and 0<identity['processId']<=0xFFFFFFFF and util._hex(identity.get('birth'),16),'HOST_IDENTITY')
    need(result.get('kind')=='LIVE_MODULE_RAM_RESULT' and result.get('status')=='LIVE_RAM_SNAPSHOT_RESOURCES_CLOSED'
         and result.get('sourceSha256')==final['sourceSha256'] and result.get('sourceDomain')=='editor_live_at_capture'
         and result.get('requestId')==scope['requestId'],'RESULT')
    util.counts(result,dict(revision=1,workerResult=0,hostExitCode=0,sourceUtf16Units=final['utf16Units']))
    util.flags(result,yes=('knownTerminal','privateAckAccepted','resourcesClosed','publicSnapshotAvailableInRam'),
        no=('retryAuthorized','sourceBodyPersisted','currentEditorUnchangedVerified','editorLiveMcpIntegrated'))
    mcp=_mcp(rows['mcp'],op,final)
    return dict(classification=CLASSIFICATION,operationId=op,nativeResourcesClosed=True,resourcesClosed=True,
        mcpAcceptanceStatus=mcp,mcpAcceptanceVerified=mcp=='VERIFIED',readBodyVerified=True,privateRamTransferVerified=True,
        sourceSha256=final['sourceSha256'],bodyBytes=final['bodyBytes'],sourceUtf16Units=final['utf16Units'],
        priorHostProcessId=identity['processId'],priorHostBirth=identity['birth'],hostProcessId=identity['processId'],hostBirth=identity['birth'],
        freshHostExitCheckRequired=True,currentTargetIdentityAndLeaseCheckRequired=True,
        bodyHashRecomputed=False,rawSourceFramesReplayed=False,mcpToolTrafficReplayed=False,
        currentIdentityVerified=False,currentLeaseVerified=False,rootOwnerExitVerified=False,writerAuthorized=False,
        retryAuthorized=False,newDispatchAuthorized=False,unloadAuthorized=False,foreignUnknownWaived=False)


def audit_closed(prior):
    return validate_closed(load_rows(prior),prior)
