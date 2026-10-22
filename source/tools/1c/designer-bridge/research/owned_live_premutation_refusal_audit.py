"""Exact BA19 historical pre-mutation refusal; no dispatch/retry/current authority.

Reads only fixed technical receipts and archived technical source pins. Original
UNKNOWN/result absence stay unchanged. A normal SDK release is not DLL unload,
UI closure, successful editor read, or arbitrary Undo-history preservation.
"""
import hashlib
import importlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[4]
OP='ba19e32fe6fd4f06821fb8f034906482'
NONCE='a5b02b20ee214e1eb0120e925f96c0cb'
PLAN_SHA='ff13959729780be0404609083930c0e995ee487b8849e84bb68c885627cb3154'
BUILD_SHA='73db27a8c1e52dabc5a9328f3b0dc0a1d2d06c897a807b1335c9e1f8d00b4d47'
SCOPE_SHA='3a0802471149bb7336c394d1f92ca250730025e4cf7cb223e18f371c5c411904'
RUN_SHA='da6f363d961832818275eb6d5b763ee9cd459e5e292246707f725d4b41dc1cf7'
CONTROLLER_SHA='185291db692db16b9f365f237aaf37c06f5ef0c5f3a3d5a61ba82b09470c2084'
SOURCE_SHA='b03990d7952ebbb42cbf1a131d993e048c659808fc0bef49812649f96ee1de43'
EPOCH_SHA='e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4'
TARGET='d593e80d-b70c-400b-9955-d02f7a4c89e9'
PROPERTY='a637f77f-3840-441d-a1c3-699c8c5cb7e0'
CLASSIFICATION='OWNED_LIVE_EDITOR_SAFE_PREMUTATION_REFUSAL'
FOLDER='build/designer-hot-v233-'+OP+'/'
ARCHIVE='artifacts/designer-bridge/owned-live-refusal-'+OP+'/source-before-baseline-diagnostics/'
PINS={
 'plan.json':'1ed16d0ca69182db4ab76f3f29071f118e0fa0432b0a5fd2774fafa6c26010e4',
 'build-proof.json':'331917930a168a15bfa5e8c6418c5641ac1bb5d8b34835faadf628f7e79e774b',
 'host-identity.json':'338791fd7bb42e1672c646480d4b68fda17fcd1d9647b97d05695e2bc167fa62',
 'host-result.json':'a501b1299e977db3d89dda9379f1aa5c3d4d706b13578b40d7ab886b75386308',
 'sdk-receipt.json':'3612386d2117ae524a392a4ae610d93badb97e435237c00482859b6e11a05c03',
 'intent.json':'643dd2e4b96ce2b3db7ec61305a95f5271d5ffc6153f5b9248a128d6d54f9d71',
 'unknown.json':'2a1bc5f8e5ba332c50f0f74ea9fefe31614d23a4cc3cc0e7fb6ff744f47e6404',
 'owned-live-module-intent.json':'3fc8ebd38142cc73b24fe8136d9994417f21bd341756661bb035eeb48c6d591b',
 'owned-live-module-proof.json':'5dffa969c717580048e9223ef946ad244e9202ef660258b78fcdfe6d24a6379d',
 'owned-live-sdk-chain-epoch.json':'1347548e211334b2544f757c7459d76f1dd6ad902644ac2ea19a6c372ce0d0dc',
}
EXTRA_JSON={
 'scope':('artifacts/designer-bridge/owned-live-editor-scope-'+NONCE+'.json',SCOPE_SHA),
 'run':('artifacts/designer-bridge/owned-live-editor-run-'+OP+'.json',RUN_SHA),
 'claim':('artifacts/designer-bridge/owned-live-editor-claim-'+SCOPE_SHA+'.json','894219557c6162c0d9745e3abf868ac0d860b8ca8eb6024d9d0b74cb50460371'),
 'archive':(ARCHIVE+'source-manifest.json','347f741f53045f03a986c7f3312799c2342c1da5537c8dc71755523b58eb4b89'),
}
SOURCE_PINS={
 'owned_live_editor_operation.py':CONTROLLER_SHA,
 'NativeOwnedLiveModuleRead.as':SOURCE_SHA,
 'text_manager_state_bridge.py':'109df191f17acfd80754fbc0e8f31bb12453cd1448defeb8c702db71311e8ace',
 'text_manager_state_bridge_primary.py':'b16c5afd526169b2b6a36bfa8aafc6d6f24d3c6ccac7c702441a2475e61aacf3',
}
BINARY_PINS={
 'Continuation.c':'9676fc5dd325b12a48d7b582bf5ab2987cecf3e868cdaba6a1a1f04d021b3ca1',
 'sdk_probe_params.h':'3e9fccea23e59ee896d60bc3474172f178fd80deaa0840499052cc6092a03585',
 'OwnedSdkDiagnosisHook.cs':'4cb409f9b74769de2ed69ac25006e22745bb3dc12f4e26e440f3e237d6e59152',
 'OwnedSdkReadonlyAttach.cs':'112007654805351263fee5c8f9c08d27d2a665eee8d9202f1d7bc0c45d1b62a4',
 'run-fixed.ps1':'47bad495adebdb8a5112088df1d94ea970c158bda030fb540229b75591e84985',
 'Continuation.def':'0ea5ae2c2de90dae5a40bca99fc3554d454b0a0c9687f9c442aa271ef77acc20',
 'Continuation.dll':'e5ceed2792ef622f6a5a2cfa95687e7abcf9ade93b5390f048c98c1ba75a543c',
 'OwnedCarrierPreflight.dll':'7602db3c9f0ac7d183d70e68db5ead50a683c40e536e6174396034cd1ff408e8',
 'sdk-result.bin':'df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119',
 'arm-result.bin':'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc',
 'callback-observe.bin':'9594da7b8aba4085b7bffe974b7caf3a2d7b5805ba9fc66510f42aba104a10e5',
}


def need(ok,code):
    if not ok:raise ValueError('OWNED_LIVE_PREMUTATION_'+code)


def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(row):return json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def counts(row,expected,code):
    need(all(type(row.get(k)) is int and row[k]==v for k,v in expected.items()),code)


def flags(row,yes=(),no=(),code='FLAGS'):
    need(all(row.get(k) is True for k in yes) and all(row.get(k) is False for k in no),code)


def _pairs(items):
    result={}
    for key,value in items:
        need(key not in result,'DUPLICATE_JSON');result[key]=value
    return result


def _json(raw):
    def reject(_):raise ValueError('OWNED_LIVE_PREMUTATION_NONFINITE')
    row=json.loads(raw,object_pairs_hook=_pairs,parse_constant=reject)
    need(type(row) is dict,'JSON_OBJECT');return row


def _read(relative,pin):
    # All paths are module-fixed literals; no caller executable/path policy.
    path=ROOT/relative;need(path.is_file() and not path.is_symlink(),'FILE')
    raw=path.read_bytes();need(len(raw)<=65536 and digest(raw)==pin,'PIN');return raw


def load_rows():
    """Read immutable technical history; never imports the evolving controller."""
    need(not(ROOT/FOLDER/'result.json').exists(),'ORIGINAL_RESULT_ABSENT')
    rows={name:_json(_read(FOLDER+name,pin)) for name,pin in PINS.items()}
    rows.update({name:_json(_read(path,pin))for name,(path,pin)in EXTRA_JSON.items()})
    for name,pin in SOURCE_PINS.items():_read(ARCHIVE+name,pin)
    for name,pin in BINARY_PINS.items():_read(FOLDER+name,pin)
    need((ROOT/FOLDER/'sdk-result.bin').read_bytes()==bytes(4),'RAW_SDK')
    return rows


def validate_closed(rows,prior):
    """Pure exact-episode semantics. No current identity, retry or owner release."""
    need(type(rows) is dict and set(rows)==set(PINS)|set(EXTRA_JSON)
         and all(type(r) is dict for r in rows.values()),'ROWS')
    need(type(prior) is dict and prior==rows['plan.json'] and digest(canonical(prior))==PLAN_SHA,'PLAN')
    p=prior;b=rows['build-proof.json'];s=rows['scope'];run=rows['run'];claim=rows['claim']
    native=rows['owned-live-module-proof.json'];ni=rows['owned-live-module-intent.json']
    host=rows['host-result.json'];sdk=rows['sdk-receipt.json'];intent=rows['intent.json'];unknown=rows['unknown.json']
    ep=rows['owned-live-sdk-chain-epoch.json']
    need(p.get('operationId')==OP and p.get('actualSourceSha256')==SOURCE_SHA
         and p.get('ownedLiveControllerSha256')==p.get('updatePreviewControllerSha256')==CONTROLLER_SHA
         and p.get('updatePreviewScopeSha256')==SCOPE_SHA and p.get('ownedProcessingId')==TARGET
         and p.get('modulePropertyId')==PROPERTY and p.get('sourceDomain')=='editor_live'
         and p.get('liveNonce')==NONCE,'FIXED_SOURCE')
    expected=digest(('// AH1C_OWNED_LIVE:'+NONCE+'\r\n// '+'X'*2300+':END\r\n').encode())
    need(p.get('expectedLiveSha256')==s.get('expectedLiveSha256')==native.get('expectedSourceSha256')==expected,'RECIPE')
    ctx=p.get('context',{});need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'))==
        (48936,'01dd5d0180299126',8292),'FIXED_TARGET')
    need(s.get('kind')=='ROOT_OWNED_LIVE_EDITOR_SCOPE' and run.get('kind')=='ROOT_OWNED_LIVE_EDITOR_RUN'
         and s.get('passed') is True and run.get('passed') is True
         and run.get('scopeSha256')==SCOPE_SHA and run.get('planSha256')==PLAN_SHA
         and run.get('buildSha256')==digest(canonical(b))==BUILD_SHA
         and run.get('liveNonce')==s.get('liveNonce')==NONCE,'SCOPE_RUN')
    for row in (s,run,p,intent,unknown,sdk):
        flags(row,yes=('sourceWritesAuthorized','ownFixtureMutationAuthorized'),
            no=('writerAuthorized','configurationSavesAuthorized','databaseUpdatesAuthorized',
                'repositoryMutationsAuthorized','applicationDataReadAuthorized'),code='AUTHORITY')
        need(row.get('ownedProcessingId')==TARGET and row.get('modulePropertyId')==PROPERTY,'TARGET_BINDING')
    for row in (intent,sdk):
        need(row.get('operationId')==OP and row.get('scopeSha256')==SCOPE_SHA
             and row.get('planSha256')==PLAN_SHA,'SDK_PLAN_JOIN')
    need(intent.get('rootRunSha256')==RUN_SHA and claim.get('kind')=='OWNED_LIVE_EDITOR_CLAIM'
         and claim.get('operationId')==OP and claim.get('scopeSha256')==SCOPE_SHA
         and claim.get('controllerSha256')==CONTROLLER_SHA and claim.get('actualSourceSha256')==SOURCE_SHA
         and claim.get('liveNonce')==NONCE,'CLAIM')
    for row,kind in ((native,'OWNED_LIVE_MODULE_READ_NATIVE'),(ni,'OWNED_LIVE_MODULE_READ_INTENT')):
        need(row.get('kind')==kind and row.get('operationId')==OP and row.get('scopeSha256')==SCOPE_SHA
             and row.get('nonce')==NONCE,'NATIVE_JOIN')
    need(native.get('reason')=='CLEAN_EMPTY_WRITABLE_BASELINE','REFUSAL_FRONTIER')
    flags(native,yes=('ownedTypedHandlesCleared',),no=('verified','expectedSeedMatched','singleOwnUndoVerified',
        'fullUndoHistoryVerified','stateEqualityVerified','nativeException','sourceBodyIncluded',
        'sourceFrameIncluded','repositoryOwnerVerified'),code='NO_READ_SUCCESS')
    counts(native,dict(openCalls=1,actionBeginCalls=0,insertionCalls=0,actionCloseCalls=0,directSaveCalls=0,
        stateBridgeCalls=0,undoCalls=0,sourceUtf16Units=0,sourceUtf8Bytes=0,firstOutputAddress=0,
        secondOutputAddress=0,helperTextReads=0,configurationSaves=0,databaseUpdates=0,
        repositoryMutations=0,businessCalls=0,dirtyFlagWrites=0),'NO_OWN_MUTATION')
    need(native.get('beforeState')==native.get('afterState')==[] and type(native.get('caretReturnCodes')) is list
         and len(native['caretReturnCodes'])==2 and all(type(x) is int and x==0 for x in native['caretReturnCodes']),
         'NO_STATE_CAPTURE')
    counts(ni,dict(maximumOpenCalls=1,maximumInsertions=1,maximumUndoCalls=1,maximumDirectSaveCalls=2),'NATIVE_INTENT')
    flags(ni,no=('sourceBodyIncluded',))
    for row in (host,sdk):
        counts(row,dict(version=233,sdkResult=0,threadId=8292),'SDK_ZERO')
        flags(row,yes=('knownTerminal','hookWorkersReleased'))
    counts(b,dict(version=233,compileExitCode=0,carrierCompileExitCode=0),'BUILD')
    flags(b,yes=('passed','carrierPreflightOnly'),no=('carrierAssemblyExecuted','goldStarted','nativeInjectionPerformed'))
    need(b.get('planSha256')==PLAN_SHA and b.get('librarySha256')==BINARY_PINS['Continuation.dll']
         and b.get('carrierAssemblySha256')==BINARY_PINS['OwnedCarrierPreflight.dll'],'BUILD_BINDING')
    need(all(b.get('derivedSha256',{}).get(name)==BINARY_PINS[name]for name in
         ('Continuation.c','sdk_probe_params.h','OwnedSdkDiagnosisHook.cs','OwnedSdkReadonlyAttach.cs','run-fixed.ps1')),'DERIVED_PINS')
    need(unknown.get('status')=='UNKNOWN_RETAIN' and unknown.get('reason')=='NATIVE_OR_FRESH_CLOSURE_UNPROVEN'
         and unknown.get('operationId')==OP and unknown.get('scopeSha256')==SCOPE_SHA,'UNKNOWN_UNCHANGED')
    flags(unknown,no=('knownTerminal','retryAuthorized','editorLiveMcpIntegrated','fullUndoHistoryVerified'))
    identity=rows['host-identity.json'];counts(identity,dict(processId=42736),'HOST_IDENTITY')
    need(identity.get('birth')=='01dd5f0b2409e715','HOST_BIRTH')
    archive=rows['archive'];need(archive.get('kind')=='OWNED_LIVE_PREMUTATION_SOURCE_ARCHIVE'
        and archive.get('operationId')==OP and archive.get('technicalSourcesOnly') is True
        and archive.get('sourceSha256')==SOURCE_PINS,'ARCHIVE')
    counts(archive,dict(applicationBodyFiles=0),'ARCHIVE_BODY')
    need(ep.get('kind')=='OWNED_LIVE_SDK_CHAIN_CPP_EXCEPTION_TYPE_EPOCH'
         and ep.get('epochCoverage')=='owned_live_sdk_compile_prepare_execute_release','WHOLE_CHAIN')
    need(digest(Path(__file__).with_name('comparison_cpp_exception_type_epoch.py').read_bytes())==EPOCH_SHA,'CLASSIFIER_PIN')
    epoch=importlib.import_module('comparison_cpp_exception_type_epoch')
    epoch.classify_type_epoch(dict(ep,kind='COMPARISON_CPP_EXCEPTION_TYPE_EPOCH',epochCoverage='synchronous_context_Execute'),
        operation_id=OP,scope_sha256=SCOPE_SHA,process_id=48936,execute_thread_id=8292,
        callback_known=True,callback_sdk_rc=0,target_identity_verified=True)
    counts(ep,dict(cppThrows=2,cppThrowsExecuteThread=2,decodedCppThrows=2,typeEventCount=2,
                   unknownCppThrows=0,listStreamCompatibleThrows=0,otherExceptions=0),'EXACT_EVENTS')
    for event in ep['typeEvents']:
        need(event.get('primaryTypeNameHash')=='f16051db' and event.get('typeNameHashes')==['f16051db','243edd7d'],
             'OBSERVED_TYPE_HASHES')
    return dict(classification=CLASSIFICATION,operationId=OP,sourceControlPremutationRefusalVerified=True,
        normalSdkContextAndFunctionReleaseReturned=True,ownedAsTypedHandlesCleared=True,
        hostWaitExitZeroVerifiedByPinnedController=True,freshHostExitCheckRequired=True,
        hostProcessId=42736,hostBirth='01dd5f0b2409e715',originalUnknownPreserved=True,
        readSuccess=False,editorLiveMcpIntegrated=False,fullUndoHistoryVerified=False,
        allCppExceptionFree=False,originalUiMayRemainOpen=True,dllSelfReferenceKeep=True,
        currentIdentityVerified=False,currentLeaseVerified=False,rootOwnerExitVerified=False,
        retryAuthorized=False,newDispatchAuthorized=False,unloadAuthorized=False,foreignUnknownWaived=False)


def audit_closed(prior):
    """Exact immutable refusal audit; does not rewrite or promote old UNKNOWN."""
    return validate_closed(load_rows(),prior)
