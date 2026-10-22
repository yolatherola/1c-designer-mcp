"""One fixed fresh stock comparison, drained owned enumeration and C++ epoch.

The old read scope joins retained ownership only. A separate grant permits one
runtime comparison; it never authorizes configuration, source or database writes.
"""
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
import json
import re
import subprocess
import time
import uuid
import owned_view_enumeration as base
import comparison_cpp_exception_epoch as epoch

c=base.c
reader=base.reader
ROOT=c.ROOT
HERE=c.HERE
BASE_SHA='650964593a3f4227b102739d8799929984dfd8aae7fe7ca92ab6131501391f29'
EPOCH_SHA='310a2a9ef7bd51c21d6ddc88240cca396c3be147c5a9141f853bd8f3e1df4881'
EPOCH_C_SHA='955a95c09742b056101c9dd14dae305d96034a77cc6232e51d9e7cc37d9a52a4'
EPOCH_CHECK_NAME='comparison-cpp-epoch-compile-c1ee7ef27eec4432ac2cd46bf6ee79d7.json'
EPOCH_CHECK_SHA='705c166fcba8a568c9babd27c94c1fe20d1a833734ec4701207d4e6cb2ca15e9'
SOURCE_NAME='NativeFreshStockComparison.as'
SOURCE_SHA='8339537c488e4ba1aef5795a64e93eeca573ea7fe65bec6615f302b39e1579b4'
CHECK_NAME='fresh-stock-comparison-check-only-9ca0877830d8472b9948b7b47a0a346a.json'
CHECK_SHA='970cfb2e80b4053e6291a17b42bb908b2218caa0ca4ba1dbb9dd282ed408210b'
MAIN_SHA=base.MAIN_SHA
PROFILE='FRESH_STOCK_COMPARISON_WITH_CPP_EXCEPTION_EPOCH'
NATIVE_FILE='fresh-stock-comparison-proof.json'
INTENT_FILE='native-compare-intent.json'
EPOCH_FILE='cpp-exception-epoch.json'
TRUE_AUTH=base.TRUE_AUTH+('stockCompareAuthorized','runtimeUiMutationPossible')
FALSE_AUTH=base.FALSE_AUTH
ZERO_NATIVE=tuple(k for k in base.ZERO_NATIVE if k!='commandDispatches')+('explicitResultMethodCalls','explicitResultQueries')
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('FRESH_STOCK_COMPARISON_'+code)


def _json(path,pin=None,bound=32768):return reader._json(path,pin,bound)


def _authority(row):
    return base._authority(row) and all(row.get(k) is True for k in TRUE_AUTH) \
        and type(row.get('maximumStockComparisons')) is int and row['maximumStockComparisons']==1


def _source():
    need(SOURCE_SHA!='0'*64,'SOURCE_NOT_FROZEN')
    raw=c.read(HERE/SOURCE_NAME);need(c.digest(raw)==SOURCE_SHA,'SOURCE_PIN')
    need(set(re.findall(r'__[A-Z][A-Z0-9_]+__',raw.decode()))=={
        '__FRESH_STOCK_COMPARE_SCOPE_ADMITTED__','__OPERATION_ID__','__SCOPE_SHA256__',
        '__PROOF_PATH__','__NATIVE_COMPARE_INTENT_PATH__'},'SOURCE_TOKENS')
    return raw


def _epoch_carrier_source():
    """Preserve BOTH original carrier GUI guards when adding the fixed epoch."""
    raw=epoch.render();need(c.digest(raw)==EPOCH_C_SHA,'EPOCH_C_PIN')
    source=raw.decode()
    source=c._replace_once(source,'if(GetCurrentThreadId()!=sdkGuiThread)rc=110;',
        'if(GetCurrentThreadId()!=sdkGuiThread || sdkGuiThread!=AH_SDK_EXPECTED_GUI_THREAD)rc=110;')
    source=c._replace_once(source,'if(!valid && diagnostic[0]==0)',
        'if(thread!=AH_SDK_EXPECTED_GUI_THREAD)valid=FALSE;\n if(!valid && diagnostic[0]==0)')
    return source.encode()


def _pins():
    for module,pin in ((base,BASE_SHA),(epoch,EPOCH_SHA)):
        need(c.digest(c.read(Path(module.__file__)))==pin,'DEPENDENCY_PIN')
    base._pins();_source();_epoch_carrier_source()
    proof=_json(ROOT/'artifacts/designer-bridge'/EPOCH_CHECK_NAME,EPOCH_CHECK_SHA)
    need(proof.get('kind')=='COMPARISON_CPP_EXCEPTION_EPOCH_COMPILE_ONLY'
        and proof.get('generatorSha256')==EPOCH_SHA and proof.get('derivedCSourceSha256')==EPOCH_C_SHA
        and proof.get('baselineSha256')==epoch.BASELINE_SHA
        and type(proof.get('positiveCompileExit')) is int and proof['positiveCompileExit']==0
        and type(proof.get('negativeMissingScopeMacroExit')) is int and proof['negativeMissingScopeMacroExit']!=0
        and proof.get('ownCompilerDirectoryRemoved') is True
        and all(proof.get(k) is False for k in ('goldStarted','libraryLoaded','sourceAdmitted'))
        and all(type(proof.get(k)) is int and proof[k]==0 for k in
            ('targetProcessId','nativeCalls','sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')),'CPP_COMPILE_PROOF')
    need(CHECK_SHA!='0'*64,'COLD_CHECK_NOT_FROZEN')
    check=_json(ROOT/'artifacts/designer-bridge'/CHECK_NAME,CHECK_SHA)
    need(check.get('kind')=='FRESH_STOCK_COMPARISON_CHECK_ONLY' and check.get('entry')=='ahFreshStockComparison'
        and check.get('sourceSha256')==SOURCE_SHA and check.get('sourceMainSha256')==MAIN_SHA
        and check.get('scopeAdmitted') is False and check.get('compareExecuted') is False
        and check.get('positive',{}).get('compileVerified') is True
        and type(check.get('positive',{}).get('exitCode')) is int and check['positive']['exitCode']==0
        and check.get('negative',{}).get('compileVerified') is False
        and type(check.get('negative',{}).get('exitCode')) is int and check['negative']['exitCode']!=0
        and all(check.get(k) is True for k in ('negativeCoverage','ownRuntimeRemoved'))
        and all(check.get(k) is False for k in ('goldStarted','scriptRunRequested')),'COLD_CHECK')


@dataclass(slots=True)
class ComparisonEpoch:
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


def _claim_path(s):return ROOT/'artifacts/designer-bridge'/('fresh-stock-comparison-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='FRESH_STOCK_COMPARISON_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
        actualSourceSha256=SOURCE_SHA,controllerSha256=s.plan['freshStockComparisonControllerSha256'],
        writerOperationId=q['operationId'],writerIntentSha256=c.digest(c.canonical(q)),packetSha256=q['packetSha256'],
        sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'],stockCompareAuthorized=True,
        maximumStockComparisons=1,maximumEnumerations=1,maximumOwnedSlots=128)


def _check(s):
    need(type(s) is ComparisonEpoch and s._issuer is _ISSUER,'ISSUED_COMPARISON');_pins()
    p=s.plan;ctx=p['context']
    need(c.canonical(p)==s.plan_raw and p.get('freshStockComparisonControllerSha256')==c.digest(c.read(Path(__file__))), 'PLAN_DRIFT')
    need(p.get('actualSourceSha256')==SOURCE_SHA and p.get('freshStockComparisonProfile')==PROFILE
        and p.get('cppEpochGeneratorSha256')==EPOCH_SHA and p.get('cppEpochCSourceSha256')==EPOCH_C_SHA
        and p.get('actualCarrierCSourceSha256')==c.digest(_epoch_carrier_source())
        and _authority(p) and p.get('writerAuthorized') is True and p.get('captureAuthorized') is False
        and type(p.get('applicationWrites')) is int and p['applicationWrites']==0
        and p.get('compareScopeSha256')==s.scope_sha256 and p.get('readScopeSha256')==s.parent.review_sha256
        and p.get('context')==s.parent.plan['context'],'PLAN_AUTHORITY')
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256'))==
        (48936,'01dd5d0180299126',8292,MAIN_SHA),'FIXED_NATIVE')
    q=reader._check_owner(s.parent);scope=_json(s.scope_path,s.scope_sha256)
    need(scope==s.scope and scope.get('kind')=='ROOT_FRESH_STOCK_COMPARISON_SCOPE' and scope.get('passed') is True
        and _authority(scope) and scope.get('actualSourceSha256')==SOURCE_SHA
        and scope.get('readScopeSha256')==s.parent.review_sha256
        and Path(scope.get('readScopePath','')).resolve()==s.parent.review_path.resolve()
        and scope.get('targets')==q['targets']
        and (scope.get('sessionNonce'),scope.get('pid'),scope.get('birth'),scope.get('guiThreadId'),scope.get('mainSha256'))==
            (ctx['heldNonce'],ctx['processId'],ctx['birth'],8292,MAIN_SHA),'COMPARE_SCOPE')
    base._lease(SimpleNamespace(plan=p))
    if s.phase in ('PREPARED','STAGED'):need(not _claim_path(s).exists(),'ALREADY_CLAIMED')
    else:need(_json(_claim_path(s))==_claim(s),'OWN_CLAIM')
    return q


def _render(s):
    _check(s);p=s.plan;out=Path(p['outputDirectory'])
    files=c.render(base._carrier_view(p),c.read(HERE/c._probe_spec(reader.PROBE)[0],32768));source=_source().decode()
    values={'__FRESH_STOCK_COMPARE_SCOPE_ADMITTED__':'true','__OPERATION_ID__':p['operationId'],
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
    authority="version=233;writerAuthorized=$true;"+''.join(k+'=$true;' for k in TRUE_AUTH)+''.join(k+'=$false;' for k in FALSE_AUTH)
    authority+="maximumStockComparisons=1;maximumEnumerations=1;maximumOwnedSlots=128;retainedReferenceOperationId='"+base.RETIRED_OPERATION+"';"
    authority+="freshStockComparisonProfile='"+PROFILE+"';actualSourceSha256='"+SOURCE_SHA+"';"
    authority+="cppEpochGeneratorSha256='"+EPOCH_SHA+"';cppEpochCSourceSha256='"+EPOCH_C_SHA+"';dllRetentionUntilProcessExitRequired=$true;"
    ps=ps.replace('version=233;',authority);files['run-fixed.ps1']=ps.encode('utf-8-sig');return files


def prepare_root(scope_path,scope_sha256):
    """Prepare fixed comparison; no host/native call until stage and root run grant."""
    _pins();path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=_json(path,scope_sha256)
    need(scope.get('kind')=='ROOT_FRESH_STOCK_COMPARISON_SCOPE' and scope.get('passed') is True
        and _authority(scope) and scope.get('actualSourceSha256')==SOURCE_SHA,'COMPARE_SCOPE_BEFORE_OWNER')
    parent=base._prepare_parent(scope['readScopePath'],scope['readScopeSha256']);p=dict(parent.plan);op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):p.pop(key)
    p.update(operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),freshStockComparisonProfile=PROFILE,
        actualSourceSha256=SOURCE_SHA,freshStockComparisonControllerSha256=c.digest(c.read(Path(__file__))),compareScopeSha256=scope_sha256,
        cppEpochGeneratorSha256=EPOCH_SHA,cppEpochCSourceSha256=EPOCH_C_SHA,actualCarrierCSourceSha256=c.digest(_epoch_carrier_source()),
        readScopeSha256=parent.review_sha256,maximumStockComparisons=1,maximumEnumerations=1,maximumOwnedSlots=128,
        retainedReferenceOperationId=base.RETIRED_OPERATION,writerAuthorized=True,captureAuthorized=False,applicationWrites=0,
        **{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})
    p['goldLeaseOwner'],p['goldLeaseBootstrapSha256']=base.owner_base._lease_binding(p['context'])
    s=ComparisonEpoch(_ISSUER,parent,scope,path,scope_sha256,p,c.canonical(p),{});_check(s)
    ns=parent.private;ns['__pending_read_operation']=op
    def fresh(plan):_check(s);need(plan==s.plan,'FRESH_PLAN');c._fresh(base._carrier_view(plan))
    def render(plan,raw):need(plan==s.plan,'RENDER_PLAN');return _render(s)
    ns.update(_fresh=fresh,render=render);s.private=ns;ns['_no_pending'](context=p['context']);return s


def stage_root(s):
    _check(s);need(s.phase=='PREPARED','STAGE_PHASE')
    proof=s.private['stage_private'](s.plan,dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',rootAuthorized=True,planSha256=c.digest(s.plan_raw)))
    s.phase='STAGED';return proof


def _native_terminal(s,native,reserved):
    """Interpret fresh source evidence only AFTER the independent Execute epoch."""
    need(type(native) is dict and native.get('kind')=='FRESH_STOCK_COMPARISON'
        and native.get('operationId')==s.plan['operationId'] and native.get('scopeSha256')==s.scope_sha256
        and native.get('readOnly') is False and native.get('configurationReadOnly') is True
        and native.get('runtimeCacheMutationPossible') is True and native.get('runtimeUiMutationPossible') is True
        and native.get('stockCompareAuthorized') is True
        and native.get('commandGroup')=='f10cbb81-f679-11d4-9dd3-0050bae2bc79'
        and type(native.get('commandId')) is int and native['commandId']==30
        and type(native.get('subCommand')) is int and native['subCommand']==0
        and native.get('retryAuthorized') is False and native.get('retentionRequired') is True
        and native.get('newOwnedSlotsOnly') is True and native.get('historicalReferenceCleanupAuthorized') is False
        and native.get('historicalReferencesRetained') is True
        and all(type(native.get(k)) is int and native[k]==v for k,v in
            (('maximumStockComparisons',1),('maximumEnumerations',1),('maximumOwnedSlots',128)))
        and all(native.get(k) is False for k in ('nativeMainDbDirectionVerified','completionEpochVerified','comparisonCompletionVerified','fullUuidPropertyDeltaVerified','onlyOwnPendingVerified'))
        and all(type(native.get(k)) is int and native[k]==0 for k in ZERO_NATIVE),'NATIVE_JOIN')
    if native.get('status')=='REFUSED_BEFORE_COMPARE':
        need(native.get('commandReturned') is False and native.get('enumCallReturned') is False
            and all(type(native.get(k)) is int and native[k]==0 for k in
                ('compareAttempts','enumerationAttempts','newOwnedSlots','nonNullSlots','validatedSlots','adoptionAttempts','releasedSlots','clearedSlots')),
            'NATIVE_ZERO_REFUSAL')
        return 'REFUSED_BEFORE_COMPARE'
    need(native.get('status') in ('FRESH_COMPARE_OBSERVED_DRAINED_CLEAN','COMPARE_RETURNED_NO_FRESH_RESULT_CLEAN')
        and all(native.get(k) is True for k in
            ('nativeIntentWritten','commandReturned','enumCallReturned','drainReturned','rootCleanBefore','rootCleanAfter','oldCounterRestored'))
        and native.get('unknownRetained') is False
        and all(type(native.get(k)) is int and native[k]==v for k,v in
            (('compareAttempts',1),('enumerationAttempts',1),('targetsCleanBefore',3),('targetsCleanAfter',3))), 'NATIVE_CLOSURE')
    counters=('newOwnedSlots','nonNullSlots','validatedSlots','adoptionAttempts','releasedSlots','clearedSlots',
              'freshCandidates','oldReferenceCountBefore','oldReferenceCountBeforeEnumeration',
              'oldReferenceCountDuringEnumeration','matchedOldViewSlots','oldReferenceCountAfter')
    need(all(type(native.get(k)) is int for k in counters),'NATIVE_COUNTER_TYPES')
    slots=native['newOwnedSlots'];nonnull=native['nonNullSlots']
    need(1<=nonnull<=slots<=128 and native['validatedSlots']==slots and native['clearedSlots']==slots
        and native['releasedSlots']==nonnull and native['adoptionAttempts']==nonnull
        and native['oldReferenceCountBefore']==10 and native['oldReferenceCountBeforeEnumeration']>0
        and 0<=native['matchedOldViewSlots']<=nonnull
        and native['oldReferenceCountDuringEnumeration']==native['oldReferenceCountBeforeEnumeration']+native['matchedOldViewSlots']
        and native['oldReferenceCountAfter']==native['oldReferenceCountBeforeEnumeration'],'NATIVE_DRAIN_BALANCE')
    need(type(reserved) is dict and reserved.get('kind')=='FRESH_STOCK_COMPARISON_RESERVED'
        and reserved.get('operationId')==s.plan['operationId'] and reserved.get('scopeSha256')==s.scope_sha256
        and reserved.get('stockCompareAuthorized') is True and reserved.get('newOwnedSlotsOnly') is True
        and reserved.get('historicalReferenceCleanupAuthorized') is False
        and reserved.get('readOnly') is False and reserved.get('configurationReadOnly') is True
        and reserved.get('runtimeCacheMutationPossible') is True and reserved.get('runtimeUiMutationPossible') is True
        and reserved.get('commandGroup')=='f10cbb81-f679-11d4-9dd3-0050bae2bc79'
        and type(reserved.get('commandId')) is int and reserved['commandId']==30
        and type(reserved.get('subCommand')) is int and reserved['subCommand']==0
        and type(reserved.get('oldReferenceCountBefore')) is int and reserved['oldReferenceCountBefore']==10
        and reserved.get('oldResultBeforePointer')==native.get('oldResultBeforePointer')
        and all(type(reserved.get(k)) is int and reserved[k]==v for k,v in
            (('maximumStockComparisons',1),('maximumEnumerations',1),('maximumOwnedSlots',128),
             ('sourceWrites',0),('configurationSaves',0),('databaseUpdates',0),('repositoryMutations',0))), 'NATIVE_INTENT')
    if native['status']=='COMPARE_RETURNED_NO_FRESH_RESULT_CLEAN':
        need(native.get('reason')=='NO_UNIQUE_FRESH_RESULT' and native.get('freshBindingVerified') is False
            and native['freshCandidates']>=0 and native['freshCandidates']!=1
            and type(native.get('selectedViewPointer')) is int and native['selectedViewPointer']==0
            and type(native.get('selectedResultPointer')) is int and native['selectedResultPointer']==0,'NATIVE_NO_FRESH')
        return native['status']
    need(native.get('reason')=='NONE' and native.get('freshBindingVerified') is True and native['freshCandidates']==1
        and native.get('coherent') is True and native.get('knownStateObserved') is True
        and type(native.get('passes')) is int and native['passes']==2
        and type(native.get('bindingSnapshotSha256')) is str
        and re.fullmatch('[0-9a-f]{64}',native['bindingSnapshotSha256']) is not None,'NATIVE_FRESH_BINDING')
    pointer_keys=('selectedViewPointer','selectedResultPointer','oldViewPointer','oldResultBeforePointer',
                  'mainSourcePointer','databaseSourcePointer')
    need(all(type(native.get(k)) is int and 0<native[k]<=0xffffffff and native[k]%4==0 for k in pointer_keys)
        and native['selectedResultPointer']!=native['oldResultBeforePointer']
        and native['mainSourcePointer']!=native['databaseSourcePointer'],'NATIVE_FRESH_POINTERS')
    need(all(type(native.get(k)) is int for k in ('selectedReferenceCountDuring','selectedReferenceCountAfter'))
        and native.get('selectedCounterBalanced') is True and native['selectedReferenceCountDuring']>=2
        and native['selectedReferenceCountAfter']==native['selectedReferenceCountDuring']-1,'NATIVE_SELECTED_DRAIN')
    need(type(native.get('completionFlag')) is int and native['completionFlag']==1
        and type(native.get('selectedObjectCount')) is int and native['selectedObjectCount']>0
        and type(native.get('visitedObjectCount')) is int and native['selectedObjectCount']==native['visitedObjectCount']
        and native.get('resultScopeGuidNull') is True and native.get('engineScopeGuidNull') is True
        and all(type(native.get(k)) is int and native[k]==0 for k in
            ('engineScopeEnabled','propertyTypeBypass','resourceDetailBranch')),'NATIVE_OBSERVED_STATE')
    return native['status']


def _authority_result(s):
    return dict(freshStockComparisonProfile=PROFILE,actualSourceSha256=SOURCE_SHA,
        freshStockComparisonControllerSha256=s.plan['freshStockComparisonControllerSha256'],
        cppEpochGeneratorSha256=EPOCH_SHA,cppEpochCSourceSha256=EPOCH_C_SHA,
        actualCarrierCSourceSha256=c.digest(_epoch_carrier_source()),scopeSha256=s.scope_sha256,
        readScopeSha256=s.parent.review_sha256,writerAuthorized=True,maximumStockComparisons=1,
        maximumEnumerations=1,maximumOwnedSlots=128,retainedReferenceOperationId=base.RETIRED_OPERATION,
        completionEpochVerified=False,comparisonCompletionVerified=False,fullUuidPropertyDeltaVerified=False,
        onlyOwnPendingVerified=False,dllRetentionUntilProcessExitRequired=True,
        **{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


def _unknown(s,reason):
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=s.plan['operationId'],
        reason=reason,retryAuthorized=False,parentWriterOperationId=s.parent.scope['writerOperationId'],**_authority_result(s))
    c.write_new(Path(s.plan['outputDirectory'])/'unknown.json',result);return result


def run_root_once(s,review_path,review_sha256):
    """Claim before dispatch. Epoch or native uncertainty NEVER creates result.json."""
    _check(s);need(s.phase=='STAGED','RUN_PHASE');p=s.plan;ctx=p['context'];out=Path(p['outputDirectory']);ns=s.private
    build=ns['require_stage'](p);review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind')=='ROOT_FRESH_STOCK_COMPARISON_RUN' and review.get('passed') is True
        and _authority(review) and review.get('planSha256')==c.digest(s.plan_raw)
        and review.get('buildSha256')==c.digest(c.canonical(build)) and review.get('scopeSha256')==s.scope_sha256
        and review.get('readScopeSha256')==s.parent.review_sha256
        and review.get('actualSourceSha256')==SOURCE_SHA,'ROOT_RUN')
    ns['_no_pending'](context=ctx)
    need(not any((out/n).exists() for n in ('intent.json','host-identity.json','host-result.json','result.json','unknown.json',
        'sdk-receipt.json',NATIVE_FILE,INTENT_FILE,EPOCH_FILE)),'ONE_ATTEMPT')
    claim=_claim(s);c.write_new(_claim_path(s),claim);s.phase='DISPATCHED_RETAIN'
    c.write_new(out/'intent.json',dict(version=233,operationId=p['operationId'],planSha256=c.digest(s.plan_raw),
        rootRunSha256=review_sha256,parentWriterOperationId=claim['writerOperationId'],**_authority_result(s)))
    ns['_fresh'](p)
    s.host=subprocess.Popen([str(reader.writer.PS),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(out/'run-fixed.ps1')],
        cwd=out,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
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
                        and type(sdk.get('sdkResult')) is int and sdk['sdkResult']==0,'SDK_TERMINAL')
                    ns['_fresh'](p)
                    ep=_json(out/EPOCH_FILE,bound=4096)
                    epoch_proof=epoch.classify_epoch(ep,operation_id=p['operationId'],scope_sha256=s.scope_sha256,
                        process_id=ctx['processId'],execute_thread_id=ctx['guiThreadId'],callback_known=True,
                        callback_sdk_rc=sdk['sdkResult'],target_identity_verified=True)
                    native=_json(out/NATIVE_FILE,bound=8192)
                    reserved=_json(out/INTENT_FILE,bound=4096) if (out/INTENT_FILE).is_file() else None
                    status=_native_terminal(s,native,reserved)
                except (OSError,ValueError):return _unknown(s,'CPP_EPOCH_NATIVE_OR_FRESH_CLOSURE_UNPROVEN')
                result=dict(version=233,status=status,knownTerminal=True,operationId=p['operationId'],planSha256=c.digest(s.plan_raw),
                    sdkResult=0,hookWorkersReleased=True,targetIdentityVerified=True,nativeInjectionPerformed=True,
                    nativeProofSha256=c.digest(c.read(out/NATIVE_FILE)),cppEpochProofSha256=c.digest(c.read(out/EPOCH_FILE)),
                    cppExceptionEpoch=epoch_proof,dllRetainedUntilProcessExit=epoch_proof['dllRetainedUntilProcessExit'],
                    parentWriterOperationId=claim['writerOperationId'],retryAuthorized=False,
                    releasePacketAllowed=False,releaseRefsAllowed=False,**_authority_result(s))
                if status=='FRESH_COMPARE_OBSERVED_DRAINED_CLEAN':
                    result['observedFreshPointers']={k:native[k] for k in ('selectedViewPointer','selectedResultPointer',
                        'mainSourcePointer','databaseSourcePointer')}
                    result['observedFreshPointersAuthority']='EXTERNAL_VM_READ_ONLY_NO_ADOPTION_NO_METHOD_CALLS'
                c.write_new(out/'result.json',result);s.phase='KNOWN_TERMINAL_RETAIN_PARENT';return result
            break
        if s.host.poll() is not None:break
        time.sleep(.05)
    return _unknown(s,'HOST_OR_SDK_TERMINAL_UNPROVEN')
