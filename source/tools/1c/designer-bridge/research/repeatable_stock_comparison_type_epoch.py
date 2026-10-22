"""One repeatable stock comparison with two owned drains and a type-aware epoch.

The old read scope joins retained ownership only. A separate grant permits one
runtime comparison; it never authorizes configuration, source or database writes.
"""
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace, FunctionType
import inspect
import json
import re
import subprocess
import time
import uuid
import owned_view_enumeration as base
import comparison_cpp_exception_type_epoch as epoch
import fresh_stock_comparison_epoch as prior

c=base.c
reader=base.reader
ROOT=c.ROOT
HERE=c.HERE
BASE_SHA='650964593a3f4227b102739d8799929984dfd8aae7fe7ca92ab6131501391f29'
PRIOR_SHA='9b2da6b8d533a0d3a126ae39aba05d828640e9b2ea13ab96f55311142a586601'
EPOCH_SHA='e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4'
EPOCH_C_SHA='0713ca28128fe452ae42b5743a2e2dbf79244c6fc455f3f7bb62c249fdcde8e9'
EPOCH_CHECK_NAME='comparison-cpp-type-epoch-compile-4bcd2b6e71514d2abacdd6183521cadd.json'
EPOCH_CHECK_SHA='8fbe902ae34f6d941676887dfd19c7d9e1236cdbb8f5680e1560a5ae3f35fa77'
SOURCE_NAME='NativeRepeatableStockComparison.as'
SOURCE_SHA='b0bf8263800314ff01aef7d38af9888f409711132a620dd194986a220c46a077'
CHECK_NAME='repeatable-stock-comparison-check-only-cbc1120e60fc4d1ca5ba6d2a3dc17a39.json'
CHECK_SHA='3a107cb68102666b8c66f91eee2b68ec3240de0f9828bb3980723aadac431b9f'
MAIN_SHA=base.MAIN_SHA
PROFILE='REPEATABLE_STOCK_COMPARISON_WITH_CPP_EXCEPTION_TYPE_EPOCH'
NATIVE_FILE='repeatable-stock-comparison-proof.json'
INTENT_FILE='native-compare-intent.json'
EPOCH_FILE='cpp-exception-type-epoch.json'
TRUE_AUTH=base.TRUE_AUTH+('stockCompareAuthorized','runtimeUiMutationPossible','exceptionTypeMetadataReadAuthorized')
FALSE_AUTH=base.FALSE_AUTH+('exceptionObjectReadAuthorized','typeRawOutput')
ZERO_NATIVE=tuple(k for k in base.ZERO_NATIVE if k!='commandDispatches')+('explicitResultMethodCalls','explicitResultQueries')
RETIRED_OBSERVATION='ff89a93ded0349e1a1153d4177bbb4ac'
RETIRED_PLAN_SHA='4ad901e911bef37e2b63fc2124f26f471e3d7224d77714cef59dd0e3c5f8fcfb'
RETIRED_SCOPE_SHA='fb3928c75cdcac31c55a41bcc9669e8fb3453abe4454250cdd3a30c422144b52'
RETIRED_NATIVE_SHA='7e6f201ff6b542874803d20664b8fb6dcc7ed866a45afa9b9c21ee02d78dfd71'
RETIRED_EPOCH_SHA='4879ffdb17a0e1e5ae802ce672e350db772dfecb7309c9f16459c242e285fee8'
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('REPEATABLE_STOCK_COMPARISON_'+code)


def _json(path,pin=None,bound=32768):return reader._json(path,pin,bound)


def _authority(row):
    return all(row.get(k) is True for k in TRUE_AUTH) and all(row.get(k) is False for k in FALSE_AUTH) \
        and all(type(row.get(k)) is int and row[k]==v for k,v in
            (('maximumStockComparisons',1),('maximumEnumerations',2),('maximumOwnedSlotsPerVector',128),('maximumPreexistingResults',128))) \
        and row.get('retainedReferenceOperationId')==base.RETIRED_OPERATION \
        and row.get('secondRetiredObservationOperationId')==RETIRED_OBSERVATION


def _source():
    need(SOURCE_SHA!='0'*64,'SOURCE_NOT_FROZEN')
    raw=c.read(HERE/SOURCE_NAME);need(c.digest(raw)==SOURCE_SHA,'SOURCE_PIN')
    need(set(re.findall(r'__[A-Z][A-Z0-9_]+__',raw.decode()))=={
        '__REPEATABLE_STOCK_COMPARE_SCOPE_ADMITTED__','__OPERATION_ID__','__SCOPE_SHA256__',
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
    for module,pin in ((base,BASE_SHA),(prior,PRIOR_SHA),(epoch,EPOCH_SHA)):
        need(c.digest(c.read(Path(module.__file__)))==pin,'DEPENDENCY_PIN')
    base._pins();_source();_epoch_carrier_source()
    need(EPOCH_CHECK_SHA!='0'*64,'CPP_COMPILE_PROOF_NOT_FROZEN')
    proof=_json(ROOT/'artifacts/designer-bridge'/EPOCH_CHECK_NAME,EPOCH_CHECK_SHA)
    need(proof.get('kind')=='COMPARISON_CPP_EXCEPTION_TYPE_EPOCH_COMPILE_ONLY'
        and proof.get('generatorSha256')==EPOCH_SHA and proof.get('derivedCSourceSha256')==EPOCH_C_SHA
        and proof.get('baselineSha256')==epoch.original.BASELINE_SHA
        and type(proof.get('positiveCompileExit')) is int and proof['positiveCompileExit']==0
        and type(proof.get('negativeMissingScopeMacroExit')) is int and proof['negativeMissingScopeMacroExit']!=0
        and proof.get('ownCompilerDirectoryRemoved') is True
        and all(proof.get(k) is False for k in ('goldStarted','libraryLoaded','sourceAdmitted'))
        and all(type(proof.get(k)) is int and proof[k]==0 for k in
            ('targetProcessId','nativeCalls','sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')),'CPP_COMPILE_PROOF')
    need(CHECK_SHA!='0'*64,'COLD_CHECK_NOT_FROZEN')
    check=_json(ROOT/'artifacts/designer-bridge'/CHECK_NAME,CHECK_SHA)
    need(check.get('kind')=='REPEATABLE_STOCK_COMPARISON_CHECK_ONLY' and check.get('entry')=='ahRepeatableStockComparison'
        and check.get('sourceSha256')==SOURCE_SHA and check.get('sourceMainSha256')==MAIN_SHA
        and check.get('scopeAdmitted') is False and check.get('compareExecuted') is False
        and check.get('positive',{}).get('compileVerified') is True
        and type(check.get('positive',{}).get('exitCode')) is int and check['positive']['exitCode']==0
        and check.get('negative',{}).get('compileVerified') is False
        and type(check.get('negative',{}).get('exitCode')) is int and check['negative']['exitCode']!=0
        and all(check.get(k) is True for k in ('negativeCoverage','ownRuntimeRemoved'))
        and all(check.get(k) is False for k in ('goldStarted','scriptRunRequested')),'COLD_CHECK')


def _retired_observation_audit(plan):
    """Allow runtime/configuration-read maintenance, NEVER relabel ff as success."""
    need(c.digest(c.canonical(plan))==RETIRED_PLAN_SHA and plan.get('operationId')==RETIRED_OBSERVATION
        and plan.get('actualSourceSha256')==prior.SOURCE_SHA
        and plan.get('freshStockComparisonControllerSha256')==PRIOR_SHA
        and (plan.get('context',{}).get('processId'),plan.get('context',{}).get('birth'),
             plan.get('context',{}).get('guiThreadId'),plan.get('context',{}).get('mainSha256'))==
            (48936,'01dd5d0180299126',8292,MAIN_SHA),'RETIRED_OBSERVATION_PLAN')
    out=ROOT/'build'/('designer-hot-v233-'+RETIRED_OBSERVATION)
    need(not (out/'result.json').exists(),'RETIRED_RESULT_MUST_REMAIN_ABSENT')
    native=_json(out/prior.NATIVE_FILE,RETIRED_NATIVE_SHA,8192)
    reserved=_json(out/prior.INTENT_FILE,bound=4096)
    # This proves only configuration-clean runtime/reference closure. Its
    # independent epoch remains rejected and old unknown.json is not changed.
    need(prior._native_terminal(SimpleNamespace(plan=plan,scope_sha256=RETIRED_SCOPE_SHA),native,reserved)==
        'FRESH_COMPARE_OBSERVED_DRAINED_CLEAN'
        and all(type(native.get(k)) is int and native[k]==v for k,v in
            (('newOwnedSlots',56),('nonNullSlots',56),('validatedSlots',56),('adoptionAttempts',56),('releasedSlots',56),
             ('clearedSlots',56),('oldReferenceCountBefore',10),('oldReferenceCountBeforeEnumeration',10),
             ('oldReferenceCountDuringEnumeration',11),('matchedOldViewSlots',1),('oldReferenceCountAfter',10),
             ('selectedReferenceCountDuring',7),('selectedReferenceCountAfter',6))),'RETIRED_OBSERVATION_RUNTIME')
    ep=_json(out/prior.EPOCH_FILE,RETIRED_EPOCH_SHA,4096)
    need(ep.get('kind')=='COMPARISON_CPP_EXCEPTION_EPOCH' and ep.get('operationId')==RETIRED_OBSERVATION
        and ep.get('scopeSha256')==RETIRED_SCOPE_SHA and ep.get('phase')=='EXECUTE_RETURNED'
        and ep.get('handlerReturn')=='CONTINUE_SEARCH' and ep.get('epochCoverage')=='synchronous_context_Execute'
        and all(ep.get(k) is True for k in ('handlerRegistered','handlerRemoved','executeEntered','executeReturned',
            'selfReferenceRetained','dllMustRemainLoadedUntilProcessExit'))
        and all(ep.get(k) is False for k in ('counterOverflow','futureOtherThreadBarrierVerified','exceptionDetailsCaptured',
            'scopeSourceBindingVerified','fullPendingVerified','databaseUpdateAuthorized'))
        and all(type(ep.get(k)) is int and ep[k]==v for k,v in
            (('processId',48936),('executeThreadId',8292),('sdkExecuteRc',0),('cppThrows',6),('cppThrowsExecuteThread',6),
             ('cppThrowsOtherThreads',0),('otherExceptions',0),('otherExceptionsExecuteThread',0),('otherExceptionsOtherThreads',0))),
        'RETIRED_REJECTED_EPOCH')
    sdk=_json(out/'sdk-receipt.json',bound=8192);intent=_json(out/'intent.json',bound=8192)
    unknown=_json(out/'unknown.json',bound=8192)
    claim=_json(ROOT/'artifacts/designer-bridge'/('fresh-stock-comparison-claim-'+RETIRED_SCOPE_SHA+'.json'))
    need(sdk.get('knownTerminal') is True and sdk.get('hookWorkersReleased') is True
        and type(sdk.get('sdkResult')) is int and sdk['sdkResult']==0
        and type(sdk.get('threadId')) is int and sdk['threadId']==8292
        and unknown.get('status')=='UNKNOWN_RETAIN' and unknown.get('knownTerminal') is False
        and unknown.get('retryAuthorized') is False and unknown.get('reason')=='CPP_EPOCH_NATIVE_OR_FRESH_CLOSURE_UNPROVEN'
        and claim.get('kind')=='FRESH_STOCK_COMPARISON_CLAIM'
        and claim.get('writerOperationId')==plan.get('parentWriterOperationId')
        and all(row.get('operationId')==RETIRED_OBSERVATION and row.get('scopeSha256')==RETIRED_SCOPE_SHA for row in
            (sdk,intent,unknown,claim))
        and all(row.get('planSha256')==RETIRED_PLAN_SHA for row in (sdk,intent))
        and all(row.get('actualSourceSha256')==prior.SOURCE_SHA for row in (sdk,intent,unknown,claim))
        and all(sdk.get(k) is False for k in prior.FALSE_AUTH),'RETIRED_SDK_INTENT_UNKNOWN_CLAIM')
    return 'REJECTED_COMPARISON_CONFIG_CLEAN_RUNTIME_MAINTENANCE_ONLY'


def _maintenance_namespace(parent):
    """Private original owner audits with ONLY two exact historical permits."""
    ns=reader._namespace(parent);source=inspect.getsource(c._no_pending)
    skip='or operation==allow_operation:';anchor='        if prior_identity!=identity: continue\n'
    need(source.count(skip)==1 and source.count(anchor)==1,'PRIVATE_AUDIT_ANCHORS')
    source=source.replace(skip,'or operation==allow_operation or operation==__pending_read_operation:',1)
    source=source.replace(anchor,anchor+
        '        if operation==__retained_reference_operation:\n'
        '            __retained_reference_audit(prior);continue\n'
        '        if operation==__retired_observation_operation:\n'
        '            __retired_observation_audit(prior);continue\n',1)
    ns.update(__retained_reference_operation=base.RETIRED_OPERATION,__retained_reference_audit=base._retained_reference_audit,
        __retired_observation_operation=RETIRED_OBSERVATION,__retired_observation_audit=_retired_observation_audit)
    exec(compile(source,'<exact-two-retained-runtime-maintenance-audit>','exec'),ns)
    audit=ns['_no_pending']
    def no_pending(allow_operation=None,context=None):
        need(context==parent.plan['context'] and allow_operation in
            (None,parent.plan['operationId'],ns['__pending_read_operation']),'MAINTENANCE_AUDIT_SCOPE')
        reader._check_owner(parent)
        return audit(allow_operation=parent.scope['writerOperationId'],context=context)
    ns['_no_pending']=no_pending;return ns


def _prepare_parent(path,pin):
    ns=dict(reader.__dict__);ns['_namespace']=_maintenance_namespace
    prepare=FunctionType(reader.prepare_root.__code__,ns,reader.prepare_root.__name__,
        reader.prepare_root.__defaults__,reader.prepare_root.__closure__)
    prepare.__kwdefaults__=reader.prepare_root.__kwdefaults__
    return prepare(path,pin)


@dataclass(slots=True)
class RepeatableEpoch:
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


def _claim_path(s):return ROOT/'artifacts/designer-bridge'/('repeatable-stock-comparison-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='REPEATABLE_STOCK_COMPARISON_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
        actualSourceSha256=SOURCE_SHA,controllerSha256=s.plan['repeatableStockComparisonControllerSha256'],
        writerOperationId=q['operationId'],writerIntentSha256=c.digest(c.canonical(q)),packetSha256=q['packetSha256'],
        sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'],stockCompareAuthorized=True,
        maximumStockComparisons=1,maximumEnumerations=2,maximumOwnedSlotsPerVector=128,maximumPreexistingResults=128,
        secondRetiredObservationOperationId=RETIRED_OBSERVATION)


def _check(s):
    need(type(s) is RepeatableEpoch and s._issuer is _ISSUER,'ISSUED_COMPARISON');_pins()
    p=s.plan;ctx=p['context']
    need(c.canonical(p)==s.plan_raw and p.get('repeatableStockComparisonControllerSha256')==c.digest(c.read(Path(__file__))), 'PLAN_DRIFT')
    need(p.get('actualSourceSha256')==SOURCE_SHA and p.get('repeatableStockComparisonProfile')==PROFILE
        and p.get('cppEpochGeneratorSha256')==EPOCH_SHA and p.get('cppEpochCSourceSha256')==EPOCH_C_SHA
        and p.get('actualCarrierCSourceSha256')==c.digest(_epoch_carrier_source())
        and _authority(p) and p.get('writerAuthorized') is True and p.get('captureAuthorized') is False
        and type(p.get('applicationWrites')) is int and p['applicationWrites']==0
        and p.get('compareScopeSha256')==s.scope_sha256 and p.get('readScopeSha256')==s.parent.review_sha256
        and p.get('context')==s.parent.plan['context'],'PLAN_AUTHORITY')
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256'))==
        (48936,'01dd5d0180299126',8292,MAIN_SHA),'FIXED_NATIVE')
    q=reader._check_owner(s.parent);scope=_json(s.scope_path,s.scope_sha256)
    need(scope==s.scope and scope.get('kind')=='ROOT_REPEATABLE_STOCK_COMPARISON_SCOPE' and scope.get('passed') is True
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
    authority="version=233;writerAuthorized=$true;"+''.join(k+'=$true;' for k in TRUE_AUTH)+''.join(k+'=$false;' for k in FALSE_AUTH)
    authority+="maximumStockComparisons=1;maximumEnumerations=2;maximumOwnedSlotsPerVector=128;maximumPreexistingResults=128;retainedReferenceOperationId='"+base.RETIRED_OPERATION+"';secondRetiredObservationOperationId='"+RETIRED_OBSERVATION+"';"
    authority+="repeatableStockComparisonProfile='"+PROFILE+"';actualSourceSha256='"+SOURCE_SHA+"';"
    authority+="cppEpochGeneratorSha256='"+EPOCH_SHA+"';cppEpochCSourceSha256='"+EPOCH_C_SHA+"';dllRetentionUntilProcessExitRequired=$true;"
    ps=ps.replace('version=233;',authority);files['run-fixed.ps1']=ps.encode('utf-8-sig');return files


def prepare_root(scope_path,scope_sha256):
    """Prepare fixed comparison; no host/native call until stage and root run grant."""
    _pins();path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=_json(path,scope_sha256)
    need(scope.get('kind')=='ROOT_REPEATABLE_STOCK_COMPARISON_SCOPE' and scope.get('passed') is True
        and _authority(scope) and scope.get('actualSourceSha256')==SOURCE_SHA,'COMPARE_SCOPE_BEFORE_OWNER')
    parent=_prepare_parent(scope['readScopePath'],scope['readScopeSha256']);p=dict(parent.plan);op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):p.pop(key)
    p.update(operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),repeatableStockComparisonProfile=PROFILE,
        actualSourceSha256=SOURCE_SHA,repeatableStockComparisonControllerSha256=c.digest(c.read(Path(__file__))),compareScopeSha256=scope_sha256,
        cppEpochGeneratorSha256=EPOCH_SHA,cppEpochCSourceSha256=EPOCH_C_SHA,actualCarrierCSourceSha256=c.digest(_epoch_carrier_source()),
        readScopeSha256=parent.review_sha256,maximumStockComparisons=1,maximumEnumerations=2,maximumOwnedSlotsPerVector=128,maximumPreexistingResults=128,
        retainedReferenceOperationId=base.RETIRED_OPERATION,secondRetiredObservationOperationId=RETIRED_OBSERVATION,
        writerAuthorized=True,captureAuthorized=False,applicationWrites=0,
        **{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})
    p['goldLeaseOwner'],p['goldLeaseBootstrapSha256']=base.owner_base._lease_binding(p['context'])
    s=RepeatableEpoch(_ISSUER,parent,scope,path,scope_sha256,p,c.canonical(p),{});_check(s)
    ns=parent.private;ns['__pending_read_operation']=op
    def fresh(plan):_check(s);need(plan==s.plan,'FRESH_PLAN');c._fresh(base._carrier_view(plan))
    def render(plan,raw):need(plan==s.plan,'RENDER_PLAN');return _render(s)
    ns.update(_fresh=fresh,render=render);s.private=ns;ns['_no_pending'](context=p['context']);return s


def stage_root(s):
    _check(s);need(s.phase=='PREPARED','STAGE_PHASE')
    proof=s.private['stage_private'](s.plan,dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',rootAuthorized=True,planSha256=c.digest(s.plan_raw)))
    s.phase='STAGED';return proof


def _drained_enum(row,phase):
    need(type(row) is dict and type(row.get('phase')) is int and row['phase']==phase
        and all(row.get(k) is True for k in ('callReturned','headerKnown','vectorKnown','drainReturned','counterBalanced','rootTargetsClean')),
        'VECTOR_CLOSURE')
    keys=('slots','nonNullSlots','validatedSlots','adoptionAttempts','releasedSlots','clearedSlots',
          'oldCountBefore','oldCountDuring','oldCountAfter','oldMatchedSlots')
    need(all(type(row.get(k)) is int for k in keys),'VECTOR_COUNTER_TYPES')
    slots=row['slots'];nonzero=row['nonNullSlots'];before=row['oldCountBefore']
    need(0<=nonzero<=slots<=128 and row['validatedSlots']==slots and row['clearedSlots']==slots
        and row['adoptionAttempts']==nonzero and row['releasedSlots']==nonzero
        and before>0 and 0<=row['oldMatchedSlots']<=nonzero
        and row['oldCountDuring']==before+row['oldMatchedSlots'] and row['oldCountAfter']==before
        and (phase!=0 or before==10),'VECTOR_DRAIN_BALANCE')


def _unstarted_enum(row,phase):
    need(type(row) is dict and type(row.get('phase')) is int and row['phase']==phase
        and row.get('callReturned') is False
        and all(type(row.get(k)) is int and row[k]==0 for k in
            ('slots','nonNullSlots','validatedSlots','adoptionAttempts','releasedSlots','clearedSlots')),'UNSTARTED_VECTOR')


def _native_terminal(s,native,reserved):
    """Two complete owned drains; only the separate typed epoch admits target path."""
    need(type(native) is dict and native.get('kind')=='REPEATABLE_STOCK_COMPARISON'
        and native.get('operationId')==s.plan['operationId'] and native.get('scopeSha256')==s.scope_sha256
        and all(native.get(k) is True for k in ('configurationReadOnly','runtimeCacheMutationPossible',
            'runtimeUiMutationPossible','stockCompareAuthorized','newOwnedSlotsOnly','historicalReferencesRetained','retentionRequired'))
        and all(native.get(k) is False for k in ('readOnly','historicalReferenceCleanupAuthorized','retryAuthorized',
            'nativeMainDbDirectionVerified','completionEpochVerified','comparisonCompletionVerified','fullUuidPropertyDeltaVerified','onlyOwnPendingVerified'))
        and native.get('commandGroup')=='f10cbb81-f679-11d4-9dd3-0050bae2bc79'
        and all(type(native.get(k)) is int and native[k]==v for k,v in
            (('commandId',30),('subCommand',0),('maximumStockComparisons',1),('maximumEnumerations',2),
             ('maximumOwnedSlotsPerVector',128),('maximumPreexistingResults',128)))
        and all(type(native.get(k)) is int and native[k]==0 for k in ZERO_NATIVE),'NATIVE_JOIN')
    rows=native.get('enumerations');need(type(rows) is list and len(rows)==2,'VECTOR_ROWS')
    compare=native.get('compareAttempts');enums=native.get('enumerationAttempts')
    need(type(compare) is int and type(enums) is int and native.get('unknownRetained') is False,'NATIVE_ATTEMPTS')
    if native.get('status')=='REFUSED_BEFORE_ENUM':
        need(compare==0 and enums==0 and native.get('commandReturned') is False,'NATIVE_ZERO_REFUSAL')
        for phase in range(2):_unstarted_enum(rows[phase],phase)
        return 'REFUSED_BEFORE_ENUM'
    need(type(reserved) is dict and reserved.get('kind')=='REPEATABLE_STOCK_COMPARISON_RESERVED'
        and reserved.get('operationId')==s.plan['operationId'] and reserved.get('scopeSha256')==s.scope_sha256
        and reserved.get('commandGroup')=='f10cbb81-f679-11d4-9dd3-0050bae2bc79'
        and all(reserved.get(k) is True for k in ('stockCompareAuthorized','newOwnedSlotsOnly','configurationReadOnly',
            'runtimeCacheMutationPossible','runtimeUiMutationPossible'))
        and reserved.get('readOnly') is False and reserved.get('historicalReferenceCleanupAuthorized') is False
        and all(type(reserved.get(k)) is int and reserved[k]==v for k,v in
            (('commandId',30),('subCommand',0),('maximumStockComparisons',1),('maximumEnumerations',2),
             ('maximumOwnedSlotsPerVector',128),('maximumPreexistingResults',128),('oldReferenceCountBefore',10),
             ('sourceWrites',0),('configurationSaves',0),('databaseUpdates',0),('repositoryMutations',0))),'NATIVE_INTENT')
    need(native.get('nativeIntentWritten') is True and native.get('rootCleanBefore') is True
        and type(native.get('targetsCleanBefore')) is int and native['targetsCleanBefore']==3,'NATIVE_BEFORE_CLEAN')
    _drained_enum(rows[0],0)
    if native.get('status')=='BEFORE_ENUM_DRAINED_REFUSED':
        need(compare==0 and enums==1 and native.get('commandReturned') is False
            and native.get('preexistingResultSetVerified') is False,'NATIVE_BEFORE_ONLY')
        _unstarted_enum(rows[1],1);return 'BEFORE_ENUM_DRAINED_REFUSED'
    need(native.get('status') in ('REPEATABLE_COMPARE_OBSERVED_DRAINED_CLEAN','COMPARE_RETURNED_NO_FRESH_RESULT_CLEAN')
        and compare==1 and enums==2 and native.get('commandReturned') is True
        and native.get('rootCleanAfter') is True and type(native.get('targetsCleanAfter')) is int and native['targetsCleanAfter']==3
        and native.get('preexistingResultSetVerified') is True and native.get('afterResultSetVerified') is True,'NATIVE_AFTER_CLEAN')
    _drained_enum(rows[1],1)
    pointers=native.get('preexistingResultPointers');views=native.get('preexistingComparisonViews');count=native.get('preexistingResultCount')
    need(type(pointers) is list and type(views) is int and type(count) is int
        and 0<=count<=views<=rows[0]['nonNullSlots']<=128 and len(pointers)==count
        and all(type(v) is int and 65536<=v<=0xffffffff and v%4==0 for v in pointers)
        and len(set(pointers))==count,'PREEXISTING_RESULT_SET')
    candidates=native.get('freshCandidates');need(type(candidates) is int and 0<=candidates<=128,'FRESH_CANDIDATES')
    if native['status']=='COMPARE_RETURNED_NO_FRESH_RESULT_CLEAN':
        need(native.get('reason')=='NO_UNIQUE_FRESH_RESULT' and candidates!=1 and native.get('freshBindingVerified') is False
            and all(type(native.get(k)) is int and native[k]==0 for k in ('selectedViewPointer','selectedResultPointer')),'NATIVE_NO_FRESH')
        return native['status']
    need(native.get('reason')=='NONE' and candidates==1 and native.get('freshBindingVerified') is True
        and native.get('coherent') is True and native.get('knownStateObserved') is True
        and type(native.get('passes')) is int and native['passes']==2 and type(native.get('bindingSnapshotSha256')) is str
        and re.fullmatch('[0-9a-f]{64}',native['bindingSnapshotSha256']) is not None,'NATIVE_FRESH_BINDING')
    keys=('selectedViewPointer','selectedResultPointer','oldViewPointer','oldResultBeforePointer','mainSourcePointer','databaseSourcePointer')
    need(all(type(native.get(k)) is int and 65536<=native[k]<=0xffffffff and native[k]%4==0 for k in keys)
        and native['selectedResultPointer'] not in pointers
        and native['mainSourcePointer']!=native['databaseSourcePointer'],'NATIVE_FRESH_POINTERS')
    need(all(type(native.get(k)) is int for k in ('selectedReferenceCountDuring','selectedReferenceCountAfter','selectedMatchedSlots'))
        and native.get('selectedCounterBalanced') is True and 1<=native['selectedMatchedSlots']<=rows[1]['nonNullSlots']
        and native['selectedReferenceCountDuring']>native['selectedMatchedSlots']
        and native['selectedReferenceCountAfter']==native['selectedReferenceCountDuring']-native['selectedMatchedSlots'],'NATIVE_SELECTED_DRAIN')
    need(type(native.get('completionFlag')) is int and native['completionFlag']==1
        and type(native.get('selectedObjectCount')) is int and native['selectedObjectCount']>0
        and type(native.get('visitedObjectCount')) is int and native['selectedObjectCount']==native['visitedObjectCount']
        and native.get('resultScopeGuidNull') is True and native.get('engineScopeGuidNull') is True
        and all(type(native.get(k)) is int and native[k]==0 for k in
            ('engineScopeEnabled','propertyTypeBypass','resourceDetailBranch')),'NATIVE_OBSERVED_STATE')
    return native['status']


def _authority_result(s):
    return dict(repeatableStockComparisonProfile=PROFILE,actualSourceSha256=SOURCE_SHA,
        repeatableStockComparisonControllerSha256=s.plan['repeatableStockComparisonControllerSha256'],
        cppEpochGeneratorSha256=EPOCH_SHA,cppEpochCSourceSha256=EPOCH_C_SHA,
        actualCarrierCSourceSha256=c.digest(_epoch_carrier_source()),scopeSha256=s.scope_sha256,
        readScopeSha256=s.parent.review_sha256,writerAuthorized=True,maximumStockComparisons=1,
        maximumEnumerations=2,maximumOwnedSlotsPerVector=128,maximumPreexistingResults=128,
        retainedReferenceOperationId=base.RETIRED_OPERATION,secondRetiredObservationOperationId=RETIRED_OBSERVATION,
        completionEpochVerified=False,comparisonCompletionVerified=False,fullUuidPropertyDeltaVerified=False,
        onlyOwnPendingVerified=False,allCppExceptionFree=False,dllRetentionUntilProcessExitRequired=True,
        **{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


def _unknown(s,reason):
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=s.plan['operationId'],
        reason=reason,retryAuthorized=False,parentWriterOperationId=s.parent.scope['writerOperationId'],**_authority_result(s))
    c.write_new(Path(s.plan['outputDirectory'])/'unknown.json',result);return result


def run_root_once(s,review_path,review_sha256):
    """Claim before dispatch. Epoch or native uncertainty NEVER creates result.json."""
    _check(s);need(s.phase=='STAGED','RUN_PHASE');p=s.plan;ctx=p['context'];out=Path(p['outputDirectory']);ns=s.private
    build=ns['require_stage'](p);review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind')=='ROOT_REPEATABLE_STOCK_COMPARISON_RUN' and review.get('passed') is True
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
                    ep=_json(out/EPOCH_FILE,bound=32768)
                    epoch_proof=epoch.classify_type_epoch(ep,operation_id=p['operationId'],scope_sha256=s.scope_sha256,
                        process_id=ctx['processId'],execute_thread_id=ctx['guiThreadId'],callback_known=True,
                        callback_sdk_rc=sdk['sdkResult'],target_identity_verified=True)
                    native=_json(out/NATIVE_FILE,bound=8192)
                    reserved=_json(out/INTENT_FILE,bound=4096) if (out/INTENT_FILE).is_file() else None
                    status=_native_terminal(s,native,reserved)
                except (OSError,ValueError):return _unknown(s,'CPP_EPOCH_NATIVE_OR_FRESH_CLOSURE_UNPROVEN')
                result=dict(version=233,status=status,knownTerminal=True,operationId=p['operationId'],planSha256=c.digest(s.plan_raw),
                    sdkResult=0,hookWorkersReleased=True,targetIdentityVerified=True,nativeInjectionPerformed=True,
                    nativeProofSha256=c.digest(c.read(out/NATIVE_FILE)),cppEpochProofSha256=c.digest(c.read(out/EPOCH_FILE)),
                    cppExceptionTypeEpoch=epoch_proof,dllRetainedUntilProcessExit=epoch_proof['dllRetainedUntilProcessExit'],
                    parentWriterOperationId=claim['writerOperationId'],retryAuthorized=False,
                    releasePacketAllowed=False,releaseRefsAllowed=False,**_authority_result(s))
                if status=='REPEATABLE_COMPARE_OBSERVED_DRAINED_CLEAN':
                    result['observedFreshPointers']={k:native[k] for k in ('selectedViewPointer','selectedResultPointer',
                        'mainSourcePointer','databaseSourcePointer')}
                    result['observedFreshPointersAuthority']='EXTERNAL_VM_READ_ONLY_NO_ADOPTION_NO_METHOD_CALLS'
                c.write_new(out/'result.json',result);s.phase='KNOWN_TERMINAL_RETAIN_PARENT';return result
            break
        if s.host.poll() is not None:break
        time.sleep(.05)
    return _unknown(s,'HOST_OR_SDK_TERMINAL_UNPROVEN')
