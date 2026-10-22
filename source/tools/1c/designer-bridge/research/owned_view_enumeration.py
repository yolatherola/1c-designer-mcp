"""Own and drain one NEW view enumeration while retaining historical b12 references.

The retained read scope joins ownership only. A separate reference grant permits
one fresh enumeration and its owned slots only; no application or configuration write is authorized.
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
import sheet_notify_pending_read as reader
import comparison_provider_read as owner_base

c=reader.c
ROOT=c.ROOT
HERE=c.HERE
SOURCE_NAME='NativeOwnedViewEnumeration.as'
SOURCE_SHA='82e8b9ed30670a69b182f376d06b37b24d5c58df81a2a389277e378f201ba89c'
READER_SHA='825e7926d8eb8ab360d6413251d661f64be415e97c6ff3073b97ff77d39b4d7a'
OWNER_BASE_SHA='4845ddd127f1fb4508085a188b799a19b20aa1f7495f66a5c63af59ae329f80e'
CHECK_NAME='owned-view-enumeration-check-only-d1c99b84a70c4a1f8569a07ad9691e2b.json'
CHECK_SHA='4e4f74126b8893d651b9012ade856b3529957ceed1b708bd7bc75e7b37f4c019'
MAIN_SHA='d06c152775ede6d0ae91d10d5736ec09a3f63e2f6b2637689ff8329e18db50b2'
PROFILE='OWNED_VIEW_ENUMERATION_ONCE'
NATIVE_FILE='owned-view-enumeration-proof.json'
INTENT_FILE='native-enum-intent.json'
TRUE_AUTH=('configurationReadOnly','runtimeCacheMutationPossible','newEnumerationAuthorized',
    'ownedVectorDrainAuthorized','retainedReferenceMaintenanceAuthorized')
FALSE_AUTH=('readOnly','sourceWritesAuthorized','configurationSavesAuthorized','databaseUpdatesAuthorized',
    'repositoryMutationsAuthorized','releaseResourcesAuthorized','configurationExportsAuthorized','configurationImportsAuthorized',
    'historicalReferencesReleaseAuthorized','manualAddRefReleaseAuthorized')
ZERO_NATIVE=('explicitReferenceAcquireCalls','explicitReferenceReleaseCalls','commandDispatches','applicationTextOutputBytes',
    'sourceWrites','metadataWrites','configurationSaves','databaseUpdates','repositoryMutations')
RETIRED_OPERATION='b12f0638f32b4d98ba41459a86f00e8e'
RETIRED_PLAN_SHA='f3ad407f86cdb8e11a2c9d0e87316bc6b236d0c2058dd04894105a68925fa499'
RETIRED_NATIVE_SHA='0c7e013f54c30a99e3ef8eeb9134ebe9d07fdd8fdbc3b29dbb537b9acacdcffe'
POST_CALLBACK_SHA='83900c7764fcb2633852a2eaec1da0548c74f732ef3b2d8a5e529d6dadb103b5'
RETIRED_SCOPE_SHA='6ec3756a26fed096b97e6ecc17a6cb057eb52c2fb547f11aa4a7eddb9d307109'
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('OWNED_VIEW_ENUMERATION_'+code)


def _json(path,pin=None,bound=32768):return reader._json(path,pin,bound)


def _authority(row):
    return all(row.get(k) is True for k in TRUE_AUTH) and all(row.get(k) is False for k in FALSE_AUTH) \
        and type(row.get('maximumEnumerations')) is int and row['maximumEnumerations']==1 \
        and type(row.get('maximumOwnedSlots')) is int and row['maximumOwnedSlots']==128 \
        and row.get('retainedReferenceOperationId')==RETIRED_OPERATION


def _source():
    raw=c.read(HERE/SOURCE_NAME)
    need(c.digest(raw)==SOURCE_SHA,'SOURCE_PIN')
    need(set(re.findall(r'__[A-Z][A-Z0-9_]+__',raw.decode()))=={
        '__OWNED_VIEW_ENUM_SCOPE_ADMITTED__','__OPERATION_ID__','__SCOPE_SHA256__','__PROOF_PATH__','__NATIVE_ENUM_INTENT_PATH__'},'SOURCE_TOKENS')
    return raw


def _pins():
    for module,pin in ((reader,READER_SHA),(owner_base,OWNER_BASE_SHA)):
        need(c.digest(c.read(Path(module.__file__)))==pin,'DEPENDENCY_PIN')
    reader._pins(reader.EDITOR_PROFILE);_source()
    proof=_json(ROOT/'artifacts/designer-bridge'/CHECK_NAME,CHECK_SHA)
    need(proof.get('kind')=='OWNED_VIEW_ENUMERATION_CHECK_ONLY' and proof.get('entry')=='ahOwnedViewEnumeration'
        and proof.get('sourceSha256')==SOURCE_SHA and proof.get('sourceMainSha256')==MAIN_SHA
        and proof.get('scopeAdmitted') is False and proof.get('enumExecuted') is False and proof.get('referenceReleaseExecuted') is False
        and proof.get('positive',{}).get('compileVerified') is True
        and type(proof.get('positive',{}).get('exitCode')) is int and proof['positive']['exitCode']==0
        and proof.get('negative',{}).get('compileVerified') is False
        and type(proof.get('negative',{}).get('exitCode')) is int and proof['negative']['exitCode']!=0
        and all(proof.get(k) is True for k in ('negativeCoverage','ownRuntimeRemoved'))
        and all(proof.get(k) is False for k in ('goldStarted','scriptRunRequested')),'COLD_CHECK')
    need(c.digest(c.read(HERE/'view_enumeration_ownership_primary.py'))==
        'eeff2d82c88924d1182abef33c7130140098852687ca32f0c5f7fb1819568f33','ENUM_OWNERSHIP_PIN')
    need(c.digest(c.read(HERE/'core_as_iunknown_ownership_primary.py'))==
        '916d7d130d7951bce99fa4a008078da7326582901f14d7964923f1da4c41e39f','RAW_ADOPTION_PIN')


def _retained_reference_audit(prior):
    """Exact b12 maintenance exception; never label its old references clean."""
    need(c.digest(c.canonical(prior))==RETIRED_PLAN_SHA
        and prior.get('operationId')==RETIRED_OPERATION
        and prior.get('actualSourceSha256')=='67470a19c7caae2964d0aae647ab07268ab39b82b80dab29f211a220f16a7a45'
        and (prior.get('context',{}).get('processId'),prior.get('context',{}).get('birth'),
             prior.get('context',{}).get('guiThreadId'),prior.get('context',{}).get('mainSha256'))==
            (48936,'01dd5d0180299126',8292,MAIN_SHA),'RETAINED_EXACT_PLAN')
    out=ROOT/'build'/('designer-hot-v233-'+RETIRED_OPERATION)
    need(not (out/'result.json').exists(),'RETAINED_NOT_REWRITTEN_TERMINAL')
    native=_json(out/'comparison-view-acquire-proof.json',RETIRED_NATIVE_SHA,8192)
    sdk=_json(out/'sdk-receipt.json',bound=8192)
    intent=_json(out/'intent.json',bound=8192);unknown=_json(out/'unknown.json',bound=8192)
    need(native.get('operationId')==RETIRED_OPERATION and native.get('scopeSha256')==RETIRED_SCOPE_SHA
        and native.get('kind')=='COMPARISON_VIEW_ACQUISITION' and native.get('status')=='UNKNOWN_RETAIN'
        and native.get('pendingReference') is True and native.get('counterRestored') is False
        and native.get('ourHandleCleanupReturned') is True and native.get('viewStillListedAfterCleanup') is True
        and native.get('rootCleanBefore') is True and native.get('rootCleanAfter') is True
        and native.get('framedViewType')=={'module':'frntend.dll','rva':0xc0e18c}
        and all(type(native.get(k)) is int and native[k]==v for k,v in
            [('referenceAcquireAttempts',1),('referenceCountBefore',9),('referenceCountReturned',10),('referenceCountAfter',10),
             ('targetsCleanBefore',3),('targetsCleanAfter',3),('sourceWrites',0),('metadataWrites',0),
             ('configurationSaves',0),('databaseUpdates',0),('repositoryMutations',0),('commandDispatches',0)]),
        'RETAINED_EXACT_NATIVE')
    need(sdk.get('operationId')==RETIRED_OPERATION and sdk.get('scopeSha256')==RETIRED_SCOPE_SHA
        and sdk.get('planSha256')==RETIRED_PLAN_SHA and sdk.get('actualSourceSha256')==prior['actualSourceSha256']
        and sdk.get('knownTerminal') is True and sdk.get('hookWorkersReleased') is True
        and type(sdk.get('sdkResult')) is int and sdk['sdkResult']==0
        and type(sdk.get('threadId')) is int and sdk['threadId']==8292
        and all(sdk.get(k) is False for k in ('sourceWritesAuthorized','configurationSavesAuthorized',
            'databaseUpdatesAuthorized','repositoryMutationsAuthorized','releaseResourcesAuthorized')),
        'RETAINED_SDK_RETURNED')
    need(intent.get('operationId')==RETIRED_OPERATION and intent.get('planSha256')==RETIRED_PLAN_SHA
        and intent.get('scopeSha256')==RETIRED_SCOPE_SHA
        and unknown.get('operationId')==RETIRED_OPERATION and unknown.get('scopeSha256')==RETIRED_SCOPE_SHA
        and unknown.get('status')=='UNKNOWN_RETAIN' and unknown.get('knownTerminal') is False
        and unknown.get('retryAuthorized') is False,'RETAINED_INTENT_UNKNOWN_JOIN')
    post=_json(ROOT/'artifacts/designer-bridge'/('comparison-view-postcallback-counter-'+RETIRED_OPERATION+'.json'),POST_CALLBACK_SHA)
    need(post.get('kind')=='COMPARISON_VIEW_POSTCALLBACK_COUNTER' and post.get('operationId')==RETIRED_OPERATION
        and post.get('priorNativeSha256')==RETIRED_NATIVE_SHA
        and (post.get('processId'),post.get('processBirth'))==(48936,'01dd5d0180299126')
        and post.get('callbackTerminalVerified') is True and post.get('viewTypeVerified') is True
        and post.get('counterRestoredAfterCallback') is False and post.get('referenceCounts')==[10,10]
        and all(type(post.get(k)) is int and post[k]==0 for k in
            ('nativeCallbacks','referenceAcquireCalls','referenceReleaseCalls','sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')),
        'RETAINED_POST_CALLBACK')
    return 'KNOWN_RUNTIME_REFERENCES_RETAINED_PENDING_EXIT'


def _maintenance_namespace(parent):
    """Keep all ordinary audits, except one pinned b12 retained-reference permit."""
    ns=reader._namespace(parent)
    source=inspect.getsource(c._no_pending)
    skip='or operation==allow_operation:'
    need(source.count(skip)==1,'PRIVATE_SELF_SKIP_ANCHOR')
    source=source.replace(skip,'or operation==allow_operation or operation==__pending_read_operation:',1)
    anchor='        if prior_identity!=identity: continue\n'
    need(source.count(anchor)==1,'PRIVATE_RETAINED_AUDIT_ANCHOR')
    source=source.replace(anchor,anchor+
        '        if operation==__retained_reference_operation:\n'
        '            __retained_reference_audit(prior);continue\n',1)
    ns.update(__retained_reference_operation=RETIRED_OPERATION,__retained_reference_audit=_retained_reference_audit)
    exec(compile(source,'<exact-retained-reference-maintenance-audit>','exec'),ns)
    audit=ns['_no_pending']
    def no_pending(allow_operation=None,context=None):
        need(context==parent.plan['context'] and allow_operation in
            (None,parent.plan['operationId'],ns['__pending_read_operation']),'MAINTENANCE_AUDIT_SCOPE')
        reader._check_owner(parent)
        return audit(allow_operation=parent.scope['writerOperationId'],context=context)
    ns['_no_pending']=no_pending
    return ns


def _prepare_parent(path,pin):
    # The default reader prepares AND audits before return. Override only this
    # one function's private namespace construction, never the imported module.
    namespace=dict(reader.__dict__);namespace['_namespace']=_maintenance_namespace
    prepare=FunctionType(reader.prepare_root.__code__,namespace,reader.prepare_root.__name__,
        reader.prepare_root.__defaults__,reader.prepare_root.__closure__)
    prepare.__kwdefaults__=reader.prepare_root.__kwdefaults__
    return prepare(path,pin)



@dataclass(slots=True)
class Enumeration:
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


def _claim_path(s):return ROOT/'artifacts/designer-bridge'/('owned-view-enumeration-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='OWNED_VIEW_ENUMERATION_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
        actualSourceSha256=SOURCE_SHA,controllerSha256=s.plan['ownedViewEnumerationControllerSha256'],
        writerOperationId=q['operationId'],writerIntentSha256=c.digest(c.canonical(q)),packetSha256=q['packetSha256'],
        sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'],newEnumerationAuthorized=True)


def _lease(s):owner_base._lease(SimpleNamespace(plan=s.plan))


def _check(s):
    need(type(s) is Enumeration and s._issuer is _ISSUER,'ISSUED_COMPARISON');_pins()
    p=s.plan;ctx=p['context']
    need(c.canonical(p)==s.plan_raw and p.get('ownedViewEnumerationControllerSha256')==c.digest(c.read(Path(__file__))), 'PLAN_DRIFT')
    need(p.get('actualSourceSha256')==SOURCE_SHA and p.get('ownedViewEnumerationProfile')==PROFILE
        and _authority(p) and p.get('writerAuthorized') is True and p.get('captureAuthorized') is False
        and type(p.get('applicationWrites')) is int and p['applicationWrites']==0
        and p.get('enumScopeSha256')==s.scope_sha256 and p.get('readScopeSha256')==s.parent.review_sha256
        and p.get('context')==s.parent.plan['context'],'PLAN_AUTHORITY')
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256'))==
        (48936,'01dd5d0180299126',8292,MAIN_SHA),'FIXED_NATIVE')
    q=reader._check_owner(s.parent);scope=_json(s.scope_path,s.scope_sha256)
    need(scope==s.scope and scope.get('kind')=='ROOT_OWNED_VIEW_ENUMERATION_SCOPE' and scope.get('passed') is True
        and _authority(scope) and scope.get('actualSourceSha256')==SOURCE_SHA
        and scope.get('readScopeSha256')==s.parent.review_sha256
        and Path(scope.get('readScopePath','')).resolve()==s.parent.review_path.resolve()
        and scope.get('targets')==q['targets']
        and (scope.get('sessionNonce'),scope.get('pid'),scope.get('birth'),scope.get('guiThreadId'),scope.get('mainSha256'))==
            (ctx['heldNonce'],ctx['processId'],ctx['birth'],8292,MAIN_SHA), 'COMPARE_SCOPE')
    _lease(s)
    if s.phase in ('PREPARED','STAGED'):need(not _claim_path(s).exists(),'ALREADY_CLAIMED')
    else:need(_json(_claim_path(s))==_claim(s),'OWN_CLAIM')
    return q


def _carrier_view(plan):
    # Only old carrier ABI validation receives a readonly view; authority is
    # truthful in the sealed plan, host script, intent and actual root grant.
    p=dict(plan);p.update(writerAuthorized=False,applicationWrites=0);return p


def _render(s):
    _check(s);p=s.plan;out=Path(p['outputDirectory'])
    files=c.render(_carrier_view(p),c.read(HERE/c._probe_spec(reader.PROBE)[0],32768));source=_source().decode()
    values={'__OWNED_VIEW_ENUM_SCOPE_ADMITTED__':'true','__OPERATION_ID__':p['operationId'],
        '__SCOPE_SHA256__':s.scope_sha256,'__PROOF_PATH__':(out/NATIVE_FILE).as_posix(),
        '__NATIVE_ENUM_INTENT_PATH__':(out/INTENT_FILE).as_posix()}
    for token,value in values.items():need(source.count(token)==1,'ONE_TOKEN');source=source.replace(token,value,1)
    header=files['sdk_probe_params.h'].decode();line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
    files['sdk_probe_params.h']=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(source,ensure_ascii=False)).encode()
    ps=files['run-fixed.ps1'].decode('utf-8-sig');need(ps.count('version=233;')==2,'HOST_AUTHORITY_ANCHOR')
    authority="version=233;writerAuthorized=$true;"+''.join(
        key+'=$true;' for key in TRUE_AUTH)+''.join(key+'=$false;' for key in FALSE_AUTH)
    authority+="maximumEnumerations=1;maximumOwnedSlots=128;retainedReferenceOperationId='"+RETIRED_OPERATION+"';"
    authority+="ownedViewEnumerationProfile='"+PROFILE+"';actualSourceSha256='"+SOURCE_SHA+"';"
    ps=ps.replace('version=233;',authority)
    files['run-fixed.ps1']=ps.encode('utf-8-sig');return files


def prepare_root(scope_path,scope_sha256):
    """Prepare one new owned enumeration; no old reference release is granted."""
    _pins();path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=_json(path,scope_sha256)
    need(scope.get('kind')=='ROOT_OWNED_VIEW_ENUMERATION_SCOPE' and scope.get('passed') is True
        and _authority(scope) and scope.get('actualSourceSha256')==SOURCE_SHA,'COMPARE_SCOPE_BEFORE_OWNER')
    parent=_prepare_parent(scope['readScopePath'],scope['readScopeSha256']);p=dict(parent.plan);op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):p.pop(key)
    p.update(operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),ownedViewEnumerationProfile=PROFILE,
        actualSourceSha256=SOURCE_SHA,ownedViewEnumerationControllerSha256=c.digest(c.read(Path(__file__))),enumScopeSha256=scope_sha256,
        readScopeSha256=parent.review_sha256,maximumEnumerations=1,maximumOwnedSlots=128,retainedReferenceOperationId=RETIRED_OPERATION,
        writerAuthorized=True,captureAuthorized=False,applicationWrites=0,
        **{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})
    p['goldLeaseOwner'],p['goldLeaseBootstrapSha256']=owner_base._lease_binding(p['context'])
    s=Enumeration(_ISSUER,parent,scope,path,scope_sha256,p,c.canonical(p),{});_check(s)
    ns=parent.private;ns['__pending_read_operation']=op
    def fresh(plan):_check(s);need(plan==s.plan,'FRESH_PLAN');c._fresh(_carrier_view(plan))
    def render(plan,raw):need(plan==s.plan,'RENDER_PLAN');return _render(s)
    ns.update(_fresh=fresh,render=render);s.private=ns;ns['_no_pending'](context=p['context']);return s


def stage_root(s):
    """Build fixed tools only; no comparison or Gold operation."""
    _check(s);need(s.phase=='PREPARED','STAGE_PHASE')
    proof=s.private['stage_private'](s.plan,dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',rootAuthorized=True,planSha256=c.digest(s.plan_raw)))
    s.phase='STAGED';return proof


def _native_terminal(s,native,reserved):
    """Native UNKNOWN never becomes terminal just because SDK returned zero."""
    p=s.plan
    need(type(native) is dict and native.get('kind')=='OWNED_VIEW_ENUMERATION'
        and native.get('operationId')==p['operationId'] and native.get('scopeSha256')==s.scope_sha256
        and native.get('readOnly') is False and native.get('configurationReadOnly') is True
        and native.get('runtimeCacheMutationPossible') is True and native.get('retryAuthorized') is False
        and native.get('retentionRequired') is True and native.get('newOwnedSlotsOnly') is True
        and native.get('historicalReferenceCleanupAuthorized') is False and native.get('historicalReferencesRetained') is True
        and type(native.get('maximumEnumerations')) is int and native['maximumEnumerations']==1
        and all(native.get(k) is False for k in ('comparisonCompletionVerified','fullUuidPropertyDeltaVerified','onlyOwnPendingVerified'))
        and all(type(native.get(k)) is int and native[k]==0 for k in ZERO_NATIVE),'NATIVE_JOIN')
    attempts=native.get('enumerationAttempts');need(type(attempts) is int and attempts in (0,1),'NATIVE_ATTEMPTS')
    if native.get('status')=='REFUSED_BEFORE_ENUM':
        need(attempts==0 and native.get('enumCallReturned') is False
            and all(type(native.get(k)) is int and native[k]==0 for k in
                ('newOwnedSlots','nonNullSlots','validatedSlots','matchedKnownView','adoptionAttempts','releasedSlots','clearedSlots')),
             'NATIVE_ZERO_REFUSAL')
        return 'REFUSED_BEFORE_ENUM'
    need(native.get('status')=='OWNED_ENUM_DRAINED_CLEAN' and attempts==1
        and all(native.get(k) is True for k in ('nativeIntentWritten','enumCallReturned','drainReturned','counterRestored','rootCleanBefore','rootCleanAfter'))
        and native.get('unknownRetained') is False and native.get('reason')=='NONE'
        and all(type(native.get(k)) is int and native[k]==3 for k in ('targetsCleanBefore','targetsCleanAfter')),
        'NATIVE_DRAIN_CLOSURE')
    counters=('newOwnedSlots','nonNullSlots','validatedSlots','matchedKnownView','adoptionAttempts','releasedSlots','clearedSlots',
              'referenceCountBefore','referenceCountDuringEnumeration','referenceCountAfter')
    need(all(type(native.get(k)) is int for k in counters),'NATIVE_COUNTER_TYPES')
    slots=native['newOwnedSlots'];nonzero=native['nonNullSlots']
    need(1<=nonzero<=slots<=128 and native['validatedSlots']==slots and native['clearedSlots']==slots
        and native['releasedSlots']==nonzero and native['adoptionAttempts']==nonzero
        and native['matchedKnownView']==1 and native['referenceCountBefore']==10
        and native['referenceCountDuringEnumeration']==11 and native['referenceCountAfter']==10,'NATIVE_COUNTER_BALANCE')
    need(type(reserved) is dict and reserved.get('kind')=='OWNED_VIEW_ENUMERATION_RESERVED'
        and reserved.get('operationId')==p['operationId'] and reserved.get('scopeSha256')==s.scope_sha256
        and reserved.get('newOwnedSlotsOnly') is True and reserved.get('historicalReferenceCleanupAuthorized') is False
        and reserved.get('readOnly') is False and reserved.get('configurationReadOnly') is True
        and reserved.get('runtimeCacheMutationPossible') is True
        and type(reserved.get('maximumEnumerations')) is int and reserved['maximumEnumerations']==1
        and type(reserved.get('referenceCountBefore')) is int and reserved['referenceCountBefore']==10
        and all(type(reserved.get(k)) is int and reserved[k]==0 for k in
            ('sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')),'NATIVE_INTENT')
    return 'OWNED_ENUM_DRAINED_CLEAN'


def _authority_result(s):
    return dict(ownedViewEnumerationProfile=PROFILE,actualSourceSha256=SOURCE_SHA,
        ownedViewEnumerationControllerSha256=s.plan['ownedViewEnumerationControllerSha256'],
        scopeSha256=s.scope_sha256,readScopeSha256=s.parent.review_sha256,writerAuthorized=True,
        maximumEnumerations=1,maximumOwnedSlots=128,retainedReferenceOperationId=RETIRED_OPERATION,
        comparisonCompletionVerified=False,fullUuidPropertyDeltaVerified=False,onlyOwnPendingVerified=False,
        **{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


def _unknown(s,reason):
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=s.plan['operationId'],
        reason=reason,retryAuthorized=False,parentWriterOperationId=s.parent.scope['writerOperationId'],**_authority_result(s))
    c.write_new(Path(s.plan['outputDirectory'])/'unknown.json',result);return result


def run_root_once(s,review_path,review_sha256):
    """Reserve once before host dispatch; native UNKNOWN never gets result.json."""
    _check(s);need(s.phase=='STAGED','RUN_PHASE');p=s.plan;ctx=p['context'];out=Path(p['outputDirectory']);ns=s.private
    build=ns['require_stage'](p);review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind')=='ROOT_OWNED_VIEW_ENUMERATION_RUN' and review.get('passed') is True
        and _authority(review) and review.get('planSha256')==c.digest(s.plan_raw)
        and review.get('buildSha256')==c.digest(c.canonical(build)) and review.get('scopeSha256')==s.scope_sha256
        and review.get('readScopeSha256')==s.parent.review_sha256
        and review.get('actualSourceSha256')==SOURCE_SHA,'ROOT_RUN')
    ns['_no_pending'](context=ctx)
    need(not any((out/n).exists() for n in ('intent.json','host-identity.json','host-result.json','result.json','unknown.json','sdk-receipt.json',NATIVE_FILE,INTENT_FILE)), 'ONE_ATTEMPT')
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
                    need(s.host.returncode==0 and sdk.get('threadId')==ctx['guiThreadId']
                        and type(sdk.get('sdkResult')) is int and sdk['sdkResult']==0,'SDK_TERMINAL')
                    ns['_fresh'](p)
                    native=_json(out/NATIVE_FILE,bound=8192)
                    reserved=_json(out/INTENT_FILE,bound=4096) if (out/INTENT_FILE).is_file() else None
                    status=_native_terminal(s,native,reserved)
                except (OSError,ValueError):return _unknown(s,'NATIVE_OR_FRESH_CLOSURE_UNPROVEN')
                result=dict(version=233,status=status,knownTerminal=True,operationId=p['operationId'],planSha256=c.digest(s.plan_raw),
                    sdkResult=0,hookWorkersReleased=True,targetIdentityVerified=True,nativeInjectionPerformed=True,
                    nativeProofSha256=c.digest(c.read(out/NATIVE_FILE)),parentWriterOperationId=claim['writerOperationId'],
                    retryAuthorized=False,releasePacketAllowed=False,releaseRefsAllowed=False,**_authority_result(s))
                c.write_new(out/'result.json',result);s.phase='KNOWN_TERMINAL_RETAIN_PARENT';return result
            break
        if s.host.poll() is not None:break
        time.sleep(.05)
    return _unknown(s,'HOST_OR_SDK_TERMINAL_UNPROVEN')
