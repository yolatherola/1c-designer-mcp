"""One exact three-resource native Update29 with cancel-only UI observation."""
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
import json
import inspect
from types import FunctionType
import post_update_readback_source as source_recipe
import modal_read_child_failure_audit as closed_failure
import owned_headless_comparison_utf8 as headless_check
import re
import subprocess
import time
import uuid
import sys
# The existing lease reader lives in tests; standalone workers do not inherit
# unittest's import path. This imports the checker without invoking tests.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
import synthetic_events_compat_guard as maintenance
import comparison_cpp_exception_type_epoch as epoch
import post_update_comparison_carrier as carrier
import update_first_context_completion_audit as closed_update
import update_preview_refusal_audit as closed_preview_failure
import sdk_compiler_section_identity as section_identity
import comparison_cpp_exception_stack_trace as previous

c=previous.c
reader=previous.reader
base=previous.repeatable.base
ROOT=c.ROOT
HERE=c.HERE
PARENT_SHA='c4e792ca4ae464c4a4b12f72cba8ba98522febb66bd6101732322f836aa913be'
SOURCE_NAME='NativePostUpdateReadback.as'
SOURCE_SHA='e6f03906977204916982c0c4257e4b8e93e8bde71414a9e0c6041dc6e2ff5e3a'
MAIN_SHA=previous.MAIN_SHA
CHECK_NAME='post-update-readback-cold-check-b7410fcd19d446b9ac39a8c5e2ea3713.json'
CHECK_SHA='15d1eb42b6c946a0996d6142bbf9a98340beb03b4db2a0bfaec5f0704ccd474b'
PROFILE='READ_ONLY_POST_UPDATE_DATABASE_READBACK'
NATIVE_FILE='post-update-readback-as-proof.json'
BRIDGE_FILE='owned-headless-comparison-core-proof.json'
FAST_FILE='database-saved-resources-proof.json'
INTENT_FILE='native-headless-intent.json'
EPOCH_FILE='cpp-exception-type-epoch.json'
EXPECTED_DATABASE_SOURCE=1383504556
TRUE_AUTH=('configurationReadOnly','runtimeCacheMutationPossible','runtimeUiMutationPossible',
 'retainedReferenceMaintenanceAuthorized','exceptionTypeMetadataReadAuthorized','runtimeComparisonCreationAuthorized',
 'comparisonFactoryAuthorized','comparisonExecuteAuthorized','scopedReferenceCallsAuthorized','manualAddRefReleaseAuthorized',
 'namedBridgeAuthorized','runtimeDatabaseResourcesReadAuthorized')
FALSE_AUTH=('readOnly','runtimeSyntheticEventsAuthorized','idleQueueInvocationAuthorized','runtimeDialogHooksAuthorized',
 'runtimeFrameBindingAuthorized','runtimeSupportInitializationAuthorized','externalAddinLoadingAuthorized','sourceWritesAuthorized',
 'configurationSavesAuthorized','databaseUpdatesAuthorized','repositoryMutationsAuthorized','releaseResourcesAuthorized',
 'configurationExportsAuthorized','configurationImportsAuthorized','stockCompareAuthorized','newEnumerationAuthorized',
 'ownedVectorDrainAuthorized','historicalReferencesReleaseAuthorized','exceptionObjectReadAuthorized','typeRawOutput',
 'commandDispatchAuthorized','positiveDialogAnswersAuthorized','resultPropertyWritesAuthorized')
ZERO_NATIVE=('nativeCommands','sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('UPDATE_PREVIEW_'+code)


def _json(path,pin=None,bound=32768):return reader._json(path,pin,bound)


def _limits():return dict(maximumFactoryCalls=1,maximumExecutions=1,maximumGetMdCont=16,
 maximumExplicitAddRef=4,maximumExplicitRelease=3,maximumProjectionNodes=524288,maximumRows=256,
 maximumNativeCommands=0,maximumEventSubscribers=0,maximumGlobalQueueInvocations=0,maximumTypeEvents=32,maximumEnumerations=0)


def _authority(row):
    return all(row.get(k) is True for k in TRUE_AUTH) and all(row.get(k) is False for k in FALSE_AUTH) \
        and all(type(row.get(k)) is int and row[k]==v for k,v in _limits().items()) and row.get('expectedDatabaseSource')==EXPECTED_DATABASE_SOURCE


def _source():
    raw=source_recipe.compose_source()
    need(c.digest(raw)==SOURCE_SHA,'COMPOSED_SOURCE_PIN')
    need(set(re.findall(r'__[A-Z0-9_]+__',raw.decode()))=={'__HEADLESS_SCOPE_ADMITTED__','__OPERATION_ID__',
        '__SCOPE_SHA256__','__PROOF_PATH__','__FAST_RESOURCES_PROOF_PATH__','__NATIVE_HEADLESS_INTENT_PATH__','__OWN_DLL_PATH__'},'SOURCE_TOKENS')
    return raw


def _pins():
    need(c.digest(c.read(Path(previous.__file__)))==PARENT_SHA,'PARENT_PIN');previous._pins();_source()
    for path,pin in [(Path(epoch.__file__),'e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4'),
        (Path(section_identity.__file__),'6f63f39ddcd8f1e3db9c25ca866e7faa89f6a8bc2be54dfd49dc958952f9754d'),
        (Path(maintenance.__file__),'590002e76a382bbf4ce2a44b90daa5e4907ea6b476dc91dc5af8ef50eb1b5ae9'),
        (Path(closed_failure.__file__),'a9df6cb09e2a37240eecb2bc85d924f4d874dcfba78d87d38916d0ec706f7f48'),
        (Path(source_recipe.__file__),'a79ce6794976566982733b3d4e097d57d01f871ef0b4bf035a6bd0f1000e38fe'),
        (Path(carrier.__file__),'3916a37347dcce7d63d26b4dac343b08ff44d394c93623c8227a248269dac047'),
        (Path(closed_preview_failure.__file__),'cd4540fd54a0fa038835300a11294f9f54526f25c6ea23154fcc2b4979be69b7'),
        (Path(closed_update.__file__),'601e79e0e477add3d55564677833f043676e3c68cdaeed381f4f9d0097dcc005')]:
        need(c.digest(c.read(path))==pin,'BUILDER_PIN')
    proof=_json(ROOT/'artifacts/designer-bridge'/CHECK_NAME,CHECK_SHA)
    need(proof.get('kind')=='POST_UPDATE_READBACK_COLD_CHECK' and proof.get('composedSourceSha256')==SOURCE_SHA
        and proof.get('sourceMainSha256')==MAIN_SHA and proof.get('realCompileFunction') is True
        and proof.get('positiveExit')==0 and proof.get('negativeExit')==103 and proof.get('cSharedLinkExit')==0
        and proof.get('cCodeSha256')==c.digest(carrier.render()) and proof.get('ownTemporaryDirectoriesRemoved') is True
        and all(proof.get(k) is False for k in ('contextCreated','bodyExecuted','sourceScopeAdmitted','goldStarted','dllLoaded')),'REAL_COLD_CHECK')



@dataclass(slots=True)
class ReadOp:
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


def validate_scope(row):
    need(row.get('kind')=='ROOT_POST_UPDATE_READBACK_SCOPE' and row.get('passed') is True
        and row.get('profile')==PROFILE and row.get('actualSourceSha256')==SOURCE_SHA and _authority(row),'SCOPE')


def prepare_parent(path,pin):
    scope=_json(path,pin);validate_scope(scope)
    function=maintenance.private_prepare();function.__globals__['validate_scope']=validate_scope
    original_reader=function.__globals__['reader'];original_inspect=function.__globals__['inspect']
    def audit(prior):
        result=closed_failure.audit_closed(prior)
        base._lease(SimpleNamespace(plan=prior));c._fresh(base._carrier_view(prior));return result
    def audit_preview_refusal(prior):
        result=closed_preview_failure.audit_closed(prior)
        base._lease(SimpleNamespace(plan=prior));c._fresh(base._carrier_view(prior));return result
    def audit_update(prior):
        result=closed_update.audit_closed(prior)
        base._lease(SimpleNamespace(plan=prior));c._fresh(base._carrier_view(prior));return result
    def namespace(parent):
        ns=original_reader._namespace(parent)
        ns.update(__update_preview_failed_operation=closed_failure.OP,__update_preview_failed_audit=audit)
        ns.update(__update_preview_refused_operation=closed_preview_failure.OP,__update_preview_refused_audit=audit_preview_refusal)
        ns.update(__post_update_closed_operation=closed_update.OP,__post_update_closed_audit=audit_update)
        return ns
    def getsource(target):
        text=original_inspect.getsource(target)
        if target is c._no_pending:
            anchor='        if prior_identity!=identity: continue\n'
            need(text.count(anchor)==1,'CLOSED_AUDIT_ANCHOR')
            text=text.replace(anchor,anchor+'        if operation==__update_preview_failed_operation:\n            __update_preview_failed_audit(prior);continue\n'
                +'        if operation==__update_preview_refused_operation:\n            __update_preview_refused_audit(prior);continue\n'
                +'        if operation==__post_update_closed_operation:\n            __post_update_closed_audit(prior);continue\n',1)
        return text
    proxy_reader=SimpleNamespace(**dict(original_reader.__dict__));proxy_reader._namespace=namespace
    proxy_inspect=SimpleNamespace(**dict(original_inspect.__dict__));proxy_inspect.getsource=getsource
    globals_=dict(function.__globals__,reader=proxy_reader,inspect=proxy_inspect)
    local=FunctionType(function.__code__,globals_,function.__name__,function.__defaults__,function.__closure__)
    return local(path,pin)


def _claim_path(s):return ROOT/'artifacts/designer-bridge'/('post-update-readback-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='UPDATE_PREVIEW_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
        actualSourceSha256=SOURCE_SHA,controllerSha256=s.plan['updatePreviewControllerSha256'],
        writerOperationId=q['operationId'],writerIntentSha256=c.digest(c.canonical(q)),packetSha256=q['packetSha256'],
        sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'],ownedUpdatePreviewOnly=True)


def _check(s):
    need(type(s) is ReadOp and s._issuer is _ISSUER,'ISSUED_READ');_pins();p=s.plan;ctx=p['context']
    need(c.canonical(p)==s.plan_raw and p.get('updatePreviewControllerSha256')==c.digest(c.read(Path(__file__)))
        and p.get('updatePreviewProfile')==PROFILE and _authority(p) and p.get('actualSourceSha256')==SOURCE_SHA
        and p.get('writerAuthorized') is False and p.get('captureAuthorized') is False
        and type(p.get('applicationWrites')) is int and p['applicationWrites']==0
        and p.get('updatePreviewScopeSha256')==s.scope_sha256 and p.get('readScopeSha256')==s.parent.review_sha256
        and ctx==s.parent.plan['context'],'PLAN_AUTHORITY')
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256'))==
        (48936,'01dd5d0180299126',8292,MAIN_SHA),'FIXED_NATIVE')
    q=reader._check_owner(s.parent);scope=_json(s.scope_path,s.scope_sha256)
    need(scope==s.scope and scope.get('kind')=='ROOT_POST_UPDATE_READBACK_SCOPE' and scope.get('passed') is True
        and _authority(scope) and scope.get('actualSourceSha256')==SOURCE_SHA and scope.get('targets')==q['targets']
        and scope.get('readScopeSha256')==s.parent.review_sha256
        and Path(scope.get('readScopePath','')).resolve()==s.parent.review_path.resolve()
        and (scope.get('sessionNonce'),scope.get('pid'),scope.get('birth'),scope.get('guiThreadId'),scope.get('mainSha256'))==
            (ctx['heldNonce'],ctx['processId'],ctx['birth'],8292,MAIN_SHA),'READ_SCOPE')
    base._lease(SimpleNamespace(plan=p))
    if s.phase in ('PREPARED','STAGED'):need(not _claim_path(s).exists(),'ALREADY_CLAIMED')
    else:need(_json(_claim_path(s))==_claim(s),'OWN_CLAIM')
    return q


def _render(s):
    _check(s);p=s.plan;out=Path(p['outputDirectory'])
    files=c.render(base._carrier_view(p),c.read(HERE/c._probe_spec(reader.PROBE)[0],32768));source=_source().decode()
    values={'__HEADLESS_SCOPE_ADMITTED__':'true','__OPERATION_ID__':p['operationId'],
        '__SCOPE_SHA256__':s.scope_sha256,'__PROOF_PATH__':(out/NATIVE_FILE).as_posix(),
        '__FAST_RESOURCES_PROOF_PATH__':(out/FAST_FILE).as_posix(),
        '__NATIVE_HEADLESS_INTENT_PATH__':(out/INTENT_FILE).as_posix(),'__OWN_DLL_PATH__':(out/'Continuation.dll').as_posix()}
    for token,value in values.items():need(source.count(token)>=1,'SOURCE_TOKEN');source=source.replace(token,value)
    header=files['sdk_probe_params.h'].decode();line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
    header=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(source,ensure_ascii=False))
    header+='\n#define AH_HPC_SCOPE_ADMITTED 1\n#define AH_POST_DATABASE_SOURCE '+str(EXPECTED_DATABASE_SOURCE)+'UL\n'
    for key,value in {'AH_CPP_EPOCH_OPERATION_ID':p['operationId'],'AH_CPP_EPOCH_SCOPE_SHA256':s.scope_sha256,
        'AH_HPC_OPERATION_ID':p['operationId'],'AH_HPC_SCOPE_SHA256':s.scope_sha256}.items():header+='\n#define '+key+' '+json.dumps(value)+'\n'
    for key,name in {'AH_CPP_EPOCH_RECEIPT_FILE':EPOCH_FILE,'AH_HPC_PROOF_FILE':headless_check.CORE_FILE,'AH_UPX_PROOF_FILE':BRIDGE_FILE}.items():
        header+='#define '+key+' L'+json.dumps((out/name).as_posix())+'\n'
    files['sdk_probe_params.h']=header.encode();code=carrier.render()
    need(code.count(b'sdkGuiThread!=AH_SDK_EXPECTED_GUI_THREAD')==2 and code.count(b'if(thread!=AH_SDK_EXPECTED_GUI_THREAD)valid=FALSE;')==1,'GUI_GUARDS')
    files['Continuation.c']=code
    ps=files['run-fixed.ps1'].decode('utf-8-sig');need(ps.count('version=233;')==2,'HOST_AUTHORITY_ANCHOR')
    auth='version=233;writerAuthorized=$false;'+''.join(k+'=$true;' for k in TRUE_AUTH)+''.join(k+'=$false;' for k in FALSE_AUTH)
    for key,value in _limits().items():auth+=key+'='+str(value)+';'
    auth+="updatePreviewProfile='"+PROFILE+"';actualSourceSha256='"+SOURCE_SHA+"';"
    files['run-fixed.ps1']=ps.replace('version=233;',auth).encode('utf-8-sig')
    files,identity=section_identity.with_section_identity(files,operation_kind='UPDATE_PREVIEW',operation_id=p['operationId']);return files


def _authority_result(s,terminal=False):
    return dict(updatePreviewProfile=PROFILE,updatePreviewControllerSha256=s.plan['updatePreviewControllerSha256'],
        actualSourceSha256=SOURCE_SHA,scopeSha256=s.scope_sha256,readScopeSha256=s.parent.review_sha256,
        writerAuthorized=False,comparisonOnly=True,databaseApplyAuthorized=False,databaseApplyVerified=terminal,
        databaseConfigurationVerified=terminal,syntheticPrintVerified=False,priorUpdateOperationId=closed_update.OP,
        expectedDatabaseSource=EXPECTED_DATABASE_SOURCE,**_limits(),**{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


def prepare_root(scope_path,scope_sha256):
    _pins();path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=_json(path,scope_sha256)
    need(scope.get('kind')=='ROOT_POST_UPDATE_READBACK_SCOPE' and scope.get('passed') is True and _authority(scope)
        and scope.get('actualSourceSha256')==SOURCE_SHA,'READ_SCOPE_BEFORE_OWNER')
    parent=prepare_parent(path,scope_sha256);p=dict(parent.plan);op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):p.pop(key)
    p.update(operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),updatePreviewProfile=PROFILE,
        updatePreviewControllerSha256=c.digest(c.read(Path(__file__))),actualSourceSha256=SOURCE_SHA,
        updatePreviewScopeSha256=scope_sha256,readScopeSha256=parent.review_sha256,
        writerAuthorized=False,captureAuthorized=False,applicationWrites=0,expectedDatabaseSource=EXPECTED_DATABASE_SOURCE,**_limits(),
        **{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})
    p['goldLeaseOwner'],p['goldLeaseBootstrapSha256']=base.owner_base._lease_binding(p['context'])
    s=ReadOp(_ISSUER,parent,scope,path,scope_sha256,p,c.canonical(p),{});_check(s)
    ns=parent.private;ns['__pending_read_operation']=op
    def fresh(plan):_check(s);need(plan==s.plan,'FRESH_PLAN');c._fresh(base._carrier_view(plan))
    def render(plan,raw):need(plan==s.plan,'RENDER_PLAN');return _render(s)
    ns.update(_fresh=fresh,render=render);s.private=ns;ns['_no_pending'](context=p['context']);return s


def stage_root(s):
    _check(s);need(s.phase=='PREPARED','STAGE_PHASE')
    proof=s.private['stage_private'](s.plan,dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',rootAuthorized=True,planSha256=c.digest(s.plan_raw)))
    s.phase='STAGED';return proof


def _counts(row,expected,code):
    need(all(type(row.get(k)) is int and row[k]==v for k,v in expected.items()),code)


def _joined(s,row,kind):
    need(type(row) is dict and row.get('kind')==kind and row.get('operationId')==s.plan['operationId']
        and row.get('scopeSha256')==s.scope_sha256,'NATIVE_JOIN')


def _native_terminal(s,native,reserved):
    _joined(s,native,'OWNED_HEADLESS_COMPARISON_AS_NATIVE');_joined(s,reserved,'OWNED_HEADLESS_COMPARISON_INTENT')
    need(native.get('reason')=='NONE' and native.get('typedHandlesCleared') is True and native.get('unknownRetain') is False
        and native.get('nativeIntentWritten') is True and native.get('beforeRootAndTargetsClean') is True
        and native.get('afterRootAndTargetsClean') is True and reserved.get('configurationReadOnly') is True,'AS_CLOSURE')
    _counts(native,dict(bridgeAttempts=1,bridgeReturned=1,beforeTargetsClean=3,afterTargetsClean=3,**{k:0 for k in ZERO_NATIVE}),'AS_COUNTS')
    out=Path(s.plan['outputDirectory']);fast=_json(out/FAST_FILE,bound=8192)
    _joined(s,fast,'DATABASE_SAVED_RESOURCES_FAST_GATE')
    need(fast.get('status')=='DATABASE_RESOURCE_FAST_CANDIDATES_VERIFIED' and fast.get('reason')=='NONE'
        and fast.get('pendingFileReference') is False and fast.get('moduleHelperTextReads')==0,'FAST_RESOURCES')
    expected=[('8daef957-4ae2-48a1-bf6c-b88163a076f5','3f413e18fe4e6f6bb8eeec10e8e2b7f54e1b0449f441779f8f861be1ab6d6ea7',''),
        ('176e2552-fd8b-4823-afc0-d17431f2fb7b','00ab097f6828f9bd79bc7c3a298196b512944a621af0f2a225f3b7d65ef827bd','90939ff38be12b52740f27153455e711b145086ee1aacb6e906eb897556f381a'),
        ('28ecdfc7-083e-4082-b272-efbf7152de5c','04e9fe8645eaab179bfd2cc0a2209c21854f1c7ac6a07e8ace68faa9b9dfa54d','f64720f5118b2eaba03197f3de83a3ee93a68738e7177751fcd92cbb618e224a')]
    targets=fast.get('targets');need(type(targets) is list and len(targets)==3,'FAST_TARGETS')
    for row,(object_id,plain,lf) in zip(targets,expected):
        need(row.get('objectId')==object_id and row.get('plainSha256')==plain and row.get('textLfNoBomSha256')==lf,'CANDIDATE_HASHES')
    _counts(fast,dict(resourcesRead=3,moduleDecodedPasses=4,coldLoads=0,coldSnapshots=0,templatePropertyComparisons=0,sourceWrites=0,metadataWrites=0,configurationSaves=0,databaseUpdates=0,repositoryMutations=0),'FAST_COUNTS')
    need(fast.get('configurationSourceDomain')=='DATABASE' and fast.get('databaseManagerAddress')==100051712
        and fast.get('databaseSourceAddress')==EXPECTED_DATABASE_SOURCE,'DB_PROVENANCE')
    core=_json(out/BRIDGE_FILE,bound=65536);_joined(s,core,'OWNED_HEADLESS_COMPARISON_CORE_NATIVE')
    _counts(core,dict(phase=8,reason=0,attempts=1,repeatedAttempts=0,getterAttempts=2,getterReturned=2,addrefAttempts=4,releaseAttempts=3,
        factoryAttempts=1,factoryReturned=1,executeAttempts=1,executeReturned=1,projectionAttempts=1,sourceTransferConsumed=2,sourceTransferInFlight=0,
        ownedReferencesRemaining=0,mainSource=344510268,databaseSource=EXPECTED_DATABASE_SOURCE,postDatabaseSourceExpected=EXPECTED_DATABASE_SOURCE,
        otherManagerChecks=5,completion=1,viewPointer=0,abiFault=0,treeError=0,treePasses=2,treeCoherent=1,treeTraversalComplete=1,
        objectMask20Count=0,rowCount=0,sourceWrites=0,configurationSaves=0,databaseUpdates=0,repositoryMutations=0,applicationTextOutputBytes=0),'CORE_COUNTS')
    need(core.get('codeVerified') is True and core.get('additionalManagersEmpty') is True and core.get('rows')==[]
        and all(type(core.get(k)) is int for k in ('selected','visited','objectFlagsObserved'))
        and 0<core['selected']==core['visited']==core['objectFlagsObserved']<=65536
        and type(core.get('treeNodes')) is int and 0<core['treeNodes']<=524288,'FULL_ZERO_DIFF')
    exc=_json(out/EPOCH_FILE,bound=32768)
    epoch.classify_type_epoch(exc,operation_id=s.plan['operationId'],scope_sha256=s.scope_sha256,process_id=48936,
        execute_thread_id=8292,callback_known=True,callback_sdk_rc=0,target_identity_verified=True)
    return 'POST_UPDATE_DATABASE_RESOURCES_AND_ZERO_DIFF_VERIFIED'


def _unknown(s,reason):
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=s.plan['operationId'],reason=reason,
        retryAuthorized=False,parentWriterOperationId=s.parent.scope['writerOperationId'],**_authority_result(s))
    c.write_new(Path(s.plan['outputDirectory'])/'unknown.json',result);return result


def run_root_once(s,review_path,review_sha256):
    _check(s);need(s.phase=='STAGED','RUN_PHASE');p=s.plan;ctx=p['context'];out=Path(p['outputDirectory']);ns=s.private
    build=ns['require_stage'](p);review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind')=='ROOT_POST_UPDATE_READBACK_RUN' and review.get('passed') is True and _authority(review)
        and review.get('planSha256')==c.digest(s.plan_raw) and review.get('buildSha256')==c.digest(c.canonical(build))
        and review.get('scopeSha256')==s.scope_sha256 and review.get('readScopeSha256')==s.parent.review_sha256
        and review.get('actualSourceSha256')==SOURCE_SHA,'ROOT_RUN')
    ns['_no_pending'](context=ctx)
    need(not any((out/n).exists() for n in ('intent.json','host-identity.json','host-result.json','result.json','unknown.json',
        'sdk-receipt.json',NATIVE_FILE,BRIDGE_FILE,FAST_FILE,INTENT_FILE,EPOCH_FILE)),'ONE_ATTEMPT')
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
                    native=_json(out/NATIVE_FILE,bound=8192)
                    reserved=_json(out/INTENT_FILE,bound=4096) if (out/INTENT_FILE).is_file() else None
                    status=_native_terminal(s,native,reserved)
                except (OSError,ValueError):return _unknown(s,'NATIVE_OR_FRESH_CLOSURE_UNPROVEN')
                result=dict(version=233,status=status,knownTerminal=True,operationId=p['operationId'],
                    planSha256=c.digest(s.plan_raw),sdkResult=0,hookWorkersReleased=True,targetIdentityVerified=True,
                    nativeInjectionPerformed=True,nativeProofSha256=c.digest(c.read(out/NATIVE_FILE)),
                    parentWriterOperationId=claim['writerOperationId'],retryAuthorized=False,
                    releasePacketAllowed=False,releaseRefsAllowed=False,**_authority_result(s,terminal=True))
                c.write_new(out/'result.json',result);s.phase='KNOWN_TERMINAL_RETAIN_PARENT';return result
            break
        if s.host.poll() is not None:break
        time.sleep(.05)
    return _unknown(s,'HOST_OR_SDK_TERMINAL_UNPROVEN')
