"""Read applied DB startup-property shapes and CM flags without sessions or text."""
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
import json
import inspect
from types import FunctionType
import post_update_comparison_operation as verified_post
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
SOURCE_NAME='NativeDatabaseStartupMetadata.as'
SOURCE_SHA='b7984b00758495f1ba0ef5c0cc9e42d64eb5f67b885793e94ad468376fdcad3b'
MAIN_SHA=previous.MAIN_SHA
CHECK_NAME='database-startup-metadata-cold-check-5379046ee32548669497653d2a68bcc7.json'
CHECK_SHA='9d50c2c8c72072f6aa900daa66f605f47b1a3105c584990d51a0b396a12fb40e'
PROFILE='DATABASE_STARTUP_METADATA_ONLY'
NATIVE_FILE='database-startup-metadata-proof.json'
INTENT_FILE='database-startup-metadata-intent.json'
EPOCH_FILE='cpp-exception-type-epoch.json'
EXPECTED_DATABASE_SOURCE=1383504556
CARRIER_SHA='5add1c2675071ca943b49fe0c5595a906eb4b84a81b72e66a89052365cca04e0'
TRUE_AUTH=('configurationReadOnly','runtimeCacheMutationPossible','runtimeUiMutationPossible',
 'retainedReferenceMaintenanceAuthorized','exceptionTypeMetadataReadAuthorized','scopedReferenceCallsAuthorized',
 'runtimeMetadataReadAuthorized')
FALSE_AUTH=('readOnly','runtimeSyntheticEventsAuthorized','idleQueueInvocationAuthorized','runtimeDialogHooksAuthorized',
 'runtimeFrameBindingAuthorized','runtimeSupportInitializationAuthorized','externalAddinLoadingAuthorized','sourceWritesAuthorized',
 'configurationSavesAuthorized','databaseUpdatesAuthorized','repositoryMutationsAuthorized','releaseResourcesAuthorized',
 'configurationExportsAuthorized','configurationImportsAuthorized','stockCompareAuthorized','newEnumerationAuthorized',
 'ownedVectorDrainAuthorized','historicalReferencesReleaseAuthorized','exceptionObjectReadAuthorized','typeRawOutput',
 'commandDispatchAuthorized','positiveDialogAnswersAuthorized','resultPropertyWritesAuthorized','manualAddRefReleaseAuthorized',
 'runtimeComparisonCreationAuthorized','comparisonFactoryAuthorized','comparisonExecuteAuthorized','namedBridgeAuthorized',
 'businessCallsAuthorized','applicationDataReadAuthorized','newSessionsAuthorized','detachedValuesAuthorized',
 'syntheticPdfWriteAuthorized','runtimeDatabaseResourcesReadAuthorized','sourceBodyReadsAuthorized')
ZERO_NATIVE=('nativeCommands','sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('STARTUP_METADATA_'+code)


def _json(path,pin=None,bound=32768):return reader._json(path,pin,bound)


def _limits():return dict(maximumNativeCommands=0,maximumEventSubscribers=0,maximumGlobalQueueInvocations=0,
 maximumTypeEvents=32,maximumEnumerations=0,maximumStartupPropertyReads=4,maximumFlagPropertyReads=24,maximumUrlGetterCalls=4)


def _authority(row):
    return all(row.get(k) is True for k in TRUE_AUTH) and all(row.get(k) is False for k in FALSE_AUTH) \
        and all(type(row.get(k)) is int and row[k]==v for k,v in _limits().items()) and row.get('expectedDatabaseSource')==EXPECTED_DATABASE_SOURCE


def _source():
    raw=c.read(HERE/SOURCE_NAME)
    need(c.digest(raw)==SOURCE_SHA,'SOURCE_PIN')
    need(set(re.findall(r'__[A-Z0-9_]+__',raw.decode()))=={'__STARTUP_METADATA_SCOPE_ADMITTED__','__OPERATION_ID__',
        '__SCOPE_SHA256__','__PROOF_PATH__','__NATIVE_STARTUP_METADATA_INTENT_PATH__'},'SOURCE_TOKENS')
    return raw


def _pins():
    need(c.digest(c.read(Path(verified_post.__file__)))=='b239fc61826dd46f6dd51ffd43046065954c18fc78a97710533c4750a540d5a6','PARENT_PIN')
    verified_post._pins();_source()
    out=ROOT/'build/designer-hot-v233-7d40505fa0eb4ffab7b6a34467a05446'
    result=_json(out/'result.json','05c2997c990f6f0356bc59fe55ee4c8e5394a090d31cda54693f932acc0a9b63')
    need(result.get('knownTerminal') is True and result.get('databaseApplyVerified') is True,'APPLIED_DATABASE')
    plan=_json(out/'plan.json');prior=SimpleNamespace(plan=plan,scope_sha256='5ac0b501356c7d4ea5cbe862b98055bdc9995a22075ad4b096854e8078fe8f72')
    need(verified_post._native_terminal(prior,_json(out/verified_post.NATIVE_FILE),_json(out/verified_post.INTENT_FILE))==
        'POST_UPDATE_DATABASE_RESOURCES_AND_ZERO_DIFF_VERIFIED','PRIOR_READBACK')
    proof=_json(ROOT/'artifacts/designer-bridge'/CHECK_NAME,CHECK_SHA)
    need(proof.get('kind')=='DATABASE_STARTUP_METADATA_COLD_CHECK' and proof.get('sourceSha256')==SOURCE_SHA
        and proof.get('sourceMainSha256')==MAIN_SHA and proof.get('realCompileFunction') is True
        and proof.get('positiveExit')==0 and proof.get('negativeExit')==103 and proof.get('cSharedLinkExit')==0
        and proof.get('ownTemporaryDirectoriesRemoved') is True and proof.get('rawCarrierSha256')==CARRIER_SHA
        and proof.get('wholeUtf8SourceInFixturePeExactlyOnce') is True
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
    need(row.get('kind')=='ROOT_DATABASE_STARTUP_METADATA_SCOPE' and row.get('passed') is True
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


def _claim_path(s):return ROOT/'artifacts/designer-bridge'/('database-startup-metadata-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='DATABASE_STARTUP_METADATA_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
        actualSourceSha256=SOURCE_SHA,controllerSha256=s.plan['updatePreviewControllerSha256'],
        writerOperationId=q['operationId'],writerIntentSha256=c.digest(c.canonical(q)),packetSha256=q['packetSha256'],
        sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'],startupMetadataOnly=True)


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
    need(scope==s.scope and scope.get('kind')=='ROOT_DATABASE_STARTUP_METADATA_SCOPE' and scope.get('passed') is True
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
    values={'__STARTUP_METADATA_SCOPE_ADMITTED__':'true','__OPERATION_ID__':p['operationId'],
        '__SCOPE_SHA256__':s.scope_sha256,'__PROOF_PATH__':(out/NATIVE_FILE).as_posix(),
        '__NATIVE_STARTUP_METADATA_INTENT_PATH__':(out/INTENT_FILE).as_posix()}
    for token,value in values.items():need(source.count(token)>=1,'SOURCE_TOKEN');source=source.replace(token,value)
    header=files['sdk_probe_params.h'].decode();line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
    header=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(source,ensure_ascii=False))
    for key,value in {'AH_CPP_EPOCH_OPERATION_ID':p['operationId'],'AH_CPP_EPOCH_SCOPE_SHA256':s.scope_sha256}.items():
        header+='\n#define '+key+' '+json.dumps(value)+'\n'
    header+='#define AH_CPP_EPOCH_RECEIPT_FILE L'+json.dumps((out/EPOCH_FILE).as_posix())+'\n'
    files['sdk_probe_params.h']=header.encode();code=epoch.render().decode()
    code=c._replace_once(code,'if(GetCurrentThreadId()!=sdkGuiThread)rc=110;',
        'if(GetCurrentThreadId()!=sdkGuiThread || sdkGuiThread!=AH_SDK_EXPECTED_GUI_THREAD)rc=110;')
    code=c._replace_once(code,'if(!valid && diagnostic[0]==0)',
        'if(thread!=AH_SDK_EXPECTED_GUI_THREAD)valid=FALSE;\n if(!valid && diagnostic[0]==0)')
    need(code.count('sdkGuiThread!=AH_SDK_EXPECTED_GUI_THREAD')==1 and code.count('if(thread!=AH_SDK_EXPECTED_GUI_THREAD)valid=FALSE;')==1,'GUI_GUARDS')
    need(c.digest(code.encode())==CARRIER_SHA,'CARRIER_PIN')
    files['Continuation.c']=code.encode()
    ps=files['run-fixed.ps1'].decode('utf-8-sig');need(ps.count('version=233;')==2,'HOST_AUTHORITY_ANCHOR')
    auth='version=233;writerAuthorized=$false;'+''.join(k+'=$true;' for k in TRUE_AUTH)+''.join(k+'=$false;' for k in FALSE_AUTH)
    for key,value in _limits().items():auth+=key+'='+str(value)+';'
    auth+="startupMetadataProfile='"+PROFILE+"';actualSourceSha256='"+SOURCE_SHA+"';"
    files['run-fixed.ps1']=ps.replace('version=233;',auth).encode('utf-8-sig')
    files,identity=section_identity.with_section_identity(files,operation_kind='DATABASE_STARTUP_METADATA',operation_id=p['operationId']);return files


def _authority_result(s,terminal=False):
    return dict(updatePreviewProfile=PROFILE,updatePreviewControllerSha256=s.plan['updatePreviewControllerSha256'],
        actualSourceSha256=SOURCE_SHA,scopeSha256=s.scope_sha256,readScopeSha256=s.parent.review_sha256,
        writerAuthorized=False,databaseApplyAuthorized=False,databaseApplyVerified=False,
        databaseConfigurationVerified=False,startupMetadataObserved=terminal,startupModulesReviewed=False,
        sourceKindBranchRuntimeVerified=False,commonModuleExecutionAuthorized=False,priorDatabaseReadbackVerified=True,
        priorDatabaseReadbackOperationId='7d40505fa0eb4ffab7b6a34467a05446',
        expectedDatabaseSource=EXPECTED_DATABASE_SOURCE,**_limits(),**{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


def prepare_root(scope_path,scope_sha256):
    _pins();path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=_json(path,scope_sha256)
    need(scope.get('kind')=='ROOT_DATABASE_STARTUP_METADATA_SCOPE' and scope.get('passed') is True and _authority(scope)
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
    _joined(s,native,'DATABASE_STARTUP_METADATA_NATIVE');_joined(s,reserved,'DATABASE_STARTUP_METADATA_INTENT')
    need(native.get('status')=='DATABASE_STARTUP_METADATA_OBSERVED' and native.get('phase')=='METADATA_ONLY'
        and native.get('reason')=='NONE' and native.get('configurationSourceDomain')=='DATABASE','METADATA_STATUS')
    need(all(native.get(k) is True for k in ('verified','nativeIntentWritten','typedHandlesCleared',
        'beforeRootAndTargetsClean','afterRootAndTargetsClean','designerPrefixPreserved'))
        and all(native.get(k) is False for k in ('exceptionObserved','startupReviewed','sourceKindBranchRuntimeVerified')),'METADATA_CLOSURE')
    _counts(native,dict(databaseManager=100051712,databaseSource=EXPECTED_DATABASE_SOURCE,beforeTargetsClean=3,afterTargetsClean=3,
        bindingPasses=2,startupPropertyReads=4,flagPropertyReads=24,commonModuleResolutions=4,
        persistentBefore=0,persistentAfter=0,singleBefore=0,singleAfter=0,
        moduleTextReads=0,storageOpens=0,newSessions=0,patientReads=0,businessCalls=0,queryExecutions=0,editorHelperCalls=0,
        **{k:0 for k in ZERO_NATIVE}),'METADATA_COUNTS')
    _counts(reserved,dict(maximumStartupPropertyReads=4,maximumFlagPropertyReads=24,maximumUrlGetterCalls=4,
        moduleTextReads=0,storageOpens=0,newSessions=0,patientReads=0,businessCalls=0,
        **{k:0 for k in ZERO_NATIVE}),'METADATA_INTENT')
    _metadata_rows(native)
    epoch.classify_type_epoch(_json(Path(s.plan['outputDirectory'])/EPOCH_FILE,bound=32768),
        operation_id=s.plan['operationId'],scope_sha256=s.scope_sha256,process_id=48936,
        execute_thread_id=8292,callback_known=True,callback_sdk_rc=0,target_identity_verified=True)
    return 'DATABASE_STARTUP_METADATA_OBSERVED'


STARTUP_PROPERTIES=('9b7bbbae-9771-46f2-9e4d-2489e0ffc702','a4a9c1e2-1e54-4c7f-af06-4ca341198fac')
COMMON_MODULES=('176e2552-fd8b-4823-afc0-d17431f2fb7b','28ecdfc7-083e-4082-b272-efbf7152de5c')
BOOL_PROPERTIES=('d12660a6-7298-4ae2-a332-b95a6459a280','6275a02e-96f0-4347-975a-2d661e6a0675',
 '7dbb2bc7-6bae-4b81-91cb-681317272a0b','c474bab9-d13a-4fbd-bfb0-9214d6dc2fde','334033a1-6bda-4dba-bc6d-0095d1b66f0b')
REUSE_PROPERTY='07ddee68-6fc0-4b88-9616-7792446d12b8'
UUID_PATTERN=r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'


def _stable_pair(value,*,unsigned=False):
    low,high=(0,0xffffffff) if unsigned else (-0x80000000,0x7fffffff)
    need(type(value) is list and len(value)==2 and all(type(x) is int and low<=x<=high for x in value)
        and value[0]==value[1],'PROPERTY_PAIR')


def _metadata_rows(native):
    rows=native.get('startupProperties');need(type(rows) is list and len(rows)==2,'STARTUP_ROWS')
    external=0
    for row,property_id in zip(rows,STARTUP_PROPERTIES):
        need(type(row) is dict and row.get('propertyId')==property_id,'STARTUP_PROPERTY')
        _stable_pair(row.get('propertyReturnCodes'));_stable_pair(row.get('urlReturnCodes'),unsigned=True)
        need(all(type(row.get(k)) is bool for k in ('valueNull','typePresent','externalObjectPresent','urlHashKnown','urlSupported')),'STARTUP_BOOLS')
        need(type(row.get('typeKind')) is int and -1<=row['typeKind']<=255
            and all(type(row.get(k)) is int and 0<=row[k]<=4096 for k in ('urlCharacters','urlUtf8Bytes')),'STARTUP_BOUNDS')
        category=row.get('typeCategory');key=row.get('canonicalInternalUrl');sha=row.get('urlSha256')
        need(type(key) is str and type(sha) is str and category in
            ('NULL_VALUE','NON_EXTERNAL_VALUE','NON_EXTERNAL_NO_TYPE','INTERNAL_UUID_ZERO','UNSUPPORTED_URL'),'STARTUP_CATEGORY')
        if row['valueNull']:
            need(category=='NULL_VALUE' and row['typeKind']==-1 and not row['externalObjectPresent']
                and row['typePresent'] is False,'NULL_STARTUP')
        else:need(category!='NULL_VALUE','NON_NULL_STARTUP')
        if not row['typePresent']:need(row['typeKind']==-1,'NO_STARTUP_TYPE')
        if row['externalObjectPresent']:
            external+=1;need(not row['valueNull'] and row['urlCharacters']<=row['urlUtf8Bytes'],'EXTERNAL_STARTUP')
            if row['urlSupported']:
                need(category=='INTERNAL_UUID_ZERO' and re.fullmatch(UUID_PATTERN+r'\.0',key) is not None
                    and not key.startswith('00000000-0000-0000-0000-000000000000')
                    and row['urlCharacters']==row['urlUtf8Bytes']==38,'INTERNAL_STARTUP_URL')
            else:need(category=='UNSUPPORTED_URL' and key=='','UNSUPPORTED_STARTUP_URL')
        else:
            need(not row['urlSupported'] and row['urlCharacters']==row['urlUtf8Bytes']==0
                and key=='' and row['urlReturnCodes']==[0,0]
                and category in ('NULL_VALUE','NON_EXTERNAL_VALUE','NON_EXTERNAL_NO_TYPE'),'NO_EXTERNAL_STARTUP')
        if row['urlUtf8Bytes']:
            need(row['urlHashKnown'] is True and re.fullmatch('[a-f0-9]{64}',sha) is not None,'STARTUP_URL_HASH')
            if key:need(c.digest(key.encode())==sha,'CANONICAL_URL_HASH')
        else:need(row['urlHashKnown'] is False and sha=='','EMPTY_URL_HASH')
    _counts(native,dict(urlGetterCalls=2*external),'URL_CALLS')
    flags=native.get('commonModuleFlags');need(type(flags) is list and len(flags)==10,'FLAG_ROWS')
    for row,(module,prop) in zip(flags,((m,p) for m in COMMON_MODULES for p in BOOL_PROPERTIES)):
        need(type(row) is dict and row.get('objectId')==module and row.get('propertyId')==prop
            and type(row.get('value')) is bool,'FLAG_ROW')
        _stable_pair(row.get('propertyReturnCodes'))
    reuse=native.get('commonModuleReuse');need(type(reuse) is list and len(reuse)==2,'REUSE_ROWS')
    for row,module in zip(reuse,COMMON_MODULES):
        need(type(row) is dict and row.get('objectId')==module and row.get('propertyId')==REUSE_PROPERTY,'REUSE_ROW')
        _stable_pair(row.get('propertyReturnCodes'))
        need(all(type(row.get(k)) is bool for k in ('valueNull','valueStabilityVerified','equalityInterfaceAvailable'))
            and type(row.get('typeKind')) is int and -1<=row['typeKind']<=255
            and type(row.get('stringUtf8Bytes')) is int and 0<=row['stringUtf8Bytes']<=256,'REUSE_TYPES')
        category=row.get('typeCategory');type_id=row.get('typeId');sha=row.get('stringSha256')
        need(type(sha) is str and type(type_id) is str and category in ('NULL_VALUE','OTHER_VALUE','OBJECT_OR_ENUM',
            'BOOLEAN_VALUE','NUMERIC_VALUE','UNDEFINED_VALUE','NULL_KIND','STRING_VALUE'),'REUSE_CATEGORY')
        if row['valueNull']:
            need(category=='NULL_VALUE' and row['typeKind']==-1 and type_id==''
                and row['valueStabilityVerified'] is True and row['equalityInterfaceAvailable'] is False,'NULL_REUSE')
        else:
            need(category!='NULL_VALUE' and re.fullmatch(r'(?:'+UUID_PATTERN+r'|\{'+UUID_PATTERN+r'\})',type_id) is not None,'REUSE_TYPE_ID')
        if category=='STRING_VALUE':
            need(row['valueStabilityVerified'] is True,'STRING_REUSE_STABILITY')
            if row['stringUtf8Bytes']:need(re.fullmatch('[a-f0-9]{64}',sha) is not None,'STRING_REUSE_HASH')
            else:need(sha=='','EMPTY_STRING_REUSE')
        else:need(row['stringUtf8Bytes']==0 and sha=='','NON_STRING_REUSE')
        if row['equalityInterfaceAvailable']:need(row['valueStabilityVerified'] is True,'REUSE_EQUALITY')


def _unknown(s,reason):
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=s.plan['operationId'],reason=reason,
        retryAuthorized=False,parentWriterOperationId=s.parent.scope['writerOperationId'],**_authority_result(s))
    c.write_new(Path(s.plan['outputDirectory'])/'unknown.json',result);return result


def run_root_once(s,review_path,review_sha256):
    _check(s);need(s.phase=='STAGED','RUN_PHASE');p=s.plan;ctx=p['context'];out=Path(p['outputDirectory']);ns=s.private
    build=ns['require_stage'](p);review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind')=='ROOT_DATABASE_STARTUP_METADATA_RUN' and review.get('passed') is True and _authority(review)
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
                    native=_json(out/NATIVE_FILE,bound=16384)
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
