"""One scoped shipped Designer initialization; no external addin loading or DB command."""
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
import json
import re
import subprocess
import time
import uuid
import sys
# The existing lease reader lives in tests; standalone workers do not inherit
# unittest's import path. This imports the checker without invoking tests.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
import comparison_cpp_exception_type_epoch as epoch
import sdk_compiler_section_identity as section_identity
import comparison_cpp_exception_stack_trace as previous

c=previous.c
reader=previous.reader
base=previous.repeatable.base
ROOT=c.ROOT
HERE=c.HERE
PARENT_SHA='c4e792ca4ae464c4a4b12f72cba8ba98522febb66bd6101732322f836aa913be'
SOURCE_NAME='NativeDesignerEventsInitialize.as'
SOURCE_SHA='b23ec2c524c0cea38f90eeaae3ed6fa19e297199ef8250f7f005fb0369ab2cce'
MAIN_SHA=previous.MAIN_SHA
CHECK_NAME='designer-events-initialize-raw-sdk-cold-cc96237a333445b39997f6f51593fd04.json'
CHECK_SHA='b6098247b09ab8ecf40b9ff636173510f2e9fb37fb053561aa43bd4133a5ba29'
PROFILE='DESIGNER_EVENTS_RUNTIME_INITIALIZE_ONLY'
NATIVE_FILE='designer-events-initialize-proof.json'
INTENT_FILE='native-designer-events-intent.json'
EPOCH_FILE='cpp-exception-type-epoch.json'
TRUE_AUTH=('runtimeSupportInitializationAuthorized','runtimeUiMutationPossible','configurationReadOnly','runtimeCacheMutationPossible','runtimeInitAndStatusOnly',
           'typedQiAuthorized','retainedReferenceMaintenanceAuthorized','commandStatusQueriesAuthorized','exceptionTypeMetadataReadAuthorized')
FALSE_AUTH=('readOnly','externalAddinLoadingAuthorized','sourceWritesAuthorized','configurationSavesAuthorized','databaseUpdatesAuthorized',
    'repositoryMutationsAuthorized','releaseResourcesAuthorized','configurationExportsAuthorized','configurationImportsAuthorized',
    'stockCompareAuthorized','newEnumerationAuthorized','ownedVectorDrainAuthorized',
    'historicalReferencesReleaseAuthorized','manualAddRefReleaseAuthorized','commandDispatchAuthorized','exceptionObjectReadAuthorized','typeRawOutput')
ZERO_NATIVE=('nativeCalls','directNativeFunctionCalls','nativeCommandCalls','enumerations',
    'manualReferenceCalls','listProjections','sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('DESIGNER_EVENTS_INITIALIZE_'+code)


def _json(path,pin=None,bound=32768):return reader._json(path,pin,bound)


def _limits():return dict(maximumRuntimeConstructors=1,maximumExternalAddinLoads=0,maximumTypedQi=1,maximumSnapshots=2,maximumStatusQueries=2,maximumHandlerQueries=2,maximumTypeEvents=32,maximumEnumerations=0,maximumNativeCommands=0)


def _authority(row):
    return all(row.get(k) is True for k in TRUE_AUTH) and all(row.get(k) is False for k in FALSE_AUTH) \
        and all(type(row.get(k)) is int and row[k]==v for k,v in _limits().items())


def _source():
    raw=c.read(HERE/SOURCE_NAME)
    need(c.digest(raw)==SOURCE_SHA,'SOURCE_PIN')
    need(set(re.findall(r'__[A-Z0-9_]+__',raw.decode()))=={
        '__DESIGNER_EVENTS_INITIALIZE_SCOPE_ADMITTED__','__OPERATION_ID__','__SCOPE_SHA256__','__PROOF_PATH__',
        '__NATIVE_DESIGNER_EVENTS_INTENT_PATH__'},'SOURCE_TOKENS')
    return raw


def _pins():
    need(c.digest(c.read(Path(previous.__file__)))==PARENT_SHA,'PARENT_PIN');previous._pins();_source()
    need(c.digest(c.read(Path(epoch.__file__)))=='e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4','EPOCH_PIN')
    need(c.digest(c.read(Path(section_identity.__file__)))=='6f63f39ddcd8f1e3db9c25ca866e7faa89f6a8bc2be54dfd49dc958952f9754d','SECTION_PIN')
    proof=_json(ROOT/'artifacts/designer-bridge'/CHECK_NAME,CHECK_SHA)
    need(proof.get('kind')=='DESIGNER_EVENTS_INITIALIZE_RAW_SDK_COLD_CHECK' and proof.get('sourceSha256')==SOURCE_SHA
        and proof.get('sourceMainSha256')==MAIN_SHA and proof.get('realCompileFunction') is True
        and proof.get('positiveExit')==0 and proof.get('negativeExit')==103 and proof.get('ownTemporaryDirectoryRemoved') is True
        and all(proof.get(k) is False for k in ('contextCreated','bodyExecuted','sourceScopeAdmitted','goldStarted')),'REAL_SDK_COLD_CHECK')



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


def _claim_path(s):return ROOT/'artifacts/designer-bridge'/('designer-events-initialize-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='DESIGNER_EVENTS_INITIALIZE_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
        actualSourceSha256=SOURCE_SHA,controllerSha256=s.plan['designerEventsInitControllerSha256'],
        writerOperationId=q['operationId'],writerIntentSha256=c.digest(c.canonical(q)),packetSha256=q['packetSha256'],
        sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'],runtimeInitAndStatusOnly=True)


def _check(s):
    need(type(s) is ReadOp and s._issuer is _ISSUER,'ISSUED_READ');_pins();p=s.plan;ctx=p['context']
    need(c.canonical(p)==s.plan_raw and p.get('designerEventsInitControllerSha256')==c.digest(c.read(Path(__file__)))
        and p.get('designerEventsInitProfile')==PROFILE and _authority(p) and p.get('actualSourceSha256')==SOURCE_SHA
        and p.get('writerAuthorized') is False and p.get('captureAuthorized') is False
        and type(p.get('applicationWrites')) is int and p['applicationWrites']==0
        and p.get('eventsInitScopeSha256')==s.scope_sha256 and p.get('readScopeSha256')==s.parent.review_sha256
        and ctx==s.parent.plan['context'],'PLAN_AUTHORITY')
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256'))==
        (48936,'01dd5d0180299126',8292,MAIN_SHA),'FIXED_NATIVE')
    q=reader._check_owner(s.parent);scope=_json(s.scope_path,s.scope_sha256)
    need(scope==s.scope and scope.get('kind')=='ROOT_DESIGNER_EVENTS_INITIALIZE_SCOPE' and scope.get('passed') is True
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
    values={'__DESIGNER_EVENTS_INITIALIZE_SCOPE_ADMITTED__':'true','__OPERATION_ID__':p['operationId'],
        '__SCOPE_SHA256__':s.scope_sha256,'__PROOF_PATH__':(out/NATIVE_FILE).as_posix(),
        '__NATIVE_DESIGNER_EVENTS_INTENT_PATH__':(out/INTENT_FILE).as_posix()}
    for token,value in values.items():need(source.count(token)==1,'ONE_TOKEN');source=source.replace(token,value,1)
    header=files['sdk_probe_params.h'].decode();line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
    files['sdk_probe_params.h']=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(source,ensure_ascii=False)).encode()
    header=files['sdk_probe_params.h'].decode()
    header+='\n#define AH_CPP_EPOCH_OPERATION_ID '+json.dumps(p['operationId'])+'\n'
    header+='#define AH_CPP_EPOCH_SCOPE_SHA256 '+json.dumps(s.scope_sha256)+'\n'
    header+='#define AH_CPP_EPOCH_RECEIPT_FILE L'+json.dumps((out/EPOCH_FILE).as_posix())+'\n'
    files['sdk_probe_params.h']=header.encode()
    code=epoch.render().decode()
    code=c._replace_once(code,'if(GetCurrentThreadId()!=sdkGuiThread)rc=110;',
        'if(GetCurrentThreadId()!=sdkGuiThread || sdkGuiThread!=AH_SDK_EXPECTED_GUI_THREAD)rc=110;')
    code=c._replace_once(code,'if(!valid && diagnostic[0]==0)',
        'if(thread!=AH_SDK_EXPECTED_GUI_THREAD)valid=FALSE;\n if(!valid && diagnostic[0]==0)')
    files['Continuation.c']=code.encode()
    ps=files['run-fixed.ps1'].decode('utf-8-sig');need(ps.count('version=233;')==2,'HOST_AUTHORITY_ANCHOR')
    auth='version=233;writerAuthorized=$false;'+''.join(k+'=$true;' for k in TRUE_AUTH)+''.join(k+'=$false;' for k in FALSE_AUTH)
    for key,value in _limits().items():auth+=key+'='+str(value)+';'
    auth+="designerEventsInitProfile='"+PROFILE+"';actualSourceSha256='"+SOURCE_SHA+"';"
    files['run-fixed.ps1']=ps.replace('version=233;',auth).encode('utf-8-sig')
    files,identity=section_identity.with_section_identity(files,operation_kind='EVENTS_INIT',operation_id=p['operationId'])
    return files


def _authority_result(s):
    return dict(designerEventsInitProfile=PROFILE,designerEventsInitControllerSha256=s.plan['designerEventsInitControllerSha256'],
        actualSourceSha256=SOURCE_SHA,scopeSha256=s.scope_sha256,readScopeSha256=s.parent.review_sha256,
        writerAuthorized=False,runtimeSupportOnly=True,actualUpdate29OwnerVerified=False,updateAdmissionGranted=False,
        databaseApplyAuthorized=False,globalPendingClean=False,**_limits(),
        **{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


def prepare_root(scope_path,scope_sha256):
    _pins();path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=_json(path,scope_sha256)
    need(scope.get('kind')=='ROOT_DESIGNER_EVENTS_INITIALIZE_SCOPE' and scope.get('passed') is True and _authority(scope)
        and scope.get('actualSourceSha256')==SOURCE_SHA,'READ_SCOPE_BEFORE_OWNER')
    parent=previous._prepare_parent(scope['readScopePath'],scope['readScopeSha256']);p=dict(parent.plan);op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):p.pop(key)
    p.update(operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),designerEventsInitProfile=PROFILE,
        designerEventsInitControllerSha256=c.digest(c.read(Path(__file__))),actualSourceSha256=SOURCE_SHA,
        eventsInitScopeSha256=scope_sha256,readScopeSha256=parent.review_sha256,
        writerAuthorized=False,captureAuthorized=False,applicationWrites=0,**_limits(),
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


def _native_terminal(s,native,reserved):
    need(type(native) is dict and native.get('kind')=='DESIGNER_EVENTS_INITIALIZE_NATIVE'
        and native.get('operationId')==s.plan['operationId'] and native.get('scopeSha256')==s.scope_sha256
        and all(native.get(k) is True for k in ('configurationReadOnly','typedHandlesCleared'))
        and all(native.get(k) is False for k in ('readOnly','actualUpdate29OwnerVerified','updateAdmissionGranted','unknownRetain'))
        and all(type(native.get(k)) is int and native[k]==0 for k in ZERO_NATIVE),'NATIVE_JOIN')
    need(all(type(native.get(k)) is int and 0<=native[k]<=1 for k in ('runtimeConstructorAttempts','runtimeConstructorReturned'))
        and type(native.get('runtimeWasAbsent')) is bool and type(native.get('runtimeReady')) is bool
        and type(native.get('registeredAddins')) is int and 0<=native['registeredAddins']<=128
        and type(native.get('explicitExternalAddinLoads')) is int and native['explicitExternalAddinLoads']==0,'INITIALIZER_COUNTS')
    need(native['runtimeConstructorReturned']==native['runtimeConstructorAttempts'],'INITIALIZER_RETURN')
    if native['runtimeConstructorAttempts']:
        need(native['runtimeWasAbsent'] and native['runtimeReady'],'INITIALIZER_PARTIAL_RETAIN')
    qi=native.get('publishedTypedQiAttempts');returned=native.get('publishedTypedQiReturned');passes=native.get('snapshotPasses');queries=native.get('statusQueries')
    need(type(qi) is int and qi in (0,1) and type(returned) is int and returned==qi
        and type(passes) is int and 0<=passes<=2 and type(queries) is int and 0<=queries<=2,'NATIVE_COUNTS')
    pointers=('shellPointer','canonicalPointer','targetPointer','ownerPointer','delegatePointer','mainEntryPointer','coreReceiverPointer')
    need(all(type(native.get(k)) is int and 0<=native[k]<=0xffffffff for k in pointers),'POINTER_TYPES')
    if qi==0:
        need(native.get('status')=='DESIGNER_EVENTS_INITIALIZE_REFUSED' and native.get('commandStatesReadVerified') is False
            and native.get('nativeIntentWritten') is False and reserved is None and passes==0 and queries==0,'ZERO_REFUSAL')
        return 'DESIGNER_EVENTS_INITIALIZE_REFUSED'
    need(native.get('nativeIntentWritten') is True and type(reserved) is dict
        and reserved.get('kind')=='DESIGNER_EVENTS_INITIALIZE_NATIVE_INTENT'
        and reserved.get('operationId')==s.plan['operationId'] and reserved.get('scopeSha256')==s.scope_sha256
        and all(reserved.get(k) is True for k in ('configurationReadOnly','runtimeInitAndStatusOnly'))
        and all(type(reserved.get(k)) is int and reserved[k]==0 for k in ('databaseUpdates','repositoryMutations')),'NATIVE_INTENT')
    need(all(native.get(k) is True for k in ('beforeRootAndTargetsClean','afterRootAndTargetsClean'))
        and all(type(native.get(k)) is int and native[k]==3 for k in ('beforeTargetsClean','afterTargetsClean')),'ROOT_CLEAN')
    if native.get('status')=='DESIGNER_EVENTS_INITIALIZE_REFUSED':
        need(native.get('commandStatesReadVerified') is False and native.get('reason') not in ('NONE','NATIVE_EXCEPTION_OR_CLEANUP'),'READ_REFUSAL')
        return 'DESIGNER_EVENTS_INITIALIZE_REFUSED'
    need(native.get('status')=='DESIGNER_EVENTS_INITIALIZED_CLEAN' and native.get('reason')=='NONE'
        and native.get('commandStatesReadVerified') is True and passes==2 and queries==2
        and all(0x10000<=native[k]<=0xffffffcc and native[k]%4==0 for k in pointers if k!='delegatePointer')
        and native['canonicalPointer']==native['shellPointer']-8 and native['targetPointer']==native['shellPointer']+8,'READ_CLOSURE')
    need(native['runtimeConstructorAttempts']==1 and native['runtimeReady'] and native['eventConnectorAvailable'],'INITIALIZED_READY')
    need(all(type(native.get(k)) is bool for k in ('updateHandlerPresent','updateEnabled','saveHandlerPresent','saveEnabled',
        'eventConnectorAvailable','messageBoxHandlersPresent','modalHandlersPresent'))
        and native['updateHandlerPresent'] and native['saveHandlerPresent'],'STATE_FIELDS')
    receipt=_json(Path(s.plan['outputDirectory'])/EPOCH_FILE,bound=32768)
    try:epoch.classify_type_epoch(receipt,operation_id=s.plan['operationId'],scope_sha256=s.scope_sha256,process_id=48936,
        execute_thread_id=8292,callback_known=True,callback_sdk_rc=0,target_identity_verified=True)
    except ValueError:return 'DESIGNER_EVENTS_INITIALIZE_CPP_REJECTED'
    return 'DESIGNER_EVENTS_INITIALIZED_CLEAN'


def _unknown(s,reason):
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=s.plan['operationId'],reason=reason,
        retryAuthorized=False,parentWriterOperationId=s.parent.scope['writerOperationId'],**_authority_result(s))
    c.write_new(Path(s.plan['outputDirectory'])/'unknown.json',result);return result


def run_root_once(s,review_path,review_sha256):
    _check(s);need(s.phase=='STAGED','RUN_PHASE');p=s.plan;ctx=p['context'];out=Path(p['outputDirectory']);ns=s.private
    build=ns['require_stage'](p);review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind')=='ROOT_DESIGNER_EVENTS_INITIALIZE_RUN' and review.get('passed') is True and _authority(review)
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
                    native=_json(out/NATIVE_FILE,bound=8192)
                    reserved=_json(out/INTENT_FILE,bound=4096) if (out/INTENT_FILE).is_file() else None
                    status=_native_terminal(s,native,reserved)
                except (OSError,ValueError):return _unknown(s,'NATIVE_OR_FRESH_CLOSURE_UNPROVEN')
                result=dict(version=233,status=status,knownTerminal=True,operationId=p['operationId'],
                    planSha256=c.digest(s.plan_raw),sdkResult=0,hookWorkersReleased=True,targetIdentityVerified=True,
                    nativeInjectionPerformed=True,nativeProofSha256=c.digest(c.read(out/NATIVE_FILE)),
                    parentWriterOperationId=claim['writerOperationId'],retryAuthorized=False,
                    releasePacketAllowed=False,releaseRefsAllowed=False,**_authority_result(s))
                c.write_new(out/'result.json',result);s.phase='KNOWN_TERMINAL_RETAIN_PARENT';return result
            break
        if s.host.poll() is not None:break
        time.sleep(.05)
    return _unknown(s,'HOST_OR_SDK_TERMINAL_UNPROVEN')
