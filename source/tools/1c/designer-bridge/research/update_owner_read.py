"""One scoped typed-QI diagnostic; candidate owner never grants Update29."""
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
import json
import re
import subprocess
import time
import uuid
import comparison_cpp_exception_stack_trace as previous

c=previous.c
reader=previous.reader
base=previous.repeatable.base
ROOT=c.ROOT
HERE=c.HERE
PARENT_SHA='c4e792ca4ae464c4a4b12f72cba8ba98522febb66bd6101732322f836aa913be'
SOURCE_NAME='NativeUpdateOwnerRead.as'
SOURCE_SHA='2ba66242f29b0ebeea8176fb225d4a601dd2c7d86ae38419947a97028c10fa61'
MAIN_SHA=previous.MAIN_SHA
CHECK_NAME='update-owner-read-check-only-56b9d186fb9441529e1a87c037c0fc39.json'
CHECK_SHA='a697b60d3801ea16f4b84de68f73ec7ca76ca177ed0b14dc1fe0669120326037'
PROFILE='UPDATE_OWNER_TYPED_QI_DIAGNOSTIC_ONLY'
NATIVE_FILE='update-owner-read-proof.json'
INTENT_FILE='native-owner-read-intent.json'
TRUE_AUTH=('readOnly','configurationReadOnly','runtimeCacheMutationPossible','typedQiOnly',
           'typedQiAuthorized','retainedReferenceMaintenanceAuthorized')
FALSE_AUTH=('sourceWritesAuthorized','configurationSavesAuthorized','databaseUpdatesAuthorized',
    'repositoryMutationsAuthorized','releaseResourcesAuthorized','configurationExportsAuthorized','configurationImportsAuthorized',
    'stockCompareAuthorized','newEnumerationAuthorized','ownedVectorDrainAuthorized',
    'historicalReferencesReleaseAuthorized','manualAddRefReleaseAuthorized','commandDispatchAuthorized')
ZERO_NATIVE=('nativeCalls','directNativeFunctionCalls','nativeCommandCalls','enumerations',
    'manualReferenceCalls','listProjections','sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('UPDATE_OWNER_READ_'+code)


def _json(path,pin=None,bound=32768):return reader._json(path,pin,bound)


def _limits():return dict(maximumTypedQi=1,maximumSnapshots=2,maximumEnumerations=0,maximumNativeCommands=0)


def _authority(row):
    return all(row.get(k) is True for k in TRUE_AUTH) and all(row.get(k) is False for k in FALSE_AUTH) \
        and all(type(row.get(k)) is int and row[k]==v for k,v in _limits().items())


def _source():
    raw=c.read(HERE/SOURCE_NAME)
    need(c.digest(raw)==SOURCE_SHA,'SOURCE_PIN')
    need(set(re.findall(r'__[A-Z0-9_]+__',raw.decode()))=={
        '__UPDATE_OWNER_READ_SCOPE_ADMITTED__','__OPERATION_ID__','__SCOPE_SHA256__','__PROOF_PATH__',
        '__NATIVE_OWNER_READ_INTENT_PATH__'},'SOURCE_TOKENS')
    return raw


def _pins():
    need(c.digest(c.read(Path(previous.__file__)))==PARENT_SHA,'PARENT_PIN');previous._pins();_source()
    proof=_json(ROOT/'artifacts/designer-bridge'/CHECK_NAME,CHECK_SHA)
    need(proof.get('kind')=='UPDATE_OWNER_READ_CHECK_ONLY' and proof.get('entry')=='ahUpdateOwnerRead'
        and proof.get('sourceSha256')==SOURCE_SHA and proof.get('sourceMainSha256')==MAIN_SHA
        and proof.get('scopeAdmitted') is False
        and proof.get('positive',{}).get('compileVerified') is True
        and type(proof.get('positive',{}).get('exitCode')) is int and proof['positive']['exitCode']==0
        and proof.get('negative',{}).get('compileVerified') is False
        and type(proof.get('negative',{}).get('exitCode')) is int and proof['negative']['exitCode']!=0
        and all(proof.get(k) is True for k in ('negativeCoverage','ownRuntimeRemoved'))
        and all(proof.get(k) is False for k in ('goldStarted','scriptRunRequested')),'COLD_CHECK')


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


def _claim_path(s):return ROOT/'artifacts/designer-bridge'/('update-owner-read-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='UPDATE_OWNER_READ_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
        actualSourceSha256=SOURCE_SHA,controllerSha256=s.plan['updateOwnerReadControllerSha256'],
        writerOperationId=q['operationId'],writerIntentSha256=c.digest(c.canonical(q)),packetSha256=q['packetSha256'],
        sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'],typedQiOnly=True)


def _check(s):
    need(type(s) is ReadOp and s._issuer is _ISSUER,'ISSUED_READ');_pins();p=s.plan;ctx=p['context']
    need(c.canonical(p)==s.plan_raw and p.get('updateOwnerReadControllerSha256')==c.digest(c.read(Path(__file__)))
        and p.get('updateOwnerReadProfile')==PROFILE and _authority(p) and p.get('actualSourceSha256')==SOURCE_SHA
        and p.get('writerAuthorized') is False and p.get('captureAuthorized') is False
        and type(p.get('applicationWrites')) is int and p['applicationWrites']==0
        and p.get('ownerReadScopeSha256')==s.scope_sha256 and p.get('readScopeSha256')==s.parent.review_sha256
        and ctx==s.parent.plan['context'],'PLAN_AUTHORITY')
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256'))==
        (48936,'01dd5d0180299126',8292,MAIN_SHA),'FIXED_NATIVE')
    q=reader._check_owner(s.parent);scope=_json(s.scope_path,s.scope_sha256)
    need(scope==s.scope and scope.get('kind')=='ROOT_UPDATE_OWNER_READ_SCOPE' and scope.get('passed') is True
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
    values={'__UPDATE_OWNER_READ_SCOPE_ADMITTED__':'true','__OPERATION_ID__':p['operationId'],
        '__SCOPE_SHA256__':s.scope_sha256,'__PROOF_PATH__':(out/NATIVE_FILE).as_posix(),
        '__NATIVE_OWNER_READ_INTENT_PATH__':(out/INTENT_FILE).as_posix()}
    for token,value in values.items():need(source.count(token)==1,'ONE_TOKEN');source=source.replace(token,value,1)
    header=files['sdk_probe_params.h'].decode();line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
    files['sdk_probe_params.h']=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(source,ensure_ascii=False)).encode()
    ps=files['run-fixed.ps1'].decode('utf-8-sig');need(ps.count('version=233;')==2,'HOST_AUTHORITY_ANCHOR')
    auth='version=233;writerAuthorized=$false;'+''.join(k+'=$true;' for k in TRUE_AUTH)+''.join(k+'=$false;' for k in FALSE_AUTH)
    for key,value in _limits().items():auth+=key+'='+str(value)+';'
    auth+="updateOwnerReadProfile='"+PROFILE+"';actualSourceSha256='"+SOURCE_SHA+"';"
    files['run-fixed.ps1']=ps.replace('version=233;',auth).encode('utf-8-sig');return files


def _authority_result(s):
    return dict(updateOwnerReadProfile=PROFILE,updateOwnerReadControllerSha256=s.plan['updateOwnerReadControllerSha256'],
        actualSourceSha256=SOURCE_SHA,scopeSha256=s.scope_sha256,readScopeSha256=s.parent.review_sha256,
        writerAuthorized=False,candidateOnly=True,actualUpdate29OwnerVerified=False,updateAdmissionGranted=False,
        databaseApplyAuthorized=False,globalPendingClean=False,**_limits(),
        **{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


def prepare_root(scope_path,scope_sha256):
    _pins();path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=_json(path,scope_sha256)
    need(scope.get('kind')=='ROOT_UPDATE_OWNER_READ_SCOPE' and scope.get('passed') is True and _authority(scope)
        and scope.get('actualSourceSha256')==SOURCE_SHA,'READ_SCOPE_BEFORE_OWNER')
    parent=previous._prepare_parent(scope['readScopePath'],scope['readScopeSha256']);p=dict(parent.plan);op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):p.pop(key)
    p.update(operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),updateOwnerReadProfile=PROFILE,
        updateOwnerReadControllerSha256=c.digest(c.read(Path(__file__))),actualSourceSha256=SOURCE_SHA,
        ownerReadScopeSha256=scope_sha256,readScopeSha256=parent.review_sha256,
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
    need(type(native) is dict and native.get('kind')=='UPDATE_OWNER_READ_NATIVE'
        and native.get('operationId')==s.plan['operationId'] and native.get('scopeSha256')==s.scope_sha256
        and all(native.get(k) is True for k in ('readOnly','configurationReadOnly','typedHandlesCleared'))
        and all(native.get(k) is False for k in ('actualUpdate29OwnerVerified','updateAdmissionGranted','unknownRetain'))
        and all(type(native.get(k)) is int and native[k]==0 for k in ZERO_NATIVE),'NATIVE_JOIN')
    qi=native.get('publishedTypedQiAttempts');returned=native.get('publishedTypedQiReturned');passes=native.get('snapshotPasses')
    need(type(qi) is int and qi in (0,1) and type(returned) is int and returned==qi
        and type(passes) is int and 0<=passes<=2,'NATIVE_COUNTS')
    pointers=('shellPointer','canonicalPointer','targetPointer','ownerPointer','delegatePointer','mainEntryPointer')
    need(all(type(native.get(k)) is int and 0<=native[k]<=0xffffffff for k in pointers),'POINTER_TYPES')
    if qi==0:
        need(native.get('status')=='OWNER_READ_REFUSED' and native.get('candidateConfigFallbackOwnerVerified') is False
            and native.get('nativeIntentWritten') is False and reserved is None and passes==0,'ZERO_REFUSAL')
        return 'OWNER_READ_REFUSED'
    need(native.get('nativeIntentWritten') is True and type(reserved) is dict
        and reserved.get('kind')=='UPDATE_OWNER_READ_NATIVE_INTENT'
        and reserved.get('operationId')==s.plan['operationId'] and reserved.get('scopeSha256')==s.scope_sha256
        and all(reserved.get(k) is True for k in ('configurationReadOnly','typedQiOnly'))
        and all(type(reserved.get(k)) is int and reserved[k]==0 for k in ('databaseUpdates','repositoryMutations')),
        'NATIVE_INTENT')
    need(all(native.get(k) is True for k in ('beforeRootAndTargetsClean','afterRootAndTargetsClean'))
        and all(type(native.get(k)) is int and native[k]==3 for k in ('beforeTargetsClean','afterTargetsClean')),'ROOT_CLEAN')
    if native.get('status')=='OWNER_READ_REFUSED':
        need(native.get('candidateConfigFallbackOwnerVerified') is False and type(native.get('reason')) is str
            and native['reason'] not in ('NONE','NATIVE_EXCEPTION_OR_CLEANUP'),'READ_REFUSAL')
        return 'OWNER_READ_REFUSED'
    need(native.get('status')=='OWNER_CANDIDATE_READ_CLEAN' and native.get('reason')=='NONE'
        and native.get('candidateConfigFallbackOwnerVerified') is True and passes==2 and native['delegatePointer']==0
        and all(0x10000<=native[k]<=0xffffffcc and native[k]%4==0 for k in pointers if k!='delegatePointer')
        and native['canonicalPointer']==native['shellPointer']-8
        and native['targetPointer']==native['shellPointer']+8,'CANDIDATE_CLOSURE')
    return 'OWNER_CANDIDATE_READ_CLEAN'


def _unknown(s,reason):
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=s.plan['operationId'],reason=reason,
        retryAuthorized=False,parentWriterOperationId=s.parent.scope['writerOperationId'],**_authority_result(s))
    c.write_new(Path(s.plan['outputDirectory'])/'unknown.json',result);return result


def run_root_once(s,review_path,review_sha256):
    _check(s);need(s.phase=='STAGED','RUN_PHASE');p=s.plan;ctx=p['context'];out=Path(p['outputDirectory']);ns=s.private
    build=ns['require_stage'](p);review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind')=='ROOT_UPDATE_OWNER_READ_RUN' and review.get('passed') is True and _authority(review)
        and review.get('planSha256')==c.digest(s.plan_raw) and review.get('buildSha256')==c.digest(c.canonical(build))
        and review.get('scopeSha256')==s.scope_sha256 and review.get('readScopeSha256')==s.parent.review_sha256
        and review.get('actualSourceSha256')==SOURCE_SHA,'ROOT_RUN')
    ns['_no_pending'](context=ctx)
    need(not any((out/n).exists() for n in ('intent.json','host-identity.json','host-result.json','result.json','unknown.json',
        'sdk-receipt.json',NATIVE_FILE,INTENT_FILE)),'ONE_ATTEMPT')
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
