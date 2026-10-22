"""One owned headless comparison, bounded new references, typed exception epoch."""
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
import json
import re
import subprocess
import time
import uuid
import comparison_cpp_exception_stack_trace as previous
import sdk_compiler_section_identity as section_identity
import headless_comparison_carrier as carrier
import comparison_cpp_exception_type_epoch as epoch

c=previous.c
reader=previous.reader
base=previous.repeatable.base
ROOT=c.ROOT
HERE=c.HERE
PARENT_SHA='c4e792ca4ae464c4a4b12f72cba8ba98522febb66bd6101732322f836aa913be'
SOURCE_NAME='NativeOwnedHeadlessComparisonUtf8.as'
SOURCE_SHA='489d99eb6b0b1153f78eca2480fc0d429ea6b6c5d219ad38e7fd41d2b822d18d'
MAIN_SHA=previous.MAIN_SHA
CHECK_NAME='owned-headless-comparison-cold-check-cc41fd495d3c4902892ef389362aa564.json'
CHECK_SHA='5122e8aab20a9eca684d9ed2dcdae28d534013e7c208be20e410a45829b3e0eb'
PROFILE='OWNED_HEADLESS_COMPARISON_WITH_TYPED_CPP_EPOCH'
NATIVE_FILE='owned-headless-comparison-as-proof.json'
CORE_FILE='owned-headless-comparison-core-proof.json'
EPOCH_FILE='cpp-exception-type-epoch.json'
INTENT_FILE='native-headless-intent.json'
TRUE_AUTH=('configurationReadOnly','runtimeCacheMutationPossible','runtimeUiMutationPossible',
    'runtimeComparisonCreationAuthorized','comparisonFactoryAuthorized','comparisonExecuteAuthorized',
    'scopedReferenceCallsAuthorized','manualAddRefReleaseAuthorized','exceptionTypeMetadataReadAuthorized',
    'namedBridgeAuthorized','retainedReferenceMaintenanceAuthorized')
FALSE_AUTH=('sourceWritesAuthorized','configurationSavesAuthorized','databaseUpdatesAuthorized','repositoryMutationsAuthorized',
    'releaseResourcesAuthorized','configurationExportsAuthorized','configurationImportsAuthorized','stockCompareAuthorized',
    'newEnumerationAuthorized','ownedVectorDrainAuthorized','historicalReferencesReleaseAuthorized','commandDispatchAuthorized',
    'exceptionObjectReadAuthorized','typeRawOutput','unrestrictedFactoryCallsAuthorized')
ZERO_NATIVE=('nativeCommands','sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('OWNED_HEADLESS_COMPARISON_'+code)


def _json(path,pin=None,bound=32768):return reader._json(path,pin,bound)


def _limits():
    return dict(maximumFactoryCalls=1,maximumExecutions=1,maximumGetMdCont=2,maximumExplicitAddRef=4,
                maximumExplicitRelease=3,maximumProjectionNodes=524288,maximumRows=256,maximumNativeCommands=0,
                maximumTypeEvents=32,maximumEnumerations=0)


def _authority(row):
    return all(row.get(k) is True for k in TRUE_AUTH) and all(row.get(k) is False for k in FALSE_AUTH) \
        and all(type(row.get(k)) is int and row[k]==v for k,v in _limits().items())


def _source():
    raw=c.read(HERE/SOURCE_NAME)
    need(c.digest(raw)==SOURCE_SHA,'SOURCE_PIN')
    need(set(re.findall(r'__[A-Z0-9_]+__',raw.decode()))=={
        '__HEADLESS_SCOPE_ADMITTED__','__OPERATION_ID__','__SCOPE_SHA256__','__PROOF_PATH__',
        '__NATIVE_HEADLESS_INTENT_PATH__','__OWN_DLL_PATH__'},'SOURCE_TOKENS')
    return raw


def _pins():
    need(c.digest(c.read(Path(previous.__file__)))==PARENT_SHA,'PARENT_PIN');previous._pins();_source()
    need(c.digest(c.read(Path(section_identity.__file__)))=='6f63f39ddcd8f1e3db9c25ca866e7faa89f6a8bc2be54dfd49dc958952f9754d','SECTION_IDENTITY_PIN')
    for filename,pin in (('headless_comparison_carrier.py','2f10a11f592901b113bf45e9abcf1158b96019268faf5b53d55a5bfc4ea5ae68'),
                         ('NativeHeadlessComparisonAdapter.c.inc','a4f78e9bed8a88d55355005f21db075a8aa19c0784667544530ccbeeb024fc05')):
        need(c.digest(c.read(HERE/filename))==pin,'ADAPTER_GENERATOR_PIN')
    need(c.digest(carrier.render())=='701ff4126abcb58b75f2fbd575d7b21b2bbb3c7ee75b47df0463c775cdac2500','DERIVED_C_PIN')
    utf8proof=_json(ROOT/'artifacts/designer-bridge/headless-utf8-sdk-cold-7c430e99c363450294f16f00b5ae61d9.json',
        '38d14ee16b8b01bbef2a8560b2cf3ac68b60619d80dc51f65c0f84bb5f63ffbd')
    need(utf8proof.get('kind')=='OWNED_HEADLESS_UTF8_SDK_BINDING_COLD_CHECK' and utf8proof.get('correctedSourceSha256')==SOURCE_SHA
        and utf8proof.get('mainSha256')==MAIN_SHA and utf8proof.get('lookupExecuted') is True
        and utf8proof.get('goldStarted') is False and utf8proof.get('bridgeInvoked') is False
        and utf8proof.get('ownTemporaryDirectoryRemoved') is True and [x['exitCode'] for x in utf8proof['runs']]==[0,18],'UTF8_SDK_COLD_CHECK')
    sdkproof=_json(ROOT/'artifacts/designer-bridge/headless-raw-sdk-cold-a4903ba899ba4319aef144388ec7fc62.json',
        'e2aa4b3b13f1b69802f8399af5f1c2526e580d3ff065c4555fd0e6900f9f424d')
    need(sdkproof.get('kind')=='OWNED_HEADLESS_RAW_SDK_COLD_CHECK' and sdkproof.get('correctedSourceSha256')=='8687b91606ee9447e031f8a79eaea3c354814692aafde70b2c280b5e2c00e5bf'
        and sdkproof.get('mainSha256')==MAIN_SHA and sdkproof.get('compileFunctionOnly') is True
        and all(sdkproof.get(k) is False for k in ('bodyExecuted','contextCreated','goldStarted'))
        and sdkproof.get('ownTemporaryDirectoryRemoved') is True and [x['exitCode'] for x in sdkproof['runs']]==[103,0],'RAW_SDK_COLD_CHECK')
    proof=_json(ROOT/'artifacts/designer-bridge'/CHECK_NAME,CHECK_SHA)
    need(proof.get('kind')=='OWNED_HEADLESS_COMPARISON_COLD_CHECK' and proof.get('sourceSha256')=='355b9a4f019adbfae49352ca6b82b424123938423fdd038f6283f3ab5c28ac1e'
        and proof.get('carrierSourceSha256')=='701ff4126abcb58b75f2fbd575d7b21b2bbb3c7ee75b47df0463c775cdac2500'
        and proof.get('sourceMainSha256')==MAIN_SHA and proof.get('sourceScopeAdmitted') is False
        and proof.get('asPositive',{}).get('compileVerified') is True and proof['asPositive']['exitCode']==0
        and proof.get('asNegative',{}).get('compileVerified') is False and proof['asNegative']['exitCode']!=0
        and proof.get('cCompileExit')==0 and proof.get('cMissingScopeExit')!=0
        and proof.get('own32BitDllBinding')==dict(loaded=1,sameModule=1,exactExport=1)
        and proof.get('ownTemporaryDirectoryRemoved') is True
        and all(proof.get(k) is False for k in ('goldStarted','sdkScriptRunRequested','nativeBridgeCalled')),'COLD_CHECK')



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


def _claim_path(s):return ROOT/'artifacts/designer-bridge'/('owned-headless-comparison-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='OWNED_HEADLESS_COMPARISON_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
        actualSourceSha256=SOURCE_SHA,controllerSha256=s.plan['ownedHeadlessComparisonControllerSha256'],
        writerOperationId=q['operationId'],writerIntentSha256=c.digest(c.canonical(q)),packetSha256=q['packetSha256'],
        sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'],runtimeComparisonOnly=True)


def _check(s):
    need(type(s) is ReadOp and s._issuer is _ISSUER,'ISSUED_READ');_pins();p=s.plan;ctx=p['context']
    need(c.canonical(p)==s.plan_raw and p.get('ownedHeadlessComparisonControllerSha256')==c.digest(c.read(Path(__file__)))
        and p.get('ownedHeadlessComparisonProfile')==PROFILE and _authority(p) and p.get('actualSourceSha256')==SOURCE_SHA
        and p.get('writerAuthorized') is False and p.get('captureAuthorized') is False
        and type(p.get('applicationWrites')) is int and p['applicationWrites']==0
        and p.get('headlessScopeSha256')==s.scope_sha256 and p.get('readScopeSha256')==s.parent.review_sha256
        and ctx==s.parent.plan['context'],'PLAN_AUTHORITY')
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256'))==
        (48936,'01dd5d0180299126',8292,MAIN_SHA),'FIXED_NATIVE')
    q=reader._check_owner(s.parent);scope=_json(s.scope_path,s.scope_sha256)
    need(scope==s.scope and scope.get('kind')=='ROOT_OWNED_HEADLESS_COMPARISON_SCOPE' and scope.get('passed') is True
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
        '__NATIVE_HEADLESS_INTENT_PATH__':(out/INTENT_FILE).as_posix(),'__OWN_DLL_PATH__':(out/'Continuation.dll').as_posix()}
    for token,value in values.items():need(source.count(token)==1,'ONE_TOKEN');source=source.replace(token,value,1)
    header=files['sdk_probe_params.h'].decode();line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
    header=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(source,ensure_ascii=False))
    macros=dict(AH_CPP_EPOCH_OPERATION_ID=json.dumps(p['operationId']),AH_CPP_EPOCH_SCOPE_SHA256=json.dumps(s.scope_sha256),
                AH_CPP_EPOCH_RECEIPT_FILE='L'+json.dumps((out/EPOCH_FILE).as_posix()),AH_HPC_SCOPE_ADMITTED='1',
                AH_HPC_OPERATION_ID=json.dumps(p['operationId']),AH_HPC_SCOPE_SHA256=json.dumps(s.scope_sha256),
                AH_HPC_PROOF_FILE='L'+json.dumps((out/CORE_FILE).as_posix()))
    header+='\n'+''.join('#define '+key+' '+value+'\n' for key,value in macros.items())
    files['sdk_probe_params.h']=header.encode();files['Continuation.c']=carrier.render()
    ps=files['run-fixed.ps1'].decode('utf-8-sig');need(ps.count('version=233;')==2,'HOST_AUTHORITY_ANCHOR')
    auth='version=233;writerAuthorized=$false;'+''.join(k+'=$true;' for k in TRUE_AUTH)+''.join(k+'=$false;' for k in FALSE_AUTH)
    for key,value in _limits().items():auth+=key+'='+str(value)+';'
    auth+="ownedHeadlessComparisonProfile='"+PROFILE+"';actualSourceSha256='"+SOURCE_SHA+"';"
    files['run-fixed.ps1']=ps.replace('version=233;',auth).encode('utf-8-sig')
    files,identity=section_identity.with_section_identity(files,operation_kind='OWNED_HEADLESS',operation_id=p['operationId'])
    return files


def _authority_result(s):
    return dict(ownedHeadlessComparisonProfile=PROFILE,ownedHeadlessComparisonControllerSha256=s.plan['ownedHeadlessComparisonControllerSha256'],
        actualSourceSha256=SOURCE_SHA,scopeSha256=s.scope_sha256,readScopeSha256=s.parent.review_sha256,
        writerAuthorized=False,comparisonOnly=True,databaseUpdateAuthorized=False,updateAdmissionGranted=False,
        databaseApplyAuthorized=False,globalPendingClean=False,**_limits(),
        **{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


def prepare_root(scope_path,scope_sha256):
    _pins();path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=_json(path,scope_sha256)
    need(scope.get('kind')=='ROOT_OWNED_HEADLESS_COMPARISON_SCOPE' and scope.get('passed') is True and _authority(scope)
        and scope.get('actualSourceSha256')==SOURCE_SHA,'READ_SCOPE_BEFORE_OWNER')
    parent=previous._prepare_parent(scope['readScopePath'],scope['readScopeSha256']);p=dict(parent.plan);op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):p.pop(key)
    p.update(operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),ownedHeadlessComparisonProfile=PROFILE,
        ownedHeadlessComparisonControllerSha256=c.digest(c.read(Path(__file__))),actualSourceSha256=SOURCE_SHA,
        headlessScopeSha256=scope_sha256,readScopeSha256=parent.review_sha256,
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
    need(type(native) is dict and native.get('kind')=='OWNED_HEADLESS_COMPARISON_AS_NATIVE'
        and native.get('operationId')==s.plan['operationId'] and native.get('scopeSha256')==s.scope_sha256
        and native.get('typedHandlesCleared') is True and native.get('unknownRetain') is False
        and all(native.get(k) is False for k in ('fullPendingVerified','databaseUpdateAuthorized'))
        and all(type(native.get(k)) is int and native[k]==0 for k in ZERO_NATIVE),'AS_CLOSURE')
    attempts=native.get('bridgeAttempts');returned=native.get('bridgeReturned')
    need(type(attempts) is int and attempts in (0,1) and type(returned) is int and returned==attempts,'BRIDGE_COUNTS')
    if attempts==0:
        need(native.get('reason') not in ('NONE','NATIVE_EXCEPTION_OR_CLEANUP'),'ZERO_REFUSAL')
        return 'HEADLESS_REFUSED_BEFORE_BRIDGE'
    need(type(reserved) is dict and reserved.get('kind')=='OWNED_HEADLESS_COMPARISON_INTENT'
        and reserved.get('operationId')==s.plan['operationId'] and reserved.get('scopeSha256')==s.scope_sha256
        and native.get('nativeIntentWritten') is True and reserved.get('configurationReadOnly') is True
        and reserved.get('maximumFactoryCalls')==1 and reserved.get('maximumExecutions')==1,'NATIVE_INTENT')
    need(all(native.get(k) is True for k in ('beforeRootAndTargetsClean','afterRootAndTargetsClean'))
        and all(type(native.get(k)) is int and native[k]==3 for k in ('beforeTargetsClean','afterTargetsClean')),'ROOT_CLEAN')
    out=Path(s.plan['outputDirectory']);core=_json(out/CORE_FILE,bound=65536);exc=_json(out/EPOCH_FILE,bound=32768)
    need(core.get('kind')=='OWNED_HEADLESS_COMPARISON_CORE_NATIVE' and core.get('operationId')==s.plan['operationId']
        and core.get('scopeSha256')==s.scope_sha256 and type(core.get('phase')) is int and core['phase'] in (1,8)
        and all(type(core.get(k)) is int and core[k]==0 for k in ('ownedReferencesRemaining','sourceTransferInFlight','abiFault','repeatedAttempts',
                     'sourceWrites','configurationSaves','databaseUpdates','repositoryMutations','applicationTextOutputBytes'))
        and core.get('fullPendingVerified') is False and core.get('databaseUpdateAuthorized') is False,'CORE_CLOSURE')
    limits={'factoryAttempts':1,'factoryReturned':1,'executeAttempts':1,'executeReturned':1,'getterAttempts':2,'getterReturned':2,
            'addrefAttempts':4,'releaseAttempts':3,'projectionAttempts':1}
    need(type(core.get('attempts')) is int and core['attempts']==1
        and all(type(core.get(k)) is int and 0<=core[k]<=limit for k,limit in limits.items()),'CORE_COUNTS')
    if core['phase']==1:return 'HEADLESS_CORE_REFUSED_CLEAN'
    need(all(core[k]==limit for k,limit in limits.items()) and core.get('codeVerified') is True
        and core.get('reason')==0 and core.get('sourceTransferConsumed')==2 and core.get('mainSource')==344510268
        and core.get('databaseSource')==170975980 and core.get('completion')==1 and core.get('viewPointer')==0
        and type(core.get('selected')) is int and 0<core['selected']==core.get('visited')<=65536,'CORE_SUCCESS')
    need(core.get('treeError')==0 and core.get('treePasses')==2 and core.get('treeCoherent')==1
        and core.get('treeTraversalComplete')==1 and core.get('objectMask20Count')==0
        and core.get('objectFlagsObserved')==core['selected'] and type(core.get('treeNodes')) is int
        and 0<core['treeNodes']<=524288,'FULL_TREE')
    rows=core.get('rows');need(type(rows) is list and len(rows)==core.get('rowCount') and len(rows)<=256,'ROWS')
    expected={('176e2552-fd8b-4823-afc0-d17431f2fb7b','d5963243-262e-4398-b4d7-fb16d06484f6'),
              ('28ecdfc7-083e-4082-b272-efbf7152de5c','d5963243-262e-4398-b4d7-fb16d06484f6'),
              ('8daef957-4ae2-48a1-bf6c-b88163a076f5','8eb4fad1-1fa6-403e-970f-2c12dbb43e23')}
    leaves=set()
    for row in rows:
        need(type(row) is dict and type(row.get('kind')) is int and row['kind'] in (0,1,3)
            and row.get('change')==1 and type(row.get('depth')) is int and 0<=row['depth']<=256,'ROW_SCOPE')
        if row['kind']==3:
            need(row.get('hasPair')==1 and re.fullmatch('[0-9a-f]{64}',row.get('pairHex',''))
                and re.fullmatch('[0-9a-f]{32}',row.get('propertyHex','')),'PROPERTY_ROW')
            pair=bytes.fromhex(row['pairHex']);left=str(uuid.UUID(bytes_le=pair[:16]));right=str(uuid.UUID(bytes_le=pair[16:]))
            prop=str(uuid.UUID(bytes_le=bytes.fromhex(row['propertyHex'])))
            need(left==right and (left,prop) in expected and (left,prop) not in leaves,'FOREIGN_OR_DUPLICATE_LEAF');leaves.add((left,prop))
    need(leaves==expected and len(rows)==8,'ONLY_THREE_PENDING_RESOURCES')
    try:
        epoch.classify_type_epoch(exc,operation_id=s.plan['operationId'],scope_sha256=s.scope_sha256,process_id=48936,
            execute_thread_id=8292,callback_known=True,callback_sdk_rc=0,target_identity_verified=True)
    except ValueError:return 'HEADLESS_OBSERVED_COMPARISON_REJECTED'
    return 'HEADLESS_COMPARISON_THREE_RESOURCES_VERIFIED'


def _unknown(s,reason):
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=s.plan['operationId'],reason=reason,
        retryAuthorized=False,parentWriterOperationId=s.parent.scope['writerOperationId'],**_authority_result(s))
    c.write_new(Path(s.plan['outputDirectory'])/'unknown.json',result);return result


def run_root_once(s,review_path,review_sha256):
    _check(s);need(s.phase=='STAGED','RUN_PHASE');p=s.plan;ctx=p['context'];out=Path(p['outputDirectory']);ns=s.private
    build=ns['require_stage'](p);review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind')=='ROOT_OWNED_HEADLESS_COMPARISON_RUN' and review.get('passed') is True and _authority(review)
        and review.get('planSha256')==c.digest(s.plan_raw) and review.get('buildSha256')==c.digest(c.canonical(build))
        and review.get('scopeSha256')==s.scope_sha256 and review.get('readScopeSha256')==s.parent.review_sha256
        and review.get('actualSourceSha256')==SOURCE_SHA,'ROOT_RUN')
    ns['_no_pending'](context=ctx)
    need(not any((out/n).exists() for n in ('intent.json','host-identity.json','host-result.json','result.json','unknown.json',
        'sdk-receipt.json',NATIVE_FILE,INTENT_FILE,CORE_FILE,EPOCH_FILE)),'ONE_ATTEMPT')
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
                    releasePacketAllowed=False,releaseRefsAllowed=False,headlessComparisonReliable=status=='HEADLESS_COMPARISON_THREE_RESOURCES_VERIFIED',**_authority_result(s))
                c.write_new(out/'result.json',result);s.phase='KNOWN_TERMINAL_RETAIN_PARENT';return result
            break
        if s.host.poll() is not None:break
        time.sleep(.05)
    return _unknown(s,'HOST_OR_SDK_TERMINAL_UNPROVEN')
