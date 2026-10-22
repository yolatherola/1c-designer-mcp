"""One explicit stock Save3 for a root-reviewed retained partial writer.

No source setter, packet transfer, forced flag, DB update or ref release exists
here. The original packet owner remains alive. Save is never inferred from SDK0;
separate stored-resource and clean-live observations must follow this command.
"""
from dataclasses import dataclass
from pathlib import Path
import json
import re
import subprocess
import time
import uuid
import sheet_notify_pending_read as reader
import editor_modules_pending_save_recipe as recipe

c=reader.c
ROOT=c.ROOT
HERE=c.HERE
SOURCE_SHA='66e0cf5fd3c61e1a04303d8f8c9efbed88ee65cbdcee66cde326ad50f0df47f2'
READER_SHA='825e7926d8eb8ab360d6413251d661f64be415e97c6ff3073b97ff77d39b4d7a'
RECIPE_SHA='cc64a68cc0bb37acd02b70789d0f4aa4004a81e75ea15af126bed1589e423ce2'
CHECK_NAME='editor-modules-pending-save3-check-only-141ab770a1e04f24821dd8c82567cfc9.json'
CHECK_SHA='bdd39d7c1ff80b177e79fd91689269021aead7e99315793807d800a0765c4818'
PROFILE='MODULE_EDITORS_DIRTY_TEMPLATE_CLEAN_STOCK_SAVE3'
NATIVE_FILE='editor-modules-pending-save3-proof.json'
BASE_CONTROLLER_SHA='cea10696c2782276714c07521f6e3ae528350e2ee4de0377f9e894341e973d24'
EDITOR_OPERATION='167a39ffe78f48d7bf14254b52b0a18a'
EDITOR_NATIVE_SHA='a336c1a584644a0802d2d453dee7213a357a3419caedfc06a3d78753e9ca10f6'
EDITOR_SOURCE_SHA='30fec2039496a5e15e630b73f0c5c80a50f716f3f26b8df1e94c771f322983d2'
EDITOR_CONTROLLER_SHA='6785592f3760450638f296a474e17f668772e8a9179066141ed144eeafa86eec'
OLD_SAVE_OPERATION='8487258702f54509ad6dfb05249d622f'
OLD_SAVE_NATIVE_SHA='84a32af2a1989a2241f73a6b390dd503f09074b847e246533d205e143f7460de'
OLD_SAVE_SOURCE_SHA='16291011d4a6f5c2e3e8b90828ea4595ff954b99ee3de6b21a29c78a72c48330'
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('EDITOR_MODULES_SAVE_'+code)


def _json(path,pin=None,bound=32768):return reader._json(path,pin,bound)


def _pins():
    for name,pin in [('sheet_notify_pending_save.py',BASE_CONTROLLER_SHA),
            ('same_text_editor_no_tree_commit.py',EDITOR_CONTROLLER_SHA),
            ('sheet_notify_pending_read.py',READER_SHA),('editor_modules_pending_save_recipe.py',RECIPE_SHA)]:
        need(c.digest(c.read(HERE/name))==pin,'TOOL_PIN')
    need(c.digest(recipe.derive_source())==SOURCE_SHA,'FIXED_SOURCE')
    check=_json(ROOT/'artifacts/designer-bridge'/CHECK_NAME,CHECK_SHA)
    need(check.get('kind')=='EDITOR_MODULES_PENDING_SAVE3_CHECK_ONLY'
        and check.get('sourceSha256')==SOURCE_SHA and check.get('positive',{}).get('compileVerified') is True
        and type(check.get('positive',{}).get('exitCode')) is int and check['positive']['exitCode']==0
        and check.get('negative',{}).get('compileVerified') is False
        and type(check.get('negative',{}).get('exitCode')) is int and check['negative']['exitCode']!=0
        and check.get('negativeCoverage') is True
        and check.get('ownRuntimeRemoved') is True and check.get('goldStarted') is False
        and check.get('saveScopeAdmitted') is False and check.get('pendingEditorsVerifiedAdmitted') is False,'COLD_CHECK')


@dataclass(slots=True)
class Save:
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


def _observation(s,operation,source_sha,native_sha):
    need(type(operation) is str and c.HEX32.fullmatch(operation),'OBSERVATION_ID')
    out=ROOT/'build'/('designer-hot-v233-'+operation)
    p=_json(out/'plan.json');n=_json(out/'runner-editors-proof.json',native_sha);sdk=_json(out/'result.json')
    need(p.get('context')==s.parent.plan['context'] and p.get('actualReadSourceSha256')==source_sha
        and p.get('parentWriterOperationId')==s.parent.scope['writerOperationId']
        and p.get('pendingScopeSha256')==s.parent.review_sha256 and sdk.get('planSha256')==c.digest(c.canonical(p))
        and sdk.get('actualReadSourceSha256')==source_sha and type(sdk.get('sdkResult')) is int and sdk['sdkResult']==0
        and all(sdk.get(k) is True for k in ('knownTerminal','hookWorkersReleased','targetIdentityVerified','probeProofPresent')),
        'OBSERVATION_SCOPE')
    need(n.get('reason')=='NONE' and all(type(n.get(k)) is int and n[k]==0 for k in
        ('sourceWrites','metadataWrites','configurationSaves','databaseUpdates','repositoryMutations')),'OBSERVATION_READ_ONLY')
    return n


def _claim(s):
    q=reader._check_owner(s.parent);ctx=s.plan['context']
    return dict(kind='EDITOR_MODULES_SAVE3_CLAIM',operationId=s.plan['operationId'],action='SAVE3',
        writerIntentSha256=c.digest(c.canonical(q)),writerOperationId=q['operationId'],packetSha256=q['packetSha256'],
        pid=ctx['processId'],birth=ctx['birth'],sessionNonce=ctx['heldNonce'],
        editorOperationId=EDITOR_OPERATION,editorNativeSha256=EDITOR_NATIVE_SHA,actualSaveSourceSha256=SOURCE_SHA)


def _claim_path(s):return ROOT/'build'/('designer-hot-v233-'+EDITOR_OPERATION)/'editor-modules-save3-claim.json'


def _editor_episode(s,q):
    """Require the actual claimed two-setter editor episode, not SDK0 alone."""
    scope=s.scope;ctx=s.plan['context']
    need(scope.get('editorCommitOperationId')==EDITOR_OPERATION
        and scope.get('editorCommitNativeSha256')==EDITOR_NATIVE_SHA,'EDITOR_EPISODE_SCOPE')
    out=ROOT/'build'/('designer-hot-v233-'+EDITOR_OPERATION)
    p=_json(out/'plan.json');intent=_json(out/'intent.json');sdk=_json(out/'result.json')
    n=_json(out/'same-text-editor-no-tree-proof.json',EDITOR_NATIVE_SHA)
    claim=_json(ROOT/'build'/('designer-writer-v263-'+q['operationId'])/'same-text-editor-no-tree-commit-claim.json')
    need(claim==dict(kind='SAME_TEXT_EDITOR_NO_TREE_COMMIT_CLAIM',operationId=EDITOR_OPERATION,
        writerOperationId=q['operationId'],writerIntentSha256=c.digest(c.canonical(q)),packetSha256=q['packetSha256'],
        scopeSha256=p.get('commitScopeSha256'),pid=ctx['processId'],birth=ctx['birth'],actualSourceSha256=EDITOR_SOURCE_SHA)
        and p.get('operationId')==EDITOR_OPERATION and p.get('context')==ctx
        and p.get('commitControllerSha256')==EDITOR_CONTROLLER_SHA and p.get('actualSourceSha256')==EDITOR_SOURCE_SHA
        and p.get('editorCommitProfile')=='SAME_TEXT_PUBLISHED_EDITOR_NO_TREE_COMMIT'
        and all(p.get(k) is True for k in ('writerAuthorized','sourceWritesAuthorized','sameLiveSourceOnly'))
        and all(p.get(k) is False for k in ('configurationSavesAuthorized','databaseUpdatesAuthorized',
            'repositoryMutationsAuthorized','releaseResourcesAuthorized')),'EDITOR_CLAIM')
    plan_sha=c.digest(c.canonical(p))
    need(intent.get('operationId')==EDITOR_OPERATION and intent.get('planSha256')==plan_sha
        and intent.get('actualSourceSha256')==EDITOR_SOURCE_SHA and intent.get('parentWriterOperationId')==q['operationId']
        and intent.get('sourceWritesAuthorized') is True and intent.get('sameLiveSourceOnly') is True
        and intent.get('configurationSavesAuthorized') is False
        and sdk.get('planSha256')==plan_sha and sdk.get('actualSourceSha256')==EDITOR_SOURCE_SHA
        and sdk.get('parentWriterOperationId')==q['operationId'] and sdk.get('threadId')==ctx['guiThreadId']
        and type(sdk.get('sdkResult')) is int and sdk['sdkResult']==0
        and all(sdk.get(k) is True for k in ('knownTerminal','hookWorkersReleased','targetIdentityVerified','probeProofPresent'))
        and n.get('kind')=='SAME_TEXT_EDITOR_COMMIT' and n.get('operationId')==EDITOR_OPERATION
        and n.get('scopeSha256')==claim['scopeSha256'] and n.get('status')=='EDITOR_RECOMMIT_RETURNED'
        and n.get('reason')=='NONE' and all(n.get(k) is True for k in ('prepared','selectionRangesRestored',
            'finalFlagsObserved','sameSourceInputOnly')) and n.get('rootDirty') is False and n.get('uiDirty') is True
        and all(type(n.get(k)) is int and n[k]==2 for k in ('setterAttempts','setterReturns','sourceReadbacks'))
        and all(type(n.get(k)) is int and n[k]==0 for k in ('rawFlagWrites','configurationSaves',
            'databaseUpdates','repositoryMutations')),'EDITOR_APPLIED')
    rows=n.get('targets')
    need(type(rows) is list and len(rows)==2 and [r.get('objectId') for r in rows]==[v['objectId'] for v in q['targets'][1:]],
        'EDITOR_TARGETS')
    for row,expected in zip(rows,q['replacementCodeSha256'],strict=True):
        need(row.get('expectedSourceSha256')==expected and row.get('sourceEqual') is True
            and row.get('objectDirty') is False and row.get('documentDirty') is True,'EDITOR_SOURCE')


def _old_save_consumed(s,q):
    """The original Save claim stays consumed; this is a new editor episode."""
    ctx=s.plan['context'];scope=s.scope
    need(scope.get('priorSaveOperationId')==OLD_SAVE_OPERATION
        and scope.get('priorSaveNativeSha256')==OLD_SAVE_NATIVE_SHA,'OLD_SAVE_SCOPE')
    claim=_json(ROOT/'build'/('designer-writer-v263-'+q['operationId'])/'save3-followup-claim.json')
    need(claim==dict(kind='OWN_WRITER_FOLLOWUP_CLAIM',operationId=OLD_SAVE_OPERATION,action='SAVE3',
        writerIntentSha256=c.digest(c.canonical(q)),writerOperationId=q['operationId'],packetSha256=q['packetSha256'],
        pid=ctx['processId'],birth=ctx['birth'],sessionNonce=ctx['heldNonce']),'OLD_SAVE_CLAIM')
    out=ROOT/'build'/('designer-hot-v233-'+OLD_SAVE_OPERATION)
    p=_json(out/'plan.json');sdk=_json(out/'result.json');n=_json(out/'known-pending-save3-proof.json',OLD_SAVE_NATIVE_SHA)
    need(p.get('context')==ctx and p.get('actualSaveSourceSha256')==OLD_SAVE_SOURCE_SHA
        and p.get('pendingSaveControllerSha256')==BASE_CONTROLLER_SHA
        and sdk.get('planSha256')==c.digest(c.canonical(p)) and type(sdk.get('sdkResult')) is int and sdk['sdkResult']==0
        and all(sdk.get(k) is True for k in ('knownTerminal','hookWorkersReleased','targetIdentityVerified'))
        and n.get('saveOperationId')==OLD_SAVE_OPERATION and n.get('writerOperationId')==q['operationId']
        and n.get('packetSha256')==q['packetSha256'] and n.get('status')=='SAVE_RETURNED_CLEAN_PENDING_COLD_READ'
        and n.get('reason')=='NONE' and type(n.get('dispatchAttempts')) is int and n['dispatchAttempts']==1
        and n.get('nativeCleanAfterReturn') is True,'OLD_SAVE_CONSUMED')


def _lease(s):
    from run_repository_observe import lease_exists
    from completed_gold_owned_document_structure_v139 import _route_count
    ctx=s.plan['context'];boot=_json(ROOT/'artifacts/designer-bridge'/('sheet-notify-bootstrap-result-'+ctx['heldNonce']+'.json'),bound=65536)
    b=boot.get('context',{});owner=s.scope.get('goldLeaseOwner')
    need(type(owner) is str and c.HEX32.fullmatch(owner) and boot.get('passed') is True
        and (b.get('processId'),b.get('processCreationFileTimeUtc'),b.get('leaseOwner'))==
            (ctx['processId'],ctx['birth'],owner) and lease_exists(owner) and _route_count()==1,'EXCLUSIVE_GOLD_ROUTE')


def _check(s):
    need(type(s) is Save and s._issuer is _ISSUER,'ISSUED_SAVE');_pins()
    need(c.digest(c.read(Path(__file__)))==s.plan['pendingSaveControllerSha256']
        and c.canonical(s.plan)==s.plan_raw,'SEALED_SAVE_PLAN')
    need(s.plan['context']==s.parent.plan['context'] and s.plan.get('pendingSaveProfile')==PROFILE
        and s.plan.get('actualSaveSourceSha256')==SOURCE_SHA and s.plan.get('configurationSaveOnceAuthorized') is True
        and s.plan.get('templateWritesAuthorized') is False
        and all(s.plan.get(k) is False for k in ('sourceWritesAuthorized','databaseUpdatesAuthorized',
            'repositoryMutationsAuthorized','releaseResourcesAuthorized')),'PLAN_SAVE_AUTHORITY')
    q=reader._check_owner(s.parent);scope=_json(s.scope_path,s.scope_sha256)
    need(scope==s.scope and scope.get('kind')=='ROOT_EDITOR_MODULES_PENDING_SAVE3_SCOPE' and scope.get('passed') is True
        and scope.get('configurationSaveOnceAuthorized') is True and scope.get('actualSaveSourceSha256')==SOURCE_SHA
        and scope.get('readScopeSha256')==s.parent.review_sha256
        and scope.get('templateWritesAuthorized') is False
        and all(scope.get(k) is False for k in ('sourceWritesAuthorized','databaseUpdatesAuthorized',
            'repositoryMutationsAuthorized','releaseResourcesAuthorized','configurationExportsAuthorized','configurationImportsAuthorized')),
        'ROOT_SCOPE')
    _editor_episode(s,q);_old_save_consumed(s,q)
    ids=[target['objectId'] for target in q['targets']]
    stored=_observation(s,scope['storedReadOperationId'],reader.RESOURCE_SOURCE_SHA,scope['storedReadNativeSha256'])
    rows=stored.get('targets')
    need(stored.get('status')=='STORED_RESOURCES_OBSERVED' and stored.get('resourcesRead')==3
        and type(rows) is list and len(rows)==3 and [r.get('objectId') for r in rows]==ids
        and rows[0].get('plainSha256')=='3f413e18fe4e6f6bb8eeec10e8e2b7f54e1b0449f441779f8f861be1ab6d6ea7'
        and [r.get('textLfNoBomSha256') for r in rows[1:]]==q['originalCodeSha256'],'STORED_ORIGINALS')
    claim=_claim_path(s)
    if s.phase in ('PREPARED','STAGED'):need(not claim.exists(),'SAVE_ALREADY_CLAIMED')
    else:need(_json(claim)==_claim(s),'EXACT_OWN_CLAIM')
    return q


def _source(s,q):
    text=recipe.derive_source().decode();p=s.plan;ctx=p['context'];out=Path(p['outputDirectory'])
    native=_json(ROOT/'build'/('designer-writer-v263-'+q['operationId'])/'composite-proof.json')
    values={'__OWN_STAND_SCOPE_ADMITTED__':'true','__PENDING_EDITORS_VERIFIED_ADMITTED__':'true',
        '__SAVE_NATIVE_PID__':str(ctx['processId']),'__SAVE_GUI_THREAD__':str(ctx['guiThreadId']),
        '__SAVE_OPERATION_ID__':p['operationId'],'__WRITER_OPERATION_ID__':q['operationId'],
        '__WRITER_PACKET_SHA256__':q['packetSha256'],'__FOLLOWUP_SCOPE_SHA256__':s.scope_sha256,
        '__PRINT_SHA256__':q['replacementCodeSha256'][0],'__REGISTRAR_SHA256__':q['replacementCodeSha256'][1],
        '__EXPECTED_TEMPLATE_DOCUMENT__':str(native['documentPointer']),
        '__SAVE_RESERVED_PATH__':(out/'save-reserved.json').as_posix(),'__PROOF_PATH__':(out/NATIVE_FILE).as_posix()}
    need(set(re.findall(r'__[A-Z][A-Z0-9_]+__',text))==set(values),'SOURCE_PLACEHOLDERS')
    for token,value in values.items():
        need(text.count(token)==(2 if token in ('__SAVE_NATIVE_PID__','__SAVE_GUI_THREAD__') else 1),'ONE_TOKEN')
        text=text.replace(token,value)
    return text


def prepare_root(scope_path,scope_sha256):
    """Issue one Save capability after read-only validation of retained evidence."""
    _pins();path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=_json(path,scope_sha256)
    parent=reader.prepare_root(scope['readScopePath'],scope['readScopeSha256'])
    # Base is an audit capability only: it is never staged or run as a read.
    p=dict(parent.plan);op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):
        p.pop(key)
    p.update(operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),
        pendingSaveProfile=PROFILE,actualSaveSourceSha256=SOURCE_SHA,pendingSaveControllerSha256=c.digest(c.read(Path(__file__))),
        pendingSaveScopeSha256=scope_sha256,configurationSaveOnceAuthorized=True,sourceWritesAuthorized=False,
        templateWritesAuthorized=False,databaseUpdatesAuthorized=False,repositoryMutationsAuthorized=False,releaseResourcesAuthorized=False)
    s=Save(_ISSUER,parent,scope,path,scope_sha256,p,c.canonical(p),{});_check(s);_lease(s)
    ns=reader._namespace(parent)
    def fresh(plan):_check(s);need(plan==s.plan,'FRESH_PLAN');c._fresh(plan);_lease(s)
    def render(plan,raw):
        q=_check(s);need(plan==s.plan,'RENDER_PLAN');files=c.render(plan,raw)
        text=_source(s,q);header=files['sdk_probe_params.h'].decode()
        line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
        header=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(text,ensure_ascii=False))
        files['sdk_probe_params.h']=('#define AH_ROOT_STOCK_SAVE_ONCE 1\n'+header).encode()
        files['Continuation.c']=c._replace_once(files['Continuation.c'].decode(),
            '#include "sdk_probe_params.h"','#include "sdk_probe_params.h"\n'
            '#if AH_ROOT_STOCK_SAVE_ONCE != 1\n#error ROOT_STOCK_SAVE_REQUIRED\n#endif').encode()
        ps=files['run-fixed.ps1'].decode('utf-8-sig');need(ps.count('version=233;')==2,'HOST_SCOPE_ANCHOR')
        ps=ps.replace('version=233;','version=233;configurationSaveOnceAuthorized=$true;sourceWritesAuthorized=$false;'
            "pendingSaveProfile='"+PROFILE+"';actualSaveSourceSha256='"+SOURCE_SHA+"';")
        files['run-fixed.ps1']=ps.encode('utf-8-sig');return files
    ns.update(_fresh=fresh,render=render);s.private=ns;return s


def stage_root(s):
    """Compile fixed carrier; does not issue Save or load a DLL into Gold."""
    _check(s);need(s.phase=='PREPARED','STAGE_PHASE')
    proof=s.private['stage_private'](s.plan,dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',
        rootAuthorized=True,planSha256=c.digest(s.plan_raw)))
    s.phase='STAGED';return proof


def run_root_once(s,review_path,review_sha256):
    """Issue exactly one reviewed stock command, retaining every original/ref."""
    _check(s);need(s.phase=='STAGED','RUN_PHASE');p=s.plan;ctx=p['context'];ns=s.private
    out=Path(p['outputDirectory']);build=ns['require_stage'](p)
    review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind')=='ROOT_EDITOR_MODULES_PENDING_SAVE3_RUN' and review.get('passed') is True
        and review.get('planSha256')==c.digest(s.plan_raw) and review.get('buildSha256')==c.digest(c.canonical(build))
        and review.get('actualSaveSourceSha256')==SOURCE_SHA and review.get('scopeSha256')==s.scope_sha256
        and review.get('configurationSaveOnceAuthorized') is True and all(review.get(k) is False for k in
            ('sourceWritesAuthorized','templateWritesAuthorized','databaseUpdatesAuthorized','repositoryMutationsAuthorized','releaseResourcesAuthorized')),'RUN_REVIEW')
    ns['_no_pending'](context=ctx)
    need(not any((out/n).exists() for n in ('intent.json','host-identity.json','host-result.json','result.json','unknown.json',NATIVE_FILE)),
        'ONE_ATTEMPT')
    claim=_claim(s);c.write_new(_claim_path(s),claim);s.phase='DISPATCHED_RETAIN'
    intent=dict(version=233,operationId=p['operationId'],planSha256=c.digest(s.plan_raw),pendingSaveProfile=PROFILE,
        actualSaveSourceSha256=SOURCE_SHA,rootSaveReviewSha256=review_sha256,parentWriterOperationId=claim['writerOperationId'],
        configurationSaveOnceAuthorized=True,sourceWritesAuthorized=False,databaseUpdatesAuthorized=False,repositoryMutationsAuthorized=False)
    c.write_new(out/'intent.json',intent);ns['_fresh'](p)
    s.host=subprocess.Popen([str(reader.writer.PS),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(out/'run-fixed.ps1')],
        cwd=out,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    c.write_new(out/'host-identity.json',reader.writer._host_identity(s.host));deadline=time.monotonic()+55
    while time.monotonic()<deadline:
        if (out/'host-result.json').is_file():
            try:result=_json(out/'host-result.json',bound=8192)
            except (OSError,ValueError):time.sleep(.05);continue
            if result.get('version')==233 and result.get('knownTerminal') is True and result.get('hookWorkersReleased') is True:
                try:s.host.wait(timeout=5)
                except subprocess.TimeoutExpired:break
                need(s.host.returncode==0 and result.get('threadId')==ctx['guiThreadId']
                    and type(result.get('sdkResult')) is int,'HOST_TERMINAL')
                ns['_fresh'](p)
                result.update(planSha256=c.digest(s.plan_raw),targetIdentityVerified=True,probe=p['probe'],policyProofPresent=False,
                    probeProofPresent=(out/NATIVE_FILE).is_file(),nativeInjectionPerformed=True,pendingSaveProfile=PROFILE,
                    actualSaveSourceSha256=SOURCE_SHA,parentWriterOperationId=claim['writerOperationId'],
                    savedMainVerified=False,releasePacketAllowed=False,releaseRefsAllowed=False,retryAuthorized=False)
                c.write_new(out/'result.json',result);s.phase='SDK_TERMINAL_SAVE_UNVERIFIED_RETAIN';return result
            break
        if s.host.poll() is not None:break
        time.sleep(.05)
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=p['operationId'],
        targetProcessId=ctx['processId'],hostProcessId=s.host.pid,retryAuthorized=False)
    c.write_new(out/'unknown.json',result);return result
