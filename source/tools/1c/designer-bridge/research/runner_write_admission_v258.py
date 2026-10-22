"""Exact-three-property admission; optional bounded technical closure read.

Root injects a fresh typed readiness result from its read-only collector. A
proof hash is a provenance join, not authentication: root reviews that reader.
Current250 never proved native permission; represent it as PENDING. This does
not invent a global pending iterator or grant Save/DB/repository permission.
No SDK/process/write executor. Only nonlegacy main review reads fixed265
metadata/current technical source; application bodies remain RAM-only.
"""
from dataclasses import dataclass
import hashlib
import json
import current_main_closure_v265 as closure265
from ram_payload_v237 import EditPacket,PacketProof,packet_proof,ROOT_ID,TEMPLATE_ID,MODULE_IDS,PROPERTY_ID
from ram_transport_v238 import Receipt,Lease

ROUTE='RUNNER_COMPOSITE_V249_WRITE'
COMPOSITE_SHA='64fb6aeabcc5e1c24f091e81bbdd85e7fe8821a3a621fcced4c521ab6e130b07'
CODEC_SHA='453df9a9c41ee4bb5068b15e058a2449c6f88ee9405b7300c24cf58b8421ee79'
TRANSPORT_SHA='47c1609b8993ca3e32491aaecbf0c45658fd7fa9789987a92dbed8306030e4bc'
MAIN_SHA='64d37425553b75c6465aef5c194f327fb7e75399ec682f686fa7b658f7a4ad66'
CLOSURE_REVIEWER_SHA='b588f19f33f68c3081afc092a22d776eb079bffaaa77cd016f124ba8f6310ef2'
NOTIFY_ROUTE='RUNNER_SHEET_NOTIFY_WRITE'
NOTIFY_COMPOSITE_SHA='307ea65c71871347cc63d3b305bc0c2ba057d3a5076a3b7cd04346f0022286bb'
NOTIFY_CLOSURE_REVIEWER_SHA='472dcd9f76ea1a347330aeaacb2455df0841219f95d7560c6a1aa5d07071e3aa'
TEMPLATE_PROPERTY='8eb4fad1-1fa6-403e-970f-2c12dbb43e23'
TEMPLATE_BEFORE='6d20f90eed3d8656fb669dcbd2701155eb481e839af968398597f6959a4842ed'
TEMPLATE_AFTER='3f413e18fe4e6f6bb8eeec10e8e2b7f54e1b0449f441779f8f861be1ab6d6ea7'
ORIGINAL_SHA=('506fe9bd7d1ade475a54dd4bfabb22f82d91a634b2477f44fdcc38b96f9417b6',
              'c5b596a38e554aa34e1e1adba527e45db35516b8e72772c6724645ed481b81ba')
ORIGINAL_LENGTH=(102426,39129)
TARGETS=((TEMPLATE_ID,TEMPLATE_PROPERTY),(MODULE_IDS[0],PROPERTY_ID),(MODULE_IDS[1],PROPERTY_ID))


def _need(ok,code):
    if not ok:raise ValueError('V258_'+code)


def _hex(value,size):
    return type(value) is str and len(value)==size and all(c in '0123456789abcdef' for c in value)


def _sha(value):_need(_hex(value,64),'PROOF_SHA256')


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


@dataclass(frozen=True,slots=True)
class Session:
    nonce:str
    pid:int
    birth:str
    gui_thread:int
    generation:int
    revision:int
    main_sha256:str=MAIN_SHA


@dataclass(frozen=True,slots=True)
class MainClosureReview:
    # Hash of a fixed root265 artifact. Constructor/typed fields alone do not
    # validate it; every request re-reads it and recomputes current closure.
    proof_sha256:str
    profile:str='LEGACY_249'


@dataclass(frozen=True,slots=True)
class Review:
    route:str
    operation_id:str
    packet_sha256:str
    composite_sha256:str
    main_sha256:str
    review_sha256:str
    compile_proof_sha256:str
    compile_result:int
    prepare_calls:int
    execute_calls:int
    function_released:bool|None
    writer_authorized:bool
    policy_reader_sha256:str|None=None
    compile_mode:str='LIVE_COMPILE_FUNCTION_RELEASED'
    standalone_pid:int|None=None
    standalone_birth:str|None=None
    standalone_process_exit:int|None=None
    standalone_terminal_gone:bool=False
    no_script_run:bool=False
    live_context_used:bool=True
    standalone_sync_wait:bool=False
    main_closure:MainClosureReview|None=None
    composition_profile:str='LEGACY_249'


@dataclass(frozen=True,slots=True)
class ReadinessRequest:
    session:Session
    receipt:Receipt
    packet:PacketProof
    review:Review


@dataclass(frozen=True,slots=True)
class TargetState:
    object_id:str
    property_id:str
    helper_sha256:str
    editor_sha256:str
    source_bytes:int
    object_clean:bool
    editor_clean:bool
    read_only:bool
    editor_bound:bool
    ownership:str
    repository_version:int


@dataclass(frozen=True,slots=True)
class TemplatePermission:
    # CURRENT_NATIVE_POLICY requires a real current query, not250/cachemode.
    status:str
    object_id:str
    property_id:str
    proof_sha256:str|None
    reader_sha256:str|None
    query_performed:bool
    result_read_only:bool
    document_bound:bool
    repeated:bool


@dataclass(frozen=True,slots=True)
class FreshReadiness:
    operation_id:str
    session:Session
    packet_sha256:str
    observation_sequence:int
    proof_sha256:str
    identity_verified:bool
    root_clean:bool
    ui_clean:bool
    targets:tuple
    template_permission:TemplatePermission


def _session(s):
    _need(type(s) is Session and _hex(s.nonce,32) and type(s.pid) is int and 0<s.pid<2**32
          and _hex(s.birth,16) and int(s.birth,16)>0 and type(s.gui_thread) is int
          and 0<s.gui_thread<2**32 and type(s.generation) is int and s.generation>0
          and type(s.revision) is int and s.revision>0,'SESSION')
    _sha(s.main_sha256)


def verify_main_closure(session,proof):
    """Re-read fixed265 root proof and actual current technical main/SDK.

    Metadata-only file reads; no native/PID/lease or writer permission query.
    FreshReadiness must still prove the exact live session before admission.
    No caller source/path/main override or authorizing bool is accepted.
    """
    _session(session)
    _need(type(proof) is MainClosureReview,'MAIN_CLOSURE_NOT_REVIEWED');_sha(proof.proof_sha256)
    _need(proof.profile in ('LEGACY_249','SHEET_NOTIFY'),'MAIN_CLOSURE_PROFILE')
    if proof.profile=='SHEET_NOTIFY':return _verify_notify_main_closure(session,proof)
    try:
        path=closure265.HERE/'current_main_closure_v265.py'
        _need(hashlib.sha256(closure265._read(path)).hexdigest()==CLOSURE_REVIEWER_SHA,'CLOSURE_REVIEWER_PIN')
        artifact=closure265.ROOT/'artifacts/designer-bridge'/('v265-current-main-closure-'+session.nonce+'.json')
        raw=closure265._read(artifact,32768)
        _need(hashlib.sha256(raw).hexdigest()==proof.proof_sha256,'CLOSURE_ARTIFACT_PIN')
        def pairs(items):
            result={}
            for key,value in items:
                _need(key not in result,'CLOSURE_DUPLICATE_JSON');result[key]=value
            return result
        recorded=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:_need(False,'CLOSURE_NONFINITE'))
        current=closure265.review_current(session.nonce)
        _need(set(recorded)==set(current)|{'reviewProducerSha256','reviewTestsSha256'},'CLOSURE_PROOF_SHAPE')
        _need(recorded['reviewProducerSha256']==CLOSURE_REVIEWER_SHA,'CLOSURE_PRODUCER_PIN')
        _sha(recorded['reviewTestsSha256'])
        _need(canonical({key:recorded[key] for key in current})==canonical(current),'CLOSURE_RECOMPUTE')
        _need(current['passed'] is True and current['heldNonce']==session.nonce
              and type(current['processId']) is int and current['processId']==session.pid
              and current['birth']==session.birth and current['mainSha256']==session.main_sha256
              and current['oldMainSha256']==MAIN_SHA and current['derivedSourceSha256']==COMPOSITE_SHA
              and current['sourceManifestSha256']==closure265.SOURCE536
              and current['sdkSha256']==closure265.SDK_PINS,'CLOSURE_CONTEXT')
        compared=current['comparison']
        _need(compared['directFreeCalls']==27 and compared['directAsFunctions']==25
              and compared['transitiveFunctions']==57
              and compared['transitiveByteEqual']+compared['diagnosticPathRelocations']==57
              and current['directWholeFunctionsByteEqual'] is True
              and current['transitiveWholeFunctionsReviewed'] is True,'CLOSURE_COMPLETE')
        return dict(proofSha256=proof.proof_sha256,mainSha256=session.main_sha256,
                    sourceManifestSha256=current['sourceManifestSha256'],writerAuthorized=False,liveFreshnessVerified=False)
    except (OSError,KeyError,TypeError,UnicodeError,json.JSONDecodeError):
        raise ValueError('V258_MAIN_CLOSURE_NOT_REVIEWED') from None


def _verify_notify_main_closure(session,proof):
    """A distinct producer/profile is mandatory for the added native helper."""
    try:
        producer=closure265.HERE/'sheet_notify_main_closure.py'
        _need(hashlib.sha256(closure265._read(producer)).hexdigest()==NOTIFY_CLOSURE_REVIEWER_SHA,
              'NOTIFY_CLOSURE_PRODUCER_PIN')
        import sheet_notify_main_closure as notify
        path=closure265.ROOT/'artifacts/designer-bridge'/('sheet-notify-current-main-closure-'+session.nonce+'.json')
        raw=closure265._read(path,65536)
        _need(hashlib.sha256(raw).hexdigest()==proof.proof_sha256,'NOTIFY_CLOSURE_ARTIFACT_PIN')
        _,recorded=notify._json(path,65536);current=notify.review_current(session.nonce)
        _need(set(recorded)==set(current)|{'reviewProducerSha256','reviewTestsSha256'}
              and recorded['reviewProducerSha256']==NOTIFY_CLOSURE_REVIEWER_SHA,'NOTIFY_CLOSURE_SHAPE')
        _sha(recorded['reviewTestsSha256'])
        _need(canonical({key:recorded[key] for key in current})==canonical(current),'NOTIFY_CLOSURE_RECOMPUTE')
        _need(current['passed'] is True and current['nonce']==session.nonce
              and type(current['processId']) is int and current['processId']==session.pid
              and current['birth']==session.birth and current['mainSha256']==session.main_sha256
              and current['compositeSha256']==NOTIFY_COMPOSITE_SHA
              and current['compositeEntry']=='ahRunnerCompositeSheetNotify'
              and current['baselineSourceManifestSha256']==closure265.SOURCE536
              and current['baselineManifestCoversExtension'] is False
              and current['sdkFileCount']==40 and current['unchangedSdkEngineSources']==41
              and current['profileComparison']['transitiveFunctions']==60
              and current['profileComparison']['extensionFunctions']==3
              and current['profileComparison']['directFreeCalls']==29
              and current['commonModuleNativeMethods']==3,'NOTIFY_CLOSURE_CONTEXT')
        return dict(proofSha256=proof.proof_sha256,mainSha256=session.main_sha256,
            sourceManifestSha256=current['baselineSourceManifestSha256'],compositionProfile='SHEET_NOTIFY',
            extensionManifestSha256=current['extensionManifestSha256'],writerAuthorized=False,liveFreshnessVerified=False)
    except (OSError,KeyError,TypeError,UnicodeError,json.JSONDecodeError):
        raise ValueError('V258_NOTIFY_MAIN_CLOSURE_NOT_REVIEWED') from None


def composition_profile(review):
    """Select only the two fixed, independently reviewed source profiles."""
    _need(type(review) is Review and type(review.composition_profile) is str
          and review.composition_profile in ('LEGACY_249','SHEET_NOTIFY'),'COMPOSITION_PROFILE')
    if review.composition_profile=='SHEET_NOTIFY':
        return NOTIFY_ROUTE,NOTIFY_COMPOSITE_SHA,'ahRunnerCompositeSheetNotify'
    return ROUTE,COMPOSITE_SHA,'ahRunnerCompositeV249'


def _lease(receipt,lease,*,admission):
    _need(type(lease) is Lease and lease.receipt==receipt,'LIVE_PACKET_LEASE')
    _need(lease.state in (('READY',) if admission else ('READY','DISPATCHED')),'PACKET_LEASE_STATE')


def _request(q):
    _need(type(q) is ReadinessRequest,'REQUEST_TYPE');_session(q.session)
    p,r,v=q.packet,q.receipt,q.review
    _need(type(p) is PacketProof and type(r) is Receipt and type(v) is Review,'INPUT_TYPES')
    _need(_hex(r.operation_id,32) and r.pid==q.session.pid and r.birth==q.session.birth
          and type(r.pid) is int and type(r.address) is int and 65536<=r.address<2**32
          and type(r.size) is int and 288<=r.size<=4194304 and r.address+r.size<=2**32,'RECEIPT_SCOPE')
    _need(r.sha256==p.packet_sha256 and r.size==p.byte_length,'PACKET_RECEIPT')
    _need(p.original_sha256==ORIGINAL_SHA and p.original_lengths==ORIGINAL_LENGTH,'COMPOSITE_ORIGINAL_BASELINE')
    route,source_sha,entry=composition_profile(v)
    _need(v.route==route and v.writer_authorized is True and v.operation_id==r.operation_id
          and v.packet_sha256==r.sha256 and v.composite_sha256==source_sha
          ,'SEPARATE_WRITER_REVIEW')
    _need(v.main_sha256==q.session.main_sha256,'MAIN_CLOSURE_NOT_REVIEWED')
    if v.composition_profile=='SHEET_NOTIFY':
        _need(type(v.main_closure) is MainClosureReview and v.main_closure.profile=='SHEET_NOTIFY',
              'NOTIFY_MAIN_CLOSURE_REQUIRED')
        verify_main_closure(q.session,v.main_closure)
    elif q.session.main_sha256!=MAIN_SHA:
        if type(v.main_closure) is MainClosureReview:
            _need(v.main_closure.profile=='LEGACY_249','LEGACY_CLOSURE_PROFILE')
        verify_main_closure(q.session,v.main_closure)
    else:_need(v.main_closure is None,'LEGACY_CLOSURE_UNEXPECTED')
    _sha(v.review_sha256);_sha(v.compile_proof_sha256)
    if v.policy_reader_sha256 is not None:_sha(v.policy_reader_sha256)
    _need(type(v.compile_result) is int and v.compile_result==0
          and type(v.prepare_calls) is int and v.prepare_calls==0
          and type(v.execute_calls) is int and v.execute_calls==0,'COMPILE_ONLY_PROOF')
    if v.compile_mode=='LIVE_COMPILE_FUNCTION_RELEASED':
        _need(v.function_released is True and v.live_context_used is True
              and v.standalone_pid is None and v.standalone_birth is None
              and v.standalone_process_exit is None and v.standalone_terminal_gone is False
              and v.no_script_run is False and v.standalone_sync_wait is False,'LIVE_COMPILE_PROOF')
    elif v.compile_mode=='STANDALONE_CHECK_TERMINAL':
        _need(v.function_released is None and v.live_context_used is False
              and type(v.standalone_process_exit) is int
              and v.standalone_process_exit==0 and v.standalone_terminal_gone is True
              and v.no_script_run is True and v.standalone_sync_wait is True,'STANDALONE_COMPILE_PROOF')
        # A synchronous CHECK child is already gone and never used as an action
        # target. Old reviewed proof need not invent an unarchived PID/birth.
        _need((v.standalone_pid is None and v.standalone_birth is None) or
              (type(v.standalone_pid) is int and 0<v.standalone_pid<2**32
               and v.standalone_pid!=q.session.pid and _hex(v.standalone_birth,16)
               and int(v.standalone_birth,16)>0),'STANDALONE_IDENTITY_PAIR')
    else:_need(False,'COMPILE_MODE')


def prepare_request(session,packet,receipt,review,lease):
    """Bind actual RAM packet, root review and live lease; return metadata only.

    No caller code/string bodies are copied into the returned request. Root's
    existing collector must obtain the exact target baseline/current permission
    for this request/session;249 repeats its own live CAS before first setters.
    """
    _need(type(packet) is EditPacket,'PACKET_TYPE')
    _need(type(receipt) is Receipt and packet.operation_id==receipt.operation_id,'PACKET_OPERATION')
    q=ReadinessRequest(session,receipt,packet_proof(packet),review)
    _request(q);_lease(receipt,lease,admission=True)
    return q


def _readiness(q,f):
    _request(q)
    _need(type(f) is FreshReadiness and f.operation_id==q.receipt.operation_id
          and f.session==q.session and f.packet_sha256==q.receipt.sha256,'FRESH_CONTEXT')
    _need(type(f.observation_sequence) is int and f.observation_sequence>0,'READ_SEQUENCE')
    _sha(f.proof_sha256)
    _need(f.identity_verified is True and f.root_clean is True and f.ui_clean is True,'FRESH_IDENTITY_OR_DIRTY_ROOT')
    _need(type(f.targets) is tuple and len(f.targets)==3,'EXACT_THREE_TARGETS')
    for index,row in enumerate(f.targets):
        _need(type(row) is TargetState and (row.object_id,row.property_id)==TARGETS[index],'TARGET_SCOPE')
        expected=TEMPLATE_BEFORE if index==0 else q.packet.original_sha256[index-1]
        length=5706 if index==0 else q.packet.original_lengths[index-1]
        _need(row.helper_sha256==row.editor_sha256==expected and type(row.source_bytes) is int
              and row.source_bytes==length,'SOURCE_CAS')
        _need(row.object_clean is True and row.editor_clean is True and row.read_only is False
              and row.editor_bound is True,'TARGET_EDITOR_STATE')
        if index:
            _need(row.ownership=='OWN' and type(row.repository_version) is int
                  and row.repository_version==(2272 if index==1 else 1646),'MODULE_OWNERSHIP_VERSION')
        else:
            _need(row.ownership=='UNKNOWN' and type(row.repository_version) is int
                  and row.repository_version==0,'TEMPLATE_SCOPE_KIND')
    t=f.template_permission
    _need(type(t) is TemplatePermission and t.object_id==TEMPLATE_ID
          and t.property_id==TEMPLATE_PROPERTY,'TEMPLATE_POLICY_SCOPE')
    if t.status=='PENDING':return ('TEMPLATE_CURRENT_NATIVE_PERMISSION_PENDING',)
    _need(t.status=='CURRENT_NATIVE_POLICY','TEMPLATE_POLICY_KIND')
    for proof in (t.proof_sha256,t.reader_sha256):_sha(proof)
    if q.review.policy_reader_sha256 is None:return ('TEMPLATE_POLICY_READER_NOT_REVIEWED',)
    _need(t.reader_sha256==q.review.policy_reader_sha256 and t.query_performed is True
          and t.result_read_only is False and t.document_bound is True
          and t.repeated is True,'TEMPLATE_NATIVE_PERMISSION')
    return ()


@dataclass(frozen=True,slots=True)
class WriterIntent:
    request:ReadinessRequest
    readiness:FreshReadiness

    def metadata(self):
        _need(not _readiness(self.request,self.readiness),'PENDING_READINESS')
        q=self.request
        route,source_sha,entry=composition_profile(q.review)
        result=dict(version=258,route=route,operationId=q.receipt.operation_id,
            sessionNonce=q.session.nonce,pid=q.session.pid,birth=q.session.birth,
            guiThread=q.session.gui_thread,generation=q.session.generation,revision=q.session.revision,
            packetAddress=q.receipt.address,packetBytes=q.receipt.size,packetSha256=q.receipt.sha256,
            rootId=ROOT_ID,targets=[dict(objectId=o,propertyId=p) for o,p in TARGETS],
            originalCodeSha256=list(q.packet.original_sha256),replacementCodeSha256=list(q.packet.replacement_sha256),
            originalTemplateSha256=TEMPLATE_BEFORE,expectedTemplateSha256=TEMPLATE_AFTER,
            compositeSha256=source_sha,codecSha256=CODEC_SHA,transportSha256=TRANSPORT_SHA,
            mainSha256=q.session.main_sha256,reviewSha256=q.review.review_sha256,
            mainClosureProofSha256=(None if q.review.main_closure is None else q.review.main_closure.proof_sha256),
            compileProofSha256=q.review.compile_proof_sha256,readinessProofSha256=self.readiness.proof_sha256,
            compileMode=q.review.compile_mode,compileFunctionReleased=q.review.function_released,
            compileStandalonePid=q.review.standalone_pid,compileStandaloneBirth=q.review.standalone_birth,
            compileStandaloneExit=q.review.standalone_process_exit,
            compileStandaloneTerminalGone=q.review.standalone_terminal_gone,
            compileNoScriptRun=q.review.no_script_run,compileLiveContextUsed=q.review.live_context_used,
            compileStandaloneSynchronousWait=q.review.standalone_sync_wait,
            readinessSequence=self.readiness.observation_sequence,
            templatePolicyProofSha256=self.readiness.template_permission.proof_sha256,
            templatePolicyReaderSha256=q.review.policy_reader_sha256,
            writerAuthorized=True,configurationSaves=0,databaseUpdates=0,repositoryMutations=0,
            configurationExports=0,configurationImports=0,oneShot=True,
            baselineCoverage='EXACT_THREE_TARGET_PROPERTIES',globalPendingIteratorVerified=False,
            packetOriginalsRetainUntil='VERIFIED_SAVE_OR_ROLLBACK',
            templateCheckpointState='REQUIRED_NATIVE_PREFLIGHT_BEFORE_FIRST_MUTATION',
            releaseOnSdkOrHooksTerminal=False,unknownRequiresRetention=True)
        if q.review.composition_profile=='SHEET_NOTIFY':
            result.update(compositionProfile='SHEET_NOTIFY',compositeEntry=entry)
        return result

    def sha256(self):
        """Canonical metadata intent hash for root's CREATE_NEW one-shot record."""
        return hashlib.sha256(canonical(self.metadata())).hexdigest()

    def render_values(self,lease):
        self.metadata();_lease(self.request.receipt,lease,admission=False)
        r=self.request.receipt
        return dict(__PAYLOAD_ADDRESS__=hex(r.address),__PAYLOAD_LENGTH__=str(r.size),
            __PAYLOAD_SHA256__=r.sha256,__OPERATION_ID__=r.operation_id,
            __WRITER_PLAN_ADMITTED__='true',__TEMPLATE_POLICY_ADMITTED__='true')


@dataclass(frozen=True,slots=True)
class Admission:
    pending:tuple
    intent:WriterIntent|None


def admit(request,readiness,lease):
    """Inject current readonly observations. PENDING never yields writer intent."""
    pending=_readiness(request,readiness);_lease(request.receipt,lease,admission=True)
    return Admission(pending,None if pending else WriterIntent(request,readiness))


@dataclass(frozen=True,slots=True)
class Execution:
    operation_id:str
    packet_sha256:str
    sdk_terminal_known:bool
    hooks_released:bool
    status:str
    mutation_possible:bool
    reference_attempted:bool
    checkpoint_retained:bool
    document_retained:bool
    proof_sha256:str|None


@dataclass(frozen=True,slots=True)
class Resolution:
    operation_id:str
    packet_sha256:str
    status:str  # SAVED_MAIN_VERIFIED or ROLLBACK_VERIFIED; actual future proof.
    target_hashes:tuple
    proof_sha256:str
    references_accounted:bool


@dataclass(frozen=True,slots=True)
class Disposition:
    state:str
    release_packet_allowed:bool=False
    release_refs_allowed:bool=False
    retry_allowed:bool=False


def checkpoint_disposition(intent,execution,resolution=None):
    """Propose retention, never release RAM or infer Save from native dirty.

    UNKNOWN/hook-terminal alone always retain. Native249 APPLIED_RAM remains
    unsaved. Root independently verifies254 save/rollback and retained ref
    counts before providing Resolution; no such actual proof exists yet.
    """
    _need(type(intent) is WriterIntent,'INTENT_TYPE');intent.metadata()
    _need(type(execution) is Execution and execution.operation_id==intent.request.receipt.operation_id
          and execution.packet_sha256==intent.request.receipt.sha256,'EXECUTION_SCOPE')
    for flag in (execution.sdk_terminal_known,execution.hooks_released,execution.mutation_possible,
                 execution.reference_attempted,execution.checkpoint_retained,execution.document_retained):
        _need(type(flag) is bool,'EXECUTION_FLAGS')
    if not execution.sdk_terminal_known or not execution.hooks_released:
        return Disposition('UNKNOWN_RETAIN')
    _sha(execution.proof_sha256)
    _need(execution.status in ('COMPOSITE_APPLIED_RAM','COMPOSITE_UNKNOWN_RETAIN',
          'COMPOSITE_REFUSED_RETAIN','COMPOSITE_REFUSED'),'COMPOSITE_STATUS')
    if resolution is None:
        if execution.status=='COMPOSITE_REFUSED' and not any((execution.mutation_possible,
            execution.reference_attempted,execution.checkpoint_retained,execution.document_retained)):
            return Disposition('REFUSED_BEFORE_MUTATION',True)
        return Disposition('APPLIED_UNSAVED_RETAIN' if execution.status=='COMPOSITE_APPLIED_RAM' else 'UNKNOWN_RETAIN')
    _need(type(resolution) is Resolution and resolution.operation_id==execution.operation_id
          and resolution.packet_sha256==execution.packet_sha256,'RESOLUTION_SCOPE')
    _sha(resolution.proof_sha256)
    q=intent.request
    expected=((TEMPLATE_AFTER,)+q.packet.replacement_sha256 if resolution.status=='SAVED_MAIN_VERIFIED'
              else (TEMPLATE_BEFORE,)+q.packet.original_sha256 if resolution.status=='ROLLBACK_VERIFIED' else None)
    _need(expected is not None and type(resolution.target_hashes) is tuple
          and resolution.target_hashes==expected and resolution.references_accounted is True,'RESOLUTION_PROOF')
    return Disposition(resolution.status,True,True)
