"""One fixed CommonModule editor read: two fresh RAM copies, no source edits.

Own issuer and truthful mutation grant; compiler/plan ABI remains frozen233.
Source bytes remain RAM; no fixture mutation, Undo, capture or saved-provider integration.
Uncertain dispatch/state/cleanup is retained, never retried or forcibly saved.
"""
from dataclasses import dataclass
import json
import importlib
from pathlib import Path
import re
import subprocess
import time
from types import FunctionType, SimpleNamespace
import uuid
import owned_live_premutation_refusal_audit as closed_refusal
import owned_editor_baseline_closure as closed_baseline

import workday_saved_module_operation as workday
import comparison_cpp_exception_type_epoch as epoch
import sdk_compiler_section_identity as section_identity

c, reader, base = workday.c, workday.reader, workday.base
HERE, ROOT = workday.HERE, workday.ROOT
MAIN_SHA = workday.MAIN_SHA
PROFILE = 'PRINT_COMMON_MODULE_LIVE_READONLY'
SCOPE_KIND = 'ROOT_LIVE_MODULE_READONLY_SCOPE'
RUN_KIND = 'ROOT_LIVE_MODULE_READONLY_RUN'
SOURCE_NAME = 'NativeLiveModuleReadOnly.as'
SOURCE_SHA = 'a68348932423dd1fc8850dd75353c873764f003ee61f06f5ade3c2f866dad117'
PREOPEN_AUDIT_SHA = '5852d4f11f5efc6906219746e5e92c566457a9a27622af4f7d1d8d88dabc8481'
PREOPEN_OPERATION = 'f11260e7e4114ec693b9c3a66908a665'
PREOPEN_PLAN_SHA = '35baf76b21331ad2ab3d6935e3655678656db7f7aa7ef5985d860ae713e749b0'
PREOPEN_HOST_PID = 40944
PREOPEN_HOST_BIRTH = '01dd5f15c86c138f'
PREOPEN_HOST_PROOF_SHA = 'a4ef82928ba9f9c011687828f80b007e253f95d542c6c26e808ae79b0aa01985'
OLD_CONTROLLER_SHA = '185291db692db16b9f365f237aaf37c06f5ef0c5f3a3d5a61ba82b09470c2084'
REFUSAL_AUDIT_SHA = 'e84b277e50fcc95b4265d081192c1285c279548dd695d3fd750741a03eeb316e'
HOST_PROOF_SHA = '0adf575547b401cc9bc492ab1ef240e2bb4bbada441e697d750178e978ec5510'
PRIOR_HOST_PID = 42736
PRIOR_HOST_BIRTH = '01dd5f0b2409e715'
WORKDAY_SHA = '071a49efd8f610e66fea01b1116623b13f145fe1c124aa2a862a5e1503d40df7'
EPOCH_SHA = 'e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4'
TARGET = '176e2552-fd8b-4823-afc0-d17431f2fb7b'
PROPERTY = workday.PROPERTY
NATIVE_FILE = 'live-module-readonly-proof.json'
INTENT_FILE = 'live-module-readonly-intent.json'
EPOCH_FILE = 'live-module-readonly-sdk-chain-epoch.json'
EPOCH_KIND = 'LIVE_MODULE_READONLY_SDK_CHAIN_CPP_EXCEPTION_TYPE_EPOCH'
EPOCH_COVERAGE = 'live_module_readonly_sdk_compile_prepare_execute_release'
TOKENS = {'__LIVE_READONLY_SCOPE_ADMITTED__','__OPERATION_ID__','__SCOPE_SHA256__',
          '__LIVE_READONLY_NONCE__','__OWN_DLL_PATH__','__LIVE_READONLY_PROOF_PATH__','__LIVE_READONLY_INTENT_PATH__'}
BRIDGE_MODULE = 'text_manager_state_bridge'
BRIDGE_SHA = '109df191f17acfd80754fbc0e8f31bb12453cd1448defeb8c702db71311e8ace'
BRIDGE_PRIMARY_SHA = 'b16c5afd526169b2b6a36bfa8aafc6d6f24d3c6ccac7c702441a2475e61aacf3'
BASELINE_CONTROLLER_SHA = 'e68f2c082f8ae9b31bc80fb42439cdd60d193c54b552956584e6104336314368'
BASELINE_CLOSURE_SHA = 'ff034ab7456f5b41cf91d8148304d04cd59b764e122b63c447a806048dbe727f'
BASELINE_OPERATION = '9b469e57508242f3a2c8cba57ea7eb05'
BASELINE_PLAN_SHA = '8ff1d13773d488809a0d2113dc963cce05bb4b322b885f70bda4567074026203'
BASELINE_HOST_PID = 30636
BASELINE_HOST_BIRTH = '01dd5f1003ae8fe4'
REQUIRED_PRIORS = {
 'bdac830148a4427ea80b9c641ef816c8':'0fa366e1c2470ff7889efb175240e44d287a78cb42479065f7117a78f013d471',
 'f614dfd76f524acbadfbfc9067684e2b':'d5e7e97d05698bb04517959965001cb4431a9495b1f6a69c650bc3761834c554'}
TRUE_AUTH = ('configurationReadOnly','runtimeCacheMutationPossible','runtimeUiMutationPossible',
             'retainedReferenceMaintenanceAuthorized','exceptionTypeMetadataReadAuthorized',
             'scopedReferenceCallsAuthorized','runtimeMetadataReadAuthorized','runtimeEditorOpenAuthorized',
             'sourceBodyReadsAuthorized','stateInitializationAllowed')
FALSE_AUTH = ('readOnly','sourceWritesAuthorized','ownFixtureMutationAuthorized',
              'writerAuthorized','captureAuthorized','repositoryOwnerVerified','configurationSavesAuthorized',
              'databaseUpdatesAuthorized','repositoryMutationsAuthorized','configurationExportsAuthorized',
              'configurationImportsAuthorized','newObjectCreationAuthorized','businessCallsAuthorized',
              'applicationDataReadAuthorized','newSessionsAuthorized','stockCompareAuthorized','commandDispatchAuthorized',
              'runtimeDialogHooksAuthorized','runtimeSyntheticEventsAuthorized','idleQueueInvocationAuthorized',
              'historicalReferencesReleaseAuthorized','manualAddRefReleaseAuthorized','externalAddinLoadingAuthorized',
              'exceptionObjectReadAuthorized','typeRawOutput','releaseResourcesAuthorized',
              'positiveDialogAnswersAuthorized','resultPropertyWritesAuthorized')
_ISSUER = object()


def need(ok, code):
    if not ok:
        raise ValueError('LIVE_MODULE_READONLY_' + code)


def _hex(value, size):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None and value != '0'*size


def _json(path, pin=None, bound=65536):
    return reader._json(path, pin, bound)


def limits():
    return dict(maximumNativeCommands=0,maximumTypeEvents=32,maximumEnumerations=0,
                maximumEditorOpens=1,maximumDirectSaves=2,maximumStateBridgeCalls=2,
                maximumSourceUtf16Units=131072,maximumWarmupGetterReads=1)


def authority(row):
    return (all(row.get(k) is True for k in TRUE_AUTH)
            and all(row.get(k) is False for k in FALSE_AUTH)
            and all(type(row.get(k)) is int and row[k] == n for k, n in limits().items()))


def validate_scope(row):
    need(type(row) is dict and row.get('kind') == SCOPE_KIND and row.get('passed') is True
         and row.get('profile') == PROFILE and authority(row)
         and row.get('moduleObjectId') == TARGET and row.get('modulePropertyId') == PROPERTY
         and row.get('allowedReadClasses') == ['CommonModule'] and row.get('sourceDomain') == 'editor_live'
         and row.get('actualSourceSha256') == SOURCE_SHA and SOURCE_SHA is not None
         and row.get('liveModuleReadonlyControllerSha256') == c.digest(c.read(Path(__file__)))
         and row.get('workdayControllerSha256') == WORKDAY_SHA
         and row.get('workdayClosureAuditSha256') == workday.CLOSURE_AUDIT_SHA
         and row.get('ownedLivePremutationRefusalAuditSha256') == REFUSAL_AUDIT_SHA
         and row.get('priorOwnedLiveOperationId') == closed_refusal.OP
         and row.get('priorOwnedLivePlanSha256') == closed_refusal.PLAN_SHA
         and row.get('priorHostTerminalProofSha256') == HOST_PROOF_SHA
         and row.get('liveStateBridgeSha256') == BRIDGE_SHA
         and row.get('liveStateBridgePrimarySha256') == BRIDGE_PRIMARY_SHA
         and row.get('ownedEditorBaselineClosureSha256') == BASELINE_CLOSURE_SHA
         and row.get('priorBaselineOperationId') == BASELINE_OPERATION
         and row.get('priorBaselinePlanSha256') == BASELINE_PLAN_SHA
         and _hex(PREOPEN_AUDIT_SHA,64) and row.get('liveModulePreopenRefusalAuditSha256') == PREOPEN_AUDIT_SHA
         and row.get('priorLiveReadonlyOperationId') == PREOPEN_OPERATION
         and row.get('priorLiveReadonlyPlanSha256') == PREOPEN_PLAN_SHA
         and row.get('priorLiveReadonlyHostTerminalProofSha256') == PREOPEN_HOST_PROOF_SHA
         and row.get('oneShot') is True and _hex(row.get('readonlyNonce'),32),'SCOPE')
    approved=workday._approved_prior_plans(row)
    need(all(approved.get(op) == pin for op,pin in REQUIRED_PRIORS.items()),'REQUIRED_PRIORS')
    workday._admission_scope_pins(row)


def _source():
    need(_hex(SOURCE_SHA,64), 'SOURCE_NOT_FROZEN')
    raw = c.read(HERE/SOURCE_NAME, 32768)
    need(c.digest(raw) == SOURCE_SHA, 'SOURCE_PIN')
    need(set(re.findall(r'__[A-Z0-9_]+__',raw.decode())) == TOKENS, 'SOURCE_TOKENS')
    return raw


def _bridge():
    need(_hex(BRIDGE_SHA,64) and _hex(BRIDGE_PRIMARY_SHA,64), 'BRIDGE_NOT_FROZEN')
    need(c.digest(c.read(HERE/(BRIDGE_MODULE+'.py'))) == BRIDGE_SHA, 'BRIDGE_PIN')
    need(c.digest(c.read(HERE/'text_manager_state_bridge_primary.py')) == BRIDGE_PRIMARY_SHA,'BRIDGE_PRIMARY_PIN')
    return importlib.import_module(BRIDGE_MODULE)


def _pins():
    need(c.digest(c.read(Path(workday.__file__))) == WORKDAY_SHA,'WORKDAY_PIN')
    need(c.digest(c.read(HERE/'owned_live_editor_operation.py')) == OLD_CONTROLLER_SHA,'OLD_CONTROLLER_PIN')
    need(c.digest(c.read(Path(closed_refusal.__file__))) == REFUSAL_AUDIT_SHA,'REFUSAL_AUDIT_PIN')
    need(c.digest(c.read(Path(epoch.__file__))) == EPOCH_SHA,'EPOCH_PIN')
    need(c.digest(c.read(HERE/'owned_editor_baseline_operation.py')) == BASELINE_CONTROLLER_SHA,'BASELINE_CONTROLLER_PIN')
    need(c.digest(c.read(Path(closed_baseline.__file__))) == BASELINE_CLOSURE_SHA,'BASELINE_CLOSURE_PIN')
    _preopen_audit();workday._pins();_source();_bridge()


def _preopen_audit():
    need(_hex(PREOPEN_AUDIT_SHA,64),'PREOPEN_AUDIT_NOT_FROZEN')
    need(c.digest(c.read(HERE/'live_module_preopen_refusal.py')) == PREOPEN_AUDIT_SHA,'PREOPEN_AUDIT_PIN')
    return importlib.import_module('live_module_preopen_refusal')


def _prior_host_terminal():
    """Fresh query-only exact-birth handle check; no kill or PID absence guess.

    Executed by Root admission/dispatch only. Tests replace this whole seam;
    the historical JSON never substitutes for the kernel terminal observation.
    """
    import ctypes as ct
    from ctypes import wintypes as w
    kernel=ct.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];kernel.OpenProcess.restype=w.HANDLE
    kernel.GetProcessTimes.argtypes=[w.HANDLE]+[ct.POINTER(w.FILETIME)]*4
    kernel.GetProcessTimes.restype=w.BOOL
    kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];kernel.WaitForSingleObject.restype=w.DWORD
    kernel.GetExitCodeProcess.argtypes=[w.HANDLE,ct.POINTER(w.DWORD)];kernel.GetExitCodeProcess.restype=w.BOOL
    kernel.CloseHandle.argtypes=[w.HANDLE];kernel.CloseHandle.restype=w.BOOL
    handle=kernel.OpenProcess(0x00101000,False,PRIOR_HOST_PID)  # synchronize + query-limited, never terminate
    need(bool(handle),'PRIOR_HOST_QUERY')
    try:
        times=[w.FILETIME() for _ in range(4)];exit_code=w.DWORD()
        need(bool(kernel.GetProcessTimes(handle,*(ct.byref(value) for value in times))),'PRIOR_HOST_TIMES')
        birth=f'{(times[0].dwHighDateTime<<32)|times[0].dwLowDateTime:016x}'
        need(birth == PRIOR_HOST_BIRTH,'PRIOR_HOST_BIRTH')
        waited=kernel.WaitForSingleObject(handle,0)
        need(waited == 0 and bool(kernel.GetExitCodeProcess(handle,ct.byref(exit_code)))
             and exit_code.value == 0,'PRIOR_HOST_TERMINAL')
        return dict(pid=PRIOR_HOST_PID,birth=birth,waitZeroMilliseconds=0,exitCode=0)
    finally:
        need(bool(kernel.CloseHandle(handle)),'PRIOR_HOST_HANDLE_CLOSE')


def _checked_refusal(prior):
    need(type(prior) is dict and prior.get('operationId') == closed_refusal.OP
         and c.digest(c.canonical(prior)) == closed_refusal.PLAN_SHA,'EXACT_PRIOR_REFUSAL')
    result=closed_refusal.audit_closed(prior)
    need(result.get('classification') == 'OWNED_LIVE_EDITOR_SAFE_PREMUTATION_REFUSAL'
         and all(result.get(k) is True for k in ('sourceControlPremutationRefusalVerified',
             'normalSdkContextAndFunctionReleaseReturned','ownedAsTypedHandlesCleared','freshHostExitCheckRequired'))
         and result.get('hostProcessId') == PRIOR_HOST_PID and result.get('hostBirth') == PRIOR_HOST_BIRTH
         and all(result.get(k) is False for k in ('readSuccess','retryAuthorized','newDispatchAuthorized',
             'currentIdentityVerified','currentLeaseVerified','unloadAuthorized','foreignUnknownWaived')),'PRIOR_REFUSAL_CLOSURE')
    observed=_json(ROOT/'artifacts/designer-bridge'/('owned-live-host-terminal-'+closed_refusal.OP+'.json'),HOST_PROOF_SHA)
    need(observed.get('kind') == 'OWNED_LIVE_MANAGED_HOST_KERNEL_TERMINAL'
         and observed.get('operationId') == closed_refusal.OP and observed.get('hostExitZeroVerified') is True
         and observed.get('queryHandlesClosed') is True and observed.get('originalUnknownPreserved') is True,
         'HISTORICAL_HOST_PROOF')
    terminal=_prior_host_terminal()
    need(type(terminal) is dict and terminal.get('birth') == PRIOR_HOST_BIRTH
         and all(type(terminal.get(k)) is int and terminal[k] == n
                 for k,n in dict(pid=PRIOR_HOST_PID,waitZeroMilliseconds=0,exitCode=0).items()),'FRESH_PRIOR_HOST')
    return result


def _baseline_host_terminal():
    # Same query-only exact-birth/signal/exit seam, distinct fixed baseline host.
    # Original helper globals remain unchanged for the old BA19 admission.
    fn=FunctionType(_prior_host_terminal.__code__,
        dict(_prior_host_terminal.__globals__,PRIOR_HOST_PID=BASELINE_HOST_PID,
             PRIOR_HOST_BIRTH=BASELINE_HOST_BIRTH),_prior_host_terminal.__name__,
        _prior_host_terminal.__defaults__,_prior_host_terminal.__closure__)
    return fn()


def _checked_baseline(prior):
    need(type(prior) is dict and prior.get('operationId') == BASELINE_OPERATION
         and c.digest(c.canonical(prior)) == BASELINE_PLAN_SHA,'EXACT_BASELINE_PRIOR')
    result=closed_baseline.audit_closed(prior)
    need(result.get('classification') == 'OWNED_EDITOR_BASELINE_SDK_RESOURCES_CLOSED'
         and all(result.get(k) is True for k in ('resourcesClosed','normalSdkContextAndFunctionReleaseReturned',
             'ownedTypedHandlesCleared','freshHostExitCheckRequired','currentTargetIdentityAndLeaseCheckRequired'))
         and type(result.get('priorHostProcessId')) is int and result['priorHostProcessId'] == BASELINE_HOST_PID
         and result.get('priorHostBirth') == BASELINE_HOST_BIRTH
         and all(result.get(k) is False for k in ('readBodyVerified','repositoryOwnerVerified',
             'currentIdentityVerified','currentLeaseVerified','rootOwnerExitVerified','retryAuthorized',
             'newDispatchAuthorized','unloadAuthorized','foreignUnknownWaived')),'BASELINE_CLOSURE')
    terminal=_baseline_host_terminal()
    need(type(terminal) is dict and terminal.get('birth') == BASELINE_HOST_BIRTH
         and all(type(terminal.get(k)) is int and terminal[k] == n
                 for k,n in dict(pid=BASELINE_HOST_PID,waitZeroMilliseconds=0,exitCode=0).items()),'FRESH_BASELINE_HOST')
    return result


def _preopen_host_terminal():
    fn=FunctionType(_prior_host_terminal.__code__,dict(_prior_host_terminal.__globals__,
        PRIOR_HOST_PID=PREOPEN_HOST_PID,PRIOR_HOST_BIRTH=PREOPEN_HOST_BIRTH),
        _prior_host_terminal.__name__,_prior_host_terminal.__defaults__,_prior_host_terminal.__closure__)
    return fn()


def _checked_preopen(prior):
    """Exact archived refusal plus a separate fresh known-terminal host check."""
    need(type(prior) is dict and prior.get('operationId') == PREOPEN_OPERATION
         and c.digest(c.canonical(prior)) == PREOPEN_PLAN_SHA,'EXACT_PREOPEN_PRIOR')
    result=_preopen_audit().audit_closed(prior)
    need(result.get('classification') == 'LIVE_MODULE_READONLY_PREOPEN_REFUSAL_SDK_RESOURCES_CLOSED'
         and all(result.get(k) is True for k in ('resourcesClosed','preopenRefusalVerified',
             'normalSdkContextAndFunctionReleaseReturned','ownedTypedHandlesCleared','originalUnknownPreserved',
             'freshHostExitCheckRequired','currentTargetIdentityAndLeaseCheckRequired'))
         and type(result.get('priorHostProcessId')) is int and result['priorHostProcessId'] == PREOPEN_HOST_PID
         and result.get('priorHostBirth') == PREOPEN_HOST_BIRTH
         and all(result.get(k) is False for k in ('readSuccess','currentIdentityVerified','currentLeaseVerified',
             'rootOwnerExitVerified','retryAuthorized','newDispatchAuthorized','unloadAuthorized','foreignUnknownWaived')),
         'PREOPEN_CLOSURE')
    observed=_json(ROOT/'artifacts/designer-bridge'/('live-module-readonly-host-terminal-'+PREOPEN_OPERATION+'.json'),
                   PREOPEN_HOST_PROOF_SHA)
    need(observed.get('kind') == 'LIVE_MODULE_READONLY_HOST_TERMINAL'
         and observed.get('operationId') == PREOPEN_OPERATION and observed.get('queryHandlesClosed') is True,
         'PREOPEN_HOST_PROOF')
    _counts(observed,dict(kills=0,unloads=0,nativeDispatches=0,sourceBodyReads=0,sourceWrites=0),'PREOPEN_HOST_SCOPE')
    observations=observed.get('observations')
    need(type(observations) is list and len(observations) == 3 and type(observations[0]) is dict
         and observations[0].get('birth') == PREOPEN_HOST_BIRTH and observations[0].get('terminal') is True,
         'PREOPEN_HISTORICAL_HOST')
    _counts(observations[0],dict(pid=PREOPEN_HOST_PID,waitZeroMilliseconds=0,exitCode=0),'PREOPEN_HISTORICAL_TERMINAL')
    terminal=_preopen_host_terminal()
    need(type(terminal) is dict and terminal.get('birth') == PREOPEN_HOST_BIRTH
         and all(type(terminal.get(k)) is int and terminal[k] == n for k,n in
                 dict(pid=PREOPEN_HOST_PID,waitZeroMilliseconds=0,exitCode=0).items()),'FRESH_PREOPEN_HOST')
    return result


@dataclass(slots=True)
class LiveModuleReadonlyOperation:
    issuer: object
    parent: object
    scope: dict
    scope_path: Path
    scope_sha256: str
    plan: dict
    plan_raw: bytes
    private: dict
    phase: str = 'PREPARED'
    host: object = None


def _private_factory(factory, **overrides):
    # The exact compat factory contains audit_partial in the SAME namespace.
    # Rehoming only prepare_parent leaves that helper calling the old validator
    # after the new profile has already passed the entry validator.
    original=factory.__globals__
    ns=dict(original,**overrides)
    for name,value in original.items():
        if name not in overrides and isinstance(value,FunctionType) and value.__globals__ is original:
            local=FunctionType(value.__code__,ns,value.__name__,value.__defaults__,value.__closure__)
            local.__kwdefaults__=value.__kwdefaults__
            ns[name]=local
    fn=FunctionType(factory.__code__,ns,factory.__name__,factory.__defaults__,factory.__closure__)
    fn.__kwdefaults__=factory.__kwdefaults__
    return fn


def _baseline_factory(factory):
    original_reader=factory.__globals__['reader'];original_inspect=factory.__globals__['inspect']
    def namespace(parent):
        ns=original_reader._namespace(parent)
        ns.update(__baseline_closed_operation=closed_refusal.OP,__baseline_closed_audit=_checked_refusal,
                  __readonly_baseline_operation=BASELINE_OPERATION,__readonly_baseline_audit=_checked_baseline,
                  __readonly_preopen_operation=PREOPEN_OPERATION,__readonly_preopen_audit=_checked_preopen)
        return ns
    def getsource(target):
        text=original_inspect.getsource(target)
        if target is c._no_pending:
            anchor='        if prior_identity!=identity: continue\n'
            need(text.count(anchor) == 1,'AUDIT_ANCHOR')
            text=text.replace(anchor,anchor+'        if operation==__baseline_closed_operation:\n'
                '            __baseline_closed_audit(prior);continue\n'
                '        if operation==__readonly_baseline_operation:\n'
                '            __readonly_baseline_audit(prior);continue\n'
                '        if operation==__readonly_preopen_operation:\n'
                '            __readonly_preopen_audit(prior);continue\n',1)
        return text
    reader_proxy=SimpleNamespace(**dict(original_reader.__dict__));reader_proxy._namespace=namespace
    inspect_proxy=SimpleNamespace(**dict(original_inspect.__dict__));inspect_proxy.getsource=getsource
    return _private_factory(factory,reader=reader_proxy,inspect=inspect_proxy,validate_scope=validate_scope)


def prepare_parent(path,pin):
    def composed(factory):
        return workday.admission._extra_factory(_baseline_factory(factory))
    fn=_private_factory(workday.admission._prepare_parent,validate_scope=validate_scope,_extra_factory=composed)
    return fn(path,pin)


def _claim_path(s):
    return ROOT/'artifacts/designer-bridge'/('live-module-readonly-claim-'+s.scope_sha256+'.json')


def _claim(s):
    q = reader._check_owner(s.parent); ctx = s.plan['context']
    return dict(kind='LIVE_MODULE_READONLY_CLAIM',operationId=s.plan['operationId'],scopeSha256=s.scope_sha256,
                actualSourceSha256=SOURCE_SHA,controllerSha256=s.plan['liveModuleReadonlyControllerSha256'],
                parentWriterOperationId=q['operationId'],parentWriterIntentSha256=c.digest(c.canonical(q)),
                sessionNonce=ctx['heldNonce'],pid=ctx['processId'],birth=ctx['birth'],readonlyNonce=s.scope['readonlyNonce'])


def _check(s):
    need(type(s) is LiveModuleReadonlyOperation and s.issuer is _ISSUER, 'ISSUED_OPERATION')
    _pins(); p=s.plan; ctx=p['context']
    need(c.canonical(p) == s.plan_raw and p.get('version') == 233
         and p.get('liveModuleReadonlyControllerSha256') == c.digest(c.read(Path(__file__)))
         and p.get('updatePreviewControllerSha256') == p['liveModuleReadonlyControllerSha256']
         and p.get('updatePreviewProfile') == PROFILE and p.get('actualSourceSha256') == SOURCE_SHA
         and authority(p) and p.get('updatePreviewScopeSha256') == s.scope_sha256
         and p.get('readScopeSha256') == s.parent.review_sha256
         and p.get('moduleObjectId') == TARGET and p.get('modulePropertyId') == PROPERTY
         and p.get('readonlyNonce') == s.scope['readonlyNonce']
         and ctx == s.parent.plan['context'], 'PLAN_AUTHORITY')
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'),ctx.get('mainSha256')) ==
         (48936,'01dd5d0180299126',8292,MAIN_SHA), 'FIXED_NATIVE')
    scope=_json(s.scope_path,s.scope_sha256); validate_scope(scope)
    q=reader._check_owner(s.parent)
    need(scope == s.scope and scope.get('targets') == q['targets']
         and scope.get('readScopeSha256') == s.parent.review_sha256
         and Path(scope.get('readScopePath','')).resolve() == s.parent.review_path.resolve()
         and (scope.get('sessionNonce'),scope.get('pid'),scope.get('birth'),scope.get('guiThreadId'),scope.get('mainSha256')) ==
             (ctx['heldNonce'],ctx['processId'],ctx['birth'],8292,MAIN_SHA), 'SCOPE_BINDING')
    workday._checked_prior(scope); workday._audit_workday_pending(ctx,scope=scope)
    _checked_refusal(_json(ROOT/'build'/('designer-hot-v233-'+closed_refusal.OP)/'plan.json'))
    _checked_baseline(_json(ROOT/'build'/('designer-hot-v233-'+BASELINE_OPERATION)/'plan.json'))
    _checked_preopen(_json(ROOT/'build'/('designer-hot-v233-'+PREOPEN_OPERATION)/'plan.json'))
    base._lease(SimpleNamespace(plan=p))
    if s.phase in ('PREPARED','STAGED'):
        need(not _claim_path(s).exists(), 'ALREADY_CLAIMED')
    else:
        need(_json(_claim_path(s)) == _claim(s), 'OWN_CLAIM')
    return q


def _sdk_chain_source(s):
    """Own fixed derivative: epoch spans compile through final SDK releases."""
    code=epoch.render().decode()
    inner=epoch.original.EXECUTE_BLOCK
    code=c._replace_once(code,inner,epoch.original.ANCHOR)
    code=c._replace_once(code,'static int execute(void *engine,void *expectedModule,unsigned char *core,int test) {',
                         'static int ahOwnedLiveSdkChainBody(void *engine,void *expectedModule,unsigned char *core,int test) {')
    # On a known CompileFunction failure an SDK-owned nonnull function output
    # still has its counted reference. Retain on ABI uncertainty instead of
    # making a raw Release call through an untrusted/partial handle.
    code=c._replace_once(code,'rc=(int)call(module,6,5,args);if(rc<0 || !fn || ahSdkAbiFault)return 103;',
        'rc=(int)call(module,6,5,args);if(rc<0 || !fn || ahSdkAbiFault){\n'
        ' if(fn && !ahSdkAbiFault)call(fn,2,0,0);return 103;\n }')
    code=c._replace_once(code,'context=(void*)call(engine,58,0,0);if(!context || ahSdkAbiFault)return 104;',
        'context=(void*)call(engine,58,0,0);if(!context || ahSdkAbiFault){\n'
        ' if(!context && !ahSdkAbiFault)call(fn,2,0,0);return 104;\n }')
    wrapper='''static int execute(void *engine,void *expectedModule,unsigned char *core,int test) {
 int rc;
 if(!ahCppEpochBegin())return 181;
 InterlockedExchange(&ahCppEpochEntered,1);InterlockedExchange(&ahCppEpochActive,1);
 InterlockedExchange(&ahOwnedLiveChainActive,1);
 rc=ahOwnedLiveSdkChainBody(engine,expectedModule,core,test);
 InterlockedExchange(&ahOwnedLiveChainActive,0);
 if(ahSdkAbiFault && rc==0)rc=107;
 if(!ahCppEpochEnd(rc))return 182;
 return rc;
}
'''
    code=c._replace_once(code,'#ifdef AH_SDK_TEST_HOST',wrapper+'#ifdef AH_SDK_TEST_HOST')
    code=code.replace('COMPARISON_CPP_EXCEPTION_TYPE_EPOCH',EPOCH_KIND)
    code=code.replace('synchronous_context_Execute',EPOCH_COVERAGE)
    code=c._replace_once(code,'if(GetCurrentThreadId()!=sdkGuiThread)rc=110;',
        'if(GetCurrentThreadId()!=sdkGuiThread || sdkGuiThread!=AH_SDK_EXPECTED_GUI_THREAD)rc=110;')
    code=c._replace_once(code,'if(!valid && diagnostic[0]==0)',
        'if(thread!=AH_SDK_EXPECTED_GUI_THREAD)valid=FALSE;\n if(!valid && diagnostic[0]==0)')
    fragment=_bridge().render(operation_id=s.plan['operationId'],scope_sha256=s.scope_sha256,
                              expected_pid=48936,gui_thread_id=8292,scope_admitted=True)
    need(type(fragment) is bytes and b'#include "sdk_probe_params.h"' not in fragment, 'BRIDGE_FRAGMENT')
    code=c._replace_once(code,'static int ahOwnedLiveSdkChainBody(',
        'volatile LONG ahOwnedLiveChainActive=0;\n'+fragment.decode()+'\nstatic int ahOwnedLiveSdkChainBody(')
    return code.encode()


def _render(s):
    _check(s); p=s.plan; out=Path(p['outputDirectory'])
    files=c.render(base._carrier_view(p),c.read(HERE/c._probe_spec(reader.PROBE)[0],32768))
    source=_source().decode()
    values={'__LIVE_READONLY_SCOPE_ADMITTED__':'true','__OPERATION_ID__':p['operationId'],
            '__SCOPE_SHA256__':s.scope_sha256,'__LIVE_READONLY_NONCE__':s.scope['readonlyNonce'],
            '__LIVE_READONLY_PROOF_PATH__':(out/NATIVE_FILE).as_posix(),
            '__LIVE_READONLY_INTENT_PATH__':(out/INTENT_FILE).as_posix(),
            '__OWN_DLL_PATH__':(out/'Continuation.dll').as_posix()}
    for token,value in values.items():
        need(token in source,'SOURCE_TOKEN'); source=source.replace(token,value)
    need(not re.search(r'__[A-Z0-9_]+__',source),'UNRESOLVED_SOURCE')
    header=files['sdk_probe_params.h'].decode()
    line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
    header=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(source,ensure_ascii=False))
    for key,value in {'AH_CPP_EPOCH_OPERATION_ID':p['operationId'],'AH_CPP_EPOCH_SCOPE_SHA256':s.scope_sha256}.items():
        header+='\n#define '+key+' '+json.dumps(value)+'\n'
    header+='#define AH_CPP_EPOCH_RECEIPT_FILE L'+json.dumps((out/EPOCH_FILE).as_posix())+'\n'
    files['sdk_probe_params.h']=header.encode()
    files['Continuation.c']=_sdk_chain_source(s)
    ps=files['run-fixed.ps1'].decode('utf-8-sig'); need(ps.count('version=233;') == 2,'HOST_AUTHORITY_ANCHOR')
    auth='version=233;'+''.join(k+'=$true;' for k in TRUE_AUTH)+''.join(k+'=$false;' for k in FALSE_AUTH)
    auth+=''.join(k+'='+str(v)+';' for k,v in limits().items())+"liveModuleReadonlyProfile='"+PROFILE+"';"
    files['run-fixed.ps1']=ps.replace('version=233;',auth).encode('utf-8-sig')
    files,_=section_identity.with_section_identity(files,operation_kind='LIVE_MODULE_READONLY',operation_id=p['operationId'])
    return files


def prepare_root(scope_path, scope_sha256):
    """Prepare an owned operation only; no native dispatch or process launch."""
    _pins(); path=c._plain(scope_path,ROOT/'artifacts/designer-bridge')
    scope=_json(path,scope_sha256); validate_scope(scope)
    workday._checked_prior(scope)
    parent=prepare_parent(path,scope_sha256); p=dict(parent.plan); op=uuid.uuid4().hex
    for key in ('pendingReadProfile','actualReadSourceSha256','pendingReadControllerSha256','pendingScopeSha256'):
        p.pop(key)
    controller=c.digest(c.read(Path(__file__)))
    p.update(operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),
             updatePreviewProfile=PROFILE,updatePreviewControllerSha256=controller,liveModuleReadonlyControllerSha256=controller,
             actualSourceSha256=SOURCE_SHA,updatePreviewScopeSha256=scope_sha256,readScopeSha256=parent.review_sha256,
             moduleObjectId=TARGET,modulePropertyId=PROPERTY,sourceDomain='editor_live',
             readonlyNonce=scope['readonlyNonce'],applicationWrites=0,
             **limits(),**{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})
    p['goldLeaseOwner'],p['goldLeaseBootstrapSha256']=base.owner_base._lease_binding(p['context'])
    s=LiveModuleReadonlyOperation(_ISSUER,parent,scope,path,scope_sha256,p,c.canonical(p),{})
    _check(s); ns=parent.private; ns['__pending_read_operation']=op
    def fresh(plan):
        _check(s); need(plan == s.plan,'FRESH_PLAN'); c._fresh(base._carrier_view(plan))
    def render(plan,raw):
        need(plan == s.plan,'RENDER_PLAN'); return _render(s)
    ns.update(_fresh=fresh,render=render); s.private=ns
    ns['_no_pending'](context=p['context'])
    return s


def stage_root(s):
    _check(s); need(s.phase == 'PREPARED','STAGE_PHASE')
    proof=s.private['stage_private'](s.plan,dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',
        rootAuthorized=True,planSha256=c.digest(s.plan_raw)))
    s.phase='STAGED'; return proof


def _counts(row, expected, reason):
    need(all(type(row.get(k)) is int and row[k] == v for k,v in expected.items()),reason)


def _joined(s,row,kind):
    need(type(row) is dict and row.get('kind') == kind and row.get('operationId') == s.plan['operationId']
         and row.get('scopeSha256') == s.scope_sha256 and row.get('nonce') == s.scope['readonlyNonce'],'NATIVE_JOIN')


def _native_terminal(s,native,intent,exception):
    _joined(s,native,'LIVE_MODULE_READONLY_NATIVE');_joined(s,intent,'LIVE_MODULE_READONLY_INTENT')
    need(native.get('verified') is True and native.get('reason') == 'NONE'
         and native.get('objectId') == TARGET and native.get('modulePropertyId') == PROPERTY
         and native.get('sourceDomain') == 'editor_live'
         and all(native.get(k) is True for k in ('readEqualityVerified','stateEqualityVerified',
             'independentOutputsVerified','ownedTypedHandlesCleared','openReturned',
             'firstSaveReturned','secondSaveReturned','warmupDocumentModifiedObserved',
             'baselineAfterWarmup','stateInitializationAllowed','runtimeCachePossible'))
         and all(native.get(k) is False for k in ('nativeException','sourceBodyIncluded','sourceFrameIncluded',
             'repositoryOwnerVerified','fullUndoHistoryVerified')),'NATIVE_FLAGS')
    need(type(native.get('warmupDocumentModified')) is bool,'WARMUP_OBSERVATION')
    _counts(native,dict(openCalls=1,directSaveCalls=2,stateBridgeCalls=2,warmupReads=1,helperTextReads=0,
        configurationSourceWrites=0,configurationSaves=0,databaseUpdates=0,repositoryMutations=0,
        businessCalls=0,dirtyFlagWrites=0),'NATIVE_COUNTS')
    units=native.get('sourceUtf16Units')
    need(type(units) is int and 0<=units<=131072 and type(native.get('comparedUtf16Units')) is int
         and native['comparedUtf16Units'] == units,'READ_LENGTH')
    _counts(intent,dict(maximumOpenCalls=1,maximumDirectSaveCalls=2,maximumStateBridgeCalls=2,
        maximumSourceUtf16Units=131072,maximumWarmupGetterReads=1,configurationSourceWrites=0),'NATIVE_INTENT')
    need(intent.get('sourceBodyIncluded') is False and intent.get('sourceFrameIncluded') is False
         and intent.get('stateInitializationAllowed') is True and intent.get('runtimeCachePossible') is True,'INTENT_SCOPE')
    for key in ('firstOutputAddress','secondOutputAddress'):
        need(type(native.get(key)) is int and 65536<=native[key]<=0xFFFFFFFF,'OUTPUT_ADDRESS')
    need(native['firstOutputAddress'] != native['secondOutputAddress'],'DISTINCT_OUTPUTS')
    before,after=native.get('beforeState'),native.get('afterState')
    need(type(before) is list and type(after) is list and len(before) == len(after) == 22
         and all(type(x) is int and 0<=x<=0xFFFFFFFF for x in before+after) and before == after
         and all(65536<=p<=0xFFFFFFFF for p in before[:8])
         and all(before[i] in (0,1) for i in (8,9,10,11,12,19,20))
         and (before[20] == 1 or before[21] == 0xFFFFFFFF),'STATE_PRESERVATION')
    codes=native.get('caretReturnCodes')
    need(type(codes) is list and len(codes) == 2 and all(type(x) is int and 0<=x<=0xFFFFFFFF for x in codes)
         and all(type(native.get(k)) is int and 0<=native[k]<=0xFFFFFFFF
                 for k in ('openReturnCode','openFlagsAfter')),'EDITOR_METADATA')
    _epoch_terminal(s,exception)
    return 'LIVE_MODULE_READONLY_STATE_PRESERVED'


def _epoch_terminal(s,exception):
    need(type(exception) is dict and exception.get('kind') == EPOCH_KIND
         and exception.get('epochCoverage') == EPOCH_COVERAGE,'WHOLE_SDK_EPOCH')
    normalized=dict(exception,kind='COMPARISON_CPP_EXCEPTION_TYPE_EPOCH',epochCoverage='synchronous_context_Execute')
    epoch.classify_type_epoch(normalized,operation_id=s.plan['operationId'],scope_sha256=s.scope_sha256,
        process_id=48936,execute_thread_id=8292,callback_known=True,callback_sdk_rc=0,target_identity_verified=True)
    _counts(exception,dict(cppThrows=0,otherExceptions=0),'EXCEPTION_FREE')


def _preopen_terminal(s,native,exception):
    """Known normal no-read refusal, not source/state success or retry authority.

    Every allowed producer reason precedes native intent and the sole open.
    Parent SDK/host/raw-result closure is checked by the caller before this gate.
    Postopen failures are deliberately excluded even if their handles clear.
    """
    _joined(s,native,'LIVE_MODULE_READONLY_NATIVE')
    need(native.get('reason') in ('HELPERSERVICE','HELPER_NULL','HELPER_TABLE','MODULE_QI',
         'MODULE_TABLE','BOUND_OBJECT','OWN_BRIDGE') and native.get('objectId') == TARGET
         and native.get('modulePropertyId') == PROPERTY and native.get('sourceDomain') == 'editor_live',
         'PREOPEN_REASON')
    need(all(native.get(k) is False for k in ('verified','readEqualityVerified','stateEqualityVerified',
         'independentOutputsVerified','openReturned','firstSaveReturned','secondSaveReturned',
         'warmupDocumentModifiedObserved','baselineAfterWarmup','nativeException','sourceBodyIncluded',
         'sourceFrameIncluded','repositoryOwnerVerified','fullUndoHistoryVerified'))
         and all(native.get(k) is True for k in ('ownedTypedHandlesCleared','stateInitializationAllowed','runtimeCachePossible'))
         and native.get('warmupDocumentModified') is None,'PREOPEN_FLAGS')
    _counts(native,{k:0 for k in ('openCalls','openReturnCode','directSaveCalls','stateBridgeCalls','warmupReads',
         'sourceUtf16Units','comparedUtf16Units','firstOutputAddress','secondOutputAddress','helperTextReads',
         'configurationSourceWrites','configurationSaves','databaseUpdates','repositoryMutations',
         'businessCalls','dirtyFlagWrites')},'PREOPEN_ZERO_COUNTS')
    _counts(native,dict(openFlagsAfter=65793),'PREOPEN_OPEN_FLAGS')
    need(native.get('beforeState') == [] and type(native['beforeState']) is list
         and native.get('afterState') == [] and type(native['afterState']) is list
         and type(native.get('caretReturnCodes')) is list and len(native['caretReturnCodes']) == 2
         and all(type(x) is int and x == 0 for x in native['caretReturnCodes']),'PREOPEN_NO_STATE')
    _epoch_terminal(s,exception)
    return 'LIVE_MODULE_READONLY_PREOPEN_REFUSED'


def _authority_result(s):
    return dict(updatePreviewProfile=PROFILE,liveModuleReadonlyControllerSha256=s.plan['liveModuleReadonlyControllerSha256'],
        actualSourceSha256=SOURCE_SHA,scopeSha256=s.scope_sha256,readScopeSha256=s.parent.review_sha256,
        moduleObjectId=TARGET,modulePropertyId=PROPERTY,sourceDomain='editor_live',
        editorLiveMcpIntegrated=False,sourceBodyPersisted=False,sourceMutationVerified=False,**limits(),
        **{k:True for k in TRUE_AUTH},**{k:False for k in FALSE_AUTH})


def _unknown(s,reason):
    s.phase='UNKNOWN_RETAIN'
    row=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=s.plan['operationId'],
        reason=reason,retryAuthorized=False,**_authority_result(s))
    c.write_new(Path(s.plan['outputDirectory'])/'unknown.json',row); return row


def run_root_once(s,review_path,review_sha256):
    """One reviewed diagnostic dispatch. UNKNOWN retains ownership; no retry."""
    _check(s); need(s.phase == 'STAGED','RUN_PHASE')
    p=s.plan; out=Path(p['outputDirectory']); ns=s.private
    build=ns['require_stage'](p); review=_json(c._plain(review_path,ROOT/'artifacts/designer-bridge'),review_sha256)
    need(review.get('kind') == RUN_KIND and review.get('passed') is True and authority(review)
         and review.get('planSha256') == c.digest(s.plan_raw)
         and review.get('buildSha256') == c.digest(c.canonical(build))
         and review.get('scopeSha256') == s.scope_sha256 and review.get('readScopeSha256') == s.parent.review_sha256
         and review.get('actualSourceSha256') == SOURCE_SHA,'ROOT_RUN')
    ns['_no_pending'](context=p['context']); workday._audit_workday_pending(p['context'],scope=s.scope)
    need(not any((out/n).exists() for n in ('intent.json','host-identity.json','host-result.json','result.json',
         'unknown.json','sdk-receipt.json',NATIVE_FILE,INTENT_FILE,EPOCH_FILE)), 'ONE_ATTEMPT')
    c.write_new(_claim_path(s),_claim(s)); s.phase='DISPATCHED_RETAIN'
    c.write_new(out/'intent.json',dict(version=233,operationId=p['operationId'],planSha256=c.digest(s.plan_raw),
        rootRunSha256=review_sha256,**_authority_result(s)))
    try:
        ns['_fresh'](p)
        s.host=subprocess.Popen([str(reader.writer.PS),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(out/'run-fixed.ps1')],
            cwd=out,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        c.write_new(out/'host-identity.json',reader.writer._host_identity(s.host))
    except Exception:
        return _unknown(s,'HOST_START_UNPROVEN')
    deadline=time.monotonic()+55
    while time.monotonic() < deadline:
        if (out/'host-result.json').is_file():
            try:
                sdk=_json(out/'host-result.json',bound=8192)
            except (OSError,ValueError):
                time.sleep(.05); continue
            if (type(sdk.get('version')) is int and sdk['version'] == 233
                    and sdk.get('knownTerminal') is True and sdk.get('hookWorkersReleased') is True):
                try:
                    s.host.wait(timeout=5)
                    need(type(s.host.returncode) is int and s.host.returncode == 0
                         and type(sdk.get('threadId')) is int and sdk['threadId'] == p['context']['guiThreadId']
                         and type(sdk.get('sdkResult')) is int and sdk['sdkResult'] == 0,'SDK_TERMINAL')
                    need(c.read(out/'sdk-result.bin',8) == bytes(4),'RAW_SDK_RESULT')
                    c.write_new(out/'sdk-receipt.json',dict(sdk,operationId=p['operationId'],
                        planSha256=c.digest(s.plan_raw),**_authority_result(s)))
                    ns['_fresh'](p)
                    native=_json(out/NATIVE_FILE);exception=_json(out/EPOCH_FILE)
                    if native.get('verified') is False:
                        # These fixed reasons occur BEFORE the source intent.
                        # An unexpected intent is uncertainty, never normalized.
                        need(not (out/INTENT_FILE).exists(),'PREOPEN_NO_NATIVE_INTENT')
                        status=_preopen_terminal(s,native,exception)
                    else:
                        status=_native_terminal(s,native,_json(out/INTENT_FILE),exception)
                except (OSError,ValueError,subprocess.TimeoutExpired):
                    return _unknown(s,'NATIVE_OR_FRESH_CLOSURE_UNPROVEN')
                row=dict(version=233,status=status,knownTerminal=True,operationId=p['operationId'],
                    planSha256=c.digest(s.plan_raw),sdkResult=0,hookWorkersReleased=True,targetIdentityVerified=True,
                    nativeInjectionPerformed=True,nativeProofSha256=c.digest(c.read(out/NATIVE_FILE)),retryAuthorized=False,
                    semanticRefusal=status == 'LIVE_MODULE_READONLY_PREOPEN_REFUSED',
                    readSuccess=status == 'LIVE_MODULE_READONLY_STATE_PRESERVED',
                    refusalReason=native['reason'] if status == 'LIVE_MODULE_READONLY_PREOPEN_REFUSED' else None,
                    releasePacketAllowed=False,releaseRefsAllowed=False,**_authority_result(s))
                c.write_new(out/'result.json',row); s.phase='KNOWN_TERMINAL_RETAIN_PARENT'; return row
            break
        if s.host.poll() is not None:
            break
        time.sleep(.05)
    return _unknown(s,'HOST_OR_SDK_TERMINAL_UNPROVEN')
