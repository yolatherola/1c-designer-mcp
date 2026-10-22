"""Root-only v234 workday saved-module orchestration with its own issuer.

No application source files, configuration loads/saves, business code, or
repository commands. The opaque live object belongs to its issuing RAM owner.
An uncertain native start/command/close is retained, never implicitly retried.
"""
from dataclasses import dataclass
import importlib
import json
import inspect
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
from types import FunctionType, SimpleNamespace
import uuid

import safe_saved_module_ram_operation as previous
import renewable_guardian_admission as admission
import resident_saved_module_operation as frozen_root
import saved_ram_session_closure_audit as closed_read
import resident_managed_carrier as managed
import sdk_compiler_section_identity as section_identity

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(HERE.parent))
from native_mcp.windows_ram_pipe import _Api
from native_mcp.session_lifecycle import SessionIdentity, SessionBroker

c, reader, base = previous.c, previous.reader, previous.base
SOURCE_NAME = 'NativeSafeCommonModuleRam.as'
SOURCE_SHA = '1f6d544d1963a19e4da54a67f246457a63ce080a30151857472802acaa2d92e3'
ADMITTED_SHA = '819038a386ae34fcfec0de8fa234b3b1f4415520b4615bb19c7884df8c43e48a'
CARRIER_SHA = 'ff59538b81fd2266e3e9f62912d79c20fb1f30b932c650a6659de0e1855f5f25'
PROVIDER_SHA = 'b9f43c59707aeecbd425c8be38aeb3dd6c14d9f94e14378743289dc2fa8eb71b'
PROFILE = 'WORKDAY_DATABASE_SAVED_COMMON_MODULES'
PROFILE_VERSION = 234
LEGACY_COMPILER_ABI_VERSION = 233
FROZEN_ROOT_SHA = '5a6384b247b2070cf0d8eddbe9632b37d301f426d512943ab7a92352aa094bff'
ADMISSION_SHA = '809da32f339297266f545326b111ce44980a408f6ba07f9a94c3f35d272adf44'
CLOSURE_AUDIT_SHA = 'f63c4b4c685fc32aab20aba06adfe6a1dd8a15819dca3599ab1741794890a354'
LEGACY_WORKDAY_CONTROLLER_SHA = '29c98d25b76bce37c04b203b062c41b48bf0e3519acdf2c30e32a69c4f476530'
PRIOR_OPERATION = '4bd5ca754178492fb4c07c3f8afd17a0'
PRIOR_PLAN_SHA = '873e62177faf531c4b0a332305f588313070cb6e6b96ac5e429b19ef366dfac8'
COMPOSITION = {
 'workdayGuardianHostSha256': 'workday_guardian_host.py',
 'workdayLifecycleSha256': 'workday_guardian_lifecycle.py',
 'workdayGuardianWorkerSha256': 'workday_guardian_worker.py',
 'workdayEvidenceSha256': 'workday_episode_evidence.py',
}
MAIN_SHA = previous.MAIN_SHA
PROPERTY = previous.PROPERTY
TRUE_AUTH = previous.TRUE_AUTH + ('residentSdkReuseAuthorized', 'residentSdkFunctionCloseAuthorized',
                                 'arbitraryCommonModuleSelectionAuthorized', 'protectedControlChannelAuthorized')
FALSE_AUTH = previous.FALSE_AUTH
_ISSUER = object()
_ADMISSION_ISSUER = object()
_ADMISSIONS = {}
_MARKER_PATTERNS = ('designer-hot-v233-*', 'designer-hot-v234-*', 'designer-writer-v263-*',
                    'designer-native-reference-*', 'designer-runner-rollback-*', 'designer-sheet-notify-*')
PINS = {
    'research/safe_saved_module_ram_operation.py': '6e3d115c9b3423c930c903707f9f548ce7e61fab4e1ce142ee8061149b4293fe',
    'research/saved_ram_session_closure_audit.py': 'f88100f76c9b1663d163cd50f62078a0ea214d157ed3095599f856bb3db573d6',
    'research/resident_managed_carrier.py': 'df071e91f3e0fe2bea80b5a850e2407bd3bed4e29322bf9ba5027f122dbe44e8',
    'research/workday_ram_carrier.py': CARRIER_SHA,
    'research/NativeSafeCommonModuleRam.as': SOURCE_SHA,
    'native_mcp/saved_source.py': '6aae709b2eb6e112ebc049f4776811325877166fc5fc35f87369b224571facdc',
    'native_mcp/server.py': '77f7bb7fcc8a372a25384c797224e87c223f66d1f585bf00e53372a31bc23e36',
    'native_mcp/session_lifecycle.py': '458ef6898abad4623ed96ad0a246929828df3c1a33b2d0be257c460945fc4b3e',
    'native_mcp/resident_server.py': '459a2f393faabc359b31aab0579d9bb6a2cd46889a911e424e0090644fc163df',
    'native_mcp/workday_wire.py': '06945271bfa4f22a474e400587ba8d558c4e6a8be2821ad9c4592bdd14790f46',
    'native_mcp/workday_channel.py': '3b601e1164fee759044cb3a77c43c9fb6f439ead0ce426eb9865df362f0bf6d8',
    'native_mcp/workday_pipe.py': '0d86fdc34b932c7a87b6286597308a44097447b3122a48be29966b7c3a2fe42f',
    'native_mcp/workday_receipt_observer.py': 'fed1a725843aee2beee628229de5e383e6cd1d3f15b5074f585f3e614b4cdd2f',
    'research/resident_saved_module_operation.py': FROZEN_ROOT_SHA,
    'research/renewable_guardian_admission.py': ADMISSION_SHA,
    'research/workday_guardian_closure_audit.py': CLOSURE_AUDIT_SHA,
}


def need(ok, code):
    if not ok:
        raise ValueError('WORKDAY_OPERATION_'+code)


def limits():
    return dict(maximumNativeCommands=0, maximumTypeEvents=32, maximumEnumerations=0,
                maximumResidentControlCommands=4096, maximumRequests=4095, maximumSessionSeconds=28800,
                maximumBodyBytes=4194304, maximumCodePoints=1048576,
                maximumPlainResourceBytes=8388608, maximumFileOpensPerRequest=2,
                maximumStorageEntryOpensPerRequest=4)


def authority(row):
    return (all(row.get(k) is True for k in TRUE_AUTH) and all(row.get(k) is False for k in FALSE_AUTH)
            and all(type(row.get(k)) is int and row[k] == n for k, n in limits().items())
            and type(row.get('expectedDatabaseSource')) is int and row['expectedDatabaseSource'] == 1383504556)


def validate_scope(row):
    need(type(row) is dict and row.get('kind') == 'ROOT_WORKDAY_SAVED_RAM_SCOPE'
         and row.get('passed') is True and row.get('profile') == PROFILE
         and row.get('actualSourceSha256') == SOURCE_SHA and authority(row)
         and row.get('allowedReadClasses') == ['CommonModule']
         and row.get('modulePropertyId') == PROPERTY
         and type(row.get('profileVersion')) is int and row['profileVersion'] == PROFILE_VERSION
         and row.get('explicitWorkdayGrantAuthorized') is True
         and row.get('workdayControllerSha256') == c.digest(c.read(Path(__file__)))
         and row.get('workdayClosureAuditSha256') == CLOSURE_AUDIT_SHA
         and row.get('priorGuardianOperationId') == PRIOR_OPERATION
         and row.get('priorGuardianPlanSha256') == PRIOR_PLAN_SHA, 'SCOPE')
    for key, filename in COMPOSITION.items():
        need(row.get(key) == c.digest(c.read(HERE/filename)), 'COMPOSITION_PIN')
    _approved_prior_plans(row)
    _admission_scope_pins(row)


def _pins(require_provider=True):
    for name, pin in PINS.items():
        need(c.digest(c.read(HERE.parent/name)) == pin, 'SOURCE_PIN')
    previous._pins()
    admission._pins()
    if require_provider:
        need(type(PROVIDER_SHA) is str and re.fullmatch('[0-9a-f]{64}', PROVIDER_SHA), 'PROVIDER_NOT_FROZEN')
        need(c.digest(c.read(HERE.parent/'native_mcp/workday_provider.py')) == PROVIDER_SHA, 'PROVIDER_PIN')


def _carrier():
    need(c.digest(c.read(HERE/'workday_ram_carrier.py')) == CARRIER_SHA, 'CARRIER_PIN')
    return importlib.import_module('workday_ram_carrier')


def _source():
    raw = c.read(HERE/SOURCE_NAME, 32768)
    need(c.digest(raw) == SOURCE_SHA, 'SOURCE_PIN')
    admitted = _carrier().admitted_source(raw)
    need(c.digest(admitted) == ADMITTED_SHA, 'ADMITTED_SOURCE_PIN')
    return raw, admitted


def _admission_scope_pins(row):
    # Preserve every frozen historical-admission pin without invoking its old
    # 64-command scope validator on this separately authorized v234 grant.
    chain = (admission.previous.previous.previous, admission.previous.previous,
             admission.previous, admission)
    keys = (('residentAdmissionAdapterSha256','closedResidentAuditSha256','closedResidentManifestSha256'),
            ('persistentMcpAdmissionSha256','fullReadClosureAuditSha256','fullReadClosureManifestSha256'),
            ('guardianNativeAdmissionSha256','persistentFrontendClosureAuditSha256','persistentFrontendClosureManifestSha256'))
    for module, fields in zip(chain[:3], keys):
        need(row.get(fields[0]) == c.digest(c.read(Path(module.__file__)))
             and row.get(fields[1]) == module.AUDIT_SHA
             and row.get(fields[2]) == module.MANIFEST_SHA, 'ADMISSION_SCOPE_PINS')
    need(row.get('renewableGuardianAdmissionSha256') == ADMISSION_SHA
         and row.get('daemonGuardianClosureAuditSha256') == admission.AUDIT_SHA
         and row.get('daemonRuntimeSha256') == admission.RUNTIME_SHA
         and row.get('guardianEpisodeWorkerSha256') == c.digest(c.read(HERE/'guardian_episode_worker.py')),
         'RENEWABLE_SCOPE_PINS')


def _checked_prior(scope):
    prior = admission._prior_plan(scope)
    need(prior.get('residentConfiguration',{}).get('serverPid') == 9124
         and prior['residentConfiguration'].get('serverBirth') == '01dd5ef34d8923df', 'PRIOR_OWNER')
    return admission._checked_audit(prior)


def _approved_prior_plans(scope):
    plans = scope.get('approvedPriorWorkdayPlans') if type(scope) is dict else None
    need(type(plans) is dict and len(plans) <= 128
         and all(type(op) is str and re.fullmatch('[0-9a-f]{32}',op) and op != '0'*32
                 and type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin) and pin != '0'*64
                 for op,pin in plans.items()), 'APPROVED_PRIOR_PLANS')
    return plans


def _prior_workday_revision(prior, scope):
    # Only the exact originally frozen source profile can use B's default.
    legacy = dict(version=234,profileVersion=234,updatePreviewProfile=PROFILE,
        updatePreviewControllerSha256=LEGACY_WORKDAY_CONTROLLER_SHA,
        workdayControllerSha256=LEGACY_WORKDAY_CONTROLLER_SHA,actualSourceSha256=SOURCE_SHA,
        admittedSourceSha256=ADMITTED_SHA,nativeRamCarrierSha256=CARRIER_SHA,residentProviderSha256=PROVIDER_SHA)
    if authority(prior) and all(type(prior.get(k)) is type(v) and prior[k] == v for k,v in legacy.items()):
        return None
    operation = prior['operationId']; plans = _approved_prior_plans(scope)
    plan_sha = c.digest(c.canonical(prior))
    need(plans.get(operation) == plan_sha, 'PRIOR_PLAN_NOT_APPROVED')
    configuration = prior.get('residentConfiguration')
    need(type(configuration) is dict and type(configuration.get('scopeSha256')) is str
         and re.fullmatch('[0-9a-f]{64}',configuration['scopeSha256']) and configuration['scopeSha256'] != '0'*64
         and prior.get('updatePreviewScopeSha256') == configuration['scopeSha256'], 'HISTORICAL_SCOPE_BINDING')
    artifacts = ROOT/'artifacts/designer-bridge'
    run = reader._json(artifacts/('workday-guardian-run-'+operation+'.json'),bound=65536)
    nonce = run.get('acceptanceNonce')
    need(run.get('kind') == 'ROOT_WORKDAY_SAVED_RAM_RUN' and run.get('passed') is True
         and run.get('planSha256') == plan_sha and run.get('scopeSha256') == configuration['scopeSha256']
         and type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) and nonce != '0'*32,
         'HISTORICAL_RUN')
    historical = reader._json(artifacts/('workday-guardian-scope-'+nonce+'.json'),configuration['scopeSha256'],bound=65536)
    fields = dict(controller='workdayControllerSha256',host='workdayGuardianHostSha256',
                  runtime='workdayLifecycleSha256',worker='workdayGuardianWorkerSha256')
    need(historical.get('kind') == 'ROOT_WORKDAY_SAVED_RAM_SCOPE' and historical.get('passed') is True
         and historical.get('profile') == PROFILE and type(historical.get('profileVersion')) is int
         and historical['profileVersion'] == PROFILE_VERSION
         and historical.get('workdayControllerSha256') == prior.get('updatePreviewControllerSha256')
         == prior.get('workdayControllerSha256'), 'HISTORICAL_REVISION')
    revision = {key:historical.get(field) for key,field in fields.items()}
    need(all(type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin) and pin != '0'*64 for pin in revision.values()),
         'HISTORICAL_REVISION_PINS')
    return revision


def _audit_workday_pending(context, allow_operation=None, scope=None):
    # Full historical proof only during admission, never from a hot read gate.
    for out in (ROOT/'build').glob('designer-hot-v234-*'):
        operation = out.name.removeprefix('designer-hot-v234-')
        if not re.fullmatch('[0-9a-f]{32}', operation) or not out.is_dir() or operation == allow_operation:
            continue
        if not (out/'intent.json').exists():
            continue
        prior = reader._json(out/'plan.json')
        need(type(prior) is dict and type(prior.get('version')) is int and prior['version'] == PROFILE_VERSION
             and prior.get('operationId') == operation and prior.get('probe') in c.FIXED_PROBES,
             'PRIOR_WORKDAY_SCOPE')
        identity = prior.get('context',{})
        need(type(identity.get('processId')) is int and identity['processId'] > 0
             and type(identity.get('birth')) is str and re.fullmatch('[a-f0-9]{16}',identity['birth']),
             'PRIOR_WORKDAY_IDENTITY')
        if (identity['processId'], identity['birth']) == (context['processId'], context['birth']):
            need(CLOSURE_AUDIT_SHA != '0'*64 and c.digest(c.read(HERE/'workday_guardian_closure_audit.py')) == CLOSURE_AUDIT_SHA,
                 'PRIOR_WORKDAY_CLOSURE_PIN')
            approved = _prior_workday_revision(prior,scope)
            result = importlib.import_module('workday_guardian_closure_audit').audit_closed(prior,approved_revision=approved)
            need(result.get('classification') == 'WORKDAY_GUARDIAN_RESOURCES_CLOSED'
                 and result.get('resourcesClosed') is True and result.get('freshOwnerExitCheckRequired') is True,
                 'PRIOR_WORKDAY_CLOSURE')
            admission._prior_owner_gone(prior,result)


def _fresh_workday(plan):
    # Exact private derivative of the pinned continuation's version/path gate.
    # Original source identity checks retain the original module globals.
    source = inspect.getsource(c._fresh)
    for old,new in (("plan.get('version')==233", "plan.get('version')==234"),
                    ("('designer-hot-v233-'+plan['operationId'])", "('designer-hot-v234-'+plan['operationId'])")):
        need(source.count(old) == 1, 'FRESH_DERIVATION_ANCHOR')
        source = source.replace(old,new,1)
    namespace = dict(c.__dict__)
    exec(compile(source,'<fixed-workday-plan-freshness>','exec'),namespace)
    return namespace['_fresh'](plan)


def prepare_parent(path, pin):
    """Use every historical branch, but bind only the new scope validator."""
    fn = FunctionType(admission._prepare_parent.__code__,
        dict(admission._prepare_parent.__globals__, validate_scope=validate_scope),
        admission._prepare_parent.__name__, admission._prepare_parent.__defaults__, admission._prepare_parent.__closure__)
    return fn(path,pin)


@dataclass(slots=True)
class WorkdayOperation:
    issuer: object
    parent: object
    scope_path: Path
    scope_sha256: str
    scope: dict
    plan: dict
    plan_raw: bytes
    private: dict
    channel: object
    phase: str = 'PREPARED'
    host: object = None
    provider: object = None
    broker: object = None
    join_attempted: bool = False
    admission_seal: object = None


@dataclass(frozen=True, slots=True)
class _AdmissionSeal:
    issuer: object
    operation: object
    parent: object
    plan_raw: bytes
    scope_path: Path
    scope_sha256: str
    scope_raw: bytes
    parent_plan_raw: bytes
    parent_scope_raw: bytes
    parent_scope_path: Path
    parent_scope_sha256: str
    owner_pid: int
    owner_birth: str
    checkpoint_path: Path
    checkpoint_sha256: str
    reservation_path: Path
    reservation_raw: bytes
    claim_raw: bytes
    intent_raw: bytes
    foreign_markers: tuple


def _marker_snapshot(own_operation):
    """Exact small technical markers only; never replay historical proofs."""
    rows = []; total = 0
    for pattern in _MARKER_PATTERNS:
        prefix = pattern[:-1]
        for out in (ROOT/'build').glob(pattern):
            operation = out.name.removeprefix(prefix)
            if not re.fullmatch('[0-9a-f]{32}', operation) or not out.is_dir():
                continue
            if pattern == 'designer-hot-v234-*' and operation == own_operation:
                continue
            out = c._plain(out, ROOT/'build')
            for name in ('intent.json', 'unknown.json'):
                path = out/name
                if path.exists():
                    raw = c.read(path, 65536); total += len(raw)
                    need(len(rows) < 4096 and total <= 16777216, 'MARKER_BOUND')
                    rows.append((path.relative_to(ROOT/'build').as_posix(), c.digest(raw)))
    return tuple(sorted(rows))


def _intent(s, review_pin):
    return dict(kind='WORKDAY_SAVED_RAM_INTENT', operationId=s.plan['operationId'],
        scopeSha256=s.scope_sha256, planSha256=c.digest(s.plan_raw), rootRunSha256=review_pin,
        applicationWrites=0, configurationExports=0, configurationImports=0, repositoryMutations=0)


def _seal_admission(s, review_pin):
    """Full admission once before install; the seal grants no dispatch by itself."""
    markers = _marker_snapshot(s.plan['operationId'])
    _check(s)
    need(s.phase == 'STAGED' and s.admission_seal is None and id(s) not in _ADMISSIONS, 'ADMISSION_ONCE')
    s.private['_no_pending'](context=s.plan['context'])
    need(_marker_snapshot(s.plan['operationId']) == markers, 'ADMISSION_MARKER_RACE')
    parent_scope = s.parent.scope
    operation = parent_scope['writerOperationId']
    need(re.fullmatch('[0-9a-f]{32}', operation), 'ADMISSION_WRITER')
    checkpoint = ROOT/'artifacts/designer-bridge'/('root-notify-actual-write-checkpoint-'+operation+'.json')
    reservation = c._reservation(s.plan['context'])
    seal = _AdmissionSeal(_ADMISSION_ISSUER, s, s.parent, s.plan_raw, s.scope_path.resolve(), s.scope_sha256,
        c.canonical(s.scope), s.parent.plan_raw, c.canonical(parent_scope),
        s.parent.review_path.resolve(), s.parent.review_sha256,
        parent_scope['ownerPid'], parent_scope['ownerBirth'], checkpoint, parent_scope['checkpointSha256'],
        reservation, c.read(reservation, 8192), c.canonical(_claim(s)), c.canonical(_intent(s, review_pin)),
        markers)
    # Recheck the mutable anchors after taking the baseline, before publishing
    # the opaque seal. The prior full owner check already bound their meanings.
    need(c.digest(c.read(seal.parent_scope_path, 32768)) == seal.parent_scope_sha256
         and c.digest(c.read(checkpoint, 32768)) == seal.checkpoint_sha256, 'ADMISSION_MARKERS')
    _ADMISSIONS[id(s)] = seal
    s.admission_seal = seal
    return seal


def _hot_check(s):
    """Fresh live/ownership markers; full history and source536 stay cold."""
    need(type(s) is WorkdayOperation and s.issuer is _ISSUER, 'HOT_ISSUED')
    seal = s.admission_seal
    need(type(seal) is _AdmissionSeal and seal.issuer is _ADMISSION_ISSUER
         and _ADMISSIONS.get(id(s)) is seal and seal.operation is s and seal.parent is s.parent,
         'HOT_ADMISSION')
    need(s.phase in ('READY', 'CLOSING') and s.plan_raw == seal.plan_raw
         and c.canonical(s.plan) == seal.plan_raw and c.canonical(s.scope) == seal.scope_raw
         and s.scope_path.resolve() == seal.scope_path and s.scope_sha256 == seal.scope_sha256,
         'HOT_PLAN_SCOPE')
    need(s.parent.plan_raw == seal.parent_plan_raw and c.canonical(s.parent.plan) == seal.parent_plan_raw
         and c.canonical(s.parent.scope) == seal.parent_scope_raw
         and s.parent.review_path.resolve() == seal.parent_scope_path
         and s.parent.review_sha256 == seal.parent_scope_sha256, 'HOT_PARENT_SCOPE')
    need(authority(s.plan) and s.plan.get('profileVersion') == PROFILE_VERSION
         and s.plan.get('explicitWorkdayGrantAuthorized') is True, 'HOT_AUTHORITY')
    need(c.digest(c.read(seal.scope_path, 65536)) == seal.scope_sha256
         and c.digest(c.read(seal.parent_scope_path, 32768)) == seal.parent_scope_sha256,
         'HOT_SCOPE_FILES')
    base._lease(SimpleNamespace(plan=s.plan))
    need(reader._process(seal.owner_pid) == seal.owner_birth, 'HOT_ORIGINAL_OWNER')
    need(c.digest(c.read(seal.checkpoint_path, 32768)) == seal.checkpoint_sha256
         and c.read(seal.reservation_path, 8192) == seal.reservation_raw, 'HOT_PARENT_MARKERS')
    out = Path(s.plan['outputDirectory'])
    need(not (out/'unknown.json').exists()
         and c.canonical(reader._json(_claim_path(s))) == seal.claim_raw
         and c.canonical(reader._json(out/'intent.json')) == seal.intent_raw, 'HOT_OWN_MARKERS')
    need(_marker_snapshot(s.plan['operationId']) == seal.foreign_markers, 'HOT_FOREIGN_MARKERS')


def _claim_path(s):
    return ROOT/'artifacts/designer-bridge'/('workday-saved-ram-claim-'+s.scope_sha256+'.json')


def _claim(s):
    owner = reader._check_owner(s.parent)
    return dict(kind='WORKDAY_SAVED_RAM_CLAIM', operationId=s.plan['operationId'], scopeSha256=s.scope_sha256,
                controllerSha256=s.plan['updatePreviewControllerSha256'], actualSourceSha256=SOURCE_SHA,
                writerOperationId=owner['operationId'], packetSha256=owner['packetSha256'],
                sessionNonce=s.plan['context']['heldNonce'], pid=48936, birth='01dd5d0180299126')


def _check(s):
    need(type(s) is WorkdayOperation and s.issuer is _ISSUER, 'ISSUED')
    _pins()
    p = s.plan
    need(c.canonical(p) == s.plan_raw and p['updatePreviewControllerSha256'] == c.digest(c.read(Path(__file__)))
         and p['updatePreviewProfile'] == PROFILE and p['actualSourceSha256'] == SOURCE_SHA
         and p['admittedSourceSha256'] == ADMITTED_SHA and p['nativeRamCarrierSha256'] == CARRIER_SHA
         and p['residentProviderSha256'] == PROVIDER_SHA and p['context'] == s.parent.plan['context']
         and type(p.get('version')) is int and p['version'] == PROFILE_VERSION
         and p.get('profileVersion') == PROFILE_VERSION and p.get('workdayControllerSha256') == p['updatePreviewControllerSha256']
         and p.get('explicitWorkdayGrantAuthorized') is True
         and authority(p) and p['writerAuthorized'] is False and p['captureAuthorized'] is False
         and type(p['applicationWrites']) is int and p['applicationWrites'] == 0, 'PLAN')
    scope = reader._json(s.scope_path, s.scope_sha256)
    validate_scope(scope)
    need(scope == s.scope and scope['targets'] == reader._check_owner(s.parent)['targets']
         and scope['readScopeSha256'] == s.parent.review_sha256
         and Path(scope['readScopePath']).resolve() == s.parent.review_path.resolve()
         and (scope['sessionNonce'], scope['pid'], scope['birth'], scope['guiThreadId'], scope['mainSha256']) ==
             ('013dc010bd784e859b1e3ba4def25f3c', 48936, '01dd5d0180299126', 8292, MAIN_SHA), 'SCOPE_JOIN')
    base._lease(SimpleNamespace(plan=p))
    _checked_prior(scope)
    _audit_workday_pending(p['context'], p['operationId'], scope)
    if s.phase in ('PREPARED', 'STAGED'):
        need(not _claim_path(s).exists(), 'ALREADY_CLAIMED')
    else:
        need(reader._json(_claim_path(s)) == _claim(s), 'CLAIM')


def prepare_root(path, pin):
    _pins()
    scope_path = c._plain(path, ROOT/'artifacts/designer-bridge')
    scope = reader._json(scope_path, pin); validate_scope(scope)
    _checked_prior(scope)
    _audit_workday_pending(dict(processId=48936,birth='01dd5d0180299126'), scope=scope)
    parent = prepare_parent(scope_path, pin)
    p = dict(parent.plan)
    op = uuid.uuid4().hex; out = ROOT/'build'/('designer-hot-v234-'+op)
    for key in ('pendingReadProfile', 'actualReadSourceSha256', 'pendingReadControllerSha256', 'pendingScopeSha256'):
        p.pop(key, None)
    p.update(version=PROFILE_VERSION, profileVersion=PROFILE_VERSION, explicitWorkdayGrantAuthorized=True,
        workdayControllerSha256=c.digest(c.read(Path(__file__))), operationId=op, outputDirectory=str(out), updatePreviewProfile=PROFILE,
        updatePreviewControllerSha256=c.digest(c.read(Path(__file__))), actualSourceSha256=SOURCE_SHA,
        admittedSourceSha256=ADMITTED_SHA, nativeRamCarrierSha256=CARRIER_SHA, residentProviderSha256=PROVIDER_SHA,
        updatePreviewScopeSha256=pin, readScopeSha256=parent.review_sha256, writerAuthorized=False,
        captureAuthorized=False, applicationWrites=0, expectedDatabaseSource=1383504556,
        **limits(), **{k: True for k in TRUE_AUTH}, **{k: False for k in FALSE_AUTH})
    p['goldLeaseOwner'], p['goldLeaseBootstrapSha256'] = base.owner_base._lease_binding(p['context'])
    previous.check_clock()
    from native_mcp.workday_channel import WorkdayResidentChannel
    nonce = uuid.uuid4().hex
    channel = WorkdayResidentChannel(48936, install_nonce=nonce, expected_birth='01dd5d0180299126', timeout=15)
    try:
        api = _Api(); now = time.monotonic()
        configuration = dict(operationId=op, scopeSha256=pin, sessionId=p['context']['heldNonce'],
            installNonce=nonce, serverPid=os.getpid(), serverBirth=api.birth(api.k.GetCurrentProcess()),
            pipePath=channel.path, installedAt=now, sessionValidUntil=now+28800,
            armPath=(out/'resident-arm.bin').as_posix(), resultPath=(out/'resident-sdk-result.bin').as_posix())
        p['residentConfiguration'] = configuration
        s = WorkdayOperation(_ISSUER, parent, scope_path, pin, scope, p, c.canonical(p), {}, channel)
        _check(s)
        ns = parent.private; ns['__pending_read_operation'] = op
        def fresh(plan):
            _check(s); need(plan == s.plan, 'FRESH_PLAN'); _fresh_workday(base._carrier_view(plan))
        def render(plan, raw):
            need(plan == s.plan, 'RENDER_PLAN'); return _render(s)
        old_no_pending = ns['_no_pending']
        def no_pending(allow_operation=None,context=None):
            _audit_workday_pending(context,op,s.scope)
            return old_no_pending(allow_operation=allow_operation,context=context)
        ns.update(_fresh=fresh, render=render, _no_pending=no_pending); s.private = ns
        ns['_no_pending'](context=p['context'])
        return s
    except BaseException:
        channel.abort_before_connect(); channel.wait_closed()
        raise


def _identity(s):
    ctx = s.plan['context']
    return dict(processId=ctx['processId'], birth=ctx['birth'], guiThreadId=ctx['guiThreadId'],
                engineAddress=0x34554a0, moduleAddress=0x34fc380)


def _render(s):
    _check(s); p = s.plan
    files = c.render(base._carrier_view(p), c.read(HERE/c._probe_spec(reader.PROBE)[0], 32768))
    header = files['sdk_probe_params.h'].decode()
    for name, expected in (('ENGINE_ADDRESS', 0x34554a0), ('MODULE_ADDRESS', 0x34fc380)):
        found = re.search(r'^#define AH_SDK_'+name+r' (0x[0-9a-fA-F]+)U$', header, re.M)
        need(found is not None and int(found[1], 16) == expected, 'SDK_ADDRESS')
    raw, admitted = _source()
    line = next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
    files['sdk_probe_params.h'] = c._replace_once(header, line,
        '#define AH_SDK_FIXED_SOURCE '+json.dumps(admitted.decode(), ensure_ascii=False)).encode()
    files['Continuation.c'] = _carrier().render(raw, configuration=p['residentConfiguration'], identity=_identity(s))
    anchor = _carrier().SECTION_ANCHOR.encode('ascii')
    need(files['Continuation.c'].count(anchor) == 1, 'SECTION_ANCHOR')
    files['Continuation.c'] = files['Continuation.c'].replace(anchor, section_identity.ANCHOR, 1)
    files.pop('run-fixed.ps1')
    files.update(managed.render(p['residentConfiguration'], _identity(s)))
    files, receipt = section_identity.with_section_identity(files,
        operation_kind='WORKDAY_SAVED_RAM', operation_id=p['operationId'])
    need(receipt['actualSourceSha256'] == ADMITTED_SHA, 'COMPILED_SOURCE_JOIN')
    return files


def abort_before_start(s):
    need(type(s) is WorkdayOperation and s.issuer is _ISSUER, 'ABORT_SCOPE')
    if s.phase in ('PREPARED', 'STAGED'):
        if not s.channel.closed and not s.channel.sealed:
            s.channel.abort_before_connect()
        need(s.channel.wait_closed(), 'UNSTARTED_OWNER_CLOSE')


def stage_root(s):
    try:
        _check(s); need(s.phase == 'PREPARED', 'STAGE_PHASE')
        s.private['FILES'] = tuple(_render(s))
        # Frozen compiler grant/build-proof version233 identifies its transport
        # ABI. The sealed operation, output path and explicit grant are v234.
        proof = s.private['stage_private'](s.plan, dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',
            rootAuthorized=True, planSha256=c.digest(s.plan_raw)))
        s.phase = 'STAGED'; return proof
    except BaseException:
        abort_before_start(s); raise


def require_stage(s):
    try:
        _check(s)
        return s.private['require_stage'](s.plan)
    except BaseException:
        abort_before_start(s); raise


def _unknown(s, reason):
    s.phase = 'UNKNOWN_RETAIN'
    row = dict(kind='WORKDAY_SAVED_RAM_UNKNOWN', version=234, operationId=s.plan['operationId'],
        status=s.phase, knownTerminal=False, retryAuthorized=False, reason=reason,
        permanentMcpBindingVerified=False, configurationExports=0, configurationImports=0,
        configurationSaves=0, databaseUpdates=0, repositoryMutations=0)
    path = Path(s.plan['outputDirectory'])/'unknown.json'
    if not path.exists():
        c.write_new(path, row)
    return row


def _fresh_identity_gate(s):
    started = time.perf_counter_ns()
    try:
        _hot_check(s)
        api = _Api(); handle = api.pin_process(48936, '01dd5d0180299126')
        try:
            api.live_process(handle, '01dd5d0180299126')
            main = Path(s.plan['context']['buildDirectory'])/'runtime/modules/snegopat/engine/main.as'
            need(c.digest(c.read(main)) == MAIN_SHA, 'LIVE_MAIN_PIN')
        finally:
            api.w.CloseHandle(handle)
    except BaseException:
        if type(s) is WorkdayOperation and s.issuer is _ISSUER:
            s.phase = 'UNKNOWN_RETAIN'
        raise
    finally:
        if type(s) is WorkdayOperation and s.issuer is _ISSUER:
            elapsed = max(0, time.perf_counter_ns()-started)
            profile = s.private.setdefault('_hot_profile', dict(freshGateCalls=0,totalNanoseconds=0,maxNanoseconds=0))
            need(type(profile) is dict and set(profile) == {'freshGateCalls','totalNanoseconds','maxNanoseconds'}
                 and all(type(v) is int and 0 <= v < 2**63 for v in profile.values()), 'HOT_PROFILE')
            profile['freshGateCalls'] += 1
            profile['totalNanoseconds'] += elapsed
            profile['maxNanoseconds'] = max(profile['maxNanoseconds'],elapsed)
    return SessionIdentity('218b5d00-7e10-486f-874c-73c2368ed5da',
        s.plan['context']['heldNonce'], 48936, '01dd5d0180299126', 'database_saved')


def _managed_join(s):
    need(s.phase in ('READY', 'CLOSING') and not s.join_attempted and s.channel.closed, 'JOIN_PHASE')
    s.join_attempted = True; s.phase = 'CLOSING'
    need(s.host is not None and s.host.poll() is None and s.host.stdin is not None, 'HOST_LIVE')
    s.host.stdin.write(b'JOIN_VERIFIED_CLOSE\n'); s.host.stdin.flush(); s.host.stdin.close()
    out = Path(s.plan['outputDirectory']); deadline = time.monotonic()+25
    while time.monotonic() < deadline:
        path = out/'resident-host-result.json'
        if path.is_file():
            try:
                row = reader._json(path, bound=4096)
            except (OSError, ValueError):
                time.sleep(.02); continue
            need(row.get('kind') == 'RESIDENT_MANAGED_TERMINAL'
                 and row.get('operationId') == s.plan['operationId'] and row.get('knownTerminal') is True
                 and row.get('hookWorkersReleased') is True and row.get('writerAuthorized') is False
                 and type(row.get('sdkResult')) is int and row['sdkResult'] == 0
                 and type(row.get('threadId')) is int and row['threadId'] == 8292, 'HOST_CLOSURE')
            s.host.wait(timeout=5)
            need(type(s.host.returncode) is int and s.host.returncode == 0 and s.channel.wait_closed(), 'HOST_EXIT')
            raw = c.read(out/'resident-sdk-result.bin', 4)
            need(raw == struct.pack('<I', 0), 'NATIVE_BOOTSTRAP_RC')
            _fresh_identity_gate(s)
            return dict(row, processId=48936, processExitCode=0, rawSdkResult=0)
        if s.host.poll() is not None:
            break
        time.sleep(.02)
    raise ValueError('WORKDAY_OPERATION_HOST_JOIN_UNKNOWN')


def _start_root_once(s, review_path, review_pin):
    """Start one reviewed fixed resident host; never executes business methods."""
    _check(s); need(s.phase == 'STAGED', 'START_PHASE')
    build = require_stage(s)
    review = reader._json(c._plain(review_path, ROOT/'artifacts/designer-bridge'), review_pin)
    need(review.get('kind') == 'ROOT_WORKDAY_SAVED_RAM_RUN' and review.get('passed') is True
         and type(review.get('profileVersion')) is int and review['profileVersion'] == PROFILE_VERSION
         and review.get('workdayControllerSha256') == s.plan['workdayControllerSha256']
         and review.get('explicitWorkdayGrantAuthorized') is True
         and authority(review) and review.get('planSha256') == c.digest(s.plan_raw)
         and review.get('buildSha256') == c.digest(c.canonical(build))
         and review.get('scopeSha256') == s.scope_sha256 and review.get('actualSourceSha256') == SOURCE_SHA
         and review.get('admittedSourceSha256') == ADMITTED_SHA
         and review.get('nativeRamCarrierSha256') == CARRIER_SHA
         and review.get('residentProviderSha256') == PROVIDER_SHA, 'ROOT_RUN')
    s.private['_no_pending'](context=s.plan['context']); _fresh_workday(base._carrier_view(s.plan))
    need(time.monotonic()+30 < s.plan['residentConfiguration']['sessionValidUntil'], 'INSTALL_EXPIRED')
    out = Path(s.plan['outputDirectory'])
    need(not any((out/name).exists() for name in ('intent.json', 'resident-arm.bin', 'resident-sdk-result.bin',
             'resident-host-ready.json', 'resident-host-result.json', 'unknown.json')), 'ONE_ATTEMPT')
    _seal_admission(s, review_pin)
    c.write_new(_claim_path(s), _claim(s))
    c.write_new(out/'intent.json', _intent(s, review_pin))
    s.phase = 'STARTING_RETAIN'
    try:
        s.host = subprocess.Popen([str(reader.writer.PS), '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', str(out/'run-resident.ps1')], cwd=out, stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        c.write_new(out/'host-identity.json', reader.writer._host_identity(s.host))
        # Start() waits for C's arm receipt AFTER C authenticates this pipe.
        # Waiting for managed ready before connect would deadlock that handshake.
        s.channel.connect()
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            path = out/'resident-host-ready.json'
            if path.is_file():
                try:
                    ready_row = reader._json(path, bound=4096)
                except (OSError, ValueError):
                    time.sleep(.02); continue
                need(ready_row.get('kind') == 'RESIDENT_MANAGED_READY'
                     and ready_row.get('operationId') == s.plan['operationId']
                     and type(ready_row.get('processId')) is int and ready_row['processId'] == 48936
                     and type(ready_row.get('threadId')) is int and ready_row['threadId'] == 8292
                     and ready_row.get('nativeSourceBindingVerified') is False
                     and ready_row.get('workerExpectedAlive') is True and s.host.poll() is None
                     and c.read(out/'resident-arm.bin', 8) == b'\0'*8, 'HOST_READY')
                s.phase = 'READY'
                _fresh_identity_gate(s)
                module = importlib.import_module('native_mcp.workday_provider')
                s.provider = module.WorkdayResidentProvider(s.channel, s.plan['residentConfiguration'], _identity(s),
                    fresh_identity_gate=lambda: _fresh_identity_gate(s), managed_join=lambda: _managed_join(s))
                s.broker = SessionBroker(_fresh_identity_gate(s), s.provider.make_ports, s.provider.close)
                c.write_new(out/'connected.json', dict(kind='WORKDAY_SAVED_RAM_CONNECTED',
                    operationId=s.plan['operationId'], knownTerminal=False, nativeSourceBindingVerified=False,
                    providerReady=True, sourceBodyFilesCreated=0, applicationWrites=0))
                return dict(status='CONNECTED', operationId=s.plan['operationId'], knownTerminal=False,
                            sourceBodyFilesCreated=0, nativeSourceBindingVerified=False)
            if s.host.poll() is not None or (out/'resident-host-result.json').is_file():
                break
            time.sleep(.02)
        return _unknown(s, 'MANAGED_READY_UNPROVEN')
    except Exception:
        return _unknown(s, 'START_OR_CHANNEL_UNPROVEN')


def start_root_once(s, review_path, review_pin):
    try:
        return _start_root_once(s, review_path, review_pin)
    except BaseException:
        abort_before_start(s)
        raise


def close_root(s):
    """Close through native proof/ACK/EOF and the owned managed host join."""
    _check(s); need(s.phase in ('READY', 'CLOSING') and s.broker is not None, 'CLOSE_PHASE')
    try:
        need(s.broker.close() == 'CLOSED' and s.join_attempted
             and type(s.host.returncode) is int and s.host.returncode == 0
             and s.channel.closed, 'FINAL_CLOSURE')
        s.phase = 'CLOSED'
        result = dict(kind='WORKDAY_SAVED_RAM_SESSION_RESULT', version=234,
            operationId=s.plan['operationId'], status='WORKDAY_SAVED_RAM_CLOSED', knownTerminal=True,
            planSha256=c.digest(s.plan_raw), sdkResult=0, hookWorkersReleased=True,
            targetIdentityVerified=True, nativeInjectionPerformed=True, sourceBodyFilesCreated=0,
            configurationExports=0, configurationImports=0, configurationSaves=0,
            databaseUpdates=0, repositoryMutations=0, retryAuthorized=False,
            permanentMcpBindingVerified=False)
        c.write_new(Path(s.plan['outputDirectory'])/'result.json', result)
        return result
    except Exception:
        return _unknown(s, 'NATIVE_OR_HOST_CLOSURE_UNPROVEN')
