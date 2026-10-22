"""Root-only V3 editor lifecycle over the existing current resident owner.

The v233 plan probe identifies the proven bootstrap/compiler/lifetime route;
editorProtocolVersion/profile/source pins and this module's explicit authority
identify the new writer. It is not the frozen read-only scope or V1 channel.
Importing this module installs nothing. Unknown native outcomes retain ownership.
"""
from dataclasses import asdict
from contextlib import closing
import hashlib
import math
import os
from pathlib import Path
import subprocess
import time
from types import FunctionType, SimpleNamespace
import uuid

import live_resident_current_operation as current

CURRENT_SHA = '0bc555b9e705cfc7180b9dec966b43de21c50db38cdabc61348153e4a79cb0bc'
if hashlib.sha256(Path(current.__file__).read_bytes()).hexdigest() != CURRENT_SHA:
    raise ValueError('LIVE_EDITOR_CURRENT_PIN')
for _name, _value in tuple(vars(current).items()):
    if _name.startswith('__'):
        continue
    if isinstance(_value, FunctionType) and _value.__globals__ is vars(current):
        _fn = FunctionType(_value.__code__, globals(), _name, _value.__defaults__, _value.__closure__)
        _fn.__kwdefaults__ = _value.__kwdefaults__
        globals()[_name] = _fn
    else:
        globals()[_name] = _value

PROFILE = 'PROCESSING_EDITOR_V3_VERIFY_UNDO'
CURRENT_SCOPE = 'ROOT_CURRENT_EDITOR_V3_SCOPE'
CURRENT_RUN = 'ROOT_CURRENT_EDITOR_V3_RUN'
SOURCE_NAME = 'NativeLiveEditorCommand.as'
SOURCE_SHA = '552c5f1f4f7851e01053f78b0619bd9dd9bfe363606034e36b346e1a47d64dcd'
CARRIER_SHA = '7bb8d3cc7d3558caa3afa495b9f52981a0de01e6cd1823e23995c607e4a37a4f'
TRANSPORT_SHA = '772567491fad6a0ce5f019b140eb61255a03fe3698c558d80a99f54804a74b2c'
CHANNEL_SHA = 'e0150201c1d429336afaafc8d2d34285f6a56ff4f8fbaaebeedaa8216babba36'
REPOSITORY_TRANSPORT_SHA = '5b4a923288a97a7bcc02c166775e605ad0d9acb8a890d2dd60fbc8925026804d'
CAPTURE_TRANSPORT_SHA = 'bca7ecb0de3414cf68ce22a7ff3321b367aab42f6ffaac049452900e8aec958e'
ACTIVATION_TRANSPORT_SHA = '155c9d2bca98a7d4c68f7f460d054bcb614989080b7af96b5f55650cab8645b0'
COMMAND_SHA = 'b56fa3499b7d59546c8b0a5bd68407e8437679b546c0093f0870f4881942a82c'
CHANGE_PLAN_SHA = '341ed4e5e42a2f674b47a799f62b0510c411c913f32ca1a2c89fdf1209762d89'
JOB_SHA = 'fc96347e103fb672c1d56fc912d733924d31b3fd03fb3925b0f466bfab1ece63'
NATIVE_WIRE_SHA = 'a4654ed50dc1dca0772f5e5b2165a36e8abfa190806ecebdb53b7171a82900d8'
REPOSITORY_SOURCE_SHA = 'd54c0c7f8388df378ebad3e8880325b2364eb306c561f32c179ad887c58748de'
RETAINED_READ_ACCOUNTING_SHA = '7832a5507bae667cfc914c35757de762b4ff4313cc5023d9d3d4cd3dcd96d078'
TERMINAL_ACCOUNTING_SHA = '7fbe3a559ec7620d612d46e501bd84ee619d1eaf371a0e426b610597704c0bed'
ACCOUNTED_RETAINED_SHA = '915aaadeb93786eceadd2e9ff771e70ee551ed4be8b02d73bbb0f09bdbafc6a5'
ACCOUNTED_REFUSED_SHA = '4dc78b0e97b4842268e7caba42ce474aff6bc6686bcebd7d80623f2807166496'
ACCOUNTED_CLEAN_REFUSED_SHA = 'a1da2ad319b423509f95ca89fd7ffcd96adfe9ab5ecfe1a4d8b6ec83a3b9922c'
ACCOUNTED_CAPTURE_FAULT_SHA = '7ff1a7c9925dfe764678a6c25e6e4627025a78d0c1a2c2625c3e5598275377e5'
ACCOUNTED_CLOSED_CAPTURE_SHA = '6a612becae7a5b66d8e5e225e69927b5ca6a8b66ad48d93a22d77c4c659ba9fe'
ACCOUNTED_READY_FAULT_SHA = '2858e944975343a24d851a095b3e7c8e30d1b9d219945d48c18faecd14605774'
ROOT_UUID = '218b5d00-7e10-486f-874c-73c2368ed5da'
TARGET_UUID = 'd593e80d-b70c-400b-9955-d02f7a4c89e9'
CLASS_UUID = 'bf845118-327b-4682-b5c6-285d2a0eb296'
PROPERTY_UUID = 'a637f77f-3840-441d-a1c3-699c8c5cb7e0'
SOURCE_DOMAIN = 'editor_live_at_capture'
ARM_FILE = 'live-editor-arm.bin'
WORKER_FILE = 'live-editor-worker-result.bin'
HOST_READY = 'live-editor-host-ready.json'
HOST_RESULT = 'live-editor-host-result.json'
HOST_SCRIPT = 'run-live-editor.ps1'
ACTIVATION_PRIOR_OPERATION = 'ded682d2a34e4ea390bc5ad532e67e6f'
ACTIVATION_PRIOR_RECEIPT_NAME = 'editor-capture-closed-reconciled-' + ACTIVATION_PRIOR_OPERATION + '.json'
ACTIVATION_PRIOR_RECEIPT_SHA = 'da827dd5b8f9fe79a6d9fbd83c51231004500b129219ad7e98828e27a8c85343'
ACTIVATION_PRIOR_PHASE_SHA = '16963c6a5bfc4d834f8c6ca83f5e9fb18ca6032c59dcc2a6289febfc64b01afc'
ACTIVATION_PRIOR_PLAN_SHA = '7d07fdf7a9321cca7b4bb4ecfb842420de57d743f1080fd3d59c34f0f0dbeec8'
ACTIVATION_PRIOR_PLAN_FILE_SHA = 'd171958f4381427fcab08f6e4170ccefb876d37ecfc412d5f0f4dc56791a68da'
TRUE_AUTH = tuple(k for k in current.TRUE_AUTH if k not in
                  ('configurationReadOnly', 'arbitraryCommonModuleSelectionAuthorized')) + (
    'sourceWritesAuthorized', 'ownFixtureMutationAuthorized', 'writerAuthorized', 'ownUndoAuthorized')
FALSE_AUTH = tuple(k for k in current.FALSE_AUTH if k not in
                   ('sourceWritesAuthorized', 'ownFixtureMutationAuthorized', 'writerAuthorized',
                    'captureAuthorized', 'repositoryMutationsAuthorized')) + (
    'configurationReadOnly', 'arbitraryCommonModuleSelectionAuthorized')
ACTIVATION_DENIED = ('sourceWritesAuthorized', 'ownFixtureMutationAuthorized',
                     'writerAuthorized', 'ownUndoAuthorized', 'captureAuthorized',
                     'repositoryMutationsAuthorized')
_ISSUER = object()
_SEALS = {}
_EDITOR_STATES = {}
_current_check = _check
_current_fresh_gate = _fresh_identity_gate
_current_abort = abort_before_start


def need(ok, code):
    if not ok:
        raise ValueError('LIVE_EDITOR_OPERATION_' + code)


def limits(activation_only=False, isolated_writer=False, apply_edit=False):
    """Per-job upper bounds; actual READ/EDIT counts remain separate facts."""
    answer = dict(maximumCommands=64, maximumReads=64, maximumEdits=1, maximumSessionSeconds=600,
                maximumRequestTtlMilliseconds=60000, maximumEditorOpens=1, maximumDirectSaves=32,
                maximumStateBridgeCalls=3, maximumCaptureCalls=3, maximumCommitCalls=3,
                maximumPublishedSetters=1, maximumOwnUndoCalls=1, maximumSourceUtf16Units=131072,
                maximumWarmupGetterReads=1, maximumBodyBytes=524288, maximumRepositoryPacketBytes=1048576,
                maximumCaptureCommands=1)
    if activation_only:
        answer.update(maximumEdits=0, maximumPublishedSetters=0, maximumOwnUndoCalls=0,
                      maximumCaptureCommands=0, maximumActivationCommands=1)
    if isolated_writer:
        answer['maximumCaptureCommands'] = 0
    if apply_edit:
        answer.update(maximumOwnUndoCalls=0, maximumCaptureCommands=0)
    return answer


def _authority_fields(activation_only=False):
    answer = dict(**{key: True for key in TRUE_AUTH}, **{key: False for key in FALSE_AUTH})
    if activation_only:
        answer.update({key: False for key in ACTIVATION_DENIED})
        answer.update(activationOnlyAuthorized=True, captureOnlyAuthorized=False,
                      setterAuthorized=False, sourceEditAuthorized=False, cancelAuthorized=False)
    return answer


def _activation_provenance(*, prior_receipt_path, prior_receipt_sha256):
    """Read only pinned technical evidence; absent historical actor stays absent."""
    artifacts = ROOT / 'artifacts/designer-bridge'
    exact = artifacts / ACTIVATION_PRIOR_RECEIPT_NAME
    need(Path(prior_receipt_path).resolve() == exact.resolve()
         and prior_receipt_sha256 == ACTIVATION_PRIOR_RECEIPT_SHA, 'ACTIVATION_PRIOR_RECEIPT')
    receipt = ram.previous._json(c._plain(exact, artifacts), ACTIVATION_PRIOR_RECEIPT_SHA, bound=32768)
    phase = ram.previous._json(c._plain(artifacts / ('editor-capture-phase-proof-' + ACTIVATION_PRIOR_OPERATION + '.json'), artifacts),
                               ACTIVATION_PRIOR_PHASE_SHA, bound=32768)
    plan = ram.previous._json(c._plain(ROOT / 'build' / ('designer-hot-v233-' + ACTIVATION_PRIOR_OPERATION) / 'plan.json', ROOT / 'build'),
                              ACTIVATION_PRIOR_PLAN_FILE_SHA, bound=32768)
    need(receipt.get('kind') == 'EDITOR_CAPTURE_CLOSED_RECONCILED'
         and receipt.get('operationId') == phase.get('operationId') == plan.get('operationId') == ACTIVATION_PRIOR_OPERATION
         and receipt.get('planSha256') == ACTIVATION_PRIOR_PLAN_SHA
         and c.digest(c.canonical(plan)) == ACTIVATION_PRIOR_PLAN_SHA
         and receipt.get('scopeSha256') == plan.get('currentScopeSha256')
         and all(receipt.get(k) is True for k in ('captureVerified', 'captureOwnRetained', 'operationResourcesClosed',
              'hookWorkersReleased', 'nativeContextClosed', 'nativeFunctionClosed', 'nativeJobClosed'))
         and all(receipt.get(k) is False for k in ('activationVerified', 'refreshVerified', 'editAuthorized',
              'cancelAuthorized', 'acquisitionProven', 'newDispatchAuthorized', 'retryAuthorized', 'sourceBodyPersisted'))
         and receipt.get('totalCaptureCommands') == receipt.get('totalRepositoryMutationAttempts') == 1
         and receipt.get('totalSourceWrites') == 0, 'ACTIVATION_PRIOR_CLOSURE')
    need((plan.get('rootUuid'), plan.get('moduleObjectId'), plan.get('metadataClassId'), plan.get('modulePropertyId'))
         == (ROOT_UUID, TARGET_UUID, CLASS_UUID, PROPERTY_UUID)
         and phase.get('kind') == 'EDITOR_CAPTURE_PHASE_VERIFIED_CLOSURE_RECONCILIATION_PENDING'
         and phase.get('sourceUnchanged') is True and phase.get('captureVerified') is True
         and phase.get('sourceBodiesPersisted') is False
         and all(phase.get(k) == 0 for k in ('applicationWrites', 'configurationSaves', 'databaseUpdates', 'storagePlacement')),
         'ACTIVATION_PRIOR_TARGET_SOURCE')
    observations = phase.get('observations')
    need(type(observations) is list and len(observations) == 3, 'ACTIVATION_PRIOR_PHASE')
    before, captured, after = observations
    need([row.get('opcode') for row in observations] == [1, 5, 1]
         and [row.get('sequence') for row in observations] == [1, 2, 3]
         and all(row.get('jobReleased') is True for row in observations)
         and (before.get('ownerClass'), after.get('ownerClass')) == (0, 1)
         and before.get('sourceSha256') == after.get('sourceSha256')
         and ram.previous._hex(after.get('sourceSha256'), 64)
         and before.get('ownerVersion') == after.get('ownerVersion') == receipt.get('captureObservationVersion') == 2467
         and before.get('documentReadOnly') is True and after.get('documentReadOnly') is True
         and before.get('documentModified') is False and after.get('documentModified') is False
         and captured.get('captureVerified') is True and captured.get('activationVerified') is False
         and captured.get('beforeVersion') == captured.get('afterVersion') == 2467,
         'ACTIVATION_PRIOR_PHASE')
    facts = captured.get('facts', {})
    need(all(facts.get(k) == 1 for k in ('capture_scoped', 'capture_verified', 'capture_attempts', 'capture_returned',
         'baseline_compared', 'readback_compared', 'cleanup_complete', 'durable_intent_verified', 'stat_before_valid', 'stat_after_valid'))
         and all(facts.get(k) == 0 for k in ('unknown', 'native_pending', 'activation_verified', 'mode_attempts',
         'event_attempts', 'source_refresh', 'edit_authorized', 'cancel_authorized', 'generation_verified')),
         'ACTIVATION_PRIOR_CAPTURE')
    identity = {key: plan['context'][key] for key in ('processId', 'birth', 'guiThreadId')}
    need(identity == dict(processId=29576, birth='01dd5fb7f0cd1090', guiThreadId=15816)
         and all(receipt['after']['native'].get(key) == identity[key] for key in ('processId', 'birth')),
         'ACTIVATION_PRIOR_IDENTITY')
    return dict(activationPriorReceiptPath=str(exact.resolve()), activationPriorReceiptSha256=prior_receipt_sha256,
                activationPriorPhaseSha256=ACTIVATION_PRIOR_PHASE_SHA, activationPriorPlanSha256=ACTIVATION_PRIOR_PLAN_SHA,
                activationPriorPlanFileSha256=ACTIVATION_PRIOR_PLAN_FILE_SHA,
                activationPriorOperationId=ACTIVATION_PRIOR_OPERATION, activationExpectedVersion=2467,
                activationExpectedSourceSha256=after['sourceSha256'], activationPriorIdentity=identity)


def activation_scope_fields(*, prior_receipt_path, prior_receipt_sha256):
    """Return Root's activation-only authority and pinned provenance, without I/O writes.

    The receipt proves historical closure; phase and plan prove target, source
    and version. Actor authority is intentionally obtained only from a fresh
    authenticated READ in the new owner, never invented from these artifacts.
    """
    return dict(**_authority_fields(True), **limits(True),
        **_activation_provenance(prior_receipt_path=prior_receipt_path, prior_receipt_sha256=prior_receipt_sha256),
        editorActivationTransportSha256=ACTIVATION_TRANSPORT_SHA,
        allowedEditObjects=[], editPolicy='ACTIVATE_OWN6')


def isolated_writer_scope_fields():
    """Exact Root scope/run fields for one fixture setter+own Undo, no dispatch."""
    return dict(**_authority_fields(), **limits(isolated_writer=True),
        isolatedWriterProbeAuthorized=True, retainedReadOnlyExperiment=False,
        captureOnlyAuthorized=False, captureAuthorized=False, repositoryMutationsAuthorized=False,
        activationOnlyAuthorized=False, cancelAuthorized=False,
        rootUuid=ROOT_UUID, moduleObjectId=TARGET_UUID, metadataClassId=CLASS_UUID,
        modulePropertyId=PROPERTY_UUID, allowedReadClasses=['Processing'],
        allowedEditObjects=[TARGET_UUID], editPolicy='EDIT_VERIFY_UNDO')


def apply_scope_fields():
    """Explicit one-setter admission; ordinary edit may invalidate prior Redo.

    This grants neither an automatic Undo nor Save/DB/repository operations.
    A fresh completed OWN read and a private RootRun are still mandatory.
    """
    fields = dict(**_authority_fields(), **limits(apply_edit=True),
        isolatedApplyAuthorized=True, isolatedWriterProbeAuthorized=False,
        retainedReadOnlyExperiment=False, captureOnlyAuthorized=False,
        captureAuthorized=False, repositoryMutationsAuthorized=False,
        activationOnlyAuthorized=False, cancelAuthorized=False,
        ordinaryRedoInvalidationAuthorized=True,
        rootUuid=ROOT_UUID, moduleObjectId=TARGET_UUID, metadataClassId=CLASS_UUID,
        modulePropertyId=PROPERTY_UUID, allowedReadClasses=['Processing'],
        allowedEditObjects=[TARGET_UUID], editPolicy='EDIT_APPLY_SINGLE_LINE')
    fields['ownUndoAuthorized'] = False
    return fields


def _apply_fields_match(row):
    return type(row) is dict and all(type(row.get(key)) is type(value) and row[key] == value
                                    for key, value in apply_scope_fields().items()) and _apply_content_valid(row)


APPLY_CONTENT_KEYS = frozenset(('baselineSha256', 'candidateSha256', 'baselineUtf16Units',
    'candidateUtf16Units', 'startUtf16', 'stopUtf16', 'replacementUtf16Units'))


def _apply_content_valid(row):
    content = row.get('applyContent')
    if type(content) is not dict or content.keys() != APPLY_CONTENT_KEYS:
        return False
    if not all(ram.previous._hex(content[key], 64) for key in ('baselineSha256', 'candidateSha256')):
        return False
    if not all(type(content[key]) is int and 0 <= content[key] <= 131072
               for key in APPLY_CONTENT_KEYS - {'baselineSha256', 'candidateSha256'}):
        return False
    return (content['baselineSha256'] != content['candidateSha256']
            and content['startUtf16'] <= content['stopUtf16'] <= content['baselineUtf16Units']
            and content['candidateUtf16Units'] == content['baselineUtf16Units']
                - content['stopUtf16'] + content['startUtf16'] + content['replacementUtf16Units']
            and row.get('applyChangeSha256') == c.digest(c.canonical(content)))


def apply_change_fields(change):
    """Bind a validated RAM content plan into the Root scope/run by hashes.

    Returns metadata only. Neither this manifest nor its digest admits an edit.
    """
    planner = _module('native_mcp.editor_change_plan', CHANGE_PLAN_SHA)
    need(type(change) is planner.EditorChangePlan, 'APPLY_CHANGE_PLAN')
    change.validate()
    content = dict(baselineSha256=change.baseline_sha256, candidateSha256=change.candidate_sha256,
        baselineUtf16Units=change.baseline_utf16_units, candidateUtf16Units=change.candidate_utf16_units,
        startUtf16=change.start_utf16, stopUtf16=change.stop_utf16,
        replacementUtf16Units=change.replacement_utf16_units)
    return dict(applyContent=content, applyChangeSha256=c.digest(c.canonical(content)))


def _isolated_fields_match(row):
    return type(row) is dict and all(type(row.get(key)) is type(value) and row[key] == value
                                    for key, value in isolated_writer_scope_fields().items())


def authority(row):
    if type(row) is not dict or type(row.get('activationOnlyAuthorized', False)) is not bool:
        return False
    if type(row.get('isolatedWriterProbeAuthorized', False)) is not bool:
        return False
    if type(row.get('isolatedApplyAuthorized', False)) is not bool:
        return False
    if row.get('isolatedApplyAuthorized', False):
        return _apply_fields_match(row)
    if row.get('isolatedWriterProbeAuthorized', False):
        return _isolated_fields_match(row)
    activation = row.get('activationOnlyAuthorized', False)
    if activation:
        return (all(row.get(k) is value for k, value in _authority_fields(True).items())
                and all(type(row.get(k)) is int and row[k] == n for k, n in limits(True).items()))
    return (all(row.get(k) is True for k in TRUE_AUTH)
            and all(row.get(k) is False for k in FALSE_AUTH)
            and type(row.get('captureOnlyAuthorized', False)) is bool
            and all(row.get(k, False) is row.get('captureOnlyAuthorized', False)
                    for k in ('captureAuthorized', 'repositoryMutationsAuthorized'))
            and all(type(row.get(k)) is int and row[k] == n for k, n in limits().items()))


def _new_pins():
    return {'live_editor_carrier.py': CARRIER_SHA, 'NativeLiveEditorCommand.as': SOURCE_SHA,
            'live_editor_job.py': JOB_SHA, 'live_editor_wire_native.py': NATIVE_WIRE_SHA,
            'live_editor_repository_source.py': REPOSITORY_SOURCE_SHA,
            'live_editor_accounted_retained.py': ACCOUNTED_RETAINED_SHA,
            'live_editor_retained_read_accounting.py': RETAINED_READ_ACCOUNTING_SHA,
            'live_editor_terminal_accounting.py': TERMINAL_ACCOUNTING_SHA,
            'live_editor_accounted_refused.py': ACCOUNTED_REFUSED_SHA,
            'live_editor_accounted_clean_refused.py': ACCOUNTED_CLEAN_REFUSED_SHA,
            'live_editor_accounted_capture_fault.py': ACCOUNTED_CAPTURE_FAULT_SHA,
            'live_editor_accounted_closed_capture.py': ACCOUNTED_CLOSED_CAPTURE_SHA,
            'live_editor_accounted_ready_fault.py': ACCOUNTED_READY_FAULT_SHA,
            'native_mcp.editor_command': COMMAND_SHA, 'native_mcp.editor_transport': TRANSPORT_SHA,
            'native_mcp.editor_change_plan': CHANGE_PLAN_SHA,
            'native_mcp.windows_editor_pipe': CHANNEL_SHA,
            'native_mcp.editor_repository_transport': REPOSITORY_TRANSPORT_SHA,
            'native_mcp.editor_capture_transport': CAPTURE_TRANSPORT_SHA,
            'native_mcp.editor_activation_transport': ACTIVATION_TRANSPORT_SHA}


def _pins():
    need(c.digest(c.read(Path(current.__file__))) == CURRENT_SHA, 'CURRENT_PIN')
    # Keep historical proof namespaces intact. Their source pins describe the
    # old read-only runs; they never constitute this writer's authorization.
    current._pins()
    for name, pin in _new_pins().items():
        need(ram.previous._hex(pin, 64), 'DEPENDENCY_NOT_FROZEN')
        path = ((HERE.parent / name.replace('.', '/')).with_suffix('.py')
                if name.startswith('native_mcp.') else HERE / name)
        need(c.digest(c.read(path)) == pin, 'DEPENDENCY_PIN')


def _components():
    _pins()
    return SimpleNamespace(
        command=_module('native_mcp.editor_command', COMMAND_SHA),
        transport=_module('native_mcp.editor_transport', TRANSPORT_SHA),
        repository_transport=_module('native_mcp.editor_repository_transport', REPOSITORY_TRANSPORT_SHA),
        capture_transport=_module('native_mcp.editor_capture_transport', CAPTURE_TRANSPORT_SHA),
        activation_transport=_module('native_mcp.editor_activation_transport', ACTIVATION_TRANSPORT_SHA),
        pipe=_module('native_mcp.windows_editor_pipe', CHANNEL_SHA),
        carrier=_module('live_editor_carrier', CARRIER_SHA))


def validate_scope(row):
    need(all(ram.previous._hex(pin, 64) for pin in _new_pins().values()), 'DEPENDENCY_NOT_FROZEN')
    need(type(row) is dict and row.get('kind') == CURRENT_SCOPE and row.get('profile') == PROFILE
         and row.get('passed') is True and row.get('oneInstallation') is True
         and row.get('editorProtocolVersion') == 3 and authority(row), 'SCOPE_AUTHORITY')
    need(type(row.get('captureOnlyAuthorized', False)) is bool, 'CAPTURE_SCOPE_TYPE')
    activation = row.get('activationOnlyAuthorized', False)
    read_only = row.get('retainedReadOnlyExperiment', False)
    need(type(read_only) is bool and (not read_only or not (activation
         or row.get('captureOnlyAuthorized', False))), 'RETAINED_READ_SCOPE')
    if row.get('isolatedWriterProbeAuthorized', False):
        need(_isolated_fields_match(row), 'ISOLATED_WRITER_SCOPE')
    if row.get('isolatedApplyAuthorized', False):
        need(_apply_fields_match(row), 'APPLY_SCOPE')
    expected = dict(liveResidentControllerSha256=c.digest(c.read(Path(__file__))),
                    liveResidentCarrierSha256=CARRIER_SHA, actualSourceSha256=SOURCE_SHA,
                    editorCommandSha256=COMMAND_SHA, editorTransportSha256=TRANSPORT_SHA,
                    editorRepositoryTransportSha256=REPOSITORY_TRANSPORT_SHA,
                    editorCaptureTransportSha256=CAPTURE_TRANSPORT_SHA,
                    editorChannelSha256=CHANNEL_SHA, liveResidentJobSha256=JOB_SHA,
                    nativeEditorWireSha256=NATIVE_WIRE_SHA, sourceDomain=SOURCE_DOMAIN,
                    rootUuid=ROOT_UUID, moduleObjectId=TARGET_UUID, metadataClassId=CLASS_UUID,
                    modulePropertyId=PROPERTY_UUID, allowedReadClasses=['Processing'],
                    allowedEditObjects=[] if activation else [TARGET_UUID],
                    editPolicy='ACTIVATE_OWN6' if activation else
                               'EDIT_APPLY_SINGLE_LINE' if row.get('isolatedApplyAuthorized', False)
                               else 'EDIT_VERIFY_UNDO')
    if activation:
        expected['editorActivationTransportSha256'] = ACTIVATION_TRANSPORT_SHA
        expected.update(activation_scope_fields(prior_receipt_path=row.get('activationPriorReceiptPath', ''),
            prior_receipt_sha256=row.get('activationPriorReceiptSha256')))
    need(all(row.get(k) == value for k, value in expected.items()), 'SCOPE_BINDING')
    need(type(row.get('bootstrapKeeperPid')) is int and row['bootstrapKeeperPid'] > 0
         and ram.previous._hex(row.get('bootstrapKeeperBirth'), 16), 'KEEPER')


def _audit_accounted_retained(prior, out):
    module = _module('live_editor_accounted_retained', ACCOUNTED_RETAINED_SHA)
    need(module.validate(prior, out) is True, 'ACCOUNTED_RETAINED')


def _audit_accounted_refused(prior, out):
    module = _module('live_editor_accounted_refused', ACCOUNTED_REFUSED_SHA)
    need(module.validate(prior, out) is True, 'ACCOUNTED_REFUSED')


def _audit_accounted_clean_refused(prior, out):
    module = _module('live_editor_accounted_clean_refused', ACCOUNTED_CLEAN_REFUSED_SHA)
    need(module.validate(prior, out) is True, 'ACCOUNTED_CLEAN_REFUSED')


def _audit_accounted_capture_fault(prior, out):
    module = _module('live_editor_accounted_capture_fault', ACCOUNTED_CAPTURE_FAULT_SHA)
    need(module.validate(prior, out) is True, 'ACCOUNTED_CAPTURE_FAULT')


def _audit_accounted_closed_capture(prior, out):
    module = _module('live_editor_accounted_closed_capture', ACCOUNTED_CLOSED_CAPTURE_SHA)
    need(module.validate(prior, out) is True, 'ACCOUNTED_CLOSED_CAPTURE')


def _audit_accounted_ready_fault(prior, out):
    module = _module('live_editor_accounted_ready_fault', ACCOUNTED_READY_FAULT_SHA)
    need(module.validate(prior, out) is True, 'ACCOUNTED_READY_FAULT')


def _audit_retained_read(prior, out, s):
    if (s.scope.get('isolatedWriterProbeAuthorized', False) or s.plan.get('isolatedWriterProbeAuthorized', False)
            or s.scope.get('isolatedApplyAuthorized', False) or s.plan.get('isolatedApplyAuthorized', False)):
        _apply_scope(s) if s.plan.get('isolatedApplyAuthorized', False) else _isolated_writer_scope(s)
        module = _module('live_editor_retained_read_accounting', RETAINED_READ_ACCOUNTING_SHA)
        fact = module.validate_quarantined_prior(prior, out, new_operation_id=s.plan['operationId'])
        need(type(fact) is module.QuarantinedPriorFact and fact.issued_for(s.plan['operationId'])
             and fact.prior_operation_id == prior.get('operationId')
             and all(getattr(fact, key) is False for key in ('resources_closed', 'retry_authorized',
                 'new_dispatch_authorized', 'source_write_authorized', 'classified_benign')),
             'ISOLATED_PRIOR_QUARANTINE_FACT')
        return
    need(s.scope.get('retainedReadOnlyExperiment') is True
         and s.plan.get('retainedReadOnlyExperiment') is True, 'RETAINED_READ_SCOPE')
    module = _module('live_editor_retained_read_accounting', RETAINED_READ_ACCOUNTING_SHA)
    need(module.validate(prior, out, new_operation_id=s.plan['operationId'], read_only=True) is True,
         'ACCOUNTED_RETAINED_READ')


def _audit_terminal_writer(prior, out, s):
    """Observe an old quarantine under a separate explicit READ or APPLY scope.

    The fact is a current observation, never source-write or retry authority.
    All inherited reservation/history/lease guards still run independently.
    """
    apply = s.plan.get('isolatedApplyAuthorized', False)
    if apply:
        _apply_scope(s)
    need((apply or s.scope.get('retainedReadOnlyExperiment') is True
         and s.plan.get('retainedReadOnlyExperiment') is True
         and s.scope.get('isolatedWriterProbeAuthorized', False) is False
         and s.plan.get('isolatedWriterProbeAuthorized', False) is False),
         'TERMINAL_PRIOR_READ_ONLY_SCOPE')
    module = _module('live_editor_terminal_accounting', TERMINAL_ACCOUNTING_SHA)
    fact = (module.observe_quarantined_prior(prior, out, new_operation_id=s.plan['operationId']) if apply
            else module.validate_quarantined_prior(prior, out, new_operation_id=s.plan['operationId'], read_only=True))
    need(type(fact) is module.TerminalQuarantineFact and fact.issued_for(s.plan['operationId'])
         and fact.prior_operation_id == prior.get('operationId')
         and all(getattr(fact, key) is False for key in ('resources_closed', 'retry_authorized',
             'new_dispatch_authorized', 'source_write_authorized', 'classified_benign')),
         'TERMINAL_PRIOR_QUARANTINE_FACT')


def _no_pending(s):
    # Preserve the whole original reservation/history/post-history audit body.
    # f47 is evaluated in its historical namespace, including its old SOURCE_SHA.
    # Only these exact separately accounted prior jobs may bypass result.json.
    # Resources stay retained; neither prior operation may ever be retried.
    need(s.plan['operationId'] not in ('ab9c4e6a5f0141708f41898769e3b6d0',
         '1fd6560631834ab88fa2d9ecf9210995',
         'f07c1365e4504afa98262df0ae0abe91',
         '1d1858deb31f45ff83766dadb3513603',
         'ded682d2a34e4ea390bc5ad532e67e6f',
         'f57d2b1cc7404ce6896c7f03513bd28f',
         'fbfbf0f432e04dcd865bcaa7647dd72d',
         'b9f1c066c3394810947527bec320de1d'), 'OLD_RETRY_FORBIDDEN')
    original = inspect.getsource(c._no_pending)
    anchor = '        if prior_identity!=identity: continue\n'
    need(original.count(anchor) == 1, 'PENDING_DERIVATION')
    extra = ("        if operation=='f47da3507ba540759dd246d0a1d34c7d':\n"
             "            __closed_idle_audit(prior,out);continue\n"
             "        if operation=='ab9c4e6a5f0141708f41898769e3b6d0':\n"
             "            __accounted_retained_audit(prior,out);continue\n"
             "        if operation=='1fd6560631834ab88fa2d9ecf9210995':\n"
             "            __accounted_refused_audit(prior,out);continue\n"
             "        if operation=='f07c1365e4504afa98262df0ae0abe91':\n"
             "            __accounted_clean_refused_audit(prior,out);continue\n"
             "        if operation=='1d1858deb31f45ff83766dadb3513603':\n"
             "            __accounted_capture_fault_audit(prior,out);continue\n"
             "        if operation=='ded682d2a34e4ea390bc5ad532e67e6f':\n"
             "            __accounted_closed_capture_audit(prior,out);continue\n"
             "        if operation=='f57d2b1cc7404ce6896c7f03513bd28f':\n"
             "            __accounted_ready_fault_audit(prior,out);continue\n"
             "        if operation=='fbfbf0f432e04dcd865bcaa7647dd72d':\n"
             "            __retained_read_audit(prior,out);continue\n"
             "        if operation=='b9f1c066c3394810947527bec320de1d':\n"
             "            __terminal_writer_audit(prior,out);continue\n")
    text = original.replace(anchor, anchor+extra, 1)
    need(text.replace(anchor+extra, anchor, 1) == original, 'PENDING_REVERSE')
    namespace = dict(vars(c), __closed_idle_audit=current._audit_closed_idle,
                     __accounted_retained_audit=_audit_accounted_retained,
                     __accounted_refused_audit=_audit_accounted_refused,
                     __accounted_clean_refused_audit=_audit_accounted_clean_refused,
                     __accounted_capture_fault_audit=_audit_accounted_capture_fault,
                     __accounted_closed_capture_audit=_audit_accounted_closed_capture,
                     __accounted_ready_fault_audit=_audit_accounted_ready_fault,
                     __retained_read_audit=lambda prior, out: _audit_retained_read(prior, out, s),
                     __terminal_writer_audit=lambda prior, out: _audit_terminal_writer(prior, out, s))
    exec(compile(text, '<editor-exact-accounted-retain>', 'exec'), namespace)
    namespace['_no_pending'](allow_operation=s.plan['operationId'], context=s.plan['context'])


def _physical(s):
    """Current physical checks with a closed read-only SQLite handle.

    SQLite's connection context manager commits/rolls back but does not close
    the handle. closing() prevents a per-check descriptor leak in this adapter.
    The pinned current implementation and its checked facts remain unchanged.
    """
    row, owned = _load_context(s.scope);ctx = s.plan['context']
    need(row['context'] == ctx and row['sdkIdentity'] == s.plan['sdkIdentity'], 'CONTEXT_CHANGED')
    for pk, bk in (('processId', 'processCreationFileTimeUtc'), ('hostProcessId', 'hostProcessCreationFileTimeUtc'),
                   ('launcherProcessId', 'launcherProcessCreationFileTimeUtc')):
        need(reader._process(owned[pk]) == owned[bk], 'BOOTSTRAP_PROCESS')
    need(reader._process(s.scope['bootstrapKeeperPid']) == s.scope['bootstrapKeeperBirth'], 'KEEPER_PROCESS')
    need(c.digest(c.read(Path(ctx['buildDirectory']) / 'runtime/modules/Snegopat/engine/main.as')) == ctx['mainSha256'], 'MAIN_CHANGED')
    need(c.inspect_owned(ctx) == s.plan['sdkIdentity'], 'HEALTHY_SDK_IDENTITY')
    state = Path(os.environ.get('AH1C_BRIDGE_STATE_DIR') or (Path(os.environ['LOCALAPPDATA']) / 'AH_1C/bridge')) / 'state.db'
    with closing(sqlite3.connect(state.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        leases = db.execute("SELECT owner_operation_id FROM execution_leases WHERE resource='ah1c-write'").fetchall()
    need(leases == [(owned['leaseOwner'],)], 'GOLD_LEASE')


def _remember(s):
    s.private.setdefault('capture_attempted', False)
    s.private.setdefault('activation_attempted', False)
    s.private.setdefault('activation_intent_reserved', False)
    _EDITOR_STATES[id(s)] = dict(operation=s, channel=s.channel, identity=c.canonical(s.channel.identity),
                                binding=s.binding, parts=s.private['parts'], last_read=None, edit_attempted=False,
                                capture_attempted=False, activation_attempted=False,
                                activation_intent_reserved=False, activation_capability=None, activation_verified=None,
                                isolated_writer_probe=(s.scope.get('isolatedWriterProbeAuthorized') is True
                                    and s.plan.get('isolatedWriterProbeAuthorized') is True),
                                isolated_writer_run=None, isolated_writer_edit_command=None,
                                isolated_apply=(s.scope.get('isolatedApplyAuthorized') is True
                                    and s.plan.get('isolatedApplyAuthorized') is True),
                                isolated_apply_run=None, isolated_apply_command=None,
                                startup_installation=None, startup_missing_ready=None, startup_close_attempted=False,
                                restored_state_mismatch=None)


def _private(s):
    row = _EDITOR_STATES.get(id(s))
    need(type(row) is dict and row['operation'] is s and s.channel is row['channel']
         and c.canonical(s.channel.identity) == row['identity'] and s.binding is row['binding']
         and s.private.get('parts') is row['parts'], 'PRIVATE_OWNER')
    return row


def _isolated_writer_scope(s):
    trusted = _private(s)
    need(trusted['isolated_writer_probe'] is True and _isolated_fields_match(s.scope)
         and _isolated_fields_match(s.plan) and c.canonical(s.plan) == s.plan_raw,
         'ISOLATED_WRITER_SCOPE')
    return trusted


def _isolated_writer_command(s, opcode, command=None, capability=None):
    # This is an additional intended-command gate, never a pending/lease waiver.
    trusted = _private(s)
    if not (trusted['isolated_writer_probe'] or s.scope.get('isolatedWriterProbeAuthorized', False)
            or s.plan.get('isolatedWriterProbeAuthorized', False)):
        return
    trusted = _isolated_writer_scope(s)
    need(opcode in (1, 2), 'ISOLATED_WRITER_COMMAND')
    need(trusted['isolated_writer_run'] == (s.plan_raw, c.canonical(s.scope), s.scope_sha256),
         'ISOLATED_WRITER_ROOT_RUN')
    if command is not None:
        parts = s.private['parts'];codec = parts.command
        need(command.binding is s.binding and command.target == codec.EditorTarget(TARGET_UUID, CLASS_UUID, PROPERTY_UUID)
             and command.policy in ((0, codec.READ_WITH_OWNERSHIP) if opcode == 1 else (codec.EDIT_VERIFY_UNDO,)),
             'ISOLATED_WRITER_TARGET_POLICY')
        if opcode == 2:
            pending = trusted['isolated_writer_edit_command']
            need(type(pending) is tuple and pending[0] is command and pending[1] is capability,
                 'ISOLATED_WRITER_PRIVATE_EDIT')


def _apply_scope(s):
    trusted = _private(s)
    need(trusted.get('isolated_apply') is True and _apply_fields_match(s.scope)
         and _apply_fields_match(s.plan) and c.canonical(s.plan) == s.plan_raw,
         'APPLY_SCOPE')
    need(all(s.scope[key] == s.plan[key] for key in ('applyContent', 'applyChangeSha256')),
         'APPLY_CONTENT_SCOPE')
    return trusted


def _apply_command(s, opcode, command=None, capability=None):
    """Private APPLY run gate; it does not waive any pending or lease guard."""
    trusted = _private(s)
    if not (trusted.get('isolated_apply') or s.scope.get('isolatedApplyAuthorized', False)
            or s.plan.get('isolatedApplyAuthorized', False)):
        need(command is None or getattr(command, 'policy', None) != 3, 'APPLY_SCOPE_REQUIRED')
        return
    trusted = _apply_scope(s)
    need(opcode in (1, 2) and trusted['isolated_apply_run'] ==
         (s.plan_raw, c.canonical(s.scope), s.scope_sha256), 'APPLY_ROOT_RUN')
    if command is not None:
        codec = trusted['parts'].command
        need(type(command) is codec.EditorCommand and command.binding is s.binding
             and command.target == codec.EditorTarget(TARGET_UUID, CLASS_UUID, PROPERTY_UUID)
             and command.policy == (codec.READ_WITH_OWNERSHIP if opcode == 1 else codec.EDIT_APPLY),
             'APPLY_TARGET_POLICY')
        if opcode == 2:
            pending = trusted['isolated_apply_command']
            need(type(pending) is tuple and pending[0] is command and pending[1] is capability,
                 'APPLY_PRIVATE_COMMAND')


def _check(s):
    _private(s)
    return _current_check(s)


def _fresh_identity_gate(s):
    try:
        _private(s)
        if s.phase == 'MISMATCH_CLOSE_ONLY':
            need(s.host is not None and s.host.poll() is None and s.host.stdin is not None,
                 'MISMATCH_CLOSE_HOST')
        return _current_fresh_gate(s)
    except BaseException:
        if type(s) is LiveResidentOperation and s.issuer is _ISSUER:
            s.phase = 'UNKNOWN_RETAIN'
        raise


def abort_before_start(s):
    result = _current_abort(s)
    if s.phase == 'ABORTED_UNSTARTED':
        _EDITOR_STATES.pop(id(s), None)
    return result


def _unknown(s, reason):
    s.phase = 'UNKNOWN_RETAIN'
    row = dict(version=233, editorProtocolVersion=3, kind='LIVE_EDITOR_UNKNOWN', profile=PROFILE,
        operationId=s.plan['operationId'], knownTerminal=False, retryAuthorized=False, reason=reason,
        sourceBodyPersisted=False, ownedBufferMayRemain=True, nativeBindingsRetainedUntilOriginalExit=True,
        sourceWriteMayHaveOccurred=bool(_EDITOR_STATES.get(id(s), {}).get('edit_attempted', False)),
        repositoryCaptureMayHaveOccurred=bool(_EDITOR_STATES.get(id(s), {}).get('capture_attempted', False)),
        ownActivationMayHaveOccurred=bool(_EDITOR_STATES.get(id(s), {}).get('activation_attempted', False)))
    path = Path(s.plan['outputDirectory']) / 'unknown.json'
    if not path.exists():
        c.write_new(path, row)
    return row


def _managed_render(s):
    files = current._managed_render(s)
    answer = {}
    replacements = {'live-resident-arm.bin': ARM_FILE, 'live-resident-worker-result.bin': WORKER_FILE,
                    'live-resident-host-ready.json': HOST_READY, 'live-resident-host-result.json': HOST_RESULT,
                    'LIVE_RESIDENT_': 'LIVE_EDITOR_', 'JOIN_VERIFIED_LIVE_RESIDENT': 'JOIN_VERIFIED_LIVE_EDITOR'}
    for name, raw in files.items():
        text = raw.decode('utf-8-sig')
        for old, new in replacements.items():
            text = text.replace(old, new)
        if name == 'run-live-resident.ps1':
            name = HOST_SCRIPT
            need(text.count('writerAuthorized=$false') == 2, 'MANAGED_AUTHORITY_ANCHOR')
            text = text.replace('writerAuthorized=$false',
                'writerAuthorized=$false;activationOnlyAuthorized=$true' if s.plan.get('activationOnlyAuthorized', False)
                else 'writerAuthorized=$true')
            if s.plan.get('activationOnlyAuthorized', False):
                # READY has its own producer and originally has no writer
                # field. The two replacements above affect TERMINAL only.
                ready = 'nativeSourceBindingVerified=$false;workerExpectedAlive=$true}'
                need(text.count("kind='LIVE_EDITOR_MANAGED_READY'") == 1 and text.count(ready) == 1,
                     'MANAGED_READY_AUTHORITY_ANCHOR')
                text = text.replace(ready, 'nativeSourceBindingVerified=$false;workerExpectedAlive=$true;'
                                    'writerAuthorized=$false;activationOnlyAuthorized=$true}')
        answer[name] = text.encode('utf-8-sig')
    return answer


def _admitted(s):
    return _components().carrier.admit_source(c.read(HERE / SOURCE_NAME, 65536),
        operation_id=s.plan['operationId'], scope_sha256=s.scope_sha256,
        scope_admitted=True, identity=_identity(s),
        **({'activation_own_admitted': True} if s.plan.get('activationOnlyAuthorized', False) else {}))


def _activation_read_admission(s, parts):
    fields = activation_scope_fields(prior_receipt_path=s.plan['activationPriorReceiptPath'],
                                    prior_receipt_sha256=s.plan['activationPriorReceiptSha256'])
    need(all(s.plan.get(key) == value for key, value in fields.items()), 'ACTIVATION_PLAN_PROVENANCE')
    need(all(s.plan['context'][key] == value for key, value in fields['activationPriorIdentity'].items()),
         'ACTIVATION_TARGET_IDENTITY')
    return parts.carrier.native_wire.ActivationReadAdmission(s.binding,
        parts.command.EditorTarget(TARGET_UUID, CLASS_UUID, PROPERTY_UUID),
        fields['activationExpectedVersion'], fields['activationExpectedSourceSha256'],
        fields['activationPriorOperationId'], fields['activationPriorReceiptSha256'])


def _render(s):
    parts = _components();identity = _identity(s);birth = int(identity['birth'], 16)
    admitted = _admitted(s)
    need(c.digest(admitted) == s.plan['compiledSourceSha256'], 'ADMITTED_SOURCE')
    definitions = dict(AH_SDK_TARGET_PID=str(identity['processId']) + 'u',
        AH_SDK_BIRTH_LOW=hex(birth & 0xffffffff) + 'u', AH_SDK_BIRTH_HIGH=hex(birth >> 32) + 'u',
        AH_SDK_ENGINE_ADDRESS=hex(identity['engineAddress']) + 'u',
        AH_SDK_MODULE_ADDRESS=hex(identity['moduleAddress']) + 'u', AH_SDK_MESSAGE='0x8065u')
    files = _managed_render(s)
    files['sdk_probe_params.h'] = ''.join('#define ' + k + ' ' + v + '\n' for k, v in definitions.items()).encode()
    files['Continuation.c'] = parts.carrier.render(admitted,
        configuration=s.plan['liveResidentConfiguration'], identity=identity,
        capture_only_admitted=s.scope.get('captureOnlyAuthorized', False),
        **(dict(apply_edit_admitted=True) if s.plan.get('isolatedApplyAuthorized', False) else {}),
        **(dict(activation_own_admitted=True, activation_read_admission=_activation_read_admission(s, parts))
           if s.plan.get('activationOnlyAuthorized', False) else {}))
    return files


def prepare_root(path, pin):
    parts = _components();path = c._plain(path, ROOT / 'artifacts/designer-bridge')
    scope = ram.previous._json(path, pin, 65536);validate_scope(scope)
    row, _ = _load_context(scope);op = uuid.uuid4().hex;out = ROOT / 'build' / ('designer-hot-v233-' + op)
    need(not out.exists(), 'ONE_OPERATION')
    identity = dict(processId=row['context']['processId'], birth=row['context']['birth'],
        guiThreadId=row['context']['guiThreadId'], engineAddress=row['sdkIdentity']['engineAddress'],
        moduleAddress=row['sdkIdentity']['moduleAddress'])
    admitted = parts.carrier.admit_source(c.read(HERE / SOURCE_NAME, 65536), operation_id=op,
        scope_sha256=pin, scope_admitted=True, identity=identity,
        **({'activation_own_admitted': True} if scope.get('activationOnlyAuthorized', False) else {}))
    binding = parts.command.EditorBinding(ROOT_UUID, identity['processId'], identity['birth'],
        identity['guiThreadId'], op, pin, SOURCE_SHA, c.digest(admitted))
    channel = parts.pipe.EditorChannel(binding, timeout=60)
    try:
        cfg = dict(operationId=op, scopeSha256=pin, **channel.identity, maximumSessionSeconds=600,
            maximumReads=64, maximumRequestTtlMilliseconds=60000,
            armPath=(out / ARM_FILE).as_posix(), resultPath=(out / WORKER_FILE).as_posix())
        plan = dict(version=233, probe=reader.PROBE, profile=PROFILE, editorProtocolVersion=3,
            operationId=op, outputDirectory=str(out), context=row['context'], sdkIdentity=row['sdkIdentity'],
            currentScopeSha256=pin, actualSourceSha256=SOURCE_SHA, compiledSourceSha256=c.digest(admitted),
            liveResidentControllerSha256=c.digest(c.read(Path(__file__))), liveResidentCarrierSha256=CARRIER_SHA,
            editorCommandSha256=COMMAND_SHA, editorTransportSha256=TRANSPORT_SHA, editorChannelSha256=CHANNEL_SHA,
            editorCaptureTransportSha256=CAPTURE_TRANSPORT_SHA,
            liveResidentJobSha256=JOB_SHA, nativeEditorWireSha256=NATIVE_WIRE_SHA,
            sourceDomain=SOURCE_DOMAIN, rootUuid=ROOT_UUID, moduleObjectId=TARGET_UUID,
            metadataClassId=CLASS_UUID, modulePropertyId=PROPERTY_UUID, allowedReadClasses=['Processing'],
            allowedEditObjects=[TARGET_UUID], editPolicy='EDIT_VERIFY_UNDO', liveResidentConfiguration=cfg,
            captureOnlyAuthorized=scope.get('captureOnlyAuthorized', False),
            captureAuthorized=scope.get('captureOnlyAuthorized', False),
            repositoryMutationsAuthorized=scope.get('captureOnlyAuthorized', False),
            **limits(), **{k: True for k in TRUE_AUTH}, **{k: False for k in FALSE_AUTH})
        if scope.get('retainedReadOnlyExperiment', False):
            plan['retainedReadOnlyExperiment'] = True
        if scope.get('isolatedWriterProbeAuthorized', False):
            plan.update(isolated_writer_scope_fields())
        if scope.get('isolatedApplyAuthorized', False):
            plan.update(apply_scope_fields())
            plan.update({key: scope[key] for key in ('applyContent', 'applyChangeSha256')})
        if scope.get('activationOnlyAuthorized', False):
            plan.update(activation_scope_fields(prior_receipt_path=scope['activationPriorReceiptPath'],
                        prior_receipt_sha256=scope['activationPriorReceiptSha256']))
        s = LiveResidentOperation(_ISSUER, None, scope, path, pin, plan, c.canonical(plan), {}, channel)
        s.binding = binding
        s.private.update(parts=parts, used_nonces=(), edit_attempted=False, last_read=None,
                         installation=None, require_stage=lambda p: require_stage(s, p))
        _remember(s)
        _check(s)
        return s
    except BaseException:
        channel.abort_before_connect();channel.wait_closed()
        if 's' in locals():
            _EDITOR_STATES.pop(id(s), None)
        raise


def _host_ready(s):
    out = Path(s.plan['outputDirectory']);deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if (out / HOST_READY).is_file():
            try:
                row = ram.previous._json(out / HOST_READY, bound=8192)
            except (OSError, ValueError):
                need(s.host is not None and s.host.poll() is None, 'READY_HOST_LIFETIME')
                time.sleep(.01);continue
            need(row.get('kind') == 'LIVE_EDITOR_MANAGED_READY' and row.get('operationId') == s.plan['operationId']
                 and row.get('processId') == s.plan['context']['processId']
                 and row.get('threadId') == s.plan['context']['guiThreadId']
                 and row.get('workerExpectedAlive') is True and row.get('nativeSourceBindingVerified') is False,
                 'MANAGED_READY')
            if s.plan.get('activationOnlyAuthorized', False):
                # Only missing fields in an otherwise identity-validated READY
                # qualify. Wrong/inverted claims remain ambiguous failures.
                purpose = {'writerAuthorized': False, 'activationOnlyAuthorized': True}
                if (s.phase == 'STARTING_RETAIN' and any(key not in row for key in purpose)
                        and all(key not in row or row[key] is value for key, value in purpose.items())):
                    trusted = _private(s)
                    if trusted['startup_installation'] is s.private['installation']:
                        trusted['startup_missing_ready'] = c.canonical(row)
                need(row.get('writerAuthorized') is False and row.get('activationOnlyAuthorized') is True,
                     'ACTIVATION_MANAGED_READY')
            return row
        need(s.host is not None and s.host.poll() is None, 'READY_HOST_LIFETIME');time.sleep(.01)
    raise ValueError('LIVE_EDITOR_OPERATION_MANAGED_READY_TIMEOUT')


def start_root_once(s, review_path, review_pin):
    _check(s);need(s.phase == 'STAGED', 'START_ONCE');proof = require_stage(s, s.plan)
    review = ram.previous._json(c._plain(review_path, ROOT / 'artifacts/designer-bridge'), review_pin)
    need(review.get('kind') == CURRENT_RUN and review.get('passed') is True
         and review.get('operationId') == s.plan['operationId'] and review.get('scopeSha256') == s.scope_sha256
         and review.get('planSha256') == c.digest(s.plan_raw)
         and review.get('buildSha256') == c.digest(c.canonical(proof)) and authority(review), 'ROOT_RUN')
    need(review.get('captureOnlyAuthorized', False) == s.plan.get('captureOnlyAuthorized', False)
         and type(review.get('captureOnlyAuthorized', False)) is bool, 'CAPTURE_RUN_AUTHORITY')
    need(review.get('activationOnlyAuthorized', False) is s.plan.get('activationOnlyAuthorized', False),
         'ACTIVATION_RUN_AUTHORITY')
    need(review.get('retainedReadOnlyExperiment', False) is s.plan.get('retainedReadOnlyExperiment', False),
         'RETAINED_READ_RUN')
    need(review.get('isolatedWriterProbeAuthorized', False) is s.plan.get('isolatedWriterProbeAuthorized', False),
         'ISOLATED_WRITER_RUN')
    need(review.get('isolatedApplyAuthorized', False) is s.plan.get('isolatedApplyAuthorized', False),
         'APPLY_RUN')
    if s.plan.get('isolatedApplyAuthorized', False):
        trusted = _apply_scope(s)
        need(_apply_fields_match(review) and all(review[key] == s.plan[key]
             for key in ('applyContent', 'applyChangeSha256')), 'APPLY_RUN_FIELDS')
        trusted['isolated_apply_run'] = (s.plan_raw, c.canonical(s.scope), s.scope_sha256)
    if s.plan.get('isolatedWriterProbeAuthorized', False):
        trusted = _isolated_writer_scope(s)
        need(_isolated_fields_match(review), 'ISOLATED_WRITER_RUN')
        trusted['isolated_writer_run'] = (s.plan_raw, c.canonical(s.scope), s.scope_sha256)
    if s.plan.get('activationOnlyAuthorized', False):
        need(all(review.get(key) == s.plan[key] for key in activation_scope_fields(
            prior_receipt_path=s.plan['activationPriorReceiptPath'],
            prior_receipt_sha256=s.plan['activationPriorReceiptSha256'])), 'ACTIVATION_RUN_PROVENANCE')
    out = Path(s.plan['outputDirectory'])
    need(not any((out / name).exists() for name in ('intent.json', 'unknown.json', HOST_READY, WORKER_FILE)), 'ONE_ATTEMPT')
    markers = _markers(s);_check(s);need(_markers(s) == markers, 'ADMISSION_RACE')
    reservation = dict(version=233, nonce=s.plan['context']['heldNonce'], operationId=s.plan['operationId'],
                       planSha256=c.digest(s.plan_raw))
    intent = dict(version=3, kind='LIVE_EDITOR_INTENT', operationId=s.plan['operationId'],
                  planSha256=c.digest(s.plan_raw), rootRunSha256=review_pin)
    c.write_new(_reservation(s), reservation);c.write_new(out / 'intent.json', intent)
    seal = _CurrentSeal(s, s.plan_raw, c.canonical(s.scope), markers,
                       c.read(_reservation(s), 8192), c.read(out / 'intent.json', 65536), proof)
    s.seal = seal;_SEALS[id(s)] = seal;s.phase = 'STARTING_RETAIN'
    try:
        _fresh_identity_gate(s)
        s.host = subprocess.Popen([str(reader.writer.PS), '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', str(out / HOST_SCRIPT)], cwd=out, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        c.write_new(out / 'host-identity.json', reader.writer._host_identity(s.host))
        installation = s.channel.connect();parts = s.private['parts']
        need(type(installation) is parts.transport.EditorInstallation and installation.binding == s.binding,
             'READY_BINDING')
        installation.validate();s.private['installation'] = installation
        _private(s)['startup_installation'] = installation
        _host_ready(s);s.phase = 'READY';_fresh_identity_gate(s)
        return s
    except BaseException as error:
        if (type(error) is ValueError and str(error) == 'LIVE_EDITOR_OPERATION_ACTIVATION_MANAGED_READY'
                and _startup_close_eligible(s)):
            s.phase = 'STARTUP_CLOSE_ONLY'
            try:
                close_unstarted_owner(s)
            except BaseException:
                s.phase = 'UNKNOWN_RETAIN'
                try:
                    _unknown(s, 'INSTALL_STARTUP_CLOSE_UNPROVEN')
                except BaseException:
                    # The original startup failure must survive a second
                    # cleanup/receipt failure; the owner still stays retained.
                    pass
        else:
            _unknown(s, 'INSTALL_CLOSURE_UNPROVEN')
        raise


def _context(s, command, capability=None):
    return dict(binding=s.binding, installation=s.private['installation'], command=command,
                now=time.monotonic(), previous_sequence=s.sequence, capability=capability,
                used_nonces=s.private['used_nonces'])


def _validate_editor_capture(s, capture, command, capability):
    _fresh_identity_gate(s);parts = s.private['parts']
    if command.opcode == parts.command.ACTIVATE_OWN6:
        need(type(capture) is parts.activation_transport.EditorActivationOutcome
             and capture.command == command and capture.binding == s.binding
             and capability is _private(s)['activation_capability'], 'ACTIVATION_COMMAND')
        parts.activation_transport.validate_activation(capture, **_context(s, command, capability))
        return True
    if command.opcode == parts.command.CAPTURE_ONLY:
        need(capability is None and capture.command == command and capture.binding == s.binding,
             'CAPTURE_ONLY_COMMAND')
        parts.capture_transport.validate_capture_only(capture, **_context(s, command))
        return True
    if command.opcode == parts.command.READ_REPOSITORY_MODULE:
        need(type(capture) is parts.repository_transport.RepositoryCapture and capability is None
             and capture.command == command and capture.binding == s.binding, 'REPOSITORY_CAPTURE_COMMAND')
        parts.repository_transport.validate_repository(capture, **_context(s, command))
        return True
    refused = type(capture) is parts.transport.EditorReadRefusal
    mismatch = type(capture) is parts.transport.EditorRestoredStateMismatch
    applied = type(capture) is getattr(parts.transport, 'EditorApplied', None)
    need((refused or mismatch or applied or type(capture) is parts.transport.EditorCapture) and capture.command == command
         and capture.binding == s.binding, 'CAPTURE_COMMAND')
    if applied:
        _apply_command(s, command.opcode, command, capability)
        parts.transport.validate_applied(capture, **_context(s, command, capability))
    elif mismatch:
        need(command.opcode == parts.command.EDIT_MODULE and capability is not None, 'MISMATCH_COMMAND')
        parts.transport.validate_restored_state_mismatch(capture, **_context(s, command, capability))
    elif refused:
        need(command.opcode == parts.command.READ_MODULE and capability is None, 'READ_REFUSAL_COMMAND')
        parts.transport.validate_refusal(capture, **_context(s, command, capability))
    else:
        parts.transport.validate_capture(capture, **_context(s, command, capability))
    return True


def _exchange_module(s, command, capability=None):
    # Check the private completion latch as well as the public phase. A caller
    # cannot restore READY or reuse a pre-mismatch read to dispatch another job.
    need(_private(s)['restored_state_mismatch'] is None and s.phase == 'READY', 'COMMAND_PHASE_BUDGET')
    parts = s.private['parts'];s.inflight = True
    try:
        _isolated_writer_command(s, command.opcode, command, capability)
        _apply_command(s, command.opcode, command, capability)
        # This Root-reviewed recovery route may observe retained native state,
        # but cannot dispatch an edit, capture or activation through the owner.
        if s.plan.get('retainedReadOnlyExperiment', False):
            need(s.scope.get('retainedReadOnlyExperiment') is True
                 and command.opcode in (parts.command.READ_MODULE, parts.command.READ_REPOSITORY_MODULE),
                 'RETAINED_READ_ONLY_COMMAND')
        _fresh_identity_gate(s)
        need(time.monotonic() <= s.private['installation'].valid_until, 'EXPIRED_CLOSE_REQUIRED')
        parts.command.build_command(command, binding=s.binding, previous_sequence=s.sequence,
            capability=capability, used_nonces=s.private['used_nonces'])
        if s.plan.get('activationOnlyAuthorized', False):
            need(command.opcode in (parts.command.READ_MODULE, parts.command.ACTIVATE_OWN6),
                 'ACTIVATION_ONLY_COMMAND')
        if command.opcode == parts.command.ACTIVATE_OWN6:
            trusted = _private(s)
            need(s.scope.get('activationOnlyAuthorized') is True and s.plan.get('activationOnlyAuthorized') is True
                 and authority(s.scope) and authority(s.plan)
                 and not s.private['activation_attempted'] and not trusted['activation_attempted']
                 and trusted['activation_intent_reserved'] and s.private['activation_intent_reserved']
                 and capability is trusted['activation_capability']
                 and not trusted['capture_attempted'] and not trusted['edit_attempted'], 'ACTIVATION_ADMISSION')
        if command.opcode == parts.command.EDIT_MODULE:
            need(not s.plan.get('activationOnlyAuthorized', False)
                 and not _private(s)['activation_attempted'] and not _private(s)['activation_intent_reserved'],
                 'ACTIVATION_EDIT_LATCH')
            need(not s.private['capture_attempted'] and not _private(s)['capture_attempted'], 'CAPTURE_EDIT_LATCH')
        elif command.opcode == parts.command.CAPTURE_ONLY:
            need(s.scope.get('captureOnlyAuthorized') is True
                 and s.plan.get('captureOnlyAuthorized') is True
                 and not s.private['capture_attempted'] and not _private(s)['capture_attempted']
                 and not s.private['edit_attempted'] and not _private(s)['edit_attempted'], 'CAPTURE_ADMISSION')
    except BaseException:
        s.inflight = False
        raise
    try:
        if command.opcode == parts.command.EDIT_MODULE:
            s.private['edit_attempted'] = True
            _private(s)['edit_attempted'] = True
        elif command.opcode == parts.command.CAPTURE_ONLY:
            s.private['capture_attempted'] = True
            _private(s)['capture_attempted'] = True
            s.private['last_read'] = None;_private(s)['last_read'] = None
        elif command.opcode == parts.command.ACTIVATE_OWN6:
            s.private['activation_attempted'] = True
            _private(s)['activation_attempted'] = True
            s.private['last_read'] = None;_private(s)['last_read'] = None
        snapshot = s.channel.exchange(command,
            lambda capture: _validate_editor_capture(s, capture, command, capability), capability=capability)
        _fresh_identity_gate(s)
        repository = command.opcode == parts.command.READ_REPOSITORY_MODULE
        capture_only = command.opcode == parts.command.CAPTURE_ONLY
        activation = command.opcode == parts.command.ACTIVATE_OWN6
        refused = type(snapshot) is parts.transport.EditorRefusalSnapshot
        mismatch = type(snapshot) is parts.transport.EditorRestoredStateMismatchSnapshot
        applied = type(snapshot) is getattr(parts.transport, 'EditorAppliedSnapshot', None)
        need(type(snapshot) is parts.activation_transport.EditorActivationSnapshot if activation else
             type(snapshot) is parts.capture_transport.EditorCaptureOnlySnapshot if capture_only else
             type(snapshot) is parts.repository_transport.RepositorySnapshot if repository else
             refused or mismatch or applied or type(snapshot) is parts.transport.EditorSnapshot, 'SNAPSHOT_TYPE')
        if activation:
            parts.activation_transport.finish_activation(snapshot.capture, snapshot.release, **_context(s, command, capability))
            observed = snapshot.capture
            _private(s)['activation_verified'] = observed.activation_verified
        elif capture_only:
            parts.capture_transport.finish_capture_only(snapshot.capture, snapshot.release, **_context(s, command))
            observed = snapshot.capture
        elif repository:
            parts.repository_transport.finish_repository(snapshot.capture, snapshot.release, **_context(s, command))
            observed = snapshot.capture
        elif applied:
            parts.transport.finish_applied(snapshot.capture, snapshot.release, **_context(s, command, capability))
            observed = snapshot.capture
        elif mismatch:
            parts.transport.finish_restored_state_mismatch(snapshot.capture, snapshot.release,
                **_context(s, command, capability))
            observed = snapshot.capture
        elif refused:
            parts.transport.finish_refusal(snapshot.refusal, snapshot.release, **_context(s, command, capability))
            observed = snapshot.refusal
        else:
            parts.transport.finish_capture(snapshot.capture, snapshot.release, **_context(s, command, capability))
            observed = snapshot.capture
        need(observed.command == command and s.channel.last_sequence == command.sequence, 'COMPLETED_COMMAND')
        s.sequence = command.sequence;s.private['used_nonces'] += (command.nonce,)
        if refused or mismatch or applied or repository or capture_only or activation:
            # A completed negative observation retires any earlier writable
            # baseline. It is never an empty module or ownership observation.
            s.private['last_read'] = None;_private(s)['last_read'] = None
        if mismatch:
            _private(s)['restored_state_mismatch'] = snapshot
            s.phase = 'MISMATCH_CLOSE_ONLY'
        return snapshot
    except BaseException:
        _unknown(s, 'EDITOR_JOB_CLOSURE_UNPROVEN')
    finally:
        s.inflight = False
    snapshot = command = capability = None
    raise ValueError('LIVE_EDITOR_OPERATION_JOB_CLOSURE_UNPROVEN')


def _ready_command(s):
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER and s.phase == 'READY'
         and not s.inflight and s.sequence < 64 and _private(s)['restored_state_mismatch'] is None,
         'COMMAND_PHASE_BUDGET')


def read_module(s):
    """Read the exact fixture; body and private observation remain only in RAM."""
    _ready_command(s);codec = s.private['parts'].command
    target = codec.EditorTarget(TARGET_UUID, CLASS_UUID, PROPERTY_UUID)
    command = codec.EditorCommand(codec.READ_MODULE, s.binding, target, s.sequence + 1,
                                  s.sequence + 1, uuid.uuid4().hex)
    snapshot = _exchange_module(s, command)
    if type(snapshot) is s.private['parts'].transport.EditorSnapshot:
        s.private['last_read'] = snapshot
        _private(s)['last_read'] = snapshot
    return snapshot


def read_owned_module(s):
    """Read the fixture and query its repository owner once, without capture.

    The fresh server observation may enable the separate fixed probe only for
    OWN with a positive version and unchanged clean source/state. This call
    neither captures an object nor grants authority on a missing/error result.
    Bodies and the private completed observation remain in RAM.
    """
    _ready_command(s);codec = s.private['parts'].command
    target = codec.EditorTarget(TARGET_UUID, CLASS_UUID, PROPERTY_UUID)
    command = codec.EditorCommand(codec.READ_MODULE, s.binding, target, s.sequence + 1,
        s.sequence + 1, uuid.uuid4().hex, codec.READ_WITH_OWNERSHIP)
    snapshot = _exchange_module(s, command)
    if type(snapshot) is s.private['parts'].transport.EditorSnapshot:
        s.private['last_read'] = snapshot
        _private(s)['last_read'] = snapshot
    return snapshot


def read_repository_module(s):
    """Read one exact-version repository packet into private RAM, without capture.

    The version is selected by the GUI callback's fresh statistic pair. Raw
    bytes are returned only after the normal ACK/release handshake. They are
    neither UTF8 module text nor authority to capture, cancel, edit or save.
    A caller must decode the pinned packet and separately join fresh live code.
    """
    _isolated_writer_command(s, 4)
    _ready_command(s);codec = s.private['parts'].command
    target = codec.EditorTarget(TARGET_UUID, CLASS_UUID, PROPERTY_UUID)
    command = codec.EditorCommand(codec.READ_REPOSITORY_MODULE, s.binding, target,
                                  s.sequence + 1, s.sequence + 1, uuid.uuid4().hex)
    return _exchange_module(s, command)


def capture_only(s):
    """Capture the admitted fixture once; no refresh, source edit, save or cancel.

    The fsynced intent contains only the exact bodyless command's metadata.
    The worker verifies it before dispatch; the GUI obtains fresh source/state
    and ownership itself. An attempted command permanently disables this owner's
    edit route, even if a later READ observes OWN.
    """
    _isolated_writer_command(s, 5)
    need(not s.plan.get('retainedReadOnlyExperiment', False), 'RETAINED_READ_ONLY_COMMAND')
    _ready_command(s);_fresh_identity_gate(s);trusted = _private(s)
    need(s.scope.get('captureOnlyAuthorized') is True and s.plan.get('captureOnlyAuthorized') is True
         and not trusted['capture_attempted'] and not s.private['capture_attempted']
         and not trusted['edit_attempted'] and not s.private['edit_attempted'], 'CAPTURE_ADMISSION')
    codec = s.private['parts'].command
    command = codec.EditorCommand(codec.CAPTURE_ONLY, s.binding,
        codec.EditorTarget(TARGET_UUID, CLASS_UUID, PROPERTY_UUID),
        s.sequence + 1, s.sequence + 1, uuid.uuid4().hex)
    raw = codec.build_command(command, binding=s.binding, previous_sequence=s.sequence,
                              used_nonces=s.private['used_nonces'])
    need(time.monotonic() <= s.private['installation'].valid_until and len(raw) == 512,
         'CAPTURE_INTENT_ADMISSION')
    out = c._plain(Path(s.plan['outputDirectory']), ROOT / 'build')
    path = out / ('capture-intent-' + str(command.sequence) + '-' + command.nonce + '.bin')
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'CAPTURE_INTENT_WRITE')
        handle.flush();os.fsync(handle.fileno())
    need(c.read(path, 512) == raw, 'CAPTURE_INTENT_READBACK')
    return _exchange_module(s, command)


def activate_owned_module(s, *, prior_receipt_path, prior_receipt_sha256):
    """Activate once from this owner's fresh clean OWN READ and pinned closure.

    Source stays in RAM. The durable file contains exactly one bodyless 512-byte
    command; it is fsynced and re-read before dispatch. This grants no source
    edit, Undo, capture, cancellation, repository mutation, Save or DB right.
    Unknown outcomes retain the owner and never permit retry.
    """
    _isolated_writer_command(s, 6)
    need(not s.plan.get('retainedReadOnlyExperiment', False), 'RETAINED_READ_ONLY_COMMAND')
    _ready_command(s);_fresh_identity_gate(s);parts = s.private['parts'];trusted = _private(s)
    need(s.scope.get('activationOnlyAuthorized') is True and s.plan.get('activationOnlyAuthorized') is True
         and authority(s.scope) and authority(s.plan)
         and not trusted['activation_attempted'] and not s.private['activation_attempted']
         and not trusted['activation_intent_reserved'] and not s.private['activation_intent_reserved']
         and not trusted['capture_attempted'] and not trusted['edit_attempted'], 'ACTIVATION_ADMISSION')
    fields = activation_scope_fields(prior_receipt_path=prior_receipt_path,
                                    prior_receipt_sha256=prior_receipt_sha256)
    need(all(s.scope.get(k) == value and s.plan.get(k) == value for k, value in fields.items()),
         'ACTIVATION_PROVENANCE_JOIN')
    need(all(s.plan['context'][key] == value for key, value in fields['activationPriorIdentity'].items()),
         'ACTIVATION_TARGET_IDENTITY')
    snapshot = s.private['last_read']
    need(snapshot is trusted['last_read'] and type(snapshot) is parts.transport.EditorSnapshot
         and snapshot.capture.command.binding is s.binding
         and snapshot.capture.command.opcode == parts.command.READ_MODULE
         and snapshot.capture.command.policy == parts.command.READ_WITH_OWNERSHIP
         and snapshot.capture.command.sequence == s.sequence == s.channel.last_sequence,
         'ACTIVATION_PRIVATE_COMPLETED_READ')
    capture = snapshot.capture
    prior_context = _context(s, capture.command)
    prior_context.update(previous_sequence=capture.command.sequence - 1,
                         used_nonces=s.private['used_nonces'][:-1])
    parts.transport.finish_capture(capture, snapshot.release, **prior_context)
    need(capture.target == parts.command.EditorTarget(TARGET_UUID, CLASS_UUID, PROPERTY_UUID)
         and capture.owner_class == 1 and capture.owner_uuid == capture.actor_uuid
         and parts.command._uuid(capture.actor_uuid)
         and capture.owner_version == fields['activationExpectedVersion']
         and snapshot.body_sha256 == fields['activationExpectedSourceSha256']
         and parts.command.ModuleText.from_utf8(snapshot.utf8).sha256 == fields['activationExpectedSourceSha256']
         and capture.before_state == capture.after_state
         and all(capture.after_state[index] == 0 for index in (8, 9, 10, 11, 19, 20))
         and capture.after_state[12] == 1, 'ACTIVATION_FRESH_OWN_SOURCE_STATE')
    capability = parts.command.ActivationCapability(s.binding, capture.target, capture.actor_uuid,
        capture.owner_version, snapshot.body_sha256, fields['activationPriorOperationId'], fields['activationPriorReceiptSha256'])
    command = parts.command.EditorCommand(parts.command.ACTIVATE_OWN6, s.binding, capture.target,
        s.sequence + 1, s.sequence + 1, uuid.uuid4().hex, expected_owner=capture.actor_uuid,
        expected_version=capture.owner_version, expected_state=capture.after_state,
        expected_source_sha256=snapshot.body_sha256)
    raw = parts.command.build_command(command, binding=s.binding, previous_sequence=s.sequence,
                                    capability=capability, used_nonces=s.private['used_nonces'])
    need(len(raw) == 512 and time.monotonic() <= s.private['installation'].valid_until,
         'ACTIVATION_INTENT_ADMISSION')
    out = c._plain(Path(s.plan['outputDirectory']), ROOT / 'build')
    need(not list(out.glob('activation-intent-*.bin')), 'ACTIVATION_INTENT_ONCE')
    trusted['activation_intent_reserved'] = s.private['activation_intent_reserved'] = True
    trusted['activation_capability'] = capability
    s.private['last_read'] = None;trusted['last_read'] = None
    path = out / ('activation-intent-' + str(command.sequence) + '-' + command.nonce + '.bin')
    with path.open('xb') as handle:
        need(handle.write(raw) == 512, 'ACTIVATION_INTENT_WRITE')
        handle.flush();os.fsync(handle.fileno())
    need(c.read(path, 512) == raw, 'ACTIVATION_INTENT_READBACK')
    return _exchange_module(s, command, capability)


def edit_verify_undo(s):
    """One own prefix/Undo from this owner's completed READ; no caller candidate.

    Root admits observed clean/no-Undo OWN state. The native initial-state gate
    independently proves no Redo before the published setter. The final own
    Redo is retained; full history restoration is deliberately not claimed.
    """
    _isolated_writer_command(s, 2)
    need(not s.plan.get('retainedReadOnlyExperiment', False), 'RETAINED_READ_ONLY_COMMAND')
    _ready_command(s);_fresh_identity_gate(s);parts = s.private['parts']
    trusted = _private(s)
    need(not s.plan.get('activationOnlyAuthorized', False)
         and not trusted['activation_attempted'] and not trusted['activation_intent_reserved'],
         'ACTIVATION_EDIT_LATCH')
    need(not s.private['capture_attempted'] and not trusted['capture_attempted'], 'CAPTURE_EDIT_LATCH')
    need(s.private['edit_attempted'] is False and trusted['edit_attempted'] is False, 'EDIT_ONCE')
    snapshot = s.private['last_read']
    need(snapshot is trusted['last_read'] and type(snapshot) is parts.transport.EditorSnapshot and snapshot.capture.command.binding == s.binding
         and snapshot.capture.command.sequence == s.sequence and snapshot.capture.command.opcode == parts.command.READ_MODULE,
         'PRIVATE_COMPLETED_READ')
    if trusted['isolated_writer_probe']:
        need(snapshot.capture.command.binding is s.binding
             and snapshot.capture.command.policy == parts.command.READ_WITH_OWNERSHIP
             and snapshot.capture.command.sequence == s.channel.last_sequence
             and snapshot.capture.target == parts.command.EditorTarget(TARGET_UUID, CLASS_UUID, PROPERTY_UUID),
             'ISOLATED_PRIVATE_OWN_READ')
    capability = parts.transport.capability_from_read(snapshot)
    baseline = parts.command.ModuleText.from_utf8(snapshot.utf8)
    marker = ('// AH1C OWNED EDITOR PROBE ' + s.plan['operationId'] + ' ').encode('ascii')
    candidate = parts.command.ModuleText.from_utf8(marker + snapshot.utf8)
    capture = snapshot.capture
    command = parts.command.EditorCommand(parts.command.EDIT_MODULE, s.binding, capability.target,
        s.sequence + 1, s.sequence + 1, uuid.uuid4().hex, parts.command.EDIT_VERIFY_UNDO,
        capture.actor_uuid, capture.owner_version, capture.after_state, baseline, candidate)
    trusted['isolated_writer_edit_command'] = (command, capability)
    try:
        return _exchange_module(s, command, capability)
    finally:
        trusted['isolated_writer_edit_command'] = None


def apply_edit(s, change):
    """Apply one planned single-line edit to this owner's fresh OWN snapshot.

    change is an exact RAM EditorChangePlan, not caller JSON or authority.
    The native command rechecks baseline, range, actor/version and selection
    before its one setter. Success preserves the candidate; no Undo, Save,
    repository mutation or database update is performed. Ordinary edit may
    invalidate the editor's prior Redo branch. An uncertain result is retained.
    """
    _apply_command(s, 2)
    _ready_command(s);_fresh_identity_gate(s)
    trusted = _apply_scope(s);parts = trusted['parts'];codec = parts.command
    need(not trusted['edit_attempted'] and not s.private['edit_attempted']
         and not trusted['capture_attempted'] and not s.private['capture_attempted']
         and not trusted['activation_attempted'] and not trusted['activation_intent_reserved'], 'APPLY_ONCE')
    snapshot = trusted['last_read']
    need(snapshot is s.private['last_read'] and type(snapshot) is parts.transport.EditorSnapshot
         and snapshot.capture.command.binding is s.binding
         and snapshot.capture.command.sequence == s.sequence == s.channel.last_sequence
         and snapshot.capture.command.policy == codec.READ_WITH_OWNERSHIP
         and snapshot.capture.target == codec.EditorTarget(TARGET_UUID, CLASS_UUID, PROPERTY_UUID),
         'APPLY_PRIVATE_OWN_READ')
    planner = _module('native_mcp.editor_change_plan', CHANGE_PLAN_SHA)
    need(type(change) is planner.EditorChangePlan, 'APPLY_CHANGE_PLAN')
    change.assert_baseline(codec.ModuleText.from_utf8(snapshot.utf8))
    need(all(s.plan[key] == value for key, value in apply_change_fields(change).items()), 'APPLY_CONTENT_PLAN')
    capability = parts.transport.apply_capability_from_read(snapshot)
    capture = snapshot.capture
    command = codec.EditorCommand(codec.EDIT_MODULE, s.binding, capability.target,
        s.sequence + 1, s.sequence + 1, uuid.uuid4().hex, codec.EDIT_APPLY,
        capture.actor_uuid, capture.owner_version, capture.after_state,
        change.baseline, change.candidate,
        apply_range=codec.EditorApplyRange(change.start_utf16, change.stop_utf16,
                                          change.replacement_utf16_units))
    trusted['isolated_apply_command'] = (command, capability)
    try:
        return _exchange_module(s, command, capability)
    finally:
        trusted['isolated_apply_command'] = None


DIAGNOSTIC_KEYS = {'kind', 'version', 'operationId', 'scopeSha256', 'readerSourceSha256', 'compiledSourceSha256',
    'sequence', 'lastCommandSequence', 'lastOpcode', 'nativeWorkerRc', 'safe', 'sdkRc', 'executeRc',
    'exceptionLine', 'exceptionLineAttempted', 'exceptionLinePinStatus', 'exceptionLineInRange',
    'contextsCreated', 'contextsReleased', 'functionsCreated', 'functionsReleased', 'contextLive', 'functionLive',
    'cppEvents', 'otherEvents', 'firstOtherExceptionCode', 'handlerLive', 'epochActive', 'gateDone', 'hookLive',
    'ioDrained', 'jobPresent', 'jobMetadataObserved', 'jobState', 'jobBorrowed', 'captureCalls', 'bodyCopiedBytes',
    'nativeReason', 'setterArmed', 'undoArmed', 'totalCommands', 'totalReads', 'totalEdits', 'totalDirectReads',
    'totalSetterAttempts', 'totalSetterReturned', 'totalUndoAttempts', 'totalUndoReturned', 'totalSourceWrites',
    'sourceBodyIncluded', 'addressesIncluded', 'writeCountsComplete', 'currentCountsIncluded',
    'packetStatus', 'scriptReason', 'scriptException', 'openCalls', 'warmupReads', 'statisticQueries',
    'statisticVerified', 'bridgeCalls', 'totalCaptureCommands', 'totalRepositoryMutationAttempts',
    'captureCountsComplete', 'captureObserved', 'captureVerified', 'activationVerified',
    'refreshVerified', 'editAuthorized', 'cancelAuthorized', 'acquisitionProven',
    'totalActivationCommands', 'activationCountsComplete', 'activationObserved', 'ownActivationVerified'}
DIAGNOSTIC_BOOL = {'safe', 'exceptionLineAttempted', 'exceptionLineInRange', 'contextLive', 'functionLive',
    'handlerLive', 'epochActive', 'gateDone', 'hookLive', 'ioDrained', 'jobPresent', 'jobMetadataObserved',
    'sourceBodyIncluded', 'addressesIncluded', 'writeCountsComplete', 'currentCountsIncluded',
    'captureCountsComplete', 'captureObserved', 'refreshVerified', 'editAuthorized', 'cancelAuthorized', 'acquisitionProven',
    'activationCountsComplete', 'activationObserved'}
DIAGNOSTIC_TEXT = {'kind', 'operationId', 'scopeSha256', 'readerSourceSha256', 'compiledSourceSha256'}
DIAGNOSTIC_NULLABLE = {'totalSetterAttempts', 'totalSetterReturned', 'totalUndoAttempts', 'totalUndoReturned', 'totalSourceWrites'}
DIAGNOSTIC_CAPTURE_FACTS = {'captureVerified', 'activationVerified'}
DIAGNOSTIC_ACTIVATION_FACTS = {'ownActivationVerified'}
DIAGNOSTIC_JOB_FACTS = dict(packetStatus=5, scriptReason=0xffffffff, scriptException=1, openCalls=1,
    warmupReads=1, statisticQueries=3, statisticVerified=1, bridgeCalls=3)
TOTAL_FIELDS = dict(totalCommands='total_commands', totalReads='total_reads', totalEdits='total_edits',
    totalDirectReads='total_direct_reads', totalSetterAttempts='total_setter_attempts',
    totalSetterReturned='total_setter_returned', totalUndoAttempts='total_undo_attempts',
    totalUndoReturned='total_undo_returned', totalSourceWrites='total_source_writes',
    totalCaptureCommands='total_capture_commands', totalRepositoryMutationAttempts='repository_mutations',
    totalActivationCommands='total_activation_commands')


def terminal_diagnostics(s):
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER and c.canonical(s.plan) == s.plan_raw,
         'DIAGNOSTIC_ISSUER_PLAN')
    path = Path(s.plan['liveResidentConfiguration']['resultPath'] + '.diagnostics.json')
    need(path.parent == Path(s.plan['outputDirectory']), 'DIAGNOSTIC_PATH')
    if not path.exists():
        return None
    row = ram.previous._json(c._plain(path, ROOT / 'build'), bound=8192)
    need(type(row) is dict and row.keys() == DIAGNOSTIC_KEYS and row['kind'] == 'LIVE_EDITOR_FINAL_DIAGNOSTIC'
         and row['version'] == 3 and row['operationId'] == s.plan['operationId']
         and row['scopeSha256'] == s.scope_sha256 and row['readerSourceSha256'] == SOURCE_SHA
         and row['compiledSourceSha256'] == s.plan['compiledSourceSha256'], 'DIAGNOSTIC_JOIN')
    need(all(type(row[k]) is bool for k in DIAGNOSTIC_BOOL)
         and all(type(row[k]) is int and -2147483648 <= row[k] <= 4294967295 for k in
                 DIAGNOSTIC_KEYS - DIAGNOSTIC_BOOL - DIAGNOSTIC_TEXT - DIAGNOSTIC_NULLABLE - DIAGNOSTIC_JOB_FACTS.keys()
                 - DIAGNOSTIC_CAPTURE_FACTS - DIAGNOSTIC_ACTIVATION_FACTS)
         and not any(row[k] for k in ('sourceBodyIncluded', 'addressesIncluded', 'refreshVerified',
                                      'editAuthorized', 'cancelAuthorized', 'acquisitionProven')), 'DIAGNOSTIC_TYPES')
    if row['captureObserved']:
        need(row['captureCountsComplete'] and all(type(row[k]) is bool for k in DIAGNOSTIC_CAPTURE_FACTS),
             'DIAGNOSTIC_CAPTURE_OBSERVED')
    else:
        need(all(row[k] is None for k in DIAGNOSTIC_CAPTURE_FACTS), 'DIAGNOSTIC_CAPTURE_UNOBSERVED')
    need(not row['activationVerified'] or row['captureVerified'] is True, 'DIAGNOSTIC_CAPTURE_ACTIVATION')
    need(row['captureVerified'] is not True or (row['totalCaptureCommands'] == 1
         and row['totalRepositoryMutationAttempts'] == 1), 'DIAGNOSTIC_CAPTURE_VERIFIED')
    if row['activationObserved']:
        need(type(row['ownActivationVerified']) is bool,
             'DIAGNOSTIC_ACTIVATION_OBSERVED')
    else:
        need(row['ownActivationVerified'] is None, 'DIAGNOSTIC_ACTIVATION_UNOBSERVED')
    need(row['ownActivationVerified'] is not True or row['totalActivationCommands'] == 1,
         'DIAGNOSTIC_OWN_ACTIVATION_VERIFIED')
    if row['jobMetadataObserved']:
        need(row['jobPresent'] and row['gateDone'] and row['ioDrained']
             and not any(row[k] for k in ('contextLive', 'functionLive', 'handlerLive', 'epochActive')),
             'DIAGNOSTIC_JOB_OBSERVATION')
        need(all(type(row[k]) is int and 0 <= row[k] <= (5 if k == 'statisticQueries' and row['lastOpcode'] == 5 else maximum)
                 for k, maximum in DIAGNOSTIC_JOB_FACTS.items()),
             'DIAGNOSTIC_JOB_FACTS')
        if row['packetStatus'] == 4:
            # This is an observable retained packet, never release/admission
            # authority. A fully joined ACK/release is still required above.
            expected = dict(lastOpcode=2, scriptReason=14, scriptException=0, openCalls=1,
                warmupReads=1, statisticQueries=3, statisticVerified=1, bridgeCalls=3,
                captureCalls=3, setterArmed=1, undoArmed=1, nativeReason=0,
                sdkRc=0, executeRc=0, cppEvents=0, otherEvents=0,
                totalSetterAttempts=1, totalSetterReturned=1, totalUndoAttempts=1,
                totalUndoReturned=1, totalSourceWrites=1)
            need(all(type(row[k]) is int and row[k] == value for k, value in expected.items())
                 and row['jobState'] in (7, 8, 9) and row['writeCountsComplete'] is True,
                 'DIAGNOSTIC_RESTORED_STATE_MISMATCH')
        elif row['packetStatus'] == 5:
            # Observability of a retained APPLIED packet is not an ACK/release
            # receipt and cannot turn an unknown owner back into READY.
            expected = dict(lastOpcode=2, scriptReason=0, scriptException=0, openCalls=1,
                warmupReads=1, statisticQueries=2, statisticVerified=1, bridgeCalls=2,
                captureCalls=2, setterArmed=1, undoArmed=0, nativeReason=0,
                sdkRc=0, executeRc=0, cppEvents=0, otherEvents=0,
                totalSetterAttempts=1, totalSetterReturned=1, totalUndoAttempts=0,
                totalUndoReturned=0, totalSourceWrites=1)
            need(_apply_fields_match(s.scope) and _apply_fields_match(s.plan)
                 and all(type(row[k]) is int and row[k] == value for k, value in expected.items())
                 and row['jobState'] in (7, 8, 9) and row['writeCountsComplete'] is True,
                 'DIAGNOSTIC_APPLIED')
    else:
        need(all(row[k] is None for k in DIAGNOSTIC_JOB_FACTS), 'DIAGNOSTIC_JOB_UNOBSERVED')
    if row['writeCountsComplete']:
        need(all(type(row[k]) is int and 0 <= row[k] <= 0xffffffff for k in DIAGNOSTIC_NULLABLE), 'DIAGNOSTIC_WRITE_COUNTS')
    else:
        need(all(row[k] is None for k in DIAGNOSTIC_NULLABLE), 'DIAGNOSTIC_UNKNOWN_COUNTS')
    if row['currentCountsIncluded']:
        need(row['writeCountsComplete'] and row['jobPresent'] and row['jobMetadataObserved'], 'DIAGNOSTIC_CURRENT_COUNTS')
    for key, maximum in {'sequence': 65, 'lastCommandSequence': 64, 'lastOpcode': 6, 'jobState': 11,
                         'jobBorrowed': 1, 'captureCalls': 3, 'bodyCopiedBytes': 262144,
                         'setterArmed': 1, 'undoArmed': 1, 'exceptionLinePinStatus': 2,
                         'totalCaptureCommands': 1, 'totalRepositoryMutationAttempts': 1, 'totalActivationCommands': 1}.items():
        need(0 <= row[key] <= maximum, 'DIAGNOSTIC_RANGE')
    need(row['totalRepositoryMutationAttempts'] <= row['totalCaptureCommands']
         and (not row['totalCaptureCommands'] or row['totalEdits'] == 0), 'DIAGNOSTIC_CAPTURE_COUNTS')
    need(not row['totalActivationCommands'] or (row['totalCaptureCommands'] == row['totalRepositoryMutationAttempts']
         == row['totalEdits'] == 0), 'DIAGNOSTIC_ACTIVATION_COUNTS')
    need(0 <= row['exceptionLine'] <= len(c.read(HERE / SOURCE_NAME, 32768).splitlines()), 'DIAGNOSTIC_LINE')
    if row['exceptionLineInRange']:
        need(row['exceptionLineAttempted'] and row['exceptionLinePinStatus'] == 1 and row['exceptionLine'] > 0, 'DIAGNOSTIC_LINE')
    else:
        need(row['exceptionLine'] == 0, 'DIAGNOSTIC_LINE_ZERO')
    return row


def _require_closed_diagnostics(s):
    row = terminal_diagnostics(s);need(row is not None, 'DIAGNOSTIC_REQUIRED')
    counts = dict(sequence=s.sequence + 1, lastCommandSequence=s.sequence, lastOpcode=3, nativeWorkerRc=0,
        sdkRc=0 if s.sequence else 999, executeRc=0 if s.sequence else -2147483647,
        contextsCreated=1 if s.sequence else 0, contextsReleased=1 if s.sequence else 0,
        functionsCreated=1 if s.sequence else 0, functionsReleased=1 if s.sequence else 0,
        exceptionLine=0, exceptionLinePinStatus=0, cppEvents=0, otherEvents=0, firstOtherExceptionCode=0,
        jobState=0, jobBorrowed=0, captureCalls=0, bodyCopiedBytes=0, nativeReason=0, setterArmed=0, undoArmed=0)
    counts.update({native: getattr(s.channel.totals, field) for native, field in TOTAL_FIELDS.items()})
    ram._counts(row, counts, 'EDITOR_CLOSED_COUNTS')
    need(row['captureObserved'] is bool(s.channel.totals.total_capture_commands), 'EDITOR_CLOSED_CAPTURE_OBSERVATION')
    need(row['activationObserved'] is bool(s.channel.totals.total_activation_commands), 'EDITOR_CLOSED_ACTIVATION_OBSERVATION')
    need(row['ownActivationVerified'] is _private(s)['activation_verified'], 'EDITOR_CLOSED_ACTIVATION_VERIFIED')
    need(not s.channel.totals.total_activation_commands or s.plan.get('activationOnlyAuthorized') is True,
         'EDITOR_CLOSED_ACTIVATION_AUTHORITY')
    ram._flags(row, yes=('safe', 'ioDrained', 'writeCountsComplete', 'captureCountsComplete', 'activationCountsComplete'), no=('currentCountsIncluded', 'exceptionLineAttempted', 'exceptionLineInRange', 'contextLive',
        'functionLive', 'handlerLive', 'epochActive', 'hookLive', 'gateDone', 'jobPresent', 'jobMetadataObserved'),
        code='EDITOR_CLOSED_FLAGS')
    return row


def _closed_receipt(s):
    totals = asdict(s.channel.totals)
    result = dict(version=233, editorProtocolVersion=3, kind='LIVE_EDITOR_RESULT', profile=PROFILE, operationId=s.plan['operationId'],
        planSha256=c.digest(s.plan_raw), scopeSha256=s.scope_sha256, actualSourceSha256=SOURCE_SHA,
        compiledSourceSha256=s.plan['compiledSourceSha256'], sourceDomain=SOURCE_DOMAIN,
        status='LIVE_EDITOR_OPERATION_RESOURCES_CLOSED', knownTerminal=True, operationResourcesClosed=True,
        hookWorkersReleased=True, targetIdentityVerified=True, sdkAttempted=True, nativeInjectionPerformed=True,
        sdkResult=0, workerResult=0, hostExitCode=0, retryAuthorized=False,
        sourceBodyPersisted=False, fullHistoryRestoredVerified=False,
        captureOnlyAuthorized=s.plan.get('captureOnlyAuthorized', False),
        captureAuthorized=s.plan.get('captureOnlyAuthorized', False),
        repositoryMutationsAuthorized=s.plan.get('captureOnlyAuthorized', False),
        nativeBindingsRetainedUntilOriginalExit=True, libraryUnloadAuthorized=False,
        **totals, **{k: True for k in TRUE_AUTH}, **{k: False for k in FALSE_AUTH})
    if s.plan.get('activationOnlyAuthorized', False):
        result.update(activation_scope_fields(prior_receipt_path=s.plan['activationPriorReceiptPath'],
                      prior_receipt_sha256=s.plan['activationPriorReceiptSha256']))
        result['ownActivationVerified'] = _private(s)['activation_verified']
    if s.plan.get('isolatedApplyAuthorized', False):
        result.update(apply_scope_fields())
        result.update({key: s.plan[key] for key in ('applyContent', 'applyChangeSha256')})
    if _private(s)['restored_state_mismatch'] is not None:
        result.update(functionalVerificationStatus='RESTORED_STATE_MISMATCH',
            functionalVerificationPassed=False, sourceRestoredVerified=True,
            sourceStateRestoredVerified=False, changedStateIndices=[9])
    return result


def _startup_close_eligible(s):
    """Private same-owner cleanup admission, never reconstructed from a JSON file."""
    try:
        trusted = _private(s);parts = trusted['parts'];installation = trusted['startup_installation']
        out = Path(s.plan['outputDirectory']);totals = s.channel.totals
        return (type(s) is LiveResidentOperation and s.issuer is _ISSUER
            and s.phase in ('STARTING_RETAIN', 'STARTUP_CLOSE_ONLY') and s.inflight is False
            and s.join_attempted is False and trusted['startup_close_attempted'] is False
            and type(s.seal) is _CurrentSeal and _SEALS.get(id(s)) is s.seal and s.seal.operation is s
            and type(installation) is parts.transport.EditorInstallation
            and installation is s.private['installation'] and installation.binding is s.binding
            and type(trusted['startup_missing_ready']) is bytes and bool(trusted['startup_missing_ready'])
            and s.plan.get('activationOnlyAuthorized') is True
            and s.scope.get('activationOnlyAuthorized') is True and authority(s.plan) and authority(s.scope)
            and s.sequence == s.channel.last_sequence == 0 and s.private['used_nonces'] == ()
            and type(totals) is parts.transport.EditorTotals
            and all(type(value) is int and value == 0 for value in asdict(totals).values())
            and all(s.private.get(key) is False and trusted[key] is False for key in
                    ('edit_attempted', 'capture_attempted', 'activation_attempted', 'activation_intent_reserved'))
            and s.private['last_read'] is None and trusted['last_read'] is None
            and s.channel.sealed is False and s.channel.closed is False and s.channel.owner_thread_alive is True
            and s.host is not None and s.host.poll() is None and s.host.stdin is not None
            and not (out/'unknown.json').exists()
            and not any(out.glob('capture-intent-*.bin')) and not any(out.glob('activation-intent-*.bin')))
    except (OSError, AttributeError, KeyError, TypeError, ValueError):
        return False


def close_unstarted_owner(s):
    """Close once after identity-valid READY omitted purpose flags, before UNKNOWN.

    Uses the original private pipe and ordinary native CLOSE/ACK/release/JOIN;
    it never recovers another process, reconnects, edits files or grants READY.
    Any unproven result remains UNKNOWN_RETAIN and cannot be retried.
    """
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER
         and s.phase == 'STARTUP_CLOSE_ONLY' and _startup_close_eligible(s), 'STARTUP_CLOSE_ADMISSION')
    _private(s)['startup_close_attempted'] = True
    return _close_known_owner(s, startup=True)


def _mismatch_close_eligible(s):
    """Admit CLOSE only from this owner's privately validated released outcome."""
    try:
        trusted = _private(s);parts = trusted['parts'];snapshot = trusted['restored_state_mismatch']
        return (type(snapshot) is parts.transport.EditorRestoredStateMismatchSnapshot
            and snapshot.capture.binding is s.binding
            and snapshot.capture.command.opcode == parts.command.EDIT_MODULE
            and snapshot.capture.command.sequence == s.sequence == s.channel.last_sequence
            and trusted['edit_attempted'] is True
            and trusted['capture_attempted'] is False and trusted['activation_attempted'] is False
            and trusted['last_read'] is None and s.private['last_read'] is None
            and not s.channel.closed and s.channel.owner_thread_alive is True
            and s.host is not None and s.host.poll() is None and s.host.stdin is not None)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def close_root(s):
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER and not s.inflight
         and (s.phase == 'READY' and _private(s)['restored_state_mismatch'] is None
              or s.phase == 'MISMATCH_CLOSE_ONLY' and _mismatch_close_eligible(s)), 'CLOSE_PHASE')
    return _close_known_owner(s)


def _close_known_owner(s, *, startup=False):
    need(type(s) is LiveResidentOperation and s.issuer is _ISSUER and not s.inflight
         and (s.phase == 'STARTUP_CLOSE_ONLY' if startup else
              s.phase == 'READY' and _private(s)['restored_state_mismatch'] is None
              or s.phase == 'MISMATCH_CLOSE_ONLY' and _mismatch_close_eligible(s)), 'CLOSE_PHASE')
    s.inflight = True
    try:
        # The inherited fresh gate checks host lifetime only for its original
        # phases. Explicitly retain that check for this cleanup-only phase.
        if startup:
            need(s.host is not None and s.host.poll() is None and s.host.stdin is not None,
                 'STARTUP_CLOSE_HOST')
        _fresh_identity_gate(s);s.phase = 'CLOSING';parts = s.private['parts']
        command = parts.command.EditorCommand(parts.command.CLOSE, s.binding, None, s.sequence + 1, 0, uuid.uuid4().hex)
        def validate(close):
            _fresh_identity_gate(s)
            need(type(close) is parts.transport.EditorClose and close.command == command, 'CLOSE_COMMAND')
            parts.transport.validate_close(close, expected_totals=s.channel.totals, **_context(s, command))
            return True
        closed = s.channel.close(command, validate)
        need(type(closed) is parts.transport.EditorClose and s.channel.wait_closed() and s.channel.closed, 'CHANNEL_CLOSED')
        s.join_attempted = True
        need(s.host is not None and s.host.poll() is None and s.host.stdin is not None, 'HOST_JOIN')
        s.host.stdin.write(b'JOIN_VERIFIED_LIVE_EDITOR\n');s.host.stdin.flush();s.host.stdin.close();s.host.wait(timeout=30)
        need(s.host.returncode == 0, 'HOST_EXIT');out = Path(s.plan['outputDirectory'])
        terminal = ram.previous._json(out / HOST_RESULT, bound=8192)
        need(terminal.get('kind') == 'LIVE_EDITOR_MANAGED_TERMINAL' and terminal.get('knownTerminal') is True
             and terminal.get('hookWorkersReleased') is True
             and terminal.get('writerAuthorized') is (not s.plan.get('activationOnlyAuthorized', False))
             and (not s.plan.get('activationOnlyAuthorized', False) or terminal.get('activationOnlyAuthorized') is True)
             and terminal.get('workerResult') == 0 and terminal.get('threadId') == s.plan['context']['guiThreadId']
             and c.read(out / WORKER_FILE, 8) == bytes(4), 'MANAGED_TERMINAL')
        _fresh_identity_gate(s);_require_closed_diagnostics(s)
        result = _closed_receipt(s)
        if startup:
            result.update(startupFailureCode='LIVE_EDITOR_OPERATION_ACTIVATION_MANAGED_READY',
                startupReadyVerified=False, sdkAttempted=False, sdkResult=None,
                sdkCommandAttempted=False, sdkExecuteAttempted=False)
        need(c.read(_reservation(s), 8192) == s.seal.reservation_raw, 'OWN_RESERVATION')
        _reservation(s).unlink();c.write_new(out / 'result.json', result)
        s.private['last_read'] = None;_private(s)['last_read'] = None;s.phase = 'CLOSED'
        return result
    except BaseException:
        return _unknown(s, 'EDITOR_CLOSE_CLOSURE_UNPROVEN')
    finally:
        s.inflight = False


def _authority_result(s):
    result = dict(profile=PROFILE, editorProtocolVersion=3, sourceDomain=SOURCE_DOMAIN,
                scopeSha256=s.scope_sha256, actualSourceSha256=SOURCE_SHA,
                compiledSourceSha256=s.plan['compiledSourceSha256'], sourceBodyPersisted=False,
                captureOnlyAuthorized=s.plan.get('captureOnlyAuthorized', False),
                captureAuthorized=s.plan.get('captureOnlyAuthorized', False),
                repositoryMutationsAuthorized=s.plan.get('captureOnlyAuthorized', False),
                **limits(), **{k: True for k in TRUE_AUTH}, **{k: False for k in FALSE_AUTH})
    if s.plan.get('activationOnlyAuthorized', False):
        result.update(activation_scope_fields(prior_receipt_path=s.plan['activationPriorReceiptPath'],
                      prior_receipt_sha256=s.plan['activationPriorReceiptSha256']))
    if s.plan.get('isolatedApplyAuthorized', False):
        result.update(apply_scope_fields())
    return result


# Do not accidentally expose inherited V1 host entry points in the new writer.
for _obsolete in ('read_snapshot', '_validate_capture', '_validate_close', '_join_host'):
    globals().pop(_obsolete, None)
