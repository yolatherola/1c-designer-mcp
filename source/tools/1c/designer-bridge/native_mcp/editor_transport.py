"""Pure V3 editor response framing and joins; no I/O or native attestation.

The trusted owner supplies the installation, request, capability and cumulative
history out of band. PRE-ACK capture facts do not prove release. The physical
validator must approve them before ACK; a joined release then permits a snapshot.
Source bytes remain private RAM fields and are never included in diagnostics.
"""
from dataclasses import dataclass, field, make_dataclass
import hashlib
import json
import math
import struct
from . import editor_command as command_codec

VERSION = 3
READY_MAGIC, FRAME_MAGIC, ACK_MAGIC, RELEASE_MAGIC = b'AH1CEDY3', b'AH1CEDF3', b'AH1CEDA3', b'AH1CEDJ3'
READY_BYTES, HEADER_BYTES, ACK_BYTES, RELEASE_BYTES = 128, 32, 120, 160
MAX_METADATA_BYTES = 16384
MAX_BODY_BYTES = command_codec.MAX_UTF8_BYTES
MAX_REPOSITORY_BYTES = 1048576
MAX_FRAME_BYTES = HEADER_BYTES + MAX_METADATA_BYTES + MAX_REPOSITORY_BYTES
MAX_INSTALLATION_TTL, MAX_CAPTURE_TTL, CLOSE_GRACE = 600., 60., 60.
ALL_RELEASED = 0x7f
EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()
NIL_UUID = '00000000-0000-0000-0000-000000000000'
OWNER_NOT_QUERIED = 3
_READY = struct.Struct('<8sII32s64sdd')
_HEADER = struct.Struct('<8sIIIIII')
_ACK = struct.Struct('<8sIIII32s64s')
_RELEASE = struct.Struct('<8sIIII32s32s64sd')
BINDING_KEYS = tuple('root_uuid process_id birth gui_thread_id operation_id scope_sha256 reader_source_sha256 compiled_source_sha256 source_domain installed_at installation_valid_until'.split())
JOB_KEYS = tuple('status reason open_calls direct_reads capture_count state_bridge_calls warmup_reads helper_text_reads setter_attempts setter_returned undo_attempts undo_returned typed_cleared independent_outputs final_state_equal statistic_queries statistic_verified selection_verified pre_setter_cas_verified readback_verified restored_verified fresh_undo_witness external_undo_returned setter_armed undo_armed exception source_writes configuration_saves database_updates repository_mutations initial_redo initial_redo_code candidate_redo candidate_redo_code restored_redo restored_redo_code redo_queries redo_refs_restored'.split())
CLOSURE_INT_KEYS = tuple('sdk_result abi_fault whole_sdk_cpp_throws whole_sdk_other_exceptions contexts_created contexts_released functions_created functions_released epoch_entered epoch_returned sdk_chain_entered sdk_chain_returned handler_removed'.split())
CLOSURE_BOOL_KEYS = tuple('context_release_returned function_release_returned job_sealed callback_quiesced io_drained'.split())
CLOSURE_KEYS = CLOSURE_INT_KEYS + CLOSURE_BOOL_KEYS
TOTAL_KEYS = tuple('total_commands total_reads total_edits total_direct_reads total_setter_attempts total_setter_returned total_undo_attempts total_undo_returned total_source_writes configuration_saves database_updates repository_mutations total_capture_commands total_activation_commands'.split())
CAPTURE_VALUE_KEYS = tuple('issued_at sampled_at valid_until status body_sha256 baseline_sha256 candidate_sha256 utf16_units bom_present crlf_count ends_lf actor_uuid owner_uuid owner_class owner_version before_state middle_state after_state'.split())
REQUEST_KEYS = ('opcode', 'sequence', 'revision', 'nonce')
TARGET_KEYS = ('object_uuid', 'class_uuid', 'property_uuid')
CAPTURE_KEYS = frozenset(('kind', 'version', *BINDING_KEYS, *REQUEST_KEYS, *TARGET_KEYS,
                          *CAPTURE_VALUE_KEYS, 'byte_count', 'job', 'closure'))
CLOSE_KEYS = frozenset(('kind', 'version', *BINDING_KEYS, *REQUEST_KEYS, 'closed_at',
    'last_command_sequence', *TOTAL_KEYS, 'job_active', 'retained_unknown', 'callback_quiesced',
    'io_drained', 'contexts_live', 'functions_live', 'buffers_live'))
EditorJobFacts = make_dataclass('EditorJobFacts', [(name, int | None) for name in JOB_KEYS],
    frozen=True, slots=True, namespace={'__module__': __name__})
EditorClosureFacts = make_dataclass('EditorClosureFacts', [(name, int) for name in CLOSURE_INT_KEYS]
    + [(name, bool) for name in CLOSURE_BOOL_KEYS], frozen=True, slots=True, namespace={'__module__': __name__})


class EditorTransportRefusal(ValueError):
    """Fixed source-free diagnostic code."""


def _need(ok, code):
    if not ok:
        raise EditorTransportRefusal('EDITOR_TRANSPORT_' + code)


def _int(value, lo=0, hi=0xffffffff):
    return type(value) is int and lo <= value <= hi


def _finite(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _binding(binding):
    ok = type(binding) is command_codec.EditorBinding
    if ok:
        try:
            binding.validate()
        except command_codec.EditorCommandRefusal:
            ok = False
    _need(ok, 'BINDING')


@dataclass(frozen=True, slots=True)
class EditorInstallation:
    binding: command_codec.EditorBinding
    installed_at: float
    valid_until: float

    def validate(self):
        _binding(self.binding)
        _need(_finite(self.installed_at) and _finite(self.valid_until)
              and 0 <= self.installed_at < self.valid_until <= self.installed_at + MAX_INSTALLATION_TTL, 'INSTALLATION_TIME')


@dataclass(frozen=True, slots=True)
class ResponseHeader:
    sequence: int
    revision: int
    metadata_length: int
    body_length: int


@dataclass(frozen=True, slots=True)
class EditorCapture:
    installation: EditorInstallation
    command: command_codec.EditorCommand
    issued_at: float
    sampled_at: float
    valid_until: float
    status: str
    body_sha256: str
    baseline_sha256: str
    candidate_sha256: str | None
    utf16_units: int
    bom_present: bool
    crlf_count: int
    ends_lf: bool
    actor_uuid: str
    owner_uuid: str
    owner_class: int
    owner_version: int
    before_state: tuple
    middle_state: tuple
    after_state: tuple
    job: EditorJobFacts
    closure: EditorClosureFacts
    utf8: bytes = field(repr=False)

    @property
    def binding(self):
        return self.installation.binding

    @property
    def target(self):
        return self.command.target


@dataclass(frozen=True, slots=True)
class EditorRestoredStateMismatch(EditorCapture):
    """Restored source with exact UI-only state mismatch; never edit success."""


@dataclass(frozen=True, slots=True)
class EditorApplied(EditorCapture):
    """Verified candidate after one setter; no automatic Undo was performed."""


@dataclass(frozen=True, slots=True)
class EditorReadRefusal:
    """Validated negative READ result; never a source/ownership observation.

    Partial wire observations stay immutable and private for canonical ACK
    validation. No text, source hash, owner or successful state API is exposed.
    """
    installation: EditorInstallation
    command: command_codec.EditorCommand
    issued_at: float
    sampled_at: float
    valid_until: float
    job: EditorJobFacts
    closure: EditorClosureFacts
    _metadata: bytes = field(repr=False)

    @property
    def binding(self):
        return self.installation.binding

    @property
    def target(self):
        return self.command.target

    @property
    def reason(self):
        return self.job.reason

    @property
    def status(self):
        return 'REFUSED'


@dataclass(frozen=True, slots=True)
class EditorTotals:
    total_commands: int = 0
    total_reads: int = 0
    total_edits: int = 0
    total_direct_reads: int = 0
    total_setter_attempts: int = 0
    total_setter_returned: int = 0
    total_undo_attempts: int = 0
    total_undo_returned: int = 0
    total_source_writes: int = 0
    configuration_saves: int = 0
    database_updates: int = 0
    repository_mutations: int = 0
    total_capture_commands: int = 0
    total_activation_commands: int = 0

    def after(self, snapshot):
        return advance_totals(self, snapshot)


@dataclass(frozen=True, slots=True)
class EditorClose:
    installation: EditorInstallation
    command: command_codec.EditorCommand
    closed_at: float
    last_command_sequence: int
    totals: EditorTotals
    job_active: bool = False
    retained_unknown: bool = False
    callback_quiesced: bool = True
    io_drained: bool = True
    contexts_live: int = 0
    functions_live: int = 0
    buffers_live: int = 0

    @property
    def body_sha256(self):
        return EMPTY_SHA256

    @property
    def utf8(self):
        return b''


@dataclass(frozen=True, slots=True)
class EditorRelease:
    binding: command_codec.EditorBinding
    target: command_codec.EditorTarget | None
    sequence: int
    revision: int
    nonce: str
    body_sha256: str
    released_at: float
    status: str = 'JOB_RELEASED'
    ack_accepted: bool = True
    borrow_returned: bool = True
    buffers_freed: bool = True
    io_drained: bool = True
    context_closed: bool = True
    function_closed: bool = True
    callback_quiesced: bool = True


@dataclass(frozen=True, slots=True)
class EditorSnapshot:
    capture: EditorCapture
    release: EditorRelease

    @property
    def utf8(self):
        return self.capture.utf8

    @property
    def body_sha256(self):
        return self.capture.body_sha256


@dataclass(frozen=True, slots=True)
class EditorRestoredStateMismatchSnapshot:
    capture: EditorRestoredStateMismatch
    release: EditorRelease

    @property
    def utf8(self):
        return self.capture.utf8

    @property
    def body_sha256(self):
        return self.capture.body_sha256


@dataclass(frozen=True, slots=True)
class EditorAppliedSnapshot:
    capture: EditorApplied
    release: EditorRelease

    @property
    def utf8(self):
        return self.capture.utf8

    @property
    def body_sha256(self):
        return self.capture.body_sha256


@dataclass(frozen=True, slots=True)
class EditorRefusalSnapshot:
    refusal: EditorReadRefusal
    release: EditorRelease

    @property
    def reason(self):
        return self.refusal.reason


def _shape(command):
    _need(type(command) is command_codec.EditorCommand and type(command.opcode) is int
          and command.opcode in (1, 2, 3, 4, 5, 6) and _int(command.sequence, 1, 65)
          and _int(command.revision) and command_codec._hex(command.nonce, 32), 'COMMAND_SHAPE')
    _binding(command.binding)
    _need((command.opcode == 3 and command.target is None and command.revision == 0)
          or (command.opcode != 3 and command.sequence <= 64 and command.revision > 0
              and type(command.target) is command_codec.EditorTarget), 'COMMAND_TARGET')


def _context(*, binding, installation, command, now, previous_sequence, capability=None, used_nonces=()):
    _binding(binding)
    _shape(command)
    _need(type(installation) is EditorInstallation, 'INSTALLATION_TYPE')
    installation.validate()
    _need(installation.binding == binding and command.binding == binding, 'INSTALLATION_JOIN')
    ok = True
    try:
        command_codec._validate(command, binding, previous_sequence, capability, used_nonces)
    except command_codec.EditorCommandRefusal:
        ok = False
    _need(ok, 'COMMAND')
    grace = CLOSE_GRACE if command.opcode == command_codec.CLOSE else 0.
    _need(_finite(now) and installation.installed_at <= now <= installation.valid_until + grace, 'COMMAND_TIME')


def build_ready(installation):
    _need(type(installation) is EditorInstallation, 'INSTALLATION_TYPE')
    installation.validate()
    return _READY.pack(READY_MAGIC, VERSION, 0, installation.binding.operation_id.encode('ascii'),
        installation.binding.scope_sha256.encode('ascii'), float(installation.installed_at), float(installation.valid_until))


def parse_ready(frame, *, binding, now):
    _binding(binding)
    _need(type(frame) is bytes and len(frame) == READY_BYTES, 'READY_LENGTH')
    magic, version, reserved, operation, scope, installed, expiry = _READY.unpack(frame)
    _need(magic == READY_MAGIC and version == VERSION and reserved == 0
          and operation == binding.operation_id.encode('ascii') and scope == binding.scope_sha256.encode('ascii'), 'READY_JOIN')
    installation = EditorInstallation(binding, installed, expiry)
    installation.validate()
    _need(_finite(now) and installed <= now <= expiry, 'READY_TIME')
    return installation


def parse_response_header(frame, *, command):
    _shape(command)
    _need(type(frame) is bytes and len(frame) == HEADER_BYTES, 'HEADER_LENGTH')
    magic, version, seq, revision, metadata, body, reserved = _HEADER.unpack(frame)
    _need(magic == FRAME_MAGIC and version == VERSION and reserved == 0
          and seq == command.sequence and revision == command.revision, 'HEADER_JOIN')
    limit = MAX_REPOSITORY_BYTES if command.opcode == command_codec.READ_REPOSITORY_MODULE else MAX_BODY_BYTES
    _need(2 <= metadata <= MAX_METADATA_BYTES and body <= limit
          and (command.opcode not in (command_codec.CLOSE, command_codec.CAPTURE_ONLY, command_codec.ACTIVATE_OWN6)
               or body == 0), 'HEADER_BOUND')
    return ResponseHeader(seq, revision, metadata, body)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _json(raw, keys):
    result = None
    try:
        result = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_pairs,
                            parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        pass
    _need(type(result) is dict and set(result) == keys, 'JSON_SCHEMA')
    return result


def _unframe(frame, command, keys):
    _need(type(frame) is bytes and HEADER_BYTES <= len(frame) <= MAX_FRAME_BYTES, 'FRAME_LENGTH')
    header = parse_response_header(frame[:HEADER_BYTES], command=command)
    _need(len(frame) == HEADER_BYTES + header.metadata_length + header.body_length, 'FRAME_BOUND')
    split = HEADER_BYTES + header.metadata_length
    return _json(frame[HEADER_BYTES:split], keys), frame[split:]


def _frame(metadata, body, command):
    encoded = None
    try:
        encoded = json.dumps(metadata, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf-8')
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        pass
    limit = MAX_REPOSITORY_BYTES if command.opcode == command_codec.READ_REPOSITORY_MODULE else MAX_BODY_BYTES
    _need(encoded is not None and 2 <= len(encoded) <= MAX_METADATA_BYTES
          and type(body) is bytes and len(body) <= limit, 'FRAME_ENCODING')
    return _HEADER.pack(FRAME_MAGIC, VERSION, command.sequence, command.revision, len(encoded), len(body), 0) + encoded + body


def _binding_metadata(installation):
    b = installation.binding
    return dict(root_uuid=b.root_uuid, process_id=b.process_id, birth=b.birth, gui_thread_id=b.gui_thread_id,
        operation_id=b.operation_id, scope_sha256=b.scope_sha256, reader_source_sha256=b.source_sha256,
        compiled_source_sha256=b.compiled_sha256, source_domain=b.source_domain,
        installed_at=installation.installed_at, installation_valid_until=installation.valid_until)


def _request_metadata(command):
    return {name: getattr(command, name) for name in REQUEST_KEYS}


def _join_metadata(metadata, installation, command, kind):
    expected = dict(kind=kind, version=VERSION, **_binding_metadata(installation), **_request_metadata(command))
    for name, value in expected.items():
        actual = metadata[name]
        if name in ('installed_at', 'installation_valid_until'):
            _need(_finite(actual) and actual == value, 'METADATA_INSTALLATION')
        else:
            _need(type(actual) is type(value) and actual == value, 'METADATA_JOIN')


def _state(state):
    ok = True
    try:
        command_codec._state(state)
    except command_codec.EditorCommandRefusal:
        ok = False
    _need(ok, 'STATE_SHAPE')


def _job(job, edit, *, not_queried=False, restored_mismatch=False):
    _need(type(job) is EditorJobFacts, 'JOB_TYPE')
    _need(type(not_queried) is bool and not (edit and not_queried), 'JOB_QUERY_MODE')
    _need(type(restored_mismatch) is bool and (not restored_mismatch or edit), 'JOB_MISMATCH_MODE')
    expected = dict(status=1, reason=0, open_calls=1, direct_reads=6 if edit else 2,
        capture_count=3 if edit else 1, state_bridge_calls=3 if edit else 2, warmup_reads=1,
        helper_text_reads=0, typed_cleared=1, independent_outputs=1, final_state_equal=1,
        statistic_queries=0 if not_queried else 3 if edit else 1,
        statistic_verified=0 if not_queried else 1, external_undo_returned=0,
        exception=0, configuration_saves=0, database_updates=0, repository_mutations=0,
        redo_queries=3 if edit else 0, redo_refs_restored=int(edit))
    for name in ('setter_attempts', 'setter_returned', 'undo_attempts', 'undo_returned', 'selection_verified',
                 'pre_setter_cas_verified', 'readback_verified', 'restored_verified', 'fresh_undo_witness',
                 'setter_armed', 'undo_armed', 'source_writes'):
        expected[name] = int(edit)
    expected.update(initial_redo=0 if edit else None, initial_redo_code=0xffffffff if edit else None,
        candidate_redo=0 if edit else None, candidate_redo_code=0xffffffff if edit else None,
        restored_redo=1 if edit else None, restored_redo_code=4 if edit else None)
    if restored_mismatch:
        expected.update(status=4, reason=14, final_state_equal=0)
    _need(all((getattr(job, name) is None if value is None else
               type(getattr(job, name)) is int and getattr(job, name) == value)
              for name, value in expected.items()), 'JOB_FACTS')


def _closure(closure):
    _need(type(closure) is EditorClosureFacts, 'CLOSURE_TYPE')
    errors = ('sdk_result', 'abi_fault', 'whole_sdk_cpp_throws', 'whole_sdk_other_exceptions')
    _need(all(type(getattr(closure, name)) is int and getattr(closure, name) == (0 if name in errors else 1)
              for name in CLOSURE_INT_KEYS)
          and all(getattr(closure, name) is True for name in CLOSURE_BOOL_KEYS), 'CLOSURE_FACTS')


def _apply_job(job, final_state_equal):
    _need(type(job) is EditorJobFacts, 'APPLY_JOB_TYPE')
    expected = dict.fromkeys(JOB_KEYS, 0)
    expected.update(status=5, reason=0, open_calls=1, direct_reads=5,
        capture_count=2, state_bridge_calls=2, warmup_reads=1, typed_cleared=1,
        independent_outputs=1, final_state_equal=int(final_state_equal),
        statistic_queries=2, statistic_verified=1, selection_verified=1,
        pre_setter_cas_verified=1, readback_verified=1, setter_attempts=1,
        setter_returned=1, setter_armed=1, source_writes=1,
        candidate_redo=0, candidate_redo_code=0xffffffff,
        restored_redo=None, restored_redo_code=None, redo_queries=2, redo_refs_restored=1)
    for name, value in expected.items():
        if name in ('initial_redo', 'initial_redo_code'):
            continue
        _need(getattr(job, name) is None if value is None else
              type(getattr(job, name)) is int and getattr(job, name) == value, 'APPLY_JOB_FACTS')
    _need(_int(job.initial_redo, 0, 1) and _int(job.initial_redo_code)
          and (job.initial_redo_code != 0xffffffff if job.initial_redo
               else job.initial_redo_code == 0xffffffff), 'APPLY_INITIAL_REDO')


def _capture_contract(capture, restored_mismatch, context, *, applied=False):
    _context(**context)
    command, installation, now = context['command'], context['installation'], context['now']
    capture_type = EditorApplied if applied else EditorRestoredStateMismatch if restored_mismatch else EditorCapture
    _need(command.opcode in (1, 2) and type(capture) is capture_type, 'CAPTURE_TYPE')
    _need(type(capture.installation) is EditorInstallation and capture.installation == installation
          and type(capture.command) is command_codec.EditorCommand and capture.command == command, 'CAPTURE_JOIN')
    _context(**{**context, 'installation': capture.installation, 'command': capture.command})
    _binding(capture.binding)
    _need(_finite(capture.issued_at) and _finite(capture.sampled_at) and _finite(capture.valid_until)
          and installation.installed_at <= capture.issued_at <= capture.sampled_at <= now
          <= capture.valid_until <= min(installation.valid_until, capture.issued_at + MAX_CAPTURE_TTL)
          and capture.issued_at < capture.valid_until, 'CAPTURE_TIME')
    edit = command.opcode == command_codec.EDIT_MODULE
    _need(not restored_mismatch or edit, 'MISMATCH_OPCODE')
    _need((edit and command.policy == command_codec.EDIT_APPLY) == applied, 'CAPTURE_POLICY')
    wanted = 'APPLIED' if applied else 'RESTORED_STATE_MISMATCH' if restored_mismatch else 'RESTORED' if edit else 'READ'
    _need(type(capture.status) is str and capture.status == wanted, 'CAPTURE_STATUS')
    measured = None
    try:
        measured = command_codec.ModuleText.from_utf8(capture.utf8)
    except command_codec.EditorCommandRefusal:
        pass
    _need(measured is not None and type(capture.body_sha256) is str and capture.body_sha256 == measured.sha256
          and _int(capture.utf16_units, 0, command_codec.MAX_UTF16_UNITS)
          and capture.utf16_units == measured.utf16_units, 'BODY_HASH_ENCODING')
    _need(type(capture.bom_present) is bool and capture.bom_present == capture.utf8.startswith(b'\xef\xbb\xbf')
          and _int(capture.crlf_count, 0, command_codec.MAX_UTF16_UNITS)
          and capture.crlf_count == capture.utf8.count(b'\r\n')
          and type(capture.ends_lf) is bool and capture.ends_lf == capture.utf8.endswith(b'\n'), 'BODY_SHAPE')
    _need(_int(capture.owner_class, 0, OWNER_NOT_QUERIED) and _int(capture.owner_version)
          and type(capture.actor_uuid) is str and type(capture.owner_uuid) is str, 'OWNER_SHAPE')
    not_queried = not edit and capture.owner_class == OWNER_NOT_QUERIED
    if not_queried:
        # This is successful context READ with no ownership observation, not
        # an unknown lifecycle. NIL is admitted only in this exact READ branch.
        _need(command.policy == 0, 'OWNER_NOT_QUERIED_POLICY')
        _need(capture.actor_uuid == NIL_UUID and capture.owner_uuid == NIL_UUID
              and capture.owner_version == 0, 'OWNER_NOT_QUERIED')
    else:
        _need(command_codec._uuid(capture.actor_uuid) and capture.owner_class <= 2, 'OWNER_SHAPE')
    if capture.owner_class == 0:
        _need(capture.owner_uuid == NIL_UUID, 'OWNER_NONE')
    elif not not_queried:
        _need(command_codec._uuid(capture.owner_uuid)
              and (capture.owner_class == 1) == (capture.owner_uuid == capture.actor_uuid), 'OWNER_IDENTITY')
    _state(capture.before_state); _state(capture.after_state)
    if applied:
        _need(capture.before_state == command.expected_state
              and capture.before_state[:8] == capture.after_state[:8]
              and capture.before_state[12] == capture.after_state[12] == 0,
              'APPLY_STATE_CAS')
        _need(all(capture.after_state[i] >= capture.before_state[i] for i in (8, 9, 10))
              and all(capture.after_state[i] == 1 for i in (11, 19, 20))
              and capture.after_state[21] == 4, 'APPLY_DIRTY_HISTORY')
        planned = command_codec._apply_plan(command)
        end = (planned.start_line + 1, planned.start_column + planned.replacement_utf16_units + 1)
        _need(capture.after_state[13:19] == end * 3, 'APPLY_POSITION')
        # The native candidate snapshot is copied to after; not a third query.
        _need(type(capture.middle_state) is tuple and capture.middle_state == capture.after_state,
              'APPLY_CANDIDATE_STATE')
        _apply_job(capture.job, capture.before_state == capture.after_state)
    elif restored_mismatch:
        _need(capture.before_state[9] == 0 and capture.after_state[9] == 1
              and all(capture.before_state[i] == capture.after_state[i] for i in range(22) if i != 9),
              'MISMATCH_UI_ONLY')
    else:
        _need(capture.before_state == capture.after_state, 'FINAL_STATE')
    if not applied:
        _job(capture.job, edit, not_queried=not_queried, restored_mismatch=restored_mismatch)
    _closure(capture.closure)
    if edit:
        _state(capture.middle_state)
        _need(capture.owner_class == 1 and capture.actor_uuid == command.expected_owner
              and capture.owner_version == command.expected_version, 'EDIT_OWNER_JOIN')
        if not applied:
            _need(capture.before_state == command.expected_state
                  and not any(capture.before_state[i] for i in (11, 12, 19, 20))
                  and capture.middle_state[:8] == capture.before_state[:8]
                  and capture.middle_state[12] == 0 and capture.middle_state[20:22] == (1, 4), 'EDIT_STATE')
        returned = command.candidate if applied else command.baseline
        _need(capture.baseline_sha256 == command.baseline.sha256 and capture.candidate_sha256 == command.candidate.sha256
              and capture.body_sha256 == returned.sha256 and capture.utf8 == returned.utf8, 'EDIT_SOURCE_JOIN')
    else:
        _need(type(capture.middle_state) is tuple and capture.middle_state == ()
              and capture.baseline_sha256 == capture.body_sha256 and capture.candidate_sha256 is None, 'READ_SOURCE_JOIN')
    return capture


def validate_capture(capture, **context):
    return _capture_contract(capture, False, context)


def validate_restored_state_mismatch(capture, **context):
    """Validate restored RAM text and exact UI0→1 delta; no success/capability."""
    return _capture_contract(capture, True, context)


def validate_applied(capture, **context):
    """Verify the exact candidate and no-Undo counters before physical ACK."""
    return _capture_contract(capture, False, context, applied=True)


def _capture_metadata(capture):
    row = dict(kind='EDITOR_CAPTURE', version=VERSION, **_binding_metadata(capture.installation), **_request_metadata(capture.command))
    row.update({name: getattr(capture.target, name) for name in TARGET_KEYS})
    row.update({name: getattr(capture, name) for name in CAPTURE_VALUE_KEYS})
    row.update(byte_count=len(capture.utf8), job={name: getattr(capture.job, name) for name in JOB_KEYS},
               closure={name: getattr(capture.closure, name) for name in CLOSURE_KEYS})
    return row


def build_capture_frame(capture, **context):
    validate_capture(capture, **context)
    return _frame(_capture_metadata(capture), capture.utf8, context['command'])


def build_restored_state_mismatch_frame(capture, **context):
    validate_restored_state_mismatch(capture, **context)
    return _frame(_capture_metadata(capture), capture.utf8, context['command'])


def build_applied_frame(capture, **context):
    validate_applied(capture, **context)
    return _frame(_capture_metadata(capture), capture.utf8, context['command'])


def _refusal_job(job):
    _need(type(job) is EditorJobFacts, 'REFUSAL_JOB_TYPE')
    partial = dict(open_calls=1, direct_reads=2, capture_count=1, state_bridge_calls=2,
        warmup_reads=1, independent_outputs=1, final_state_equal=1,
        statistic_queries=1, statistic_verified=1)
    nullable = ('initial_redo', 'initial_redo_code', 'candidate_redo', 'candidate_redo_code',
                'restored_redo', 'restored_redo_code')
    _need(_int(job.reason, 1) and type(job.status) is int and job.status == 2
          and type(job.typed_cleared) is int and job.typed_cleared == 1, 'REFUSAL_JOB_STATUS')
    for name in JOB_KEYS:
        if name in ('reason', 'status', 'typed_cleared'):
            continue
        value = getattr(job, name)
        if name in nullable:
            _need(value is None, 'REFUSAL_JOB_REDO')
        elif name in partial:
            _need(_int(value, 0, partial[name]), 'REFUSAL_PARTIAL_FACTS')
        else:
            _need(type(value) is int and value == 0, 'REFUSAL_ZERO_WRITES')
    _need(job.statistic_verified <= job.statistic_queries and job.warmup_reads <= job.open_calls,
          'REFUSAL_PARTIAL_JOIN')


def validate_refusal(refusal, **context):
    """Accept only a clean, sealed no-write READ refusal before ACK."""
    _context(**context)
    command, installation, now = context['command'], context['installation'], context['now']
    _need(type(refusal) is EditorReadRefusal and command.opcode == command_codec.READ_MODULE,
          'REFUSAL_TYPE')
    _need(type(refusal.command) is command_codec.EditorCommand and refusal.command == command
          and type(refusal.installation) is EditorInstallation and refusal.installation == installation,
          'REFUSAL_JOIN')
    _need(_finite(refusal.issued_at) and _finite(refusal.sampled_at) and _finite(refusal.valid_until)
          and installation.installed_at <= refusal.issued_at <= refusal.sampled_at <= now
          <= refusal.valid_until <= min(installation.valid_until, refusal.issued_at + MAX_CAPTURE_TTL)
          and refusal.issued_at < refusal.valid_until, 'REFUSAL_TIME')
    _need(type(refusal._metadata) is bytes and 2 <= len(refusal._metadata) <= MAX_METADATA_BYTES,
          'REFUSAL_METADATA')
    row = _json(refusal._metadata, CAPTURE_KEYS)
    _join_metadata(row, installation, command, 'EDITOR_CAPTURE')
    _need(all(type(row[k]) is str and row[k] == getattr(command.target, k) for k in TARGET_KEYS),
          'REFUSAL_TARGET')
    expected = dict(status='REFUSED', body_sha256=EMPTY_SHA256, baseline_sha256=EMPTY_SHA256,
        candidate_sha256=None, byte_count=0, utf16_units=0, bom_present=False, crlf_count=0, ends_lf=False)
    _need(all(type(row[k]) is type(v) and row[k] == v for k, v in expected.items()), 'REFUSAL_NO_BODY')
    _need(all(_finite(row[k]) and row[k] == getattr(refusal, k) for k in
              ('issued_at', 'sampled_at', 'valid_until')), 'REFUSAL_TIME_JOIN')
    # Raw partial words are diagnostics only, not a valid successful 22-state.
    _need(all(type(row[k]) is list and len(row[k]) == 22 and all(_int(v) for v in row[k])
              for k in ('before_state', 'after_state'))
          and type(row['middle_state']) is list and row['middle_state'] == [], 'REFUSAL_OBSERVATIONS')
    _need(all(type(row[k]) is str and (row[k] == NIL_UUID or command_codec._uuid(row[k]))
              for k in ('actor_uuid', 'owner_uuid')) and _int(row['owner_class'], 0, 3)
          and _int(row['owner_version']), 'REFUSAL_OWNER_OBSERVATION')
    _refusal_job(refusal.job); _closure(refusal.closure)
    for key, names, facts in (('job', JOB_KEYS, refusal.job), ('closure', CLOSURE_KEYS, refusal.closure)):
        _need(type(row[key]) is dict and set(row[key]) == set(names)
              and all(type(row[key][k]) is type(getattr(facts, k)) and row[key][k] == getattr(facts, k)
                      for k in names), 'REFUSAL_FACTS_JOIN')
    return refusal


def parse_refusal_frame(frame, **context):
    """Decode the existing negative V3 frame without exposing source fields."""
    _context(**context)
    row, body = _unframe(frame, context['command'], CAPTURE_KEYS)
    _need(body == b'', 'REFUSAL_NO_BODY')
    _need(type(row['job']) is dict and set(row['job']) == set(JOB_KEYS)
          and type(row['closure']) is dict and set(row['closure']) == set(CLOSURE_KEYS), 'REFUSAL_SCHEMA')
    private = None
    try:
        private = json.dumps(row, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf8')
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        pass
    _need(private is not None, 'REFUSAL_METADATA')
    result = EditorReadRefusal(context['installation'], context['command'], row['issued_at'],
        row['sampled_at'], row['valid_until'], EditorJobFacts(**row['job']),
        EditorClosureFacts(**row['closure']), private)
    return validate_refusal(result, **context)


def build_refusal_frame(refusal, **context):
    validate_refusal(refusal, **context)
    return _frame(_json(refusal._metadata, CAPTURE_KEYS), b'', context['command'])


def parse_editor_frame(frame, **context):
    """Dispatch success, known restored mismatch or clean READ refusal, never UNKNOWN."""
    _context(**context)
    if context['command'].opcode == command_codec.READ_REPOSITORY_MODULE:
        from .editor_repository_transport import parse_repository_frame
        return parse_repository_frame(frame, **context)
    if context['command'].opcode == command_codec.CAPTURE_ONLY:
        from .editor_capture_transport import parse_capture_only_frame
        return parse_capture_only_frame(frame, **context)
    if context['command'].opcode == command_codec.ACTIVATE_OWN6:
        from .editor_activation_transport import parse_activation_frame
        return parse_activation_frame(frame, **context)
    row, _ = _unframe(frame, context['command'], CAPTURE_KEYS)
    if row['status'] == 'APPLIED':
        return parse_applied_frame(frame, **context)
    if row['status'] == 'RESTORED_STATE_MISMATCH':
        return parse_restored_state_mismatch_frame(frame, **context)
    return (parse_refusal_frame if row['status'] == 'REFUSED' else parse_capture_frame)(frame, **context)


def parse_capture_frame(frame, **context):
    return _parse_capture_frame(frame, EditorCapture, validate_capture, context)


def parse_restored_state_mismatch_frame(frame, **context):
    return _parse_capture_frame(frame, EditorRestoredStateMismatch, validate_restored_state_mismatch, context)


def parse_applied_frame(frame, **context):
    return _parse_capture_frame(frame, EditorApplied, validate_applied, context)


def _parse_capture_frame(frame, capture_type, validator, context):
    _context(**context)
    command, installation = context['command'], context['installation']
    _need(command.opcode in (1, 2), 'CAPTURE_OPCODE')
    row, body = _unframe(frame, command, CAPTURE_KEYS)
    _join_metadata(row, installation, command, 'EDITOR_CAPTURE')
    _need(all(type(row[name]) is str and row[name] == getattr(command.target, name) for name in TARGET_KEYS), 'TARGET_JOIN')
    _need(type(row['job']) is dict and set(row['job']) == set(JOB_KEYS)
          and type(row['closure']) is dict and set(row['closure']) == set(CLOSURE_KEYS), 'FACT_SCHEMA')
    _need(_int(row['byte_count'], 0, MAX_BODY_BYTES) and row['byte_count'] == len(body), 'BYTE_COUNT')
    _need(all(type(row[name]) is list for name in ('before_state', 'middle_state', 'after_state')), 'STATE_TYPE')
    values = {name: row[name] for name in CAPTURE_VALUE_KEYS}
    for name in ('before_state', 'middle_state', 'after_state'):
        values[name] = tuple(values[name])
    capture = capture_type(installation, command, **values, job=EditorJobFacts(**row['job']),
                            closure=EditorClosureFacts(**row['closure']), utf8=body)
    return validator(capture, **context)


def _totals(totals):
    _need(type(totals) is EditorTotals and all(_int(getattr(totals, name), 0, 384) for name in TOTAL_KEYS), 'TOTALS_TYPE')
    _need(totals.total_commands == totals.total_reads + totals.total_edits
          + totals.total_capture_commands + totals.total_activation_commands <= 64
          # READ attempts include clean refusals with honestly partial reads.
          # VERIFY_UNDO contributes six reads and one Undo; APPLY contributes
          # five reads and no Undo. Derive their counts without new wire keys.
          and 5 * totals.total_edits + totals.total_undo_attempts <= totals.total_direct_reads <= 2 * totals.total_reads
          + 5 * totals.total_edits + totals.total_undo_attempts
          + 32 * totals.total_capture_commands + 32 * totals.total_activation_commands
          and all(getattr(totals, name) == totals.total_edits for name in
                  ('total_setter_attempts', 'total_setter_returned', 'total_source_writes'))
          and totals.total_undo_attempts == totals.total_undo_returned <= totals.total_edits
          and totals.total_capture_commands <= 1
          and (totals.total_capture_commands == 0 or totals.total_edits == 0)
          and totals.total_activation_commands <= 1
          and (totals.total_activation_commands == 0
               or totals.total_edits == totals.total_capture_commands == 0)
          and totals.repository_mutations <= totals.total_capture_commands
          and totals.configuration_saves == totals.database_updates == 0, 'TOTALS_FACTS')


def validate_close(close, *, expected_totals, **context):
    _context(**context); _totals(expected_totals)
    command, installation, now = context['command'], context['installation'], context['now']
    _need(command.opcode == 3 and type(close) is EditorClose and type(close.command) is command_codec.EditorCommand
          and close.command == command and type(close.installation) is EditorInstallation
          and close.installation == installation, 'CLOSE_JOIN')
    _totals(close.totals)
    _need(close.totals == expected_totals and _int(close.last_command_sequence, 0, 64)
          and close.last_command_sequence == context['previous_sequence'] == close.totals.total_commands, 'CLOSE_TOTALS')
    _need(_finite(close.closed_at) and installation.installed_at <= close.closed_at <= now
          <= installation.valid_until + CLOSE_GRACE, 'CLOSE_TIME')
    _need(close.job_active is False and close.retained_unknown is False and close.callback_quiesced is True
          and close.io_drained is True and all(type(getattr(close, name)) is int and getattr(close, name) == 0
              for name in ('contexts_live', 'functions_live', 'buffers_live')), 'CLOSE_CLEAN')
    return close


def build_close_frame(close, *, expected_totals, **context):
    validate_close(close, expected_totals=expected_totals, **context)
    row = dict(kind='EDITOR_CLOSE_READY', version=VERSION, **_binding_metadata(close.installation), **_request_metadata(close.command))
    row.update({name: getattr(close, name) for name in ('closed_at', 'last_command_sequence', 'job_active',
        'retained_unknown', 'callback_quiesced', 'io_drained', 'contexts_live', 'functions_live', 'buffers_live')})
    row.update({name: getattr(close.totals, name) for name in TOTAL_KEYS})
    return _frame(row, b'', close.command)


def parse_close_frame(frame, *, expected_totals, **context):
    _context(**context)
    row, body = _unframe(frame, context['command'], CLOSE_KEYS)
    _join_metadata(row, context['installation'], context['command'], 'EDITOR_CLOSE_READY')
    _need(body == b'', 'CLOSE_BODY')
    close = EditorClose(context['installation'], context['command'], row['closed_at'], row['last_command_sequence'],
        EditorTotals(**{name: row[name] for name in TOTAL_KEYS}), **{name: row[name] for name in
        ('job_active', 'retained_unknown', 'callback_quiesced', 'io_drained', 'contexts_live', 'functions_live', 'buffers_live')})
    return validate_close(close, expected_totals=expected_totals, **context)


def build_ack(command, body_sha256, *, accepted):
    _shape(command)
    _need(command_codec._hex(body_sha256, 64) and type(accepted) is bool
          and (command.opcode != 3 or body_sha256 == EMPTY_SHA256), 'ACK_FIELDS')
    return _ACK.pack(ACK_MAGIC, VERSION, 0 if accepted else 1, command.sequence, command.revision,
                     command.nonce.encode('ascii'), body_sha256.encode('ascii'))


def parse_ack(frame, *, command, body_sha256):
    _shape(command)
    _need(command_codec._hex(body_sha256, 64) and (command.opcode != 3 or body_sha256 == EMPTY_SHA256), 'ACK_FIELDS')
    _need(type(frame) is bytes and len(frame) == ACK_BYTES, 'ACK_LENGTH')
    magic, version, status, seq, revision, nonce, digest = _ACK.unpack(frame)
    _need(magic == ACK_MAGIC and version == VERSION and status in (0, 1) and seq == command.sequence
          and revision == command.revision and nonce == command.nonce.encode('ascii')
          and digest == body_sha256.encode('ascii'), 'ACK_JOIN')
    return status == 0


def _validate_any(capture, expected_totals, context):
    if type(capture) is EditorClose:
        validate_close(capture, expected_totals=expected_totals, **context)
    else:
        _need(expected_totals is None, 'UNEXPECTED_TOTALS')
        if context['command'].opcode == command_codec.READ_REPOSITORY_MODULE:
            from .editor_repository_transport import validate_repository
            validate_repository(capture, **context)
            return
        if context['command'].opcode == command_codec.CAPTURE_ONLY:
            from .editor_capture_transport import validate_capture_only
            validate_capture_only(capture, **context)
            return
        if context['command'].opcode == command_codec.ACTIVATE_OWN6:
            from .editor_activation_transport import validate_activation
            validate_activation(capture, **context)
            return
        validator = (validate_applied if type(capture) is EditorApplied
                     else validate_restored_state_mismatch if type(capture) is EditorRestoredStateMismatch
                     else validate_refusal if type(capture) is EditorReadRefusal else validate_capture)
        validator(capture, **context)


def _transfer_sha(capture):
    return EMPTY_SHA256 if type(capture) is EditorReadRefusal else capture.body_sha256


def _release(release, capture, context):
    command, binding, now = context['command'], context['binding'], context['now']
    _need(type(release) is EditorRelease, 'RELEASE_TYPE')
    _binding(release.binding)
    _need((command.target is None and release.target is None)
          or type(release.target) is command_codec.EditorTarget, 'RELEASE_TARGET')
    if release.target is not None:
        _need(all(command_codec._uuid(getattr(release.target, name)) for name in TARGET_KEYS), 'RELEASE_TARGET')
    _need(release.binding == binding and release.target == command.target
          and _int(release.sequence, 1, 65) and release.sequence == command.sequence
          and _int(release.revision) and release.revision == command.revision
          and type(release.nonce) is str and release.nonce == command.nonce
          and type(release.body_sha256) is str and release.body_sha256 == _transfer_sha(capture)
          and type(release.status) is str and release.status == 'JOB_RELEASED', 'RELEASE_JOIN')
    start = capture.closed_at if type(capture) is EditorClose else capture.sampled_at
    _need(_finite(release.released_at) and start <= release.released_at <= now, 'RELEASE_TIME')
    _need(all(getattr(release, name) is True for name in
              ('ack_accepted', 'borrow_returned', 'buffers_freed', 'io_drained', 'context_closed', 'function_closed', 'callback_quiesced')), 'RELEASE_FACTS')


def build_release(release, *, capture, expected_totals=None, **context):
    _validate_any(capture, expected_totals, context); _release(release, capture, context)
    command = context['command']
    target = b'\0' * 32 if command.opcode == 3 else command.target.object_uuid.replace('-', '').encode('ascii')
    return _RELEASE.pack(RELEASE_MAGIC, VERSION, release.sequence, release.revision, ALL_RELEASED,
        release.nonce.encode('ascii'), target, release.body_sha256.encode('ascii'), float(release.released_at))


def parse_release(frame, *, capture, expected_totals=None, **context):
    _validate_any(capture, expected_totals, context)
    _need(type(frame) is bytes and len(frame) == RELEASE_BYTES, 'RELEASE_LENGTH')
    magic, version, seq, revision, flags, nonce, target, digest, released = _RELEASE.unpack(frame)
    command = context['command']
    wanted_target = b'\0' * 32 if command.opcode == 3 else command.target.object_uuid.replace('-', '').encode('ascii')
    _need(magic == RELEASE_MAGIC and version == VERSION and flags == ALL_RELEASED and seq == command.sequence
          and revision == command.revision and nonce == command.nonce.encode('ascii') and target == wanted_target
          and digest == _transfer_sha(capture).encode('ascii'), 'RELEASE_HEADER')
    release = EditorRelease(context['binding'], command.target, seq, revision, command.nonce, _transfer_sha(capture), released)
    _release(release, capture, context)
    return release


def finish_capture(capture, release, **context):
    validate_capture(capture, **context); _release(release, capture, context)
    return EditorSnapshot(capture, release)


def finish_restored_state_mismatch(capture, release, **context):
    validate_restored_state_mismatch(capture, **context); _release(release, capture, context)
    return EditorRestoredStateMismatchSnapshot(capture, release)


def finish_applied(capture, release, **context):
    validate_applied(capture, **context); _release(release, capture, context)
    return EditorAppliedSnapshot(capture, release)


def finish_refusal(refusal, release, **context):
    validate_refusal(refusal, **context); _release(release, refusal, context)
    return EditorRefusalSnapshot(refusal, release)


def advance_totals(totals, snapshot):
    """Advance only after the trusted owner validated and finished a release."""
    _totals(totals)
    from .editor_repository_transport import RepositorySnapshot, validate_repository
    from .editor_capture_transport import EditorCaptureOnlySnapshot, validate_capture_only
    from .editor_activation_transport import EditorActivationSnapshot, validate_activation
    repository = type(snapshot) is RepositorySnapshot
    capture_only = type(snapshot) is EditorCaptureOnlySnapshot
    activation_only = type(snapshot) is EditorActivationSnapshot
    refused = type(snapshot) is EditorRefusalSnapshot
    restored_mismatch = type(snapshot) is EditorRestoredStateMismatchSnapshot
    applied = type(snapshot) is EditorAppliedSnapshot
    if applied:
        capture, release = snapshot.capture, snapshot.release
        _need(type(capture) is EditorApplied and type(release) is EditorRelease, 'APPLY_SNAPSHOT')
        capability = command_codec.EditCapability(capture.binding, capture.target,
            capture.command.expected_owner, policy=command_codec.EDIT_APPLY)
        context = dict(binding=capture.binding, installation=capture.installation, command=capture.command,
                       now=release.released_at, previous_sequence=capture.command.sequence - 1, capability=capability)
        validate_applied(capture, **context); _release(release, capture, context)
    elif restored_mismatch:
        capture, release = snapshot.capture, snapshot.release
        _need(type(capture) is EditorRestoredStateMismatch and type(release) is EditorRelease, 'MISMATCH_SNAPSHOT')
        capability = command_codec.EditCapability(capture.binding, capture.target, capture.command.expected_owner)
        context = dict(binding=capture.binding, installation=capture.installation, command=capture.command,
                       now=release.released_at, previous_sequence=capture.command.sequence - 1, capability=capability)
        validate_restored_state_mismatch(capture, **context); _release(release, capture, context)
    elif activation_only:
        capture, release = snapshot.capture, snapshot.release
        _need(type(release) is EditorRelease, 'ACTIVATION_SNAPSHOT_RELEASE')
        context = dict(binding=capture.binding, installation=capture.installation, command=capture.command,
                       now=release.released_at, previous_sequence=capture.command.sequence - 1,
                       capability=capture.capability)
        validate_activation(capture, **context); _release(release, capture, context)
    elif capture_only:
        capture, release = snapshot.capture, snapshot.release
        _need(type(release) is EditorRelease, 'CAPTURE_ONLY_SNAPSHOT_RELEASE')
        context = dict(binding=capture.binding, installation=capture.installation, command=capture.command,
                       now=release.released_at, previous_sequence=capture.command.sequence - 1)
        validate_capture_only(capture, **context); _release(release, capture, context)
    elif repository:
        capture, release = snapshot.capture, snapshot.release
        _need(type(release) is EditorRelease, 'REPOSITORY_SNAPSHOT_RELEASE')
        context = dict(binding=capture.binding, installation=capture.installation, command=capture.command,
                       now=release.released_at, previous_sequence=capture.command.sequence - 1)
        validate_repository(capture, **context); _release(release, capture, context)
    elif refused:
        capture, release = snapshot.refusal, snapshot.release
        _need(type(capture) is EditorReadRefusal and type(release) is EditorRelease, 'REFUSAL_SNAPSHOT')
        context = dict(binding=capture.binding, installation=capture.installation, command=capture.command,
                       now=release.released_at, previous_sequence=capture.command.sequence - 1)
        validate_refusal(capture, **context); _release(release, capture, context)
    else:
        _history_snapshot(snapshot)
        capture, release = snapshot.capture, snapshot.release
    _need(capture.command.sequence == totals.total_commands + 1 and release.sequence == capture.command.sequence
          and release.body_sha256 == _transfer_sha(capture) and release.nonce == capture.command.nonce
          and release.binding == capture.binding and release.target == capture.target, 'TOTALS_SEQUENCE')
    edit = capture.command.opcode == 2
    if repository or capture_only or activation_only:
        pass  # Dedicated binary contract was checked above; no editor/TM facts.
    elif refused:
        _refusal_job(capture.job)
    elif applied:
        _apply_job(capture.job, capture.before_state == capture.after_state)
    else:
        _job(capture.job, edit, not_queried=not edit and capture.owner_class == OWNER_NOT_QUERIED,
             restored_mismatch=restored_mismatch)
    _closure(capture.closure)
    _need(all(getattr(release, name) is True for name in
        ('ack_accepted', 'borrow_returned', 'buffers_freed', 'io_drained', 'context_closed', 'function_closed', 'callback_quiesced')), 'TOTALS_RELEASE')
    values = {name: getattr(totals, name) for name in TOTAL_KEYS}
    values['total_commands'] += 1
    values['total_reads'] += int(not edit and not capture_only and not activation_only)
    values['total_edits'] += int(edit)
    values['total_capture_commands'] += int(capture_only)
    values['total_activation_commands'] += int(activation_only)
    values['repository_mutations'] += capture.job.repository_mutations
    values['total_direct_reads'] += capture.job.direct_reads
    for target, source in (('total_setter_attempts', 'setter_attempts'), ('total_setter_returned', 'setter_returned'),
        ('total_undo_attempts', 'undo_attempts'), ('total_undo_returned', 'undo_returned'), ('total_source_writes', 'source_writes')):
        values[target] += getattr(capture.job, source)
    result = EditorTotals(**values); _totals(result)
    return result


def capability_from_read(snapshot):
    """Derive an exact admission record after a physically validated READ/release.

    This helper is not native attestation. READ does not observe Redo; the first
    EDIT must still prove no initial Undo/Redo in its fresh native preflight.
    """
    _need(type(snapshot) is not EditorRefusalSnapshot, 'CAPABILITY_REFUSED_READ')
    _need(type(snapshot) is not EditorRestoredStateMismatchSnapshot, 'CAPABILITY_STATE_MISMATCH')
    _history_snapshot(snapshot)
    capture = snapshot.capture
    _need(capture.owner_class != OWNER_NOT_QUERIED, 'CAPABILITY_NOT_QUERIED')
    _need(capture.command.opcode == 1 and capture.status == 'READ' and capture.owner_class == 1
          and capture.owner_uuid == capture.actor_uuid and capture.owner_version > 0
          and not any(capture.before_state[i] for i in (11, 12, 19, 20)), 'CAPABILITY_READ')
    _job(capture.job, False); _closure(capture.closure)
    _need(type(snapshot.release) is EditorRelease and snapshot.release.sequence == capture.command.sequence
          and snapshot.release.nonce == capture.command.nonce and snapshot.release.body_sha256 == capture.body_sha256
          and snapshot.release.binding == capture.binding and snapshot.release.target == capture.target
          and snapshot.release.ack_accepted is True and snapshot.release.buffers_freed is True, 'CAPABILITY_RELEASE')
    return command_codec.EditCapability(capture.binding, capture.target, capture.actor_uuid)


def apply_capability_from_read(snapshot):
    """Explicit Root APPLY admission from an exact validated OWNED READ/release.

    Dirty text and existing history are allowed; native preflight must still
    recheck ownership/version, editability, identities, full source and range.
    This is not native attestation or permission recovered from JSON/a plan.
    """
    _history_snapshot(snapshot)
    capture = snapshot.capture
    _need(capture.command.opcode == command_codec.READ_MODULE
          and capture.command.policy == command_codec.READ_WITH_OWNERSHIP
          and capture.status == 'READ' and capture.owner_class == 1
          and capture.owner_uuid == capture.actor_uuid and capture.owner_version > 0
          and capture.before_state[12] == 0, 'APPLY_CAPABILITY_READ')
    return command_codec.EditCapability(capture.binding, capture.target,
        capture.actor_uuid, policy=command_codec.EDIT_APPLY)


def _history_snapshot(snapshot):
    """Recheck immutable historical joins, not physical authority or current TTL."""
    _need(type(snapshot) is EditorSnapshot and type(snapshot.capture) is EditorCapture
          and type(snapshot.release) is EditorRelease, 'SNAPSHOT_TYPE')
    capture = snapshot.capture
    _shape(capture.command)
    capability = None
    if capture.command.opcode == 2:
        capability = command_codec.EditCapability(capture.binding, capture.target, capture.command.expected_owner)
    context = dict(binding=capture.binding, installation=capture.installation, command=capture.command,
                   now=snapshot.release.released_at, previous_sequence=capture.command.sequence - 1, capability=capability)
    validate_capture(capture, **context)
    _release(snapshot.release, capture, context)
