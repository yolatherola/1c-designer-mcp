"""Pure V3 editor command codec, independent of the native 1536-byte job.

No I/O, native pointers, MCP writer, attestation or mutable replay registry.
Root supplies the trusted binding, expected request and edit capability directly;
none is recovered as authority from decoded bytes. The owner must atomically
advance its accepted sequence/nonce history. State words are opaque comparisons,
never addresses to dereference. The native job creates all owned RAM pointers.
"""
from dataclasses import dataclass, field
import hashlib
import re
import struct
import uuid

VERSION = 3
READ_MODULE, EDIT_MODULE, CLOSE = 1, 2, 3
READ_REPOSITORY_MODULE = 4
CAPTURE_ONLY = 5
ACTIVATE_OWN6 = 6
EDIT_VERIFY_UNDO = 1
READ_WITH_OWNERSHIP = 2
EDIT_APPLY = 3
COMMAND_MAGIC = b'AH1CEDC3'
ROOT_UUID = '218b5d00-7e10-486f-874c-73c2368ed5da'
SOURCE_DOMAIN = 'editor_live_at_capture'
MAX_UTF16_UNITS = 131072
MAX_UTF8_BYTES = 524288
MAX_SEQUENCE = 64
HEADER_BYTES = 512
MAX_FRAME_BYTES = HEADER_BYTES + 2 * MAX_UTF8_BYTES
ZERO_UUID = b'\0' * 16
ZERO_SHA = b'\0' * 32

# Little endian integers; RFC-4122 UUID bytes (not Windows GUID memory order).
# These named offsets are the carrier's decoding contract, not native pointers.
HEADER_LAYOUT = (
    ('magic', '8s'), ('version', 'H'), ('opcode', 'H'), ('policy', 'I'),
    ('root_uuid', '16s'), ('process_id', 'I'), ('birth', 'Q'),
    ('gui_thread_id', 'I'), ('operation_id', '16s'),
    ('scope_sha256', '32s'), ('source_sha256', '32s'),
    ('compiled_sha256', '32s'), ('source_domain', '32s'),
    ('object_uuid', '16s'), ('class_uuid', '16s'), ('property_uuid', '16s'),
    ('sequence', 'I'), ('revision', 'I'), ('nonce', '16s'),
    ('expected_owner', '16s'), ('expected_version', 'I'),
    ('expected_state', '88s'), ('baseline_bytes', 'I'), ('candidate_bytes', 'I'),
    ('baseline_units', 'I'), ('candidate_units', 'I'),
    ('baseline_sha256', '32s'), ('candidate_sha256', '32s'), ('reserved', '60s'))
OFFSETS = {}
_offset = 0
for _name, _format in HEADER_LAYOUT:
    OFFSETS[_name] = _offset
    _offset += struct.calcsize('<' + _format)
_HEADER = struct.Struct('<' + ''.join(fmt for _, fmt in HEADER_LAYOUT))
_STATE = struct.Struct('<22I')
_APPLY_RANGE = struct.Struct('<4sIII')
assert _HEADER.size == HEADER_BYTES


class EditorCommandRefusal(ValueError):
    """Stable failure code with no payload or caller values."""


def _need(ok, code):
    if not ok:
        raise EditorCommandRefusal('EDITOR_COMMAND_' + code)


def _int(value, low, high):
    return type(value) is int and low <= value <= high


def _hex(value, size):
    return (type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value)
            is not None and value != '0' * size)


def _uuid(value):
    return (type(value) is str and re.fullmatch(
        '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value)
        is not None and value != '00000000-0000-0000-0000-000000000000')


@dataclass(frozen=True, slots=True)
class EditorBinding:
    root_uuid: str
    process_id: int
    birth: str
    gui_thread_id: int
    operation_id: str
    scope_sha256: str
    source_sha256: str
    compiled_sha256: str
    source_domain: str = SOURCE_DOMAIN

    def validate(self):
        _need(type(self.root_uuid) is str and self.root_uuid == ROOT_UUID, 'ROOT')
        _need(_int(self.process_id, 1, 0xffffffff) and _hex(self.birth, 16)
              and _int(self.gui_thread_id, 1, 0xffffffff), 'PROCESS')
        _need(_hex(self.operation_id, 32) and all(_hex(x, 64) for x in
              (self.scope_sha256, self.source_sha256, self.compiled_sha256)), 'BINDING_PINS')
        _need(type(self.source_domain) is str and self.source_domain == SOURCE_DOMAIN, 'DOMAIN')


@dataclass(frozen=True, slots=True)
class EditorTarget:
    object_uuid: str
    class_uuid: str
    property_uuid: str

    def validate(self):
        _need(all(_uuid(x) for x in (self.object_uuid, self.class_uuid, self.property_uuid)), 'TARGET')


@dataclass(frozen=True, slots=True)
class ModuleText:
    _utf8: bytes = field(repr=False)
    sha256: str
    utf16_units: int

    @classmethod
    def from_utf8(cls, body):
        _need(type(body) is bytes and len(body) <= MAX_UTF8_BYTES, 'TEXT_BYTES')
        decoded = None
        try:
            decoded = body.decode('utf-8', 'strict')
        except UnicodeError:
            pass
        _need(decoded is not None, 'TEXT_ENCODING')
        _need('\0' not in decoded, 'TEXT_NUL')
        units = len(decoded.encode('utf-16-le', 'strict')) // 2
        _need(units <= MAX_UTF16_UNITS and decoded.encode('utf-8') == body, 'TEXT_BOUND')
        return cls(body, hashlib.sha256(body).hexdigest(), units)

    @classmethod
    def from_text(cls, text):
        _need(type(text) is str, 'TEXT_TYPE')
        _need(len(text) <= MAX_UTF16_UNITS, 'TEXT_BOUND')
        body = None
        try:
            body = text.encode('utf-8', 'strict')
        except UnicodeError:
            pass
        _need(body is not None, 'TEXT_ENCODING')
        return cls.from_utf8(body)

    @property
    def utf8(self):
        return self._utf8

    def validate(self):
        measured = ModuleText.from_utf8(self._utf8)
        _need(_hex(self.sha256, 64) and self.sha256 == measured.sha256
              and _int(self.utf16_units, 0, MAX_UTF16_UNITS)
              and self.utf16_units == measured.utf16_units, 'TEXT_DIGEST')


@dataclass(frozen=True, slots=True)
class EditCapability:
    """Trusted Root admission record, not cryptographic/native attestation.

    It is supplied out of band, never accepted from a mapping or command frame.
    The exact first fixture may be admitted without hardcoding every target to it.
    """
    binding: EditorBinding
    target: EditorTarget
    owner_uuid: str
    policy: int = EDIT_VERIFY_UNDO

    def validate(self):
        _binding(self.binding)
        _need(type(self.target) is EditorTarget, 'CAPABILITY_TARGET')
        self.target.validate()
        _need(_uuid(self.owner_uuid) and type(self.policy) is int
              and self.policy in (EDIT_VERIFY_UNDO, EDIT_APPLY), 'CAPABILITY_OWNER_POLICY')


@dataclass(frozen=True, slots=True)
class ActivationCapability:
    """Root-issued admission for one exact already-owned capture closure.

    Root verifies the prior receipt and a fresh ownership read before issuance.
    These identifiers are out-of-band joins, never authority decoded from a
    command. Activation grants no edit, cancel or repository freshness rights.
    """
    binding: EditorBinding
    target: EditorTarget
    owner_uuid: str
    expected_version: int
    expected_source_sha256: str
    prior_capture_operation_id: str
    prior_capture_receipt_sha256: str

    def validate(self):
        _binding(self.binding)
        _need(type(self.target) is EditorTarget, 'ACTIVATION_TARGET')
        self.target.validate()
        _need(_uuid(self.owner_uuid) and _int(self.expected_version, 1, 0x7fffffff),
              'ACTIVATION_OWNER_VERSION')
        _need(_hex(self.expected_source_sha256, 64)
              and _hex(self.prior_capture_operation_id, 32)
              and self.prior_capture_operation_id != self.binding.operation_id
              and _hex(self.prior_capture_receipt_sha256, 64), 'ACTIVATION_PROVENANCE')


@dataclass(frozen=True, slots=True)
class EditorApplyRange:
    """Half-open UTF16 content range; carries no ownership or write authority."""
    start_utf16: int
    stop_utf16: int
    replacement_units: int

    def validate(self):
        _need(_int(self.start_utf16, 0, MAX_UTF16_UNITS)
              and _int(self.stop_utf16, self.start_utf16, MAX_UTF16_UNITS)
              and _int(self.replacement_units, 0, MAX_UTF16_UNITS), 'APPLY_RANGE')


@dataclass(frozen=True, slots=True)
class EditorCommand:
    opcode: int
    binding: EditorBinding
    target: EditorTarget | None
    sequence: int
    revision: int
    nonce: str
    policy: int = 0
    expected_owner: str | None = None
    expected_version: int = 0
    expected_state: tuple = ()
    baseline: ModuleText | None = field(default=None, repr=False)
    candidate: ModuleText | None = field(default=None, repr=False)
    expected_source_sha256: str | None = None
    apply_range: EditorApplyRange | None = None


def _apply_plan(command):
    """Reprove the exact single-line splice, never derive permission from it."""
    interval = command.apply_range
    _need(type(interval) is EditorApplyRange, 'APPLY_RANGE_TYPE')
    interval.validate()
    _need(type(command.baseline) is ModuleText and type(command.candidate) is ModuleText, 'EDIT_TEXT')
    command.baseline.validate(); command.candidate.validate()
    baseline, candidate = command.baseline, command.candidate
    _need(interval.stop_utf16 <= baseline.utf16_units
          and candidate.utf16_units == baseline.utf16_units
              - (interval.stop_utf16 - interval.start_utf16) + interval.replacement_units, 'APPLY_SPLICE')
    raw = candidate.utf8.decode('utf-8').encode('utf-16-le')
    replacement = None
    try:
        replacement = ModuleText.from_text(raw[interval.start_utf16 * 2:
            (interval.start_utf16 + interval.replacement_units) * 2].decode('utf-16-le', 'strict'))
    except (UnicodeError, EditorCommandRefusal):
        pass
    _need(replacement is not None, 'APPLY_REPLACEMENT')
    # Lazy import avoids a cycle: the pure planner itself uses ModuleText.
    from .editor_change_plan import plan_edit, EditorChangePlanRefusal
    planned = None
    try:
        planned = plan_edit(baseline, baseline.sha256, replacement,
            utf16_span=(interval.start_utf16, interval.stop_utf16))
    except EditorChangePlanRefusal:
        pass
    _need(planned is not None and planned.candidate.utf8 == candidate.utf8, 'APPLY_SPLICE')
    return planned


def _range_wire(command):
    if command.opcode == EDIT_MODULE and command.policy == EDIT_APPLY:
        interval = command.apply_range
        return _APPLY_RANGE.pack(b'RNG1', interval.start_utf16,
            interval.stop_utf16, interval.replacement_units) + b'\0' * 44
    return b'\0' * 60


def _binding(binding):
    _need(type(binding) is EditorBinding, 'BINDING')
    binding.validate()


def _state(state):
    _need(type(state) is tuple and len(state) == 22
          and all(_int(x, 0, 0xffffffff) for x in state), 'STATE_WORDS')
    _need(all(x >= 65536 for x in state[:8])
          and all(state[i] in (0, 1) for i in (8, 9, 10, 11, 12, 19, 20))
          and (state[20] == 1 or state[21] == 0xffffffff), 'STATE_SHAPE')


def _validate(command, binding, previous_sequence, capability, used_nonces):
    _binding(binding)
    _need(type(command) is EditorCommand, 'COMMAND_TYPE')
    _binding(command.binding)
    _need(command.binding == binding, 'BINDING_JOIN')
    _need(type(command.opcode) is int
          and command.opcode in (READ_MODULE, EDIT_MODULE, CLOSE, READ_REPOSITORY_MODULE,
                                 CAPTURE_ONLY, ACTIVATE_OWN6), 'OPCODE')
    _need(_int(previous_sequence, 0, MAX_SEQUENCE)
          and _int(command.sequence, 1, MAX_SEQUENCE + (command.opcode == CLOSE))
          and command.sequence == previous_sequence + 1, 'SEQUENCE')
    _need(_hex(command.nonce, 32), 'NONCE')
    _need(type(used_nonces) is tuple and len(used_nonces) <= MAX_SEQUENCE
          and all(_hex(x, 32) for x in used_nonces)
          and len(set(used_nonces)) == len(used_nonces)
          and command.nonce not in used_nonces, 'NONCE_REPLAY')
    _need(type(command.policy) is int and type(command.expected_version) is int, 'INTEGER_TYPES')
    _need((command.opcode == EDIT_MODULE and command.policy == EDIT_APPLY)
          or command.apply_range is None, 'NONAPPLY_RANGE')
    if command.opcode == CLOSE:
        _need(command.target is None and type(command.revision) is int and command.revision == 0, 'CLOSE_TARGET')
    else:
        _need(type(command.target) is EditorTarget and _int(command.revision, 1, 0xffffffff), 'MODULE_TARGET')
        command.target.validate()
    if command.opcode == ACTIVATE_OWN6:
        _need(type(capability) is ActivationCapability, 'ACTIVATION_CAPABILITY')
        capability.validate()
        _need(capability.binding == binding and capability.target == command.target
              and capability.owner_uuid == command.expected_owner
              and capability.expected_version == command.expected_version
              and capability.expected_source_sha256 == command.expected_source_sha256,
              'ACTIVATION_JOIN')
        _need(command.policy == 0 and command.baseline is None and command.candidate is None,
              'ACTIVATION_PAYLOAD')
        _state(command.expected_state)
        _need(all(command.expected_state[i] == 0 for i in (8, 9, 10, 11, 19, 20))
              and command.expected_state[12] == 1, 'ACTIVATION_STATE')
        return
    _need(command.expected_source_sha256 is None, 'LEGACY_SOURCE_HASH')
    if command.opcode != EDIT_MODULE:
        allowed_policy = command.policy in (0, READ_WITH_OWNERSHIP) if command.opcode == READ_MODULE else command.policy == 0
        _need(allowed_policy and command.expected_owner is None and command.expected_version == 0
              and type(command.expected_state) is tuple and command.expected_state == ()
              and command.baseline is None and command.candidate is None, 'NONEDIT_PAYLOAD')
        return
    _need(command.policy in (EDIT_VERIFY_UNDO, EDIT_APPLY), 'EDIT_POLICY')
    _need(type(capability) is EditCapability, 'EDIT_CAPABILITY')
    capability.validate()
    _need(capability.binding == binding and capability.target == command.target
          and capability.policy == command.policy and capability.owner_uuid == command.expected_owner,
          'CAPABILITY_JOIN')
    _need(_uuid(command.expected_owner) and _int(command.expected_version, 1, 0xffffffff), 'EDIT_OWNER_VERSION')
    _state(command.expected_state)
    _need(type(command.baseline) is ModuleText and type(command.candidate) is ModuleText, 'EDIT_TEXT')
    command.baseline.validate()
    command.candidate.validate()
    _need(command.baseline.utf8 != command.candidate.utf8, 'EDIT_UNCHANGED')
    if command.policy == EDIT_APPLY:
        _need(command.expected_state[12] == 0, 'APPLY_READONLY')
        _apply_plan(command)


def build_command(command, *, binding, previous_sequence, capability=None, used_nonces=()):
    """Encode a Root-issued request; the result is private RAM, never a log value."""
    _validate(command, binding, previous_sequence, capability, used_nonces)
    target = command.target
    baseline, candidate = command.baseline, command.candidate
    raw = _HEADER.pack(COMMAND_MAGIC, VERSION, command.opcode, command.policy,
        uuid.UUID(binding.root_uuid).bytes, binding.process_id, int(binding.birth, 16),
        binding.gui_thread_id, bytes.fromhex(binding.operation_id),
        bytes.fromhex(binding.scope_sha256), bytes.fromhex(binding.source_sha256),
        bytes.fromhex(binding.compiled_sha256), binding.source_domain.encode('ascii').ljust(32, b'\0'),
        *(uuid.UUID(value).bytes if target else ZERO_UUID for value in
          ((target.object_uuid, target.class_uuid, target.property_uuid) if target else ('', '', ''))),
        command.sequence, command.revision, bytes.fromhex(command.nonce),
        uuid.UUID(command.expected_owner).bytes if command.expected_owner else ZERO_UUID,
        command.expected_version, _STATE.pack(*command.expected_state)
        if baseline or command.opcode == ACTIVATE_OWN6 else b'\0' * 88,
        len(baseline.utf8) if baseline else 0, len(candidate.utf8) if candidate else 0,
        baseline.utf16_units if baseline else 0, candidate.utf16_units if candidate else 0,
        bytes.fromhex(baseline.sha256) if baseline else
        bytes.fromhex(command.expected_source_sha256) if command.opcode == ACTIVATE_OWN6 else ZERO_SHA,
        bytes.fromhex(candidate.sha256) if candidate else ZERO_SHA, _range_wire(command))
    return raw + (baseline.utf8 + candidate.utf8 if baseline else b'')


def parse_command(frame, *, binding, expected_command, previous_sequence, capability=None, used_nonces=()):
    """Decode only a request matching the trusted outstanding identity and scope."""
    _validate(expected_command, binding, previous_sequence, capability, used_nonces)
    _need(type(frame) is bytes and HEADER_BYTES <= len(frame) <= MAX_FRAME_BYTES, 'FRAME_LENGTH')
    header = dict(zip((name for name, _ in HEADER_LAYOUT), _HEADER.unpack(frame[:HEADER_BYTES])))
    _need(header['magic'] == COMMAND_MAGIC and header['version'] == VERSION
          and header['reserved'] == _range_wire(expected_command), 'HEADER')
    bl, cl = header['baseline_bytes'], header['candidate_bytes']
    _need(bl <= MAX_UTF8_BYTES and cl <= MAX_UTF8_BYTES
          and header['baseline_units'] <= MAX_UTF16_UNITS and header['candidate_units'] <= MAX_UTF16_UNITS
          and len(frame) == HEADER_BYTES + bl + cl, 'BODY_LENGTH')
    # Encoding the trusted request makes every field an exact join, including
    # domain, target, owner, full state, sequence, revision and nonce. This also
    # rejects noncanonical UUID bytes, nonedit payload and all unknown fields.
    expected_frame = build_command(expected_command, binding=binding, previous_sequence=previous_sequence,
                                   capability=capability, used_nonces=used_nonces)
    _need(frame[:HEADER_BYTES] == expected_frame[:HEADER_BYTES], 'REQUEST_JOIN')
    if expected_command.opcode == EDIT_MODULE:
        baseline = ModuleText.from_utf8(frame[HEADER_BYTES:HEADER_BYTES + bl])
        candidate = ModuleText.from_utf8(frame[HEADER_BYTES + bl:])
        _need(baseline.sha256 == header['baseline_sha256'].hex()
              and candidate.sha256 == header['candidate_sha256'].hex()
              and baseline.utf16_units == header['baseline_units']
              and candidate.utf16_units == header['candidate_units'], 'BODY_DIGEST')
    _need(frame == expected_frame, 'BODY_JOIN')
    return expected_command
