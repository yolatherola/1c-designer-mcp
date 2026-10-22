"""Bounded resident LIVE protocol, with separate PRE-ACK and released states.

No I/O, native attestation, automatic ACK, replay registry, or session advancement.
The physical owner verifies the installation/SDK proofs and atomically maintains
the last accepted READ sequence. A parsed capture alone is never a final snapshot.
"""
from dataclasses import dataclass, field, fields
import hashlib
import json
import struct
from . import resident_live_source as source

VERSION = 1
READ = 1
CLOSE = 2
COMMAND_MAGIC = b'AH1CLVC1'
READY_MAGIC = b'AH1CLVY1'
FRAME_MAGIC = b'AH1CLVF1'
ACK_MAGIC = b'AH1CLVA1'
RELEASE_MAGIC = b'AH1CLVJ1'
TAIL = 0x3143564c
COMMAND_BYTES = 128
READY_BYTES = 128
HEADER_BYTES = 32
ACK_BYTES = 120
RELEASE_BYTES = 160
MAX_METADATA_BYTES = 16384
MAX_BODY_BYTES = source.MAX_BYTES
MAX_FRAME_BYTES = HEADER_BYTES+MAX_METADATA_BYTES+MAX_BODY_BYTES
CLOSE_GRACE = 60.0
ALL_RELEASED = 0x7f
EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()
_COMMAND = struct.Struct('<8sIIII32s32s32sII')
_READY = struct.Struct('<8sII32s64sdd')
_HEADER = struct.Struct('<8sIIIIII')
_ACK = struct.Struct('<8sIIII32s64s')
_RELEASE = struct.Struct('<8sIIII32s32s64sd')
_BINDING_KEYS = ('root_uuid', 'process_id', 'birth', 'operation_id', 'scope_sha256',
    'reader_source_sha256', 'compiled_source_sha256', 'installed_at', 'installation_valid_until', 'source_domain')
_RECEIPT_KEYS = tuple(f.name for f in fields(source.ResidentLiveReceipt) if f.name not in ('binding', 'target'))
CAPTURE_KEYS = frozenset(('kind', 'version', *_BINDING_KEYS, 'object_uuid', 'property_uuid', 'issued_at', *_RECEIPT_KEYS))
CLOSE_KEYS = frozenset(('kind', 'version', *_BINDING_KEYS, 'sequence', 'request_id', 'revision',
    'last_read_sequence', 'job_active', 'callback_quiesced', 'io_drained', 'contexts_live', 'functions_live',
    'buffers_live', 'source_writes', 'configuration_saves', 'database_updates', 'repository_mutations'))
_RELEASE_FLAGS = ('ack_accepted', 'borrow_returned', 'buffers_freed', 'io_drained',
                  'context_closed', 'function_closed', 'callback_quiesced')
_COUNTS = dict(whole_sdk_cpp_throws=0, whole_sdk_other_exceptions=0, sdk_result=0, abi_fault=0,
    contexts_created=1, contexts_released=1, functions_created=1, functions_released=1,
    direct_save_calls=2, state_bridge_calls=2, warmup_reads=1, helper_text_reads=0,
    source_writes=0, configuration_saves=0, database_updates=0, repository_mutations=0)


class ResidentLiveWireRefusal(ValueError):
    """Stable failure without source bytes, caller values, or decoder context."""


def _need(ok, code):
    if not ok:
        raise ResidentLiveWireRefusal('RESIDENT_LIVE_WIRE_'+code)


def _same_number(left, right):
    return source._finite(left) and source._finite(right) and float(left) == float(right)


@dataclass(frozen=True, slots=True)
class ResidentLiveContext:
    root_uuid: str
    process_id: int
    birth: str
    operation_id: str
    scope_sha256: str
    reader_source_sha256: str
    compiled_source_sha256: str
    source_domain: str = source.SOURCE_DOMAIN

    def validate(self):
        _need(type(self.root_uuid) is str and self.root_uuid == source.ROOT_UUID, 'ROOT')
        _need(source._int(self.process_id, 1, 2**32-1) and source._hex(self.birth, 16), 'PROCESS')
        _need(source._hex(self.operation_id, 32) and source._hex(self.scope_sha256, 64)
              and source._hex(self.reader_source_sha256, 64) and source._hex(self.compiled_source_sha256, 64), 'PINS')
        _need(type(self.source_domain) is str and self.source_domain == source.SOURCE_DOMAIN, 'DOMAIN')


@dataclass(frozen=True, slots=True)
class ResidentLiveCommand:
    opcode: int
    sequence: int
    request_id: str
    revision: int
    target: source.ResidentLiveTarget | None


@dataclass(frozen=True, slots=True)
class ResponseHeader:
    sequence: int
    revision: int
    metadata_length: int
    body_length: int


@dataclass(frozen=True, slots=True)
class ResidentLiveCapture:
    request: source.ResidentLiveReadRequest
    receipt: source.ResidentLiveReceipt
    utf8: bytes = field(repr=False, compare=False)


def _binding(binding):
    _need(type(binding) is source.ResidentLiveBinding, 'BINDING')
    binding.validate()


def _command_shape(command):
    _need(type(command) is ResidentLiveCommand and type(command.opcode) is int
          and command.opcode in (READ, CLOSE) and source._hex(command.request_id, 32), 'COMMAND')
    if command.opcode == READ:
        _need(source._int(command.sequence, 1, 64) and source._int(command.revision, 1, 2**32-1)
              and type(command.target) is source.ResidentLiveTarget, 'READ_COMMAND')
        command.target.validate()
    else:
        _need(source._int(command.sequence, 1, 65) and type(command.revision) is int
              and command.revision == 0 and command.target is None, 'CLOSE_COMMAND')


def _command(command, binding, now, previous_sequence):
    _binding(binding); _command_shape(command)
    _need(source._int(previous_sequence, 0, 64) and command.sequence == previous_sequence+1, 'SEQUENCE')
    _need(source._finite(now) and binding.installed_at <= now, 'COMMAND_TIME')
    if command.opcode == READ:
        _need(previous_sequence < 64 and now <= binding.valid_until, 'READ_EXPIRY')
    else:
        # A finite cleanup-only window does not extend READ or renew installation.
        _need(now <= binding.valid_until+CLOSE_GRACE, 'CLOSE_EXPIRY')


def build_command(command, *, binding, now, previous_sequence):
    """Emit fixed READ/CLOSE bytes; there is no code, address, path, or time input."""
    _command(command, binding, now, previous_sequence)
    target = b'\0'*32 if command.opcode == CLOSE else command.target.object_uuid.replace('-', '').encode('ascii')
    return _COMMAND.pack(COMMAND_MAGIC, VERSION, command.opcode, command.sequence, command.revision,
        command.request_id.encode('ascii'), target, binding.operation_id.encode('ascii'),
        60000 if command.opcode == READ else 0, TAIL)


def parse_command(frame, *, binding, now, previous_sequence):
    _need(type(frame) is bytes and len(frame) == COMMAND_BYTES, 'COMMAND_LENGTH')
    magic, version, opcode, seq, revision, nonce, target, operation, ttl, tail = _COMMAND.unpack(frame)
    _need(magic == COMMAND_MAGIC and version == VERSION and tail == TAIL, 'COMMAND_HEADER')
    _binding(binding)
    _need(operation == binding.operation_id.encode('ascii') and ttl == (60000 if opcode == READ else 0), 'COMMAND_CONTEXT')
    parsed = None
    try:
        request_id = nonce.decode('ascii')
        obj = target.decode('ascii')
        if opcode == READ and source._hex(obj, 32):
            canonical = '-'.join((obj[:8], obj[8:12], obj[12:16], obj[16:20], obj[20:]))
            parsed = source.ResidentLiveTarget(canonical, source.PROPERTY_UUID)
    except UnicodeDecodeError:
        request_id = None
    _need(opcode != CLOSE or target == b'\0'*32, 'CLOSE_TARGET')
    command = ResidentLiveCommand(opcode, seq, request_id, revision, parsed)
    _command(command, binding, now, previous_sequence)
    return command


def build_ready(binding):
    """C-to-server READY carries runtime installation times, not stage time."""
    _binding(binding)
    return _READY.pack(READY_MAGIC, VERSION, 0, binding.operation_id.encode('ascii'),
                       binding.scope_sha256.encode('ascii'), float(binding.installed_at), float(binding.valid_until))


def parse_ready(frame, *, context, now):
    _need(type(context) is ResidentLiveContext, 'CONTEXT')
    context.validate()
    _need(type(frame) is bytes and len(frame) == READY_BYTES, 'READY_LENGTH')
    magic, version, reserved, op, scope, installed, expiry = _READY.unpack(frame)
    _need(magic == READY_MAGIC and version == VERSION and reserved == 0
          and op == context.operation_id.encode('ascii') and scope == context.scope_sha256.encode('ascii'), 'READY_CONTEXT')
    binding = source.ResidentLiveBinding(context.root_uuid, context.process_id, context.birth,
        context.operation_id, context.scope_sha256, context.reader_source_sha256, context.compiled_source_sha256,
        installed, expiry, context.source_domain)
    _binding(binding)
    _need(source._finite(now) and installed <= now <= expiry, 'READY_TIME')
    return binding


def _metadata_binding(binding):
    return dict(root_uuid=binding.root_uuid, process_id=binding.process_id, birth=binding.birth,
        operation_id=binding.operation_id, scope_sha256=binding.scope_sha256,
        reader_source_sha256=binding.reader_source_sha256, compiled_source_sha256=binding.compiled_source_sha256,
        installed_at=binding.installed_at, installation_valid_until=binding.valid_until, source_domain=binding.source_domain)


def _join_metadata_binding(metadata, binding):
    _binding(binding)
    expected = _metadata_binding(binding)
    _need(all(_same_number(metadata[key], expected[key]) if key in ('installed_at', 'installation_valid_until')
              else type(metadata[key]) is type(expected[key]) and metadata[key] == expected[key]
              for key in _BINDING_KEYS), 'METADATA_BINDING')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _json(data, keys):
    parsed = None
    try:
        parsed = json.loads(data.decode('utf-8', 'strict'), object_pairs_hook=_pairs,
                            parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeDecodeError, RecursionError):
        pass
    _need(type(parsed) is dict and set(parsed) == keys, 'JSON_SCHEMA')
    return parsed


def parse_response_header(frame, *, command):
    """Bound lengths before the caller allocates or reads the remaining frame."""
    _command_shape(command)
    _need(type(frame) is bytes and len(frame) == HEADER_BYTES, 'HEADER_LENGTH')
    magic, version, seq, revision, meta_len, body_len, reserved = _HEADER.unpack(frame)
    _need(magic == FRAME_MAGIC and version == VERSION and reserved == 0
          and seq == command.sequence and revision == command.revision, 'HEADER_JOIN')
    _need(2 <= meta_len <= MAX_METADATA_BYTES and body_len <= MAX_BODY_BYTES
          and (command.opcode != CLOSE or body_len == 0), 'HEADER_BOUND')
    return ResponseHeader(seq, revision, meta_len, body_len)


def _unframe(frame, command, keys):
    _need(type(frame) is bytes and HEADER_BYTES <= len(frame) <= MAX_FRAME_BYTES, 'FRAME_LENGTH')
    header = parse_response_header(frame[:HEADER_BYTES], command=command)
    _need(len(frame) == HEADER_BYTES+header.metadata_length+header.body_length, 'FRAME_BOUND')
    split = HEADER_BYTES+header.metadata_length
    return _json(frame[HEADER_BYTES:split], keys), frame[split:]


def _frame(metadata, body, command):
    raw = None
    try:
        raw = json.dumps(metadata, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf-8')
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        pass
    _need(raw is not None, 'JSON_ENCODING')
    _need(2 <= len(raw) <= MAX_METADATA_BYTES and type(body) is bytes and len(body) <= MAX_BODY_BYTES, 'FRAME_BOUND')
    return _HEADER.pack(FRAME_MAGIC, VERSION, command.sequence, command.revision, len(raw), len(body), 0)+raw+body


def validate_capture(capture, *, binding, command, now, previous_sequence):
    """Validate PRE-ACK facts without inventing a release or final snapshot.

    Successful schema/joins do not physically attest SDK or authorize an ACK.
    The trusted owner separately establishes the physical capture/epoch proofs.
    """
    _command(command, binding, now, previous_sequence)
    _need(command.opcode == READ and type(capture) is ResidentLiveCapture
          and type(capture.request) is source.ResidentLiveReadRequest
          and type(capture.receipt) is source.ResidentLiveReceipt and type(capture.utf8) is bytes, 'CAPTURE_TYPE')
    q, r = capture.request, capture.receipt
    _need(type(q.binding) is source.ResidentLiveBinding and type(q.target) is source.ResidentLiveTarget
          and q.binding == binding and q.target == command.target and type(q.sequence) is int
          and q.sequence == command.sequence and type(q.request_id) is str and q.request_id == command.request_id
          and type(q.revision) is int and q.revision == command.revision, 'REQUEST_JOIN')
    # Equality is insufficient for a nested binding (True == 1 in Python).
    _binding(q.binding); q.target.validate()
    source._job_join(r, q)
    _need(source._finite(q.issued_at) and source._finite(q.valid_until) and source._finite(r.sampled_at)
          and source._finite(r.valid_until) and binding.installed_at <= q.issued_at <= r.sampled_at <= now
          <= r.valid_until <= q.valid_until <= min(binding.valid_until, q.issued_at+source.MAX_TTL)
          and q.issued_at < q.valid_until, 'CAPTURE_TIME')
    _need(type(r.native_root_uuid) is str and r.native_root_uuid == binding.root_uuid
          and type(r.native_class_uuid) is str and r.native_class_uuid == source.CLASS_UUID
          and type(r.native_object_uuid) is str and r.native_object_uuid == q.target.object_uuid
          and type(r.native_property_uuid) is str and r.native_property_uuid == source.PROPERTY_UUID, 'NATIVE_BINDING')
    body = capture.utf8
    _need(source._int(r.byte_count, 0, MAX_BODY_BYTES) and r.byte_count == len(body)
          and source._hex(r.source_sha256, 64) and hashlib.sha256(body).hexdigest() == r.source_sha256, 'BODY_HASH')
    _need(type(r.bom_present) is bool and r.bom_present == body.startswith(b'\xef\xbb\xbf')
          and source._int(r.crlf_count, 0, source.MAX_UTF16_UNITS) and r.crlf_count == body.count(b'\r\n')
          and type(r.ends_lf) is bool and r.ends_lf == body.endswith(b'\n'), 'BYTE_SHAPE')
    source._state(r.before_state, r.after_state)
    _need(all(type(getattr(r, key)) is int and getattr(r, key) == value for key, value in _COUNTS.items()), 'COUNTS')
    _need(all(type(getattr(r, key)) is bool and getattr(r, key) is True for key in
              ('context_release_returned', 'function_release_returned', 'typed_handles_cleared', 'read_equality_verified')), 'SDK_CLOSURE')
    text = None
    try:
        text = body.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        pass
    _need(text is not None, 'UTF8')
    _need('\0' not in text and source._int(r.utf16_units, 0, source.MAX_UTF16_UNITS)
          and len(text.encode('utf-16-le'))//2 == r.utf16_units, 'UTF16_BOUND')
    return capture


def build_capture_frame(capture, *, binding, command, now, previous_sequence):
    validate_capture(capture, binding=binding, command=command, now=now, previous_sequence=previous_sequence)
    r = capture.receipt
    metadata = dict(kind='RESIDENT_LIVE_CAPTURE', version=VERSION, **_metadata_binding(binding),
        object_uuid=r.target.object_uuid, property_uuid=r.target.property_uuid, issued_at=capture.request.issued_at)
    metadata.update({key: getattr(r, key) for key in _RECEIPT_KEYS})
    return _frame(metadata, capture.utf8, command)


def parse_capture_frame(frame, *, binding, command, now, previous_sequence):
    _command(command, binding, now, previous_sequence)
    _need(command.opcode == READ, 'READ_OPCODE')
    m, body = _unframe(frame, command, CAPTURE_KEYS)
    _join_metadata_binding(m, binding)
    _need(type(m['kind']) is str and m['kind'] == 'RESIDENT_LIVE_CAPTURE'
          and type(m['version']) is int and m['version'] == VERSION, 'CAPTURE_KIND')
    target = source.ResidentLiveTarget(m['object_uuid'], m['property_uuid'])
    target.validate()
    _need(type(m['before_state']) is list and type(m['after_state']) is list, 'STATE_TYPE')
    values = {key: m[key] for key in _RECEIPT_KEYS}
    values.update(before_state=tuple(m['before_state']), after_state=tuple(m['after_state']))
    receipt = source.ResidentLiveReceipt(binding=binding, target=target, **values)
    request = source.ResidentLiveReadRequest(binding, target, m['sequence'], m['request_id'],
                                            m['revision'], m['issued_at'], m['valid_until'])
    capture = ResidentLiveCapture(request, receipt, body)
    return validate_capture(capture, binding=binding, command=command, now=now, previous_sequence=previous_sequence)


def validate_receipt(capture, receipt, *, binding, command, now, previous_sequence):
    """Require the trusted physical validator's receipt to match every frame fact.

    Calling this does not itself query the native process. The channel obtains
    receipt from its approved physical callback, never an untrusted frame alias.
    """
    _need(type(capture) is ResidentLiveCapture and type(receipt) is source.ResidentLiveReceipt, 'TRUSTED_RECEIPT_TYPE')
    # Dataclass equality alone treats True == 1. Validate both typed facts before
    # equality so a physical callback cannot return a numeric/boolean mismatch.
    validate_capture(ResidentLiveCapture(capture.request, receipt, capture.utf8),
        binding=binding, command=command, now=now, previous_sequence=previous_sequence)
    _need(receipt == capture.receipt, 'TRUSTED_RECEIPT_JOIN')
    return validate_capture(capture, binding=binding, command=command, now=now, previous_sequence=previous_sequence)


def build_ack(command, body_sha256, *, accepted):
    """Only an explicit trusted-owner decision can emit an accepted ACK."""
    _command_shape(command)
    _need(source._hex(body_sha256, 64) and type(accepted) is bool, 'ACK_FIELDS')
    _need(command.opcode != CLOSE or body_sha256 == EMPTY_SHA256, 'CLOSE_HASH')
    return _ACK.pack(ACK_MAGIC, VERSION, 0 if accepted else 1, command.sequence, command.revision,
                     command.request_id.encode('ascii'), body_sha256.encode('ascii'))


def parse_ack(frame, *, command, body_sha256):
    _command_shape(command)
    _need(source._hex(body_sha256, 64) and (command.opcode != CLOSE or body_sha256 == EMPTY_SHA256), 'ACK_FIELDS')
    _need(type(frame) is bytes and len(frame) == ACK_BYTES, 'ACK_LENGTH')
    magic, version, status, seq, rev, nonce, digest = _ACK.unpack(frame)
    _need(magic == ACK_MAGIC and version == VERSION and status in (0, 1)
          and seq == command.sequence and rev == command.revision
          and nonce == command.request_id.encode('ascii') and digest == body_sha256.encode('ascii'), 'ACK_JOIN')
    return status == 0


def build_release(release, *, capture, binding, command, now, previous_sequence):
    finish_capture(capture, release, binding=binding, command=command, now=now, previous_sequence=previous_sequence)
    return _RELEASE.pack(RELEASE_MAGIC, VERSION, release.sequence, release.revision, ALL_RELEASED,
        release.request_id.encode('ascii'), release.target.object_uuid.replace('-', '').encode('ascii'),
        release.source_sha256.encode('ascii'), float(release.released_at))


def parse_release(frame, *, capture, binding, command, now, previous_sequence):
    validate_capture(capture, binding=binding, command=command, now=now, previous_sequence=previous_sequence)
    _need(type(frame) is bytes and len(frame) == RELEASE_BYTES, 'RELEASE_LENGTH')
    magic, version, seq, rev, flags, nonce, target, digest, released_at = _RELEASE.unpack(frame)
    _need(magic == RELEASE_MAGIC and version == VERSION and flags == ALL_RELEASED
          and seq == command.sequence and rev == command.revision
          and nonce == command.request_id.encode('ascii')
          and target == command.target.object_uuid.replace('-', '').encode('ascii')
          and digest == capture.receipt.source_sha256.encode('ascii'), 'RELEASE_JOIN')
    release = source.ResidentLiveRelease(binding, command.target, seq, command.request_id, rev,
        capture.receipt.source_sha256, released_at, 'JOB_RELEASED', **{key: True for key in _RELEASE_FLAGS})
    finish_capture(capture, release, binding=binding, command=command, now=now, previous_sequence=previous_sequence)
    return release


def finish_capture(capture, release, *, binding, command, now, previous_sequence):
    """Produce a final typed snapshot only after a real, joined release receipt."""
    validate_capture(capture, binding=binding, command=command, now=now, previous_sequence=previous_sequence)
    _need(type(release) is source.ResidentLiveRelease, 'RELEASE_TYPE')
    snapshot = source.ResidentLiveSnapshot(capture.receipt, release, capture.utf8)
    text = source.validate_snapshot(snapshot, capture.request, command.target, now, previous_sequence=previous_sequence)
    del text
    return snapshot


def build_close_frame(metadata, *, binding, command, now, previous_sequence):
    """Encode supplied CLOSE_READY facts; never infer cleanup from a command."""
    _command(command, binding, now, previous_sequence)
    _need(command.opcode == CLOSE, 'CLOSE_OPCODE')
    _need(type(metadata) is dict and set(metadata) == CLOSE_KEYS, 'CLOSE_SCHEMA')
    frame = _frame(metadata, b'', command)
    parse_close_frame(frame, binding=binding, command=command, now=now, previous_sequence=previous_sequence)
    return frame


def parse_close_frame(frame, *, binding, command, now, previous_sequence):
    _command(command, binding, now, previous_sequence)
    _need(command.opcode == CLOSE, 'CLOSE_OPCODE')
    m, body = _unframe(frame, command, CLOSE_KEYS)
    _join_metadata_binding(m, binding)
    _need(m['kind'] == 'RESIDENT_LIVE_CLOSE_READY' and type(m['kind']) is str
          and type(m['version']) is int and m['version'] == VERSION
          and type(m['sequence']) is int and m['sequence'] == command.sequence
          and type(m['revision']) is int and m['revision'] == 0
          and type(m['request_id']) is str and m['request_id'] == command.request_id
          and type(m['last_read_sequence']) is int and m['last_read_sequence'] == previous_sequence, 'CLOSE_JOIN')
    _need(m['job_active'] is False and m['callback_quiesced'] is True and m['io_drained'] is True
          and all(type(m[key]) is int and m[key] == 0 for key in ('contexts_live', 'functions_live',
              'buffers_live', 'source_writes', 'configuration_saves', 'database_updates', 'repository_mutations')),
          'CLOSE_READY')
    return m
