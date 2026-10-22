"""Pure resident LIVE capture contract; no native attestation or saved fallback.

An approved physical producer supplies the facts and the caller supplies the
expected job and last accepted sequence. This module checks their joins only.
Installation lifetime is distinct from closure of one READ's SDK/RAM resources.
"""
from dataclasses import dataclass, field
import hashlib
import math
import re

SOURCE_DOMAIN = 'editor_live_at_capture'
ROOT_UUID = '218b5d00-7e10-486f-874c-73c2368ed5da'
CLASS_UUID = '0fe48980-252d-11d6-a3c7-0050bae0a776'
PROPERTY_UUID = 'd5963243-262e-4398-b4d7-fb16d06484f6'
MAX_UTF16_UNITS = 131072
MAX_BYTES = 524288
MAX_SEQUENCE = 64
MAX_INSTALLATION_TTL = 600.0
MAX_TTL = 60.0


class ResidentLiveRefusal(ValueError):
    """Fixed body-free failure code; never includes an input or source text."""


def _need(ok, code):
    if not ok:
        raise ResidentLiveRefusal('RESIDENT_LIVE_' + code)


def _int(value, low, high):
    return type(value) is int and low <= value <= high


def _finite(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _hex(value, size):
    return (type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None
            and value != '0'*size)


def _uuid(value):
    return (type(value) is str and re.fullmatch(
        '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value) is not None
        and value != '00000000-0000-0000-0000-000000000000')


@dataclass(frozen=True, slots=True)
class ResidentLiveBinding:
    root_uuid: str
    process_id: int
    birth: str
    operation_id: str
    scope_sha256: str
    reader_source_sha256: str
    compiled_source_sha256: str
    installed_at: float
    valid_until: float
    source_domain: str = SOURCE_DOMAIN

    def validate(self):
        _need(type(self.root_uuid) is str and self.root_uuid == ROOT_UUID, 'ROOT')
        _need(_int(self.process_id, 1, 2**32-1) and _hex(self.birth, 16), 'PROCESS')
        _need(_hex(self.operation_id, 32) and _hex(self.scope_sha256, 64)
              and _hex(self.reader_source_sha256, 64) and _hex(self.compiled_source_sha256, 64), 'SOURCE_BINDING')
        _need(type(self.source_domain) is str and self.source_domain == SOURCE_DOMAIN, 'DOMAIN')
        _need(_finite(self.installed_at) and _finite(self.valid_until) and 0 <= self.installed_at
              < self.valid_until <= self.installed_at+MAX_INSTALLATION_TTL, 'INSTALLATION_EXPIRY')


@dataclass(frozen=True, slots=True)
class ResidentLiveTarget:
    object_uuid: str
    property_uuid: str

    def validate(self):
        # A UUID alone never proves class membership; the capture joins it below.
        _need(_uuid(self.object_uuid) and type(self.property_uuid) is str
              and self.property_uuid == PROPERTY_UUID, 'TARGET')


@dataclass(frozen=True, slots=True)
class ResidentLiveReadRequest:
    binding: ResidentLiveBinding
    target: ResidentLiveTarget
    sequence: int
    request_id: str
    revision: int
    issued_at: float
    valid_until: float


@dataclass(frozen=True, slots=True)
class ResidentLiveReceipt:
    binding: ResidentLiveBinding
    target: ResidentLiveTarget
    sequence: int
    request_id: str
    revision: int
    native_root_uuid: str
    native_class_uuid: str
    native_object_uuid: str
    native_property_uuid: str
    sampled_at: float
    valid_until: float
    byte_count: int
    source_sha256: str
    utf16_units: int
    bom_present: bool
    crlf_count: int
    ends_lf: bool
    before_state: tuple
    after_state: tuple
    whole_sdk_cpp_throws: int
    whole_sdk_other_exceptions: int
    sdk_result: int
    abi_fault: int
    contexts_created: int
    contexts_released: int
    functions_created: int
    functions_released: int
    context_release_returned: bool
    function_release_returned: bool
    typed_handles_cleared: bool
    read_equality_verified: bool
    direct_save_calls: int
    state_bridge_calls: int
    warmup_reads: int
    helper_text_reads: int
    source_writes: int
    configuration_saves: int
    database_updates: int
    repository_mutations: int


@dataclass(frozen=True, slots=True)
class ResidentLiveRelease:
    binding: ResidentLiveBinding
    target: ResidentLiveTarget
    sequence: int
    request_id: str
    revision: int
    source_sha256: str
    released_at: float
    status: str
    ack_accepted: bool
    borrow_returned: bool
    buffers_freed: bool
    io_drained: bool
    context_closed: bool
    function_closed: bool
    callback_quiesced: bool


@dataclass(frozen=True, slots=True)
class ResidentLiveSnapshot:
    receipt: ResidentLiveReceipt
    release: ResidentLiveRelease
    utf8: bytes = field(repr=False, compare=False)


def _job_join(value, request):
    _need(type(value.binding) is ResidentLiveBinding and type(value.target) is ResidentLiveTarget, 'JOB_TYPE')
    value.binding.validate(); value.target.validate()
    _need(value.binding == request.binding and value.target == request.target
          and _int(value.sequence, 1, MAX_SEQUENCE) and value.sequence == request.sequence
          and _hex(value.request_id, 32) and value.request_id == request.request_id
          and _int(value.revision, 1, 2**32-1) and value.revision == request.revision, 'JOB_JOIN')


def _state(before, after):
    _need(type(before) is tuple and type(after) is tuple and len(before) == len(after) == 22
          and all(_int(x, 0, 2**32-1) for x in before+after) and before == after, 'STATE_EQUALITY')
    _need(all(_int(x, 65536, 2**32-1) for x in before[:8])
          and all(before[i] in (0, 1) for i in (8, 9, 10, 11, 12, 19, 20))
          and (before[20] == 1 or before[21] == 0xFFFFFFFF), 'STATE_SHAPE')


def validate_snapshot(snapshot, expected_request, current_target, now, *, previous_sequence):
    """Return transient text only after capture and POST-ACK job closure joins.

    previous_sequence is trusted caller state, not an attested fact or a mutable
    module-global replay registry. Accepting a job must advance it atomically in
    the future provider. Current target means intended target, not a native read.
    """
    _need(type(expected_request) is ResidentLiveReadRequest
          and type(expected_request.binding) is ResidentLiveBinding
          and type(expected_request.target) is ResidentLiveTarget
          and type(current_target) is ResidentLiveTarget, 'REQUEST')
    request = expected_request
    request.binding.validate(); request.target.validate(); current_target.validate()
    _need(current_target == request.target and _hex(request.request_id, 32)
          and _int(request.revision, 1, 2**32-1), 'REQUEST_IDENTITY')
    _need(_int(previous_sequence, 0, MAX_SEQUENCE-1) and _int(request.sequence, 1, MAX_SEQUENCE)
          and request.sequence == previous_sequence+1, 'SEQUENCE')
    _need(_finite(request.issued_at) and _finite(request.valid_until)
          and request.binding.installed_at <= request.issued_at < request.valid_until
          <= min(request.binding.valid_until, request.issued_at+MAX_TTL), 'REQUEST_EXPIRY')
    _need(type(snapshot) is ResidentLiveSnapshot and type(snapshot.receipt) is ResidentLiveReceipt
          and type(snapshot.release) is ResidentLiveRelease and type(snapshot.utf8) is bytes, 'SNAPSHOT')
    receipt, release = snapshot.receipt, snapshot.release
    _job_join(receipt, request); _job_join(release, request)
    _need(type(receipt.native_root_uuid) is str and receipt.native_root_uuid == request.binding.root_uuid
          and type(receipt.native_class_uuid) is str and receipt.native_class_uuid == CLASS_UUID
          and type(receipt.native_object_uuid) is str and receipt.native_object_uuid == request.target.object_uuid
          and type(receipt.native_property_uuid) is str
          and receipt.native_property_uuid == request.target.property_uuid, 'NATIVE_BINDING')
    _need(_finite(now) and _finite(receipt.sampled_at) and _finite(receipt.valid_until)
          and _finite(release.released_at) and request.issued_at <= receipt.sampled_at <= release.released_at
          <= now <= receipt.valid_until <= request.valid_until, 'CAPTURE_EXPIRY')
    body = snapshot.utf8
    _need(_int(receipt.byte_count, 0, MAX_BYTES) and receipt.byte_count == len(body)
          and _hex(receipt.source_sha256, 64) and hashlib.sha256(body).hexdigest() == receipt.source_sha256
          and _hex(release.source_sha256, 64) and release.source_sha256 == receipt.source_sha256, 'BODY_HASH')
    _need(type(receipt.bom_present) is bool and receipt.bom_present == body.startswith(b'\xef\xbb\xbf')
          and _int(receipt.crlf_count, 0, MAX_UTF16_UNITS) and receipt.crlf_count == body.count(b'\r\n')
          and type(receipt.ends_lf) is bool and receipt.ends_lf == body.endswith(b'\n'), 'BYTE_SHAPE')
    _state(receipt.before_state, receipt.after_state)
    _need(all(type(getattr(receipt, key)) is bool and getattr(receipt, key) is True for key in
              ('context_release_returned', 'function_release_returned', 'typed_handles_cleared',
               'read_equality_verified')), 'SDK_CLOSURE')
    counts = dict(whole_sdk_cpp_throws=0, whole_sdk_other_exceptions=0, sdk_result=0, abi_fault=0,
                  contexts_created=1, contexts_released=1, functions_created=1, functions_released=1,
                  direct_save_calls=2, state_bridge_calls=2, warmup_reads=1, helper_text_reads=0,
                  source_writes=0, configuration_saves=0, database_updates=0, repository_mutations=0)
    _need(all(type(getattr(receipt, key)) is int and getattr(receipt, key) == value
              for key, value in counts.items()), 'EVIDENCE_COUNTS')
    _need(type(release.status) is str and release.status == 'JOB_RELEASED'
          and all(type(getattr(release, key)) is bool and getattr(release, key) is True for key in
                  ('ack_accepted', 'borrow_returned', 'buffers_freed', 'io_drained', 'context_closed',
                   'function_closed', 'callback_quiesced')), 'POST_ACK_CLOSURE')
    # Raise outside the decoder's except block: even exception context must not
    # retain UnicodeDecodeError.object (the source bytes).
    text = None
    try:
        text = body.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        pass
    _need(text is not None, 'UTF8')
    _need('\x00' not in text and _int(receipt.utf16_units, 0, MAX_UTF16_UNITS)
          and len(text.encode('utf-16-le', 'strict'))//2 == receipt.utf16_units, 'UTF16_BOUND')
    return text


def metadata(snapshot, expected_request, current_target, now, *, previous_sequence):
    """Return validated body-free metadata; the installation is still resident."""
    text = validate_snapshot(snapshot, expected_request, current_target, now, previous_sequence=previous_sequence)
    del text
    r = snapshot.receipt
    return dict(source_domain=SOURCE_DOMAIN, capture_id=r.request_id, capture_version=r.revision,
        sequence=r.sequence, operation_id=r.binding.operation_id, scope_sha256=r.binding.scope_sha256,
        root_uuid=r.binding.root_uuid, class_uuid=r.native_class_uuid, object_uuid=r.target.object_uuid,
        property_uuid=r.target.property_uuid, process_id=r.binding.process_id, birth=r.binding.birth,
        reader_source_sha256=r.binding.reader_source_sha256, compiled_source_sha256=r.binding.compiled_source_sha256,
        installed_at=r.binding.installed_at, installation_valid_until=r.binding.valid_until,
        captured_at=r.sampled_at, released_at=snapshot.release.released_at, valid_until=r.valid_until,
        source_sha256=r.source_sha256, byte_count=r.byte_count, utf16_units=r.utf16_units,
        bom_present=r.bom_present, crlf_count=r.crlf_count, ends_lf=r.ends_lf,
        document_modified_at_capture=bool(r.before_state[11]), document_readonly_at_capture=bool(r.before_state[12]),
        text_manager_modified_at_capture=bool(r.before_state[19]), undo_available_at_capture=bool(r.before_state[20]),
        capture_read_verified=True, state_preservation_verified=True, job_resources_closed=True,
        installation_remains_resident=True, installation_closed_verified=False,
        current_editor_unchanged_verified=False, native_attestation_performed=False,
        writer_authorized=False, retry_authorized=False, source_body_included=False)
