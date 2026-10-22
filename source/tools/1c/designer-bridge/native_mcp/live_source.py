"""Immutable captured-editor source contract; bytes stay in caller-owned RAM.

The trusted producer must physically establish the evidence. This pure validator
binds one snapshot to its expected request; it performs no native attestation,
I/O, current-editor check, saved-source fallback, or writer authorization.
"""
from dataclasses import dataclass, field
import hashlib
import math
import re

SOURCE_DOMAIN = 'editor_live_at_capture'
ROOT_UUID = '218b5d00-7e10-486f-874c-73c2368ed5da'
OBJECT_UUID = '176e2552-fd8b-4823-afc0-d17431f2fb7b'
PROPERTY_UUID = 'd5963243-262e-4398-b4d7-fb16d06484f6'
MAX_UTF16_UNITS = 131072
MAX_UTF8_BYTES = MAX_UTF16_UNITS * 4
MAX_BYTES = MAX_UTF8_BYTES  # Public parser bound; no truncation to the old262k limit.
MAX_TTL = 60.0


class LiveRefusal(ValueError):
    """Stable metadata-only failure; never includes a body or caller value."""


def need(ok, code):
    if not ok:
        raise LiveRefusal('LIVE_' + code)


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def finite(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _hex(value, size):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None and value != '0'*size


@dataclass(frozen=True, slots=True)
class LiveBinding:
    root_uuid: str
    process_id: int
    birth: str
    operation_id: str
    scope_sha256: str
    valid_until: float
    source_domain: str = SOURCE_DOMAIN

    def validate(self):
        need(type(self.root_uuid) is str and self.root_uuid == ROOT_UUID, 'ROOT')
        need(integer(self.process_id, 1, 2**32-1) and _hex(self.birth, 16), 'PROCESS')
        need(_hex(self.operation_id, 32) and _hex(self.scope_sha256, 64), 'SCOPE')
        need(type(self.source_domain) is str and self.source_domain == SOURCE_DOMAIN, 'DOMAIN')
        need(finite(self.valid_until) and self.valid_until > 0, 'BINDING_EXPIRY')


@dataclass(frozen=True, slots=True)
class LiveTarget:
    object_uuid: str
    property_uuid: str

    def validate(self):
        # Initial production capability is one CommonModule, not arbitrary BSL.
        need(type(self.object_uuid) is str and self.object_uuid == OBJECT_UUID
             and type(self.property_uuid) is str and self.property_uuid == PROPERTY_UUID, 'TARGET')


@dataclass(frozen=True, slots=True)
class LiveReadRequest:
    binding: LiveBinding
    target: LiveTarget
    request_id: str
    revision: int
    issued_at: float
    valid_until: float


@dataclass(frozen=True, slots=True)
class LiveReceipt:
    binding: LiveBinding
    target: LiveTarget
    request_id: str
    revision: int
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
    context_release_returned: bool
    function_release_returned: bool
    typed_handles_cleared: bool
    read_equality_verified: bool
    direct_save_calls: int = 2
    state_bridge_calls: int = 2
    warmup_reads: int = 1
    helper_text_reads: int = 0
    source_writes: int = 0
    configuration_saves: int = 0
    database_updates: int = 0
    repository_mutations: int = 0


@dataclass(frozen=True, slots=True)
class LiveSnapshot:
    receipt: LiveReceipt
    utf8: bytes = field(repr=False, compare=False)


def _state(before, after):
    need(type(before) is tuple and type(after) is tuple and len(before) == len(after) == 22
         and all(integer(x, 0, 2**32-1) for x in before+after) and before == after, 'STATE_EQUALITY')
    need(all(integer(x, 65536, 2**32-1) for x in before[:8])
         and all(before[i] in (0, 1) for i in (8, 9, 10, 11, 12, 19, 20))
         and (before[20] == 1 or before[21] == 0xFFFFFFFF), 'STATE_SHAPE')


def validate_snapshot(snapshot, expected_request, current_target, now):
    """Return transient text after strict request, byte and evidence validation.

    current_target is the caller's intended target, not a current native query.
    Dirty/read-only/Undo observations may have either value when preserved.
    Expiry bounds use host monotonic time; they do not prove no later edit.
    """
    need(type(expected_request) is LiveReadRequest and type(expected_request.binding) is LiveBinding
         and type(expected_request.target) is LiveTarget and type(current_target) is LiveTarget, 'REQUEST')
    request = expected_request
    request.binding.validate();request.target.validate();current_target.validate()
    need(current_target == request.target and _hex(request.request_id, 32)
         and integer(request.revision, 1, 2**53-1), 'REQUEST_IDENTITY')
    need(finite(request.issued_at) and finite(request.valid_until) and 0 <= request.issued_at
         <= request.valid_until <= min(request.binding.valid_until, request.issued_at+MAX_TTL), 'REQUEST_EXPIRY')
    need(type(snapshot) is LiveSnapshot and type(snapshot.receipt) is LiveReceipt
         and type(snapshot.utf8) is bytes, 'SNAPSHOT')
    receipt = snapshot.receipt
    need(type(receipt.binding) is LiveBinding and type(receipt.target) is LiveTarget, 'RECEIPT_TYPE')
    receipt.binding.validate();receipt.target.validate()
    need(receipt.binding == request.binding and receipt.target == request.target
         and _hex(receipt.request_id, 32) and receipt.request_id == request.request_id
         and integer(receipt.revision, 1, 2**53-1) and receipt.revision == request.revision, 'RECEIPT_JOIN')
    need(finite(now) and finite(receipt.sampled_at) and finite(receipt.valid_until)
         and request.issued_at <= receipt.sampled_at <= now <= receipt.valid_until
         <= request.valid_until, 'RECEIPT_EXPIRY')
    body = snapshot.utf8
    need(integer(receipt.byte_count, 0, MAX_UTF8_BYTES) and receipt.byte_count == len(body)
         and _hex(receipt.source_sha256, 64)
         and hashlib.sha256(body).hexdigest() == receipt.source_sha256, 'BODY_HASH')
    need(type(receipt.bom_present) is bool and receipt.bom_present == body.startswith(b'\xef\xbb\xbf')
         and integer(receipt.crlf_count, 0, MAX_UTF16_UNITS) and receipt.crlf_count == body.count(b'\r\n')
         and type(receipt.ends_lf) is bool and receipt.ends_lf == body.endswith(b'\n'), 'BYTE_SHAPE')
    _state(receipt.before_state, receipt.after_state)
    need(all(type(getattr(receipt, key)) is bool and getattr(receipt, key) is True for key in
             ('context_release_returned', 'function_release_returned', 'typed_handles_cleared', 'read_equality_verified')),
         'READ_CLOSURE')
    counts = dict(whole_sdk_cpp_throws=0, whole_sdk_other_exceptions=0, sdk_result=0, abi_fault=0,
                  direct_save_calls=2, state_bridge_calls=2, warmup_reads=1, helper_text_reads=0,
                  source_writes=0, configuration_saves=0, database_updates=0, repository_mutations=0)
    need(all(type(getattr(receipt, key)) is int and getattr(receipt, key) == value
             for key, value in counts.items()), 'EVIDENCE_COUNTS')
    try:
        text = body.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        raise LiveRefusal('LIVE_UTF8') from None
    need('\x00' not in text and integer(receipt.utf16_units, 0, MAX_UTF16_UNITS)
         and len(text.encode('utf-16-le', 'strict'))//2 == receipt.utf16_units, 'UTF16_BOUND')
    return text


def metadata(snapshot, expected_request, current_target, now):
    """Return only validated capture metadata; never return or retain text."""
    text = validate_snapshot(snapshot, expected_request, current_target, now)
    del text
    receipt = snapshot.receipt
    return dict(source_domain=SOURCE_DOMAIN, source_view=SOURCE_DOMAIN, capture_id=receipt.request_id,
        capture_version=receipt.revision, captured_at=receipt.sampled_at, valid_until=receipt.valid_until,
        object_uuid=receipt.target.object_uuid, property_uuid=receipt.target.property_uuid,
        root_uuid=receipt.binding.root_uuid, process_id=receipt.binding.process_id, birth=receipt.binding.birth,
        operation_id=receipt.binding.operation_id, scope_sha256=receipt.binding.scope_sha256,
        source_sha256=receipt.source_sha256, byte_count=receipt.byte_count, utf16_units=receipt.utf16_units,
        bom_present=receipt.bom_present, crlf_count=receipt.crlf_count, ends_lf=receipt.ends_lf,
        document_modified_at_capture=bool(receipt.before_state[11]),
        document_readonly_at_capture=bool(receipt.before_state[12]),
        text_manager_modified_at_capture=bool(receipt.before_state[19]),
        undo_available_at_capture=bool(receipt.before_state[20]),
        capture_read_verified=True, state_preservation_verified=True,
        current_editor_unchanged_verified=False, native_attestation_performed=False,
        writer_authorized=False, source_body_included=False)
