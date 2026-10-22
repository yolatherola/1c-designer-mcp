"""Pure SAME_VERSION capture bookkeeping, separate from V3 READ/EDIT authority.

Root owns the private issuer and supplies physically verified observations.
Decoded mappings/text alone never mint a repository snapshot or task receipt.
Full32 statistic equality is an observation, not a lock generation or atomic CAS.
This module performs no I/O, native call, persistence, capture, cancel or setter.
"""
from dataclasses import dataclass, field
import hashlib
import json
import math
import struct
import uuid
from . import editor_command as command

POLICY = 'CAPTURE_OWN_SAME_VERSION'
FREE, OWN, FOREIGN = 0, 1, 2
MAX_AGE, MAX_TTL = 30., 600.
NIL_UUID = '00000000-0000-0000-0000-000000000000'


class CaptureRefusal(ValueError):
    """Fixed diagnostic without source, witness bytes or caller values."""

    @property
    def action(self):
        return 'REFRESH_REQUIRED' if str(self) == 'EDITOR_CAPTURE_REFRESH_REQUIRED' else 'REFUSE'


def need(ok, code):
    if not ok:
        raise CaptureRefusal('EDITOR_CAPTURE_'+code)


def _int(value, low=0, high=0xffffffff):
    return type(value) is int and low <= value <= high


def _finite(value):
    return type(value) in (int, float) and abs(value) <= 1e15 and math.isfinite(value)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _checked(value, kind, callback, code):
    ok = type(value) is kind
    if ok:
        try:
            callback()
        except command.EditorCommandRefusal:
            ok = False
    need(ok, code)


@dataclass(frozen=True, slots=True)
class OwnershipWitness:
    """Native statistic32: int32 version, revised byte, GUID bytes_le, date8.

    Padding/date remain opaque and participate in every full-witness join.
    No field is an address or a credential.
    """
    raw: bytes = field(repr=False)

    def validate(self):
        need(type(self.raw) is bytes and len(self.raw) == 32, 'WITNESS_SIZE')
        need(struct.unpack_from('<i', self.raw)[0] >= 0 and self.raw[4] in (0, 1), 'WITNESS_FIELDS')
        need((self.raw[4] == 0) == (self.raw[8:24] == bytes(16)), 'WITNESS_OWNER')

    @property
    def version(self):
        self.validate(); return struct.unpack_from('<i', self.raw)[0]

    @property
    def owner_uuid(self):
        self.validate(); return str(uuid.UUID(bytes_le=self.raw[8:24]))

    def owner_class(self, actor_uuid):
        self.validate(); need(command._uuid(actor_uuid), 'ACTOR')
        return FREE if self.owner_uuid == NIL_UUID else OWN if self.owner_uuid == actor_uuid else FOREIGN


@dataclass(frozen=True, slots=True)
class CaptureAuthority:
    """Trusted Root record; never construct from a decoded request or response."""
    binding: command.EditorBinding
    target: command.EditorTarget
    actor_uuid: str
    current_root_uuid: str  # Current UI configuration model; target is a separate object.
    issued_at: float
    valid_until: float
    allow_own_cancel: bool = False
    policy: str = POLICY

    def validate(self):
        _checked(self.binding, command.EditorBinding, lambda: self.binding.validate(), 'BINDING')
        _checked(self.target, command.EditorTarget, lambda: self.target.validate(), 'TARGET')
        need(command._uuid(self.actor_uuid) and type(self.current_root_uuid) is str
             and self.current_root_uuid == self.binding.root_uuid, 'AUTHORITY_ROOT_ACTOR')
        need(type(self.policy) is str and self.policy == POLICY and type(self.allow_own_cancel) is bool, 'AUTHORITY_POLICY')
        need(_finite(self.issued_at) and _finite(self.valid_until)
             and 0 <= self.issued_at < self.valid_until <= self.issued_at+MAX_TTL, 'AUTHORITY_TIME')


@dataclass(frozen=True, slots=True)
class RepositoryRead:
    """Root supplies the authoritative decoder result and two fresh statistics.

    requested_version is not a server echo/latest-version assertion. Root must
    bind the decoder's target and raw packet SHA to this exact admitted request.
    """
    binding: command.EditorBinding
    target: command.EditorTarget
    current_root_uuid: str
    actor_uuid: str
    requested_version: int
    packet_sha256: str
    resource_name: str
    packet_bytes: int
    packet_complete: bool
    text: command.ModuleText = field(repr=False)
    stat_before: OwnershipWitness = field(repr=False)
    stat_after: OwnershipWitness = field(repr=False)
    observed_at: float


@dataclass(frozen=True, slots=True)
class LiveObservation:
    binding: command.EditorBinding
    target: command.EditorTarget
    current_root_uuid: str
    actor_uuid: str
    source: command.ModuleText = field(repr=False)
    statistic: OwnershipWitness = field(repr=False)
    state22: tuple = field(repr=False)
    receiver_words: tuple = field(repr=False)  # Compare-only receiver/table observations.
    receiver_mode: int
    document_readonly: bool
    text_readonly: bool
    observed_at: float
    source_reads: int = 1
    state_reads: int = 1
    statistic_queries: int = 1
    document_readonly_reads: int = 1
    text_readonly_reads: int = 1


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    read: RepositoryRead = field(repr=False)
    _seal: object = field(repr=False)


@dataclass(frozen=True, slots=True)
class CaptureIntent:
    operation_id: str
    phase: str
    sequence: int
    nonce: str
    created_at: float
    metadata_sha256: str
    _metadata: bytes = field(repr=False)
    _seal: object = field(repr=False)

    def metadata(self):
        """Canonical ASCII JSON plus LF is hashed for Root's CreateNew/fsync."""
        need(type(self._metadata) is bytes and 0 < len(self._metadata) <= 8192
             and command._hex(self.metadata_sha256, 64) and _sha(self._metadata) == self.metadata_sha256,
             'INTENT_METADATA')
        row = None
        try:
            row = json.loads(self._metadata)
        except (ValueError, UnicodeError, RecursionError):
            pass
        need(type(row) is dict and row.get('operationId') == self.operation_id
             and row.get('phase') == self.phase and row.get('sequence') == self.sequence
             and row.get('nonce') == self.nonce and row.get('createdAt') == self.created_at, 'INTENT_METADATA')
        return row


@dataclass(frozen=True, slots=True)
class DurableIntent:
    """Root's private persistence observation; this module cannot prove fsync."""
    intent_sha256: str
    stored_sha256: str
    committed_at: float


@dataclass(frozen=True, slots=True)
class CaptureAttempt:
    intent: CaptureIntent
    started_at: float
    _seal: object = field(repr=False)


@dataclass(frozen=True, slots=True)
class NativeFacts:
    call_attempts: int
    call_returned: int
    mode_attempts: int
    mode_returned: int
    notification_attempts: int
    notification_returned: int
    result_target_uuid: str = ''
    result_map_counts: tuple = ()
    ambiguous: bool = False
    sdk_result: int = 0
    abi_fault: int = 0
    cpp_events: int = 0
    other_exceptions: int = 0
    source_writes: int = 0
    configuration_saves: int = 0
    database_updates: int = 0
    repository_placements: int = 0
    retained_handles: int | None = None


@dataclass(frozen=True, slots=True)
class NativeCompletion:
    after: LiveObservation = field(repr=False)
    facts: NativeFacts


@dataclass(frozen=True, slots=True)
class CaptureReceipt:
    """Observed OWN/editability only; not proof that this task acquired a lock."""
    intent: CaptureIntent
    version: int
    actor_uuid: str
    witness_sha256: str
    source_sha256: str
    retained_handles: int | None
    _before: LiveObservation = field(repr=False)
    _after: LiveObservation = field(repr=False)
    _seal: object = field(repr=False)

    @property
    def native_lifetime_verified(self):
        return False

    @property
    def runtime_persistence_supported(self):
        return False

    @property
    def acquisition_proven(self):
        return False

    @property
    def cancel_authorized(self):
        return False

    @property
    def status(self):
        return 'OWN_OBSERVED_FRESH_READ_ONLY'


class CaptureOwner:
    """One Root-owned capture attempt and an observed editability receipt.

    Methods return bookkeeping tokens, never native commands/EditCapability.
    After a begun operation every invalid/ambiguous completion retains UNKNOWN.
    Root separately owns native handle lifetime and fresh physical admission.
    Current native primitives do not prove new acquisition/cancellation rights
    or receiver lifetime across callbacks. Cancellation therefore stays blocked.
    """
    __slots__ = ('_authority', '_issuer', '_seal', '_phase', '_repository', '_before', '_intent',
                 '_attempt', '_receipt', '_sequence', '_nonces')

    def __init__(self, authority, *, issuer):
        need(type(authority) is CaptureAuthority and type(issuer) is object, 'OWNER_AUTHORITY')
        authority.validate()
        self._authority, self._issuer, self._seal = authority, issuer, object()
        self._phase, self._repository, self._before = 'NEW', None, None
        self._intent = self._attempt = self._receipt = None
        self._sequence, self._nonces = 0, set()

    @property
    def phase(self):
        return self._phase

    def _auth(self, issuer, now):
        need(issuer is self._issuer, 'ISSUER')
        self._authority.validate()
        need(_finite(now) and self._authority.issued_at <= now <= self._authority.valid_until, 'TIME')

    def _join(self, value, now):
        authority = self._authority
        _checked(value.binding, command.EditorBinding, lambda: value.binding.validate(), 'BINDING')
        _checked(value.target, command.EditorTarget, lambda: value.target.validate(), 'TARGET')
        need(type(value.binding) is command.EditorBinding and value.binding == authority.binding
             and type(value.target) is command.EditorTarget and value.target == authority.target
             and type(value.current_root_uuid) is str and value.current_root_uuid == authority.current_root_uuid
             and type(value.actor_uuid) is str and value.actor_uuid == authority.actor_uuid, 'SUBJECT_JOIN')
        need(_finite(value.observed_at) and authority.issued_at <= value.observed_at <= now
             <= value.observed_at+MAX_AGE, 'OBSERVATION_TIME')

    def _live(self, value, now):
        need(type(value) is LiveObservation, 'LIVE_TYPE'); self._join(value, now)
        _checked(value.source, command.ModuleText, lambda: value.source.validate(), 'SOURCE')
        need(type(value.statistic) is OwnershipWitness, 'WITNESS_TYPE'); value.statistic.validate()
        _checked(value.state22, tuple, lambda: command._state(value.state22), 'STATE')
        # Root/UI/object/document dirtiness blocks this strict initial capture,
        # even when the module text itself still matches the repository bytes.
        need(not any(value.state22[i] for i in (8, 9, 10, 11, 19, 20))
             and value.state22[21] == 0xffffffff, 'DIRTY_HISTORY')
        need(type(value.document_readonly) is bool and type(value.text_readonly) is bool
             and value.state22[12] == int(value.document_readonly), 'READONLY')
        need(type(value.receiver_words) is tuple and len(value.receiver_words) == 2
             and all(_int(v, 65536) for v in value.receiver_words)
             and _int(value.receiver_mode, 1, 2), 'RECEIVER')
        need(all(_int(getattr(value, name), 1, 2) for name in ('source_reads', 'state_reads', 'statistic_queries'))
             and type(value.document_readonly_reads) is int and value.document_readonly_reads == 1
             and type(value.text_readonly_reads) is int and value.text_readonly_reads == 1, 'OBSERVATION_CALLS')

    def admit_repository(self, read, *, issuer, now):
        self._auth(issuer, now); need(self._phase == 'NEW' and self._repository is None, 'REPOSITORY_ONCE')
        need(type(read) is RepositoryRead, 'REPOSITORY_TYPE'); self._join(read, now)
        _checked(read.text, command.ModuleText, lambda: read.text.validate(), 'REPOSITORY_SOURCE')
        need(_int(read.requested_version, 1, 0x7fffffff) and command._hex(read.packet_sha256, 64), 'REPOSITORY_VERSION_PACKET')
        need(type(read.resource_name) is str and read.resource_name == self._authority.target.object_uuid+'.0'
             and _int(read.packet_bytes, 1, 1048576) and read.packet_complete is True, 'REPOSITORY_COMPLETE_RESOURCE')
        need(type(read.stat_before) is OwnershipWitness and type(read.stat_after) is OwnershipWitness, 'WITNESS_TYPE')
        read.stat_before.validate(); read.stat_after.validate()
        need(read.stat_before.raw == read.stat_after.raw, 'REPOSITORY_STAT_DRIFT')
        need(read.stat_before.version == read.requested_version, 'REFRESH_REQUIRED')
        need(read.stat_before.owner_class(read.actor_uuid) == FREE, 'REQUIRES_FREE')
        self._repository = RepositorySnapshot(read, self._seal)
        return self._repository

    def _new_intent(self, phase, sequence, nonce, live, now):
        need(_int(sequence, 1, 64) and sequence == self._sequence+1 and command._hex(nonce, 32)
             and nonce not in self._nonces, 'SEQUENCE_NONCE')
        row = dict(kind='EDITOR_CAPTURE_INTENT', policy=POLICY, phase=phase,
            operationId=self._authority.binding.operation_id, scopeSha256=self._authority.binding.scope_sha256,
            objectUuid=self._authority.target.object_uuid, classUuid=self._authority.target.class_uuid,
            propertyUuid=self._authority.target.property_uuid, actorUuid=self._authority.actor_uuid,
            sequence=sequence, nonce=nonce, createdAt=now, version=live.statistic.version,
            sourceSha256=live.source.sha256, repositoryPacketSha256=self._repository.read.packet_sha256,
            witnessSha256=_sha(live.statistic.raw), stateSha256=_sha(struct.pack('<22I', *live.state22)))
        raw = json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')+b'\n'
        self._intent = CaptureIntent(row['operationId'], phase, sequence, nonce, now, _sha(raw), raw, self._seal)
        self._sequence = sequence; self._nonces.add(nonce)
        return self._intent

    def prepare(self, live, repository, sequence, nonce, *, issuer, now):
        self._auth(issuer, now); need(self._phase == 'NEW', 'PHASE')
        need(type(repository) is RepositorySnapshot and repository is self._repository and repository._seal is self._seal,
             'PRIVATE_REPOSITORY')
        self._live(live, now); self._join(repository.read, now)
        need(live.statistic.version == repository.read.requested_version, 'REFRESH_REQUIRED')
        need(live.statistic.raw == repository.read.stat_after.raw and live.statistic.owner_class(live.actor_uuid) == FREE,
             'FREE_WITNESS_JOIN')
        need(live.source.utf8 == repository.read.text.utf8 and live.source.sha256 == repository.read.text.sha256, 'REFRESH_REQUIRED')
        need(live.receiver_mode == 1, 'ORIGINAL_RECEIVER_MODE')
        intent = self._new_intent('CAPTURE', sequence, nonce, live, now)
        self._before, self._phase = live, 'CAPTURE_PREPARED'
        return intent

    def _begin(self, intent, durable, phase, issuer, now):
        self._auth(issuer, now); need(self._phase == phase+'_PREPARED', 'PHASE')
        need(type(intent) is CaptureIntent and intent is self._intent and intent._seal is self._seal, 'PRIVATE_INTENT')
        need(type(durable) is DurableIntent and type(durable.intent_sha256) is str
             and type(durable.stored_sha256) is str
             and durable.intent_sha256 == durable.stored_sha256 == intent.metadata_sha256
             and _finite(durable.committed_at) and intent.created_at <= durable.committed_at <= now
             <= intent.created_at+MAX_AGE, 'DURABLE_INTENT')
        self._phase = phase+'_PENDING'; self._attempt = CaptureAttempt(intent, now, self._seal)
        return self._attempt

    def begin_capture(self, intent, durable, *, issuer, now):
        return self._begin(intent, durable, 'CAPTURE', issuer, now)

    def _completion(self, attempt, result, phase, issuer, now):
        need(issuer is self._issuer, 'ISSUER')
        need(self._phase == phase+'_PENDING', 'PHASE')
        try:
            self._auth(issuer, now)
            need(type(attempt) is CaptureAttempt and attempt is self._attempt and attempt._seal is self._seal, 'PRIVATE_ATTEMPT')
            need(type(result) is NativeCompletion and type(result.facts) is NativeFacts, 'COMPLETION_TYPE')
            facts = result.facts
            need(type(facts.ambiguous) is bool and facts.ambiguous is False, 'AMBIGUOUS')
            need(type(facts.result_target_uuid) is str and facts.result_target_uuid == self._authority.target.object_uuid
                 and type(facts.result_map_counts) is tuple and len(facts.result_map_counts) == 6
                 and all(type(v) is int for v in facts.result_map_counts)
                 and facts.result_map_counts == (1, 0, 0, 0, 0, 0), 'RPC_RESPONSE_SCOPE')
            need(all(type(getattr(facts, name)) is int and getattr(facts, name) == 1 for name in
                ('call_attempts', 'call_returned', 'mode_attempts', 'mode_returned', 'notification_attempts', 'notification_returned')),
                'NATIVE_CALLS')
            need(all(type(getattr(facts, name)) is int and getattr(facts, name) == 0 for name in
                ('sdk_result', 'abi_fault', 'cpp_events', 'other_exceptions', 'source_writes',
                 'configuration_saves', 'database_updates', 'repository_placements')), 'NATIVE_FAILURE_WRITES')
            need(facts.retained_handles is None or _int(facts.retained_handles, 0, 64), 'RETAINED_HANDLES')
            self._live(result.after, now)
            need(result.after.observed_at >= attempt.started_at, 'COMPLETION_TIME')
            return result.after, facts
        except Exception:
            self._phase = 'UNKNOWN'
            raise

    def complete_capture(self, attempt, result, *, issuer, now):
        after, facts = self._completion(attempt, result, 'CAPTURE', issuer, now)
        try:
            before = self._before
            need(after.statistic.owner_class(after.actor_uuid) == OWN and after.statistic.version == before.statistic.version,
                 'CAPTURE_OWN_VERSION')
            need(after.receiver_words == before.receiver_words and after.receiver_mode == 2
                 and after.document_readonly is False and after.text_readonly is False, 'CAPTURE_WRITABLE')
            need(all(after.state22[i] == before.state22[i] for i in range(22) if i != 12)
                 and after.source.utf8 == before.source.utf8, 'CAPTURE_SOURCE_STATE')
            receipt = CaptureReceipt(self._intent, after.statistic.version, after.actor_uuid, _sha(after.statistic.raw),
                after.source.sha256, facts.retained_handles, before, after, self._seal)
            self._receipt, self._phase = receipt, 'OWN_OBSERVED'
            return receipt
        except Exception:
            self._phase = 'UNKNOWN'; raise

    def require_fresh_read(self, receipt, *, issuer, now):
        """Validate only this task receipt; never return an editor write capability."""
        self._auth(issuer, now)
        need(self._phase == 'OWN_OBSERVED' and type(receipt) is CaptureReceipt and receipt is self._receipt
             and receipt._seal is self._seal, 'PRIVATE_RECEIPT')
        return receipt

    def prepare_cancel(self, receipt, current, sequence, nonce, *, issuer, now):
        """Check task/witness joins, then refuse: native acquisition is unproved.

        No cancellation intent/token can be issued by the current contract.
        This gate deliberately has no Root-supplied boolean/proof override.
        """
        self.require_fresh_read(receipt, issuer=issuer, now=now)
        need(self._authority.allow_own_cancel is True, 'CANCEL_PERMISSION')
        self._live(current, now)
        need(current.statistic.raw == receipt._after.statistic.raw and current.statistic.owner_class(current.actor_uuid) == OWN,
             'CANCEL_FULL_WITNESS')
        need(current.receiver_words == receipt._after.receiver_words and current.receiver_mode == 2
             and current.document_readonly is False and current.text_readonly is False
             and current.state22 == receipt._after.state22 and current.source.utf8 == receipt._after.source.utf8,
             'CANCEL_SOURCE_STATE')
        need(_int(sequence, 1, 64) and sequence == self._sequence+1 and command._hex(nonce, 32)
             and nonce not in self._nonces, 'SEQUENCE_NONCE')
        # A successful Ex141 response and same-account OWN are not evidence of
        # a new acquisition by this task. No fabricated Root proof bypass exists.
        need(receipt.cancel_authorized, 'CANCEL_ACQUISITION_NOT_PROVEN')

    def mark_unknown(self, attempt, *, issuer):
        need(issuer is self._issuer, 'ISSUER')
        need(self._phase == 'CAPTURE_PENDING' and attempt is self._attempt, 'PRIVATE_ATTEMPT')
        self._phase = 'UNKNOWN'
