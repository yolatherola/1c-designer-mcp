"""Bodyless OWN activation facts, joined to a separately trusted admission.

The prior capture receipt is not accepted from response JSON. It remains in
the Root-issued capability, including during ACK/release and total accounting.
An activation result never grants source editing or repository authority.
"""
from dataclasses import dataclass, field, make_dataclass
import struct
import uuid

from . import editor_command as codec
from . import editor_transport as wire

FACT_KEYS = tuple(('scope_admitted own_verified activation_verified baseline_compared '
    'state_compared readback_compared reason native_pending durable_intent_verified '
    'mode_attempts mode_returned event_attempts event_returned cleanup_complete unknown '
    'intent_mode_used stat_before_valid stat_after_valid event_cas_verified').split())
ActivationFacts = make_dataclass('ActivationFacts', [(name, int) for name in FACT_KEYS],
    frozen=True, slots=True, namespace={'__module__': __name__})
# These are the existing native adapter roles. Selection, cloning, repository
# revise and all factory/constructor routes are forbidden for this command.
ROLE_MAX = (0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 5, 5, 1, 2, 1)
VALUE_KEYS = tuple(('issued_at sampled_at valid_until status body_sha256 actor_uuid '
    'before_owner_uuid before_owner_class before_version after_owner_uuid after_owner_class '
    'after_version stat_before stat_after before_state after_state').split())
KEYS = frozenset(('kind', 'version', *wire.BINDING_KEYS, *wire.REQUEST_KEYS,
    *wire.TARGET_KEYS, *VALUE_KEYS, 'body_kind', 'byte_count', 'activation',
    'native_attempts', 'native_returned', 'job', 'closure'))


@dataclass(frozen=True, slots=True)
class EditorActivationOutcome:
    installation: wire.EditorInstallation
    command: codec.EditorCommand
    capability: object = field(repr=False)
    issued_at: float
    sampled_at: float
    valid_until: float
    status: str
    body_sha256: str
    actor_uuid: str
    before_owner_uuid: str
    before_owner_class: int
    before_version: int
    after_owner_uuid: str
    after_owner_class: int
    after_version: int
    stat_before: bytes = field(repr=False)
    stat_after: bytes = field(repr=False)
    before_state: tuple = field(repr=False)
    after_state: tuple = field(repr=False)
    activation: ActivationFacts
    native_attempts: tuple
    native_returned: tuple
    job: wire.EditorJobFacts
    closure: wire.EditorClosureFacts

    @property
    def binding(self): return self.installation.binding

    @property
    def target(self): return self.command.target

    @property
    def activation_verified(self): return self.activation.activation_verified == 1

    @property
    def refresh_verified(self): return False

    @property
    def edit_authorized(self): return False

    @property
    def cancel_authorized(self): return False

    @property
    def acquisition_proven(self): return False


@dataclass(frozen=True, slots=True)
class EditorActivationSnapshot:
    capture: EditorActivationOutcome
    release: wire.EditorRelease


def _facts(outcome):
    f = outcome.activation
    wire._need(type(f) is ActivationFacts, 'ACTIVATION_FACTS_TYPE')
    for name in FACT_KEYS:
        maximum = 0xffffffff if name == 'reason' else 15 if name == 'native_pending' else 1
        wire._need(wire._int(getattr(f, name), 0, maximum), 'ACTIVATION_FACTS')
    wire._need(f.scope_admitted == f.durable_intent_verified == f.cleanup_complete == 1
        and f.native_pending == f.unknown == 0, 'ACTIVATION_KNOWN_TERMINAL')
    for values in (outcome.native_attempts, outcome.native_returned):
        wire._need(type(values) is tuple and len(values) == 15
            and all(wire._int(value, 0, limit) for value, limit in zip(values, ROLE_MAX)),
            'ACTIVATION_NATIVE_COUNTS')
    wire._need(outcome.native_attempts == outcome.native_returned, 'ACTIVATION_NATIVE_RETURN')
    wire._need((f.mode_attempts, f.mode_returned, f.event_attempts, f.event_returned) ==
        (outcome.native_attempts[12], outcome.native_returned[12],
         outcome.native_attempts[14], outcome.native_returned[14]), 'ACTIVATION_CALL_JOIN')
    wire._need(f.event_attempts <= min(f.mode_returned, f.event_cas_verified)
        and f.mode_returned <= f.mode_attempts
        <= min(f.own_verified, f.baseline_compared, f.state_compared, f.intent_mode_used)
        and f.event_returned <= f.event_attempts and f.own_verified <= f.stat_before_valid,
        'ACTIVATION_ORDER')
    if outcome.status == 'ACTIVATED':
        # The native receipt requires all owned references and three distinct
        # ownership observations, not merely counts below the role limits.
        wire._need(outcome.native_attempts == ROLE_MAX, 'ACTIVATION_NATIVE_SUCCESS_COUNTS')
        wire._need(f.reason == 0 and all(getattr(f, name) == 1 for name in
            ('own_verified', 'activation_verified', 'baseline_compared', 'state_compared',
             'readback_compared', 'mode_attempts', 'mode_returned', 'event_attempts',
             'event_returned', 'intent_mode_used', 'stat_before_valid', 'stat_after_valid',
             'event_cas_verified')),
            'ACTIVATION_SUCCESS')
    else:
        wire._need(f.reason > 0 and f.activation_verified == 0, 'ACTIVATION_FAILURE')
        if outcome.status == 'REFUSED':
            wire._need(f.mode_attempts == f.event_attempts == 0, 'ACTIVATION_REFUSED_EFFECTS')
        else:
            wire._need(f.own_verified == 1, 'ACTIVATION_PARTIAL_OWN')


def _stat(outcome, before):
    prefix = 'before' if before else 'after'
    raw = outcome.stat_before if before else outcome.stat_after
    valid = getattr(outcome.activation, 'stat_' + prefix + '_valid')
    owner, kind, version = (getattr(outcome, prefix + suffix)
        for suffix in ('_owner_uuid', '_owner_class', '_version'))
    wire._need(type(raw) is bytes and len(raw) == 32 and type(owner) is str
        and wire._int(kind, 0, 3) and wire._int(version, 0, 0x7fffffff), 'ACTIVATION_STAT_SHAPE')
    if not valid:
        wire._need(owner == wire.NIL_UUID and kind == wire.OWNER_NOT_QUERIED and version == 0,
                   'ACTIVATION_STAT_UNOBSERVED')
        return
    wire._need(codec._uuid(outcome.actor_uuid), 'ACTIVATION_STAT_ACTOR')
    native_owner = str(uuid.UUID(bytes_le=raw[8:24]))
    native_kind = 0 if native_owner == wire.NIL_UUID else 1 if native_owner == outcome.actor_uuid else 2
    wire._need(raw[4] in (0, 1) and (raw[4] == 0) == (native_owner == wire.NIL_UUID)
        and struct.unpack_from('<i', raw)[0] == version and owner == native_owner
        and kind == native_kind, 'ACTIVATION_STAT_JOIN')


def _job(outcome):
    job, facts = outcome.job, outcome.activation
    wire._need(type(job) is wire.EditorJobFacts, 'ACTIVATION_JOB_TYPE')
    bounds = dict(open_calls=1, direct_reads=32, state_bridge_calls=3,
        warmup_reads=1, independent_outputs=1, final_state_equal=1, statistic_queries=3,
        statistic_verified=1, readback_verified=1)
    expected = dict.fromkeys(wire.JOB_KEYS, 0)
    expected.update(status=1 if outcome.status == 'ACTIVATED' else 2,
                    reason=facts.reason, typed_cleared=1)
    for name in ('initial_redo', 'initial_redo_code', 'candidate_redo',
                 'candidate_redo_code', 'restored_redo', 'restored_redo_code'):
        expected[name] = None
    for name, value in expected.items():
        actual = getattr(job, name)
        if name in bounds:
            wire._need(wire._int(actual, 0, bounds[name]), 'ACTIVATION_JOB_BOUND')
        else:
            wire._need(actual is None if value is None else type(actual) is int and actual == value,
                       'ACTIVATION_JOB_FACTS')
    wire._need(job.statistic_queries == outcome.native_attempts[6], 'ACTIVATION_STAT_COUNT')
    if outcome.activation_verified:
        wire._need(job.open_calls == job.warmup_reads == job.independent_outputs == 1
            and job.state_bridge_calls == 3 and job.direct_reads >= 2
            and job.statistic_verified == job.final_state_equal == 1, 'ACTIVATION_JOB_SUCCESS')


def validate_activation(outcome, **context):
    """Validate this bodyless response; confer no new source/repository rights."""
    wire._context(**context)
    wire._need(type(outcome) is EditorActivationOutcome
        and type(outcome.installation) is wire.EditorInstallation
        and outcome.installation == context['installation'] and outcome.command == context['command']
        and outcome.command.opcode == codec.ACTIVATE_OWN6
        and type(outcome.capability) is codec.ActivationCapability
        and outcome.capability == context.get('capability'), 'ACTIVATION_CONTEXT')
    wire._need(type(outcome.status) is str
        and outcome.status in ('ACTIVATED', 'ACTIVATION_FAILED', 'REFUSED'), 'ACTIVATION_STATUS')
    wire._need(all(wire._finite(getattr(outcome, name)) for name in ('issued_at', 'sampled_at', 'valid_until'))
        and outcome.installation.installed_at <= outcome.issued_at <= outcome.sampled_at <= context['now']
        <= outcome.valid_until <= min(outcome.installation.valid_until,
                                      outcome.issued_at + wire.MAX_CAPTURE_TTL), 'ACTIVATION_TIME')
    wire._need(type(outcome.body_sha256) is str and outcome.body_sha256 == wire.EMPTY_SHA256
        and type(outcome.actor_uuid) is str
        and (outcome.actor_uuid == wire.NIL_UUID or codec._uuid(outcome.actor_uuid)), 'ACTIVATION_IDENTITY')
    _facts(outcome); _job(outcome); wire._closure(outcome.closure)
    _stat(outcome, True); _stat(outcome, False)
    f = outcome.activation
    wire._need(f.stat_before_valid + f.stat_after_valid <= outcome.native_attempts[6],
               'ACTIVATION_STAT_QUERIES')
    for state in (outcome.before_state, outcome.after_state):
        wire._need(type(state) is tuple and len(state) == 22
            and all(wire._int(value) for value in state), 'ACTIVATION_STATE_SHAPE')
    if f.own_verified:
        wire._need(outcome.actor_uuid == outcome.command.expected_owner == outcome.before_owner_uuid
            and outcome.before_owner_class == 1
            and outcome.before_version == outcome.command.expected_version, 'ACTIVATION_INITIAL_OWN')
    if f.state_compared:
        wire._need(outcome.before_state == outcome.command.expected_state, 'ACTIVATION_BASELINE_STATE')
    if outcome.activation_verified:
        wire._need(outcome.after_owner_uuid == outcome.actor_uuid and outcome.after_owner_class == 1
            and outcome.after_version == outcome.before_version and outcome.stat_after == outcome.stat_before
            and outcome.after_state[12] == 0
            and all(a == b for i, (a, b) in enumerate(zip(outcome.before_state, outcome.after_state)) if i != 12),
            'ACTIVATION_FINAL_STATE')
    return outcome


def build_activation_frame(outcome, **context):
    validate_activation(outcome, **context)
    row = dict(kind='EDITOR_OWN_ACTIVATION', version=wire.VERSION, body_kind='activation_metadata',
        byte_count=0, **wire._binding_metadata(outcome.installation), **wire._request_metadata(outcome.command))
    row.update({name: getattr(outcome.target, name) for name in wire.TARGET_KEYS})
    row.update({name: getattr(outcome, name) for name in VALUE_KEYS})
    row.update(stat_before=outcome.stat_before.hex(), stat_after=outcome.stat_after.hex(),
        activation={name: getattr(outcome.activation, name) for name in FACT_KEYS},
        native_attempts=outcome.native_attempts, native_returned=outcome.native_returned,
        job={name: getattr(outcome.job, name) for name in wire.JOB_KEYS},
        closure={name: getattr(outcome.closure, name) for name in wire.CLOSURE_KEYS})
    return wire._frame(row, b'', outcome.command)


def parse_activation_frame(frame, **context):
    wire._context(**context)
    wire._need(context['command'].opcode == codec.ACTIVATE_OWN6, 'ACTIVATION_OPCODE')
    row, body = wire._unframe(frame, context['command'], KEYS)
    wire._join_metadata(row, context['installation'], context['command'], 'EDITOR_OWN_ACTIVATION')
    wire._need(body == b'' and type(row['byte_count']) is int and row['byte_count'] == 0
        and row['body_kind'] == 'activation_metadata' and all(type(row[name]) is str
        and row[name] == getattr(context['command'].target, name) for name in wire.TARGET_KEYS),
        'ACTIVATION_BODY_JOIN')
    for name, keys in (('activation', FACT_KEYS), ('job', wire.JOB_KEYS), ('closure', wire.CLOSURE_KEYS)):
        wire._need(type(row[name]) is dict and row[name].keys() == set(keys), 'ACTIVATION_SCHEMA')
    for name in ('stat_before', 'stat_after'):
        raw = row[name]
        wire._need(type(raw) is str and len(raw) == 64 and all(ch in '0123456789abcdef' for ch in raw),
                   'ACTIVATION_STAT_ENCODING')
        row[name] = bytes.fromhex(raw)
    for name in ('native_attempts', 'native_returned', 'before_state', 'after_state'):
        wire._need(type(row[name]) is list, 'ACTIVATION_ARRAY_ENCODING')
        row[name] = tuple(row[name])
    outcome = EditorActivationOutcome(context['installation'], context['command'], context.get('capability'),
        **{name: row[name] for name in VALUE_KEYS}, activation=ActivationFacts(**row['activation']),
        native_attempts=row['native_attempts'], native_returned=row['native_returned'],
        job=wire.EditorJobFacts(**row['job']), closure=wire.EditorClosureFacts(**row['closure']))
    return validate_activation(outcome, **context)


def finish_activation(outcome, release, **context):
    """Expose facts only after the joined ACK and owned-resource release."""
    validate_activation(outcome, **context); wire._release(release, outcome, context)
    return EditorActivationSnapshot(outcome, release)
