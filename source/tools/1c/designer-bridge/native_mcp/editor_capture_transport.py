"""Metadata-only CAPTURE_ONLY5 results over the existing ACK/release lifecycle.

The trusted owner supplies the exact request and binding out of band. Native
source/state CAS stays in the compiled callback; this record contains no source
observation, refreshed source, generation proof, or edit/cancel authority.
Repository mutations count attempted capture calls, including known failures.
"""
from dataclasses import dataclass, field, make_dataclass
import struct
import uuid

from . import editor_command as command_codec
from . import editor_transport as wire

FACT_KEYS = tuple(('capture_scoped capture_verified activation_verified baseline_compared '
    'readback_compared reason source_refresh edit_authorized cancel_authorized generation_verified '
    'native_pending durable_intent_verified capture_attempts capture_returned mode_attempts '
    'mode_returned event_attempts event_returned repository_mutations owner_edit_latched '
    'cleanup_complete unknown intent_capture_used intent_mode_used stat_before_valid stat_after_valid').split())
CaptureOnlyFacts = make_dataclass('CaptureOnlyFacts', [(name, int) for name in FACT_KEYS],
    frozen=True, slots=True, namespace={'__module__': __name__})
ROLE_NAMES = tuple(('info factory variant_dtor record_copy result_ctor result_dtor stat revise '
                    'release selection owned_slot_dtor query mode_set mode_get event').split())
ROLE_MAX = (1, 1, 2, 1, 1, 1, 5, 1, 1, 1, 7, 5, 1, 2, 1)
VALUE_KEYS = tuple(('issued_at sampled_at valid_until status body_sha256 actor_uuid '
    'before_owner_uuid before_owner_class before_version after_owner_uuid after_owner_class after_version '
    'stat_before stat_after').split())
KEYS = frozenset(('kind', 'version', *wire.BINDING_KEYS, *wire.REQUEST_KEYS, *wire.TARGET_KEYS,
                  *VALUE_KEYS, 'body_kind', 'byte_count', 'capture', 'native_attempts',
                  'native_returned', 'job', 'closure'))


@dataclass(frozen=True, slots=True)
class EditorCaptureOnlyOutcome:
    installation: wire.EditorInstallation
    command: command_codec.EditorCommand
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
    capture: CaptureOnlyFacts
    native_attempts: tuple
    native_returned: tuple
    job: wire.EditorJobFacts
    closure: wire.EditorClosureFacts

    @property
    def binding(self):
        return self.installation.binding

    @property
    def target(self):
        return self.command.target

    @property
    def capture_verified(self):
        return self.capture.capture_verified == 1

    @property
    def activation_verified(self):
        return self.capture.activation_verified == 1

    @property
    def refresh_verified(self):
        return False

    @property
    def edit_authorized(self):
        return False

    @property
    def cancel_authorized(self):
        return False

    @property
    def acquisition_proven(self):
        return False


@dataclass(frozen=True, slots=True)
class EditorCaptureOnlySnapshot:
    capture: EditorCaptureOnlyOutcome
    release: wire.EditorRelease


def _facts(outcome):
    facts = outcome.capture
    wire._need(type(facts) is CaptureOnlyFacts
               and all(wire._int(getattr(facts, name), 0, 0xffffffff if name == 'reason' else 1)
                       for name in FACT_KEYS), 'CAPTURE_ONLY_FACTS')
    wire._need(all(getattr(facts, name) == 0 for name in ('source_refresh', 'edit_authorized',
        'cancel_authorized', 'generation_verified', 'native_pending', 'unknown'))
        and facts.owner_edit_latched == facts.cleanup_complete == 1, 'CAPTURE_ONLY_CLOSURE')
    for values in (outcome.native_attempts, outcome.native_returned):
        wire._need(type(values) is tuple and len(values) == len(ROLE_NAMES)
                   and all(wire._int(value, 0, maximum) for value, maximum in zip(values, ROLE_MAX)),
                   'CAPTURE_ONLY_NATIVE_COUNTS')
    wire._need(outcome.native_attempts == outcome.native_returned, 'CAPTURE_ONLY_NATIVE_PENDING')
    wire._need((facts.capture_attempts, facts.mode_attempts, facts.event_attempts)
               == tuple(outcome.native_attempts[i] for i in (7, 12, 14))
               and (facts.capture_returned, facts.mode_returned, facts.event_returned)
               == tuple(outcome.native_returned[i] for i in (7, 12, 14))
               and facts.repository_mutations == facts.capture_attempts, 'CAPTURE_ONLY_CALL_JOIN')
    wire._need(facts.capture_verified <= facts.capture_scoped <= facts.capture_returned
               and facts.activation_verified <= facts.capture_verified
               and facts.readback_compared <= facts.baseline_compared
               and facts.mode_attempts <= facts.capture_verified
               and facts.event_attempts <= facts.mode_returned
               and facts.capture_attempts <= facts.intent_capture_used
               and facts.mode_attempts <= facts.intent_mode_used, 'CAPTURE_ONLY_PHASES')
    if facts.capture_attempts:
        wire._need(facts.durable_intent_verified == facts.baseline_compared == 1
                   and facts.stat_before_valid == 1, 'CAPTURE_ONLY_INTENT_CAS')
    if outcome.status == 'CAPTURED':
        wire._need(facts.reason == 0 and facts.capture_verified == facts.activation_verified
                   == facts.readback_compared == facts.mode_attempts == facts.event_attempts == 1,
                   'CAPTURE_ONLY_SUCCESS')
        wire._need(outcome.native_attempts[6] == 5, 'CAPTURE_ONLY_SUCCESS_STAT_COUNT')
    elif outcome.status == 'ACTIVATION_FAILED':
        wire._need(facts.reason > 0 and facts.capture_verified == 1 and facts.activation_verified == 0,
                   'CAPTURE_ONLY_ACTIVATION_FAILURE')
    else:
        wire._need(facts.reason > 0 and facts.capture_verified == facts.activation_verified == 0,
                   'CAPTURE_ONLY_REFUSAL')


def _job(outcome):
    job, facts = outcome.job, outcome.capture
    wire._need(type(job) is wire.EditorJobFacts, 'CAPTURE_ONLY_JOB_TYPE')
    bounds = dict(open_calls=1, direct_reads=32, capture_count=2, state_bridge_calls=3,
                  warmup_reads=1, independent_outputs=1, final_state_equal=1,
                  statistic_queries=5, statistic_verified=1, selection_verified=1,
                  pre_setter_cas_verified=1, readback_verified=1)
    expected = dict.fromkeys(wire.JOB_KEYS, 0)
    expected.update(status=1 if outcome.status == 'CAPTURED' else 2, reason=facts.reason,
                    typed_cleared=1, repository_mutations=facts.repository_mutations)
    for name in ('initial_redo', 'initial_redo_code', 'candidate_redo', 'candidate_redo_code',
                 'restored_redo', 'restored_redo_code'):
        expected[name] = None
    for name, value in expected.items():
        actual = getattr(job, name)
        if name in bounds:
            wire._need(wire._int(actual, 0, bounds[name]), 'CAPTURE_ONLY_JOB_BOUND')
        else:
            wire._need(actual is None if value is None else type(actual) is int and actual == value,
                       'CAPTURE_ONLY_JOB_FACTS')
    wire._need(job.statistic_queries == outcome.native_attempts[6], 'CAPTURE_ONLY_STAT_COUNT')
    if facts.capture_attempts:
        wire._need(job.open_calls == job.warmup_reads == job.independent_outputs == 1
                   and job.capture_count >= 1 and job.state_bridge_calls >= 2 and job.direct_reads >= 2,
                   'CAPTURE_ONLY_BASELINE_FACTS')


def _stat(outcome, before):
    prefix = 'before' if before else 'after'
    raw = outcome.stat_before if before else outcome.stat_after
    valid = getattr(outcome.capture, 'stat_' + prefix + '_valid')
    owner, kind, version = (getattr(outcome, prefix + suffix)
                            for suffix in ('_owner_uuid', '_owner_class', '_version'))
    wire._need(type(raw) is bytes and len(raw) == 32 and type(owner) is str
               and wire._int(kind, 0, 3) and wire._int(version, 0, 0x7fffffff), 'CAPTURE_ONLY_STAT_SHAPE')
    if not valid:
        wire._need(owner == wire.NIL_UUID and kind == wire.OWNER_NOT_QUERIED and version == 0,
                   'CAPTURE_ONLY_UNVERIFIED_STAT')
        return
    wire._need(command_codec._uuid(outcome.actor_uuid), 'CAPTURE_ONLY_STAT_ACTOR')
    native_owner = str(uuid.UUID(bytes_le=raw[8:24]))
    native_kind = 0 if native_owner == wire.NIL_UUID else 1 if native_owner == outcome.actor_uuid else 2
    wire._need(raw[4] in (0, 1) and (raw[4] == 0) == (native_owner == wire.NIL_UUID)
               and struct.unpack_from('<i', raw)[0] == version and owner == native_owner
               and kind == native_kind, 'CAPTURE_ONLY_STAT_JOIN')


def validate_capture_only(outcome, **context):
    """Validate metadata against the trusted command; confer no write authority."""
    wire._context(**context)
    wire._need(type(outcome) is EditorCaptureOnlyOutcome
               and type(outcome.installation) is wire.EditorInstallation
               and type(outcome.command) is command_codec.EditorCommand
               and outcome.installation == context['installation']
               and outcome.command == context['command'] and outcome.command.opcode == command_codec.CAPTURE_ONLY,
               'CAPTURE_ONLY_CONTEXT')
    wire._need(type(outcome.status) is str and outcome.status in ('CAPTURED', 'ACTIVATION_FAILED', 'REFUSED'),
               'CAPTURE_ONLY_STATUS')
    wire._need(all(wire._finite(getattr(outcome, name)) for name in ('issued_at', 'sampled_at', 'valid_until'))
        and outcome.installation.installed_at <= outcome.issued_at <= outcome.sampled_at <= context['now']
        <= outcome.valid_until <= min(outcome.installation.valid_until, outcome.issued_at + wire.MAX_CAPTURE_TTL),
        'CAPTURE_ONLY_TIME')
    wire._need(type(outcome.body_sha256) is str and outcome.body_sha256 == wire.EMPTY_SHA256
               and type(outcome.actor_uuid) is str
               and (outcome.actor_uuid == wire.NIL_UUID or command_codec._uuid(outcome.actor_uuid)),
               'CAPTURE_ONLY_IDENTITY')
    _facts(outcome); _job(outcome); wire._closure(outcome.closure)
    _stat(outcome, True); _stat(outcome, False)
    facts = outcome.capture
    wire._need(facts.stat_before_valid + facts.stat_after_valid <= outcome.native_attempts[6],
               'CAPTURE_ONLY_STAT_QUERIES')
    if facts.capture_attempts:
        wire._need(outcome.before_owner_class == 0 and outcome.before_version > 0,
                   'CAPTURE_ONLY_INITIAL_FREE')
    if facts.capture_verified:
        wire._need(facts.stat_after_valid == 1 and outcome.after_owner_class == 1
                   and outcome.after_owner_uuid == outcome.actor_uuid
                   and outcome.after_version == outcome.before_version > 0,
                   'CAPTURE_ONLY_OBSERVED_OWN')
    return outcome


def build_capture_only_frame(outcome, **context):
    """Build an empty-body frame from validated immutable facts only."""
    validate_capture_only(outcome, **context)
    row = dict(kind='EDITOR_CAPTURE_ONLY', version=wire.VERSION, body_kind='capture_metadata',
               byte_count=0, **wire._binding_metadata(outcome.installation), **wire._request_metadata(outcome.command))
    row.update({name: getattr(outcome.target, name) for name in wire.TARGET_KEYS})
    row.update({name: getattr(outcome, name) for name in VALUE_KEYS})
    row.update(stat_before=outcome.stat_before.hex(), stat_after=outcome.stat_after.hex(),
               capture={name: getattr(outcome.capture, name) for name in FACT_KEYS},
               native_attempts=outcome.native_attempts, native_returned=outcome.native_returned,
               job={name: getattr(outcome.job, name) for name in wire.JOB_KEYS},
               closure={name: getattr(outcome.closure, name) for name in wire.CLOSURE_KEYS})
    return wire._frame(row, b'', outcome.command)


def parse_capture_only_frame(frame, **context):
    """Parse only this command's exact capture schema, without decoding text."""
    wire._context(**context)
    wire._need(context['command'].opcode == command_codec.CAPTURE_ONLY, 'CAPTURE_ONLY_OPCODE')
    row, body = wire._unframe(frame, context['command'], KEYS)
    wire._join_metadata(row, context['installation'], context['command'], 'EDITOR_CAPTURE_ONLY')
    wire._need(body == b'' and type(row['byte_count']) is int and row['byte_count'] == 0
               and type(row['body_kind']) is str and row['body_kind'] == 'capture_metadata'
               and all(type(row[name]) is str and row[name] == getattr(context['command'].target, name)
                       for name in wire.TARGET_KEYS), 'CAPTURE_ONLY_BODY_JOIN')
    for name, keys in (('capture', FACT_KEYS), ('job', wire.JOB_KEYS), ('closure', wire.CLOSURE_KEYS)):
        wire._need(type(row[name]) is dict and set(row[name]) == set(keys), 'CAPTURE_ONLY_SCHEMA')
    for name in ('stat_before', 'stat_after'):
        raw = row[name]
        wire._need(type(raw) is str and len(raw) == 64 and all(ch in '0123456789abcdef' for ch in raw),
                   'CAPTURE_ONLY_STAT_ENCODING')
        row[name] = bytes.fromhex(raw)
    for name in ('native_attempts', 'native_returned'):
        wire._need(type(row[name]) is list, 'CAPTURE_ONLY_NATIVE_ENCODING')
        row[name] = tuple(row[name])
    outcome = EditorCaptureOnlyOutcome(context['installation'], context['command'],
        **{name: row[name] for name in VALUE_KEYS}, capture=CaptureOnlyFacts(**row['capture']),
        native_attempts=row['native_attempts'], native_returned=row['native_returned'],
        job=wire.EditorJobFacts(**row['job']), closure=wire.EditorClosureFacts(**row['closure']))
    return validate_capture_only(outcome, **context)


def finish_capture_only(outcome, release, **context):
    """Expose a completed result only after the normal joined release proof."""
    validate_capture_only(outcome, **context); wire._release(release, outcome, context)
    return EditorCaptureOnlySnapshot(outcome, release)
