"""Binary repository packets on the editor lifecycle; never module UTF8.

These immutable RAM records describe one joined request/response, not physical
attestation or write authority. A packet has no server-version echo: its request
version must agree with both full native statistic witnesses. Decoding the module
is a separate step after the ordinary ACK/release handshake.
"""
from dataclasses import dataclass, field, make_dataclass
import hashlib
import struct
import uuid

from . import editor_command as command_codec
from . import editor_transport as wire

MAX_PACKET_BYTES = 1048576
FACT_KEYS = tuple('rpc_attempts rpc_returned stat_attempts stat_returned stream_attempts stream_returned packet_copies pending adoption'.split())
RepositoryFacts = make_dataclass('RepositoryFacts', [(name, int) for name in FACT_KEYS],
    frozen=True, slots=True, namespace={'__module__': __name__})
VALUE_KEYS = tuple('issued_at sampled_at valid_until status body_sha256 actor_uuid owner_uuid owner_class owner_version requested_version resource_name stat_before stat_after'.split())
KEYS = frozenset(('kind', 'version', *wire.BINDING_KEYS, *wire.REQUEST_KEYS, *wire.TARGET_KEYS,
                  *VALUE_KEYS, 'body_kind', 'byte_count', 'repository', 'job', 'closure'))


@dataclass(frozen=True, slots=True)
class RepositoryCapture:
    installation: wire.EditorInstallation
    command: command_codec.EditorCommand
    issued_at: float
    sampled_at: float
    valid_until: float
    status: str
    body_sha256: str
    actor_uuid: str
    owner_uuid: str
    owner_class: int
    owner_version: int
    requested_version: int
    resource_name: str
    stat_before: bytes = field(repr=False)
    stat_after: bytes = field(repr=False)
    repository: RepositoryFacts
    job: wire.EditorJobFacts
    closure: wire.EditorClosureFacts
    packet: bytes = field(repr=False)

    @property
    def binding(self):
        return self.installation.binding

    @property
    def target(self):
        return self.command.target


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    capture: RepositoryCapture
    release: wire.EditorRelease


def _facts(capture):
    """A known refusal has no outstanding resource or packet to consume."""
    facts, job = capture.repository, capture.job
    wire._need(type(facts) is RepositoryFacts and type(job) is wire.EditorJobFacts, 'REPOSITORY_FACT_TYPE')
    wire._need(all(wire._int(getattr(facts, name)) for name in FACT_KEYS), 'REPOSITORY_FACT_FIELDS')
    wire._need(facts.pending == 0 and facts.adoption == 3
               and facts.rpc_returned == facts.rpc_attempts <= 1
               and facts.stat_returned == facts.stat_attempts <= 2
               and facts.stream_returned == facts.stream_attempts <= 2
               and facts.packet_copies <= 1, 'REPOSITORY_RESOURCE_CLOSURE')
    expected = dict.fromkeys(wire.JOB_KEYS, 0)
    wire._need(wire._int(job.independent_outputs, 0, 1) and wire._int(job.statistic_verified, 0, 1),
               'REPOSITORY_PARTIAL_FACTS')
    expected.update(status=1 if capture.status == 'READ' else 2, reason=job.reason,
                    typed_cleared=1, independent_outputs=1 if capture.status == 'READ' else job.independent_outputs,
                    statistic_queries=facts.stat_attempts,
                    statistic_verified=1 if capture.status == 'READ' else job.statistic_verified)
    for name in ('initial_redo', 'initial_redo_code', 'candidate_redo', 'candidate_redo_code',
                 'restored_redo', 'restored_redo_code'):
        expected[name] = None
    wire._need(all(getattr(job, key) is None if value is None else
                   type(getattr(job, key)) is int and getattr(job, key) == value
                   for key, value in expected.items()), 'REPOSITORY_JOB_FACTS')
    wire._need(wire._int(job.reason) and (job.reason == 0) == (capture.status == 'READ'), 'REPOSITORY_REASON')
    if capture.status == 'READ':
        wire._need(tuple(getattr(facts, name) for name in FACT_KEYS) == (1, 1, 2, 2, 2, 2, 1, 0, 3),
                   'REPOSITORY_SUCCESS_FACTS')


def validate_repository(capture, **context):
    wire._context(**context)
    wire._need(type(capture) is RepositoryCapture and capture.installation == context['installation']
               and capture.command == context['command'] and capture.command.opcode == command_codec.READ_REPOSITORY_MODULE,
               'REPOSITORY_CONTEXT')
    wire._need(type(capture.status) is str and capture.status in ('READ', 'REFUSED'), 'REPOSITORY_STATUS')
    wire._need(all(wire._finite(getattr(capture, name)) for name in ('issued_at', 'sampled_at', 'valid_until'))
               and capture.installation.installed_at <= capture.issued_at <= capture.sampled_at <= context['now'] <= capture.valid_until
               <= min(capture.installation.valid_until, capture.issued_at + wire.MAX_CAPTURE_TTL), 'REPOSITORY_TIME')
    wire._need(type(capture.packet) is bytes and len(capture.packet) <= MAX_PACKET_BYTES
               and type(capture.body_sha256) is str
               and capture.body_sha256 == hashlib.sha256(capture.packet).hexdigest(), 'REPOSITORY_PACKET_SHA')
    wire._need(type(capture.resource_name) is str
               and capture.resource_name == capture.target.object_uuid + '.0', 'REPOSITORY_RESOURCE')
    wire._need(all(type(getattr(capture, name)) is bytes and len(getattr(capture, name)) == 32
                   for name in ('stat_before', 'stat_after')), 'REPOSITORY_STAT_SIZE')
    _facts(capture); wire._closure(capture.closure)
    if capture.status == 'REFUSED':
        wire._need(not capture.packet and type(capture.requested_version) is int
                   and 0 <= capture.requested_version <= 0x7fffffff
                   and type(capture.owner_version) is int and capture.owner_version == 0
                   and type(capture.owner_class) is int and capture.owner_class == wire.OWNER_NOT_QUERIED
                   and capture.actor_uuid == wire.NIL_UUID and capture.owner_uuid == wire.NIL_UUID,
                   'REPOSITORY_REFUSAL_BODY')
        return
    wire._need(capture.packet and command_codec._uuid(capture.actor_uuid)
               and capture.stat_before == capture.stat_after
               and wire._int(capture.requested_version, 1, 0x7fffffff), 'REPOSITORY_WITNESS')
    raw = capture.stat_before
    version = struct.unpack_from('<i', raw)[0]
    owner = str(uuid.UUID(bytes_le=raw[8:24]))
    kind = 0 if owner == wire.NIL_UUID else 1 if owner == capture.actor_uuid else 2
    wire._need(raw[4] in (0, 1) and (raw[4] == 0) == (owner == wire.NIL_UUID)
               and type(capture.owner_version) is int and version == capture.requested_version == capture.owner_version
               and type(capture.owner_uuid) is str and owner == capture.owner_uuid
               and type(capture.owner_class) is int and kind == capture.owner_class, 'REPOSITORY_STAT_JOIN')


def build_repository_frame(capture, **context):
    validate_repository(capture, **context)
    row = dict(kind='EDITOR_REPOSITORY_PACKET', version=wire.VERSION, body_kind='repository_packet',
               **wire._binding_metadata(capture.installation), **wire._request_metadata(capture.command))
    row.update({name: getattr(capture.target, name) for name in wire.TARGET_KEYS})
    row.update({name: getattr(capture, name) for name in VALUE_KEYS})
    row.update(stat_before=capture.stat_before.hex(), stat_after=capture.stat_after.hex(), byte_count=len(capture.packet),
               repository={name: getattr(capture.repository, name) for name in FACT_KEYS},
               job={name: getattr(capture.job, name) for name in wire.JOB_KEYS},
               closure={name: getattr(capture.closure, name) for name in wire.CLOSURE_KEYS})
    return wire._frame(row, capture.packet, capture.command)


def parse_repository_frame(frame, **context):
    wire._context(**context)
    wire._need(context['command'].opcode == command_codec.READ_REPOSITORY_MODULE, 'REPOSITORY_OPCODE')
    row, body = wire._unframe(frame, context['command'], KEYS)
    wire._join_metadata(row, context['installation'], context['command'], 'EDITOR_REPOSITORY_PACKET')
    wire._need(row['body_kind'] == 'repository_packet' and type(row['body_kind']) is str
               and wire._int(row['byte_count'], 0, MAX_PACKET_BYTES) and row['byte_count'] == len(body)
               and all(type(row[name]) is str and row[name] == getattr(context['command'].target, name)
                       for name in wire.TARGET_KEYS), 'REPOSITORY_BODY_JOIN')
    for name, keys in (('job', wire.JOB_KEYS), ('closure', wire.CLOSURE_KEYS), ('repository', FACT_KEYS)):
        wire._need(type(row[name]) is dict and set(row[name]) == set(keys), 'REPOSITORY_SCHEMA')
    # Hex decoding is bounded and fixed-shape; malformed source bytes never
    # enter a text decoder or an exception carrying the packet.
    for name in ('stat_before', 'stat_after'):
        value = row[name]
        wire._need(type(value) is str and len(value) == 64 and all(ch in '0123456789abcdef' for ch in value),
                   'REPOSITORY_STAT_ENCODING')
        row[name] = bytes.fromhex(value)
    capture = RepositoryCapture(context['installation'], context['command'],
        **{name: row[name] for name in VALUE_KEYS}, repository=RepositoryFacts(**row['repository']),
        job=wire.EditorJobFacts(**row['job']), closure=wire.EditorClosureFacts(**row['closure']), packet=body)
    validate_repository(capture, **context)
    return capture


def finish_repository(capture, release, **context):
    validate_repository(capture, **context); wire._release(release, capture, context)
    return RepositorySnapshot(capture, release)
