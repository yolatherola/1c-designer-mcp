"""Pure V3 fixtures; source strings are synthetic and remain in RAM."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_mcp import editor_command as c
from native_mcp import editor_transport as w

ACTOR = 'cab12345-1234-4567-89ab-cdef01234567'
OTHER = 'f58148bc-4333-4347-af6e-e0fbe01f3210'
TEXT = '\ufeffПроцедура Синтетика()\r\n    // 🔬\r\nКонецПроцедуры\r\n'
STATE = tuple(0x10000 + i * 16 for i in range(8)) + (1, 0, 1, 0, 0, 1, 2, 3, 4, 5, 6, 0, 0, 0xffffffff)


def binding_for():
    return c.EditorBinding(c.ROOT_UUID, 1234, '01dd5fb7f0cd1090', 5678,
                           'a' * 32, 'b' * 64, 'c' * 64, 'd' * 64)


def target_for():
    return c.EditorTarget('d593e80d-b70c-400b-9955-d02f7a4c89e9',
        'a87c7b15-106f-4c92-a7f3-68c02cc686d9', 'a637f77f-3840-441d-a1c3-699c8c5cb7e0')


def capture_for(command, installation, now, body=None, *, owner_not_queried=False):
    """Shared Root channel fixture: READ synthetic body or EDIT command baseline."""
    edit = command.opcode == c.EDIT_MODULE
    assert not owner_not_queried or command.opcode == c.READ_MODULE
    body = command.baseline.utf8 if edit else TEXT.encode('utf-8') if body is None else body
    measured = c.ModuleText.from_utf8(body)
    before = command.expected_state if edit else STATE
    middle = list(before)
    middle[11] = middle[19] = middle[20] = 1; middle[21] = 4
    job = dict.fromkeys(w.JOB_KEYS, 0)
    job.update(status=1, open_calls=1, direct_reads=6 if edit else 2,
        capture_count=3 if edit else 1, state_bridge_calls=3 if edit else 2,
        warmup_reads=1, typed_cleared=1, independent_outputs=1, final_state_equal=1,
        statistic_queries=0 if owner_not_queried else 3 if edit else 1,
        statistic_verified=0 if owner_not_queried else 1,
        redo_queries=3 if edit else 0, redo_refs_restored=int(edit))
    for name in ('setter_attempts', 'setter_returned', 'undo_attempts', 'undo_returned', 'selection_verified',
                 'pre_setter_cas_verified', 'readback_verified', 'restored_verified', 'fresh_undo_witness',
                 'setter_armed', 'undo_armed', 'source_writes'):
        job[name] = int(edit)
    job.update(initial_redo=0 if edit else None, initial_redo_code=0xffffffff if edit else None,
        candidate_redo=0 if edit else None, candidate_redo_code=0xffffffff if edit else None,
        restored_redo=1 if edit else None, restored_redo_code=4 if edit else None)
    errors = ('sdk_result', 'abi_fault', 'whole_sdk_cpp_throws', 'whole_sdk_other_exceptions')
    closure = {name: 0 if name in errors else 1 for name in w.CLOSURE_INT_KEYS}
    closure.update({name: True for name in w.CLOSURE_BOOL_KEYS})
    issued = max(installation.installed_at, now - .2)
    sampled = max(issued, now - .1)
    return w.EditorCapture(installation, command, issued, sampled,
        min(installation.valid_until, issued + 60), 'RESTORED' if edit else 'READ', measured.sha256,
        command.baseline.sha256 if edit else measured.sha256, command.candidate.sha256 if edit else None,
        measured.utf16_units, body.startswith(b'\xef\xbb\xbf'), body.count(b'\r\n'), body.endswith(b'\n'),
        w.NIL_UUID if owner_not_queried else command.expected_owner if edit else ACTOR,
        w.NIL_UUID if owner_not_queried else command.expected_owner if edit else ACTOR,
        w.OWNER_NOT_QUERIED if owner_not_queried else 1, 0 if owner_not_queried else command.expected_version if edit else 42,
        before, tuple(middle) if edit else (), before,
        w.EditorJobFacts(**job), w.EditorClosureFacts(**closure), body)


def fixture(command=None, binding=None, installation=None, now=None):
    binding = command.binding if command is not None else binding or binding_for()
    installation = installation or w.EditorInstallation(binding, 100., 700.)
    now = installation.installed_at + 7 if now is None else now
    command = command or c.EditorCommand(c.READ_MODULE, binding, target_for(), 1, 1, '1' * 32)
    capability = c.EditCapability(binding, command.target, command.expected_owner) if command.opcode == 2 else None
    context = dict(binding=binding, installation=installation, command=command, now=now,
                   previous_sequence=command.sequence - 1, capability=capability)
    return capture_for(command, installation, now), context


def edit_for(binding=None, sequence=2):
    binding = binding or binding_for()
    return c.EditorCommand(c.EDIT_MODULE, binding, target_for(), sequence, 7, 'e' * 32, c.EDIT_VERIFY_UNDO,
        ACTOR, 42, STATE, c.ModuleText.from_text(TEXT),
        c.ModuleText.from_text('// AH1C OWNED EDITOR PROBE ' + binding.operation_id + ' ' + TEXT))


def close_for(command, installation, totals, now):
    return w.EditorClose(installation, command, now - .1, command.sequence - 1, totals)


def release_for(capture, now):
    return w.EditorRelease(capture.installation.binding, capture.command.target, capture.command.sequence,
        capture.command.revision, capture.command.nonce,
        w.EMPTY_SHA256 if type(capture) is w.EditorReadRefusal else capture.body_sha256, now - .05)


def refusal_for(command, installation, now=107.):
    """Clean synthetic READ refusal; partial observations never become source."""
    capture = capture_for(command, installation, now)
    row = w._capture_metadata(capture)
    row.update(status='REFUSED', body_sha256=w.EMPTY_SHA256, baseline_sha256=w.EMPTY_SHA256,
        candidate_sha256=None, byte_count=0, utf16_units=0, bom_present=False, crlf_count=0,
        ends_lf=False, actor_uuid=w.NIL_UUID, owner_uuid=w.NIL_UUID, owner_class=0,
        owner_version=0, before_state=[0]*22, middle_state=[], after_state=[0]*22)
    job = dict.fromkeys(w.JOB_KEYS, 0)
    job.update(status=2, reason=105, open_calls=1, warmup_reads=1, typed_cleared=1)
    for key in ('initial_redo', 'initial_redo_code', 'candidate_redo', 'candidate_redo_code',
                'restored_redo', 'restored_redo_code'):
        job[key] = None
    row['job'] = job
    return w.parse_refusal_frame(raw_frame(row, b'', command), binding=command.binding,
        installation=installation, command=command, now=now, previous_sequence=command.sequence-1)


def metadata(frame):
    header = w._HEADER.unpack(frame[:32]); end = 32 + header[4]
    return json.loads(frame[32:end]), frame[end:]


def raw_frame(row, body, command):
    raw = json.dumps(row, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    return w._HEADER.pack(w.FRAME_MAGIC, 3, command.sequence, command.revision, len(raw), len(body), 0) + raw + body


def changed(frame, codec, index, value):
    values = list(codec.unpack(frame)); values[index] = value
    return codec.pack(*values)


class EditorTransportTests(unittest.TestCase):
    def refused(self, function, *args, **kwargs):
        with self.assertRaises(w.EditorTransportRefusal) as caught:
            function(*args, **kwargs)
        self.assertRegex(str(caught.exception), '^EDITOR_TRANSPORT_[A-Z_]+$')
        self.assertNotIn('Синтетика', str(caught.exception))
        self.assertIsNone(caught.exception.__context__)

    def test_clean_read_refusal_release_totals_close_without_source_or_capability(self):
        _, ctx = fixture()
        ctx['command'] = replace(ctx['command'], policy=c.READ_WITH_OWNERSHIP)
        refusal = refusal_for(ctx['command'], ctx['installation'], ctx['now'])
        raw = w.build_refusal_frame(refusal, **ctx)
        self.assertEqual(refusal, w.parse_editor_frame(raw, **ctx))
        self.assertEqual(105, refusal.reason)
        for name in ('utf8', 'body_sha256', 'actor_uuid', 'owner_uuid', 'before_state'):
            self.assertFalse(hasattr(refusal, name))
        self.assertNotIn('_metadata=', repr(refusal))
        self.refused(w.parse_capture_frame, raw, **ctx)
        self.assertTrue(w.parse_ack(w.build_ack(ctx['command'], w.EMPTY_SHA256, accepted=True),
            command=ctx['command'], body_sha256=w.EMPTY_SHA256))
        release = release_for(refusal, ctx['now'])
        release = w.parse_release(w.build_release(release, capture=refusal, **ctx), capture=refusal, **ctx)
        snapshot = w.finish_refusal(refusal, release, **ctx)
        self.refused(w.capability_from_read, snapshot)
        totals = w.advance_totals(w.EditorTotals(), snapshot)
        self.assertEqual((1, 1, 0, 0), (totals.total_commands, totals.total_reads,
            totals.total_direct_reads, totals.total_source_writes))
        close = c.EditorCommand(c.CLOSE, ctx['binding'], None, 2, 0, '2'*32)
        close_ctx = dict(ctx, command=close, previous_sequence=1)
        closed = close_for(close, ctx['installation'], totals, ctx['now'])
        self.assertEqual(closed, w.parse_close_frame(w.build_close_frame(closed,
            expected_totals=totals, **close_ctx), expected_totals=totals, **close_ctx))

    def test_read_refusal_dirty_or_forged_facts_never_admitted(self):
        _, ctx = fixture(); refusal = refusal_for(ctx['command'], ctx['installation'], ctx['now'])
        original, _ = metadata(w.build_refusal_frame(refusal, **ctx))
        cases = []
        for key, value in (('status', 1), ('reason', 0), ('typed_cleared', 0), ('setter_armed', 1),
            ('setter_attempts', 1), ('setter_returned', 1), ('undo_armed', 1), ('undo_returned', 1),
            ('source_writes', 1), ('configuration_saves', 1), ('exception', 1), ('direct_reads', 3),
            ('statistic_verified', 1), ('open_calls', True)):
            cases.append(dict(original, job=dict(original['job'], **{key: value})))
        for key, value in (('whole_sdk_cpp_throws', 1), ('sdk_result', 1), ('job_sealed', False),
                           ('callback_quiesced', False), ('io_drained', False)):
            cases.append(dict(original, closure=dict(original['closure'], **{key: value})))
        for key, value in (('nonce', 'f'*32), ('object_uuid', OTHER), ('status', 'UNKNOWN'),
            ('body_sha256', 'f'*64), ('byte_count', 1), ('before_state', [True]*22),
            ('owner_uuid', 'invalid'), ('sampled_at', 1e999)):
            cases.append(dict(original, **{key: value}))
        for row in cases:
            self.refused(w.parse_editor_frame, raw_frame(row, b'', ctx['command']), **ctx)
        self.refused(w.parse_refusal_frame, raw_frame(original, b'secret', ctx['command']), **ctx)
        # JSON permits an exponent whose Python float overflows; diagnostics
        # must still discard the internal encoding exception and its context.
        raw = json.dumps(original, separators=(',', ':')).encode().replace(b'"sampled_at":106.9', b'"sampled_at":1e999')
        frame = w._HEADER.pack(w.FRAME_MAGIC, 3, 1, 1, len(raw), 0, 0) + raw
        self.refused(w.parse_refusal_frame, frame, **ctx)
        release = release_for(refusal, ctx['now'])
        self.refused(w.finish_refusal, refusal, replace(release, buffers_freed=False), **ctx)
        self.refused(w.advance_totals, w.EditorTotals(), w.EditorRefusalSnapshot(refusal, None))

    def test_layouts_ready_and_installation_lifetime(self):
        capture, context = fixture(); installation = context['installation']
        self.assertEqual((128, 32, 120, 160), (w._READY.size, w._HEADER.size, w._ACK.size, w._RELEASE.size))
        raw = w.build_ready(installation)
        self.assertEqual(installation, w.parse_ready(raw, binding=context['binding'], now=107.))
        for index, value in ((0, b'AH1CLVY1'), (1, 1), (2, 1), (3, b'f' * 32), (4, b'f' * 64),
                             (5, float('nan')), (6, 701.)):
            self.refused(w.parse_ready, changed(raw, w._READY, index, value), binding=context['binding'], now=107.)
        for now in (True, 99., 701., float('inf')):
            self.refused(w.parse_ready, raw, binding=context['binding'], now=now)
        for bad in (raw[:-1], raw + b'\0', bytearray(raw)):
            self.refused(w.parse_ready, bad, binding=context['binding'], now=107.)

    def test_read_edit_capture_roundtrip_private_unicode_and_separate_release(self):
        for command in (None, edit_for(sequence=1)):
            capture, context = fixture(command)
            raw = w.build_capture_frame(capture, **context)
            parsed = w.parse_capture_frame(raw, **context)
            self.assertEqual(capture, parsed)
            self.assertEqual(TEXT.encode('utf-8'), parsed.utf8)
            self.assertNotIn('Синтетика', repr(capture)); self.assertNotIn('🔬', repr(capture))
            self.assertEqual(capture.body_sha256, hashlib.sha256(capture.utf8).hexdigest())
            release = release_for(capture, context['now'])
            released = w.parse_release(w.build_release(release, capture=capture, **context), capture=capture, **context)
            snapshot = w.finish_capture(capture, released, **context)
            self.assertEqual(capture.utf8, snapshot.utf8)
            self.assertNotIn('Синтетика', repr(snapshot))
            with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
                capture.job.direct_reads = 999

    def test_full_binding_request_target_schema_and_json_duplicates(self):
        capture, context = fixture(); raw = w.build_capture_frame(capture, **context); original, body = metadata(raw)
        for key, value in (('root_uuid', OTHER), ('process_id', True), ('gui_thread_id', 1), ('birth', 'f' * 16),
            ('operation_id', 'f' * 32), ('scope_sha256', 'f' * 64), ('reader_source_sha256', 'f' * 64),
            ('compiled_source_sha256', 'f' * 64), ('source_domain', 'saved'), ('installed_at', 101.),
            ('installation_valid_until', 699.), ('opcode', 2), ('sequence', True), ('revision', 2),
            ('nonce', 'f' * 32), ('object_uuid', OTHER), ('class_uuid', OTHER), ('property_uuid', OTHER),
            ('kind', 'OTHER'), ('version', True), ('unknown', 1)):
            row = dict(original); row[key] = value
            self.refused(w.parse_capture_frame, raw_frame(row, body, capture.command), **context)
        for nested in ('job', 'closure'):
            row = dict(original); row[nested] = dict(row[nested], unknown=1)
            self.refused(w.parse_capture_frame, raw_frame(row, body, capture.command), **context)
        encoded = json.dumps(original, separators=(',', ':')).encode()
        duplicate = encoded[:-1] + b',"version":3}'
        raw = w._HEADER.pack(w.FRAME_MAGIC, 3, 1, 1, len(duplicate), len(body), 0) + duplicate + body
        self.refused(w.parse_capture_frame, raw, **context)
        row = dict(original); row['sampled_at'] = float('nan')
        self.refused(w.parse_capture_frame, raw_frame(row, body, capture.command), **context)

    def test_body_hash_encoding_shape_bound_and_states(self):
        capture, context = fixture()
        for changes in ({'utf8': b'\xff'}, {'utf8': b'a\0b'}, {'body_sha256': 'f' * 64},
                        {'utf16_units': True}, {'bom_present': False}, {'crlf_count': True}, {'ends_lf': False},
                        {'utf8': b'x' * (w.MAX_BODY_BYTES + 1)}, {'before_state': list(STATE)},
                        {'after_state': STATE[:-1]}, {'middle_state': STATE}):
            self.refused(w.build_capture_frame, replace(capture, **changes), **context)
        state = list(STATE); state[0] = 65535
        self.refused(w.build_capture_frame, replace(capture, before_state=tuple(state), after_state=tuple(state)), **context)
        state = list(STATE); state[19] = True
        self.refused(w.build_capture_frame, replace(capture, before_state=tuple(state), after_state=tuple(state)), **context)
        empty = capture_for(capture.command, capture.installation, context['now'], body=b'')
        self.assertEqual(empty, w.parse_capture_frame(w.build_capture_frame(empty, **context), **context))

    def test_read_ownership_metadata_is_honest_and_capability_requires_own_clean(self):
        capture, context = fixture()
        snapshot = w.finish_capture(capture, release_for(capture, context['now']), **context)
        self.assertEqual(c.EditCapability(capture.binding, capture.target, ACTOR), w.capability_from_read(snapshot))
        self.assertIsNone(capture.job.initial_redo)
        own_zero = replace(capture, owner_version=0)
        zero_frame = w.build_capture_frame(own_zero, **context)
        parsed_zero = w.parse_capture_frame(zero_frame, **context)
        self.assertEqual(0, parsed_zero.owner_version)
        own_zero_snapshot = w.finish_capture(parsed_zero, release_for(parsed_zero, context['now']), **context)
        self.refused(w.capability_from_read, own_zero_snapshot)
        for owner_class, owner_uuid, version in ((0, w.NIL_UUID, 0), (2, OTHER, 77)):
            other = replace(capture, owner_class=owner_class, owner_uuid=owner_uuid, owner_version=version)
            other_snapshot = w.finish_capture(other, release_for(other, context['now']), **context)
            self.refused(w.capability_from_read, other_snapshot)
        for changes in ({'owner_class': True}, {'owner_class': 1, 'owner_uuid': OTHER}, {'actor_uuid': w.NIL_UUID},
                        {'owner_class': 0, 'owner_uuid': ACTOR}, {'owner_version': True}):
            self.refused(w.build_capture_frame, replace(capture, **changes), **context)
        dirty = list(STATE); dirty[11] = 1
        other = replace(capture, before_state=tuple(dirty), after_state=tuple(dirty))
        other_snapshot = w.finish_capture(other, release_for(other, context['now']), **context)
        self.refused(w.capability_from_read, other_snapshot)

    def test_not_queried_read_completes_ack_release_totals_and_normal_close_without_capability(self):
        known,context = fixture()
        capture = capture_for(known.command,known.installation,context['now'],owner_not_queried=True)
        self.assertEqual((w.NIL_UUID,w.NIL_UUID,3,0,0,0),
            (capture.actor_uuid,capture.owner_uuid,capture.owner_class,capture.owner_version,
             capture.job.statistic_queries,capture.job.statistic_verified))
        raw = w.build_capture_frame(capture,**context)
        parsed = w.parse_capture_frame(raw,**context)
        self.assertEqual(parsed,capture);self.assertEqual(parsed.status,'READ')
        self.assertEqual(parsed.utf8,TEXT.encode('utf8'))
        self.assertEqual(parsed.before_state,parsed.after_state)
        ack = w.build_ack(parsed.command,parsed.body_sha256,accepted=True)
        self.assertIs(w.parse_ack(ack,command=parsed.command,body_sha256=parsed.body_sha256),True)
        release = release_for(parsed,context['now'])
        released = w.parse_release(w.build_release(release,capture=parsed,**context),capture=parsed,**context)
        snapshot = w.finish_capture(parsed,released,**context)
        with self.assertRaisesRegex(w.EditorTransportRefusal,'^EDITOR_TRANSPORT_CAPABILITY_NOT_QUERIED$'):
            w.capability_from_read(snapshot)
        totals = w.advance_totals(w.EditorTotals(),snapshot)
        self.assertEqual((1,1,0,2,0,0),(totals.total_commands,totals.total_reads,totals.total_edits,
            totals.total_direct_reads,totals.total_source_writes,totals.total_undo_attempts))
        close_command = c.EditorCommand(c.CLOSE,parsed.binding,None,2,0,'f'*32)
        close_context = dict(binding=parsed.binding,installation=parsed.installation,command=close_command,
            now=108.,previous_sequence=1,used_nonces=(parsed.command.nonce,))
        close = close_for(close_command,parsed.installation,totals,108.)
        closed = w.parse_close_frame(w.build_close_frame(close,expected_totals=totals,**close_context),
            expected_totals=totals,**close_context)
        final_release = release_for(closed,108.)
        self.assertEqual(final_release,w.parse_release(w.build_release(final_release,capture=closed,
            expected_totals=totals,**close_context),capture=closed,expected_totals=totals,**close_context))
        self.assertFalse(closed.retained_unknown);self.assertFalse(closed.job_active)
        self.assertTrue(closed.callback_quiesced)

    def test_not_queried_read_admits_only_canonical_nil_zero_and_no_statistic(self):
        known,context = fixture()
        capture = capture_for(known.command,known.installation,context['now'],owner_not_queried=True)
        raw = w.build_capture_frame(capture,**context);original,body = metadata(raw)
        for key,value in (('actor_uuid',ACTOR),('owner_uuid',ACTOR),('actor_uuid','{'+w.NIL_UUID+'}'),
            ('owner_uuid',None),('owner_version',1),('owner_version',True),('owner_class',True),
            ('owner_class',3.0),('owner_class','3'),('owner_class',4),('status','UNKNOWN')):
            row = dict(original);row[key] = value
            with self.subTest(key=key,value=value):
                self.refused(w.parse_capture_frame,raw_frame(row,body,capture.command),**context)
        for key,value in (('statistic_queries',1),('statistic_verified',1),('statistic_queries',False),
                          ('statistic_verified',False),('setter_attempts',1),('source_writes',1)):
            with self.subTest(fact=key,value=value):
                self.refused(w.build_capture_frame,replace(capture,job=replace(capture.job,**{key:value})),**context)

    def test_not_queried_owner_does_not_weaken_known_read_edit_or_uuid_domains(self):
        known,context = fixture()
        for owner_class in (0,1,2):
            capture = replace(known,owner_class=owner_class,owner_uuid=w.NIL_UUID if owner_class==0 else ACTOR if owner_class==1 else OTHER)
            # Known observations retain their old verified one-query contract.
            w.build_capture_frame(capture,**context)
            self.refused(w.build_capture_frame,replace(capture,actor_uuid=w.NIL_UUID),**context)
            self.refused(w.build_capture_frame,replace(capture,job=replace(capture.job,statistic_queries=0,statistic_verified=0)),**context)
        edit,edit_context = fixture(edit_for(sequence=1))
        self.refused(w.build_capture_frame,replace(edit,actor_uuid=w.NIL_UUID,owner_uuid=w.NIL_UUID,
            owner_class=3,owner_version=0,job=replace(edit.job,statistic_queries=0,statistic_verified=0)),**edit_context)
        self.assertFalse(c._uuid(w.NIL_UUID))
        self.refused(w.build_capture_frame,replace(known,command=replace(known.command,
            target=replace(known.target,object_uuid=w.NIL_UUID))),**context)

    def test_not_queried_read_keeps_all_body_closure_state_and_release_guards(self):
        known,context = fixture()
        capture = capture_for(known.command,known.installation,context['now'],owner_not_queried=True)
        for changes in ({'utf8':b'changed'},{'body_sha256':'f'*64},{'after_state':STATE[:-1]},
                        {'baseline_sha256':'f'*64},{'candidate_sha256':'f'*64}):
            self.refused(w.build_capture_frame,replace(capture,**changes),**context)
        for key in w.CLOSURE_KEYS:
            value = getattr(capture.closure,key)
            self.refused(w.build_capture_frame,replace(capture,
                closure=replace(capture.closure,**{key:1 if type(value) is bool else True})),**context)
        release = release_for(capture,context['now'])
        for key in ('ack_accepted','borrow_returned','buffers_freed','io_drained','context_closed','function_closed','callback_quiesced'):
            self.refused(w.finish_capture,capture,replace(release,**{key:False}),**context)

    def test_read_with_ownership_requires_verified_known_result_and_can_admit_only_own(self):
        binding = binding_for()
        command = c.EditorCommand(c.READ_MODULE,binding,target_for(),1,1,'1'*32,c.READ_WITH_OWNERSHIP)
        capture,context = fixture(command)
        for owner_class,owner_uuid,version in ((0,w.NIL_UUID,0),(1,ACTOR,42),(2,OTHER,77)):
            observed = replace(capture,owner_class=owner_class,owner_uuid=owner_uuid,owner_version=version)
            raw = w.build_capture_frame(observed,**context)
            parsed = w.parse_capture_frame(raw,**context)
            self.assertEqual(parsed.command.policy,c.READ_WITH_OWNERSHIP)
            self.assertEqual((parsed.job.statistic_queries,parsed.job.statistic_verified),(1,1))
            snapshot = w.finish_capture(parsed,release_for(parsed,context['now']),**context)
            if owner_class == 1:
                self.assertEqual(w.capability_from_read(snapshot),c.EditCapability(binding,command.target,ACTOR))
            else:
                self.refused(w.capability_from_read,snapshot)
        unknown = capture_for(command,capture.installation,context['now'],owner_not_queried=True)
        with self.assertRaisesRegex(w.EditorTransportRefusal,'OWNER_NOT_QUERIED_POLICY'):
            w.build_capture_frame(unknown,**context)
        for key in ('statistic_queries','statistic_verified'):
            self.refused(w.build_capture_frame,replace(capture,job=replace(capture.job,**{key:0})),**context)
        # A policy2 outstanding request cannot accept fast READ's NIL facts,
        # even when the rest of the actual response identity is identical.
        fast = replace(command,policy=0)
        fast_capture = capture_for(fast,capture.installation,context['now'],owner_not_queried=True)
        frame = w.build_capture_frame(fast_capture,**dict(context,command=fast))
        self.refused(w.parse_capture_frame,frame,**context)

    def test_edit_requires_own_setter_undo_restore_cas_and_honest_redo(self):
        capture, context = fixture(edit_for(sequence=1))
        for key in w.JOB_KEYS:
            value = getattr(capture.job, key)
            self.refused(w.build_capture_frame, replace(capture, job=replace(capture.job, **{key: True if value == 1 else 999})), **context)
        for changes in ({'owner_uuid': OTHER}, {'owner_version': 43}, {'actor_uuid': OTHER},
                        {'baseline_sha256': 'f' * 64}, {'candidate_sha256': 'f' * 64}, {'status': 'UNKNOWN'}):
            self.refused(w.build_capture_frame, replace(capture, **changes), **context)
        state = list(STATE); state[20] = 1; state[21] = 4
        bad_command = replace(capture.command, expected_state=tuple(state))
        bad = capture_for(bad_command, capture.installation, context['now'])
        self.refused(w.build_capture_frame, bad, **{**context, 'command': bad_command})
        state = list(capture.middle_state); state[21] = 7
        self.refused(w.build_capture_frame, replace(capture, middle_state=tuple(state)), **context)
        self.refused(w.build_capture_frame, capture, **{**context, 'capability': None})

    def test_capture_time_replay_and_closure_boolean_spoof(self):
        capture, context = fixture()
        for changes in ({'sampled_at': float('nan')}, {'issued_at': 99.}, {'valid_until': 800.}, {'valid_until': 106.}):
            self.refused(w.build_capture_frame, replace(capture, **changes), **context)
        for key in w.CLOSURE_KEYS:
            value = getattr(capture.closure, key)
            wrong = 1 if type(value) is bool else True
            self.refused(w.build_capture_frame, replace(capture, closure=replace(capture.closure, **{key: wrong})), **context)
        self.refused(w.build_capture_frame, capture, **{**context, 'previous_sequence': 1})
        self.refused(w.build_capture_frame, capture, **{**context, 'used_nonces': (capture.command.nonce,)})
        self.refused(w.build_capture_frame, capture, **{**context, 'now': True})
        spoof = replace(capture, command=replace(capture.command, sequence=True))
        self.refused(w.build_capture_frame, spoof, **context)

    def test_header_bounds_old_protocol_truncated_and_trailing(self):
        capture, context = fixture(); raw = w.build_capture_frame(capture, **context)
        header = raw[:32]
        for index, value in ((0, b'AH1CLVF1'), (1, 1), (2, 2), (3, 2), (4, 1),
                             (4, w.MAX_METADATA_BYTES + 1), (5, w.MAX_BODY_BYTES + 1), (6, 1)):
            self.refused(w.parse_response_header, changed(header, w._HEADER, index, value), command=capture.command)
        for bad in (raw[:31], raw[:-1], raw + b'\0', bytearray(raw)):
            self.refused(w.parse_capture_frame, bad, **context)

    def test_ack_explicit_acceptance_and_full_release_joins(self):
        capture, context = fixture(); command = capture.command
        for accepted in (True, False):
            raw = w.build_ack(command, capture.body_sha256, accepted=accepted)
            self.assertIs(accepted, w.parse_ack(raw, command=command, body_sha256=capture.body_sha256))
        self.refused(w.build_ack, command, capture.body_sha256, accepted=1)
        raw = w.build_ack(command, capture.body_sha256, accepted=True)
        for index, value in ((0, b'AH1CLVA1'), (1, 1), (2, 2), (3, 2), (4, 2), (5, b'f' * 32), (6, b'f' * 64)):
            self.refused(w.parse_ack, changed(raw, w._ACK, index, value), command=command, body_sha256=capture.body_sha256)
        release = release_for(capture, context['now']); raw = w.build_release(release, capture=capture, **context)
        for index, value in ((0, b'AH1CLVJ1'), (1, 1), (2, 2), (3, 2), (4, 0), (5, b'f' * 32),
                             (6, b'f' * 32), (7, b'f' * 64), (8, float('nan')), (8, 108.)):
            self.refused(w.parse_release, changed(raw, w._RELEASE, index, value), capture=capture, **context)
        for key in ('ack_accepted', 'borrow_returned', 'buffers_freed', 'io_drained', 'context_closed', 'function_closed', 'callback_quiesced'):
            self.refused(w.finish_capture, capture, replace(release, **{key: False}), **context)
        self.refused(w.advance_totals, w.EditorTotals(), capture)

    def test_cumulative_close_counts_real_edit_and_release_after_ack(self):
        read, read_ctx = fixture()
        snapshot = w.finish_capture(read, release_for(read, read_ctx['now']), **read_ctx)
        totals = w.advance_totals(w.EditorTotals(), snapshot)
        edit, edit_ctx = fixture(edit_for())
        snapshot = w.finish_capture(edit, release_for(edit, edit_ctx['now']), **edit_ctx)
        totals = totals.after(snapshot)
        self.assertEqual((2, 1, 1, 8, 1, 1, 1), (totals.total_commands, totals.total_reads, totals.total_edits,
            totals.total_direct_reads, totals.total_source_writes, totals.total_setter_attempts, totals.total_undo_attempts))
        close_command = c.EditorCommand(c.CLOSE, read.binding, None, 3, 0, 'f' * 32)
        context = dict(binding=read.binding, installation=read.installation, command=close_command,
                       now=750., previous_sequence=2)
        close = close_for(close_command, read.installation, totals, context['now'])
        raw = w.build_close_frame(close, expected_totals=totals, **context)
        parsed = w.parse_close_frame(raw, expected_totals=totals, **context)
        self.assertEqual(close, parsed)
        release = release_for(close, context['now'])
        raw_release = w.build_release(release, capture=close, expected_totals=totals, **context)
        self.assertEqual(b'\0' * 32, w._RELEASE.unpack(raw_release)[6])
        self.assertEqual(release, w.parse_release(raw_release, capture=close, expected_totals=totals, **context))
        self.refused(w.parse_close_frame, raw, expected_totals=w.EditorTotals(), **context)
        self.refused(w.build_close_frame, replace(close, totals=replace(totals, total_source_writes=0)), expected_totals=totals, **context)
        for changes in ({'retained_unknown': True}, {'job_active': True}, {'callback_quiesced': 1}, {'contexts_live': True}):
            self.refused(w.build_close_frame, replace(close, **changes), expected_totals=totals, **context)
        self.refused(w.build_close_frame, close, expected_totals=totals, **{**context, 'now': 761.})
        self.refused(w.advance_totals, totals, snapshot)

    def test_close_empty_history_and_schema_boolean_counts(self):
        binding = binding_for(); installation = w.EditorInstallation(binding, 100., 700.)
        command = c.EditorCommand(c.CLOSE, binding, None, 1, 0, 'f' * 32)
        totals = w.EditorTotals(); close = close_for(command, installation, totals, 107.)
        context = dict(binding=binding, installation=installation, command=command, now=107., previous_sequence=0)
        raw = w.build_close_frame(close, expected_totals=totals, **context); row, body = metadata(raw)
        for name, value in (('total_source_writes', True), ('last_command_sequence', True),
                            ('retained_unknown', 0), ('closed_at', float('nan')), ('unknown', 0)):
            bad = dict(row); bad[name] = value
            self.refused(w.parse_close_frame, raw_frame(bad, body, command), expected_totals=totals, **context)
        self.refused(w.build_ack, command, hashlib.sha256(b'other').hexdigest(), accepted=True)


if __name__ == '__main__':
    unittest.main()
