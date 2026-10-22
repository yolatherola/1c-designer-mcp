"""V3 codec tests use synthetic editor bytes only; no native/SDK/Gold calls."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from native_mcp import editor_command as w

TEXT = '\ufeffПроцедура Проба()\r\n    // синтетический 🔬\r\nКонецПроцедуры\r\n'
ACTOR = 'cab12345-1234-4567-89ab-cdef01234567'


def fixture():
    binding = w.EditorBinding(w.ROOT_UUID, 1234, '01dd5fb7f0cd1090', 5678,
                              'a' * 32, 'b' * 64, 'c' * 64, 'd' * 64)
    target = w.EditorTarget('d593e80d-b70c-400b-9955-d02f7a4c89e9',
                            'a87c7b15-106f-4c92-a7f3-68c02cc686d9',
                            'a637f77f-3840-441d-a1c3-699c8c5cb7e0')
    state = tuple(0x10000 + i * 16 for i in range(8)) + (1, 0, 1, 0, 0, 1, 2, 3, 4, 5, 6, 0, 0, 0xffffffff)
    command = w.EditorCommand(w.EDIT_MODULE, binding, target, 1, 7, 'e' * 32,
        w.EDIT_VERIFY_UNDO, ACTOR, 42, state, w.ModuleText.from_text(TEXT),
        w.ModuleText.from_text(TEXT + '// bounded own test\r\n'))
    return command, w.EditCapability(binding, target, ACTOR)


def activation_fixture():
    edit, _ = fixture()
    state = list(edit.expected_state)
    for i in (8, 9, 10, 11, 19, 20):
        state[i] = 0
    state[12] = 1
    sha = edit.baseline.sha256
    command = w.EditorCommand(w.ACTIVATE_OWN6, edit.binding, edit.target, 2, 7, 'f' * 32,
        expected_owner=ACTOR, expected_version=42, expected_state=tuple(state),
        expected_source_sha256=sha)
    capability = w.ActivationCapability(edit.binding, edit.target, ACTOR, 42, sha, '8' * 32, '9' * 64)
    return command, capability


def build(command, capability=None, **kwargs):
    return w.build_command(command, binding=command.binding, previous_sequence=command.sequence - 1,
                           capability=capability, **kwargs)


def parse(frame, command, capability=None, **kwargs):
    return w.parse_command(frame, binding=command.binding, expected_command=command,
                           previous_sequence=command.sequence - 1, capability=capability, **kwargs)


def mutate(frame, name, value):
    values = list(w._HEADER.unpack(frame[:w.HEADER_BYTES]))
    values[[name for name, _ in w.HEADER_LAYOUT].index(name)] = value
    return w._HEADER.pack(*values) + frame[w.HEADER_BYTES:]


class EditorCommandTests(unittest.TestCase):
    def refused(self, function, *args, **kwargs):
        with self.assertRaises(w.EditorCommandRefusal) as caught:
            function(*args, **kwargs)
        error = caught.exception
        self.assertRegex(str(error), '^EDITOR_COMMAND_[A-Z_]+$')
        self.assertNotIn('синтетический', str(error))
        self.assertNotIn('bounded own test', str(error))
        self.assertIsNone(error.__context__)
        return str(error)

    def test_activation_exact_bodyless_roundtrip_and_private_root_capability(self):
        command, cap = activation_fixture()
        raw = build(command, cap)
        self.assertEqual((6, 512), (command.opcode, len(raw)))
        self.assertIs(command, parse(raw, command, cap))
        self.assertEqual(w._STATE.pack(*command.expected_state), raw[284:372])
        self.assertEqual(bytes(16), raw[372:388])
        self.assertEqual(bytes.fromhex(command.expected_source_sha256), raw[388:420])
        self.assertEqual(bytes(92), raw[420:512])
        self.assertNotIn(bytes.fromhex(cap.prior_capture_operation_id), raw)
        self.assertNotIn(bytes.fromhex(cap.prior_capture_receipt_sha256), raw)
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            cap.owner_uuid = command.target.object_uuid

    def test_activation_requires_exact_out_of_band_admission_and_closed_prior_identity(self):
        command, cap = activation_fixture()
        _, editcap = fixture()
        for wrong in (None, {}, editcap, replace(cap, owner_uuid=command.target.object_uuid),
                      replace(cap, expected_version=43), replace(cap, expected_source_sha256='1' * 64),
                      replace(cap, binding=replace(cap.binding, process_id=4321)),
                      replace(cap, target=replace(cap.target, object_uuid=ACTOR)),
                      replace(cap, prior_capture_operation_id=cap.binding.operation_id),
                      replace(cap, prior_capture_operation_id='0' * 32),
                      replace(cap, prior_capture_receipt_sha256='0' * 64),
                      replace(cap, expected_version=0), replace(cap, expected_version=True),
                      replace(cap, expected_version=0x80000000)):
            self.refused(build, command, wrong)
        for changes in ({'policy': 1}, {'baseline': fixture()[0].baseline},
                        {'candidate': fixture()[0].candidate}, {'expected_source_sha256': None},
                        {'expected_source_sha256': '0' * 64}, {'expected_owner': None},
                        {'expected_version': True}):
            self.refused(build, replace(command, **changes), cap)

    def test_activation_header_tamper_sequence_replay_and_clean_readonly_state(self):
        command, cap = activation_fixture(); raw = build(command, cap)
        for name, value in (('opcode', 5), ('policy', 1), ('expected_owner', bytes(16)),
                            ('expected_version', 43), ('baseline_sha256', b'1' * 32),
                            ('candidate_sha256', b'1' * 32), ('baseline_bytes', 1),
                            ('candidate_units', 1), ('expected_state', bytes(88)),
                            ('reserved', b'x' + bytes(59))):
            self.refused(parse, mutate(raw, name, value), command, cap)
        self.refused(parse, raw + b'x', command, cap)
        self.refused(build, command, cap, used_nonces=(command.nonce,))
        self.refused(w.parse_command, raw, binding=command.binding, expected_command=command,
                     previous_sequence=0, capability=cap)
        for i in (8, 9, 10, 11, 12, 19, 20):
            state = list(command.expected_state); state[i] = 1 - state[i]
            self.refused(build, replace(command, expected_state=tuple(state)), cap)
        self.refused(build, replace(command, expected_state=command.expected_state[:-1]), cap)
        maximum = replace(command, expected_version=0x7fffffff)
        maximum_cap = replace(cap, expected_version=0x7fffffff)
        self.assertEqual(maximum, parse(build(maximum, maximum_cap), maximum, maximum_cap))

    def test_source_hash_extension_is_forbidden_on_every_legacy_opcode(self):
        edit, cap = fixture()
        for opcode in (w.READ_MODULE, w.EDIT_MODULE, w.CLOSE, w.READ_REPOSITORY_MODULE, w.CAPTURE_ONLY):
            command = edit if opcode == w.EDIT_MODULE else w.EditorCommand(
                opcode, edit.binding, None if opcode == w.CLOSE else edit.target, 1,
                0 if opcode == w.CLOSE else 7, '7' * 32)
            self.assertIsNone(command.expected_source_sha256)
            self.refused(build, replace(command, expected_source_sha256='1' * 64), cap)

    def test_all_legacy_synthetic_frames_match_pre_activation_codec_bytes(self):
        # Measured from the frozen 46b90607 codec before opcode6 integration.
        # This catches accidental legacy layout/serialization changes.
        expected = {
            (1, 0): 'e250aeb40ba88f2d6715478ccca95bc6ef84d9f5772881c65bed58a097f35dc5',
            (1, 2): '0859553a8d743fd8c28f18ae26fa606b0c29827d9b86bfb1cb351fbf0cec6ec5',
            (2, 1): 'e3226a8a1f921ddd1fd5de8dd4f5fd3c52ad3948385365fe35ba2f74e6d0821c',
            (3, 0): 'e1de91b094373ec572d7d6a2b1a0c9cb85160041d3aacb183e2aff5cddb2322c',
            (4, 0): '017acf85aa6aa06d6b7d92ce1e1f53543bf4994b23a4c1a8b148ff276e789f4d',
            (5, 0): 'f4763270f9ef2399736616d2c0a934d8d001650d68ecec52548d6dbbbceadfa3'}
        edit, cap = fixture()
        for (opcode, policy), sha in expected.items():
            command = edit if opcode == w.EDIT_MODULE else w.EditorCommand(
                opcode, edit.binding, None if opcode == w.CLOSE else edit.target, 1,
                0 if opcode == w.CLOSE else 7, 'e' * 32, policy)
            self.assertEqual(sha, hashlib.sha256(build(command, cap)).hexdigest())

    def test_declarative_layout_is_independent_512_bytes(self):
        self.assertEqual(512, w._HEADER.size)
        self.assertEqual((3, 1, 2, 3, 1), (w.VERSION, w.READ_MODULE, w.EDIT_MODULE, w.CLOSE, w.EDIT_VERIFY_UNDO))
        self.assertEqual({'magic': 0, 'version': 8, 'opcode': 10, 'policy': 12, 'root_uuid': 16,
            'process_id': 32, 'birth': 36, 'gui_thread_id': 44, 'operation_id': 48,
            'scope_sha256': 64, 'source_sha256': 96, 'compiled_sha256': 128,
            'source_domain': 160, 'object_uuid': 192, 'class_uuid': 208, 'property_uuid': 224,
            'sequence': 240, 'revision': 244, 'nonce': 248, 'expected_owner': 264,
            'expected_version': 280, 'expected_state': 284, 'baseline_bytes': 372,
            'candidate_bytes': 376, 'baseline_units': 380, 'candidate_units': 384,
            'baseline_sha256': 388, 'candidate_sha256': 420, 'reserved': 452}, w.OFFSETS)
        self.assertFalse(any('pointer' in name or 'address' in name for name in w.OFFSETS))

    def test_exact_unicode_bom_crlf_roundtrip_and_both_hashes(self):
        command, cap = fixture()
        raw = build(command, cap)
        self.assertIs(command, parse(raw, command, cap))
        self.assertEqual(TEXT.encode('utf-8'), command.baseline.utf8)
        self.assertEqual(len(TEXT.encode('utf-16-le')) // 2, command.baseline.utf16_units)
        self.assertEqual(hashlib.sha256(TEXT.encode('utf-8')).hexdigest(), command.baseline.sha256)
        self.assertEqual(raw[512:], command.baseline.utf8 + command.candidate.utf8)
        self.assertEqual(bytes.fromhex(command.target.object_uuid.replace('-', '')), raw[192:208])
        self.assertEqual(bytes.fromhex(ACTOR.replace('-', '')), raw[264:280])

    def test_repository_read_is_explicit_bodyless_and_cannot_smuggle_edit_authority(self):
        edit, cap = fixture()
        command = w.EditorCommand(w.READ_REPOSITORY_MODULE, edit.binding, edit.target, 1, 7, '9' * 32)
        raw = build(command)
        self.assertEqual(len(raw), w.HEADER_BYTES)
        self.assertEqual(raw[264:], bytes(w.HEADER_BYTES - 264))
        self.assertIs(parse(raw, command), command)
        for invalid in (replace(command, policy=w.READ_WITH_OWNERSHIP),
                        replace(command, expected_owner=ACTOR), replace(command, expected_version=42),
                        replace(command, baseline=edit.baseline), replace(command, candidate=edit.candidate),
                        replace(command, expected_state=edit.expected_state)):
            with self.subTest(field=invalid):
                self.refused(build, invalid, cap)
        for offset in (w.OFFSETS['expected_owner'], w.OFFSETS['expected_version'],
                       w.OFFSETS['baseline_bytes'], w.OFFSETS['reserved']):
            changed = bytearray(raw); changed[offset] = 1
            self.refused(parse, bytes(changed), command)

    def test_typed_records_are_frozen_and_payload_is_private_in_repr(self):
        command, cap = fixture()
        for value in (command, cap, command.binding, command.target, command.baseline):
            self.assertNotIn('синтетический', repr(value))
            self.assertNotIn('bounded own test', repr(value))
            with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
                value.injected = 1
        self.assertNotIn('_utf8=', repr(command.baseline))
        self.assertNotIn('baseline=', repr(command))

    def test_capture_only_bodyless_scope_never_accepts_refresh_or_edit_payload(self):
        edit, cap = fixture()
        capture = w.EditorCommand(w.CAPTURE_ONLY, edit.binding, edit.target, 1, 7, '9' * 32)
        raw = build(capture)
        self.assertEqual(512, len(raw))
        self.assertEqual(bytes(248), raw[264:])
        self.assertIs(capture, parse(raw, capture))
        # Capture authorization belongs to the owner scope, never this frame.
        for changes in ({'policy': w.READ_WITH_OWNERSHIP}, {'expected_owner': ACTOR},
                        {'expected_version': 42}, {'expected_state': edit.expected_state},
                        {'baseline': edit.baseline}, {'candidate': edit.candidate}):
            with self.subTest(fields=tuple(changes)):
                self.refused(build, replace(capture, **changes), cap)
        for name, value in (('expected_owner', b'1' * 16), ('reserved', b'1' * 60),
                            ('baseline_sha256', b'1' * 32)):
            self.refused(parse, mutate(raw, name, value), capture)
        self.refused(parse, raw, replace(capture, target=replace(capture.target, object_uuid=ACTOR)))

    def test_read_and_close_have_no_edit_metadata_or_body(self):
        edit, cap = fixture()
        read = w.EditorCommand(w.READ_MODULE, edit.binding, edit.target, 1, 1, '1' * 32)
        close = w.EditorCommand(w.CLOSE, edit.binding, None, 65, 0, '2' * 32)
        for command in (read, replace(read,policy=w.READ_WITH_OWNERSHIP), close):
            raw = build(command)
            self.assertEqual(512, len(raw))
            self.assertEqual(command, parse(raw, command))
            for changes in ({'baseline': edit.baseline}, {'candidate': edit.candidate},
                            {'expected_owner': ACTOR}, {'expected_version': 1},
                            {'expected_state': edit.expected_state}, {'policy': 1}):
                self.refused(build, replace(command, **changes), cap)
        self.refused(build, replace(close, target=edit.target))
        self.refused(build, replace(close, revision=1))
        self.refused(build, replace(read, target=None))
        self.assertEqual(w.READ_WITH_OWNERSHIP,2)
        for policy in (1,3,0xffffffff):
            self.refused(build,replace(read,policy=policy))
        self.refused(build,replace(close,policy=w.READ_WITH_OWNERSHIP))

    def test_edit_requires_out_of_band_exact_capability(self):
        command, cap = fixture()
        for wrong in (None, {}, command, replace(cap, owner_uuid=command.target.object_uuid),
                      replace(cap, target=replace(cap.target, object_uuid=ACTOR)),
                      replace(cap, binding=replace(cap.binding, process_id=4321))):
            self.refused(build, command, wrong)
        self.refused(build, replace(command, policy=2), cap)
        self.refused(build, replace(command, candidate=command.baseline), cap)
        # Root can explicitly admit another exact target; codec does not bake in a product fixture.
        other = replace(command.target, object_uuid=ACTOR)
        issued = replace(command, target=other)
        self.assertEqual(issued, parse(build(issued, replace(cap, target=other)), issued, replace(cap, target=other)))

    def test_all_binding_and_target_joins_are_exact(self):
        command, cap = fixture()
        raw = build(command, cap)
        for changes in ({'root_uuid': ACTOR}, {'process_id': 4321}, {'birth': '1' * 16},
                        {'gui_thread_id': 8765}, {'operation_id': 'f' * 32},
                        {'scope_sha256': '1' * 64}, {'source_sha256': '2' * 64},
                        {'compiled_sha256': '3' * 64}, {'source_domain': 'saved'}):
            other = replace(command.binding, **changes)
            self.refused(w.build_command, command, binding=other, previous_sequence=0, capability=cap)
        for field in ('object_uuid', 'class_uuid', 'property_uuid'):
            wrong = replace(command, target=replace(command.target, **{field: ACTOR}))
            self.refused(parse, raw, wrong, replace(cap, target=wrong.target))

    def test_strict_uuids_hex_domain_and_boolean_integer_rejection(self):
        command, cap = fixture()
        for field, value in (('process_id', True), ('gui_thread_id', False), ('birth', '0' * 16),
                             ('operation_id', 'F' * 32), ('scope_sha256', '0' * 64),
                             ('source_sha256', 123), ('compiled_sha256', 'c' * 63),
                             ('source_domain', b'editor_live_at_capture')):
            bad = replace(command.binding, **{field: value})
            self.refused(build, replace(command, binding=bad), replace(cap, binding=bad))
        for field in ('object_uuid', 'class_uuid', 'property_uuid'):
            for value in (True, '0' * 32, ACTOR.upper(), '00000000-0000-0000-0000-000000000000'):
                bad = replace(command.target, **{field: value})
                self.refused(build, replace(command, target=bad), replace(cap, target=bad))
        for field in ('opcode', 'sequence', 'revision', 'policy', 'expected_version'):
            self.refused(build, replace(command, **{field: True}), cap)
        for field, value in (('sequence', 0), ('revision', 0), ('expected_version', 0),
                             ('expected_version', 2**32), ('nonce', '0' * 32), ('nonce', 'E' * 32)):
            self.refused(build, replace(command, **{field: value}), cap)

    def test_full22state_word_bounds_flags_and_undo_sentinel(self):
        command, cap = fixture()
        for bad in (list(command.expected_state), command.expected_state[:-1], command.expected_state + (0,)):
            self.refused(build, replace(command, expected_state=bad), cap)
        for index, value in ((0, 65535), (1, 2**32), (2, True), (8, 2), (9, -1),
                             (10, 2), (11, 2), (12, 2), (19, 2), (20, 2), (21, 4)):
            bad = list(command.expected_state); bad[index] = value
            self.refused(build, replace(command, expected_state=tuple(bad)), cap)
        state = list(command.expected_state); state[20] = 1; state[21] = 4
        issued = replace(command, expected_state=tuple(state))
        self.assertEqual(issued, parse(build(issued, cap), issued, cap))

    def test_utf8_utf16_bounds_invalid_encoding_nul_and_digest_spoof(self):
        at_limit = w.ModuleText.from_text('🔬' * (w.MAX_UTF16_UNITS // 2))
        self.assertEqual(w.MAX_UTF16_UNITS, at_limit.utf16_units)
        for bad in ('x' * (w.MAX_UTF16_UNITS + 1), '🔬' * (w.MAX_UTF16_UNITS // 2 + 1),
                    '\ud800', '\udfff', 'a\0b'):
            self.refused(w.ModuleText.from_text, bad)
        for bad in (b'\xed\xa0\x80', b'\xc0\x80', b'\xff', b'\xf0\x9f',
                    b'a\0b', bytearray(b'a'), b'x' * (w.MAX_UTF8_BYTES + 1)):
            self.refused(w.ModuleText.from_utf8, bad)
        command, cap = fixture()
        for forged in (replace(command.baseline, sha256='1' * 64),
                       replace(command.baseline, utf16_units=True),
                       replace(command.baseline, utf16_units=1)):
            self.refused(build, replace(command, baseline=forged), cap)
        empty = replace(command, baseline=w.ModuleText.from_utf8(b''))
        self.assertEqual(empty, parse(build(empty, cap), empty, cap))

    def test_old_magic_versions_unknown_opcode_and_every_header_join(self):
        command, cap = fixture(); raw = build(command, cap)
        changes = {'magic': b'AH1CLVC1', 'version': 1, 'opcode': 77, 'policy': 2,
            'root_uuid': b'1' * 16, 'process_id': 4321, 'birth': 1, 'gui_thread_id': 1,
            'operation_id': b'1' * 16, 'scope_sha256': b'1' * 32, 'source_sha256': b'1' * 32,
            'compiled_sha256': b'1' * 32, 'source_domain': b'saved'.ljust(32, b'\0'),
            'object_uuid': b'1' * 16, 'class_uuid': b'1' * 16, 'property_uuid': b'1' * 16,
            'sequence': 2, 'revision': 8, 'nonce': b'1' * 16, 'expected_owner': b'1' * 16,
            'expected_version': 43, 'expected_state': b'1' * 88, 'baseline_units': 1,
            'candidate_units': 1, 'baseline_sha256': b'1' * 32, 'candidate_sha256': b'1' * 32,
            'reserved': b'x' + b'\0' * 59}
        for name, value in changes.items():
            with self.subTest(name=name):
                self.refused(parse, mutate(raw, name, value), command, cap)
        self.refused(parse, b'AH1CLVC1' + b'\0' * 120, command, cap)

    def test_truncated_trailing_body_lengths_and_tampering(self):
        command, cap = fixture(); raw = build(command, cap)
        for bad in (raw[:511], raw[:512], raw[:-1], raw + b'\0', bytearray(raw)):
            self.refused(parse, bad, command, cap)
        for name in ('baseline_bytes', 'candidate_bytes'):
            self.refused(parse, mutate(raw, name, 0xffffffff), command, cap)
        for name in ('baseline_units', 'candidate_units'):
            self.refused(parse, mutate(raw, name, 0xffffffff), command, cap)
        for index in (512, len(raw) - 1):
            bad = bytearray(raw); bad[index] ^= 1
            self.refused(parse, bytes(bad), command, cap)
        bad = raw[:512] + b'\xff' + raw[513:]
        self.refused(parse, bad, command, cap)

    def test_replay_identity_is_explicit_and_caller_owned(self):
        command, cap = fixture(); raw = build(command, cap)
        self.refused(w.parse_command, raw, binding=command.binding, expected_command=command,
                     previous_sequence=1, capability=cap)
        self.refused(parse, raw, replace(command, nonce='f' * 32), cap)
        self.refused(parse, raw, replace(command, revision=8), cap)
        self.refused(build, command, cap, used_nonces=(command.nonce,))
        self.refused(build, command, cap, used_nonces=('f' * 32, 'f' * 32))
        self.refused(build, command, cap, used_nonces=[])
        self.refused(w.build_command, command, binding=command.binding,
                     previous_sequence=False, capability=cap)
        maximum = replace(command, sequence=64)
        self.assertEqual(maximum, parse(build(maximum, cap), maximum, cap))
        self.refused(build, replace(command, sequence=65), cap)

    def test_unknown_keys_pointer_payloads_are_never_host_schema(self):
        command, cap = fixture()
        for bad in ({'opcode': 2, 'baseline_pointer': 65536},
                    {'command': command, 'candidate_pointer': 65536},
                    {'expected_state_pointer': 65536}, {'unknown': TEXT}):
            self.refused(w.build_command, bad, binding=command.binding,
                         previous_sequence=0, capability=cap)
        self.refused(build, replace(command, baseline=65536), cap)
        self.refused(build, replace(command, candidate=65536), cap)
        self.refused(build, replace(command, expected_state=65536), cap)


if __name__ == '__main__':
    unittest.main()
