"""Synthetic RAM-only source planning; no native, SDK, Gold or body files."""
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import importlib
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from native_mcp import editor_change_plan as p
from native_mcp import editor_command as c
from native_mcp import editor_transport as w


def text(value):
    return c.ModuleText.from_text(value)


def plan(source, replacement, **selector):
    baseline = text(source)
    return p.plan_edit(baseline, baseline.sha256, text(replacement), **selector)


class EditorChangePlanTests(unittest.TestCase):
    def refused(self, function, *args, reason=None, **kwargs):
        with self.assertRaises(p.EditorChangePlanRefusal) as caught:
            function(*args, **kwargs)
        error = caught.exception
        self.assertRegex(str(error), '^EDITOR_CHANGE_PLAN_[A-Z0-9_]+$')
        self.assertIsNone(error.__context__)
        if reason is not None:
            self.assertEqual('EDITOR_CHANGE_PLAN_' + reason, str(error))

    def test_anchor_and_exact_span_produce_identical_deterministic_plan(self):
        baseline = text('prefix СЕКРЕТ 🔬 suffix')
        replacement = text('НОВОЕ')
        first = p.plan_edit(baseline, baseline.sha256, replacement, anchor='СЕКРЕТ 🔬')
        second = p.plan_edit(baseline, baseline.sha256, replacement, utf16_span=(7, 16))
        self.assertEqual(first, second)
        self.assertEqual(first, p.plan_edit(baseline, baseline.sha256, replacement, anchor='СЕКРЕТ 🔬'))
        self.assertEqual('prefix НОВОЕ suffix'.encode(), first.candidate.utf8)
        self.assertEqual(hashlib.sha256(first.candidate.utf8).hexdigest(), first.candidate_sha256)
        self.assertEqual((0, 7, 0, 16),
                         (first.start_line, first.start_column, first.stop_line, first.stop_column))
        self.assertEqual(len(first.candidate.utf8), first.candidate_byte_count)
        self.assertEqual(first.candidate.utf16_units, first.candidate_utf16_units)
        self.assertEqual(replacement.utf16_units, first.replacement_utf16_units)
        first.validate()
        first.assert_baseline(c.ModuleText.from_utf8(bytes(baseline.utf8)))

    def test_utf16_emoji_boundaries_and_byte_offsets(self):
        result = plan('α🔬z', '😀', utf16_span=(1, 3))
        self.assertEqual(('α😀z'.encode(), 1, 3, 2, 6),
                         (result.candidate.utf8, result.start_utf16, result.stop_utf16,
                          result.start_byte, result.stop_byte))
        self.assertEqual((4, 4, 2), (result.baseline_utf16_units,
                         result.candidate_utf16_units, result.replacement_utf16_units))
        for span in ((2, 3), (1, 2), (2, 2)):
            self.refused(plan, 'α🔬z', 'x', utf16_span=span, reason='SURROGATE_BOUNDARY')

    def test_anchor_uniqueness_includes_overlapping_matches(self):
        for source, anchor in (('foo foo', 'foo'), ('aaa', 'aa')):
            self.refused(plan, source, 'x', anchor=anchor, reason='ANCHOR_AMBIGUOUS')
        self.refused(plan, 'source', 'x', anchor='missing', reason='ANCHOR_MISSING')
        for anchor in ('', 1, b'source', '\0', '\ud800'):
            self.refused(plan, 'source', 'x', anchor=anchor, reason='ANCHOR')

    def test_stale_and_malformed_sha_fail_before_deriving_candidate(self):
        baseline = text('СЕКРЕТ')
        self.refused(p.plan_edit, baseline, 'f' * 64, text('НОВОЕ'),
                     anchor='СЕКРЕТ', reason='STALE_BASELINE')
        for digest in (None, {}, 'F' * 64, '1' * 63, 'g' * 64):
            self.refused(p.plan_edit, baseline, digest, text('НОВОЕ'),
                         anchor='СЕКРЕТ', reason='EXPECTED_SHA256')
        result = p.plan_edit(baseline, baseline.sha256, text('НОВОЕ'), anchor='СЕКРЕТ')
        self.refused(result.assert_baseline, text('СЕКРЕТ!'), reason='STALE_BASELINE')
        self.refused(result.assert_baseline, {'utf8': baseline.utf8}, reason='CURRENT_BASELINE')

    def test_exact_span_bounds_and_selector_types(self):
        for span in ((-1, 0), (2, 1), (0, 4)):
            self.refused(plan, 'abc', 'x', utf16_span=span, reason='SPAN_BOUND')
        for span in ([0, 1], (), (0,), (0, 1, 2), (False, 1), (0, 1.0), '0:1'):
            self.refused(plan, 'abc', 'x', utf16_span=span, reason='SPAN')
        self.refused(plan, 'abc', 'x', reason='SELECTOR')
        self.refused(plan, 'abc', 'x', anchor='a', utf16_span=(0, 1), reason='SELECTOR')

    def test_insert_delete_and_empty_baseline_are_reusable(self):
        self.assertEqual(b'abc!', plan('abc', '!', utf16_span=(3, 3)).candidate.utf8)
        self.assertEqual(b'!abc', plan('abc', '!', utf16_span=(0, 0)).candidate.utf8)
        self.assertEqual(b'ab', plan('abc', '', anchor='c').candidate.utf8)
        result = plan('', '🔬', utf16_span=(0, 0))
        self.assertEqual((0, 2, 0, 0), (result.baseline_utf16_units,
            result.candidate_utf16_units, result.start_line, result.start_column))
        self.refused(plan, 'abc', 'a', anchor='a', reason='UNCHANGED')
        self.refused(plan, '', '', utf16_span=(0, 0), reason='UNCHANGED')

    def test_preserves_bom_mixed_eol_and_all_outside_bytes(self):
        source = '\ufeffα\r\nβ\nγ\rδ🔬target\r\nlast'
        result = plan(source, 'замена', anchor='target')
        self.assertEqual((3, 3, 3, 9),
                         (result.start_line, result.start_column, result.stop_line, result.stop_column))
        self.assertEqual(source.replace('target', 'замена').encode(), result.candidate.utf8)
        self.assertTrue(result.candidate.utf8.startswith(b'\xef\xbb\xbf'))
        self.assertEqual(result.baseline.utf8[:result.start_byte], result.candidate.utf8[:result.start_byte])
        self.assertEqual(result.baseline.utf8[result.stop_byte:],
                         result.candidate.utf8[result.start_byte + result.replacement_byte_count:])
        self.assertEqual((2, 1, 1), (result.candidate.utf8.count(b'\r\n'),
            result.candidate.utf8.count(b'\n') - result.candidate.utf8.count(b'\r\n'),
            result.candidate.utf8.count(b'\r') - result.candidate.utf8.count(b'\r\n')))
        result.validate()

    def test_initial_bom_is_protected_and_counted_explicitly(self):
        self.refused(plan, '\ufeffabc', 'x', anchor='\ufeff', reason='BOM_BOUNDARY')
        self.refused(plan, '\ufeffabc', 'x', utf16_span=(0, 0), reason='BOM_BOUNDARY')
        result = plan('\ufeffabc', 'x', anchor='a')
        self.assertEqual((1, 1, 3), (result.start_utf16, result.start_column, result.start_byte))

    def test_unicode_is_not_normalized_or_case_folded(self):
        source = 'e\u0301 É target \u2028'
        result = plan(source, 'é', anchor='target')
        self.assertEqual('e\u0301 É é \u2028'.encode(), result.candidate.utf8)
        self.refused(plan, source, 'x', anchor='é', reason='ANCHOR_MISSING')

    def test_crlf_cannot_be_split_even_by_empty_insertion(self):
        for span in ((2, 2), (1, 2), (2, 3)):
            self.refused(plan, 'a\r\nb', 'x', utf16_span=span, reason='CRLF_BOUNDARY')
        self.assertEqual(b'ax\r\nb', plan('a\r\nb', 'x', utf16_span=(1, 1)).candidate.utf8)
        result = plan('a\r\nb', 'x', utf16_span=(3, 3))
        self.assertEqual((1, 0, b'a\r\nxb'), (result.start_line, result.start_column, result.candidate.utf8))
        self.refused(plan, 'a\rX\nb', '', anchor='X', reason='CRLF_JOIN')
        self.assertEqual(b'a\rY\nb', plan('a\rX\nb', 'Y', anchor='X').candidate.utf8)

    def test_linebreak_edits_rejected_in_both_modes(self):
        for replacement in ('x\n', 'x\r', '\r\n'):
            self.refused(plan, 'abc', replacement, anchor='a', reason='REPLACEMENT_LINEBREAK')
        for source, anchor in (('a\nb', 'a\nb'), ('a\rb', 'a\rb'), ('a\r\nb', 'a\r\nb')):
            self.refused(plan, source, 'x', anchor=anchor, reason='REPLACED_LINEBREAK')
            self.refused(plan, source, 'x', utf16_span=(0, len(source)), reason='REPLACED_LINEBREAK')

    def test_strict_text_validation_and_no_body_in_errors(self):
        baseline = text('СЕКРЕТ')
        for malformed in (c.ModuleText(b'\xff', 'f' * 64, 1),
                          c.ModuleText(b'a\0b', 'f' * 64, 3),
                          c.ModuleText(b'\xed\xa0\x80', 'f' * 64, 1),
                          replace(baseline, sha256='f' * 64),
                          replace(baseline, utf16_units=True)):
            self.refused(p.plan_edit, malformed, baseline.sha256, text('x'),
                         anchor='СЕКРЕТ', reason='BASELINE')
            self.refused(p.plan_edit, baseline, baseline.sha256, malformed,
                         anchor='СЕКРЕТ', reason='REPLACEMENT')
        for value in ('СЕКРЕТ', baseline.utf8, {'_utf8': baseline.utf8}):
            self.refused(p.plan_edit, value, baseline.sha256, text('x'),
                         anchor='СЕКРЕТ', reason='BASELINE')

    def test_utf16_and_utf8_candidate_bounds_independently(self):
        baseline = text('a' * c.MAX_UTF16_UNITS)
        self.refused(p.plan_edit, baseline, baseline.sha256, text('x'),
                     utf16_span=(1, 1), reason='CANDIDATE_BOUND')
        # UTF8 max is deliberately tighter here so a valid UTF16 candidate
        # exercises the separate byte bound without megabytes of fixtures.
        with mock.patch.object(c, 'MAX_UTF8_BYTES', 5):
            self.refused(plan, 'яя', 'я', utf16_span=(0, 0), reason='CANDIDATE_BOUND')

    def test_immutable_private_bodies_and_recomputed_metadata(self):
        result = plan('СЕКРЕТ', 'НОВОЕ', anchor='СЕКРЕТ')
        for body in ('СЕКРЕТ', 'НОВОЕ', repr(result.baseline.utf8), repr(result.candidate.utf8)):
            self.assertNotIn(body, repr(result))
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            result.start_utf16 = 1
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            result.candidate._utf8 = b'forged'
        for name, value in (('start_byte', 1), ('stop_column', 999),
                            ('candidate_sha256', 'f' * 64), ('start_line', False),
                            ('candidate_byte_count', 999), ('_candidate', text('forged'))):
            self.refused(replace(result, **{name: value}).validate, reason='PLAN_METADATA')

    def test_planning_and_import_are_inert_without_body_io(self):
        forbidden = AssertionError('unexpected body I/O')
        with mock.patch('builtins.open', side_effect=forbidden), \
             mock.patch('io.open', side_effect=forbidden), \
             mock.patch('os.open', side_effect=forbidden), \
             mock.patch.object(pathlib.Path, 'read_bytes', side_effect=forbidden), \
             mock.patch.object(pathlib.Path, 'write_bytes', side_effect=forbidden):
            importlib.reload(p)
            result = plan('СЕКРЕТ', 'НОВОЕ', anchor='СЕКРЕТ')
            result.validate()
            result.assert_baseline(text('СЕКРЕТ'))

    def test_snapshots_and_untrusted_dicts_cannot_mint_capability(self):
        # Reuse real codec-validated synthetic snapshots, not empty shape stubs.
        from test_editor_transport import fixture, release_for, refusal_for, OTHER
        capture, context = fixture()
        capture = replace(capture, owner_class=2, owner_uuid=OTHER, owner_version=77)
        readonly = w.finish_capture(capture, release_for(capture, context['now']), **context)
        refused_capture = refusal_for(context['command'], context['installation'], context['now'])
        refusal = w.finish_refusal(refused_capture,
            release_for(refused_capture, context['now']), **context)
        result = plan('СЕКРЕТ', 'НОВОЕ', anchor='СЕКРЕТ')
        for value in (refusal, readonly, result, {'baseline': result.baseline},
                      {'candidate': result.candidate, 'owner_class': 1}):
            self.refused(p.plan_edit, value, result.baseline_sha256, text('x'),
                         anchor='СЕКРЕТ', reason='BASELINE')
        for value in (refusal, readonly, result):
            with self.assertRaises(w.EditorTransportRefusal):
                w.capability_from_read(value)
        # Reading somebody else's source may support a content-only plan;
        # neither that plan nor its body grants edit admission.
        observed = c.ModuleText.from_utf8(readonly.utf8)
        content_only = p.plan_edit(observed, observed.sha256, text('изменение'), anchor='Синтетика')
        self.assertIn('изменение'.encode(), content_only.candidate.utf8)
        with self.assertRaises(w.EditorTransportRefusal):
            w.capability_from_read(content_only)
        self.assertFalse(isinstance(result, c.EditCapability))
        names = {item.name for item in fields(result)}
        self.assertFalse(names & {'owner', 'owner_uuid', 'target', 'binding', 'capability', 'undo', 'redo'})
        self.assertFalse(hasattr(result, 'command'))


if __name__ == '__main__':
    unittest.main()
