"""Pure RAM planning for one exact, single-line source replacement.

A plan describes bytes, never permission to edit or a native APPLIED result.
The caller must independently admit its target, ownership, freshness, native
coordinate convention and lifecycle before invoking any setter. No history
state is accepted or changed here. Module bodies stay private in repr output.
"""
from dataclasses import dataclass, field

from .editor_command import EditorCommandRefusal, ModuleText


class EditorChangePlanRefusal(ValueError):
    """Stable technical reason only; never includes source or replacement text."""


def _need(condition, reason):
    if not condition:
        raise EditorChangePlanRefusal('EDITOR_CHANGE_PLAN_' + reason)


def _text(value, reason):
    _need(type(value) is ModuleText, reason)
    valid = True
    try:
        value.validate()
    except EditorCommandRefusal:
        valid = False
    # Raise outside the handler so no underlying exception retains a body echo.
    _need(valid, reason)
    return value.utf8.decode('utf-8', 'strict')


def _boundary_index(text, requested):
    units = 0
    for index, char in enumerate(text):
        if units == requested:
            return index
        units += 2 if ord(char) > 0xffff else 1
    _need(units == requested, 'SURROGATE_BOUNDARY')
    return len(text)


def _position(text, stop):
    """Logical 0-based line/UTF16 column; BOM counts as a source character."""
    line = column = index = 0
    while index < stop:
        char = text[index]
        if char == '\r':
            if index + 1 < stop and text[index + 1] == '\n':
                index += 1
            line += 1
            column = 0
        elif char == '\n':
            line += 1
            column = 0
        else:
            column += 2 if ord(char) > 0xffff else 1
        index += 1
    return line, column


@dataclass(frozen=True, slots=True)
class EditorChangePlan:
    """Immutable content plan, not an EditCapability or a command.

    Ranges are half-open in the original baseline. Line/column positions are
    logical 0-based UTF16 coordinates, with CRLF treated as one line break and
    lone CR/LF as line breaks; native setter conversion is outside this module.
    Public construction/deserialization confers no trust: validate recomputes
    every field and assert_baseline performs a fresh exact byte comparison.
    """
    baseline_sha256: str
    candidate_sha256: str
    baseline_byte_count: int
    candidate_byte_count: int
    replacement_byte_count: int
    baseline_utf16_units: int
    candidate_utf16_units: int
    replacement_utf16_units: int
    start_utf16: int
    stop_utf16: int
    start_byte: int
    stop_byte: int
    start_line: int
    start_column: int
    stop_line: int
    stop_column: int
    _baseline: ModuleText = field(repr=False)
    _candidate: ModuleText = field(repr=False)
    _replacement: ModuleText = field(repr=False)

    @property
    def baseline(self):
        return self._baseline

    @property
    def candidate(self):
        return self._candidate

    @property
    def replacement(self):
        return self._replacement

    def validate(self):
        """Recompute content and metadata only; does not validate authority."""
        _text(self._candidate, 'CANDIDATE')
        measured = plan_edit(self._baseline, self.baseline_sha256,
                             self._replacement,
                             utf16_span=(self.start_utf16, self.stop_utf16))
        # Exact field types prevent bool/int equality from hiding forged metadata.
        _need(all(type(getattr(self, name)) is type(getattr(measured, name))
                  and getattr(self, name) == getattr(measured, name)
                  for name in self.__dataclass_fields__), 'PLAN_METADATA')

    def assert_baseline(self, current):
        """Check this plan against a fresh ModuleText; no edit is performed."""
        self.validate()
        _text(current, 'CURRENT_BASELINE')
        _need(current.sha256 == self.baseline_sha256
              and current.utf8 == self._baseline.utf8, 'STALE_BASELINE')


def plan_edit(baseline, expected_sha256, replacement, *, anchor=None,
              utf16_span=None):
    """Prepare one exact replacement without I/O or native/ownership effects.

    baseline and replacement must be exact validated ModuleText instances.
    Select either a nonempty unique literal anchor (including overlapping
    matches), or an exact (start, stop) tuple of UTF16 offsets. Empty spans
    permit insertion and empty replacements permit deletion. The replaced
    span and replacement must contain no CR/LF. No newline normalization,
    Unicode normalization, surrogate/CRLF splitting, or initial BOM edits.
    Refusals disclose only a stable reason. All bodies remain in caller RAM.
    """
    text = _text(baseline, 'BASELINE')
    inserted = _text(replacement, 'REPLACEMENT')
    _need(type(expected_sha256) is str and len(expected_sha256) == 64
          and all(char in '0123456789abcdef' for char in expected_sha256),
          'EXPECTED_SHA256')
    _need(baseline.sha256 == expected_sha256, 'STALE_BASELINE')
    _need((anchor is not None) != (utf16_span is not None), 'SELECTOR')
    _need('\r' not in inserted and '\n' not in inserted, 'REPLACEMENT_LINEBREAK')
    if anchor is not None:
        _need(type(anchor) is str and len(anchor) > 0, 'ANCHOR')
        # Invalid/NUL/oversized anchor text fails without encoding error echoes.
        valid_anchor = True
        try:
            ModuleText.from_text(anchor)
        except EditorCommandRefusal:
            valid_anchor = False
        _need(valid_anchor, 'ANCHOR')
        start = text.find(anchor)
        _need(start >= 0, 'ANCHOR_MISSING')
        _need(text.find(anchor, start + 1) < 0, 'ANCHOR_AMBIGUOUS')
        stop = start + len(anchor)
        start_units = len(text[:start].encode('utf-16-le')) // 2
        stop_units = len(text[:stop].encode('utf-16-le')) // 2
    else:
        _need(type(utf16_span) is tuple and len(utf16_span) == 2
              and all(type(value) is int for value in utf16_span), 'SPAN')
        start_units, stop_units = utf16_span
        _need(0 <= start_units <= stop_units <= baseline.utf16_units, 'SPAN_BOUND')
        start = _boundary_index(text, start_units)
        stop = _boundary_index(text, stop_units)
    _need(not any(0 < index < len(text) and text[index - 1:index + 1] == '\r\n'
                  for index in (start, stop)), 'CRLF_BOUNDARY')
    _need('\r' not in text[start:stop] and '\n' not in text[start:stop],
          'REPLACED_LINEBREAK')
    # Deleting a complete line between lone CR and LF would silently turn
    # two existing line breaks into one CRLF even though their bytes survive.
    _need(not (not inserted and start < stop and start > 0 and stop < len(text)
               and text[start - 1] == '\r' and text[stop] == '\n'), 'CRLF_JOIN')
    _need(not text.startswith('\ufeff') or start > 0, 'BOM_BOUNDARY')
    start_byte = len(text[:start].encode('utf-8'))
    stop_byte = len(text[:stop].encode('utf-8'))
    body = baseline.utf8[:start_byte] + replacement.utf8 + baseline.utf8[stop_byte:]
    candidate = None
    try:
        candidate = ModuleText.from_utf8(body)
    except EditorCommandRefusal:
        pass
    _need(candidate is not None, 'CANDIDATE_BOUND')
    _need(candidate.utf8 != baseline.utf8, 'UNCHANGED')
    start_line, start_column = _position(text, start)
    stop_line, stop_column = _position(text, stop)
    return EditorChangePlan(baseline.sha256, candidate.sha256,
        len(baseline.utf8), len(candidate.utf8), len(replacement.utf8),
        baseline.utf16_units, candidate.utf16_units, replacement.utf16_units,
        start_units, stop_units, start_byte, stop_byte,
        start_line, start_column, stop_line, stop_column,
        baseline, candidate, replacement)
