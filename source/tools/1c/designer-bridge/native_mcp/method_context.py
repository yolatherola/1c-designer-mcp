"""Bounded method neighborhood over the already verified, pinned RAM index.

Adapter for live_symbol_index_v204 e30e38ee; no parser, provider, file access or
cross-object resolution. Source snippets exist only in the returned response.
"""
from dataclasses import asdict, is_dataclass
from bisect import bisect_right
import json
import re

INDEX_SHA = 'e30e38eecc48544f6375ff4ffffa0f3620b9cdf19f65fd9acee31cac431693bf'
MAX_BYTES = 24*1024
METHOD_BYTES = 8*1024
NEIGHBOR_BYTES = 1024
MAX_NEIGHBORS = 8
MAX_ENTRIES = 4
MAX_CALLS = 32
MAX_UNRESOLVED = 16
MAX_CANDIDATES = 4
MAX_CALL_SITES = 4
_QUALIFIED_SITE = re.compile(r'\.(?:\s|//[^\r\n]*(?:\r\n|\r|\n)|/\*[\s\S]*?\*/)*([^\W\d]\w*)\s*\(')


def _plain(value):
    if is_dataclass(value): return _plain(asdict(value))
    if type(value) is dict: return {key: _plain(item) for key, item in value.items()}
    if type(value) in (tuple, list): return [_plain(item) for item in value]
    return value


def _size(row):
    return len(json.dumps(row, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf8'))


def _prefix(text, maximum):
    # Allocate the text budget before constructing its JSON row. Counting JSON
    # escapes prevents control characters from multiplying the response size.
    used = 0
    stop = len(text)
    for i, char in enumerate(text):
        cost = 2 if char in '"\\\b\f\n\r\t' else 6 if ord(char)<32 else len(char.encode('utf8'))
        if used+cost > maximum:
            stop = i
            break
        used += cost
    if stop == len(text): return text, False
    result = text[:stop]
    # Keep CRLF atomic when the byte budget happens to end between its halves.
    if result.endswith('\r') and text[len(result):].startswith('\n'): result = result[:-1]
    return result, True


class _Budget:
    def __init__(self, row):
        self.row = row
        self.used = _size(row)

    def add(self, destination, value):
        extra = _size(value)+(1 if destination else 0)
        if self.used+extra > MAX_BYTES-512: return False
        destination.append(value)
        self.used += extra
        return True

    def finish(self):
        self.row['truncated'] = any(self.row['omissions'].values()) or any(
            snippet['truncated'] for snippet in self.row['snippets'])
        # Only these initially fixed scalar fields change after row admission.
        # Determine their encoded delta without re-encoding any method body.
        size = self.used+sum(len(str(value))-1 for value in self.row['omissions'].values())
        size -= int(self.row['truncated'])+int(self.row['body_included'])+int(self.row['body_available'])
        reported = size
        for _ in range(4):
            actual = size+len(str(reported))-1
            if actual == reported: break
            reported = actual
        self.row['budget']['used_utf8_bytes'] = reported
        # The complete response is encoded exactly once as the final bound.
        if _size(self.row) != reported or reported > MAX_BYTES:
            raise ValueError('METHOD_CONTEXT_RESPONSE_BOUND')
        return self.row


def build_method_context(index, target, method_name, body):
    """Return selected source and one local lexical hop within 24KiB UTF-8.

    The session must supply the body and index from the same unexpired capture.
    The index retains metadata only. Qualified calls stay unresolved even when
    another captured module contains a method with a matching name.
    """
    if type(method_name) is not str or not 0 < len(method_name) <= 256 or type(body) is not str:
        raise ValueError('METHOD_CONTEXT_ARGUMENT')
    index._target(target)
    record = index._records.get(target)
    if record is None: raise ValueError('METHOD_CONTEXT_TARGET')
    parsed = record.parsed
    if type(parsed.symbols) is not tuple or type(parsed.calls) is not tuple:
        raise ValueError('METHOD_CONTEXT_INDEX_SHAPE')
    folded = method_name.casefold()
    selected = [i for i, symbol in enumerate(parsed.symbols) if symbol.name.casefold() == folded]
    selected_set = set(selected)
    status = 'STALE' if record.stale else 'AMBIGUOUS' if len(selected)>1 else 'FOUND' if selected else 'NOT_FOUND'
    row = dict(status=status, entries=[], callers=[], neighbors=[], unresolved=[], snippets=[],
        stale=record.stale, body_available=False, body_included=False,
        coverage=_plain(index.coverage()), neighborhood_coverage='captured_module_only',
        lexical_only=True, resolution_kind='lexical_direct_calls', semantic_validation='UNVERIFIED',
        global_resolution='UNVERIFIED', writer_authorized=False, truncated=False,
        omissions=dict(entries=0, direct_calls=0, callers=0, neighbors=0, unresolved=0,
            snippets=0, candidate_definitions=0, call_sites=0, symbol_metadata=0),
        budget=dict(limit_utf8_bytes=MAX_BYTES, used_utf8_bytes=0, method_text_limit_utf8_bytes=METHOD_BYTES,
            max_neighbors=MAX_NEIGHBORS))
    budget = _Budget(row)
    if status in ('STALE', 'NOT_FOUND'): return budget.finish()
    by_name = {}
    for i, symbol in enumerate(parsed.symbols): by_name.setdefault(symbol.name.casefold(), []).append(i)
    lines = body.splitlines(keepends=True)
    offsets = [0]
    for line in lines: offsets.append(offsets[-1]+len(line))
    # The frozen parser can lose a receiver around whitespace/newlines. It has
    # no call columns, so conservatively reject every same-name call on a line
    # containing a qualified occurrence. This is a veto, not a second parser;
    # comments/strings may cause explicit false-unresolved results, never links.
    qualified_sites = {(match.group(1).casefold(), bisect_right(offsets, match.start(1)))
        for match in _QUALIFIED_SITE.finditer(body)}
    outgoing = []
    neighbor_roles = {}
    caller_groups = {}
    # One pass over the existing call table; never rescan all definitions per
    # edge and never ask the old unbounded get_context to build a response.
    for call in parsed.calls:
        callee = call.callee.casefold()
        uncertain_qualification = '.' not in call.callee and (callee, call.line) in qualified_sites
        if call.caller_index in selected_set:
            candidates = by_name.get(callee, []) if '.' not in call.callee and not uncertain_qualification else []
            resolution = ('local' if len(candidates)==1 else 'ambiguous_local') if candidates else 'unresolved'
            outgoing.append((call, candidates, resolution, uncertain_qualification))
            if len(candidates)==1 and candidates[0] not in selected_set:
                neighbor_roles.setdefault(candidates[0], set()).add('callee')
        if '.' not in call.callee and not uncertain_qualification and callee == folded:
            caller_groups.setdefault(call.caller_index, []).append(call.line)
            if call.caller_index not in selected_set:
                neighbor_roles.setdefault(call.caller_index, set()).add('caller')
    symbols = {}

    def symbol(i):
        # Do not retain the temporary conversion in the long-lived index.
        if i not in symbols: symbols[i] = _plain(index._symbol(record, i))
        return symbols[i]

    entries = {}
    for i in selected[:MAX_ENTRIES]:
        entry = dict(symbol=symbol(i), direct_calls=[])
        if not budget.add(row['entries'], entry):
            full = symbol(i)
            compact = {key: full[key] for key in ('target', 'source_sha256', 'revision', 'name', 'kind',
                'start_line', 'end_line', 'line_base', 'semantic_validation', 'writer_authorized')}
            compact['metadata_truncated'] = True
            entry = dict(symbol=compact, direct_calls=[])
            if not budget.add(row['entries'], entry):
                row['omissions']['entries'] += 1
                continue
            row['omissions']['symbol_metadata'] += 1
        entries[i] = entry
    row['omissions']['entries'] += max(0, len(selected)-MAX_ENTRIES)
    def snippet(i, role, maximum):
        item = parsed.symbols[i]
        if not 1 <= item.start_line <= item.end_line <= len(lines):
            raise ValueError('METHOD_CONTEXT_SOURCE_RANGE')
        start, stop = offsets[item.start_line-1], offsets[item.end_line]
        text, truncated = _prefix(body[start:stop], maximum)
        return dict(name=item.name, role=role, method_start_line=item.start_line,
            method_end_line=item.end_line, start_line=item.start_line,
            end_line=item.start_line+max(0, len(text.splitlines())-1), line_base=1,
            start_offset=start, end_offset=start+len(text), offset_base=0,
            position_unit='unicode_code_points', text=text, utf8_bytes=len(text.encode('utf8')),
            truncated=truncated)

    # Ambiguous definitions are reported independently; do not select one body.
    if status == 'FOUND':
        requested = snippet(selected[0], 'requested', METHOD_BYTES)
        if not budget.add(row['snippets'], requested): row['omissions']['snippets'] += 1

    for i, roles in list(neighbor_roles.items())[:MAX_NEIGHBORS]:
        neighbor = dict(symbol=symbol(i), relations=sorted(roles))
        if not budget.add(row['neighbors'], neighbor):
            row['omissions']['neighbors'] += 1
            continue
        if status == 'FOUND':
            fragment = snippet(i, 'neighbor', NEIGHBOR_BYTES)
            if not budget.add(row['snippets'], fragment): row['omissions']['snippets'] += 1
    row['omissions']['neighbors'] += max(0, len(neighbor_roles)-MAX_NEIGHBORS)
    for i, sites in list(caller_groups.items())[:MAX_NEIGHBORS]:
        caller = dict(symbol=symbol(i), call_sites=sites[:MAX_CALL_SITES], line_base=1,
            resolution='local' if len(selected)==1 else 'ambiguous_local',
            global_resolution='UNVERIFIED', writer_authorized=False)
        if not budget.add(row['callers'], caller): row['omissions']['callers'] += 1
        row['omissions']['call_sites'] += max(0, len(sites)-MAX_CALL_SITES)
    row['omissions']['callers'] += max(0, len(caller_groups)-MAX_NEIGHBORS)
    unresolved_total = 0
    considered_calls = 0
    for call, candidates, resolution, uncertain_qualification in outgoing:
        if resolution != 'local': unresolved_total += 1
        entry = entries.get(call.caller_index)
        # Stop constructing large candidate expansions after the result limit.
        if considered_calls >= MAX_CALLS or entry is None:
            row['omissions']['direct_calls'] += 1
        else:
            considered_calls += 1
            edge = dict(callee=call.callee, line=call.line, line_base=1, resolution=resolution,
                candidates=[symbol(i) for i in candidates[:MAX_CANDIDATES]],
                global_resolution='UNVERIFIED', writer_authorized=False)
            if uncertain_qualification: edge['resolution_reason'] = 'qualified_callsite_uncertain'
            if not budget.add(entry['direct_calls'], edge): row['omissions']['direct_calls'] += 1
            row['omissions']['candidate_definitions'] += max(0, len(candidates)-MAX_CANDIDATES)
        if resolution != 'local' and len(row['unresolved']) < MAX_UNRESOLVED:
            dependency = dict(callee=call.callee, line=call.line, line_base=1, resolution=resolution,
                classification='qualified_callsite_uncertain' if uncertain_qualification else
                    'qualified_unresolved' if '.' in call.callee else
                    'ambiguous_local' if candidates else 'unresolved_unqualified',
                module_identity_verified=False, global_resolution='UNVERIFIED')
            budget.add(row['unresolved'], dependency)
    row['omissions']['unresolved'] = unresolved_total-len(row['unresolved'])
    row['body_included'] = any(fragment['text'] for fragment in row['snippets'])
    row['body_available'] = row['body_included']
    return budget.finish()
