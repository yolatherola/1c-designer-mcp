"""Metadata-only whole-function review of249 at a262-owned technical runtime.

No native/process/DPAPI calls. This is source equivalence evidence, never a
fresh live identity observation or execution/write permission.
"""
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
OLD_NONCE = '6c5fb1ffca5d42a0ac3c4d2f42f1ba3f'
COMPOSER_PIN = 'a27af50b026f444f16aa66feaabc7cbfb842126d1b8f87eae53c38e802cfcf4d'
MAIN_PIN = '64d37425553b75c6465aef5c194f327fb7e75399ec682f686fa7b658f7a4ad66'
DERIVED_PIN = '64fb6aeabcc5e1c24f091e81bbdd85e7fe8821a3a621fcced4c521ab6e130b07'
SOURCE536 = '805717ad3532c13cb69dfd076681c57ea5574dac9d94f3e68b366091b5984581'
SDK_PINS = {
    'ah_capture_status.v': '109cd5e33d48a38b116854398337875bdc2c9335a8010942b6a26f7efe6d20ef',
    'textmgr.v': '61c83d8fd9a3c78f3ed573b649074b3aa8e646d8ff54f40aa296d5f4e992a75a',
    'metadata.v': 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed',
}
DIAGNOSTIC_PATHS = {
    'ahCommandContextSnapshotV211': 'bootstrap-command-context-v211.json',
    'ahFrameAbiSnapshotV211': 'bootstrap-frame-abi-v211.json',
    'ahParentFrameMarkerV211': 'bootstrap-parent-frame-v211-',
    'ahSelectedMainWindowRoleV211': 'bootstrap-selected-main-window-role-v211.json',
}
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\r\n]*|/\*.*?\*/', re.S)
HEADER = re.compile(r'(?m)^[ \t]*[A-Za-z_]\w*(?:<[^>\n]+>)?[ \t]*[@&]*[ \t]+(ah\w+)\s*\([^;{}]*\)\s*\{')


def need(value, code):
    if not value:
        raise ValueError('V265_' + code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(path, bound=2097152):
    need(path.is_absolute() and '..' not in path.parts and ROOT in path.parents, 'PATH')
    for item in (path, *path.parents):
        info = item.lstat()
        need(not item.is_symlink() and not getattr(info, 'st_file_attributes', 0) & 0x400, 'REPARSE')
        if item == ROOT:
            break
    need(path.is_file() and 0 < path.stat().st_size <= bound, 'BOUND')
    with path.open('rb') as stream:
        raw = stream.read(bound + 1)
    need(0 < len(raw) <= bound, 'BOUND')
    return raw


def _masked(text):
    return TOKEN.sub(lambda item: ' ' * len(item.group()), text)


def _functions(text):
    clean = _masked(text)
    found = {}
    for match in HEADER.finditer(clean):
        cursor, depth = match.end(), 1
        while cursor < len(clean) and depth:
            if clean[cursor] == '{':
                depth += 1
            elif clean[cursor] == '}':
                depth -= 1
            cursor += 1
        need(depth == 0, 'FUNCTION_BRACES')
        found.setdefault(match[1], []).append(text[match.start():cursor])
    return found


def _calls(text):
    return set(re.findall(r'(?<![.A-Za-z0-9_])\b(ah\w+)\s*\(', _masked(text)))


def _one(functions, name):
    need(name in functions and len(functions[name]) == 1, 'FUNCTION_MISSING_OR_DUPLICATE')
    return functions[name][0]


def _diagnostic_relocation(name, old, new, old_prefix, new_prefix):
    """One explicit whole string literal; no body/nonce/whitespace normalizer."""
    need(name in DIAGNOSTIC_PATHS, 'TRANSITIVE_CHANGED')
    original = '"' + old_prefix + '/' + DIAGNOSTIC_PATHS[name] + '"'
    replacement = '"' + new_prefix + '/' + DIAGNOSTIC_PATHS[name] + '"'
    literals = [item.group() for item in TOKEN.finditer(old) if item.group().startswith('"')]
    need(literals.count(original) == 1 and old.count(original) == 1
         and new.count(replacement) == 1, 'DIAGNOSTIC_LITERAL')
    need(old.replace(original, replacement, 1) == new
         and new.replace(replacement, original, 1) == old, 'DIAGNOSTIC_WHOLE_REVERSE')
    return 1


def _compare(source, old, new, old_prefix, new_prefix, native_free, native_methods):
    direct = _calls(source) - {'ahRunnerCompositeV249'}
    methods = set(re.findall(r'\.\s*(ah\w+)\s*\(', _masked(source)))
    need(len(direct) == 27 and methods == set(native_methods), 'COMPOSITE_CALLS')
    a, b = _functions(old), _functions(new)
    rows = []
    for name in sorted(direct - set(native_free)):
        left, right = _one(a, name), _one(b, name)
        need(left == right, 'DIRECT_FUNCTION_CHANGED')
        rows.append(dict(name=name, bytes=len(left.encode()), sha256=sha(left.encode())))
    need(len(rows) == 25 and direct & set(native_free) == set(native_free), 'DIRECT_COUNT')
    seen, pending, external, transitive = set(), set(direct), set(), []
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        if name not in a:
            need(name not in b, 'NEW_EXTERNAL_DEFINITION')
            external.add(name)
            continue
        seen.add(name)
        left, right = _one(a, name), _one(b, name)
        relocations = 0 if left == right else _diagnostic_relocation(name, left, right, old_prefix, new_prefix)
        transitive.append(dict(name=name, oldSha256=sha(left.encode()), newSha256=sha(right.encode()),
                               byteEqual=left == right, diagnosticPathRelocations=relocations))
        pending |= _calls(left) - {name} - seen
    return dict(directFunctionProofs=rows, directFreeCalls=27, directAsFunctions=25,
                nativeFreeAliases=sorted(native_free), nativeMethodAliases=sorted(methods),
                transitiveFunctionProofs=sorted(transitive, key=lambda row: row['name']),
                transitiveFunctions=len(seen), transitiveByteEqual=sum(row['byteEqual'] for row in transitive),
                diagnosticPathRelocations=sum(row['diagnosticPathRelocations'] for row in transitive),
                transitiveExternalCalls=sorted(external))


def review_current(held_nonce):
    """Return reviewed metadata only for a262READY_HELD-owned current main.

    Parent must still revalidate live PID/birth/thread/source/lease before use.
    No proof/body/main/hash override, arbitrary source or bool admission input.
    """
    need(type(held_nonce) is str and re.fullmatch('[a-f0-9]{32}', held_nonce), 'NONCE')
    need(sha(_read(HERE / 'runner_composite_v249.py')) == COMPOSER_PIN, 'COMPOSER_PIN')
    import runner_composite_v249 as composer
    source = composer.derive_source()
    need(sha(source) == DERIVED_PIN, 'DERIVED_PIN')
    old_runtime = ROOT / 'build' / ('designer-v43-' + OLD_NONCE) / 'runtime/modules/snegopat'
    runtime = ROOT / 'build' / ('designer-v43-' + held_nonce) / 'runtime/modules/snegopat'
    metadata_path = ROOT / 'artifacts/designer-bridge' / ('v262-held-bootstrap-' + held_nonce + '.json')
    metadata_raw = _read(metadata_path, 32768)
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_JSON')
            result[key] = value
        return result
    receipt = json.loads(metadata_raw, object_pairs_hook=pairs,
                         parse_constant=lambda _: need(False, 'NONFINITE'))
    need(receipt.get('version') == 262 and receipt.get('nonce') == held_nonce and receipt.get('passed') is True
         and receipt.get('bootstrapState') == 'READY_HELD' and receipt.get('sourceCount') == 536
         and receipt.get('sourceManifestSha256') == SOURCE536 and receipt.get('writerAuthorized') is False
         and Path(receipt['buildDirectory']) == runtime.parents[2], 'BOOTSTRAP_RECEIPT')
    ctx, obs = receipt['context'], receipt['nativeObservation']
    need(type(ctx['processId']) is int and 0 < ctx['processId'] < 2**32
         and type(ctx['processCreationFileTimeUtc']) is str and re.fullmatch('[a-f0-9]{16}', ctx['processCreationFileTimeUtc'])
         and int(ctx['processCreationFileTimeUtc'], 16) != 0, 'IDENTITY')
    need(obs.get('pid') == ctx['processId'] and obs.get('birth') == ctx['processCreationFileTimeUtc']
         and obs.get('status') == 'ALIVE' and obs.get('nativeKernelVerified') is True
         and obs.get('sourceJoinVerified') is True and obs.get('fake') is False, 'OBSERVATION')
    old_raw, new_raw = _read(old_runtime / 'engine/main.as'), _read(runtime / 'engine/main.as')
    need(sha(old_raw) == MAIN_PIN and sha(new_raw) == receipt['mainSha256'], 'MAIN_PIN')
    sdk = {}
    for name, pin in SDK_PINS.items():
        left, right = _read(old_runtime / 'v8api' / name), _read(runtime / 'v8api' / name)
        need(left == right and sha(left) == pin, 'SDK_PIN')
        sdk[name] = right.decode('utf-8')
    old, new = old_raw.decode('utf-8'), new_raw.decode('utf-8')
    old_sessions = set(re.findall('designer-v43-' + OLD_NONCE + '/session-([a-f0-9]{32})/', old))
    need(len(old_sessions) == 1, 'OLD_SESSION')
    session = receipt['publication']['sessionId']
    need(type(session) is str and re.fullmatch('[a-f0-9]{32}', session), 'CURRENT_SESSION')
    old_prefix = (old_runtime.parents[2] / ('session-' + next(iter(old_sessions)))).as_posix()
    new_prefix = (runtime.parents[2] / ('session-' + session)).as_posix()
    counts = composer.verify_closure(source.decode(), new, sdk['ah_capture_status.v'], sdk['textmgr.v'])
    need(counts == (27, 3), 'NATIVE_ALIAS_CLOSURE')
    comparison = _compare(source.decode(), old, new, old_prefix, new_prefix, composer._NATIVE_FREE, composer._NATIVE_METHODS)
    return dict(version=265, passed=True, heldNonce=held_nonce, processId=ctx['processId'],
                birth=ctx['processCreationFileTimeUtc'], sourceManifestSha256=SOURCE536,
                bootstrapReceiptSha256=sha(metadata_raw), oldMainSha256=MAIN_PIN, mainSha256=sha(new_raw),
                composerSha256=COMPOSER_PIN, derivedSourceSha256=DERIVED_PIN, sdkSha256=dict(SDK_PINS),
                comparison=comparison, directWholeFunctionsByteEqual=True,
                transitiveWholeFunctionsReviewed=True, sourceBodiesPrinted=False,
                liveFreshnessVerified=False, writerAuthorized=False, runtimeExecuted=False)


if __name__ == '__main__':
    raise SystemExit('V265_METADATA_ONLY_NO_RUNTIME_CLI')
