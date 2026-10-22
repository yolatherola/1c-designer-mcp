"""Pure V102 session source proof. This does not grant a Gold/native call.

Only the exact reviewed V99 entry may mutate its created Constant. The wrapper
holds typed witnesses and gates terminal on durable output and fresh guards;
host/client roles, source pins, PID/birth and lease remain root prerequisites.
"""
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'tests/NativeGoldOwnedConstantSessionV102.as'
SOURCE_SHA256 = '6750d4f275f830fe5daf6d7117797f74beef9a79faede99a7106ed60ec4f89bc'
ENTRY_SHA256 = '6249c98886947d95a5f229923a75d5d5ec7bde0a07ca228bc7a5ed0e194d0799'
GUARD_SHA256 = '1b6e35f02fb5830e0b3a1482dfcbf4b7fdcf4b4084895933edecbc462fa7edc5'
PREFIX = 'ahGoldOwnedConstantV99'
RESULT_FILENAME = 'gold-owned-constant-v99.json'
ENTRY_CALL = ('ahGoldOwnedConstantV99(operation,ahGoldOwnedConstantV99Consumed,'
              'ahGoldOwnedConstantV99State,terminalResult,attemptedWrites)')
COUNTERS = ('factories', 'ids', 'attaches', 'names', 'setters', 'deletes')
FUNCTIONS = (PREFIX+'AttemptsV102', PREFIX+'CountersKnownV102', PREFIX+'Permit',
             PREFIX+'SafeTerminal', 'ahGoldOwnedConstantSessionV102')


def _need(ok, code):
    if not ok:
        raise ValueError(code)


def _mask(text):
    return re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"',
                  lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text, flags=re.S)


def _ordered(text, *items):
    return all(item in text for item in items) and all(
        text.index(left) < text.index(right) for left, right in zip(items, items[1:]))


def _parts(code):
    """Collect only exact top-level globals/functions; never execute AS."""
    declarations, functions = [], {}
    depth = 0
    start = 0
    name = None
    body_start = 0
    for index, char in enumerate(code):
        if char == '{':
            if depth == 0:
                match = re.fullmatch(r'(?:bool|uint|string)\s+(\w+)\s*\([^{};]*\)', code[start:index].strip())
                _need(match is not None and match[1] not in functions, 'GC102_TOP_LEVEL_REJECTED')
                name, body_start = match[1], index+1
            depth += 1
        elif char == '}':
            depth -= 1
            _need(depth >= 0, 'GC102_BALANCE_REJECTED')
            if depth == 0:
                functions[name] = code[body_start:index]
                start = index+1
        elif char == ';' and depth == 0:
            declarations.append(''.join(code[start:index].split()))
            start = index+1
    _need(depth == 0 and not code[start:].strip(), 'GC102_BALANCE_REJECTED')
    return declarations, functions


def verify_source(raw):
    """Validate reviewed ordering/scope and the full hash, not runtime success."""
    _need(type(raw) is bytes and 0 < len(raw) <= 16384, 'GC102_SOURCE_BOUND_REJECTED')
    try:
        text = raw.decode('utf-8', 'strict')
    except UnicodeError:
        raise ValueError('GC102_SOURCE_ENCODING_REJECTED') from None
    code = _mask(text)
    declarations, functions = _parts(code)
    _need(declarations == [
        'bool'+PREFIX+'Enabled=__GOLD_OWNED_CONSTANT_V99__',
        'bool'+PREFIX+'Consumed=false,'+PREFIX+'Terminal=false',
        'uint'+PREFIX+'WriteAttempts=0',
        'AhGCStateV99'+PREFIX+'State'], 'GC102_GLOBAL_STATE_REJECTED')
    _need(set(functions) == set(FUNCTIONS), 'GC102_FUNCTION_SET_REJECTED')
    _need(not re.search(r'\b(?:initialize|eval|Execute|CreateFile|LoadLibrary|initFuncDefFromAddress|setMdPropVal|setModified|clearModified|UpdateDBCfg|SaveCfg|createByClsid|mem)\b', code),
          'GC102_FORBIDDEN_EFFECT_REJECTED')
    _need(code.count('ahGoldOwnedConstantV99(') == 1 and ENTRY_CALL in code,
          'GC102_SINGLE_ENTRY_REJECTED')
    attempts = functions[PREFIX+'AttemptsV102']
    _need(all(attempts.count(PREFIX+'State.'+key) == 1 for key in COUNTERS)
          and attempts.count('State.') == len(COUNTERS), 'GC102_ATTEMPTS_REJECTED')
    counters = functions[PREFIX+'CountersKnownV102']
    _need(all(PREFIX+'State.'+key+'<=1' in counters for key in COUNTERS),
          'GC102_COUNTER_BOUND_REJECTED')
    permit = functions[PREFIX+'Permit']
    _need(PREFIX+'Enabled && !'+PREFIX+'Consumed && ahGCPermitV99(operation)' in permit,
          'GC102_PERMISSION_REJECTED')
    safe = functions[PREFIX+'SafeTerminal']
    required = [PREFIX+'Enabled', PREFIX+'Consumed', PREFIX+'Terminal',
                PREFIX+'State.baseline', '!'+PREFIX+'State.unknown', PREFIX+'State.own is null',
                PREFIX+'CountersKnownV102()', PREFIX+'WriteAttempts=='+PREFIX+'AttemptsV102()',
                'ahGCRootV99('+PREFIX+'State)', PREFIX+'State.root.objById(ahGCIdV99()) is null',
                PREFIX+'State.root.childCount(ahGCKindV99())=='+PREFIX+'State.beforeCount',
                'ahGCForeignV99('+PREFIX+'State)', 'ahGCSourceV99('+PREFIX+'State)']
    _need(all(item in safe for item in required) and '||' not in safe
          and safe.index('ahGCRootV99(') < safe.index('.root.objById('), 'GC102_FRESH_TERMINAL_REJECTED')
    wrapper = functions['ahGoldOwnedConstantSessionV102']
    _need(_ordered(wrapper,'if(!'+PREFIX+'Permit(operation))', PREFIX+'Terminal=false',
                   ENTRY_CALL, PREFIX+'WriteAttempts='+PREFIX+'AttemptsV102()'),
          'GC102_ONESHOT_ORDER_REJECTED')
    _need('bool terminalResult=false;uint attemptedWrites=0;' in wrapper
          and 'CppCatch caught(' in wrapper and 'catcher.hasException' in wrapper
          and 'attemptedWrites!='+PREFIX+'WriteAttempts' in wrapper
          and code.count(PREFIX+'State.unknown=true') == 2,
          'GC102_UNKNOWN_RETAINS_REJECTED')
    _need('ahCycleDurable("'+RESULT_FILENAME+'",result)' in text
          and _ordered(wrapper,'if(!ahCycleDurable(', PREFIX+'Terminal=terminalResult && !'+PREFIX+'State.unknown'),
          'GC102_DURABLE_RESULT_REJECTED')
    _need(not re.search(r'\b(?:parse|json|fromString|valueFromString)\w*\s*\(', code, re.I),
          'GC102_JSON_AUTHORITY_REJECTED')
    _need(hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'GC102_SOURCE_PIN_REJECTED')
    return dict(sessionSourceVerified=True, sourceSha256=SOURCE_SHA256, entrySourceSha256=ENTRY_SHA256,
                callerHeldState=True, freshTerminalRequired=True, resultFilename=RESULT_FILENAME,
                metadataAttemptLimit=6, nativePermit=False, safeTerminalRuntimeVerified=False,
                dedicatedHostRoleRequired=True, dedicatedClientRoleRequired=True,
                authenticatedPidBirthLeaseRequired=True, persistedGoldVerified=False,
                databaseUpdateAuthorized=False, repositoryWritesPermitted=False)


def verify_static():
    """Read only pinned V99/platform prerequisites and exact wrapper source."""
    entry = importlib.import_module('gold_owned_constant_contract_v99').verify_static()
    _need(entry['sourceSha256'] == ENTRY_SHA256 and entry['callerHeldStateRequired'] is True,
          'GC102_ENTRY_PIN_REJECTED')
    guard = (HERE / 'gold_owned_constant_guard_v99.py').read_bytes()
    _need(hashlib.sha256(guard).hexdigest() == GUARD_SHA256, 'GC102_GUARD_PIN_REJECTED')
    result = verify_source(SOURCE.read_bytes())
    result['guardSourceSha256'] = GUARD_SHA256
    result['pinnedConstantStaticVerified'] = entry['pinnedConstantStaticVerified']
    return result


def parse_host_terminal(raw):
    """Bounded unique JSON decoder; it grants no completion authority."""
    _need(type(raw) is bytes and 0 < len(raw) <= 65536, 'GC102_TERMINAL_BOUND_REJECTED')
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, 'GC102_DUPLICATE_TERMINAL_REJECTED')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('GC102_NONFINITE_TERMINAL_REJECTED')
    try:
        info = json.loads(raw.decode('utf-8-sig','strict'),object_pairs_hook=pairs,parse_constant=invalid)
    except (UnicodeError,json.JSONDecodeError,RecursionError):
        raise ValueError('GC102_TERMINAL_ENCODING_REJECTED') from None
    _need(type(info) is dict, 'GC102_TERMINAL_SHAPE_REJECTED')
    return info


def verify_receipts(raw, read_marker):
    """Pure physical V99 proof: known refusal is distinct from capability."""
    guard = importlib.import_module('gold_owned_constant_guard_v99')
    info = guard.parse_result(raw)
    result = guard.verify(info,info['version'],read_marker)
    return dict(passed=True,safeTerminalObserved=result['safeTerminalObserved'],
                ownConstantVerified=result['ownConstantVerified'],writeCount=info['writeAttempts'],
                operationId=info['operationId'],physicalMarkerCount=result['physicalMarkerCount'],
                processStopPermitted=False,leaseMutationPermitted=False)


def _contained(path,boundary):
    """Reject every existing reparse component before diagnostic reads."""
    path,boundary=Path(os.path.abspath(path)),Path(os.path.abspath(boundary))
    _need(path.is_relative_to(boundary),'GC102_PATH_OUTSIDE_SCOPE')
    for component in (path,*path.parents):
        if component.exists() or component.is_symlink():
            info=component.lstat()
            _need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,
                  'GC102_REPARSE_PATH_REJECTED')
        if component==boundary:break
    return path


def inspect_session(session):
    """Read only own fixed diagnostics. No connection, settings or Gold data."""
    root = HERE.parents[3]
    session = _contained(Path(session),root/'build')
    _need(session.parent.parent == root/'build'
          and re.fullmatch('designer-v43-[a-f0-9]{32}',session.parent.name) is not None
          and re.fullmatch('session-[a-f0-9]{32}',session.name) is not None,
          'GC102_SESSION_PATH_REJECTED')
    verify_static()
    guard = importlib.import_module('gold_owned_constant_guard_v99')
    limits = {guard.marker_filename(p):guard.MARKER_LIMIT for p in guard.PHASES}
    limits[guard.REGISTRY_FILENAME] = guard.REGISTRY_LIMIT
    limits[RESULT_FILENAME] = 16384
    def read_fixed(name):
        _need(type(name) is str and name in limits, 'GC102_FIXED_DIAGNOSTIC_REJECTED')
        path = _contained(session/name,session)
        before = path.stat()
        _need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limits[name], 'GC102_DIAGNOSTIC_BOUND_REJECTED')
        with path.open('rb') as stream:
            body = stream.read(limits[name]+1)
        after = path.stat()
        _need(len(body)==before.st_size==after.st_size
              and (before.st_mtime_ns,before.st_ino)==(after.st_mtime_ns,after.st_ino),
              'GC102_DIAGNOSTIC_CHANGED')
        return body
    return verify_receipts(read_fixed(RESULT_FILENAME),read_fixed)


if __name__=='__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-session',required=True)
    try:
        print(json.dumps(inspect_session(parser.parse_args().verify_session),separators=(',',':')))
    except Exception:
        print('{"passed":false,"code":"GC102_PHYSICAL_TERMINAL_REJECTED"}')
        raise SystemExit(1)
