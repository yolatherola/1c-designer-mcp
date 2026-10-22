"""Pure V115 session and physical-result proof; no native close/lease authority."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat

from gold_owned_constant_session_contract_v102 import _mask, _parts, _ordered

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'tests/NativeGoldOwnedManagedFormSessionV115.as'
SOURCE_SHA256 = 'b24ff4f92d14d48dc8cf84a1ef42f353bcf848e720f1f672bcba00125556a39c'
ENTRY_SHA256 = '5c0e8d34695ba176b988bbc8261a5d6c62b68797faf80657087fd12eb4ae34e1'
GUARD_SHA256 = 'd25d311b2ddfaaa5b7512ff8068f50f7c52fb0cd952602792fae7ae1673f2a7e'
PREFIX = 'ahGoldOwnedManagedFormV107'
RESULT_FILENAME = 'gold-owned-managed-form-v107.json'
ENTRY_CALL = PREFIX + '(operation,' + PREFIX + 'Consumed,' + PREFIX + 'State,terminalResult,attemptedWrites)'
FIELDS = ('factories','attaches','setters','body.nameSetters','body.stores','body.deletes')
BOUNDS = dict(factories=2,attaches=2,setters=1,**{'body.nameSetters':2,'body.stores':1,'body.deletes':2})
FUNCTIONS = (PREFIX+'AttemptsV115', PREFIX+'CountersKnownV115', PREFIX+'Permit',
             PREFIX+'SafeTerminal', 'ahGoldOwnedManagedFormSessionV115')


def need(ok, code):
    if not ok:raise ValueError('GM115_' + code)


def verify_source(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 16384, 'SOURCE_BOUND')
    try:text = raw.decode('utf-8')
    except UnicodeError:raise ValueError('GM115_SOURCE_ENCODING') from None
    code = _mask(text);declarations, functions = _parts(code)
    need(declarations == ['bool'+PREFIX+'Enabled=__GOLD_OWNED_MANAGED_FORM_V107__',
        'bool'+PREFIX+'Consumed=false,'+PREFIX+'Terminal=false',
        'uint'+PREFIX+'WriteAttempts=0','AhGoldManagedStateV107'+PREFIX+'State'], 'GLOBAL_STATE')
    need(set(functions) == set(FUNCTIONS), 'FUNCTION_SET')
    need(not re.search(r'\b(?:initialize|eval|Execute|CreateFile|LoadLibrary|initFuncDefFromAddress|setMdPropVal|setModified|clearModified|UpdateDBCfg|SaveCfg|createByClsid|mem)\b',code), 'FORBIDDEN_EFFECT')
    need(code.count(PREFIX+'(') == 1 and ENTRY_CALL in code, 'SINGLE_ENTRY')
    attempts = functions[PREFIX+'AttemptsV115']
    need(all(attempts.count(PREFIX+'State.'+key) == 1 for key in FIELDS)
         and attempts.count('State.') == len(FIELDS) and attempts.count('ahGMIdSettersV107') == 1, 'ATTEMPTS')
    counters = functions[PREFIX+'CountersKnownV115']
    need(all(PREFIX+'State.'+key+'<='+str(limit) in counters for key,limit in BOUNDS.items())
         and 'ahGMIdSettersV107<=2' in counters and PREFIX+'AttemptsV115()<=12' in counters, 'COUNTER_BOUND')
    need(PREFIX+'Enabled && !'+PREFIX+'Consumed && ahGMPermitV107(operation)' in functions[PREFIX+'Permit'], 'PERMIT')
    safe = functions[PREFIX+'SafeTerminal']
    need(all(item in safe for item in (PREFIX+'Enabled',PREFIX+'Consumed',PREFIX+'Terminal',
        '!'+PREFIX+'State.unknown','!ahGMUnknownV107',PREFIX+'CountersKnownV115()',
        PREFIX+'WriteAttempts=='+PREFIX+'AttemptsV115()',
        'ahGoldOwnedManagedFormSafeTerminalV107('+PREFIX+'State)')) and '||' not in safe, 'FRESH_TERMINAL')
    wrapper = functions['ahGoldOwnedManagedFormSessionV115']
    need(_ordered(wrapper,'if(!'+PREFIX+'Permit(operation))',PREFIX+'Terminal=false',
          ENTRY_CALL,PREFIX+'WriteAttempts='+PREFIX+'AttemptsV115()'), 'ONESHOT_ORDER')
    need('bool terminalResult=false;uint attemptedWrites=0;' in wrapper and 'CppCatch caught(' in wrapper
         and 'catcher.hasException' in wrapper and 'attemptedWrites!='+PREFIX+'WriteAttempts' in wrapper
         and code.count(PREFIX+'State.unknown=true') == 2, 'UNKNOWN_STICKY')
    need('ahCycleDurable("'+RESULT_FILENAME+'",result)' in text
         and _ordered(wrapper,'if(!ahCycleDurable(',PREFIX+'Terminal=terminalResult && !'+PREFIX+'State.unknown && !ahGMUnknownV107'), 'DURABLE_BEFORE_TERMINAL')
    need(not re.search(r'\b(?:parse|json|fromString|valueFromString)\w*\s*\(',code,re.I), 'NO_JSON_AUTHORITY')
    need(hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'SOURCE_PIN')
    return dict(sessionSourceVerified=True, sourceSha256=SOURCE_SHA256, callerHeldState=True,
        metadataAttemptLimit=12,resultFilename=RESULT_FILENAME,freshTerminalRequired=True,
        nativePermit=False,safeTerminalRuntimeVerified=False,persistedGoldVerified=False,
        databaseUpdateAuthorized=False,repositoryWritesPermitted=False)


def verify_static():
    entry = importlib.import_module('gold_owned_managed_form_contract_v107').verify_static()
    need(entry['sourceSha256'] == ENTRY_SHA256, 'ENTRY_PIN')
    need(hashlib.sha256((HERE/'gold_owned_managed_form_guard_v107.py').read_bytes()).hexdigest() == GUARD_SHA256,'GUARD_PIN')
    result = verify_source(SOURCE.read_bytes())
    result.update(entrySourceSha256=ENTRY_SHA256,guardSourceSha256=GUARD_SHA256,pinnedManagedFormStaticVerified=True)
    return result


def parse_host_terminal(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 65536, 'TERMINAL_BOUND')
    def pairs(items):
        out = {}
        for key,value in items:
            need(key not in out, 'TERMINAL_DUPLICATE');out[key]=value
        return out
    def invalid(_):raise ValueError('GM115_TERMINAL_NONFINITE')
    try:info=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=pairs,parse_constant=invalid)
    except (UnicodeError,json.JSONDecodeError,RecursionError):raise ValueError('GM115_TERMINAL_ENCODING') from None
    need(type(info) is dict,'TERMINAL_SHAPE')
    return info


def terminal_ready(terminal, comparison):
    """Typed completed host facts only, never process or lease operations."""
    need(type(comparison) is dict and comparison.get('passed') is True
         and comparison.get('safeTerminalObserved') is True and type(comparison.get('ownManagedFormVerified')) is bool
         and type(comparison.get('writeCount')) is int and 0<=comparison['writeCount']<=12,'COMPARISON')
    need(type(terminal) is dict and terminal.get('stage')=='gold-owned-managed-form-v107-host'
         and terminal.get('goldOwnedManagedFormV107') is True
         and terminal.get('goldOwnedManagedFormTerminalVerifiedV107') is True
         and type(terminal.get('goldOwnedManagedFormVerifiedV107')) is bool
         and terminal['goldOwnedManagedFormVerifiedV107'] is comparison['ownManagedFormVerified']
         and terminal.get('closeConfirmed') is True and terminal.get('processStopped') is True
         and type(terminal.get('writeCount')) is int and terminal['writeCount']==comparison['writeCount']
         and terminal.get('normalDesignerExitClaimed') is False
         and terminal.get('closeMethod')=='protected-ACK-fresh-CLOSE_VERIFY-and-held-original-loader-Dispose'
         and all(terminal.get(k) is False for k in ('goldOwnedConstantV99','goldOwnObjectModuleV82','goldOwnObjectModuleV78','captureFreshV81'))
         and all(type(terminal.get(k)) is int and terminal[k]==0 for k in ('configurationSaves','databaseUpdates','repositoryMutations')),
         'TERMINAL_REJECTED')
    return True


def verify_receipts(raw,read_marker,read_binary):
    guard=importlib.import_module('gold_owned_managed_form_guard_v107')
    info=guard.parse_result(raw)
    seen=set();marker_names={guard.marker_filename(phase) for phase in guard.PHASES}
    def marker(name):
        result=read_marker(name)
        if name in marker_names:seen.add(name)
        return result
    terminal=guard.verify_terminal(info,info['version'],marker,info['operationId'])
    capability=terminal['managedFormVerified'];failure=None;resources=0
    if capability:
        # No exception from native/identity/alias/source/writer/physical checks
        # is eligible for the narrow resource-only refusal classification.
        binaries,_,_=guard.verify_nonresource_full(info,info['version'],marker,read_binary,info['operationId'])
        resources=len(binaries)
        try:
            guard.verify_resource_capability(binaries)
        except ValueError as error:
            if type(error) is not ValueError or error.args!=('V80_UNREVIEWED_RESOURCE_CHANGE',):
                raise
            guard.verify_own_resource_refusal_scope(binaries)
            capability=False;failure='V80_UNREVIEWED_RESOURCE_CHANGE'
    return dict(passed=True,safeTerminalObserved=True,ownManagedFormVerified=capability,
        writeCount=info['writeAttempts'],operationId=info['operationId'],
        physicalMarkerCount=len(seen),resourceCount=resources,capabilityFailureCode=failure,
        resourceNormalizationVerified=False,
        processStopPermitted=False,leaseMutationPermitted=False,persistedGoldVerified=False)


def _contained(path,boundary):
    path,boundary=Path(os.path.abspath(path)),Path(os.path.abspath(boundary))
    need(path.is_relative_to(boundary),'PATH_SCOPE')
    for component in (path,*path.parents):
        if component.exists() or component.is_symlink():
            item=component.lstat()
            need(not stat.S_ISLNK(item.st_mode) and not getattr(item,'st_file_attributes',0)&0x400,'REPARSE')
        if component==boundary:break
    return path


def inspect_session(session):
    """Read closed own diagnostics only; never read connections or Gold data."""
    root=HERE.parents[3];session=_contained(Path(session),root/'build')
    need(session.parent.parent==root/'build' and re.fullmatch('designer-v43-[a-f0-9]{32}',session.parent.name)
         and re.fullmatch('session-[a-f0-9]{32}',session.name),'SESSION_PATH')
    verify_static()
    guard=importlib.import_module('gold_owned_managed_form_guard_v107')
    limits={guard.marker_filename(p):guard.MARKER_LIMIT for p in guard.PHASES}
    limits[guard.REGISTRY_FILENAME]=guard.REGISTRY_LIMIT;limits[RESULT_FILENAME]=guard.RESULT_LIMIT
    limits.update({name:guard.BINARY_LIMIT for name in guard.BINARY_FILENAMES})
    def read_fixed(name):
        need(type(name) is str and name in limits,'FIXED_NAME')
        path=_contained(session/name,session);before=path.stat()
        need(stat.S_ISREG(before.st_mode) and 0<before.st_size<=limits[name],'FILE_BOUND')
        with path.open('rb') as stream:body=stream.read(limits[name]+1)
        after=path.stat()
        need(len(body)==before.st_size==after.st_size and (before.st_mtime_ns,before.st_ino)==(after.st_mtime_ns,after.st_ino),'FILE_CHANGED')
        return body
    return verify_receipts(read_fixed(RESULT_FILENAME),read_fixed,read_fixed)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify-session',required=True)
    try:print(json.dumps(inspect_session(parser.parse_args().verify_session),separators=(',',':')))
    except Exception:
        print('{"passed":false,"code":"GM115_PHYSICAL_TERMINAL_REJECTED"}')
        raise SystemExit(1)
