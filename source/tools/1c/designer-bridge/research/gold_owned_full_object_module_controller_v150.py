"""Bounded physical exchanges/result for V150. No live/process capability."""
from pathlib import Path
import hashlib
import json
import re
import stat
import sys

# The host also invokes this verifier by absolute script path without PYTHONPATH.
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'tests')]
from pending_operation_inspector import contained

COMMANDS = ('PING','STATUS','READLIVE','SOURCE_ONCE','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','GOLD_OWNED_FULL_OBJECT_MODULE_V150','CLOSE_SAFE')
RESULT = 'gold-owned-full-object-module-v150.json'

def need(ok, code):
    if not ok:raise ValueError('GFM150_' + code)

def parse_object(raw):
    def pairs(items):
        result={}
        for k,v in items:need(k not in result,'DUPLICATE_JSON');result[k]=v
        return result
    def invalid(_):raise ValueError('GFM150_NONFINITE_JSON')
    need(type(raw) is bytes and 0<len(raw)<=1048576,'JSON_BOUND')
    result=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=pairs,parse_constant=invalid)
    need(type(result) is dict,'OBJECT_REQUIRED');return result

def parse_host_terminal(raw):
    need(type(raw) is bytes and 0<len(raw)<=65536,'HOST_BOUND')
    return parse_object(raw)


def read_fixed(path,boundary,limit,allow_empty=False):
    boundary=Path(boundary);path=contained(Path(path),boundary);before=path.stat()
    need(path.parent==boundary and stat.S_ISREG(before.st_mode) and (0 if allow_empty else 1)<=before.st_size<=limit,'FILE_BOUND')
    with path.open('rb') as stream:raw=stream.read(limit+1)
    after=path.stat();need(len(raw)==before.st_size==after.st_size and (before.st_mtime_ns,before.st_ino)==(after.st_mtime_ns,after.st_ino),'FILE_CHANGED')
    return raw

def verify_exchange(reply,command,operation,caller,session,server=None):
    session=Path(session)
    need(command in COMMANDS and type(operation) is str and re.fullmatch('[a-f0-9]{32}',operation),'COMMAND')
    need(type(reply) is dict and reply.get('command')==reply.get('status')==command and reply.get('operationId')==operation,'EXCHANGE_HEADER')
    if server is not None:
        need(type(server) is tuple and len(server)==2 and type(server[0]) is int and 0<server[0]<=0x7fffffff and type(server[1]) is str
             and re.fullmatch('[a-f0-9]{16}',server[1]) and server[1]!='0'*16
             and type(reply.get('processId')) is int and reply['processId']==server[0]
             and reply.get('processCreationFileTimeUtc')==reply.get('birth')==server[1],'SERVER_IDENTITY')
    exchange=reply.get('exchangeId');need(type(exchange) is str and re.fullmatch('[a-f0-9]{32}',exchange),'EXCHANGE_ID')
    need(type(caller) is dict and set(caller)=={'pid','birth'} and type(caller['pid']) is int and 0<caller['pid']<=0x7fffffff
         and type(caller['birth']) is str and re.fullmatch('[a-f0-9]{16}',caller['birth']) and caller['birth']!='0'*16
         and reply.get('caller')==caller and type(reply['caller']['pid']) is int,'CALLER')
    need(type(reply.get('bytes')) is int and (0 if command=='PING' else 1)<=reply['bytes']<=1048576 and type(reply.get('replayed')) is bool,'EXCHANGE_TYPE')
    result=session/('owned-full-object-module-client-v150-'+operation+'-'+exchange+'.txt')
    witness=session/('owned-full-object-module-caller-v150-'+operation+'-'+exchange+'.json')
    need(type(reply.get('resultFile')) is str and Path(reply['resultFile'])==result and type(reply.get('callerWitnessFile')) is str and Path(reply['callerWitnessFile'])==witness,'EXCHANGE_PATH')
    raw=read_fixed(result,session,1048576,command=='PING');wraw=read_fixed(witness,session,8192)
    need(reply['bytes']==len(raw) and reply.get('sha256')==hashlib.sha256(raw).hexdigest() and reply.get('callerWitnessSha256')==hashlib.sha256(wraw).hexdigest(),'EXCHANGE_HASH')
    row=parse_object(wraw);need(set(row)=={'command','operationId','exchangeId','caller'} and row['command']==command and row['operationId']==operation
        and row['exchangeId']==exchange and row['caller']==caller and type(row['caller']['pid']) is int,'CALLER_WITNESS')
    return raw

def parse_result(raw):
    from gold_owned_full_object_module_guard_v150 import parse
    return parse(raw)


def verify_native(native,version,read):
    from gold_owned_full_object_module_guard_v150 import PHASES,marker_filename,REGISTRY_FILENAME,verify_observation
    need(type(version) is int and version>=0,'SOURCE_VERSION')
    need(type(native) is dict and type(native.get('phases')) is list,'NATIVE_SHAPE')
    markers={marker_filename(p):read(marker_filename(p)) for p,v in zip(PHASES,native['phases']) if v}
    registry=read(REGISTRY_FILENAME)
    readbacks={key:read('gold-owned-full-object-module-v150-'+key+'.utf8') for key in ('editor','helper','empty-editor','empty-helper')} if native.get('completeObservation') is True else {}
    comparison=verify_observation(json.dumps(native,separators=(',',':')).encode('utf-8'),markers,registry,readbacks)
    need(comparison['textCycleObservationVerified'] is True and comparison['knownCleanTerminalObserved'] is True
         and native['writeAttempts']==9,'FULL_TERMINAL_REQUIRED')
    bodies=markers|{REGISTRY_FILENAME:registry}|{'gold-owned-full-object-module-v150-'+key+'.utf8':raw for key,raw in readbacks.items()}
    need(len(bodies)==37,'PHYSICAL_CORE_COUNT')
    return comparison|dict(safeTerminalObserved=True,ownFullObjectModuleVerified=True,writeCount=9,physicalWitnessCount=38,
        physicalWitnessSha256={name:hashlib.sha256(body).hexdigest() for name,body in bodies.items()})


def physical_limit(name):
    from gold_owned_full_object_module_guard_v150 import PHASES,marker_filename,REGISTRY_FILENAME
    if name==RESULT:return 32768,False
    if name in {marker_filename(p) for p in PHASES}|{REGISTRY_FILENAME}:return 1024,False
    if name in {'gold-owned-full-object-module-v150-'+key+'.utf8' for key in ('editor','helper','empty-editor','empty-helper')}:
        return 262144,name.endswith(('empty-editor.utf8','empty-helper.utf8'))
    raise ValueError('GFM150_WITNESS_NAME')


def inspect_physical(session,operation,version):
    session=Path(session);bodies={}
    def read(name):
        limit,empty=physical_limit(name);raw=read_fixed(session/name,session,limit,empty)
        if name in bodies:need(bodies[name]==raw,'WITNESS_CHANGED')
        bodies[name]=raw;return raw
    native=parse_result(read(RESULT));comparison=verify_native(native,version,read)
    need(native['operationId']==operation,'PHYSICAL_OPERATION')
    from gold_owned_full_object_module_contract_v150 import prepare_payload
    input_raw=read_fixed(session/'gold-owned-full-object-module-v150-input.utf8',session,74501)
    prepare_payload(input_raw)
    dispatched=read_fixed(session/'gold-owned-full-object-module-v150-dispatched',session,32)
    need(dispatched==operation.encode('ascii'),'ENTRY_OPERATION')
    return native,comparison,bodies


def terminal_ready(terminal,comparison):
    """Physical typed capability and fresh authenticated host close must agree."""
    need(type(comparison) is dict and comparison.get('safeTerminalObserved') is True
         and type(comparison.get('ownFullObjectModuleVerified')) is bool
         and comparison.get('ownFullObjectModuleVerified') is True and type(comparison.get('writeCount')) is int and comparison['writeCount']==9,'COMPARISON')
    need(type(terminal) is dict and terminal.get('stage')=='gold-owned-full-object-module-v150-host'
         and terminal.get('goldOwnedFullObjectModuleV150') is True
         and terminal.get('goldOwnedFullObjectModuleTerminalVerifiedV150') is True
         and terminal.get('goldOwnedFullObjectModuleVerifiedV150') is True
         and terminal['goldOwnedFullObjectModuleVerifiedV150'] is comparison['ownFullObjectModuleVerified']
         and terminal.get('closeConfirmed') is True and terminal.get('processStopped') is True
         and type(terminal.get('writeCount')) is int and terminal['writeCount']==comparison['writeCount']
         and terminal.get('normalDesignerExitClaimed') is False
         and terminal.get('closeMethod')=='protected-ACK-fresh-CLOSE_VERIFY-and-held-original-loader-Dispose'
         and all(terminal.get(k) is False for k in ('managedInputRecordV145','goldOwnedDocumentStructureV139','goldOwnedEmptyObjectsV130','goldOwnedManagedFormV107','goldOwnedConstantV99','goldOwnObjectModuleV82','goldOwnObjectModuleV78','captureFreshV81'))
         and all(type(terminal.get(k)) is int and terminal[k]==0 for k in ('configurationSaves','databaseUpdates','repositoryMutations')),'TERMINAL_REJECTED')
    return True


def verify_static():
    from gold_owned_full_object_module_contract_v150 import verify_static as prototype
    body=Path(__file__).parents[1]/'tests/NativeGoldOwnedFullObjectModuleSessionV150.as'
    raw=body.read_bytes();text=raw.decode('utf-8-sig')
    for literal in ('ahGoldOwnedFullObjectModuleV150FreshState','ahGFMRootV150(s)','ahGCSourceV99(s.scope)',
                    'ahGFMGraphV150(s.scope.root,0,count,s)','s.scope.root.objById(ahGFMIdV150()) !is null',
                    's.scope.root.childCount(ahGFMKindV150())!=s.beforeCount','MemoryBuffer ahGoldOwnedFullObjectModuleV150Input(74501)',
                    'MemoryBuffer extra(1)','trailing!=0','ahGFMInputHeldV150(ahGoldOwnedFullObjectModuleV150Input,s)',
                    'ahGoldOwnedFullObjectModuleV150State.unknown=true','ahGoldOwnedFullObjectModuleV150Terminal=false'):
        need(literal in text,'SESSION_SOURCE')
    need(text.count('result=ahGoldOwnedFullObjectModuleV150(')==1 and 's.attempts!=9' in text,'ONE_ENTRY')
    need('ahCycleDurable("gold-owned-full-object-module-v150.json"' not in text,'NO_DUPLICATE_RESULT_WRITE')
    need(text.index('ahGoldOwnedFullObjectModuleV150FreshState()){') < text.index('ahGoldOwnedFullObjectModuleV150Terminal=true;'),'TERMINAL_ORDER')
    return dict(passed=True,prototype=prototype(),sessionSourceSha256=hashlib.sha256(raw).hexdigest(),
                controllerSourceSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),nativeAuthority=False)


def verify_session(session):
    session=Path(session)
    need(re.fullmatch('session-[a-f0-9]{32}',session.name) is not None,'SESSION_PATH')
    from gold_owned_full_object_module_guard_v150 import parse
    LIMIT=32768
    raw=read_fixed(session/RESULT,session,LIMIT);info=parse_result(raw)
    _,comparison,_=inspect_physical(session,info['operationId'],0)
    return comparison


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--verify-session',required=True)
    try:print(json.dumps(verify_session(parser.parse_args().verify_session)))
    except Exception:
        print(json.dumps(dict(passed=False,code='GFM150_PHYSICAL_REJECTED')));raise SystemExit(1)
