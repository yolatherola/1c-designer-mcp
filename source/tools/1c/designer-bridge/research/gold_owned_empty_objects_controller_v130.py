"""Bounded physical exchanges/result for V130. No live/process capability."""
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

COMMANDS = ('PING','STATUS','READLIVE','SOURCE_ONCE','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','GOLD_OWNED_EMPTY_OBJECTS_V130','CLOSE_SAFE')
RESULT = 'gold-owned-empty-objects-v130.json'

def need(ok, code):
    if not ok:raise ValueError('GE130_' + code)

def parse_object(raw):
    def pairs(items):
        result={}
        for k,v in items:need(k not in result,'DUPLICATE_JSON');result[k]=v
        return result
    def invalid(_):raise ValueError('GE130_NONFINITE_JSON')
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
    result=session/('owned-empty-objects-client-v130-'+operation+'-'+exchange+'.txt')
    witness=session/('owned-empty-objects-caller-v130-'+operation+'-'+exchange+'.json')
    need(type(reply.get('resultFile')) is str and Path(reply['resultFile'])==result and type(reply.get('callerWitnessFile')) is str and Path(reply['callerWitnessFile'])==witness,'EXCHANGE_PATH')
    raw=read_fixed(result,session,1048576,command=='PING');wraw=read_fixed(witness,session,8192)
    need(reply['bytes']==len(raw) and reply.get('sha256')==hashlib.sha256(raw).hexdigest() and reply.get('callerWitnessSha256')==hashlib.sha256(wraw).hexdigest(),'EXCHANGE_HASH')
    row=parse_object(wraw);need(set(row)=={'command','operationId','exchangeId','caller'} and row['command']==command and row['operationId']==operation
        and row['exchangeId']==exchange and row['caller']==caller and type(row['caller']['pid']) is int,'CALLER_WITNESS')
    return raw

def inspect_physical(session,operation,version):
    from gold_owned_empty_objects_guard_v130 import parse_result,verify,PHASES,marker_filename,registry_filename,MARKER_LIMIT,REGISTRY_LIMIT,LIMIT
    session=Path(session);bodies={}
    limits={marker_filename(p):MARKER_LIMIT for p in PHASES}
    limits.update({registry_filename(k):REGISTRY_LIMIT for k in ('Document','Catalog')});limits[RESULT]=LIMIT
    def read(name):
        need(name in limits,'WITNESS_NAME');raw=read_fixed(session/name,session,limits[name])
        if name in bodies:need(bodies[name]==raw,'WITNESS_CHANGED')
        bodies[name]=raw;return raw
    native=parse_result(read(RESULT));comparison=verify(native,version,read)
    need(comparison['safeTerminalObserved'] is True and native['operationId']==operation,'PHYSICAL_OPERATION')
    return native,comparison,bodies


def terminal_ready(terminal,comparison):
    """Physical typed capability and fresh authenticated host close must agree."""
    need(type(comparison) is dict and comparison.get('safeTerminalObserved') is True
         and type(comparison.get('ownEmptyObjectsVerified')) is bool
         and type(comparison.get('writeCount')) is int and 0<=comparison['writeCount']<=10,'COMPARISON')
    need(type(terminal) is dict and terminal.get('stage')=='gold-owned-empty-objects-v130-host'
         and terminal.get('goldOwnedEmptyObjectsV130') is True
         and terminal.get('goldOwnedEmptyObjectsTerminalVerifiedV130') is True
         and type(terminal.get('goldOwnedEmptyObjectsVerifiedV130')) is bool
         and terminal['goldOwnedEmptyObjectsVerifiedV130'] is comparison['ownEmptyObjectsVerified']
         and terminal.get('closeConfirmed') is True and terminal.get('processStopped') is True
         and type(terminal.get('writeCount')) is int and terminal['writeCount']==comparison['writeCount']
         and terminal.get('normalDesignerExitClaimed') is False
         and terminal.get('closeMethod')=='protected-ACK-fresh-CLOSE_VERIFY-and-held-original-loader-Dispose'
         and all(terminal.get(k) is False for k in ('goldOwnedManagedFormV107','goldOwnedConstantV99','goldOwnObjectModuleV82','goldOwnObjectModuleV78','captureFreshV81'))
         and all(type(terminal.get(k)) is int and terminal[k]==0 for k in ('configurationSaves','databaseUpdates','repositoryMutations')),'TERMINAL_REJECTED')
    return True


def verify_static():
    from gold_owned_empty_objects_contract_v130 import verify_static as prototype
    body=Path(__file__).parents[1]/'tests/NativeGoldOwnedEmptyObjectsSessionV130.as'
    raw=body.read_bytes();text=raw.decode('utf-8-sig')
    for literal in ('ahGoldOwnedEmptyObjectsV130FreshState','ahGEBaseV130(s)',
                    'ahGEForeignGraphV130(s.scope.root,0,nodes,s)',
                    's.scope.root.objById(ahGEIdV130(0))','s.scope.root.objById(ahGEIdV130(1))',
                    'ahGoldOwnedEmptyObjectsV130State.unknown=true',
                    'ahGoldOwnedEmptyObjectsV130Terminal=false',
                    'ahCycleDurable("gold-owned-empty-objects-v130.json",result)'):
        need(literal in text,'SESSION_SOURCE')
    need(text.index('ahCycleDurable("gold-owned-empty-objects-v130.json",result)') <
         text.index('ahGoldOwnedEmptyObjectsV130Terminal=terminalResult'),'DURABLE_ORDER')
    need(text.count('result=ahGoldOwnedEmptyObjectsV130(')==1 and '10' in text,'ONE_ENTRY')
    return dict(passed=True,prototype=prototype(),sessionSourceSha256=hashlib.sha256(raw).hexdigest(),
                controllerSourceSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),nativeAuthority=False)


def verify_session(session):
    session=Path(session)
    need(re.fullmatch('session-[a-f0-9]{32}',session.name) is not None,'SESSION_PATH')
    from gold_owned_empty_objects_guard_v130 import parse_result,LIMIT
    raw=read_fixed(session/RESULT,session,LIMIT);info=parse_result(raw)
    _,comparison,_=inspect_physical(session,info['operationId'],info['version'])
    return comparison


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--verify-session',required=True)
    try:print(json.dumps(verify_session(parser.parse_args().verify_session)))
    except Exception:
        print(json.dumps(dict(passed=False,code='GE130_PHYSICAL_REJECTED')));raise SystemExit(1)
