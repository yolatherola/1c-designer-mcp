"""Pure sealed-session/physical verifier for the dedicated own-memory route."""
import hashlib
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
for directory in (HERE,HERE.parent/'tests'):
    if str(directory) not in sys.path:sys.path.insert(0,str(directory))
from gold_owned_document_structure_controller_v139 import read_fixed,parse_object,parse_host_terminal
from managed_input_record_guard_v145 import parse_result,verify,PHASES,REGISTRIES,BINARIES,marker_filename,MARKER_LIMIT,RESULT_LIMIT,BINARY_LIMIT

RESULT='managed-input-record-v145.json'
COMMANDS={'PING','STATUS','READLIVE','SOURCE_ONCE','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','MANAGED_INPUT_RECORD_V145','CLOSE_SAFE'}
PERMIT_SOURCE='''bool ahManagedInputSessionPermitV145(const string&in operation){
    if(!ahManagedInputSessionEnabledV145 || ahManagedInputSessionConsumedV145 || !ahCommandHex(operation))return false;
    string path="__SESSION_PATH__/managed-input-record-v145-permit-"+operation;
    uint handle=CreateFile(path.cstr,0x80000000,1,0,3,0x80,0);if(handle==0xffffffff)return false;
    utf8string wanted=(ahManagedInputSessionTokenV145+"|"+operation+"|MANAGED_INPUT_RECORD_V145").toUtf8();
    MemoryBuffer input(wanted.length+1);uint count=0;
    bool okay=ReadFile(handle,input.bytes,wanted.length+1,mem::addressOf(count),0)!=0;CloseHandle(handle);
    if(!okay || count!=wanted.length)return false;
    for(uint i=0;i<count;i++)if(mem::byte[input.bytes+i]!=mem::byte[wanted.ptr+i])return false;
    return true;
}'''


def need(ok,code):
    if not ok:raise ValueError('V145_'+code)


def verify_permit_source(text):
    """Exact reader proved by V152: read one extra byte, accept only full equality."""
    start='bool ahManagedInputSessionPermitV145('
    end='\nbool ahManagedInputSessionSafeTerminalV145('
    need(type(text)is str and text.count(start)==1 and text.count(end)==1,'PERMIT_SOURCE')
    need(text[text.index(start):text.index(end)]==PERMIT_SOURCE,'PERMIT_SOURCE')
    return True


def verify_exchange(reply,command,operation,caller,session,server=None):
    session=Path(session)
    need(command in COMMANDS and type(operation)is str and re.fullmatch('[a-f0-9]{32}',operation),'COMMAND')
    need(type(reply)is dict and reply.get('command')==reply.get('status')==command and reply.get('operationId')==operation,'EXCHANGE_HEADER')
    if server is not None:
        need(type(server)is tuple and len(server)==2 and type(server[0])is int and 0<server[0]<=0x7fffffff
             and type(server[1])is str and re.fullmatch('[a-f0-9]{16}',server[1]) and server[1]!='0'*16
             and reply.get('processId')==server[0] and type(reply.get('processId'))is int
             and reply.get('processCreationFileTimeUtc')==reply.get('birth')==server[1],'SERVER_IDENTITY')
    exchange=reply.get('exchangeId');need(type(exchange)is str and re.fullmatch('[a-f0-9]{32}',exchange),'EXCHANGE_ID')
    need(type(caller)is dict and caller.keys()=={'pid','birth'} and type(caller['pid'])is int and 0<caller['pid']<=0x7fffffff
         and type(caller['birth'])is str and re.fullmatch('[a-f0-9]{16}',caller['birth']) and caller['birth']!='0'*16
         and reply.get('caller')==caller and type(reply['caller']['pid'])is int,'CALLER')
    result=session/('managed-input-client-v145-'+operation+'-'+exchange+'.txt')
    witness=session/('managed-input-caller-v145-'+operation+'-'+exchange+'.json')
    need(type(reply.get('resultFile'))is str and Path(reply['resultFile'])==result
         and type(reply.get('callerWitnessFile'))is str and Path(reply['callerWitnessFile'])==witness,'EXCHANGE_PATH')
    raw=read_fixed(result,session,1048576,command=='PING');wraw=read_fixed(witness,session,8192)
    need(type(reply.get('bytes'))is int and reply['bytes']==len(raw) and type(reply.get('replayed'))is bool
         and reply.get('sha256')==hashlib.sha256(raw).hexdigest()
         and reply.get('callerWitnessSha256')==hashlib.sha256(wraw).hexdigest(),'EXCHANGE_HASH')
    row=parse_object(wraw);need(row.keys()=={'command','operationId','exchangeId','caller'} and row['command']==command
         and row['operationId']==operation and row['exchangeId']==exchange and row['caller']==caller
         and type(row['caller']['pid'])is int,'CALLER_WITNESS')
    return raw


def inspect_physical(session,operation,version=None):
    session=Path(session);bodies={}
    need(session.is_absolute() and session.parent.parent==ROOT/'build'
         and re.fullmatch('designer-v43-[a-f0-9]{32}',session.parent.name)
         and re.fullmatch('session-[a-f0-9]{32}',session.name),'SESSION_PATH')
    need(type(operation)is str and re.fullmatch('[a-f0-9]{32}',operation),'OPERATION')
    if version is not None:need(type(version)is int and version>=0,'VERSION')
    limits={marker_filename(p):MARKER_LIMIT for p in PHASES}|{name:MARKER_LIMIT for name in REGISTRIES}
    limits.update({name:BINARY_LIMIT for name in BINARIES});limits[RESULT]=RESULT_LIMIT
    def read(name):
        need(name in limits,'WITNESS_NAME');raw=read_fixed(session/name,session,limits[name])
        if name in bodies:need(bodies[name]==raw,'WITNESS_CHANGED')
        bodies[name]=raw;return raw
    native=parse_result(read(RESULT));need(native['operationId']==operation,'PHYSICAL_OPERATION')
    comparison=verify(native,read,read)
    comparison.update(safeTerminalObserved=True,ownMemoryRoundtripVerified=True,writeCount=0)
    return native,comparison,bodies


def terminal_ready(terminal,comparison):
    need(type(comparison)is dict and comparison.get('verified')is True and comparison.get('safeTerminalObserved')is True
         and comparison.get('ownMemoryRoundtripVerified')is True and type(comparison.get('writeCount'))is int
         and comparison['writeCount']==0,'COMPARISON')
    need(type(terminal)is dict and terminal.get('stage')=='gold-readonly-command-host'
         and terminal.get('managedInputRecordV145')is True and terminal.get('managedInputTerminalVerifiedV145')is True
         and terminal.get('managedInputVerifiedV145')is True and terminal.get('closeConfirmed')is True
         and terminal.get('processStopped')is True and type(terminal.get('writeCount'))is int and terminal['writeCount']==0
         and all(terminal.get(k)is False for k in ('goldOwnedDocumentStructureV139','goldOwnedEmptyObjectsV130',
             'goldOwnedManagedFormV107','goldOwnedConstantV99','goldOwnObjectModuleV82','goldOwnObjectModuleV78','captureFreshV81'))
         and all(type(terminal.get(k))is int and terminal[k]==0 for k in ('configurationSaves','databaseUpdates','repositoryMutations')),'TERMINAL_REJECTED')
    return True


def verify_static():
    from managed_input_record_contract_v145 import verify_static as prototype
    raw=(HERE.parent/'tests/NativeManagedInputRecordSessionV145.as').read_bytes();text=raw.decode('utf-8-sig')
    verify_permit_source(text)
    for literal in ('ahManagedInputSessionStateV145.pins.length!=0','ahManagedInputSessionStateV145.unknown=true',
        'ahDocumentModulesV48Clean(','ahCommandSelectedBufferUnchanged()','ahPipeScopeAlive()',
        'root.objById(ahGDIdV139(0))','root.objById(ahGDIdV139(3))'):
        need(literal in text,'SESSION_SOURCE')
    need(text.count('result=ahManagedInputRecordV145(')==1
         and text.index('ahCycleDurable("managed-input-record-v145.json",result)')<text.index('ahManagedInputSessionTerminalV145=true'),'DURABLE_ORDER')
    return dict(passed=True,prototype=prototype(),sessionSourceSha256=hashlib.sha256(raw).hexdigest(),nativeAuthority=False)


def verify_session(session):
    session=Path(session);need(re.fullmatch('session-[a-f0-9]{32}',session.name),'SESSION_PATH')
    info=parse_result(read_fixed(session/RESULT,session,RESULT_LIMIT))
    return inspect_physical(session,info['operationId'])[1]


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--verify-session',required=True)
    try:print(json.dumps(verify_session(parser.parse_args().verify_session)))
    except Exception:
        print(json.dumps(dict(passed=False,code='V145_PHYSICAL_REJECTED')));raise SystemExit(1)
