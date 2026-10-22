"""Closed own diagnostics for the managed-form controller; no native actions."""
import hashlib
import json
from pathlib import Path
import re
import stat
from pending_operation_inspector import contained


def need(ok,code):
    if not ok:raise ValueError('GM116_'+code)


def parse_object(raw):
    def pairs(items):
        value={}
        for key,item in items:
            need(key not in value,'DUPLICATE_JSON');value[key]=item
        return value
    def nonfinite(_):raise ValueError('GM116_NONFINITE_JSON')
    try:result=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=pairs,parse_constant=nonfinite)
    except (UnicodeError,json.JSONDecodeError,RecursionError):raise ValueError('GM116_JSON_REJECTED') from None
    need(type(result) is dict,'OBJECT_REQUIRED')
    return result


def read_fixed(path,boundary,limit,allow_empty=False):
    path=contained(Path(path),Path(boundary));before=path.stat()
    need(path.parent==boundary and stat.S_ISREG(before.st_mode) and (0 if allow_empty else 1)<=before.st_size<=limit,'FILE_BOUND')
    with path.open('rb') as stream:raw=stream.read(limit+1)
    after=path.stat()
    need(len(raw)==before.st_size==after.st_size and
         (before.st_mtime_ns,before.st_ino)==(after.st_mtime_ns,after.st_ino),'FILE_CHANGED')
    return raw


def verify_exchange(reply,command,operation,caller,session):
    """Compare a real held caller with its unique durable exchange witnesses."""
    session=Path(session)
    need(type(reply) is dict and reply.get('command')==reply.get('status')==command
         and reply.get('operationId')==operation and type(operation) is str
         and re.fullmatch('[a-f0-9]{32}',operation),'EXCHANGE_HEADER')
    exchange=reply.get('exchangeId')
    need(type(exchange) is str and re.fullmatch('[a-f0-9]{32}',exchange),'EXCHANGE_ID')
    need(type(caller) is dict and set(caller)=={'pid','birth'} and type(caller['pid']) is int
         and caller['pid']>0 and type(caller['birth']) is str
         and re.fullmatch('[a-f0-9]{16}',caller['birth']) and reply.get('caller')==caller
         and type(reply.get('caller')) is dict and type(reply['caller'].get('pid')) is int,'CALLER_IDENTITY')
    need(type(reply.get('replayed')) is bool and type(reply.get('bytes')) is int
         and (0 if command=='PING' else 1)<=reply['bytes']<=1048576,'EXCHANGE_TYPES')
    result=session/('owned-managed-form-client-v107-'+operation+'-'+exchange+'.txt')
    witness=session/('owned-managed-form-caller-v107-'+operation+'-'+exchange+'.json')
    need(type(reply.get('resultFile')) is str and Path(reply['resultFile'])==result
         and type(reply.get('callerWitnessFile')) is str and Path(reply['callerWitnessFile'])==witness,'EXCHANGE_PATH')
    raw=read_fixed(result,session,1048576,command=='PING');wraw=read_fixed(witness,session,8192)
    need(reply['bytes']==len(raw) and reply.get('sha256')==hashlib.sha256(raw).hexdigest()
         and reply.get('callerWitnessSha256')==hashlib.sha256(wraw).hexdigest(),'EXCHANGE_HASH')
    row=parse_object(wraw)
    need(set(row)=={'command','operationId','exchangeId','caller'}
         and row['command']==command and row['operationId']==operation and row['exchangeId']==exchange
         and type(row['caller']) is dict and set(row['caller'])=={'pid','birth'}
         and type(row['caller']['pid']) is int and row['caller']==caller,'CALLER_WITNESS')
    return raw


def inspect_physical(session,operation,version):
    """Read just the fixed diagnostics required by the actual native outcome."""
    from gold_owned_managed_form_guard_v107 import (parse_result,verify_terminal,PHASES,
        marker_filename,REGISTRY_FILENAME,RESULT_FILENAME,MARKER_LIMIT,REGISTRY_LIMIT,
        RESULT_LIMIT,BINARY_FILENAMES,BINARY_LIMIT)
    from gold_owned_managed_form_session_contract_v115 import verify_receipts
    session=Path(session);bodies={}
    limits={marker_filename(p):MARKER_LIMIT for p in PHASES}
    limits.update({REGISTRY_FILENAME:REGISTRY_LIMIT,RESULT_FILENAME:RESULT_LIMIT})
    limits.update({n:BINARY_LIMIT for n in BINARY_FILENAMES})
    def read(name):
        need(type(name) is str and name in limits,'WITNESS_NAME')
        raw=read_fixed(session/name,session,limits[name])
        if name in bodies:need(bodies[name]==raw,'WITNESS_CHANGED')
        bodies[name]=raw
        return raw
    raw=read(RESULT_FILENAME);native=parse_result(raw)
    verify_terminal(native,version,read,operation)
    comparison=verify_receipts(raw,read,read)
    need(comparison['operationId']==operation and native['operationId']==operation,'PHYSICAL_OPERATION')
    return native,comparison,bodies
