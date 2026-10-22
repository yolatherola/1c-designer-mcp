"""Strict bounded eight-tool guardian frames. No OS, files, or attestation.

Builders emit canonical UTF-8 JSON. Parsers accept only the fixed envelopes and
allowlisted argument grammar; the owner independently verifies kernel peer,
binding-token possession/currentness, generation and native proof. Returned
source is legitimate caller-owned RAM only, never a diagnostic or file cache.
"""
import json
import math
import re
import struct

MAGIC=b'AH1CGDN1'
VERSION=1
HEADER_BYTES=16
MAX_REQUEST_BYTES=16384
MAX_RESPONSE_BYTES=131072
MAX_DEPTH=32
_HEADER=struct.Struct('<8sII')
TOOLS=frozenset(('health','open_saved_session','observe_module','read_module_slice','search_symbols','get_context',
                 'refresh_observed','close_saved_session'))
ERRORS=frozenset(('REQUEST_REFUSED','REQUEST_FAILED','DISCONNECTED','STALE_BINDING','BUSY','UNKNOWN_RETAIN'))
_UNBOUND=frozenset(('health','open_saved_session'))
_BASE=frozenset(('source_domain','generation','nocache'))
_TARGET=_BASE|{'object_uuid','property_uuid'}
_FIELDS={
    'health':(frozenset(('nocache',)),frozenset()),
    'open_saved_session':(frozenset(('nocache',)),frozenset()),
    'observe_module':(_TARGET,frozenset()),
    'read_module_slice':(_TARGET,frozenset(('offset','count','expected_sha256'))),
    'search_symbols':(_BASE,frozenset(('query','include_stale','limit','offset'))),
    'get_context':(_TARGET|{'method_name'},frozenset(('include_stale',))),
    'refresh_observed':(_BASE,frozenset()),
    'close_saved_session':(_BASE,frozenset()),
}


class GuardianWireRefusal(ValueError):
    """Stable body-free envelope, grammar, type or framing refusal."""


def _need(ok,code):
    if not ok:raise GuardianWireRefusal('GUARDIAN_WIRE_'+code)


def _integer(value,low,high):return type(value) is int and low<=value<=high
def _hex(value,size):return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None
def _token(value):return _hex(value,32) and value!='0'*32
def _uuid(value):return type(value) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value) is not None and value!='00000000-0000-0000-0000-000000000000'
def _word(value,minimum=0):return type(value) is str and minimum<=len(value)<=256 and not any(ord(c)<32 or ord(c)==127 for c in value)


def _tree(value,depth=0):
    _need(depth<=MAX_DEPTH,'JSON_DEPTH')
    if type(value) is dict:
        _need(all(type(k) is str for k in value),'JSON_KEY')
        for k,v in value.items():
            # Also rejects lone surrogate keys without reflecting the key.
            try:k.encode('utf-8','strict')
            except UnicodeError:raise GuardianWireRefusal('GUARDIAN_WIRE_UTF8') from None
            _tree(v,depth+1)
    elif type(value) is list:
        for item in value:_tree(item,depth+1)
    elif type(value) is str:
        _need(len(value)<=MAX_RESPONSE_BYTES,'PAYLOAD_BOUND')
        try:value.encode('utf-8','strict')
        except UnicodeError:raise GuardianWireRefusal('GUARDIAN_WIRE_UTF8') from None
    elif type(value) is float:_need(math.isfinite(value),'JSON_NONFINITE')
    else:_need(value is None or type(value) in (int,bool),'JSON_TYPE')


def _pairs(items):
    out={}
    for key,value in items:
        _need(key not in out,'JSON_DUPLICATE');out[key]=value
    return out


def _constant(_value):raise GuardianWireRefusal('GUARDIAN_WIRE_JSON_NONFINITE')


def _encode(row,maximum):
    _need(type(row) is dict,'JSON_OBJECT');_tree(row)
    try:raw=json.dumps(row,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8','strict')
    except (ValueError,TypeError,RecursionError,UnicodeError):raise GuardianWireRefusal('GUARDIAN_WIRE_JSON') from None
    _need(0<len(raw)<=maximum,'PAYLOAD_BOUND');return _HEADER.pack(MAGIC,VERSION,len(raw))+raw


def parse_header(header,*,response=False)->int:
    """Check the exact16-byte header before a transport allocates payload RAM."""
    _need(type(response) is bool,'MODE')
    _need(type(header) is bytes and len(header)==HEADER_BYTES,'HEADER_LENGTH')
    magic,version,size=_HEADER.unpack(header)
    _need(magic==MAGIC and version==VERSION,'HEADER')
    _need(0<size<=(MAX_RESPONSE_BYTES if response else MAX_REQUEST_BYTES),'PAYLOAD_BOUND')
    return size


def _decode(frame,*,response):
    _need(type(frame) is bytes and len(frame)>=HEADER_BYTES,'FRAME_LENGTH')
    size=parse_header(frame[:HEADER_BYTES],response=response)
    _need(len(frame)==HEADER_BYTES+size,'FRAME_LENGTH')
    try:row=json.loads(frame[HEADER_BYTES:].decode('utf-8','strict'),object_pairs_hook=_pairs,parse_constant=_constant)
    except GuardianWireRefusal:raise
    except (ValueError,TypeError,RecursionError,UnicodeError):raise GuardianWireRefusal('GUARDIAN_WIRE_JSON') from None
    _need(type(row) is dict,'JSON_OBJECT');_tree(row);return row


def _request(row):
    _need(type(row) is dict and row.keys()=={'kind','request_id','tool','args','binding_token'},'REQUEST_SCHEMA')
    _need(type(row['kind']) is str and row['kind']=='CALL' and _token(row['request_id'])
          and type(row['tool']) is str and row['tool'] in TOOLS,'REQUEST_IDENTITY')
    tool=row['tool'];args=row['args'];required,optional=_FIELDS[tool]
    _need(type(args) is dict and required<=args.keys()<=required|optional,'ARGUMENT_SCHEMA')
    _need(args['nocache'] is True,'NOCACHE')
    _need(row['binding_token'] is None if tool in _UNBOUND else _token(row['binding_token']),'BINDING_TOKEN')
    if tool in _UNBOUND:return
    _need(type(args['source_domain']) is str and args['source_domain']=='database_saved','DOMAIN')
    _need(_integer(args['generation'],1,2**53-1),'GENERATION')
    if 'object_uuid' in args:
        _need(_uuid(args['object_uuid']) and _uuid(args['property_uuid']) and args['object_uuid']!=args['property_uuid'],'TARGET')
    if 'offset' in args:_need(_integer(args['offset'],0,1048576),'OFFSET')
    if 'count' in args:_need(_integer(args['count'],1,16384),'COUNT')
    if 'limit' in args:_need(_integer(args['limit'],1,100),'LIMIT')
    if 'include_stale' in args:_need(type(args['include_stale']) is bool,'FLAG')
    if 'query' in args:_need(_word(args['query']),'QUERY')
    if 'method_name' in args:_need(_word(args['method_name'],1),'METHOD')
    if 'expected_sha256' in args:_need(args['expected_sha256'] is None or _hex(args['expected_sha256'],64),'HASH')
    if tool=='read_module_slice' and args.get('offset',0)>0:_need(args.get('expected_sha256') is not None,'CONTINUATION_HASH')


def build_request(row)->bytes:
    """Validate the exact eight-tool CALL grammar and emit canonical bytes."""
    _request(row);return _encode(row,MAX_REQUEST_BYTES)


def parse_request(frame)->dict:
    row=_decode(frame,response=False);_request(row);return row


def _response(row,request_id):
    _need(_token(request_id),'EXPECTED_REQUEST_ID')
    _need(type(row) is dict and row.keys()=={'kind','request_id','ok','result','error'},'RESPONSE_SCHEMA')
    _need(type(row['kind']) is str and row['kind']=='RESULT' and _token(row['request_id'])
          and row['request_id']==request_id and type(row['ok']) is bool,'RESPONSE_IDENTITY')
    if row['ok']:_need(type(row['result']) is dict and row['error'] is None,'SUCCESS')
    else:_need(row['result'] is None and type(row['error']) is str and row['error'] in ERRORS,'ERROR_ENUM')


def build_response(row,*,request_id)->bytes:
    """Encode a RESULT. Success source remains RAM; errors are fixed enum only."""
    _response(row,request_id);return _encode(row,MAX_RESPONSE_BYTES)


def parse_response(frame,*,request_id)->dict:
    row=_decode(frame,response=True);_response(row,request_id);return row
