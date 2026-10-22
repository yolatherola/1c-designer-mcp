"""One request-bound LIVE RAM frame and post-validation ACK; no I/O or native.

Wire metadata is not physical attestation. A trusted receiver must separately
join SDK/AS/epoch evidence before constructing the validated snapshot and ACK.
"""
from dataclasses import dataclass,field
import hashlib
import json
import math
from pathlib import Path
import re
import struct
from types import MappingProxyType

SOURCE_SHA='8b8c8dc805d7de3cff9aa0ff81189ea3cbff1f7d73095887cf4c3fa48b4ba0d3'
if hashlib.sha256(Path(__file__).with_name('live_source.py').read_bytes()).hexdigest()!=SOURCE_SHA:
    raise ValueError('LIVE_WIRE_SOURCE_PIN')
from . import live_source as source

MAGIC=b'AH1CLFR1';READY_MAGIC=b'AH1CLRD1';ACK_MAGIC=b'AH1CLAK1'
HEADER=struct.Struct('<8sIIIIII');ACK=struct.Struct('<8sII32s64s')
HEADER_BYTES=32;READY_BYTES=40;ACK_BYTES=112
MAX_METADATA=16384;MAX_BODY=524288;MAX_UTF16=131072
READER_SOURCE_SHA='4610f385654d36cdb6673b12ed2a9206338d6535405de5782f1e3598688cf9a9'
_KEYS=frozenset(('operation_id','scope_sha256','request_id','revision','root_uuid','object_uuid',
    'property_uuid','reader_source_sha256','compiled_source_sha256','source_domain','issued_at',
    'valid_until','captured_at','source_sha256','byte_count','utf16_units','bom_present','crlf_count','ends_lf'))


class LiveWireRefusal(ValueError):
    """Fixed body-free protocol refusal."""


def need(ok,code):
    if not ok:raise LiveWireRefusal('LIVE_WIRE_'+code)


def _int(value,low,high):return type(value) is int and low<=value<=high
def _finite(value):
    try:return type(value) in (int,float) and math.isfinite(value)
    except OverflowError:return False
def _hex(value,size):return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None and value!='0'*size


@dataclass(frozen=True,slots=True)
class LiveFrameContext:
    operation_id:str
    scope_sha256:str
    request_id:str
    revision:int
    compiled_source_sha256:str
    process_id:int
    birth:str

    def validate(self):
        need(_hex(self.operation_id,32) and _hex(self.scope_sha256,64) and _hex(self.request_id,32)
             and _hex(self.compiled_source_sha256,64) and _int(self.revision,1,0xFFFFFFFF)
             and _int(self.process_id,1,0xFFFFFFFF) and _hex(self.birth,16),'CONTEXT')


@dataclass(frozen=True,slots=True)
class LiveFrame:
    metadata:object=field(repr=False)
    utf8:bytes=field(repr=False,compare=False)


def _pairs(items):
    result={}
    for key,value in items:
        need(key not in result,'DUPLICATE_JSON');result[key]=value
    return result


def _json(raw):
    def reject(_):raise LiveWireRefusal('LIVE_WIRE_NONFINITE')
    try:value=json.loads(raw,object_pairs_hook=_pairs,parse_constant=reject)
    except (ValueError,TypeError,UnicodeError,RecursionError):raise LiveWireRefusal('LIVE_WIRE_JSON') from None
    need(type(value) is dict,'JSON_OBJECT');return value


def parse_header(raw):
    """Bound lengths before allocating or reading variable frame segments."""
    need(type(raw) is bytes and len(raw)==HEADER_BYTES,'HEADER_SIZE')
    magic,version,metadata,body,units,revision,reserved=HEADER.unpack(raw)
    need(magic==MAGIC and version==1 and reserved==0,'HEADER_PROFILE')
    need(_int(metadata,1,MAX_METADATA) and _int(body,0,MAX_BODY)
         and _int(units,0,MAX_UTF16) and _int(revision,1,0xFFFFFFFF),'HEADER_BOUND')
    return metadata,body,units,revision


def _validate(metadata,body,context,now):
    need(type(context) is LiveFrameContext,'CONTEXT_TYPE');context.validate()
    need(type(metadata) is dict and metadata.keys()==_KEYS and type(body) is bytes,'SCHEMA')
    need(all(metadata.get(key)==getattr(context,key) and type(metadata[key]) is str
             for key in ('operation_id','scope_sha256','request_id','compiled_source_sha256'))
         and type(metadata['revision']) is int and metadata['revision']==context.revision,'IDENTITY_JOIN')
    need(metadata['root_uuid']==source.ROOT_UUID and metadata['object_uuid']==source.OBJECT_UUID
         and metadata['property_uuid']==source.PROPERTY_UUID
         and metadata['reader_source_sha256']==READER_SOURCE_SHA
         and metadata['source_domain']==source.SOURCE_DOMAIN
         and all(type(metadata[k]) is str for k in ('root_uuid','object_uuid','property_uuid',
             'reader_source_sha256','source_domain')),'SOURCE_PROFILE')
    issued,captured,until=(metadata[k]for k in ('issued_at','captured_at','valid_until'))
    need(all(_finite(v) for v in (issued,captured,until,now)) and 0<=issued<=captured<=now<=until<=issued+60,'TIME')
    need(_int(metadata['byte_count'],0,MAX_BODY) and metadata['byte_count']==len(body)
         and _int(metadata['utf16_units'],0,MAX_UTF16) and _hex(metadata['source_sha256'],64)
         and hashlib.sha256(body).hexdigest()==metadata['source_sha256'],'BODY_HASH')
    need(type(metadata['bom_present']) is bool and metadata['bom_present']==body.startswith(b'\xef\xbb\xbf')
         and type(metadata['ends_lf']) is bool and metadata['ends_lf']==body.endswith(b'\n')
         and _int(metadata['crlf_count'],0,MAX_UTF16) and metadata['crlf_count']==body.count(b'\r\n'),'BYTE_SHAPE')
    try:text=body.decode('utf-8','strict');units=len(text.encode('utf-16-le','strict'))//2
    except UnicodeError:raise LiveWireRefusal('LIVE_WIRE_ENCODING') from None
    need('\x00' not in text and units==metadata['utf16_units'],'UTF16');del text


def build_frame(metadata,body,context,*,now):
    """Encode synthetic/trusted bytes; this does not attest native evidence."""
    _validate(metadata,body,context,now)
    raw=json.dumps(metadata,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8')
    need(0<len(raw)<=MAX_METADATA,'METADATA_BOUND')
    return HEADER.pack(MAGIC,1,len(raw),len(body),metadata['utf16_units'],metadata['revision'],0)+raw+body


def parse_frame(raw,context,*,now):
    need(type(raw) is bytes and len(raw)>=HEADER_BYTES,'FRAME_SIZE')
    meta,body,units,revision=parse_header(raw[:HEADER_BYTES])
    need(len(raw)==HEADER_BYTES+meta+body,'FRAME_BOUND')
    metadata=_json(raw[HEADER_BYTES:HEADER_BYTES+meta]);value=raw[HEADER_BYTES+meta:]
    need(metadata.get('utf16_units')==units and type(metadata.get('utf16_units')) is int
         and metadata.get('revision')==revision and type(metadata.get('revision')) is int,'HEADER_JOIN')
    _validate(metadata,value,context,now)
    return LiveFrame(MappingProxyType(metadata),value)


def expected_request(frame,context):
    """Bind runtime times to fixed identity; no current native identity claim."""
    need(type(frame) is LiveFrame and type(context) is LiveFrameContext,'FRAME_TYPE');context.validate()
    m=frame.metadata
    binding=source.LiveBinding(source.ROOT_UUID,context.process_id,context.birth,context.operation_id,
                              context.scope_sha256,m['valid_until'])
    return source.LiveReadRequest(binding,source.LiveTarget(source.OBJECT_UUID,source.PROPERTY_UUID),
        context.request_id,context.revision,m['issued_at'],m['valid_until'])


def validate_result(frame,snapshot,request,context,*,now):
    """Final RAM/receipt join after the trusted physical verifier, before ACK."""
    need(type(frame) is LiveFrame,'FRAME_TYPE')
    _validate(dict(frame.metadata),frame.utf8,context,now)
    need(request==expected_request(frame,context),'REQUEST_JOIN')
    try:text=source.validate_snapshot(snapshot,request,request.target,now)
    except Exception:raise LiveWireRefusal('LIVE_WIRE_SNAPSHOT_UNPROVEN') from None
    del text;m=frame.metadata;r=snapshot.receipt
    need(snapshot.utf8==frame.utf8 and r.sampled_at==m['captured_at'] and r.valid_until==m['valid_until']
         and r.byte_count==m['byte_count'] and r.source_sha256==m['source_sha256']
         and r.utf16_units==m['utf16_units'] and r.bom_present is m['bom_present']
         and r.crlf_count==m['crlf_count'] and r.ends_lf is m['ends_lf'],'SNAPSHOT_JOIN')
    return snapshot


def ready_bytes(context):
    need(type(context) is LiveFrameContext,'CONTEXT_TYPE');context.validate()
    return READY_MAGIC+context.request_id.encode('ascii')


def build_ack(context,body_sha256,*,accepted):
    need(type(context) is LiveFrameContext,'CONTEXT_TYPE');context.validate()
    need(_hex(body_sha256,64) and type(accepted) is bool,'ACK_INPUT')
    return ACK.pack(ACK_MAGIC,0 if accepted else 1,context.revision,
                    context.request_id.encode('ascii'),body_sha256.encode('ascii'))


def parse_ack(raw,context,body_sha256):
    need(type(context) is LiveFrameContext,'CONTEXT_TYPE');context.validate()
    need(_hex(body_sha256,64),'ACK_INPUT')
    need(type(raw) is bytes and len(raw)==ACK_BYTES,'ACK_SIZE')
    magic,status,revision,request,pin=ACK.unpack(raw)
    need(magic==ACK_MAGIC and status in (0,1) and revision==context.revision
         and request==context.request_id.encode('ascii') and pin==body_sha256.encode('ascii'),'ACK_JOIN')
    return status==0
