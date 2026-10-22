"""Bounded saved-source RAM frames; no I/O, transport or native attestation.

The producer's physical identity and source provenance remain an external trust
boundary. Request timestamps use the host clock. Body bytes are never normalized
or reflected in diagnostics; returned frames/snapshots are caller-owned RAM.
"""
from dataclasses import asdict
import json
import struct
from .saved_source import (MAX_BYTES,SourceBinding,Target,ReadRequest,SnapshotReceipt,
                           SavedSnapshot,SavedRefusal,finite,validate_snapshot)

MAGIC=b'AH1CRAM1'
MAX_METADATA_BYTES=16384
HEADER_BYTES=16
MAX_FRAME_BYTES=HEADER_BYTES+MAX_METADATA_BYTES+MAX_BYTES
_HEADER=struct.Struct('<8sII')
_BINDING=frozenset(('root_uuid','session_id','process_id','birth','generation','source_domain','valid_until'))
_TARGET=frozenset(('object_uuid','property_uuid'))
_STR=frozenset(('request_id','source_sha256','saved_resource_sha256','dirty_before','dirty_after','decoder_profile'))
_INT=frozenset(('revision','byte_count','crlf_count','helper_calls','source_writes','configuration_saves','database_updates','repository_mutations'))
_BOOL=frozenset(('bom_present','ends_lf','identity_verified','repeated_read_verified','schema_verified'))
_TIME=frozenset(('sampled_at','valid_until'))
_RECEIPT=_STR|_INT|_BOOL|_TIME|{'binding','target'}

def _need(ok,code):
    if not ok:raise SavedRefusal('RAM_WIRE_'+code)

def _object(value,keys):
    _need(type(value) is dict and value.keys()==keys,'SCHEMA')

def _pairs(items):
    result={}
    for key,value in items:
        _need(key not in result,'DUPLICATE_KEY')
        result[key]=value
    return result

def _constant(_value):raise SavedRefusal('RAM_WIRE_JSON_CONSTANT')

def _packet(metadata,body):
    _object(metadata,_RECEIPT)
    binding=metadata['binding'];target=metadata['target']
    _object(binding,_BINDING);_object(target,_TARGET)
    _need(all(type(binding[k]) is str for k in ('root_uuid','session_id','birth','source_domain'))
          and all(type(binding[k]) is int for k in ('process_id','generation'))
          and finite(binding['valid_until']) and all(type(x) is str for x in target.values()),'SCHEMA_TYPE')
    _need(all(type(metadata[k]) is str for k in _STR)
          and all(type(metadata[k]) is int for k in _INT)
          and all(type(metadata[k]) is bool for k in _BOOL)
          and all(finite(metadata[k]) for k in _TIME),'SCHEMA_TYPE')
    values=dict(metadata,binding=SourceBinding(**binding),target=Target(**target))
    return SavedSnapshot(SnapshotReceipt(**values),body)

def build_frame(packet:SavedSnapshot,request:ReadRequest,now:float)->bytes:
    """Validate one request-bound snapshot and encode one complete RAM frame.

    No file/pipe operations or source execution occur. The caller owns the
    returned bytes and controls their lifetime; cryptographic erasure is absent.
    """
    _need(type(packet) is SavedSnapshot and type(packet.receipt) is SnapshotReceipt
          and type(packet.receipt.binding) is SourceBinding and type(packet.receipt.target) is Target
          and type(packet.utf8) is bytes,'PACKET')
    validate_snapshot(packet,request,now)
    metadata=asdict(packet.receipt)
    _packet(metadata,packet.utf8) # Apply the same exact type schema both ways.
    try:raw=json.dumps(metadata,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8')
    except (TypeError,ValueError,UnicodeError,RecursionError):raise SavedRefusal('RAM_WIRE_JSON') from None
    _need(0<len(raw)<=MAX_METADATA_BYTES,'METADATA_BOUND')
    return _HEADER.pack(MAGIC,len(raw),len(packet.utf8))+raw+packet.utf8

def parse_frame(frame:bytes,request:ReadRequest,now:float)->SavedSnapshot:
    """Parse a complete frame and validate receipt/hash/UTF8 against a request.

    This complete-frame parser performs no buffering/retry. Torn or extra bytes
    fail closed; a transport must apply the same length caps before allocation.
    """
    _need(type(frame) is bytes and HEADER_BYTES<=len(frame)<=MAX_FRAME_BYTES,'FRAME_BOUND')
    magic,metadata_len,body_len=_HEADER.unpack_from(frame)
    _need(magic==MAGIC,'MAGIC')
    _need(0<metadata_len<=MAX_METADATA_BYTES and body_len<=MAX_BYTES,'LENGTH_BOUND')
    _need(len(frame)==HEADER_BYTES+metadata_len+body_len,'FRAME_LENGTH')
    split=HEADER_BYTES+metadata_len
    try:
        metadata=json.loads(frame[HEADER_BYTES:split].decode('utf-8','strict'),
                            object_pairs_hook=_pairs,parse_constant=_constant)
    except SavedRefusal:raise
    except (UnicodeError,ValueError,TypeError,RecursionError):raise SavedRefusal('RAM_WIRE_JSON') from None
    packet=_packet(metadata,frame[split:])
    validate_snapshot(packet,request,now)
    return packet
