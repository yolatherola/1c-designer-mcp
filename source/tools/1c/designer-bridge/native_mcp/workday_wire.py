"""v234 workday protocol3 command/response codec. No OS/native calls or attestation.

The caller establishes the context identity, serializes command admission, and
validates physical SDK/ownership proofs before emitting an accepted ACK. This
module neither advances a session nor retries or acknowledges automatically.
"""
from dataclasses import dataclass,field
import json
import re
import struct
from .saved_source import (SourceBinding,Target,ReadRequest,SnapshotReceipt,SavedSnapshot,SavedRefusal,
                           GuardState,digest,finite,integer,validate_snapshot)
from .ram_wire import MAX_FRAME_BYTES,HEADER_BYTES,build_frame,parse_frame

READ=3
GUARD=4
CLOSE=5
SUCCESS=0
REFUSED=1
UNKNOWN=2
BUSY=3
CLOSED=4
COMMAND_BYTES=160
RESPONSE_HEADER_BYTES=32
ACK_BYTES=16
PROFILE_VERSION=234
PROTOCOL_VERSION=3
MAX_SESSION_SECONDS=28800
MAX_SEQUENCE=4096
MAX_PROOF_BYTES=16384
MAX_EPOCH_BYTES=32768
MAX_RESPONSE_BYTES=RESPONSE_HEADER_BYTES+MAX_PROOF_BYTES+MAX_EPOCH_BYTES+MAX_FRAME_BYTES
MODULE_PROPERTY='d5963243-262e-4398-b4d7-fb16d06484f6'
COMMAND_MAGIC=b'AH1CCMD3'
RESPONSE_MAGIC=b'AH1CRSP3'
ACK_MAGIC=b'AH1CACK3'
TAIL=0x33444d43
_COMMAND=struct.Struct('<8sIIII32s32sQddQdI24sI')
_RESPONSE=struct.Struct('<8sIIIIII')
_ACK=struct.Struct('<8sII')

class ResidentWireRefusal(SavedRefusal):
    """Stable body-free binary/schema/request refusal."""

def _need(ok,code):
    if not ok:raise ResidentWireRefusal('RESIDENT_WIRE_'+code)

def _nonce(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{32}',value) is not None and value!='0'*32

def _same_double(left,right):
    return finite(left) and finite(right) and struct.pack('<d',float(left))==struct.pack('<d',float(right))

@dataclass(frozen=True,slots=True)
class ResidentCommand:
    opcode:int
    sequence:int
    binding:SourceBinding
    target:Target|None
    request_id:str
    revision:int
    issued_at:float
    valid_until:float
    guard_sequence:int=0

@dataclass(frozen=True,slots=True)
class ResponseHeader:
    sequence:int
    opcode:int
    status:int
    proof_length:int
    epoch_length:int
    frame_length:int

@dataclass(frozen=True,slots=True)
class ResidentResponse:
    sequence:int
    opcode:int
    status:int
    proof:dict=field(repr=False)
    epoch:dict|None=field(repr=False)
    snapshot:SavedSnapshot|None=field(default=None,repr=False)

def _target(target):
    _need(type(target) is Target,'TARGET')
    target.validate();_need(target.property_uuid==MODULE_PROPERTY,'MODULE_PROPERTY')

def _request_join(command,request):
    _need(type(request) is ReadRequest and type(request.binding) is SourceBinding and type(request.target) is Target
          and request.binding==command.binding and request.target==command.target
          and type(request.request_id) is str and request.request_id==command.request_id
          and integer(request.revision,1,2**53-1) and request.revision==command.revision
          and _same_double(request.issued_at,command.issued_at)
          and _same_double(request.valid_until,command.valid_until),'READ_REQUEST_JOIN')

def _command(command,*,context,now,previous_sequence,guard=None,request=None):
    _need(type(command) is ResidentCommand and type(context) is SourceBinding,'COMMAND_TYPE')
    context.validate()
    _need(context.source_domain=='database_saved','SOURCE_DOMAIN')
    _need(type(command.binding) is SourceBinding and command.binding==context,'CONTEXT')
    _need(integer(previous_sequence,0,MAX_SEQUENCE-1) and integer(command.sequence,1,MAX_SEQUENCE)
          and command.sequence==previous_sequence+1,'SEQUENCE')
    _need(type(command.opcode) is int and command.opcode in (READ,GUARD,CLOSE)
          and (command.sequence!=MAX_SEQUENCE or command.opcode==CLOSE),'OPCODE')
    _need(_nonce(command.request_id),'NONCE')
    _need(finite(now) and now>=0 and finite(command.issued_at) and command.issued_at>=0
          and finite(command.valid_until) and command.issued_at<=now<=command.valid_until
          and 0<command.valid_until-command.issued_at<=60,'TIME')
    if command.opcode==CLOSE:
        # Cleanup of an owned session remains available after binding expiry.
        _need(command.target is None and type(command.revision) is int and command.revision==0
              and type(command.guard_sequence) is int and command.guard_sequence==0
              and guard is None and request is None,'CLOSE_FIELDS')
        return
    _target(command.target)
    _need(now<=command.valid_until<=context.valid_until<=command.issued_at+60,'BINDING_TIME')
    if command.opcode==GUARD:
        _need(type(command.revision) is int and command.revision==0 and type(command.guard_sequence) is int
              and command.guard_sequence==0 and guard is None and request is None,'GUARD_FIELDS')
        return
    _need(integer(command.revision,1,2**53-1) and integer(command.guard_sequence,1,MAX_SEQUENCE-1)
          and command.guard_sequence==previous_sequence,'READ_FIELDS')
    _need(type(guard) is ResidentCommand and guard.opcode==GUARD and type(guard.opcode) is int
          and type(guard.sequence) is int and guard.sequence==command.guard_sequence
          and type(guard.binding) is SourceBinding and guard.binding==command.binding
          and type(guard.target) is Target and guard.target==command.target
          and type(guard.revision) is int and guard.revision==0
          and type(guard.guard_sequence) is int and guard.guard_sequence==0
          and _nonce(guard.request_id) and guard.request_id!=command.request_id,'GUARD_TICKET')
    _need(finite(guard.issued_at) and guard.issued_at>=0 and finite(guard.valid_until)
          and guard.issued_at<=command.issued_at and now<=guard.valid_until<=context.valid_until
          and 0<guard.valid_until-guard.issued_at<=60,'GUARD_TIME')
    _request_join(command,request)

def build_command(command,*,context,now,previous_sequence,guard=None,request=None)->bytes:
    """Validate one current-context command and emit exactly160 little-endian bytes."""
    _command(command,context=context,now=now,previous_sequence=previous_sequence,guard=guard,request=request)
    target=b'\0'*32 if command.opcode==CLOSE else command.target.object_uuid.replace('-','').encode('ascii')
    return _COMMAND.pack(COMMAND_MAGIC,PROTOCOL_VERSION,command.opcode,command.sequence,0 if command.opcode==CLOSE else command.opcode,
        command.request_id.encode('ascii'),target,command.revision,float(command.issued_at),float(command.valid_until),
        context.generation,float(context.valid_until),command.guard_sequence,b'\0'*24,TAIL)

def parse_command(frame,*,context,now,previous_sequence,guard=None,request=None)->ResidentCommand:
    """Parse one full command; hidden identity comes only from the trustedcontext."""
    _need(type(frame) is bytes and len(frame)==COMMAND_BYTES,'COMMAND_LENGTH')
    magic,version,opcode,sequence,selector,nonce,target,revision,issued,valid,generation,binding_valid,guard_seq,reserved,tail=_COMMAND.unpack(frame)
    _need(magic==COMMAND_MAGIC and version==PROTOCOL_VERSION and tail==TAIL and reserved==b'\0'*24,'COMMAND_HEADER')
    _need(type(context) is SourceBinding and generation==context.generation
          and _same_double(binding_valid,context.valid_until),'CONTEXT_FIELDS')
    _need(selector==(0 if opcode==CLOSE else opcode),'SELECTOR')
    try:
        nonce_text=nonce.decode('ascii','strict')
        if opcode==CLOSE:
            _need(target==b'\0'*32,'CLOSE_UUID');selected=None
        else:
            hex_id=target.decode('ascii','strict');_need(_nonce(hex_id),'UUID')
            selected=Target(hex_id[:8]+'-'+hex_id[8:12]+'-'+hex_id[12:16]+'-'+hex_id[16:20]+'-'+hex_id[20:],MODULE_PROPERTY)
    except UnicodeError:raise ResidentWireRefusal('RESIDENT_WIRE_ASCII') from None
    command=ResidentCommand(opcode,sequence,context,selected,nonce_text,revision,issued,valid,guard_seq)
    _command(command,context=context,now=now,previous_sequence=previous_sequence,guard=guard,request=request)
    return command

def _response_header(header,command=None):
    _need(type(header) is ResponseHeader and integer(header.sequence,1,MAX_SEQUENCE)
          and type(header.opcode) is int and header.opcode in (READ,GUARD,CLOSE)
          and integer(header.status,SUCCESS,CLOSED),'RESPONSE_FIELDS')
    _need(header.sequence!=MAX_SEQUENCE or header.opcode==CLOSE,'RESPONSE_SEQUENCE')
    _need(header.status!=CLOSED or header.opcode==CLOSE,'CLOSED_OPCODE')
    _need(header.opcode!=CLOSE or header.status!=SUCCESS,'CLOSE_STATUS')
    _need(integer(header.proof_length,1,MAX_PROOF_BYTES) and integer(header.epoch_length,0,MAX_EPOCH_BYTES)
          and integer(header.frame_length,0,MAX_FRAME_BYTES),'RESPONSE_BOUNDS')
    if header.status==SUCCESS and header.opcode==READ:
        _need(header.frame_length>HEADER_BYTES,'SOURCE_FRAME_REQUIRED')
    else:_need(header.frame_length==0,'SOURCE_FRAME_FORBIDDEN')
    if header.status in (SUCCESS,CLOSED):_need(header.epoch_length>0,'EPOCH_REQUIRED')
    if command is not None:
        _need(type(command) is ResidentCommand and header.sequence==command.sequence and header.opcode==command.opcode,'RESPONSE_JOIN')

def build_response_header(header,command=None)->bytes:
    _response_header(header,command)
    return _RESPONSE.pack(RESPONSE_MAGIC,header.sequence,header.opcode,header.status,
                          header.proof_length,header.epoch_length,header.frame_length)

def parse_response_header(frame,command=None)->ResponseHeader:
    """Check the32-byte length header before a transport allocates response RAM."""
    _need(type(frame) is bytes and len(frame)==RESPONSE_HEADER_BYTES,'RESPONSE_HEADER_LENGTH')
    magic,*values=_RESPONSE.unpack(frame);_need(magic==RESPONSE_MAGIC,'RESPONSE_MAGIC')
    header=ResponseHeader(*values);_response_header(header,command);return header

def build_ack(sequence,status)->bytes:
    """Explicit ACK only; accepted0 must follow the caller's semantic proof gate."""
    _need(integer(sequence,1,MAX_SEQUENCE) and integer(status,0,1),'ACK_FIELDS')
    return _ACK.pack(ACK_MAGIC,sequence,status)

def parse_ack(frame,*,sequence)->int:
    _need(type(frame) is bytes and len(frame)==ACK_BYTES and integer(sequence,1,MAX_SEQUENCE),'ACK_LENGTH')
    magic,observed,status=_ACK.unpack(frame)
    _need(magic==ACK_MAGIC and observed==sequence and integer(status,0,1),'ACK_FIELDS');return status

_PROOF_STR=frozenset(('kind','operationId','scopeSha256','sessionId','installNonce','requestId','targetUuidHex','sourceSha256','savedResourceSha256'))
_PROOF_TIME=frozenset(('bindingValidUntil','requestValidUntil','issuedAt','sampledAt'))
_PROOF_BOOL=frozenset(('contextCleared','functionRetained','handlerRemoved','epochClean','hookRemoved','peerVerified','readyVerified',
                       'pipeClosed','drainCompleted','buffersFreed','nativeEnvelopeValid','dllSelfReferenceRetained'))
_PROOF_INT=frozenset(('version','sequence','opcode','status','terminalRc','generation','guardSequence','processId','guiThreadId','workerThreadId','sdkRc',
    'compileCount','contextCount','nativeStatus','nativeReason','bodyBytes','codePoints','crlfCount','bomPresent','endsLf','passes','propertyReads',
    'fileOpens','adoptedFiles','pendingReference','beforeClean','afterClean','prefixPreserved','typedCleared','nativeException','storedBytes','databaseRoot','databaseManager'))
_PROOF_KEYS=_PROOF_STR|_PROOF_TIME|_PROOF_BOOL|_PROOF_INT|{'guardState'}
_BINDING_KEYS=frozenset(('root_uuid','session_id','process_id','birth','generation','source_domain','valid_until'))
_GUARD_KEYS=frozenset(('binding','target','dirty_state','checked_at','valid_until','identity_verified'))
_EPOCH_KIND='RESIDENT_RAM_SDK_CHAIN_CPP_EXCEPTION_TYPE_EPOCH'

def _pairs(items):
    result={}
    for key,value in items:
        _need(key not in result,'JSON_DUPLICATE');result[key]=value
    return result

def _constant(_value):raise ResidentWireRefusal('RESIDENT_WIRE_JSON_NONFINITE')

def _tree(value,depth=0):
    _need(depth<=32,'JSON_DEPTH')
    if type(value) is float:_need(finite(value),'JSON_NONFINITE')
    elif type(value) is dict:
        _need(all(type(key) is str for key in value),'JSON_KEYS')
        for item in value.values():_tree(item,depth+1)
    elif type(value) in (list,tuple):
        for item in value:_tree(item,depth+1)
    else:_need(value is None or type(value) in (str,int,bool),'JSON_TYPE')

def _encode_json(value,limit):
    _need(type(value) is dict,'JSON_OBJECT');_tree(value)
    try:raw=json.dumps(value,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8')
    except (ValueError,TypeError,UnicodeError,RecursionError):raise ResidentWireRefusal('RESIDENT_WIRE_JSON') from None
    _need(0<len(raw)<=limit,'JSON_BOUND');return raw

def _decode_json(raw,limit):
    _need(type(raw) is bytes and 0<len(raw)<=limit,'JSON_BOUND')
    try:value=json.loads(raw.decode('utf-8','strict'),object_pairs_hook=_pairs,parse_constant=_constant)
    except SavedRefusal:raise
    except (ValueError,TypeError,UnicodeError,RecursionError):raise ResidentWireRefusal('RESIDENT_WIRE_JSON') from None
    _need(type(value) is dict,'JSON_OBJECT');_tree(value);return value

def _proof(proof,command,status,now):
    _need(type(proof) is dict and proof.keys()==_PROOF_KEYS,'PROOF_SCHEMA')
    _need(all(type(proof[k]) is str for k in _PROOF_STR)
          and all(type(proof[k]) is bool for k in _PROOF_BOOL)
          and all(type(proof[k]) is int for k in _PROOF_INT)
          and all(finite(proof[k]) for k in _PROOF_TIME),'PROOF_TYPE')
    _need(proof['version']==PROTOCOL_VERSION and proof['kind']=='RESIDENT_NATIVE_RAM_CARRIER' and _nonce(proof['operationId'])
          and digest(proof['scopeSha256']) and _nonce(proof['installNonce']),'PROOF_IDENTITY')
    _need(proof['sequence']==command.sequence and proof['opcode']==command.opcode and proof['status']==status
          and proof['requestId']==command.request_id and proof['sessionId']==command.binding.session_id
          and proof['processId']==command.binding.process_id and proof['generation']==command.binding.generation
          and proof['guardSequence']==command.guard_sequence,'PROOF_JOIN')
    _need(_same_double(proof['issuedAt'],command.issued_at) and _same_double(proof['requestValidUntil'],command.valid_until)
          and _same_double(proof['bindingValidUntil'],command.binding.valid_until),'PROOF_TIME_JOIN')
    expected='' if command.target is None else command.target.object_uuid.replace('-','')
    _need(proof['targetUuidHex']==expected,'PROOF_TARGET')
    _need(finite(now) and command.issued_at<=proof['sampledAt']<=now,'PROOF_SAMPLE')
    if status==SUCCESS:_need(proof['sampledAt']<=command.valid_until,'PROOF_SAMPLE')
    _need(all(proof[k]=='' or digest(proof[k]) for k in ('sourceSha256','savedResourceSha256')),'PROOF_HASH')
    if status==SUCCESS and command.opcode==GUARD:
        state=proof['guardState'];_need(type(state) is dict and state.keys()==_GUARD_KEYS,'GUARD_SCHEMA')
        binding=state['binding'];target=state['target']
        _need(type(binding) is dict and binding.keys()==_BINDING_KEYS and type(target) is dict
              and target.keys()=={'object_uuid','property_uuid'},'GUARD_SCHEMA')
        parsed=GuardState(SourceBinding(**binding),Target(**target),state['dirty_state'],state['checked_at'],state['valid_until'],state['identity_verified'])
        parsed.binding.validate();parsed.target.validate()
        _need(parsed.binding==command.binding and parsed.target==command.target and type(parsed.dirty_state) is str
              and parsed.dirty_state=='clean' and parsed.identity_verified is True
              and finite(parsed.checked_at) and finite(parsed.valid_until)
              and command.issued_at<=parsed.checked_at<=proof['sampledAt']<=now<=parsed.valid_until<=command.valid_until,'GUARD_JOIN')
        _need(all(proof[k]==0 for k in ('bodyBytes','codePoints','crlfCount','bomPresent','endsLf','passes','propertyReads','fileOpens','adoptedFiles','storedBytes'))
              and proof['sourceSha256']==proof['savedResourceSha256']=='','GUARD_NO_SOURCE')
    else:_need(proof['guardState'] is None,'GUARD_FORBIDDEN')

def _response(response,command,request,now):
    _need(type(response) is ResidentResponse and type(command) is ResidentCommand,'RESPONSE_TYPE')
    _need(type(command.binding) is SourceBinding,'CONTEXT');command.binding.validate()
    _need(command.binding.source_domain=='database_saved' and integer(command.sequence,1,MAX_SEQUENCE)
          and type(command.opcode) is int and command.opcode in (READ,GUARD,CLOSE) and _nonce(command.request_id)
          and integer(response.status,SUCCESS,CLOSED),'RESPONSE_COMMAND')
    if command.opcode!=CLOSE:_target(command.target)
    _need(type(response.sequence) is int and response.sequence==command.sequence
          and type(response.opcode) is int and response.opcode==command.opcode,'RESPONSE_JOIN')
    _proof(response.proof,command,response.status,now)
    if response.epoch is not None:
        _need(type(response.epoch) is dict and response.epoch.get('kind')==_EPOCH_KIND,'EPOCH_SCHEMA')
    if response.status==SUCCESS and response.opcode==READ:
        _request_join(command,request);_need(type(response.snapshot) is SavedSnapshot,'SNAPSHOT_REQUIRED')
        receipt=response.snapshot.receipt;_need(type(receipt) is SnapshotReceipt,'SNAPSHOT_TYPE')
        _need(type(response.snapshot.utf8) is bytes,'SNAPSHOT_TYPE')
        validate_snapshot(response.snapshot,request,now)
        try:points=len(response.snapshot.utf8.decode('utf-8','strict'))
        except UnicodeError:raise ResidentWireRefusal('RESIDENT_WIRE_UTF8') from None
        _need(receipt.source_sha256==response.proof['sourceSha256'] and receipt.saved_resource_sha256==response.proof['savedResourceSha256']
              and receipt.byte_count==response.proof['bodyBytes'] and receipt.crlf_count==response.proof['crlfCount']
              and int(receipt.bom_present)==response.proof['bomPresent'] and int(receipt.ends_lf)==response.proof['endsLf']
              and points==response.proof['codePoints'],'SNAPSHOT_PROOF_JOIN')
    else:_need(response.snapshot is None,'SNAPSHOT_FORBIDDEN')

def build_response(response,command,*,request=None,now)->bytes:
    """Build a synthetic/trusted response; never declares SDK/native proofs valid."""
    _response(response,command,request,now)
    proof=_encode_json(response.proof,MAX_PROOF_BYTES)
    epoch=b'' if response.epoch is None else _encode_json(response.epoch,MAX_EPOCH_BYTES)
    frame=b'' if response.snapshot is None else build_frame(response.snapshot,request,now)
    header=ResponseHeader(response.sequence,response.opcode,response.status,len(proof),len(epoch),len(frame))
    return build_response_header(header,command)+proof+epoch+frame

def parse_response(frame,command,*,request=None,now)->ResidentResponse:
    """Decode bounded bytes. The caller must validate physical proofs before ACK0.

    Full SDK/ownership/lease classification is deliberately external. This codec
    checks framing/types/request joins; it neither attests nor marks a session
    clean. Successful GUARD is not a source snapshot; refusals carry no source.
    """
    _need(type(frame) is bytes and RESPONSE_HEADER_BYTES<=len(frame)<=MAX_RESPONSE_BYTES,'RESPONSE_LENGTH')
    header=parse_response_header(frame[:RESPONSE_HEADER_BYTES],command)
    _need(len(frame)==RESPONSE_HEADER_BYTES+header.proof_length+header.epoch_length+header.frame_length,'RESPONSE_LENGTH')
    at=RESPONSE_HEADER_BYTES;proof=_decode_json(frame[at:at+header.proof_length],MAX_PROOF_BYTES);at+=header.proof_length
    epoch=None if not header.epoch_length else _decode_json(frame[at:at+header.epoch_length],MAX_EPOCH_BYTES);at+=header.epoch_length
    snapshot=None
    if header.frame_length:
        _request_join(command,request);snapshot=parse_frame(frame[at:],request,now)
    response=ResidentResponse(header.sequence,header.opcode,header.status,proof,epoch,snapshot)
    _response(response,command,request,now);return response
