"""Bounded replayable receipt metadata, never source/frame storage or file I/O.

Install before the first command on a trusted resident channel. Its validator
still owns native/epoch acceptance. This decorator copies only whitelisted
metadata after validation, then records ACK only after transport returns. Local
EOF/owner exit remains distinct from managed/native SDK closure.
"""
import hashlib
import inspect
import json
from pathlib import Path
import re
import struct
import threading

from . import resident_channel,resident_wire as wire,ram_wire
from .saved_source import SnapshotReceipt,SavedSnapshot,SourceBinding,Target,SavedRefusal,finite,integer

PINS={'resident_channel.py':'91420eddd9240bb9d28e1a626f0e320edcd7efe17d6d5d00f041b1d8834b388f',
      'resident_wire.py':'6d6089671de1fb7cc9fddca88fc43eb44c55bbcc5eeb766fed8387fa32966e2d',
      'ram_wire.py':'4aa2e5c4555850633f1a2af7a0a1944b03e1c01d780f3b150e31a7b725d1776a'}
_EPOCH_STR={'kind','phase','operationId','scopeSha256','handlerReturn','epochCoverage','typeDecoderProfile','hashAlgorithm'}
_EPOCH_INT={'processId','executeThreadId','sdkExecuteRc','cppThrows','cppThrowsExecuteThread','cppThrowsOtherThreads','otherExceptions',
    'otherExceptionsExecuteThread','otherExceptionsOtherThreads','sdkChainRc','maximumTypeEvents','maximumCatchableTypes','maximumNameBytes',
    'typeEventCount','decodedCppThrows','unknownCppThrows','listStreamCompatibleThrows'}
_EPOCH_BOOL={'handlerRegistered','handlerRemoved','executeEntered','executeReturned','counterOverflow','selfReferenceRetained',
    'dllMustRemainLoadedUntilProcessExit','futureOtherThreadBarrierVerified','exceptionDetailsCaptured','scopeSourceBindingVerified',
    'fullPendingVerified','databaseUpdateAuthorized','sdkChainEntered','sdkChainReturned','sdkChainComplete','typeMetadataOnly',
    'exceptionObjectRead','typeEventOverflow','typeDecoderReentry','allCppExceptionFree','listStreamPathExceptionFreeVerified'}
_EPOCH_KEYS=_EPOCH_STR|_EPOCH_INT|_EPOCH_BOOL|{'typeEvents'}
MAX_RECORD_BYTES=wire.MAX_PROOF_BYTES+wire.MAX_EPOCH_BYTES+ram_wire.MAX_METADATA_BYTES+2048


def _need(ok,code):
    if not ok:raise SavedRefusal('SAVED_RECEIPT_OBSERVER_'+code)


def _hex(value,size,*,empty=False):
    return type(value) is str and ((empty and value=='') or (re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None and value!='0'*size))


def _typed(value,strings,ints,bools,times=(),special=()):
    """Copy only exact bounded metadata scalars; no arbitrary object protocol."""
    keys=set(strings)|set(ints)|set(bools)|set(times)|set(special)
    _need(type(value) is dict and value.keys()==keys,'SCHEMA')
    _need(all(type(value[k]) is str and len(value[k])<=128 for k in strings)
          and all(integer(value[k],-2**31,2**53-1) for k in ints)
          and all(type(value[k]) is bool for k in bools)
          and all(finite(value[k]) and 0<=value[k]<=2**53-1 for k in times),'TYPE')
    return {k:value[k] for k in keys if k not in special}


def _size(value,maximum):
    # Only already selected, detached metadata is serialized for the bound.
    _need(len(json.dumps(value,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8'))<=maximum,'BOUND')


def _binding(value):
    out=_typed(value,('root_uuid','session_id','birth','source_domain'),('process_id','generation'),(),('valid_until',))
    binding=SourceBinding(**out);binding.validate()
    _need(binding.source_domain=='database_saved','DOMAIN')
    return out


def _target(value):
    out=_typed(value,('object_uuid','property_uuid'),(),())
    target=Target(**out);target.validate();_need(target.property_uuid==wire.MODULE_PROPERTY,'PROPERTY')
    return out


def _guard(value):
    out=_typed(value,('dirty_state',),(),('identity_verified',),('checked_at','valid_until'),('binding','target'))
    _need(out['dirty_state']=='clean' and out['identity_verified'] is True,'GUARD')
    out['binding']=_binding(value['binding']);out['target']=_target(value['target'])
    return out


def _receipt(receipt):
    _need(type(receipt) is SnapshotReceipt and type(receipt.binding) is SourceBinding and type(receipt.target) is Target,'RECEIPT')
    # Select slots before validation; dataclasses.asdict would invoke arbitrary
    # __deepcopy__ on a malformed field before its primitive type was checked.
    value={key:getattr(receipt,key) for key in ram_wire._RECEIPT if key not in ('binding','target')}
    value['binding']={key:getattr(receipt.binding,key) for key in ram_wire._BINDING}
    value['target']={key:getattr(receipt.target,key) for key in ram_wire._TARGET}
    out=_typed(value,ram_wire._STR,ram_wire._INT,ram_wire._BOOL,ram_wire._TIME,('binding','target'))
    _need(_hex(out['request_id'],32) and _hex(out['source_sha256'],64) and _hex(out['saved_resource_sha256'],64)
          and out['dirty_before']==out['dirty_after']=='clean' and out['decoder_profile']=='FORMAT15_RAM','RECEIPT_STRING')
    out['binding']=_binding(value['binding']);out['target']=_target(value['target'])
    _size(out,ram_wire.MAX_METADATA_BYTES);return out


def _proof(value):
    out=_typed(value,wire._PROOF_STR,wire._PROOF_INT,wire._PROOF_BOOL,wire._PROOF_TIME,('guardState',))
    _need(out['kind']=='RESIDENT_NATIVE_RAM_CARRIER'
          and all(_hex(out[k],32) for k in ('operationId','sessionId','installNonce','requestId'))
          and _hex(out['scopeSha256'],64) and _hex(out['targetUuidHex'],32,empty=True)
          and all(_hex(out[k],64,empty=True) for k in ('sourceSha256','savedResourceSha256')),'PROOF_STRING')
    out['guardState']=None if value['guardState'] is None else _guard(value['guardState'])
    _size(out,wire.MAX_PROOF_BYTES);return out


def _epoch(value):
    out=_typed(value,_EPOCH_STR,_EPOCH_INT,_EPOCH_BOOL,special=('typeEvents',))
    _need(type(value['typeEvents']) is list and not value['typeEvents'],'EPOCH_EVENTS')
    _need(out['kind']=='RESIDENT_RAM_SDK_CHAIN_CPP_EXCEPTION_TYPE_EPOCH' and out['phase']=='SDK_CHAIN_RETURNED'
          and out['handlerReturn']=='CONTINUE_SEARCH' and out['epochCoverage']=='synchronous_gui_sdk_chain'
          and out['typeDecoderProfile']=='X86_MSVC_IMAGE_TYPES_LISTSTREAM_CATCHABLE_BASES'
          and out['hashAlgorithm']=='FNV1A32_OBSERVATION_ONLY' and _hex(out['operationId'],32) and _hex(out['scopeSha256'],64),'EPOCH_STRING')
    out['typeEvents']=[];_size(out,wire.MAX_EPOCH_BYTES);return out


def _request(command):
    _need(type(command) is bytes and len(command)==160,'COMMAND')
    magic,version,op,seq,selector,nonce,target,revision,issued,valid,generation,bvalid,guard,reserved,tail=wire._COMMAND.unpack(command)
    _need(magic==wire.COMMAND_MAGIC and version==2 and reserved==bytes(24) and tail==wire.TAIL
          and op in (3,4,5) and 1<=seq<=64 and (seq<64 or op==5) and selector==(0 if op==5 else op),'COMMAND')
    try:
        request_id=nonce.decode('ascii');target_id='' if op==5 else target.decode('ascii')
    except UnicodeError:raise SavedRefusal('SAVED_RECEIPT_OBSERVER_COMMAND') from None
    _need(_hex(request_id,32) and (target==bytes(32) if op==5 else _hex(target_id,32))
          and integer(revision,0,2**53-1) and integer(generation,1,2**53-1)
          and all(finite(v) and 0<=v<=2**53-1 for v in (issued,valid,bvalid))
          and 0<valid-issued<=60 and bvalid>0 and (revision>0 if op==3 else revision==0)
          and (guard==seq-1 and guard>0 if op==3 else guard==0),'COMMAND')
    return dict(version=version,opcode=op,sequence=seq,selector=selector,requestId=request_id,targetUuidHex=target_id,
        revision=revision,issuedAt=issued,requestValidUntil=valid,generation=generation,bindingValidUntil=bvalid,guardSequence=guard)


def _capture(command,result):
    _need(type(result) is tuple and len(result)==2 and type(result[0]) is wire.ResidentResponse
          and type(result[1]) is tuple and len(result[1])==2,'VALIDATOR_RESULT')
    response,counts=result
    _need(integer(counts[0],0,64) and integer(counts[1],1,2**32-1),'COUNTS')
    request=_request(command);proof=_proof(response.proof);epoch=_epoch(response.epoch)
    _need(type(response.sequence) is int and response.sequence==request['sequence']
          and type(response.opcode) is int and response.opcode==request['opcode']
          and type(response.status) is int and response.status==(4 if response.opcode==5 else 0),'RESPONSE')
    for key in ('sequence','opcode','requestId','targetUuidHex','issuedAt','requestValidUntil','generation','bindingValidUntil','guardSequence'):
        matched=wire._same_double(proof[key],request[key]) if key in wire._PROOF_TIME else (
            type(proof[key]) is type(request[key]) and proof[key]==request[key])
        _need(matched,'JOIN')
    _need(proof['status']==response.status and proof['contextCount']==counts[0] and proof['workerThreadId']==counts[1]
          and epoch['operationId']==proof['operationId'] and epoch['scopeSha256']==proof['scopeSha256']
          and epoch['processId']==proof['processId'] and epoch['executeThreadId']==proof['guiThreadId'],'JOIN')
    receipt=None
    if response.opcode==3:
        _need(type(response.snapshot) is SavedSnapshot,'SNAPSHOT')
        receipt=_receipt(response.snapshot.receipt)
        _need(receipt['request_id']==request['requestId'] and receipt['revision']==request['revision']
              and receipt['source_sha256']==proof['sourceSha256'] and receipt['saved_resource_sha256']==proof['savedResourceSha256']
              and receipt['byte_count']==proof['bodyBytes'],'RECEIPT_JOIN')
    else:_need(response.snapshot is None,'SNAPSHOT_FORBIDDEN')
    record=dict(kind='RESIDENT_ACCEPTED_RECEIPT_METADATA',capturePhase='VALIDATED_BEFORE_ACK',phase='ACK_CONFIRMED',
        ackConfirmed=False,eofConfirmed=False,requestMetadata=request,nativeProof=proof,epoch=epoch,snapshotReceipt=receipt,
        counts=dict(contexts=counts[0],workerThreadId=counts[1]),sourceBodyIncluded=False,sourceFrameIncluded=False)
    _size(record,MAX_RECORD_BYTES);return record


class ResidentReceiptObserver:
    """Trusted channel decorator; bounded metadata, no source or persistence.

    records() returns detached JSON-compatible copies. Install before command1;
    failure seals observation without issuing another command or retrying ACK.
    The underlying channel alone owns I/O, ACK, cancellation and local cleanup.
    """
    def __init__(self,channel,*,maximum_records=64):
        here=Path(__file__).resolve().parent
        for name,pin in PINS.items():_need(hashlib.sha256((here/name).read_bytes()).hexdigest()==pin,'DEPENDENCY_PIN')
        _need(integer(maximum_records,1,64),'CAP')
        _need(callable(getattr(channel,'exchange',None)) and callable(getattr(channel,'wait_closed',None)),'CHANNEL')
        self._channel=channel;self._maximum=maximum_records;self._records=[];self._failed=False
        self._serial=threading.Lock();self._metadata=threading.Lock()

    @property
    def path(self):return self._channel.path
    @property
    def closed(self):return self._channel.closed
    @property
    def sealed(self):return self._failed or self._channel.sealed
    @property
    def owner_thread_alive(self):return self._channel.owner_thread_alive

    def connect(self):return self._channel.connect()
    def abort_before_connect(self):return self._channel.abort_before_connect()

    def wait_closed(self,timeout=5.0):
        result=self._channel.wait_closed(timeout)
        if result is True and self._channel.closed is True:
            with self._metadata:
                if self._records and self._records[-1]['requestMetadata']['opcode']==5:
                    self._records[-1]['eofConfirmed']=True
        return result

    def records(self):
        """Return detached accepted metadata only; no body/frame/response refs."""
        with self._metadata:
            # Only stored whitelist metadata is serialized, never validatorresult.
            return json.loads(json.dumps(self._records,allow_nan=False))

    def exchange(self,command,validator):
        _need(callable(validator) and not inspect.iscoroutinefunction(validator),'VALIDATOR')
        _need(self._serial.acquire(blocking=False),'BUSY')
        capture=None;result=None;failed=False;calls=0
        try:
            with self._metadata:
                _need(not self._failed,'SEALED');_need(len(self._records)<self._maximum,'CAP')
                expected=len(self._records)+1
            def validate(raw):
                nonlocal capture,calls
                calls+=1;_need(calls==1,'DUPLICATE_VALIDATOR')
                result=validator(raw)
                if inspect.isawaitable(result):
                    if inspect.iscoroutine(result):result.close()
                    raise SavedRefusal('SAVED_RECEIPT_OBSERVER_ASYNC_VALIDATOR')
                candidate=_capture(command,result)
                _need(candidate['requestMetadata']['sequence']==expected,'SEQUENCE')
                capture=candidate
                return result
            result=self._channel.exchange(command,validate)
            _need(capture is not None,'VALIDATOR_NOT_CALLED')
            capture['ackConfirmed']=True
            if capture['requestMetadata']['opcode']==5:capture['eofConfirmed']=self._channel.closed is True
            with self._metadata:self._records.append(capture)
        except Exception:
            self._failed=True;failed=True;result=None
        finally:
            capture=None;self._serial.release()
        # Raise outside the original exception handler: no __context__ chain
        # retaining the failed validator's frame/source through diagnostics.
        if failed:raise SavedRefusal('SAVED_RECEIPT_OBSERVER_EXCHANGE_UNPROVEN') from None
        return result
