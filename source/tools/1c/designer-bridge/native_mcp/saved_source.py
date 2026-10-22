"""Immutable saved-source wire contract. No native calls, paths or body files.

The provider must physically establish the claims in a receipt. Validation here
binds those claims to one request; it does not turn a Python callback into an
attested native transport. There is no editor-live or legacy-helper fallback.
"""
from dataclasses import dataclass, field
import hashlib
import math
import re

MAX_BYTES=4*1048576
MAX_CHARS=1048576
DOMAINS=('main_saved','database_saved')

class SavedRefusal(ValueError):
    """Sanitized stable refusal, never a provider diagnostic or body."""

def need(ok,code):
    if not ok:raise SavedRefusal('SAVED_'+code)

def integer(value,low,high):return type(value) is int and low<=value<=high

def finite(value):return type(value) in (int,float) and math.isfinite(value)

def uuid(value):return type(value) is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value) is not None and value!='00000000-0000-0000-0000-000000000000'

def digest(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None

@dataclass(frozen=True,slots=True)
class SourceBinding:
    root_uuid:str
    session_id:str
    process_id:int
    birth:str
    generation:int
    source_domain:str
    valid_until:float
    def validate(self):
        need(uuid(self.root_uuid),'ROOT')
        need(type(self.session_id) is str and re.fullmatch('[0-9a-f]{32}',self.session_id) is not None and self.session_id!='0'*32,'SESSION')
        need(integer(self.process_id,1,2**32-1) and type(self.birth) is str and re.fullmatch('[0-9a-f]{16}',self.birth) is not None and self.birth!='0'*16,'PROCESS')
        need(integer(self.generation,1,2**53-1) and self.source_domain in DOMAINS and type(self.source_domain) is str,'DOMAIN_GENERATION')
        need(finite(self.valid_until) and self.valid_until>0,'SCOPE_EXPIRY')

@dataclass(frozen=True,slots=True)
class Target:
    object_uuid:str
    property_uuid:str
    def validate(self):need(uuid(self.object_uuid) and uuid(self.property_uuid) and self.object_uuid!=self.property_uuid,'TARGET')

@dataclass(frozen=True,slots=True)
class GuardState:
    binding:SourceBinding
    target:Target
    dirty_state:str
    checked_at:float
    valid_until:float
    identity_verified:bool

@dataclass(frozen=True,slots=True)
class ReadRequest:
    binding:SourceBinding
    target:Target
    request_id:str
    revision:int
    issued_at:float
    valid_until:float

@dataclass(frozen=True,slots=True)
class SnapshotReceipt:
    binding:SourceBinding
    target:Target
    request_id:str
    revision:int
    sampled_at:float
    valid_until:float
    byte_count:int
    source_sha256:str
    saved_resource_sha256:str
    bom_present:bool
    crlf_count:int
    ends_lf:bool
    identity_verified:bool
    repeated_read_verified:bool
    schema_verified:bool
    dirty_before:str
    dirty_after:str
    decoder_profile:str='FORMAT15_RAM'
    helper_calls:int=0
    source_writes:int=0
    configuration_saves:int=0
    database_updates:int=0
    repository_mutations:int=0

@dataclass(frozen=True,slots=True)
class SavedSnapshot:
    receipt:SnapshotReceipt
    utf8:bytes=field(repr=False,compare=False)

def validate_snapshot(packet,request,now):
    """Validate exact receipt and byte-preserving UTF-8, returning transient text.

    Caller drops the returned body in finally; no normalization or cryptographic
    memory-erasure guarantee is implied. BOM remains a Unicode code point.
    """
    need(type(request) is ReadRequest and type(request.binding) is SourceBinding and type(request.target) is Target,'REQUEST')
    request.binding.validate();request.target.validate()
    need(type(request.request_id) is str and re.fullmatch('[0-9a-f]{32}',request.request_id) is not None and integer(request.revision,1,2**53-1),'REQUEST_ID')
    need(finite(request.issued_at) and finite(request.valid_until) and request.issued_at<=request.valid_until<=request.binding.valid_until,'REQUEST_EXPIRY')
    need(type(packet) is SavedSnapshot and type(packet.receipt) is SnapshotReceipt and type(packet.utf8) is bytes,'PACKET')
    r=packet.receipt;b=packet.utf8
    need(type(request) is ReadRequest and r.binding==request.binding and type(r.binding) is SourceBinding and r.target==request.target and type(r.target) is Target,'RECEIPT_BINDING')
    need(type(r.request_id) is str and r.request_id==request.request_id and integer(r.revision,1,2**53-1) and r.revision==request.revision,'REPLAY')
    need(finite(now) and finite(r.sampled_at) and finite(r.valid_until) and request.issued_at<=r.sampled_at<=now<=r.valid_until<=request.valid_until,'RECEIPT_EXPIRY')
    need(integer(r.byte_count,0,MAX_BYTES) and r.byte_count==len(b) and digest(r.source_sha256) and hashlib.sha256(b).hexdigest()==r.source_sha256 and digest(r.saved_resource_sha256),'BYTES_HASH')
    need(type(r.bom_present) is bool and r.bom_present==b.startswith(b'\xef\xbb\xbf') and integer(r.crlf_count,0,MAX_CHARS) and r.crlf_count==b.count(b'\r\n') and type(r.ends_lf) is bool and r.ends_lf==b.endswith(b'\n'),'BYTE_SHAPE')
    need(all(getattr(r,k) is True for k in ('identity_verified','repeated_read_verified','schema_verified')) and r.dirty_before=='clean' and r.dirty_after=='clean' and r.decoder_profile=='FORMAT15_RAM','READ_PROOF')
    need(all(type(getattr(r,k)) is int and getattr(r,k)==0 for k in ('helper_calls','source_writes','configuration_saves','database_updates','repository_mutations')),'SIDE_EFFECT')
    try:text=b.decode('utf-8','strict')
    except UnicodeDecodeError:raise SavedRefusal('SAVED_UTF8') from None
    need(len(text)<=MAX_CHARS and '\x00' not in text,'TEXT_BOUND')
    return text
