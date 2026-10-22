"""Fixed delegate's negative command path; no native call or update admission."""
import hashlib
import struct
import uuid
from repository_pe_probe import PE
from current_comparison_factory_primary import _decoder, local_cfg

IMAGE_SHA='9556defc1ccd1cd8b05ed63d4b0287f40fac2bccba42a68fc229927c8b5fc8a5'
SPANS={
 'execute':(0x9b07f0,33,'97f76b584fdcf959cb33a36cb2951e6a3b53dd0a67b9a7d7b308c2397fcbaae4'),
 'request':(0x9b0870,33,'db71b41f08fc316983e9bbf332a7bcf406828f66be7464ee5099cf2c290872b3'),
 'dispatch':(0x243a60,1154,'bfdd026f966d3ae3813dfd7b183c8bd8158598a0ea8ba43f8261ab4b78c61635'),
 'equal':(0x8f3400,66,'e9a3b941974142ce136d97127ea97a7dd42a4a660564cc481697310e5d6096bb')}
KEYS=((0xe08484,261),(0xe08498,262),(0xe097d0,12),(0xe097f8,58),
      (0xe097e4,13),(0xe09a00,51),(0xe09a3c,57))
CONFIG_GROUP='f10cbb81-f679-11d4-9dd3-0050bae2bc79'
FRNTEND_GROUP='6b7291bf-bcd2-41af-bac7-414d47cc6e6a'

def need(ok,code):
 if not ok:raise ValueError('DELEGATE_NEGATIVE_PATH_'+code)

def verify_units(bodies,key_bytes,*,check_hashes=True):
 """Verify whole bodies and the exact seven keys, including every false edge."""
 need(type(bodies) is dict and set(bodies)==set(SPANS),'BODY_SET')
 rows={};cfg={}
 for name,(rva,size,pin) in SPANS.items():
  raw=bodies[name];need(type(raw) is bytes and len(raw)==size,'BODY_BOUND')
  if check_hashes:need(hashlib.sha256(raw).hexdigest()==pin,'BODY_PIN')
  cfg[name]=local_cfg(raw,rva);rows.update({i.address:(i.mnemonic,i.op_str) for i in _decoder().disasm(raw,rva)})
 need(type(key_bytes) is dict and set(key_bytes)=={a for a,n in KEYS},'KEY_SET')
 numbers=[]
 for index,(rva,number) in enumerate(KEYS):
  raw=key_bytes[rva];need(type(raw) is bytes and len(raw)==20,'KEY_BOUND')
  expected=uuid.UUID(int=0).bytes_le if index<2 else uuid.UUID(FRNTEND_GROUP).bytes_le
  need(raw==expected+struct.pack('<I',number),'EXACT_KEY');numbers.append(number)
 anchors={
  0x9b07f6:('lea','eax, [ecx - 0x18]'),0x9b0809:('push','0'),
  0x9b087b:('lea','eax, [ecx - 0x18]'),0x9b0880:('push','1'),
  0x243a95:('jne','0x243ac6'),0x243acd:('je','0x243b10'),
  0x243b19:('jne','0x243b4a'),0x243b4e:('je','0x243b96'),
  0x243b9f:('jne','0x243bd0'),0x243bd4:('je','0x243c20'),
  0x243c29:('jne','0x243c5a'),0x243c5e:('je','0x243d63'),
  0x243d6a:('call','0x8f3400'),0x243d71:('je','0x243e01'),
  0x243e08:('call','0x8f3400'),0x243e0f:('je','0x243e52'),
  0x243e59:('call','0x8f3400'),0x243e60:('je','0x243ea3'),
  0x243ea3:('xor','al, al'),0x243eb6:('ret','0xc'),
  0x8f340d:('cmp','eax, dword ptr [ebx + 0x10]'),0x8f3410:('jne','0x8f343a'),
  0x8f343b:('xor','al, al'),0x8f343f:('ret','4')}
 need(all(rows.get(at)==value for at,value in anchors.items()),'NEGATIVE_EDGE')
 need(29 not in numbers and 30 not in numbers,'CONFIG_NUMBER_COLLISION')
 return dict(kind='UPDATE_OWNER_DELEGATE_NEGATIVE_PRIMARY',platformSha256=IMAGE_SHA,
  delegateFacetRva=0xc39318,canonicalFacetRva=0xc39330,canonicalOffset=-0x18,
  dispatchRva=0x243a60,supportedCommandNumbers=numbers,configGroup=CONFIG_GROUP,
  config29RejectedStatically=True,config30RejectedStatically=True,requestAndExecuteReturnFalse=True,
  reason='seven_command_number_mismatches_reach_final_false',normalCfg=cfg,
  runtimeCodeAndKeysVerified=False,actualUpdate29OwnerVerified=False,databaseUpdateAuthorized=False,nativeCalls=0)

def verify_primary():
 """Read installed platform code only; returned proof is not a live binding."""
 pe=PE('frntend.dll');need(hashlib.sha256(pe.data).hexdigest()==IMAGE_SHA,'PLATFORM_PIN')
 def take(rva,size):
  off=pe.offset(pe.base+rva);return pe.data[off:off+size]
 bodies={name:take(rva,size) for name,(rva,size,pin) in SPANS.items()}
 keys={rva:take(rva,20) for rva,number in KEYS}
 return verify_units(bodies,keys),bodies,keys
