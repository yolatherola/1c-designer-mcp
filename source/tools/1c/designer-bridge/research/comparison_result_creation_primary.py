"""Actual uncached creator's successful allocation/QI path, offline only.

The platform's malloc contract is a trusted allocator boundary. This is not a
claim that a process is unpatched, permission to call, or a complete proof of
every constructor/allocator side effect. Runtime matching remains mandatory.
"""
from pathlib import Path
import hashlib
import struct
import uuid
from repository_pe_probe import PE, PLATFORM
from current_comparison_factory_primary import _decoder, local_cfg
from configuration_comparison_service_primary_v177 import imported

BASE=0x26dc0000
IID='d7b5a01d-f882-4677-8944-d926ea06d67d'
NUKE_SHA='58394f53e86a30eb97a4e62670055f3a655bbaeb672cdb6bb1e9de5f0fbc511c'
SPANS={
 'wrapper':(0x8ede90,89,'4a495f61e7135cc2e13ce93ef30b326b7a320f1fd2337fd2aac9755dcdba65f2'),
 'callback':(0x962e10,34,'5212ebb192bbf3566b99f0aa359dc812defdd3b89c61911f42944c44c17dff75'),
 'creator':(0x9636d0,236,'ebda0776f8994979724d849116ae21098b4c3a23bb4ed67997a94a54c4dc0987'),
 'newNothrow':(0xb129a5,80,'bc9d559f50b39e29115db12c6cc80c325a613d64bcc069583b4ccdd99f3c8581'),
 'newThrow':(0xb12952,48,'20eea40733b5245e77a7c4874b8509e1f13f67342b121c5cb953f8ddb5bd5031'),
 'mallocThunk':(0xb1231e,6,'e14cd5f4361550bf9f7db247b7d91c9d085b22626b4d34d823e13a486cd3efda'),
 'queryThunk':(0x963a10,26,'d2a226b854676cda719d7a5640621a33d421b0ecd2e7bd888ef3e67972eba5c7'),
 'query':(0x8f0580,234,'97a0568cd952f0c443fe52096f4962424e7a235baf1f8f6788ed7728941f4d7f'),
 'unknownTest':(0x8f0550,38,'d24c771beb319eb7a74d36b6f7ae271defcdea7b1f3ea0276eecd28ab7fa89ab'),
 'map':(0xc0e7c0,72,'fd69e3bba4a029ead649f86ec0ef58e800c3d2a87165a8e38b0f905f93b8f5bb'),
 'iid':(0xc0dae0,16,'2595f6fba326f16eedcddabc2b486cb0ffa35e4aa8f94778a7644846d9cd6a8b'),
 'resultTable':(0xc0df98,48,'ab9d08c6b60387eea1e48b04bb2e8776ee8f0c79d99119cde0f53ff5bd0c1388')}


def need(ok,code):
 if not ok:raise ValueError('RESULT_CREATION_'+code)


def local_regions(raw,start,seeds=(),terminal_branches=()):
 """Close normal and explicitly declared EH local entries, no callee claims."""
 rows={i.address:i for i in _decoder().disasm(raw,start)}
 need(sum(i.size for i in rows.values())==len(raw),'CFG_DECODE')
 pending=[start,*seeds];seen=set();external=set();returns=[]
 while pending:
  at=pending.pop()
  if at in seen:continue
  need(at in rows,'CFG_ADDRESS');seen.add(at);ins=rows[at];nexts=[]
  if ins.mnemonic=='ret':returns.append(ins.op_str or '0')
  elif ins.mnemonic.startswith('j'):
   need(ins.operands[0].type==2,'CFG_INDIRECT_BRANCH')
   target=ins.operands[0].imm
   if target in terminal_branches:external.add(target)
   else:nexts.append(target)
   if ins.mnemonic!='jmp':nexts.append(at+ins.size)
  else:nexts.append(at+ins.size)
  pending.extend(nexts)
 need(seen==set(rows),'CFG_UNREACHED')
 need(external==set(terminal_branches),'CFG_FAILURE_BOUNDARY')
 return dict(instructions=len(rows),returns=sorted(returns),additionalEhEntries=list(seeds),failureBoundaries=sorted(external))


def verify_units(bodies,*,check_hashes=True):
 need(type(bodies) is dict and set(bodies)==set(SPANS),'UNIT_SET')
 for name,(_,size,pin) in SPANS.items():
  need(type(bodies[name]) is bytes and len(bodies[name])==size,'UNIT_BOUND')
  if check_hashes:need(hashlib.sha256(bodies[name]).hexdigest()==pin,'UNIT_PIN')
 rows={i.address:(i.mnemonic,i.op_str) for name,(rva,_,_) in SPANS.items()
       if name not in ('map','iid','resultTable') for i in _decoder().disasm(bodies[name],rva)}
 anchors={
  0x8eded7:('mov','eax, dword ptr [eax + 0x24]'),0x8ededa:('call','eax'),
  0x962e1c:('test','ecx, ecx'),0x962e1e:('jne','0x962e29'),0x962e20:('call','0x9636d0'),
  0x963728:('mov','dword ptr [ebx], 0'),0x96372e:('push','0x5a4'),0x96373d:('call','0xb129a5'),
  0x963742:('mov','esi, eax'),0x963749:('je','0x963781'),0x96374b:('mov','ecx, esi'),0x96374d:('call','0x135470'),
  0x963752:('mov','dword ptr [esi], 0x279cdf98'),0x96378e:('mov','eax, dword ptr [esi]'),
  0x963790:('push','ebx'),0x963791:('push','dword ptr [ebp - 0x14]'),0x963794:('push','esi'),0x963795:('call','dword ptr [eax]'),
  0xb129d5:('call','0xb12952'),0xb12967:('call','0xb1231e'),0xb1231e:('jmp','dword ptr [0x279ba238]'),
  0x963a16:('mov','ecx, dword ptr [ebp + 8]'),0x963a19:('mov','edx, 0x279ce7c0'),0x963a21:('call','0x8f0580'),
  0x8f0603:('jne','0x8f0624'),0x8f0607:('cmp','eax, 1'),0x8f060a:('je','0x8f0643'),
  0x8f0643:('mov','esi, dword ptr [esi - 4]'),0x8f0646:('add','esi, dword ptr [ebp - 4]'),
  0x8f064c:('call','dword ptr [eax + 4]'),0x8f0652:('mov','dword ptr [eax], esi'),0x8f0654:('xor','eax, eax')}
 need(all(rows.get(at)==pair for at,pair in anchors.items()),'SUCCESS_PATH_ANCHOR')
 need(uuid.UUID(bytes_le=bodies['iid'])==uuid.UUID(IID),'REQUESTED_IID')
 need(struct.unpack_from('<3I',bodies['map'])==(BASE+0xc0dae0,0,1),'DIRECT_SELF_IID_MAPPING')
 table=struct.unpack('<12I',bodies['resultTable'])
 need(table[0]==BASE+0x963a10 and table[3]==BASE+0x136c70 and table[11]==BASE+0x137da0,'RESULT_TABLE')
 cfg={name:local_cfg(bodies[name],SPANS[name][0]) for name in ('wrapper','callback','queryThunk','query','unknownTest')}
 cfg['creator']=local_regions(bodies['creator'],0x9636d0,(0x963776,0x96377c))
 cfg['newNothrow']=local_regions(bodies['newNothrow'],0xb129a5,(0xb129dd,0xb129e3))
 cfg['newThrow']=local_regions(bodies['newThrow'],0xb12952,terminal_branches=(0xb134fc,0xaad840))
 return dict(kind='COMPARISON_RESULT_CREATION_PRIMARY',requestedIid=IID,outerUnknownMustBeNull=True,
  allocationSize=0x5a4,normalQueryResultOffset=0,returnedReferenceAcquiredByQi=True,
  uncachedSuccessAllocatesDistinctStorageStatically=True,creatorCfg=cfg,
  allocatorContract='trusted_platform_C_malloc_live_allocation',allocatorImplementationTransitivelyAudited=False,
  callbackMustMatch=0x962e10,registrationModeMustEqual=0,registrationDelegateMustBeAbsent=True,
  runtimeRegistrationAndCodeMatched=False,freshAllocationVerified=False,factoryCallable=False,nativeCalls=0,databaseUpdateAuthorized=False)


def nuke_image():
 """Read only this newly identified fixed allocator DLL, without old allowlist edits."""
 data=(PLATFORM/'nuke83.dll').read_bytes();need(len(data)==54832 and hashlib.sha256(data).hexdigest()==NUKE_SHA,'NUKE_PIN')
 need(data[:2]==b'MZ','NUKE_DOS');nt=struct.unpack_from('<I',data,60)[0];opt=nt+24
 need(data[nt:nt+4]==b'PE\0\0' and struct.unpack_from('<H',data,nt+4)[0]==0x14c
      and struct.unpack_from('<H',data,opt)[0]==0x10b,'NUKE_PE32')
 sections=[];count=struct.unpack_from('<H',data,nt+6)[0];need(count<=16,'NUKE_SECTIONS')
 start=opt+struct.unpack_from('<H',data,nt+20)[0]
 for i in range(count):
  virtual,rva,size,raw=struct.unpack_from('<4I',data,start+40*i+8)
  need(raw+size<=len(data),'NUKE_SECTION_BOUND');sections.append((rva,size,raw))
 def take(rva,size):
  for base,length,raw in sections:
   if base<=rva and rva+size<=base+length:return data[raw+rva-base:raw+rva-base+size]
  need(False,'NUKE_RVA')
 export,export_size=struct.unpack_from('<2I',data,opt+96)
 fields=struct.unpack('<IIHHIIIIIII',take(export,40));_,_,_,_,_,ordinal_base,nfunctions,nnames,functions,names,ordinals=fields
 need(nnames<=256 and nfunctions<=256,'NUKE_EXPORT_BOUND');found=[]
 for index in range(nnames):
  string_rva=struct.unpack('<I',take(names+index*4,4))[0]
  name=take(string_rva,7)
  if name==b'malloc\0':
   ordinal=struct.unpack('<H',take(ordinals+index*2,2))[0];need(ordinal<nfunctions,'NUKE_ORDINAL')
   target=struct.unpack('<I',take(functions+ordinal*4,4))[0];found.append((target,ordinal_base+ordinal))
 need(found==[(0x1080,20)] and not export<=0x1080<export+export_size,'NUKE_MALLOC_EXPORT')
 return dict(data=data,base=struct.unpack_from('<I',data,opt+28)[0],take=take)


def verify_primary():
 image=PE('frntend.dll');need(image.base==BASE,'IMAGE_BASE');bodies={}
 for name,(rva,size,_) in SPANS.items():
  at=image.offset(BASE+rva);bodies[name]=image.data[at:at+size]
 proof=verify_units(bodies);boundary=imported(image,iat=0xbfa238)
 need(boundary['module']=='nuke83.dll' and boundary['symbol']=='malloc','ALLOCATOR_IMPORT')
 nuke=nuke_image();wrapper=nuke['take'](0x1080,34)
 proof.update(allocatorImport=boundary,allocatorDllSha256=NUKE_SHA,allocatorExportRva=0x1080,
              allocatorWrapperSha256=hashlib.sha256(wrapper).hexdigest())
 return proof,bodies,wrapper
