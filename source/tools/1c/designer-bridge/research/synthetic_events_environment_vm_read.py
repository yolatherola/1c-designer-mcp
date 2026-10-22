"""Read only the failed synthetic adapter's fixed tool globals and code.

The old UNKNOWN is preserved. No SDK, callbacks, COM, reference operations,
application metadata, configuration save or database update is performed.
"""
from pathlib import Path
from types import SimpleNamespace
import ctypes as ct
import hashlib,json,struct,uuid
import synthetic_events_roundtrip as ctl
import update_owner_runtime_read as vm

ROOT=ctl.ROOT;OP='0f1368b7c3a649408cb2f82850ce0213'
DLL_SHA='3748e1a899fe9df8b33e11d23dbccba7c62d09a7bcd74f8e589859b9dfdda3a7'
SPANS=((0x5579,0x564e-0x5579),(0x5278,0x52ef-0x5278),(0x5965,0x59a7-0x5965))


def need(ok,code):
 if not ok:raise ValueError('SYNTHETIC_ENVIRONMENT_VM_'+code)


def image_bytes(raw,runtime_base):
 """Map this exact own PE32 and apply only its standard HIGHLOW relocations."""
 need(hashlib.sha256(raw).hexdigest()==DLL_SHA,'DLL_PIN')
 u16=lambda at:struct.unpack_from('<H',raw,at)[0];u32=lambda at:struct.unpack_from('<I',raw,at)[0]
 nt=u32(0x3c);opt=nt+24
 need(raw[:2]==b'MZ' and raw[nt:nt+4]==b'PE\0\0' and u16(nt+4)==0x14c and u16(opt)==0x10b,'PE')
 preferred=u32(opt+28);size=u32(opt+56);need(preferred==0x10000000 and 0xc438<=size<=1048576,'IMAGE_BOUND')
 mapped=bytearray(size);header=u32(opt+60);need(header<=len(raw) and header<=size,'HEADER');mapped[:header]=raw[:header]
 for i in range(u16(nt+6)):
  p=opt+u16(nt+20)+40*i;vs,rva,amount,at=struct.unpack_from('<IIII',raw,p+8)
  need(rva+max(vs,amount)<=size and at+amount<=len(raw),'SECTION');mapped[rva:rva+amount]=raw[at:at+amount]
 # Fixed disassembly anchors bind each selected datum to the proved C branch.
 need(mapped[0x55c6:0x55d4]==bytes.fromhex('8b05bc78001081f8a05445030f85'),'TRIAL_ENGINE_BRANCH')
 need(mapped[0x5282:0x528d]==b'\xb8\x60\x00\x00\x00\x50\xb8\xa8\xc3\x00\x10','STATE96_ANCHOR')
 reloc_rva,reloc_size=u32(opt+96+5*8),u32(opt+100+5*8);end=reloc_rva+reloc_size
 need(0<reloc_size<=65536 and end<=size,'RELOC_DIRECTORY');cursor=reloc_rva;count=0
 while cursor<end:
  page,amount=struct.unpack_from('<II',mapped,cursor);need(amount>=8 and amount%2==0 and cursor+amount<=end,'RELOC_BLOCK')
  for at in range(cursor+8,cursor+amount,2):
   entry=struct.unpack_from('<H',mapped,at)[0];kind=entry>>12
   if not kind:continue
   need(kind==3 and page+(entry&4095)+4<=size,'RELOC_TYPE');target=page+(entry&4095)
   word=struct.unpack_from('<I',mapped,target)[0];struct.pack_into('<I',mapped,target,(word+runtime_base-preferred)&0xffffffff);count+=1
  cursor+=amount
 need(cursor==end and count>0,'RELOC_COMPLETE');return mapped,count


def state_words(word,base):
 values=dict(trialEngine=word(base+0x78bc),sdkGuiThread=word(base+0x78cc),abiFault=word(base+0x78b8),
  pageRefusals=word(base+0xc424),environmentRefusals=word(base+0xc428),repeatedCalls=word(base+0xc42c),
  initialized=word(base+0xc430),proofWritten=word(base+0xc434))
 state=[word(base+0xc3a8+4*i) for i in range(24)];calls=[word(base+0xc408+4*i) for i in range(7)]
 need(values==dict(trialEngine=0,sdkGuiThread=8292,abiFault=0,pageRefusals=0,environmentRefusals=1,repeatedCalls=0,initialized=0,proofWritten=0)
  and state==[0]*24 and calls==[0]*7,'NONEMPTY_OR_CHANGED_STATE')
 return dict(globals=values,runtimeWords=state,commandCalls=calls,phase=state[4],sinkPointer=state[6])


def collect_root():
 ctl._pins();c=ctl.c;folder=ROOT/'build'/('designer-hot-v233-'+OP);plan=ctl._json(folder/'plan.json')
 sdk=ctl._json(folder/'sdk-receipt.json','4a76bf46f33fd26f21d414abdb0975c181aa31c893d86c30eaf298e47dc7f16a')
 native=ctl._json(folder/'synthetic-events-proof.json','b9a8cd649723e0e482b9b9cf2c131c213ea6eb5b460d5ed10b0ce618315eae81')
 epoch=ctl._json(folder/'cpp-exception-type-epoch.json','b7e12ff0777d08b5009e0efdc687969bbad3ac3fe2efee72cf1325daba996842')
 unknown=ctl._json(folder/'unknown.json','cd4608876f33b026c20d21ac80d37596b81847cc1c83152e5ecf6f4aa9dae3e3')
 need(sdk.get('sdkResult')==0 and sdk.get('knownTerminal') is True and sdk.get('hookWorkersReleased') is True
  and native.get('reason')=='CREATE_SINK' and native.get('bridgeCalls')==1 and native.get('sinkCreated') is False
  and native.get('syntheticEvents')==0 and native.get('afterRootAndTargetsClean') is True
  and unknown.get('status')=='UNKNOWN_RETAIN' and not (folder/ctl.BRIDGE_FILE).exists(),'FAILED_RECEIPTS')
 need(epoch.get('executeReturned') is True and epoch.get('sdkExecuteRc')==0 and epoch.get('handlerRemoved') is True
  and epoch.get('cppThrows')==epoch.get('otherExceptions')==0,'QUIESCENT_EPOCH')
 need(c.digest(c.read(folder/'Continuation.c'))=='af0d04464af1c27f3ccb2e47847a8b1a337fad6999085b22bc6769254a805d7d','C_PIN')
 def fresh():c._fresh(ctl.base._carrier_view(plan));ctl.base._lease(SimpleNamespace(plan=plan))
 fresh();v=vm.VmRead()
 try:
  v.identity();snapshot=v.k.CreateToolhelp32Snapshot(0x18,vm.PID);need(snapshot not in (None,ct.c_void_p(-1).value),'MODULE_SNAPSHOT')
  target=(folder/'Continuation.dll').resolve();found=[]
  try:
   entry=v.Entry();entry.dwSize=ct.sizeof(entry);ok=v.k.Module32FirstW(snapshot,ct.byref(entry));count=0;need(ok,'MODULE_FIRST')
   while ok:
    count+=1;need(count<=512,'MODULE_BOUND')
    if Path(entry.szExePath).resolve()==target:found.append(int(entry.modBaseAddr))
    ok=v.k.Module32NextW(snapshot,ct.byref(entry))
  finally:v.k.CloseHandle(snapshot)
  need(len(found)==1,'EXACT_LOADED_DLL');base=found[0];mapped,relocs=image_bytes(target.read_bytes(),base)
  def readback():
   for rva,length in SPANS:need(v.chunked(base+rva,length)==mapped[rva:rva+length],'RUNTIME_CODE_CHANGED')
   return state_words(v.word,base)
  first=readback();need(readback()==first,'TWO_PASS_CHANGED');v.identity();fresh()
  proof=dict(kind='SYNTHETIC_ENVIRONMENT_REFUSAL_VM_READ',operationId=uuid.uuid4().hex,parentOperationId=OP,
   readerSourceSha256=c.digest(Path(__file__).read_bytes()),processId=vm.PID,birth=vm.BIRTH,loadedOwnDllBase=base,
   exactDllSha256=DLL_SHA,relocationsVerified=relocs,twoIdenticalPasses=True,readablePagesValidated=True,state=first,
   classification='INITIAL_ENVIRONMENT_REFUSAL_NO_SINK',originalUnknownPreserved=True,successClaimed=False,
   sdkCalls=0,nativeCallbacks=0,referenceCalls=0,configurationSaves=0,databaseUpdates=0,repositoryMutations=0,applicationTextOutputBytes=0)
  path=ROOT/'artifacts/designer-bridge'/('synthetic-environment-refusal-vm-read-'+proof['operationId']+'.json');c.write_new(path,proof)
  return dict(path=str(path),sha256=c.digest(path.read_bytes()),result=proof)
 finally:v.close()


if __name__=='__main__':print(json.dumps(collect_root(),sort_keys=True))
