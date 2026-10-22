"""Read only three tool-runtime globals after a failed Designer constructor.

No SDK call, script evaluation, callback, reference operation or write occurs.
Only fixed Core.As metadata and the three declared handle storage words are
read; application metadata modules and clinical values are never inspected.
"""
from pathlib import Path
import hashlib
import json
import struct
import uuid
from types import SimpleNamespace
import update_owner_runtime_read as vm
import designer_events_initialize as ctl
from core_as_sdk_probe import Image

ROOT=ctl.ROOT
PARENT='5f85728757774731b330a608f19f26b7'
WANTED={'oneDesigner','oneAddinMgr','dspWindows'}
SPANS={0xa6430:(112,'615b15083321faf15484644f7c5a1fe34d059b765ed206c59422bea982c6b0e8'),
       0xa6660:(150,'a3402f34f76e681e362947706d5fab4c08bbb247f6eb9724c9f2f0177253d2cc')}


def need(ok,code):
 if not ok:raise ValueError('DESIGNER_INITIALIZER_VM_'+code)


def collect_root():
 ctl._pins();folder=ROOT/'build'/('designer-hot-v233-'+PARENT)
 plan=ctl._json(folder/'plan.json');sdk=ctl._json(folder/'sdk-receipt.json');unknown=ctl._json(folder/'unknown.json')
 need(plan['designerEventsInitControllerSha256']=='1fcf9ddba9419539ed7b5150c87a81af0756cb858292d7269056314471350518'
  and sdk['sdkResult']==3 and sdk['hookWorkersReleased'] is True and sdk['knownTerminal'] is True
  and unknown['status']=='UNKNOWN_RETAIN' and not (folder/ctl.NATIVE_FILE).exists(),'FAILED_PARENT')
 def fresh():ctl.c._fresh(ctl.base._carrier_view(plan));ctl.base._lease(SimpleNamespace(plan=plan))
 fresh();core=plan['sdkIdentity']['coreBase'];module=plan['sdkIdentity']['moduleAddress']
 image=Image(Path(plan['context']['corePath']));bodies={}
 for rva,(size,pin) in SPANS.items():
  at=image.offset(rva);raw=image.data[at:at+size];need(hashlib.sha256(raw).hexdigest()==pin,'PRIMARY_PIN');bodies[rva]=raw
 reader=vm.VmRead()
 try:
  reader.identity()
  def snapshot():
   need(reader.word(module)==core+0x28e454,'MODULE_TABLE')
   for rva,raw in bodies.items():need(reader.chunked(core+rva,len(raw))==raw,'RUNTIME_CODE')
   vector,count=reader.word(module+0x10c),reader.word(module+0x110)
   need(0<count<=4096 and vector>=65536,'GLOBAL_VECTOR')
   found={}
   for index in range(count):
    prop=reader.word(vector+index*4)
    need(prop>=65536 and prop%4==0,'GLOBAL_PROPERTY')
    length=reader.word(prop)
    # All three names fit the SDK's <=11 byte inline-name branch. Other
    # names are not copied or emitted; no other global value is read.
    if length not in (10,11):continue
    name=reader.read(prop+4,length).decode('ascii',errors='replace')
    if name not in WANTED:continue
    need(name not in found,'DUPLICATE_GLOBAL')
    storage=reader.word(prop+0x2c);need(storage>=65536 and storage%4==0,'GLOBAL_STORAGE')
    value=reader.word(storage);table=reader.word(value) if value else 0
    methods=[]
    if value:
     need(core<=table<core+0x320000,'SCRIPT_OBJECT_TABLE')
     methods=[reader.word(table+i*4)-core for i in range(10)]
     need(all(0<=entry<0x320000 for entry in methods),'SCRIPT_OBJECT_METHODS')
    found[name]=dict(index=index,propertyPointer=prop,storagePointer=storage,valuePointer=value,
     datatypeToken=reader.word(prop+0x10),datatypeObjectType=reader.word(prop+0x14),datatypeFlags=reader.read(prop+0x18,1)[0],
     tableRva=table-core if table else 0,methodRvas=methods)
   need(set(found)==WANTED,'GLOBALS_NOT_FOUND')
   return dict(globalCount=count,globals=found)
  first=snapshot();need(snapshot()==first,'TWO_PASS_CHANGED');reader.identity();fresh()
  result=dict(kind='DESIGNER_INITIALIZER_THREE_GLOBALS_VM_READ',operationId=uuid.uuid4().hex,parentOperationId=PARENT,
   processId=vm.PID,birth=vm.BIRTH,readerSourceSha256=ctl.c.digest(Path(__file__).read_bytes()),
   twoIdenticalPasses=True,readablePagesValidated=True,globalState=first,coreBase=core,
   nativeCallbacks=0,sdkCalls=0,referenceCalls=0,constructorRetry=False,configurationSaves=0,databaseUpdates=0,
   repositoryMutations=0,applicationTextOutputBytes=0,initializerClosureProved=False)
  path=ROOT/'artifacts/designer-bridge'/('designer-initializer-three-globals-vm-read-'+result['operationId']+'.json')
  ctl.c.write_new(path,result);return dict(path=str(path),sha256=ctl.c.digest(path.read_bytes()),result=result)
 finally:reader.close()


if __name__=='__main__':print(json.dumps(collect_root(),sort_keys=True))
