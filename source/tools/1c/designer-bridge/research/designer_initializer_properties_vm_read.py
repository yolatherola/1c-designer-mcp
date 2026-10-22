"""Two-pass VM_READ of fixed tool-runtime Designer fields, never SDK execution."""
from pathlib import Path
import hashlib
import json
import uuid
from types import SimpleNamespace
import designer_initializer_vm_read as parent
from core_as_sdk_probe import Image

ROOT=parent.ROOT
FIELDS={'_addins','_profileRoot','_snegopat','_hotkeys','_events','_windows','_metadata',
        '_v8files','_develop','_env','_cmdService','_winApi','_starterIpc'}
SPANS={0xdce90:(48,'a79e5f898857604c3d928c38257eac8bb3fc20d566571f9871d56a52e8c3be35'),
       0xdcec0:(144,'4740a8ab812c80ef91c1143ce3196f883707e0698a6a02b4cc486bd03d36ede7')}


def collect_root():
 ctl=parent.ctl;need=parent.need
 need(ctl.c.digest(Path(parent.__file__).read_bytes())=='7f122655d000aa8fdc5864200fd1024561e09804078a57ca6f0ac899a90e57c0','PARENT_READER_PIN')
 prior=ctl._json(ROOT/'artifacts/designer-bridge/designer-initializer-three-globals-vm-read-cdf10c4784fb4c01b63d342953bcef21.json',
  '86af3360f08b9e0968c19ad15cf61cc9d6ed781822de2e12e474ec004f141a96')
 plan=ctl._json(ROOT/'build'/('designer-hot-v233-'+parent.PARENT)/'plan.json');core=plan['sdkIdentity']['coreBase'];module=plan['sdkIdentity']['moduleAddress']
 def fresh():ctl.c._fresh(ctl.base._carrier_view(plan));ctl.base._lease(SimpleNamespace(plan=plan))
 fresh();image=Image(Path(plan['context']['corePath']));bodies={}
 for rva,(size,pin) in SPANS.items():
  at=image.offset(rva);raw=image.data[at:at+size];need(hashlib.sha256(raw).hexdigest()==pin,'PRIMARY_PROPERTY_PIN');bodies[rva]=raw
 reader=parent.vm.VmRead()
 try:
  reader.identity()
  def name(address):
   count=reader.word(address);need(0<count<=64,'TECHNICAL_NAME_BOUND')
   at=address+4 if count<=11 else reader.word(address+4)
   return reader.chunked(at,count).decode('ascii',errors='strict')
  def snapshot():
   need(reader.word(module)==core+0x28e454,'MODULE_TABLE')
   for rva,body in bodies.items():need(reader.chunked(core+rva,len(body))==body,'RUNTIME_PROPERTY_CODE')
   for row in prior['globalState']['globals'].values():
    need(reader.word(row['storagePointer'])==row['valuePointer'],'PREVIOUS_GLOBAL_CHANGED')
   obj=prior['globalState']['globals']['oneDesigner']['valuePointer']
   ty=reader.word(obj+4);need(ty==prior['globalState']['globals']['oneDesigner']['datatypeObjectType'],'DESIGNER_TYPE')
   count,vector=reader.word(ty+0x58),reader.word(ty+0x54);need(len(FIELDS)<=count<=64,'DESIGNER_PROPERTY_COUNT')
   fields={}
   for index in range(count):
    prop=reader.word(vector+4*index);label=name(prop)
    # Designer also declares internal fields below its constructor. Their
    # metadata names may be visited; their values are outside this reader.
    if label not in FIELDS:continue
    need(label not in fields,'PROPERTY_NAME')
    flags=reader.read(prop+0x18,1)[0];offset=reader.word(prop+0x1c)
    need(flags&4 and offset%4==0 and 8<=offset<=4096,'HANDLE_PROPERTY_OFFSET')
    fields[label]=dict(index=index,offset=offset,valuePointer=reader.word(obj+offset))
   need(set(fields)==FIELDS,'PROPERTY_SET')
   vector,count=reader.word(module+0x10c),reader.word(module+0x110);need(0<count<=4096,'GLOBAL_BOUND')
   extra={}
   for index in range(count):
    prop=reader.word(vector+index*4);length=reader.word(prop)
    if length not in (7,13):continue
    label=name(prop)
    if label not in ('coreMainFrame','mdiView'):continue
    need(label not in extra and reader.read(prop+0x18,1)[0]&4,'EXTRA_HANDLE')
    storage=reader.word(prop+0x2c);extra[label]=dict(index=index,storagePointer=storage,valuePointer=reader.word(storage))
   need('coreMainFrame' in extra,'CORE_FRAME_GLOBAL')
   return dict(designerObject=obj,designerType=ty,designerPropertyCount=reader.word(ty+0x58),fields=fields,
    bootstrapGlobals=extra,optionalMdiViewGlobalPresent='mdiView' in extra)
  first=snapshot();need(snapshot()==first,'PROPERTIES_CHANGED');reader.identity();fresh()
  result=dict(kind='DESIGNER_INITIALIZER_PROPERTIES_VM_READ',operationId=uuid.uuid4().hex,parentOperationId=parent.PARENT,
   processId=parent.vm.PID,birth=parent.vm.BIRTH,readerSourceSha256=ctl.c.digest(Path(__file__).read_bytes()),
   twoIdenticalPasses=True,readablePagesValidated=True,state=first,scope='fixed_tool_runtime_handles_only',
   nativeCallbacks=0,sdkCalls=0,referenceCalls=0,constructorRetry=False,configurationSaves=0,databaseUpdates=0,
   repositoryMutations=0,applicationTextOutputBytes=0,initializerClosureProved=False)
  path=ROOT/'artifacts/designer-bridge'/('designer-initializer-properties-vm-read-'+result['operationId']+'.json');ctl.c.write_new(path,result)
  return dict(path=str(path),sha256=ctl.c.digest(path.read_bytes()),result=result)
 finally:reader.close()


if __name__=='__main__':print(json.dumps(collect_root(),sort_keys=True))
