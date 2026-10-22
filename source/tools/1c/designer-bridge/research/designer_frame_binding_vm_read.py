"""Independent VM-only readback of the two repaired tool-runtime bindings.

No SDK execution, native callback, reference operation or application read.
The old failed constructor remains UNKNOWN; this receipt does not admit apply.
"""
from pathlib import Path
from types import SimpleNamespace
import json
import uuid
import designer_initializer_properties_vm_read as old

ROOT=old.ROOT
OP='b4fa9b80dddc49198d4d58f3c95e6540'


def need(ok,code):
 if not ok:raise ValueError('FRAME_BINDING_VM_'+code)


def project(read_word,*,module,core,globals_proof,properties_proof,frames,native):
 """Bounded pure projection; an unrelated or changed handle refuses."""
 state=properties_proof['state'];gp=globals_proof['globalState']['globals'];obj=state['designerObject']
 need(read_word(module)==core+0x28e454 and read_word(module+0x110)==815,'MODULE')
 need(read_word(obj)==core+gp['oneDesigner']['tableRva'] and read_word(obj+4)==state['designerType'],'DESIGNER')
 need(read_word(state['designerType']+0x58)==state['designerPropertyCount']==16,'TYPE')
 values={}
 for name,row in gp.items():
  value=read_word(row['storagePointer']);need(value==row['valuePointer'],'GLOBAL_CHANGED');values[name]=value
 for name,row in state['fields'].items():
  offset=row['offset'];need(type(offset) is int and 8<=offset<=4096 and offset%4==0,'OFFSET')
  value=read_word(obj+offset);need(value==row['valuePointer'],'PREFIX_CHANGED');values[name]=value
 need(set(frames)=={'mainFrame','coreMainFrame'},'FRAME_NAMES')
 for name,key in [('mainFrame','mainFrameAfter'),('coreMainFrame','coreMainFrameAfter')]:
  value=read_word(frames[name]);need(value==native[key] and value>=65536,'FRAME_CHANGED');values[name]=value
 return values


def collect_root():
 ctl=old.parent.ctl;c=ctl.c;ctl._pins()
 need(c.digest(Path(old.__file__).read_bytes())=='0018aeaa97cbf8d69d4243819bae0a1299ce6749bf9e5d325c689db702143755','OLD_READER')
 folder=ROOT/'build'/('designer-hot-v233-'+OP)
 result=ctl._json(folder/'result.json','c68e03939cd632a939e47e2a0aca32bba498fedb8b5dbe3fd1686838a1846a93')
 native=ctl._json(folder/'designer-frame-binding-repair-proof.json','3a1d8a8d37973146cd6ca30511786a8ec1cad52eb2ec324f21898004ba8e31de')
 need(result['knownTerminal'] is True and result['sdkResult']==0 and result['status']=='FRAME_CONTEXT_REPAIRED_PREFIX_PRESERVED','RESULT')
 need(native['frameBindings']==2 and native['designerPrefixPreserved'] is True,'NATIVE')
 plan=ctl._json(folder/'plan.json')
 need(c.digest(c.canonical(plan))=='2e9025f025a6a7fb4271b535599285b44052e5e617d5f7efa86dbcab7f43d1b9','PLAN_CANONICAL_PIN')
 gp=ctl._json(ROOT/'artifacts/designer-bridge/designer-initializer-three-globals-vm-read-cdf10c4784fb4c01b63d342953bcef21.json','86af3360f08b9e0968c19ad15cf61cc9d6ed781822de2e12e474ec004f141a96')
 pp=ctl._json(ROOT/'artifacts/designer-bridge/designer-initializer-properties-vm-read-371d4328582047e79d58e548b47c5781.json','ff93f01160ce4e11c9c18c2e67cafcce1f3bc1d05354561a9ea495cb41c7da9c')
 def fresh():c._fresh(ctl.base._carrier_view(plan));ctl.base._lease(SimpleNamespace(plan=plan))
 fresh();reader=old.parent.vm.VmRead()
 try:
  reader.identity();module=plan['sdkIdentity']['moduleAddress'];core=plan['sdkIdentity']['coreBase']
  def snapshot():
   count=reader.word(module+0x110);need(count==815,'GLOBAL_COUNT');vector=reader.word(module+0x10c);frames={}
   for i in range(count):
    prop=reader.word(vector+4*i);length=reader.word(prop)
    if length not in (9,13):continue
    at=prop+4 if length<=11 else reader.word(prop+4)
    name=reader.chunked(at,length).decode('ascii',errors='replace')
    if name not in ('mainFrame','coreMainFrame'):continue
    need(name not in frames and reader.read(prop+0x18,1)[0]&4,'FRAME_METADATA')
    storage=reader.word(prop+0x2c);need(storage>=65536 and storage%4==0,'FRAME_STORAGE');frames[name]=storage
   values=project(reader.word,module=module,core=core,globals_proof=gp,properties_proof=pp,frames=frames,native=native)
   return dict(frames=frames,values=values)
  first=snapshot();need(snapshot()==first,'TWO_PASS');reader.identity();fresh()
  receipt=dict(kind='DESIGNER_FRAME_BINDING_VM_READ',operationId=uuid.uuid4().hex,parentOperationId=OP,
   readerSourceSha256=c.digest(Path(__file__).read_bytes()),processId=old.parent.vm.PID,birth=old.parent.vm.BIRTH,
   twoIdenticalPasses=True,readablePagesValidated=True,state=first,designerPrefixPreserved=True,
   nativeCallbacks=0,sdkCalls=0,referenceCalls=0,constructorRetry=False,configurationSaves=0,databaseUpdates=0,
   repositoryMutations=0,applicationTextOutputBytes=0,initializerClosureProved=False,databaseUpdateAuthorized=False)
  path=ROOT/'artifacts/designer-bridge'/('designer-frame-binding-vm-read-'+receipt['operationId']+'.json');c.write_new(path,receipt)
  return dict(path=str(path),sha256=c.digest(path.read_bytes()),result=receipt)
 finally:reader.close()


if __name__=='__main__':print(json.dumps(collect_root(),sort_keys=True))
