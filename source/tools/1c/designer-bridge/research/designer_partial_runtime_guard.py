"""Exact private admission for a two-binding repair after one partial initializer.

The original initializer stays UNKNOWN. No imported router is changed, no
reference is released, and this permit cannot authorize a constructor or DB
operation. VM reads inspect only the fixed tool-runtime handle prefix.
"""
from pathlib import Path
from types import FunctionType,SimpleNamespace
import inspect
import comparison_cpp_exception_stack_trace as previous
import update_owner_runtime_read as vm

c=previous.c;reader=previous.reader;ROOT=c.ROOT
FAILED='5f85728757774731b330a608f19f26b7'
FRAME_SOURCE_SHA='8739d48fd30b7e40d7a0a893119d548669bdf336220550d0191e3c8274380f77'
PINS={
 'sdk-receipt.json':'aa6d33f6fe1f3b15752b4ab585aba8e53991f3508bc2e4dc000f8bd59e5629d9',
 'cpp-exception-type-epoch.json':'d23b07ea3e8cab0524a0e2412c8504a4a7f7a6e3d1eb220810753e0b76d99615',
 'unknown.json':'d485ae00612d309ee2f9e77871abca0cd184a2dcdd5f3f7f87d681c361dc7146'}


def need(ok,code):
 if not ok:raise ValueError('PARTIAL_RUNTIME_REPAIR_'+code)


def validate_scope(row):
 need(row.get('kind')=='ROOT_DESIGNER_FRAME_BINDING_REPAIR_SCOPE' and row.get('passed') is True
  and row.get('actualSourceSha256')==FRAME_SOURCE_SHA and row.get('runtimeFrameBindingAuthorized') is True
  and row.get('configurationReadOnly') is True and type(row.get('maximumFrameBindings')) is int and row['maximumFrameBindings']==2,'SCOPE')
 for key in ('sourceWritesAuthorized','configurationSavesAuthorized','databaseUpdatesAuthorized','repositoryMutationsAuthorized',
  'configurationExportsAuthorized','configurationImportsAuthorized','runtimeSupportInitializationAuthorized','commandDispatchAuthorized',
  'historicalReferencesReleaseAuthorized','manualAddRefReleaseAuthorized','externalAddinLoadingAuthorized'):
  need(row.get(key) is False,'ESCALATED_SCOPE')


def partial_words(read_word,*,module,core,globals_proof,properties_proof):
 """Pure bounded projection, usable with a synthetic reader in tests."""
 saved=properties_proof['state'];globals_saved=globals_proof['globalState']['globals'];obj=saved['designerObject']
 need(read_word(module)==core+0x28e454 and read_word(module+0x110)==815,'MODULE')
 need(read_word(obj)==core+globals_saved['oneDesigner']['tableRva'] and read_word(obj+4)==saved['designerType'],'DESIGNER')
 need(read_word(saved['designerType']+0x58)==saved['designerPropertyCount']==16,'DESIGNER_METADATA')
 observed={}
 for name,row in globals_saved.items():
  value=read_word(row['storagePointer']);need(value==row['valuePointer'],'GLOBAL_CHANGED');observed[name]=value
 for name,row in saved['fields'].items():
  need(type(row['offset']) is int and row['offset']%4==0 and 8<=row['offset']<=4096,'FIELD_OFFSET')
  value=read_word(obj+row['offset']);need(value==row['valuePointer'],'PARTIAL_PREFIX_CHANGED');observed[name]=value
 frame=saved['bootstrapGlobals']['coreMainFrame'];need(frame['valuePointer']==0 and read_word(frame['storagePointer'])==0,'FRAME_ALREADY_BOUND')
 observed['coreMainFrame']=0
 return observed


def audit_partial(prior,*,scope_path,scope_sha):
 scope=reader._json(scope_path,scope_sha);validate_scope(scope)
 need(c.digest(c.read(c.HERE/'NativeDesignerFrameBindingRepair.as'))==FRAME_SOURCE_SHA,'FRAME_SOURCE')
 folder=ROOT/'build'/('designer-hot-v233-'+FAILED)
 need(prior.get('operationId')==FAILED and prior.get('actualSourceSha256')=='b23ec2c524c0cea38f90eeaae3ed6fa19e297199ef8250f7f005fb0369ab2cce'
  and prior.get('designerEventsInitControllerSha256')=='1fcf9ddba9419539ed7b5150c87a81af0756cb858292d7269056314471350518'
  and prior.get('configurationSavesAuthorized') is False and prior.get('databaseUpdatesAuthorized') is False,'FAILED_PLAN')
 rows={name:reader._json(folder/name,pin) for name,pin in PINS.items()}
 sdk=rows['sdk-receipt.json'];ep=rows['cpp-exception-type-epoch.json'];unknown=rows['unknown.json']
 need(sdk.get('operationId')==FAILED and sdk.get('sdkResult')==3 and sdk.get('knownTerminal') is True
  and sdk.get('hookWorkersReleased') is True and unknown.get('status')=='UNKNOWN_RETAIN'
  and unknown.get('knownTerminal') is False and not (folder/'designer-events-initialize-proof.json').exists(),'FAILED_TERMINAL')
 need(ep.get('operationId')==FAILED and ep.get('phase')=='EXECUTE_RETURNED' and ep.get('sdkExecuteRc')==3
  and all(ep.get(k) is True for k in ('executeEntered','executeReturned','handlerRemoved')),'QUIESCENT_EPOCH')
 gp=reader._json(ROOT/'artifacts/designer-bridge/designer-initializer-three-globals-vm-read-cdf10c4784fb4c01b63d342953bcef21.json',
  '86af3360f08b9e0968c19ad15cf61cc9d6ed781822de2e12e474ec004f141a96')
 pp=reader._json(ROOT/'artifacts/designer-bridge/designer-initializer-properties-vm-read-371d4328582047e79d58e548b47c5781.json',
  'ff93f01160ce4e11c9c18c2e67cafcce1f3bc1d05354561a9ea495cb41c7da9c')
 c._fresh(previous.repeatable.base._carrier_view(prior));previous.repeatable.base._lease(SimpleNamespace(plan=prior))
 ctx=prior['context'];need((ctx['processId'],ctx['birth'],ctx['guiThreadId'])==(48936,'01dd5d0180299126',8292),'TARGET')
 v=vm.VmRead()
 try:
  v.identity();args=dict(module=prior['sdkIdentity']['moduleAddress'],core=prior['sdkIdentity']['coreBase'],globals_proof=gp,properties_proof=pp)
  first=partial_words(v.word,**args);need(partial_words(v.word,**args)==first,'TWO_PASS_CHANGED');v.identity()
 finally:v.close()
 return 'EXACT_PARTIAL_RUNTIME_RETAINED_FRAME_BINDING_ONLY'


def prepare_parent(scope_path,scope_sha):
 """Create one private router namespace; keep all original global gates intact."""
 path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=reader._json(path,scope_sha);validate_scope(scope)
 need(c.digest(c.read(Path(previous.__file__)))=='c4e792ca4ae464c4a4b12f72cba8ba98522febb66bd6101732322f836aa913be','PARENT_PIN')
 def namespace(parent):
  ns=reader._namespace(parent);source=inspect.getsource(c._no_pending)
  skip='or operation==allow_operation:';anchor='        if prior_identity!=identity: continue\n'
  need(source.count(skip)==1 and source.count(anchor)==1,'AUDIT_ANCHORS')
  source=source.replace(skip,'or operation==allow_operation or operation==__pending_read_operation:',1)
  source=source.replace(anchor,anchor+
   '        if operation==__retained_reference_operation:\n            __retained_reference_audit(prior);continue\n'
   '        if operation==__retired_observation_operation:\n            __retired_observation_audit(prior);continue\n'
   '        if operation==__retired_trace_predecessor:\n            __retired_trace_predecessor_audit(prior);continue\n'
   '        if operation==__partial_runtime_operation:\n            __partial_runtime_audit(prior);continue\n',1)
  ns.update(__retained_reference_operation=previous.repeatable.base.RETIRED_OPERATION,
   __retained_reference_audit=previous.repeatable.base._retained_reference_audit,
   __retired_observation_operation=previous.repeatable.RETIRED_OBSERVATION,
   __retired_observation_audit=previous.repeatable._retired_observation_audit,
   __retired_trace_predecessor=previous.RETIRED,__retired_trace_predecessor_audit=previous._retired_trace_predecessor_audit,
   __partial_runtime_operation=FAILED,__partial_runtime_audit=lambda prior:audit_partial(prior,scope_path=path,scope_sha=scope_sha))
  exec(compile(source,'<exact-frame-binding-repair-private-audit>','exec'),ns);audit=ns['_no_pending']
  def no_pending(allow_operation=None,context=None):
   need(context==parent.plan['context'] and allow_operation in (None,parent.plan['operationId'],ns['__pending_read_operation']),'NAMESPACE_SCOPE')
   reader._check_owner(parent);return audit(allow_operation=parent.scope['writerOperationId'],context=context)
  ns['_no_pending']=no_pending;return ns
 ns=dict(reader.__dict__);ns['_namespace']=namespace
 prepare=FunctionType(reader.prepare_root.__code__,ns,reader.prepare_root.__name__,reader.prepare_root.__defaults__,reader.prepare_root.__closure__)
 prepare.__kwdefaults__=reader.prepare_root.__kwdefaults__;return prepare(scope['readScopePath'],scope['readScopeSha256'])
