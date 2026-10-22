"""Private seven-event admission bound to the verified frame/hook recovery.

The failed full constructor stays UNKNOWN. This permit neither repeats it nor
admits a command, save, source edit, application read or database update.
"""
from pathlib import Path
from types import FunctionType,SimpleNamespace
import designer_partial_runtime_guard as old
import inspect
import synthetic_events_environment_vm_read as failed
import designer_frame_binding_vm_read as post

c=old.c;ROOT=old.ROOT;reader=old.reader
SOURCE_SHA='dacdf2c31a2419ff55dd548f6927b72702463a6ee55c912448cc3b1dcd27eebd'


def need(ok,code):
 if not ok:raise ValueError('SYNTHETIC_EVENTS_GUARD_'+code)


def validate_scope(row):
 need(row.get('kind')=='ROOT_SYNTHETIC_EVENTS_NORMAL_SCOPE' and row.get('passed') is True
  and row.get('actualSourceSha256')==SOURCE_SHA and row.get('runtimeSyntheticEventsAuthorized') is True
  and row.get('configurationReadOnly') is True and type(row.get('maximumSyntheticEvents')) is int
  and row['maximumSyntheticEvents']==7 and type(row.get('maximumEventSubscribers')) is int
  and row['maximumEventSubscribers']==2,'SCOPE')
 for key in ('sourceWritesAuthorized','configurationSavesAuthorized','databaseUpdatesAuthorized','repositoryMutationsAuthorized',
  'configurationExportsAuthorized','configurationImportsAuthorized','runtimeSupportInitializationAuthorized','commandDispatchAuthorized',
  'historicalReferencesReleaseAuthorized','manualAddRefReleaseAuthorized','externalAddinLoadingAuthorized','runtimeFrameBindingAuthorized','runtimeDialogHooksAuthorized'):
  need(row.get(key) is False,'ESCALATED_SCOPE')


def audit_partial(prior,*,scope_path,scope_sha):
 scope=reader._json(scope_path,scope_sha);validate_scope(scope)
 need(c.digest(c.read(c.HERE/'NativeSyntheticEventsRoundtripNormal.as'))==SOURCE_SHA,'SOURCE')
 folder=ROOT/'build'/('designer-hot-v233-'+old.FAILED)
 need(prior.get('operationId')==old.FAILED and prior.get('actualSourceSha256')=='b23ec2c524c0cea38f90eeaae3ed6fa19e297199ef8250f7f005fb0369ab2cce'
  and prior.get('designerEventsInitControllerSha256')=='1fcf9ddba9419539ed7b5150c87a81af0756cb858292d7269056314471350518'
  and prior.get('databaseUpdatesAuthorized') is False and prior.get('configurationSavesAuthorized') is False,'FAILED_PLAN')
 rows={name:reader._json(folder/name,pin) for name,pin in old.PINS.items()}
 sdk=rows['sdk-receipt.json'];ep=rows['cpp-exception-type-epoch.json'];unknown=rows['unknown.json']
 need(sdk.get('sdkResult')==3 and sdk.get('knownTerminal') is True and sdk.get('hookWorkersReleased') is True
  and unknown.get('status')=='UNKNOWN_RETAIN' and unknown.get('knownTerminal') is False
  and not (folder/'designer-events-initialize-proof.json').exists(),'OLD_RESULT')
 need(ep.get('phase')=='EXECUTE_RETURNED' and ep.get('sdkExecuteRc')==3
  and all(ep.get(k) is True for k in ('executeEntered','executeReturned','handlerRemoved')),'OLD_EPOCH')
 hooks=ROOT/'build/designer-hot-v233-95f52aa67ce14fdbbfe5a4eedb8d8b73'
 installed=reader._json(hooks/'result.json','434b064923bd3cb3535fb939d63b22ea3bf6c78c7d1a757045b0923097d3fe03')
 hook_native=reader._json(hooks/'designer-dialog-hooks-proof.json','ac45172387132d03a469510988fd527fd6e5e70f753fa97835bf9e5cfbafbee3')
 need(installed.get('sdkResult')==0 and installed.get('knownTerminal') is True and installed.get('status')=='DIALOG_HOOKS_INSTALLED_PREFIX_PRESERVED'
  and hook_native.get('statesBefore')==[0,0,0] and hook_native.get('statesAfter')==[2,2,2]
  and hook_native.get('designerPrefixPreserved') is True,'HOOKS_INSTALLED')
 repaired=ROOT/'build'/('designer-hot-v233-'+post.OP)
 result=reader._json(repaired/'result.json','c68e03939cd632a939e47e2a0aca32bba498fedb8b5dbe3fd1686838a1846a93')
 native=reader._json(repaired/'designer-frame-binding-repair-proof.json','3a1d8a8d37973146cd6ca30511786a8ec1cad52eb2ec324f21898004ba8e31de')
 need(result.get('knownTerminal') is True and result.get('sdkResult')==0 and result.get('status')=='FRAME_CONTEXT_REPAIRED_PREFIX_PRESERVED','REPAIR')
 observed=reader._json(ROOT/'artifacts/designer-bridge/designer-frame-binding-vm-read-689c97ad14c341a8a2b68fcacbac0069.json',
  '4e1e7815c170069aecf61ace49cb4cc571d6a6635baef21e27b23fd3ac122c2e')
 need(c.digest(c.read(Path(post.__file__)))==observed['readerSourceSha256']=='d1186d91c446b7347a3b4c7923c42b81a63a2221b4b6294f6af0ac886963d853','READBACK_SOURCE')
 gp=reader._json(ROOT/'artifacts/designer-bridge/designer-initializer-three-globals-vm-read-cdf10c4784fb4c01b63d342953bcef21.json','86af3360f08b9e0968c19ad15cf61cc9d6ed781822de2e12e474ec004f141a96')
 pp=reader._json(ROOT/'artifacts/designer-bridge/designer-initializer-properties-vm-read-371d4328582047e79d58e548b47c5781.json','ff93f01160ce4e11c9c18c2e67cafcce1f3bc1d05354561a9ea495cb41c7da9c')
 c._fresh(old.previous.repeatable.base._carrier_view(prior));old.previous.repeatable.base._lease(SimpleNamespace(plan=prior))
 v=old.vm.VmRead()
 try:
  v.identity();args=dict(module=prior['sdkIdentity']['moduleAddress'],core=prior['sdkIdentity']['coreBase'],
   globals_proof=gp,properties_proof=pp,frames=observed['state']['frames'],native=native)
  first=post.project(v.word,**args);need(post.project(v.word,**args)==first==observed['state']['values'],'FRESH_READBACK');v.identity()
 finally:v.close()
 return 'EXACT_PARTIAL_RUNTIME_SYNTHETIC_EVENTS_NORMAL_ONLY'


def audit_refusal(prior):
 need(prior.get('operationId')==failed.OP and prior.get('syntheticEventsControllerSha256')=='18f5b03ceba04720049320e2f0fdbc67753f0db64a1cd5cf80e0a7e7c0e932a9'
  and prior.get('actualSourceSha256')=='99b78191012c42b5e5fdcf5164c01b072e6187b2b382e5483edca1ccd3f85cd5'
  and prior.get('databaseUpdatesAuthorized') is False and prior.get('sourceWritesAuthorized') is False,'REFUSAL_PLAN')
 folder=ROOT/'build'/('designer-hot-v233-'+failed.OP)
 rows={name:reader._json(folder/name,pin) for name,pin in {
  'sdk-receipt.json':'4a76bf46f33fd26f21d414abdb0975c181aa31c893d86c30eaf298e47dc7f16a',
  'synthetic-events-proof.json':'b9a8cd649723e0e482b9b9cf2c131c213ea6eb5b460d5ed10b0ce618315eae81',
  'cpp-exception-type-epoch.json':'b7e12ff0777d08b5009e0efdc687969bbad3ac3fe2efee72cf1325daba996842',
  'unknown.json':'cd4608876f33b026c20d21ac80d37596b81847cc1c83152e5ecf6f4aa9dae3e3'}.items()}
 sdk=rows['sdk-receipt.json'];native=rows['synthetic-events-proof.json'];ep=rows['cpp-exception-type-epoch.json']
 need(sdk.get('sdkResult')==0 and sdk.get('knownTerminal') is True and sdk.get('hookWorkersReleased') is True
  and native.get('reason')=='CREATE_SINK' and native.get('bridgeCalls')==1 and native.get('sinkCreated') is False
  and native.get('syntheticEvents')==0 and native.get('afterRootAndTargetsClean') is True
  and rows['unknown.json'].get('status')=='UNKNOWN_RETAIN' and not (folder/'synthetic-event-bridge-proof.json').exists(),'REFUSAL_RECEIPTS')
 need(ep.get('executeReturned') is True and ep.get('sdkExecuteRc')==0 and ep.get('handlerRemoved') is True
  and ep.get('cppThrows')==ep.get('otherExceptions')==0,'REFUSAL_QUIESCENCE')
 proof=reader._json(ROOT/'artifacts/designer-bridge/synthetic-environment-refusal-vm-read-1561efe2acb04078b8a2235cb30e3722.json',
  '208548ac4d8b836afc72031c7eec83c5d84be17698bebb8d964cf3218a87994f')
 need(c.digest(c.read(Path(failed.__file__)))=='f35411be8e61ec6be5a70bd9612b5d0478edc349c4133d9cf73038acf4fc0a19'
  and proof.get('classification')=='INITIAL_ENVIRONMENT_REFUSAL_NO_SINK' and proof.get('twoIdenticalPasses') is True,'REFUSAL_VM_PIN')
 c._fresh(old.previous.repeatable.base._carrier_view(prior));old.previous.repeatable.base._lease(SimpleNamespace(plan=prior))
 base=proof['loadedOwnDllBase'];mapped,count=failed.image_bytes(c.read(folder/'Continuation.dll'),base)
 need(base==158990336 and count==279,'REFUSAL_IMAGE')
 v=old.vm.VmRead()
 try:
  v.identity()
  def readback():
   for rva,length in failed.SPANS:need(v.chunked(base+rva,length)==mapped[rva:rva+length],'REFUSAL_RUNTIME_CODE')
   return failed.state_words(v.word,base)
  first=readback();need(readback()==first==proof['state'],'REFUSAL_STATE_CHANGED');v.identity()
 finally:v.close()
 return 'EXACT_CREATE_ENVIRONMENT_REFUSAL_NO_SINK'


def prepare_parent(scope_path,scope_sha):
 """Admit only this new source after both old partial states are rechecked."""
 path=c._plain(scope_path,ROOT/'artifacts/designer-bridge');scope=reader._json(path,scope_sha);validate_scope(scope)
 need(c.digest(c.read(Path(old.__file__)))=='12a06401650fb9d76c5cd4e3db28ce68ac78513b80803842669f5613008de649','BUILDER_PIN')
 previous=old.previous
 def namespace(parent):
  ns=reader._namespace(parent);text=inspect.getsource(c._no_pending)
  skip='or operation==allow_operation:';anchor='        if prior_identity!=identity: continue\n'
  need(text.count(skip)==1 and text.count(anchor)==1,'AUDIT_ANCHORS')
  text=text.replace(skip,'or operation==allow_operation or operation==__pending_read_operation:',1)
  text=text.replace(anchor,anchor+
   '        if operation==__retained_reference_operation:\n            __retained_reference_audit(prior);continue\n'
   '        if operation==__retired_observation_operation:\n            __retired_observation_audit(prior);continue\n'
   '        if operation==__retired_trace_predecessor:\n            __retired_trace_predecessor_audit(prior);continue\n'
   '        if operation==__partial_runtime_operation:\n            __partial_runtime_audit(prior);continue\n'
   '        if operation==__synthetic_refusal_operation:\n            __synthetic_refusal_audit(prior);continue\n',1)
  ns.update(__retained_reference_operation=previous.repeatable.base.RETIRED_OPERATION,
   __retained_reference_audit=previous.repeatable.base._retained_reference_audit,
   __retired_observation_operation=previous.repeatable.RETIRED_OBSERVATION,__retired_observation_audit=previous.repeatable._retired_observation_audit,
   __retired_trace_predecessor=previous.RETIRED,__retired_trace_predecessor_audit=previous._retired_trace_predecessor_audit,
   __partial_runtime_operation=old.FAILED,__partial_runtime_audit=lambda prior:audit_partial(prior,scope_path=path,scope_sha=scope_sha),
   __synthetic_refusal_operation=failed.OP,__synthetic_refusal_audit=audit_refusal)
  exec(compile(text,'<exact-normal-synthetic-event-private-audit>','exec'),ns);audit=ns['_no_pending']
  def no_pending(allow_operation=None,context=None):
   need(context==parent.plan['context'] and allow_operation in (None,parent.plan['operationId'],ns['__pending_read_operation']),'NAMESPACE_SCOPE')
   reader._check_owner(parent);return audit(allow_operation=parent.scope['writerOperationId'],context=context)
  ns['_no_pending']=no_pending;return ns
 ns=dict(reader.__dict__);ns['_namespace']=namespace
 prepare=FunctionType(reader.prepare_root.__code__,ns,reader.prepare_root.__name__,reader.prepare_root.__defaults__,reader.prepare_root.__closure__)
 prepare.__kwdefaults__=reader.prepare_root.__kwdefaults__;return prepare(scope['readScopePath'],scope['readScopeSha256'])
