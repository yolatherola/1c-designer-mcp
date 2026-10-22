"""Private seven-event admission bound to the verified frame/hook recovery.

The failed full constructor stays UNKNOWN. This permit neither repeats it nor
admits a command, save, source edit, application read or database update.
"""
from pathlib import Path
from types import FunctionType,SimpleNamespace
import designer_partial_runtime_guard as old
import designer_frame_binding_vm_read as post

c=old.c;ROOT=old.ROOT;reader=old.reader
SOURCE_SHA='99b78191012c42b5e5fdcf5164c01b072e6187b2b382e5483edca1ccd3f85cd5'


def need(ok,code):
 if not ok:raise ValueError('SYNTHETIC_EVENTS_GUARD_'+code)


def validate_scope(row):
 need(row.get('kind')=='ROOT_SYNTHETIC_EVENTS_SCOPE' and row.get('passed') is True
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
 need(c.digest(c.read(c.HERE/'NativeSyntheticEventsRoundtrip.as'))==SOURCE_SHA,'SOURCE')
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
 return 'EXACT_PARTIAL_RUNTIME_SYNTHETIC_EVENTS_ONLY'


def prepare_parent(scope_path,scope_sha):
 """Reuse only the frozen private namespace builder with narrower callbacks."""
 need(c.digest(c.read(Path(old.__file__)))=='12a06401650fb9d76c5cd4e3db28ce68ac78513b80803842669f5613008de649','BUILDER_PIN')
 ns=dict(old.__dict__);ns.update(validate_scope=validate_scope,audit_partial=audit_partial)
 prepare=FunctionType(old.prepare_parent.__code__,ns,old.prepare_parent.__name__,old.prepare_parent.__defaults__,old.prepare_parent.__closure__)
 return prepare(scope_path,scope_sha)
