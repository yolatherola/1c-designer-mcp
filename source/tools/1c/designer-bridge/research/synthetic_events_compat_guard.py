"""Private seven-event admission after one exact failed but closed SDK case.

Preserves the historical UNKNOWN. This does not retire arbitrary failures or
grant a native dialog, command, save, metadata edit, or database permission.
"""
from pathlib import Path
from types import FunctionType, SimpleNamespace
import inspect
import synthetic_events_normal_guard as previous
import comparison_cpp_exception_type_epoch as epoch

c=previous.c; ROOT=previous.ROOT; reader=previous.reader
SOURCE_SHA=previous.SOURCE_SHA
FINISHED='cb92625a93e84140a9cbea5f8a67607e'
PREVIOUS_SHA='63da0c7e06e5784d0bd0d5382cafa1d02c4dd6a5541a9bed27a21cf8cb7b959d'
PINS={
 'sdk-receipt.json':'8ad858f160b99f867a0815f2e2eb77ec1da18192a19e2f252279b578dfe3fade',
 'synthetic-events-proof.json':'5156680b14470b748fe719b1584041e2e04d2bca97424e305c3eae9b26310797',
 'synthetic-event-bridge-proof.json':'c0dde6c6230bf79584ecdb2c93bf838ab3cfd75431b3fe0c7329a897c8624554',
 'cpp-exception-type-epoch.json':'e126080c0b13b7ade7cbe7d20574adc3e02deb7ea6cb5c6846c98c2ee4b1a77a',
 'unknown.json':'d8a8482b7362dd7840c2042d0bd0dfc9256c0e923102a895aa9465867a2b6077'}


def need(ok,code):
 if not ok:raise ValueError('SYNTHETIC_COMPAT_GUARD_'+code)


def validate_scope(row):
 need(row.get('kind')=='ROOT_SYNTHETIC_EVENTS_COMPAT_SCOPE','SCOPE_KIND')
 copy=dict(row);copy['kind']='ROOT_SYNTHETIC_EVENTS_NORMAL_SCOPE'
 previous.validate_scope(copy)


def validate_finished(rows,prior):
 """Classify only the pinned 6/7 failure whose subscriptions and refs closed."""
 need(prior.get('operationId')==FINISHED
  and prior.get('syntheticEventsControllerSha256')=='b371a8b41d5f6393fb47150df9be676704f876efbbe6203245112d9be4698c9e'
  and prior.get('actualSourceSha256')==SOURCE_SHA,'FINISHED_PLAN')
 for k in ('sourceWritesAuthorized','configurationSavesAuthorized','databaseUpdatesAuthorized',
           'repositoryMutationsAuthorized','commandDispatchAuthorized'):
  need(prior.get(k) is False,'FINISHED_AUTHORITY')
 sdk=rows['sdk-receipt.json'];native=rows['synthetic-events-proof.json']
 bridge=rows['synthetic-event-bridge-proof.json'];ep=rows['cpp-exception-type-epoch.json'];unknown=rows['unknown.json']
 for row in (sdk,native,bridge,ep,unknown):need(row.get('operationId')==FINISHED,'FINISHED_JOIN')
 need(sdk.get('sdkResult')==0 and type(sdk.get('sdkResult')) is int
  and sdk.get('knownTerminal') is True and sdk.get('hookWorkersReleased') is True
  and unknown.get('status')=='UNKNOWN_RETAIN' and unknown.get('knownTerminal') is False
  and unknown.get('retryAuthorized') is False,'FINISHED_TERMINAL')
 need(native.get('reason')=='CALLBACK_COUNTERS' and native.get('casesVerified') is False
  and native.get('unknownRetain') is False and native.get('fullPendingVerified') is False
  and native.get('databaseUpdateAuthorized') is False,'FINISHED_FAILURE')
 need(all(native.get(k) is True for k in ('typedHandlesCleared','nativeIntentWritten','beforeRootAndTargetsClean',
  'afterRootAndTargetsClean','designerPrefixPreserved','sinkCreated','subscribersDisconnected','sinkFinished')),'FINISHED_CLEANUP')
 zeros=('nativeDialogs','nativeCommands','sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')
 expected=dict(beforeTargetsClean=3,afterTargetsClean=3,syntheticEvents=7,bridgeCalls=14,answers=1,modalSeen=4,
  messagesSeen=2,rejected=1,mutations=1,finalRefs=0,finalPhase=3,createBridgeStatus=0,createVariantType=9,finishBridgeStatus=0,
  **{k:0 for k in zeros})
 need(all(type(native.get(k)) is int and native[k]==v for k,v in expected.items()),'FINISHED_AS_COUNTERS')
 expected=dict(phase=3,status=0,refs=0,busy=0,armed=0,nodesSet=0,payloadSet=0,finished=1,guardAccepts=8,guardRejects=0,
  admitted=6,modalSeen=4,lastStage=3,messagesSeen=2,answers=1,rejected=1,mutations=1,poisoned=0,lastError=6,
  reentrant=0,propertyCalls=28,pageRefusals=0,environmentRefusals=0,repeatedCalls=0,applicationTextOutputBytes=0,
  **{k:0 for k in zeros})
 need(all(type(bridge.get(k)) is int and bridge[k]==v for k,v in expected.items()),'FINISHED_C_COUNTERS')
 need(bridge.get('engineBindingSource')=='SNEGOPAT_GLOBAL_0x37674' and bridge.get('normalEngineObserved') is True
  and type(bridge.get('commandCalls')) is list and bridge['commandCalls']==[1,2,8,1,1,1]
  and all(type(x) is int for x in bridge['commandCalls']),'FINISHED_NORMAL_BINDING')
 for row in (native,bridge,ep):need(row.get('scopeSha256')==prior.get('syntheticEventsScopeSha256'),'FINISHED_SCOPE')
 epoch.classify_type_epoch(ep,operation_id=FINISHED,scope_sha256=prior['syntheticEventsScopeSha256'],
  process_id=48936,execute_thread_id=8292,callback_known=True,callback_sdk_rc=0,target_identity_verified=True)
 need(ep.get('cppThrows')==ep.get('otherExceptions')==0,'FINISHED_EXCEPTIONS')
 return 'EXACT_FAILED_SYNTHETIC_CASE_WITH_DISCONNECTED_SUBSCRIPTIONS_AND_ZERO_REFS'


def audit_finished(prior):
 folder=ROOT/'build'/('designer-hot-v233-'+FINISHED)
 need(not (folder/'result.json').exists(),'FINISHED_HISTORY')
 rows={name:reader._json(folder/name,pin) for name,pin in PINS.items()}
 result=validate_finished(rows,prior)
 c._fresh(previous.old.previous.repeatable.base._carrier_view(prior))
 previous.old.previous.repeatable.base._lease(SimpleNamespace(plan=prior))
 return result


def private_prepare():
 """Build a private guard; this function alone never inspects a process."""
 need(c.digest(c.read(Path(previous.__file__)))==PREVIOUS_SHA,'PREVIOUS_PIN')
 ns=dict(previous.__dict__)
 # Both functions get a private namespace; imported module globals stay intact.
 ns['validate_scope']=validate_scope
 ns['audit_partial']=FunctionType(previous.audit_partial.__code__,ns,previous.audit_partial.__name__,
  previous.audit_partial.__defaults__,previous.audit_partial.__closure__)
 source=inspect.getsource(previous.prepare_parent)
 anchor="   '        if operation==__synthetic_refusal_operation:\\n            __synthetic_refusal_audit(prior);continue\\n',1)"
 replacement="   '        if operation==__synthetic_refusal_operation:\\n            __synthetic_refusal_audit(prior);continue\\n'\n   '        if operation==__synthetic_finished_operation:\\n            __synthetic_finished_audit(prior);continue\\n',1)"
 need(source.count(anchor)==1,'AUDIT_ANCHOR');source=source.replace(anchor,replacement,1)
 anchor='__synthetic_refusal_operation=failed.OP,__synthetic_refusal_audit=audit_refusal)'
 need(source.count(anchor)==1,'BINDING_ANCHOR')
 source=source.replace(anchor,anchor[:-1]+',\n   __synthetic_finished_operation=FINISHED,__synthetic_finished_audit=audit_finished)',1)
 ns.update(FINISHED=FINISHED,audit_finished=audit_finished)
 exec(compile(source,'<exact-compat-synthetic-private-admission>','exec'),ns)
 return ns['prepare_parent']


def prepare_parent(scope_path,scope_sha):
 """Copy the exact prior private guard, adding only this closed failure audit."""
 return private_prepare()(scope_path,scope_sha)
