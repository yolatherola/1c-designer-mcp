"""One historical FAILED_CLOSED case, never success or a retry permission.

Only exact pinned technical files are read. No controller import, SDK, process
query, lease mutation, pending bypass, historical rewrite or exception-success
classifier is performed. The caller owns any future private admission policy.
"""
from pathlib import Path
import hashlib
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
OP='c22e6a82dbf8461583a94de91801a404'
SCOPE_SHA='6681a1b67883e144e589cae582fcc18c34ec7a12353016053f7ae0e4498d3ac7'
PLAN_SHA='8b0223be9c8169954657504bd4c801c9663195afae1143efa14d37ceb0873390'
CONTROLLER_SHA='9684ce8471886312899e54e8e971d8415ad6f16a5605b32c3853e815421aab62'
PARENT_SHA='d7e49b5edaf5800c313303cea04a4900a167d406cd3eed765f5777a80e7f2d08'
CHILD_SHA='7c4db9c862b35b9058e9be38a75b580f478f666a511717b3d44e137b3f02f708'
CLASSIFICATION='EXACT_MODAL_READ_CHILD_FAILED_CLOSED_WITH_GUARD_REFUSAL_AND_OUTER_LISTSTREAM_FAILURE'
PINS={
 'build-proof.json':'adf940fb51b70a93fb277fee34fa512f61a4607f6eaf162a7614b90565101f7b',
 'cpp-exception-type-epoch.json':'c8b64e02fc4fcd570ea91f94a6d8d2202284179a46ecd057f6d3f6c0c28b0799',
 'host-identity.json':'724a86fdf674f8d2eb1404c0c811cf8471d2394db2bc83bad46ee52227f7a33d',
 'host-result.json':'d4fa99e2bb52e89e6fc3b4836c7e3a05965aec02044f6921784e67bd0d31aa0a',
 'intent.json':'b8178a053c1c5811275f8f026b4884ac1dbcacf443aab4aedc6fe0569ecfa585',
 'modal-read-child-c-proof.json':'7a5fa31fbc6461c01a88c56c650fa5ec986627c870828b3525d6a7605f1bfbcd',
 'modal-read-child-proof.json':'86a9c1009a03f01b9407cb5e03a8157703dfdabdfb443ef3e4ff25c0efea0b71',
 'modal-read-parent-proof.json':'e4490ed22cfb156ccf3871230b3dfd2f3e9d92ad33fa6deed9a39b1cbb1a3c70',
 'native-modal-read-parent-intent.json':'b4cfa13f9a1d03ebef536af144e31e8c87d9b4e69b8e15c9a93e9571d0dee4e8',
 'plan.json':'d595411dff0262926b387764a1fdb8e8e498b8cb0f6a72afcb803de9ca68cccf',
 'sdk-receipt.json':'477aceb260e3fe9bb46e0961eeda62af3ff654bd6a7a7ca496fe250d1f5332f1',
 'unknown.json':'5fadc004e5373191d575f49163cc7af1693b7800d947ad1cafdc8e2f3fa2e3ee',
}
SOURCE_PINS={
 'tools/1c/designer-bridge/research/modal_read_child_operation.py':CONTROLLER_SHA,
 'tools/1c/designer-bridge/research/NativeModalReadParent.as':PARENT_SHA,
 'tools/1c/designer-bridge/research/NativeModalReadChild.as':CHILD_SHA,
 'tools/1c/designer-bridge/research/NativeModalReadChild.c.inc':'f856cfb12cb6d341ede9ea82437a8aecf810ad521da215a0fd03590ff97b2522',
 'tools/1c/designer-bridge/research/modal_read_child_carrier.py':'1e01e2c057af80c94addd68e96bf23dba62b65056dedb80c988010abf6b8fdf0',
 'tools/1c/designer-bridge/research/comparison_cpp_exception_type_epoch.py':'e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4',
 'build/designer-v43-013dc010bd784e859b1e3ba4def25f3c/runtime/modules/snegopat/engine/main.as':'d06c152775ede6d0ae91d10d5736ec09a3f63e2f6b2637689ff8329e18db50b2',
 'build/designer-v43-013dc010bd784e859b1e3ba4def25f3c/runtime/modules/snegopat/engine/com_windows.as':'49e4836e29499f8f13140f6dfa2b9477065ea5cb9d47f4de4aef490a51c683c8',
 'artifacts/designer-bridge/modal-read-child-scope-977c486a3f2f42e0a896481c4425c8ce.json':SCOPE_SHA,
}
ZERO_WRITES=('nativeCommands','sourceWrites','configurationSaves','databaseUpdates','repositoryMutations')


def need(ok,code):
 if not ok:raise ValueError('MODAL_READ_CHILD_FAILED_AUDIT_'+code)


def counts(row,expected,code):
 need(all(type(row.get(k)) is int and row[k]==v for k,v in expected.items()),code)


def flags(row,yes=(),no=(),code='FLAGS'):
 need(all(row.get(k) is True for k in yes) and all(row.get(k) is False for k in no),code)


def canonical(row):return json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def validate_closed(rows,prior):
 """Pure strict semantics for this known failure; no success classification."""
 need(type(rows) is dict and set(rows)==set(PINS) and all(type(x) is dict for x in rows.values()),'ROWS')
 need(type(prior) is dict and prior==rows['plan.json'] and hashlib.sha256(canonical(prior)).hexdigest()==PLAN_SHA,'EXACT_PLAN')
 need(prior.get('operationId')==OP and prior.get('modalReadChildScopeSha256')==SCOPE_SHA
  and prior.get('modalReadChildControllerSha256')==CONTROLLER_SHA
  and prior.get('actualSourceSha256')==PARENT_SHA and prior.get('childSourceSha256')==CHILD_SHA,'SOURCE_BINDING')
 flags(prior,no=('writerAuthorized','sourceWritesAuthorized','configurationSavesAuthorized','databaseUpdatesAuthorized',
  'repositoryMutationsAuthorized','commandDispatchAuthorized','configurationExportsAuthorized','configurationImportsAuthorized'),code='AUTHORITY')
 counts(prior,dict(applicationWrites=0,configurationExports=0,configurationImports=0),'PLAN_WRITES')
 ctx=prior.get('context',{});need((ctx.get('processId'),ctx.get('guiThreadId'),ctx.get('birth'))==(48936,8292,'01dd5d0180299126'),'TARGET')
 parent=rows['modal-read-parent-proof.json'];child=rows['modal-read-child-proof.json'];bridge=rows['modal-read-child-c-proof.json']
 ep=rows['cpp-exception-type-epoch.json'];sdk=rows['sdk-receipt.json'];host=rows['host-result.json'];unknown=rows['unknown.json']
 intent=rows['intent.json'];native_intent=rows['native-modal-read-parent-intent.json'];build=rows['build-proof.json']
 for row in (parent,child,bridge,ep,sdk,unknown,intent,native_intent):
  need(row.get('operationId')==OP and row.get('scopeSha256')==SCOPE_SHA,'JOIN')
 for row in (sdk,host):
  flags(row,yes=('knownTerminal','hookWorkersReleased'),no=('writerAuthorized','sourceWritesAuthorized','configurationSavesAuthorized','databaseUpdatesAuthorized','repositoryMutationsAuthorized'),code='HOST_TERMINAL')
  counts(row,dict(sdkResult=0,threadId=8292),'HOST_COUNTS')
  need(row.get('actualSourceSha256')==PARENT_SHA,'HOST_SOURCE')
 need(sdk.get('planSha256')==intent.get('planSha256')==build.get('planSha256')==PLAN_SHA,'PLAN_JOIN')
 flags(build,yes=('passed',),no=('nativeInjectionPerformed','goldStarted','carrierAssemblyExecuted'),code='BUILD')
 counts(build,dict(compileExitCode=0,carrierCompileExitCode=0),'BUILD_COUNTS')
 flags(unknown,no=('knownTerminal','retryAuthorized','actualUpdate29OwnerVerified','updateAdmissionGranted','databaseApplyAuthorized','globalPendingClean'),code='HISTORY')
 need(unknown.get('status')=='UNKNOWN_RETAIN' and unknown.get('reason')=='NATIVE_OR_FRESH_CLOSURE_UNPROVEN','UNKNOWN_UNCHANGED')
 flags(parent,yes=('nativeIntentWritten','beforeRootAndTargetsClean','afterRootAndTargetsClean','designerPrefixPreserved','typedHandlesCleared','hooksPreserved','entered'),no=('verified','exceptionObserved','left'),code='PARENT_CLOSURE')
 need(parent.get('reason')=='LEAVE' and parent.get('kind')=='MODAL_READ_PARENT_NATIVE','PARENT_FAILURE')
 counts(parent,dict(beforeTargetsClean=3,afterTargetsClean=3,nativeMessageAttempts=1,nativeMessageReturned=1,nativeMessageResult=-1,bridgeCalls=2,bridgeStatus=0,bridgePhase=3,childExecutions=1,childSdkRc=0,childSdkValue=1,childContextRestored=1,persistentBefore=0,persistentAfter=0,singleBefore=0,singleAfter=0,queueInvocations=0,**{k:0 for k in ZERO_WRITES}),'PARENT_COUNTS')
 need(child.get('kind')=='MODAL_READ_CHILD_NATIVE' and child.get('reason')=='QUEUES_OR_SUBSCRIBERS','CHILD_FAILURE')
 flags(child,yes=('typedHandlesCleared',),no=('verified','beforeRootAndTargetsClean','afterRootAndTargetsClean','exceptionObserved'),code='CHILD_REFUSAL')
 counts(child,dict(beforeTargetsClean=0,afterTargetsClean=0,modalState=0,queueInvocations=0,**{k:0 for k in ZERO_WRITES}),'CHILD_COUNTS')
 need(bridge.get('kind')=='MODAL_READ_CHILD_C','BRIDGE_KIND')
 ones=('prepareCalls','prepareReturns','parentEntered','parentReturned','parentContextRestored','hookAttempts','hookReturns','unhookAttempts','unhookReturns','postAttempts','postReturns','enterCalls','leaveCalls','childExecutions','childReturned','contextPrepared','contextReleased','contextRestored','handlerRegistered','handlerRemoved','executeEntered','executeReturned')
 zeros=('status','hookOwn','functionOwn','contextOwn','sdkRc','abiFault','handlerRetained','cppThrows','otherExceptions','exceptionOverflow','exceptionReentry','wrongMessages','duplicateMessages','environmentRefusals','outputRefusals','commandRefusals')
 counts(bridge,dict(phase=4,sdkValue=1,**{k:1 for k in ones},**{k:0 for k in zeros},**{k:0 for k in ZERO_WRITES}),'BRIDGE_CLOSURE')
 # Current proof does not export busy. A newly added positive/bool busy claim
 # must never override phase4/context0/nohandler/unhook/function0 closure.
 for k in ('busy','childBusy','parentExecuting'):
  if k in bridge:counts(bridge,{k:0},'RETAINED_BUSY')
 need(ep.get('kind')=='COMPARISON_CPP_EXCEPTION_TYPE_EPOCH' and ep.get('phase')=='EXECUTE_RETURNED'
  and ep.get('typeDecoderProfile')=='X86_MSVC_IMAGE_TYPES_LISTSTREAM_CATCHABLE_BASES','OUTER_EPOCH')
 flags(ep,yes=('handlerRegistered','handlerRemoved','executeEntered','executeReturned','selfReferenceRetained','dllMustRemainLoadedUntilProcessExit','typeMetadataOnly'),no=('counterOverflow','typeEventOverflow','typeDecoderReentry','exceptionObjectRead','fullPendingVerified','databaseUpdateAuthorized','allCppExceptionFree','listStreamPathExceptionFreeVerified'),code='OUTER_FAILURE_FLAGS')
 counts(ep,dict(processId=48936,executeThreadId=8292,sdkExecuteRc=0,cppThrows=2,cppThrowsExecuteThread=2,cppThrowsOtherThreads=0,otherExceptions=0,otherExceptionsExecuteThread=0,otherExceptionsOtherThreads=0,typeEventCount=2,decodedCppThrows=2,unknownCppThrows=0,listStreamCompatibleThrows=2,maximumTypeEvents=32,maximumCatchableTypes=16,maximumNameBytes=96),'EXACT_LISTSTREAM_FAILURE')
 events=ep.get('typeEvents');need(type(events) is list and len(events)==2,'EVENTS')
 for event in events:
  need(type(event) is dict,'EVENT_OBJECT')
  flags(event,yes=('decoded','allCatchableTypesExamined','listStreamCompatible'),code='LISTSTREAM_EVENT')
  counts(event,dict(catchableTypeCount=2),'EVENT_COUNT')
  need(event.get('primaryTypeNameHash')=='6771ce59' and event.get('typeNameHashes')==['6771ce59','243edd7d'],'EVENT_HASHES')
 counts(native_intent,dict(maximumNativeMessageCalls=1,maximumChildExecutions=1,maximumOwnedHooks=1,timeoutArgument=1,nativeCommands=0,sourceWrites=0,databaseUpdates=0,repositoryMutations=0),'NATIVE_INTENT')
 return CLASSIFICATION


def audit_closed(prior):
 """Read exact immutable history and report FAILED_CLOSED, with no live calls.

 This deliberately does not call _fresh/_lease or exempt a pending operation.
 A future private guard must decide its new scope and fresh checks separately.
 """
 folder=ROOT/'build'/('designer-hot-v233-'+OP)
 need(not (folder/'result.json').exists(),'NO_SUCCESS_RESULT')
 for name,pin in SOURCE_PINS.items():
  need(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==pin,'SOURCE_PIN')
 rows={}
 for name,pin in PINS.items():
  raw=(folder/name).read_bytes();need(len(raw)<=32768 and hashlib.sha256(raw).hexdigest()==pin,'RECEIPT_PIN')
  rows[name]=json.loads(raw)
 return validate_closed(rows,prior)
