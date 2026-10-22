"""Exact historical pre-command refusal, never success or retry permission.

Only pinned files are read. No SDK/controller imports, live identity, lease,
process/VM calls, exception-success classifier, or historical writes.
"""
from pathlib import Path
import hashlib
import json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
OP='99cf88e1a59f43a0a2ffe5e1ed3496c4'
SCOPE_SHA='af54c60a2a71d699b2732441c14da1b700d64ef25d1c182d290e928d904b250b'
PLAN_SHA='31143bf8237f8bcd9fedd16ec68ce463f9c8eb36a062fce50761b80b64b02ff0'
CONTROLLER_SHA='358b7368ebf6ce901eb936dc9daf1f4fc8b1774bce42bcacdef6c470d145aaf4'
SOURCE_SHA='2307887fa443bb7a31225fcd8f723d21c5662a3f28fca3bd8b5ea82df724d249'
CLASSIFICATION='REFUSED_BEFORE_CREATE_CONTEXT_HEADROOM'
PINS={'plan.json': '15195b7a68352aafeb8d4cfcbf12469c9befe0f7b52ad5109de72d21dcf87d2c', 'build-proof.json': '5b402ea70a8ed76c1292b2c02bf72c2e1e10891cf831e8c69581484aa035014d', 'host-identity.json': 'd1e3daaf2870261355c513eb4089164002081d3423541cf8c76ba68ca1fff180', 'host-result.json': '41ebe665077d63eaecd29b130461f5d59c7ce30a389fe9d345ff84ae8b267407', 'sdk-receipt.json': 'f52bebd93e6c9983838b213fffcdfa5de69fd7a70fec13a73aa47c8813aa2b75', 'intent.json': '030805b758e11e4c190b156d7ef29cf0449b71e318213d39bc0d9ba24a845986', 'unknown.json': '20ca137495bcb2d1fb5304fe9eedbda0e3740bc8199b2573245acd76bcd44ee3', 'cpp-exception-type-epoch.json': '1db4ceb4ae7c410999a2c72c4207e45fe7cd583ca503d7af44f899764a2ff948', 'update-preview-proof.json': 'b86d3041eeae889d19df4d0a820828f1f6d7dc5d0db3c04285ae21539a01d047', 'update-preview-c-proof.json': '86c67b8609aae07fc89f70c915fc55e55cad8602b86fd92cb34f48bf53248ab3', 'owned-headless-comparison-as-proof.json': 'b8f271d72f940cb6b1e90efafaea7ef686e4599517e673a9bad77e6247234828', 'owned-headless-comparison-core-proof.json': 'bd5d11717af05fcef4b5d1caecaa6e49cceb41ac441755465d1550818b9d0ee9', 'native-headless-intent.json': '1d6c6861c9b7711850d9d8e73224f9e88fb06c78783d93b8cc4e9e3cb98b576f', 'update-preview-fast-resources-proof.json': '6d772115e987ffc47fd2aa54678fa15b0f06b123409ca66500da7e409e91801f'}
SOURCE_PINS={'tools/1c/designer-bridge/research/update_preview_operation.py': '358b7368ebf6ce901eb936dc9daf1f4fc8b1774bce42bcacdef6c470d145aaf4', 'tools/1c/designer-bridge/research/update_preview_carrier.py': '05babaeadafa47022523d0d88242719e8922b21374bf27043eb2edd93c60549c', 'tools/1c/designer-bridge/research/update_context_primary.py': '70c3ab2c7b0ff255d1016cdcabed3e58b99579a41b93b9a69ca68f3891e84607', 'tools/1c/designer-bridge/research/native_update_context_gate.h': 'ee2e1aa20a86d17b299c9049563a9e2accf04b4653a1281273d3777777d65f1e', 'tools/1c/designer-bridge/research/NativeUpdatePreview.c.inc': '63cc52ce2b482fb769d4d916ef61270d8143bc204dca87549bf8e79342f87a8b', 'tools/1c/designer-bridge/research/NativeUpdatePreview.as': 'c107d81f13bdbc006180a2993b7cd9e127778498ba3ed9645ada08eb3c995e3b', 'tools/1c/designer-bridge/research/NativeSavedResourcesFastGate.as': '022c9e566551052c09fe5638e10e6bfba86b8cf8f94c663749daadc99bfcf6a9', 'tools/1c/designer-bridge/research/native_update_allowlist_gate.h': 'fb65f9b7dfc1f13aa867e5b4727ae765c3b828d6f6fc1c000b6aabe5b3979dcb', 'tools/1c/designer-bridge/research/native_update_preview_sink.h': 'a5d2eab1ff57dc4c98cbe1d82ba9af788099d5bee2d67941470fa97a433a3686', 'tools/1c/designer-bridge/research/native_update_preview_message_sink.h': 'f6ed19124bcbcb1bdedee5fdf89ae48f02df0643bb028cb7ba1d5e8d9d9ec376', 'tools/1c/designer-bridge/research/comparison_cpp_exception_type_epoch.py': 'e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4', 'build/designer-hot-v233-99cf88e1a59f43a0a2ffe5e1ed3496c4/Continuation.c': '5befdece34e66b494aeaeabc923542d16ac19c884342bc272b42f008eec1b58c', 'build/designer-hot-v233-99cf88e1a59f43a0a2ffe5e1ed3496c4/sdk_probe_params.h': '84de34a3ef4aeb30057f4da8234653dcfbb1577d52daa9bb35baab2c8b7b3ca6', 'build/designer-hot-v233-99cf88e1a59f43a0a2ffe5e1ed3496c4/OwnedSdkReadonlyAttach.cs': '112007654805351263fee5c8f9c08d27d2a665eee8d9202f1d7bc0c45d1b62a4', 'build/designer-hot-v233-99cf88e1a59f43a0a2ffe5e1ed3496c4/OwnedSdkDiagnosisHook.cs': '4cb409f9b74769de2ed69ac25006e22745bb3dc12f4e26e440f3e237d6e59152', 'build/designer-hot-v233-99cf88e1a59f43a0a2ffe5e1ed3496c4/run-fixed.ps1': '173ea976c963c30e8049bcab6954143e00df614b8751e534ebeb2c2f08094606', 'build/designer-hot-v233-99cf88e1a59f43a0a2ffe5e1ed3496c4/Continuation.dll': '4b431b78dda9c692dc553f001a744cdfc209f327795ac33fa6da87202b7f1f9e', 'artifacts/designer-bridge/update-preview-scope-0283821b27394e6887393cacc86fd274.json': 'af54c60a2a71d699b2732441c14da1b700d64ef25d1c182d290e928d904b250b', 'build/designer-v43-013dc010bd784e859b1e3ba4def25f3c/runtime/modules/snegopat/engine/main.as': 'd06c152775ede6d0ae91d10d5736ec09a3f63e2f6b2637689ff8329e18db50b2'}
EXPECTED_ROWS=[{'kind': 1, 'change': 1, 'depth': 0, 'hasPair': 1, 'pairHex': '005d8b21107e6f48874c73c2368ed5da005d8b21107e6f48874c73c2368ed5da', 'propertyHex': '00000000000000000000000000000000'}, {'kind': 1, 'change': 1, 'depth': 2, 'hasPair': 1, 'pairHex': '52256e178bfd2348afc0d17431f2fb7b52256e178bfd2348afc0d17431f2fb7b', 'propertyHex': '00000000000000000000000000000000'}, {'kind': 3, 'change': 1, 'depth': 4, 'hasPair': 1, 'pairHex': '52256e178bfd2348afc0d17431f2fb7b52256e178bfd2348afc0d17431f2fb7b', 'propertyHex': '433296d52e269843b4d7fb16d06484f6'}, {'kind': 1, 'change': 1, 'depth': 2, 'hasPair': 1, 'pairHex': 'c7dfec283e088240b272efbf7152de5cc7dfec283e088240b272efbf7152de5c', 'propertyHex': '00000000000000000000000000000000'}, {'kind': 3, 'change': 1, 'depth': 4, 'hasPair': 1, 'pairHex': 'c7dfec283e088240b272efbf7152de5cc7dfec283e088240b272efbf7152de5c', 'propertyHex': '433296d52e269843b4d7fb16d06484f6'}, {'kind': 1, 'change': 1, 'depth': 2, 'hasPair': 1, 'pairHex': 'be3d6a6894bee7459e8bdd93f0cd579cbe3d6a6894bee7459e8bdd93f0cd579c', 'propertyHex': '00000000000000000000000000000000'}, {'kind': 1, 'change': 1, 'depth': 4, 'hasPair': 1, 'pairHex': '57f9ae8de24aa148bf6cb88163a076f557f9ae8de24aa148bf6cb88163a076f5', 'propertyHex': '00000000000000000000000000000000'}, {'kind': 3, 'change': 1, 'depth': 6, 'hasPair': 1, 'pairHex': '57f9ae8de24aa148bf6cb88163a076f557f9ae8de24aa148bf6cb88163a076f5', 'propertyHex': 'd1fab48ea61f3e40970f2c12dbb43e23'}]
EXPECTED_TARGETS=[('8daef957-4ae2-48a1-bf6c-b88163a076f5', '3f413e18fe4e6f6bb8eeec10e8e2b7f54e1b0449f441779f8f861be1ab6d6ea7', ''), ('176e2552-fd8b-4823-afc0-d17431f2fb7b', '00ab097f6828f9bd79bc7c3a298196b512944a621af0f2a225f3b7d65ef827bd', '90939ff38be12b52740f27153455e711b145086ee1aacb6e906eb897556f381a'), ('28ecdfc7-083e-4082-b272-efbf7152de5c', '04e9fe8645eaab179bfd2cc0a2209c21854f1c7ac6a07e8ace68faa9b9dfa54d', 'f64720f5118b2eaba03197f3de83a3ee93a68738e7177751fcd92cbb618e224a')]

ZERO_WRITES=('sourceWrites','configurationSaves','repositoryMutations')

def need(ok,code):
 if not ok:raise ValueError('UPDATE_PREVIEW_REFUSAL_'+code)

def counts(row,expected,code):
 need(all(type(row.get(k)) is int and row[k]==v for k,v in expected.items()),code)

def flags(row,yes=(),no=(),code='FLAGS'):
 need(all(row.get(k) is True for k in yes) and all(row.get(k) is False for k in no),code)

def canonical(row):return json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()

def validate_closed(rows,prior):
 """Strict pure semantics for this exact refusal, without live admission."""
 need(type(rows) is dict and set(rows)==set(PINS) and all(type(x) is dict for x in rows.values()),'ROWS')
 need(type(prior) is dict and prior==rows['plan.json'] and hashlib.sha256(canonical(prior)).hexdigest()==PLAN_SHA,'PLAN')
 need(prior.get('operationId')==OP and prior.get('updatePreviewScopeSha256')==SCOPE_SHA
  and prior.get('updatePreviewControllerSha256')==CONTROLLER_SHA and prior.get('actualSourceSha256')==SOURCE_SHA,'SOURCE')
 ctx=prior.get('context',{});need((ctx.get('processId'),ctx.get('guiThreadId'),ctx.get('birth'))==(48936,8292,'01dd5d0180299126'),'TARGET')
 for name,row in rows.items():
  if name not in ('plan.json','build-proof.json','host-result.json','host-identity.json'):
   need(row.get('operationId')==OP and row.get('scopeSha256')==SCOPE_SHA,'JOIN')
 a=rows['update-preview-proof.json'];c=rows['update-preview-c-proof.json'];ep=rows['cpp-exception-type-epoch.json']
 sdk=rows['sdk-receipt.json'];host=rows['host-result.json'];unknown=rows['unknown.json'];intent=rows['intent.json'];build=rows['build-proof.json']
 need(a.get('kind')=='UPDATE_PREVIEW_NATIVE' and a.get('reason')=='CREATE_ALLOWLIST_GATE','REASON')
 flags(a,yes=('beforeRootAndTargetsClean','afterRootAndTargetsClean','designerPrefixPreserved','typedHandlesCleared','hooksPreserved','resourcesVerified'),
  no=('verified','nativeIntentWritten','exceptionObserved','entered','left','sinksCreated','subscribersDisconnected','sinksFinished','databaseApplyVerified'),code='AS_REFUSAL')
 counts(a,dict(beforeTargetsClean=3,afterTargetsClean=3,commandAttempts=0,commandReturned=0,bridgeCalls=1,bridgeStatus=1,bridgePhase=0,
  persistentBefore=0,persistentAfter=0,singleBefore=0,singleAfter=0,positiveAnswers=0,**{k:0 for k in ZERO_WRITES}),'AS_COUNTS')
 need(c.get('kind')=='UPDATE_PREVIEW_C' and c.get('controls')==[],'C_KIND')
 ones=('parentEntered','parentReturned','parentRestored','pendingAllowed','otherEmpty','routeVerified','contextChecks')
 zeros=('phase','commandScopeActive','createCalls','nodeCalls','enterCalls','leaveCalls','contextAllowed','contextCount','contextDataRangeVerified',
  'modalRefs','messageRefs','modalBusy','messageBusy','modalPayloadOwn','messagePayloadOwn','modalFinished','messageFinished','modalAdmitted','messageAdmitted',
  'modalCancelled','messageCancelled','modalFailed','messageFailed','modalError','messageError','modalRejected','messageRejected','modalReentries','messageReentries',
  'modalCancelAttempts','messageCancelAttempts','metadataComplete','metadataUnavailable','controlsExpected','controlsRead','messageType','messageTimeout','abiFault','positiveAnswers','resultPuts')
 counts(c,dict(contextState=6,contextCapacity=90,**{k:1 for k in ones},**{k:0 for k in zeros},**{k:0 for k in ZERO_WRITES}),'C_BEFORE_CREATE')
 need(c['contextCapacity']-c['contextCount']<145,'HEADROOM_REFUSAL')
 for row in (a,c):
  for key in ('nativeCommands','databaseUpdates','busy','contextOwn','functionOwn','hookOwn','parentExecuting'):
   if key in row:counts(row,{key:0},'EXTRA_EFFECT')
 for row in (sdk,host):
  flags(row,yes=('knownTerminal','hookWorkersReleased'),no=('writerAuthorized','sourceWritesAuthorized','configurationSavesAuthorized','repositoryMutationsAuthorized','positiveDialogAnswersAuthorized','resultPropertyWritesAuthorized','configurationExportsAuthorized','configurationImportsAuthorized'),code='HOST_CLOSED')
  counts(row,dict(sdkResult=0,threadId=8292),'HOST_COUNTS')
  need(row.get('actualSourceSha256')==SOURCE_SHA,'HOST_SOURCE')
 need(sdk.get('planSha256')==intent.get('planSha256')==build.get('planSha256')==PLAN_SHA,'PLAN_JOIN')
 flags(build,yes=('passed',),no=('goldStarted','nativeInjectionPerformed','carrierAssemblyExecuted'),code='BUILD')
 counts(build,dict(compileExitCode=0,carrierCompileExitCode=0),'BUILD_COUNTS')
 flags(unknown,no=('knownTerminal','retryAuthorized','databaseApplyVerified','updateAdmissionGranted','globalPendingClean','actualUpdate29OwnerVerified','syntheticPrintVerified'),code='NO_SUCCESS')
 need(unknown.get('status')=='UNKNOWN_RETAIN' and unknown.get('reason')=='NATIVE_OR_FRESH_CLOSURE_UNPROVEN','UNKNOWN_PRESERVED')
 need(ep.get('kind')=='COMPARISON_CPP_EXCEPTION_TYPE_EPOCH' and ep.get('phase')=='EXECUTE_RETURNED','EPOCH')
 flags(ep,yes=('handlerRegistered','handlerRemoved','executeEntered','executeReturned','typeMetadataOnly','selfReferenceRetained','dllMustRemainLoadedUntilProcessExit'),
  no=('counterOverflow','typeEventOverflow','typeDecoderReentry','exceptionObjectRead','fullPendingVerified','databaseUpdateAuthorized','allCppExceptionFree','listStreamPathExceptionFreeVerified'),code='EPOCH_CLOSED')
 counts(ep,dict(processId=48936,executeThreadId=8292,sdkExecuteRc=0,cppThrows=4,cppThrowsExecuteThread=4,cppThrowsOtherThreads=0,
  otherExceptions=0,otherExceptionsExecuteThread=0,otherExceptionsOtherThreads=0,typeEventCount=4,decodedCppThrows=4,unknownCppThrows=0,listStreamCompatibleThrows=0),'EXACT_EVENTS')
 events=ep.get('typeEvents');need(type(events) is list and len(events)==4,'EVENTS')
 for event,hashes in zip(events,[['f16051db','243edd7d'],['f16051db','243edd7d'],['679b708b'],['d2715cd6','243edd7d']]):
  flags(event,yes=('decoded','allCatchableTypesExamined'),no=('listStreamCompatible',),code='DECODED')
  counts(event,dict(catchableTypeCount=len(hashes)),'EVENT_COUNT');need(event.get('typeNameHashes')==hashes and event.get('primaryTypeNameHash')==hashes[0],'EVENT_HASH')
 h=rows['owned-headless-comparison-core-proof.json'];ha=rows['owned-headless-comparison-as-proof.json'];f=rows['update-preview-fast-resources-proof.json']
 flags(h,yes=('codeVerified',),no=('fullPendingVerified','databaseUpdateAuthorized'),code='HEADLESS_FLAGS')
 counts(h,dict(phase=8,reason=0,attempts=1,repeatedAttempts=0,getterAttempts=2,getterReturned=2,addrefAttempts=4,releaseAttempts=3,
  factoryAttempts=1,factoryReturned=1,executeAttempts=1,executeReturned=1,projectionAttempts=1,sourceTransferConsumed=2,sourceTransferInFlight=0,
  ownedReferencesRemaining=0,mainSource=344510268,databaseSource=170975980,completion=1,selected=13568,visited=13568,viewPointer=0,abiFault=0,treeError=0,
  treeNodes=335181,treePasses=2,treeCoherent=1,treeTraversalComplete=1,objectFlagsObserved=13568,objectMask20Count=0,rowCount=8,applicationTextOutputBytes=0,databaseUpdates=0,**{k:0 for k in ZERO_WRITES}),'HEADLESS_CLOSED')
 need(h.get('rows')==EXPECTED_ROWS,'EXACT_ALLOWLIST')
 flags(ha,yes=('nativeIntentWritten','beforeRootAndTargetsClean','afterRootAndTargetsClean','typedHandlesCleared'),no=('unknownRetain','fullPendingVerified','databaseUpdateAuthorized'),code='HEADLESS_AS')
 counts(ha,dict(bridgeAttempts=1,bridgeReturned=1,beforeTargetsClean=3,afterTargetsClean=3,nativeCommands=0,databaseUpdates=0,**{k:0 for k in ZERO_WRITES}),'HEADLESS_AS_COUNTS')
 need(f.get('status')=='SAVED_RESOURCE_FAST_CANDIDATES_VERIFIED' and f.get('reason')=='NONE','FAST')
 flags(f,no=('pendingFileReference','writerAuthorized'),code='FAST_CLOSED')
 counts(f,dict(resourcesRead=3,moduleDecodedPasses=4,coldLoads=0,coldSnapshots=0,templatePropertyComparisons=0,metadataWrites=0,databaseUpdates=0,**{k:0 for k in ZERO_WRITES}),'FAST_COUNTS')
 targets=f.get('targets');need(type(targets) is list and len(targets)==3,'TARGETS')
 need([(r.get('objectId'),r.get('plainSha256'),r.get('textLfNoBomSha256')) for r in targets]==EXPECTED_TARGETS,'SAVED_HASHES')
 return CLASSIFICATION

def audit_closed(prior):
 """Read exact immutable history; no live state or future retry admission."""
 folder=ROOT/'build'/('designer-hot-v233-'+OP)
 need(not (folder/'result.json').exists() and not (folder/'native-update-preview-intent.json').exists(),'NO_COMMAND_OR_SUCCESS')
 for name,pin in SOURCE_PINS.items():need(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==pin,'SOURCE_PIN')
 rows={}
 for name,pin in PINS.items():
  raw=(folder/name).read_bytes();need(len(raw)<=32768 and hashlib.sha256(raw).hexdigest()==pin,'RECEIPT_PIN');rows[name]=json.loads(raw)
 return validate_closed(rows,prior)
