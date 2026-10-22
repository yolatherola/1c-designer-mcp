"""Exact returned-command quiescence, never DB success or retry permission.

Only pinned files are read. No SDK/controller imports, live identity, lease,
process/VM calls, exception-success classifier, or historical writes.
"""
from pathlib import Path
import hashlib
import json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
OP='3614b4c9b9314707bbc476ecc0029436'
SCOPE_SHA='a92a9c292e94ac7d0bf2527cf752a54c185b46742606d68f0ca65baf5314e24f'
PLAN_SHA='c3a811e1a1c06aac42baaef35be322ffe70fee2bab72f750be4e7cac65e37e91'
CONTROLLER_SHA='f1748e4e1328f783f01bce1bf8d053cb02701ed6063c5c257bed4cb5f83e5cdc'
SOURCE_SHA='2307887fa443bb7a31225fcd8f723d21c5662a3f28fca3bd8b5ea82df724d249'
CLASSIFICATION='COMMAND_RETURNED_RESOURCES_CLOSED_DATABASE_OUTCOME_UNVERIFIED'
PINS={'plan.json': '787a0fe40a6502a9ab6592ee7a799ec57708abba1722dbadea0f107b32b3b1dd', 'build-proof.json': 'ae2e45bc637e5b715f06fa914a38b6d650a97c8ac054659b5df6665a13fa6303', 'host-identity.json': 'a7297c1025b401d537e84557b779f403ddb79d22d8164409b63929e0f045851c', 'host-result.json': '104b526b114fd58ba11b9db467349759e9dd06f8e07dc50e862128ee8f8631b3', 'sdk-receipt.json': 'b43c903674355a44048858d01ed809eee6b828fb9b8b219670e2ad11b4938b85', 'intent.json': '3b34c0d197dac485a0e5db3ef853579e56203d28c6574b77cbefd5ab86c46d68', 'unknown.json': 'df76b2b69f8c0cf117f271ec77e9b6ceefde6bde83acf5c34a07db7ba02d9987', 'cpp-exception-type-epoch.json': '2b6e9211e7beafe0fc3734ea52a6cfb91b271069dc5e5edbc6e61722c3087730', 'update-preview-proof.json': '51693d12267385754016947e5fad20d2539fd0f07e81988df4f8b246a79ae8d5', 'update-preview-c-proof.json': 'bd277957966bc614eb8383e25dc6a64a53d8f7f503b5835e17e54b98a641d101', 'owned-headless-comparison-as-proof.json': '25d7c30f42f96abdc805f2e6d78349ee6a30364c53a842ed7651d3fcb50765cd', 'owned-headless-comparison-core-proof.json': '976872d653ce20efabd2f765629359bf707edaf47873e3d130093dd5914f74a2', 'native-headless-intent.json': 'b69d132d5909326a9b47baeb45a00fa4227d6c501e4d6393a5e07cc213ade20c', 'native-update-preview-intent.json': '46bde3864c2f24203ac887442eaa651eef4ca3ded50b0a248e9541699b08268a', 'update-preview-fast-resources-proof.json': '5e11891a5f07475db549e47f3bb3bc80ae08ed2a5688e0336baf021a9550a725'}
SOURCE_PINS={'tools/1c/designer-bridge/research/update_preview_first_context_operation.py': 'f1748e4e1328f783f01bce1bf8d053cb02701ed6063c5c257bed4cb5f83e5cdc', 'tools/1c/designer-bridge/research/update_preview_first_context_carrier.py': '6b9331b8e1eefd9adaf7fa6a67b71992d068e42d6197d412d84ca20136cbadd0', 'tools/1c/designer-bridge/research/update_context_primary.py': '70c3ab2c7b0ff255d1016cdcabed3e58b99579a41b93b9a69ca68f3891e84607', 'tools/1c/designer-bridge/research/native_update_first_context_gate.h': '56daec8821ab2efb56047dc13347de4970c9441d3170dd8648c718ac81e1f462', 'tools/1c/designer-bridge/research/NativeUpdateFirstContext.c.inc': '17a21c0e480cbc0ce55c9dfa780afdb6fc0559efb306d15aa1a03a66e6fd2e5e', 'tools/1c/designer-bridge/research/NativeUpdatePreview.as': 'c107d81f13bdbc006180a2993b7cd9e127778498ba3ed9645ada08eb3c995e3b', 'tools/1c/designer-bridge/research/NativeSavedResourcesFastGate.as': '022c9e566551052c09fe5638e10e6bfba86b8cf8f94c663749daadc99bfcf6a9', 'tools/1c/designer-bridge/research/native_update_allowlist_gate.h': 'fb65f9b7dfc1f13aa867e5b4727ae765c3b828d6f6fc1c000b6aabe5b3979dcb', 'tools/1c/designer-bridge/research/native_update_preview_sink.h': 'a5d2eab1ff57dc4c98cbe1d82ba9af788099d5bee2d67941470fa97a433a3686', 'tools/1c/designer-bridge/research/native_update_preview_message_sink.h': 'f6ed19124bcbcb1bdedee5fdf89ae48f02df0643bb028cb7ba1d5e8d9d9ec376', 'tools/1c/designer-bridge/research/comparison_cpp_exception_type_epoch.py': 'e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4', 'tools/1c/designer-bridge/research/update_preview_refusal_audit.py': 'cd4540fd54a0fa038835300a11294f9f54526f25c6ea23154fcc2b4979be69b7', 'build/designer-hot-v233-3614b4c9b9314707bbc476ecc0029436/Continuation.c': 'dff6900889f39e9f67b151a6cf584b105e0882e1fbf925b918c006620e81f009', 'build/designer-hot-v233-3614b4c9b9314707bbc476ecc0029436/sdk_probe_params.h': 'c36cc179c72e685d5b1946ccb88a05571ec4863b3bf1c2b5075f0af0ad5d28f2', 'build/designer-hot-v233-3614b4c9b9314707bbc476ecc0029436/OwnedSdkReadonlyAttach.cs': '112007654805351263fee5c8f9c08d27d2a665eee8d9202f1d7bc0c45d1b62a4', 'build/designer-hot-v233-3614b4c9b9314707bbc476ecc0029436/OwnedSdkDiagnosisHook.cs': '4cb409f9b74769de2ed69ac25006e22745bb3dc12f4e26e440f3e237d6e59152', 'build/designer-hot-v233-3614b4c9b9314707bbc476ecc0029436/run-fixed.ps1': '81811f6b2cc9b09476f1ac5e2192d48b7e4e242ef400461bc084463a61ef0883', 'build/designer-hot-v233-3614b4c9b9314707bbc476ecc0029436/Continuation.dll': '4d31c597ec88685c05fca1148d09b9fb936e3dee68ea4dbff56b8a335aa752cc', 'artifacts/designer-bridge/update-preview-first-context-scope-857c8a8fafed4a0ca4a2b19a3d95485c.json': 'a92a9c292e94ac7d0bf2527cf752a54c185b46742606d68f0ca65baf5314e24f', 'build/designer-v43-013dc010bd784e859b1e3ba4def25f3c/runtime/modules/snegopat/engine/main.as': 'd06c152775ede6d0ae91d10d5736ec09a3f63e2f6b2637689ff8329e18db50b2'}
EXPECTED_ROWS=[{'kind': 1, 'change': 1, 'depth': 0, 'hasPair': 1, 'pairHex': '005d8b21107e6f48874c73c2368ed5da005d8b21107e6f48874c73c2368ed5da', 'propertyHex': '00000000000000000000000000000000'}, {'kind': 1, 'change': 1, 'depth': 2, 'hasPair': 1, 'pairHex': '52256e178bfd2348afc0d17431f2fb7b52256e178bfd2348afc0d17431f2fb7b', 'propertyHex': '00000000000000000000000000000000'}, {'kind': 3, 'change': 1, 'depth': 4, 'hasPair': 1, 'pairHex': '52256e178bfd2348afc0d17431f2fb7b52256e178bfd2348afc0d17431f2fb7b', 'propertyHex': '433296d52e269843b4d7fb16d06484f6'}, {'kind': 1, 'change': 1, 'depth': 2, 'hasPair': 1, 'pairHex': 'c7dfec283e088240b272efbf7152de5cc7dfec283e088240b272efbf7152de5c', 'propertyHex': '00000000000000000000000000000000'}, {'kind': 3, 'change': 1, 'depth': 4, 'hasPair': 1, 'pairHex': 'c7dfec283e088240b272efbf7152de5cc7dfec283e088240b272efbf7152de5c', 'propertyHex': '433296d52e269843b4d7fb16d06484f6'}, {'kind': 1, 'change': 1, 'depth': 2, 'hasPair': 1, 'pairHex': 'be3d6a6894bee7459e8bdd93f0cd579cbe3d6a6894bee7459e8bdd93f0cd579c', 'propertyHex': '00000000000000000000000000000000'}, {'kind': 1, 'change': 1, 'depth': 4, 'hasPair': 1, 'pairHex': '57f9ae8de24aa148bf6cb88163a076f557f9ae8de24aa148bf6cb88163a076f5', 'propertyHex': '00000000000000000000000000000000'}, {'kind': 3, 'change': 1, 'depth': 6, 'hasPair': 1, 'pairHex': '57f9ae8de24aa148bf6cb88163a076f557f9ae8de24aa148bf6cb88163a076f5', 'propertyHex': 'd1fab48ea61f3e40970f2c12dbb43e23'}]
EXPECTED_TARGETS=[('8daef957-4ae2-48a1-bf6c-b88163a076f5', '3f413e18fe4e6f6bb8eeec10e8e2b7f54e1b0449f441779f8f861be1ab6d6ea7', ''), ('176e2552-fd8b-4823-afc0-d17431f2fb7b', '00ab097f6828f9bd79bc7c3a298196b512944a621af0f2a225f3b7d65ef827bd', '90939ff38be12b52740f27153455e711b145086ee1aacb6e906eb897556f381a'), ('28ecdfc7-083e-4082-b272-efbf7152de5c', '04e9fe8645eaab179bfd2cc0a2209c21854f1c7ac6a07e8ace68faa9b9dfa54d', 'f64720f5118b2eaba03197f3de83a3ee93a68738e7177751fcd92cbb618e224a')]

ZERO_WRITES=('sourceWrites','configurationSaves','repositoryMutations')

def need(ok,code):
 if not ok:raise ValueError('UPDATE_FIRST_CONTEXT_COMPLETION_'+code)

def counts(row,expected,code):
 need(all(type(row.get(k)) is int and row[k]==v for k,v in expected.items()),code)

def flags(row,yes=(),no=(),code='FLAGS'):
 need(all(row.get(k) is True for k in yes) and all(row.get(k) is False for k in no),code)

def canonical(row):return json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()

def validate_closed(rows,prior):
 """Strict pure semantics for this returned command; DB outcome unverified."""
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
 need(a.get('kind')=='UPDATE_PREVIEW_NATIVE' and a.get('reason')=='NONE','REASON')
 flags(a,yes=('verified','nativeIntentWritten','beforeRootAndTargetsClean','afterRootAndTargetsClean','designerPrefixPreserved','typedHandlesCleared','hooksPreserved','resourcesVerified','entered','left','sinksCreated','subscribersDisconnected','sinksFinished'),
  no=('exceptionObserved','databaseApplyVerified'),code='AS_OWN_CLOSURE')
 counts(a,dict(beforeTargetsClean=3,afterTargetsClean=3,commandAttempts=1,commandReturned=1,bridgeCalls=7,bridgeStatus=0,bridgePhase=5,
  persistentBefore=0,persistentAfter=0,singleBefore=0,singleAfter=0,positiveAnswers=0,**{k:0 for k in ZERO_WRITES}),'AS_COUNTS')
 need(c.get('kind')=='UPDATE_PREVIEW_C' and c.get('controls')==[],'C_KIND')
 ones=('parentEntered','parentReturned','parentRestored','pendingAllowed','otherEmpty','routeVerified','contextAllowed','contextDataRangeVerified','createCalls','nodeCalls','enterCalls','leaveCalls','modalFinished','messageFinished')
 zeros=('commandScopeActive','contextCount','contextStackLimit','contextConfigurationWrites','modalRefs','messageRefs','modalBusy','messageBusy','modalPayloadOwn','messagePayloadOwn','modalAdmitted','messageAdmitted',
  'modalCancelled','messageCancelled','modalFailed','messageFailed','modalError','messageError','modalRejected','messageRejected','modalReentries','messageReentries',
  'modalCancelAttempts','messageCancelAttempts','metadataComplete','metadataUnavailable','controlsExpected','controlsRead','messageType','messageTimeout','abiFault','positiveAnswers','resultPuts')
 counts(c,dict(phase=5,contextChecks=2,contextState=6,contextCapacity=90,contextStackLimitReads=4,**{k:1 for k in ones},**{k:0 for k in zeros},**{k:0 for k in ZERO_WRITES}),'C_OWN_CLOSURE')
 need(c['contextCapacity']-c['contextCount']>=19,'FIRST_HEADROOM')
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
 flags(ep,yes=('handlerRegistered','handlerRemoved','executeEntered','executeReturned','typeMetadataOnly','selfReferenceRetained','dllMustRemainLoadedUntilProcessExit','typeEventOverflow'),
  no=('counterOverflow','typeDecoderReentry','exceptionObjectRead','fullPendingVerified','databaseUpdateAuthorized','allCppExceptionFree','listStreamPathExceptionFreeVerified'),code='EPOCH_CLOSED')
 counts(ep,dict(processId=48936,executeThreadId=8292,sdkExecuteRc=0,cppThrows=310,cppThrowsExecuteThread=310,cppThrowsOtherThreads=0,
  otherExceptions=0,otherExceptionsExecuteThread=0,otherExceptionsOtherThreads=0,typeEventCount=310,decodedCppThrows=32,unknownCppThrows=278,listStreamCompatibleThrows=0),'EXACT_EVENTS')
 # Overflow is the exact reason this cannot certify Update29/DB success.
 # Unknown 278 events are NOT treated as exception-free or non-ListStream.
 events=ep.get('typeEvents');need(type(events) is list and len(events)==32,'OBSERVED_EVENT_COUNT')
 need(hashlib.sha256(canonical(events)).hexdigest()=='c41d64408ef5c06c7a832bc72f5891b60833843d4d753b0f8a497ac34fffaf9e','EXACT_OBSERVED_EVENTS')
 for event in events:
  flags(event,yes=('decoded','allCatchableTypesExamined'),no=('listStreamCompatible',),code='OBSERVED_DECODED')
 ni=rows['native-update-preview-intent.json'];need(ni.get('kind')=='UPDATE_PREVIEW_INTENT','NATIVE_INTENT')
 counts(ni,dict(command=29,maximumDispatchAttempts=1,maximumModalCancels=1,maximumMessageCancels=1,positiveAnswers=0,**{k:0 for k in ZERO_WRITES}),'NATIVE_INTENT_COUNTS')
 flags(ni,yes=('databaseApplyPossible',),code='POSSIBLE_APPLY')
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
 need(not (folder/'result.json').exists(),'NO_SUCCESS_RESULT')
 for name,pin in SOURCE_PINS.items():need(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==pin,'SOURCE_PIN')
 rows={}
 for name,pin in PINS.items():
  raw=(folder/name).read_bytes();need(len(raw)<=32768 and hashlib.sha256(raw).hexdigest()==pin,'RECEIPT_PIN');rows[name]=json.loads(raw)
 return validate_closed(rows,prior)
