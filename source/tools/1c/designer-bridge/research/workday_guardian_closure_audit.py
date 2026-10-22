"""Historical closure of the frozen v234 saved-module profile; no dispatch.

The JSONL is streamed twice: the fixed evidence verifier first, then native/
SDK-epoch/config joins. No source frames or application bodies are read. A
closed historical owner still requires a NEW kernel exit/identity/lease check.
"""
import hashlib
import json
import math
from pathlib import Path
import re
import stat
from collections import deque
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
CONTROLLER_SHA = '29c98d25b76bce37c04b203b062c41b48bf0e3519acdf2c30e32a69c4f476530'
HOST_SHA = '332e361121b4322c233d738cc7330e3eedf4f5d12143b986014051e6a960ce26'
RUNTIME_SHA = '4b580d378fb946bf20b76ff5ecd82a740fd5ac85bc0d61e559e9dffd01faeafc'
WORKER_SHA = 'aab4b550abf9ffe877f0e207c00939f289c38b1f575b549d3795807ca4dee62c'
EVIDENCE_SHA = '9d3a2be280d5b0c84028b361a4e0baa3c4d5f23d8fa56739f87195aa060bebf5'
PINS = {
 'workday_episode_evidence.py': EVIDENCE_SHA,
 '../native_mcp/workday_provider.py': 'b9f43c59707aeecbd425c8be38aeb3dd6c14d9f94e14378743289dc2fa8eb71b',
 'workday_ram_carrier.py': 'ff59538b81fd2266e3e9f62912d79c20fb1f30b932c650a6659de0e1855f5f25',
 'resident_managed_carrier.py': 'df071e91f3e0fe2bea80b5a850e2407bd3bed4e29322bf9ba5027f122dbe44e8',
 'sdk_compiler_section_identity.py': '6f63f39ddcd8f1e3db9c25ca866e7faa89f6a8bc2be54dfd49dc958952f9754d',
 'NativeSafeCommonModuleRam.as': '1f6d544d1963a19e4da54a67f246457a63ce080a30151857472802acaa2d92e3',
}
FILES = ('Continuation.c', 'sdk_probe_params.h', 'OwnedSdkDiagnosisHook.cs',
         'OwnedSdkReadonlyAttach.cs', 'run-resident.ps1')
STAGE = ('plan.json', 'build-proof.json', 'intent.json', 'result.json', 'resident-host-result.json',
         'resident-host-ready.json', 'host-identity.json', 'resident-sdk-result.bin',
         'Continuation.dll', 'OwnedCarrierPreflight.dll', *FILES)
# These are immutable historical policy values, not hashes of evolving files.
# Filled from the already reviewed frozen scope/plan, never from caller paths.
SCOPE_FIXED = {'acceptanceHarnessSha256': 'd79f2ad6c12c181aebb126e7cf6894284cb6da0b20bb1eb260274a15e523ce3a', 'actualSourceSha256': '1f6d544d1963a19e4da54a67f246457a63ce080a30151857472802acaa2d92e3', 'allowedReadClasses': ['CommonModule'], 'applicationDataReadAuthorized': False, 'arbitraryCommonModuleSelectionAuthorized': True, 'birth': '01dd5d0180299126', 'businessCallsAuthorized': False, 'closedResidentAuditSha256': '0da8c6eb1234c5b5cba7c1f15740dae36fa2ae4069ac6571f4fecb54e5af2d8a', 'closedResidentManifestSha256': '53236d0bef10070f7181407539a9242566a4d6dec7ae3481b1e38e9e94a9afab', 'commandDispatchAuthorized': False, 'comparisonExecuteAuthorized': False, 'comparisonFactoryAuthorized': False, 'configurationExportsAuthorized': False, 'configurationImportsAuthorized': False, 'configurationReadOnly': True, 'configurationSavesAuthorized': False, 'daemonGuardianClosureAuditSha256': 'dc74b681f0d1a2dc098ed4199a19935e46a667f827b41762a589b22ab791e3dc', 'daemonRuntimeSha256': '8d27e9db466e7d4dbbe6a23f0a7f28c487426980fa784d292cfcec8158d8b206', 'databaseUpdatesAuthorized': False, 'detachedValuesAuthorized': False, 'exceptionObjectReadAuthorized': False, 'exceptionTypeMetadataReadAuthorized': True, 'expectedDatabaseSource': 1383504556, 'explicitWorkdayGrantAuthorized': True, 'externalAddinLoadingAuthorized': False, 'fullReadClosureAuditSha256': '28a3403ebbc796b10e4719069502097aab1f45cfd773d26a2ed1046ec59bb6a2', 'fullReadClosureManifestSha256': '3809bbfe69ae67f402d7843500304e0d48697775151d8b5b9fb3502d54ba7662', 'guardianCompositionPins': {'native_mcp/guardian_client.py': 'a8b76c3a6c314c3bccbe07c9a56d90898d5bb01a9dd4f0839b219cd78e110ce9', 'native_mcp/guardian_descriptor.py': '244a2cecfbd7e12796807aa10ad3d13f9b87f11de74a82cc3ed30405aca3a0b3', 'native_mcp/guardian_relay_server.py': '09f0adf1ac100787c00d9554527c5aaa76e4b493edf05b03dfcc53d5c90dfbfa', 'native_mcp/guardian_service.py': '4c350782bc9cef3d5d0b74574471abee95c56faf547acd2e1424e47251b57e04', 'native_mcp/guardian_wire.py': '3ca907c8f4df783cba01f63fb002e86c9cb2a262f504b785f50a9276c938a456', 'native_mcp/host_slot.py': 'bb6882c1284106199a2f184ecc971fa97d249bb13011a8a1337d4a2ae158ea94', 'native_mcp/resident_receipt_observer.py': '5ef7207201dca1bf54cc828027ff07c7d1b6caa7159c9c5feacb9cea44d5cbe6', 'native_mcp/windows_guardian_pipe.py': 'c0c7a7a6a03e43d59fd29965a3b227ff337b212a577702cc5db2c76cca25e8b3', 'research/guardian_native_admission.py': '5f8aad5ea45df9d3e56f58054e7a48c4c4fc41eaa4bb3c24cf8e30b3f1f6bc6b', 'research/resident_saved_module_operation.py': '5a6384b247b2070cf0d8eddbe9632b37d301f426d512943ab7a92352aa094bff', 'research/run_guardian_stdio_mcp.py': 'bca07e2dd7f0f50e4aa4e2f39028ea36e84c423f663e8e9dcda5e93cfeb5b360'}, 'guardianEpisodeWorkerSha256': 'ad061bcf02e9db6d33b95e1d11deabf29961130fdd6f32cbf9c77f25c482bf26', 'guardianNativeAdmissionSha256': '5f8aad5ea45df9d3e56f58054e7a48c4c4fc41eaa4bb3c24cf8e30b3f1f6bc6b', 'guardianRelayAcceptanceAuthorized': True, 'guiThreadId': 8292, 'historicalReferencesReleaseAuthorized': False, 'hostSlotSha256': 'bb6882c1284106199a2f184ecc971fa97d249bb13011a8a1337d4a2ae158ea94', 'idleQueueInvocationAuthorized': False, 'independentGuardianProcessAuthorized': True, 'kind': 'ROOT_WORKDAY_SAVED_RAM_SCOPE', 'mainSha256': 'd06c152775ede6d0ae91d10d5736ec09a3f63e2f6b2637689ff8329e18db50b2', 'manualAddRefReleaseAuthorized': False, 'maximumBodyBytes': 4194304, 'maximumCodePoints': 1048576, 'maximumEnumerations': 0, 'maximumEventSubscribers': 0, 'maximumFileOpensPerRequest': 2, 'maximumFlagPropertyReads': 24, 'maximumGlobalQueueInvocations': 0, 'maximumNativeCommands': 0, 'maximumPlainResourceBytes': 8388608, 'maximumRequests': 4095, 'maximumResidentControlCommands': 4096, 'maximumSessionSeconds': 28800, 'maximumStartupPropertyReads': 4, 'maximumStorageEntryOpensPerRequest': 4, 'maximumTypeEvents': 32, 'maximumUrlGetterCalls': 4, 'modulePropertyId': 'd5963243-262e-4398-b4d7-fb16d06484f6', 'namedBridgeAuthorized': False, 'nativeGuardianHostSha256': 'd79f2ad6c12c181aebb126e7cf6894284cb6da0b20bb1eb260274a15e523ce3a', 'nativeOwnedRamOutputAuthorized': True, 'nativeOwnerUnderStdioJobAuthorized': False, 'newEnumerationAuthorized': False, 'newSessionsAuthorized': False, 'ownedVectorDrainAuthorized': False, 'passed': True, 'persistentFrontendClosureAuditSha256': '4be25ce025c5aeaee08b7746dbf535fc9f88da8e2b763bc15f077b5ba148e687', 'persistentFrontendClosureManifestSha256': '5d1a24045b60405965ff6129163f8e13f972a6735a7043457f58ec0b36d785fd', 'persistentMcpAdmissionSha256': '4179e0c9e7526b4c8a48e7da1ba7f7fd9fef7fec22564e0208c8b65ff565aeea', 'persistentMcpInProcessAcceptanceAuthorized': False, 'persistentServerSha256': '09f0adf1ac100787c00d9554527c5aaa76e4b493edf05b03dfcc53d5c90dfbfa', 'persistentStdioLauncherSha256': 'bca07e2dd7f0f50e4aa4e2f39028ea36e84c423f663e8e9dcda5e93cfeb5b360', 'pid': 48936, 'positiveDialogAnswersAuthorized': False, 'profile': 'WORKDAY_DATABASE_SAVED_COMMON_MODULES', 'profileVersion': 234, 'protectedControlChannelAuthorized': True, 'readOnly': False, 'readScopePath': 'F:\\Projects\\AH_1C\\artifacts\\designer-bridge\\pending-editor-read-scope-1ee748ced8984a199aeb8f0b9d576cf6.json', 'readScopeSha256': '6f9ee05e6d6bf98982cc7bc0d2db1a2b1f5a30e6dba9e431053165d51cce3f35', 'receiptObserverSha256': '5ef7207201dca1bf54cc828027ff07c7d1b6caa7159c9c5feacb9cea44d5cbe6', 'releaseResourcesAuthorized': False, 'renewableGuardianAdmissionSha256': '809da32f339297266f545326b111ce44980a408f6ba07f9a94c3f35d272adf44', 'repositoryMutationsAuthorized': False, 'residentAdmissionAdapterSha256': '3bfc223fb21b6fc1280490f3d07a9acf57e6db9647fce72e813b4e54562e4d4c', 'residentSdkFunctionCloseAuthorized': True, 'residentSdkReuseAuthorized': True, 'resultPropertyWritesAuthorized': False, 'retainedReferenceMaintenanceAuthorized': True, 'runtimeCacheMutationPossible': True, 'runtimeComparisonCreationAuthorized': False, 'runtimeDatabaseResourcesReadAuthorized': True, 'runtimeDialogHooksAuthorized': False, 'runtimeFrameBindingAuthorized': False, 'runtimeMetadataReadAuthorized': True, 'runtimeSupportInitializationAuthorized': False, 'runtimeSyntheticEventsAuthorized': False, 'runtimeUiMutationPossible': True, 'scopedRamPipeTransferAuthorized': True, 'scopedReferenceCallsAuthorized': True, 'sessionNonce': '013dc010bd784e859b1e3ba4def25f3c', 'sourceBodyReadsAuthorized': True, 'sourceWritesAuthorized': False, 'stdioNativeAcceptanceAuthorized': True, 'stockCompareAuthorized': False, 'syntheticPdfWriteAuthorized': False, 'targets': [{'objectId': '8daef957-4ae2-48a1-bf6c-b88163a076f5', 'propertyId': '8eb4fad1-1fa6-403e-970f-2c12dbb43e23'}, {'objectId': '176e2552-fd8b-4823-afc0-d17431f2fb7b', 'propertyId': 'd5963243-262e-4398-b4d7-fb16d06484f6'}, {'objectId': '28ecdfc7-083e-4082-b272-efbf7152de5c', 'propertyId': 'd5963243-262e-4398-b4d7-fb16d06484f6'}], 'typeRawOutput': False, 'workdayControllerSha256': '29c98d25b76bce37c04b203b062c41b48bf0e3519acdf2c30e32a69c4f476530', 'workdayEvidenceSha256': '9d3a2be280d5b0c84028b361a4e0baa3c4d5f23d8fa56739f87195aa060bebf5', 'workdayGuardianHostSha256': '332e361121b4322c233d738cc7330e3eedf4f5d12143b986014051e6a960ce26', 'workdayGuardianWorkerSha256': 'aab4b550abf9ffe877f0e207c00939f289c38b1f575b549d3795807ca4dee62c', 'workdayLifecycleSha256': '4b580d378fb946bf20b76ff5ecd82a740fd5ac85bc0d61e559e9dffd01faeafc'}
PLAN_FIXED = {'actualSourceSha256': '1f6d544d1963a19e4da54a67f246457a63ce080a30151857472802acaa2d92e3', 'admittedSourceSha256': '819038a386ae34fcfec0de8fa234b3b1f4415520b4615bb19c7884df8c43e48a', 'applicationDataReadAuthorized': False, 'applicationWrites': 0, 'arbitraryCommonModuleSelectionAuthorized': True, 'businessCallsAuthorized': False, 'captureAuthorized': False, 'commandDispatchAuthorized': False, 'comparisonExecuteAuthorized': False, 'comparisonFactoryAuthorized': False, 'configurationExports': 0, 'configurationExportsAuthorized': False, 'configurationImports': 0, 'configurationImportsAuthorized': False, 'configurationReadOnly': True, 'configurationSavesAuthorized': False, 'context': {'birth': '01dd5d0180299126', 'buildDirectory': 'F:\\Projects\\AH_1C\\build\\designer-v43-013dc010bd784e859b1e3ba4def25f3c', 'corePath': 'F:\\Projects\\AH_1C\\build\\designer-v43-013dc010bd784e859b1e3ba4def25f3c\\runtime\\lib\\x86\\core_as.dll', 'guiThreadId': 8292, 'heldNonce': '013dc010bd784e859b1e3ba4def25f3c', 'mainSha256': 'd06c152775ede6d0ae91d10d5736ec09a3f63e2f6b2637689ff8329e18db50b2', 'processId': 48936, 'registrySha256': '800997a50b33801ca580c6923554c8a4a5ea8e4044b96b59f6ba4b8fc6af6a7e', 'snegopatPath': 'F:\\Projects\\AH_1C\\build\\designer-v43-013dc010bd784e859b1e3ba4def25f3c\\runtime\\modules\\snegopat\\lib\\x86\\snegopat.dll', 'sourceManifestSha256': '805717ad3532c13cb69dfd076681c57ea5574dac9d94f3e68b366091b5984581'}, 'controllerSha256': '04569dda63f46c12956518cec3e474d714fc25c14fc683c17d79f13606a4d681', 'databaseUpdatesAuthorized': False, 'detachedValuesAuthorized': False, 'exceptionObjectReadAuthorized': False, 'exceptionTypeMetadataReadAuthorized': True, 'expectedDatabaseSource': 1383504556, 'explicitWorkdayGrantAuthorized': True, 'externalAddinLoadingAuthorized': False, 'historicalReferencesReleaseAuthorized': False, 'idleQueueInvocationAuthorized': False, 'loadedDllRequiresTargetExitBeforeCleanup': True, 'manualAddRefReleaseAuthorized': False, 'maximumBodyBytes': 4194304, 'maximumCodePoints': 1048576, 'maximumEnumerations': 0, 'maximumFileOpensPerRequest': 2, 'maximumNativeCommands': 0, 'maximumPlainResourceBytes': 8388608, 'maximumRequests': 4095, 'maximumResidentControlCommands': 4096, 'maximumSessionSeconds': 28800, 'maximumStorageEntryOpensPerRequest': 4, 'maximumTypeEvents': 32, 'namedBridgeAuthorized': False, 'nativeDriverPins': {'NativeSdkCall.s': 'ab5c81990fe2838b366a3cde486e5b06c0650a1bc9bc9b85f43774eb47699374', 'NativeSdkGoldDiagnosis.c': 'e22ea0a88316fdeca21e70c3e6509619624cbe3203c05d8315a7e241830d6d0c', 'OwnedSdkDiagnosisHook.cs': '33fa5dc780b670dd28ff69b8bc29519c681a80eb44ade8ebb4f30d78155cb7f7', 'OwnedSdkReadonlyAttach.cs': '112007654805351263fee5c8f9c08d27d2a665eee8d9202f1d7bc0c45d1b62a4'}, 'nativeOwnedRamOutputAuthorized': True, 'nativeRamCarrierSha256': 'ff59538b81fd2266e3e9f62912d79c20fb1f30b932c650a6659de0e1855f5f25', 'newEnumerationAuthorized': False, 'newSessionsAuthorized': False, 'oneShot': True, 'ownedVectorDrainAuthorized': False, 'parentWriterOperationId': 'cec0c6449a7b43b8ba2435807df39888', 'positiveDialogAnswersAuthorized': False, 'probe': 'RUNNER_EDITORS_V247', 'probeSha256': 'aefd6e34b44fcdfa67eb4a7f245797f0f11d2eda24666a0e2cb12fc3d0731e2f', 'profileVersion': 234, 'protectedControlChannelAuthorized': True, 'readOnly': False, 'readScopeSha256': '6f9ee05e6d6bf98982cc7bc0d2db1a2b1f5a30e6dba9e431053165d51cce3f35', 'releaseResourcesAuthorized': False, 'repositoryMutationsAuthorized': False, 'residentProviderSha256': 'b9f43c59707aeecbd425c8be38aeb3dd6c14d9f94e14378743289dc2fa8eb71b', 'residentSdkFunctionCloseAuthorized': True, 'residentSdkReuseAuthorized': True, 'resultPropertyWritesAuthorized': False, 'retainedReferenceMaintenanceAuthorized': True, 'runtimeCacheMutationPossible': True, 'runtimeComparisonCreationAuthorized': False, 'runtimeDatabaseResourcesReadAuthorized': True, 'runtimeDialogHooksAuthorized': False, 'runtimeFrameBindingAuthorized': False, 'runtimeMetadataReadAuthorized': True, 'runtimeSupportInitializationAuthorized': False, 'runtimeSyntheticEventsAuthorized': False, 'runtimeUiMutationPossible': True, 'scopedRamPipeTransferAuthorized': True, 'scopedReferenceCallsAuthorized': True, 'sdkIdentity': {'coreBase': 1528102912, 'engineAddress': 54875296, 'engineTableRva': 2683268, 'guiThreadId': 8292, 'moduleAddress': 55559040, 'moduleCount': 1, 'moduleTableRva': 2679892, 'snegopatBase': 88408064}, 'sourceBodyReadsAuthorized': True, 'sourceWritesAuthorized': False, 'stockCompareAuthorized': False, 'syntheticPdfWriteAuthorized': False, 'testSha256': 'f230b1d69fdb8a69f617f264d9c8d3dfaf35046f066d77687de46c0e270bb998', 'typeRawOutput': False, 'updatePreviewControllerSha256': '29c98d25b76bce37c04b203b062c41b48bf0e3519acdf2c30e32a69c4f476530', 'updatePreviewProfile': 'WORKDAY_DATABASE_SAVED_COMMON_MODULES', 'updatePreviewScopeSha256': '5b958102e79a9d9cd0bfa7b4e9e214718a6823cd835bd99b267762ba8fc0ab4f', 'version': 234, 'workdayControllerSha256': '29c98d25b76bce37c04b203b062c41b48bf0e3519acdf2c30e32a69c4f476530', 'writerAuthorized': False}


def need(ok, code):
    if not ok:
        raise ValueError('WORKDAY_CLOSURE_' + code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


AUDITOR_SHA = digest(Path(__file__).read_bytes())
DEFAULT_REVISION = dict(controller=CONTROLLER_SHA, host=HOST_SHA, runtime=RUNTIME_SHA, worker=WORKER_SHA)
PRIOR_AUDITOR_SHA = '7e9cc7ba23edf1c73cf353bcde71b5bef3eb6d005ff61cd1a719d76a71b74bd2'
PRIOR_REVISION = dict(controller='aeee5d4e9da151e2e26ae4c41beb3385a27307b5ca4596b33879b234ef3bb825',
    host='1e7407de4dd739b22faa21a1c9cf73eb1865c613d7f2b45de37b5ca352e1c2bd',
    runtime=RUNTIME_SHA, worker='c0bd90754c83acd78c27d5bcbef0c3449c0d8da926c91c3f844e80b265af5a1a')
REVISION_FIELDS = dict(controller='workdayControllerSha256', host='workdayGuardianHostSha256',
                       runtime='workdayLifecycleSha256', worker='workdayGuardianWorkerSha256')


def canonical(row):
    return json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf8')


def token(value, size=32):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None and value != '0'*size


def exact(row, expected, code):
    need(type(row) is dict and all(k in row and _same(row[k], v) for k, v in expected.items()), code)


def _same(left, right):
    if type(left) is not type(right): return False
    if type(right) is dict: return left.keys() == right.keys() and all(_same(left[k], v) for k, v in right.items())
    if type(right) is list: return len(left) == len(right) and all(_same(x,y) for x,y in zip(left,right))
    return left == right


def _pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, 'DUPLICATE_KEY'); out[key] = value
    return out


def _plain(value, depth=0):
    need(depth <= 24, 'DEPTH')
    if type(value) is dict:
        need(len(value) <= 160 and all(type(k) is str and len(k) <= 128 for k in value), 'KEYS')
        for x in value.values(): _plain(x, depth+1)
    elif type(value) is list:
        need(len(value) <= 128, 'LIST')
        for x in value: _plain(x, depth+1)
    elif type(value) is str: need(len(value) <= 4096, 'STRING')
    elif type(value) is float: need(math.isfinite(value), 'FINITE')
    else: need(value is None or type(value) in (int, bool), 'TYPE')


def _json(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 1048576, 'JSON_BOUND')
    row = json.loads(raw.decode('utf8'), object_pairs_hook=_pairs,
                     parse_constant=lambda _: need(False, 'CONSTANT'))
    _plain(row); return row


def _pins():
    for name, pin in PINS.items(): need(digest((HERE/name).read_bytes()) == pin, 'DEPENDENCY_PIN')


_pins()
import workday_episode_evidence as evidence
import workday_ram_carrier as carrier
import resident_managed_carrier as managed
import sdk_compiler_section_identity as section
from native_mcp import workday_provider as provider, workday_wire as wire
SOURCE = (HERE/'NativeSafeCommonModuleRam.as').read_bytes()
IDENTITY = dict(processId=48936, birth='01dd5d0180299126', guiThreadId=8292,
                engineAddress=0x34554a0, moduleAddress=0x34fc380)


def _path(path, base):
    need(path.is_absolute() and path.resolve() == path and path.is_relative_to(base), 'PATH')
    for part in (path, *path.parents):
        if part == ROOT.parent: break
        info = part.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT, 'REPARSE')
    return path


def _bytes(path, base):
    _path(path, base); info = path.stat()
    need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 2097152, 'FILE_BOUND')
    raw = path.read_bytes(); need(0 < len(raw) <= 2097152, 'FILE_BOUND'); return raw


def load_rows(plan):
    need(type(plan) is dict and token(plan.get('operationId')), 'PLAN_OPERATION')
    op = plan['operationId']; out = ROOT/'build'/('designer-hot-v234-'+op); art = ROOT/'artifacts/designer-bridge'
    need(not (out/'unknown.json').exists(), 'UNKNOWN_PRESENT')
    rows = {'stage': {n: _bytes(out/n, out) for n in STAGE}, 'unknownPresent': False}
    for n in ('run', 'runtime', 'cleanup', 'owner-exit'):
        rows[n] = _bytes(art/('workday-guardian-'+n+'-'+op+'.json'), art)
    run = _json(rows['run']); need(token(run.get('acceptanceNonce')), 'SCOPE_NONCE')
    rows['scope'] = _bytes(art/('workday-guardian-scope-'+run['acceptanceNonce']+'.json'), art)
    _path(out/evidence.FILE_NAME, out)
    rows['records'] = _lines(out/evidence.FILE_NAME)
    return rows


def _lines(path):
    with path.open('rb') as stream:
        while True:
            line = stream.readline(evidence.MAX_RECORD_BYTES+2)
            if not line: break
            yield line


def _stage(rows, plan, revision):
    stage = rows['stage']; need(type(stage) is dict and set(stage) == set(STAGE), 'STAGE_SCHEMA')
    p = _json(stage['plan.json']); need(canonical(p) == canonical(plan), 'PRIOR_PLAN')
    policy = dict(PLAN_FIXED, workdayControllerSha256=revision['controller'], updatePreviewControllerSha256=revision['controller'])
    policy.pop('updatePreviewScopeSha256')  # Dynamic scope is joined to its raw bytes below.
    need(set(p) == set(PLAN_FIXED)|{'residentConfiguration','operationId','outputDirectory','goldLeaseOwner','goldLeaseBootstrapSha256'}, 'PLAN_SCHEMA')
    exact(p, policy, 'PLAN_PROFILE'); op = p['operationId']; need(token(op), 'OPERATION')
    need(p['outputDirectory'] == str(ROOT/'build'/('designer-hot-v234-'+op)), 'OUTPUT')
    need(token(p['goldLeaseOwner']) and token(p['goldLeaseBootstrapSha256'],64), 'HISTORICAL_LEASE_FORMAT')
    cfg = p['residentConfiguration']
    need(type(cfg) is dict and set(cfg) == provider._CONFIG_KEYS, 'CONFIG_SCHEMA')
    exact(cfg, dict(operationId=op, sessionId=p['context']['heldNonce']), 'CONFIG_JOIN')
    need(token(cfg['scopeSha256'], 64) and token(cfg['installNonce']) and token(cfg['serverBirth'], 16)
         and type(cfg['serverPid']) is int and 0 < cfg['serverPid'] < 2**32
         and type(cfg['installedAt']) in (int, float) and type(cfg['sessionValidUntil']) in (int, float)
         and 0 <= cfg['installedAt'] < cfg['sessionValidUntil'] <= cfg['installedAt']+28800, 'CONFIG_VALUES')
    need(cfg['armPath'] == (ROOT/'build'/('designer-hot-v234-'+op)/'resident-arm.bin').as_posix()
         and cfg['resultPath'] == (ROOT/'build'/('designer-hot-v234-'+op)/'resident-sdk-result.bin').as_posix()
         and type(cfg['pipePath']) is str and re.fullmatch(r'\\\\\.\\pipe\\AH1C-RAM-[0-9a-f]{32}', cfg['pipePath']), 'CONFIG_PATH')
    b = _json(stage['build-proof.json'])
    exact(b, dict(version=233, passed=True, compileExitCode=0, carrierCompileExitCode=0,
        carrierPreflightOnly=True, carrierAssemblyExecuted=False, goldStarted=False, nativeInjectionPerformed=False,
        planSha256=digest(canonical(p)), compilerSha256='11b86934bb2833f57fa0453a605ca342aee9207e193faea9b973baa2b2b4c35b',
        carrierCompilerSha256='012e8cd8adff0c439a90ffd22c0e33efeb6fbc8cf660d52b4858d310649382fa'), 'BUILD')
    need(type(b['derivedSha256']) is dict and set(b['derivedSha256']) == set(FILES), 'BUILD_FILES')
    for name in FILES: need(digest(stage[name]) == b['derivedSha256'][name], 'DERIVED_PIN')
    need(digest(stage['Continuation.dll']) == b['librarySha256'] and
         digest(stage['OwnedCarrierPreflight.dll']) == b['carrierAssemblySha256'], 'BINARY_PIN')
    header = stage['sdk_probe_params.h'].decode('utf8')
    for key, value in (('TARGET_PID',48936), ('BIRTH_LOW',0x80299126), ('BIRTH_HIGH',0x1dd5d01),
                       ('ENGINE_ADDRESS',0x34554a0), ('MODULE_ADDRESS',0x34fc380)):
        found = re.findall(r'^#define AH_SDK_'+key+r' (0x[0-9a-fA-F]+|[0-9]+)U$', header, re.M)
        need(len(found) == 1 and int(found[0], 0) == value, 'HEADER_IDENTITY')
    need('#define AH_SDK_RESULT_FILE L'+json.dumps((ROOT/'build'/('designer-hot-v234-'+op)/'sdk-result.bin').as_posix()) in header, 'HEADER_RESULT')
    lines = [x for x in header.splitlines() if x.startswith(section.PREFIX)]
    need(len(lines) == 1 and digest(json.loads(lines[0][len(section.PREFIX):]).encode('utf8')) == p['admittedSourceSha256'], 'ADMITTED_SOURCE')
    files = dict(managed.render(cfg, IDENTITY), **{'Continuation.c': carrier.render(SOURCE, configuration=cfg, identity=IDENTITY), 'sdk_probe_params.h': stage['sdk_probe_params.h']})
    need(files['Continuation.c'].count(carrier.SECTION_ANCHOR.encode()) == 1, 'SECTION_ANCHOR')
    files['Continuation.c'] = files['Continuation.c'].replace(carrier.SECTION_ANCHOR.encode(), section.ANCHOR, 1)
    files, _ = section.with_section_identity(files, operation_kind='WORKDAY_SAVED_RAM', operation_id=op)
    need(all(files[n] == stage[n] for n in FILES), 'DERIVED_RENDER')
    return p, cfg, b


def _records(lines, p, summary):
    obj = object.__new__(provider.WorkdayResidentProvider)
    obj.configuration = p['residentConfiguration']; obj.identity = IDENTITY
    obj._sequence = obj._contexts = 0; obj._worker = None; obj._classify_epoch = provider._classifier()
    state = evidence._state(); sha = hashlib.sha256(); size = metadata = 0
    generation = 0; expiry = None; revision = 0; sampled = obj.configuration['installedAt']; targets = {}
    # Match the native ring exactly: sequence never resets, but evicted nonces
    # may be reused by a NEW current-sequence command after 256 accepted frames.
    nonces = deque(maxlen=256)
    for raw in lines:
        need(type(raw) is bytes and 1 < len(raw) <= evidence.MAX_RECORD_BYTES+1 and raw.endswith(b'\n'), 'JOURNAL_LINE')
        size += len(raw); metadata += len(raw)-1
        need(size <= evidence.MAX_FILE_BYTES and metadata <= evidence.MAX_METADATA_BYTES and obj._sequence < 4095, 'JOURNAL_BOUND')
        row = _json(raw[:-1]); normalized = evidence._record(row, p['operationId'], state)
        need(evidence._encode(normalized)+b'\n' == raw, 'JOURNAL_CANONICAL'); sha.update(raw)
        q, proof = row['requestMetadata'], row['nativeProof']; close = q['opcode'] == wire.CLOSE
        need(q['opcode'] == (wire.CLOSE if close else (wire.GUARD if q['sequence'] % 2 else wire.READ)), 'ORDER')
        need(q['requestId'] not in nonces and token(q['requestId']), 'NONCE'); nonces.append(q['requestId'])
        need(sampled <= q['issuedAt'] < q['requestValidUntil'] <= q['issuedAt']+5
             and proof['sessionId'] == obj.configuration['sessionId'] and proof['processId'] == IDENTITY['processId'], 'REQUEST_IDENTITY_TIME')
        sampled = proof['sampledAt']
        if not close:
            need(q['requestValidUntil'] <= q['bindingValidUntil'] <= min(q['issuedAt']+60, obj.configuration['sessionValidUntil']), 'BINDING_TIME')
            if q['generation'] != generation:
                need(q['opcode'] == wire.GUARD and q['generation'] > generation, 'GENERATION'); revision = 0
            else: need(q['bindingValidUntil'] == expiry, 'GENERATION_EXPIRY')
            generation, expiry = q['generation'], q['bindingValidUntil']
            r = proof['guardState'] if q['opcode'] == wire.GUARD else row['snapshotReceipt']
            exact(r['binding'], dict(root_uuid=provider.ROOT_UUID, session_id=obj.configuration['sessionId'],
                  birth=IDENTITY['birth'], process_id=48936, source_domain='database_saved', generation=generation, valid_until=expiry), 'SOURCE_BINDING')
            exact(r['target'], dict(property_uuid=wire.MODULE_PROPERTY), 'MODULE_PROPERTY')
            if q['opcode'] == wire.READ:
                revision += 1; need(q['revision'] == revision, 'REVISION')
                exact(r, dict(source_writes=0, helper_calls=0, configuration_saves=0, database_updates=0, repository_mutations=0,
                    identity_verified=True, schema_verified=True, repeated_read_verified=True, dirty_before='clean', dirty_after='clean', decoder_profile='FORMAT15_RAM'), 'SOURCE_CLOSURE')
                signature = tuple(proof[k] for k in ('sourceSha256', 'savedResourceSha256', 'bodyBytes', 'storedBytes', 'codePoints', 'crlfCount', 'bomPresent', 'endsLf'))
                need(targets.get(q['targetUuidHex'], signature) == signature, 'SOURCE_CHANGED'); targets[q['targetUuidHex']] = signature
        elif generation:
            need(q['generation'] == generation and q['bindingValidUntil'] == expiry, 'CLOSE_BINDING')
        contexts, worker = obj._native(SimpleNamespace(status=proof['status'], proof=proof, epoch=row['epoch']), SimpleNamespace(opcode=q['opcode']))
        obj._contexts, obj._worker, obj._sequence = contexts, worker, q['sequence']
    result = evidence._summary(p['operationId'], state, sha.hexdigest(), size, metadata)
    need(_same(result, summary) and result['count'] % 2 == 1 and result['guardCount'] == result['readCount'] <= 2047, 'JOURNAL_SUMMARY')
    return result


def validate_closed(rows, plan, *, approved_revision=None):
    """Pure metadata replay; rows contain fixed technical bytes + iterable lines."""
    need(type(rows) is dict and rows.get('unknownPresent') is False, 'UNKNOWN_OR_MISSING')
    revision = DEFAULT_REVISION if approved_revision is None else approved_revision
    need(type(revision) is dict and revision.keys() == DEFAULT_REVISION.keys()
         and all(token(v, 64) for v in revision.values()), 'APPROVED_REVISION')
    p, cfg, build = _stage(rows, plan, revision); op = p['operationId']; stage = rows['stage']
    scope, run, runtime, cleanup, owner = (_json(rows[k]) for k in ('scope', 'run', 'runtime', 'cleanup', 'owner-exit'))
    policy = dict(SCOPE_FIXED)
    for name, field in REVISION_FIELDS.items(): policy[field] = revision[name]
    dynamic = {'acceptanceNonce', 'priorGuardianOperationId', 'priorGuardianPlanSha256'}
    if approved_revision is not None:
        auditor = scope.get('workdayClosureAuditSha256')
        # The prior closed hot revision was reviewed with exactly B7e9. Do not
        # make that historical scope claim a new hash or permit it for others.
        need(auditor == AUDITOR_SHA or (_same(revision, PRIOR_REVISION) and auditor == PRIOR_AUDITOR_SHA), 'AUDITOR_REVISION')
        policy['workdayClosureAuditSha256'] = auditor
        if 'approvedPriorWorkdayPlans' in scope:
            plans = scope['approvedPriorWorkdayPlans']
            need(type(plans) is dict and len(plans) <= 128
                 and all(token(k) and token(v,64) for k,v in plans.items()), 'PRIOR_PLAN_MAP')
            policy['approvedPriorWorkdayPlans'] = plans
    need(set(scope) == set(policy)|dynamic and token(scope['acceptanceNonce'])
         and token(scope['priorGuardianOperationId']) and token(scope['priorGuardianPlanSha256'], 64), 'SCOPE_SCHEMA')
    exact(scope, policy, 'FROZEN_SCOPE')
    scope_sha, plan_sha, run_sha = digest(rows['scope']), digest(canonical(p)), digest(rows['run'])
    need(scope_sha == cfg['scopeSha256'] == p['updatePreviewScopeSha256'], 'SCOPE_JOIN')
    exact(run, dict(scope, kind='ROOT_WORKDAY_SAVED_RAM_RUN', planSha256=plan_sha, buildSha256=digest(canonical(build)),
                    scopeSha256=scope_sha, admittedSourceSha256=p['admittedSourceSha256'], nativeRamCarrierSha256=p['nativeRamCarrierSha256'], residentProviderSha256=p['residentProviderSha256']), 'RUN')
    exact(_json(stage['intent.json']), dict(kind='WORKDAY_SAVED_RAM_INTENT', operationId=op, planSha256=plan_sha,
        scopeSha256=scope_sha, rootRunSha256=run_sha, applicationWrites=0, configurationExports=0, configurationImports=0, repositoryMutations=0), 'INTENT')
    result = _json(stage['result.json'])
    exact(result, dict(kind='WORKDAY_SAVED_RAM_SESSION_RESULT', version=234, operationId=op, status='WORKDAY_SAVED_RAM_CLOSED',
        knownTerminal=True, retryAuthorized=False, sdkResult=0, targetIdentityVerified=True, hookWorkersReleased=True,
        nativeInjectionPerformed=True, planSha256=plan_sha, permanentMcpBindingVerified=False, sourceBodyFilesCreated=0,
        configurationExports=0, configurationImports=0, configurationSaves=0, databaseUpdates=0, repositoryMutations=0), 'RESULT')
    exact(_json(stage['resident-host-result.json']), dict(kind='RESIDENT_MANAGED_TERMINAL', operationId=op,
        knownTerminal=True, writerAuthorized=False, threadId=8292, sdkResult=0, hookWorkersReleased=True), 'MANAGED')
    exact(_json(stage['resident-host-ready.json']), dict(kind='RESIDENT_MANAGED_READY', operationId=op,
        processId=48936, threadId=8292, workerExpectedAlive=True, nativeSourceBindingVerified=False), 'READY')
    hostid = _json(stage['host-identity.json'])
    need(type(hostid.get('processId')) is int and 0 < hostid['processId'] < 2**32 and token(hostid.get('birth'),16), 'MANAGED_IDENTITY')
    exact(hostid, dict(image=r'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe',
          imageSha256='68b9b6ba72c89599da0b7395363e941988be1328f239eb123f45b523770d47b5'), 'MANAGED_IMAGE')
    need(stage['resident-sdk-result.bin'] == bytes(4), 'RAW_SDK')
    exact(runtime, dict(kind='WORKDAY_GUARDIAN_DAEMON_EPISODE', operationId=op, passed=True, planSha256=plan_sha,
        scopeSha256=scope_sha, buildSha256=digest(canonical(build)), rootRunSha256=run_sha, hostSourceSha256=revision['host'],
        daemonRuntimeSha256=revision['runtime'], workerSourceSha256=revision['worker'], ownerPid=cfg['serverPid'], ownerBirth=cfg['serverBirth'],
        managedHostExitCode=0, channelClosed=True, channelOwnerThreadAlive=False, permanentRegistrationVerified=False,
        configurationExports=0, configurationImports=0, configurationSaves=0, databaseUpdates=0, repositoryMutations=0,
        businessInvocations=0, rawSourceFramesPersisted=False, sourceBodyFilesCreated=0, rootResult=result), 'RUNTIME')
    life = runtime['lifecycle']; exact(life, dict(state='CLOSED', nativeCloseAttempts=1), 'LIFECYCLE')
    need(life.get('reason') in ('EXPLICIT_STOP','TIME_BUDGET','COMMAND_BUDGET','OUTER_RPC_BUDGET','RECEIPT_BUDGET','CLIENT_CLOSE'), 'REASON')
    need(life.get('admissionClosedBeforeNativeClose') is (life['reason'] != 'CLIENT_CLOSE'), 'ADMISSION_ORDER')
    exact(runtime['report'], dict(kind='WORKDAY_GUARDIAN_DAEMON_CLOSURE', operationId=op, passed=True,
        finalizerCalls=1, serviceState='STOPPED', sourceBodyIncluded=False, sourceFrameIncluded=False,
        rootResult=result, receiptJournal=runtime['receiptJournal']), 'REPORT')
    summary = _records(rows['records'], p, runtime['receiptJournal'])
    exact(cleanup, dict(kind='WORKDAY_GUARDIAN_LOCAL_CLEANUP_BEFORE_OWNER_EXIT', operationId=op,
        ownerPid=cfg['serverPid'], ownerBirth=cfg['serverBirth'], endpointRemoved=True, nativePhase='CLOSED',
        managedHostExitCode=0, finalizerCalls=1, remainingTasksBeforeClose=0, runnerClosed=True,
        loadedNativeDllUnloaded=False, originalRamOwnerReleased=False, sourceBodyFilesCreated=0), 'CLEANUP')
    need(token(cleanup.get('endpointCipherSha256'),64), 'CIPHER_HASH')
    exact(owner, dict(kind='WORKDAY_GUARDIAN_OWNER_EXIT', operationId=op, ownerPid=cfg['serverPid'], ownerBirth=cfg['serverBirth'],
        runtimeSha256=digest(rows['runtime']), cleanupSha256=digest(rows['cleanup']), independentExecTerminal=True,
        independentExecExitCode=0, forcedTerminationPerformed=False, freshKernelOpenProcessSucceeded=False,
        freshKernelOpenProcessError=87, previousOwnerIdentityAbsent=True, loadedNativeDllUnloaded=False, originalRamOwnerReleased=False), 'OWNER_EXIT_RECORD')
    return dict(classification='WORKDAY_GUARDIAN_RESOURCES_CLOSED', resourcesClosed=True, operationId=op,
        planSha256=plan_sha, ownerPid=cfg['serverPid'], ownerBirth=cfg['serverBirth'], pairs=summary['readCount'],
        records=summary['count'], priorOwnerProcessId=cfg['serverPid'], priorOwnerBirth=cfg['serverBirth'],
        freshOwnerExitCheckRequired=True, freshPriorOwnerExitCheckRequired=True, newScopeRequired=True,
        currentIdentityVerified=False, currentLeaseVerified=False, sameOwnerReuseAuthorized=False,
        dispatchAuthorized=False, retryAuthorized=False, loadedNativeDllUnloaded=False,
        originalRamOwnerReleased=False, fullRawTranscriptVerified=False)


def audit_closed(plan, *, approved_revision=None):
    """Read only exact derived artifacts; caller must separately check NOW."""
    failed = False; result = None
    try:
        _pins(); rows = load_rows(plan)
        runtime = _json(rows['runtime']); out = ROOT/'build'/('designer-hot-v234-'+plan['operationId'])
        evidence.verify_receipts(out, plan['operationId'], runtime['receiptJournal'])
        result = validate_closed(rows, plan, approved_revision=approved_revision)
    except Exception:
        failed = True
    if failed: raise ValueError('WORKDAY_CLOSURE_UNPROVEN') from None
    return result
