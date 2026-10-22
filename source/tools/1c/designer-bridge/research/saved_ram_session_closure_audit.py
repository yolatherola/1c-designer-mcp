"""Exact historical120b RAM-read closure, without native I/O or new authority.

Reads fixed technical/tool files only. Never reconnects, renews a lease, reads a
body, rewrites success/UNKNOWN, releases a DLL, or grants dispatch authority.
"""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[4]
OPERATION = '120b286802e1465094e1252a3b3ab5af'
PLAN_SHA = '7810941d0f829f7a9e02975c908a67f207ee022e8a90943c7f184d306d452588'
SCOPE_SHA = 'b9238480d2048b5c3c67a4684d7a12334fc082ae08856f2157565eaefa674d8e'
MANIFEST = ROOT / 'artifacts/designer-bridge/saved-ram-session-closed-120b286802e1465094e1252a3b3ab5af-manifest.json'
MANIFEST_SHA = '37060ccf5164b1a256fca358dffb87e3afd343c57a5866feaecd996b1e2a9ed4'
RAW_HASHSET_SHA = 'd93a4ce0ba108b7d7e98404a4e770de337287a1770b46341054c3f077d9d3a0e'
STAGE = ROOT / ('build/designer-hot-v233-' + OPERATION)
BODY_HASHES = ('cc5ad44ccb49b9317009524fc2a7e13f842891752aea5bbadf334bc22c677ecb',
               'e51179b3e2ad0511fbf7dc345e7b544810eca253f195eb1861500f0978e0236b')
RESOURCE_HASHES = ('00ab097f6828f9bd79bc7c3a298196b512944a621af0f2a225f3b7d65ef827bd',
                   '04e9fe8645eaab179bfd2cc0a2209c21854f1c7ac6a07e8ace68faa9b9dfa54d')
SOURCE_SHA = 'df1711a1f39c84c38f87e844eb6c218e80ef638d6f55a3bb45aee23db0f36319'
CONTROLLER_SHA = '6e3d115c9b3423c930c903707f9f548ce7e61fab4e1ce142ee8061149b4293fe'
CARRIER_SHA = 'c75ca413a26e5cccb6f4ff68f9a3d4e88ae5b9b960560e408afa0b606cdf1301'
NATIVE_SHAS = ('a38f4473b5897c95be54f76d2070878d6b046cdf5e1ec7f03176a02aabcff82a',
               'dbfa987d862ac19e35d2c716360d8b2fb7c871eaedf90604aeee1e0987411ffc')
EPOCH_SHA = '352155f06c88414c3045c25937a329689969bc6f450639bcaa2ad28558e99d04'
EXPECTED_ROWS = {'raw_hashes', 'scope', 'run', 'claim', 'baseline'} | {
    'stage/'+name for name in ('plan.json','intent.json','result.json','build-proof.json',
                               'second-carrier-build-proof.json')} | {
    'stage/slot'+str(i)+'-'+name for i in (0,1) for name in
    ('native.json','epoch.json','result.json','intent.json','host-result.json',
     'host-identity.json','sdk-result.bin','arm.bin','callback.bin')}


def need(ok, code):
    if not ok:
        raise ValueError('SAVED_RAM_CLOSURE_' + code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def verified_bytes(raw, expected_sha, maximum):
    """Pure raw-pin guard; ordinary file bytes are not normalized before hashing."""
    need(type(raw) is bytes and 0 < len(raw) <= maximum and digest(raw) == expected_sha, 'RAW_PIN')
    return raw


def _manifest():
    raw = verified_bytes(MANIFEST.read_bytes(), MANIFEST_SHA, 16384)
    value = json.loads(raw)
    need(value['kind'] == 'SAVED_RAM_CLOSED_SESSION_FIXED_MANIFEST'
         and value['operationId'] == OPERATION and len(value['files']) == 40, 'MANIFEST')
    return value['files']


def load_rows():
    """Load only the fixed pinned technical snapshot. No caller-provided paths."""
    files = _manifest()
    rows = {'raw_hashes': {}}
    for key, spec in files.items():
        path = ROOT / spec['path']
        need(path.resolve().is_relative_to(ROOT.resolve()), 'FIXED_PATH')
        raw = verified_bytes(path.read_bytes(), spec['sha256'], spec['bytes'])
        need(len(raw) == spec['bytes'], 'FILE_LENGTH')
        rows['raw_hashes'][key] = digest(raw)
        if path.suffix == '.json':
            rows[key] = json.loads(raw)
        elif key.endswith(('-sdk-result.bin', '-arm.bin', '-callback.bin')):
            rows[key] = raw
    return rows


def exact(row, expected, code):
    need(type(row) is dict and all(type(row.get(key)) is type(value) and row[key] == value
                                   for key, value in expected.items()), code)


def validate_closed(rows, prior):
    """Validate historical closure metadata only; never admits a current command."""
    need(type(prior) is dict and digest(canonical(prior)) == PLAN_SHA, 'PRIOR_PLAN')
    need(type(rows) is dict and set(rows) == EXPECTED_ROWS
         and type(rows.get('raw_hashes')) is dict, 'ROWS')
    hashes = rows['raw_hashes']
    need(digest(canonical(hashes)) == RAW_HASHSET_SHA, 'RAW_HASHSET')
    p = rows['stage/plan.json']
    need(type(p) is dict and canonical(p) == canonical(prior), 'PLAN_JOIN')
    exact(p, dict(operationId=OPERATION, updatePreviewScopeSha256=SCOPE_SHA,
        actualSourceSha256=SOURCE_SHA, updatePreviewControllerSha256=CONTROLLER_SHA,
        nativeRamCarrierSha256=CARRIER_SHA, sourceWritesAuthorized=False,
        configurationSavesAuthorized=False, databaseUpdatesAuthorized=False,
        repositoryMutationsAuthorized=False, maximumRequests=2), 'PLAN_AUTHORITY')
    common = dict(operationId=OPERATION, planSha256=PLAN_SHA)
    exact(rows['stage/intent.json'], common | dict(scopeSha256=SCOPE_SHA,
        applicationWrites=0, configurationExports=0, configurationImports=0, repositoryMutations=0), 'INTENT')
    exact(rows['run'], dict(kind='ROOT_SAFE_SAVED_RAM_RUN', passed=True,
        planSha256=PLAN_SHA, scopeSha256=SCOPE_SHA, actualSourceSha256=SOURCE_SHA,
        nativeRamCarrierSha256=CARRIER_SHA, maximumRequests=2, sourceWritesAuthorized=False,
        configurationSavesAuthorized=False, databaseUpdatesAuthorized=False,
        repositoryMutationsAuthorized=False), 'ROOT_RUN')
    exact(rows['scope'], dict(kind='ROOT_SAFE_SAVED_RAM_SCOPE', passed=True,
        actualSourceSha256=SOURCE_SHA, maximumRequests=2, sourceWritesAuthorized=False,
        configurationSavesAuthorized=False, databaseUpdatesAuthorized=False,
        repositoryMutationsAuthorized=False), 'ROOT_SCOPE')
    exact(rows['claim'], dict(kind='SAFE_SAVED_RAM_CLAIM', operationId=OPERATION,
        scopeSha256=SCOPE_SHA, controllerSha256=CONTROLLER_SHA, actualSourceSha256=SOURCE_SHA,
        writerOperationId='cec0c6449a7b43b8ba2435807df39888',
        packetSha256='293269103842d21a288ce068ced7fafc65a8a090e381d4aea560121cbf692dcf',
        pid=48936, birth='01dd5d0180299126', sessionNonce='013dc010bd784e859b1e3ba4def25f3c'), 'CLAIM')
    build, second = rows['stage/build-proof.json'], rows['stage/second-carrier-build-proof.json']
    exact(build, dict(passed=True, compileExitCode=0, carrierCompileExitCode=0,
        planSha256=PLAN_SHA, nativeInjectionPerformed=False, goldStarted=False), 'BUILD')
    exact(second, dict(passed=True, compileExitCode=0, planSha256=PLAN_SHA,
        assemblyExecuted=False), 'SECOND_BUILD')
    need(digest(canonical(build)) == rows['run']['buildSha256']
         and digest(canonical(second)) == rows['run']['secondBuildSha256'], 'BUILD_JOIN')
    need(build['librarySha256'] == hashes['stage/Continuation.dll']
         and build['carrierAssemblySha256'] == hashes['stage/OwnedCarrierPreflight.dll']
         and second['assemblySha256'] == hashes['stage/OwnedCarrierSlot1Preflight.dll'], 'BINARY_JOIN')
    need(len(build['derivedSha256']) == 7 and all(hashes['stage/'+name] == pin
         for name, pin in build['derivedSha256'].items()), 'DERIVED_JOIN')
    result = rows['stage/result.json']
    exact(result, dict(kind='SAFE_SAVED_RAM_SESSION_RESULT', operationId=OPERATION,
        status='TWO_NATIVE_DATABASE_SAVED_MODULES_RAM_VERIFIED', knownTerminal=True,
        nativeSavedRamReadVerified=True, sameLibraryAndFunctionReused=True,
        sdkCompilations=1, sdkContexts=2, permanentMcpBindingVerified=False,
        sourceBodyFilesCreated=0, databaseUpdates=0, repositoryMutations=0,
        retryAuthorized=False), 'SESSION_RESULT')
    slots = p['nativeRamSlots']
    need(type(slots) is list and len(slots) == 2 and slots[0]['requestId'] != slots[1]['requestId']
         and slots[0]['pipePath'] != slots[1]['pipePath'], 'DISTINCT_JOBS')
    baseline = rows['baseline']
    exact(baseline, dict(kind='DATABASE_SAVED_RESOURCES_FAST_GATE',
        operationId='7d40505fa0eb4ffab7b6a34467a05446',
        status='DATABASE_RESOURCE_FAST_CANDIDATES_VERIFIED', stablePasses=2,
        configurationSourceDomain='DATABASE', databaseManagerAddress=100051712,
        databaseSourceAddress=1383504556, pendingFileReference=False), 'DB_BASELINE')
    for i, slot in enumerate(slots):
        prefix = 'stage/slot'+str(i)+'-'
        native, epoch, job = (rows[prefix+key] for key in ('native.json', 'epoch.json', 'result.json'))
        exact(native, dict(kind='NATIVE_RAM_CARRIER', operationId=OPERATION,
            scopeSha256=SCOPE_SHA, requestId=slot['requestId'], job=i, processId=48936,
            guiThreadId=8292, sdkRc=0, terminalRc=0, compileCount=1, contextCount=i+1,
            functionRetained=i == 0, nativeStatus=1, nativeReason=0, pendingReference=0,
            typedCleared=1, nativeException=0, passes=2, propertyReads=2, fileOpens=2,
            adoptedFiles=2, beforeClean=1, afterClean=1, prefixPreserved=1,
            databaseRoot=1383504556, databaseManager=100051712,
            bodyBytes=(104266,39746)[i], storedBytes=(105037,40517)[i],
            codePoints=(60244,22365)[i], crlfCount=(1340,534)[i], bomPresent=1, endsLf=1,
            sourceSha256=BODY_HASHES[i], savedResourceSha256=RESOURCE_HASHES[i]), 'NATIVE_COUNTS')
        need(all(native.get(key) is True for key in ('contextCleared','handlerRemoved',
            'epochClean','hookRemoved','peerVerified','pipeClosed','drainCompleted',
            'buffersFreed','readyVerified','nativeEnvelopeValid')), 'NATIVE_CLOSURE')
        need(type(native.get('workerThreadId')) is int and native['workerThreadId'] > 0
             and native['workerThreadId'] != 8292, 'WORKER')
        need(type(native.get('sampledAt')) is float and slot['issuedAt'] <= native['sampledAt'] <= slot['validUntil']
             and slot['validUntil']-slot['issuedAt'] == 60 and slot['revision'] == i+1, 'PAST_FRESHNESS')
        exact(epoch, dict(kind='NATIVE_RAM_SDK_CHAIN_CPP_EXCEPTION_TYPE_EPOCH',
            phase='SDK_CHAIN_RETURNED', operationId=OPERATION, scopeSha256=SCOPE_SHA,
            processId=48936, executeThreadId=8292, epochCoverage='synchronous_gui_sdk_chain',
            sdkExecuteRc=0, sdkChainRc=0, cppThrows=0, otherExceptions=0,
            unknownCppThrows=0, listStreamCompatibleThrows=0, typeEventCount=0,
            cppThrowsExecuteThread=0, cppThrowsOtherThreads=0,
            otherExceptionsExecuteThread=0, otherExceptionsOtherThreads=0,
            decodedCppThrows=0, maximumTypeEvents=32, maximumCatchableTypes=16,
            maximumNameBytes=96, exceptionObjectRead=False,
            typeEventOverflow=False, counterOverflow=False, typeDecoderReentry=False,
            selfReferenceRetained=True, dllMustRemainLoadedUntilProcessExit=True), 'EPOCH')
        need(all(epoch.get(key) is True for key in ('handlerRegistered','handlerRemoved',
            'executeEntered','executeReturned','sdkChainEntered','sdkChainReturned','sdkChainComplete'))
            and type(epoch.get('typeEvents')) is list and not epoch['typeEvents'], 'EPOCH_CLOSURE')
        exact(rows[prefix+'host-result.json'], dict(nativeRamJob=i, threadId=8292,
            sdkResult=0, writerAuthorized=False, knownTerminal=True, hookWorkersReleased=True), 'HOST')
        exact(rows[prefix+'intent.json'], common | dict(job=i, requestId=slot['requestId'],
            rootRunSha256=rows['stage/intent.json']['rootRunSha256']), 'JOB_INTENT')
        exact(job, common | dict(kind='SAFE_SAVED_RAM_JOB_RESULT', job=i,
            status='NATIVE_DATABASE_SAVED_MODULE_RAM_VERIFIED', requestId=slot['requestId'],
            knownTerminal=True, nativeSavedRamReadVerified=True, hookWorkersReleased=True,
            sdkResult=0, retryAuthorized=False, permanentMcpBindingVerified=False,
            bodyBytes=(104266,39746)[i],
            sourceBodyFilesCreated=0, applicationWrites=0, configurationExports=0,
            configurationImports=0, configurationSaves=0, databaseUpdates=0, repositoryMutations=0,
            sourceSha256=BODY_HASHES[i], savedResourceSha256=RESOURCE_HASHES[i],
            nativeProofSha256=NATIVE_SHAS[i], epochSha256=EPOCH_SHA), 'JOB_RESULT')
        need(rows[prefix+'sdk-result.bin'] == struct.pack('<I',0)
             and rows[prefix+'arm.bin'] == bytes(8)
             and rows[prefix+'callback.bin'] == struct.pack('<6I',48936,8292,0,33746,8292,1), 'SDK_BINARY')
        base = baseline['targets'][i+1]
        need(base['objectId'] == slot['target']['object_uuid']
             and base['propertyId'] == slot['target']['property_uuid']
             and base['plainSha256'] == native['savedResourceSha256']
             and base['textRawSha256'] == native['sourceSha256'], 'BASELINE_JOIN')
    return dict(classification='SAVED_MODULE_READ_SESSION_RESOURCES_CLOSED',
        operationId=OPERATION, resourcesClosed=True, dllSelfReferenceRetained=True,
        dllUnloadAuthorized=False, originalRamOwnerReleaseAuthorized=False,
        sourceBodiesRead=False, currentIdentityVerified=False, currentLeaseVerified=False,
        newScopeRequired=True, dispatchAuthorized=False, retryAuthorized=False,
        permanentMcpBindingVerified=False, databaseUpdateAuthorized=False)


def audit_closed(priorplan):
    """Historical exception only; caller still needs fresh PID/birth/lease/new scope."""
    need(not (STAGE/'unknown.json').exists(), 'UNKNOWN_PRESENT')
    return validate_closed(load_rows(), priorplan)
