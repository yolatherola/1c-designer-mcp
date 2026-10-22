"""Exact offline closure of one refused metadata read, never retry admission.

Raw mdPropVal return integers are recorded observations, not proof that a value
changed. This audit reads technical files only; it never checks a process/VM,
acquires a lease, alters UNKNOWN, releases references, or creates a result.
Future private pending-operation recognition must separately check fresh
identity and the current owned route lease before using this classification.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
OP = 'cbc495321b8e4804ba48d129d4bb5316'
CLASSIFICATION = 'REFUSED_METADATA_READ_RESOURCES_CLOSED'
PLAN_SHA = '7be407a8dc7d3b5362b5e0f5d38bfa392e7e3149968ec6cf28027464b691a708'
BUILD_SHA = '424527be6f0f70a4b33913af1ff03413ab51633e2558d8e8bb34d4e4565d2c90'
SCOPE_SHA = '5cd8138735304d1a28c0bcc816cb13ce6989a45157bb82c306ccd0c8ffc37681'
SOURCE_SHA = 'b7984b00758495f1ba0ef5c0cc9e42d64eb5f67b885793e94ad468376fdcad3b'
CONTROLLER_SHA = '8d10da05e34553e77e11e090e473823d820417711be46f02acdfb53b317acd5f'
SOURCE_PINS = {
    'tools/1c/designer-bridge/research/NativeDatabaseStartupMetadata.as': SOURCE_SHA,
    'tools/1c/designer-bridge/research/database_startup_metadata_operation.py': CONTROLLER_SHA,
    'tools/1c/designer-bridge/research/comparison_cpp_exception_type_epoch.py': 'e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4',
    'artifacts/designer-bridge/database-startup-metadata-scope-286976bc636c4c76bb623a7c4e91a853.json': SCOPE_SHA,
    'artifacts/designer-bridge/database-startup-metadata-cold-check-5379046ee32548669497653d2a68bcc7.json': '9d50c2c8c72072f6aa900daa66f605f47b1a3105c584990d51a0b396a12fb40e',
}
PINS = {
    'plan.json': '77b666d4a673818f9e764153a0a776954596c2720399ea284ebf93959a6fa3d7',
    'build-proof.json': 'eff31c16241d81d5210d5b301b87b3ff79de620d83dae2301f3f54422974226e',
    'unknown.json': '342976a313d5d2b631788371dd350a6c29c120ff5dd924a5441b6d5a58f3cffc',
    'intent.json': '76b71e3588cbb65d66b0f90b8faad8c5dc3bb64f0dc39c9bc38490c49e960ce0',
    'host-identity.json': '08885cf4c8c413dcb29088533546c4dbc5dd478077d8f87906ae59fb609115cf',
    'host-result.json': '5b1b8a459e14859372e037b642b435c26f209aecfd7b3c13ad37be9b481217c5',
    'sdk-receipt.json': '1e0d96995c6c7ab1cc11cd7477c5bfdbecb0d4cfe16dd7636eabda07713815d3',
    'database-startup-metadata-proof.json': '7121e69da75dcd443cba07d7a30df3733ab17cc3560fb64edf5fbb66b9ec012f',
    'database-startup-metadata-intent.json': '5ebb3c413ccc27635a1625b5c0175e8257113d73972d2153afad9f0138a15634',
    'cpp-exception-type-epoch.json': 'afa4887495e7a16e27503e1ea34fbace72189b9c6a5780ac4b8b505e7008bb89',
}
ZERO_NATIVE = ('nativeCommands', 'sourceWrites', 'configurationSaves', 'databaseUpdates', 'repositoryMutations',
               'moduleTextReads', 'storageOpens', 'newSessions', 'patientReads', 'businessCalls')
FALSE_AUTH = ('writerAuthorized', 'sourceWritesAuthorized', 'configurationSavesAuthorized', 'databaseUpdatesAuthorized',
              'repositoryMutationsAuthorized', 'businessCallsAuthorized', 'applicationDataReadAuthorized',
              'newSessionsAuthorized', 'sourceBodyReadsAuthorized', 'commandDispatchAuthorized')
PRINT_ID = '176e2552-fd8b-4823-afc0-d17431f2fb7b'
REG_ID = '28ecdfc7-083e-4082-b272-efbf7152de5c'
BOOL_PROPERTIES = ('d12660a6-7298-4ae2-a332-b95a6459a280', '6275a02e-96f0-4347-975a-2d661e6a0675',
                   '7dbb2bc7-6bae-4b81-91cb-681317272a0b', 'c474bab9-d13a-4fbd-bfb0-9214d6dc2fde',
                   '334033a1-6bda-4dba-bc6d-0095d1b66f0b')


def need(ok, code):
    if not ok:
        raise ValueError('STARTUP_REFUSAL_' + code)


def canonical(row):
    return json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def counts(row, expected, code):
    need(all(type(row.get(k)) is int and row[k] == value for k, value in expected.items()), code)


def flags(row, *, yes=(), no=(), code='FLAGS'):
    need(all(row.get(k) is True for k in yes) and all(row.get(k) is False for k in no), code)


def pair(value, expected, code):
    need(type(value) is list and len(value) == 2 and all(type(x) is int for x in value) and value == expected, code)


def validate_closed(rows, prior):
    """Validate exact refusal semantics in supplied technical JSON, without I/O."""
    need(type(rows) is dict and set(rows) == set(PINS), 'RECEIPT_SET')
    need(type(prior) is dict and prior == rows['plan.json']
         and hashlib.sha256(canonical(prior)).hexdigest() == PLAN_SHA, 'PLAN')
    need(prior.get('operationId') == OP and prior.get('actualSourceSha256') == SOURCE_SHA
         and prior.get('updatePreviewControllerSha256') == CONTROLLER_SHA
         and prior.get('updatePreviewScopeSha256') == SCOPE_SHA, 'SOURCE_SCOPE')
    flags(prior, no=FALSE_AUTH, code='PLAN_AUTHORITY')
    ctx = prior.get('context', {})
    need((ctx.get('processId'), ctx.get('guiThreadId'), ctx.get('birth')) == (48936, 8292, '01dd5d0180299126'), 'TARGET')
    build = rows['build-proof.json']
    need(hashlib.sha256(canonical(build)).hexdigest() == BUILD_SHA and build.get('planSha256') == PLAN_SHA, 'BUILD')
    flags(build, yes=('passed', 'carrierPreflightOnly'), no=('goldStarted', 'nativeInjectionPerformed', 'carrierAssemblyExecuted'), code='STAGED_ONLY')
    unknown = rows['unknown.json']
    need(unknown.get('status') == 'UNKNOWN_RETAIN' and unknown.get('reason') == 'NATIVE_OR_FRESH_CLOSURE_UNPROVEN', 'UNKNOWN')
    flags(unknown, yes=('priorDatabaseReadbackVerified',), no=FALSE_AUTH + ('knownTerminal', 'retryAuthorized',
          'startupMetadataObserved', 'startupModulesReviewed', 'sourceKindBranchRuntimeVerified', 'commonModuleExecutionAuthorized'), code='NO_PROMOTION')
    for name in ('unknown.json', 'intent.json', 'sdk-receipt.json', 'database-startup-metadata-proof.json',
                 'database-startup-metadata-intent.json', 'cpp-exception-type-epoch.json'):
        need(rows[name].get('operationId') == OP and rows[name].get('scopeSha256') == SCOPE_SHA, 'JOIN')
    for name in ('intent.json', 'sdk-receipt.json'):
        flags(rows[name], no=FALSE_AUTH, code='AUTHORITY')
    for name in ('host-result.json', 'sdk-receipt.json'):
        flags(rows[name], yes=('knownTerminal', 'hookWorkersReleased'), code='SDK_TERMINAL')
        counts(rows[name], dict(sdkResult=0, threadId=8292, version=233), 'SDK_COUNTS')
    ep = rows['cpp-exception-type-epoch.json']
    need(ep.get('kind') == 'COMPARISON_CPP_EXCEPTION_TYPE_EPOCH' and ep.get('phase') == 'EXECUTE_RETURNED'
         and ep.get('handlerReturn') == 'CONTINUE_SEARCH', 'EPOCH_KIND')
    flags(ep, yes=('handlerRegistered', 'handlerRemoved', 'executeEntered', 'executeReturned', 'selfReferenceRetained',
          'dllMustRemainLoadedUntilProcessExit', 'typeMetadataOnly'),
          no=('counterOverflow', 'typeEventOverflow', 'typeDecoderReentry', 'exceptionObjectRead'), code='EPOCH_FLAGS')
    counts(ep, dict(processId=48936, executeThreadId=8292, sdkExecuteRc=0, cppThrows=0, cppThrowsExecuteThread=0,
          cppThrowsOtherThreads=0, otherExceptions=0, otherExceptionsExecuteThread=0, otherExceptionsOtherThreads=0,
          typeEventCount=0, decodedCppThrows=0, unknownCppThrows=0, listStreamCompatibleThrows=0), 'EPOCH_COUNTS')
    need(ep.get('typeEvents') == [], 'EPOCH_EVENTS')
    native = rows['database-startup-metadata-proof.json']
    need(native.get('kind') == 'DATABASE_STARTUP_METADATA_NATIVE' and native.get('phase') == 'METADATA_ONLY'
         and native.get('status') == 'REFUSED' and native.get('reason') == 'REUSE_CHANGED'
         and native.get('configurationSourceDomain') == 'DATABASE', 'NATIVE_REFUSAL')
    flags(native, yes=('nativeIntentWritten', 'beforeRootAndTargetsClean', 'afterRootAndTargetsClean',
          'designerPrefixPreserved', 'typedHandlesCleared'),
          no=('verified', 'exceptionObserved', 'startupReviewed', 'sourceKindBranchRuntimeVerified'), code='RESOURCES_CLOSED')
    counts(native, dict(databaseManager=100051712, databaseSource=1383504556, beforeTargetsClean=3, afterTargetsClean=3,
          bindingPasses=1, startupPropertyReads=4, flagPropertyReads=18, urlGetterCalls=4, commonModuleResolutions=3,
          persistentBefore=0, persistentAfter=0, singleBefore=0, singleAfter=0, queryExecutions=0, editorHelperCalls=0,
          **{k: 0 for k in ZERO_NATIVE}), 'PARTIAL_COUNTS')
    reserved = rows['database-startup-metadata-intent.json']
    need(reserved.get('kind') == 'DATABASE_STARTUP_METADATA_INTENT', 'INTENT_KIND')
    counts(reserved, dict(maximumStartupPropertyReads=4, maximumFlagPropertyReads=24, maximumUrlGetterCalls=4,
          **{k: 0 for k in ZERO_NATIVE}), 'INTENT_COUNTS')
    props = native.get('startupProperties')
    need(type(props) is list and len(props) == 2, 'STARTUP_ROWS')
    for row, property_id, sha in zip(props,
            ('9b7bbbae-9771-46f2-9e4d-2489e0ffc702', 'a4a9c1e2-1e54-4c7f-af06-4ca341198fac'),
            ('e2498e80790b013df816845aaba25f3659027414b0852e4a269291e540632ce7',
             '6213590123da0600f6b2a1e694bf34e585f63730caca77639ab4c12a7a329d15')):
        need(row.get('propertyId') == property_id and row.get('typeCategory') == 'UNSUPPORTED_URL'
             and row.get('canonicalInternalUrl') == '' and row.get('urlSha256') == sha, 'STARTUP_SHAPE')
        flags(row, yes=('typePresent', 'externalObjectPresent', 'urlHashKnown'), no=('valueNull', 'urlSupported'), code='STARTUP_FLAGS')
        counts(row, dict(typeKind=100, urlCharacters=38, urlUtf8Bytes=38), 'STARTUP_BOUNDS')
        pair(row.get('propertyReturnCodes'), [2, 2], 'STARTUP_CODES')
        pair(row.get('urlReturnCodes'), [345857464, 345857464], 'URL_CODES')
    observed = native.get('commonModuleFlags')
    need(type(observed) is list and len(observed) == 10, 'FLAG_ROWS')
    for index, row in enumerate(observed):
        need(row.get('objectId') == (PRINT_ID if index < 5 else REG_ID)
             and row.get('propertyId') == BOOL_PROPERTIES[index % 5]
             and row.get('value') is (False, True, False, True, False)[index % 5], 'FLAG_VALUE')
        pair(row.get('propertyReturnCodes'), [0, 0], 'FLAG_CODES')
    # PRINT flags were repeated before refusal. REG's second zeros are untouched
    # producer defaults: the partial read counts above do not certify a repeat.
    reuse = native.get('commonModuleReuse')
    need(type(reuse) is list and len(reuse) == 2, 'REUSE_ROWS')
    for row, module, code in zip(reuse, (PRINT_ID, REG_ID), ([2, 4], [3, 0])):
        need(row.get('objectId') == module and row.get('propertyId') == '07ddee68-6fc0-4b88-9616-7792446d12b8'
             and row.get('typeCategory') == 'OBJECT_OR_ENUM'
             and row.get('typeId') == '{a70b7dd7-4eb1-4ed1-bbe9-246866b07dd7}'
             and row.get('stringSha256') == '', 'REUSE_OBSERVATION')
        counts(row, dict(typeKind=100, stringUtf8Bytes=0), 'REUSE_KIND')
        flags(row, no=('valueNull', 'valueStabilityVerified', 'equalityInterfaceAvailable'), code='REUSE_UNPROVEN')
        pair(row.get('propertyReturnCodes'), code, 'REUSE_RAW_CODES')
    return CLASSIFICATION


def audit_closed(prior):
    """Read immutable pinned evidence; return closure classification, no admission."""
    folder = ROOT / 'build' / ('designer-hot-v233-' + OP)
    need(not (folder / 'result.json').exists(), 'NO_SUCCESS_RESULT')
    for name, pin in SOURCE_PINS.items():
        need(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == pin, 'SOURCE_PIN')
    rows = {}
    for name, pin in PINS.items():
        raw = (folder / name).read_bytes()
        need(len(raw) <= 32768 and hashlib.sha256(raw).hexdigest() == pin, 'RECEIPT_PIN')
        rows[name] = json.loads(raw)
    result = validate_closed(rows, prior)
    for name, pin in rows['build-proof.json']['derivedSha256'].items():
        need(Path(name).name == name and hashlib.sha256((folder / name).read_bytes()).hexdigest() == pin, 'STAGE_PIN')
    need(hashlib.sha256((folder / 'Continuation.dll').read_bytes()).hexdigest()
         == rows['build-proof.json']['librarySha256'], 'DLL_PIN')
    return result
