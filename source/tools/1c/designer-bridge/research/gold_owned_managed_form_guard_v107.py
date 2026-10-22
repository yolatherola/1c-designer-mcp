"""Pure physical proof for one unsaved own managed form in live Gold.

No I/O occurs except the trusted caller's fixed bounded readers. This result is
not a write, save, update, repository, stop, lease-release or cleanup permit.
Known pre-body refusals may prove terminal preservation; unknown outcomes never
do. A layout fixture is read only, and its BSL is never evaluated.
"""
import hashlib
import json
import re

import managed_form_type_guard_v74 as _enum_guard
import managed_layout_guard_v80 as _layout_guard
import managed_layout_contract_v80 as _layout

RESULT_LIMIT = 32768
MARKER_LIMIT = REGISTRY_LIMIT = 1024
BINARY_LIMIT = _layout.LIMIT
RESULT_FILENAME = 'gold-owned-managed-form-v107.json'
REGISTRY_FILENAME = 'owned-managed-layout-v107-registry.json'
PHASES = _layout_guard.PHASES + ('beforeLayeredResourceRead', 'afterLayeredResourceRead')
TERMINAL_PHASES = ('beforeScopeExit', 'afterScopeExit', 'beforeFinalSourceControl', 'afterFinalSourceControl')
ZERO_COUNTERS = _layout_guard.ZERO_COUNTERS + ('dirtyFlagWrites',)
BODY_FILENAME = 'owned-managed-layout-v107-body-resource.bin'
BEFORE_FILENAME = 'owned-managed-layout-v107-before-resource.bin'
FRESH_FILENAME = 'owned-managed-layout-v107-fresh-resource.bin'
LAYERED_FILENAME = 'owned-managed-layout-v107-layered-resource.bin'
TEMPLATE_FILENAMES = tuple('owned-managed-layout-v107-' + k + '-template.bin'
                           for k in ('attribute', 'command', 'button'))
BINARY_FILENAMES = (BEFORE_FILENAME,) + TEMPLATE_FILENAMES + (BODY_FILENAME, FRESH_FILENAME, LAYERED_FILENAME)
SCOPE = dict(goldRootId='218b5d00-7e10-486f-874c-73c2368ed5da',
             ownProcessingId='9c5f3c76-4d3b-5c0d-b1b2-37024a0993d7',
             ownFormId='e51a959c-fec9-5244-8a8e-ea02fdc0a0db',
             processingClassId='bf845118-327b-4682-b5c6-285d2a0eb296',
             formClassId='d5b0e5ed-256d-401c-9c36-f630cafd8a62',
             goldControlFormId='0ed914fb-2a1a-4b58-9fad-eaa103b47c9e',
             formTypePropertyId='e3331ed0-3854-478d-b6b5-4f14acdd6edb')
COUNTERS = dict(ownFactoryCalls=2, idSetterCalls=2, ownAttachCalls=2, ownTypeSetterCalls=1)
FLAGS = ('baselineClean', 'ownAbsentBefore', 'createdOnlyRegistryVerified',
         'sourceControlPreserved', 'sourceValueUnchanged', 'foreignGraphPreserved',
         'rootIdentityPreserved', 'ownAbsent', 'nativeException', 'returnUnknown',
         'managedKindVerified', 'managedFormVerified', 'formBodyVerified',
         'authenticatedDiscardEligible', 'ownScopeExited', 'rootModifiedAfter',
         'uiModifiedAfter', 'finalControlsMeasured')
FALSE_CLAIMS = ('persistedGoldVerified', 'databaseConfigurationVerified',
                'independentBackingVerified', 'deepCloneVerified',
                'foreignPropertyContentHashed', 'dirtyFlagsForced')
MAIN_KEYS = ('status', 'operationId', 'version', 'processingCountBefore', 'processingCountAfter',
             'writeAttempts', 'canonical', 'canonicalAfter', 'ownBefore', 'ownAfter',
             'enum', 'helperProbe', 'resource', 'body', 'lifecycle', 'profile') + tuple(SCOPE) + tuple(COUNTERS) + FLAGS + FALSE_CLAIMS + ZERO_COUNTERS
BODY_KEYS = tuple(k for k in _layout_guard.BODY_KEYS if k != 'ownedMemoryOnly') + ('ownedMemoryOnly', 'ownLiveGoldOnly', 'canonicalGate')
CANONICAL_GATES = ('notEntered','input','currentRoot','sourceControl','requiredHandles','referenceHandle','referenceAlias','ready')
REGISTRY_KEYS = ('operationId', 'stage', 'createdOnly', 'ownRootId', 'capturedSourceVersion',
                 'ownProcessingId', 'ownFormId', 'processingClassId', 'formClassId',
                 'canonical', 'ownFactoryCalls', 'idSetterCalls', 'ownAttachCalls', 'attachedIds', 'goldSaves')


def _need(ok, code):
    if not ok:
        raise ValueError(code)


def _shape(value, keys, code):
    _need(type(value) is dict and set(value) == set(keys), code)


def _uint(value, minimum=0, maximum=0xffffffff):
    return type(value) is int and minimum <= value <= maximum


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        _need(key not in value, 'GM107_DUPLICATE_JSON')
        value[key] = item
    return value


def _bad_number(_raw):
    raise ValueError('GM107_NONINTEGER_JSON')


def _parse(raw, limit):
    _need(type(raw) in (bytes, str), 'GM107_JSON_TYPE')
    body = raw.encode('utf-8') if type(raw) is str else raw
    _need(0 < len(body) <= limit and not body.startswith(b'\xef\xbb\xbf'), 'GM107_JSON_SIZE')
    try:
        result = json.loads(body.decode('utf-8', 'strict'), object_pairs_hook=_pairs,
                            parse_float=_bad_number, parse_constant=_bad_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('GM107_JSON_REJECTED') from None
    _need(type(result) is dict, 'GM107_JSON_SHAPE')
    return result


def parse_result(raw):
    return _parse(raw, RESULT_LIMIT)


def marker_filename(phase):
    _need(type(phase) is str and phase in PHASES, 'GM107_PHASE')
    return 'owned-managed-layout-v107-' + phase + '.json'


def _file(reader, name, limit):
    _need(callable(reader), 'GM107_READER')
    try:
        raw = reader(name)
    except Exception:
        raise ValueError('GM107_READ_FAILED') from None
    _need(type(raw) is bytes and 0 < len(raw) <= limit, 'GM107_READ_SIZE')
    return raw


def _marker(reader, phase, operation):
    value = _parse(_file(reader, marker_filename(phase), MARKER_LIMIT), MARKER_LIMIT)
    _shape(value, ('phase', 'operationId') + ZERO_COUNTERS, 'GM107_MARKER_SHAPE')
    _need(value['phase'] == phase and value['operationId'] == operation
          and all(_uint(value[k]) and value[k] == 0 for k in ZERO_COUNTERS), 'GM107_MARKER_CONTENT')


def _canonical(value):
    _shape(value, _enum_guard.CANONICAL_KEYS, 'GM107_CANONICAL_SHAPE')
    _need(all(_uint(pointer, 1) for pointer in value.values()), 'GM107_CANONICAL_POINTER')
    _need(value['ownManager'] == value['goldManager'] and value['ownRoot'] == value['goldRoot'],
          'GM107_DETACHED_MANAGER')
    keys = ('goldManager', 'goldRoot', 'goldControlForm', 'ownMemory', 'ownProcessing', 'ownForm')
    _need(len({value[k] for k in keys}) == len(keys), 'GM107_CANONICAL_ALIAS')


def _snapshot(value):
    _shape(value, _enum_guard.SNAPSHOT_KEYS, 'GM107_SNAPSHOT_SHAPE')
    expected = dict(rootId=SCOPE['goldRootId'], processingId=SCOPE['ownProcessingId'],
                    processingClassId=SCOPE['processingClassId'], formId=SCOPE['ownFormId'],
                    formClassId=SCOPE['formClassId'], formParentId=SCOPE['ownProcessingId'],
                    processingParentId=SCOPE['goldRootId'], rootIndexVerified=True)
    _need(value == expected, 'GM107_SNAPSHOT_SCOPE')


def _registry(reader, info):
    raw = _file(reader, REGISTRY_FILENAME, REGISTRY_LIMIT)
    value = _parse(raw, REGISTRY_LIMIT)
    _shape(value, REGISTRY_KEYS, 'GM107_REGISTRY_SHAPE')
    _need(value['operationId'] == info['operationId'] and value['stage'] == 'beforeAttach'
          and value['createdOnly'] is True and value['ownRootId'] == SCOPE['goldRootId']
          and _uint(value['capturedSourceVersion'], 1) and value['capturedSourceVersion'] == info['version']
          and all(value[k] == SCOPE[k] for k in ('ownProcessingId', 'ownFormId', 'processingClassId', 'formClassId')),
          'GM107_REGISTRY_SCOPE')
    _canonical(value['canonical'])
    _need(value['canonical'] == info['canonical']
          and all(_uint(value[k]) and value[k] == count for k, count in
                  (('ownFactoryCalls', 2), ('idSetterCalls', 2), ('ownAttachCalls', 0), ('goldSaves', 0)))
          and type(value['attachedIds']) is list and value['attachedIds'] == [], 'GM107_REGISTRY_COUNTER')
    return dict(registry=value, sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))


def _helper(value, required):
    if value is None:
        _need(not required, 'GM107_HELPER_MISSING')
        return
    _shape(value, ('present', 'table', 'abiVerified', 'getMDObjCalls'), 'GM107_HELPER_SHAPE')
    _need(type(value['present']) is bool and type(value['abiVerified']) is bool
          and _uint(value['getMDObjCalls'], 0, 16), 'GM107_HELPER_TYPE')
    table = value['table']
    if table is not None:
        _shape(table, ('module', 'rva'), 'GM107_ADDRESS_SHAPE')
        _need(type(table['module']) is str and re.fullmatch(r'[A-Za-z0-9_]{1,64}\.dll', table['module']) is not None
              and _uint(table['rva']), 'GM107_ADDRESS_CONTENT')
    _need((value['present'] and table is not None) or (not value['present'] and table is None), 'GM107_HELPER_PRESENCE')
    if value['abiVerified']:
        _need(table == dict(module='basicui.dll', rva=0x60b344), 'GM107_HELPER_ABI')
    else:
        _need(value['getMDObjCalls'] == 0, 'GM107_UNKNOWN_HELPER_CALL')
    if required:
        _need(value['abiVerified'] and value['getMDObjCalls'] > 0, 'GM107_HELPER_REQUIRED')


PROFILE_COMPONENTS = ('rootBinding','fullForeignGraph','documentFullSource','wideCollectObserve','nativeWriter','ownWitnessIO')
PROFILE_KEYS = ('version','measurementBoundary','clockAvailable','frequencyHz','timingVerified','finalized',
                'stackBalanced','total','components','accountedExclusiveUs','unprofiledUs',
                'timingAffectsCapability','cachedControlsUsed','closeIncluded')
PROFILE_ROW_KEYS = ('started','returned','verified','inclusiveUs','exclusiveUs')
PROFILE_LIMIT_US = 600_000_000


def verify_profile(value):
    """Validate diagnostics only; timing never substitutes a native guard."""
    _shape(value,PROFILE_KEYS,'GM107_PROFILE_SHAPE')
    _need(_uint(value['version']) and value['version']==1
          and type(value['measurementBoundary']) is str
          and value['measurementBoundary']=='permit-accepted-to-result-build','GM107_PROFILE_SCOPE')
    flags=('clockAvailable','timingVerified','finalized','stackBalanced',
           'timingAffectsCapability','cachedControlsUsed','closeIncluded')
    _need(all(type(value[k]) is bool for k in flags) and value['finalized'] is True
          and all(value[k] is False for k in ('timingAffectsCapability','cachedControlsUsed','closeIncluded')),
          'GM107_PROFILE_FLAGS')
    _need((_uint(value['frequencyHz'],1,10**12) if value['clockAvailable'] else value['frequencyHz'] is None),
          'GM107_PROFILE_CLOCK')
    _shape(value['components'],PROFILE_COMPONENTS,'GM107_PROFILE_COMPONENTS')
    verified=value['timingVerified']
    _need(not verified or (value['clockAvailable'] and value['stackBalanced']),'GM107_PROFILE_VERIFIED')
    rows=[value['total'],*value['components'].values()]
    for row in rows:
        _shape(row,PROFILE_ROW_KEYS,'GM107_PROFILE_ROW')
        _need(_uint(row['started'],0,100000) and _uint(row['returned'],0,row['started'])
              and type(row['verified']) is bool,'GM107_PROFILE_COUNTERS')
        measured=verified and row['started']>0
        _need(row['verified'] is measured,'GM107_PROFILE_MEASURED')
        if measured:
            _need(row['started']==row['returned'] and _uint(row['inclusiveUs'],0,PROFILE_LIMIT_US)
                  and _uint(row['exclusiveUs'],0,row['inclusiveUs']),'GM107_PROFILE_TIMING')
        else:
            _need(row['inclusiveUs'] is None and row['exclusiveUs'] is None,'GM107_PROFILE_UNMEASURED')
    total=value['total']
    _need(sum(row['started'] for row in rows)<=100000,'GM107_PROFILE_COUNTER_BOUND')
    _need(total['started']==1 and total['returned']<=1,'GM107_PROFILE_TOTAL')
    if verified:
        _need(total['returned']==1,'GM107_PROFILE_TOTAL')
        accounted=sum(row['exclusiveUs'] or 0 for row in value['components'].values())
        _need(_uint(value['accountedExclusiveUs'],0,PROFILE_LIMIT_US) and value['accountedExclusiveUs']==accounted
              and _uint(value['unprofiledUs'],0,PROFILE_LIMIT_US) and value['unprofiledUs']==total['exclusiveUs']
              and 0<=total['inclusiveUs']-accounted-value['unprofiledUs']<=len(PROFILE_COMPONENTS),
              'GM107_PROFILE_ACCOUNTING')
    else:
        _need(value['accountedExclusiveUs'] is None and value['unprofiledUs'] is None,'GM107_PROFILE_UNMEASURED')
    return dict(timingVerified=verified,diagnosticOnly=True)


def _common(info, version, operation):
    _shape(info, MAIN_KEYS, 'GM107_MAIN_SHAPE')
    verify_profile(info['profile'])
    _need(_uint(version, 1) and _uint(info['version'], 1) and info['version'] == version, 'GM107_VERSION')
    op = info['operationId']
    _need(type(op) is str and re.fullmatch(r'[0-9a-f]{32}', op) is not None
          and (operation is None or operation == op), 'GM107_OPERATION')
    _need(all(info[k] == v for k, v in SCOPE.items()), 'GM107_SCOPE')
    _need(all(type(info[k]) is bool for k in FLAGS + FALSE_CLAIMS), 'GM107_BOOL')
    _need(all(info[k] is False for k in FALSE_CLAIMS)
          and all(_uint(info[k]) and info[k] == 0 for k in ZERO_COUNTERS), 'GM107_FOREIGN_CLAIM')
    _need(all(_uint(info[k], 0, limit) for k, limit in
              (('ownFactoryCalls', 2), ('idSetterCalls', 2), ('ownAttachCalls', 2), ('ownTypeSetterCalls', 1),
               ('writeAttempts', 12), ('processingCountBefore', 100000), ('processingCountAfter', 100000))), 'GM107_COUNTER_TYPE')
    _shape(info['lifecycle'], PHASES, 'GM107_LIFECYCLE_SHAPE')
    _need(all(type(info['lifecycle'][p]) is bool for p in PHASES), 'GM107_LIFECYCLE_TYPE')
    _shape(info['body'], BODY_KEYS, 'GM107_BODY_SHAPE')
    body = info['body']
    _need(body['ownedMemoryOnly'] is False and body['ownLiveGoldOnly'] is True, 'GM107_BODY_RECEIVER')
    _need(all(_uint(body[k], 0, count) for k, count in _layout_guard.BODY_COUNTERS.items()), 'GM107_BODY_COUNTER_TYPE')
    _need(type(body['layoutLoadCalls']) is int and 0 <= body['layoutLoadCalls'] <= 1
          and type(body['prewriteGate']) is str and body['prewriteGate'] in _layout_guard.PREWRITE_GATES,
          'GM107_BODY_STAGE')
    _need(type(body['canonicalGate']) is str and body['canonicalGate'] in CANONICAL_GATES
          and (body['canonicalGate']=='notEntered' or body['bodyFactoryCalls']==1), 'GM107_CANONICAL_STAGE')
    _need(all(type(body[k]) is bool for k in _layout_guard.BODY_FLAGS + ('ownLiveGoldOnly', 'layoutVerified')),
          'GM107_BODY_FLAG_TYPE')
    attempts = sum(info[k] for k in COUNTERS) + body['ownNameSetterCalls'] + body['bodyStoreCalls'] + body['ownDeleteCalls']
    _need(info['writeAttempts'] == attempts, 'GM107_WRITE_COUNT')
    _helper(info['helperProbe'], False)
    return op


def verify_terminal(info, version, read_marker, operation=None):
    """Validate known terminal preservation, never unknown/default observations."""
    op = _common(info, version, operation)
    _need(info['status'] in ('GOLD_OWNED_MANAGED_FORM_VERIFIED_V107', 'GOLD_OWNED_MANAGED_FORM_UNVERIFIED_V107')
          and info['nativeException'] is False and info['returnUnknown'] is False, 'GM107_UNKNOWN_OUTCOME')
    required = ('baselineClean', 'ownAbsentBefore', 'sourceControlPreserved', 'sourceValueUnchanged',
                'foreignGraphPreserved', 'rootIdentityPreserved', 'ownAbsent', 'authenticatedDiscardEligible',
                'ownScopeExited', 'finalControlsMeasured')
    _need(all(info[k] is True for k in required)
          and info['processingCountBefore'] == info['processingCountAfter'], 'GM107_TERMINAL_PRESERVATION')
    enum = info['enum'];_shape(enum, _enum_guard.ENUM_KEYS, 'GM107_SOURCE_ENUM_SHAPE')
    _need(enum['typeId'] == _enum_guard.FORM_TYPE and type(enum['sourceBeforeId']) is int
          and enum['sourceBeforeId'] in (0, 1) and type(enum['sourceAfterId']) is int
          and enum['sourceAfterId'] == enum['sourceBeforeId'], 'GM107_SOURCE_ENUM_ID')
    for first, last in (('sourceCarrierBefore', 'sourceCarrierAfter'), ('sourceCanonicalBefore', 'sourceCanonicalAfter')):
        _need(_uint(enum[first], 1) and _uint(enum[last], 1) and enum[first] == enum[last], 'GM107_SOURCE_ENUM_IDENTITY')
    _need(type(enum['sourceTypeMutableBefore']) is bool and type(enum['sourceTypeMutableAfter']) is bool
          and enum['sourceTypeMutableBefore'] == enum['sourceTypeMutableAfter']
          and all(enum[k] is True for k in ('sourceNativeEqualPreserved', 'sourceHeldReadOnly', 'enumIdAbiVerified'))
          and enum['numberGuessUsed'] is False and enum['independentCloneVerified'] is False,
          'GM107_SOURCE_ENUM_PRESERVATION')
    for phase in TERMINAL_PHASES:
        _need(info['lifecycle'][phase] is True, 'GM107_TERMINAL_LIFECYCLE')
        _marker(read_marker, phase, op)
    if info['createdOnlyRegistryVerified']:
        _registry(read_marker, info)
    elif info['ownAttachCalls']:
        raise ValueError('GM107_ATTACHED_WITHOUT_REGISTRY')
    writer_pairs = (('ownFactoryCalls', 'ProcessingFactory'), ('idSetterCalls', 'ProcessingFactory'),
                    ('ownAttachCalls', 'ProcessingAttach'), ('ownTypeSetterCalls', 'TypeSetter'))
    for key, stage in writer_pairs:
        if info[key]:
            pairs = [stage]
            if info[key] == 2 and key in ('ownFactoryCalls', 'idSetterCalls'):
                pairs.append('FormFactory')
            if info[key] == 2 and key == 'ownAttachCalls':
                pairs.append('FormAttach')
            for suffix in pairs:
                for prefix in ('before', 'after'):
                    phase = prefix + suffix
                    _need(info['lifecycle'][phase] is True, 'GM107_WRITER_LIFECYCLE')
                    _marker(read_marker, phase, op)
    if info['body']['ownNameSetterCalls']:
        for phase in ('beforeNames', 'afterNames'):
            _need(info['lifecycle'][phase] is True, 'GM107_NAME_LIFECYCLE')
            _marker(read_marker, phase, op)
    deleted = info['body']['ownDeleteCalls']
    _need(deleted == info['ownAttachCalls'], 'GM107_DELETE_COUNT')
    if deleted:
        stages = ('DeleteProcessing',) if deleted == 1 else ('DeleteForm', 'DeleteProcessing')
        for stage in stages:
            for prefix in ('before', 'after'):
                phase = prefix + stage
                _need(info['lifecycle'][phase] is True, 'GM107_DELETE_LIFECYCLE')
                _marker(read_marker, phase, op)
    partial = info['status'].endswith('UNVERIFIED_V107')
    _need(all(info[k] is (not partial) for k in ('managedKindVerified', 'managedFormVerified', 'formBodyVerified')),
          'GM107_CAPABILITY_STATUS')
    if partial:
        _need(all(info['body'][k] == 0 for k in _layout_guard.BODY_COUNTERS
                  if k not in ('ownNameSetterCalls', 'ownDeleteCalls'))
              and info['body']['layoutLoadCalls'] == 0 and info['body']['verified'] is False,
              'GM107_POST_BODY_REFUSAL_UNKNOWN')
    return dict(terminalPreservationVerified=True, managedFormVerified=not partial,
                persistedGoldVerified=False, processStopAuthorized=False, cleanupAuthorized=False,
                leaseReleaseAuthorized=False)


def verify_nonresource_full(info, version, read_marker, read_binary=None, operation=None):
    """All former full native/identity/writer checks, before resource capability.

    Returns only the already bounded own binary witnesses and enum observation.
    An error here never becomes a capability refusal or safe-close permission.
    """
    terminal = verify_terminal(info, version, read_marker, operation)
    _need(terminal['managedFormVerified'] is True, 'GM107_FULL_OUTCOME')
    _need(all(info[k] == v for k, v in COUNTERS.items()) and info['writeAttempts'] == 12
          and info['createdOnlyRegistryVerified'] is True, 'GM107_FULL_COUNTER')
    canonical = info['canonical'];_canonical(canonical);_canonical(info['canonicalAfter'])
    _need(canonical == info['canonicalAfter'], 'GM107_CANONICAL_CHANGED')
    _snapshot(info['ownBefore']);_snapshot(info['ownAfter'])
    _need(info['ownBefore'] == info['ownAfter'], 'GM107_GRAPH_CHANGED')
    source, mutable = _enum_guard._enum(info['enum'], canonical)
    _helper(info['helperProbe'], True)
    body = info['body']
    flags = tuple(k for k in _layout_guard.BODY_FLAGS if k != 'ownedMemoryOnly') + ('ownLiveGoldOnly', 'layoutVerified')
    _need(all(body[k] is True for k in flags)
          and all(body[k] == count for k, count in _layout_guard.BODY_COUNTERS.items())
          and body['layoutLoadCalls'] == 1 and body['prewriteGate'] == 'prewritePassed'
          and body['canonicalGate'] == 'ready', 'GM107_BODY_COMPLETE')
    _need(body['moduleFixtureSha256'] == _layout.MODULE_SHA and _uint(body['moduleCharacterCount'])
          and body['moduleCharacterCount'] == len(_layout.MODULE)
          and body['bodyFilename'] == BODY_FILENAME and _uint(body['bodyBytes'], 17, BINARY_LIMIT), 'GM107_MODULE_PROOF')
    readback = body['readback'];_shape(readback, _layout_guard.READBACK_KEYS, 'GM107_READBACK_SHAPE')
    _snapshot(readback['scope'])
    _need(readback['scope'] == info['ownAfter'] and all(readback[k] is True for k in ('verified', 'moduleTextEqual', 'nativeEqual', 'freshBody'))
          and readback['moduleFixtureSha256'] == _layout.MODULE_SHA and _uint(readback['moduleCharacterCount'])
          and readback['moduleCharacterCount'] == len(_layout.MODULE)
          and _uint(readback['groupId']) and readback['groupId'] == 1001
          and _uint(readback['groupCount']) and readback['groupCount'] == 1
          and readback['groupName'] == _layout.GROUP_NAME and type(readback['typeId']) is int and readback['typeId'] == source,
          'GM107_READBACK_CONTENT')
    identities = readback['canonical'];_shape(identities, ('first', 'bound', 'fresh'), 'GM107_BODY_IDENTITIES')
    occupied = set(canonical.values()) | {info['enum']['sourceCanonicalBefore']}
    _need(all(_uint(v, 1) for v in identities.values()) and len(set(identities.values())) == 3
          and set(identities.values()).isdisjoint(occupied), 'GM107_BODY_ALIAS')
    deletion = body['deletion'];_shape(deletion, _layout_guard.DELETION_KEYS, 'GM107_DELETION_SHAPE')
    _need(_uint(deletion['processingChildCount']) and deletion['processingChildCount'] == info['processingCountBefore']
          and all(deletion[k] is True for k in deletion if k != 'processingChildCount'), 'GM107_DELETION_CONTENT')
    records = body['records'];_need(type(records) is list and len(records) == 3, 'GM107_RECORDS')
    for index, record in enumerate(records):
        _shape(record, _layout_guard.RECORD_KEYS, 'GM107_RECORD_SHAPE')
        _need(record['classId'] == _layout.RECORDS[index][0] and record['templateFilename'] == TEMPLATE_FILENAMES[index]
              and all(type(record[k]) is int and record[k] == n for k, n in (('factoryCalls', 2), ('serializeCalls', 2), ('deserializeCalls', 1)))
              and all(record[k] is True for k in ('abiVerified', 'roundtripVerified', 'inputConsumed', 'sourceReturnedBool', 'cloneReturnedBool', 'sourceNonNull', 'cloneNonNull'))
              and record['rawCanaryVerified'] is False and record['gate'] == 'passed', 'GM107_RECORD_CONTENT')
        pair = (record['sourceCanonical'], record['cloneCanonical'])
        _need(all(_uint(v, 1) for v in pair) and pair[0] != pair[1]
              and set(pair).isdisjoint(occupied | {identities['first']}), 'GM107_RECORD_ALIAS')
    resource = info['resource']
    _shape(resource, ('getterCalls', 'abiVerified', 'outputCanaryVerified', 'countedFileVerified', 'profileVerified',
                      'bytes', 'filename', 'ownResourceOnly', 'configurationExport'), 'GM107_RESOURCE_SHAPE')
    _need(_uint(resource['getterCalls']) and resource['getterCalls'] == 1
          and all(resource[k] is True for k in ('abiVerified', 'outputCanaryVerified', 'countedFileVerified', 'profileVerified', 'ownResourceOnly'))
          and resource['configurationExport'] is False and resource['filename'] == LAYERED_FILENAME
          and _uint(resource['bytes'], 17, BINARY_LIMIT), 'GM107_RESOURCE_CONTENT')
    for phase in PHASES:
        _need(info['lifecycle'][phase] is True, 'GM107_FULL_LIFECYCLE')
        _marker(read_marker, phase, info['operationId'])
    binaries = {name: _file(read_binary, name, BINARY_LIMIT) for name in BINARY_FILENAMES}
    _need(all(len(data) > 16 for data in binaries.values()) and len(binaries[BODY_FILENAME]) == body['bodyBytes']
          and len(binaries[LAYERED_FILENAME]) == resource['bytes'], 'GM107_BINARY_SIZE')
    for record in records:
        _need(_uint(record['templateBytes'], 17, BINARY_LIMIT)
              and record['templateBytes'] == len(binaries[record['templateFilename']]), 'GM107_TEMPLATE_SIZE')
    return binaries, source, mutable


def verify_resource_capability(binaries):
    """Keep the full exact resource-preservation criteria unchanged."""
    _layout.preserved_fields(binaries[BEFORE_FILENAME], binaries[BODY_FILENAME], *(binaries[n] for n in TEMPLATE_FILENAMES))
    profile = _layout.inspect_resource(binaries[FRESH_FILENAME])
    expected = _layout.form_tree(binaries[BODY_FILENAME])
    _need(expected == _layout.form_tree(binaries[FRESH_FILENAME]) == _layout.form_tree(binaries[LAYERED_FILENAME]),
          'GM107_FRESH_RESOURCE_CHANGED')
    return profile


def verify_own_resource_refusal_scope(binaries):
    """Safe discard scope for deleted own objects; not resource correctness.

    All nonresource checks must already have passed. Unknown default fields or
    generated IDs are never repaired, normalized or declared correct. Foreign
    module text/links/collections cannot be smuggled into this fixed fixture.
    """
    profiles = [_layout.inspect_resource(binaries[n]) for n in
                (BODY_FILENAME, FRESH_FILENAME, LAYERED_FILENAME)]
    _need(profiles[0] == profiles[1] == profiles[2]
          and binaries[FRESH_FILENAME] == binaries[LAYERED_FILENAME], 'GM107_RESOURCE_REFUSAL_SCOPE')
    return dict(ownResourceScopeVerified=True, resourceNormalizationVerified=False,
                resourceProfileVerified=False, layeredResourceVerified=False)


def verify(info, version, read_marker, read_binary=None, operation=None):
    """Full body/model/fresh layered-resource proof with every physical witness."""
    binaries, source, mutable = verify_nonresource_full(info, version, read_marker, read_binary, operation)
    profile = verify_resource_capability(binaries)
    return dict(terminalPreservationVerified=True, ownedLiveGoldFormVerified=True, managedFormVerified=True,
                resourceProfileVerified=True, layeredResourceVerified=True, profile=profile,
                moduleFixtureSha256=_layout.MODULE_SHA, sourceTypeId=source, sourceTypeMutable=mutable,
                physicalMarkerCount=len(PHASES), resourceCount=len(BINARY_FILENAMES),
                bodyResourceSha256=hashlib.sha256(binaries[BODY_FILENAME]).hexdigest(),
                persistedGoldVerified=False, independentBackingVerified=False,
                processStopAuthorized=False, cleanupAuthorized=False, leaseReleaseAuthorized=False)
