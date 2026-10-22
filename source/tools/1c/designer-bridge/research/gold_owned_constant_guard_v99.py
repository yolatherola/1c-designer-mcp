"""Pure observations for one unsaved own Gold Constant; never a writer permit.

The trusted bounded reader is restricted by the future controller to the fixed
22 phase receipts and registry. Unknown/native exceptions grant no safe close.
"""
import hashlib
import json
import re

RESULT_LIMIT = 16384
MARKER_LIMIT = REGISTRY_LIMIT = 1024
RESULT_FILENAME = 'gold-owned-constant-v99.json'
REGISTRY_FILENAME = 'gold-owned-constant-v99-registry.json'
PHASES = tuple(part + stage for stage in (
    'Baseline', 'Factory', 'Attach', 'Name', 'DefaultRead', 'BooleanConstructor',
    'TypeSetter', 'Readback', 'Delete', 'ScopeExit', 'FinalSourceControl')
    for part in ('before', 'after'))
TERMINAL_PHASES = PHASES[-4:]
WRITER_PHASES = (('factoryCalls', 'Factory'), ('idSetterCalls', 'Factory'),
                 ('attachCalls', 'Attach'), ('nameSetterCalls', 'Name'),
                 ('typeSetterCalls', 'TypeSetter'), ('deleteCalls', 'Delete'))
ZERO_COUNTERS = ('foreignSourceWrites', 'goldSaves', 'repositoryWrites',
                 'databaseUpdates', 'businessCalls', 'dirtyFlagWrites')
SCOPE = dict(goldRootId='218b5d00-7e10-486f-874c-73c2368ed5da',
             ownConstantId='e61c6271-9d05-4b8f-a25a-65b3c67f3e9e',
             constantClassId='0195e80c-b157-11d4-9435-004095e12fc7',
             typePropertyId='b1053250-abe6-11d4-9434-004095e12fc7',
             ownName='АгентДиагностикаКонстантыV99')
TYPE_DESCRIPTION = 'f5c65050-3bbb-11d5-b988-0050bae0a95d'
COUNTERS = ('factoryCalls', 'idSetterCalls', 'attachCalls', 'nameSetterCalls',
            'defaultTypeReadCalls', 'booleanConstructorCalls', 'typeSetterCalls',
            'freshTypeReadCalls', 'typeEqualityCalls', 'deleteCalls')
FLAGS = ('baselineClean', 'ownAbsentBefore', 'constantKindDeclared',
         'createdOnlyRegistryVerified', 'factoryVerified', 'ownAttached', 'ownNamed',
         'defaultTypeObserved', 'defaultTypeVerified', 'ownBooleanVerified',
         'typeSetterReturned', 'freshReadbackVerified', 'freshTypeEqual',
         'ownDeleted', 'parentCleared', 'ownAbsent', 'rootIdentityPreserved',
         'foreignGraphPreserved', 'goldSourcePreserved', 'taskScopeExited',
         'authenticatedDiscardEligible', 'ownConstantVerified', 'rootModifiedAfter',
         'uiModifiedAfter', 'nativeException', 'returnUnknown', 'defaultTypeMutable',
         'defaultEqualsBoolean')
FALSE_CLAIMS = ('persistedGoldVerified', 'databaseConfigurationVerified',
                'qualifierReadbackVerified', 'independentBackingVerified',
                'foreignPropertyContentHashed', 'dirtyFlagsForced')
MAIN_KEYS = ('status', 'operationId', 'version', 'lifecycle', 'canonical',
             'canonicalAfter', 'defaultTypeClassId', 'writeAttempts',
             'constantCountBefore', 'constantCountAttached', 'constantCountAfter') + tuple(SCOPE) + COUNTERS + FLAGS + FALSE_CLAIMS + ZERO_COUNTERS
CANONICAL_KEYS = ('goldManager', 'goldRoot', 'selectedDocument', 'ownConstant')
REGISTRY_KEYS = ('operationId', 'stage', 'createdOnly', 'rootId', 'objectId',
                 'classId', 'typePropertyId', 'version', 'canonical',
                 'factoryCalls', 'idSetterCalls', 'attachCalls', 'attachedIds', 'goldSaves')


def _need(ok, code):
    if not ok:
        raise ValueError(code)


def _shape(value, keys, code):
    _need(type(value) is dict and set(value) == set(keys), code)


def _pairs(items):
    result = {}
    for key, value in items:
        _need(key not in result, 'GC99_DUPLICATE_JSON_REJECTED')
        result[key] = value
    return result


def _not_number(_text):
    raise ValueError('GC99_NONINTEGER_JSON_REJECTED')


def _parse(raw, limit):
    _need(type(raw) in (bytes, str), 'GC99_JSON_TYPE_REJECTED')
    try:
        body = raw.encode('utf-8') if type(raw) is str else raw
        _need(0 < len(body) <= limit and not body.startswith(b'\xef\xbb\xbf'),
              'GC99_JSON_SIZE_ENCODING_REJECTED')
        value = json.loads(body.decode('utf-8', 'strict'), object_pairs_hook=_pairs,
                           parse_float=_not_number, parse_constant=_not_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('GC99_JSON_REJECTED') from None
    _need(type(value) is dict, 'GC99_JSON_SHAPE_REJECTED')
    return value


def parse_result(raw):
    return _parse(raw, RESULT_LIMIT)


def marker_filename(phase):
    _need(type(phase) is str and phase in PHASES, 'GC99_PHASE_REJECTED')
    return 'gold-owned-constant-v99-' + phase + '.json'


def _read(reader, name, limit):
    _need(callable(reader), 'GC99_READER_REQUIRED')
    try:
        raw = reader(name)
    except Exception:
        raise ValueError('GC99_PHYSICAL_RECEIPT_UNAVAILABLE') from None
    _need(type(raw) is bytes, 'GC99_PHYSICAL_RECEIPT_TYPE_REJECTED')
    return _parse(raw, limit), raw


def _marker(reader, phase, operation):
    item, raw = _read(reader, marker_filename(phase), MARKER_LIMIT)
    _shape(item, ('phase', 'operationId') + ZERO_COUNTERS, 'GC99_MARKER_SHAPE_REJECTED')
    _need(item['phase'] == phase and item['operationId'] == operation
          and all(type(item[k]) is int and item[k] == 0 for k in ZERO_COUNTERS),
          'GC99_MARKER_REJECTED')
    return dict(phase=phase, sha256=hashlib.sha256(raw).hexdigest())


def _canonical(value):
    _shape(value, CANONICAL_KEYS, 'GC99_CANONICAL_SHAPE_REJECTED')
    _need(all(type(value[k]) is int and 0 < value[k] <= 0xffffffff for k in CANONICAL_KEYS)
          and len(set(value.values())) == len(CANONICAL_KEYS), 'GC99_CANONICAL_ALIAS_REJECTED')


def _registry(reader, info):
    item, raw = _read(reader, REGISTRY_FILENAME, REGISTRY_LIMIT)
    _shape(item, REGISTRY_KEYS, 'GC99_REGISTRY_SHAPE_REJECTED')
    _need(item['operationId'] == info['operationId'] and item['stage'] == 'beforeAttach'
          and item['createdOnly'] is True and item['rootId'] == SCOPE['goldRootId']
          and item['objectId'] == SCOPE['ownConstantId'] and item['classId'] == SCOPE['constantClassId']
          and item['typePropertyId'] == SCOPE['typePropertyId'] and type(item['version']) is int
          and item['version'] == info['version'] and type(item['attachedIds']) is list
          and item['attachedIds'] == [], 'GC99_REGISTRY_SCOPE_REJECTED')
    _canonical(item['canonical'])
    _need(item['canonical'] == info['canonical'], 'GC99_REGISTRY_CANONICAL_REJECTED')
    _need(all(type(item[k]) is int and item[k] == v for k, v in
              (('factoryCalls', 1), ('idSetterCalls', 1), ('attachCalls', 0), ('goldSaves', 0))),
          'GC99_REGISTRY_COUNTER_REJECTED')
    return dict(sha256=hashlib.sha256(raw).hexdigest(), createdOnlyVerified=True)


def verify(info, version, read_marker):
    """Verify measured known terminal observations; no execution/cleanup authority.

    A valid capability refusal returns ownConstantVerified=False. Baseline dirty,
    unknown/exception, missing terminal receipts or retained own objects fail.
    Root/PIDbirth/lease/authenticated close are separate controller obligations.
    """
    _shape(info, MAIN_KEYS, 'GC99_MAIN_SHAPE_REJECTED')
    _need(type(version) is int and version >= 0 and type(info['version']) is int
          and info['version'] == version, 'GC99_VERSION_REJECTED')
    _need(type(info['operationId']) is str and re.fullmatch('[0-9a-f]{32}', info['operationId'])
          and info['status'] in ('GOLD_OWNED_CONSTANT_VERIFIED_V99', 'GOLD_OWNED_CONSTANT_UNVERIFIED_V99')
          and all(type(info[k]) is str and info[k] == v for k, v in SCOPE.items()), 'GC99_SCOPE_REJECTED')
    _need(all(type(info[k]) is bool for k in FLAGS + FALSE_CLAIMS), 'GC99_BOOLEAN_REJECTED')
    _need(info['returnUnknown'] is False and info['nativeException'] is False, 'GC99_UNKNOWN_RETAINS')
    _need(all(type(info[k]) is int and info[k] == 0 for k in ZERO_COUNTERS)
          and all(info[k] is False for k in FALSE_CLAIMS), 'GC99_FOREIGN_WRITE_CLAIM_REJECTED')
    for key in COUNTERS:
        _need(type(info[key]) is int and 0 <= info[key] <= (2 if key == 'typeEqualityCalls' else 1),
              'GC99_COUNTER_REJECTED')
    _need(type(info['writeAttempts']) is int and info['writeAttempts'] == sum(info[k] for k in
          ('factoryCalls', 'idSetterCalls', 'attachCalls', 'nameSetterCalls', 'typeSetterCalls', 'deleteCalls')),
          'GC99_WRITE_ACCOUNTING_REJECTED')
    _need(info['idSetterCalls'] <= info['factoryCalls'] and info['attachCalls'] <= info['idSetterCalls']
          and info['nameSetterCalls'] <= info['attachCalls'] and info['defaultTypeReadCalls'] <= info['nameSetterCalls']
          and info['booleanConstructorCalls'] <= info['defaultTypeReadCalls']
          and info['typeSetterCalls'] <= info['booleanConstructorCalls']
          and info['freshTypeReadCalls'] <= info['typeSetterCalls'] and info['deleteCalls'] <= info['attachCalls'],
          'GC99_COUNTER_ORDER_REJECTED')
    _need(info['typeEqualityCalls'] <= info['booleanConstructorCalls'] + info['freshTypeReadCalls'],
          'GC99_EQUALITY_ORDER_REJECTED')
    _shape(info['lifecycle'], PHASES, 'GC99_LIFECYCLE_SHAPE_REJECTED')
    _need(all(type(info['lifecycle'][p]) is bool for p in PHASES), 'GC99_LIFECYCLE_TYPE_REJECTED')
    # A refusal cannot hide a completed writer whose durable boundary failed.
    # Factory and its UUID setter share one native before/after boundary.
    writer_phases = {part + stage for counter, stage in WRITER_PHASES
                     if info[counter] for part in ('before', 'after')}
    _need(all(info['lifecycle'][p] is True for p in writer_phases),
          'GC99_WRITER_LIFECYCLE_REJECTED')
    for key in ('constantCountBefore', 'constantCountAttached', 'constantCountAfter'):
        _need(type(info[key]) is int and 0 <= info[key] <= 100000, 'GC99_COUNT_REJECTED')
    _need(info['constantCountBefore'] == info['constantCountAfter'], 'GC99_FOREIGN_COUNT_CHANGED')
    terminal_flags = ('baselineClean', 'ownAbsentBefore', 'ownAbsent', 'rootIdentityPreserved',
                      'foreignGraphPreserved', 'goldSourcePreserved', 'taskScopeExited', 'authenticatedDiscardEligible')
    _need(all(info[k] is True for k in terminal_flags)
          and all(info['lifecycle'][p] is True for p in TERMINAL_PHASES)
          and (info['attachCalls'] == 0 or info['ownDeleted'] is True and info['parentCleared'] is True
               and info['deleteCalls'] == 1), 'GC99_TERMINAL_UNVERIFIED')
    if info['canonical'] is not None:
        _canonical(info['canonical'])
    if info['canonicalAfter'] is not None:
        _canonical(info['canonicalAfter'])
        _need(info['canonicalAfter'] == info['canonical'], 'GC99_CANONICAL_CHANGED')
    _need(type(info['defaultTypeClassId']) is str, 'GC99_DEFAULT_TYPE_REJECTED')
    if info['defaultTypeObserved']:
        _need(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', info['defaultTypeClassId']) is not None,
              'GC99_DEFAULT_TYPE_REJECTED')
    else:
        _need(info['defaultTypeClassId'] == '' and info['defaultTypeMutable'] is False,
              'GC99_UNOBSERVED_TYPE_CLAIM_REJECTED')
    if info['defaultTypeVerified']:
        _need(info['defaultTypeObserved'] is True and info['defaultTypeClassId'] == TYPE_DESCRIPTION
              and info['defaultTypeMutable'] is False, 'GC99_IMMUTABLE_DESCRIPTOR_REJECTED')
    implications = (('factoryVerified', 'idSetterCalls'), ('ownAttached', 'attachCalls'),
                    ('ownNamed', 'nameSetterCalls'), ('defaultTypeObserved', 'defaultTypeReadCalls'),
                    ('ownBooleanVerified', 'booleanConstructorCalls'), ('typeSetterReturned', 'typeSetterCalls'),
                    ('freshReadbackVerified', 'freshTypeReadCalls'), ('freshTypeEqual', 'freshTypeReadCalls'),
                    ('ownDeleted', 'deleteCalls'))
    _need(all(not info[flag] or info[counter] == 1 for flag, counter in implications),
          'GC99_FLAG_COUNTER_REJECTED')
    _need(not info['attachCalls'] or info['createdOnlyRegistryVerified'] is True,
          'GC99_ATTACH_WITHOUT_REGISTRY_REJECTED')
    _need(not info['createdOnlyRegistryVerified'] or info['factoryCalls'] == info['idSetterCalls'] == 1
          and info['factoryVerified'] is True and info['canonical'] is not None,
          'GC99_REGISTRY_FACTORY_REJECTED')
    _need(not info['freshTypeEqual'] or info['typeEqualityCalls'] == 2,
          'GC99_FRESH_EQUALITY_REJECTED')
    _need(not info['defaultEqualsBoolean'] or info['typeEqualityCalls'] >= 1,
          'GC99_DEFAULT_EQUALITY_REJECTED')
    registry = _registry(read_marker, info) if info['createdOnlyRegistryVerified'] else None
    verified = info['status'] == 'GOLD_OWNED_CONSTANT_VERIFIED_V99'
    _need(info['ownConstantVerified'] is verified, 'GC99_FALSE_SUCCESS_REJECTED')
    if verified:
        _need(all(info[k] == (2 if k == 'typeEqualityCalls' else 1) for k in COUNTERS)
              and all(info[k] is True for k in FLAGS[:22])
              and info['defaultTypeMutable'] is False and all(info['lifecycle'].values())
              and info['canonical'] is not None and info['canonicalAfter'] == info['canonical']
              and info['constantCountAttached'] == info['constantCountBefore'] + 1,
              'GC99_COMPLETE_UNVERIFIED')
    required_phases = set(PHASES if verified else TERMINAL_PHASES) | writer_phases
    physical = [_marker(read_marker, p, info['operationId'])
                for p in PHASES if p in required_phases]
    return dict(ownConstantVerified=verified, safeTerminalObserved=True,
                safeFailureObserved=not verified, physicalMarkerCount=len(physical),
                physicalMarkers=physical, registry=registry, persistedGoldVerified=False,
                databaseUpdateAuthorized=False, repositoryWritesPermitted=False,
                nativePermit=False, normalDesignerExitVerified=False)
