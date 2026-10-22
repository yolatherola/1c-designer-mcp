"""Pure verification of an isolated own Constant and its terminal source proof.

The caller owns the bounded contained/reparse-safe receipt reader and lease.
This module never performs I/O, stops processes, or grants a Gold writer. A
known capability refusal can prove safe terminal source state without proving
Constant creation/type/readback/deletion. Raw result JSON must be parsed first.
"""
import hashlib
import json
import re

MARKER_LIMIT = REGISTRY_LIMIT = 1024
RESULT_LIMIT = 32768
REGISTRY_FILENAME = 'owned-constant-v77-registry.json'
RESULT_FILENAME = 'owned-constant-v77.json'
PHASES = tuple(part + stage for stage in (
    'SourceRead', 'MemoryFactory', 'OwnConnect', 'ConstantFactory',
    'ConstantAttach', 'NameSetter', 'DefaultRead', 'TypeConstructor',
    'TypeSetter', 'FreshReadback', 'DeleteConstant', 'ScopeExit',
    'FinalSourceControl') for part in ('before', 'after'))
TERMINAL_PHASES = PHASES[-4:]
ZERO_COUNTERS = ('goldSourceWrites', 'goldSaves', 'repositoryWrites',
                 'databaseUpdates', 'businessCalls')
GOLD_ROOT = '218b5d00-7e10-486f-874c-73c2368ed5da'
GOLD_CONTROL_FORM = '0ed914fb-2a1a-4b58-9fad-eaa103b47c9e'
GOLD_CONTROL_FORM_CLASS = 'fb880e93-47d7-4127-9357-a20e69c17545'
FORM_TYPE_PROPERTY = 'e3331ed0-3854-478d-b6b5-4f14acdd6edb'
FORM_TYPE = 'b5fdf93a-40ea-4fc2-8911-2cb676377eff'
OWN_CONSTANT = 'f64e6079-43b1-4584-bbc8-788a6aac63e2'
CONSTANT_CLASS = '0195e80c-b157-11d4-9435-004095e12fc7'
TYPE_PROPERTY = 'b1053250-abe6-11d4-9434-004095e12fc7'
TYPE_DESCRIPTION = 'f5c65050-3bbb-11d5-b988-0050bae0a95d'
CONSTANT_NAME = 'АгентДиагностикаКонстантыV77'
CANONICAL_KEYS = ('goldManager', 'goldRoot', 'goldControlForm', 'ownMemory',
                  'ownManager', 'ownRoot', 'ownConstant')
SNAPSHOT_KEYS = ('rootId', 'constantId', 'constantClassId', 'constantParentId',
                 'rootIndexVerified')
SOURCE_KEYS = ('typeId', 'beforeId', 'afterId', 'carrierBefore', 'carrierAfter',
               'canonicalBefore', 'canonicalAfter', 'typeMutableBefore',
               'typeMutableAfter', 'known', 'heldReadOnly', 'nativeEqualPreserved')
DEFAULT_KEYS = ('observed', 'descriptorVerified', 'classId', 'mutable', 'equalsBoolean')
ATTACHMENT_KEYS = ('ownRootClassId', 'declaredKindCount', 'constantKindDeclared',
                   'childCountBefore', 'childCountAfter', 'rootValidAfter',
                   'receiverValidAfter', 'parentLinkPresent', 'indexPresent',
                   'rawRoot', 'rawRootAsMdObject', 'rawParent', 'rawObject', 'rawIndexed')
ATTACHMENT_FLAGS = ('constantKindDeclared', 'rootValidAfter', 'receiverValidAfter',
                    'parentLinkPresent', 'indexPresent')
ATTACHMENT_NUMBERS = ('declaredKindCount', 'childCountBefore', 'childCountAfter')
ATTACHMENT_ADDRESSES = ('rawRoot', 'rawRootAsMdObject', 'rawParent', 'rawObject', 'rawIndexed')
DELETION_KEYS = ('ownConstantAbsent', 'constantChildCount', 'parentLinkCleared',
                 'managerRootIdentityUnchanged')
COUNTERS = dict(createdOnly=1, memoryFactoryCalls=1, ownConnectCalls=1,
                ownFactoryCalls=1, ownIdSetterCalls=1, ownAttachCalls=1,
                ownNameSetterCalls=1, ownDefaultTypeReadCalls=1,
                ownTypeConstructorCalls=1, ownTypeSetterCalls=1,
                ownFreshTypeReadCalls=1, ownTypeEqualityCalls=2, ownDeleteCalls=1)
FLAGS = ('createdOnlyRegistryVerified', 'memoryFactoryVerified', 'ownManagerVerified',
         'constantFactoryVerified', 'ownAttachVerified', 'ownNameVerified',
         'ownBooleanConstructorVerified', 'ownTypeSetterAbiVerified',
         'ownTypeSetterReturned', 'freshReadbackVerified', 'freshTypeEqual',
         'deletionVerified')
FALSE_CLAIMS = ('qualifierReadbackVerified', 'persistedMemoryVerified',
                'persistedGoldVerified', 'independentBackingVerified', 'deepCloneVerified')
SCOPE = dict(goldRootId=GOLD_ROOT, goldControlFormId=GOLD_CONTROL_FORM,
             goldControlFormClassId=GOLD_CONTROL_FORM_CLASS,
             sourceTypePropertyId=FORM_TYPE_PROPERTY, ownConstantId=OWN_CONSTANT,
             constantClassId=CONSTANT_CLASS, constantTypePropertyId=TYPE_PROPERTY,
             constantName=CONSTANT_NAME)
MAIN_KEYS = ('status', 'version', 'canonical', 'canonicalAfter', 'ownBefore',
             'ownAfter', 'source', 'defaultType', 'deletion', 'sourceControlPreserved',
             'sourceValueUnchanged', 'ownScopeExited', 'nativeException', 'returnUnknown',
             'existingHelpersRequired', 'ownConstantVerified', 'lifecycle', 'attachment') \
    + tuple(SCOPE) + tuple(COUNTERS) + FLAGS + FALSE_CLAIMS + ZERO_COUNTERS
REGISTRY_KEYS = ('stage', 'createdOnly', 'ownRootId', 'capturedSourceVersion',
                 'ownConstantId', 'constantClassId', 'canonical', 'ownFactoryCalls',
                 'ownIdSetterCalls', 'ownAttachCalls', 'attachedIds') + ZERO_COUNTERS
GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _shape(value, keys, code):
    _need(type(value) is dict and set(value) == set(keys), code)


def _uint(value):
    return type(value) is int and 0 < value <= 0xffffffff


def _root_id(value):
    _need(type(value) is str and GUID.fullmatch(value) is not None
          and value not in (GOLD_ROOT, OWN_CONSTANT), 'V77_OWN_ROOT_REJECTED')


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'V77_DUPLICATE_JSON_REJECTED')
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError('V77_JSON_CONSTANT_REJECTED')


def _parse(raw, limit, code):
    _need(type(raw) in (bytes, str), code)
    try:
        payload = raw.encode('utf-8') if type(raw) is str else raw
        _need(0 < len(payload) <= limit, code)
        result = json.loads(payload.decode('utf-8'), object_pairs_hook=_unique_pairs,
                            parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError(code) from None
    _need(type(result) is dict, code)
    return result


def parse_result(raw):
    """Parse fixed-size raw UTF8 JSON while rejecting duplicate nested keys."""
    return _parse(raw, RESULT_LIMIT, 'V77_RESULT_JSON_REJECTED')


def marker_filename(phase):
    _need(type(phase) is str and phase in PHASES, 'V77_PHASE_REJECTED')
    return 'owned-constant-v77-' + phase + '.json'


def _read(reader, filename, limit):
    _need(callable(reader), 'V77_READER_REJECTED')
    try:
        body = reader(filename)
    except Exception:
        raise ValueError('V77_RECEIPT_READ_REJECTED') from None
    _need(type(body) is bytes, 'V77_RECEIPT_BYTES_REJECTED')
    return _parse(body, limit, 'V77_RECEIPT_JSON_REJECTED'), body


def _marker(reader, phase):
    receipt, _ = _read(reader, marker_filename(phase), MARKER_LIMIT)
    _shape(receipt, ('phase',) + ZERO_COUNTERS, 'V77_MARKER_REJECTED')
    _need(receipt['phase'] == phase and all(type(receipt[k]) is int and receipt[k] == 0
          for k in ZERO_COUNTERS), 'V77_MARKER_REJECTED')
    return receipt


def _canonical(value):
    _shape(value, CANONICAL_KEYS, 'V77_CANONICAL_REJECTED')
    _need(all(_uint(item) for item in value.values())
          and len(set(value.values())) == len(CANONICAL_KEYS), 'V77_CANONICAL_REJECTED')


def _snapshot(value, partial=False):
    if partial and type(value) is dict and set(value) == {'rootId'}:
        _root_id(value['rootId'])
        return
    _shape(value, SNAPSHOT_KEYS, 'V77_SNAPSHOT_REJECTED')
    _root_id(value['rootId'])
    _need(value['constantId'] == OWN_CONSTANT and value['constantClassId'] == CONSTANT_CLASS
          and value['constantParentId'] == value['rootId']
          and value['rootIndexVerified'] is True, 'V77_SNAPSHOT_REJECTED')


def _source(value, canonical):
    _shape(value, SOURCE_KEYS, 'V77_SOURCE_REJECTED')
    _need(value['typeId'] == FORM_TYPE and type(value['beforeId']) is int
          and value['beforeId'] in (0, 1) and type(value['afterId']) is int
          and value['afterId'] == value['beforeId'], 'V77_SOURCE_REJECTED')
    for before, after in (('carrierBefore', 'carrierAfter'), ('canonicalBefore', 'canonicalAfter')):
        _need(_uint(value[before]) and _uint(value[after]) and value[before] == value[after]
              and (canonical is None or value[before] not in canonical.values()),
              'V77_SOURCE_ALIAS_REJECTED')
    _need(type(value['typeMutableBefore']) is bool and type(value['typeMutableAfter']) is bool
          and value['typeMutableBefore'] == value['typeMutableAfter']
          and value['known'] is True and value['heldReadOnly'] is True
          and value['nativeEqualPreserved'] is True, 'V77_SOURCE_REJECTED')


def _registry(reader, info):
    """Validate only the fixed physical before-attach receipt; no bool authority."""
    _need(type(info) is dict and type(info.get('ownBefore')) is dict
          and 'rootId' in info['ownBefore'] and 'version' in info and 'canonical' in info,
          'V77_REGISTRY_CONTEXT_REJECTED')
    _root_id(info['ownBefore']['rootId'])
    _canonical(info['canonical'])
    receipt, body = _read(reader, REGISTRY_FILENAME, REGISTRY_LIMIT)
    _shape(receipt, REGISTRY_KEYS, 'V77_REGISTRY_REJECTED')
    _need(receipt['stage'] == 'beforeAttach' and receipt['createdOnly'] is True
          and receipt['ownRootId'] == info['ownBefore']['rootId']
          and type(receipt['capturedSourceVersion']) is int
          and type(info['version']) is int and 0 < info['version'] <= 0x7fffffff
          and receipt['capturedSourceVersion'] == info['version']
          and receipt['ownConstantId'] == OWN_CONSTANT and receipt['constantClassId'] == CONSTANT_CLASS
          and receipt['canonical'] == info['canonical'] and type(receipt['attachedIds']) is list
          and receipt['attachedIds'] == [], 'V77_REGISTRY_REJECTED')
    _canonical(receipt['canonical'])
    _need(all(type(receipt[k]) is int and receipt[k] == expected for k, expected in (
        ('ownFactoryCalls', 1), ('ownIdSetterCalls', 1), ('ownAttachCalls', 0)))
          and all(type(receipt[k]) is int and receipt[k] == 0 for k in ZERO_COUNTERS),
          'V77_REGISTRY_REJECTED')
    return dict(receipt=receipt, sha256=hashlib.sha256(body).hexdigest())


def _partial(info):
    for key, maximum in COUNTERS.items():
        _need(type(info[key]) is int and 0 <= info[key] <= maximum, 'V77_COUNTER_REJECTED')
    _need(info['createdOnly'] == info['ownFactoryCalls']
          and all(type(info[k]) is bool for k in FLAGS), 'V77_COUNTER_OR_FLAG_REJECTED')
    for key in ('canonical', 'canonicalAfter'):
        if info[key] is not None:
            _canonical(info[key])
    for key in ('ownBefore', 'ownAfter'):
        if info[key] is not None:
            _snapshot(info[key], partial=True)
    default = info['defaultType']
    _shape(default, DEFAULT_KEYS, 'V77_DEFAULT_REJECTED')
    _need(all(type(default[k]) is bool for k in DEFAULT_KEYS if k != 'classId'), 'V77_DEFAULT_REJECTED')
    if default['observed']:
        _need(type(default['classId']) is str and GUID.fullmatch(default['classId']) is not None
              and info['ownDefaultTypeReadCalls'] == 1, 'V77_DEFAULT_REJECTED')
    else:
        _need(default['classId'] == '' and default['mutable'] is False
              and default['descriptorVerified'] is False and default['equalsBoolean'] is False,
              'V77_DEFAULT_REJECTED')
    if default['descriptorVerified']:
        _need(default['observed'] is True and default['classId'] == TYPE_DESCRIPTION
              and default['mutable'] is False, 'V77_DEFAULT_REJECTED')
    if default['equalsBoolean']:
        _need(default['descriptorVerified'] is True and info['ownBooleanConstructorVerified'] is True
              and info['ownTypeEqualityCalls'] >= 1, 'V77_DEFAULT_REJECTED')
    if info['deletion'] is not None:
        _shape(info['deletion'], DELETION_KEYS, 'V77_DELETION_REJECTED')
        _need(type(info['deletion']['constantChildCount']) is int
              and info['deletion']['constantChildCount'] in (0, 1)
              and all(type(info['deletion'][k]) is bool for k in DELETION_KEYS if k != 'constantChildCount'),
              'V77_DELETION_REJECTED')
    # A partial observation carries no create/delete authority. Still reject
    # impossible ordering of the exact own writer counters and dependent claims.
    order = ('memoryFactoryCalls', 'ownConnectCalls', 'ownFactoryCalls', 'ownIdSetterCalls',
             'ownAttachCalls', 'ownNameSetterCalls', 'ownDefaultTypeReadCalls',
             'ownTypeConstructorCalls', 'ownTypeSetterCalls', 'ownFreshTypeReadCalls', 'ownDeleteCalls')
    _need(all(info[after] <= info[before] for before, after in zip(order, order[1:])),
          'V77_COUNTER_ORDER_REJECTED')
    requirements = {
        'memoryFactoryVerified': ('memoryFactoryCalls',),
        'ownManagerVerified': ('memoryFactoryVerified', 'ownConnectCalls'),
        'constantFactoryVerified': ('ownManagerVerified', 'ownFactoryCalls', 'ownIdSetterCalls'),
        'createdOnlyRegistryVerified': ('constantFactoryVerified',),
        'ownAttachVerified': ('createdOnlyRegistryVerified', 'ownAttachCalls'),
        'ownNameVerified': ('ownAttachVerified', 'ownNameSetterCalls'),
        'ownBooleanConstructorVerified': ('ownNameVerified', 'ownTypeConstructorCalls'),
        'ownTypeSetterAbiVerified': ('ownBooleanConstructorVerified',),
        'ownTypeSetterReturned': ('ownTypeSetterAbiVerified', 'ownTypeSetterCalls'),
        'freshReadbackVerified': ('ownTypeSetterReturned', 'ownFreshTypeReadCalls', 'freshTypeEqual'),
        'freshTypeEqual': ('ownBooleanConstructorVerified', 'ownFreshTypeReadCalls'),
        'deletionVerified': ('freshReadbackVerified', 'ownDeleteCalls'),
    }
    _need(all(not info[k] or all(info[parent] for parent in parents)
              for k, parents in requirements.items()), 'V77_CLAIM_ORDER_REJECTED')


def _attachment(info, full=False):
    """Validate bounded own observations without treating raw pointers as QI.

    Missing numeric observations are represented by null on early refusal. A
    positive full proof additionally needs the same typed parent/index raw
    addresses; root and root-as-IMDObject may legitimately differ by interface.
    """
    value = info['attachment']
    _shape(value, ATTACHMENT_KEYS, 'V77_ATTACHMENT_SHAPE_REJECTED')
    _need(all(type(value[k]) is bool for k in ATTACHMENT_FLAGS)
          and all(value[k] is None or type(value[k]) is int and 0 <= value[k] <= 64
                  for k in ATTACHMENT_NUMBERS)
          and all(value[k] is None or _uint(value[k]) for k in ATTACHMENT_ADDRESSES),
          'V77_ATTACHMENT_VALUE_REJECTED')
    root_class = value['ownRootClassId']
    _need(type(root_class) is str and (root_class == '' or GUID.fullmatch(root_class) is not None)
          and (root_class == '') is (value['declaredKindCount'] is None)
          and (not value['constantKindDeclared'] or value['declaredKindCount'] is not None
               and value['declaredKindCount'] > 0), 'V77_ATTACHMENT_CLASS_REJECTED')
    _need((value['parentLinkPresent'] or value['rawParent'] is None)
          and (value['indexPresent'] is (value['rawIndexed'] is not None)),
          'V77_ATTACHMENT_POINTER_REJECTED')
    after_observed = any(value[k] for k in ATTACHMENT_FLAGS if k != 'constantKindDeclared') \
        or value['childCountAfter'] is not None or value['rawParent'] is not None or value['rawIndexed'] is not None
    _need(not after_observed or info['ownAttachCalls'] == 1, 'V77_ATTACHMENT_ORDER_REJECTED')
    if full:
        _need(all(value[k] is True for k in ATTACHMENT_FLAGS)
              and all(_uint(value[k]) for k in ATTACHMENT_ADDRESSES)
              and value['childCountBefore'] == 0 and value['childCountAfter'] == 1
              and value['rawParent'] == value['rawRootAsMdObject']
              and value['rawObject'] == value['rawIndexed'], 'V77_ATTACHMENT_PROOF_REJECTED')


def verify(info, version, read_marker):
    """Verify source/scope termination, then the stricter complete Constant proof.

    Only terminal4 witnesses are read on a known UNVERIFIED result. Verified
    requires all26 plus the independent physical before-attach registry. A
    successful result grants no Gold mutation, force stop or cleanup capability.
    """
    _shape(info, MAIN_KEYS, 'V77_RESULT_SHAPE_REJECTED')
    _need(info['status'] in ('OWN_CONSTANT_VERIFIED_V77', 'OWN_CONSTANT_UNVERIFIED_V77')
          and info['nativeException'] is False and info['returnUnknown'] is False
          and info['sourceControlPreserved'] is True and info['sourceValueUnchanged'] is True
          and info['ownScopeExited'] is True and info['existingHelpersRequired'] is True,
          'V77_TERMINAL_OUTCOME_REJECTED')
    _need(type(version) is int and 0 < version <= 0x7fffffff and type(info['version']) is int
          and info['version'] == version, 'V77_VERSION_REJECTED')
    _need(all(info[k] == expected for k, expected in SCOPE.items()), 'V77_SCOPE_REJECTED')
    _need(all(info[k] is False for k in FALSE_CLAIMS)
          and all(type(info[k]) is int and info[k] == 0 for k in ZERO_COUNTERS),
          'V77_WRITE_OR_CLAIM_REJECTED')
    _partial(info)
    _attachment(info)
    _source(info['source'], info['canonical'])
    _shape(info['lifecycle'], PHASES, 'V77_LIFECYCLE_REJECTED')
    _need(all(type(info['lifecycle'][p]) is bool for p in PHASES)
          and all(info['lifecycle'][p] is True for p in TERMINAL_PHASES), 'V77_LIFECYCLE_REJECTED')
    # These receipts remain mandatory even if own default/factory/Type refuses.
    for phase in TERMINAL_PHASES:
        _marker(read_marker, phase)
    full = info['status'] == 'OWN_CONSTANT_VERIFIED_V77'
    _need(info['ownConstantVerified'] is full, 'V77_CONSTANT_CLAIM_REJECTED')
    registry_hash = None
    if full:
        _attachment(info, full=True)
        _need(all(info[k] == expected for k, expected in COUNTERS.items())
              and all(info[k] is True for k in FLAGS)
              and all(info['lifecycle'][p] is True for p in PHASES), 'V77_CONSTANT_PROOF_REJECTED')
        _canonical(info['canonical'])
        _canonical(info['canonicalAfter'])
        _need(info['canonical'] == info['canonicalAfter'], 'V77_CANONICAL_CHANGED')
        _snapshot(info['ownBefore'])
        _snapshot(info['ownAfter'])
        _need(info['ownBefore'] == info['ownAfter']
              and info['defaultType']['descriptorVerified'] is True, 'V77_CONSTANT_PROOF_REJECTED')
        _shape(info['deletion'], DELETION_KEYS, 'V77_DELETION_REJECTED')
        _need(info['deletion']['constantChildCount'] == 0 and all(info['deletion'][k] is True
              for k in DELETION_KEYS if k != 'constantChildCount'), 'V77_DELETION_REJECTED')
        for phase in PHASES:
            if phase not in TERMINAL_PHASES:
                _marker(read_marker, phase)
        registry_hash = _registry(read_marker, info)['sha256']
    return dict(sourceObservationVerified=True, ownConstantVerified=full, safeFailureClose=not full,
                physicalMarkerCount=len(PHASES) if full else len(TERMINAL_PHASES),
                registryVerified=full, registrySha256=registry_hash,
                ownConstantId=OWN_CONSTANT, sourceTypeMutable=info['source']['typeMutableBefore'],
                attachment=dict(info['attachment']),
                persistedMemoryVerified=False, persistedGoldVerified=False,
                independentBackingVerified=False, deepCloneVerified=False,
                qualifierReadbackVerified=False, goldWritesPermitted=False,
                repositoryWritesPermitted=False, cleanupGranted=False)
