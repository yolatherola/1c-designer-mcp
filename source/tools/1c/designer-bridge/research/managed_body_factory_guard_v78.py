"""Pure verification of one published V78 body-factory observation.

Only the trusted caller reads owned runtime files. This module requests ten fixed
receipt basenames, never configuration/CF/body data, and grants no write or
cleanup capability. A failed factory can be a verified observation.
"""
import json
import re

MARKER_LIMIT = 1024
RESULT_LIMIT = 32768
PHASES = ('beforeSourceRead', 'afterSourceRead', 'beforeFactory', 'afterFactory',
          'beforeInspect', 'afterInspect', 'beforeScopeExit', 'afterScopeExit',
          'beforeFinalSourceControl', 'afterFinalSourceControl')
ZERO_COUNTERS = ('goldSourceWrites', 'goldSaves', 'repositoryWrites',
                 'databaseUpdates', 'businessCalls')
GOLD_ROOT = '218b5d00-7e10-486f-874c-73c2368ed5da'
GOLD_CONTROL_FORM = '0ed914fb-2a1a-4b58-9fad-eaa103b47c9e'
GOLD_CONTROL_FORM_CLASS = 'fb880e93-47d7-4127-9357-a20e69c17545'
FORM_TYPE_PROPERTY = 'e3331ed0-3854-478d-b6b5-4f14acdd6edb'
FORM_TYPE = 'b5fdf93a-40ea-4fc2-8911-2cb676377eff'
BODY_CLASS = '5e44d99d-7d52-49bf-bc73-4dc0b575b8fb'
UNKNOWN_IID = '00000000-0000-0000-c000-000000000046'
CANONICAL_KEYS = ('goldManager', 'goldRoot', 'goldControlForm')
SOURCE_KEYS = ('typeId', 'beforeId', 'afterId', 'beforeCarrier', 'afterCarrier',
               'beforeCanonical', 'afterCanonical', 'beforeTypeMutable',
               'afterTypeMutable', 'nativeEqualPreserved', 'heldReadOnly')
FACTORY_KEYS = ('route', 'requestedClassId', 'requestedIid', 'callCount',
                'callReturned', 'returnedBool', 'outputNonNull', 'sdkOutCounted',
                'rawOutputAdapterUsed', 'outputCanaryVerified',
                'mngcoreLoadedBefore', 'mngcoreLoadedAfter', 'inspection')
INSPECTION_KEYS = ('primaryTable', 'primarySlots', 'primaryAbiVerified', 'canonical',
                   'sourceDisjointVerified', 'documentQiSucceeded',
                   'documentAbiVerified', 'documentTable', 'persistenceQiSucceeded',
                   'persistenceAbiVerified', 'persistenceTable', 'getClsidCalls',
                   'observedClassId', 'classVerified')
INSPECTION_BOOLS = ('primaryAbiVerified', 'sourceDisjointVerified',
                    'documentQiSucceeded', 'documentAbiVerified',
                    'persistenceQiSucceeded', 'persistenceAbiVerified', 'classVerified')
FALSE_CLAIMS = ('managedKindVerified', 'managedFormVerified', 'formBodyVerified',
                'persistedMemoryVerified', 'persistedGoldVerified',
                'independentBackingVerified', 'deepCloneVerified')
WRITE_COUNTERS = ('metadataFactories', 'metadataAttachCalls', 'metadataSetters', 'bodyWriters')
MAIN_KEYS = ('status', 'version', 'goldRootId', 'goldControlFormId',
             'goldControlFormClassId', 'formTypePropertyId', 'canonicalBefore',
             'canonicalAfter', 'source', 'factory', 'observationVerified',
             'bodyFactoryVerified', 'sourceControlPreserved', 'sourceValueUnchanged',
             'nativeException', 'returnUnknown', 'ownScopeExited', 'lifecycle') \
    + FALSE_CLAIMS + WRITE_COUNTERS + ZERO_COUNTERS
SLOT_RVAS = dict(queryInterface=0x2ccbf0, addRef=0xaf1b0, release=0x2ccc10,
                 layout=0x9d0a0, module=0xa55a0)
PRIMARY_RVA = 0x6654ac
DOCUMENT_RVA = 0x665454
PERSISTENCE_RVA = 0x66543c
GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
MODULE = re.compile(r'[a-zA-Z0-9_-]{1,58}\.(?:dll|exe)')


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _shape(value, keys, code):
    _need(type(value) is dict and set(value) == set(keys), code)


def _uint(value, zero=False):
    return type(value) is int and (0 if zero else 1) <= value <= 0xffffffff


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'V78_DUPLICATE_JSON_REJECTED')
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError('V78_JSON_CONSTANT_REJECTED')


def _parse(raw, limit, code):
    _need(type(raw) in (bytes, str), code)
    try:
        payload = raw.encode('utf-8') if type(raw) is str else raw
        _need(0 < len(payload) <= limit, code)
        value = json.loads(payload.decode('utf-8'), object_pairs_hook=_unique_pairs,
                           parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError(code) from None
    _need(type(value) is dict, code)
    return value


def parse_result(raw):
    """Parse bounded raw JSON without discarding duplicate keys, including nested keys."""
    return _parse(raw, RESULT_LIMIT, 'V78_RESULT_JSON_REJECTED')


def marker_filename(phase):
    """Return one fixed receipt basename, without resolving a path or reading a file."""
    _need(type(phase) is str and phase in PHASES, 'V78_PHASE_REJECTED')
    return 'managed-body-factory-v78-' + phase + '.json'


def _marker(reader, phase):
    _need(callable(reader), 'V78_MARKER_READER_REJECTED')
    filename = marker_filename(phase)
    try:
        raw = reader(filename)
    except Exception:
        raise ValueError('V78_MARKER_READ_REJECTED') from None
    _need(type(raw) is bytes, 'V78_MARKER_REJECTED')
    receipt = _parse(raw, MARKER_LIMIT, 'V78_MARKER_REJECTED')
    _shape(receipt, ('phase',) + ZERO_COUNTERS, 'V78_MARKER_REJECTED')
    _need(receipt['phase'] == phase and all(type(receipt[key]) is int
          and receipt[key] == 0 for key in ZERO_COUNTERS), 'V78_MARKER_REJECTED')
    return receipt


def _canonical(value):
    _shape(value, CANONICAL_KEYS, 'V78_CANONICAL_REJECTED')
    _need(all(_uint(item) for item in value.values())
          and len(set(value.values())) == len(CANONICAL_KEYS), 'V78_CANONICAL_REJECTED')


def _source(value, canonical):
    _shape(value, SOURCE_KEYS, 'V78_SOURCE_REJECTED')
    _need(value['typeId'] == FORM_TYPE and type(value['beforeId']) is int
          and value['beforeId'] in (0, 1) and type(value['afterId']) is int
          and value['afterId'] == value['beforeId'], 'V78_SOURCE_REJECTED')
    for before, after in (('beforeCarrier', 'afterCarrier'),
                          ('beforeCanonical', 'afterCanonical')):
        _need(_uint(value[before]) and _uint(value[after]) and value[before] == value[after]
              and value[before] not in canonical.values(), 'V78_SOURCE_ALIAS_REJECTED')
    _need(type(value['beforeTypeMutable']) is bool and type(value['afterTypeMutable']) is bool
          and value['beforeTypeMutable'] == value['afterTypeMutable']
          and value['nativeEqualPreserved'] is True and value['heldReadOnly'] is True,
          'V78_SOURCE_REJECTED')


def _address(value):
    if value is None:
        return
    _shape(value, ('module', 'rva'), 'V78_ADDRESS_REJECTED')
    _need(type(value['module']) is str and MODULE.fullmatch(value['module']) is not None
          and _uint(value['rva'], zero=True), 'V78_ADDRESS_REJECTED')


def _known_address(value, rva):
    return value == dict(module='mngcore.dll', rva=rva)


def _inactive(value):
    _need(value['canonical'] == 0 and value['sourceDisjointVerified'] is False
          and value['documentQiSucceeded'] is False and value['documentAbiVerified'] is False
          and value['documentTable'] is None and value['persistenceQiSucceeded'] is False
          and value['persistenceAbiVerified'] is False and value['persistenceTable'] is None
          and value['getClsidCalls'] == 0 and value['observedClassId'] is None
          and value['classVerified'] is False, 'V78_UNKNOWN_QI_REJECTED')


def _inspection(factory, source, canonical):
    value = factory['inspection']
    _shape(value, INSPECTION_KEYS, 'V78_INSPECTION_REJECTED')
    _need(all(type(value[key]) is bool for key in INSPECTION_BOOLS)
          and _uint(value['canonical'], zero=True) and type(value['getClsidCalls']) is int
          and value['getClsidCalls'] in (0, 1), 'V78_INSPECTION_REJECTED')
    for key in ('primaryTable', 'documentTable', 'persistenceTable'):
        _address(value[key])
    made = factory['returnedBool']
    nonnull = factory['outputNonNull']
    if not nonnull:
        _need(value['primaryTable'] is None, 'V78_NULL_OUTPUT_REJECTED')
    known_primary = made and nonnull and _known_address(value['primaryTable'], PRIMARY_RVA)
    if known_primary:
        _shape(value['primarySlots'], SLOT_RVAS, 'V78_PRIMARY_SLOTS_REJECTED')
        for item in value['primarySlots'].values():
            _address(item)
        slots_match = all(_known_address(value['primarySlots'][key], rva)
                          for key, rva in SLOT_RVAS.items())
        _need(value['primaryAbiVerified'] is slots_match, 'V78_PRIMARY_ABI_REJECTED')
    else:
        _need(value['primarySlots'] is None and value['primaryAbiVerified'] is False,
              'V78_UNKNOWN_SLOTS_REJECTED')
    if not (known_primary and value['primaryAbiVerified']):
        _inactive(value)
        return False
    own = value['canonical']
    forbidden = set(canonical.values()) | {source['beforeCarrier'], source['beforeCanonical']}
    _need(own == 0 or own not in forbidden, 'V78_FACTORY_SOURCE_ALIAS_REJECTED')
    if not value['sourceDisjointVerified']:
        # Known QI can fail or identify a different primary. No further methods are permitted.
        inactive = dict(value, canonical=0)
        _inactive(inactive)
        return False
    _need(_uint(own), 'V78_DISJOINT_REJECTED')
    for prefix, rva in (('document', DOCUMENT_RVA), ('persistence', PERSISTENCE_RVA)):
        qi, abi, table = value[prefix + 'QiSucceeded'], value[prefix + 'AbiVerified'], value[prefix + 'Table']
        if not qi:
            _need(abi is False and table is None, 'V78_QI_RESULT_REJECTED')
        if abi:
            _need(qi is True and _known_address(table, rva), 'V78_TYPED_ABI_REJECTED')
    if value['persistenceAbiVerified']:
        _need(value['getClsidCalls'] == 1 and type(value['observedClassId']) is str
              and GUID.fullmatch(value['observedClassId']) is not None,
              'V78_CLASS_GETTER_REJECTED')
        _need(value['classVerified'] is (value['observedClassId'] == BODY_CLASS),
              'V78_CLASS_REJECTED')
    else:
        _need(value['getClsidCalls'] == 0 and value['observedClassId'] is None
              and value['classVerified'] is False, 'V78_UNKNOWN_CLASS_GETTER_REJECTED')
    return (factory['mngcoreLoadedAfter'] and value['documentAbiVerified']
            and value['persistenceAbiVerified'] and value['classVerified'])


def verify(info, version, read_marker):
    """Verify an observation and distinguish the stricter known body-factory result.

    Call parse_result on the raw main response first. read_marker must be the
    caller's bounded, contained, reparse-safe reader for this owned session. Exact
    interface flags require the separate frozen fixed-PE/SDK prerequisite; JSON
    cannot prove its own native ABI. No managed body or persistence is claimed.
    """
    _shape(info, MAIN_KEYS, 'V78_RESULT_SHAPE_REJECTED')
    _need(info['status'] == 'MANAGED_BODY_FACTORY_OBSERVED_V78'
          and info['observationVerified'] is True and info['sourceControlPreserved'] is True
          and info['sourceValueUnchanged'] is True and info['ownScopeExited'] is True
          and info['nativeException'] is False and info['returnUnknown'] is False
          and type(info['bodyFactoryVerified']) is bool, 'V78_OUTCOME_REJECTED')
    _need(type(version) is int and 0 < version <= 0x7fffffff and type(info['version']) is int
          and info['version'] == version, 'V78_VERSION_REJECTED')
    expected = dict(goldRootId=GOLD_ROOT, goldControlFormId=GOLD_CONTROL_FORM,
                    goldControlFormClassId=GOLD_CONTROL_FORM_CLASS,
                    formTypePropertyId=FORM_TYPE_PROPERTY)
    _need(all(info[key] == item for key, item in expected.items()), 'V78_SCOPE_REJECTED')
    _need(all(info[key] is False for key in FALSE_CLAIMS)
          and all(type(info[key]) is int and info[key] == 0
                  for key in WRITE_COUNTERS + ZERO_COUNTERS), 'V78_WRITE_OR_CLAIM_REJECTED')
    _canonical(info['canonicalBefore'])
    _canonical(info['canonicalAfter'])
    _need(info['canonicalBefore'] == info['canonicalAfter'], 'V78_CANONICAL_CHANGED')
    _source(info['source'], info['canonicalBefore'])
    factory = info['factory']
    _shape(factory, FACTORY_KEYS, 'V78_FACTORY_REJECTED')
    _need(factory['route'] == 'publishedSCOM' and factory['requestedClassId'] == BODY_CLASS
          and factory['requestedIid'] == UNKNOWN_IID and type(factory['callCount']) is int
          and factory['callCount'] == 1 and factory['callReturned'] is True
          and factory['sdkOutCounted'] is True and factory['rawOutputAdapterUsed'] is False
          and factory['outputCanaryVerified'] is False
          and all(type(factory[key]) is bool for key in ('returnedBool', 'outputNonNull',
                  'mngcoreLoadedBefore', 'mngcoreLoadedAfter')), 'V78_FACTORY_REJECTED')
    verified = _inspection(factory, info['source'], info['canonicalBefore'])
    _need(info['bodyFactoryVerified'] is verified, 'V78_FACTORY_CLAIM_REJECTED')
    _shape(info['lifecycle'], PHASES, 'V78_LIFECYCLE_REJECTED')
    _need(all(info['lifecycle'][phase] is True for phase in PHASES), 'V78_LIFECYCLE_REJECTED')
    for phase in PHASES:
        _marker(read_marker, phase)
    return dict(observationVerified=True, bodyFactoryVerified=verified,
                physicalMarkerCount=len(PHASES), managedKindVerified=False,
                managedFormVerified=False, formBodyVerified=False,
                persistedMemoryVerified=False, persistedGoldVerified=False,
                independentBackingVerified=False, deepCloneVerified=False)
