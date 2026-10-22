"""Pure own managed-form proof without configuration dump/load or persistence.

Only a fixed emitted form-body resource may be read through a trusted bounded
reader. No fixture code executes, no file/process changes, and no Gold-writing,
capture, repository placement, stop or cleanup authority is granted.
"""
import hashlib
import json

import managed_form_type_guard_v74 as _type
import managed_layout_contract_v80 as _layout

OWN_PROCESSING = _type.OWN_PROCESSING
OWN_FORM = _type.OWN_FORM
PROCESSING_CLASS = _type.PROCESSING_CLASS
FORM_CLASS = _type.FORM_CLASS
GOLD_ROOT = _type.GOLD_ROOT
GOLD_CONTROL_FORM = _type.GOLD_CONTROL_FORM
FORM_TYPE = _type.FORM_TYPE
ZERO_COUNTERS = _type.ZERO_COUNTERS
REGISTRY_FILENAME = 'owned-managed-layout-v80-registry.json'
REGISTRY_LIMIT = MARKER_LIMIT = 1024
RESULT_LIMIT = 32768
BODY_FILENAME = 'owned-managed-layout-v80-body-resource.bin'
BINARY_LIMIT = 1048576
MODULE_FIXTURE_SHA256 = _layout.MODULE_SHA
MODULE_CHARACTER_COUNT = len(_layout.MODULE)
PROCESSING_NAME = 'АгентУправляемаяФормаV80'
FORM_NAME = 'ФормаV80'
GROUP_NAME = 'ГруппаПроверкиV80'
_PAIRS = ('SourceRead', 'ProcessingFactory', 'FormFactory', 'ProcessingAttach',
    'FormAttach', 'TypeSetter', 'Readback', 'Names', 'BodyFactory', 'ModuleWrite',
    'SeedSave', 'SeedLoad', 'GroupFactory', 'GroupSet', 'GroupAdd',
    'AttributeFactory', 'AttributeSerialize', 'AttributeDeserialize', 'AttributeReserialize',
    'CommandFactory', 'CommandSerialize', 'CommandDeserialize', 'CommandReserialize',
    'ButtonFactory', 'ButtonSerialize', 'ButtonDeserialize', 'ButtonReserialize',
    'LayoutBuild', 'LayoutLoad', 'BodySave', 'PayloadWrite', 'BoundBodyFactory',
    'BoundBodyLoad', 'BodyStore')
PHASES = tuple(part + stage for stage in _PAIRS for part in ('before', 'after')) + (
    'beforeBodyReadback', 'beforeFreshResourceSave', 'afterFreshResourceSave', 'afterBodyReadback',
    'beforeDeleteForm', 'afterDeleteForm', 'beforeDeleteProcessing', 'afterDeleteProcessing',
    'beforeScopeExit', 'afterScopeExit', 'beforeFinalSourceControl', 'afterFinalSourceControl')
BEFORE_FILENAME = 'owned-managed-layout-v80-before-resource.bin'
FRESH_FILENAME = 'owned-managed-layout-v80-fresh-resource.bin'
TEMPLATE_FILENAMES = tuple('owned-managed-layout-v80-' + name + '-template.bin'
                           for name in ('attribute', 'command', 'button'))
BINARY_FILENAMES = (BEFORE_FILENAME,) + TEMPLATE_FILENAMES + (BODY_FILENAME, FRESH_FILENAME)
RECORD_KEYS = ('classId', 'factoryCalls', 'serializeCalls', 'deserializeCalls',
               'abiVerified', 'roundtripVerified', 'inputConsumed', 'sourceCanonical',
               'cloneCanonical', 'templateFilename', 'templateBytes', 'rawCanaryVerified',
               'gate', 'sourceReturnedBool', 'cloneReturnedBool', 'sourceNonNull', 'cloneNonNull')
BODY_COUNTERS = dict(bodyFactoryCalls=1, ownNameSetterCalls=2, moduleWriteCalls=1,
                     groupFactoryCalls=1, groupSetCalls=1, groupAddCalls=1,
                     bodySaveCalls=8, bodyLoadCalls=3, boundBodyFactoryCalls=1,
                     bodyStoreCalls=1, ownDeleteCalls=2)
BODY_FLAGS = ('verified', 'ownNamesVerified', 'moduleFixtureVerified',
              'groupAddedBeforeFinalSave', 'boundBodyReadbackVerified',
              'noCachedBodyReadback', 'ownFormRemoved', 'ownProcessingRemoved',
              'ownedMemoryOnly')
PREWRITE_GATES = ('notEntered', 'factory', 'primary', 'canonical', 'document',
                  'getter', 'defaultText', 'prewritePassed')
BODY_KEYS = BODY_FLAGS + tuple(BODY_COUNTERS) + (
    'moduleFixtureSha256', 'moduleCharacterCount', 'bodyFilename', 'bodyBytes',
    'readback', 'deletion', 'prewriteGate', 'layoutVerified', 'layoutLoadCalls', 'records')
READBACK_KEYS = ('verified', 'scope', 'canonical', 'moduleTextEqual',
                 'moduleFixtureSha256', 'moduleCharacterCount', 'groupId',
                 'groupName', 'groupCount', 'typeId', 'nativeEqual', 'freshBody')
DELETION_KEYS = ('ownFormAbsent', 'ownProcessingAbsent', 'processingChildCount',
                 'formLinkCleared', 'processingLinkCleared', 'managerRootIdentityUnchanged')
FALSE_CLAIMS = ('persistedMemoryVerified', 'persistedGoldVerified',
                'independentBackingVerified', 'deepCloneVerified', 'physicalProfileVerified')


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _shape(value, keys, code):
    _need(type(value) is dict and set(value) == set(keys), code)


def _reject_json_constant(_value):
    raise ValueError('V80_RESULT_JSON_REJECTED')


def parse_result(raw):
    """Parse bounded main JSON without discarding duplicate keys at any depth."""
    _need(type(raw) in (bytes, str), 'V80_RESULT_JSON_REJECTED')
    try:
        payload = raw.encode('utf-8') if type(raw) is str else raw
        _need(0 < len(payload) <= RESULT_LIMIT, 'V80_RESULT_JSON_REJECTED')
        value = json.loads(payload.decode('utf-8'), object_pairs_hook=_type._unique_pairs,
                           parse_constant=_reject_json_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('V80_RESULT_JSON_REJECTED') from None
    _need(type(value) is dict, 'V80_RESULT_JSON_REJECTED')
    return value


def prewrite_gate(body):
    """Validate one fixed diagnostic stage, without granting action or full success.

    A stage identifies the active guard, including its existing marker I/O and
    nested checks. Even prewritePassed does not prove the later body pipeline.
    The current schema deliberately rejects historical bodies missing this field.
    """
    _shape(body, BODY_KEYS, 'V80_BODY_REJECTED')
    gate = body['prewriteGate']
    _need(type(gate) is str and gate in PREWRITE_GATES, 'V80_PREWRITE_GATE_REJECTED')
    return gate


def marker_filename(phase):
    """Return one exact witness basename without path resolution or I/O."""
    _need(type(phase) is str and phase in PHASES, 'V80_PHASE_REJECTED')
    return 'owned-managed-layout-v80-' + phase + '.json'


def _json_file(reader, filename):
    _need(callable(reader), 'V80_MARKER_READ_REJECTED')
    try:
        body = reader(filename)
    except Exception:
        raise ValueError('V80_MARKER_READ_REJECTED') from None
    _need(type(body) is bytes and 0 < len(body) <= MARKER_LIMIT, 'V80_MARKER_SIZE_REJECTED')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_type._unique_pairs)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('V80_MARKER_CONTENT_REJECTED') from None
    return value


def _marker(reader, phase):
    value = _json_file(reader, marker_filename(phase))
    _shape(value, ('phase',) + ZERO_COUNTERS, 'V80_MARKER_CONTENT_REJECTED')
    _need(value['phase'] == phase and all(type(value[key]) is int and value[key] == 0
                                        for key in ZERO_COUNTERS), 'V80_MARKER_CONTENT_REJECTED')


def _registry(read_marker, info):
    """Verify an emitted before-attach canary; partial evidence grants no action.

    The frozen type guard's exact canary schema is reused with this one basename.
    A partial ownBefore.rootId observation cannot become final success.
    """
    def fixed_reader(name):
        _need(name == _type.REGISTRY_FILENAME and callable(read_marker),
              'V80_REGISTRY_READ_REJECTED')
        return read_marker(REGISTRY_FILENAME)
    try:
        return _type._registry(fixed_reader, info)
    except ValueError:
        raise ValueError('V80_REGISTRY_REJECTED') from None


def _read_body(reader, count):
    _need(callable(reader), 'V80_BODY_RESOURCE_READ_REJECTED')
    try:
        body = reader(BODY_FILENAME)
    except Exception:
        raise ValueError('V80_BODY_RESOURCE_READ_REJECTED') from None
    _need(type(body) is bytes and 16 < len(body) <= BINARY_LIMIT
          and type(count) is int and len(body) == count, 'V80_BODY_RESOURCE_SIZE_REJECTED')
    return body


def _timing(info):
    verified, elapsed, setter = (info.get(key) for key in
                                ('nativeTimingVerified', 'nativeElapsedUs', 'ownTypeSetterElapsedUs'))
    _need(type(verified) is bool and type(elapsed) is int and type(setter) is int,
          'V80_TIMING_REJECTED')
    _need((verified and 0 <= setter <= elapsed <= 0x7fffffffffffffff)
          or (not verified and elapsed == -1 and setter == -1), 'V80_TIMING_REJECTED')
    return dict(nativeTimingVerified=verified, nativeElapsedUs=elapsed,
                ownTypeSetterElapsedUs=setter)


def _body(value, enum, canonical, snapshot):
    _need(prewrite_gate(value) == 'prewritePassed', 'V80_PREWRITE_GATE_REJECTED')
    _need(all(value[key] is True for key in BODY_FLAGS)
          and all(type(value[key]) is int and value[key] == count
                  for key, count in BODY_COUNTERS.items()), 'V80_BODY_COUNTER_REJECTED')
    _need(value['moduleFixtureSha256'] == MODULE_FIXTURE_SHA256
          and type(value['moduleCharacterCount']) is int
          and value['moduleCharacterCount'] == MODULE_CHARACTER_COUNT
          and value['bodyFilename'] == BODY_FILENAME and type(value['bodyBytes']) is int
          and 16 < value['bodyBytes'] <= BINARY_LIMIT, 'V80_MODULE_PROOF_REJECTED')
    readback = value['readback']
    _shape(readback, READBACK_KEYS, 'V80_READBACK_REJECTED')
    _type._snapshot(readback['scope'])
    _need(readback['scope'] == snapshot and all(readback[key] is True for key in
          ('verified', 'moduleTextEqual', 'nativeEqual', 'freshBody'))
          and readback['moduleFixtureSha256'] == MODULE_FIXTURE_SHA256
          and type(readback['moduleCharacterCount']) is int
          and readback['moduleCharacterCount'] == MODULE_CHARACTER_COUNT
          and type(readback['groupId']) is int and readback['groupId'] == 1001
          and readback['groupName'] == GROUP_NAME
          and type(readback['groupCount']) is int and readback['groupCount'] == 1
          and type(readback['typeId']) is int and readback['typeId'] == enum['sourceBeforeId'],
          'V80_READBACK_REJECTED')
    identities = readback['canonical']
    _shape(identities, ('first', 'bound', 'fresh'), 'V80_FRESH_BODY_REJECTED')
    occupied = set(canonical.values()) | {enum['sourceCanonicalBefore']}
    _need(all(_type._uint(pointer) for pointer in identities.values())
          and len(set(identities.values())) == 3
          and set(identities.values()).isdisjoint(occupied), 'V80_FRESH_BODY_REJECTED')
    deletion = value['deletion']
    _shape(deletion, DELETION_KEYS, 'V80_DELETION_REJECTED')
    _need(type(deletion['processingChildCount']) is int and deletion['processingChildCount'] == 0
          and all(deletion[key] is True for key in DELETION_KEYS if key != 'processingChildCount'),
          'V80_DELETION_REJECTED')


def verify(info, version, read_marker, read_binary=None):
    """Verify one owned form/body construction, fresh readback and exact deletion.

    Readers must be the trusted host's bounded, reparse-safe own file readers.
    Only 80 phase basenames, the before-attach registry and BODY_FILENAME are
    requested. Complete native schema emits that resource, so its reader is
    required. Expected fixture SHA is a reference; full native text equality
    and the actual harmless module readback are required separately. Timers are
    diagnostic only; no native speed or persistence claim follows from them.
    """
    _need(type(info) is dict and info.get('status') == 'OWN_MANAGED_LAYOUT_VERIFIED_V80'
          and info.get('nativeException') is False and info.get('returnUnknown') is False,
          'V80_OUTCOME_REJECTED')
    _need(type(version) is int and version > 0 and type(info.get('version')) is int
          and info['version'] == version, 'V80_VERSION_REJECTED')
    timing = _timing(info)
    expected = dict(goldRootId=GOLD_ROOT, goldControlFormId=GOLD_CONTROL_FORM,
                    goldControlFormClassId=_type.GOLD_CONTROL_FORM_CLASS,
                    formTypePropertyId=_type.FORM_TYPE_PROPERTY, **_type.OWN_FIELDS)
    _need(all(info.get(key) == value for key, value in expected.items()), 'V80_SCOPE_REJECTED')
    _need(all(info.get(key) is True for key in ('sourceControlPreserved', 'sourceValueUnchanged',
              'managedKindVerified', 'managedFormVerified', 'formBodyVerified',
              'createdOnlyRegistryVerified', 'ownScopeExited'))
          and all(info.get(key) is False for key in FALSE_CLAIMS), 'V80_CLAIM_REJECTED')
    canonical = info.get('canonical')
    _type._canonical(canonical)
    _type._canonical(info.get('canonicalAfter'))
    _need(canonical == info['canonicalAfter'], 'V80_CANONICAL_CHANGED')
    for key in ('ownBefore', 'ownAfter'):
        _type._snapshot(info.get(key))
    _need(info['ownBefore'] == info['ownAfter'], 'V80_SNAPSHOT_CHANGED')
    source, mutable = _type._enum(info.get('enum'), canonical)
    _need(all(type(info.get(key)) is int and info[key] == count
              for key, count in _type.COUNTERS.items())
          and all(type(info.get(key)) is int and info[key] == 0 for key in ZERO_COUNTERS),
          'V80_COUNTER_REJECTED')
    _body(info.get('body'), info['enum'], canonical, info['ownAfter'])
    _need(info['body'].get('layoutVerified') is True
          and type(info['body'].get('layoutLoadCalls')) is int
          and info['body']['layoutLoadCalls'] == 1, 'V80_LAYOUT_REJECTED')
    records = info['body'].get('records')
    _need(type(records) is list and len(records) == 3, 'V80_RECORDS_REJECTED')
    occupied = set(canonical.values()) | {info['enum']['sourceCanonicalBefore']}
    # The first body is held throughout template creation. Bound/fresh bodies
    # are allocated later and may legally reuse released record addresses.
    occupied.add(info['body']['readback']['canonical']['first'])
    for index, record in enumerate(records):
        _shape(record, RECORD_KEYS, 'V80_RECORD_REJECTED')
        _need(record['classId'] == _layout.RECORDS[index][0]
              and record['templateFilename'] == TEMPLATE_FILENAMES[index]
              and all(type(record[key]) is int and record[key] == count for key, count in
                      (('factoryCalls', 2), ('serializeCalls', 2), ('deserializeCalls', 1)))
              and all(record[key] is True for key in ('abiVerified', 'roundtripVerified', 'inputConsumed'))
              and record['rawCanaryVerified'] is False and record['gate'] == 'passed'
              and all(record[key] is True for key in ('sourceReturnedBool', 'cloneReturnedBool', 'sourceNonNull', 'cloneNonNull')),
              'V80_RECORD_REJECTED')
        pair = (record['sourceCanonical'], record['cloneCanonical'])
        # Each pair was live together. Pairs from different released scopes may reuse addresses.
        _need(all(_type._uint(pointer) for pointer in pair) and pair[0] != pair[1]
              and set(pair).isdisjoint(occupied), 'V80_RECORD_IDENTITY_REJECTED')
    lifecycle = info.get('lifecycle')
    _shape(lifecycle, PHASES, 'V80_LIFECYCLE_REJECTED')
    _need(all(lifecycle[phase] is True for phase in PHASES), 'V80_LIFECYCLE_REJECTED')
    for phase in PHASES:
        _marker(read_marker, phase)
    registry = _registry(read_marker, info)
    binaries = {}
    _need(callable(read_binary), 'V80_BINARY_READER_REJECTED')
    for filename in BINARY_FILENAMES:
        try:
            raw = read_binary(filename)
        except Exception:
            raise ValueError('V80_BINARY_READER_REJECTED') from None
        _need(type(raw) is bytes and 16 < len(raw) <= BINARY_LIMIT, 'V80_BINARY_SIZE_REJECTED')
        binaries[filename] = raw
    _need(len(binaries[BODY_FILENAME]) == info['body']['bodyBytes'], 'V80_BODY_RESOURCE_SIZE_REJECTED')
    for record in records:
        _need(type(record['templateBytes']) is int
              and record['templateBytes'] == len(binaries[record['templateFilename']]), 'V80_TEMPLATE_SIZE_REJECTED')
    try:
        _layout.preserved_fields(binaries[BEFORE_FILENAME], binaries[BODY_FILENAME],
                                 *(binaries[name] for name in TEMPLATE_FILENAMES))
        layout = _layout.inspect_resource(binaries[FRESH_FILENAME])
        _need(_layout.form_tree(binaries[BODY_FILENAME]) == _layout.form_tree(binaries[FRESH_FILENAME]),
              'V80_FRESH_RESOURCE_CHANGED')
    except (ValueError, TypeError, IndexError):
        raise ValueError('V80_RESOURCE_PROFILE_REJECTED') from None
    body = binaries[BODY_FILENAME]
    return dict(ownedManagedLayoutVerified=True, ownedManagedFormVerified=True, managedKindVerified=True,
                layout=layout, templateRoundtripVerified=True, recordFactoryCalls=6,
                resourceProfileVerified=True, resourceCount=6,
                managedFormVerified=True, formBodyVerified=True, sourceId=source,
                sourceTypeMutable=mutable, physicalMarkerCount=len(PHASES),
                registryPhysicallyVerified=True, registry=registry['registry'],
                registrySha256=registry['sha256'], registryBytes=registry['bytes'],
                bodyResourceVerified=True, bodyResourceBytes=len(body),
                bodyResourceSha256=hashlib.sha256(body).hexdigest(),
                moduleFixtureSha256=MODULE_FIXTURE_SHA256,
                moduleCharacterCount=MODULE_CHARACTER_COUNT,
                persistedMemoryVerified=False, persistedGoldVerified=False,
                independentBackingVerified=False, deepCloneVerified=False,
                physicalProfileVerified=False, **timing)
