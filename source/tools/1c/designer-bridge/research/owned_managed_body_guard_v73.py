"""Pure own managed-body result and physical CF pair checks.

Trusted callers supply bounded, reparse-safe readers for the exact owned files.
No source executes and no process, configuration, repository or file is changed.
This proof concerns owned MemoryFile objects; it grants no Gold-writing action.
"""
import hashlib
import json

import managed_form_type_guard_v74 as _type
from owned_managed_cf_guard_v73 import verify_owned_pair

OWN_PROCESSING = _type.OWN_PROCESSING
OWN_FORM = _type.OWN_FORM
PROCESSING_CLASS = _type.PROCESSING_CLASS
FORM_CLASS = _type.FORM_CLASS
GOLD_ROOT = _type.GOLD_ROOT
GOLD_CONTROL_FORM = _type.GOLD_CONTROL_FORM
FORM_TYPE = _type.FORM_TYPE
ZERO_COUNTERS = _type.ZERO_COUNTERS
REGISTRY_FILENAME = 'owned-managed-body-v73-registry.json'
REGISTRY_LIMIT = MARKER_LIMIT = 1024
BINARY_LIMIT = 1048576
BODY_FILENAME = 'owned-managed-body-v73-body.bin'
CREATED_FILENAME = 'owned-managed-body-v73-created.cf'
DELETED_FILENAME = 'owned-managed-body-v73-deleted.cf'
BINARY_FILENAMES = (BODY_FILENAME, CREATED_FILENAME, DELETED_FILENAME)
MODULE_FIXTURE_SHA256 = 'b8f4ce623dbccf3c952583208bedc580f913934e6f63f1f45376c0d3daf4d0db'
MODULE_CHARACTER_COUNT = 318
PROCESSING_NAME = 'АгентУправляемаяФормаV73'
FORM_NAME = 'ФормаV73'
GROUP_NAME = 'ГруппаПроверкиV73'
PHASES = tuple(part + stage for stage in (
    'SourceRead', 'ProcessingFactory', 'FormFactory', 'ProcessingAttach',
    'FormAttach', 'TypeSetter', 'Readback', 'Names', 'BodyFactory',
    'ModuleWrite', 'SeedSave', 'SeedLoad', 'GroupFactory', 'GroupSet',
    'GroupAdd', 'BodySave', 'PayloadWrite', 'BoundBodyFactory', 'BoundBodyLoad',
    'BodyStore', 'BodyReadback', 'CreatedPreSave', 'CreatedPostSave',
    'CreatedExtract', 'CreatedReopen', 'DeleteForm', 'DeleteProcessing',
    'DeletedPreSave', 'DeletedPostSave', 'DeletedExtract', 'DeletedReopen',
    'ScopeExit', 'FinalSourceControl') for part in ('before', 'after'))
BODY_COUNTERS = dict(bodyFactoryCalls=1, ownNameSetterCalls=2, moduleWriteCalls=1,
                     groupFactoryCalls=1, groupSetCalls=1, groupAddCalls=1,
                     bodySaveCalls=2, bodyLoadCalls=2, boundBodyFactoryCalls=1,
                     bodyStoreCalls=1, preSaveCalls=2, postSaveCalls=2,
                     extractCalls=2, freshConnectCalls=2, ownDeleteCalls=2)
BODY_FLAGS = ('verified', 'ownNamesVerified', 'moduleFixtureVerified',
              'groupAddedBeforeFinalSave', 'boundBodyReadbackVerified',
              'noCachedBodyReadback', 'ownFormRemoved', 'ownProcessingRemoved',
              'ownedMemoryOnly')
BODY_KEYS = BODY_FLAGS + tuple(BODY_COUNTERS) + (
    'createdCF', 'deletedCF', 'moduleFixtureSha256', 'moduleCharacterCount',
    'bodyFilename', 'bodyBytes')
CF_COMMON_KEYS = ('verified', 'expectedDeleted', 'bytes', 'rootId',
                  'evidenceWritten', 'extractSlot', 'freshManager', 'freshRoot',
                  'freshManagedBodyModuleGroup', 'ownGraphAbsent', 'filename', 'canonical')
CF_CREATED_KEYS = CF_COMMON_KEYS + ('scope', 'moduleTextEqual', 'moduleFixtureSha256',
                                   'moduleCharacterCount', 'groupId', 'groupName',
                                   'groupCount', 'typeId', 'nativeEqual')
CF_DELETED_KEYS = CF_COMMON_KEYS + ('rootIndexAbsent', 'processingChildCount')
FALSE_CLAIMS = ('persistedGoldVerified', 'independentBackingVerified', 'deepCloneVerified')


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _shape(value, keys, code):
    _need(type(value) is dict and set(value) == set(keys), code)


def marker_filename(phase):
    """Return one fixed marker basename; perform no path lookup or I/O."""
    _need(type(phase) is str and phase in PHASES, 'V73_PHASE_REJECTED')
    return 'owned-managed-body-v73-' + phase + '.json'


def _json_file(reader, filename, kind):
    _need(callable(reader), 'V73_' + kind + '_READ_REJECTED')
    try:
        body = reader(filename)
    except Exception:
        raise ValueError('V73_' + kind + '_READ_REJECTED') from None
    _need(type(body) is bytes and 0 < len(body) <= 1024, 'V73_' + kind + '_SIZE_REJECTED')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_type._unique_pairs)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('V73_' + kind + '_CONTENT_REJECTED') from None
    return value, body


def _marker(reader, phase):
    value, _ = _json_file(reader, marker_filename(phase), 'MARKER')
    _shape(value, ('phase',) + ZERO_COUNTERS, 'V73_MARKER_REJECTED')
    _need(value['phase'] == phase and all(type(value[key]) is int and value[key] == 0
                                        for key in ZERO_COUNTERS), 'V73_MARKER_REJECTED')


def _registry(read_marker, info):
    """Verify and preserve a physical own before-attach canary, even on refusal.

    Partial ownBefore.rootId is sufficient for observation only. A canary grants
    no success, retry, deletion, cleanup or Gold-write permission.
    """
    def fixed_reader(name):
        _need(name == _type.REGISTRY_FILENAME, 'V73_REGISTRY_READ_REJECTED')
        _need(callable(read_marker), 'V73_REGISTRY_READ_REJECTED')
        return read_marker(REGISTRY_FILENAME)

    try:
        return _type._registry(fixed_reader, info)
    except ValueError:
        raise ValueError('V73_REGISTRY_REJECTED') from None


def _binary(reader, name, count=None):
    _need(callable(reader) and name in BINARY_FILENAMES, 'V73_BINARY_READ_REJECTED')
    try:
        body = reader(name)
    except Exception:
        raise ValueError('V73_BINARY_READ_REJECTED') from None
    _need(type(body) is bytes and 16 < len(body) <= BINARY_LIMIT,
          'V73_BINARY_SIZE_REJECTED')
    _need(count is None or type(count) is int and len(body) == count,
          'V73_BINARY_LENGTH_REJECTED')
    return body


def _fresh_canonical(value, keys, occupied):
    _shape(value, keys, 'V73_FRESH_CANONICAL_REJECTED')
    _need(all(_type._uint(pointer) for pointer in value.values())
          and len(set(value.values())) == len(keys)
          and set(value.values()).isdisjoint(occupied), 'V73_FRESH_CANONICAL_REJECTED')


def _cf_common(value, deleted, occupied):
    _shape(value, CF_DELETED_KEYS if deleted else CF_CREATED_KEYS, 'V73_CF_PROOF_REJECTED')
    root = _type._root(value['rootId'])
    _need(root != '00000000-0000-0000-0000-000000000000', 'V73_PERSISTED_ROOT_REJECTED')
    _need(all(value[key] is True for key in ('verified', 'evidenceWritten', 'freshManager', 'freshRoot'))
          and value['expectedDeleted'] is deleted
          and value['freshManagedBodyModuleGroup'] is (not deleted)
          and value['ownGraphAbsent'] is deleted, 'V73_CF_READBACK_REJECTED')
    _need(type(value['bytes']) is int and 16 < value['bytes'] <= BINARY_LIMIT
          and type(value['extractSlot']) is int and value['extractSlot'] == 43
          and value['filename'] == (DELETED_FILENAME if deleted else CREATED_FILENAME),
          'V73_CF_FILE_REJECTED')
    _fresh_canonical(value['canonical'], ('manager', 'root') if deleted else
                     ('manager', 'root', 'processing', 'form', 'body'), occupied)
    return root


def _body(value, source, canonical):
    _shape(value, BODY_KEYS, 'V73_BODY_REJECTED')
    _need(all(value[key] is True for key in BODY_FLAGS)
          and all(type(value[key]) is int and value[key] == count
                  for key, count in BODY_COUNTERS.items()), 'V73_BODY_COUNTER_REJECTED')
    _need(value['moduleFixtureSha256'] == MODULE_FIXTURE_SHA256
          and type(value['moduleCharacterCount']) is int
          and value['moduleCharacterCount'] == MODULE_CHARACTER_COUNT
          and value['bodyFilename'] == BODY_FILENAME
          and type(value['bodyBytes']) is int and 16 < value['bodyBytes'] <= BINARY_LIMIT,
          'V73_MODULE_PROOF_REJECTED')
    occupied = set(canonical.values()) | {source['sourceCanonicalBefore']}
    created = value['createdCF']
    deleted = value['deletedCF']
    root = _cf_common(created, False, occupied)
    _need(_cf_common(deleted, True, occupied) == root, 'V73_PERSISTED_ROOT_CHANGED')
    _type._snapshot(created['scope'])
    _need(created['scope']['rootId'] == root and created['moduleTextEqual'] is True
          and created['moduleFixtureSha256'] == MODULE_FIXTURE_SHA256
          and type(created['moduleCharacterCount']) is int
          and created['moduleCharacterCount'] == MODULE_CHARACTER_COUNT
          and type(created['groupId']) is int and created['groupId'] == 1001
          and created['groupName'] == GROUP_NAME
          and type(created['groupCount']) is int and created['groupCount'] == 1
          and type(created['typeId']) is int and created['typeId'] == source['sourceBeforeId']
          and created['nativeEqual'] is True, 'V73_FRESH_BODY_READBACK_REJECTED')
    _need(deleted['rootIndexAbsent'] is True and type(deleted['processingChildCount']) is int
          and deleted['processingChildCount'] == 0, 'V73_FRESH_DELETE_REJECTED')
    return root


def _timing(info):
    verified = info.get('nativeTimingVerified')
    elapsed = info.get('nativeElapsedUs')
    setter = info.get('ownTypeSetterElapsedUs')
    _need(type(verified) is bool and type(elapsed) is int and type(setter) is int,
          'V73_TIMING_REJECTED')
    _need((verified and 0 <= setter <= elapsed <= 0x7fffffffffffffff)
          or (not verified and elapsed == -1 and setter == -1), 'V73_TIMING_REJECTED')
    return dict(nativeTimingVerified=verified, nativeElapsedUs=elapsed,
                ownTypeSetterElapsedUs=setter)


def verify(info, version, read_marker, read_binary):
    """Check exact own native evidence, all receipts, canary and physical CF pair.

    Fixed readers are supplied by the trusted host after a known terminal native
    result. Full fixture text equality is native evidence; its sealed SHA is a
    reference, not a native-computed readback hash. Fresh own graph/module/group
    and deletion proof are required separately from the physical CF profile.
    There is no Gold persistence/backing/deep-clone or cleanup authorization.
    """
    _need(type(info) is dict and info.get('status') == 'OWN_MANAGED_BODY_VERIFIED'
          and info.get('nativeException') is False and info.get('returnUnknown') is False,
          'V73_OUTCOME_REJECTED')
    _need(type(version) is int and version > 0 and type(info.get('version')) is int
          and info['version'] == version, 'V73_VERSION_REJECTED')
    timing = _timing(info)
    expected = dict(goldRootId=GOLD_ROOT, goldControlFormId=GOLD_CONTROL_FORM,
                    goldControlFormClassId=_type.GOLD_CONTROL_FORM_CLASS,
                    formTypePropertyId=_type.FORM_TYPE_PROPERTY, **_type.OWN_FIELDS)
    _need(all(info.get(key) == value for key, value in expected.items()), 'V73_SCOPE_REJECTED')
    _need(all(info.get(key) is True for key in ('sourceControlPreserved', 'sourceValueUnchanged',
              'managedKindVerified', 'managedFormVerified', 'formBodyVerified',
              'persistedMemoryVerified', 'createdOnlyRegistryVerified', 'ownScopeExited'))
          and all(info.get(key) is False for key in FALSE_CLAIMS)
          and info.get('physicalProfileVerified') is False, 'V73_CLAIM_REJECTED')
    canonical = info.get('canonical')
    _type._canonical(canonical)
    _type._canonical(info.get('canonicalAfter'))
    _need(canonical == info['canonicalAfter'], 'V73_CANONICAL_CHANGED')
    for key in ('ownBefore', 'ownAfter'):
        _type._snapshot(info.get(key))
    _need(info['ownBefore'] == info['ownAfter'], 'V73_SNAPSHOT_CHANGED')
    source, mutable = _type._enum(info.get('enum'), canonical)
    _need(all(type(info.get(key)) is int and info[key] == count
              for key, count in _type.COUNTERS.items())
          and all(type(info.get(key)) is int and info[key] == 0 for key in ZERO_COUNTERS),
          'V73_COUNTER_REJECTED')
    root = _body(info.get('body'), info['enum'], canonical)
    lifecycle = info.get('lifecycle')
    _shape(lifecycle, PHASES, 'V73_LIFECYCLE_REJECTED')
    _need(all(lifecycle[phase] is True for phase in PHASES), 'V73_LIFECYCLE_REJECTED')
    for phase in PHASES:
        _marker(read_marker, phase)
    registry = _registry(read_marker, info)
    body = _binary(read_binary, BODY_FILENAME, info['body']['bodyBytes'])
    created = _binary(read_binary, CREATED_FILENAME, info['body']['createdCF']['bytes'])
    deleted = _binary(read_binary, DELETED_FILENAME, info['body']['deletedCF']['bytes'])
    physical = verify_owned_pair(created, deleted, root)
    return dict(ownedManagedBodyVerified=True, managedKindVerified=True,
                managedFormVerified=True, formBodyVerified=True, persistedMemoryVerified=True,
                physicalProfileVerified=True, physical=physical, sourceId=source,
                sourceTypeMutable=mutable, physicalMarkerCount=len(PHASES),
                registryPhysicallyVerified=True, registry=registry['registry'],
                registrySha256=registry['sha256'], registryBytes=registry['bytes'],
                bodyBytes=len(body), bodySha256=hashlib.sha256(body).hexdigest(),
                moduleFixtureSha256=MODULE_FIXTURE_SHA256,
                moduleCharacterCount=MODULE_CHARACTER_COUNT, persistedGoldVerified=False,
                independentBackingVerified=False, deepCloneVerified=False, **timing)
