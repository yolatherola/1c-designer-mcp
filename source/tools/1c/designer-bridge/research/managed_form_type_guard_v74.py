"""Pure guard for readonly Gold enum input and an exact own Form receiver.

The measured scalar transition is type-only evidence. No creator, clone, body,
MemoryFile persistence or Gold-writing capability is granted by this module.
"""
import hashlib
import json
import re

OWN_PROCESSING = 'f0e50730-e59b-4c8a-a189-0e62365aa372'
OWN_FORM = '4e68b5c9-17f4-4e20-a63b-804392cd97a2'
PROCESSING_CLASS = 'bf845118-327b-4682-b5c6-285d2a0eb296'
FORM_CLASS = 'd5b0e5ed-256d-401c-9c36-f630cafd8a62'
GOLD_ROOT = '218b5d00-7e10-486f-874c-73c2368ed5da'
GOLD_CONTROL_FORM = '0ed914fb-2a1a-4b58-9fad-eaa103b47c9e'
GOLD_CONTROL_FORM_CLASS = 'fb880e93-47d7-4127-9357-a20e69c17545'
FORM_TYPE_PROPERTY = 'e3331ed0-3854-478d-b6b5-4f14acdd6edb'
FORM_TYPE = 'b5fdf93a-40ea-4fc2-8911-2cb676377eff'
MARKER_LIMIT = 1024
REGISTRY_LIMIT = 1024
REGISTRY_FILENAME = 'owned-form-type-v74-registry.json'
GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
CANONICAL_KEYS = ('goldManager', 'goldRoot', 'goldControlForm', 'ownMemory',
                  'ownManager', 'ownRoot', 'ownProcessing', 'ownForm')
SNAPSHOT_KEYS = ('rootId', 'processingId', 'processingClassId', 'formId',
                 'formClassId', 'formParentId', 'processingParentId', 'rootIndexVerified')
PHASES = ('beforeSourceRead', 'afterSourceRead', 'beforeProcessingFactory',
          'afterProcessingFactory', 'beforeFormFactory', 'afterFormFactory',
          'beforeProcessingAttach', 'afterProcessingAttach', 'beforeFormAttach',
          'afterFormAttach', 'beforeTypeSetter', 'afterTypeSetter', 'beforeReadback',
          'afterReadback', 'beforeScopeExit', 'afterScopeExit',
          'beforeFinalSourceControl', 'afterFinalSourceControl')
ZERO_COUNTERS = ('goldSourceWrites', 'goldSaves', 'repositoryWrites',
                 'databaseUpdates', 'businessCalls')
COUNTERS = dict(createdOnly=2, ownFactoryCalls=2, ownAttachCalls=2, ownTypeSetterCalls=1,
                enumCreatorFactoryCalls=0, enumCreateCalls=0)
OWN_FIELDS = dict(ownProcessingId=OWN_PROCESSING, ownFormId=OWN_FORM,
                  processingClassId=PROCESSING_CLASS, formClassId=FORM_CLASS)
FALSE_CLAIMS = ('managedFormVerified', 'formBodyVerified', 'persistedMemoryVerified',
                'persistedGoldVerified', 'independentBackingVerified', 'deepCloneVerified')
ENUM_TRUE_FLAGS = ('sourceNativeEqualPreserved', 'sourceHeldReadOnly', 'enumIdAbiVerified',
                   'ownSetterAbiVerified', 'readbackVerified')
ENUM_FALSE_FLAGS = ('numberGuessUsed', 'independentCloneVerified')
ENUM_KEYS = ('typeId', 'sourceBeforeId', 'sourceAfterId', 'ownBeforeId', 'ownAfterId',
             'nativeEqualBefore', 'nativeEqualAfter', 'sourceCarrierBefore', 'sourceCarrierAfter',
             'sourceCanonicalBefore', 'sourceCanonicalAfter', 'sourceTypeMutableBefore',
             'sourceTypeMutableAfter') + ENUM_TRUE_FLAGS + ENUM_FALSE_FLAGS
REGISTRY_KEYS = ('stage', 'createdOnly', 'ownRootId', 'capturedSourceVersion',
                 'ownProcessingId', 'ownFormId', 'processingClassId', 'formClassId',
                 'canonical', 'ownFactoryCalls', 'ownAttachCalls', 'attachedIds') + ZERO_COUNTERS


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _shape(value, keys, code):
    _need(type(value) is dict and set(value) == set(keys), code)


def _uint(value):
    return type(value) is int and 0 < value <= 0xffffffff


def _root(value):
    _need(type(value) is str and GUID.fullmatch(value) is not None
          and value not in (GOLD_ROOT, GOLD_CONTROL_FORM, OWN_PROCESSING, OWN_FORM),
          'V74_ROOT_REJECTED')
    return value


def _canonical(value):
    _shape(value, CANONICAL_KEYS, 'V74_CANONICAL_REJECTED')
    _need(all(_uint(pointer) for pointer in value.values())
          and len(set(value.values())) == len(CANONICAL_KEYS), 'V74_CANONICAL_REJECTED')


def _snapshot(value):
    _shape(value, SNAPSHOT_KEYS, 'V74_SNAPSHOT_REJECTED')
    root = _root(value['rootId'])
    expected = dict(processingId=OWN_PROCESSING, processingClassId=PROCESSING_CLASS,
                    formId=OWN_FORM, formClassId=FORM_CLASS, formParentId=OWN_PROCESSING,
                    processingParentId=root)
    _need(all(value[key] == item for key, item in expected.items())
          and value['rootIndexVerified'] is True, 'V74_SCOPE_REJECTED')


def marker_filename(phase):
    """Return one fixed own marker basename; perform no path resolution or I/O."""
    _need(type(phase) is str and phase in PHASES, 'V74_PHASE_REJECTED')
    return 'owned-form-type-v74-' + phase + '.json'


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'V74_JSON_DUPLICATE_REJECTED')
        result[key] = value
    return result


def _json_file(reader, filename, limit, kind):
    _need(callable(reader), 'V74_' + kind + '_READ_REJECTED')
    try:
        body = reader(filename)
    except Exception:
        raise ValueError('V74_' + kind + '_READ_REJECTED') from None
    _need(type(body) is bytes and 0 < len(body) <= limit, 'V74_' + kind + '_SIZE_REJECTED')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('V74_' + kind + '_CONTENT_REJECTED') from None
    return value, body


def _marker(reader, phase):
    value, _ = _json_file(reader, marker_filename(phase), MARKER_LIMIT, 'MARKER')
    _shape(value, ('phase',) + ZERO_COUNTERS, 'V74_MARKER_CONTENT_REJECTED')
    _need(value['phase'] == phase and all(type(value[key]) is int and value[key] == 0
                                        for key in ZERO_COUNTERS), 'V74_MARKER_CONTENT_REJECTED')


def _registry(read_marker, info):
    """Verify the physical before-attach canary; return parsed contents and SHA.

    This helper can preserve a partial native observation independently of final
    success. It requires that observation's version, own root, fixed identities
    and canonical graph, but never treats a durable bool as physical authority.
    The resulting canary grants neither retries, deletion nor Gold writes.
    """
    _need(type(info) is dict and type(info.get('version')) is int and info['version'] > 0
          and type(info.get('ownBefore')) is dict, 'V74_REGISTRY_CONTEXT_REJECTED')
    root = _root(info['ownBefore'].get('rootId'))
    _canonical(info.get('canonical'))
    _need(all(info.get(key) == item for key, item in OWN_FIELDS.items()),
          'V74_REGISTRY_CONTEXT_REJECTED')
    value, body = _json_file(read_marker, REGISTRY_FILENAME, REGISTRY_LIMIT, 'REGISTRY')
    _shape(value, REGISTRY_KEYS, 'V74_REGISTRY_CONTENT_REJECTED')
    _need(value['stage'] == 'beforeAttach' and value['createdOnly'] is True
          and value['ownRootId'] == root and type(value['capturedSourceVersion']) is int
          and value['capturedSourceVersion'] == info['version']
          and all(value[key] == item for key, item in OWN_FIELDS.items()),
          'V74_REGISTRY_SCOPE_REJECTED')
    _canonical(value['canonical'])
    _need(value['canonical'] == info['canonical'], 'V74_REGISTRY_CANONICAL_REJECTED')
    _need(type(value['ownFactoryCalls']) is int and value['ownFactoryCalls'] == 2
          and type(value['ownAttachCalls']) is int and value['ownAttachCalls'] == 0
          and type(value['attachedIds']) is list and value['attachedIds'] == []
          and all(type(value[key]) is int and value[key] == 0 for key in ZERO_COUNTERS),
          'V74_REGISTRY_COUNTER_REJECTED')
    return dict(registry=value, sha256=hashlib.sha256(body).hexdigest(), bytes=len(body))


def _enum(value, canonical):
    _shape(value, ENUM_KEYS, 'V74_ENUM_REJECTED')
    _need(value['typeId'] == FORM_TYPE, 'V74_ENUM_TYPE_REJECTED')
    source = value['sourceBeforeId']
    _need(type(source) is int and source in (0, 1), 'V74_ENUM_ID_REJECTED')
    expected = dict(sourceAfterId=source, ownBeforeId=1 - source, ownAfterId=source)
    _need(all(type(value[key]) is int and value[key] == item for key, item in expected.items())
          and value['nativeEqualBefore'] is False and value['nativeEqualAfter'] is True,
          'V74_ENUM_TRANSITION_REJECTED')
    for first, last in (('sourceCarrierBefore', 'sourceCarrierAfter'),
                        ('sourceCanonicalBefore', 'sourceCanonicalAfter')):
        _need(_uint(value[first]) and _uint(value[last]) and value[first] == value[last],
              'V74_SOURCE_IDENTITY_REJECTED')
    _need(value['sourceCanonicalBefore'] not in canonical.values(), 'V74_SOURCE_ALIAS_REJECTED')
    mutable = value['sourceTypeMutableBefore']
    _need(type(mutable) is bool and type(value['sourceTypeMutableAfter']) is bool
          and mutable == value['sourceTypeMutableAfter'], 'V74_SOURCE_MUTABILITY_REJECTED')
    _need(all(value[key] is True for key in ENUM_TRUE_FLAGS)
          and all(value[key] is False for key in ENUM_FALSE_FLAGS), 'V74_ENUM_CLAIM_REJECTED')
    return source, mutable


def verify(info, version, read_marker):
    """Verify one exact own scalar transition, eighteen markers and its canary.

    read_marker is the trusted caller's bounded, reparse-safe owned runtime reader.
    It is called only for fixed phase basenames and REGISTRY_FILENAME. The source
    may remain mutable and globally shared; carrier preservation is not a clone
    proof. After-ownscope source receipts are mandatory. Failure codes are fixed
    and reveal no content; success authorizes neither Gold writes nor cleanup.
    """
    _need(type(info) is dict and info.get('status') == 'OWN_FORM_TYPE_VERIFIED_V74'
          and info.get('nativeException') is False and info.get('returnUnknown') is False,
          'V74_OUTCOME_REJECTED')
    _need(type(version) is int and version > 0 and type(info.get('version')) is int
          and info['version'] == version, 'V74_VERSION_REJECTED')
    expected = dict(goldRootId=GOLD_ROOT, goldControlFormId=GOLD_CONTROL_FORM,
                    goldControlFormClassId=GOLD_CONTROL_FORM_CLASS,
                    formTypePropertyId=FORM_TYPE_PROPERTY, **OWN_FIELDS)
    _need(all(info.get(key) == item for key, item in expected.items()), 'V74_SCOPE_REJECTED')
    _need(info.get('sourceControlPreserved') is True and info.get('sourceValueUnchanged') is True
          and info.get('managedKindVerified') is True and info.get('createdOnlyRegistryVerified') is True
          and all(info.get(key) is False for key in FALSE_CLAIMS), 'V74_CLAIM_REJECTED')
    canonical = info.get('canonical')
    _canonical(canonical)
    _canonical(info.get('canonicalAfter'))
    _need(canonical == info['canonicalAfter'], 'V74_CANONICAL_CHANGED')
    for key in ('ownBefore', 'ownAfter'):
        _snapshot(info.get(key))
    _need(info['ownBefore'] == info['ownAfter'], 'V74_SNAPSHOT_CHANGED')
    source, mutable = _enum(info.get('enum'), canonical)
    _need(all(type(info.get(key)) is int and info[key] == item for key, item in COUNTERS.items())
          and all(type(info.get(key)) is int and info[key] == 0 for key in ZERO_COUNTERS),
          'V74_COUNTER_REJECTED')
    lifecycle = info.get('lifecycle')
    _shape(lifecycle, PHASES, 'V74_LIFECYCLE_REJECTED')
    _need(all(lifecycle[phase] is True for phase in PHASES), 'V74_LIFECYCLE_REJECTED')
    _need(callable(read_marker), 'V74_MARKER_READ_REJECTED')
    for phase in PHASES:
        _marker(read_marker, phase)
    registry = _registry(read_marker, info)
    return dict(typeOnlyVerified=True, managedKindVerified=True, sourceId=source,
                ownBeforeId=1 - source, ownAfterId=source, sourceTypeMutable=mutable,
                physicalMarkerCount=len(PHASES), registryPhysicallyVerified=True,
                registry=registry['registry'], registrySha256=registry['sha256'],
                registryBytes=registry['bytes'], managedFormVerified=False,
                formBodyVerified=False, persistedMemoryVerified=False, persistedGoldVerified=False,
                independentBackingVerified=False, deepCloneVerified=False)
