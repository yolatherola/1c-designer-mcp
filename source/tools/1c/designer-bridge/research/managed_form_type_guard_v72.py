"""Validate an own FormType transition; execute no native code or Gold writes."""
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
GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
CANONICAL_KEYS = ('goldManager', 'goldRoot', 'goldControlForm', 'ownMemory',
                  'ownManager', 'ownRoot', 'ownProcessing', 'ownForm')
SNAPSHOT_KEYS = ('rootId', 'processingId', 'processingClassId', 'formId',
                 'formClassId', 'formParentId', 'processingParentId', 'rootIndexVerified')
PHASES = ('beforeCreator', 'afterCreator', 'beforeCandidate0', 'afterCandidate0',
          'beforeCandidate1', 'afterCandidate1', 'beforeProcessingFactory',
          'afterProcessingFactory', 'beforeFormFactory', 'afterFormFactory',
          'beforeProcessingAttach', 'afterProcessingAttach', 'beforeFormAttach',
          'afterFormAttach', 'beforeTypeSetter', 'afterTypeSetter', 'beforeReadback',
          'afterReadback', 'beforeScopeExit', 'afterScopeExit')
COUNTERS = dict(createdOnly=2, ownAttachCalls=2, enumCreatorFactoryCalls=1,
                enumCreateCalls=2, ownTypeSetterCalls=1)
ZERO_COUNTERS = ('goldSourceWrites', 'goldSaves', 'repositoryWrites',
                 'databaseUpdates', 'businessCalls')
FALSE_CLAIMS = ('managedFormVerified', 'formBodyVerified', 'persistedGoldVerified',
                'independentBackingVerified')
ENUM_TRUE_FLAGS = ('cachedInputReadOnly', 'creatorAbiVerified', 'enumIdAbiVerified',
                   'ownSetterAbiVerified', 'readbackVerified')
ENUM_FALSE_FLAGS = ('numberGuessUsed', 'independentCloneVerified')
ENUM_KEYS = ('typeId', 'candidateIds', 'candidateMatches', 'managedCandidateId',
             'goldBeforeId', 'goldAfterId', 'ownBeforeId', 'ownAfterId') + ENUM_TRUE_FLAGS + ENUM_FALSE_FLAGS


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _shape(value, keys, code):
    _need(type(value) is dict and set(value) == set(keys), code)


def _snapshot(value):
    _shape(value, SNAPSHOT_KEYS, 'V72_SNAPSHOT_REJECTED')
    root = value['rootId']
    _need(type(root) is str and GUID.fullmatch(root) is not None
          and root not in (GOLD_ROOT, GOLD_CONTROL_FORM, OWN_PROCESSING, OWN_FORM),
          'V72_ROOT_REJECTED')
    expected = dict(processingId=OWN_PROCESSING, processingClassId=PROCESSING_CLASS,
                    formId=OWN_FORM, formClassId=FORM_CLASS, formParentId=OWN_PROCESSING,
                    processingParentId=root)
    _need(all(value[key] == expected_value for key, expected_value in expected.items())
          and value['rootIndexVerified'] is True, 'V72_SCOPE_REJECTED')


def marker_filename(phase):
    """Return a fixed own marker basename; perform no path resolution or I/O."""
    _need(type(phase) is str and phase in PHASES, 'V72_PHASE_REJECTED')
    return 'owned-form-type-v72-' + phase + '.json'


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'V72_MARKER_CONTENT_REJECTED')
        result[key] = value
    return result


def _marker(reader, phase):
    try:
        body = reader(marker_filename(phase))
    except Exception:
        raise ValueError('V72_MARKER_READ_REJECTED') from None
    _need(type(body) is bytes and 0 < len(body) <= MARKER_LIMIT,
          'V72_MARKER_SIZE_REJECTED')
    try:
        marker = json.loads(body.decode('utf-8'), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('V72_MARKER_CONTENT_REJECTED') from None
    _shape(marker, ('phase',) + ZERO_COUNTERS, 'V72_MARKER_CONTENT_REJECTED')
    _need(marker['phase'] == phase and all(type(marker[key]) is int
          and marker[key] == 0 for key in ZERO_COUNTERS), 'V72_MARKER_CONTENT_REJECTED')


def _enum(value):
    _shape(value, ENUM_KEYS, 'V72_ENUM_REJECTED')
    _need(value['typeId'] == FORM_TYPE, 'V72_ENUM_TYPE_REJECTED')
    candidates = value['candidateIds']
    matches = value['candidateMatches']
    _need(type(candidates) is list and len(candidates) == 2
          and all(type(candidate) is int for candidate in candidates) and candidates == [0, 1]
          and type(matches) is list and len(matches) == 2
          and all(type(match) is bool for match in matches) and sum(matches) == 1,
          'V72_CANDIDATE_REJECTED')
    managed = matches.index(True)
    expected = dict(managedCandidateId=managed, goldBeforeId=managed, goldAfterId=managed,
                    ownBeforeId=1 - managed, ownAfterId=managed)
    _need(all(type(value[key]) is int and value[key] == expected_value
              for key, expected_value in expected.items()), 'V72_ENUM_TRANSITION_REJECTED')
    _need(all(value[key] is True for key in ENUM_TRUE_FLAGS)
          and all(value[key] is False for key in ENUM_FALSE_FLAGS), 'V72_ENUM_CLAIM_REJECTED')
    return managed


def verify(info, version, read_marker):
    """Validate a completed type-only own transition and twenty physical markers.

    read_marker is the trusted caller's bounded, reparse-safe reader inside the
    exact owned runtime. It is invoked only for the fixed basenames after receipt
    checks. Native equality chooses the managed ID; the guard never guesses it.
    Failures expose fixed codes and grant neither retry, cleanup nor Gold writes.
    Cached enum input is read-only; complete form/backing independence is unproven.
    """
    _need(type(info) is dict and info.get('status') == 'OWN_FORM_TYPE_VERIFIED'
          and info.get('nativeException') is False and info.get('returnUnknown') is False,
          'V72_OUTCOME_REJECTED')
    _need(type(version) is int and version > 0 and type(info.get('version')) is int
          and info['version'] == version, 'V72_VERSION_REJECTED')
    expected = dict(goldRootId=GOLD_ROOT, goldControlFormId=GOLD_CONTROL_FORM,
                    goldControlFormClassId=GOLD_CONTROL_FORM_CLASS,
                    formTypePropertyId=FORM_TYPE_PROPERTY, ownProcessingId=OWN_PROCESSING,
                    ownFormId=OWN_FORM, processingClassId=PROCESSING_CLASS, formClassId=FORM_CLASS)
    _need(all(info.get(key) == value for key, value in expected.items()), 'V72_SCOPE_REJECTED')
    _need(info.get('sourceControlPreserved') is True and info.get('sourceValueUnchanged') is True
          and info.get('managedKindVerified') is True
          and all(info.get(key) is False for key in FALSE_CLAIMS), 'V72_CLAIM_REJECTED')
    canonical = info.get('canonical')
    after = info.get('canonicalAfter')
    for values in (canonical, after):
        _shape(values, CANONICAL_KEYS, 'V72_CANONICAL_REJECTED')
        _need(all(type(value) is int and 0 < value <= 0xffffffff for value in values.values())
              and len(set(values.values())) == len(CANONICAL_KEYS), 'V72_CANONICAL_REJECTED')
    _need(canonical == after, 'V72_CANONICAL_CHANGED')
    for key in ('ownBefore', 'ownAfter'):
        _snapshot(info.get(key))
    _need(info['ownBefore'] == info['ownAfter'], 'V72_SNAPSHOT_CHANGED')
    managed = _enum(info.get('enum'))
    _need(all(type(info.get(key)) is int and info[key] == value for key, value in COUNTERS.items())
          and all(type(info.get(key)) is int and info[key] == 0 for key in ZERO_COUNTERS),
          'V72_COUNTER_REJECTED')
    lifecycle = info.get('lifecycle')
    _shape(lifecycle, PHASES, 'V72_LIFECYCLE_REJECTED')
    _need(all(lifecycle[phase] is True for phase in PHASES), 'V72_LIFECYCLE_REJECTED')
    _need(callable(read_marker), 'V72_MARKER_READ_REJECTED')
    for phase in PHASES:
        _marker(read_marker, phase)
    return dict(typeOnlyVerified=True, managedKindVerified=True, managedCandidateId=managed,
                ownBeforeId=1 - managed, ownAfterId=managed, physicalMarkerCount=len(PHASES),
                managedFormVerified=False, formBodyVerified=False, persistedGoldVerified=False,
                independentBackingVerified=False)
