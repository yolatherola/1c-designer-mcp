"""Validate a completed own-only persistence roundtrip; execute no native code."""
import json
import re

OWN_PROCESSING = '7a4c8e91-80c4-4cf9-9676-3e7be4d4258a'
OWN_FORM = 'ad93c870-5d7c-45cc-b852-1414469c112e'
PROCESSING_CLASS = 'bf845118-327b-4682-b5c6-285d2a0eb296'
FORM_CLASS = 'd5b0e5ed-256d-401c-9c36-f630cafd8a62'
SERIALIZATION_CLSID = 'fcdd75d2-4a14-42ab-b179-a76dba40dc86'
GOLD_ROOT = '218b5d00-7e10-486f-874c-73c2368ed5da'
SOURCE_NAME = 'ФормаИсточникV71'
TARGET_NAME = 'ФормаПриемникV71'
PAYLOAD_LIMIT = 1048576
MARKER_LIMIT = 1024
GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
CANONICAL_KEYS = ('goldManager', 'goldRoot', 'sourceManager', 'sourceRoot',
                  'sourceProcessing', 'sourceForm', 'targetManager', 'targetRoot',
                  'targetProcessing', 'targetForm', 'sourceMemory', 'targetMemory',
                  'descriptorMemory')
SNAPSHOT_KEYS = ('rootId', 'processingId', 'processingClassId', 'formId',
                 'formClassId', 'formParentId', 'processingParentId', 'rootIndexVerified')
CLSID_KEYS = ('sourceSerializationClsid', 'targetSerializationClsid',
              'sourceSerializationClsidAfter', 'targetSerializationClsidAfter')
PHASES = ('beforeSourceSerialize', 'afterSourceSerialize', 'beforeTargetDeserialize',
          'afterTargetDeserialize', 'beforeReaderClose', 'afterReaderClose',
          'beforeTargetSerialize', 'afterTargetSerialize', 'beforeSourceReserialize',
          'afterSourceReserialize', 'beforeScopeExit', 'afterScopeExit')
COUNTERS = dict(createdOnly=4, ownAttachCalls=4, sourceSerializeCalls=2,
                targetSerializeCalls=1, targetDeserializeCalls=1, readerCloseCalls=1)
ZERO_COUNTERS = ('goldSourceWrites', 'goldSaves', 'repositoryWrites',
                 'databaseUpdates', 'businessCalls')
FALSE_CLAIMS = ('managedFormVerified', 'formBodyVerified', 'persistedGoldVerified',
                'independentBackingVerified')


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _shape(value, keys, code):
    _need(type(value) is dict and set(value) == set(keys), code)


def _snapshot(value):
    _shape(value, SNAPSHOT_KEYS, 'V71_SNAPSHOT_REJECTED')
    root = value['rootId']
    _need(type(root) is str and GUID.fullmatch(root) is not None
          and root not in (GOLD_ROOT, OWN_PROCESSING, OWN_FORM), 'V71_ROOT_REJECTED')
    expected = dict(processingId=OWN_PROCESSING, processingClassId=PROCESSING_CLASS,
                    formId=OWN_FORM, formClassId=FORM_CLASS, formParentId=OWN_PROCESSING,
                    processingParentId=root)
    _need(all(value[key] == expected_value for key, expected_value in expected.items())
          and value['rootIndexVerified'] is True, 'V71_SCOPE_REJECTED')


def marker_filename(phase):
    """Return one allowlisted own marker name; no path resolution or I/O."""
    _need(phase in PHASES, 'V71_PHASE_REJECTED')
    return 'owned-persistence-v71-' + phase + '.json'


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'V71_MARKER_CONTENT_REJECTED')
        result[key] = value
    return result


def _marker(reader, phase):
    try:
        body = reader(marker_filename(phase))
    except Exception:
        raise ValueError('V71_MARKER_READ_REJECTED') from None
    _need(type(body) is bytes and 0 < len(body) <= MARKER_LIMIT,
          'V71_MARKER_SIZE_REJECTED')
    try:
        marker = json.loads(body.decode('utf-8-sig'), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('V71_MARKER_CONTENT_REJECTED') from None
    _shape(marker, ('phase',) + ZERO_COUNTERS, 'V71_MARKER_CONTENT_REJECTED')
    _need(marker['phase'] == phase and all(type(marker[key]) is int
          and marker[key] == 0 for key in ZERO_COUNTERS), 'V71_MARKER_CONTENT_REJECTED')


def verify(info, version, read_marker):
    """Validate fresh sanitized native evidence and all twelve durable markers.

    read_marker is the trusted caller's bounded reader inside the exact owned
    runtime. It is called only with fixed marker filenames after receipt checks.
    Marker failures never expose raw content or authorize retries/cleanup. Native
    byte comparisons establish payload equality, while this guard checks scope,
    complete lifecycle and truthful limits. This is no writer or deep-clone grant.
    """
    _need(type(info) is dict and info.get('status') == 'OWN_PERSISTENCE_ROUNDTRIP_VERIFIED'
          and info.get('nativeException') is False and info.get('returnUnknown') is False,
          'V71_OUTCOME_REJECTED')
    _need(type(version) is int and version > 0 and type(info.get('version')) is int
          and info['version'] == version, 'V71_VERSION_REJECTED')
    expected = dict(ownProcessingId=OWN_PROCESSING, ownFormId=OWN_FORM,
                    processingClassId=PROCESSING_CLASS, formClassId=FORM_CLASS,
                    sourceName=SOURCE_NAME, targetNameBefore=TARGET_NAME, targetNameAfter=SOURCE_NAME)
    _need(all(info.get(key) == value for key, value in expected.items()), 'V71_SCOPE_REJECTED')
    _need(info.get('sourceControlPreserved') is True
          and all(info.get(key) is False for key in FALSE_CLAIMS), 'V71_CLAIM_REJECTED')
    canonical = info.get('canonical')
    after = info.get('canonicalAfter')
    for values in (canonical, after):
        _shape(values, CANONICAL_KEYS, 'V71_CANONICAL_REJECTED')
        _need(all(type(value) is int and 0 < value <= 0xffffffff for value in values.values())
              and len(set(values.values())) == len(CANONICAL_KEYS), 'V71_CANONICAL_REJECTED')
    _need(canonical == after, 'V71_CANONICAL_CHANGED')
    for key in ('sourceBefore', 'sourceAfter', 'targetBefore', 'targetAfter'):
        _snapshot(info.get(key))
    _need(info['sourceBefore'] == info['sourceAfter'] and info['targetBefore'] == info['targetAfter'],
          'V71_SNAPSHOT_CHANGED')
    persistence = info.get('persistence')
    _shape(persistence, CLSID_KEYS + ('payloadBytes', 'inputConsumed', 'payloadEqual', 'sourceStable'),
           'V71_PERSISTENCE_REJECTED')
    _need(all(persistence[key] == SERIALIZATION_CLSID for key in CLSID_KEYS), 'V71_CLSID_REJECTED')
    size = persistence['payloadBytes']
    _need(type(size) is int and 0 < size <= PAYLOAD_LIMIT
          and all(persistence[key] is True for key in ('inputConsumed', 'payloadEqual', 'sourceStable')),
          'V71_PAYLOAD_REJECTED')
    _need(all(type(info.get(key)) is int and info[key] == value for key, value in COUNTERS.items())
          and all(type(info.get(key)) is int and info[key] == 0 for key in ZERO_COUNTERS),
          'V71_COUNTER_REJECTED')
    lifecycle = info.get('lifecycle')
    _shape(lifecycle, PHASES, 'V71_LIFECYCLE_REJECTED')
    _need(all(lifecycle[phase] is True for phase in PHASES), 'V71_LIFECYCLE_REJECTED')
    _need(callable(read_marker), 'V71_MARKER_READ_REJECTED')
    for phase in PHASES:
        _marker(read_marker, phase)
    return dict(ownRoundTripVerified=True, managedFormVerified=False, formBodyVerified=False,
                persistedGoldVerified=False, independentBackingVerified=False, payloadBytes=size)
