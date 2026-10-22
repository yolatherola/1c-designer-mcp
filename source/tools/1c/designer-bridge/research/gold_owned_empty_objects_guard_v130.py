"""Pure strict OWN Document/Catalog transient proof, never an execution permit."""
import hashlib
import json
import re

LIMIT = 32768
MARKER_LIMIT = REGISTRY_LIMIT = 1024
ROOT_ID = '218b5d00-7e10-486f-874c-73c2368ed5da'
OBJECTS = (
    ('Document', 'a15bb4ec-c135-4ad8-932a-957186160a7e',
     '061d872a-5787-460e-95ac-ed74ea3a3e84', 'AgentEmptyDocumentV125'),
    ('Catalog', 'c1ae574d-387b-4a6c-bbd1-224fda69c16f',
     'cf4abea6-37b2-11d4-940f-008048da11f9', 'AgentEmptyCatalogV125'),
)
PHASES = ('beforeBaseline', 'afterBaseline') + tuple(
    prefix + kind + action for kind, _, _, _ in OBJECTS
    for action in ('Factory', 'Attach', 'Name', 'Readback', 'Delete')
    for prefix in ('before', 'after')) + (
    'beforeScopeExit', 'afterScopeExit', 'beforeFinalSourceControl', 'afterFinalSourceControl')
TERMINAL_PHASES = PHASES[-4:]
FOREIGN_CHECKS = ('baseline', 'documentBeforeDelete', 'afterDocumentDelete',
                  'catalogBeforeDelete', 'finalAfterScope')
ZERO_COUNTERS = ('foreignSourceWrites', 'goldSaves', 'repositoryWrites', 'databaseUpdates',
                 'businessCalls', 'dirtyFlagWrites', 'configurationExports', 'configurationImports')
MARKER_ZEROS = ZERO_COUNTERS[:6]
FALSE_CLAIMS = ('persistedGoldVerified', 'databaseConfigurationVerified',
                'foreignPropertyContentHashed', 'formVerified', 'attributeVerified',
                'typePropertiesVerified', 'captureLatestVerified', 'dirtyFlagsForced',
                'nativePermit', 'writerAuthorized')
FLAGS = ('baselineClean', 'rootIdentityPreserved', 'goldSourcePreserved', 'foreignGraphPreserved',
         'taskScopeExited', 'authenticatedDiscardEligible', 'ownEmptyObjectsVerified',
         'nativeException', 'returnUnknown')
KEYS = ('status', 'operationId', 'version', 'goldRootId', 'writeAttempts',
        'foreignGraphPasses', 'foreignGraphNodes', 'foreignChecks', 'objects', 'lifecycle') + \
       ZERO_COUNTERS + FALSE_CLAIMS + FLAGS
ROW_COUNTS = ('factoryCalls', 'idSetterCalls', 'attachCalls', 'nameSetterCalls', 'freshReadCalls', 'deleteCalls')
ROW_FLAGS = ('kindDeclared', 'ownAbsentBefore', 'factoryVerified', 'createdOnlyRegistryVerified',
             'ownAttached', 'ownNamed', 'freshReadbackVerified', 'ownDeleted', 'parentCleared', 'ownAbsent')
ROW_KEYS = ('kind', 'ownId', 'classId', 'name', 'writeAttempts', 'countBefore', 'countAttached',
            'countAfter', 'canonical', 'canonicalAfter') + ROW_COUNTS + ROW_FLAGS
CANONICAL_KEYS = ('goldManager', 'goldRoot', 'selectedDocument', 'ownObject')
REGISTRY_KEYS = ('operationId', 'stage', 'createdOnly', 'kind', 'rootId', 'ownId', 'classId',
                 'version', 'canonical', 'factoryCalls', 'idSetterCalls', 'attachCalls', 'attachedIds', 'goldSaves')
WRITER_PAIRS = {'factoryCalls': 'Factory', 'idSetterCalls': 'Factory', 'attachCalls': 'Attach',
                'nameSetterCalls': 'Name', 'deleteCalls': 'Delete'}


def need(ok, code):
    if not ok:
        raise ValueError('GE130_' + code)


def parse_result(raw, *, limit=LIMIT):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'JSON_REJECTED');value[key] = item
        return value

    def invalid(_):
        raise ValueError('GE130_JSON_REJECTED')

    need(type(raw) is bytes and 0 < len(raw) <= limit, 'JSON_REJECTED')
    try:
        result = json.loads(raw.decode('utf8'), object_pairs_hook=pairs,
                            parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('GE130_JSON_REJECTED') from None
    need(type(result) is dict, 'JSON_REJECTED');return result


def marker_filename(phase):
    need(type(phase) is str and phase in PHASES, 'MARKER_NAME_REJECTED')
    return 'gold-owned-empty-objects-v130-' + phase + '.json'


def registry_filename(kind):
    need(type(kind) is str and kind in ('Document', 'Catalog'), 'REGISTRY_NAME_REJECTED')
    return 'gold-owned-empty-objects-v130-' + kind.lower() + '-registry.json'


def _read(reader, name, limit):
    need(callable(reader), 'READER_REQUIRED')
    try:
        raw = reader(name)
    except Exception:
        raise ValueError('GE130_WITNESS_UNAVAILABLE') from None
    need(type(raw) is bytes and 0 < len(raw) <= limit, 'WITNESS_BOUND_REJECTED')
    return raw


def _marker(reader, phase, operation):
    raw = _read(reader, marker_filename(phase), MARKER_LIMIT)
    info = parse_result(raw, limit=MARKER_LIMIT)
    need(set(info) == {'phase', 'operationId', *MARKER_ZEROS}
         and info['phase'] == phase and info['operationId'] == operation
         and all(type(info[k]) is int and info[k] == 0 for k in MARKER_ZEROS), 'MARKER_REJECTED')
    return raw


def _canonical(value):
    need(type(value) is dict and set(value) == set(CANONICAL_KEYS)
         and all(type(value[k]) is int and 0 < value[k] <= 0xffffffff for k in CANONICAL_KEYS)
         and len(set(value.values())) == 4, 'CANONICAL_REJECTED')


def _registry(reader, info, row):
    raw = _read(reader, registry_filename(row['kind']), REGISTRY_LIMIT)
    value = parse_result(raw, limit=REGISTRY_LIMIT)
    need(set(value) == set(REGISTRY_KEYS) and value['operationId'] == info['operationId']
         and value['stage'] == 'beforeAttach' and value['createdOnly'] is True
         and value['kind'] == row['kind'] and value['rootId'] == ROOT_ID
         and value['ownId'] == row['ownId'] and value['classId'] == row['classId']
         and type(value['version']) is int and value['version'] == info['version']
         and value['canonical'] == row['canonical'] and value['attachedIds'] == []
         and type(value['attachedIds']) is list
         and all(type(value[k]) is int and value[k] == expected for k, expected in
                 (('factoryCalls', 1), ('idSetterCalls', 1), ('attachCalls', 0), ('goldSaves', 0))), 'REGISTRY_REJECTED')
    _canonical(value['canonical'])
    return raw


def verify(info, version, read_marker):
    """Verify terminal or partial OWN evidence; caller proves role/lease/PID/pins.

    Executed writers always require both physical receipts, including partial
    refusal. UNKNOWN/exception/source failure never grants close or cleanup.
    """
    need(type(info) is dict and set(info) == set(KEYS), 'SHAPE_REJECTED')
    need(type(version) is int and 0 <= version <= 0x7fffffff and type(info['version']) is int
         and info['version'] == version, 'VERSION_REJECTED')
    need(type(info['operationId']) is str and re.fullmatch('[a-f0-9]{32}', info['operationId'])
         and info['goldRootId'] == ROOT_ID, 'OPERATION_SCOPE_REJECTED')
    need(all(type(info[k]) is bool for k in FLAGS), 'FLAG_TYPE_REJECTED')
    need(info['nativeException'] is False and info['returnUnknown'] is False, 'UNKNOWN_REJECTED')
    need(all(info[k] is True for k in FLAGS if k not in
             ('nativeException', 'returnUnknown', 'ownEmptyObjectsVerified')), 'TERMINAL_REJECTED')
    need(all(type(info[k]) is int and info[k] == 0 for k in ZERO_COUNTERS), 'WRITES_REJECTED')
    need(all(info[k] is False for k in FALSE_CLAIMS), 'FALSE_CLAIM_REJECTED')
    full = info['ownEmptyObjectsVerified']
    need(info['status'] == ('GOLD_OWNED_EMPTY_OBJECTS_VERIFIED_V130' if full else
                           'GOLD_OWNED_EMPTY_OBJECTS_UNVERIFIED_V130'), 'STATUS_REJECTED')
    phases = info['lifecycle'];foreign = info['foreignChecks']
    need(type(phases) is dict and set(phases) == set(PHASES)
         and all(type(v) is bool for v in phases.values()), 'LIFECYCLE_REJECTED')
    need(type(foreign) is dict and set(foreign) == set(FOREIGN_CHECKS)
         and all(type(v) is bool for v in foreign.values())
         and foreign['baseline'] is True and foreign['finalAfterScope'] is True, 'FOREIGN_REJECTED')
    need(type(info['foreignGraphNodes']) is int and 0 < info['foreignGraphNodes'] <= 100000
         and type(info['foreignGraphPasses']) is int and info['foreignGraphPasses'] == sum(foreign.values()),
         'FOREIGN_COUNT_REJECTED')
    rows = info['objects'];need(type(rows) is list and len(rows) == 2, 'OBJECTS_REJECTED')
    required = set(TERMINAL_PHASES) | {'beforeBaseline', 'afterBaseline'}
    registries = [];canonical = [];writes = 0
    for row, (kind, own, cls, name) in zip(rows, OBJECTS):
        need(type(row) is dict and set(row) == set(ROW_KEYS)
             and (row['kind'], row['ownId'], row['classId'], row['name']) == (kind, own, cls, name), 'OWN_SCOPE_REJECTED')
        need(all(type(row[k]) is bool for k in ROW_FLAGS)
             and all(type(row[k]) is int and 0 <= row[k] <= 1 for k in ROW_COUNTS), 'ROW_TYPE_REJECTED')
        factory, ids, attach, names, reads, deletes = (row[k] for k in ROW_COUNTS)
        need(deletes == attach and 0 <= reads <= names <= attach <= ids <= factory <= 1, 'WRITER_LEDGER_REJECTED')
        need(type(row['writeAttempts']) is int and row['writeAttempts'] == factory + ids + attach + names + deletes,
             'ATTEMPT_COUNT_REJECTED')
        writes += row['writeAttempts']
        need(all(type(row[k]) is int and 0 <= row[k] <= 100001 for k in
                 ('countBefore', 'countAttached', 'countAfter'))
             and row['countAfter'] == row['countBefore'] and row['countBefore'] <= 100000,
             'CHILD_COUNT_REJECTED')
        need(row['kindDeclared'] is True and row['ownAbsentBefore'] is True and row['ownAbsent'] is True,
             'OWN_BASELINE_REJECTED')
        need(row['factoryVerified'] is (ids == 1)
             and (not row['createdOnlyRegistryVerified'] or row['factoryVerified'])
             and row['ownAttached'] is (attach == 1) and row['ownDeleted'] is (deletes == 1)
             and row['parentCleared'] is (deletes == 1)
             and (not row['ownNamed'] or names == 1) and (not row['freshReadbackVerified'] or reads == 1),
             'WRITER_FLAG_REJECTED')
        if attach:
            need(row['createdOnlyRegistryVerified'] is True
                 and row['countAttached'] == row['countBefore'] + 1, 'OWN_ATTACH_REJECTED')
        else:
            need(row['countAttached'] == 0, 'UNMEASURED_COUNT_REJECTED')
        for count_key, action in WRITER_PAIRS.items():
            if row[count_key]:required.update((f'before{kind}{action}', f'after{kind}{action}'))
        if reads:required.update((f'before{kind}Readback', f'after{kind}Readback'))
        if row['createdOnlyRegistryVerified']:
            _canonical(row['canonical']);registries.append(row)
        elif row['canonical'] is not None:
            _canonical(row['canonical'])
        if row['canonical'] is not None:canonical.append(row['canonical'])
        if row['canonicalAfter'] is not None:
            _canonical(row['canonicalAfter'])
            need(reads == 1 and row['canonicalAfter'] == row['canonical'], 'FRESH_CANONICAL_REJECTED')
        if row['freshReadbackVerified']:
            need(row['canonicalAfter'] is not None and row['ownNamed'] is True, 'READBACK_REJECTED')
        if full:
            need(all(row[k] is True for k in ROW_FLAGS)
                 and all(row[k] == 1 for k in ROW_COUNTS) and row['canonicalAfter'] == row['canonical']
                 and row['canonical'] is not None, 'FULL_OBJECT_REJECTED')
    need(type(info['writeAttempts']) is int and info['writeAttempts'] == writes and 0 <= writes <= 10,
         'TOTAL_ATTEMPTS_REJECTED')
    need(foreign['documentBeforeDelete'] is (rows[0]['deleteCalls'] == 1)
         and foreign['afterDocumentDelete'] is (rows[0]['deleteCalls'] == 1)
         and foreign['catalogBeforeDelete'] is (rows[1]['deleteCalls'] == 1), 'FOREIGN_BOUNDARY_REJECTED')
    if rows[1]['factoryCalls']:
        need(rows[0]['freshReadbackVerified'] is True and rows[0]['deleteCalls'] == 1
             and foreign['afterDocumentDelete'] is True, 'SEQUENCE_REJECTED')
    if len(canonical) == 2:
        need(all(canonical[0][k] == canonical[1][k] for k in CANONICAL_KEYS[:3])
             and canonical[0]['ownObject'] != canonical[1]['ownObject'], 'CANONICAL_ALIAS_REJECTED')
    if full:
        need(writes == 10 and all(foreign.values()) and all(phases.values()), 'FULL_PROOF_REJECTED')
        required = set(PHASES)
    need(all(phases[phase] is True for phase in required), 'EXECUTED_PHASE_REJECTED')
    # Terminal physical proof is mandatory for every branch. No boolean alone
    # can authorize close; unavailable reads become a stable ValueError.
    witnesses = {}
    for phase in PHASES:
        if phase in required:
            raw = _marker(read_marker, phase, info['operationId'])
            witnesses[marker_filename(phase)] = hashlib.sha256(raw).hexdigest()
    for row in registries:
        raw = _registry(read_marker, info, row)
        witnesses[registry_filename(row['kind'])] = hashlib.sha256(raw).hexdigest()
    return dict(verified=full, ownEmptyObjectsVerified=full, safeTerminalObserved=True,
                writeCount=writes, physicalWitnessSha256=witnesses, physicalWitnessCount=len(witnesses),
                foreignStructureVerified=True, foreignPropertyContentHashed=False,
                persistedGoldVerified=False, databaseConfigurationVerified=False,
                formVerified=False, attributeVerified=False, captureLatestVerified=False,
                nativePermit=False, writerAuthorized=False)
