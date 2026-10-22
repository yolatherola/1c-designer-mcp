"""Pure bounded transient OWN structure evidence; never an execution permit."""
import hashlib
import json
import re

LIMIT = 32768
WITNESS_LIMIT = 1024
ROOT_ID = '218b5d00-7e10-486f-874c-73c2368ed5da'
OBJECTS = (
    ('Document', 'f9465e2d-cf68-4a8a-9f22-c0ad3b3a0139',
     '061d872a-5787-460e-95ac-ed74ea3a3e84', 'AgentStructureDocumentV139', ROOT_ID),
    ('DocumentAttribute', '909463f7-dcb9-496a-98a0-1659b6ac9139',
     '45e46cbc-3e24-4165-8b7b-cc98a6f80211', 'AgentStructureAttributeV139',
     'f9465e2d-cf68-4a8a-9f22-c0ad3b3a0139'),
    ('TablePart', 'a4566be1-6f2c-48e7-bd30-bf76f5fd2139',
     '21c53e09-8950-4b5e-a6a0-1054f1bbc274', 'AgentStructureTablePartV139',
     'f9465e2d-cf68-4a8a-9f22-c0ad3b3a0139'),
    ('TablePartAttribute', '2d1fc5a3-9686-43ac-aba9-ec3eef7d3139',
     '888744e1-b616-11d4-9436-004095e12fc7', 'AgentStructureColumnV139',
     'a4566be1-6f2c-48e7-bd30-bf76f5fd2139'),
)
PARENTS = (None, 0, 0, 2)
PHASES = ('beforeBaseline', 'afterBaseline') + tuple(
    prefix + row[0] + action for row in OBJECTS
    for action in ('Factory', 'Id', 'Attach', 'Name') for prefix in ('before', 'after')) + tuple(
    prefix + row[0] + 'Readback' for row in OBJECTS for prefix in ('before', 'after')) + tuple(
    prefix + row[0] + 'Delete' for row in reversed(OBJECTS) for prefix in ('before', 'after')) + (
    'beforeScopeExit', 'afterScopeExit', 'beforeFinalSourceControl', 'afterFinalSourceControl')
TERMINAL_PHASES = PHASES[-4:]
FOREIGN_CHECKS = ('baseline',) + tuple('after' + row[0] + 'Name' for row in OBJECTS) + (
    'beforeReverseCleanup',) + tuple('after' + row[0] + 'Delete' for row in reversed(OBJECTS)) + ('finalAfterScope',)
ZERO_COUNTERS = ('foreignSourceWrites', 'goldSaves', 'repositoryWrites', 'databaseUpdates',
                 'businessCalls', 'dirtyFlagWrites', 'configurationExports', 'configurationImports')
MARKER_ZEROS = ZERO_COUNTERS[:6]
FALSE_CLAIMS = ('persistedGoldVerified', 'databaseConfigurationVerified', 'foreignPropertyContentHashed',
                'formVerified', 'typePropertiesVerified', 'stringTypeVerified', 'qualifierVerified',
                'captureLatestVerified', 'dirtyFlagsForced', 'nativePermit', 'writerAuthorized')
FLAGS = ('baselineClean', 'rootIdentityPreserved', 'goldSourcePreserved', 'foreignGraphPreserved',
         'taskScopeExited', 'authenticatedDiscardEligible', 'ownStructureVerified', 'nativeException', 'returnUnknown')
KEYS = ('status', 'operationId', 'version', 'goldRootId', 'writeAttempts',
        'foreignGraphPasses', 'foreignGraphNodes', 'foreignChecks', 'objects', 'lifecycle') + ZERO_COUNTERS + FALSE_CLAIMS + FLAGS
ROW_COUNTS = ('factoryCalls', 'idSetterCalls', 'attachCalls', 'nameSetterCalls', 'freshReadCalls', 'deleteCalls')
ROW_FLAGS = ('kindDeclared', 'ownAbsentBefore', 'factoryVerified', 'createdOnlyRegistryVerified',
             'ownAttached', 'ownNamed', 'freshReadbackVerified', 'ownDeleted', 'parentCleared', 'ownAbsent')
ROW_KEYS = ('kind', 'ownId', 'classId', 'name', 'parentId', 'writeAttempts', 'countBefore',
            'countAttached', 'countAfter', 'registrySequence', 'canonical', 'canonicalAfter') + ROW_COUNTS + ROW_FLAGS
CANONICAL_KEYS = ('goldManager', 'goldRoot', 'selectedDocument', 'ownObject')
REGISTRY_KEYS = ('operationId', 'stage', 'createdOnly', 'kind', 'rootId', 'ownId', 'classId',
                 'parentId', 'version', 'sequence', 'canonical', 'factoryCalls', 'idSetterCalls',
                 'attachCalls', 'attachedIds', 'goldSaves')
WRITERS = dict(zip(('factoryCalls', 'idSetterCalls', 'attachCalls', 'nameSetterCalls', 'deleteCalls'),
                   ('Factory', 'Id', 'Attach', 'Name', 'Delete')))


def need(ok, code):
    if not ok:
        raise ValueError('GD139_' + code)


def parse_result(raw, *, limit=LIMIT):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'JSON_REJECTED')
            value[key] = item
        return value

    def invalid(_):
        raise ValueError('GD139_JSON_REJECTED')

    need(type(raw) is bytes and 0 < len(raw) <= limit, 'JSON_REJECTED')
    try:
        value = json.loads(raw.decode('utf8'), object_pairs_hook=pairs,
                           parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('GD139_JSON_REJECTED') from None
    need(type(value) is dict, 'JSON_REJECTED')
    return value


def marker_filename(phase):
    need(type(phase) is str and phase in PHASES, 'MARKER_NAME_REJECTED')
    return 'gold-owned-document-structure-v139-' + phase + '.json'


def registry_filename(kind):
    need(type(kind) is str and kind in tuple(row[0] for row in OBJECTS), 'REGISTRY_NAME_REJECTED')
    return 'gold-owned-document-structure-v139-' + kind.lower() + '-registry.json'


def _read(reader, name):
    need(callable(reader), 'READER_REQUIRED')
    try:
        raw = reader(name)
    except Exception:
        raise ValueError('GD139_WITNESS_UNAVAILABLE') from None
    need(type(raw) is bytes and 0 < len(raw) <= WITNESS_LIMIT, 'WITNESS_BOUND_REJECTED')
    return raw


def _canonical(value):
    need(type(value) is dict and set(value) == set(CANONICAL_KEYS)
         and all(type(value[k]) is int and 0 < value[k] <= 0xffffffff for k in CANONICAL_KEYS)
         and len(set(value.values())) == 4, 'CANONICAL_REJECTED')


def verify(info, version, read_witness):
    """Require actual terminal receipts even for known partial cleanup.

    Role/lease/PID/source closure remain the caller's responsibility. UNKNOWN,
    exceptions, unbalanced children or missing physical source receipts refuse
    the proof; this function never returns a native or writer authorization.
    """
    need(type(info) is dict and set(info) == set(KEYS), 'SHAPE_REJECTED')
    need(type(version) is int and 0 <= version <= 0x7fffffff and type(info['version']) is int
         and info['version'] == version, 'VERSION_REJECTED')
    need(type(info['operationId']) is str and re.fullmatch('[a-f0-9]{32}', info['operationId'])
         and info['goldRootId'] == ROOT_ID, 'OPERATION_SCOPE_REJECTED')
    need(all(type(info[k]) is bool for k in FLAGS), 'FLAG_TYPE_REJECTED')
    need(info['nativeException'] is False and info['returnUnknown'] is False, 'UNKNOWN_REJECTED')
    need(all(info[k] is True for k in FLAGS if k not in
             ('nativeException', 'returnUnknown', 'ownStructureVerified')), 'TERMINAL_REJECTED')
    need(all(type(info[k]) is int and info[k] == 0 for k in ZERO_COUNTERS), 'WRITES_REJECTED')
    need(all(info[k] is False for k in FALSE_CLAIMS), 'FALSE_CLAIM_REJECTED')
    full = info['ownStructureVerified']
    need(info['status'] == ('GOLD_OWNED_DOCUMENT_STRUCTURE_VERIFIED_V139' if full else
                           'GOLD_OWNED_DOCUMENT_STRUCTURE_UNVERIFIED_V139'), 'STATUS_REJECTED')
    phases, foreign, rows = (info[k] for k in ('lifecycle', 'foreignChecks', 'objects'))
    need(type(phases) is dict and set(phases) == set(PHASES)
         and all(type(v) is bool for v in phases.values()), 'LIFECYCLE_REJECTED')
    need(type(foreign) is dict and set(foreign) == set(FOREIGN_CHECKS)
         and all(type(v) is bool for v in foreign.values())
         and all(foreign[k] is True for k in ('baseline', 'beforeReverseCleanup', 'finalAfterScope')), 'FOREIGN_REJECTED')
    need(type(info['foreignGraphNodes']) is int and 0 < info['foreignGraphNodes'] <= 100000
         and type(info['foreignGraphPasses']) is int and info['foreignGraphPasses'] == sum(foreign.values()), 'FOREIGN_COUNT_REJECTED')
    need(type(rows) is list and len(rows) == 4, 'OBJECTS_REJECTED')
    required = set(TERMINAL_PHASES) | {'beforeBaseline', 'afterBaseline'}
    registries, canonical, writes = [], [], 0
    for index, (row, expected) in enumerate(zip(rows, OBJECTS)):
        need(type(row) is dict and set(row) == set(ROW_KEYS)
             and tuple(row[k] for k in ('kind', 'ownId', 'classId', 'name', 'parentId')) == expected, 'OWN_SCOPE_REJECTED')
        need(all(type(row[k]) is bool for k in ROW_FLAGS)
             and all(type(row[k]) is int and 0 <= row[k] <= 1 for k in ROW_COUNTS), 'ROW_TYPE_REJECTED')
        factory, ids, attach, names, reads, deletes = (row[k] for k in ROW_COUNTS)
        need(deletes == attach and 0 <= reads <= names <= attach <= ids <= factory <= 1, 'WRITER_LEDGER_REJECTED')
        need(type(row['writeAttempts']) is int and row['writeAttempts'] == factory + ids + attach + names + deletes,
             'ATTEMPT_COUNT_REJECTED')
        writes += row['writeAttempts']
        need(all(type(row[k]) is int and 0 <= row[k] <= 100001 for k in ('countBefore', 'countAttached', 'countAfter'))
             and row['countBefore'] <= 100000 and row['countAfter'] == row['countBefore']
             and (index == 0 or row['countBefore'] == 0), 'CHILD_COUNT_REJECTED')
        need(type(row['registrySequence']) is int and 0 <= row['registrySequence'] <= 64, 'REGISTRY_SEQUENCE_REJECTED')
        need(row['ownAbsentBefore'] is True and row['ownAbsent'] is True
             and (not factory or row['kindDeclared'] is True), 'OWN_BASELINE_REJECTED')
        need(row['factoryVerified'] is (ids == 1) and (not row['createdOnlyRegistryVerified'] or row['factoryVerified'])
             and row['ownAttached'] is (attach == 1) and row['ownDeleted'] is (deletes == 1)
             and row['parentCleared'] is (deletes == 1) and (not row['ownNamed'] or names == 1)
             and (not row['freshReadbackVerified'] or reads == 1), 'WRITER_FLAG_REJECTED')
        if attach:
            need(row['createdOnlyRegistryVerified'] is True and row['countAttached'] == row['countBefore'] + 1, 'OWN_ATTACH_REJECTED')
        else:
            need(row['countAttached'] == 0, 'UNMEASURED_COUNT_REJECTED')
        for key, action in WRITERS.items():
            if row[key]:
                required.update(('before' + row['kind'] + action, 'after' + row['kind'] + action))
        if reads:
            required.update(('before' + row['kind'] + 'Readback', 'after' + row['kind'] + 'Readback'))
        if row['createdOnlyRegistryVerified']:
            _canonical(row['canonical'])
            need(row['registrySequence'] > 0, 'REGISTRY_SEQUENCE_REJECTED')
            registries.append(row)
        elif row['canonical'] is not None:
            _canonical(row['canonical'])
        if row['canonical'] is not None:
            canonical.append(row['canonical'])
        if row['canonicalAfter'] is not None:
            _canonical(row['canonicalAfter'])
            need(reads == 1 and row['canonicalAfter'] == row['canonical'], 'FRESH_CANONICAL_REJECTED')
        if row['freshReadbackVerified']:
            need(row['canonicalAfter'] is not None and row['ownNamed'] is True, 'READBACK_REJECTED')
        need(foreign['after' + row['kind'] + 'Name'] is (names == 1)
             and foreign['after' + row['kind'] + 'Delete'] is (deletes == 1), 'FOREIGN_BOUNDARY_REJECTED')
        if factory and index:
            parent = rows[PARENTS[index]]
            need(parent['ownNamed'] is True and parent['attachCalls'] == 1, 'PARENT_SEQUENCE_REJECTED')
        if index and factory:
            need(rows[index - 1]['ownNamed'] is True, 'CREATE_SEQUENCE_REJECTED')
        if reads:
            need(all(other['ownNamed'] is True and other['attachCalls'] == 1 for other in rows), 'FRESH_STRUCTURE_REJECTED')
        if full:
            need(all(row[k] is True for k in ROW_FLAGS) and all(row[k] == 1 for k in ROW_COUNTS)
                 and row['canonicalAfter'] == row['canonical'] and row['canonical'] is not None, 'FULL_OBJECT_REJECTED')
    need(type(info['writeAttempts']) is int and info['writeAttempts'] == writes and 0 <= writes <= 20, 'TOTAL_ATTEMPTS_REJECTED')
    if canonical:
        need(all(all(value[k] == canonical[0][k] for k in CANONICAL_KEYS[:3]) for value in canonical)
             and len({value['ownObject'] for value in canonical}) == len(canonical), 'CANONICAL_ALIAS_REJECTED')
    if full:
        need(writes == 20 and all(phases.values()) and all(foreign.values()), 'FULL_PROOF_REJECTED')
        required = set(PHASES)
    # A terminal report cannot hide executed phases or manufacture an unexecuted
    # native writer. Registry events are inserted between exact Id and Attach.
    need(all(phases[k] is (k in required) for k in PHASES), 'EXECUTED_PHASE_REJECTED')
    witnesses, events, counters = {}, [], {}
    for phase in PHASES:
        if phase not in required:
            continue
        name = marker_filename(phase)
        raw = _read(read_witness, name)
        value = parse_result(raw, limit=WITNESS_LIMIT)
        need(set(value) == {'phase', 'operationId', 'sequence', 'writeAttempts', *MARKER_ZEROS}
             and value['phase'] == phase and value['operationId'] == info['operationId']
             and type(value['sequence']) is int and 1 <= value['sequence'] <= 64
             and type(value['writeAttempts']) is int and 0 <= value['writeAttempts'] <= writes
             and all(type(value[k]) is int and value[k] == 0 for k in MARKER_ZEROS), 'MARKER_REJECTED')
        witnesses[name] = hashlib.sha256(raw).hexdigest()
        events.append((PHASES.index(phase) * 2, value['sequence']))
        counters[phase] = value['writeAttempts']
    for row in registries:
        name = registry_filename(row['kind'])
        raw = _read(read_witness, name)
        value = parse_result(raw, limit=WITNESS_LIMIT)
        need(set(value) == set(REGISTRY_KEYS) and value['operationId'] == info['operationId']
             and value['stage'] == 'beforeAttach' and value['createdOnly'] is True
             and value['kind'] == row['kind'] and value['rootId'] == ROOT_ID
             and all(value[k] == row[k] for k in ('ownId', 'classId', 'parentId', 'canonical'))
             and type(value['version']) is int and value['version'] == version
             and type(value['sequence']) is int and value['sequence'] == row['registrySequence']
             and type(value['attachedIds']) is list and value['attachedIds'] == []
             and all(type(value[k]) is int and value[k] == expected for k, expected in
                     (('factoryCalls', 1), ('idSetterCalls', 1), ('attachCalls', 0), ('goldSaves', 0))), 'REGISTRY_REJECTED')
        _canonical(value['canonical'])
        witnesses[name] = hashlib.sha256(raw).hexdigest()
        events.append((PHASES.index('after' + row['kind'] + 'Id') * 2 + 1, value['sequence']))
    ordered = [sequence for _, sequence in sorted(events)]
    need(all(a < b for a, b in zip(ordered, ordered[1:])), 'PHYSICAL_SEQUENCE_REJECTED')
    running = 0
    for phase in PHASES:
        if phase not in required:
            continue
        before = phase.startswith('before')
        writer = any(phase == prefix + row['kind'] + action and row[key] == 1
                     for row in rows for key, action in WRITERS.items() for prefix in ('before', 'after'))
        if writer and not before:
            running += 1
        need(counters[phase] == running, 'PHYSICAL_ATTEMPTS_REJECTED')
    need(running == writes, 'PHYSICAL_ATTEMPTS_REJECTED')
    return dict(verified=full, ownStructureVerified=full, safeTerminalObserved=True,
                writeCount=writes, physicalWitnessSha256=witnesses, physicalWitnessCount=len(witnesses),
                foreignStructureVerified=True, foreignPropertyContentHashed=False,
                persistedGoldVerified=False, databaseConfigurationVerified=False, typePropertiesVerified=False,
                stringTypeVerified=False, qualifierVerified=False, formVerified=False,
                captureLatestVerified=False, nativePermit=False, writerAuthorized=False)
