"""Pure terminal proof for one own Gold Processing ObjectModule. No I/O or kill."""
import hashlib
import json
import math
import re

RESULT_LIMIT = 32768
MARKER_LIMIT = REGISTRY_LIMIT = 1024
RESULT_FILENAME = 'gold-own-object-module-v78.json'
REGISTRY_FILENAME = 'gold-own-object-module-v78-registry.json'
PHASES = tuple(part + stage for stage in (
    'Baseline', 'Factory', 'Attach', 'Name', 'Helper', 'OpenModule', 'ActionBegin',
    'Insertion', 'ActionClose', 'Undo', 'Readback', 'Delete', 'ScopeExit', 'FinalSourceControl')
    for part in ('before', 'after'))
TERMINAL_PHASES = PHASES[-4:]
ZERO_COUNTERS = ('foreignSourceWrites', 'goldSaves', 'repositoryWrites',
                 'databaseUpdates', 'businessCalls', 'dirtyFlagWrites')
SCOPE = dict(goldRootId='218b5d00-7e10-486f-874c-73c2368ed5da',
             ownProcessingId='6f24d183-3a3f-4bcd-9b79-d1a66be11778',
             processingClassId='bf845118-327b-4682-b5c6-285d2a0eb296',
             modulePropertyId='a637f77f-3840-441d-a1c3-699c8c5cb7e0',
             ownName='АгентПробаObjectModuleV78')
COUNTERS = ('factoryCalls', 'idSetterCalls', 'attachCalls', 'nameSetterCalls',
            'openModuleCalls', 'actionBeginCalls', 'moduleWriteCalls', 'actionCloseCalls', 'undoCalls', 'deleteCalls')
READ_COUNTERS = ('uiGetterCalls', 'editorTextGetterCalls')
FLAGS = ('baselineClean', 'rootIdentityPreserved', 'foreignGraphPreserved', 'goldSourcePreserved',
         'createdOnlyRegistryVerified', 'objectFactoryVerified', 'ownAttached', 'ownNamed',
         'helperBoundVerified', 'moduleOpenVerified', 'documentAbiVerified', 'initialEmpty',
         'initialDocumentClean', 'initialWritable', 'actionBeginAccepted', 'insertionExact',
         'actionClosed', 'documentModifiedAfterInsertion', 'undoAccepted', 'fullTextRestored',
         'helperTextRestored', 'documentCleanAfterUndo', 'selectionRestored', 'ownDeleted',
         'ownAbsent', 'parentCleared', 'nativeException', 'returnUnknown', 'taskScopeExited',
         'authenticatedDiscardEligible', 'ownModuleUndoVerified', 'rootModifiedAfter', 'uiModifiedAfter')
FLAGS += ('existingGoldUiVerified', 'editorTextBoundVerified')
FALSE_CLAIMS = ('dirtyFlagsForced', 'persistedGoldVerified', 'databaseConfigurationVerified', 'foreignPropertyContentHashed')
NUMBERS = ('writeAttempts', 'inputFlags', 'outputFlags', 'nativeReturn', 'processingCountBefore', 'processingCountAfter')
MAIN_KEYS = ('status', 'operationId', 'version', 'lifecycle') + tuple(SCOPE) + COUNTERS + READ_COUNTERS + FLAGS + FALSE_CLAIMS + NUMBERS + ZERO_COUNTERS
REGISTRY_KEYS = ('operationId', 'stage', 'createdOnly', 'rootId', 'objectId', 'classId', 'propertyId',
                 'version', 'factoryCalls', 'idSetterCalls', 'attachCalls', 'attachedIds', 'saveCalls')


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _shape(value, keys, code):
    _need(type(value) is dict and set(value) == set(keys), code)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'GOM78_DUPLICATE_JSON_REJECTED')
        result[key] = value
    return result


def _constant(_value):
    raise ValueError('GOM78_NONFINITE_JSON_REJECTED')


def _float(value):
    number = float(value)
    _need(math.isfinite(number), 'GOM78_NONFINITE_JSON_REJECTED')
    return number


def _parse(raw, limit):
    _need(type(raw) in (bytes, str), 'GOM78_JSON_REJECTED')
    try:
        payload = raw.encode('utf-8') if type(raw) is str else raw
        _need(0 < len(payload) <= limit, 'GOM78_JSON_SIZE_REJECTED')
        result = json.loads(payload.decode('utf-8'), object_pairs_hook=_pairs,
                            parse_constant=_constant, parse_float=_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('GOM78_JSON_REJECTED') from None
    _need(type(result) is dict, 'GOM78_JSON_REJECTED')
    return result


def parse_result(raw):
    return _parse(raw, RESULT_LIMIT)


def marker_filename(phase):
    _need(type(phase) is str and phase in PHASES, 'GOM78_PHASE_REJECTED')
    return 'gold-own-object-module-v78-' + phase + '.json'


def _read(reader, name, limit):
    try:
        body = reader(name)
    except Exception:
        raise ValueError('GOM78_RECEIPT_UNAVAILABLE') from None
    _need(type(body) is bytes, 'GOM78_RECEIPT_TYPE_REJECTED')
    return _parse(body, limit), body


def _marker(reader, phase):
    receipt, body = _read(reader, marker_filename(phase), MARKER_LIMIT)
    _shape(receipt, ('phase', 'operationId') + ZERO_COUNTERS, 'GOM78_MARKER_SHAPE_REJECTED')
    _need(receipt['phase'] == phase and type(receipt['operationId']) is str
          and re.fullmatch('[0-9a-f]{32}', receipt['operationId']) is not None
          and all(type(receipt[k]) is int and receipt[k] == 0 for k in ZERO_COUNTERS),
          'GOM78_MARKER_REJECTED')
    return dict(phase=phase, operationId=receipt['operationId'], sha256=hashlib.sha256(body).hexdigest())


def _registry(reader, info):
    receipt, body = _read(reader, REGISTRY_FILENAME, REGISTRY_LIMIT)
    _shape(receipt, REGISTRY_KEYS, 'GOM78_REGISTRY_SHAPE_REJECTED')
    _need(receipt['operationId'] == info['operationId'] and receipt['stage'] == 'beforeAttach'
          and receipt['createdOnly'] is True and receipt['rootId'] == SCOPE['goldRootId']
          and receipt['objectId'] == SCOPE['ownProcessingId'] and receipt['classId'] == SCOPE['processingClassId']
          and receipt['propertyId'] == SCOPE['modulePropertyId'] and type(receipt['version']) is int
          and receipt['version'] == info['version'] and type(receipt['attachedIds']) is list
          and receipt['attachedIds'] == [], 'GOM78_REGISTRY_SCOPE_REJECTED')
    _need(all(type(receipt[k]) is int and receipt[k] == v for k, v in
              (('factoryCalls', 1), ('idSetterCalls', 1), ('attachCalls', 0), ('saveCalls', 0))),
          'GOM78_REGISTRY_COUNTER_REJECTED')
    return dict(sha256=hashlib.sha256(body).hexdigest())


def verify(info, version, read_marker):
    """Prove a complete Undo or a known restored/absent terminal refusal.

    authenticatedDiscardEligible is a prerequisite for the separate parent
    close protocol. It never authorizes this pure module to stop a process.
    """
    _shape(info, MAIN_KEYS, 'GOM78_RESULT_SHAPE_REJECTED')
    _need(info['status'] in ('GOLD_OWN_OBJECT_MODULE_VERIFIED_V78', 'GOLD_OWN_OBJECT_MODULE_UNVERIFIED_V78')
          and type(info['operationId']) is str and re.fullmatch('[0-9a-f]{32}', info['operationId']) is not None,
          'GOM78_STATUS_REJECTED')
    _need(type(version) is int and 0 <= version <= 0x7fffffff and type(info['version']) is int
          and info['version'] == version, 'GOM78_VERSION_REJECTED')
    _need(all(info[k] == v for k, v in SCOPE.items()), 'GOM78_SCOPE_REJECTED')
    _need(all(type(info[k]) is bool for k in FLAGS) and all(info[k] is False for k in FALSE_CLAIMS)
          and all(type(info[k]) is int and info[k] == 0 for k in ZERO_COUNTERS), 'GOM78_TYPE_OR_WRITE_REJECTED')
    _need(all(type(info[k]) is int and 0 <= info[k] <= 1 for k in COUNTERS + READ_COUNTERS)
          and all(type(info[k]) is int and 0 <= info[k] <= 0xffffffff for k in NUMBERS), 'GOM78_COUNTER_REJECTED')
    _need(info['inputFlags'] == 65793 and info['processingCountBefore'] <= 100000
          and info['processingCountAfter'] == info['processingCountBefore'], 'GOM78_FINAL_COUNT_REJECTED')
    sequence = COUNTERS[:-1]
    _need(all(info[after] <= info[before] for before, after in zip(sequence, sequence[1:]))
          and info['deleteCalls'] <= info['attachCalls']
          and info['writeAttempts'] == sum(info[k] for k in COUNTERS if k != 'openModuleCalls'),
          'GOM78_COUNTER_ORDER_REJECTED')
    _need(info['uiGetterCalls'] <= info['nameSetterCalls']
          and info['editorTextGetterCalls'] <= info['openModuleCalls'], 'GOM78_READ_COUNTER_ORDER_REJECTED')
    dependencies = {
        'objectFactoryVerified': ('factoryCalls', 'idSetterCalls'),
        'createdOnlyRegistryVerified': ('objectFactoryVerified',),
        'ownAttached': ('attachCalls', 'objectFactoryVerified'),
        'ownNamed': ('nameSetterCalls', 'ownAttached'),
        'existingGoldUiVerified': ('uiGetterCalls', 'ownNamed'),
        'helperBoundVerified': ('ownNamed', 'existingGoldUiVerified'),
        'editorTextBoundVerified': ('editorTextGetterCalls', 'openModuleCalls'),
        'documentAbiVerified': ('openModuleCalls', 'helperBoundVerified'),
        'moduleOpenVerified': ('openModuleCalls', 'documentAbiVerified', 'editorTextBoundVerified'),
        'initialEmpty': ('moduleOpenVerified',),
        'initialDocumentClean': ('moduleOpenVerified',),
        'initialWritable': ('moduleOpenVerified',),
        'actionBeginAccepted': ('actionBeginCalls', 'initialEmpty', 'initialDocumentClean', 'initialWritable'),
        'insertionExact': ('moduleWriteCalls', 'actionBeginAccepted'),
        'actionClosed': ('actionCloseCalls', 'insertionExact'),
        'documentModifiedAfterInsertion': ('actionClosed',),
        'undoAccepted': ('undoCalls', 'actionClosed'),
        'fullTextRestored': ('undoAccepted',),
        'helperTextRestored': ('undoAccepted',),
        'documentCleanAfterUndo': ('undoAccepted',),
        'selectionRestored': ('fullTextRestored', 'helperTextRestored', 'documentCleanAfterUndo'),
        'ownDeleted': ('deleteCalls', 'parentCleared'),
        'parentCleared': ('deleteCalls',),
    }
    _need(all(not info[claim] or all(info[k] == 1 for k in required)
              for claim, required in dependencies.items()), 'GOM78_DEPENDENCY_REJECTED')
    _need(info['nativeException'] is False and info['returnUnknown'] is False
          and all(info[k] is True for k in ('baselineClean', 'rootIdentityPreserved', 'foreignGraphPreserved',
                    'goldSourcePreserved', 'taskScopeExited', 'ownAbsent', 'authenticatedDiscardEligible')),
          'GOM78_TERMINAL_REJECTED')
    if info['attachCalls']:
        _need(info['createdOnlyRegistryVerified'] is True and info['objectFactoryVerified'] is True
              and info['deleteCalls'] == 1 and info['ownDeleted'] is True and info['parentCleared'] is True,
              'GOM78_OWN_DELETE_REJECTED')
    if info['actionBeginCalls']:
        _need(all(info[k] == 1 for k in ('moduleWriteCalls', 'actionCloseCalls', 'undoCalls'))
              and all(info[k] is True for k in ('actionBeginAccepted', 'insertionExact', 'actionClosed',
                       'undoAccepted', 'fullTextRestored', 'helperTextRestored', 'documentCleanAfterUndo', 'selectionRestored')),
              'GOM78_UNRESTORED_ACTION_REJECTED')
    _shape(info['lifecycle'], PHASES, 'GOM78_LIFECYCLE_SHAPE_REJECTED')
    _need(all(type(info['lifecycle'][p]) is bool for p in PHASES)
          and all(info['lifecycle'][p] is True for p in TERMINAL_PHASES), 'GOM78_TERMINAL_RECEIPT_REJECTED')
    stages = dict(factoryCalls='Factory', attachCalls='Attach', nameSetterCalls='Name',
                  openModuleCalls='OpenModule', actionBeginCalls='ActionBegin', moduleWriteCalls='Insertion',
                  actionCloseCalls='ActionClose', undoCalls='Undo', deleteCalls='Delete')
    _need(all(not info[counter] or all(info['lifecycle'][part + stage] for part in ('before', 'after'))
              for counter, stage in stages.items()), 'GOM78_CALL_RECEIPT_REJECTED')
    full = info['status'] == 'GOLD_OWN_OBJECT_MODULE_VERIFIED_V78'
    _need(info['ownModuleUndoVerified'] is full, 'GOM78_SUCCESS_CLAIM_REJECTED')
    if full:
        _need(all(info[k] == 1 for k in COUNTERS + READ_COUNTERS)
              and all(info[k] is True for k in FLAGS if k not in ('nativeException', 'returnUnknown', 'rootModifiedAfter', 'uiModifiedAfter'))
              and all(info['lifecycle'][p] is True for p in PHASES), 'GOM78_FULL_PROOF_REJECTED')
    receipts = [_marker(read_marker, p) for p in (PHASES if full else TERMINAL_PHASES)]
    _need(all(r['operationId'] == info['operationId'] for r in receipts), 'GOM78_MARKER_OPERATION_REJECTED')
    registry = _registry(read_marker, info) if info['createdOnlyRegistryVerified'] else None
    return dict(ownModuleUndoVerified=full, sourceObservationVerified=True,
                authenticatedDiscardEligible=True, physicalMarkerCount=len(receipts),
                operationId=info['operationId'], writeAttempts=info['writeAttempts'],
                registryVerified=registry is not None, registrySha256=None if registry is None else registry['sha256'],
                rootModifiedAfter=info['rootModifiedAfter'], uiModifiedAfter=info['uiModifiedAfter'],
                persistedGoldVerified=False, databaseConfigurationVerified=False,
                foreignPropertyContentHashed=False, processStopPermitted=False, savePermitted=False)
