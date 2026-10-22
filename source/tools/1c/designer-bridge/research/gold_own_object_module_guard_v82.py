"""Pure terminal proof for one own Gold Processing ObjectModule. No I/O or kill."""
import hashlib
import json
import math
import re

RESULT_LIMIT = 32768
MARKER_LIMIT = REGISTRY_LIMIT = 1024
RESULT_FILENAME = 'gold-own-object-module-v82.json'
REGISTRY_FILENAME = 'gold-own-object-module-v82-registry.json'
PHASES = tuple(part + stage for stage in (
    'Baseline', 'Factory', 'Attach', 'Name', 'Helper', 'OpenModule', 'ActionBegin',
    'Insertion', 'ActionClose', 'Undo', 'Readback', 'Delete', 'ScopeExit', 'FinalSourceControl')
    for part in ('before', 'after'))
TERMINAL_PHASES = PHASES[-4:]
ZERO_COUNTERS = ('foreignSourceWrites', 'goldSaves', 'repositoryWrites',
                 'databaseUpdates', 'businessCalls', 'dirtyFlagWrites')
SCOPE = dict(goldRootId='218b5d00-7e10-486f-874c-73c2368ed5da',
             ownProcessingId='2c8d17c0-17b1-514d-bf64-c3267719bdfe',
             processingClassId='bf845118-327b-4682-b5c6-285d2a0eb296',
             modulePropertyId='a637f77f-3840-441d-a1c3-699c8c5cb7e0',
             ownName='АгентПробаObjectModuleV82')
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
MAIN_KEYS = ('status', 'operationId', 'version', 'lifecycle', 'helperProbe', 'openProbe', 'documentProbe') + tuple(SCOPE) + COUNTERS + READ_COUNTERS + FLAGS + FALSE_CLAIMS + NUMBERS + ZERO_COUNTERS
HELPER_STAGES = ('notEntered', 'getEditHelper', 'moduleQI', 'helperABI', 'getMDObj', 'initialText', 'openReady')
HELPER_KEYS = ('stage', 'getEditHelperCalls', 'helperNonNull', 'moduleQiCalls', 'moduleNonNull',
               'helperTable', 'moduleTable', 'helperTableKnown', 'moduleTableKnown',
               'getMdObjTarget', 'textOfModuleTarget', 'openModuleTarget', 'slotsVerified',
               'getMdObjCalls', 'boundNonNull', 'boundEqualsOwn', 'boundGraphVerified',
               'initialTextReads', 'initialReadReturned', 'initialLengthBounded', 'initialCharacters')
HELPER_COUNTERS = ('getEditHelperCalls', 'moduleQiCalls', 'getMdObjCalls', 'initialTextReads')
HELPER_BOOLEANS = ('helperNonNull', 'moduleNonNull', 'helperTableKnown', 'moduleTableKnown',
                   'slotsVerified', 'boundNonNull', 'boundEqualsOwn', 'boundGraphVerified',
                   'initialReadReturned', 'initialLengthBounded')
HELPER_ADDRESSES = ('helperTable', 'moduleTable', 'getMdObjTarget', 'textOfModuleTarget', 'openModuleTarget')
ADDRESS_MODULES = ('basicui.dll', 'frntend.dll', 'basic.dll', 'backend.dll', 'core83.dll', 'txtedt.dll', 'txtedui.dll')
KNOWN_HELPER = dict(helperTable={'module': 'basicui.dll', 'rva': 0x60ae54},
                    moduleTable={'module': 'basicui.dll', 'rva': 0x60ad5c},
                    getMdObjTarget={'module': 'basicui.dll', 'rva': 0xf3b70},
                    textOfModuleTarget={'module': 'basicui.dll', 'rva': 0x35c470},
                    openModuleTarget={'module': 'basicui.dll', 'rva': 0x35c6f0})
OPEN_STAGES = ('notEntered', 'notReturned', 'afterOpenMarker', 'nullOutputs',
               'textTable', 'textSlot', 'editorTable', 'editorSlots', 'ready')
OPEN_BOOLEANS = ('openReturned', 'textNonNull', 'editorNonNull', 'textTableKnown',
                 'editorTableKnown', 'textSlotsVerified', 'editorSlotsVerified')
OPEN_ADDRESSES = ('textTable', 'editorTable', 'textManagerTarget', 'editorQiTarget', 'editorManagerTarget')
OPEN_COUNTERS = ('textSlotReads', 'editorSlotReads')
OPEN_KEYS = ('stage',) + OPEN_BOOLEANS + OPEN_ADDRESSES + OPEN_COUNTERS
KNOWN_OPEN = dict(textTable={'module': 'txtedt.dll', 'rva': 0x46dc4},
                  editorTable={'module': 'txtedui.dll', 'rva': 0x10db3c},
                  textManagerTarget={'module': 'txtedt.dll', 'rva': 0x2dcf0},
                  editorQiTarget={'module': 'txtedui.dll', 'rva': 0xe4680},
                  editorManagerTarget={'module': 'txtedui.dll', 'rva': 0xa2020})
DOCUMENT_STAGES = ('notEntered', 'qiNotCompleted', 'nullOutput', 'documentTable', 'documentSlots', 'ready')
DOCUMENT_BOOLEANS = ('documentQiObserved', 'documentNonNull', 'documentTableKnown', 'documentSlotsVerified')
DOCUMENT_ADDRESSES = ('documentTable', 'modifiedTarget', 'readOnlyTarget')
DOCUMENT_KEYS = ('stage',) + DOCUMENT_BOOLEANS + DOCUMENT_ADDRESSES + ('documentSlotReads',)
KNOWN_DOCUMENT = dict(documentTable={'module': 'txtedui.dll', 'rva': 0x109978},
                      modifiedTarget={'module': 'txtedui.dll', 'rva': 0x74450},
                      readOnlyTarget={'module': 'txtedui.dll', 'rva': 0x7d7d0})
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
        _need(key not in result, 'GOM82_DUPLICATE_JSON_REJECTED')
        result[key] = value
    return result


def _constant(_value):
    raise ValueError('GOM82_NONFINITE_JSON_REJECTED')


def _float(value):
    number = float(value)
    _need(math.isfinite(number), 'GOM82_NONFINITE_JSON_REJECTED')
    return number


def _parse(raw, limit):
    _need(type(raw) in (bytes, str), 'GOM82_JSON_REJECTED')
    try:
        payload = raw.encode('utf-8') if type(raw) is str else raw
        _need(0 < len(payload) <= limit, 'GOM82_JSON_SIZE_REJECTED')
        result = json.loads(payload.decode('utf-8'), object_pairs_hook=_pairs,
                            parse_constant=_constant, parse_float=_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('GOM82_JSON_REJECTED') from None
    _need(type(result) is dict, 'GOM82_JSON_REJECTED')
    return result


def parse_result(raw):
    return _parse(raw, RESULT_LIMIT)


def marker_filename(phase):
    _need(type(phase) is str and phase in PHASES, 'GOM82_PHASE_REJECTED')
    return 'gold-own-object-module-v82-' + phase + '.json'


def _read(reader, name, limit):
    try:
        body = reader(name)
    except Exception:
        raise ValueError('GOM82_RECEIPT_UNAVAILABLE') from None
    _need(type(body) is bytes, 'GOM82_RECEIPT_TYPE_REJECTED')
    return _parse(body, limit), body


def _marker(reader, phase):
    receipt, body = _read(reader, marker_filename(phase), MARKER_LIMIT)
    _shape(receipt, ('phase', 'operationId') + ZERO_COUNTERS, 'GOM82_MARKER_SHAPE_REJECTED')
    _need(receipt['phase'] == phase and type(receipt['operationId']) is str
          and re.fullmatch('[0-9a-f]{32}', receipt['operationId']) is not None
          and all(type(receipt[k]) is int and receipt[k] == 0 for k in ZERO_COUNTERS),
          'GOM82_MARKER_REJECTED')
    return dict(phase=phase, operationId=receipt['operationId'], sha256=hashlib.sha256(body).hexdigest())


def _registry(reader, info):
    receipt, body = _read(reader, REGISTRY_FILENAME, REGISTRY_LIMIT)
    _shape(receipt, REGISTRY_KEYS, 'GOM82_REGISTRY_SHAPE_REJECTED')
    _need(receipt['operationId'] == info['operationId'] and receipt['stage'] == 'beforeAttach'
          and receipt['createdOnly'] is True and receipt['rootId'] == SCOPE['goldRootId']
          and receipt['objectId'] == SCOPE['ownProcessingId'] and receipt['classId'] == SCOPE['processingClassId']
          and receipt['propertyId'] == SCOPE['modulePropertyId'] and type(receipt['version']) is int
          and receipt['version'] == info['version'] and type(receipt['attachedIds']) is list
          and receipt['attachedIds'] == [], 'GOM82_REGISTRY_SCOPE_REJECTED')
    _need(all(type(receipt[k]) is int and receipt[k] == v for k, v in
              (('factoryCalls', 1), ('idSetterCalls', 1), ('attachCalls', 0), ('saveCalls', 0))),
          'GOM82_REGISTRY_COUNTER_REJECTED')
    return dict(sha256=hashlib.sha256(body).hexdigest())


def _helper_probe(info):
    """Validate measured dispatch prerequisites; unknown tables grant no call."""
    probe = info['helperProbe']
    _shape(probe, HELPER_KEYS, 'GOM82_HELPER_SHAPE_REJECTED')
    _need(type(probe['stage']) is str and probe['stage'] in HELPER_STAGES
          and all(type(probe[k]) is int and 0 <= probe[k] <= 1 for k in HELPER_COUNTERS)
          and all(type(probe[k]) is bool for k in HELPER_BOOLEANS), 'GOM82_HELPER_TYPE_REJECTED')
    for key in HELPER_ADDRESSES:
        address = probe[key]
        if address is None:
            continue
        _shape(address, ('module', 'rva'), 'GOM82_HELPER_ADDRESS_REJECTED')
        _need(type(address['module']) is str and address['module'] in ADDRESS_MODULES
              and type(address['rva']) is int and 0 <= address['rva'] < 0x40000000,
              'GOM82_HELPER_ADDRESS_REJECTED')
    _need(probe['helperTableKnown'] is (probe['helperTable'] == KNOWN_HELPER['helperTable'])
          and probe['moduleTableKnown'] is (probe['moduleTable'] == KNOWN_HELPER['moduleTable']),
          'GOM82_HELPER_TABLE_CLAIM_REJECTED')
    _need(probe['getEditHelperCalls'] <= int(info['existingGoldUiVerified'])
          and probe['helperNonNull'] <= bool(probe['getEditHelperCalls'])
          and probe['moduleQiCalls'] == int(probe['helperNonNull'])
          and probe['moduleNonNull'] <= bool(probe['moduleQiCalls']), 'GOM82_HELPER_ORDER_REJECTED')
    _need((probe['helperNonNull'] or probe['helperTable'] is None)
          and (probe['moduleNonNull'] or probe['moduleTable'] is None), 'GOM82_HELPER_NULL_REJECTED')
    tables = probe['helperTableKnown'] and probe['moduleTableKnown']
    if not tables:
        _need(all(probe[k] is None for k in HELPER_ADDRESSES[2:])
              and probe['slotsVerified'] is False and probe['getMdObjCalls'] == 0,
              'GOM82_HELPER_UNKNOWN_DISPATCH_REJECTED')
    expected_slots = tables and all(probe[k] == KNOWN_HELPER[k] for k in HELPER_ADDRESSES[2:])
    _need(probe['slotsVerified'] is expected_slots and probe['getMdObjCalls'] == int(expected_slots),
          'GOM82_HELPER_SLOT_CLAIM_REJECTED')
    _need(probe['boundNonNull'] <= bool(probe['getMdObjCalls'])
          and probe['boundEqualsOwn'] <= probe['boundNonNull']
          and probe['boundGraphVerified'] <= probe['boundEqualsOwn']
          and info['helperBoundVerified'] is probe['boundGraphVerified'], 'GOM82_HELPER_BINDING_REJECTED')
    _need(probe['initialTextReads'] <= int(probe['boundGraphVerified'])
          and probe['initialReadReturned'] <= bool(probe['initialTextReads'])
          and probe['initialLengthBounded'] <= probe['initialReadReturned'], 'GOM82_HELPER_TEXT_ORDER_REJECTED')
    if probe['initialLengthBounded']:
        _need(type(probe['initialCharacters']) is int and 0 <= probe['initialCharacters'] <= 1048576,
              'GOM82_HELPER_TEXT_LENGTH_REJECTED')
    else:
        _need(probe['initialCharacters'] is None, 'GOM82_HELPER_TEXT_LENGTH_REJECTED')
    stage = probe['stage']
    expected_stage = ('notEntered' if not probe['getEditHelperCalls'] else
                      'getEditHelper' if not probe['helperNonNull'] else
                      'moduleQI' if not probe['moduleNonNull'] else
                      'helperABI' if not probe['slotsVerified'] else
                      'getMDObj' if not probe['initialTextReads'] else
                      'openReady' if info['openModuleCalls'] else 'initialText')
    _need(stage == expected_stage, 'GOM82_HELPER_STAGE_REJECTED')
    if info['openModuleCalls']:
        _need(probe['boundGraphVerified'] is True and probe['initialTextReads'] == 1
              and probe['initialReadReturned'] is True and probe['initialLengthBounded'] is True
              and probe['initialCharacters'] == 0, 'GOM82_HELPER_PREOPEN_REJECTED')
    return dict(stage=stage, dispatchPrerequisitesVerified=probe['slotsVerified'],
                receiverVerified=probe['boundGraphVerified'])


def open_probe(info):
    """Validate diagnostics only; even a truthful postopen failure cannot close."""
    probe = info['openProbe']
    _shape(probe, OPEN_KEYS, 'GOM82_OPEN_SHAPE_REJECTED')
    _need(type(probe['stage']) is str and probe['stage'] in OPEN_STAGES
          and all(type(probe[k]) is bool for k in OPEN_BOOLEANS)
          and type(probe['textSlotReads']) is int and 0 <= probe['textSlotReads'] <= 1
          and type(probe['editorSlotReads']) is int and probe['editorSlotReads'] in (0, 2),
          'GOM82_OPEN_TYPE_REJECTED')
    for key in OPEN_ADDRESSES:
        address = probe[key]
        if address is None:
            continue
        _shape(address, ('module', 'rva'), 'GOM82_OPEN_ADDRESS_REJECTED')
        _need(type(address['module']) is str and address['module'] in ADDRESS_MODULES
              and type(address['rva']) is int and 0 <= address['rva'] < 0x40000000,
              'GOM82_OPEN_ADDRESS_REJECTED')
    stage = probe['stage']
    _need(type(info['openModuleCalls']) is int and info['openModuleCalls'] in (0, 1)
          and type(info['returnUnknown']) is bool and type(info['moduleOpenVerified']) is bool
          and all(type(info[k]) is int and info[k] in (0, 1) for k in ('editorTextGetterCalls', 'actionBeginCalls')),
          'GOM82_OPEN_ORDER_REJECTED')
    if stage in OPEN_STAGES[:3]:
        _need(all(probe[k] is None for k in OPEN_ADDRESSES)
              and all(probe[k] is False for k in OPEN_BOOLEANS[3:])
              and all(probe[k] == 0 for k in OPEN_COUNTERS), 'GOM82_OPEN_COLD_REJECTED')
        if stage == 'notEntered':
            _need(info['openModuleCalls'] == 0 and all(probe[k] is False for k in OPEN_BOOLEANS),
                  'GOM82_OPEN_COLD_REJECTED')
        elif stage == 'notReturned':
            _need(info['openModuleCalls'] == 1 and all(probe[k] is False for k in OPEN_BOOLEANS)
                  and info['returnUnknown'] is True, 'GOM82_OPEN_RETURN_REJECTED')
        else:
            _need(info['openModuleCalls'] == 1 and probe['openReturned'] is True
                  and info['lifecycle']['afterOpenModule'] is False and info['returnUnknown'] is True,
                  'GOM82_OPEN_MARKER_REJECTED')
        ready = False
    else:
        _need(info['openModuleCalls'] == 1 and probe['openReturned'] is True,
              'GOM82_OPEN_RETURN_REJECTED')
        _need((probe['textNonNull'] or probe['textTable'] is None)
              and (probe['editorNonNull'] or probe['editorTable'] is None), 'GOM82_OPEN_NULL_REJECTED')
        if stage == 'nullOutputs':
            _need(not (probe['textNonNull'] and probe['editorNonNull'])
                  and all(probe[k] is False for k in OPEN_BOOLEANS[3:])
                  and all(probe[k] is None for k in OPEN_ADDRESSES[2:])
                  and all(probe[k] == 0 for k in OPEN_COUNTERS), 'GOM82_OPEN_NULL_REJECTED')
            ready = False
        else:
            _need(probe['textNonNull'] is True and probe['editorNonNull'] is True
                  and probe['textTableKnown'] is (probe['textTable'] == KNOWN_OPEN['textTable']),
                  'GOM82_OPEN_TABLE_CLAIM_REJECTED')
            _need(probe['textSlotReads'] == int(probe['textTableKnown'])
                  and (probe['textTableKnown'] or probe['textManagerTarget'] is None)
                  and probe['textSlotsVerified'] is (probe['textTableKnown'] and probe['textManagerTarget'] == KNOWN_OPEN['textManagerTarget']),
                  'GOM82_OPEN_TEXT_SLOT_REJECTED')
            if probe['textSlotsVerified']:
                _need(probe['editorTableKnown'] is (probe['editorTable'] == KNOWN_OPEN['editorTable']),
                      'GOM82_OPEN_TABLE_CLAIM_REJECTED')
            else:
                _need(probe['editorTableKnown'] is False, 'GOM82_OPEN_EDITOR_ORDER_REJECTED')
            _need(probe['editorSlotReads'] == 2 * int(probe['editorTableKnown'])
                  and (probe['editorTableKnown'] or all(probe[k] is None for k in OPEN_ADDRESSES[3:]))
                  and probe['editorSlotsVerified'] is (probe['editorTableKnown'] and all(probe[k] == KNOWN_OPEN[k] for k in OPEN_ADDRESSES[3:])),
                  'GOM82_OPEN_EDITOR_SLOT_REJECTED')
            ready = probe['textSlotsVerified'] and probe['editorSlotsVerified']
            expected = ('textTable' if not probe['textTableKnown'] else 'textSlot' if not probe['textSlotsVerified'] else
                        'editorTable' if not probe['editorTableKnown'] else 'editorSlots' if not probe['editorSlotsVerified'] else 'ready')
            _need(stage == expected, 'GOM82_OPEN_STAGE_REJECTED')
        if not ready:
            _need(info['returnUnknown'] is True, 'GOM82_OPEN_UNKNOWN_REJECTED')
    _need(not info['moduleOpenVerified'] or ready, 'GOM82_OPEN_SUCCESS_REJECTED')
    _need(not info['editorTextGetterCalls'] or ready, 'GOM82_OPEN_UNKNOWN_GETTER_REJECTED')
    _need(not info['actionBeginCalls'] or ready, 'GOM82_OPEN_UNKNOWN_WRITE_REJECTED')
    return dict(stage=stage, diagnosticVerified=True, outputAbiReady=ready, processStopPermitted=False)


def document_probe(info):
    """Validate guarded diagnostics; this never grants UNKNOWN close."""
    probe = info['documentProbe']
    _shape(probe, DOCUMENT_KEYS, 'GOM82_DOCUMENT_SHAPE_REJECTED')
    _need(type(probe['stage']) is str and probe['stage'] in DOCUMENT_STAGES
          and all(type(probe[k]) is bool for k in DOCUMENT_BOOLEANS)
          and type(probe['documentSlotReads']) is int and probe['documentSlotReads'] in (0, 2),
          'GOM82_DOCUMENT_TYPE_REJECTED')
    for key in DOCUMENT_ADDRESSES:
        address = probe[key]
        if address is None:
            continue
        _shape(address, ('module', 'rva'), 'GOM82_DOCUMENT_ADDRESS_REJECTED')
        _need(type(address['module']) is str and address['module'] in ADDRESS_MODULES
              and type(address['rva']) is int and 0 <= address['rva'] < 0x40000000,
              'GOM82_DOCUMENT_ADDRESS_REJECTED')
    _need(all(type(info[k]) is bool for k in ('documentAbiVerified', 'moduleOpenVerified',
                                             'editorTextBoundVerified', 'returnUnknown', 'nativeException'))
          and all(type(info[k]) is int and info[k] in (0, 1) for k in ('editorTextGetterCalls', 'actionBeginCalls')),
          'GOM82_DOCUMENT_ORDER_REJECTED')
    stage = probe['stage']
    if stage in DOCUMENT_STAGES[:2]:
        _need(all(probe[k] is False for k in DOCUMENT_BOOLEANS)
              and all(probe[k] is None for k in DOCUMENT_ADDRESSES)
              and probe['documentSlotReads'] == 0 and info['documentAbiVerified'] is False,
              'GOM82_DOCUMENT_COLD_REJECTED')
        if stage == 'qiNotCompleted':
            _need(info['openProbe']['stage'] == 'ready' and info['editorTextBoundVerified'] is True
                  and info['editorTextGetterCalls'] == 1
                  and (info['returnUnknown'] is True or info['nativeException'] is True),
                  'GOM82_DOCUMENT_QI_UNKNOWN_REJECTED')
        else:
            _need(info['editorTextBoundVerified'] is False, 'GOM82_DOCUMENT_PREQI_REJECTED')
        ready = False
    else:
        _need(probe['documentQiObserved'] is True and info['openProbe']['stage'] == 'ready'
              and info['editorTextBoundVerified'] is True and info['editorTextGetterCalls'] == 1,
              'GOM82_DOCUMENT_QI_ORDER_REJECTED')
        _need((probe['documentNonNull'] or probe['documentTable'] is None)
              and probe['documentTableKnown'] is (probe['documentTable'] == KNOWN_DOCUMENT['documentTable']),
              'GOM82_DOCUMENT_TABLE_CLAIM_REJECTED')
        if not probe['documentTableKnown']:
            _need(probe['documentSlotReads'] == 0 and probe['documentSlotsVerified'] is False
                  and probe['modifiedTarget'] is None and probe['readOnlyTarget'] is None,
                  'GOM82_DOCUMENT_UNKNOWN_SLOT_REJECTED')
        else:
            _need(probe['documentNonNull'] is True and probe['documentSlotReads'] == 2,
                  'GOM82_DOCUMENT_SLOT_ORDER_REJECTED')
        ready = probe['documentTableKnown'] and all(probe[k] == KNOWN_DOCUMENT[k] for k in DOCUMENT_ADDRESSES[1:])
        _need(probe['documentSlotsVerified'] is ready and info['documentAbiVerified'] is ready,
              'GOM82_DOCUMENT_SLOT_CLAIM_REJECTED')
        expected = ('nullOutput' if not probe['documentNonNull'] else 'documentTable' if not probe['documentTableKnown']
                    else 'documentSlots' if not ready else 'ready')
        _need(stage == expected, 'GOM82_DOCUMENT_STAGE_REJECTED')
        if not ready:
            _need(info['returnUnknown'] is True or info['nativeException'] is True,
                  'GOM82_DOCUMENT_UNKNOWN_REJECTED')
    _need((not info['moduleOpenVerified'] and not info['actionBeginCalls']) or ready,
          'GOM82_DOCUMENT_UNKNOWN_METHOD_REJECTED')
    return dict(stage=stage, diagnosticVerified=True, documentAbiReady=ready, processStopPermitted=False)


def verify(info, version, read_marker):
    """Prove a complete Undo or a known restored/absent terminal refusal.

    authenticatedDiscardEligible is a prerequisite for the separate parent
    close protocol. It never authorizes this pure module to stop a process.
    """
    _shape(info, MAIN_KEYS, 'GOM82_RESULT_SHAPE_REJECTED')
    _need(info['status'] in ('GOLD_OWN_OBJECT_MODULE_VERIFIED_V82', 'GOLD_OWN_OBJECT_MODULE_UNVERIFIED_V82')
          and type(info['operationId']) is str and re.fullmatch('[0-9a-f]{32}', info['operationId']) is not None,
          'GOM82_STATUS_REJECTED')
    _need(type(version) is int and 0 <= version <= 0x7fffffff and type(info['version']) is int
          and info['version'] == version, 'GOM82_VERSION_REJECTED')
    _need(all(info[k] == v for k, v in SCOPE.items()), 'GOM82_SCOPE_REJECTED')
    _need(all(type(info[k]) is bool for k in FLAGS) and all(info[k] is False for k in FALSE_CLAIMS)
          and all(type(info[k]) is int and info[k] == 0 for k in ZERO_COUNTERS), 'GOM82_TYPE_OR_WRITE_REJECTED')
    _need(all(type(info[k]) is int and 0 <= info[k] <= 1 for k in COUNTERS + READ_COUNTERS)
          and all(type(info[k]) is int and 0 <= info[k] <= 0xffffffff for k in NUMBERS), 'GOM82_COUNTER_REJECTED')
    helper = _helper_probe(info)
    opening = open_probe(info)
    document = document_probe(info)
    _need(info['inputFlags'] == 65793 and info['processingCountBefore'] <= 100000
          and info['processingCountAfter'] == info['processingCountBefore'], 'GOM82_FINAL_COUNT_REJECTED')
    sequence = COUNTERS[:-1]
    _need(all(info[after] <= info[before] for before, after in zip(sequence, sequence[1:]))
          and info['deleteCalls'] <= info['attachCalls']
          and info['writeAttempts'] == sum(info[k] for k in COUNTERS if k != 'openModuleCalls'),
          'GOM82_COUNTER_ORDER_REJECTED')
    _need(info['uiGetterCalls'] <= info['nameSetterCalls']
          and info['editorTextGetterCalls'] <= info['openModuleCalls'], 'GOM82_READ_COUNTER_ORDER_REJECTED')
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
              for claim, required in dependencies.items()), 'GOM82_DEPENDENCY_REJECTED')
    _need(info['nativeException'] is False and info['returnUnknown'] is False
          and all(info[k] is True for k in ('baselineClean', 'rootIdentityPreserved', 'foreignGraphPreserved',
                    'goldSourcePreserved', 'taskScopeExited', 'ownAbsent', 'authenticatedDiscardEligible')),
          'GOM82_TERMINAL_REJECTED')
    if info['attachCalls']:
        _need(info['createdOnlyRegistryVerified'] is True and info['objectFactoryVerified'] is True
              and info['deleteCalls'] == 1 and info['ownDeleted'] is True and info['parentCleared'] is True,
              'GOM82_OWN_DELETE_REJECTED')
    if info['actionBeginCalls']:
        _need(all(info[k] == 1 for k in ('moduleWriteCalls', 'actionCloseCalls', 'undoCalls'))
              and all(info[k] is True for k in ('actionBeginAccepted', 'insertionExact', 'actionClosed',
                       'undoAccepted', 'fullTextRestored', 'helperTextRestored', 'documentCleanAfterUndo', 'selectionRestored')),
              'GOM82_UNRESTORED_ACTION_REJECTED')
    _shape(info['lifecycle'], PHASES, 'GOM82_LIFECYCLE_SHAPE_REJECTED')
    _need(all(type(info['lifecycle'][p]) is bool for p in PHASES)
          and all(info['lifecycle'][p] is True for p in TERMINAL_PHASES), 'GOM82_TERMINAL_RECEIPT_REJECTED')
    stages = dict(factoryCalls='Factory', attachCalls='Attach', nameSetterCalls='Name',
                  openModuleCalls='OpenModule', actionBeginCalls='ActionBegin', moduleWriteCalls='Insertion',
                  actionCloseCalls='ActionClose', undoCalls='Undo', deleteCalls='Delete')
    _need(all(not info[counter] or all(info['lifecycle'][part + stage] for part in ('before', 'after'))
              for counter, stage in stages.items()), 'GOM82_CALL_RECEIPT_REJECTED')
    full = info['status'] == 'GOLD_OWN_OBJECT_MODULE_VERIFIED_V82'
    _need(info['ownModuleUndoVerified'] is full, 'GOM82_SUCCESS_CLAIM_REJECTED')
    if full:
        _need(all(info[k] == 1 for k in COUNTERS + READ_COUNTERS)
              and all(info[k] is True for k in FLAGS if k not in ('nativeException', 'returnUnknown', 'rootModifiedAfter', 'uiModifiedAfter'))
              and all(info['lifecycle'][p] is True for p in PHASES), 'GOM82_FULL_PROOF_REJECTED')
    receipts = [_marker(read_marker, p) for p in (PHASES if full else TERMINAL_PHASES)]
    _need(all(r['operationId'] == info['operationId'] for r in receipts), 'GOM82_MARKER_OPERATION_REJECTED')
    registry = _registry(read_marker, info) if info['createdOnlyRegistryVerified'] else None
    return dict(ownModuleUndoVerified=full, sourceObservationVerified=True,
                helperProbe=helper, openProbe=opening, documentProbe=document,
                authenticatedDiscardEligible=True, physicalMarkerCount=len(receipts),
                operationId=info['operationId'], writeAttempts=info['writeAttempts'],
                registryVerified=registry is not None, registrySha256=None if registry is None else registry['sha256'],
                rootModifiedAfter=info['rootModifiedAfter'], uiModifiedAfter=info['uiModifiedAfter'],
                persistedGoldVerified=False, databaseConfigurationVerified=False,
                foreignPropertyContentHashed=False, processStopPermitted=False, savePermitted=False)
