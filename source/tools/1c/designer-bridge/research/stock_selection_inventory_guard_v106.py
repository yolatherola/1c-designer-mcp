"""Bounded pure V106 observations. No dictionary here is a native permit."""
from __future__ import annotations

import json
import re

ROOT_ID = '218b5d00-7e10-486f-874c-73c2368ed5da'
OBJECT_ID = '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'
CLASS_ID = '061d872a-5787-460e-95ac-ed74ea3a3e84'
RESULT_LIMIT = 16384
PROCESS_SLOTS = ('0', '1', '2', '6', '14')
RECEIVER_SLOTS = ('16',)
COLLECTION_SLOTS = ('0', '1', '2')
HELPER_SLOTS = ('0', '1', '2', '3', '4')
NODE_KEYS = frozenset(('present', 'headerReadable', 'tableReadable', 'table', 'slots'))
ZERO_COUNTERS = ('privateMachineCalls', 'unknownVirtualCalls', 'getServiceCalls',
    'aggregateCalls', 'constructorCalls', 'plannerCalls', 'stockSelectionGetterCalls',
    'provider49Calls', 'provider50Calls', 'metadataWrites', 'goldSourceWrites',
    'goldSaves', 'repositoryWrites', 'databaseUpdates', 'businessCalls', 'dialogCalls',
    'configurationExports', 'configurationImports')
COUNTER_KEYS = frozenset(ZERO_COUNTERS + ('publishedCurrentProcessCalls',
    'existingReadOnlyGuardCalls', 'metadataBindingChecks'))
BINDING_KEYS = frozenset(('targetBefore', 'targetAfter', 'controllerAbiVerified',
    'sameCallbackGlobals', 'countedSourceHeld', 'fieldSame'))
SOURCE_KEYS = frozenset(('selectedBufferBefore', 'selectedBufferAfter', 'latchedCleanBefore',
    'latchedCleanAfter', 'ownershipFreeLatchedBefore', 'ownershipFreeLatchedAfter'))
PLANNER_KEYS = frozenset(('available', 'retainedMembershipBefore', 'retainedMembershipAfter',
    'knownAbi', 'countedReferenceBefore', 'countedReferenceAfter', 'refcountBefore',
    'refcountAfter', 'count', 'keyId', 'recordId', 'exactRequestedOnly', 'closingHead',
    'collection', 'helper'))
TOP_KEYS = frozenset(('status', 'version', 'rootId', 'objectId', 'classId', 'parentId',
    'binding', 'source', 'process', 'controller', 'planner', 'observationVerified',
    'sourceControlPreserved', 'externalFullComparisonRequired', 'fullStockSelectionVerified',
    'futureCtorVerified', 'nativePermit', 'captureVerified', 'nativeException',
    'returnUnknown', 'counters'))


def need(condition, code):
    if not condition:
        raise ValueError('V106_' + code)


def _keys(value, keys):
    need(type(value) is dict and set(value) == set(keys), 'SHAPE_REJECTED')


def _int(value, low=0, high=2**32-1):
    need(type(value) is int and low <= value <= high, 'INTEGER_REJECTED')


def _bool(value):
    need(type(value) is bool, 'BOOLEAN_REJECTED')


def _address(value):
    if value is None:
        return
    _keys(value, ('module', 'rva'))
    need(type(value['module']) is str and re.fullmatch(r'[a-z0-9_.-]{1,64}\.(?:dll|exe)', value['module']),
         'MODULE_REJECTED')
    _int(value['rva'], 0, 0x7fffffff)


def _node(value, slots):
    _keys(value, NODE_KEYS)
    for name in ('present', 'headerReadable', 'tableReadable'):
        _bool(value[name])
    _keys(value['slots'], slots)
    _address(value['table'])
    for item in value['slots'].values():
        _address(item)
    need(not value['headerReadable'] or value['present'], 'NODE_HEADER_WITHOUT_RECEIVER')
    need(not value['tableReadable'] or value['headerReadable'], 'NODE_TABLE_WITHOUT_HEADER')
    if not value['tableReadable']:
        need(value['table'] is None and all(item is None for item in value['slots'].values()),
             'NODE_UNREADABLE_CONTENT')


def parse_result(raw):
    """Parse at most 16 KiB, reject duplicate keys/nonfinite/deep hostile JSON."""
    need(type(raw) in (str, bytes), 'RESULT_TYPE')
    try:
        if isinstance(raw, bytes):
            need(len(raw) <= RESULT_LIMIT, 'RESULT_SIZE')
            raw = raw.decode('utf-8')
        need(0 < len(raw.encode('utf-8')) <= RESULT_LIMIT, 'RESULT_SIZE')
        def pairs(items):
            result = {}
            for key, value in items:
                need(key not in result, 'DUPLICATE_KEY')
                result[key] = value
            return result
        def reject(_):
            raise ValueError('V106_NONFINITE')
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)
        need(type(value) is dict, 'RESULT_OBJECT')
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('V106_RESULT_JSON') from error
    except ValueError as error:
        if str(error).startswith('V106_'):
            raise
        raise ValueError('V106_RESULT_JSON') from error


def verify(native, version):
    """Validate inventory/source scope; full comparisons remain outer obligations."""
    _int(version, 0, 0x7fffffff)
    _keys(native, TOP_KEYS)
    need(native['status'] == 'STOCK_SELECTION_INVENTORY_OBSERVED_V106', 'OBSERVATION_INCOMPLETE')
    _int(native['version'], 0, 0x7fffffff)
    need(native['version'] == version, 'VERSION_CHANGED')
    for name, expected in (('rootId', ROOT_ID), ('objectId', OBJECT_ID), ('classId', CLASS_ID), ('parentId', ROOT_ID)):
        need(native[name] == expected, 'TARGET_REJECTED')
    _keys(native['binding'], BINDING_KEYS)
    _keys(native['source'], SOURCE_KEYS)
    need(all(value is True for value in native['binding'].values()), 'BOUND_SCOPE_CHANGED')
    need(all(value is True for value in native['source'].values()), 'SOURCE_OR_OWNER_CHANGED')
    for name in ('observationVerified', 'sourceControlPreserved', 'externalFullComparisonRequired'):
        need(native[name] is True, 'CONTROL_REQUIRED')
    for name in ('fullStockSelectionVerified', 'futureCtorVerified', 'nativePermit',
                 'captureVerified', 'nativeException', 'returnUnknown'):
        need(native[name] is False, 'UNSUPPORTED_AUTHORITY')
    _keys(native['counters'], COUNTER_KEYS)
    for name in COUNTER_KEYS:
        _int(native['counters'][name])
        expected = 1 if name == 'publishedCurrentProcessCalls' else (4 if name == 'existingReadOnlyGuardCalls'
            else (2 if name == 'metadataBindingChecks' else 0))
        need(native['counters'][name] == expected, 'CALL_COUNT_REJECTED')
    p = native['process']
    _keys(p, ('callCount', 'callReturned', 'scopedHandleReleased', 'inventory'))
    _int(p['callCount'])
    need(p['callCount'] == 1 and p['callReturned'] is True and p['scopedHandleReleased'] is True,
         'PROCESS_LIFETIME_REJECTED')
    _node(p['inventory'], PROCESS_SLOTS)
    need(p['inventory']['present'] and p['inventory']['tableReadable'] and p['inventory']['table'] is not None,
         'PROCESS_UNAVAILABLE')
    c = native['controller']
    _keys(c, ('fieldOffset', 'fieldReadPerformed', 'eligibilityReceiver'))
    _int(c['fieldOffset'])
    need(c['fieldOffset'] == 0x38 and c['fieldReadPerformed'] is True, 'DEPENDENCY_FIELD_REJECTED')
    _node(c['eligibilityReceiver'], RECEIVER_SLOTS)
    planner = native['planner']
    _keys(planner, PLANNER_KEYS)
    for name in ('available', 'retainedMembershipBefore', 'retainedMembershipAfter', 'knownAbi',
                 'countedReferenceBefore', 'countedReferenceAfter', 'exactRequestedOnly', 'closingHead'):
        _bool(planner[name])
    _node(planner['collection'], COLLECTION_SLOTS)
    _node(planner['helper'], HELPER_SLOTS)
    if planner['knownAbi']:
        need(all(planner[name] is True for name in ('available', 'retainedMembershipBefore',
            'retainedMembershipAfter', 'countedReferenceBefore', 'countedReferenceAfter')), 'COLLECTION_LIFETIME_REJECTED')
        for name in ('refcountBefore', 'refcountAfter'):
            _int(planner[name], 1, 4096)
        need(planner['refcountBefore'] == planner['refcountAfter'], 'COLLECTION_REFERENCE_CHANGED')
        node = planner['collection']
        need(node['present'] and node['tableReadable'] and node['table'] == dict(module='devtool.dll', rva=0x18ddcc)
             and node['slots']['2'] == dict(module='devtool.dll', rva=0x14b8b0), 'COLLECTION_ABI_REJECTED')
        if planner['count'] is not None:
            _int(planner['count'], 0, 16)
        for name in ('keyId', 'recordId'):
            need(planner[name] in (None, OBJECT_ID), 'FOREIGN_RECORD_REJECTED')
        exact = planner['count'] == 1 and planner['closingHead'] and planner['keyId'] == OBJECT_ID and planner['recordId'] == OBJECT_ID
        need(planner['exactRequestedOnly'] is exact, 'EXACT_MAP_REJECTED')
        if planner['count'] != 1:
            need(planner['keyId'] is None and planner['recordId'] is None, 'UNREAD_MAP_CONTENT')
        if planner['count'] not in (0, 1):
            need(planner['closingHead'] is False, 'UNREAD_MAP_CHAIN')
    else:
        need(planner['countedReferenceBefore'] is False and planner['countedReferenceAfter'] is False,
             'UNKNOWN_COLLECTION_COUNTED')
        need(all(planner[name] is None for name in ('refcountBefore', 'refcountAfter', 'count', 'keyId', 'recordId'))
             and not planner['exactRequestedOnly'] and not planner['closingHead'], 'UNKNOWN_COLLECTION_CONTENT')
        need(not planner['collection']['present'] and not planner['helper']['present'], 'UNKNOWN_COLLECTION_INSPECTED')
    return dict(stage='V106StockSelectionInventory', verified=True, version=version,
        externalFullComparisonRequired=True, fullStockSelectionVerified=False,
        futureCtorVerified=False, nativePermit=False, captureVerified=False,
        dependencyMethodsCalled=0, plannerAvailable=planner['knownAbi'])
