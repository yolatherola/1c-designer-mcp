"""Strict readonly typed receiver observations; never Main/DB or Save authority.

Same-interface pointer equality is not canonical identity or metadata equality.
The caller separately proves source pins, PID/birth, lease and the close path.
"""
import json
import re

LIMIT = 32768
OWN_ID = 'e65cf9ac-3af8-42f2-bd9d-68542f5e1b09'
GOLD_ROOT_ID = '218b5d00-7e10-486f-874c-73c2368ed5da'
ORIGINS = ('current-edit-ui', 'templates-main-ui', 'default-infobase')
ROW_FLAGS = ('uiReturned', 'uiAbiVerified', 'managerReturned', 'managerAbiVerified',
             'rootReturned', 'rootAbiVerified', 'rootClassReturned',
             'rootManagerInterfacePointerEqual', 'managerRootInterfacePointerEqual',
             'rootInterfacePointerEqualCurrent', 'managerInterfacePointerEqualCurrent',
             'ownPresent', 'ownIdMatches')
ROW_COUNTS = ('uiRootCalls', 'rootManagerCalls', 'managerRootCalls', 'rootIdReads',
              'rootClassReads', 'classIdReads', 'ownLookupCalls', 'ownIdReads')
ROW_KEYS = ('origin', 'rootId', 'rootClassId', 'ownObjectId') + ROW_FLAGS + ROW_COUNTS
SCOPE_FLAGS = ('scopeBeforeVerified', 'scopeAfterVerified', 'selectedSourcePreserved',
               'bindingAndVersionUnchanged', 'receiverHandlesScoped', 'scopeExited')
OBSERVATION_FLAGS = ('editServiceReturned', 'editServiceAbiVerified',
                     'infoBaseServiceReturned', 'infoBaseReturned', 'infoBaseAbiVerified')
RELATION_FLAGS = ('templatesInfoBaseRootInterfacePointerEqual',
                  'templatesInfoBaseManagerInterfacePointerEqual', 'templatesInfoBaseRootUuidEqual')
COUNTS = ('editServiceRequests', 'templatesUiCalls', 'infoBaseServiceRequests',
          'defaultInfoBaseCalls', 'infoBaseManagerCalls', 'infoBaseRootCalls')
ZERO_COUNTERS = ('explicitQueryInterfaceCalls', 'rawAdoptions', 'objectFactoryCalls',
                 'metadataSetters', 'ownedDeletes', 'configurationWrites',
                 'configurationSaves', 'configurationExports', 'configurationImports',
                 'repositoryMutations', 'databaseUpdates', 'businessCalls',
                 'eventSubscriptions', 'eventUnsubscriptions', 'eventNotifications')
FALSE_CLAIMS = ('canonicalIdentityVerified', 'templatesMainRoleVerified',
                'infoBaseDatabaseRoleVerified', 'semanticMainDbRoleVerified',
                'metadataEqualityVerified', 'pendingOwnOnlyVerified', 'saveAuthorized',
                'databaseUpdateAuthorized', 'observerAuthorized', 'captureAuthorized', 'nativePermit')
KEYS = ('status', 'version', 'ownObjectId', 'nativeException', 'returnUnknown', 'receivers') + \
       SCOPE_FLAGS + OBSERVATION_FLAGS + RELATION_FLAGS + COUNTS + ZERO_COUNTERS + FALSE_CLAIMS
GUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z')


def need(ok, code):
    if not ok:
        raise ValueError('V126_RECEIVER_' + code)


def parse_result(raw):
    """Parse only bounded strict UTF8 JSON with unique keys and integer numbers."""
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'JSON_REJECTED')
            value[key] = item
        return value

    def invalid(_):
        raise ValueError('V126_RECEIVER_JSON_REJECTED')

    need(type(raw) is bytes and 0 < len(raw) <= LIMIT, 'JSON_REJECTED')
    try:
        result = json.loads(raw.decode('utf8'), object_pairs_hook=pairs,
                            parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('V126_RECEIVER_JSON_REJECTED') from None
    need(type(result) is dict, 'JSON_REJECTED')
    return result


def _guid(value, code):
    need(type(value) is str and GUID.fullmatch(value), code)


def _row(row, origin):
    need(type(row) is dict and set(row) == set(ROW_KEYS) and row['origin'] == origin,
         'ROW_SCOPE_REJECTED')
    need(all(type(row[k]) is bool for k in ROW_FLAGS), 'ROW_FLAG_TYPE_REJECTED')
    need(all(type(row[k]) is int and 0 <= row[k] <= 1 for k in ROW_COUNTS), 'ROW_COUNT_REJECTED')
    need(not row['uiAbiVerified'] or row['uiReturned'], 'UI_ORDER_REJECTED')
    need(not row['managerAbiVerified'] or row['managerReturned'], 'MANAGER_ORDER_REJECTED')
    need(not row['rootAbiVerified'] or row['rootReturned'], 'ROOT_ORDER_REJECTED')
    if origin == 'default-infobase':
        need(row['uiReturned'] is False and row['uiAbiVerified'] is False
             and row['uiRootCalls'] == 0, 'IB_UI_CLAIM_REJECTED')
    else:
        need(row['uiRootCalls'] == int(row['uiAbiVerified'])
             and (not row['rootReturned'] or row['uiAbiVerified'])
             and (not row['managerReturned'] or row['rootAbiVerified']), 'UI_CALL_REJECTED')
    root_read = int(row['rootAbiVerified'])
    need(all(row[k] == root_read for k in
             ('rootIdReads', 'rootClassReads', 'rootManagerCalls', 'ownLookupCalls')),
         'ROOT_CALL_REJECTED')
    need(row['managerRootCalls'] == int(row['rootAbiVerified'] and row['managerAbiVerified']),
         'MANAGER_CALL_REJECTED')
    need(row['classIdReads'] == int(row['rootClassReturned'])
         and (not row['rootClassReturned'] or row['rootAbiVerified']), 'CLASS_CALL_REJECTED')
    need(row['ownIdReads'] == int(row['ownPresent'])
         and (not row['ownPresent'] or row['ownLookupCalls'] == 1), 'OWN_CALL_REJECTED')
    if row['rootAbiVerified']:
        _guid(row['rootId'], 'ROOT_ID_REJECTED')
    else:
        need(row['rootId'] is None, 'UNREAD_ROOT_REJECTED')
    if row['rootClassReturned']:
        _guid(row['rootClassId'], 'CLASS_ID_REJECTED')
        need(row['rootClassId'] != '00000000-0000-0000-0000-000000000000', 'CLASS_ID_REJECTED')
    else:
        need(row['rootClassId'] is None, 'UNREAD_CLASS_REJECTED')
    if row['ownPresent']:
        need(row['ownObjectId'] == OWN_ID and row['ownIdMatches'] is True, 'OWN_SCOPE_REJECTED')
    else:
        need(row['ownObjectId'] is None and row['ownIdMatches'] is False, 'OWN_NULL_REJECTED')
    need(not row['rootManagerInterfacePointerEqual'] or
         (row['rootManagerCalls'] == 1 and row['managerReturned']), 'ROOT_MANAGER_RELATION_REJECTED')
    need(not row['managerRootInterfacePointerEqual'] or row['managerRootCalls'] == 1,
         'MANAGER_ROOT_RELATION_REJECTED')
    need(not row['rootInterfacePointerEqualCurrent'] or row['rootReturned'], 'ROOT_EQUAL_REJECTED')
    need(not row['managerInterfacePointerEqualCurrent'] or row['managerReturned'], 'MANAGER_EQUAL_REJECTED')
    return all(row[k] is True for k in ('rootReturned', 'rootAbiVerified', 'rootClassReturned',
                                       'managerReturned', 'managerAbiVerified',
                                       'rootManagerInterfacePointerEqual', 'managerRootInterfacePointerEqual'))


def verify(info, version):
    """Accept exact typed observations only; all semantic/writer claims stay false.

    Missing Templates Main/IB or an unsupported known table is incomplete, not
    proof of DB role. Current Gold receiver/source/lifetime must be verified.
    """
    need(type(info) is dict and set(info) == set(KEYS), 'SHAPE_REJECTED')
    need(type(version) is int and 0 < version <= 0x7fffffff
         and type(info['version']) is int and info['version'] == version, 'VERSION_REJECTED')
    need(info['status'] == 'METADATA_RECEIVER_INVENTORY_OBSERVED_V126'
         and info['ownObjectId'] == OWN_ID, 'SCOPE_REJECTED')
    need(all(info[k] is True for k in SCOPE_FLAGS), 'LIFETIME_SOURCE_REJECTED')
    need(info['nativeException'] is False and info['returnUnknown'] is False, 'UNKNOWN_REJECTED')
    need(all(type(info[k]) is bool for k in OBSERVATION_FLAGS + RELATION_FLAGS), 'FLAG_TYPE_REJECTED')
    need(all(type(info[k]) is int and info[k] == 0 for k in ZERO_COUNTERS), 'WRITES_REJECTED')
    need(all(info[k] is False for k in FALSE_CLAIMS), 'CLAIM_REJECTED')
    need(all(type(info[k]) is int and 0 <= info[k] <= 1 for k in COUNTS), 'COUNT_TYPE_REJECTED')
    need(info['editServiceRequests'] == info['infoBaseServiceRequests'] == 1, 'SERVICE_CALL_REJECTED')
    need(not info['editServiceAbiVerified'] or info['editServiceReturned'], 'EDIT_ORDER_REJECTED')
    need(info['templatesUiCalls'] == int(info['editServiceAbiVerified'])
         and info['defaultInfoBaseCalls'] == int(info['infoBaseServiceReturned'])
         and info['infoBaseManagerCalls'] == int(info['infoBaseAbiVerified']), 'GETTER_CALL_REJECTED')
    need(not info['infoBaseReturned'] or info['defaultInfoBaseCalls'] == 1,
         'BASE_ORDER_REJECTED')
    need(not info['infoBaseAbiVerified'] or info['infoBaseReturned'], 'BASE_ABI_REJECTED')
    rows = info['receivers']
    need(type(rows) is list and len(rows) == 3, 'ROWS_REJECTED')
    complete = [_row(row, origin) for row, origin in zip(rows, ORIGINS)]
    current, template, base = rows
    need(complete[0] and current['uiReturned'] is True and current['uiAbiVerified'] is True
         and current['rootId'] == GOLD_ROOT_ID and current['rootInterfacePointerEqualCurrent'] is True
         and current['managerInterfacePointerEqualCurrent'] is True, 'CURRENT_RECEIVER_REJECTED')
    need(not template['uiReturned'] or info['templatesUiCalls'] == 1, 'TEMPLATE_RETURN_REJECTED')
    need(not base['managerReturned'] or info['infoBaseManagerCalls'] == 1, 'BASE_MANAGER_REJECTED')
    need(info['infoBaseRootCalls'] == int(info['infoBaseAbiVerified'] and base['managerAbiVerified'])
         and (not base['rootReturned'] or info['infoBaseRootCalls'] == 1), 'BASE_ROOT_REJECTED')
    for row in rows[1:]:
        if row['rootInterfacePointerEqualCurrent'] and row['rootIdReads'] == 1:
            need(row['rootAbiVerified'] is True and row['rootId'] == current['rootId']
                 and row['rootClassId'] == current['rootClassId']
                 and row['ownPresent'] is current['ownPresent'], 'ROOT_EQUAL_ID_REJECTED')
        if row['rootInterfacePointerEqualCurrent']:
            need(row['rootAbiVerified'] is True, 'ROOT_EQUAL_ABI_REJECTED')
        if row['managerInterfacePointerEqualCurrent']:
            need(row['managerAbiVerified'] is True, 'MANAGER_EQUAL_ABI_REJECTED')
        if row['managerInterfacePointerEqualCurrent'] and row['managerRootInterfacePointerEqual']:
            need(row['rootInterfacePointerEqualCurrent'] is True, 'MANAGER_EQUAL_ROOT_REJECTED')
    root_equal = info['templatesInfoBaseRootInterfacePointerEqual']
    manager_equal = info['templatesInfoBaseManagerInterfacePointerEqual']
    uuid_equal = template['rootIdReads'] == base['rootIdReads'] == 1 and template['rootId'] == base['rootId']
    need(info['templatesInfoBaseRootUuidEqual'] is uuid_equal, 'ROOT_UUID_RELATION_REJECTED')
    for relation, key, returned in ((root_equal, 'rootInterfacePointerEqualCurrent', 'rootReturned'),
                                    (manager_equal, 'managerInterfacePointerEqualCurrent', 'managerReturned')):
        need(not relation or (template[returned] and base[returned]), 'NULL_RELATION_REJECTED')
        if template[key] and base[key]:
            need(relation is True, 'TRANSITIVE_RELATION_REJECTED')
        elif template[key] != base[key]:
            need(relation is False, 'TRANSITIVE_RELATION_REJECTED')
    if root_equal and template['rootIdReads'] == base['rootIdReads'] == 1:
        need(uuid_equal and template['rootClassId'] == base['rootClassId']
             and template['ownPresent'] is base['ownPresent'], 'SAME_ROOT_UUID_REJECTED')
    if manager_equal and template['managerRootInterfacePointerEqual'] and base['managerRootInterfacePointerEqual']:
        need(root_equal, 'SAME_MANAGER_ROOT_REJECTED')
    verified = all(complete) and info['editServiceAbiVerified'] and info['infoBaseAbiVerified']
    return dict(verified=bool(verified), receiverInventoryObserved=True,
                receiverInventoryVerified=bool(verified), ownObjectId=OWN_ID,
                ownPresence={row['origin']: row['ownPresent'] for row in rows},
                templatesInfoBaseRootInterfacePointerEqual=root_equal,
                templatesInfoBaseManagerInterfacePointerEqual=manager_equal,
                templatesInfoBaseRootUuidEqual=uuid_equal,
                selectedSourcePreserved=True, canonicalIdentityVerified=False,
                semanticMainDbRoleVerified=False, metadataEqualityVerified=False,
                pendingOwnOnlyVerified=False, nativePermit=False, saveAuthorized=False,
                databaseUpdateAuthorized=False, observerAuthorized=False, captureAuthorized=False)
