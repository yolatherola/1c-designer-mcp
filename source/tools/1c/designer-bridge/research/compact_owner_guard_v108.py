"""Pure bounded verification of a same-callback wide/compact owner observation.

No files, processes, IB or repository are opened. Ownership is observational;
OWN never proves capture by this task and no observation grants writes/cancel.
"""
from __future__ import annotations
import json
import re
import struct
import uuid

RESULT_LIMIT = 8192
OBJECT = '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'
ROOT = '218b5d00-7e10-486f-874c-73c2368ed5da'
CLASS = '061d872a-5787-460e-95ac-ed74ea3a3e84'
ZERO = '00000000-0000-0000-0000-000000000000'
CANONICAL_KEYS = ('ui', 'root', 'object', 'manager', 'controller', 'provider')
FLAGS = ('bindingVerified', 'selectionVerified', 'ownerVerified', 'versionVerified', 'wideCompactParity')
ZERO_COUNTERS = ('configurationWrites', 'configurationSaves', 'repositoryMutations', 'databaseUpdates', 'businessCalls')
FALSE_CLAIMS = ('tcpEndpointVerified', 'atomicSnapshotVerified', 'lockGenerationVerified', 'staleRefreshVerified', 'writerAuthorized')
FAILURE_STAGES = tuple(range(1, 30)) + tuple(range(100, 107))
MANAGER_RELATION_FLAGS = ('uiAbiVerified', 'uiPageVerified', 'managerAbiVerified',
                          'managerPageVerified', 'managerEqualsCounted', 'cachedRootEqualsCounted')
KEYS = ('status', 'objectId', 'rootId', 'classId', 'version', 'nativeException', 'returnUnknown', 'bindingFailureStage',
        'uiAliasDiagnostic', 'metadataAliasDiagnostic',
        'canonical', 'connectionTable', 'actorId', 'revised', 'ownerId', 'ownership',
        'widePacketHex', 'compactPacketHex', 'wholePacketEqual', 'timingVerified',
        'wideElapsedUs', 'compactElapsedUs', 'wideCalls', 'compactStatisticCalls',
        'rawCanonicalQueries', 'adoptedCanonicalOutputs') + FLAGS + ZERO_COUNTERS + FALSE_CLAIMS


def need(ok, code):
    if not ok:
        raise ValueError('V108_' + code)


def _pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, 'JSON_REJECTED')
        out[key] = value
    return out


def _constant(_):
    raise ValueError('V108_JSON_REJECTED')


def parse_result(raw):
    """Strict bounded UTF-8, unique keys, no floats or non-finite constants."""
    need(type(raw) in (str, bytes), 'JSON_REJECTED')
    try:
        data = raw.encode('utf-8') if type(raw) is str else raw
        need(0 < len(data) <= RESULT_LIMIT, 'JSON_REJECTED')
        out = json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                         parse_float=_constant, parse_constant=_constant)
        need(type(out) is dict, 'JSON_REJECTED')
        return out
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('V108_JSON_REJECTED') from None


def _guid(value):
    need(type(value) is str, 'GUID_REJECTED')
    text = value[1:-1] if value.startswith('{') and value.endswith('}') else value
    need(re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', text) is not None, 'GUID_REJECTED')
    return str(uuid.UUID(text))


def _canonical(value):
    need(type(value) is dict and set(value) == set(CANONICAL_KEYS), 'CANONICAL_REJECTED')
    need(all(type(x) is int and 0 < x <= 0xffffffff for x in value.values())
         and len(set(value.values())) == len(CANONICAL_KEYS), 'CANONICAL_REJECTED')


def _code_address(value):
    if value is None:
        return
    need(type(value) is dict and set(value) == {'module', 'rva'}
         and type(value['module']) is str
         and re.fullmatch(r'[a-z0-9_.-]{1,64}\.(?:dll|exe)', value['module']) is not None
         and type(value['rva']) is int and 0 <= value['rva'] <= 0x7fffffff, 'DIAGNOSTIC_ADDRESS_REJECTED')


def _manager_relation(value):
    need(type(value) is dict and set(value) == {'held', 'current'}, 'MANAGER_DIAGNOSTIC_SHAPE_REJECTED')
    for snapshot in value.values():
        need(type(snapshot) is dict and set(snapshot) == set(MANAGER_RELATION_FLAGS)
             and all(type(snapshot[k]) is bool for k in MANAGER_RELATION_FLAGS), 'MANAGER_DIAGNOSTIC_BOOL_REJECTED')
        for observed, prerequisite in (('uiPageVerified', 'uiAbiVerified'),
                                      ('managerAbiVerified', 'uiPageVerified'),
                                      ('managerPageVerified', 'managerAbiVerified'),
                                      ('managerEqualsCounted', 'managerPageVerified'),
                                      ('cachedRootEqualsCounted', 'managerPageVerified')):
            need(not snapshot[observed] or snapshot[prerequisite], 'MANAGER_DIAGNOSTIC_ORDER_REJECTED')


def _alias_diagnostic(info, stage):
    ui, metadata = info['uiAliasDiagnostic'], info['metadataAliasDiagnostic']
    # Reaching stage11 proves only the currently-counted UI's model. The old
    # frame UI remains observational even when its manager/root differ.
    if stage == 0 or 10 <= stage <= 28:
        need(type(ui) is dict
             and set(ui) == {'heldPrimaryTable', 'heldInterfaceTable', 'primaryAbiVerified',
                             'interfaceAbiVerified', 'plus4EqualsCurrent', 'managerRelation'}, 'DIAGNOSTIC_SHAPE_REJECTED')
        _manager_relation(ui['managerRelation'])
        for key in ('heldPrimaryTable', 'heldInterfaceTable'):
            _code_address(ui[key])
        need(all(type(ui[k]) is bool for k in ('primaryAbiVerified', 'interfaceAbiVerified', 'plus4EqualsCurrent')),
             'DIAGNOSTIC_BOOL_REJECTED')
        if ui['primaryAbiVerified']:
            need(ui['heldPrimaryTable'] == {'module': 'frntend.dll', 'rva': 0xc0e588}, 'DIAGNOSTIC_ABI_REJECTED')
        if ui['interfaceAbiVerified']:
            need(ui['heldInterfaceTable'] == {'module': 'frntend.dll', 'rva': 0xc0e458}, 'DIAGNOSTIC_ABI_REJECTED')
        if ui['managerRelation']['held']['uiAbiVerified']:
            need(ui['heldPrimaryTable'] == {'module': 'frntend.dll', 'rva': 0xc0e458}
                 and ui['primaryAbiVerified'] is False, 'MANAGER_DIAGNOSTIC_ABI_REJECTED')
        current_matches = all(ui['managerRelation']['current'][key] for key in MANAGER_RELATION_FLAGS)
        need(current_matches == (stage != 10), 'CURRENT_MODEL_BINDING_REJECTED')
    else:
        need(ui is None, 'DIAGNOSTIC_STAGE_REJECTED')
    if stage == 11:
        need(type(metadata) is dict and set(metadata) == {'heldTable', 'equalsManager', 'equalsRoot', 'providerMatch'},
             'DIAGNOSTIC_SHAPE_REJECTED')
        _code_address(metadata['heldTable'])
        need(type(metadata['equalsManager']) is bool and type(metadata['equalsRoot']) is bool
              and metadata['providerMatch'] is False, 'DIAGNOSTIC_BOOL_REJECTED')
    else:
        need(metadata is None, 'DIAGNOSTIC_STAGE_REJECTED')


def _packet(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, 'PACKET_REJECTED')
    raw = bytes.fromhex(value)
    version = struct.unpack_from('<i', raw)[0]
    need(version >= 0 and raw[4] in (0, 1), 'PACKET_REJECTED')
    owner = str(uuid.UUID(bytes_le=raw[8:24]))
    revised = raw[4] == 1
    need(revised == (owner != ZERO), 'PACKET_REJECTED')
    return raw, version, revised, owner


def verify(info, version):
    """Return verified ownership/parity or an honest known unsupported binding.

    Fresh UI/PIDbirth/lease/source-preservation/protected close and configured
    TCP transport remain caller obligations. Native UNKNOWN/exception is fatal.
    Padding bytes5..7 may differ; all29 meaningful record bytes must match.
    """
    need(type(version) is int and 0 <= version <= 0x7fffffff, 'VERSION_REJECTED')
    need(type(info) is dict and set(info) == set(KEYS), 'SHAPE_REJECTED')
    need(info['objectId'] == OBJECT and info['rootId'] == ROOT and info['classId'] == CLASS, 'SCOPE_REJECTED')
    need(info['nativeException'] is False and info['returnUnknown'] is False, 'UNKNOWN_REJECTED')
    stage = info['bindingFailureStage']
    need(type(stage) is int and stage in (0,) + FAILURE_STAGES, 'BINDING_STAGE_REJECTED')
    _alias_diagnostic(info, stage)
    for key in ZERO_COUNTERS:
        need(type(info[key]) is int and info[key] == 0, 'WRITES_REJECTED')
    need(all(info[key] is False for key in FALSE_CLAIMS), 'CLAIM_REJECTED')
    need(all(type(info[key]) is bool for key in FLAGS + ('revised', 'wholePacketEqual', 'timingVerified')), 'BOOL_REJECTED')
    need(type(info['wideCalls']) is int and info['wideCalls'] == 1
         and type(info['compactStatisticCalls']) is int and info['compactStatisticCalls'] in (0, 1), 'CALLS_REJECTED')
    need(type(info['rawCanonicalQueries']) is int and type(info['adoptedCanonicalOutputs']) is int
         and 0 <= info['adoptedCanonicalOutputs'] <= info['rawCanonicalQueries'] <= 6, 'QI_COUNT_REJECTED')
    need(type(info['version']) is int and info['version'] in (-1, version), 'VERSION_REJECTED')
    actor, owner = _guid(info['actorId']), _guid(info['ownerId'])
    for key in ('wideElapsedUs', 'compactElapsedUs'):
        need(type(info[key]) is int and -1 <= info[key] <= 300_000_000, 'TIMING_REJECTED')
    if info['timingVerified']:
        need(info['wideElapsedUs'] >= 0 and info['compactElapsedUs'] >= 0, 'TIMING_REJECTED')
    else:
        need(info['wideElapsedUs'] == info['compactElapsedUs'] == -1, 'TIMING_REJECTED')
    verified = info['status'] == 'COMPACT_OWNER_VERIFIED_V108'
    need(verified or info['status'] == 'COMPACT_OWNER_UNVERIFIED_V108', 'STATUS_REJECTED')
    if not verified:
        need(stage in FAILURE_STAGES, 'BINDING_STAGE_REJECTED')
        need(all(info[key] is False for key in FLAGS) and info['ownership'] == 'UNKNOWN'
             and info['timingVerified'] is False, 'REFUSAL_REJECTED')
        need(info['canonical'] is None and info['connectionTable'] is None
             and actor == ZERO and owner == ZERO
             and info['widePacketHex'] == info['compactPacketHex'] == '', 'REFUSAL_REJECTED')
        return dict(verified=False, compactOwnerVerified=False, bindingFailureStage=stage,
                    uiAliasDiagnostic=info['uiAliasDiagnostic'], metadataAliasDiagnostic=info['metadataAliasDiagnostic'],
                    state='UNKNOWN', writerAuthorized=False,
                    captureCreatedThisTask=False, staleRefreshVerified=False, lockGenerationVerified=False)
    need(stage == 0 and all(info[key] is True for key in FLAGS) and info['compactStatisticCalls'] == 1
         and info['rawCanonicalQueries'] == info['adoptedCanonicalOutputs'] == 6
         and info['version'] == version and actor != ZERO, 'VERIFIED_REJECTED')
    _canonical(info['canonical'])
    table = info['connectionTable']
    need(type(table) is dict and set(table) == {'module', 'rva'}
         and type(table['module']) is str and table['module'] in ('crcore.dll', 'rclient.dll', 'devtool.dll', 'core83.dll')
         and type(table['rva']) is int and 0 < table['rva'] <= 0x7fffffff, 'BINDING_REJECTED')
    wide, wv, wr, wo = _packet(info['widePacketHex'])
    compact, cv, cr, co = _packet(info['compactPacketHex'])
    need((wv, wr, wo) == (cv, cr, co) == (version, info['revised'], owner), 'PARITY_REJECTED')
    need(all(wide[i] == compact[i] for i in list(range(5)) + list(range(8, 32)))
         and info['wholePacketEqual'] == (wide == compact), 'PARITY_REJECTED')
    state = 'FREE' if not cr else ('OWN' if owner == actor else 'FOREIGN')
    need(info['ownership'] == state, 'OWNER_REJECTED')
    return dict(verified=True, compactOwnerVerified=True, bindingFailureStage=0, objectId=OBJECT, version=version,
                state=state, actorId=actor, ownerId=None if owner == ZERO else owner,
                sameCallbackParityVerified=True, wholePacketEqual=wide == compact,
                timingVerified=info['timingVerified'], wideElapsedUs=info['wideElapsedUs'],
                compactElapsedUs=info['compactElapsedUs'], configurationWrites=0, repositoryMutations=0,
                writerAuthorized=False, captureCreatedThisTask=False, tcpEndpointVerified=False,
                atomicSnapshotVerified=False, lockGenerationVerified=False, staleRefreshVerified=False)
