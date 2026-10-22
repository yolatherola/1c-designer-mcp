"""Pure post-capture comparison; never captures, cancels, or executes BSL.

The outer client owns the route lease and verifies kernel PID/birth/session.
Native state owns one new FREE->OWN capture. A comparison failure issues no
cancel capability: that original host, lease, and capture remain for review.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import weakref

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from native_source_codec import decode_module_packet
from metadata_descriptor_codec_v47 import compare_document_profiles

OBJECT = '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'
ROOT = '218b5d00-7e10-486f-874c-73c2368ed5da'
CLASS = '061d872a-5787-460e-95ac-ed74ea3a3e84'
LIMIT = 1048576
MARKER_LIMIT = 1024
ZERO_COUNTERS = ('sourceSetterCalls', 'goldSaves', 'databaseUpdates', 'repositoryPlacement', 'businessCalls')
CLAIMS = ('externalChildDescriptionsVerified', 'externalChildBodiesVerified', 'staleRefreshVerified',
          'lockGenerationVerified', 'persistedGoldVerified')
FILE_ROLES = ('descriptor-live.bin', 'descriptor-repository.bin', 'object-false.bsl', 'object-true.bsl',
              'object-repository.bin', 'manager-false.bsl', 'manager-true.bsl', 'manager-repository.bin')
FILENAMES = tuple('capture-fresh-v81-' + role for role in FILE_ROLES)
INTENT_FILENAME = 'capture-fresh-v81-capture-dispatched'
PREPARE_PHASES = ('captureObserved', 'sourceObserved')
TERMINAL_PHASES = ('cancelDispatched', 'cancelObserved')
HEX32 = re.compile('[0-9a-f]{32}')
BIRTH = re.compile('[0-9a-f]{16}')
GUID = re.compile('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')


def need(ok, code):
    if not ok:
        raise ValueError('V81_' + code)


def _integer(value, lo, hi):
    return type(value) is int and lo <= value <= hi


def _unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, 'DUPLICATE_KEY')
        out[key] = value
    return out


def parse_result(body):
    need(type(body) is bytes and 0 < len(body) <= 16384, 'RESULT_SIZE')
    try:
        info = json.loads(body.decode('utf-8'), object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('V81_JSON_CONSTANT')))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('V81_RESULT_ENCODING') from error
    need(type(info) is dict, 'RESULT_SCHEMA')
    return info


def marker_filename(phase):
    need(phase in PREPARE_PHASES + TERMINAL_PHASES, 'MARKER_PHASE')
    return 'capture-fresh-v81-' + phase + '.json'


def _read(reader, name, limit, minimum=1):
    need(callable(reader), 'READER_REQUIRED')
    try:
        body = reader(name)
    except (OSError, KeyError, ValueError) as error:
        raise ValueError('V81_FILE_UNAVAILABLE') from error
    need(type(body) is bytes and minimum <= len(body) <= limit, 'FILE_BOUND')
    return body


def _marker(reader, phase, info):
    body = _read(reader, marker_filename(phase), MARKER_LIMIT)
    value = parse_result(body)
    keys = {'phase', 'captureOperationId', 'sessionId'} | set(ZERO_COUNTERS)
    need(set(value) == keys and value['phase'] == phase, 'MARKER_SCHEMA')
    need(value['captureOperationId'] == info['captureOperationId'] and value['sessionId'] == info['sessionId'],
         'MARKER_IDENTITY')
    for key in ZERO_COUNTERS:
        need(type(value[key]) is int and value[key] == 0, 'MARKER_COUNTER')
    return {'phase': phase, 'sha256': hashlib.sha256(body).hexdigest()}


def _base(info, *, session_id, process_id, birth, operation_id):
    need(type(info) is dict, 'SCHEMA')
    need(type(session_id) is str and HEX32.fullmatch(session_id), 'EXPECTED_SESSION')
    need(_integer(process_id, 1, 0xffffffff), 'EXPECTED_PID')
    need(type(birth) is str and BIRTH.fullmatch(birth) and int(birth, 16) > 0, 'EXPECTED_BIRTH')
    need(type(operation_id) is str and HEX32.fullmatch(operation_id), 'EXPECTED_OPERATION')
    need(info.get('rootId') == ROOT and info.get('objectId') == OBJECT and info.get('classId') == CLASS, 'SCOPE')
    need(info.get('sessionId') == session_id and type(info.get('processId')) is int and info['processId'] == process_id
         and info.get('birth') == birth and info.get('captureOperationId') == operation_id, 'IDENTITY')
    need(type(info.get('version')) is int and 0 <= info['version'] <= 0x7fffffff, 'VERSION')
    actor = info.get('actorId')
    need(type(actor) is str and GUID.fullmatch(actor) and actor != '00000000-0000-0000-0000-000000000000', 'ACTOR')
    for key in ZERO_COUNTERS:
        need(type(info.get(key)) is int and info[key] == 0, 'COUNTER')
    for key in CLAIMS:
        need(info.get(key) is False, 'UNSUPPORTED_CLAIM')
    need(info.get('nativeException') is False and info.get('returnUnknown') is False, 'UNKNOWN')


class VerifiedCaptureFresh:
    """Opaque capability issued only after actual bounded files compare.

    The dictionary returned by summary() is evidence, never cancel authority.
    """
    __slots__ = ('__weakref__',)

    def __new__(cls, *args, **kwargs):
        raise TypeError('V81_CAPABILITY_NOT_CONSTRUCTIBLE')

    def summary(self):
        need(type(self) is VerifiedCaptureFresh and self in _issued, 'UNISSUED_CAPABILITY')
        return copy.deepcopy(_issued[self]['summary'])


_issued = weakref.WeakKeyDictionary()


def verify_prepared(info, read_file, *, session_id, process_id, birth, operation_id):
    """Read fresh native witnesses, compare complete descriptors/texts, issue capability.

    read_file must be a trusted contained/reparse-rejecting reader restricted to
    FILENAMES, INTENT_FILENAME and marker_filename(). This function also enforces bytes/bounds.
    Source newline differences fail closed; normalized equality is not enough.
    """
    _base(info, session_id=session_id, process_id=process_id, birth=birth, operation_id=operation_id)
    expected = {'status', 'rootId', 'objectId', 'classId', 'sessionId', 'processId', 'birth', 'captureOperationId',
                'actorId', 'version', 'ownershipBefore', 'ownershipAfter', 'captureDispatched', 'captureReturned',
                'ownWitnessVerified', 'bindingUnchanged', 'dirtyVerified', 'freshSourceObserved', 'selectorFirstDword',
                'packetScopeVerified', 'resultScopeVerified', 'allModulePropertiesEnumerated', 'fileBytes',
                'moduleRows', 'nativeException', 'returnUnknown', 'repositoryMutations'} | set(ZERO_COUNTERS) | set(CLAIMS)
    need(set(info) == expected, 'PREPARED_SCHEMA')
    need(info['status'] == 'CAPTURE_FRESH_PREPARED_V81' and info['ownershipBefore'] == 'FREE'
         and info['ownershipAfter'] == 'OWN', 'PREPARED_STATUS')
    for key in ('captureDispatched', 'captureReturned', 'ownWitnessVerified', 'bindingUnchanged', 'dirtyVerified',
                'freshSourceObserved', 'packetScopeVerified', 'resultScopeVerified', 'allModulePropertiesEnumerated'):
        need(info[key] is True, 'PREPARED_FLAG')
    need(type(info['selectorFirstDword']) is int and info['selectorFirstDword'] == -1, 'SELECTOR')
    need(type(info['repositoryMutations']) is int and info['repositoryMutations'] == 1, 'MUTATION_COUNT')
    intent = _read(read_file, INTENT_FILENAME, 32)
    need(intent == operation_id.encode('ascii'), 'CAPTURE_INTENT_IDENTITY')
    sizes = info['fileBytes']
    need(type(sizes) is dict and set(sizes) == set(FILENAMES), 'FILE_SCOPE')
    bodies = {}
    for name in FILENAMES:
        minimum = 0 if name.endswith('.bsl') else 1
        need(_integer(sizes[name], minimum, LIMIT), 'FILE_SIZE')
        body = _read(read_file, name, LIMIT, minimum)
        need(len(body) == sizes[name], 'FILE_LENGTH')
        bodies[name] = body
    descriptor = compare_document_profiles(bodies[FILENAMES[0]], bodies[FILENAMES[1]])
    need(descriptor['descriptorEqual'] is True, 'DESCRIPTOR_CHANGED')
    rows = info['moduleRows']
    need(type(rows) is list and len(rows) == 2, 'MODULE_COUNT')
    expected_properties = {'a637f77f-3840-441d-a1c3-699c8c5cb7e0': '0',
                           'd1b64a2c-8078-4982-8190-8f81aefda192': '2'}
    modules = []
    seen = set()
    for row in rows:
        need(type(row) is dict and set(row) == {'propertyId', 'resource', 'contextCount', 'liveFalseCharacters',
                                              'liveTrueCharacters', 'liveModesEqual'}, 'MODULE_ROW_SCHEMA')
        prop = row['propertyId']
        need(prop in expected_properties and prop not in seen, 'MODULE_PROPERTY')
        seen.add(prop)
        suffix = expected_properties[prop]
        need(row['resource'] == OBJECT + '.' + suffix and _integer(row['contextCount'], 1, 16)
             and row['liveModesEqual'] is True, 'MODULE_RESOURCE')
        offset = 2 if suffix == '0' else 5
        try:
            a, b = (bodies[FILENAMES[offset + k]].decode('utf-8') for k in (0, 1))
        except UnicodeError as error:
            raise ValueError('V81_MODULE_ENCODING') from error
        need(a == b and type(row['liveFalseCharacters']) is int and type(row['liveTrueCharacters']) is int
             and len(a.encode('utf-16-le')) // 2 == row['liveFalseCharacters'] == row['liveTrueCharacters'],
             'MODULE_CONTEXT')
        comparison = decode_module_packet(bodies[FILENAMES[offset + 2]]).summary(a)
        # The platform's editor emits LF while the stock packet may use CRLF.
        # Only the established BOM/newline codec normalization is permitted.
        need(comparison['normalizedLineEndingsEqual'] is True
             and comparison['normalization'] == 'bom-decoding-and-newlines-only', 'MODULE_TEXT_CHANGED')
        modules.append({'propertyId': prop, 'resource': row['resource'], **comparison})
    markers = [_marker(read_file, phase, info) for phase in PREPARE_PHASES]
    summary = {'currentContentVerified': True, 'documentDescriptorProfileVerified': True,
               'documentModuleTextsComplete': True, 'descriptor': descriptor, 'modules': modules,
               'physicalMarkers': markers, 'fileSha256': {name: hashlib.sha256(body).hexdigest()
                                                         for name, body in bodies.items()},
               'captureIntentSha256': hashlib.sha256(intent).hexdigest(),
               **{key: False for key in CLAIMS}}
    capability = object.__new__(VerifiedCaptureFresh)
    _issued[capability] = {'info': copy.deepcopy(info), 'summary': summary}
    return capability


def make_prepare_permit(token, operation_id, session_id, process_id, birth):
    """Format trusted outer-client permission; grants neither capture nor verification."""
    need(type(token) is str and HEX32.fullmatch(token) and type(operation_id) is str
         and HEX32.fullmatch(operation_id) and type(session_id) is str and HEX32.fullmatch(session_id)
         and _integer(process_id, 1, 0xffffffff) and type(birth) is str and BIRTH.fullmatch(birth)
         and int(birth, 16) > 0, 'PREPARE_PERMIT_IDENTITY')
    return f'{token} {operation_id} {session_id} {process_id} {birth}'.encode('ascii')


def make_cancel_permit(verified, token, cancel_operation_id):
    """Only a capability from actual complete comparison can authorize own cancel."""
    need(type(verified) is VerifiedCaptureFresh and verified in _issued, 'UNISSUED_CAPABILITY')
    issued = _issued[verified]
    info = issued['info']
    need(type(token) is str and HEX32.fullmatch(token) and type(cancel_operation_id) is str
         and HEX32.fullmatch(cancel_operation_id) and cancel_operation_id != info['captureOperationId'], 'CANCEL_PERMIT')
    # An idempotent formatting repeat is harmless; changing the operation/token
    # cannot repurpose a completed comparison into a second native cancellation.
    pair = (token, cancel_operation_id)
    need(issued.get('cancelPermit', pair) == pair, 'CANCEL_PERMIT_ALREADY_BOUND')
    issued['cancelPermit'] = pair
    return (f'{token} {info["captureOperationId"]} {cancel_operation_id} {info["sessionId"]} '
            f'{info["processId"]} {info["birth"]} {info["version"]}').encode('ascii')


def verify_terminal(info, verified, read_file, *, cancel_operation_id):
    """Require a known own cancel, fresh FREE, preserved source and physical receipt."""
    need(type(verified) is VerifiedCaptureFresh and verified in _issued, 'UNISSUED_CAPABILITY')
    issued = _issued[verified]
    need(issued.get('cancelPermit', (None, None))[1] == cancel_operation_id, 'CANCEL_PERMIT_NOT_ISSUED')
    before = issued['info']
    _base(info, session_id=before['sessionId'], process_id=before['processId'], birth=before['birth'],
          operation_id=before['captureOperationId'])
    expected = {'status', 'rootId', 'objectId', 'classId', 'sessionId', 'processId', 'birth', 'captureOperationId',
                'cancelOperationId', 'actorId', 'version', 'cancelDispatched', 'cancelReturned', 'freeVerified',
                'bindingUnchanged', 'sourcePreserved', 'dirtyVerified', 'nativeException', 'returnUnknown',
                'repositoryMutations'} | set(ZERO_COUNTERS) | set(CLAIMS)
    need(set(info) == expected, 'TERMINAL_SCHEMA')
    need(info['status'] == 'CAPTURE_FRESH_VERIFIED_V81' and info['cancelOperationId'] == cancel_operation_id
         and type(cancel_operation_id) is str and HEX32.fullmatch(cancel_operation_id)
         and cancel_operation_id != before['captureOperationId'], 'TERMINAL_STATUS')
    need(info['actorId'] == before['actorId'] and info['version'] == before['version'], 'TERMINAL_STATE')
    need(type(info['repositoryMutations']) is int and info['repositoryMutations'] == 2, 'TERMINAL_MUTATION_COUNT')
    for key in ('cancelDispatched', 'cancelReturned', 'freeVerified', 'bindingUnchanged', 'sourcePreserved', 'dirtyVerified'):
        need(info[key] is True, 'TERMINAL_FLAG')
    markers = [_marker(read_file, phase, info) for phase in TERMINAL_PHASES]
    return {'captureFreshVerified': True, 'ownCaptureCancelled': True, 'physicalMarkers': markers,
            'currentContentVerified': True, **{key: False for key in CLAIMS}}
