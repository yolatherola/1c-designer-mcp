"""Pure validation of fresh STATUS lock ownership; grants no writer permit.

The caller supplies a STATUS from its sealed native session and its expected
object UUID. This checks evidence consistency; it performs no repository RPC,
capture/cancel, source refresh, generation/CAS check or configuration operation.
"""
import json
import math
import re

RESULT_LIMIT = 32768
ZERO_UUID = '00000000-0000-0000-0000-000000000000'
OWNERSHIP_KEYS = ('objectId', 'state', 'verified', 'actorId', 'ownerId',
                  'readOnly', 'captureCreatedThisTask')
STATES = ('FREE', 'OWN', 'FOREIGN', 'UNKNOWN')
SCOPE_FLAGS = ('scopeAlive', 'selectionVerified', 'repositoryBoundVerified',
               'ownerVerified', 'generationVerified')
RECORD_FLAGS = ('queried', 'bounded', 'ownerVerified', 'generationVerified')
RECORD_KEYS = RECORD_FLAGS + ('versionNumber', 'revised', 'revisorId')
_UUID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', re.ASCII)


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _uuid(value, allow_zero=False):
    _need(type(value) is str, 'OWNERSHIP_UUID_REJECTED')
    if value.startswith('{') and value.endswith('}'):
        value = value[1:-1]
    _need(_UUID.fullmatch(value) is not None, 'OWNERSHIP_UUID_REJECTED')
    value = value.lower()
    _need(allow_zero or value != ZERO_UUID, 'OWNERSHIP_UUID_REJECTED')
    return value


def _pairs(items):
    result = {}
    for key, value in items:
        _need(key not in result, 'OWNERSHIP_JSON_REJECTED')
        result[key] = value
    return result


def _constant(_value):
    raise ValueError('OWNERSHIP_JSON_REJECTED')


def _finite_float(value):
    result = float(value)
    _need(math.isfinite(result), 'OWNERSHIP_JSON_REJECTED')
    return result


def parse_result(raw):
    """Parse bounded UTF-8 STATUS with unique keys and finite JSON constants.

    No file is opened and no raw JSON/error payload is returned on rejection.
    """
    _need(type(raw) in (bytes, str), 'OWNERSHIP_JSON_REJECTED')
    try:
        data = raw.encode('utf-8') if type(raw) is str else raw
        _need(0 < len(data) <= RESULT_LIMIT, 'OWNERSHIP_JSON_REJECTED')
        result = json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                            parse_constant=_constant, parse_float=_finite_float)
        _need(type(result) is dict, 'OWNERSHIP_JSON_REJECTED')
        return result
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('OWNERSHIP_JSON_REJECTED') from None


def _record(value):
    """Validate available scalars, then report whether a full record is known."""
    if value is None:
        return False, None, None
    _need(type(value) is dict, 'OWNERSHIP_RECORD_REJECTED')
    for key in RECORD_FLAGS + ('lockGenerationVerified',):
        if key in value:
            _need(type(value[key]) is bool, 'OWNERSHIP_RECORD_REJECTED')
    # The existing generationVerified checks decoded version fields only.
    # This route has no independently verified lock generation or CAS token.
    _need(value.get('lockGenerationVerified', False) is False,
          'OWNERSHIP_GENERATION_CLAIM_REJECTED')
    if 'versionNumber' in value:
        _need(type(value['versionNumber']) is int
              and 0 <= value['versionNumber'] <= 0x7fffffff,
              'OWNERSHIP_RECORD_REJECTED')
    if 'revised' in value:
        _need(type(value['revised']) is bool, 'OWNERSHIP_RECORD_REJECTED')
    owner = _uuid(value['revisorId'], allow_zero=True) if 'revisorId' in value else None
    if not all(key in value for key in RECORD_KEYS):
        return False, None, None
    consistent = value['revised'] == (owner != ZERO_UUID)
    fresh = all(value[key] is True for key in RECORD_FLAGS) and consistent
    return fresh, value['revised'], None if owner == ZERO_UUID else owner


def verify(status, expected_object):
    """Return the seven normalized ownership fields after strict consistency checks.

    UNKNOWN is a safe unverified observation with no actor/owner disclosure.
    Verified states additionally require the current bound/selected scope and
    queried/bounded repository record. OWN is not evidence of capture by this
    task and cannot authorize cancellation, writes or source replacement.
    """
    expected = _uuid(expected_object)
    _need(type(status) is dict and all(key in status for key in SCOPE_FLAGS)
          and 'repositoryStatus' in status and 'ownership' in status,
          'OWNERSHIP_STATUS_REJECTED')
    _need(all(type(status[key]) is bool for key in SCOPE_FLAGS),
          'OWNERSHIP_STATUS_REJECTED')
    record_fresh, revised, record_owner = _record(status['repositoryStatus'])
    ownership = status['ownership']
    _need(type(ownership) is dict and set(ownership) == set(OWNERSHIP_KEYS),
          'OWNERSHIP_SHAPE_REJECTED')
    object_id = _uuid(ownership['objectId'])
    _need(object_id == expected, 'OWNERSHIP_OBJECT_REJECTED')
    state = ownership['state']
    _need(type(state) is str and state in STATES and type(ownership['verified']) is bool,
          'OWNERSHIP_STATE_REJECTED')
    _need(ownership['readOnly'] is True and ownership['captureCreatedThisTask'] is False,
          'OWNERSHIP_PERMISSION_CLAIM_REJECTED')
    actor = ownership['actorId']
    owner = ownership['ownerId']
    if state == 'UNKNOWN':
        _need(ownership['verified'] is False and actor is None and owner is None,
              'OWNERSHIP_UNKNOWN_REJECTED')
    else:
        _need(ownership['verified'] is True and record_fresh
              and all(status[key] is True for key in SCOPE_FLAGS),
              'OWNERSHIP_FRESH_RECORD_REJECTED')
        actor = _uuid(actor)
        owner = _uuid(owner) if owner is not None else None
        _need(owner == record_owner, 'OWNERSHIP_OWNER_REJECTED')
        _need((state == 'FREE' and revised is False and owner is None)
              or (state == 'OWN' and revised is True and owner == actor)
              or (state == 'FOREIGN' and revised is True and owner is not None and owner != actor),
              'OWNERSHIP_RELATION_REJECTED')
    return dict(objectId=object_id, state=state, verified=ownership['verified'],
                actorId=actor, ownerId=owner, readOnly=True, captureCreatedThisTask=False)
