"""Pure physical CF checks for the fixed future own managed-form fixture.

No configuration is loaded, files extracted, source executed or native code
called. Content markers establish physical presence only; fresh native body,
module/group readback and managed-kind verification remain separate requirements.
"""
import base64
import copy
import hashlib
from pathlib import Path
import re
import sys
import uuid

_TESTS = Path(__file__).resolve().parents[1] / 'tests'
if str(_TESTS) not in sys.path:
    sys.path.insert(0, str(_TESTS))
from owned_cf_codec import read_entries
from saved_pilot_codec import parse

PROCESSING = 'f0e50730-e59b-4c8a-a189-0e62365aa372'
FORM = '4e68b5c9-17f4-4e20-a63b-804392cd97a2'
PROCESSING_CLASS = 'bf845118-327b-4682-b5c6-285d2a0eb296'
PROCESSING_NAME = 'АгентУправляемаяФормаV73'
FORM_NAME = 'ФормаV73'
GROUP_NAME = 'ГруппаПроверкиV73'
MODULE_FIXTURE_SHA256 = 'b8f4ce623dbccf3c952583208bedc580f913934e6f63f1f45376c0d3daf4d0db'
MODULE_SENTINEL = 'c7bce69f'
GOLD_ROOT = '218b5d00-7e10-486f-874c-73c2368ed5da'
GOLD_CONTROL_FORM = '0ed914fb-2a1a-4b58-9fad-eaa103b47c9e'
GOLD_DOCUMENT = '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'
FORBIDDEN = frozenset((GOLD_ROOT, GOLD_CONTROL_FORM, GOLD_DOCUMENT))
OWN_STREAMS = frozenset((PROCESSING, FORM, FORM + '.0'))
SERVICE_STREAMS = frozenset(('root', 'version', 'versions'))
GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
VERSION_LIMIT = 4096


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _root(root_id):
    _need(type(root_id) is str and GUID.fullmatch(root_id) is not None
          and root_id not in FORBIDDEN | {PROCESSING, FORM}
          and uuid.UUID(root_id).int != 0, 'V73_ROOT_REJECTED')
    return root_id


def _known_gold_absent(packet):
    lower = packet.lower()
    for identity in FORBIDDEN:
        _need(identity.encode('ascii') not in lower
              and identity.encode('utf-16-le') not in lower
              and identity.encode('utf-16-be') not in lower
              and uuid.UUID(identity).bytes_le not in packet
              and uuid.UUID(identity).bytes not in packet, 'V73_GOLD_REFERENCE_REJECTED')


def _tree(packet):
    try:
        result = parse(packet.decode('utf-8-sig'))
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('V73_DESCRIPTOR_FORMAT_REJECTED') from None

    def visit(node):
        if type(node) is list:
            for child in node:
                visit(child)
        elif type(node) is str and node.startswith('#base64:'):
            try:
                decoded = base64.b64decode(''.join(node[8:].split()), validate=True)
            except (ValueError, UnicodeError):
                raise ValueError('V73_DESCRIPTOR_FORMAT_REJECTED') from None
            _known_gold_absent(decoded)
    visit(result)
    return result


def _leaves(node):
    if type(node) is list:
        for child in node:
            yield from _leaves(child)
    else:
        yield node


def _root_removal(before, after, root):
    source, result = _tree(before), _tree(after)
    _need(len(source) >= 2 and source[0] == 2 and type(source[1]) is list
          and source[1] and source[1][0] == root, 'V73_ROOT_DESCRIPTOR_REJECTED')
    expected = copy.deepcopy(source)
    groups = []

    def visit(node):
        if type(node) is not list:
            return
        if node and node[0] == PROCESSING_CLASS:
            groups.append(node)
        for child in node:
            visit(child)
    visit(expected)
    _need(len(groups) == 1 and groups[0] == [PROCESSING_CLASS, 1, PROCESSING],
          'V73_ROOT_OWN_GROUP_REJECTED')
    groups[0][:] = [PROCESSING_CLASS, 0]
    _need(result == expected, 'V73_ROOT_OTHER_CHANGE_REJECTED')


def _versions(packet, names):
    _need(0 < len(packet) <= VERSION_LIMIT, 'V73_VERSION_FORMAT_REJECTED')
    value = _tree(packet)
    size = len(names) + 1
    _need(len(value) == 2 + size * 2 and value[:2] == [1, size],
          'V73_VERSION_FORMAT_REJECTED')
    rows = list(zip(value[2::2], value[3::2]))
    keys = [name for name, _ in rows]
    cookies = [cookie for _, cookie in rows]
    _need(all(type(name) is str for name in keys) and len(set(keys)) == size
          and set(keys) == set(names) | {''}, 'V73_VERSION_KEYS_REJECTED')
    _need(all(type(cookie) is str and GUID.fullmatch(cookie) is not None
              and uuid.UUID(cookie).int != 0 for cookie in cookies)
          and len(set(cookies)) == size, 'V73_VERSION_COOKIE_REJECTED')
    return rows


def _version_removal(before, after, created_names, deleted_names, root):
    source = _versions(before, created_names)
    result = _versions(after, deleted_names)
    expected = [(name, cookie) for name, cookie in source if name not in OWN_STREAMS]
    _need([name for name, _ in result] == [name for name, _ in expected],
          'V73_VERSION_ORDER_REJECTED')
    old = dict(source)
    old_cookies = set(old.values())
    allowed = {root, '', 'root', 'version', 'versions'}
    changed = []
    for name, cookie in result:
        if cookie != old[name]:
            _need(name in allowed, 'V73_VERSION_OTHER_CHANGE_REJECTED')
            _need(cookie not in old_cookies, 'V73_VERSION_FRESHNESS_REJECTED')
            changed.append(name)
    return changed


def verify_owned_pair(createdCF, deletedCF, root_id):
    """Verify fixed own streams, exact root removal and scoped version cookies.

    Both inputs are bounded bytes. The auxiliary UUID is derived from the exact
    own CF shared set, then its key/content/cookie must survive byte-identically.
    The caller must separately bind CF provenance, measure native fresh readback
    and verify Gold preservation. This function grants no loading/deletion ability.
    """
    root = _root(root_id)
    _need(type(createdCF) is bytes and type(deletedCF) is bytes, 'V73_INPUT_REJECTED')
    try:
        created, deleted = read_entries(createdCF), read_entries(deletedCF)
    except (ValueError, TypeError, RecursionError):
        raise ValueError('V73_CF_ENVELOPE_REJECTED') from None
    shared = SERVICE_STREAMS | {root}
    auxiliary = set(created) - shared - OWN_STREAMS
    _need(len(auxiliary) == 1, 'V73_GRAPH_SCOPE_REJECTED')
    aux = next(iter(auxiliary))
    _need(GUID.fullmatch(aux) is not None and aux not in FORBIDDEN | {PROCESSING, FORM, root}
          and uuid.UUID(aux).int != 0, 'V73_GRAPH_SCOPE_REJECTED')
    shared = shared | {aux}
    _need(set(created) == shared | OWN_STREAMS and len(created) == 8
          and set(deleted) == shared and len(deleted) == 5
          and not FORBIDDEN.intersection(created) and not FORBIDDEN.intersection(deleted),
          'V73_GRAPH_SCOPE_REJECTED')
    for packet in (*created.values(), *deleted.values()):
        _known_gold_absent(packet)
    _need(root.encode('ascii') in created['root'] and root.encode('ascii') in deleted['root'],
          'V73_ROOT_INDEX_REJECTED')
    for name in shared - {root, 'versions'}:
        _need(created[name] == deleted[name], 'V73_SHARED_CONTENT_CHANGED')
    processing, form, body = (_tree(created[name]) for name in (PROCESSING, FORM, FORM + '.0'))
    _need(list(_leaves(processing)).count(PROCESSING_NAME) == 1
          and list(_leaves(form)).count(FORM_NAME) == 1
          and GROUP_NAME in _leaves(body)
          and any(type(value) is str and MODULE_SENTINEL in value for value in _leaves(body)),
          'V73_OWN_CONTENT_MARKERS_REJECTED')
    _root_removal(created[root], deleted[root], root)
    changed_cookies = _version_removal(created['versions'], deleted['versions'],
                                       set(created), set(deleted), root)
    return dict(verified=True, beforeEntryCount=8, afterEntryCount=5,
                ownProcessingFormBodyPhysicallyRemoved=True, rootIndexPreserved=True,
                rootDescriptorOwnRemovalVerified=True, sharedStreamSetPreserved=True,
                sharedImmutableContentPreserved=True, ownNameGroupModuleMarkersPresent=True,
                auxiliaryStreamName=aux, auxiliarySha256=hashlib.sha256(created[aux]).hexdigest(),
                versionCookieChangedNames=changed_cookies, removedStreamNames=sorted(OWN_STREAMS),
                rootId=root, beforeSha256=hashlib.sha256(createdCF).hexdigest(),
                afterSha256=hashlib.sha256(deletedCF).hexdigest(),
                beforeBytes=len(createdCF), afterBytes=len(deletedCF),
                expectedFixtureSha256=MODULE_FIXTURE_SHA256, moduleFixtureVerified=False,
                nativeReadbackRequired=True,
                nativeReadbackVerified=False, runtimeBodyVerified=False,
                managedKindVerified=False, managedFormVerified=False,
                independentBackingVerified=False, persistedGoldVerified=False)
