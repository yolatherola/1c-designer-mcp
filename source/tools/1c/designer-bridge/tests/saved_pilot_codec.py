"""Bounded independent verification of this pilot's persisted native files.

Reads only supplied packets; emits digests/counts, never source or connections.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import sys
import zlib

PROCESSING = '8d64f197-c9b8-4332-90da-18f192cf1a57'
FORM = 'dadd405a-e2dc-435c-b3cd-d1b50ef0f301'
ROOT = '218b5d00-7e10-486f-874c-73c2368ed5da'
PROCESSING_KIND = 'bf845118-327b-4682-b5c6-285d2a0eb296'
FORM_KIND = 'd5b0e5ed-256d-401c-9c36-f630cafd8a62'
UUID = re.compile('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
MAX_PACKET = 1024*1024
MAX_TEXT = 4*1024*1024


def decode_packet(packet: bytes):
    if not 0 < len(packet) <= MAX_PACKET:
        raise ValueError('SAVED_PACKET_SIZE_REJECTED')
    inflater = zlib.decompressobj(-15)
    try:
        data = inflater.decompress(packet, MAX_TEXT+1)
    except zlib.error as error:
        raise ValueError('SAVED_PACKET_DEFLATE_REJECTED') from error
    if (len(data) > MAX_TEXT or inflater.unconsumed_tail or not inflater.eof or inflater.unused_data):
        raise ValueError('SAVED_PACKET_BOUNDS_REJECTED')
    try:
        text = data.decode('utf-8-sig', errors='strict')
    except UnicodeError as error:
        raise ValueError('SAVED_PACKET_ENCODING_REJECTED') from error
    return parse(text)


def parse(text: str):
    """Parse counted metadata arrays and doubled quoted strings, without eval."""
    if len(text) > MAX_TEXT:
        raise ValueError('SAVED_TEXT_BOUNDS_REJECTED')
    cursor = 0
    nodes = 0

    def space():
        nonlocal cursor
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1

    def value(depth=0):
        nonlocal cursor, nodes
        nodes += 1
        if depth > 64 or nodes > 100000:
            raise ValueError('SAVED_PARSE_BOUNDS_REJECTED')
        space()
        if cursor >= len(text):
            raise ValueError('SAVED_PARSE_TRUNCATED')
        if text[cursor] == '{':
            cursor += 1
            result = []
            space()
            if cursor < len(text) and text[cursor] == '}':
                raise ValueError('SAVED_PARSE_EMPTY_ARRAY_REJECTED')
            while True:
                result.append(value(depth+1))
                space()
                if cursor >= len(text):
                    raise ValueError('SAVED_PARSE_TRUNCATED')
                mark = text[cursor]
                cursor += 1
                if mark == '}':
                    return result
                if mark != ',':
                    raise ValueError('SAVED_PARSE_SEPARATOR_REJECTED')
        if text[cursor] == '"':
            cursor += 1
            result = []
            while cursor < len(text):
                character = text[cursor]
                cursor += 1
                if character == '"':
                    if cursor < len(text) and text[cursor] == '"':
                        cursor += 1
                        result.append('"')
                    else:
                        return ''.join(result)
                else:
                    result.append(character)
            raise ValueError('SAVED_PARSE_STRING_TRUNCATED')
        begin = cursor
        while cursor < len(text) and text[cursor] not in ',}':
            cursor += 1
        token = text[begin:cursor].strip()
        if not token or '"' in token or '{' in token:
            raise ValueError('SAVED_PARSE_TOKEN_REJECTED')
        if re.fullmatch('-?[0-9]{1,16}', token):
            return int(token)
        if (UUID.fullmatch(token) or re.fullmatch(r'-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?', token)
                or re.fullmatch(r'#base64:[A-Za-z0-9+/=\s]+', token)):
            return token
        raise ValueError('SAVED_PARSE_SCALAR_REJECTED')

    result = value()
    space()
    if cursor != len(text) or not isinstance(result, list):
        raise ValueError('SAVED_PARSE_TRAILING_REJECTED')
    return result


def groups(value):
    result = {}

    def visit(node):
        if not isinstance(node, list):
            return
        if (len(node) >= 2 and isinstance(node[0], str) and UUID.fullmatch(node[0])
                and type(node[1]) is int and node[1] >= 0
                and len(node) == node[1]+2 and all(isinstance(x, str) and UUID.fullmatch(x) for x in node[2:])):
            if node[0] in result or len(set(node[2:])) != node[1]:
                raise ValueError('SAVED_CLASS_GROUP_DUPLICATE')
            result[node[0]] = sorted(node[2:])
        for child in node:
            visit(child)

    visit(value)
    return result


def normalize(text):
    # The native managed serializer doubles CR when encoding the editor's
    # CRLF. This normalization was observed in the saved pilot, not assumed
    # to apply to arbitrary documents or other module file formats.
    return text.replace('\r\r\n', '\n').replace('\r\n', '\n').replace('\r', '\n').rstrip('\n')


def verify_created(packets: dict[str, bytes], fixture: str):
    if set(packets) != {PROCESSING, FORM, FORM+'.0', ROOT}:
        raise ValueError('SAVED_PILOT_FILE_SCOPE_REJECTED')
    decoded = {key: decode_packet(packet) for key, packet in packets.items()}
    processing, form, body, root = (decoded[x] for x in (PROCESSING, FORM, FORM+'.0', ROOT))
    try:
        info = processing[1][3][1]
        if (processing[0] != 1 or info[0] != 3 or info[1] != [1, 0, PROCESSING]
                or info[2] != 'АгентПробаИнструментов_c7bce69f'
                or groups(processing).get(FORM_KIND) != [FORM]):
            raise ValueError('SAVED_PROCESSING_DESCRIPTOR_REJECTED')
        properties = form[1][1][1]
        info = properties[1]
        if (form[0] != 1 or properties[0] != 13 or info[0] != 3 or info[1] != [1, 0, FORM]
                or info[2] != 'ФормаПроверкиИзменена' or properties[3] != 1):
            raise ValueError('SAVED_MANAGED_FORM_DESCRIPTOR_REJECTED')
        if (body[0] != 4 or not isinstance(body[1], list) or body[1][0] != 49
                or not isinstance(body[2], str) or normalize(body[2]) != normalize(fixture)):
            raise ValueError('SAVED_MANAGED_BODY_MODULE_REJECTED')
        if root[0] != 2 or root[1][0] != ROOT:
            raise ValueError('SAVED_ROOT_IDENTITY_REJECTED')
        root_groups = groups(root)
        if PROCESSING not in root_groups.get(PROCESSING_KIND, []):
            raise ValueError('SAVED_ROOT_PILOT_REFERENCE_REJECTED')
    except (IndexError, TypeError) as error:
        raise ValueError('SAVED_PILOT_SHAPE_REJECTED') from error
    module = normalize(body[2]).encode('utf-8')
    return {'verified': True, 'phase': 'created', 'processingVerified': True,
            'managedFormVerified': True, 'savedModuleMatchesFixture': True,
            'moduleCharacters': len(normalize(body[2])), 'moduleSha256': hashlib.sha256(module).hexdigest(),
            'rootGroups': root_groups,
            'files': {key: {'bytes': len(packet), 'sha256': hashlib.sha256(packet).hexdigest()} for key, packet in packets.items()}}


def verify_deleted(packet: bytes, created: dict):
    if created.get('verified') is not True or created.get('phase') != 'created':
        raise ValueError('SAVED_PRIOR_CREATION_PROOF_REJECTED')
    root = decode_packet(packet)
    if root[0] != 2 or root[1][0] != ROOT:
        raise ValueError('SAVED_ROOT_IDENTITY_REJECTED')
    current = groups(root)
    expected = {key: list(value) for key, value in created['rootGroups'].items()}
    own = expected.get(PROCESSING_KIND, [])
    if own.count(PROCESSING) != 1:
        raise ValueError('SAVED_PRIOR_ROOT_SCOPE_REJECTED')
    own.remove(PROCESSING)
    if current != expected:
        raise ValueError('SAVED_DELETE_FOREIGN_ROOT_CHANGE_REJECTED')
    return {'verified': True, 'phase': 'deleted', 'ownProcessingAbsent': True,
            'allOtherRootGroupsPreserved': True, 'rootGroupCount': len(current),
            'rootSha256': hashlib.sha256(packet).hexdigest(), 'rootBytes': len(packet)}


def main():
    phase, directory = sys.argv[1], Path(sys.argv[2])
    if phase == 'created':
        packets = {key: (directory/(key+'.bin')).read_bytes() for key in (PROCESSING, FORM, FORM+'.0', ROOT)}
        fixture = Path(__file__).with_name('fixtures')/'OwnedManagedForm/Module.bsl'
        proof = verify_created(packets, fixture.read_text(encoding='utf-8-sig'))
    elif phase == 'deleted':
        created = json.loads(Path(sys.argv[3]).read_text(encoding='utf-8-sig'))
        proof = verify_deleted((directory/(ROOT+'.bin')).read_bytes(), created)
    else:
        raise ValueError('SAVED_PHASE_REJECTED')
    path = directory/'independent-saved-proof.json'
    with path.open('x', encoding='utf-8') as stream:
        json.dump(proof, stream, ensure_ascii=False, separators=(',', ':'))
    print(json.dumps({key: value for key, value in proof.items() if key not in ('rootGroups',)} | {'proofFile': str(path)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
