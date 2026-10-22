"""Own managed layout codec and exact 8.3.18.1208 static prerequisites.

Only own factory templates may enter build_resource. This module never loads a
DLL, connects to 1C, reads a configuration, or prints module/resource contents.
The caller must prove the origin and same-class native roundtrip separately.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
import struct
import sys
import uuid

TESTS = Path(__file__).resolve().parents[1] / 'tests'
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))
from module_resource_codec import Atom, form_tree

LIMIT = 1048576
ATTR = 'f1c20ebb-b32c-4f23-b126-e920edbee526'
COMMAND = '8a40c9cb-b801-40dd-a5a1-48ce1f60fd1c'
BUTTON = 'a9f3b1ac-f51b-431e-b102-55a69acdecad'
GROUP = 'cd5394d0-7dda-4b56-8927-93ccbe967a01'
ATTRIBUTE_NAME = 'AgentTextV80'
COMMAND_NAME = 'AgentActionV80'
BUTTON_NAME = 'AgentButtonV80'
COMMAND_ID = 1002
BUTTON_ID = 1003
GROUP_ID = 1001
GROUP_NAME = '\u0413\u0440\u0443\u043f\u043f\u0430\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0438V80'
MODULE = ('&AtClient\nProcedure AgentActionV80(Command)\n'
          '    AgentTextV80 = "V80";\nEndProcedure\n')
MODULE_SHA = hashlib.sha256(MODULE.encode()).hexdigest()
PRIMARY_SOURCE = 'https://snegopat.ru/scripts/file?ci=ef09c54fba6e53d4&name=FuncProcPanel.js'

# No handwritten font/picture/localization schema: those fields stay native.
RECORDS = (
    (ATTR, 0x6782bc, 4, 0x67830c,
     (0x3a6055, 0xacaf8, 0x3a604b, 0x3a4bb0, 0x3a4bc0, 0x3a4c20), 0x6783ac),
    (COMMAND, 0x666ab0, 4, 0x666a98,
     (0x2e0e15, 0xacaf8, 0x2e0e3d, 0x2dd4b0, 0x2dd4c0, 0x2dd7a0), 0x666c00),
    (BUTTON, 0x665ecc, 12, 0x665ea4,
     (0x2d8689, 0x170405, 0x2d866b, 0x2d6db0, 0x2d6dc0, 0x2d71d0), 0x66612c),
)
SERIALIZERS = (
    (0x3a4bc0, 86, 'dbe6b127b36683f28119213dc2be302788bae7e88e8edaee6537623efcbb93bd'),
    (0x2dd4c0, 736, 'd3a072898f0d3af7130c84ab52e6e249d681d287bcf99a8556752cf9bf6766d8'),
    (0x2d6dc0, 1010, '2e437277eb4a39999e59786b469610a9127360f5bbd83085e0d193a27c416b77'),
)


def verify_static():
    """Hash-check installed PE bytes and whole serializers, without DLL loading."""
    from repository_pe_probe import PE
    pe = PE('mngcore.dll')
    for cls, primary, offset, table, slots, literal in RECORDS:
        at = pe.offset(pe.base + table)
        actual = tuple(v - pe.base for v in struct.unpack_from('<6I', pe.data, at))
        if actual != slots:
            raise ValueError('V80_RECORD_TABLE_REJECTED')
        at = pe.offset(pe.base + literal)
        if str(uuid.UUID(bytes_le=pe.data[at:at + 16])) != cls:
            raise ValueError('V80_RECORD_CLASS_REJECTED')
        # The primary address must itself map to the pinned image.
        pe.offset(pe.base + primary)
    for rva, size, expected in SERIALIZERS:
        at = pe.offset(pe.base + rva)
        body = pe.data[at:at + size]
        if hashlib.sha256(body).hexdigest() != expected or body[-3:] != b'\xc2\x08\x00':
            raise ValueError('V80_SERIALIZER_REJECTED')
    return {'version': '8.3.18.1208', 'staticVerified': True,
            'recordClasses': [r[0] for r in RECORDS],
            'nativeRoundtripVerified': False, 'managedFormVerified': False}


def _atom(value, text):
    return type(value) is Atom and value == text


def _composite(value, number):
    return type(value) is list and len(value) == 1 and _atom(value[0], str(number))


def _record(data, kind):
    if type(data) is not bytes or not 0 < len(data) <= LIMIT:
        raise ValueError('V80_RECORD_SIZE')
    value = form_tree(data)
    if kind == 'attribute':
        ok = len(value) == 4 and _atom(value[0], '0') and type(value[1]) is str
    elif kind == 'command':
        ok = len(value) >= 18 and _atom(value[0], '9') and type(value[2]) is str and type(value[8]) is str
    elif kind == 'button':
        ok = len(value) >= 10 and _atom(value[0], '31') and value[3] in (Atom('0'), Atom('1'))
        if ok:
            shift = 1 if _atom(value[3], '1') else 0
            ok = type(value[5 + shift]) is str and type(value[8 + shift]) is list
    else:
        raise ValueError('V80_RECORD_KIND')
    if not ok:
        raise ValueError('V80_RECORD_SCHEMA')
    return value


def _encode(value):
    if type(value) is list:
        return '{' + ','.join(_encode(v) for v in value) + '}'
    if type(value) is Atom:
        if not value or any(c in value for c in '{}",\x00'):
            raise ValueError('V80_ATOM')
        return str(value)
    if type(value) is str:
        return '"' + value.replace('"', '""') + '"'
    raise ValueError('V80_FIELD_TYPE')


def _body(data, count):
    value = form_tree(data)
    if (len(value) != 10 or not _atom(value[0], '4') or type(value[2]) is not str
            or type(value[1]) is not list or len(value[1]) != 48 + count * 2
            or not _atom(value[1][0], '49') or not _atom(value[1][23], str(count))):
        raise ValueError('V80_BODY_SCHEMA')
    if not _atom(value[1][24], GROUP) and not _atom(value[1][24], GROUP.upper()):
        raise ValueError('V80_GROUP_CLASS')
    group = value[1][25]
    if (type(group) is not list or len(group) != 29 or not _atom(group[0], '22')
            or not _atom(group[2], str(GROUP_ID)) or group[6] != GROUP_NAME):
        raise ValueError('V80_GROUP_SCOPE')
    return value


def build_resource(body, attribute, command, button):
    """Modify only reviewed own fields; return UTF8 body bytes, never config XML."""
    root = _body(body, 1)
    for index in (4, 5, 6, 7):
        if root[index] != [Atom('0'), Atom('0')]:
            raise ValueError('V80_COLLECTION_NONEMPTY')
    if root[2].replace('\r\n', '\n') != MODULE:
        raise ValueError('V80_MODULE_SCOPE')
    a, c, b = (_record(attribute, 'attribute'), _record(command, 'command'), _record(button, 'button'))
    a = deepcopy(a); c = deepcopy(c); b = deepcopy(b)
    a[1] = ATTRIBUTE_NAME
    a[2] = ['Pattern', ['S']]
    c[1] = [Atom(str(COMMAND_ID))]
    c[2] = COMMAND_NAME
    c[8] = COMMAND_NAME
    shift = 1 if _atom(b[3], '1') else 0
    b[1] = [Atom(str(BUTTON_ID))]
    b[5 + shift] = BUTTON_NAME
    b[8 + shift] = [Atom(str(COMMAND_ID))]
    root[4] = [Atom('0'), Atom('1'), a]
    root[5] = [Atom('0'), Atom('1'), c]
    layout = root[1]
    layout[23] = Atom('2')
    layout[26:26] = [Atom(BUTTON), b]
    result = b'\xef\xbb\xbf' + _encode(root).encode('utf-8')
    if len(result) > LIMIT:
        raise ValueError('V80_BODY_SIZE')
    inspect_resource(result)
    return result


def inspect_resource(data):
    """Independently verify native saved attr/command/button linkage and handler."""
    root = _body(data, 2)
    if root[2].replace('\r\n', '\n') != MODULE:
        raise ValueError('V80_MODULE_READBACK')
    for index in (6, 7):
        if root[index] != [Atom('0'), Atom('0')]:
            raise ValueError('V80_FOREIGN_COLLECTION')
    for index in (4, 5):
        col = root[index]
        if type(col) is not list or len(col) != 3 or not _atom(col[0], '0') or not _atom(col[1], '1'):
            raise ValueError('V80_COLLECTION_READBACK')
    a, c, b = root[4][2], root[5][2], root[1][27]
    if len(a) != 4 or not _atom(a[0], '0') or a[1] != ATTRIBUTE_NAME or a[2] != ['Pattern', ['S']]:
        raise ValueError('V80_ATTRIBUTE_READBACK')
    if (len(c) < 18 or not _atom(c[0], '9') or not _composite(c[1], COMMAND_ID)
            or c[2] != COMMAND_NAME or c[8] != COMMAND_NAME):
        raise ValueError('V80_COMMAND_READBACK')
    if not _atom(root[1][26], BUTTON) and not _atom(root[1][26], BUTTON.upper()):
        raise ValueError('V80_BUTTON_CLASS')
    if len(b) < 10 or not _atom(b[0], '31') or b[3] not in (Atom('0'), Atom('1')):
        raise ValueError('V80_BUTTON_SCHEMA')
    shift = 1 if _atom(b[3], '1') else 0
    if not _composite(b[1], BUTTON_ID) or b[5 + shift] != BUTTON_NAME or not _composite(b[8 + shift], COMMAND_ID):
        raise ValueError('V80_BUTTON_LINK')
    return {'attributeName': ATTRIBUTE_NAME, 'attributeType': 'String',
            'commandId': COMMAND_ID, 'commandName': COMMAND_NAME, 'action': COMMAND_NAME,
            'buttonId': BUTTON_ID, 'buttonName': BUTTON_NAME, 'buttonCommandId': COMMAND_ID,
            'groupId': GROUP_ID, 'groupName': GROUP_NAME, 'groupCount': 1,
            'buttonCount': 1, 'moduleSha256': MODULE_SHA, 'moduleCharacterCount': len(MODULE)}


def preserved_fields(before, after, attribute, command, button):
    """Reject modifications to default fields outside the reviewed replacement set."""
    if form_tree(build_resource(before, attribute, command, button)) != form_tree(after):
        raise ValueError('V80_UNREVIEWED_RESOURCE_CHANGE')
    return True
