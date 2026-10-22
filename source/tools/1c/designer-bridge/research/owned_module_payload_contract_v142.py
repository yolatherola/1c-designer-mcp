"""Pure text contract; no native/Gold/editor authority. Import performs no I/O."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'tests/NativeOwnedModulePayloadV142.as'
LIMIT = 262144
FINAL_SOURCES = {
    'ObjectModule.bsl': '0320a444334420e1cecf3a0bc462add6365e014fd39b144a38889b04ce228aa7',
    'FormModule.bsl': 'd94bb5d3b83da6ec65c44d6919ea1c56c3a01d9b74e5293c3d318f94e1a85115',
}


def prepare(raw):
    """Reject malformed text, normalize line endings, count editor UTF-16 units."""
    if type(raw) is not bytes or not 0 < len(raw) <= LIMIT:
        raise ValueError('V142_PAYLOAD_BOUND')
    value = raw.decode('utf-8-sig', errors='strict')
    if not value or '\0' in value:
        raise ValueError('V142_PAYLOAD_EMPTY_OR_NUL')
    if '\r' in value.replace('\r\n', ''):
        raise ValueError('V142_BARE_CR')
    text = value.replace('\r\n', '\n').replace('\n', '\r\n')
    units = len(text.encode('utf-16-le')) // 2
    if not 0 < units <= LIMIT:
        raise ValueError('V142_NORMALIZED_BOUND')
    lines = text.split('\r\n')
    return dict(text=text, utf16Units=units, endLine=len(lines),
                endColumn=1 + len(lines[-1].encode('utf-16-le')) // 2,
                inputSha256=hashlib.sha256(raw).hexdigest(),
                normalizedUtf8Sha256=hashlib.sha256(text.encode('utf-8')).hexdigest(),
                nativeWriterAuthorized=False)


def literal(text):
    """Core.As quoted string; the BSL body remains data inside one literal."""
    return json.dumps(text, ensure_ascii=False)


def valid_fixtures(root):
    """Read only fixed code files and refuse any change from the accepted package."""
    fixtures = [('ascii', b'x'), ('russian', 'Строка'.encode()),
                ('lf', b'a\nb\n'), ('crlf', b'a\r\nb'), ('mixed', b'a\r\nb\nc'),
                ('supplementary', '😀\nя😀'.encode()), ('bom', b'\xef\xbb\xbfx'),
                ('maximum', b'x' * LIMIT)]
    for name, expected in FINAL_SOURCES.items():
        raw = (root / 'tools/data-anonymization/managed' / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('V142_ACCEPTED_SOURCE_CHANGED')
        fixtures.append((name, raw))
    return fixtures


INVALID_FIXTURES = (
    b'', b'\0', b'x\0y', b'\xef\xbb\xbf', b'\xc0\xaf', b'\xe0\x80\x80',
    b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'\xf5\x80\x80\x80',
    b'\xe2\x82', b'\x80', b'\xe2A\xa0', b'a\r', b'a\rb',
)


def verify_output(raw, exit_code, count):
    if type(raw) is not bytes or len(raw) > 16384 or type(exit_code) is not int or exit_code != 0:
        raise ValueError('V142_OUTPUT_OR_EXIT')
    expected = [f'V142_PAYLOAD|{i}|true'.encode('ascii') for i in range(count)]
    if raw.splitlines() != expected:
        raise ValueError('V142_PAYLOAD_OBSERVATION_REJECTED')
    return dict(verified=True, checks=count, utf8RoundtripVerified=True,
                nativeModuleWriteVerified=False, nativeWriterAuthorized=False)
