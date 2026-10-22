"""Fixed two-module edit packet. Bodies/checkpoints remain caller-owned RAM only.

This module performs no I/O and grants no native/editor/repository authority.
The native writer must independently verify live ownership, source and rollback.
"""
from dataclasses import dataclass
import hashlib
import struct

VERSION = 237
MAGIC = b'AH1CR237'
ROOT_ID = '218b5d00-7e10-486f-874c-73c2368ed5da'
TEMPLATE_ID = '8daef957-4ae2-48a1-bf6c-b88163a076f5'
MODULE_IDS = ('176e2552-fd8b-4823-afc0-d17431f2fb7b', '28ecdfc7-083e-4082-b272-efbf7152de5c')
PROPERTY_ID = 'd5963243-262e-4398-b4d7-fb16d06484f6'
MAX_MODULE_BYTES = 1024 * 1024
MAX_PACKET_BYTES = 4 * 1024 * 1024
HEADER = struct.Struct('<8sI32s16s16sI')
RECORD_HEADER = struct.Struct('<16s16sII32s32s')


def _need(ok, code):
    if not ok:
        raise ValueError('V237_' + code)


def _hex(value, length):
    return type(value) is str and len(value) == length and all(char in '0123456789abcdef' for char in value)


def _guid_le(value):
    # Called only with the fixed canonical metadata IDs above.
    raw = bytes.fromhex(value.replace('-', ''))
    return raw[:4][::-1] + raw[4:6][::-1] + raw[6:8][::-1] + raw[8:]


ROOT_LE = _guid_le(ROOT_ID)
TEMPLATE_LE = _guid_le(TEMPLATE_ID)
MODULES_LE = tuple(_guid_le(value) for value in MODULE_IDS)
PROPERTY_LE = _guid_le(PROPERTY_ID)


def _body(value):
    _need(type(value) is bytes, 'BODY_TYPE')
    _need(len(value) <= MAX_MODULE_BYTES, 'BODY_BOUND')
    _need(b'\0' not in value, 'BODY_NUL')
    valid = False
    try:
        valid = value.decode('utf-8', errors='strict').encode('utf-8', errors='strict') == value
    except UnicodeError:
        pass
    # Raise outside the decoder exception handler: the error has no raw-body
    # UnicodeDecodeError context for a caller to accidentally log.
    _need(valid, 'BODY_UTF8')
    return value


@dataclass(frozen=True, slots=True, repr=False)
class ModuleEdit:
    """Original and replacement UTF8 bytes, including exact BOM/newline bytes."""
    module_id: str
    property_id: str
    original: bytes
    replacement: bytes

    def __post_init__(self):
        _need(type(self.module_id) is str and self.module_id in MODULE_IDS, 'MODULE_ID')
        _need(type(self.property_id) is str and self.property_id == PROPERTY_ID, 'PROPERTY_ID')
        _body(self.original)
        _body(self.replacement)
        _need(self.original != self.replacement, 'GENUINE_EDIT')

    def __repr__(self):
        return ('ModuleEdit(original_bytes=' + str(len(self.original))
                + ', replacement_bytes=' + str(len(self.replacement)) + ', bodies=<redacted>)')


@dataclass(frozen=True, slots=True, repr=False)
class EditPacket:
    """Fixed target scope plus two ordered immutable edits and RAM checkpoints."""
    operation_id: str
    modules: tuple
    root_id: str = ROOT_ID
    template_id: str = TEMPLATE_ID

    def __post_init__(self):
        _need(type(self.modules) in (tuple, list), 'MODULE_CONTAINER')
        object.__setattr__(self, 'modules', tuple(self.modules))
        _validate_packet(self)

    @property
    def original_checkpoint(self):
        """Return original bytes in fixed module order; this performs no undo."""
        return tuple(edit.original for edit in self.modules)

    def __repr__(self):
        return 'EditPacket(modules=' + str(len(self.modules)) + ', operation=<redacted>, bodies=<redacted>)'


def _validate_packet(packet):
    _need(type(packet) is EditPacket, 'PACKET_TYPE')
    _need(_hex(packet.operation_id, 32), 'OPERATION')
    _need(type(packet.root_id) is str and packet.root_id == ROOT_ID, 'ROOT_ID')
    _need(type(packet.template_id) is str and packet.template_id == TEMPLATE_ID, 'TEMPLATE_ID')
    _need(type(packet.modules) is tuple and len(packet.modules) == 2, 'MODULE_COUNT')
    length = HEADER.size + 2 * RECORD_HEADER.size
    for index, edit in enumerate(packet.modules):
        _need(type(edit) is ModuleEdit and type(edit.module_id) is str and edit.module_id == MODULE_IDS[index], 'MODULE_ORDER')
        _need(type(edit.property_id) is str and edit.property_id == PROPERTY_ID, 'PROPERTY_ID')
        _body(edit.original)
        _body(edit.replacement)
        _need(edit.original != edit.replacement, 'GENUINE_EDIT')
        length += len(edit.original) + len(edit.replacement)
    _need(length <= MAX_PACKET_BYTES, 'PACKET_BOUND')
    return length


def encode_packet(packet):
    """Return a validated binary packet in RAM; no persistence or execution."""
    length = _validate_packet(packet)
    parts = [HEADER.pack(MAGIC, VERSION, packet.operation_id.encode('ascii'), ROOT_LE, TEMPLATE_LE, 2)]
    for index, edit in enumerate(packet.modules):
        parts.append(RECORD_HEADER.pack(MODULES_LE[index], PROPERTY_LE, len(edit.original), len(edit.replacement),
                                        hashlib.sha256(edit.original).digest(), hashlib.sha256(edit.replacement).digest()))
        parts.extend((edit.original, edit.replacement))
    raw = b''.join(parts)
    _need(len(raw) == length, 'ENCODE_LENGTH')
    return raw


def decode_packet(raw, *, expected_sha256, expected_operation_id):
    """Decode only the expected complete packet; return original checkpoints too.

    Both expected values must come from the caller's separately held intent.
    The hash is a consistency check, not authentication or writer permission.
    """
    _need(_hex(expected_sha256, 64), 'EXPECTED_SHA256')
    _need(_hex(expected_operation_id, 32), 'EXPECTED_OPERATION')
    _need(type(raw) is bytes, 'PACKET_BYTES')
    _need(HEADER.size + 2 * RECORD_HEADER.size <= len(raw) <= MAX_PACKET_BYTES, 'PACKET_BOUND')
    _need(hashlib.sha256(raw).hexdigest() == expected_sha256, 'PACKET_SHA256')
    magic, version, operation, root, template, count = HEADER.unpack_from(raw)
    _need(magic == MAGIC and version == VERSION, 'HEADER')
    _need(operation == expected_operation_id.encode('ascii'), 'OPERATION_MISMATCH')
    _need(root == ROOT_LE and template == TEMPLATE_LE, 'TARGET_SCOPE')
    _need(count == 2, 'MODULE_COUNT')
    offset = HEADER.size
    edits = []
    for index in range(2):
        _need(offset + RECORD_HEADER.size <= len(raw), 'TRUNCATED_RECORD')
        module, prop, original_length, replacement_length, original_hash, replacement_hash = RECORD_HEADER.unpack_from(raw, offset)
        offset += RECORD_HEADER.size
        _need(module == MODULES_LE[index], 'MODULE_ORDER')
        _need(prop == PROPERTY_LE, 'PROPERTY_ID')
        _need(original_length <= MAX_MODULE_BYTES and replacement_length <= MAX_MODULE_BYTES, 'BODY_BOUND')
        _need(offset + original_length + replacement_length <= len(raw), 'TRUNCATED_BODY')
        original = raw[offset:offset + original_length]
        offset += original_length
        replacement = raw[offset:offset + replacement_length]
        offset += replacement_length
        _need(hashlib.sha256(original).digest() == original_hash
              and hashlib.sha256(replacement).digest() == replacement_hash, 'BODY_SHA256')
        edits.append(ModuleEdit(MODULE_IDS[index], PROPERTY_ID, original, replacement))
    _need(offset == len(raw), 'TRAILING_BYTES')
    packet = EditPacket(expected_operation_id, tuple(edits))
    _need(encode_packet(packet) == raw, 'NONCANONICAL_PACKET')
    return packet


@dataclass(frozen=True, slots=True)
class PacketProof:
    """Hashes/counts only; contains no operation, IDs, source text or body bytes."""
    packet_sha256: str
    byte_length: int
    module_count: int
    original_lengths: tuple
    replacement_lengths: tuple
    original_sha256: tuple
    replacement_sha256: tuple

    def __post_init__(self):
        _need(_hex(self.packet_sha256, 64), 'PROOF_HASH')
        _need(type(self.module_count) is int and self.module_count == 2, 'PROOF_COUNT')
        for lengths in (self.original_lengths, self.replacement_lengths):
            _need(type(lengths) is tuple and len(lengths) == 2
                  and all(type(value) is int and 0 <= value <= MAX_MODULE_BYTES for value in lengths), 'PROOF_LENGTHS')
        for hashes in (self.original_sha256, self.replacement_sha256):
            _need(type(hashes) is tuple and len(hashes) == 2 and all(_hex(value, 64) for value in hashes), 'PROOF_HASHES')
        length = HEADER.size + 2 * RECORD_HEADER.size + sum(self.original_lengths) + sum(self.replacement_lengths)
        _need(type(self.byte_length) is int and self.byte_length == length <= MAX_PACKET_BYTES, 'PROOF_PACKET_LENGTH')

    def as_dict(self):
        return {'packetSha256': self.packet_sha256, 'byteLength': self.byte_length, 'moduleCount': self.module_count,
                'originalLengths': self.original_lengths, 'replacementLengths': self.replacement_lengths,
                'originalSha256': self.original_sha256, 'replacementSha256': self.replacement_sha256}


def packet_proof(packet):
    """Return hash/count metadata for a validated RAM packet, without body repr."""
    raw = encode_packet(packet)
    return PacketProof(hashlib.sha256(raw).hexdigest(), len(raw), 2,
                       tuple(len(edit.original) for edit in packet.modules),
                       tuple(len(edit.replacement) for edit in packet.modules),
                       tuple(hashlib.sha256(edit.original).hexdigest() for edit in packet.modules),
                       tuple(hashlib.sha256(edit.replacement).hexdigest() for edit in packet.modules))
