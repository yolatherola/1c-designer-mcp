"""Fixed V73 body/file contracts, verified by reads only; never load a DLL.

The published document ABI and actual body subobject are proved separately from
the binary-derived helper/store/CF slots. Static success grants no native call.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
CACHE = HERE.parents[3] / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40'
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from repository_pe_probe import PE

ARCHIVE_SHA = '464256ea84009d66f2d177ce92cb128479ba634da6a493a93aef579410710fde'
MODULES = {
    'mngcore.dll': (0x36c20000, 'dc5cb334612edad964a712dbcfbb2c206160125c5b2b7d0f63bd42341194b477'),
    'basicui.dll': (0x24770000, 'e19126902ca7b0ee839c3492224f91a28d11000d3f1a74116443a21d2fab2ea8'),
    'backend.dll': (0x1f400000, '498664a61cee45d979bd4d8eacfddf20e7510780df52daaeacd5314bce22e739'),
    'basic.dll': (0x228b0000, '1d6c1020b517bf19fef2626ace1bc0c2402f38d8993c192da05e2b67404863a2'),
}
SDK_SHAS = {
    'modules/snegopat/v8api/document.v': 'b1c12ef6a2d4ea9d655bd9057c7a605b2497bb6c22ddb9f6323efc3ad21c369e',
    'modules/snegopat/v8api/metadata.v': 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed',
    'modules/snegopat/v8api/process.v': '92458b3e1a862051bf9b1d8b0cac750de5fddc62294324ca70a94820cdb1a9ef',
    'modules/snegopat/v8api/string.v': 'ccaccd6390ff0709921cb9e966a8cb2cab497c48a1fe8ff1bd65eecc078d76ad',
    'modules/snegopat/v8api/file.v': 'c41ffff5ba6d270e143bbd779dcdd8d9b03d9b624611b785266ad80f05f3218a',
}
BODY_CLASS = '5E44D99D-7D52-49BF-BC73-4DC0B575B8FB'
DOCUMENT_IID = '39D1961C-1881-4E3F-8453-16AD0A648B05'
PERSISTENCE_IID = '45B81B41-9540-11D4-9427-008048DA11F9'
EXTERNAL_IID = 'E80EA0D4-FE4C-446F-9567-9833A72DD396'
UNKNOWN_IID = '00000000-0000-0000-C000-000000000046'

# Includes all local return/exception-transfer paths of the named functions.
# extractWrapper ends in a guarded virtual tail jump, not a local RET.
RANGES = {
    'bodyPrimaryTable': ('mngcore.dll', 0x6654ac, 32, '2457d8ea5d03e00d7f2344d2b6ba8300c5ac31acb98266455bd2415f7f0eebe5'),
    'bodyDocumentTable': ('mngcore.dll', 0x665454, 20, '9cfb0a6ef44a37bc90e2c50f5111d347a0d4fe0e631e6b45b5ee10dc9a8a7897'),
    'bodyPersistenceTable': ('mngcore.dll', 0x66543c, 24, '961d1cd499f2dda5e54bbd4d6d00f7e9021001306514aaf93c733a25c3a8b648'),
    'bodyQIMap': ('mngcore.dll', 0x6656f8, 96, '33e78d044026ea8af26a007f71e7b55596565b88a99e7f81ba53bbda183d2e20'),
    'bodyClsid': ('mngcore.dll', 0x665678, 16, '27ef4b9509cd232e1251f1e58a9753897725de5d776d7d66bc68a68d635939e0'),
    'bodyQI': ('mngcore.dll', 0x2ccbf0, 26, 'cb9ee6dd5a9c3a039cf126fcf87327af95268d465d0188c3fe2e23846fda2bcc'),
    'bodyQIHelper': ('mngcore.dll', 0x8e9e0, 234, '97a0568cd952f0c443fe52096f4962424e7a235baf1f8f6788ed7728941f4d7f'),
    'bodyCtor': ('mngcore.dll', 0x2ccc40, 118, 'fbebf8a9f3b1243498dfa1fbeb2db759979d42db56900d0d178ad055bf159d7f'),
    'bodyFactory': ('mngcore.dll', 0x2ccd50, 132, '508c8713b037ef251658ec6f66b111808ef75f913678d53b593f17031ba032e9'),
    'bodyGetClsid': ('mngcore.dll', 0x2c89d0, 8, '1a28db2c7fc666a9d88c3f0d8bc775677f9f1f54147895daf47e5029200fae5f'),
    'bodyAddRef': ('mngcore.dll', 0xaf1b0, 19, 'c1adbb856513fe4bccbfccb18b27333ab1168b514a215d7f357142a2c231a9e0'),
    'bodyRelease': ('mngcore.dll', 0x2ccc10, 47, '6656d4d0f958f59b24a70e78022cb05196cf19c9fefacb7f17340dc4fbd50c7c'),
    'documentQI': ('mngcore.dll', 0x2ce455, 10, '0d68f441c3d9da2b8fe05c097dd094f659516ccf0f1315a044b3b8217a20a72c'),
    'documentAddRef': ('mngcore.dll', 0xafc51, 10, '1883b67692c7177c6a074236cef13ea8630c333ba2961298c41807632e91b43e'),
    'documentRelease': ('mngcore.dll', 0x2ce407, 10, 'd2f58de144628e6643c1497e4490e773ce0a2d2d49a33ef8cfa8b6f9382da53a'),
    'bodySave': ('mngcore.dll', 0x2c96d0, 273, '2ac47e7448327838beb195093e64a8aff4ec414751e81f56e13e3752423fbd6b'),
    'bodyLoad': ('mngcore.dll', 0x2c98c0, 292, '41088c00cdc9faf6ec7f479b72d8175d6fefbf454c10c2bad1a2b9fbea7d31f7'),
    'bodySaveAdapter': ('mngcore.dll', 0x2c97f0, 197, '27962ae641c498e46435476cdde08fceab70cf01c5b3f8ec8827b7b43d139753'),
    'bodyLoadAdapter': ('mngcore.dll', 0x2c99f0, 235, '05a8d59de3a90d416384021499bed83489d190b7009dd8ce8826cd2ac8edbd33'),
    'bodyModule': ('mngcore.dll', 0xa55a0, 13, '1fec6e043271c242f4731089f48beb307e373792092e391b3e708e49540bc204'),
    'bodyLayout': ('mngcore.dll', 0x9d0a0, 13, 'c6a8a8f832de4f35a6b3b6d48a027bfb8ffc90c8c677b769e70dfe0fc38a6098'),
    'helperTable': ('basicui.dll', 0x60b344, 76, 'd37b5af8b743e5319bb4153e1d7cd99ab0a6a0014b295ff348d31d0872a2c4a4'),
    'helperCreate': ('basicui.dll', 0x179f70, 41, '59e6126d171e5868ffdc0a9a726518ad0ba13b63ea378e99e27ad0d544f0bb7e'),
    'helperResolve': ('basicui.dll', 0x193a40, 363, '12318f7237f8d0f684fbfb09a8955a0da5f8da22fe09d44ab20c79826c6b5b1b'),
    'helperOutput': ('basicui.dll', 0x1c0460, 507, '2df0f1d84fca0fd051d887e2a29a571b90a583cec789ac643f0a4ca86a6c0db6'),
    'helperIUnknownIid': ('basicui.dll', 0x5e5f88, 16, 'c0b8112a8998b72d19d314c4b80a0734cdd386cb917d2627cd68cc17d6080b65'),
    'externalTable': ('backend.dll', 0xf18f50, 60, '8ff80029a4456518f8159964d842c42c42a93bf375b2fb886aee5a1e75da7080'),
    'externalStore': ('backend.dll', 0x618df0, 169, '948417f1308bf544bb5ab57314edb9c6a88ec3608260e094f32ff31378d31189'),
    'layoutPrimaryTable': ('mngcore.dll', 0x677d6c, 12, 'bb8fd350d23c6a5990df0fe3b5ea7f34cbeda3b3d3ff90ee10233658d407940f'),
    'layoutBaseTable': ('mngcore.dll', 0x677d1c, 36, '38f7b30b346ac183106d287b74ac37c430ed9b8b1918a966d4a6bafe57308c43'),
    'layoutRetain': ('mngcore.dll', 0x30b971, 10, '28d9c737661f167af757d629877af85e3b3639b041835610d9ce971088556ede'),
    'groupPrimaryTable': ('mngcore.dll', 0x6756d8, 112, 'd155791e868fbdf5f1fe95e13b5421036dc711a1fe6bcab5542ae0969b0885aa'),
    'groupRetain': ('mngcore.dll', 0x30b881, 10, '6dfd3dd40e4b004405f64da905f79600a481ef0e0495940f4e3ea2984855fcb4'),
    'borrowedAddRef': ('mngcore.dll', 0x8d070, 19, 'bc02528feddbe6ae8ecb1235c9853b9d963d7a65e999537834e606221ff5d708'),
    'groupClone': ('mngcore.dll', 0x38bc20, 869, 'cfee8d7e27ed850c2a3fd1bdb9adf7e19eb486a069144ed9f86fd79a6528eeb1'),
    'groupIdGet': ('mngcore.dll', 0x2eb7b0, 13, 'a15f452d50344cb534d44596ad2229dba1c01986afdef60298b472ae6af94c88'),
    'groupIdSet': ('mngcore.dll', 0x389940, 94, '12625411571ad7491f496965933ccfb744dd5a76b4b52364b0b0d4c66e96b152'),
    'layoutCount': ('mngcore.dll', 0x30a700, 19, 'b7ccccb0e73fdd9b2a9a42a12f768226b02770a0b200d692ff079d2d66718608'),
    'layoutAdd': ('mngcore.dll', 0x3a1570, 24, '69cf17a5a2f590102eb2a7de6753837d998abca9d5c1dd734fcd5470272946dd'),
    'managerTable': ('backend.dll', 0xede36c, 176, 'db2501b1dc3b786c06f40156c14b95af86ee2573e7c57d18a3cfbe0ebf9ab528'),
    'managerInnerTable': ('backend.dll', 0xe553cc, 176, '092b7231ca8eb377cc3569cfb2b2bb37c7f43b8b1c380db3de7827dad52273b0'),
    'preSave': ('backend.dll', 0x2af940, 1856, 'a5827abf1c5c68b0d1a2ad24b8c2b908fc0c7cf600f4f3300191948e247907ec'),
    'postSave': ('backend.dll', 0x2b0080, 693, 'c36f7289e9be669ffc79d548b4743f8b75938a38dcb6046a041f20298d768e8e'),
    'extractWrapper': ('backend.dll', 0x2b0380, 64, '2e7edf031193d12f925a4af78af3165af22a30eb84e059758ee9c4109a768563'),
    'extractInner': ('backend.dll', 0x3dc70, 3517, '60f404147107a73b45890916e385d1cdf050a8b33c7e1dea865a176df44ece36'),
    'processingMdTable': ('basic.dll', 0x8caf18, 112, 'c78b07654012115fbd7f120a1473a9c5a8e352db032d0009135a7e1672b7ae95'),
    'rootMdTable': ('backend.dll', 0xf15214, 120, 'a36e57717aea6b876d3426f39c4cc2f56f3b41cc2e4d4b6854e1bbdd382f43ac'),
    'deleteForm': ('basic.dll', 0x4eac00, 34, '17abe51d6a3c2bb67bfcaf2590c6c6c2dacdaaed9f9f04d34136a4512889a298'),
    'deleteProcessing': ('backend.dll', 0x5c6e20, 138, 'a714c4fe4cb593b913cf24fde60cf18da15fd0baac2a9813b8548f67e87ea103'),
}
TABLE_SLOTS = {
    'bodyPrimaryTable': {0: 0x2ccbf0, 1: 0xaf1b0, 2: 0x2ccc10, 4: 0x9d0a0, 6: 0xa55a0},
    'bodyDocumentTable': {0: 0x2ce455, 1: 0xafc51, 2: 0x2ce407, 3: 0x2c96d0, 4: 0x2c98c0},
    'bodyPersistenceTable': {3: 0x2c89d0, 4: 0x2c89e0, 5: 0x2c8fb0},
    'helperTable': {17: 0x179f70, 18: 0x179fa0},
    'externalTable': {7: 0x618df0},
    'layoutPrimaryTable': {1: 0x30b971},
    'layoutBaseTable': {4: 0x30a700, 6: 0x3a1570},
    'groupPrimaryTable': {1: 0x30b881, 19: 0x2eb7b0, 20: 0x389940, 27: 0x38bc20},
    'managerTable': {22: 0x2af940, 23: 0x2b0080, 43: 0x2b0380},
    'managerInnerTable': {43: 0x3dc70},
    'processingMdTable': {26: 0x4eac00},
    'rootMdTable': {26: 0x5c6e20},
}
REF_IMPORTS = {
    0x61c074: ('KERNEL32.dll', 'InterlockedIncrement'),
    0x61c078: ('KERNEL32.dll', 'InterlockedDecrement'),
}
QI_ROWS = (
    ('A2D59F32-5860-495E-AC7C-5346FC91975F', 0, 1), (DOCUMENT_IID, 4, 1),
    (PERSISTENCE_IID, 8, 1), ('BC619E47-0E6D-44D6-AC6C-B7B1495FE623', 12, 1),
    ('099EDA64-C2A5-11D4-9438-004095E12FC7', 20, 1),
    ('48C41E48-F8A0-4762-B6DC-3B64AF74700E', 24, 1),
    ('A6FC5DCB-73F3-4FA5-A94E-375F5C1DEF54', 28, 1), ('END', 0, 0),
)
ABI_PROFILE = {
    'platform': '8.3.18.1208', 'architecture': 'x86', 'documentIid': DOCUMENT_IID,
    'documentFromPrimary': 4, 'saveSlot': 3, 'loadSlot': 4,
    'documentConvention': 'stdcall', 'documentRetBytes': 8, 'documentFile': 'IFile@+',
    'documentResult': 'void', 'bodyClsid': BODY_CLASS, 'moduleOffset': 48,
    'moduleStringBytes': 24, 'moduleWrites': 'native-v8string-assignment',
    'bodyFactoryApi': 'SCOM_Process.createByClsid', 'factoryRequestedIid': UNKNOWN_IID,
    'privateBodyFactoryAllowed': False, 'outputCanaryRequired': True,
    'helperCreateSlot': 17, 'helperCreatePublished': False, 'helperRetBytes': 16,
    'helperReturn': 'output-address', 'helperOutputOwnership': 'counted-QI-or-transfer',
    'externalIid': EXTERNAL_IID, 'storeSlot': 7, 'storeRetBytes': 8,
    'layoutBorrowed': True, 'borrowedAddRefBeforeAdoption': True,
    'layoutBaseFromPrimary': -40, 'groupNameOffset': 80, 'groupCloneSlot': 27,
    'groupCloneRetBytes': 8, 'groupIdSlot': 19, 'groupIdSetSlot': 20,
    'layoutAddSlot': 6, 'layoutAddRetBytes': 12, 'snapshotAfterGroupAdd': True,
    'preSaveSlot': 22, 'preSaveRetBytes': 8, 'postSaveSlot': 23, 'postSaveRetBytes': 4,
    'extractSlot': 43, 'extractInnerSlot': 43, 'extractRetBytes': 8,
    'publishedExtractSlot42Allowed': False, 'managerInnerOffset': 204,
    'freshOwnReadMode': 0, 'deleteSlot': 26, 'deleteRetBytes': 12,
    'goldBodyInputAllowed': False, 'goldSaveAllowed': False, 'nativePermit': False,
}


def need(condition, code):
    if not condition:
        raise ValueError(code)


def exact_equal(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(exact_equal(actual[k], v) for k, v in expected.items())
    return actual == expected


def verify_profile(profile):
    """Reject slot/convention/ownership substitutions, including bool-as-int."""
    need(exact_equal(profile, ABI_PROFILE), 'V73_ABI_PROFILE_REJECTED')


def verify_ranges(reader):
    """Check immutable whole-function/table ranges using a pure byte reader."""
    need(callable(reader), 'V73_READER_REJECTED')
    result = {}
    for key, (name, rva, length, expected) in RANGES.items():
        body = reader(name, rva, length)
        need(type(body) is bytes and len(body) == length
             and hashlib.sha256(body).hexdigest() == expected, 'V73_RANGE_REJECTED_' + key)
        result[key] = body
    return result


def verify_tables(bodies, bases):
    """Check real relative vtable targets; PE bases cannot be supplied ad hoc."""
    need(exact_equal(bases, {name: value[0] for name, value in MODULES.items()}), 'V73_BASE_REJECTED')
    for key, slots in TABLE_SLOTS.items():
        name = RANGES[key][0]
        body = bodies[key]
        for slot, rva in slots.items():
            need(type(body) is bytes and len(body) >= (slot + 1) * 4
                 and struct.unpack_from('<I', body, slot * 4)[0] == bases[name] + rva,
                 'V73_TABLE_REJECTED_' + key)


def verify_qi_map(body, read_guid):
    """Prove the document subobject offset using actual IID rows, not type names."""
    need(type(body) is bytes and len(body) == 96 and callable(read_guid), 'V73_QI_MAP_REJECTED')
    actual = []
    for at in range(0, len(body), 12):
        pointer, offset, flag = struct.unpack_from('<III', body, at)
        if pointer:
            raw = read_guid(pointer)
            need(type(raw) is bytes and len(raw) == 16, 'V73_QI_GUID_REJECTED')
            identifier = str(uuid.UUID(bytes_le=raw)).upper()
        else:
            identifier = 'END'
        actual.append((identifier, offset, flag))
    need(tuple(actual) == QI_ROWS, 'V73_QI_MAP_REJECTED')


def verify_ref_imports(symbols):
    need(exact_equal(symbols, REF_IMPORTS), 'V73_REF_IMPORT_REJECTED')


def _ref_imports(pe):
    """Resolve only two reference-counter IAT slots in the fixed managed DLL."""
    nt = struct.unpack_from('<I', pe.data, 0x3c)[0]
    directory = struct.unpack_from('<I', pe.data, nt + 24 + 104)[0]
    at = pe.offset(pe.base + directory)
    result = {}

    def ascii_name(rva):
        start = pe.offset(pe.base + rva)
        end = pe.data.find(b'\x00', start, start + 128)
        need(end >= start, 'V73_REF_IMPORT_REJECTED')
        return pe.data[start:end].decode('ascii')

    for _ in range(256):
        original, stamp, chain, name, iat = struct.unpack_from('<IIIII', pe.data, at)
        if not any((original, stamp, chain, name, iat)):
            return result
        thunk = pe.offset(pe.base + (original or iat))
        for index in range(4096):
            symbol = struct.unpack_from('<I', pe.data, thunk + index * 4)[0]
            if not symbol:
                break
            slot = iat + index * 4
            if slot in REF_IMPORTS:
                need(not symbol & 0x80000000, 'V73_REF_IMPORT_REJECTED')
                result[slot] = (ascii_name(name), ascii_name(symbol + 2))
        else:
            raise ValueError('V73_REF_IMPORT_REJECTED')
        at += 20
    raise ValueError('V73_REF_IMPORT_REJECTED')


def _has(body, hex_text, code):
    need(type(body) is bytes and bytes.fromhex(hex_text) in body, code)


def _call(body, entry, offset, target, code):
    need(body[offset:offset + 1] == b'\xe8' and len(body) >= offset + 5
         and entry + offset + 5 + struct.unpack_from('<i', body, offset + 1)[0] == target, code)


def verify_edges(bodies):
    """Independent instruction checks for receiver adjustment and ref ownership.

    This inspects fixed instruction bytes, not an AS helper's own assertions. It
    does not resolve every imported/virtual/transitive implementation.
    """
    for key in ('bodySave', 'bodyLoad'):
        need(bodies[key].endswith(b'\xc2\x08\x00'), 'V73_DOCUMENT_RET_REJECTED')
        _has(bodies[key], '8d4efc', 'V73_DOCUMENT_THIS_REJECTED')
    _call(bodies['bodySave'], 0x2c96d0, 0x89, 0x2c97f0, 'V73_SAVE_LINK_REJECTED')
    _call(bodies['bodyLoad'], 0x2c98c0, 0x85, 0x2c99f0, 'V73_LOAD_LINK_REJECTED')
    for key in ('documentQI', 'documentAddRef', 'documentRelease'):
        need(bodies[key][:5] == bytes.fromhex('836c240404'), 'V73_DOCUMENT_ADJUST_REJECTED')
    _has(bodies['bodyQIHelper'], '56 8b06 ff5004 8937', 'V73_QI_COUNT_REJECTED')
    _has(bodies['bodyCtor'], 'c7410454542837', 'V73_DOCUMENT_CONSTRUCTOR_REJECTED')
    need(bodies['bodyGetClsid'] == bytes.fromhex('b878562837c20400'), 'V73_BODY_CLASS_LINK_REJECTED')
    _has(bodies['bodyFactory'], '6a6c', 'V73_FACTORY_ALLOC_REJECTED')
    _has(bodies['bodyFactory'], '53ff75fc57ff10', 'V73_FACTORY_QI_REJECTED')
    need(bodies['bodyModule'] == bytes.fromhex('558bec8b450883c0305dc20400'), 'V73_MODULE_GETTER_REJECTED')
    need(bodies['bodyLayout'] == bytes.fromhex('558bec8b45088b402c5dc20400'), 'V73_LAYOUT_GETTER_REJECTED')
    _has(bodies['helperCreate'], '6a01', 'V73_HELPER_CREATE_FLAG_REJECTED')
    _has(bodies['helperCreate'], '8d917cffffff', 'V73_HELPER_THIS_REJECTED')
    need(bodies['helperCreate'].endswith(bytes.fromhex('c21000')), 'V73_HELPER_RET_REJECTED')
    _has(bodies['helperOutput'], '8b0a52ff5104', 'V73_HELPER_COUNT_REJECTED')
    _has(bodies['helperOutput'], '8b45088930', 'V73_HELPER_TRANSFER_REJECTED')
    need(bodies['helperIUnknownIid'] == uuid.UUID(UNKNOWN_IID).bytes_le, 'V73_CANONICAL_QI_REJECTED')
    _has(bodies['externalStore'], '8b7314', 'V73_STORE_OWNER_REJECTED')
    _has(bodies['externalStore'], '8b450c8945c4', 'V73_STORE_INPUT_REJECTED')
    _has(bodies['externalStore'], 'ff75c4', 'V73_STORE_INPUT_REJECTED')
    _has(bodies['externalStore'], '5057ffd6', 'V73_STORE_INPUT_REJECTED')
    for key, adjustment in (('layoutRetain', 40), ('groupRetain', 24)):
        need(bodies[key][:5] == b'\x83\x6c\x24\x04' + bytes([adjustment]), 'V73_BORROWED_RETAIN_REJECTED')
        entry = RANGES[key][1]
        body = bodies[key]
        need(body[5] == 0xe9 and entry + 10 + struct.unpack_from('<i', body, 6)[0] == 0x8d070,
             'V73_BORROWED_RETAIN_TARGET_REJECTED')
    need(bodies['borrowedAddRef'] == bytes.fromhex('558bec8b450883c0048945085dff2574c02337'),
         'V73_BORROWED_COUNT_REJECTED')
    _has(bodies['groupClone'], '68e4010000', 'V73_GROUP_ALLOC_REJECTED')
    _has(bodies['groupClone'], '8b450c8d4f188908', 'V73_GROUP_OUTPUT_REJECTED')
    _has(bodies['groupClone'], '8b0151ff5004', 'V73_GROUP_OUTPUT_COUNT_REJECTED')
    need(bodies['layoutAdd'].endswith(bytes.fromhex('c20c00')), 'V73_LAYOUT_ADD_RET_REJECTED')
    need(bodies['groupClone'].endswith(bytes.fromhex('c20800')), 'V73_GROUP_CLONE_RET_REJECTED')
    _has(bodies['extractWrapper'], '8b45088b80cc0000008b085f5e5b8945085dffa1ac000000', 'V73_EXTRACT_THIS_SLOT_REJECTED')
    need(bodies['extractInner'][0x3e9d5 - 0x3dc70:0x3e9d5 - 0x3dc70 + 3] == bytes.fromhex('c20800'), 'V73_EXTRACT_RET_REJECTED')
    _has(bodies['preSave'], 'c20800', 'V73_PRE_SAVE_RET_REJECTED')
    _has(bodies['postSave'], 'c20400', 'V73_POST_SAVE_RET_REJECTED')
    for key in ('deleteForm', 'deleteProcessing'):
        need(bodies[key].endswith(bytes.fromhex('c20c00')), 'V73_DELETE_RET_REJECTED')


def _compact(text):
    return re.sub(r'\s+', ' ', re.sub(r'//[^\n]*', '', text)).strip()


def verify_sdk_texts(texts):
    """Check published signatures and compatibility branches before native use."""
    need(type(texts) is dict and set(texts) == set(SDK_SHAS), 'V73_SDK_SET_REJECTED')
    document = _compact(texts['modules/snegopat/v8api/document.v'])
    need(':iface IPersistableDocument {' + DOCUMENT_IID + '} :virt void save(IFile@+ file) void load(IFile@+ file)' in document,
         'V73_SDK_DOCUMENT_REJECTED')
    metadata = _compact(texts['modules/snegopat/v8api/metadata.v'])
    need(':iface IMDExtObj {' + EXTERNAL_IID + '} :virt +11 uint url(URL&)' in metadata,
         'V73_SDK_EXTERNAL_REJECTED')
    need('13 uint extPropEditor(IUnknown@&, const Guid& propUuid) const Guid& extPropEditorCLSID(const Guid& propUuid) uint extProp(IUnknown@&, const Guid& propUuid, bool noCached = false) const Guid& extPropCLSID(const Guid& propUuid)' in metadata,
         'V73_SDK_HELPER_REJECTED')
    need('uint connectConfig(IConfigMngr@& res, IFile@ file, int mode, int t=0, int m=0)' in metadata,
         'V73_SDK_CONNECT_REJECTED')
    need('void extractConfig(IConfigMngr& target)' in metadata and '42 #endif void extractConfig' in metadata,
         'V73_SDK_STALE_EXTRACT_REJECTED')
    process = _compact(texts['modules/snegopat/v8api/process.v'])
    need('bool createByClsid(const Guid&in clsid, const Guid&in iid, IUnknown@&out ppObject)' in process,
         'V73_SDK_FACTORY_REJECTED')
    string = _compact(texts['modules/snegopat/v8api/string.v'])
    need('void opAssign(const v8string&in s)' in string
         and 'v8string__dtor(obj); v8string__ctor1(obj, s);' in string
         and '#elif x86 = 1 24 #endif' in string,
         'V73_SDK_STRING_ASSIGN_REJECTED')
    file = _compact(texts['modules/snegopat/v8api/file.v'])
    need('CLSID_MemoryFile' in file and ':iface IFile ' in file and ':iface IFileEx ' in file,
         'V73_SDK_FILE_REJECTED')


def verify_static():
    """Return static prerequisites only; read exact SDK members and fixed DLLs.

    No source/runtime traversal, temporary extraction, DLL loading, handle,
    connection, repository, or Gold operation occurs in this function.
    """
    verify_profile(ABI_PROFILE)
    archive = CACHE / 'snegopat.zip'
    need(hashlib.sha256(archive.read_bytes()).hexdigest() == ARCHIVE_SHA, 'V73_ARCHIVE_REJECTED')
    texts = {}
    with zipfile.ZipFile(archive) as bundle:
        for member, expected in SDK_SHAS.items():
            raw = bundle.read(member)
            need(hashlib.sha256(raw).hexdigest() == expected, 'V73_SDK_HASH_REJECTED')
            texts[member] = raw.decode('utf-8-sig')
    verify_sdk_texts(texts)
    pes = {name: PE(name) for name in MODULES}
    for name, (base, expected) in MODULES.items():
        need(pes[name].base == base and hashlib.sha256(pes[name].data).hexdigest() == expected,
             'V73_PLATFORM_REJECTED')

    def read_range(name, rva, length):
        pe = pes[name]
        offset = pe.offset(pe.base + rva)
        return pe.data[offset:offset + length]

    bodies = verify_ranges(read_range)
    verify_tables(bodies, {name: pe.base for name, pe in pes.items()})
    verify_ref_imports(_ref_imports(pes['mngcore.dll']))
    verify_qi_map(bodies['bodyQIMap'], lambda pointer: read_range('mngcore.dll', pointer - pes['mngcore.dll'].base, 16))
    need(bodies['bodyClsid'] == uuid.UUID(BODY_CLASS).bytes_le, 'V73_BODY_CLASS_REJECTED')
    verify_edges(bodies)
    return {
        'staticContractVerified': True, 'platform': '8.3.18.1208', 'architecture': 'x86',
        'moduleShas': {name: value[1] for name, value in MODULES.items()},
        'sdkMemberShas': dict(SDK_SHAS), 'rangeCount': len(RANGES), 'abi': dict(ABI_PROFILE),
        'publishedDocumentAbiVerified': True, 'actualDocumentQIAndTableVerified': True,
        'actualBodySaveLoadVerified': True, 'documentAbortStub': False,
        'countedQIAndBorrowedRetainVerified': True, 'helperCreateBinaryDerived': True,
        'bodyFactoryRegistrationProven': False, 'helperCreatePublished': False,
        'runtimeFactoryResultAndCanaryRequired': True, 'ownedHelperReceiverRequired': True,
        'bodySaveAfterGroupAddRequired': True, 'extractSlot43Verified': True,
        'initializerStandardLayoutProven': False, 'normalizationRuntimeProven': False,
        'transitiveCallsFullyProven': False, 'bodyDeepIndependenceVerified': False,
        'foreignPropertyPreservationVerified': False, 'managedFormVerified': False,
        'runtimeBodyVerified': False, 'persistedMemoryVerified': False, 'persistedGoldVerified': False,
        'nativePermit': False, 'nativeCalls': 0, 'goldCalls': 0,
    }


if __name__ == '__main__':
    print(json.dumps(verify_static(), sort_keys=True))
