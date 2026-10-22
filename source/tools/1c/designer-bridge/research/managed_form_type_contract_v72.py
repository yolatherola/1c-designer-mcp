"""Fixed V72 FormType prerequisites. Read bytes only; never load/call a DLL.

The scalar FormType branch is stronger evidence than carrier pointer inequality,
but is not a proof of complete form independence or transitive runtime safety.
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

MODULES = {
    'basic.dll': (0x228b0000, '1d6c1020b517bf19fef2626ace1bc0c2402f38d8993c192da05e2b67404863a2'),
    'backend.dll': (0x1f400000, '498664a61cee45d979bd4d8eacfddf20e7510780df52daaeacd5314bce22e739'),
    'core83.dll': (0x10020000, '46e7019a142a01367d27c28b646ce8defea54ad60afe9fc467738b75c8663f14'),
}
SDK_SHAS = {
    'modules/snegopat/v8api/value.v': 'c99b23ab9d0f81493f138f7bac66b96019ab9c69fd121202beab352772534288',
    'modules/snegopat/v8api/metadata.v': 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed',
    'modules/snegopat/v8api/process.v': '92458b3e1a862051bf9b1d8b0cac750de5fddc62294324ca70a94820cdb1a9ef',
    'modules/snegopat/engine/com_v8value.as': '4c90e1ca9efd414e164a1f54fe1cc6ca6924da9eab713c8db4ca661e443f3276',
}
FORM_TYPE = 'B5FDF93A-40EA-4FC2-8911-2CB676377EFF'
FORM_TYPE_PROPERTY = 'E3331ED0-3854-478D-B6B5-4F14ACDD6EDB'
I_ENUM = '9CD510D8-ABFC-11D4-9434-004095E12FC7'
I_CREATOR = 'A89A27EA-9190-4F45-BA27-B6A3287E26A8'
I_VALUE = 'FD7B6CC3-DC8E-11D2-B8D0-008048DA0335'
I_TYPE = 'FD7B6CC0-DC8E-11D2-B8D0-008048DA0335'
I_MD_OBJECT = '12BFDDD0-36CC-11D4-940F-008048DA11F9'
VALUE_CTOR = '??0Value@core@@QAE@PAVIValue@1@@Z'
VALUE_DEFAULT_CTOR = '??0Value@core@@QAE@XZ'
CURRENT_PROCESS = '?current_process@core@@YAPAVSCOM_Process@1@XZ'
EXPORTS = {VALUE_CTOR: 0x1f1f50, CURRENT_PROCESS: 0x1df6c0}
IMPORTS = {'backend.dll': {
    0xe48634: ('core83.dll', VALUE_CTOR),
    0xe48660: ('core83.dll', VALUE_DEFAULT_CTOR),
    0xe470fc: ('KERNEL32.dll', 'InterlockedIncrement'),
    0xe47204: ('KERNEL32.dll', 'InterlockedDecrement'),
}}

# Every function range includes all return paths, excluding the next function.
# The registration block is a bounded literal/ID construction block, not a factory.
RANGES = {
    'formFactory': ('basic.dll', 0x4ee310, 192, '61ea508533f1b3b3193106f4fe39f49f2070fa2458d45158a02642fd676be3be'),
    'formMdTable': ('basic.dll', 0x8cb258, 140, '87bd40ec385ebe1738b87fca62cd6793300e468e9da354cb4daed4186d1083ea'),
    'formSetGuid': ('basic.dll', 0x4edec0, 400, '5bd7411c90c406e47b7b348c4659a9b8558291ce61d79a8f2e60a977bc0cb31a'),
    'formGuidDispatch': ('basic.dll', 0x50b0a0, 134, '2f3b5b366aa872b9a8feb8f786531f697d15b8c0c714e6e615f7cb7b9699c9cf'),
    'formIndexSetter': ('basic.dll', 0x50ae60, 545, '8bbfba106242ac9df44c0db3a4f7b08be46ae5eff5945aeacbfc07b67a17b725'),
    'formTypeBranch': ('basic.dll', 0x50aeab, 146, 'ec4858556b88cc39a5323f77773cea778d4ccc9abf89b04233b103b95f6bfe28'),
    'formTypeJumpTable': ('basic.dll', 0x50b084, 20, 'dc43c11ac5ba352b8c4e47bc272dd1177f46c20f43c0962a3c02af5033fc87ce'),
    'formTypeRegistration': ('basic.dll', 0x48ac78, 22, 'a8372fe9efe5cc14e99d27d7ee1cfb72817cc09c95e2aff12b7d8394cdd1dc21'),
    'formTypeProperty': ('basic.dll', 0x894938, 16, '905d7a175d27f18393afbd2d21cc50b11e76cdf0e918ca80f5282584f12aeeb9'),
    'formTypeGetter': ('basic.dll', 0x50ad7d, 96, '1a4f4230ec97a86f86db90c6478395046b56f9dab410591bdce4cc3bc29f110b'),
    'formTypeGetterGuid': ('basic.dll', 0x894948, 16, '0631ab7892911bd061d5c0e75b6bd936ebb6555d05e8da811197c726928d7a24'),
    'formChanged': ('basic.dll', 0x3d4570, 125, '615c5e74ba8a0f3ebbf2118b8e88f36cc87e51fdb30713e73c1dff2bd62eebec'),
    'formChangeMap': ('basic.dll', 0x3d3500, 103, 'a1b177c990d3a2ebe63c66daae08cf98844f4e340e93baee034c8184ced9ecfb'),
    'formModified': ('basic.dll', 0x49e630, 125, '669097f9a8f67cfe0118187d76e7a0a277887204749f32eba97e8e84b7b328eb'),
    'formEnumIid': ('basic.dll', 0x89d1e8, 16, '70a78701931380a7580aaa9aebb419afc8af057419809d478609357e46f9bebc'),
    'creatorTable': ('backend.dll', 0xe5985c, 20, 'bb869266377e43f2cd38ab7c853d04fd50005fcc998a7875808553582f876029'),
    'creatorQIMap': ('backend.dll', 0xe59cc0, 84, 'bac8e2dc8b5d64292b04ffafb84806aeceeb4033371ea8e57a69576b4362cc7c'),
    'creatorIid': ('backend.dll', 0xe4f358, 16, '1b03e40c8dcc6b3519a01399bc5f54b7d833c2c0e8405839a15785e460ec3da9'),
    'creatorQI': ('backend.dll', 0x9a5040, 112, '9656542158a9a185ce1eb15166f5aa5a299ca9593b0aab76f1f49febd6ec2f95'),
    'creatorQIAdjust': ('backend.dll', 0x9a606d, 10, '539ae28ca6ff618d536e5603f175f5e1a21c83e17c1d519de1b0fe166a710562'),
    'creatorRefAdjust': ('backend.dll', 0x9a6077, 10, '3e734d7b4e6777f9704fa45ba54f3bfbbf80c5a36c3c2da7908232528eca6475'),
    'creatorCreate': ('backend.dll', 0x9a2cc0, 65, '6b1290b87bd244ba15c9ac37e28316a7be9f6ed5ff52133eea1231cea9dde469'),
    'creatorFactoryRequest': ('backend.dll', 0x964ea0, 123, '6ec86bb8d7c9769bb9f4384e16e11007f5882bcd210b85453d312f154631b4e0'),
    'enumIValueTable': ('backend.dll', 0xf1563c, 48, 'b69630828592544f42eaa4d70358af94f995cee4d8a9e115c0ed65bb359d2ade'),
    'enumTable': ('backend.dll', 0xf15624, 24, '1f3ccd3fa9d97595ab63ed1aed8773ee63ed4a0407a1edfe65eee83e18307fb2'),
    'enumQIMap': ('backend.dll', 0xf16b44, 48, '45ae05a369b80d7268c1793bf8eba45568552b83b5fbabd078bf35eab55298b1'),
    'enumIid': ('backend.dll', 0xe5f954, 16, '70a78701931380a7580aaa9aebb419afc8af057419809d478609357e46f9bebc'),
    'enumQI': ('backend.dll', 0xb4b200, 26, '63e923ed7893a5a3fe2f23f58cb8cf3e67badb91305a090925f54633573ff4c1'),
    'enumQIAdjust': ('backend.dll', 0xb51c27, 10, 'c8f85e231a32ab0f61dd2d0b16b9fb3d37d9e0c106802f345a3ec76809455561'),
    'qiHelper': ('backend.dll', 0x966490, 234, '97a0568cd952f0c443fe52096f4962424e7a235baf1f8f6788ed7728941f4d7f'),
    'enumAddRef': ('backend.dll', 0x967510, 19, '14e55d54842778a997335654e3ea228555d321fe65829d41a16ecabe4b5e3716'),
    'enumRelease': ('backend.dll', 0xb4b220, 45, 'edafb0b6b82cf9da05d890da351f5b3877d2247421c4713dd90647127cd230df'),
    'enumGetType': ('backend.dll', 0x92360, 13, '76ced998ddd7e549ba2e18dabbae375f3b4aa65cbcfad484df1e9e87e8df9fe5'),
    'enumGetId': ('backend.dll', 0x92140, 13, '825a2a5b28ccb2103feda7dc97da578e80d804f64b4da0f9296d726921a5902a'),
    'enumGetTypeGuid': ('backend.dll', 0x5ca470, 18, '50bafa45bf1293f75d9a44dde5ee6ab43ab2a643a8601384ff3ee85e9100ceda'),
    'enumEquals': ('backend.dll', 0x5ca280, 289, '6f6ef621df0fd8ded5fb585dcdd8c7bd5d20075f2c7253769c1d96567cecb686'),
    'enumRegistration': ('backend.dll', 0x5cd908, 268, '8d5da56fc95d664f2e3da80b18f05163f8cbda6525483296ffd40a8c4a7a500a'),
    'enumRegistrationType': ('backend.dll', 0xe86ca4, 16, '0631ab7892911bd061d5c0e75b6bd936ebb6555d05e8da811197c726928d7a24'),
    'enumItemConstructor': ('backend.dll', 0xb51f20, 53, 'f685ab84d733c54a34294ef7635222b97668efa5d73cb0c98cf02a0aa9c5272b'),
    'richFormName': ('backend.dll', 0xf1059c, 23, '584d625f3275531a53e81c5ff8327d79929616ece9befb7bb52cb9c05ec53612'),
    'logicFormName': ('backend.dll', 0xf105b4, 24, 'a15fde3ad5e574b63174ff5dfd803d712a5bd64bc4023116e4597638f7484221'),
    'valueIValueConstructor': ('core83.dll', 0x1f1f50, 85, '04b417d750150106292d474ea4ba1053492b0cff3c2d9287fa6db326a355ce49'),
    'currentProcess': ('core83.dll', 0x1df6c0, 13, '350ffc6e1613ad41ba15f029b1fea8ff364933d736c06002d0e0636d814aaa6d'),
}
ABI_PROFILE = {
    'platform': '8.3.18.1208', 'architecture': 'x86',
    'setGuidConvention': 'stdcall', 'setGuidSlot': 13, 'setGuidRetBytes': 12,
    'setGuidValue': 'const Value&', 'formPropertyIndex': 6,
    'ownBodyFromMdObject': 12, 'ownBodyKindOffset': 220,
    'ownModifiedFromMdObject': 60, 'creatorIid': I_CREATOR,
    'creatorCreateSlot': 3, 'creatorCreateConvention': 'stdcall',
    'creatorCreateRetBytes': 12, 'creatorReturn': 'output-Value-address',
    'creatorCarrier': 'cached-IValue-AddRef', 'creatorGetAllAllowed': False,
    'enumIid': I_ENUM, 'enumFromIValue': 4, 'enumIdSlot': 4,
    'enumIdOffset': 20, 'enumIdConvention': 'stdcall', 'enumIdRetBytes': 4,
    'enumEqualsSlot': 9, 'enumEqualsRetBytes': 8,
    'enumEqualsMeaning': 'type-Guid-and-integer-id',
    'managedId': 'runtime-unique-equality', 'goldSetterAllowed': False,
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def exact_equal(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(exact_equal(actual[k], v) for k, v in expected.items())
    if isinstance(expected, (list, tuple)):
        return len(actual) == len(expected) and all(exact_equal(a, e) for a, e in zip(actual, expected))
    return actual == expected


def verify_abi_profile(profile):
    require(exact_equal(profile, ABI_PROFILE), 'V72_ABI_PROFILE_CHANGED')


def clean_lines(text):
    return [' '.join(x.split()) for x in text.splitlines() if x.strip() and not x.strip().startswith('//')]


def interface_lines(text, kind, name, guid):
    match = re.search(r'(?m)^:' + kind + ' ' + re.escape(name) + r'\s+\{([^}]+)\}\s*$', text)
    require(match is not None and match.group(1) == guid, 'V72_SDK_INTERFACE_CHANGED')
    tail = text[match.end():]
    end = re.search(r'(?m)^:(?:iface|service|class|struct|global|guid)\b', tail)
    return clean_lines(tail[:end.start()] if end else tail)


def verify_sdk_layout(value, metadata, process, example):
    require(all(type(x) is str for x in (value, metadata, process, example)), 'V72_SDK_LAYOUT_CHANGED')
    require(interface_lines(value, 'iface', 'IEnumValCreator', I_CREATOR) ==
            [':virt', 'uint create(Value&out val, int eval)', 'void getAll(Vector& vals)'], 'V72_CREATOR_SIGNATURE_CHANGED')
    require(interface_lines(value, 'iface', 'IValue', I_VALUE) == [':virt', 'IType@ getType()', '+1',
            'bool getBool(bool& out)', 'bool getNumeric(Numeric& out)', 'bool getString(v8string& out)',
            'bool getDate(Date& out)', 'bool isEqual(IValue& in)'], 'V72_IVALUE_LAYOUT_CHANGED')
    type_lines = interface_lines(value, 'iface', 'IType', I_TYPE)
    require(type_lines[:4] == [':virt', 'int getTypeKind()', 'const Guid& getClsid()',
                             'uint16& getTypeString(int alias)'], 'V72_TYPE_GUID_SIGNATURE_CHANGED')
    md = interface_lines(metadata, 'iface', 'IMDObject', I_MD_OBJECT)
    require(md[:15] == [':virt', 'IMDClass@+ get_mdClass()', '+1', 'const Guid& get_id()',
            'void set_id(const Guid& id)', 'void set_mdParentLink(IMDParentLink@+ site)',
            'IMDParentLink@+ get_mdParentLink()', '+3', 'int mdPropVal(const Guid& mdPropId, Value& value)',
            'bool setMdPropVal(const Guid& mdPropId, const Value& value)',
            'bool validateMDPropValue(const Guid& mdPropId, Value& value, v8string& errString, bool)',
            'int mdPropVal(uint id, Value& value)', 'bool setMdPropVal(uint id, const Value& value)',
            'bool validateMdPropVal(uint id, Value& value, v8string& errString, bool)', '+1'], 'V72_SETTER_SIGNATURE_CHANGED')
    process_lines = interface_lines(process, 'service', 'SCOM_Process', 'EBF766A9-F32C-11D3-9851-008048DA1252')
    require(process_lines[:4] == [':virt', '+1',
            'bool createByName(const v8string&in clsName, const Guid&in iid, IUnknown@&out ppObject)',
            'bool createByClsid(const Guid&in clsid, const Guid&in iid, IUnknown@&out ppObject)'], 'V72_FACTORY_SIGNATURE_CHANGED')
    props = re.search(r'(?m)^:class Value\s*\r?\n:props\s*\r?\n(.*?)^:dlls\s*$', value, re.S)
    require(props is not None and clean_lines(props.group(1)) == ['int_ptr vtable', 'IValue@ pValue'], 'V72_VALUE_LAYOUT_CHANGED')
    require(('void ctor(IValue@)|' + VALUE_CTOR + '|??0Value@core@@QEAA@PEAVIValue@1@@Z') in clean_lines(value),
            'V72_VALUE_CTOR_SIGNATURE_CHANGED')
    require('IPersistableObject&& pers = cast<IUnknown>(value.pValue);' in clean_lines(example), 'V72_TYPED_QI_EXAMPLE_CHANGED')
    require(':iface IEnumVal ' not in value, 'V72_UNPUBLISHED_ENUM_ASSUMPTION')


def read_sdk_members():
    # Exactly four known members; no cache catalogue/prepare/checked_cache chain.
    with zipfile.ZipFile(CACHE / 'snegopat.zip') as archive:
        for name in SDK_SHAS:
            require(0 < archive.getinfo(name).file_size <= 65536, 'V72_SDK_MEMBER_BOUND_CHANGED')
        return {name: archive.read(name) for name in SDK_SHAS}


def verify_sdk_members(members):
    require(type(members) is dict and members.keys() == SDK_SHAS.keys(), 'V72_SDK_MEMBER_SET_CHANGED')
    for name, sha in SDK_SHAS.items():
        require(type(members[name]) is bytes and hashlib.sha256(members[name]).hexdigest() == sha, 'V72_SDK_SHA_CHANGED')
    verify_sdk_layout(*(members[n].decode('utf-8-sig') for n in SDK_SHAS))


def verify_module(name, base, data):
    require(name in MODULES and type(base) is int and base == MODULES[name][0], 'V72_MODULE_BASE_CHANGED')
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == MODULES[name][1], 'V72_MODULE_SHA_CHANGED')


def read_range(pe, rva, size):
    at = pe.offset(pe.base + rva)
    data = pe.data[at:at + size]
    require(len(data) == size, 'V72_RANGE_BOUNDARY_CHANGED')
    return data


def collect_ranges(modules):
    return {key: read_range(modules[m], r, n) for key, (m, r, n, _) in RANGES.items()}


def verify_ranges(ranges):
    require(type(ranges) is dict and ranges.keys() == RANGES.keys(), 'V72_RANGE_SET_CHANGED')
    for key, (_, _, size, sha) in RANGES.items():
        require(type(ranges[key]) is bytes and len(ranges[key]) == size, 'V72_RANGE_BOUNDARY_CHANGED')
        require(hashlib.sha256(ranges[key]).hexdigest() == sha, 'V72_RANGE_BYTES_CHANGED')


def native_layout(ranges):
    """Independent semantic gates on pinned bytes; no instruction execution."""
    def words(name):
        return struct.unpack('<' + str(len(ranges[name]) // 4) + 'I', ranges[name])
    def guid(name):
        return str(uuid.UUID(bytes_le=ranges[name])).upper()
    b, k = MODULES['basic.dll'][0], MODULES['backend.dll'][0]
    require(words('formMdTable')[13] == b + 0x4edec0 and words('formMdTable')[33] == b + 0x49e630,
            'V72_FORM_TABLE_CHANGED')
    require(guid('formTypeProperty') == FORM_TYPE_PROPERTY and guid('formTypeGetterGuid') == FORM_TYPE,
            'V72_FORM_TYPE_GUID_CHANGED')
    require(words('formTypeJumpTable')[1] == b + 0x50aeab and
            b'\x6a\x01\x6a\x06\x68' + struct.pack('<I', b + 0x894938) in ranges['formTypeRegistration'],
            'V72_FORM_TYPE_INDEX_CHANGED')
    require(guid('formEnumIid') == I_ENUM and b'\xff\x50\x10' in ranges['formTypeBranch'] and
            b'\x89\x86\xdc\x00\x00\x00' in ranges['formTypeBranch'], 'V72_SCALAR_BRANCH_CHANGED')
    require(words('creatorTable') == tuple(k + x for x in (0x9a606d, 0x9a6077, 0x9a6077, 0x9a2cc0, 0x9a2c60)),
            'V72_CREATOR_TABLE_CHANGED')
    creator = ranges['creatorCreate']
    require(creator.endswith(b'\xc2\x0c\x00') and b'\xff\x70\x14\xff\x15' + struct.pack('<I', k + 0xe48634) in creator,
            'V72_CACHED_CTOR_CHANGED')
    require(guid('creatorIid') == I_CREATOR and words('creatorQIMap')[9:12] == (k + 0xe4f358, 0x34, 1) and
            ranges['creatorQIAdjust'][:5] == b'\x83\x6c\x24\x04\x34', 'V72_CREATOR_QI_CHANGED')
    require(words('enumIValueTable')[9] == k + 0x5ca280 and words('enumIValueTable')[3] == k + 0x92360 and
            words('enumTable')[3:5] == (k + 0x5ca470, k + 0x92140), 'V72_ENUM_TABLE_CHANGED')
    require(guid('enumIid') == I_ENUM and words('enumQIMap')[3:6] == (k + 0xe5f954, 4, 1) and
            ranges['enumGetId'] == bytes.fromhex('558bec8b45088b40145dc20400'), 'V72_ENUM_ID_CHANGED')
    require(ranges['enumGetTypeGuid'].endswith(b'\xff\x61\x10') and
            b'\x39\x47\x18' in ranges['enumEquals'], 'V72_ENUM_EQUALITY_CHANGED')
    registration = ranges['enumRegistration']
    require(guid('enumRegistrationType') == FORM_TYPE and
            b'\x6a\x00\xe8' in registration and b'\x6a\x01\xe8' in registration and
            ranges['richFormName'] == b'IDS_FORM_TYPE_RICHFORM\x00' and
            ranges['logicFormName'] == b'IDS_FORM_TYPE_LOGICFORM\x00', 'V72_ENUM_RECORD_CHANGED')


def read_linkage(modules):
    """Parse only pointed core exports and backend imports in fixed PE bytes."""
    result = {'exports': {}, 'imports': {}}
    for name, pe in modules.items():
        if name not in ('core83.dll', 'backend.dll'):
            continue
        data = pe.data
        optional = struct.unpack_from('<I', data, 0x3c)[0] + 24
        def z(rva):
            at = pe.offset(pe.base + rva)
            end = data.find(b'\x00', at, at + 2048)
            require(end >= at, 'V72_LINKAGE_STRING_BOUND')
            return data[at:end].decode('ascii')
        if name == 'core83.dll':
            rva = struct.unpack_from('<I', data, optional + 96)[0]
            fields = struct.unpack_from('<IIHHIIIIIII', data, pe.offset(pe.base + rva))
            count, functions, names, ordinals = fields[7], fields[8], fields[9], fields[10]
            for i in range(count):
                symbol = z(struct.unpack_from('<I', data, pe.offset(pe.base + names) + i * 4)[0])
                if symbol in EXPORTS:
                    ordinal = struct.unpack_from('<H', data, pe.offset(pe.base + ordinals) + i * 2)[0]
                    result['exports'][symbol] = struct.unpack_from('<I', data, pe.offset(pe.base + functions) + ordinal * 4)[0]
        else:
            rva = struct.unpack_from('<I', data, optional + 104)[0]
            at = pe.offset(pe.base + rva)
            while True:
                oft, time, forward, library, first = struct.unpack_from('<5I', data, at)
                at += 20
                if not any((oft, time, forward, library, first)):
                    break
                index, table = 0, pe.offset(pe.base + (oft or first))
                while True:
                    pointer = struct.unpack_from('<I', data, table + index * 4)[0]
                    if not pointer:
                        break
                    iat = first + index * 4
                    if iat in IMPORTS[name]:
                        require(not pointer & 0x80000000, 'V72_LINKAGE_ORDINAL_CHANGED')
                        result['imports'][iat] = (z(library), z(pointer + 2))
                    index += 1
    return result


def verify_linkage(linkage):
    require(exact_equal(linkage, {'exports': EXPORTS, 'imports': IMPORTS['backend.dll']}), 'V72_LINKAGE_CHANGED')


def derive_managed_id(equal_to_known_managed):
    """Accept only a unique measured equality; never infer an ID from its name."""
    require(type(equal_to_known_managed) is dict and len(equal_to_known_managed) == 2 and
            all(type(k) is int and k in (0, 1) for k in equal_to_known_managed) and
            all(type(v) is bool for v in equal_to_known_managed.values()), 'V72_MAPPING_UNVERIFIABLE')
    matched = [k for k, v in equal_to_known_managed.items() if v]
    require(len(matched) == 1, 'V72_MAPPING_UNVERIFIABLE')
    return matched[0]


def validate_candidate(candidate):
    """Validate necessary reported scalar readings; does not attest their origin.

    Memory bounds, typed lifetimes and measurement provenance are enforced by
    the native host. This pure helper cannot make a setter safe by itself.
    """
    expected_keys = {'iValueAddress', 'enumAddress', 'iValueTableModule', 'iValueTableRva',
                     'enumTableModule', 'enumTableRva', 'enumIid', 'typeClsid', 'enumId', 'sourceDerivedValue'}
    require(type(candidate) is dict and candidate.keys() == expected_keys, 'V72_CANDIDATE_SCHEMA_CHANGED')
    p, e = candidate['iValueAddress'], candidate['enumAddress']
    require(type(p) is int and type(e) is int and 0x10000 <= p <= 0x7ffffffb and e == p + 4,
            'V72_CANDIDATE_POINTER_REJECTED')
    require(candidate['iValueTableModule'] == candidate['enumTableModule'] == 'backend.dll' and
            type(candidate['iValueTableRva']) is int and candidate['iValueTableRva'] == 0xf1563c and
            type(candidate['enumTableRva']) is int and candidate['enumTableRva'] == 0xf15624,
            'V72_CANDIDATE_TABLE_REJECTED')
    require(candidate['enumIid'] == I_ENUM and candidate['typeClsid'] == FORM_TYPE and
            type(candidate['enumId']) is int and candidate['enumId'] in (0, 1), 'V72_CANDIDATE_TYPE_REJECTED')
    require(candidate['sourceDerivedValue'] is False, 'V72_BORROWED_SOURCE_INPUT_REJECTED')


def validate_inventory(inventory):
    """Pure fail-closed guard for a readonly receipt, never a mutation permit."""
    required = {'factoryCreated', 'creatorQIVerified', 'candidateTypeB5Verified', 'memoryBoundsVerified',
                'typedLifetimesVerified', 'equalityPinned', 'knownManagedControlReadOnly'}
    require(type(inventory) is dict and inventory.keys() == required | {'creatorTableRva', 'candidates', 'equalities'},
            'V72_INVENTORY_SCHEMA_CHANGED')
    require(all(inventory[k] is True for k in required), 'V72_INVENTORY_UNVERIFIABLE')
    require(type(inventory['creatorTableRva']) is int and inventory['creatorTableRva'] == 0xe5985c,
            'V72_CREATOR_TARGET_REJECTED')
    candidates = inventory['candidates']
    require(type(candidates) is dict and len(candidates) == 2 and all(type(k) is int and k in (0, 1) for k in candidates),
            'V72_CANDIDATE_SET_REJECTED')
    for key, candidate in candidates.items():
        validate_candidate(candidate)
        require(candidate['enumId'] == key, 'V72_CANDIDATE_ID_REJECTED')
    # Distinct IDs cannot be contemporaneous readings of the same inline ID.
    # This consistency check does not claim deep backing independence.
    require(candidates[0]['iValueAddress'] != candidates[1]['iValueAddress'], 'V72_CANDIDATE_ALIAS_REJECTED')
    return {'managedId': derive_managed_id(inventory['equalities']), 'readOnlyInventoryAccepted': True,
            'setterAuthorized': False, 'deepEnumCloneProven': False, 'wholeFormBackingIndependent': False}


def verify_static():
    members = read_sdk_members()
    verify_sdk_members(members)
    modules = {name: PE(name) for name in MODULES}
    for name, pe in modules.items():
        verify_module(name, pe.base, pe.data)
    ranges = collect_ranges(modules)
    verify_ranges(ranges)
    native_layout(ranges)
    verify_linkage(read_linkage(modules))
    verify_abi_profile(ABI_PROFILE)
    return {
        'platform': '8.3.18.1208', 'architecture': 'x86', 'staticContractVerified': True,
        'moduleShas': {n: s for n, (_, s) in MODULES.items()}, 'sdkMemberShas': dict(SDK_SHAS),
        'pinnedRanges': len(RANGES), 'creatorCreateReturnsCachedCarrier': True,
        'publishedCreatorCreateSlot': 3, 'publishedGetAllSlot': 4, 'getAllAllowed': False,
        'nativeGetAllLayoutProven': False, 'nativeEnumInterfacePublished': False,
        'enumRegistrationIds': [0, 1], 'managedIdAssumed': False,
        'scalarStoredInOwnFormBranch': True, 'inputKindTypeWrittenByBranch': False,
        'enumCarrierPointerStoredInFormKind': False, 'creatorB5GuidBindingProven': False,
        'runtimeMappingProven': False, 'virtualSyncDeepCalleesProven': False,
        'managedKindRuntimeProven': False, 'bodyRuntimeProven': False,
        'deepEnumCloneProven': False, 'wholeFormBackingIndependent': False,
        'setterAuthorized': False, 'nativeCalls': 0, 'goldCalls': 0,
    }


if __name__ == '__main__':
    print(json.dumps(verify_static(), ensure_ascii=False, sort_keys=True))
