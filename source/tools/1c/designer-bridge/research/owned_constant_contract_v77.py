"""Read-only pinned Constant prerequisite for 8.3.18.1208/x86.

Reads three exact platform PE files and three fixed SDK members. It never loads
a platform DLL, creates metadata, reads a configuration, or grants a writer.
Complete byte ranges cover normal CFG branches, not exception or lifetime proof.
"""
import hashlib
from pathlib import Path
import struct
import uuid
import zipfile

from repository_pe_probe import PE

HERE = Path(__file__).resolve().parent
SDK_ARCHIVE = HERE.parents[3] / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40/snegopat.zip'
CONSTANT_CLASS = '0195e80c-b157-11d4-9435-004095e12fc7'
ATTRIBUTE_CLASS = 'cf4abea7-37b2-11d4-940f-008048da11f9'
CONSTANT_NAMES = dict(singularEn='Constant', singularRu='Константа',
                      pluralEn='Constants', pluralRu='Константы')
TYPE_PROPERTY = 'b1053250-abe6-11d4-9434-004095e12fc7'
TYPE_DESCRIPTION = 'f5c65050-3bbb-11d5-b988-0050bae0a95d'
TYPE_DOMAIN_IID = 'fd3a880b-fda8-4d71-8c8a-5a8a6a9c2cab'
SDK_SHAS = {
    'modules/snegopat/v8api/metadata.v': 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed',
    'modules/snegopat/v8api/value.v': 'c99b23ab9d0f81493f138f7bac66b96019ab9c69fd121202beab352772534288',
    'modules/snegopat/v8api/TypeDomainPattern.v': 'd28085c084faa86860a5b73aae267c5d64f1f3ca0c60cfbeeba891cd1b1c3aa3',
}
# The last argument is the SHA of this exact complete function or fixed table.
RANGES = {
    'constantFactory': ('basic.dll', 0x4d93d0, 187, '96c9563a6fcf45e2d1e598ae5081246011000e261fd90a67354d416ce84a9301'),
    'constantObjectCtor': ('basic.dll', 0x7a3940, 140, 'c7be2d2bb97e13c69960329b6f64767cc3425f3a5f1982dba94017d2106edb24'),
    'constantClassCtor': ('basic.dll', 0x54d710, 1895, '5d2fc12668a7c95d621886613067398a1d3a7aaeb823760cde9727027ea17d2b'),
    'constantClassRegistrar': ('basic.dll', 0x500e60, 203, 'b28e985672585238057aaede9aa83cb4c49313bb6c531f0b25fc71541a0399f3'),
    'constantGetter': ('basic.dll', 0x4d77c0, 388, '8527be15d5b59651c4f8bd39b4068844aea361f9c08e4fe2d57105124b50802f'),
    'constantSetter': ('basic.dll', 0x4d7950, 409, 'e7c2ae3fc2fca877db4d887f515bab28656053639ef18643b0ee3d48241def37'),
    'constantOwnSet': ('basic.dll', 0x54c450, 830, '2e536a936239596c20f1f14a14d97ebd8cd6fdccc61a13237ab6502223f7923b'),
    'genericGuidSet': ('basic.dll', 0x501b50, 135, '921f847abb3fd17447453b16034deef14837e3feb706a4e7fa7fdbe199e6ca16'),
    'typeParentSet': ('basic.dll', 0x542440, 2228, '8fc9d998b9d63fa87bd9606abfd261806b07242a36a7c48c77bf24e163f0e22f'),
    'typePropertyRegistration': ('basic.dll', 0x54178c, 22, '329dec4275644e2fb59c8512e578e4cff9c39c0e30ef1aab7bd733bd152730c5'),
    'constantClassGuid': ('basic.dll', 0x884ea8, 16, 'b9b370c933c6c65725a93a7c6d7843d11f2ba1b5454cac756b74e47a3e665781'),
    'typePropertyGuid': ('basic.dll', 0x890b84, 16, '30541a298fa9d38c0dcbe25ffc7fa9de98a7784c7f69e041c15c56742fdd7852'),
    'typeDomainIID': ('basic.dll', 0x87dd80, 16, '2a157aa62ee7b0cd9a6329001c86e92aaa42660eaedb52ff0c25e4651489990a'),
    'constantClassTable': ('basic.dll', 0x8cca90, 108, '34e0ab520a8c014b32c5edb3c7aa4fcc22f09f0f757f61bbea3b5fb4fd089b08'),
    'constantMdTable': ('basic.dll', 0x8c99b4, 148, '8043e307669c2e567e4d8dd7a214f3974f5e15c28bd38ad4562f1c07b6df4465'),
    'constantNamePointers': ('basic.dll', 0x9c16d8, 32, 'eb32fa5905e84868211cc64949cc9bdcbf5810cb47697eeede0ec57bb509429e'),
    'singularEn': ('basic.dll', 0x88e238, 18, '062f0c846b503665e30f42e692d126178dd9739ab765b83f635d3204d5ddc20d'),
    'singularRu': ('basic.dll', 0x88e2d4, 20, 'cfb78fd38d5d9eb5bab7abee1c48a4a3ac5ae5952b1bf8100ac1347fd01384f2'),
    'pluralEn': ('basic.dll', 0x88e2e8, 20, '2d5a2797ef03b1155667516cd750e712c66021caf6072c96a76708b81a1423c3'),
    'pluralRu': ('basic.dll', 0x88e2a4, 20, '28aa5f5774ce7c17be66e141be873f025907f51f4304fb731f821752e907f958'),
    'rootKindRegistration': ('basic.dll', 0x4d539c, 49, '109da5570b67a2c5ac899f72e22cf70ee97f42b00b237ed73c2a4936f8a62b88'),
    'rootMdTable': ('backend.dll', 0xf15214, 120, 'a36e57717aea6b876d3426f39c4cc2f56f3b41cc2e4d4b6854e1bbdd382f43ac'),
    'rootAttach': ('backend.dll', 0x5c6d10, 154, '881ef63135002cae2533235d557143407f9be9263f842a9113549ae06ba2b30e'),
    'rootDelete': ('backend.dll', 0x5c6e20, 138, 'a714c4fe4cb593b913cf24fde60cf18da15fd0baac2a9813b8548f67e87ea103'),
}


def need(condition, code):
    if not condition:
        raise ValueError(code)


def read_sdk_members():
    """Read only fixed bounded SDK members, without extraction or cache edits."""
    with zipfile.ZipFile(SDK_ARCHIVE) as archive:
        need(all(0 < archive.getinfo(name).file_size <= 65536 for name in SDK_SHAS),
             'V77_SDK_SIZE_REJECTED')
        return {name: archive.read(name) for name in SDK_SHAS}


def verify_sdk_members(members):
    need(type(members) is dict and members.keys() == SDK_SHAS.keys(), 'V77_SDK_SET_REJECTED')
    for name, expected in SDK_SHAS.items():
        data = members[name]
        need(type(data) is bytes and hashlib.sha256(data).hexdigest() == expected, 'V77_SDK_HASH_REJECTED')
    metadata, value, domain = (members[name].decode('utf-8-sig') for name in SDK_SHAS)
    need('int mdPropVal(const Guid& mdPropId, Value& value)' in metadata
         and 'bool setMdPropVal(const Guid& mdPropId, const Value& value)' in metadata
         and 'IMDClass@+ mdClass(const Guid& id)' in metadata, 'V77_METADATA_API_REJECTED')
    need('bool hasCtor(uint)' in value and 'void create(IValue@&out, Vector&)' in value
         and 'bool isMutable()' in value and 'void ctor(const Guid&in)' in value,
         'V77_TYPE_API_REJECTED')
    need('??4TypeDomainPattern@core@@QAEAAV01@ABV01@@Z' in domain, 'V77_TYPE_COPY_API_REJECTED')


def collect_ranges(modules):
    need(type(modules) is dict and set(modules) == {'basic.dll', 'backend.dll', 'core83.dll'},
         'V77_MODULE_SET_REJECTED')
    result = {}
    for name, (module, rva, size, _) in RANGES.items():
        pe = modules[module]
        offset = pe.offset(pe.base + rva)
        result[name] = pe.data[offset:offset + size]
    return result


def verify_ranges(ranges):
    need(type(ranges) is dict and ranges.keys() == RANGES.keys(), 'V77_RANGE_SET_REJECTED')
    for name, (_, _, size, expected) in RANGES.items():
        data = ranges[name]
        need(type(data) is bytes and len(data) == size, 'V77_RANGE_SIZE_REJECTED')
        need(hashlib.sha256(data).hexdigest() == expected, 'V77_RANGE_HASH_REJECTED')


def verify_class_names(ranges):
    """Verify the registrar's four bounded names; GUID similarity is not identity."""
    need(type(ranges) is dict and all(name in ranges for name in CONSTANT_NAMES),
         'V77_CLASS_NAMES_REJECTED')
    for name, expected in CONSTANT_NAMES.items():
        raw = ranges[name]
        need(type(raw) is bytes and len(raw) == len(expected.encode('utf-16le')) + 2
             and raw[-2:] == b'\0\0', 'V77_CLASS_NAMES_REJECTED')
        try:
            text = raw[:-2].decode('utf-16le')
        except UnicodeError as error:
            raise ValueError('V77_CLASS_NAMES_REJECTED') from error
        need(text == expected, 'V77_CLASS_NAMES_REJECTED')


def verify_linkage(ranges):
    """Check fixed class/type/slot provenance after verifying complete byte pins."""
    verify_ranges(ranges)
    verify_class_names(ranges)
    for name, expected in (('constantClassGuid', CONSTANT_CLASS), ('typePropertyGuid', TYPE_PROPERTY),
                           ('typeDomainIID', TYPE_DOMAIN_IID)):
        need(str(uuid.UUID(bytes_le=ranges[name])) == expected, 'V77_GUID_LINK_REJECTED')
    def words(name):
        return struct.unpack('<' + str(len(ranges[name]) // 4) + 'I', ranges[name])
    need(words('constantClassTable')[3] == 0x228b0000 + 0xd8d80
         and words('constantClassTable')[4] == 0x228b0000 + 0x499db0
         and words('constantClassTable')[6] == 0x228b0000 + 0x4d9390
         and words('constantClassTable')[8] == 0x228b0000 + 0x4d93d0
         and words('constantMdTable')[12:14] == (0x228b0000 + 0x4d77c0, 0x228b0000 + 0x4d7950)
         and words('rootMdTable')[24] == 0x1f400000 + 0x5c6d10
         and words('rootMdTable')[26] == 0x1f400000 + 0x5c6e20, 'V77_TABLE_LINK_REJECTED')
    # Slot8 factory returns a counted IMDObject subobject at +0x164, not +4/+8.
    factory = ranges['constantFactory']
    need(bytes.fromhex('6834020000') in factory
         and bytes.fromhex('8d8e64010000') in factory
         and factory[0x4b] == 0xe8
         and 0x4d941b + 5 + struct.unpack_from('<i', factory, 0x4c)[0] == 0x7a3940,
         'V77_FACTORY_LINK_REJECTED')
    need(bytes.fromhex('c78664010000b4991723') in ranges['constantObjectCtor'],
         'V77_FACTORY_LINK_REJECTED')
    registrar = ranges['constantClassRegistrar']
    need(registrar[0x43] == 0xe8
         and 0x500ea3 + 5 + struct.unpack_from('<i', registrar, 0x44)[0] == 0x54d710
         and bytes.fromhex('c70390ca1723') in registrar
         and bytes.fromhex('0f1005a84e13230f1107') in ranges['constantClassCtor'],
         'V77_CLASS_LINK_REJECTED')
    # These are the exact globals consumed by the registrar, not unconnected
    # strings that merely happen to occur in the platform image.
    names = words('constantNamePointers')
    need(tuple(names[i] for i in (0, 1, 6, 7)) == tuple(0x228b0000 + n for n in
         (0x88e238, 0x88e2d4, 0x88e2e8, 0x88e2a4)), 'V77_CLASS_NAMES_REJECTED')
    need(all(bytes.fromhex(pattern) in ranges['constantClassCtor'] for pattern in
         ('a1d8162723', 'a1dc162723', 'a1f0162723', 'a1f4162723',
          '89472c', '894730', '89473c', '894740')), 'V77_CLASS_NAMES_REJECTED')
    need(bytes.fromhex('68a84e1323') in ranges['rootKindRegistration']
         and bytes.fromhex('6a0568684c14236a01') in ranges['rootKindRegistration'],
         'V77_ROOT_KIND_LINK_REJECTED')
    need(bytes.fromhex('6a016a0568840b1423') in ranges['typePropertyRegistration'],
         'V77_TYPE_INDEX_REJECTED')
    need(bytes.fromhex('6880dd1223') in ranges['typeParentSet']
         and bytes.fromhex('8d8fe4000000ff15a0b31223') in ranges['typeParentSet'],
         'V77_TYPE_COPY_LINK_REJECTED')
    # Published Guid setter -> this Constant's setter -> the same reviewed
    # TypeDomainPattern base branch. No private setter is called by native AS.
    for name, at, caller, target in (
            ('constantSetter', 0x92, 0x4d79e2, 0x501b50),
            ('constantSetter', 0x117, 0x4d7a67, 0x501b50),
            ('genericGuidSet', 0x59, 0x501ba9, 0x54c450),
            ('constantOwnSet', 0x327, 0x54c777, 0x542440)):
        body = ranges[name]
        need(body[at] == 0xe8 and caller + 5 + struct.unpack_from('<i', body, at+1)[0] == target,
             'V77_TYPE_ROUTE_REJECTED')
    for name, stack in (('constantFactory', 8), ('constantGetter', 12), ('constantSetter', 12),
                        ('constantOwnSet', 8), ('genericGuidSet', 8), ('typeParentSet', 8),
                        ('rootAttach', 8), ('rootDelete', 12)):
        need(ranges[name].endswith(b'\xc2' + struct.pack('<H', stack)), 'V77_RETURN_ABI_REJECTED')


def verify_static():
    """Verify offline prerequisites only; no runtime/default/writer permission."""
    members = read_sdk_members()
    verify_sdk_members(members)
    # PE validates exact whole-file hashes and x86 format before any range read.
    modules = {name: PE(name) for name in ('basic.dll', 'backend.dll', 'core83.dll')}
    verify_linkage(collect_ranges(modules))
    return dict(platform='8.3.18.1208', architecture='x86', staticContractVerified=True,
                constantClassId=CONSTANT_CLASS, typePropertyId=TYPE_PROPERTY,
                typeDescriptionId=TYPE_DESCRIPTION, factoryTableRva=0x8cca90,
                factoryRva=0x4d93d0, ownRootAttachRva=0x5c6d10, ownRootDeleteRva=0x5c6e20,
                constantClassNames=dict(CONSTANT_NAMES), attributeClassId=ATTRIBUTE_CLASS,
                pinnedRanges=len(RANGES), sdkMemberShas=dict(SDK_SHAS),
                nativePermit=False, runtimeConstantVerified=False, defaultTypeVerified=False,
                qualifierReadbackVerified=False, exceptionAbiVerified=False,
                persistedMemoryVerified=False, persistedGoldVerified=False,
                goldWritesPermitted=False, repositoryWritesPermitted=False)
