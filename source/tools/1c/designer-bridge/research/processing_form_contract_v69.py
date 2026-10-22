"""Read-only, fixed Processing.Form native prerequisite; no platform calls."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import uuid
import xml.etree.ElementTree as ET
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CACHE = ROOT / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40'
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from repository_pe_probe import PE

MODULES = {
    'basic.dll': (0x228b0000, '1d6c1020b517bf19fef2626ace1bc0c2402f38d8993c192da05e2b67404863a2'),
    'backend.dll': (0x1f400000, '498664a61cee45d979bd4d8eacfddf20e7510780df52daaeacd5314bce22e739'),
}
SDK_SHAS = {
    'modules/snegopat/v8api/metadata.v': 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed',
    'modules/snegopat/v8api/document.v': 'b1c12ef6a2d4ea9d655bd9057c7a605b2497bb6c22ddb9f6323efc3ad21c369e',
}
QI_EXTENSION = ROOT / 'tools/1c/designer-bridge/tests/NativeOwnedSourceApply.v'
QI_SHA = 'ce7cedc3f859586d3af36b5bbc188c4408533e119ca868974c1ee845a72009f5'
QI_IID = '4285C446-A958-4550-8475-ECAD7766DCB2'
SOURCE_PARENT = ROOT / 'DataProcessors/КонсольЗапросовУФ.xml'
SOURCE_FORM = ROOT / 'DataProcessors/КонсольЗапросовУФ/Forms/Настройки.xml'
PARENT_SHA = 'a69f72a0b41e3ad6360c134f8d70b29ab35429685c7010b264c00dc0239e34a6'
FORM_SHA = 'b0c18b59c162e1f7ae92cab39b59edff58a67451ee7071003539b826ac4bcfab'
PARENT_ID = 'c80fe1d6-4f67-454a-92bd-98b01e1e8332'
FORM_ID = 'b8a520d4-c823-477e-ba92-708656e9c9c6'
PROCESSING_CLASS = 'BF845118-327B-4682-B5C6-285D2A0EB296'
FORM_CLASS = 'D5B0E5ED-256D-401C-9C36-F630CAFD8A62'

# Functions include all normal CFG returns; the complete QI helper includes
# all five returns. Thunks end at their unconditional tail jump.
FUNCTIONS = {
    'processingFactory': ('basic.dll', 0x4ec650, 184, '27ced2bd9dacb4b686a8fe35ccd7eacf34bfe8bdcac0c30212880e90a35fc673'),
    'formFactory': ('basic.dll', 0x4ee310, 192, '61ea508533f1b3b3193106f4fe39f49f2070fa2458d45158a02642fd676be3be'),
    'processingConstructor': ('basic.dll', 0x7a33d0, 100, '2c522368de1a08637987188966191d97d81f21e5c2a4ff91273c0f000affdbbc'),
    'formPersistenceSave': ('basic.dll', 0x79f2b0, 31, 'f5fc7f9a6a05a2176701a343067daf2ab7983f3e097513b228286cda89059f93'),
    'formPersistenceLoad': ('basic.dll', 0x79f2d0, 37, '31e79eeb97ce3a01ac272c353743a0e3c6a430d73cfadb216a8084f58ec3a595'),
    'formPersistenceQIThunk': ('basic.dll', 0x7a65f9, 10, '9873cd15f38706d8d062534c416d62c7bd639d76572ed66b73bf85e028bc6a05'),
    'formMdObjectQIThunk': ('basic.dll', 0x7a53e8, 10, '570ef396a2ae153c9a4bbc12b8fff7ed8209803b2af48a56003a5bd5070ffa7c'),
    'formQI': ('basic.dll', 0x7a3220, 26, '240dc2560f42282739c4cb782be5b1e85bf615deeaf8dccc7489b1ff70b06988'),
    'qiMapHelper': ('basic.dll', 0x6ae930, 234, '97a0568cd952f0c443fe52096f4962424e7a235baf1f8f6788ed7728941f4d7f'),
}
TABLES = {
    'processingClass': ('basic.dll', 0x8cd470, 36, '808ec379a8ccec4982ee37b7f501bffcb21baa9af7b192227476865f322e7e18', {8: 0x4ec650}),
    'formClass': ('basic.dll', 0x8ccc5c, 36, '0c8ebbc447666fa24d67294f614d30ac13038d349a7f32b625bf58a7898b9ffd', {8: 0x4ee310}),
    'processingMdObject': ('basic.dll', 0x8caf18, 112, 'c78b07654012115fbd7f120a1473a9c5a8e352db032d0009135a7e1672b7ae95', {24: 0x4eabb0, 26: 0x4eac00}),
    'formMdObject': ('basic.dll', 0x8cb258, 112, '65ac9b511f21e5cfbeb310cb2ed185349dfcebf327b215c9b54c14ad03bceca3', {0: 0x7a53e8}),
    'formPersistence': ('basic.dll', 0x8cb244, 20, '238a4a879287b68f459a641786f69208ca17837cc1623ddade96c13d0849dbfd', {0: 0x7a65f9, 3: 0x79f2b0, 4: 0x79f2d0}),
    'ownMemoryRoot': ('backend.dll', 0xf15214, 120, 'a36e57717aea6b876d3426f39c4cc2f56f3b41cc2e4d4b6854e1bbdd382f43ac', {24: 0x5c6d10, 26: 0x5c6e20}),
    'ownMemoryManager': ('backend.dll', 0xede36c, 324, 'ae32b906dee0bf3c2446ac5aa14a68912f932dce373ebade2cbf850db8207fbe', {22: 0x2af940, 23: 0x2b0080, 43: 0x2b0380, 80: 0x2ae370}),
    'ownMemoryInner': ('backend.dll', 0xe553cc, 176, '092b7231ca8eb377cc3569cfb2b2bb37c7f43b8b1c380db3de7827dad52273b0', {43: 0x3dc70}),
    'formTypeEquality': ('backend.dll', 0xf1563c, 40, 'e55782a5aa9da5f4fd8c87024ae486d570fc1d23c1c361ca1e50a6cac65c7290', {9: 0x5ca280}),
}
QI_MAP = ('basic.dll', 0x8ce3f0, 84, '6bad21466eaedd615fceffce2d71b9bb711f562516515a2d15a4f68ec1bb6024')
QI_ROWS = (
    ('12BFDDD0-36CC-11D4-940F-008048DA11F9', 8, 1),
    ('45B81B41-9540-11D4-9427-008048DA11F9', 0, 1),
    (QI_IID, 4, 1),
    ('D3624077-1010-45F0-A596-77ADD399D777', 8, 1),
    ('B1303399-C60B-4584-AD50-7AE1BCB79966', 8, 1),
    ('AAD5326B-08BF-4AC1-B115-4CD314B4A11C', 8, 1),
    ('END', 0, 0),
)
RANGES = dict(FUNCTIONS)
RANGES.update({key: value[:4] for key, value in TABLES.items()})
RANGES['formQIMap'] = QI_MAP


def require(condition, code):
    if not condition:
        raise ValueError(code)


def verify_sha(data, wanted, code):
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == wanted, code)


def verify_module(name, base, data):
    require(name in MODULES and type(base) is int and base == MODULES[name][0], 'V69_MODULE_BASE_CHANGED')
    verify_sha(data, MODULES[name][1], 'V69_MODULE_SHA_CHANGED')


def read_range(pe, rva, size):
    at = pe.offset(pe.base + rva)
    return pe.data[at:at + size]


def collect_ranges(modules):
    return {key: read_range(modules[name], rva, size) for key, (name, rva, size, _) in RANGES.items()}


def verify_ranges(ranges):
    require(isinstance(ranges, dict) and set(ranges) == set(RANGES), 'V69_RANGE_SET_CHANGED')
    for key, (_, _, size, wanted) in RANGES.items():
        body = ranges[key]
        require(type(body) is bytes and len(body) == size, 'V69_RANGE_BOUNDARY_CHANGED')
        verify_sha(body, wanted, 'V69_RANGE_BYTES_CHANGED')


def collect_table_points(modules):
    return {key: (name, rva, {slot: struct.unpack_from('<I', read_range(modules[name], rva, size), slot * 4)[0]
                                    - modules[name].base for slot in slots})
            for key, (name, rva, size, _, slots) in TABLES.items()}


def verify_table_points(points):
    require(isinstance(points, dict) and set(points) == set(TABLES), 'V69_TABLE_SET_CHANGED')
    for key, (name, rva, _, _, slots) in TABLES.items():
        require(points[key] == (name, rva, slots), 'V69_TABLE_POINT_CHANGED')


def collect_qi_rows(pe):
    data = read_range(pe, QI_MAP[1], QI_MAP[2])
    rows = []
    for index in range(7):
        pointer, offset, tag = struct.unpack_from('<III', data, index * 12)
        guid = str(uuid.UUID(bytes_le=pe.data[pe.offset(pointer):pe.offset(pointer) + 16])).upper() if pointer else 'END'
        rows.append((guid, offset, tag))
    return tuple(rows)


def verify_qi_rows(rows):
    require(rows == QI_ROWS, 'V69_QI_MAP_CHANGED')


def clean_lines(text):
    return [' '.join(line.split()) for line in text.splitlines() if line.strip() and not line.strip().startswith('//')]


def verify_sdk_layout(metadata, document, extension):
    require(all(type(x) is str for x in (metadata, document, extension)), 'V69_SDK_LAYOUT_CHANGED')
    require('uint connectConfig(IConfigMngr@& res, IFile@ file, int mode, int t=0, int m=0)' in clean_lines(metadata),
            'V69_SDK_CONFIG_SIGNATURE_CHANGED')
    require('load(IInPersistenceStorage' not in metadata, 'V69_SDK_METADATA_LOAD_BINDING_CHANGED')
    require(clean_lines(extension) == [':iface AhOwnedMetadataPersistence {' + QI_IID + '}', ':virt', '+2'],
            'V69_SDK_QI_ONLY_CHANGED')
    for line in ('void save(IFile@+ file)', 'void load(IFile@+ file)', 'void setFile(IFile@+ file)', 'void close()'):
        require(line in clean_lines(document), 'V69_SDK_STORAGE_SIGNATURE_CHANGED')
    require(':iface IInPersistenceStorage {24865124-AB36-11D4-B9A4-008048DA0334}' in clean_lines(document),
            'V69_SDK_STORAGE_SIGNATURE_CHANGED')


def verify_sdk_members(members, extension):
    require(isinstance(members, dict) and set(members) == set(SDK_SHAS), 'V69_SDK_MEMBER_SET_CHANGED')
    for name, wanted in SDK_SHAS.items():
        verify_sha(members[name], wanted, 'V69_SDK_SHA_CHANGED')
    verify_sha(extension, QI_SHA, 'V69_QI_EXTENSION_SHA_CHANGED')
    verify_sdk_layout(members['modules/snegopat/v8api/metadata.v'].decode('utf-8-sig'),
                      members['modules/snegopat/v8api/document.v'].decode('utf-8-sig'), extension.decode('utf-8-sig'))


def read_sdk_members():
    with zipfile.ZipFile(CACHE / 'snegopat.zip') as archive:
        for name in SDK_SHAS:
            require(0 < archive.getinfo(name).file_size <= 65536, 'V69_SDK_MEMBER_BOUND_CHANGED')
        return {name: archive.read(name) for name in SDK_SHAS}


def verify_source_layout(parent, form):
    ns = {'m': 'http://v8.1c.ru/8.3/MDClasses'}
    p, f = ET.fromstring(parent)[0], ET.fromstring(form)[0]
    require(p.tag == '{' + ns['m'] + '}DataProcessor' and p.attrib.get('uuid') == PARENT_ID and
            p.findtext('m:Properties/m:Name', namespaces=ns) == 'КонсольЗапросовУФ', 'V69_SOURCE_PARENT_CHANGED')
    require(f.tag == '{' + ns['m'] + '}Form' and f.attrib.get('uuid') == FORM_ID and
            f.findtext('m:Properties/m:Name', namespaces=ns) == 'Настройки' and
            f.findtext('m:Properties/m:FormType', namespaces=ns) == 'Managed' and
            'Настройки' in [node.text for node in p.findall('m:ChildObjects/m:Form', ns)], 'V69_SOURCE_FORM_CHANGED')


def verify_source_bytes(parent, form):
    verify_sha(parent, PARENT_SHA, 'V69_SOURCE_SHA_CHANGED')
    verify_sha(form, FORM_SHA, 'V69_SOURCE_SHA_CHANGED')
    verify_source_layout(parent, form)


def verify_static():
    """Fixed local PE/SDK/source XML only; no runtime metadata or connections."""
    modules = {name: PE(name) for name in MODULES}
    for name, pe in modules.items():
        verify_module(name, pe.base, pe.data)
    verify_sdk_members(read_sdk_members(), QI_EXTENSION.read_bytes())
    verify_source_bytes(SOURCE_PARENT.read_bytes(), SOURCE_FORM.read_bytes())
    verify_ranges(collect_ranges(modules))
    verify_table_points(collect_table_points(modules))
    verify_qi_rows(collect_qi_rows(modules['basic.dll']))
    return {
        'stage': 'V69ProcessingFormStaticPrerequisite', 'passed': True, 'platform': '8.3.18.1208',
        'moduleShas': {name: value[1] for name, value in MODULES.items()}, 'sdkMemberShas': dict(SDK_SHAS),
        'sourceParentId': PARENT_ID, 'sourceFormId': FORM_ID, 'processingClassId': PROCESSING_CLASS, 'formClassId': FORM_CLASS,
        'sourceParentSha256': PARENT_SHA, 'sourceFormSha256': FORM_SHA, 'sourceLocalManagedCandidateVerified': True,
        'sdkMetadataPersistenceQIOnly': True, 'sdkCallableMetadataLoadDeclared': False,
        'nativeProcessingFormLoadWrapperVerified': True, 'metadataQIAddRefBeforeOutputVerified': True,
        'factoryStdcallRetBytes': 8, 'formFactoryOutputFromAllocation': 8,
        'metadataPersistenceFromMdObject': -4, 'loadStdcallRetBytes': 16,
        'loadArguments': ['selfMetadataPersistence', 'IInPersistenceStorage*', 'Vector*', 'uint32 flag'],
        'loadFlag': 1, 'loadNativeThisFromPersistence': 16, 'loadNativeTargetRva': 0x50b3a0,
        'tables': {key: {'module': name, 'rva': rva, 'slots': slots} for key, (name, rva, _, _, slots) in TABLES.items()},
        'ranges': {key: {'module': name, 'rva': rva, 'bytes': size, 'sha256': sha} for key, (name, rva, size, sha) in RANGES.items()},
        'reviewedMemoryManagerInnerOffset': 0xcc, 'nativeExtractSlot': 43, 'sdkExtractSlot42Permitted': False,
        'runtimeFactoryQIAndTableCheckRequired': True, 'runtimeSourceClassParentVersionCheckRequired': True,
        'runtimeIndependentManagerRootParentCheckRequired': True, 'runtimeFormTypeNonaliasEqualityCheckRequired': True,
        'runtimeSourceDescriptorUnchangedCheckRequired': True, 'sourceValueTransferPermitted': False,
        'crossClassDescriptorLoadPermitted': False, 'liveProcessingFormLoadProven': False,
        'deepLoadImplementationAndExceptionEdgesProven': False, 'sourceResourceClosureProven': False,
        'formTypeNonaliasProven': False, 'independentCloneProven': False, 'runtimeCacheValidated': False,
        'goldCalls': 0, 'nativeCalls': 0,
    }


if __name__ == '__main__':
    print(json.dumps(verify_static(), ensure_ascii=True, separators=(',', ':')))
