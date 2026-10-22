"""Fixed published own-object persistence prerequisite; no native execution."""
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
    'modules/snegopat/v8api/document.v': 'b1c12ef6a2d4ea9d655bd9057c7a605b2497bb6c22ddb9f6323efc3ad21c369e',
    'modules/snegopat/v8api/process.v': '92458b3e1a862051bf9b1d8b0cac750de5fddc62294324ca70a94820cdb1a9ef',
    'modules/snegopat/v8api/metadata.v': 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed',
    'modules/snegopat/v8api/file.v': 'c41ffff5ba6d270e143bbd779dcdd8d9b03d9b624611b785266ad80f05f3218a',
}
PUBLISHED_IID = '45B81B41-9540-11D4-9427-008048DA11F9'
PROCESSING_CLASS = 'BF845118-327B-4682-B5C6-285D2A0EB296'
FORM_CLASS = 'D5B0E5ED-256D-401C-9C36-F630CAFD8A62'
PERSISTENCE = {
    'IPersistableObject': (PUBLISHED_IID, ('const Guid& getCLSID()',
        'void serialize(IOutPersistenceStorage@+ storage)', 'void deserialize(IInPersistenceStorage@+ storage)')),
    'IOutPersistenceStorage': ('24865123-AB36-11D4-B9A4-008048DA0334', ('void f()',)),
    'IInPersistenceStorage': ('24865124-AB36-11D4-B9A4-008048DA0334', ('void f()',)),
    'IStreamPersistenceStorage': ('86EB9CD0-FFA0-4E4C-8134-05DCF57C253C',
        ('void setFile(IFile@+ file)', 'void open(const URL& url)', 'void close()')),
}
STORAGE_CLASSES = {
    'CLSID_StreamOutPersistenceStorage': 'E3DDF5CD-4150-41B9-9D92-8B2E7CF39DD5',
    'CLSID_StreamInPersistenceStorage': '25802095-C067-4AD9-B340-B23A2349FEC3',
}
PROCESS_METHODS = (
    '+1', 'bool createByName(const v8string&in clsName, const Guid&in iid, IUnknown@&out ppObject)',
    'bool createByClsid(const Guid&in clsid, const Guid&in iid, IUnknown@&out ppObject)',
    'bool aggregateInstance(const Guid&in clsid, IUnknown@ pOuter, IUnknown@&out ptr)',
    '+1', 'int getCategoryClasses(Vector& clsids, const Guid& clsid)', '+3',
    'bool registerService(const Guid&in, const Guid&in)', '+1',
    'IUnknown@+ getService(const Guid&in idService)', '+2', 'uint32 loadComponent(uint32 name)',
)
FACTORIES = {PROCESSING_CLASS: 0x4ec650, FORM_CLASS: 0x4ee310}
# Exact SDK and native contracts; this is not a test of strings in a parent AS file.
ABI_PROFILE = {
    'iid': PUBLISHED_IID, 'factoryConvention': 'stdcall', 'factoryRetBytes': 8,
    'persistenceConvention': 'stdcall', 'getClsidSlot': 3, 'getClsidRetBytes': 4,
    'serializeSlot': 4, 'deserializeSlot': 5, 'storageCallRetBytes': 8,
    'storageArguments': 2, 'getClsidCopy': 'Guid-by-value',
    'storageQI': 'canonical-IUnknown', 'factoryDelegateCacheKey': 'native-function-address',
    'uniqueFactoryDelegates': 2, 'metadataLoadAllowed': False,
}
FUNCTIONS = {
    'processingFactory': ('basic.dll', 0x4ec650, 184, '27ced2bd9dacb4b686a8fe35ccd7eacf34bfe8bdcac0c30212880e90a35fc673'),
    'formFactory': ('basic.dll', 0x4ee310, 192, '61ea508533f1b3b3193106f4fe39f49f2070fa2458d45158a02642fd676be3be'),
    'processingConstructor': ('basic.dll', 0x7a33d0, 100, '2c522368de1a08637987188966191d97d81f21e5c2a4ff91273c0f000affdbbc'),
    'processingQI': ('basic.dll', 0x7a33b0, 26, '9291e72bbfa3814afdcfa51fbd7dabb4982835a9c362e1097b38d5ee7027bc54'),
    'processingMdQI': ('basic.dll', 0x7a5d94, 10, 'a387655dab50549295a636af5a43026b2ae9afcc03030661b4026208dddb2d6c'),
    'processingPersistenceQI': ('basic.dll', 0x7a601a, 10, 'a0a86bcc4c886b8d5a7a8f56a1253d2fb34259cbd0060e8c53377db46e9a6e41'),
    'formQI': ('basic.dll', 0x7a3220, 26, '240dc2560f42282739c4cb782be5b1e85bf615deeaf8dccc7489b1ff70b06988'),
    'formMdQI': ('basic.dll', 0x7a53e8, 10, '570ef396a2ae153c9a4bbc12b8fff7ed8209803b2af48a56003a5bd5070ffa7c'),
    'qiHelper': ('basic.dll', 0x6ae930, 234, '97a0568cd952f0c443fe52096f4962424e7a235baf1f8f6788ed7728941f4d7f'),
    'processingGetClsid': ('basic.dll', 0x79dc50, 8, '59a4eb505c733e464c956db109fca5bccdbcd5fe3bb70474779632654d28388e'),
    'processingSerialize': ('basic.dll', 0x79dc30, 31, '9e5dd8749783972fe62c20cfb80385e7311b5e54c0576841c21c85b69d7aa3b1'),
    'processingDeserialize': ('basic.dll', 0x79dc10, 31, 'c28e197b0bfb5e8b1976210b7d2da07bd9fda611eff91f67bb3fcaa17d60a528'),
    'formGetClsid': ('basic.dll', 0x79db70, 8, '0a2c48cc2f06542e45c59f25c7f9f5d764d6d7f4f3bb373dd66350f0d65fd30a'),
    'formSerialize': ('basic.dll', 0x79d9c0, 21, 'c5ee67fb84007da7c9dea4548ef2cb22cd3a92a4535a92349d2e8e759d769ef4'),
    'formDeserialize': ('basic.dll', 0x79d9a0, 21, '8f4773dd6456a19dacddbea8a9c7ce2960a5a4609bf0606002cd3380b885aa8b'),
    'processingSerializeBody': ('basic.dll', 0x4e9040, 506, '067a4079fab2dcb18326405363e1d82bf641112609afce0355baeb2644900cad'),
    'processingDeserializeBody': ('basic.dll', 0x4e9240, 798, '1443c1c9c1fe0ea996445e6f0890dcde54bbcd45d23fb5123539ab6b21ecbd49'),
    'formSerializeBody': ('basic.dll', 0x4ed4d0, 552, '24bf79416ee8b7117cb86f8bc99948127c0911b1f37042cae6af980d0b1c0f8f'),
    'formDeserializeBody': ('basic.dll', 0x4ed700, 798, '5d32cf78cb4f04f4c708f6150a937dd0e00b79557d6819014f2104e2d0d5c89a'),
    'currentProcess': ('core83.dll', 0x1df6c0, 13, '350ffc6e1613ad41ba15f029b1fea8ff364933d736c06002d0e0636d814aaa6d'),
}
TABLES = {
    'processingFactoryClass': ('basic.dll', 0x8cd470, 36, '808ec379a8ccec4982ee37b7f501bffcb21baa9af7b192227476865f322e7e18', {8: 0x4ec650}),
    'formFactoryClass': ('basic.dll', 0x8ccc5c, 36, '0c8ebbc447666fa24d67294f614d30ac13038d349a7f32b625bf58a7898b9ffd', {8: 0x4ee310}),
    'processingPublishedPersistence': ('basic.dll', 0x8cab54, 24, 'f4ff85526a938e182df07ff15038719ca76d7202fbb312842c156882000f636e',
        {0: 0x7a601a, 1: 0x7a6152, 2: 0x7a56e4, 3: 0x79dc50, 4: 0x79dc30, 5: 0x79dc10}),
    'formPublishedPersistence': ('basic.dll', 0x8cacf0, 24, '7a2f18612f8f826d61ac085ff0f1ea14eb1c8291bbb73aee2ce2126e769b6590',
        {0: 0x7a3220, 1: 0x6b6b40, 2: 0x6b6b10, 3: 0x79db70, 4: 0x79d9c0, 5: 0x79d9a0}),
    'processingMdObject': ('basic.dll', 0x8caf18, 112, 'c78b07654012115fbd7f120a1473a9c5a8e352db032d0009135a7e1672b7ae95', {0: 0x7a5d94, 24: 0x4eabb0, 26: 0x4eac00}),
    'formMdObject': ('basic.dll', 0x8cb258, 112, '65ac9b511f21e5cfbeb310cb2ed185349dfcebf327b215c9b54c14ad03bceca3', {0: 0x7a53e8}),
    'ownMemoryRoot': ('backend.dll', 0xf15214, 120, 'a36e57717aea6b876d3426f39c4cc2f56f3b41cc2e4d4b6854e1bbdd382f43ac', {24: 0x5c6d10, 26: 0x5c6e20}),
}
QI_MAPS = {
    'processingQIMap': (0x8ce6d0, 180, 'c912254f0d10922c371820e52f076c872e8a0e21edad68224d5f35af09e1e1e4', 4, 8),
    'formQIMap': (0x8ce3f0, 84, '6bad21466eaedd615fceffce2d71b9bb711f562516515a2d15a4f68ec1bb6024', 8, 0),
}
QI_ROWS = {
    'processingQIMap': (
        ('12BFDDD0-36CC-11D4-940F-008048DA11F9', 4, 1),
        ('97AF18E0-53EC-11D4-9416-008048DA11F9', 0, 1), (PUBLISHED_IID, 8, 1),
        ('4285C446-A958-4550-8475-ECAD7766DCB2', 16, 1),
        ('D3624077-1010-45F0-A596-77ADD399D777', 4, 1),
        ('310A0593-242B-11D5-B979-0050BAE0A95D', 4, 1),
        ('65DDAB4D-8D5B-4050-960A-AC83CBAB209C', 12, 1),
        ('2A77206E-BE68-4EA7-9352-1DB0F0489E10', 4, 1),
        ('C808FC72-A8BE-4310-8654-35213EF291E6', 40, 1),
        ('2CF91738-C0DE-4DEC-B573-15227A59AB7A', 20, 1),
        ('50F369F2-56D8-4B12-9D8A-455B96A91982', 44, 1),
        ('C498D391-9F4F-441E-8040-A570F5176C9C', 48, 1),
        ('912C5777-F404-41B1-8BF2-E3C3DCF2C696', 56, 1),
        ('542FF310-5814-4C97-A5B6-028C1FD9117C', 64, 1), ('END', 0, 0)),
    'formQIMap': (
        ('12BFDDD0-36CC-11D4-940F-008048DA11F9', 8, 1), (PUBLISHED_IID, 0, 1),
        ('4285C446-A958-4550-8475-ECAD7766DCB2', 4, 1),
        ('D3624077-1010-45F0-A596-77ADD399D777', 8, 1),
        ('B1303399-C60B-4584-AD50-7AE1BCB79966', 8, 1),
        ('AAD5326B-08BF-4AC1-B115-4CD314B4A11C', 8, 1), ('END', 0, 0)),
}
SERIALIZATION_CLASSES = {
    'processingSerializationClass': (0x8cda80, '7B9317D2-BF20-4534-99CE-364C86A45916'),
    'formSerializationClass': (0x8cdae0, 'FCDD75D2-4A14-42AB-B179-A76DBA40DC86'),
}
RANGES = dict(FUNCTIONS)
RANGES.update({key: value[:4] for key, value in TABLES.items()})
RANGES.update({key: ('basic.dll', value[0], value[1], value[2]) for key, value in QI_MAPS.items()})


def require(condition, code):
    if not condition:
        raise ValueError(code)


def exact_equal(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(exact_equal(actual[k], v) for k, v in expected.items())
    if isinstance(expected, (tuple, list)):
        return len(actual) == len(expected) and all(exact_equal(a, e) for a, e in zip(actual, expected))
    return actual == expected


def verify_abi_profile(profile):
    require(exact_equal(profile, ABI_PROFILE), 'V71_ABI_PROFILE_CHANGED')


def factory_registration_plan(classes):
    """Describe required address-keyed registrations for two own graphs.

    This pure plan does not register or execute delegates. Actual AS caching
    and self-pointer checks remain runtime preconditions for the parent.
    """
    require(type(classes) in (tuple, list) and len(classes) == 4 and
            all(type(c) is str and c in FACTORIES for c in classes) and
            all(classes.count(c) == 2 for c in FACTORIES), 'V71_FACTORY_PROFILE_CHANGED')
    seen = set()
    result = []
    for clsid in classes:
        address = FACTORIES[clsid]
        result.append((clsid, address, address not in seen))
        seen.add(address)
    return tuple(result)


def clean_lines(text):
    return [' '.join(line.split()) for line in text.splitlines()
            if line.strip() and not line.strip().startswith('//')]


def verify_interface(text, kind, name, guid, methods):
    require(type(text) is str, 'V71_SDK_INTERFACE_CHANGED')
    match = re.search(r'(?m)^:' + kind + ' ' + re.escape(name) + r'\s+\{([^}]+)\}\s*$', text)
    require(match is not None and match.group(1) == guid, 'V71_SDK_INTERFACE_CHANGED')
    tail = text[match.end():]
    boundary = re.search(r'(?m)^:(?:iface|service|class|struct|global|guid)\b', tail)
    lines = clean_lines(tail[:boundary.start()] if boundary else tail)
    require(lines == [':virt', *methods], 'V71_SDK_PROTOTYPE_CHANGED')


def verify_sdk_layout(document, process, metadata, file):
    require(all(type(x) is str for x in (document, process, metadata, file)), 'V71_SDK_LAYOUT_CHANGED')
    for name, (guid, methods) in PERSISTENCE.items():
        verify_interface(document, 'iface', name, guid, methods)
    for name, guid in STORAGE_CLASSES.items():
        require(re.search(r'(?m)^:guid ' + name + r'\s+\{' + guid + r'\}\s*$', document) is not None,
                'V71_STREAM_CLASS_CHANGED')
    verify_interface(process, 'service', 'SCOM_Process', 'EBF766A9-F32C-11D3-9851-008048DA1252', PROCESS_METHODS)
    require(('SCOM_Process@ currentProcess()|?current_process@core@@YAPAVSCOM_Process@1@XZ'
             '|?current_process@core@@YAPEAVSCOM_Process@1@XZ') in clean_lines(process), 'V71_PROCESS_BINDING_CHANGED')
    require('uint connectConfig(IConfigMngr@& res, IFile@ file, int mode, int t=0, int m=0)' in clean_lines(metadata),
            'V71_MEMORY_CONFIG_SIGNATURE_CHANGED')
    require(re.search(r'(?m)^:guid CLSID_MemoryFile\s+\{C1AF3F04-620A-40BC-8CA8-F6089B4A46F5\}\s*$', file) is not None,
            'V71_MEMORY_CLASS_CHANGED')


def read_sdk_members():
    with zipfile.ZipFile(CACHE / 'snegopat.zip') as archive:
        for name in SDK_SHAS:
            require(0 < archive.getinfo(name).file_size <= 65536, 'V71_SDK_MEMBER_BOUND_CHANGED')
        return {name: archive.read(name) for name in SDK_SHAS}


def verify_sdk_members(members):
    require(type(members) is dict and members.keys() == SDK_SHAS.keys(), 'V71_SDK_MEMBER_SET_CHANGED')
    for name, wanted in SDK_SHAS.items():
        require(type(members[name]) is bytes and hashlib.sha256(members[name]).hexdigest() == wanted, 'V71_SDK_SHA_CHANGED')
    verify_sdk_layout(*(members['modules/snegopat/v8api/' + name + '.v'].decode('utf-8-sig')
                        for name in ('document', 'process', 'metadata', 'file')))


def verify_module(name, base, data):
    require(name in MODULES and type(base) is int and base == MODULES[name][0], 'V71_MODULE_BASE_CHANGED')
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == MODULES[name][1], 'V71_MODULE_SHA_CHANGED')


def read_range(pe, rva, size):
    at = pe.offset(pe.base + rva)
    return pe.data[at:at + size]


def collect_ranges(modules):
    return {key: read_range(modules[module], rva, size) for key, (module, rva, size, _) in RANGES.items()}


def verify_ranges(ranges):
    require(type(ranges) is dict and ranges.keys() == RANGES.keys(), 'V71_RANGE_SET_CHANGED')
    for key, (_, _, size, wanted) in RANGES.items():
        body = ranges[key]
        require(type(body) is bytes and len(body) == size, 'V71_RANGE_BOUNDARY_CHANGED')
        require(hashlib.sha256(body).hexdigest() == wanted, 'V71_RANGE_BYTES_CHANGED')


def collect_slots(modules):
    return {key: (module, rva, {slot: struct.unpack_from('<I', read_range(modules[module], rva, size), slot * 4)[0]
                              - modules[module].base for slot in slots})
            for key, (module, rva, size, _, slots) in TABLES.items()}


def verify_slots(slots):
    expected = {key: (module, rva, points) for key, (module, rva, _, _, points) in TABLES.items()}
    require(exact_equal(slots, expected), 'V71_PUBLISHED_TABLE_CHANGED')


def collect_qi_rows(pe):
    result = {}
    for key, (rva, size, _, _, _) in QI_MAPS.items():
        body = read_range(pe, rva, size)
        rows = []
        for i in range(size // 12):
            pointer, offset, tag = struct.unpack_from('<III', body, i * 12)
            guid = str(uuid.UUID(bytes_le=pe.data[pe.offset(pointer):pe.offset(pointer) + 16])).upper() if pointer else 'END'
            rows.append((guid, offset, tag))
        result[key] = tuple(rows)
    return result


def verify_qi_rows(rows):
    require(exact_equal(rows, QI_ROWS), 'V71_PUBLISHED_QI_CHANGED')


def collect_serialization_guids(pe):
    return {key: str(uuid.UUID(bytes_le=read_range(pe, rva, 16))).upper()
            for key, (rva, _) in SERIALIZATION_CLASSES.items()}


def verify_serialization_guids(guids):
    require(exact_equal(guids, {key: value[1] for key, value in SERIALIZATION_CLASSES.items()}), 'V71_SERIALIZATION_CLSID_CHANGED')


def verify_static():
    """Validate exact SDK members/PE bytes only; never traverse runtime assets."""
    modules = {name: PE(name) for name in MODULES}
    for name, pe in modules.items():
        verify_module(name, pe.base, pe.data)
    verify_sdk_members(read_sdk_members())
    verify_abi_profile(dict(ABI_PROFILE))
    verify_ranges(collect_ranges(modules))
    verify_slots(collect_slots(modules))
    verify_qi_rows(collect_qi_rows(modules['basic.dll']))
    verify_serialization_guids(collect_serialization_guids(modules['basic.dll']))
    return {
        'stage': 'V71PublishedOwnedPersistenceStaticPrerequisite', 'passed': True, 'platform': '8.3.18.1208',
        'moduleShas': {key: value[1] for key, value in MODULES.items()}, 'sdkMemberShas': dict(SDK_SHAS),
        'publishedInterface': PUBLISHED_IID, 'abiProfile': dict(ABI_PROFILE),
        'tables': {key: {'module': module, 'rva': rva, 'slots': slots} for key, (module, rva, _, _, slots) in TABLES.items()},
        'ranges': {key: {'module': module, 'rva': rva, 'bytes': size, 'sha256': sha} for key, (module, rva, size, sha) in RANGES.items()},
        'serializationClasses': {key: value[1] for key, value in SERIALIZATION_CLASSES.items()},
        'processingFactoryOutputFromAllocation': 4, 'formFactoryOutputFromAllocation': 8,
        'processingPublishedPersistenceFromMdObject': 4, 'formPublishedPersistenceFromMdObject': -8,
        'processingPersistenceNativeThisAdjustment': 0x48, 'formPersistenceNativeThisAdjustment': 0x14,
        'publishedQIAddRefBeforeOutputVerified': True, 'formDeserializeIsAbortStub': False,
        'processingDeserializeIsAbortStub': False, 'deserializeTargetBodiesPinned': True,
        'serializeDeserializeDeepCalleesAndExceptionEdgesFullyProven': False,
        'runtimeFactoryDelegateCacheRequired': True, 'runtimeDelegateRegistrationProven': False,
        'runtimeTwoOwnMemoryManagersRequired': True, 'runtimeSameOwnUuidClassParentRequired': True,
        'runtimeTypedUnknownStorageQIRequired': True, 'runtimeClsidCopyByValueAndPairEqualityRequired': True,
        'runtimeLifecyclePhaseReceiptsRequired': True, 'runtimeFactoryAndPublishedTableGuardsRequired': True,
        'metadataPersistenceLoadPermitted': False, 'goldDescriptorOrFormTypePermitted': False,
        'publishedOwnRoundtripProven': False, 'ownScopeDestructionProven': False,
        'independentBackingCloneProven': False, 'formCreationProven': False, 'runtimeCacheValidated': False,
        'goldCalls': 0, 'nativeCalls': 0,
    }


if __name__ == '__main__':
    print(json.dumps(verify_static(), ensure_ascii=True, separators=(',', ':')))
