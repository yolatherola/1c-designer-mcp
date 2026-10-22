"""Fixed-build SDK/persistence prerequisites only; never load or call a DLL."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import zipfile

HERE = Path(__file__).resolve().parent
CACHE = HERE.parents[3] / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40'
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from repository_pe_probe import PE

CORE_SHA256 = '46e7019a142a01367d27c28b646ce8defea54ad60afe9fc467738b75c8663f14'
IMAGE_BASE = 0x10020000
SDK_SHAS = {
    'modules/snegopat/v8api/document.v': 'b1c12ef6a2d4ea9d655bd9057c7a605b2497bb6c22ddb9f6323efc3ad21c369e',
    'modules/snegopat/v8api/process.v': '92458b3e1a862051bf9b1d8b0cac750de5fddc62294324ca70a94820cdb1a9ef',
    'modules/snegopat/v8api/value.v': 'c99b23ab9d0f81493f138f7bac66b96019ab9c69fd121202beab352772534288',
    'modules/snegopat/engine/com_v8value.as': '4c90e1ca9efd414e164a1f54fe1cc6ca6924da9eab713c8db4ca661e443f3276',
}
# SDK order is checked without guessing native vtable slots/addresses.
PERSISTENCE = {
    'IPersistableObject': ('45B81B41-9540-11D4-9427-008048DA11F9', (
        'const Guid& getCLSID()', 'void serialize(IOutPersistenceStorage@+ storage)',
        'void deserialize(IInPersistenceStorage@+ storage)')),
    'IOutPersistenceStorage': ('24865123-AB36-11D4-B9A4-008048DA0334', ('void f()',)),
    'IInPersistenceStorage': ('24865124-AB36-11D4-B9A4-008048DA0334', ('void f()',)),
    'IStreamPersistenceStorage': ('86EB9CD0-FFA0-4E4C-8134-05DCF57C253C', (
        'void setFile(IFile@+ file)', 'void open(const URL& url)', 'void close()')),
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
PROCESS_BINDING = ('SCOM_Process@ currentProcess()|?current_process@core@@YAPAVSCOM_Process@1@XZ'
                   '|?current_process@core@@YAPEAVSCOM_Process@1@XZ')
VALUE_BINDING = ('void ctor(IValue@)|??0Value@core@@QAE@PAVIValue@1@@Z'
                 '|??0Value@core@@QEAA@PEAVIValue@1@@Z')
EXPORTS = {
    'iValueCtor': ('??0Value@core@@QAE@PAVIValue@1@@Z', 0x1f1f50),
    'currentProcess': ('?current_process@core@@YAPAVSCOM_Process@1@XZ', 0x1df6c0),
}
# Whole functions through their ret4/ret0, not selected opcode snippets.
FUNCTIONS = {
    'iValueCtor': (0x1f1f50, 85, '04b417d750150106292d474ea4ba1053492b0cff3c2d9287fa6db326a355ce49'),
    'currentProcess': (0x1df6c0, 13, '350ffc6e1613ad41ba15f029b1fea8ff364933d736c06002d0e0636d814aaa6d'),
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def clean_lines(text):
    return [' '.join(line.split()) for line in text.splitlines()
            if line.strip() and not line.strip().startswith('//')]


def verify_interface(text, kind, name, guid, methods):
    require(type(text) is str, 'V68_SDK_INTERFACE_CHANGED')
    header = re.search(r'(?m)^:' + kind + r' ' + re.escape(name) + r'\s+\{([^}]+)\}\s*$', text)
    require(header is not None and header.group(1) == guid, 'V68_SDK_INTERFACE_CHANGED')
    tail = text[header.end():]
    boundary = re.search(r'(?m)^:(?:iface|service|class|struct|global|guid)\b', tail)
    block = tail[:boundary.start()] if boundary else tail
    lines = clean_lines(block)
    require(lines and lines[0] == ':virt' and tuple(lines[1:]) == tuple(methods),
            'V68_SDK_PROTOTYPE_CHANGED')


def verify_document_layout(text):
    for name, (guid, methods) in PERSISTENCE.items():
        verify_interface(text, 'iface', name, guid, methods)
    for name, guid in STORAGE_CLASSES.items():
        pattern = r'(?m)^:guid ' + re.escape(name) + r'\s+\{' + re.escape(guid) + r'\}\s*$'
        require(re.search(pattern, text) is not None, 'V68_STORAGE_CLASS_CHANGED')


def verify_process_layout(text):
    verify_interface(text, 'service', 'SCOM_Process', 'EBF766A9-F32C-11D3-9851-008048DA1252',
                     PROCESS_METHODS)
    require(PROCESS_BINDING in clean_lines(text), 'V68_PROCESS_BINDING_CHANGED')


def verify_value_layout(text):
    require(type(text) is str, 'V68_VALUE_LAYOUT_CHANGED')
    match = re.search(r'(?m)^:class Value\s*\r?\n:props\s*\r?\n(.*?)^:dlls\s*$', text, re.S)
    require(match is not None and clean_lines(match.group(1)) == ['int_ptr vtable', 'IValue@ pValue'],
            'V68_VALUE_LAYOUT_CHANGED')
    value_block = text[match.start():text.index('// Type', match.end())]
    require(VALUE_BINDING in clean_lines(value_block), 'V68_VALUE_BINDING_CHANGED')
    verify_interface(text, 'iface', 'IValue', 'FD7B6CC3-DC8E-11D2-B8D0-008048DA0335', (
        'IType@ getType()', '+1', 'bool getBool(bool& out)', 'bool getNumeric(Numeric& out)',
        'bool getString(v8string& out)', 'bool getDate(Date& out)', 'bool isEqual(IValue& in)'))


def verify_qi_source(text):
    require(type(text) is str, 'V68_QI_SOURCE_CHANGED')
    pattern = ('IPersistableObject&& pers = cast<IUnknown>(value.pValue);\n'
               'if (pers !is null)\n'
               'result.insertLast("Guid сериализации: " + pers.getCLSID());')
    require(pattern in '\n'.join(clean_lines(text)), 'V68_QI_SOURCE_CHANGED')


def verify_sdk_members(members):
    require(isinstance(members, dict) and set(members) == set(SDK_SHAS), 'V68_SDK_MEMBER_SET_CHANGED')
    for name, wanted in SDK_SHAS.items():
        require(type(members[name]) is bytes and hashlib.sha256(members[name]).hexdigest() == wanted,
                'V68_SDK_SHA_CHANGED')
    verify_document_layout(members['modules/snegopat/v8api/document.v'].decode('utf-8-sig'))
    verify_process_layout(members['modules/snegopat/v8api/process.v'].decode('utf-8-sig'))
    verify_value_layout(members['modules/snegopat/v8api/value.v'].decode('utf-8-sig'))
    verify_qi_source(members['modules/snegopat/engine/com_v8value.as'].decode('utf-8-sig'))


def read_sdk_members():
    with zipfile.ZipFile(CACHE / 'snegopat.zip') as archive:
        for name in SDK_SHAS:
            require(0 < archive.getinfo(name).file_size <= 65536, 'V68_SDK_MEMBER_BOUND_CHANGED')
        return {name: archive.read(name) for name in SDK_SHAS}


def verify_core_bytes(data):
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == CORE_SHA256, 'V68_CORE_SHA_CHANGED')


def export_map(pe):
    data = pe.data
    nt = struct.unpack_from('<I', data, 60)[0]
    directory = pe.offset(pe.base + struct.unpack_from('<I', data, nt + 24 + 96)[0])
    count = struct.unpack_from('<I', data, directory + 24)[0]
    functions, names, ordinals = struct.unpack_from('<III', data, directory + 28)
    result = {}
    for index in range(count):
        name_rva = struct.unpack_from('<I', data, pe.offset(pe.base + names) + index * 4)[0]
        at = pe.offset(pe.base + name_rva)
        name = data[at:data.index(0, at)].decode('ascii')
        ordinal = struct.unpack_from('<H', data, pe.offset(pe.base + ordinals) + index * 2)[0]
        result[name] = struct.unpack_from('<I', data, pe.offset(pe.base + functions) + ordinal * 4)[0]
    return result


def verify_exports(mapping):
    require(isinstance(mapping, dict), 'V68_EXPORT_CHANGED')
    for name, rva in EXPORTS.values():
        require(type(mapping.get(name)) is int and mapping[name] == rva, 'V68_EXPORT_CHANGED')


def collect_function_bytes(pe):
    return {key: pe.data[pe.offset(pe.base + rva):pe.offset(pe.base + rva) + size]
            for key, (rva, size, _) in FUNCTIONS.items()}


def verify_function_bytes(bodies):
    require(isinstance(bodies, dict) and set(bodies) == set(FUNCTIONS), 'V68_FUNCTION_SET_CHANGED')
    for key, (_, size, wanted) in FUNCTIONS.items():
        body = bodies[key]
        require(type(body) is bytes and len(body) == size, 'V68_FUNCTION_BOUNDARY_CHANGED')
        require(hashlib.sha256(body).hexdigest() == wanted, 'V68_FUNCTION_BYTES_CHANGED')


def verify_image_base(base):
    require(type(base) is int and base == IMAGE_BASE, 'V68_CORE_BASE_CHANGED')


def verify_static():
    """Read only exact SDK members and core83 PE; no runtime traversal/settings."""
    pe = PE('core83.dll')
    verify_core_bytes(pe.data)
    verify_image_base(pe.base)
    verify_sdk_members(read_sdk_members())
    verify_exports(export_map(pe))
    verify_function_bytes(collect_function_bytes(pe))
    return {
        'stage': 'V68OwnedValuePersistenceStaticPrerequisite', 'passed': True,
        'platform': '8.3.18.1208', 'moduleSha256': CORE_SHA256, 'sdkMemberShas': dict(SDK_SHAS),
        'runtimeCacheValidated': False, 'sdkPersistencePrototypesVerified': True,
        'sdkCreateByClsidPrototypeVerified': True, 'sdkCanonicalQIExampleVerified': True,
        'serializationClsidGetter': 'IPersistableObject.getCLSID', 'typeClsidSubstitutionAllowed': False,
        'valueBytes': 8, 'vtableOffset': 0, 'pValueOffset': 4,
        'iValueCtorThiscall': True, 'iValueCtorRetBytes': 4, 'iValueCtorAddsRef': True,
        'iValueCtorSharesPassedIValue': True, 'nullIValueCreatesUndefined': True,
        'currentProcessCdecl': True, 'currentProcessRetBytes': 0,
        'exports': {key: {'name': name, 'rva': rva} for key, (name, rva) in EXPORTS.items()},
        'functions': {key: {'rva': rva, 'bytes': size, 'sha256': sha}
                      for key, (rva, size, sha) in FUNCTIONS.items()},
        'manualPersistenceSlotsProven': False, 'nativeQIIdentityRetentionProven': False,
        'sourceSerializationClsidMeasured': False, 'sourceSerializeSupportedProven': False,
        'sourceFactoryClassAllowed': False, 'freshFactoryIValueProven': False,
        'deserializeRoundtripProven': False, 'independentCloneProven': False,
        'formSetterProven': False, 'goldCalls': 0, 'nativeCalls': 0,
    }


if __name__ == '__main__':
    print(json.dumps(verify_static(), ensure_ascii=True, separators=(',', ':')))
