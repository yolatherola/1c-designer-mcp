"""Read-only, fixed-build core::Value ownership contract; never load a DLL."""
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
SDK_SHA256 = 'c99b23ab9d0f81493f138f7bac66b96019ab9c69fd121202beab352772534288'
SDK_MEMBER = 'modules/snegopat/v8api/value.v'
IMAGE_BASE = 0x10020000
VALUE_VTABLE_RVA = 0x2a8150
EXPORTS = {
    'defaultCtor': ('??0Value@core@@QAE@XZ', 0x1f1ba0),
    'constCopyCtor': ('??0Value@core@@QAE@ABV01@@Z', 0x1f1bb0),
    'assignment': ('??4Value@core@@QAEAAV01@ABV01@@Z', 0x1f2030),
    'dtor': ('??1Value@core@@QAE@XZ', 0x1f1fe0),
    'clear': ('?clear@GenericValue@core@@QAEXXZ', 0x1efce0),
    'setIValue': ('?setIValue@Value@core@@UAEXPAVIValue@2@@Z', 0x1f2140),
}
# Entire functions, including their ret/ret4. No selected-instruction-only pin.
FUNCTIONS = {
    'defaultCtor': (0x1f1ba0, 16, 'c6081adc34c693ec101380221b2690e462d153ec7efd053d405d6d4dbb117432'),
    'constCopyCtor': (0x1f1bb0, 85, '94694f809e31202a5f57306a784b1a2bde7ce57267d33a1b99ad269628a1a0b8'),
    'assignment': (0x1f2030, 86, 'd4df8f4a05becc97d13e2421f31f2fa4344592b0b2d1b185ea65b626174f9d8d'),
    'dtor': (0x1f1fe0, 68, '468cc4779e22e02762e2169c8dee4e64b8741f1954735a5460ae4befb7607ae0'),
    'clear': (0x1efce0, 10, '01a8197d1e1dba0fcfe5e2fff130412351ab3bced740960e3cbcfbf7c748da8d'),
    'setIValue': (0x1f2140, 44, '44ee127d1f88b85da2b6e39df7ea4e0fa017b688ae1d1ef583662dc088880fa4'),
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def verify_core_bytes(data):
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == CORE_SHA256,
            'V67_CORE_SHA_CHANGED')


def verify_sdk_layout(text):
    require(type(text) is str, 'V67_SDK_LAYOUT_CHANGED')
    match = re.search(r'(?m)^:class Value\s*\r?\n:props\s*\r?\n(.*?)^:dlls\s*$', text, re.S)
    require(match is not None, 'V67_SDK_LAYOUT_CHANGED')
    fields = [line.strip() for line in match.group(1).splitlines() if line.strip()]
    require(fields == ['int_ptr vtable', 'IValue@ pValue'], 'V67_SDK_LAYOUT_CHANGED')
    value_block = text[match.start():text.index('// Type', match.end())]
    for declaration in (
        'void ctor(const Value&in)|??0Value@core@@QAE@ABV01@@Z',
        'Value& opAssign(const Value&in)|??4Value@core@@QAEAAV01@ABV01@@Z',
        'void ctor()|??0Value@core@@QAE@XZ',
        'void dtor()|??1Value@core@@QAE@XZ',
        'void clear()|?clear@GenericValue@core@@QAEXXZ',
    ):
        require(declaration in value_block, 'V67_SDK_BINDING_CHANGED')


def verify_sdk_bytes(data):
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == SDK_SHA256,
            'V67_SDK_SHA_CHANGED')
    verify_sdk_layout(data.decode('utf-8-sig'))


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
    require(isinstance(mapping, dict), 'V67_EXPORT_CHANGED')
    for name, rva in EXPORTS.values():
        require(type(mapping.get(name)) is int and mapping[name] == rva, 'V67_EXPORT_CHANGED')


def collect_function_bytes(pe):
    return {key: pe.data[pe.offset(pe.base + rva):pe.offset(pe.base + rva) + size]
            for key, (rva, size, _) in FUNCTIONS.items()}


def verify_function_bytes(bodies):
    require(isinstance(bodies, dict) and set(bodies) == set(FUNCTIONS), 'V67_FUNCTION_SET_CHANGED')
    for key, (_, size, wanted) in FUNCTIONS.items():
        body = bodies[key]
        require(type(body) is bytes and len(body) == size, 'V67_FUNCTION_BOUNDARY_CHANGED')
        require(hashlib.sha256(body).hexdigest() == wanted, 'V67_FUNCTION_BYTES_CHANGED')


def verify_vtable(base, vtable_rva, slot0_address):
    require(type(base) is int and base == IMAGE_BASE and
            type(vtable_rva) is int and vtable_rva == VALUE_VTABLE_RVA and
            type(slot0_address) is int and slot0_address == base + EXPORTS['setIValue'][1],
            'V67_CLEAR_VTABLE_CHANGED')


def verify_static():
    """Validate only the fixed SDK archive member and installed PE file.

    Runtime preparation has its own guard. This narrow gate does not traverse
    cache assets or read runtime metadata, settings or connection files.
    Never starts a process, loads a native module or persists files.
    """
    pe = PE('core83.dll')
    verify_core_bytes(pe.data)
    with zipfile.ZipFile(CACHE / 'snegopat.zip') as archive:
        sdk = archive.read(SDK_MEMBER)
    verify_sdk_bytes(sdk)
    verify_exports(export_map(pe))
    verify_function_bytes(collect_function_bytes(pe))
    slot0 = struct.unpack_from('<I', pe.data, pe.offset(pe.base + VALUE_VTABLE_RVA))[0]
    verify_vtable(pe.base, VALUE_VTABLE_RVA, slot0)
    return {
        'stage': 'V67OwnedValueStaticContract', 'passed': True, 'platform': '8.3.18.1208',
        'module': 'core83.dll', 'moduleSha256': CORE_SHA256, 'sdkValueSha256': SDK_SHA256,
        'runtimeCacheValidated': False,
        'valueBytes': 8, 'vtableOffset': 0, 'pValueOffset': 4, 'valueVtableRva': VALUE_VTABLE_RVA,
        'exports': {key: {'name': name, 'rva': rva} for key, (name, rva) in EXPORTS.items()},
        'functions': {key: {'rva': rva, 'bytes': size, 'sha256': sha}
                      for key, (rva, size, sha) in FUNCTIONS.items()},
        'thiscall': True, 'copyArgumentConst': True, 'copyAddsRef': True,
        'copySharesIValue': True, 'assignmentAddsRefBeforeRelease': True,
        'selfAssignmentSafe': True, 'clearReplacesWithUndefined': True,
        'dtorReleasesIValue': True, 'dtorZerosPointer': False,
        'independentCloneProven': False, 'formTypeImmutableProven': False,
        'formSetterProven': False, 'callbackLifetimeProven': False,
        'goldCalls': 0, 'nativeCalls': 0,
    }


if __name__ == '__main__':
    print(json.dumps(verify_static(), ensure_ascii=True, separators=(',', ':')))
