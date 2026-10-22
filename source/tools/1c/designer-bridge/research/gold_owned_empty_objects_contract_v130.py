"""Closed primary normal branches for OWN empty Document/Catalog, no permit."""
import hashlib
import json
from pathlib import Path
import re
import struct

from repository_pe_probe import PE

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE = HERE.parent / 'tests/NativeGoldOwnedEmptyObjectsV130.as'
SOURCE_SHA = '88e6080a54c1b1252e1c8e581f9d3517c3fb1550062b9f90ad832550477bb521'
READ_HELPER = HERE.parent / 'tests/NativeGoldOwnedConstantV99.as'
READ_HELPER_SHA = '6249c98886947d95a5f229923a75d5d5ec7bde0a07ca228bc7a5ed0e194d0799'
CATALOG_OBSERVATION = ROOT / 'artifacts/designer-bridge/v130-catalog-factory-primary-observation-35ea1c41be3f4d529d07c055871dcb5b.json'
CATALOG_OBSERVATION_SHA = 'eccc7cd52eab4cb47ab393195b61443d776f0ba9e68058890e9d1ab520d173e6'
RANGES = {
    'documentFactory': ('basic.dll', 0x4c2410, 184, '683a21ea7a8a6c504b3895918eb0c2f08e9bbd7287a0a886f96daa24e1d9558c'),
    'catalogFactory': ('basic.dll', 0x4dfee0, 184, '273200f9a47878ac310afd98a53826d061cc9ad9d2f96c308def3ceaddef9f89'),
    'documentCtor': ('basic.dll', 0x79bcd0, 250, 'f827ab1e7ed2aa3cd00d19119f106408e7b0dc202a064bc94fcf2d30b5198dc4'),
    'catalogCtor': ('basic.dll', 0x7a3790, 283, '5b4be7d17b854d24e53d08a81199c12b97ded63963d7f88ce8071051b7ea2208'),
    'documentClassTable': ('basic.dll', 0x8c7fcc, 108, '0af121bf6f172d9507a9d3f689185bb7bb4491ef0a04c82da91ba6d162d2bcff'),
    'catalogClassTable': ('basic.dll', 0x8cc910, 108, 'd320d75dd96b3106fd5a0f5a3946ed26768ea49fe03929e4f7280377488b4c68'),
    'documentObjectTable': ('basic.dll', 0x8c7130, 148, '537348ea62224d1d603a81949f146b38b4f2ed3bd486fcbd291e4a48fa3f2826'),
    'catalogObjectTable': ('basic.dll', 0x8ca0c0, 148, 'e8c7bffd0aaaa02f019a154be25e0e1f9b6cf5e4a3b24e07ef2b22b6e38d851b'),
    'rootObjectTable': ('backend.dll', 0xf15214, 120, 'a36e57717aea6b876d3426f39c4cc2f56f3b41cc2e4d4b6854e1bbdd382f43ac'),
    'rootAttach': ('backend.dll', 0x5c6d10, 154, '881ef63135002cae2533235d557143407f9be9263f842a9113549ae06ba2b30e'),
    'rootDelete': ('backend.dll', 0x5c6e20, 138, 'a714c4fe4cb593b913cf24fde60cf18da15fd0baac2a9813b8548f67e87ea103'),
    'documentQiMap': ('basic.dll', 0x8c8830, 16, '42cf0d1e884795387db9d86a2f0a1c1369e438630aa07a8f2c7b7f645efa55e8'),
    'catalogQiMap': ('basic.dll', 0x8ce900, 16, '42cf0d1e884795387db9d86a2f0a1c1369e438630aa07a8f2c7b7f645efa55e8'),
    'rootQiMap': ('backend.dll', 0xf16b78, 16, 'ab4cfdba8c7c8e156b185d3749d4a069c4d9dda3b49ecb6c848a46444e4c225c'),
    'managerQiMap': ('backend.dll', 0xede744, 16, '8d3eac165b396bf127a10840ffa504c7e6ae8dce643cfd1660d5bab40ca231db'),
    'basicUnknownDetector': ('basic.dll', 0x6ae900, 48, '595d8cfdd27660f94dba10cc8c33aa2404e2e86fab71223893013a9ead9de028'),
    'backendUnknownDetector': ('backend.dll', 0x966460, 48, '595d8cfdd27660f94dba10cc8c33aa2404e2e86fab71223893013a9ead9de028'),
    'basicCommonQi': ('basic.dll', 0x6ae930, 240, 'a7a1643ca72eb8dda018a9c6a72a7c5e8c8aeacd614a56d4ea669a29989e48c8'),
    'backendCommonQi': ('backend.dll', 0x966490, 240, 'a7a1643ca72eb8dda018a9c6a72a7c5e8c8aeacd614a56d4ea669a29989e48c8'),
}
# Fixed normal metadata getters/setters/Release, before any factory adoption.
OBJECT_SLOTS = (0, 1, 2, 3, 5, 6, 8, 12, 13, 32)
OBJECT_RVAS = {
    'documentObjectTable': (0x79cd20, 0x79ca7e, 0x79d026, 0x4bfbb0, 0x4bfbf0, 0x4bfc10, 0x4bfcc0, 0x4bfd50, 0x4bfee0, 0x4c09c0),
    'catalogObjectTable': (0x7a5d10, 0x7a5d06, 0x7a66e8, 0x4dd9c0, 0x4dda00, 0x4dda20, 0x4ddad0, 0x4ddb60, 0x4ddcf0, 0x4de7d0),
}


def need(ok, code):
    if not ok:raise ValueError('GE130_STATIC_' + code)


def _mask(text):
    return re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"',
                  lambda m: ''.join('\n' if ch == '\n' else ' ' for ch in m[0]), text, flags=re.S)


def _function_only(code):
    depth = start = 0;entries = 0
    for index, char in enumerate(code):
        if char == '{':
            if depth == 0:
                head = code[start:index].strip()
                need(re.fullmatch(r'class\s+AhGE(?:Object|State)V130|(?:bool|Guid|string|uint)\s+\w+\s*\([^{};]*\)', head),
                     'EXECUTABLE_GLOBAL_REJECTED')
                entries += int(head.startswith('string ahGoldOwnedEmptyObjectsV130('))
            depth += 1
        elif char == '}':
            depth -= 1;need(depth >= 0, 'SOURCE_BALANCE_REJECTED')
            if depth == 0:start = index + 1
        elif char == ';' and depth == 0:
            need(re.fullmatch(r'funcdef\s+(?:int_ptr|void)\s+AhGE(?:Factory|Attach|Delete)V130\s*\([^{};]*\)', code[start:index].strip()),
                 'EXECUTABLE_GLOBAL_REJECTED')
            start = index + 1
    need(depth == 0 and not code[start:].strip() and entries == 1, 'FUNCTION_ONLY_REJECTED')


def verify_source(raw, *, check_pin=True):
    need(type(raw) is bytes and 0 < len(raw) <= 65536, 'SOURCE_REJECTED')
    try:text = raw.decode('utf8')
    except UnicodeError:raise ValueError('GE130_STATIC_SOURCE_REJECTED') from None
    code = _mask(text);_function_only(code)
    need('bool&inout consumed,AhGEStateV130&inout s,bool&out terminalResult,uint&out attemptedWrites' in code
         and 'if(consumed || !ahGEPermitV130(operation))' in code
         and '!__GOLD_OWNED_EMPTY_OBJECTS_V130__' in code
         and '__GOLD_OWNED_EMPTY_OBJECTS_TOKEN_V130__|' in text
         and code.index('consumed=true') < code.index('if(s.baseline)docComplete='), 'ROLE_STATE_REJECTED')
    need(not re.search(r'\b(?:connectConfig|LoadLibrary|GetProcAddress|setModified|clearModified|SaveCfg|UpdateDBCfg|eval|Execute|createByClsid)\s*\(', code),
         'FORBIDDEN_EFFECT_REJECTED')
    need(code.count('.setMdPropVal(') == 1 and code.count('row.own.setMdPropVal(') == 1
         and code.count('row.own.id=') == 1 and code.count('row.factory(cls.self,output.bytes+16)') == 1
         and code.count('s.attach(s.scope.root.self,row.own.self)') == 1
         and code.count('s.remove(s.scope.root.self,kind.self,id.self)') == 1, 'WRITER_SCOPE_REJECTED')
    need(code.count('ahGERunObjectV130(s,s.document,0,phases)') == 1
         and code.count('ahGERunObjectV130(s,s.catalog,1,phases)') == 1
         and 'row.own.mdParentLink !is null' in code
         and 'row.own.self==ahPipeObject.self' in code
         and 's.scope.root.objById(ahGEIdV130(index)) !is null' in code, 'OWN_PROVENANCE_REJECTED')
    need(code.index('if(created!=0 && !ahGEObjectAbiV130(created,index))') < code.index('toIUnknown(created)')
         and 'ahPermissionReadable(self,4)' in code and 'ahPermissionReadable(mem::int_ptr[self],count*4)' in code
         and '0x8c7130:0x8ca0c0,37' in code
         and 'array<uint> slots={0,1,2,3,5,6,8,12,13,32};' in code
         and 'if(hr!=0 || !ahGECanonicalPinV130(pin' in code
         and 'int_ptr pin=fresh?mem::addressOf(row.canonicalAfter):mem::addressOf(row.canonicalOwn);' in code,
         'OUTPUT_MAPPING_REJECTED')
    need('bool ahGECanonicalPinV130(int_ptr pin,' in code and 'IUnknown&& pin=fresh?' not in code,
         'UNKNOWN_RELEASE_REJECTED')
    need('s.unknown=true;return false;' in code and 'if(catcher.hasException)s.unknown=true;' in code
         and 'if(!catcher.hasException && !s.unknown && ahGEMarkV130' in code
         and 's.document.deletes==s.document.attaches && s.catalog.deletes==s.catalog.attaches' in code,
         'UNKNOWN_TERMINAL_REJECTED')
    need('ahGEForeignV130(s,1)' in code and 'ahGEForeignV130(s,2)' in code
         and 'ahGEForeignV130(s,3)' in code and 'ahGEForeignV130(s,4)' in code
         and code.count('ahGEForeignV130(s,') == 4 and 's.foreignPasses==5' in code,
         'FIVE_BOUNDARIES_REJECTED')
    need(code.index('row.registry=registry.length') < code.index('row.attaches++')
         and code.index('row.attaches++') < code.index('row.names++')
         and code.index('row.names++') < code.index('row.reads++'), 'REGISTRY_WRITER_ORDER_REJECTED')
    for literal in ('a15bb4ec-c135-4ad8-932a-957186160a7e', 'c1ae574d-387b-4a6c-bbd1-224fda69c16f',
                    '061d872a-5787-460e-95ac-ed74ea3a3e84', 'cf4abea6-37b2-11d4-940f-008048da11f9',
                    'AgentEmptyDocumentV125', 'AgentEmptyCatalogV125'):
        need(literal in text, 'FIXED_SCOPE_REJECTED')
    if check_pin:need(hashlib.sha256(raw).hexdigest() == SOURCE_SHA, 'SOURCE_PIN_REJECTED')
    return dict(sourceContractVerified=True, functionOnly=True, callerHeldStateRequired=True,
                dedicatedHostAndClientRoleRequired=True, privateOneShotPermitRequired=True,
                maxCountedWrites=10, fullForeignStructureBoundaries=5,
                nativePermit=False, writerAuthorized=False, emptyCrudVerified=False)


def verify_slices(read):
    need(callable(read), 'READER_REQUIRED');bodies = {}
    for name, (module, rva, size, digest) in RANGES.items():
        try:raw = read(module, rva, size)
        except Exception:raise ValueError('GE130_STATIC_SPAN_UNAVAILABLE') from None
        need(type(raw) is bytes and len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, 'SPAN_REJECTED')
        bodies[name] = raw
    word = lambda name, offset: struct.unpack_from('<I', bodies[name], offset)[0]
    for label, factory, ctor, table in (('document', 0x4c2410, 0x79bcd0, 0x8c7130),
                                      ('catalog', 0x4dfee0, 0x7a3790, 0x8ca0c0)):
        body = bodies[label + 'Factory']
        need(body[-3:] == bytes.fromhex('c20800') and body[0x6e:0x71] == bytes.fromhex('8d4e4c')
             and body[0x78:0x7a] == bytes.fromhex('890f')
             and body[0x85:0x8b] == bytes.fromhex('8b0151ff5004')
             and body[0xa0:0xa3] == bytes.fromhex('ff5108'), 'COUNTED_FACTORY_OUTPUT_REJECTED')
        need(factory + 0x50 + struct.unpack_from('<i', body, 0x4c)[0] == ctor
             and bodies[label + 'Ctor'][-3:] == bytes.fromhex('c20400')
             and bytes.fromhex('c7464c') + struct.pack('<I', 0x228b0000 + table) in bodies[label + 'Ctor']
             and word(label + 'ClassTable', 8 * 4) == 0x228b0000 + factory, 'CTOR_TABLE_REJECTED')
    for name, expected in OBJECT_RVAS.items():
        need(tuple(word(name, slot * 4) - 0x228b0000 for slot in OBJECT_SLOTS) == expected, 'OWN_OBJECT_SLOTS_REJECTED')
    need(word('rootObjectTable', 24 * 4) == 0x1f400000 + 0x5c6d10
         and word('rootObjectTable', 26 * 4) == 0x1f400000 + 0x5c6e20
         and bodies['rootAttach'][-3:] == bytes.fromhex('c20800')
         and bodies['rootDelete'][-3:] == bytes.fromhex('c20c00'), 'ROOT_ABI_REJECTED')
    need(word('documentQiMap', 4) == word('catalogQiMap', 4) == 0x4c
         and word('rootQiMap', 4) == 4 and word('managerQiMap', 4) == 0, 'UNKNOWN_MAP_OFFSET_REJECTED')
    for name in ('basicCommonQi', 'backendCommonQi'):
        need(bodies[name][0x3d:0x4b] == bytes.fromhex('8b72040375fc568b06ff50048937'), 'UNKNOWN_COUNTED_OUT_REJECTED')
    return dict(normalFactoryOutputCountedVerified=True, stdcallFactoryArgumentBytes=8,
                outputInterfaceOffset=0x4c, documentObjectTableRva=0x8c7130,
                catalogObjectTableRva=0x8ca0c0, unknownMapOffsets=(0x4c, 0x4c, 4, 0),
                rootAttachArgumentBytes=8, rootDeleteArgumentBytes=12, primarySpanCount=len(bodies),
                exceptionUnwindAbiVerified=False, fullTransitiveCtorEffectsVerified=False,
                nativePermit=False, writerAuthorized=False, emptyCrudVerified=False)


def verify_static():
    need(hashlib.sha256(READ_HELPER.read_bytes()).hexdigest() == READ_HELPER_SHA, 'READ_HELPER_CHANGED')
    raw = CATALOG_OBSERVATION.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == CATALOG_OBSERVATION_SHA, 'CATALOG_OBSERVATION_CHANGED')
    observation = json.loads(raw)
    need(observation['passed'] is True and observation['classId'] == 'cf4abea6-37b2-11d4-940f-008048da11f9'
         and observation['factoryRva'] == 0x4dfee0 and observation['outputMdObjectTableRva'] == 0x8ca0c0
         and observation['nativePermit'] is False, 'CATALOG_PRIMARY_REJECTED')
    result = verify_source(SOURCE.read_bytes())
    images = {module: PE(module) for module in ('basic.dll', 'backend.dll')}
    def read(module, rva, count):
        image = images[module];at = image.offset(image.base + rva)
        return image.data[at:at + count]
    result.update(verify_slices(read), sourceSha256=SOURCE_SHA,
                  measuredConstantReadHelperSha256=READ_HELPER_SHA,
                  catalogPrimaryObservationSha256=CATALOG_OBSERVATION_SHA,
                  wholeSdkCompiled=False, runtimeEmptyCrudVerified=False)
    return result
