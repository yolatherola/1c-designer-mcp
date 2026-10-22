"""Function-only OWN structure + pinned normal primary ABI. Import is inert.

No SDK compile/load, native call, runtime operation, database or writer permit.
Existing primary PE files are read only by explicitly called verify_static().
"""
import hashlib
from pathlib import Path
import re
import struct

import gold_owned_empty_objects_contract_v130 as p130
import owned_metadata_children_abi_v137 as p137
import gold_owned_document_structure_guard_v139 as guard
from repository_pe_probe import PE

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'tests/NativeGoldOwnedDocumentStructureV139.as'
SOURCE_SHA = '79f1f00badcd5f1f167bdaba1930120dcd1975f0d714410b5130790ed0b38a28'
READ_HELPER = p130.READ_HELPER
READ_HELPER_SHA = p130.READ_HELPER_SHA
CHILD_CONTRACT = HERE / 'owned_metadata_children_abi_v137.py'
CHILD_CONTRACT_SHA = 'a0360352599e89f9026103dc29febe5d3686c18daa2aa0f1161937c4c6aca30a'
P130_SPANS = ('documentFactory', 'documentCtor', 'documentClassTable', 'documentObjectTable',
              'rootObjectTable', 'rootAttach', 'rootDelete', 'documentQiMap', 'rootQiMap',
              'managerQiMap', 'basicUnknownDetector', 'backendUnknownDetector')
RANGES = dict(p137.RANGES)
RANGES.update({'v130_' + name: p130.RANGES[name] for name in P130_SPANS})
RANGES.update({
    'documentPropCount': ('basic.dll', 0x4c24d0, 19, '8f5d534296fcbc36f1c474a815c3162e4048377f14cf9e9da5a9eaa52966c817'),
    'documentPropId': ('basic.dll', 0x4c24f0, 19, '09972f6a15ebab2809b0bf78f7060c49a3617a9e7e1a21ce2234476b270a7135'),
    'childPropCount': ('basic.dll', 0x499ee0, 19, '1ae87d5015304423e5c2f8d335a7e2a5cc6cd41cfecd721201ab05a435fc8ffd'),
    'childPropId': ('basic.dll', 0x499f00, 19, '6e65ac3fca4d1520a8bce6f4587424e90d683b12e70f728b28d314010b67af7f'),
    'columnPropCount': ('backend.dll', 0x1d9dd0, 19, '1ae87d5015304423e5c2f8d335a7e2a5cc6cd41cfecd721201ab05a435fc8ffd'),
    'columnPropId': ('backend.dll', 0x56b930, 19, '6e65ac3fca4d1520a8bce6f4587424e90d683b12e70f728b28d314010b67af7f'),
})
OBJECT_RVAS = {
    'doc': (0x79cd20,0x79ca7e,0x79d026,0x4bfbb0,0x4bfbd0,0x4bfbf0,0x4bfc10,0x4bfc40,0x4bfcc0,0x4bfce0,0x4bfd00,0x4bfd30,0x4bfd50,0x4bfee0,0x4c0080,0x4c0200,0x4c0330,0x4c04c0,0x4c04f0,0x4c0510,0x4c0540,0x4c0570,0x4c05a0,0x4c05d0,0x4c0720,0x4c0750,0x4c0780,0x4c07b0,0x4c0900,0x4c0930,0x4c0960,0x4c0990,0x4c09c0,0x4c0a50,0x4c0ae0,0x4c0b70,0x4c0c00),
    'attr': (0x79cc58,0x79cdcb,0x79ccf9,0x497f50,0x497f70,0x497f90,0x497fb0,0x497fe0,0x498060,0x4c3fb0,0x4c3ff0,0x4c4120,0x4c4250,0x4c43e0,0x498630,0x4c4580,0x4c46b0,0x498a80,0x498ab0,0x498ad0,0x4c4850,0x4c4880,0x498b60,0x498b90,0x498ce0,0x498d10,0x498d40,0x498d70,0x498ec0,0x498ef0,0x498f20,0x498f50,0x498f80,0x499010,0x4990a0,0x4990d0,0x499160),
    'tp': (0x79cbf9,0x79cd6f,0x79d105,0x4c6070,0x4c6090,0x4c60b0,0x4c60d0,0x4c6100,0x4c6180,0x4c61a0,0x4c6260,0x4c6290,0x4c62b0,0x4c64f0,0x4c6690,0x4c6810,0x4c6a20,0x4c6bc0,0x4c6bf0,0x4c6c10,0x4c6c40,0x4c6c70,0x4c6ca0,0x4c6cd0,0x4c6e20,0x4c6e50,0x4c6e80,0x4c6eb0,0x4c7000,0x4c7030,0x4c7060,0x4c7090,0x4c70c0,0x4c7150,0x4c71e0,0x4c7210,0x4c72a0),
    'col': (0xb51ca9,0xb421b1,0xb42740,0x569a00,0x569a20,0x569a40,0x569a60,0x569a90,0x569b10,0x592320,0x569b50,0x569c80,0x5e2080,0x5e2210,0x56a100,0x5e23b0,0x5e24e0,0x56a550,0x56a580,0x56a5a0,0x56a5d0,0x56a600,0x56a630,0x56a660,0x56a7b0,0x56a7e0,0x56a810,0x56a840,0x56a990,0x56a9c0,0x56a9f0,0x56aa20,0x56aa50,0x56aae0,0x56ab70,0x56aba0,0x56ac30),
}


def need(ok, code):
    if not ok:
        raise ValueError('GD139_STATIC_' + code)


def _function_only(code):
    depth = start = entries = 0
    for index, char in enumerate(code):
        if char == '{':
            if depth == 0:
                head = code[start:index].strip()
                need(re.fullmatch(r'class\s+AhGD(?:Object|State)V139|(?:bool|Guid|string|uint|void|IMDObject&&)\s+\w+\s*\([^{};]*\)', head), 'EXECUTABLE_GLOBAL_REJECTED')
                entries += int(head.startswith('string ahGoldOwnedDocumentStructureV139('))
            depth += 1
        elif char == '}':
            depth -= 1
            need(depth >= 0, 'SOURCE_BALANCE_REJECTED')
            if depth == 0:
                start = index + 1
        elif char == ';' and depth == 0:
            need(re.fullmatch(r'funcdef\s+(?:int_ptr|int|void)\s+AhGD(?:Factory|QI|Attach|Delete)V139\s*\([^{};]*\)', code[start:index].strip()), 'EXECUTABLE_GLOBAL_REJECTED')
            start = index + 1
    need(depth == 0 and not code[start:].strip() and entries == 1, 'FUNCTION_ONLY_REJECTED')


def verify_source(raw, *, check_pin=True):
    need(type(raw) is bytes and 0 < len(raw) <= 65536, 'SOURCE_REJECTED')
    try:
        text = raw.decode('utf8')
    except UnicodeError:
        raise ValueError('GD139_STATIC_SOURCE_REJECTED') from None
    code = p130._mask(text)
    _function_only(code)
    need('bool&inout consumed,AhGDStateV139&inout s,bool&out terminalResult,uint&out attemptedWrites' in code
         and 'if(consumed || !ahGDPermitV139(operation))' in code
         and '!__GOLD_OWNED_DOCUMENT_STRUCTURE_V139__' in code
         and '__GOLD_OWNED_DOCUMENT_STRUCTURE_TOKEN_V139__|' in text
         and 's.unknown || s.catcher.hasException || s.operation.length!=0 || s.attempts!=0 || s.sequence!=0' in code
         and code.index('consumed=true') < code.index('if(s.baseline && ahGDCreateV139'), 'ROLE_STATE_REJECTED')
    need(not re.search(r'\b(?:connectConfig|LoadLibrary|GetProcAddress|setModified|clearModified|SaveCfg|UpdateDBCfg|eval|Execute|createByClsid|ahGCRunV99|ahGERunObjectV130)\s*\(', code), 'FORBIDDEN_EFFECT_REJECTED')
    need(code.count('.setMdPropVal(') == 1 and code.count('row.own.setMdPropVal(') == 1
         and code.count('row.own.id=') == 1 and code.count('row.factory(cls.self,output.bytes+16)') == 1
         and code.count('row.attach(parent.self,row.own.self)') == 1
         and code.count('row.remove(parent.self,kind.self,id.self)') == 1, 'WRITER_SCOPE_REJECTED')
    need('s.attempts>=20' in code and code.count('ahGDAttemptV139(s)') == 5
         and 's.attempts==20 && s.foreignPasses==11' in code
         and '!s.unknown && !s.catcher.hasException' in code, 'ATTEMPT_BUDGET_REJECTED')
    need(code.count('if(s.catcher.hasException){s.unknown=true;return false;}') == 5
         and 'if(s.catcher.hasException){s.unknown=true;return' in code, 'IMMEDIATE_EXCEPTION_STOP_REJECTED')
    for index, field in enumerate(('document', 'attribute', 'tablePart', 'column')):
        need(code.count(f'ahGDCreateV139(s,s.{field},{index},phases)') == 1
             and code.count(f'ahGDFreshV139(s,s.{field},{index},phases)') == 1
             and code.count(f'ahGDDeleteObjectV139(s,s.{field},{index},phases)') == 1, 'FIXED_CALL_SET_REJECTED')
    for kind, own, cls, name, _ in guard.OBJECTS:
        need(f'Guid("{{{own}}}")' in text and f'Guid("{{{cls}}}")' in text
             and f'"{name}"' in text and f'"{kind}"' in text, 'FIXED_SCOPE_REJECTED')
    for label, expected in OBJECT_RVAS.items():
        found = re.search(r'array<uint> ' + label + r'=\{([^}]+)\};', code)
        need(found is not None and tuple(int(item.strip(), 16) for item in found[1].split(',')) == expected, 'FULL37_SLOTS_REJECTED')
    need('n<37' in code and 'ahGDTableRvaV139(i),37' in code
         and 'ahPermissionReadable(self,4)' in code and 'ahPermissionReadable(mem::int_ptr[self],count*4)' in code
         and code.index('row.rawFactory!=0 && !ahGDObjectAbiV139(row.rawFactory,i)') < code.index('toIUnknown(row.rawFactory)')
         and code.index('!ahGDObjectAbiV139(row.rawQI,i)') < code.index('toIUnknown(row.rawQI)')
         and 'row.rawQI!=receiver' in code and 'MemoryBuffer output(36)' in code
         and 'mem::byte[buffer.bytes+20+i]!=0xa5' in code, 'OUTPUT_ADOPTION_REJECTED')
    # Core.As creates an input temporary for &in on this script class, whose
    # only constructor requires a size. &inout binds the original allocation;
    # the exact read-only body still forbids any canary/buffer mutation.
    canary = re.search(r'bool ahGDCanaryV139\(MemoryBuffer&inout buffer\)\{([^{}]+)\}', code)
    expected = 'for(uint i=0;i<16;i++)if(mem::byte[buffer.bytes+i]!=0xa5 || mem::byte[buffer.bytes+20+i]!=0xa5)return false;return true;'
    need(canary is not None and canary[1] == expected, 'CANARY_NO_IMPLICIT_COPY_REJECTED')
    # The concrete Document handles Attr and TablePart with the same native
    # target. Core.As registration is unique by (funcdef type, address), so the
    # caller-held shared handles must be bound once and copied with &&.
    target_body = ('if(i>3 || parent is null || !ahGDParentKnownV139(s,i))return false;'
                   'IMDObject&& current=ahGDParentV139(s,i);if(current is null || parent.self!=current.self)return false;'
                   'int_ptr table=mem::int_ptr[parent.self];uint slot=deleting?26:24;'
                   'uint target=i==0?(deleting?0x5c6e20:0x5c6d10):i==3?(deleting?0x4c6e80:0x4c6e20):(deleting?0x4c0780:0x4c0720);'
                   'return ahGDAddressV139(mem::int_ptr[table+slot*4],i==0?"backend.dll":"basic.dll",target);')
    target_function = re.search(r'bool ahGDParentTargetV139\(AhGDStateV139&in s,IMDObject&& parent,uint i,bool deleting\)\{([^{}]+)\}', text)
    need(target_function is not None and re.sub(r'\s+', '', target_function[1]) == re.sub(r'\s+', '', target_body), 'FRESH_PARENT_TARGET_REJECTED')
    need('AhGDAttachV139&& sharedDocumentAttach;AhGDDeleteV139&& sharedDocumentRemove;' in code,
         'SHARED_DOCUMENT_DELEGATE_REJECTED')
    binding_code = re.sub(r'\s+', '', code)
    for field, shared, slot, deleting, counter, invocation in (
            ('attach', 'sharedDocumentAttach', 24, 'false', 'attaches', 'row.attach(parent.self,row.own.self)'),
            ('remove', 'sharedDocumentRemove', 26, 'true', 'deletes', 'row.remove(parent.self,kind.self,id.self)')):
        bind = (f'if(i==1 || i==2){{if(s.{shared} is null)initFuncDefFromAddress(mem::int_ptr[table+{slot}*4],&&s.{shared},asCALL_STDCALL);'
                f'&&row.{field}=s.{shared};}}else if(row.{field} is null)initFuncDefFromAddress(mem::int_ptr[table+{slot}*4],&&row.{field},asCALL_STDCALL);')
        fresh = f'if(row.{field} is null || !ahGDParentTargetV139(s,parent,i,{deleting}) || !ahGDAttemptV139(s))return false;row.{counter}++;{invocation};'
        need(binding_code.count(re.sub(r'\s+', '', bind)) == 1 and binding_code.count(re.sub(r'\s+', '', fresh)) == 1
             and code.count(f'initFuncDefFromAddress(mem::int_ptr[table+{slot}*4]') == 2
             and code.count(f'!ahGDParentTargetV139(s,parent,i,{deleting})') == 2,
             'SHARED_DOCUMENT_DELEGATE_REJECTED')
    need('row.own.mdParentLink !is null' in code and 'row.own.self==ahPipeObject.self' in code
         and 's.scope.root.objById(ahGDIdV139(i)) !is null' in code
         and 'if(i==3)return s.tablePart.own;return s.document.own;' in code
         and 'actualParent.self==parent.self' in code and 'parent.child(ahGDKindV139(i),ahGDIdV139(i))' in code
         and 'child.id==ahGDIdV139(fixed)' in code, 'OWN_PARENT_COLLISION_REJECTED')
    need(code.index('row.registry=registry.length') < code.index('row.attaches++')
         and code.index('row.attaches++') < code.index('row.names++')
         and 'row.beforeCount!=0' in code and 'ahGDEmptyV139(row.own)' in code
         and 'if(s.document.own.childCount(kind)!=wanted)' in code
         and 'if(s.tablePart.own.childCount(kind)!=wanted)' in code, 'STRUCTURE_BOUNDS_REJECTED')
    need('!ahGDNameCapabilityV139(s,row,i)' in code and 'uint count=cls.propCount()' in code
         and 'cls.getPropIDAt(n)==name' in code and 'count>256' in code
         and '!ahPermissionReadable(begin,count*16)' in code and 'return found==1;' in code
         and 'mem::int_ptr[table+9*4]' in code and 'mem::int_ptr[table+10*4]' in code, 'NAME_CAPABILITY_REJECTED')
    cleanup = [code.index(f'ahGDDeleteObjectV139(s,s.{field},{index},phases)')
               for index, field in ((3, 'column'), (2, 'tablePart'), (1, 'attribute'), (0, 'document'))]
    need(cleanup == sorted(cleanup) and 'row.attaches==row.deletes' in code
         and 'row.rawFactory==0 && row.rawQI==0' in code
         and '!s.unknown && s.baseline && ahGDAllSettledV139(s)' in code
         and 'if(s.catcher.hasException)s.unknown=true;' in code, 'UNKNOWN_CLEANUP_REJECTED')
    need('phases(54)' in code and 'phases[50] && phases[51] && phases[52] && phases[53]' in code
         and 's.rootPreserved=ahGCRootV99(s.scope);s.sourcePreserved=ahGCSourceV99(s.scope);s.foreignPreserved=ahGDForeignV139(s,10)' in code
         and 'freshRoot=s.scope.manager.getMDCont()' in code and 'freshRoot.objById(ahGDIdV139(i))' in code
         and 'row.afterCanonical==row.canonical' in code, 'FRESH_PHYSICAL_TERMINAL_REJECTED')
    for false_claim in guard.FALSE_CLAIMS:
        need(f'\\"{false_claim}\\":false' in text, 'FALSE_CAPABILITY_REJECTED')
    if check_pin:
        need(hashlib.sha256(raw).hexdigest() == SOURCE_SHA, 'SOURCE_PIN_REJECTED')
    return dict(sourceContractVerified=True, functionOnly=True, maxAttemptedWrites=20,
                fullForeignStructureBoundaries=11, actualPhysicalPhases=54, createdOnlyRegistries=4,
                callerHeldUnknownStateRequired=True, dedicatedHostAndClientRoleRequired=True,
                privateOneShotPermitRequired=True, typePropertiesVerified=False,
                stringTypeVerified=False, qualifierVerified=False, nativePermit=False, writerAuthorized=False)


def verify_special_unknown(bodies):
    """Close detector -> first-map-offset -> AddRef-before-out -> S_OK/ret8.

    No map-minus-four convention is used. EDX points at the first IMDObject
    registration row; that row's offset is also the IUnknown special result.
    All source bodies must have been hash-verified before runtime integration.
    """
    for name, common, detector in (('basic', 0x6ae930, 0x6ae900), ('backend', 0x966490, 0x966460)):
        raw = bodies[name + 'CommonQI']
        found = bodies['v130_' + name + 'UnknownDetector']
        need(raw[0x2d:0x34] == bytes.fromhex('538b5d088bcb56') and raw[0x34] == 0xe8
             and common + 0x39 + struct.unpack_from('<i', raw, 0x35)[0] == detector
             and raw[0x39:0x3d] == bytes.fromhex('85c07419')
             and raw[0x3d:0x56] == bytes.fromhex('8b72040375fc568b06ff500489375e5b33c05f8be55dc20800'), 'SPECIAL_UNKNOWN_BRANCH_REJECTED')
        need(found[:38] == bytes.fromhex('833900751e837904007518817908c0000000750f81790c000000467506b801000000c333c0c3'), 'UNKNOWN_IID_DETECTOR_REJECTED')
    expected = (('attributeQiMap', 'basic.dll', 0x164), ('tablePartQiMap', 'basic.dll', 0x188),
                ('columnQiMap', 'backend.dll', 0x164))
    for name, module, offset in expected:
        iid = 0xe62d7c if module == 'backend.dll' else 0x898b04
        need(struct.unpack('<III', bodies[name]) == (p137.BASES[module] + iid, offset, 1), 'UNKNOWN_FIRST_ROW_REJECTED')
    return dict(childCanonicalIUnknownNormalStaticVerified=True, childCanonicalOffsets=(0x164, 0x188, 0x164),
                canonicalIUnknownRuntimeVerified=False, nativePermit=False, writerAuthorized=False)


def verify_slices(read):
    need(callable(read), 'READER_REQUIRED')
    bodies = {}
    for name, (module, rva, size, sha) in RANGES.items():
        try:
            raw = read(module, rva, size)
        except Exception:
            raise ValueError('GD139_STATIC_SPAN_UNAVAILABLE') from None
        need(type(raw) is bytes and len(raw) == size and hashlib.sha256(raw).hexdigest() == sha, 'SPAN_REJECTED')
        bodies[name] = raw
    p137.verify_linkage({name: bodies[name] for name in p137.RANGES})
    result = verify_special_unknown(bodies)
    body = bodies['v130_documentFactory']
    need(body[-3:] == bytes.fromhex('c20800') and body[0x6e:0x71] == bytes.fromhex('8d4e4c')
         and body[0x78:0x7a] == bytes.fromhex('890f') and body[0x85:0x8b] == bytes.fromhex('8b0151ff5004')
         and body[0xa0:0xa3] == bytes.fromhex('ff5108')
         and 0x4c2410 + 0x50 + struct.unpack_from('<i', body, 0x4c)[0] == 0x79bcd0, 'DOCUMENT_FACTORY_REJECTED')
    word = lambda name, offset: struct.unpack_from('<I', bodies[name], offset)[0]
    for label, name, module in (('doc', 'documentMdTable', 'basic.dll'), ('attr', 'attributeMdTable', 'basic.dll'),
                                ('tp', 'tablePartMdTable', 'basic.dll'), ('col', 'columnMdTable', 'backend.dll')):
        need(tuple(value - p137.BASES[module] for value in struct.unpack('<37I', bodies[name])) == OBJECT_RVAS[label], 'FULL37_SLOTS_REJECTED')
    need(word('v130_rootObjectTable', 24 * 4) == p137.BASES['backend.dll'] + 0x5c6d10
         and word('v130_rootObjectTable', 26 * 4) == p137.BASES['backend.dll'] + 0x5c6e20
         and bodies['v130_rootAttach'][-3:] == bytes.fromhex('c20800')
         and bodies['v130_rootDelete'][-3:] == bytes.fromhex('c20c00'), 'ROOT_PARENT_REJECTED')
    for table, module, prefix in (('v130_documentClassTable', 'basic.dll', 'document'),
                                  ('attributeClassTable', 'basic.dll', 'child'),
                                  ('tablePartClassTable', 'basic.dll', 'child'),
                                  ('columnClassTable', 'backend.dll', 'column')):
        for slot, suffix in ((9, 'PropCount'), (10, 'PropId')):
            name = prefix + suffix
            need(word(table, slot * 4) == p137.BASES[module] + RANGES[name][1]
                 and bodies[name][-3:] == bytes.fromhex('c20400' if slot == 9 else 'c20800'), 'NAME_VECTOR_GETTERS_REJECTED')
    result.update(primarySpanCount=len(bodies), allFourFull37TablesVerified=True,
                  factoryOutputOffsets=(0x4c, 0x164, 0x188, 0x164), parentAttachArgumentBytes=8,
                  parentDeleteArgumentBytes=12, exceptionUnwindVerified=False,
                  namePropertyEnumerationNormalStaticVerified=True,
                  fullTransitiveCtorVerified=False, destructorTransitiveEffectsVerified=False,
                  runtimeStructureCrudVerified=False)
    return result


def verify_static():
    """Read only existing exact source/helpers/PE; no SDK/runtime execution."""
    need(hashlib.sha256(READ_HELPER.read_bytes()).hexdigest() == READ_HELPER_SHA, 'READ_HELPER_CHANGED')
    need(hashlib.sha256(CHILD_CONTRACT.read_bytes()).hexdigest() == CHILD_CONTRACT_SHA, 'CHILD_CONTRACT_CHANGED')
    result = verify_source(SOURCE.read_bytes())
    images = {name: PE(name) for name in ('basic.dll', 'backend.dll')}

    def read(module, rva, size):
        image = images[module]
        at = image.offset(image.base + rva)
        return image.data[at:at + size]

    result.update(verify_slices(read), sourceSha256=SOURCE_SHA, wholeSdkCompiled=False,
                  readHelperSha256=READ_HELPER_SHA, childContractSha256=CHILD_CONTRACT_SHA)
    return result
