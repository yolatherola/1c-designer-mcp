"""Read-only source/PE contract for V108; it never loads or calls platform DLLs.

Static compatibility is a prerequisite, not permission or native trial evidence.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import re
import struct
from repository_pe_probe import PE, HASHES

HERE = Path(__file__).resolve().parent
TESTS = HERE.parent / 'tests'
AS_SOURCE = TESTS / 'NativeCompactOwnerV108.as'
DEPENDENCIES = {
    'NativeRepositoryObserve.as': 'd7ac427467016667ac2b9e84a97a92727ef6955a2bf5dc439d4da36871bff16d',
    'NativeRepositoryPlan.as': '77738f69fab72dafbd35c342bbd4e3a3090cc548f7dcd741df69a2dda4daeebd',
    'NativeMetadataDocumentPermission.as': 'e0031b86bec623fea19c79423be63a0e790585f38a8f06ddd100f86d254685c3',
}
RANGES = {
    'provider40': (0x19e20, 0x1a060, '02c12ca4027bad80ca7c8f24e15fa844e93dff7f0725b10d5f8905f9498a9d1c'),
    'controllerQI': (0x14e4d0, 0x14e4f0, '5603d912cb82407abc1e0a9493af4e64c080e9a0ebc5e66743bf7edf3f0fe1a6'),
    'providerQI': (0x11af90, 0x11afb0, 'f742b0f782232503877e9f881414f2a579778eab7552ff6d9a199a4c02d2f3a3'),
    'unknownSpecialBranch': (0x10f870, 0x10f8d7, 'f426e00206c4478b4f8f673c42fc0a14851b5fd8f11f77c3df3738ccddfb6a50'),
    'controllerMap': (0x18ef68, 0x18ef70, '3c2bce0f463723bf6e6cefd99cf83b5618122ebc0e1e61db0ea1d57e780ba90e'),
    'providerMap': (0x186ce0, 0x186ce8, 'c78007469156c29d7409c8c267b739cea8beed4a8a611c71c24868e7e04cfc81'),
}
UI_RANGES = {
    'constructorPrefix': (0x962c20, 30, 'c6c89b8c336c8f45ac8d415d955b7125b3c74ce2a9327bf88e464c1c9b0bce48'),
    'primaryTable': (0xc0e588, 12, 'd68dc40348886e7e61abff70d101a28e799810236f507737fa56b119050b3030'),
    'typedTable': (0xc0e458, 12, '0c8b0758f7393c7e20d7e899f2f408479ea3bf9f771d4fdba5f420af32a842b5'),
    'typedQIThunk': (0x9643ce, 10, '70413117e311b13c87479fee76acd02df4dfea45d93768c599f97934b4a782dc'),
    'primaryQI': (0x962ba0, 26, 'f34445b9622be4c00ee3aa2858fb27466920fd86381b2e6065edea0cbacc1dd5'),
    'qiMap': (0xc0e670, 24, '8f517f90e15dda851bd0442cc6d3c998093a4b8b8d9460bf4a8740004bfdcce5'),
}
MANAGER_RANGES = {
    'typedUiTable26': ('frntend.dll', 0xc0e458, 108, 'a152d070d318c329d2299321a90cc484b4426f4dedaa1be4f843034aac507fb8'),
    'uiGetter26': ('frntend.dll', 0x147b90, 37, 'f73146874874d7174b722e93f104e572463c7607bc83d4d484d6334585a4b018'),
    'managerTable85': ('backend.dll', 0xede0a4, 344, '05250dc12f3b5647f2405f0113dfb3a2d80ae9c5e20385787bed29a431612362'),
    'managerCachedEntry': ('backend.dll', 0x2aeb40, 126, 'c68f0f61c1233a62a3c24aee2369d6de42a8d5d453e10d213dc91f782277f01e'),
    'managerCachedExit': ('backend.dll', 0x2af5b7, 30, 'a4ec316398c2c9bac8c49ddd3e2adbcb66f139f0c372c19f715db379b6fe18b9'),
}
PROVIDER_ROLE_RANGES = {
    'configFieldStore': ('config.dll', 0xc7c7b, 36, '79970a12db66f402e91c7b7443a7243d3fdb7d54ef7ba5d3cea55152a0358ce3'),
    'configWiring': ('config.dll', 0xc7cbe, 14, '4356152eeacc3e21f6de7335d751129151c09701bb29dfc9b46238c4ad87b94b'),
    'currentProcessService': ('config.dll', 0x230db0, 38, '86aafd06dd50497dc46febe0f4f49cc539316d029e1caa6a7a7d8e8756447466'),
    'serviceAcquisition': ('config.dll', 0x237570, 125, '3ed86133f99e9fee8baa6bf4122ee946779bffd0eb5d359469ce24058774899b'),
    'serviceClsid': ('config.dll', 0x2ba8a0, 16, '2b841bc8cc51e965522064dcf9170fdc0caee680dad8591c2a82a44667a708ee'),
    'serviceIid': ('config.dll', 0x2ba29c, 16, '9e013e9ba5bedea81fa8ca5d9c189ad8cc4e26172c2d428fc80ad4f95b2fd703'),
    'controllerMap': ('devtool.dll', 0x18ef68, 40, '4efb2da5b4e39507b910f1804f81782ca997e1f4c416af6a5a210b538872d605'),
    'controllerOpsTable3': ('devtool.dll', 0x18db1c, 16, '1d0fb67c35ff3e90bb719cde45c33c20ee16e92731862996f06ecfe59734fd97'),
    'controllerProviderManagerStore': ('devtool.dll', 0xbc668, 117, '5e5aed491170d2c530809fb2edf647d3fca26e61edb705329dc99601ad1daa42'),
    'serviceRegistration': ('devtool.dll', 0x1c75e0, 20, 'eab2e1f961829173d4a4c031d434c47fdd3be4356a909e83e9564e9857815637'),
    'factoryEntry': ('devtool.dll', 0x14baf0, 34, '363f0d6ed56c4fc84ffe14e877353954a54e2f897a0a132a560e99a90806c2cd'),
    'defaultControllerConstructor': ('devtool.dll', 0x14d760, 243, '33459521d25bec6888ca85bbbf0a52a72b842c489a7dbbd707f1d9995ac90f36'),
    'controllerServiceIid': ('devtool.dll', 0x18efd0, 16, '9e013e9ba5bedea81fa8ca5d9c189ad8cc4e26172c2d428fc80ad4f95b2fd703'),
    'controllerServiceClsid': ('devtool.dll', 0x18e96c, 16, '2b841bc8cc51e965522064dcf9170fdc0caee680dad8591c2a82a44667a708ee'),
}


def need(ok, code):
    if not ok:
        raise ValueError('V108_STATIC_' + code)


def _masked(source):
    return re.sub(r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/',
                  lambda m: re.sub(r'[^\r\n]', ' ', m.group()), source)


def _function(source, name):
    code = _masked(source)
    m = re.search(r'(?m)^(?:bool|string|IUnknown&&)\s+' + re.escape(name) + r'\([^)]*\)\s*\{', code)
    need(m is not None, 'FUNCTION_REJECTED')
    start, depth = m.end() - 1, 0
    for at in range(start, len(code)):
        depth += (code[at] == '{') - (code[at] == '}')
        if depth == 0:
            return source[start:at + 1]
    raise ValueError('V108_STATIC_FUNCTION_REJECTED')


def verify_source(source):
    """Validate only this fixed function-only readonly implementation."""
    need(type(source) is str and 0 < len(source.encode('utf-8')) <= 32768, 'SOURCE_REJECTED')
    code = _masked(source)
    # The published SDK uses the generic type grid<T>; the vendor compiler
    # rejects that registered type name as a local variable identifier.
    need(re.search(r'\bint_ptr\s+grid\s*(?:[=;,])', code) is None, 'RESERVED_IDENTIFIER_REJECTED')
    forbidden = ('transmitCommand', 'setMdPropVal', 'deleteMdObject', 'attachChild', 'mdTreeShow',
                 'activateObjInTree', 'ahScopePlan', 'ahCollectScopePlan', 'ahRepoRawVtable',
                 'ahSourceGetObjects', 'ahSourceExternalFile', 'CreateFile', 'LoadLibrary', 'VirtualAlloc')
    need(not any(re.search(r'\b' + re.escape(x) + r'\b', code) for x in forbidden), 'SIDE_EFFECT_REJECTED')
    need(re.search(r'(?m)^\s*void\s+main\s*\(', code) is None, 'ENTRY_REJECTED')
    check = _function(source, 'ahCompactOwnerCheckV108')
    bind = _function(source, 'ahCompactBindV108')
    entry = _function(source, 'ahCompactOwnerV108')
    query = _function(source, 'ahCompactRawCanonicalV108')
    selection = _function(source, 'ahCompactSelectionV108')
    need(code.count('ahCollectRepositoryObserve(') == 1 and 'ahCollectRepositoryObserve();' in entry
         and 'ahCollectRepositoryObserve' not in _masked(check + bind), 'WIDE_REUSE_REJECTED')
    need(check.count('ahRepoStatistic(provider,true)') == 1
         and check.index('ahCompactBindV108(state,false)') < check.index('ahRepoStatistic(provider,true)')
         < check.rindex('ahCompactBindV108(state,false)'), 'READ_ORDER_REJECTED')
    for token in ('ahRepoSelectionVerified', 'ahRepoBoundVerified', 'ahRepoOwnerVerified', 'ahRepoGenerationVerified',
                  'ahRepoLastVersion==version', 'ahRepoLastRevised==revised', 'ahRepoLastRevisor==owner'):
        need(token in check, 'OLD_GUARD_REJECTED')
    for token in ('ahPipeScopeAlive()', 'ahCompactSelectionV108(state)', 'controller!=ahPlanController',
                  'provider!=ahPlanProvider', 'state.canonical==canonical', 'state.actor==actor',
                  'state.depotRaw==depot', 'state.connectionRaw==connection', 'state.connectionTable==mem::int_ptr[connection]',
                  'queryIface(iid,uiPin)', 'queryIface(iid,rootPin)', 'queryIface(iid,objectPin)', 'queryIface(iid,managerPin)',
                  'ahCompactRawCanonicalV108(controller,true)', 'ahCompactRawCanonicalV108(provider,false)',
                  'ahCompactConnectionCodeV108(mem::int_ptr[connection])',
                  'controller+0x34', 'provider+0x124', 'provider+0x158', 'provider+0x10'):
        need(token in bind, 'BINDING_REJECTED')
    for token in ('end-first!=4', 'mem::int_ptr[first]!=row', 'row+0x24', '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'):
        need(token in selection, 'SELECTION_REJECTED')
    need('00000000-0000-0000-C000-000000000046' in query and 'output(36,0xa5)' in query
         and 'output[i+20]!=0xa5' in query and 'pin=toIUnknown(owned)' in query
         and 'owned!=raw' in query and 'mem::int_ptr[outputTable+8]' in query
         and query.index('owned!=raw') < query.index('pin=toIUnknown(owned)')
         and query.index('mem::int_ptr[outputTable+8]') < query.index('pin=toIUnknown(owned)')
         and 'ahCompactReturnUnknownV108=true' in query, 'COUNTED_QI_REJECTED')
    need('i<5 || i>=8' in entry and 'state.readCalls' in entry and 'ahPerformanceCounter' in entry
         and 'catcher.hasException' in entry, 'PARITY_REJECTED')
    stage_pattern = r'\bstate\.bindingFailureStage\s*=\s*(\d+)\s*;'
    for body, expected in ((bind, tuple(range(1, 26)) + (0,)),
                           (selection, tuple(range(100, 107)) + (0,)),
                           (check, (26, 27)), (entry, (28,))):
        need(tuple(map(int, re.findall(stage_pattern, _masked(body)))) == expected, 'STAGE_MAP_REJECTED')
    need('uint bindingFailureStage=29;' in code
         and 'ahPlanProvider==0 || mem::int_ptr[plain+0x6c]!=ahPlanProvider' in bind
         and 'mem::int_ptr[plain+0x1c]!=manager.self' in bind
         and 'mem::int_ptr[ahStatusUi.self+0x118]!=manager.self' in bind
         and 'mem::int_ptr[controller+0x34]!=manager.self' in bind,
         'STAGE_STATE_REJECTED')
    for name in ('ahCompactUiAliasDiagnosticV108', 'ahCompactMetadataAliasDiagnosticV108',
                 'ahCompactUiManagerDiagnosticV108'):
        diagnostic = _masked(_function(source, name))
        calls = set(re.findall(r'\b([A-Za-z_]\w*)\s*\(', diagnostic))
        allowed = {'if', 'ahCompactPageV108', 'ahRepoAddress', 'ahCompactAddressV108'}
        if name == 'ahCompactUiAliasDiagnosticV108':
            allowed.add('ahCompactUiManagerDiagnosticV108')
        if name == 'ahCompactUiManagerDiagnosticV108':
            allowed = {'if', 'ahCompactPageV108', 'ahCompactAddressV108', 'ahCompactTableV108'}
        need(calls <= allowed,
             'DIAGNOSTIC_CALL_REJECTED')
        need('queryIface' not in diagnostic and 'toIUnknown' not in diagnostic, 'DIAGNOSTIC_CALL_REJECTED')
    relation = _function(source, 'ahCompactUiManagerDiagnosticV108')
    for token in ('ahCompactTableV108(ui,"frntend.dll",0xc0e458,27)',
                  'mem::int_ptr[uiTable],"frntend.dll",0x9643ce',
                  'mem::int_ptr[uiTable+4],"frntend.dll",0x9643c4',
                  'mem::int_ptr[uiTable+8],"frntend.dll",0x96429f',
                  'mem::int_ptr[uiTable+26*4],"frntend.dll",0x147b90',
                  'uiPage=uiAbi && ahCompactPageV108(ui,0x11c);',
                  'if(uiPage){', 'int_ptr rawManager=mem::int_ptr[ui+0x118];',
                  'ahCompactTableV108(rawManager,"backend.dll",0xede0a4,86)',
                  'mem::int_ptr[managerTable],"backend.dll",0xa72ad0',
                  'mem::int_ptr[managerTable+4],"backend.dll",0x967510',
                  'mem::int_ptr[managerTable+8],"backend.dll",0xa72af0',
                  'mem::int_ptr[managerTable+85*4],"backend.dll",0x2aeb40',
                  'managerPage=managerAbi && ahCompactPageV108(rawManager,0x88);',
                  'if(managerPage){', 'managerSame=rawManager==expectedManager;',
                  'rootSame=mem::int_ptr[rawManager+0x84]==expectedRoot;',
                  'modelVerified=false;',
                  'modelVerified=uiAbi && uiPage && managerAbi && managerPage && managerSame && rootSame;'):
        need(token in relation, 'MANAGER_DIAGNOSTIC_REJECTED')
    need(relation.index('uiPage=uiAbi') < relation.index('mem::int_ptr[ui+0x118]')
         and relation.index('managerPage=managerAbi') < relation.index('mem::int_ptr[rawManager+0x84]'),
         'MANAGER_DIAGNOSTIC_ORDER_REJECTED')
    # New model output contains booleans only; no borrowed object address escapes.
    output = relation[relation.index('return "'):]
    need(set(re.findall(r'\b[A-Za-z_]\w*\b', _masked(output))) <=
         {'return', 'uiAbi', 'uiPage', 'managerAbi', 'managerPage', 'managerSame', 'rootSame'},
         'MANAGER_DIAGNOSTIC_OUTPUT_REJECTED')
    alias = _function(source, 'ahCompactUiAliasDiagnosticV108')
    need('bool&out modelVerified)' in source and 'bool&out currentModelVerified)' in source
         and _masked(relation).count('modelVerified=') == 2
         and 'currentModelVerified=false;bool heldModelVerified=false;' in alias
         and 'string heldRelation=ahCompactUiManagerDiagnosticV108(held,expectedManager,expectedRoot,heldModelVerified);' in alias
         and 'string currentRelation=ahCompactUiManagerDiagnosticV108(current,expectedManager,expectedRoot,currentModelVerified);' in alias
         and _masked(alias).count('currentModelVerified=') == 1,
         'CURRENT_MODEL_BINDING_REJECTED')
    need(re.search(r'state\.bindingFailureStage=10;bool currentModelVerified=false;\s*'
                   r'state\.uiAliasDiagnostic=ahCompactUiAliasDiagnosticV108\(mem::int_ptr\[plain\+0x20\],'
                   r'ahStatusUi\.self,manager\.self,root\.self,currentModelVerified\);\s*'
                   r'if\(!currentModelVerified\)return false;\s*state\.bindingFailureStage=11;', _masked(bind)) is not None
         and 'mem::int_ptr[plain+0x20]!=ahStatusUi.self' not in bind
         and bind.count('ahCompactUiAliasDiagnosticV108(') == 1,
         'CURRENT_MODEL_BINDING_REJECTED')
    metadata = _function(source, 'ahCompactMetadataAliasDiagnosticV108')
    need('bool providerMatch=provider!=0 && held==provider;' in metadata
         and _masked(metadata).count('providerMatch=') == 1,
         'PROVIDER_ROLE_REJECTED')
    need(re.search(r'state\.bindingFailureStage=11;\s*if\(ahPlanProvider==0 \|\| mem::int_ptr\[plain\+0x6c\]!=ahPlanProvider\)\s*\{\s*'
                       r'state\.metadataAliasDiagnostic=ahCompactMetadataAliasDiagnosticV108\(mem::int_ptr\[plain\+0x6c\],'
                       r'manager\.self,root\.self,ahPlanProvider\);return false;', _masked(bind)) is not None,
         'DIAGNOSTIC_REFUSAL_REJECTED')
    need(not re.search(r'\b(?:capture|cancel|save|update|business)\s*\(', code, re.I), 'SIDE_EFFECT_REJECTED')
    return dict(functionOnly=True, compactReadOnly=True, reusableWideCalls=0, nativePermit=False,
                captureAuthorized=False, staleRefreshVerified=False, lockGenerationVerified=False)


def _platform_contract():
    pe = PE('devtool.dll')
    table = pe.offset(pe.base + 0x1869bc)
    for slot, rva in ((0, 0x11af90), (1, 0x10e4e0), (2, 0x11afb0), (40, 0x19e20)):
        need(struct.unpack_from('<I', pe.data, table + slot * 4)[0] == pe.base + rva, 'PROVIDER_SLOT_REJECTED')
    table = pe.offset(pe.base + 0x18dbdc)
    for slot, rva in ((0, 0x14e4d0), (1, 0x14e520), (2, 0x14e4f0)):
        need(struct.unpack_from('<I', pe.data, table + slot * 4)[0] == pe.base + rva, 'CONTROLLER_SLOT_REJECTED')
    for name, (first, end, sha) in RANGES.items():
        data = pe.data[pe.offset(pe.base + first):pe.offset(pe.base + end)]
        need(hashlib.sha256(data).hexdigest() == sha, 'WHOLE_BODY_REJECTED')
        if name.endswith('QI'):
            need(data[0:3] == bytes.fromhex('55 8b ec') and data[23:26] == bytes.fromhex('c2 0c 00'), 'QI_ABI_REJECTED')
        if name.endswith('Map'):
            need(struct.unpack_from('<i', data, 4)[0] == 0, 'UNKNOWN_OUTPUT_OFFSET_REJECTED')
        if name == 'unknownSpecialBranch':
            # IUnknown: self+map[4] (both maps0), AddRef via result.slot1,
            # then transfer counted result to caller output and HRESULT0.
            need(data[0x4d:0x5f] == bytes.fromhex('8b 72 04 03 f0 56 8b 06 ff 50 04 8b 4d 0c 33 c0 89 31'),
                 'COUNTED_OUTPUT_REJECTED')
    platforms = {'devtool.dll': HASHES['devtool.dll'].lower()}
    for module in ('frame.dll', 'config.dll', 'frntend.dll', 'backend.dll', 'crcore.dll', 'rclient.dll', 'core83.dll'):
        PE(module)  # Only read/hash PE bytes; never load a DLL.
        platforms[module] = HASHES[module].lower()
    ui = PE('frntend.dll'); slices = {}
    for name, (rva, size, sha) in UI_RANGES.items():
        body = ui.data[ui.offset(ui.base + rva):ui.offset(ui.base + rva) + size]
        need(hashlib.sha256(body).hexdigest() == sha, 'UI_ALIAS_LAYOUT_REJECTED');slices[name] = body
    need(struct.unpack('<III', slices['primaryTable']) == tuple(ui.base + r for r in (0x962ba0, 0x962c00, 0x962bc0))
         and struct.unpack('<III', slices['typedTable']) == tuple(ui.base + r for r in (0x9643ce, 0x9643c4, 0x96429f))
         and struct.unpack_from('<i', slices['qiMap'], 4)[0] == 4, 'UI_ALIAS_OFFSET_REJECTED')
    # The constructor prefix stores primary atself and published UI atself+4;
    # this is a static layout witness, never an actual live instance claim.
    need(slices['constructorPrefix'][15:21] == b'\xc7\x06' + struct.pack('<I', ui.base + 0xc0e588)
         and slices['constructorPrefix'][23:30] == b'\xc7\x46\x04' + struct.pack('<I', ui.base + 0xc0e458),
         'UI_ALIAS_CONSTRUCTOR_REJECTED')
    images = {'frntend.dll': ui, 'backend.dll': PE('backend.dll')}
    def read_manager_slice(module, rva, size):
        image = images[module];start = image.offset(image.base + rva)
        return image.data[start:start + size]
    manager_relation = _manager_layout(read_manager_slice)
    role_images = {'config.dll': PE('config.dll'), 'devtool.dll': pe}
    def read_role_slice(module, rva, size):
        image = role_images[module];start = image.offset(image.base + rva)
        return image.data[start:start + size]
    provider_role = _provider_role_layout(read_role_slice)
    return dict(platformSha256=platforms, providerSlot=40, outputBytes=32,
                statisticAbi='stdcall(self,out32,const Guid*)', calleeStackPop=12,
                meaningfulByteOffsets=list(range(5)) + list(range(8, 32)), wholeFunctionShas={k: v[2] for k, v in RANGES.items()},
                uiAliasLayoutShas={k: v[2] for k, v in UI_RANGES.items()}, uiAliasRuntimeVerified=False,
                **manager_relation, **provider_role)


def _manager_layout(read_slice):
    """Static cached-field semantics only; never execute the getter slowpath."""
    need(callable(read_slice), 'MANAGER_READER_REJECTED');data = {}
    for name, (module, rva, size, digest) in MANAGER_RANGES.items():
        try:raw = read_slice(module, rva, size)
        except Exception:raise ValueError('V108_STATIC_MANAGER_SLICE_REJECTED') from None
        need(type(raw) is bytes and len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
             'MANAGER_SLICE_REJECTED');data[name] = raw
    # Preferred addresses are relocated only for this installed PE baseline.
    front, back = 0x26dc0000, 0x1f400000
    need(tuple(struct.unpack_from('<I', data['typedUiTable26'], n * 4)[0] - front for n in (0, 1, 2, 26))
         == (0x9643ce, 0x9643c4, 0x96429f, 0x147b90), 'MANAGER_UI_SLOT_REJECTED')
    need(tuple(struct.unpack_from('<I', data['managerTable85'], n * 4)[0] - back for n in (0, 1, 2, 85))
         == (0xa72ad0, 0x967510, 0xa72af0, 0x2aeb40), 'MANAGER_SLOT_REJECTED')
    getter = data['uiGetter26'];head = data['managerCachedEntry']
    need(getter[6:12] == bytes.fromhex('8b 88 18 01 00 00')
         and getter[22:33] == bytes.fromhex('8b 01 6a 00 51 ff 90 54 01 00 00')
         and getter[-3:] == bytes.fromhex('c2 04 00'), 'MANAGER_UI_FIELD_REJECTED')
    need(head[0x4e:0x54] == bytes.fromhex('8b 87 84 00 00 00')
         and head[0x5a:0x5e] == bytes.fromhex('85 c0 74 20')
         and head[-5] == 0xe9
         and 0x2aeb40 + len(head) + struct.unpack_from('<i', head, len(head) - 4)[0] == 0x2af5b7
         and data['managerCachedExit'][-3:] == bytes.fromhex('c2 08 00'), 'MANAGER_CACHED_FIELD_REJECTED')
    return dict(uiManagerRelationLayoutVerified=True, managerRelationRuntimeVerified=False,
                managerGetterExecuted=False, diagnosticNativeCalls=0,
                uiManagerRelationShas={k: v[3] for k, v in MANAGER_RANGES.items()})


def _provider_role_layout(read_slice):
    """Close stock field/argument roles only; no factory or getter is called.

    This does not identify a live provider instance. Runtime binding still
    requires exact fresh provider equality and all later manager/root guards.
    """
    need(callable(read_slice), 'PROVIDER_READER_REJECTED');data = {}
    for name, (module, rva, size, digest) in PROVIDER_ROLE_RANGES.items():
        try:raw = read_slice(module, rva, size)
        except Exception:raise ValueError('V108_STATIC_PROVIDER_SLICE_REJECTED') from None
        need(type(raw) is bytes and len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
             'PROVIDER_SLICE_REJECTED');data[name] = raw
    config, devtool = 0x25e40000, 0x30af0000
    need(data['configWiring'] == bytes.fromhex('6a00 ff711c ff716c 8b07 57 ff500c')
         and bytes.fromhex('8b416c 89796c') in data['configFieldStore'], 'PROVIDER_ARGUMENT_REJECTED')
    need(data['serviceIid'] == data['controllerServiceIid']
         == bytes.fromhex('b6d1bebc7b8c834ab005449568a3db33')
         and data['serviceClsid'] == data['controllerServiceClsid']
         == bytes.fromhex('3005d5a5796bfb4f8f35a5a2159ae617'), 'PROVIDER_SERVICE_ID_REJECTED')
    need(b'\xff\x15' + struct.pack('<I', config + 0x2ad780) in data['currentProcessService']
         and b'\x68' + struct.pack('<I', config + 0x2ba29c) in data['serviceAcquisition']
         and b'\x68' + struct.pack('<I', config + 0x2ba8a0) in data['serviceAcquisition']
         and bytes.fromhex('ff5014') in data['serviceAcquisition'], 'PROVIDER_SERVICE_CHAIN_REJECTED')
    need(struct.unpack_from('<I', data['serviceRegistration'], 0)[0] == devtool + 0x18e96c
         and struct.unpack_from('<I', data['serviceRegistration'], 12)[0] == devtool + 0x14baf0,
         'PROVIDER_FACTORY_REJECTED')
    factory = data['factoryEntry'];constructor = data['defaultControllerConstructor']
    need(factory[16] == 0xe8 and 0x14baf0 + 21 + struct.unpack_from('<i', factory, 17)[0] == 0x14d760
         and b'\xc7\x06' + struct.pack('<I', devtool + 0x18dbdc) in constructor
         and b'\xc7\x46\x08' + struct.pack('<I', devtool + 0x18db1c) in constructor,
         'PROVIDER_CONTROLLER_CLASS_REJECTED')
    need(struct.unpack_from('<II', data['controllerMap'], 12) == (devtool + 0x18efd0, 8)
         and struct.unpack_from('<I', data['controllerOpsTable3'], 12)[0] == devtool + 0xbc640,
         'PROVIDER_CONTROLLER_SLOT_REJECTED')
    stores = data['controllerProviderManagerStore']
    need(bytes.fromhex('8b7d08 8b5d0c') in stores
         and bytes.fromhex('8b4728 8d4d14 894514 895f28') in stores
         and bytes.fromhex('8b5d10') in stores
         and bytes.fromhex('8b472c 8d4d14 894514 895f2c') in stores,
         'PROVIDER_CONTROLLER_FIELD_REJECTED')
    return dict(providerRoleLayoutVerified=True, providerRoleRuntimeVerified=False,
                providerRoleSourceFieldOffset=0x6c, controllerProviderOffset=0x30,
                controllerManagerOffset=0x34, providerRoleNativeCalls=0,
                providerRoleShas={k: v[3] for k, v in PROVIDER_ROLE_RANGES.items()})


def verify_static():
    source = AS_SOURCE.read_bytes()
    try:
        result = verify_source(source.decode('utf-8-sig'))
    except UnicodeError:
        raise ValueError('V108_STATIC_SOURCE_REJECTED') from None
    for name, expected in DEPENDENCIES.items():
        need(hashlib.sha256((TESTS / name).read_bytes()).hexdigest() == expected, 'DEPENDENCY_REJECTED')
    result.update(_platform_contract(), sourceSha256=hashlib.sha256(source).hexdigest(),
                  dependencySha256=dict(DEPENDENCIES), runtimeExecuted=False, entireGoalComplete=False)
    return result
