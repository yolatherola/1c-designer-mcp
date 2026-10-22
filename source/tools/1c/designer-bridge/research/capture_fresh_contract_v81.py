"""Offline, hash-pinned contract for the two-phase exact Document CaptureFresh.

Only source text and fixed PE bytes are read. No cache preparation, DLL loading,
runtime process, IB, repository, connection, or configuration payload is opened.
Static compatibility never grants capture or proves a native trial succeeded.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import struct

from repository_pe_probe import PE, HASHES

HERE = Path(__file__).resolve().parent
AS_SOURCE = HERE.parent / 'tests' / 'NativeCaptureFreshV81.as'
SOURCE_LIMIT = 65536
DEPENDENCIES = {
    'NativeRepositoryObserve.as': 'd7ac427467016667ac2b9e84a97a92727ef6955a2bf5dc439d4da36871bff16d',
    'NativeRepositoryPlan.as': '77738f69fab72dafbd35c342bbd4e3a3090cc548f7dcd741df69a2dda4daeebd',
    'NativeRepositorySource.as': '64c20dd68c7e79f3ad4ad77a313081fc4c842e0f9431df86a3703c939131ad25',
    'NativeFactoryCopyV49.as': '1dc54ce7cbf4e96a4efbfefc05eb864feacc66a5de06d403f291a8e0ef6915fb',
    'NativeCaptureNotificationV56.as': '7827bef256dd0d223b4932e2bbfa79232c318d5da8cf6d1f21299500637d64f1',
    'NativeStatisticPacketV54.as': '7dbd0a7b804ba313c143b3cd3eab83fd9c9617240f1c8d584246df6180ca9f7c',
    'NativeSelectionInputsV46.as': '0b070f9492c67cfdd4a94a59e8c8e692f97e1e3f97fa669fef57bceac5a4381f',
}
SELECTOR_SHA = 'fce50b4a42b2ad181480549eb78117133d316b405d3551631ed44d64eaf8be29'


def need(ok, code):
    if not ok:
        raise ValueError('V81_STATIC_' + code)


def _wrapper(entry, inner):
    return (bytes.fromhex('55 8b ec 8b 4d 08 6a 00 ff 75 0c 8d 49 f8 e8')
            + struct.pack('<i', inner - (entry + 19)) + bytes.fromhex('5d c2 08 00'))


def _platform_contract():
    pe = PE('devtool.dll')
    table = pe.offset(pe.base + 1628956)
    wrappers = []
    for slot, entry, inner in ((9, 0xbd600, 0xbcea0), (13, 0xbedf0, 0xbeee0)):
        actual = struct.unpack_from('<I', pe.data, table + slot * 4)[0]
        need(actual == pe.base + entry, 'STOCK_SLOT')
        at = pe.offset(actual)
        body = pe.data[at:at + 23]
        need(body == _wrapper(actual, pe.base + inner), 'STOCK_WRAPPER')
        wrappers.append({'slot': slot, 'entryRva': entry, 'explicitSelf': True, 'calleePopBytes': 8,
                         'sha256': hashlib.sha256(body).hexdigest()})
    provider = pe.offset(pe.base + 1599932)
    for slot, entry in ((10, 88256), (38, 104624), (49, 115488)):
        need(struct.unpack_from('<I', pe.data, provider + slot * 4)[0] == pe.base + entry, 'PROVIDER_SLOT')
    at = pe.offset(pe.base + 0x18eaac)
    selector = pe.data[at:at + 32]
    need(struct.unpack_from('<i', selector)[0] == -1 and hashlib.sha256(selector).hexdigest() == SELECTOR_SHA,
         'SELECTOR')
    # Whole-function slice witnesses; no disassembler or native execution.
    for first, end, sha in (
        (0xbcea0, 0xbd600, '02cc06cc9e7b7839d9ceb2f7914f2fa706a3e1da219b9761ed6c832339602e3a'),
        (0xb3c88, 0xb3d42, '22d6506939402129edca5a5a872a1b96b51a03d47bc916afd5fad90559de87c6')):
        a, b = pe.offset(pe.base + first), pe.offset(pe.base + end)
        need(hashlib.sha256(pe.data[a:b]).hexdigest() == sha, 'STOCK_SLICE')
    return {'platformSha256': HASHES['devtool.dll'].lower(), 'stockWrappers': wrappers,
            'selectorSha256': SELECTOR_SHA, 'selectorFirstDword': -1}


def _masked(source):
    """Mask strings/comments while preserving offsets for balanced code slices."""
    pattern = r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/'
    return re.sub(pattern, lambda match: re.sub(r'[^\r\n]', ' ', match.group()), source)


def _function(source, name):
    masked = _masked(source)
    match = re.search(r'(?m)^(?:bool|string|int_ptr)\s+' + re.escape(name) + r'\([^)]*\)\s*\{', masked)
    need(match is not None, 'FUNCTION_' + name)
    start = match.end() - 1
    depth = 0
    for at in range(start, len(masked)):
        if masked[at] == '{': depth += 1
        if masked[at] == '}':
            depth -= 1
            if depth == 0:
                return source[start:at + 1]
    raise ValueError('V81_STATIC_UNBALANCED_FUNCTION')


def _order(body, *pieces):
    cursor = 0
    for piece in pieces:
        at = body.find(piece, cursor)
        need(at >= 0, 'ORDER')
        cursor = at + len(piece)


def _source_contract(source):
    need(type(source) is str and 0 < len(source.encode('utf-8')) <= SOURCE_LIMIT, 'SOURCE_SIZE')
    masked = _masked(source)
    stack = []
    pairs = {'}': '{', ')': '(', ']': '['}
    for char in masked:
        if char in '{([': stack.append(char)
        elif char in '})]':
            need(bool(stack) and stack.pop() == pairs[char], 'DELIMITERS')
    need(not stack, 'DELIMITERS')
    forbidden = {'setMdPropVal', 'setProp', 'saveConfig', 'updateDBCfg', 'applyObjects', 'packetApply',
                 'ahSourceFetchOnce', 'ahSourceModuleOnce', 'ahSourceModuleTextOnce', 'ahCaptureNotificationV56'}
    need(not forbidden.intersection(re.findall(r'\b[A-Za-z_][A-Za-z_0-9]*\b', masked)), 'FORBIDDEN_CALL')
    need(not re.search(r'\b(?:ahSourceFetched|ahSourceModuleFetched|ahV48Consumed|ahSourcePacket)\s*=', masked),
         'CACHE_STATE_WRITE')
    need(masked.count('ahV81Capture(') == 1 and masked.count('ahV81Cancel(') == 1, 'STOCK_CALL_COUNT')
    need('bool AhCaptureFreshStockV81(int_ptr self,int_ptr requested)' in source, 'STOCK_SIGNATURE')
    prepare = _function(source, 'ahCaptureFreshV81Prepare')
    _order(prepare, 'ahCaptureFreshV81Permit(operation,"prepare")', 'ahV81Started=true',
           '!ahRepoGenerationVerified', 'ahRepoLastRevised || ahRepoLastRevisor!=IID_NULL',
           '061d872a-5787-460e-95ac-ed74ea3a3e84', 'ahV81RequestClone()', 'ahV81Clean(false,false)',
           'ahCycleDurable("capture-fresh-v81-capture-dispatched",operation)', 'ahV81Captured=true;ahV81Unknown=true',
           'requested.alloc(1,16)', 'ahV81Capture(ahV81Controller+8,requested.self)', 'ahV81Clean(true,false)',
           'ahV81Witness=ahRepoStatisticBytes', 'ahV81Marker("captureObserved")', 'ahV81FreshPacket()',
           'ahV81ReleaseRequest()', 'ahV81Descriptor(true)', 'ahV81Modules(true,true)', 'ahV81Marker("sourceObserved")')
    cancel = _function(source, 'ahCaptureFreshV81VerifyCancel')
    _order(cancel, 'ahCaptureFreshV81Permit(operation,"verify-cancel")', 'ahV81FinishUsed=true', 'ahV81Unknown=true',
           'ahV81Clean(true,true)', 'ahV81Descriptor(false)', 'ahV81Modules(false,true)',
           'ahV81Marker("cancelDispatched")', 'requested.alloc(1,16)', 'ahV81CancelDispatched=true',
           'ahV81Cancel(ahV81Controller+8,requested.self)', 'ahV81Clean(false,false)', 'ahV81Descriptor(false)',
           'ahV81Modules(false,false)', 'ahV81Marker("cancelObserved")')
    need('ahV81Cancel(' not in prepare and 'ahV81Capture(' not in cancel, 'PHASE_SEPARATION')
    permit = _function(source, 'ahCaptureFreshV81Permit')
    for fragment in ('if(ahV81Started)return false', '!ahV81Prepared || ahV81FinishUsed',
                     'operation==ahV81CaptureOperation', '__SESSION_ID__', 'ahGetCurrentProcessId()',
                     'ahV81Birth', 'ahV81Version', 'capture-fresh-v81-verify-cancel.permit'):
        need(fragment in permit, 'PERMIT_SCOPE')
    need('return !ahV81Captured || (ahV81Cancelled && !ahV81Unknown && !ahV81Exception)' in source, 'SAFE_TERMINAL')
    record = _function(source, 'ahV81FreshRequestRecord')
    _order(record, 'ahFactoryV49Collection(ahV81Request)', 'ahSelectionInputV46Map(ahV81Request)',
           'ahPlanObjectInfo(', 'actual!=id', 'int_ptr target=', 'ahStatisticBindingVariantDtorV54(target+0x20)',
           'ahCaptureV56RecordCopy(target,', 'ahFactoryV49RecordEqual(expected,after)',
           'ahStatisticBindingVariantDtorV54(mem::addressOf(server[16+0x20]))', 'mem::byte[target+0x64+n]=0')
    need(not re.search(r'mem::memcpy\(\s*target\b', _masked(record)), 'RAW_OWNED_RECORD_COPY')
    packet = _function(source, 'ahV81FreshPacket')
    _order(packet, 'ahV81FreshRequestRecord()', 'ahV81Clean(true,true)', 'ahSourceConstruct(',
           'selector=GetModuleHandle("devtool.dll".cstr)+0x18eaac', 'int(mem::dword[selector])!=-1',
           'ahSourceGetObjects(ahV81Provider,', 'ahV81Request', 'ahV81ResultScope=bound',
           'count<=1', '1139556', 'ahSourceFind(packet,id.self)', '1139492',
           'ahV81ReadFile(', 'ahV81PacketScope=ok;ahSourceDestruct(', 'ahV81Clean(true,true)')
    need(not re.search(r'mem::dword\[selector\]\s*=', _masked(packet)), 'SELECTOR_WRITE')
    bind = _function(source, 'ahV81Bind')
    for delegate in ('ahV81Capture', 'ahV81Cancel', 'ahSourceExternalFile', 'ahSourceGetObjects',
                     'ahSourceFind', 'ahSourceMainFileGetter'):
        need(re.search(r'if\(' + delegate + r' is null\)initFuncDefFromAddress', bind) is not None, 'BIND_ONCE')
    modules = _function(source, 'ahV81Modules')
    _order(modules, 'cls.propertiesCount>256', 'for(uint n=0;n<cls.propertiesCount;n++)', 'module.hasModule(',
           'A637F77F-3840-441D-A1C3-699C8C5CB7E0', 'D1B64A2C-8078-4982-8190-8F81AEFDA192',
           'path.substr(start).lowered()!=resource', 'module.textOfModule(prop,false,a)',
           'module.textOfModule(prop,true,b)', 'a.str!=b.str', 'ahV81External(resource,',
           'ahV81Clean(owned,owned)', 'return count==2 && seen0 && seen2')
    need('b.str!=ahV81Texts[at+1]' in modules, 'FRESH_CANCEL_SOURCE')
    return {'sourceSha256': hashlib.sha256(source.encode('utf-8')).hexdigest(), 'stockCallsPerPhase': 1,
            'twoPhaseComparisonRequired': True, 'bindOnceVerified': True, 'countedRecordCopyVerified': True}


def verify_static(source=None):
    """Validate only local static compatibility; native permission remains false."""
    if source is None:
        source = AS_SOURCE.read_bytes().decode('utf-8')
    proof = _source_contract(source)
    deps = {}
    for name, expected in DEPENDENCIES.items():
        actual = hashlib.sha256((HERE.parent / 'tests' / name).read_bytes()).hexdigest()
        need(actual == expected, 'DEPENDENCY_HASH')
        deps[name] = actual
    return {**proof, **_platform_contract(), 'dependencySha256': deps, 'staticCompatible': True,
            'nativePermit': False, 'nativeMethodsExecuted': 0, 'currentContentVerified': False,
            'staleRefreshVerified': False, 'lockGenerationVerified': False,
            'externalChildDescriptionsVerified': False, 'externalChildBodiesVerified': False,
            'persistedGoldVerified': False}
