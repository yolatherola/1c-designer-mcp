"""Offline V99 source/Constant prerequisite; importing grants no native call.

Frozen V77 corrected class/type-copy proof is separate from V82 Gold Processing
patterns. Neither establishes this new Constant's actual live-root capability.
"""
import hashlib
import importlib
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'tests/NativeGoldOwnedConstantV99.as'
SOURCE_SHA256 = '6249c98886947d95a5f229923a75d5d5ec7bde0a07ca228bc7a5ed0e194d0799'
BASE_SHAS = {
    'research/owned_constant_contract_v77.py': '7ef3d3b8b64566e02d1d398f8668a396b1690ebe67bfeb1c4e4e6ffce42d8fd0',
    'tests/NativeOwnedTypeHelpersV77.as': '7f231c1137e790062da537cad6b7044736dfccaef0daef9ff77fb09188346c59',
}
PATTERN_SHAS = {
    'NativeOwnedConstantV77.as': 'b195932d8ca8522fd82c4ef25140806fa7e5c5a33402a028eb9da70000f19e1e',
    'NativeGoldOwnObjectModuleV82.as': 'ddf4db4e400886500f4e0abf5d2c366c440043a69975bc6e759d9eb507856cb9',
}
CONSTANT = '0195e80c-b157-11d4-9435-004095e12fc7'
OWN = 'e61c6271-9d05-4b8f-a25a-65b3c67f3e9e'


def _need(ok, code):
    if not ok:
        raise ValueError(code)


def _mask(text):
    # Preserve positions/newlines while excluding comments/string data from the
    # side-effect/top-level scan. The exact AS compiler remains a separate gate.
    return re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"',
                  lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text, flags=re.S)


def _function_only(code):
    depth = 0
    start = 0
    top = []
    for index, char in enumerate(code):
        if char == '{':
            if depth == 0:
                head = code[start:index].strip()
                _need(re.fullmatch(r'class\s+AhGCStateV99|(?:bool|Guid|string)\s+\w+\s*\([^{};]*\)', head) is not None,
                      'GC99_EXECUTABLE_GLOBAL_REJECTED')
                top.append(head)
            depth += 1
        elif char == '}':
            depth -= 1
            _need(depth >= 0, 'GC99_SOURCE_BALANCE_REJECTED')
            if depth == 0:
                start = index + 1
        elif char == ';' and depth == 0:
            item = code[start:index].strip()
            _need(re.fullmatch(r'funcdef\s+(?:int_ptr|void)\s+AhGC(?:Factory|Attach|Delete)V99\s*\([^{};]*\)', item) is not None,
                  'GC99_EXECUTABLE_GLOBAL_REJECTED')
            start = index + 1
    _need(depth == 0 and not code[start:].strip(), 'GC99_SOURCE_BALANCE_REJECTED')
    _need(sum(h.startswith('string ahGoldOwnedConstantV99(') for h in top) == 1,
          'GC99_ENTRY_REJECTED')


def verify_source(raw):
    """Validate the fixed function-only candidate; not runtime or writer proof."""
    _need(type(raw) is bytes and 0 < len(raw) <= 65536, 'GC99_SOURCE_BYTES_REJECTED')
    try:
        text = raw.decode('utf-8', 'strict')
    except UnicodeError:
        raise ValueError('GC99_SOURCE_ENCODING_REJECTED') from None
    code = _mask(text)
    _function_only(code)
    _need(OWN in text and CONSTANT in text and 'АгентДиагностикаКонстантыV99' in text
          and 'cf4abea7-37b2-11d4-940f-008048da11f9' not in text.lower(), 'GC99_CONSTANT_SCOPE_REJECTED')
    _need('!__GOLD_OWNED_CONSTANT_V99__' in code and 'if(consumed || !ahGCPermitV99(operation))' in code
          and code.index('consumed=true') < code.index('if(s.baseline)verified=ahGCRunV99')
          and '__GOLD_OWNED_CONSTANT_TOKEN_V99__|' in text, 'GC99_ROLE_ONESHOT_REJECTED')
    _need('bool&inout consumed,AhGCStateV99&inout s,bool&out terminalResult,uint&out attemptedWrites' in code
          and 'terminalResult=false;attemptedWrites=0;' in code
          and code.index('terminalResult=false;attemptedWrites=0;') < code.index('if(consumed ||')
          and 'AhGCStateV99 s;' not in code
          and 'terminalResult=terminal;attemptedWrites=s.factories+s.ids+s.attaches+s.names+s.setters+s.deletes;' in code,
          'GC99_CALLER_STATE_REJECTED')
    _need(not re.search(r'\b(?:connectConfig|LoadLibrary|GetProcAddress|SaveCfg|UpdateDBCfg|setModified|clearModified|eval|Execute|createByClsid)\s*\(', code)
          and not re.search(r'\.(?:save|load|update|capture|cancel|insert|erase)\s*\(', code.replace('.getTextManager().save(', '.getTextManager().readBuffer(')),
          'GC99_FORBIDDEN_EFFECT_REJECTED')
    _need(code.count('.setMdPropVal(') == 2 and code.count('s.own.setMdPropVal(') == 2
          and code.count('s.attach(s.root.self,s.own.self)') == 1
          and code.count('s.remove(s.root.self,kind.self,id.self)') == 1
          and code.count('s.factory(cls.self,output.bytes+16)') == 1,
          'GC99_FIXED_WRITER_REJECTED')
    required = ('0x8cca90', '0x4d93d0', '0x8c99b4', '0x4d77c0', '0x4d7950',
                '0xf15214', '0x5c6d10', '0x5c6e20', '0xc0e458', '0x147b90')
    _need(all(item in code for item in required), 'GC99_KNOWN_ABI_REJECTED')
    _need(code.index('if(!s.declared') < code.index('s.factories++')
          and code.index('s.registry=registry.length') < code.index('s.attaches++')
          and code.index('s.attaches++') < code.index('s.names++') < code.index('s.setters++')
          and code.index('if(!catcher.hasException && !s.unknown') < code.index('s.deletes++'),
          'GC99_OWNERSHIP_ORDER_REJECTED')
    _need('s.own.mdParentLink !is null' in code and 's.absentBefore' in code
          and 's.root.objById(ahGCIdV99()) is null' in code and '!s.root.isModified()' in code
          and '!ahRepoLastRevised' in code and 's.source.length>0' in code,
          'GC99_BASELINE_REJECTED')
    _need('queryIface(iid,manager)' in code and 'queryIface(iid,root)' in code
          and 'queryIface(iid,source)' in code and 'queryIface(iid,own)' in code,
          'GC99_CANONICAL_QI_REJECTED')
    _need('ahConstantBuiltinDescriptionV77(4,booleanValue)' in code
          and 'ahConstantDescriptionEqualV77(readValue.pValue,booleanValue.pValue)' in code
          and 'ahGCDescriptorV99(booleanValue)' in code,
          'GC99_OWN_BOOLEAN_REJECTED')
    # Source checks explain the contract, while the exact pin closes unlisted
    # call sites/side effects. A changed candidate needs a fresh local review.
    _need(hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'GC99_SOURCE_PIN_REJECTED')
    return dict(sourceContractVerified=True, sourceSha256=hashlib.sha256(raw).hexdigest(),
                constantClassId=CONSTANT, ownConstantId=OWN, functionOnly=True, callerHeldStateRequired=True,
                nativePermit=False, liveConstantVerified=False, defaultTypeVerified=False,
                persistedGoldVerified=False, databaseUpdateAuthorized=False,
                dedicatedHostRoleRequired=True, dedicatedClientRoleRequired=True,
                authenticatedPidBirthLeaseRequired=True, patternSourceShas=dict(PATTERN_SHAS))


def verify_static():
    """Read exact public sources/platform prerequisites; never load a DLL."""
    for name, expected in BASE_SHAS.items():
        body = (HERE.parent / name).read_bytes()
        _need(hashlib.sha256(body).hexdigest() == expected, 'GC99_BASE_HASH_REJECTED')
    base = importlib.import_module('owned_constant_contract_v77').verify_static()
    _need(base['constantClassId'] == CONSTANT and base['factoryTableRva'] == 0x8cca90
          and base['factoryRva'] == 0x4d93d0 and base['ownRootAttachRva'] == 0x5c6d10
          and base['ownRootDeleteRva'] == 0x5c6e20 and base['nativePermit'] is False,
          'GC99_PRIMARY_PREREQUISITE_REJECTED')
    result = verify_source(SOURCE.read_bytes())
    result['baseSourceShas'] = dict(BASE_SHAS)
    result['pinnedConstantStaticVerified'] = True
    return result
