"""Pure V82 prerequisite: fixed V78 ABI plus a bounded helper identity branch.

Reads only fixed SDK/PE and the two scoped source files. Does not execute native
code, prepare a cache, connect, or grant a writer/close permission.
"""
import hashlib
from pathlib import Path
import re
import uuid

import gold_own_object_module_contract_v78 as prior
import processing_object_module_helper_contract_v94 as processing
import processing_object_module_editor_contract_v98 as editor
from repository_pe_probe import PE

HERE = Path(__file__).resolve().parent
AS_SOURCE = HERE.parent / 'tests/NativeGoldOwnObjectModuleV82.as'
PRIOR_SHA = 'f1e00bbe5e6a9fa34b20c767ec94e060b8ebcabc24e24b2e41c85f0890db2901'
PROCESSING_SHA = 'be2dcce9fa7fadd217b02bf6278d64201ebee77ce8f748a64b93af12c749fc0b'
EDITOR_SHA = 'b3af3a0d35007d452aafe7254abf7b4e568d5b51f27daef6206e63b68b5a538c'
OWN_ID = '2c8d17c0-17b1-514d-bf64-c3267719bdfe'
MAPPING_BRANCH = bytes.fromhex('33359cc7d5243315a0c7d524330d94c7d524330598c7d5240bf10bd00bf2750c0f100584c7d524e9b0000000')
MAPPING_GUIDS = bytes.fromhex('a9a1224d09e14246a9eb2e71f37f72b1185184bf7b328246b5c6285d2a0eb296')


def need(ok, code):
    if not ok:
        raise ValueError('GOM82_STATIC_' + code)


def verify_mapping(branch, guids):
    need(type(branch) is bytes and branch == MAPPING_BRANCH, 'MAPPING_BRANCH_REJECTED')
    need(type(guids) is bytes and guids == MAPPING_GUIDS, 'MAPPING_GUIDS_REJECTED')
    need(str(uuid.UUID(bytes_le=guids[16:])) == 'bf845118-327b-4682-b5c6-285d2a0eb296'
         and str(uuid.UUID(bytes_le=guids[:16])) == '4d22a1a9-e109-4642-a9eb-2e71f37f72b1',
         'MAPPING_IDENTITY_REJECTED')


def _block(source, anchor):
    """Locate a fixed brace block after masking comments and literal contents."""
    masked = re.sub(r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/',
                    lambda m: re.sub(r'[^\r\n]', ' ', m.group()), source)
    start = source.find(anchor)
    need(start >= 0 and source.find(anchor, start + 1) < 0, 'SOURCE_ANCHOR_REJECTED')
    opening = masked.find('{', start)
    need(opening >= 0, 'SOURCE_BLOCK_REJECTED')
    depth = 0
    for at in range(opening, len(masked)):
        if masked[at] == '{': depth += 1
        if masked[at] == '}':
            depth -= 1
            if depth == 0: return source[opening:at + 1]
    raise ValueError('GOM82_STATIC_SOURCE_BLOCK_REJECTED')


def verify_source(source):
    need(type(source) is str and 0 < len(source.encode('utf-8')) <= 65536, 'SOURCE_SIZE_REJECTED')
    need(OWN_ID in source and 'АгентПробаObjectModuleV82' in source
         and 'GOLD_OWN_OBJECT_MODULE_V82' in source and 'V78' not in source, 'SOURCE_SCOPE_REJECTED')
    # Processing has a different helper implementation from Document. Both
    # receivers must match before their method tables can be inspected.
    need('s.helperTableKnown=ahGoldModuleAddressV82(mem::int_ptr[helper.self],"basicui.dll",0x60ae54);' in source
         and 's.moduleTableKnown=ahGoldModuleAddressV82(mem::int_ptr[module.self],"basicui.dll",0x60ad5c);' in source,
         'SOURCE_PROCESSING_RECEIVER_REJECTED')
    known = _block(source, 'if(s.helperTableKnown && s.moduleTableKnown)')
    dispatched = _block(source, 'if(s.helperSlotsVerified)')
    need(all(value in known for value in ('ht+23*4', 'mt+5*4', 'mt+11*4',
             '0xf3b70', '0x35c470', '0x35c6f0'))
         and dispatched in known and source.count('helper.getMDObj()') == 2
         and 'helper.getMDObj()' in dispatched
         and 's.boundGraphVerified=s.boundEqualsOwn && ahGoldModuleGraphV82(bound)' in dispatched,
         'SOURCE_UNKNOWN_GETTER_REJECTED')
    before = source.index('if(!s.helperBound || !s.existingUi')
    initial = source.index('s.initialReadReturned=module.textOfModule(')
    length = source.index('if(!s.initialReadReturned || !s.initialLengthBounded || s.initialCharacters!=0')
    opening = source.index('s.nativeReturn=module.openModule(')
    need(before < initial < length < opening and source.count('module.openModule(') == 1,
         'SOURCE_PREOPEN_ORDER_REJECTED')
    need('moduleQiCalls' in source and 'helperProbe' in source
         and 's.helperStage="openReady"' in source and 's.helperStage="initialText"' in source,
         'SOURCE_DIAGNOSTICS_REJECTED')
    verify_open_diagnostics(source)
    verify_document_diagnostics(source)
    for forbidden in ('setModified(', 'saveConfig(', 'UpdateDBCfg(', 'SOURCE_ONCE',
                      'loadFromFile(', 'exportConfig(', 'ahGoldWrite', 'ahOwnedSave'):
        need(forbidden not in source, 'SOURCE_FORBIDDEN_CALL_REJECTED')


def verify_open_diagnostics(source):
    """Guarded inventory only; preserve published calls and UNKNOWN exits."""
    opening = source.index('s.open++;s.nativeReturn=module.openModule(')
    returned = source.index('s.openReturned=true;s.openStage="afterOpenMarker";')
    observed = source.index('if(s.textNonNull)s.textTable=ahGoldModuleObservedAddressV82(')
    null_gate = source.index('if(text is null || editor is null){s.returnUnknown=true;return false;}')
    text_table = source.index('if(!s.textTableKnown){s.returnUnknown=true;return false;}')
    text_inventory = source.index('s.textManagerTarget=ahGoldModuleObservedAddressV82(')
    text_slot = source.index('if(!s.textSlotsVerified){s.returnUnknown=true;return false;}')
    editor_table = source.index('if(!s.editorTableKnown){s.returnUnknown=true;return false;}')
    editor_inventory = source.index('s.editorQiTarget=ahGoldModuleObservedAddressV82(')
    editor_slot = source.index('if(!s.editorSlotsVerified){s.returnUnknown=true;return false;}')
    getter = source.index('editor.getITextManager(editorText)')
    need(opening < returned < observed < null_gate < text_table < text_inventory < text_slot
         < editor_table < editor_inventory < editor_slot < getter,
         'SOURCE_OPEN_DIAGNOSTIC_ORDER_REJECTED')
    for exact in (
            's.textTableKnown=ahGoldModuleAddressV82(tt,"txtedt.dll",0x46dc4);',
            's.textSlotsVerified=ahGoldModuleAddressV82(mem::int_ptr[tt+10*4],"txtedt.dll",0x2dcf0);',
            's.editorTableKnown=ahGoldModuleAddressV82(et,"txtedui.dll",0x10db3c);',
            's.editorSlotsVerified=ahGoldModuleAddressV82(mem::int_ptr[et],"txtedui.dll",0xe4680)\n        && ahGoldModuleAddressV82(mem::int_ptr[et+3*4],"txtedui.dll",0xa2020);',
            's.openStage="notReturned";', 's.openStage="nullOutputs";',
            's.openStage="textTable";', 's.openStage="textSlot";s.textSlotReads=1;',
            's.openStage="editorTable";', 's.openStage="editorSlots";s.editorSlotReads=2;',
            's.openStage="ready";', '+",\\"openProbe\\":"+ahGoldModuleOpenProbeV82(s)'):
        need(exact in source.replace('\r', ''), 'SOURCE_OPEN_DIAGNOSTIC_GUARD_REJECTED')
    need(source.count('editor.getITextManager(') == 1
         and source.count('module.openModule(') == 1
         and 's.nativeReturn==' not in source and 's.nativeReturn!=' not in source,
         'SOURCE_OPEN_EXTRA_CALL_OR_HRESULT_REJECTED')


def verify_document_diagnostics(source):
    bound = source.index('if(!s.editorBound){s.returnUnknown=true;return false;}')
    preqi = source.index('s.documentStage="qiNotCompleted";')
    qi = source.index('IDocument&& document=text.unk;IDocument&& goldDocument=ahPipeText.unk;')
    observed = source.index('s.documentQiObserved=true;s.documentNonNull=document !is null;')
    document = _block(source, 'if(document !is null)')
    known = _block(source, 'if(s.documentTableKnown)')
    call = source.index('s.initialClean=!document.isModified();s.writable=!document.getReadOnly();')
    graph = source.index('if(!s.opened){s.returnUnknown=true;return false;}')
    need(bound < preqi < qi < observed < source.index('if(document !is null)') < graph < call
         and known in document
         and 's.documentTableKnown=ahGoldModuleAddressV82(dt,"txtedui.dll",0x109978);' in document
         and 's.documentStage="documentSlots";s.documentSlotReads=2;' in known
         and 's.modifiedTarget=ahGoldModuleObservedAddressV82(mem::int_ptr[dt+8*4]);' in known
         and 's.readOnlyTarget=ahGoldModuleObservedAddressV82(mem::int_ptr[dt+22*4]);' in known
         and 's.documentSlotsVerified=ahGoldModuleAddressV82(mem::int_ptr[dt+8*4],"txtedui.dll",0x74450)\n                && ahGoldModuleAddressV82(mem::int_ptr[dt+22*4],"txtedui.dll",0x7d7d0);' in known
         and 's.documentKnown=s.documentSlotsVerified;' in source
         and 's.opened=s.documentKnown && s.editorBound' in source,
         'SOURCE_DOCUMENT_DIAGNOSTIC_GUARD_REJECTED')
    for exact in ('editorText.self==text.self',
                  'mem::addressOf(editorText.getTextManager())==mem::addressOf(text.getTextManager())',
                  '+",\\"documentProbe\\":"+ahGoldModuleDocumentProbeV82(s)'):
        need(exact in source, 'SOURCE_DOCUMENT_BINDING_OR_SHAPE_REJECTED')
    need(source.count('IDocument&& document=text.unk;') == 1
         and source.count('IDocument&& goldDocument=ahPipeText.unk;') == 1
         and source.count('document.isModified()') == 3
         and source.count('document.getReadOnly()') == 1
         and source.count('helper.getMDObj()') == 2,
         'SOURCE_DOCUMENT_EXTRA_CALL_REJECTED')


def verify_static():
    need(hashlib.sha256(Path(prior.__file__).read_bytes()).hexdigest() == PRIOR_SHA,
         'PRIOR_CONTRACT_CHANGED')
    need(hashlib.sha256(Path(processing.__file__).read_bytes()).hexdigest() == PROCESSING_SHA,
         'PROCESSING_CONTRACT_CHANGED')
    need(hashlib.sha256(Path(editor.__file__).read_bytes()).hexdigest() == EDITOR_SHA,
         'EDITOR_CONTRACT_CHANGED')
    report = prior.verify_static()
    processing_report = processing.verify_static()
    editor_report = editor.verify_static()
    editor.verify_binding(0x10db3c, (0xe4680, 0xe45ab, 0xe439d, 0xa2020))
    processing.verify_binding((0x60ae54, 0x60ad5c), (0xf3b70, 0x35c470, 0x35c6f0))
    pe = PE('basicui.dll')
    at = pe.offset(pe.base + 0x1265)
    guid_at = pe.offset(pe.base + 0x5ec784)
    verify_mapping(pe.data[at:at + 44], pe.data[guid_at:guid_at + 32])
    verify_source(AS_SOURCE.read_text(encoding='utf-8-sig'))
    return report | dict(version='V82', implementationRevision=4, priorContractSha256=PRIOR_SHA,
        pinnedRanges=report['pinnedRanges']+processing_report['pinnedRanges']+editor_report['pinnedRanges'],
        processingHelperContractSha256=PROCESSING_SHA, processingHelperStaticContract=processing_report,
        processingEditorContractSha256=EDITOR_SHA, processingEditorStaticContract=editor_report,
        sourceDiagnosticDispatchOrderVerified=True, processingHelperClassGuidBranchVerified=True,
        mappedHelperClassId='4d22a1a9-e109-4642-a9eb-2e71f37f72b1',
        mappingBranchRva=0x1265, mappingBranchSha256=hashlib.sha256(MAPPING_BRANCH).hexdigest(),
        helperFactoryClassMappingIndependentlyProven=False,
        actualProcessingHelperTableRuntimeVerified=False,
        runtimeObjectModuleUndoVerified=False, nativePermitGranted=False,
        goldSavePermitted=False, databaseUpdatePermitted=False, persistedGoldVerified=False)
