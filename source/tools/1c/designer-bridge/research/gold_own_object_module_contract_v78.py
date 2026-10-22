"""Narrow fixed SDK/PE prerequisites. No cache controller, DLL load or Gold I/O."""
import hashlib
from pathlib import Path
import struct
import uuid
import zipfile

from repository_pe_probe import PE

SDK = Path(__file__).resolve().parents[4] / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40/snegopat.zip'
SDK_SHAS = {
    'modules/snegopat/v8api/metadata.v': 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed',
    'modules/snegopat/v8api/textmgr.v': 'bd00273245d758bc9c257333539f9beff3d0941fbfc6e4ae98f58885c1309965',
    'modules/snegopat/v8api/document.v': 'b1c12ef6a2d4ea9d655bd9057c7a605b2497bb6c22ddb9f6323efc3ad21c369e',
    'modules/snegopat/v8api/text.v': '629f8c74cd5cdefb41eceb43a7b9133da2719c3afafea73de670e47df8f89904',
}
RANGES = {
    'processingClass': ('basic.dll', 0x8cd470, 36, '808ec379a8ccec4982ee37b7f501bffcb21baa9af7b192227476865f322e7e18'),
    'processingFactory': ('basic.dll', 0x4ec650, 184, '27ced2bd9dacb4b686a8fe35ccd7eacf34bfe8bdcac0c30212880e90a35fc673'),
    'processingConstructor': ('basic.dll', 0x7a33d0, 100, '2c522368de1a08637987188966191d97d81f21e5c2a4ff91273c0f000affdbbc'),
    'processingObject': ('basic.dll', 0x8caf18, 148, 'aeb1c987d78692543216c76a12db425f111191abe42351bc7afaf20c7e1cef84'),
    'rootObject': ('backend.dll', 0xf15214, 120, 'a36e57717aea6b876d3426f39c4cc2f56f3b41cc2e4d4b6854e1bbdd382f43ac'),
    'rootAttach': ('backend.dll', 0x5c6d10, 154, '881ef63135002cae2533235d557143407f9be9263f842a9113549ae06ba2b30e'),
    'rootDelete': ('backend.dll', 0x5c6e20, 138, 'a714c4fe4cb593b913cf24fde60cf18da15fd0baac2a9813b8548f67e87ea103'),
    'processingHelperRegistration': ('basicui.dll', 0x5274f, 30, '69c0062158f5917f20919988bbef61db2a5a9c930e3c32e09c6beac424ebf43b'),
    'helper': ('basicui.dll', 0x603a00, 96, 'd9cee3e2bdf709d82919c1a012ae2d27312e32e4a00f7a63d7091833474261cd'),
    'moduleHelper': ('basicui.dll', 0x603904, 48, '070b9ff826df6c6d2b30034a386a90b1ffaef120f0668ba73ac7902b38bba259'),
    'helperQI': ('basicui.dll', 0x543ad0, 26, 'acea6e3ebaf193a475485d671b95930b8f3bf7435ced6c9a5ba11b722c3a622a'),
    'helperQIMap': ('basicui.dll', 0x604488, 192, '57e7113baa420cc18ef198633098c5093b02ae751513ef36994a5e2bb7e9bad1'),
    'helperConstructorTables': ('basicui.dll', 0x5437a6, 150, '3ea3d76d81e44b0b04c0a184c28d6f9651dcad34f22f098ca087b909c914aff7'),
    'helperObjectGetter': ('basicui.dll', 0x174aa0, 28, 'd5fde18667a9ebae253fc42373dc5df129e8461d2d4981aa7b62b7ba97efe0e8'),
    'moduleOpen': ('basicui.dll', 0x282570, 145, '97db2f765b73bb2a82977360f3c766379ef34b6c266c9d108f11d17764ec9019'),
    'textManager': ('txtedt.dll', 0x46dc4, 56, 'acd128aad7552b134dc88f819afafacdd70f257943b2af65e962208bd94aabc0'),
    'document': ('txtedui.dll', 0x109978, 120, 'a2d1306dde38fa86a0319f3a93a99fa2a599c5b97deca738baf3a6b3e310605d'),
    'actionBegin': ('core83.dll', 0x1d1ac0, 48, 'bfb85b2b72f74dadd53bcd201952303c93df70133d621b48028cca127b3c7677'),
    'actionClose': ('core83.dll', 0x1d1b10, 145, '3518e68b2e244c0ebdf86803d79d6b3243051b33fff26df6fcee92644cf5e6f0'),
    'undo': ('core83.dll', 0x1d1dc0, 235, 'e0fd30e697a69f7cbb137d934b1320579ff72af07d1fde265f56580285436c26'),
    'editorTable': ('txtedui.dll', 0x10c1f4, 20, '6386311ea9ce82d7f774c388f0ff1c95df9ce8f43d946b88af3e6c262893748d'),
    'editorQI': ('txtedui.dll', 0xcf230, 26, 'a9303f8954041847dc4ee177d162bf3764e1de01440bad4a73f0ced4effdabe2'),
    'editorQIThunk': ('txtedui.dll', 0xd289b, 13, '15f32dbcf1f992832cd43a6dd7fd1c20135bdbf26c4581931b695648a8e8437a'),
    'editorQIMap': ('txtedui.dll', 0x10ca90, 180, '18cc09651e981e7130e1414aa926723f2e3a61f1bc3e39e70fe0c143d9f3affb'),
    'editorConstructorTable': ('txtedui.dll', 0xcf378, 10, 'ac1c26fa5d2d96405dec4026e005f3a6f5a9f49eab4a743d67dd5e28257f684a'),
    'editorManagerGetter': ('txtedui.dll', 0xa2020, 226, '8a971033b364f5e7b37ed896ccc92b9bb0305a4d7f7de22fe71d4d15190e9909'),
    'editServiceTable': ('frntend.dll', 0xc4848c, 52, '58f337fbffc57bc0ff20b9b7c4d505a9874732afac99373cc1084db587b2598e'),
    'editServiceUIGetter': ('frntend.dll', 0x3e82f0, 411, '191ac5cbe14f105000d1ba87c622cc56b162cd280ad809574735d25181f2d2df'),
    'uiTable': ('frntend.dll', 0xc0e458, 108, 'a152d070d318c329d2299321a90cc484b4426f4dedaa1be4f843034aac507fb8'),
    'uiQIThunk': ('frntend.dll', 0x9643ce, 10, '70413117e311b13c87479fee76acd02df4dfea45d93768c599f97934b4a782dc'),
    'uiQI': ('frntend.dll', 0x962ba0, 26, 'f34445b9622be4c00ee3aa2858fb27466920fd86381b2e6065edea0cbacc1dd5'),
    'uiQIMap': ('frntend.dll', 0xc0e670, 24, '8f517f90e15dda851bd0442cc6d3c998093a4b8b8d9460bf4a8740004bfdcce5'),
    'uiRootGetter': ('frntend.dll', 0x147b90, 37, 'f73146874874d7174b722e93f104e572463c7607bc83d4d484d6334585a4b018'),
}
EXPORTS = {
    '?createNewAction@TextManager@core@@UAE_NW4DocActionType@2@ABVTextPosition@2@1PAUIUnknown@@@Z': 0x1d1ac0,
    '?closeNewAction@TextManager@core@@UAEXABVTextPosition@2@0@Z': 0x1d1b10,
    '?undo@TextManager@core@@QAE_NAAVTextPosition@2@0PAPAUIUnknown@@PAVIRedoUndoProcessingSite@2@@Z': 0x1d1dc0,
}


def need(condition, code):
    if not condition:
        raise ValueError(code)


def read_sdk():
    with zipfile.ZipFile(SDK) as archive:
        need(all(0 < archive.getinfo(n).file_size <= 65536 for n in SDK_SHAS), 'V78_SDK_SIZE_REJECTED')
        return {n: archive.read(n) for n in SDK_SHAS}


def verify_sdk(members):
    need(type(members) is dict and members.keys() == SDK_SHAS.keys(), 'V78_SDK_SCOPE_REJECTED')
    for name, sha in SDK_SHAS.items():
        need(type(members[name]) is bytes and hashlib.sha256(members[name]).hexdigest() == sha, 'V78_SDK_HASH_REJECTED')
    text = members['modules/snegopat/v8api/metadata.v'].decode('utf-8-sig')
    need('IMDEditModuleHelper {963CE56B-FCF9-4E6D-8EBC-374721B63ABA}' in text
         and 'IMDObject@+ getMDObj()' in text
         and 'uint openModule(ITextManager@&, const Guid& propId, uint32& open, ITextEditor@& editor)' in text
         and 'bool textOfModule(const Guid& propId, bool s, v8string&out result)' in text,
         'V78_PUBLISHED_SIGNATURE_REJECTED')
    need('uint getConfigMngrUI(IConfigMngrUI@&, IMDObject@+)' in text
         and 'IConfigMngrUI {B725F668-13C8-4BFF-90B9-33E19AA42E06}' in text
         and 'IMDContainer@+ getMDCont()' in text,
         'V78_PUBLISHED_UI_SIGNATURE_REJECTED')
    editor = members['modules/snegopat/v8api/text.v'].decode('utf-8-sig')
    need('ITextEditor {E82EFAF1-28B8-11d5-B08A-008048DA0765}' in editor
         and 'uint getITextManager(ITextManager@&out)' in editor,
         'V78_PUBLISHED_EDITOR_SIGNATURE_REJECTED')


def collect_ranges(modules):
    need(type(modules) is dict and set(modules) == {r[0] for r in RANGES.values()}, 'V78_MODULE_SCOPE_REJECTED')
    return {name: modules[module].data[modules[module].offset(modules[module].base + rva):
                modules[module].offset(modules[module].base + rva) + size]
            for name, (module, rva, size, _) in RANGES.items()}


def verify_ranges(ranges):
    need(type(ranges) is dict and ranges.keys() == RANGES.keys(), 'V78_RANGE_SCOPE_REJECTED')
    for name, (_, _, size, sha) in RANGES.items():
        body = ranges[name]
        need(type(body) is bytes and len(body) == size and hashlib.sha256(body).hexdigest() == sha,
             'V78_RANGE_PIN_REJECTED')
    words = lambda name: struct.unpack('<' + 'I' * (len(ranges[name]) // 4), ranges[name])
    need(words('processingClass')[8] == 0x228b0000 + 0x4ec650
         and words('processingObject')[12:14] == (0x228b0000 + 0x4ea200, 0x228b0000 + 0x4ea390)
         and words('rootObject')[24] == 0x1f400000 + 0x5c6d10
         and words('rootObject')[26] == 0x1f400000 + 0x5c6e20
         and words('helper')[23] == 0x24770000 + 0x174aa0
         and words('moduleHelper')[5] == 0x24770000 + 0x282280
         and words('moduleHelper')[11] == 0x24770000 + 0x282570,
         'V78_SLOT_BINDING_REJECTED')
    need(words('editorTable')[0] == 0x17f20000 + 0xd289b
         and words('editorTable')[3] == 0x17f20000 + 0xa2020
         and words('editServiceTable')[4] == 0x26dc0000 + 0x3e75d0
         and words('editServiceTable')[12] == 0x26dc0000 + 0x3e82f0
         and words('uiTable')[0] == 0x26dc0000 + 0x9643ce
         and words('uiTable')[26] == 0x26dc0000 + 0x147b90,
         'V78_EDITOR_UI_SLOT_REJECTED')
    # Published helper QI rows are counted subinterfaces at +a4 and +ac.
    rows = list(struct.iter_unpack('<III', ranges['helperQIMap']))
    need(rows[1] == (0x24770000 + 0x5fabc4, 0xa4, 1)
         and rows[4] == (0x24770000 + 0x5fab74, 0xac, 1), 'V78_HELPER_QI_REJECTED')
    need(tuple(struct.iter_unpack('<III', ranges['editorQIMap']))[14]
         == (0x17f20000 + 0x1059f8, 0x198, 1)
         and tuple(struct.iter_unpack('<III', ranges['uiQIMap']))[0]
         == (0x26dc0000 + 0xc0031c, 4, 1), 'V78_EDITOR_UI_QI_REJECTED')
    for key, stack in (('processingFactory', 8), ('rootAttach', 8), ('rootDelete', 12),
                       ('moduleOpen', 20), ('actionBegin', 16), ('actionClose', 8), ('undo', 16),
                       ('editorManagerGetter', 8), ('editServiceUIGetter', 12), ('uiRootGetter', 4)):
        need(ranges[key].endswith(b'\xc2' + struct.pack('<H', stack)), 'V78_STACK_ABI_REJECTED')


def export_map(pe):
    data = pe.data
    nt = struct.unpack_from('<I', data, 60)[0]
    at = pe.offset(pe.base + struct.unpack_from('<I', data, nt + 120)[0])
    count = struct.unpack_from('<I', data, at + 24)[0]
    functions, names, ordinals = struct.unpack_from('<III', data, at + 28)
    result = {}
    for index in range(count):
        start = pe.offset(pe.base + struct.unpack_from('<I', data, pe.offset(pe.base + names) + index * 4)[0])
        name = data[start:data.index(0, start)].decode('ascii')
        ordinal = struct.unpack_from('<H', data, pe.offset(pe.base + ordinals) + index * 2)[0]
        result[name] = struct.unpack_from('<I', data, pe.offset(pe.base + functions) + ordinal * 4)[0]
    return result


def verify_exports(mapping):
    need(type(mapping) is dict and all(type(mapping.get(name)) is int and mapping[name] == rva
                                     for name, rva in EXPORTS.items()), 'V78_EXPORT_BINDING_REJECTED')


def verify_static():
    verify_sdk(read_sdk())
    modules = {name: PE(name) for name in sorted({r[0] for r in RANGES.values()})}
    verify_ranges(collect_ranges(modules))
    verify_exports(export_map(modules['core83.dll']))
    basicui = modules['basicui.dll']
    def guid(rva):
        start = basicui.offset(basicui.base + rva)
        return str(uuid.UUID(bytes_le=basicui.data[start:start + 16]))
    need(guid(0x5ec794) == 'bf845118-327b-4682-b5c6-285d2a0eb296'
         and guid(0x5ead98) == '5ba8fc91-44e1-46ae-a0b0-2e54bb98065d'
         and guid(0x5fab74) == '963ce56b-fcf9-4e6d-8ebc-374721b63aba', 'V78_HELPER_REGISTRATION_REJECTED')
    return dict(staticContractVerified=True, platform='8.3.18.1208', architecture='x86',
                pinnedRanges=len(RANGES), publishedModuleOpenStackBytes=20,
                processingHelperServiceRegistrationVerified=True, helperCountedQIOffsets=(0xa4, 0xac),
                runtimeHelperObjectBindingRequired=True, runtimeTableAndDocumentChecksRequired=True,
                existingGoldUiAndEditorBindingRequired=True, editorTableRva=0x10c1f4,
                uiTableRva=0xc0e458, uiGetterSlot=12, editorManagerGetterSlot=3,
                helperFactoryClassMappingIndependentlyProven=False, runtimeObjectModuleUndoVerified=False,
                goldSavePermitted=False, databaseUpdatePermitted=False, nativePermitGranted=False,
                foreignPropertyContentHashed=False, persistedGoldVerified=False)
