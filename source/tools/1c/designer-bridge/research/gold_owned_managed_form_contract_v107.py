"""Read-only prerequisites for an unsaved task-owned live Gold managed form.

This verifier reads fixed local SDK/PE/source bytes only. It neither loads a DLL
nor grants a native call, capture, configuration Save, database update or close.
The future native receiver tables and serialization roundtrip remain measured
requirements, including the currently unmeasured live Form helper variant.
"""
import hashlib
import importlib
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'tests/NativeGoldOwnedManagedFormV107.as'
SOURCE_SHA256 = '5c0e8d34695ba176b988bbc8261a5d6c62b68797faf80657087fd12eb4ae34e1'
OWN_PROCESSING = '9c5f3c76-4d3b-5c0d-b1b2-37024a0993d7'
OWN_FORM = 'e51a959c-fec9-5244-8a8e-ea02fdc0a0db'
BASE_SHAS = {
    'owned_managed_body_contract_v73.py': '8a1aec10f79b99dd0cc78b50234ae10cc5a8f785d60060734e43562b0dbacaaf',
    'managed_form_type_contract_v74.py': 'ea32a4d4c47899c516dea558e67ad8e9adb00e94969ca488a96b46d3f88267b4',
    'managed_layout_contract_v80.py': '11ebd01737263a645b67a0b77f6016a93ac46e466e7702b4f63e4001919d4973',
}
RANGES = {
    'managerResourceTable': ('backend.dll', 0xede0a4, 344, '05250dc12f3b5647f2405f0113dfb3a2d80ae9c5e20385787bed29a431612362'),
    'managerInnerTable': ('backend.dll', 0xe553cc, 64, '4532c88fabccea8c1d840608474303526cdbd8c101592c052b68c0ab41bf2f9d'),
    'managerGetResource': ('backend.dll', 0x2a8e60, 34, 'e91ee7cc8178f828185b1b5d2821de8efbab12d88091005e7d6ca1b4de18a18c'),
    'innerGetResource': ('backend.dll', 0x35120, 31, '6423bf561e552c1663dcfa36c273d6d4f2e1bda966303d15351ff42be224e376'),
    'formHelperTable': ('basicui.dll', 0x60b344, 96, 'da38bcb7f0af3624a5b87cd054261e61403da023cd66990debe9a7710b9ca9ea'),
    'formGetMDObj': ('basicui.dll', 0x1787b0, 25, '7bff47f8ec7a3950f867a5e6930a605cba36221b8a8ed23d9ef6f6c2ca5d7365'),
    'formExtProp': ('basicui.dll', 0x179d90, 41, '156995a47696bcd1cc37c731c812d3aafcde21b0cd7c0203f31079e6eba703ab'),
    'formHelperQI': ('basicui.dll', 0x55d039, 13, 'ab685cf666f8844b1f8ce69692faab1a123ea475527ed034a66ae3cc3bad6114'),
    'processingFactory': ('basic.dll', 0x4ec650, 184, '27ced2bd9dacb4b686a8fe35ccd7eacf34bfe8bdcac0c30212880e90a35fc673'),
    'formFactory': ('basic.dll', 0x4ee310, 192, '61ea508533f1b3b3193106f4fe39f49f2070fa2458d45158a02642fd676be3be'),
    'processingClassTable': ('basic.dll', 0x8cd470, 36, '808ec379a8ccec4982ee37b7f501bffcb21baa9af7b192227476865f322e7e18'),
    'formClassTable': ('basic.dll', 0x8ccc5c, 36, '0c8ebbc447666fa24d67294f614d30ac13038d349a7f32b625bf58a7898b9ffd'),
    'processingMdObject': ('basic.dll', 0x8caf18, 112, 'c78b07654012115fbd7f120a1473a9c5a8e352db032d0009135a7e1672b7ae95'),
    'formMdObject': ('basic.dll', 0x8cb258, 112, '65ac9b511f21e5cfbeb310cb2ed185349dfcebf327b215c9b54c14ad03bceca3'),
}


def _need(ok, code):
    if not ok:
        raise ValueError(code)


def validate_ranges(slices, bases):
    """Pure byte gate; altered table/ABI bytes can be tested without file edits."""
    _need(type(slices) is dict and set(slices) == set(RANGES), 'GM107_RANGE_SET')
    for name, (module, _rva, size, expected) in RANGES.items():
        data = slices[name]
        _need(type(data) is bytes and len(data) == size
              and hashlib.sha256(data).hexdigest() == expected, 'GM107_RANGE_REJECTED')
    table = slices['managerResourceTable']
    _need(struct.unpack_from('<I', table, 79 * 4)[0] == bases['backend.dll'] + 0x2a8e60
          and struct.unpack_from('<I', table, 85 * 4)[0] == bases['backend.dll'] + 0x2aeb40,
          'GM107_MANAGER_SLOT')
    _need(slices['managerGetResource'][-3:] == b'\xc2\x10\x00'
          and slices['innerGetResource'][-3:] == b'\xc2\x10\x00'
          and slices['formGetMDObj'][-3:] == b'\xc2\x04\x00', 'GM107_CALLING_CONVENTION')
    form = slices['formHelperTable']
    for slot, rva in ((15, 0x179d90), (16, 0x179dc0), (17, 0x179f70), (23, 0x1787b0)):
        _need(struct.unpack_from('<I', form, slot * 4)[0] == bases['basicui.dll'] + rva,
              'GM107_HELPER_SLOT')
    for name, rva in (('processingClassTable', 0x4ec650), ('formClassTable', 0x4ee310)):
        _need(struct.unpack_from('<I', slices[name], 8 * 4)[0] == bases['basic.dll'] + rva,
              'GM107_FACTORY_SLOT')
    return True


def _function(text, name):
    # Definitions start at a line's type/name; call sites do not match.
    match = re.search(r'(?m)^(?:bool|string|uint|int_ptr|IMDObject&&)\s+' + re.escape(name) + r'\(', text)
    _need(match is not None, 'GM107_FUNCTION_MISSING')
    begin = text.index('{', match.start()); depth = 1; at = begin + 1
    while depth and at < len(text):
        if text[at] == '{':
            depth += 1
        elif text[at] == '}':
            depth -= 1
        at += 1
    _need(depth == 0, 'GM107_SOURCE_BALANCE')
    return text[match.start():at]


# Exact reversible projection: only reviewed QPC inserts/moves may differ
# from the immutable actual0189 source. Removed clocks do not grant authority.
PROFILE_BASE_SOURCE_SHA256 = '9934a89bdbe4c410bc001b66a4c4f22c5c0b9fc3b9de8177de1f280534d00ea3'
PROFILE_IMPLEMENTATION_SHA256 = 'c45e65f348cb48732771eae04e7692c1eeaf1aad0ca731f477cf51658f26a482'
PROFILE_CHANGES = (('bool ahGMRootV107(IMDContainer&& root,IConfigMngr&& manager){', 'bool ahGMRootInnerV107(IMDContainer&& root,IConfigMngr&& manager){', 1), ('string ahGMForeignGraphV107(IMDObject&& object,uint depth,uint&inout count){', 'string ahGMForeignGraphInnerV107(IMDObject&& object,uint depth,uint&inout count){', 1), ('string part=ahGMForeignGraphV107(child,depth+1,count);', 'string part=ahGMForeignGraphInnerV107(child,depth+1,count);', 1), ('bool ahBodyWriteFileV107(IFileEx&& memory,const string&in name,uint64&out bytes){', 'bool ahBodyWriteFileInnerV107(IFileEx&& memory,const string&in name,uint64&out bytes){', 1), ('    IDocument&& document=ahPipeText.unk;if(document is null)return false;int_ptr table=mem::int_ptr[document.self];\r\n    if(!ahOwnTypeAddressV107(table,"txtedui.dll",0x109978)\r\n        || !ahOwnTypeAddressV107(mem::int_ptr[table+8*4],"txtedui.dll",0x74450)\r\n        || !ahOwnTypeAddressV107(mem::int_ptr[table+22*4],"txtedui.dll",0x7d7d0) || document.isModified())return false;\r\n    v8string source;if(!ahPipeText.getTextManager().save(source) || source.str!=ahGMSourceV107)return false;', '    /*GM107P:DOCBEGIN*/uint ahGMProfileDocumentTokenV107=ahGMProfileBeginV107(2);/*GM107P:DOCbegin*/\r\n    IDocument&& document=ahPipeText.unk;if(document is null){ahGMProfileEndV107(2,ahGMProfileDocumentTokenV107);return false;}int_ptr table=mem::int_ptr[document.self];\r\n    if(!ahOwnTypeAddressV107(table,"txtedui.dll",0x109978)\r\n        || !ahOwnTypeAddressV107(mem::int_ptr[table+8*4],"txtedui.dll",0x74450)\r\n        || !ahOwnTypeAddressV107(mem::int_ptr[table+22*4],"txtedui.dll",0x7d7d0) || document.isModified()){ahGMProfileEndV107(2,ahGMProfileDocumentTokenV107);return false;}\r\n    v8string source;if(!ahPipeText.getTextManager().save(source) || source.str!=ahGMSourceV107){ahGMProfileEndV107(2,ahGMProfileDocumentTokenV107);return false;}\r\n    /*GM107P:DOCEND*/ahGMProfileEndV107(2,ahGMProfileDocumentTokenV107);/*GM107P:DOCend*/', 1), ('    ahCollectRepositoryObserve();', '    ahGMWideObserveV107();', 1), ('ahCycleDurable(', 'ahGMDurableV107(', 2), ('calls++;persistence.serialize(output);', '/*GM107P:B0*/uint ahGMProfileToken0V107=ahGMProfileBeginV107(4);/*GM107P:b0*/calls++;persistence.serialize(output);/*GM107P:E0*/ahGMProfileEndV107(4,ahGMProfileToken0V107);/*GM107P:e0*/', 1), ('factories++;bool made=currentProcess().createByClsid(ahLayoutClassV107(index),IID_IUnknown,original);', '/*GM107P:B1*/uint ahGMProfileToken1V107=ahGMProfileBeginV107(4);/*GM107P:b1*/factories++;bool made=currentProcess().createByClsid(ahLayoutClassV107(index),IID_IUnknown,original);/*GM107P:E1*/ahGMProfileEndV107(4,ahGMProfileToken1V107);/*GM107P:e1*/', 1), ('factories++;cloneMade=currentProcess().createByClsid(ahLayoutClassV107(index),IID_IUnknown,clone);', '/*GM107P:B2*/uint ahGMProfileToken2V107=ahGMProfileBeginV107(4);/*GM107P:b2*/factories++;cloneMade=currentProcess().createByClsid(ahLayoutClassV107(index),IID_IUnknown,clone);/*GM107P:E2*/ahGMProfileEndV107(4,ahGMProfileToken2V107);/*GM107P:e2*/', 1), ('loads++;clonePersistence.deserialize(input);', '/*GM107P:B3*/uint ahGMProfileToken3V107=ahGMProfileBeginV107(4);/*GM107P:b3*/loads++;clonePersistence.deserialize(input);/*GM107P:E3*/ahGMProfileEndV107(4,ahGMProfileToken3V107);/*GM107P:e3*/', 1), ('ahLayoutAdditionalSaveCallsV107++;document.save(file);', '/*GM107P:B4*/uint ahGMProfileToken4V107=ahGMProfileBeginV107(4);/*GM107P:b4*/ahLayoutAdditionalSaveCallsV107++;document.save(file);/*GM107P:E4*/ahGMProfileEndV107(4,ahGMProfileToken4V107);/*GM107P:e4*/', 1), ('ahLayoutAdditionalSaveCallsV107++;document.save(beforeFile);', '/*GM107P:B5*/uint ahGMProfileToken5V107=ahGMProfileBeginV107(4);/*GM107P:b5*/ahLayoutAdditionalSaveCallsV107++;document.save(beforeFile);/*GM107P:E5*/ahGMProfileEndV107(4,ahGMProfileToken5V107);/*GM107P:e5*/', 1), ('ahLayoutAdditionalLoadCallsV107++;document.load(payloadFile);', '/*GM107P:B6*/uint ahGMProfileToken6V107=ahGMProfileBeginV107(4);/*GM107P:b6*/ahLayoutAdditionalLoadCallsV107++;document.load(payloadFile);/*GM107P:E6*/ahGMProfileEndV107(4,ahGMProfileToken6V107);/*GM107P:e6*/', 1), ('count++;\r\n    if(processing)ahOwnTypeProcessingFactoryV107(self,output.bytes+16);\r\n    else ahOwnTypeFormFactoryV107(self,output.bytes+16);', '/*GM107P:B7*/uint ahGMProfileToken7V107=ahGMProfileBeginV107(4);/*GM107P:b7*/count++;\r\n    if(processing)ahOwnTypeProcessingFactoryV107(self,output.bytes+16);\r\n    else ahOwnTypeFormFactoryV107(self,output.bytes+16);/*GM107P:E7*/ahGMProfileEndV107(4,ahGMProfileToken7V107);/*GM107P:e7*/', 1), ('ahGMIdSettersV107++;object.id=id;', '/*GM107P:B8*/uint ahGMProfileToken8V107=ahGMProfileBeginV107(4);/*GM107P:b8*/ahGMIdSettersV107++;object.id=id;/*GM107P:E8*/ahGMProfileEndV107(4,ahGMProfileToken8V107);/*GM107P:e8*/', 1), ('count++;\r\n    if(root)ahOwnTypeRootAttachV107(self,mem::addressOf(child));\r\n    else ahOwnTypeProcessingAttachV107(self,mem::addressOf(child));', '/*GM107P:B9*/uint ahGMProfileToken9V107=ahGMProfileBeginV107(4);/*GM107P:b9*/count++;\r\n    if(root)ahOwnTypeRootAttachV107(self,mem::addressOf(child));\r\n    else ahOwnTypeProcessingAttachV107(self,mem::addressOf(child));/*GM107P:E9*/ahGMProfileEndV107(4,ahGMProfileToken9V107);/*GM107P:e9*/', 1), ('clones++;int_ptr returnedOutput=ahBodyGroupCloneCallV107(template,output.bytes+16);', '/*GM107P:B10*/uint ahGMProfileToken10V107=ahGMProfileBeginV107(4);/*GM107P:b10*/clones++;int_ptr returnedOutput=ahBodyGroupCloneCallV107(template,output.bytes+16);/*GM107P:E10*/ahGMProfileEndV107(4,ahGMProfileToken10V107);/*GM107P:e10*/', 1), ('sets++;tov8string(created+0x50).ref=name;ahBodyGroupSetIdCallV107(created,1001);', '/*GM107P:B11*/uint ahGMProfileToken11V107=ahGMProfileBeginV107(4);/*GM107P:b11*/sets++;tov8string(created+0x50).ref=name;ahBodyGroupSetIdCallV107(created,1001);/*GM107P:E11*/ahGMProfileEndV107(4,ahGMProfileToken11V107);/*GM107P:e11*/', 1), ('adds++;ahBodyGroupAddCallV107(base,created,true);', '/*GM107P:B12*/uint ahGMProfileToken12V107=ahGMProfileBeginV107(4);/*GM107P:b12*/adds++;ahBodyGroupAddCallV107(base,created,true);/*GM107P:E12*/ahGMProfileEndV107(4,ahGMProfileToken12V107);/*GM107P:e12*/', 1), ('ahLayoutAdditionalSaveCallsV107++;freshDocument.save(freshFile);', '/*GM107P:B13*/uint ahGMProfileToken13V107=ahGMProfileBeginV107(4);/*GM107P:b13*/ahLayoutAdditionalSaveCallsV107++;freshDocument.save(freshFile);/*GM107P:E13*/ahGMProfileEndV107(4,ahGMProfileToken13V107);/*GM107P:e13*/', 1), ('deletes++;ahBodyFormDeleteCallV107(self,kind.self,id.self);', '/*GM107P:B14*/uint ahGMProfileToken14V107=ahGMProfileBeginV107(4);/*GM107P:b14*/deletes++;ahBodyFormDeleteCallV107(self,kind.self,id.self);/*GM107P:E14*/ahGMProfileEndV107(4,ahGMProfileToken14V107);/*GM107P:e14*/', 1), ('deletes++;ahBodyProcessingDeleteCallV107(self,processingKind.self,processingId.self);', '/*GM107P:B15*/uint ahGMProfileToken15V107=ahGMProfileBeginV107(4);/*GM107P:b15*/deletes++;ahBodyProcessingDeleteCallV107(self,processingKind.self,processingId.self);/*GM107P:E15*/ahGMProfileEndV107(4,ahGMProfileToken15V107);/*GM107P:e15*/', 1), ('s.nameSetters++;bool p=processing.setMdPropVal(Guid("{CF4ABEA2-37B2-11D4-940F-008048DA11F9}"),pn);', '/*GM107P:B16*/uint ahGMProfileToken16V107=ahGMProfileBeginV107(4);/*GM107P:b16*/s.nameSetters++;bool p=processing.setMdPropVal(Guid("{CF4ABEA2-37B2-11D4-940F-008048DA11F9}"),pn);/*GM107P:E16*/ahGMProfileEndV107(4,ahGMProfileToken16V107);/*GM107P:e16*/', 1), ('s.nameSetters++;bool f=form.setMdPropVal(Guid("{CF4ABEA2-37B2-11D4-940F-008048DA11F9}"),fn);', '/*GM107P:B17*/uint ahGMProfileToken17V107=ahGMProfileBeginV107(4);/*GM107P:b17*/s.nameSetters++;bool f=form.setMdPropVal(Guid("{CF4ABEA2-37B2-11D4-940F-008048DA11F9}"),fn);/*GM107P:E17*/ahGMProfileEndV107(4,ahGMProfileToken17V107);/*GM107P:e17*/', 1), ('s.bodies++;bool made=currentProcess().createByClsid(Guid("{5E44D99D-7D52-49BF-BC73-4DC0B575B8FB}"),IID_IUnknown,body);', '/*GM107P:B18*/uint ahGMProfileToken18V107=ahGMProfileBeginV107(4);/*GM107P:b18*/s.bodies++;bool made=currentProcess().createByClsid(Guid("{5E44D99D-7D52-49BF-BC73-4DC0B575B8FB}"),IID_IUnknown,body);/*GM107P:E18*/ahGMProfileEndV107(4,ahGMProfileToken18V107);/*GM107P:e18*/', 1), ('s.moduleWrites++;tov8string(textAddress).ref=text;', '/*GM107P:B19*/uint ahGMProfileToken19V107=ahGMProfileBeginV107(4);/*GM107P:b19*/s.moduleWrites++;tov8string(textAddress).ref=text;/*GM107P:E19*/ahGMProfileEndV107(4,ahGMProfileToken19V107);/*GM107P:e19*/', 1), ('s.bodySaves++;document.save(seedFile);', '/*GM107P:B20*/uint ahGMProfileToken20V107=ahGMProfileBeginV107(4);/*GM107P:b20*/s.bodySaves++;document.save(seedFile);/*GM107P:E20*/ahGMProfileEndV107(4,ahGMProfileToken20V107);/*GM107P:e20*/', 1), ('s.bodyLoads++;document.load(seedFile);', '/*GM107P:B21*/uint ahGMProfileToken21V107=ahGMProfileBeginV107(4);/*GM107P:b21*/s.bodyLoads++;document.load(seedFile);/*GM107P:E21*/ahGMProfileEndV107(4,ahGMProfileToken21V107);/*GM107P:e21*/', 1), ('s.bodySaves++;document.save(payloadFile);', '/*GM107P:B22*/uint ahGMProfileToken22V107=ahGMProfileBeginV107(4);/*GM107P:b22*/s.bodySaves++;document.save(payloadFile);/*GM107P:E22*/ahGMProfileEndV107(4,ahGMProfileToken22V107);/*GM107P:e22*/', 1), ('s.boundFactories++;int_ptr boundOutput=ahBodyBoundFactoryCallV107(helperSelf,output.bytes+16,property.self,false);', '/*GM107P:B23*/uint ahGMProfileToken23V107=ahGMProfileBeginV107(4);/*GM107P:b23*/s.boundFactories++;int_ptr boundOutput=ahBodyBoundFactoryCallV107(helperSelf,output.bytes+16,property.self,false);/*GM107P:E23*/ahGMProfileEndV107(4,ahGMProfileToken23V107);/*GM107P:e23*/', 1), ('s.bodyLoads++;boundDocument.load(payloadFile);', '/*GM107P:B24*/uint ahGMProfileToken24V107=ahGMProfileBeginV107(4);/*GM107P:b24*/s.bodyLoads++;boundDocument.load(payloadFile);/*GM107P:E24*/ahGMProfileEndV107(4,ahGMProfileToken24V107);/*GM107P:e24*/', 1), ('s.stores++;bool stored=ahBodyStoreCallV107(ext,mem::addressOf(boundBody));', '/*GM107P:B25*/uint ahGMProfileToken25V107=ahGMProfileBeginV107(4);/*GM107P:b25*/s.stores++;bool stored=ahBodyStoreCallV107(ext,mem::addressOf(boundBody));/*GM107P:E25*/ahGMProfileEndV107(4,ahGMProfileToken25V107);/*GM107P:e25*/', 1), ('s.body.deletes++;ahBodyProcessingDeleteCallV107(s.root.self,kind.self,id.self);', '/*GM107P:B26*/uint ahGMProfileToken26V107=ahGMProfileBeginV107(4);/*GM107P:b26*/s.body.deletes++;ahBodyProcessingDeleteCallV107(s.root.self,kind.self,id.self);/*GM107P:E26*/ahGMProfileEndV107(4,ahGMProfileToken26V107);/*GM107P:e26*/', 1), ('s.setters++;bool changed=s.form.setMdPropVal(typeId,sourceValue);', '/*GM107P:B27*/uint ahGMProfileToken27V107=ahGMProfileBeginV107(4);/*GM107P:b27*/s.setters++;bool changed=s.form.setMdPropVal(typeId,sourceValue);/*GM107P:E27*/ahGMProfileEndV107(4,ahGMProfileToken27V107);/*GM107P:e27*/', 1), ('    consumed=true;s.operation=operation;ahGMOperationV107=operation;', '    consumed=true;s.operation=operation;ahGMOperationV107=operation;\r\n    /*GM107P:RESET*/ahGMProfileResetV107();uint ahGMProfileTotalTokenV107=ahGMProfileBeginV107(6);/*GM107P:RESETEND*/', 1), ('    return "{\\"status\\":\\""+(s.complete?', '    /*GM107P:FINISH*/ahGMProfileEndV107(6,ahGMProfileTotalTokenV107);ahGMProfileActiveV107=false;ahGMProfileFinalizedV107=true;/*GM107P:FINISHEND*/\r\n    return "{\\"status\\":\\""+(s.complete?', 1), ('        +",\\"goldSourceWrites\\":0,\\"goldSaves\\":0,\\"repositoryWrites\\":0,\\"databaseUpdates\\":0,\\"businessCalls\\":0,\\"dirtyFlagWrites\\":0,\\"lifecycle\\":"+ahOwnTypeLifecycleV107(phases)+"}";', '        +",\\"profile\\":"+ahGMProfileJsonV107()\r\n        +",\\"goldSourceWrites\\":0,\\"goldSaves\\":0,\\"repositoryWrites\\":0,\\"databaseUpdates\\":0,\\"businessCalls\\":0,\\"dirtyFlagWrites\\":0,\\"lifecycle\\":"+ahOwnTypeLifecycleV107(phases)+"}";', 1))


def unprofiled_source(raw):
    _need(type(raw) is bytes, 'GM107_PROFILE_SOURCE_TYPE')
    text = raw.decode('utf-8', 'strict')
    begin = '// GM107_PROFILE_IMPLEMENTATION_BEGIN'
    end = '// GM107_PROFILE_IMPLEMENTATION_END'
    _need(text.count(begin)==text.count(end)==1, 'GM107_PROFILE_IMPLEMENTATION')
    at=text.index(begin);block=text[at:]
    _need(block.rstrip().endswith(end) and hashlib.sha256(block.encode()).hexdigest()==PROFILE_IMPLEMENTATION_SHA256,
          'GM107_PROFILE_IMPLEMENTATION')
    text=text[:at]
    for old,new,count in reversed(PROFILE_CHANGES):
        _need(text.count(new)==count, 'GM107_PROFILE_EDIT')
        text=text.replace(new,old)
    result=text.encode('utf-8')
    _need(hashlib.sha256(result).hexdigest()==PROFILE_BASE_SOURCE_SHA256,'GM107_PROFILE_BASE_SOURCE')
    return result


def validate_source(raw):
    """Structural native safety assertions, separate from the whole-source pin."""
    _need(type(raw) is bytes and 0 < len(raw) <= 131072, 'GM107_SOURCE_SIZE')
    text = unprofiled_source(raw).decode('utf-8', 'strict')
    _need(OWN_PROCESSING in text and OWN_FORM in text, 'GM107_SCOPE')
    _need(not any(word in text for word in ('connectConfig(', 'extractConfig(', 'openModule(',
          'setModified(', 'ahBodyPreSave', 'ahBodyPostSave', 'loadFromString(', 'doModal(')),
          'GM107_FORBIDDEN_ROUTE')
    entry = _function(text, 'ahGoldOwnedManagedFormV107')
    # Initial clean-only evidence stays mandatory. Post-own checks cannot call
    # the detached-memory helper which rejects a legitimately dirty Gold root.
    _need(text.count('ahOwnedValueV67GoldControl()') == 1
          and text.count('ahOwnedValueV67Control()') == 1
          and entry.index('ahOwnedValueV67GoldControl()') < entry.index('ahOwnTypeFactoryV107(')
          and entry.index('ahOwnedValueV67Control()') < entry.index('ahOwnTypeFactoryV107('),
          'GM107_BASELINE_CONTROL')
    source = _function(text, 'ahGMSourceControlV107')
    _need(source.index('ahGMControlV107(root,manager)') < source.index('root.objById(')
          < source.index('control.isModified()') < source.index('parent.getMDObject()')
          < source.index('document.isModified()') < source.index('return control;'),
          'GM107_POST_OWN_CONTROL_ORDER')
    _need(all(check in source for check in ('control is null', 'formClass is null', 'parent is null',
          'document is null', 'documentClass is null', 'control.id!=Guid("{0ed914fb-2a1a-4b58-9fad-eaa103b47c9e}")',
          'formClass.id!=Guid("{FB880E93-47D7-4127-9357-A20E69C17545}")', 'document.self!=ahPipeObject.self',
          'document.id!=Guid("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}")',
          'documentClass.id!=Guid("{061D872A-5787-460E-95AC-ED74EA3A3E84}")'))
          and not any(word in source for word in ('root.isModified()', 'ahStatusUi.isModified()',
              'queryIface(', 'toIUnknown(', 'mem::', 'initFuncDefFromAddress(')), 'GM107_POST_OWN_CONTROL_SCOPE')
    preservation = _function(text, 'ahGMControlV107')
    _need(all(check in preservation for check in ('ahGMRootV107(root,manager)', 'ahGMForeignGraphV107(root,0,nodes)',
          'nodes!=ahGMForeignNodesV107', 'ahPipeObject.isModified()', 'document.isModified()',
          'source.str!=ahGMSourceV107', 'ahCollectRepositoryObserve()', 'ahRepoOwnerVerified',
          'ahRepoGenerationVerified', 'ahRepoLastVersion==ahGMVersionV107', 'ahRepoLastRevised==ahGMRevisedV107',
          'ahRepoLastRevisor==ahGMOwnerV107', 'ahPlanController==ahGMControllerV107',
          'ahPlanProvider==ahGMProviderV107')), 'GM107_POST_OWN_PRESERVATION')
    for name in ('ahLayoutRecordTemplateV107', 'ahLayoutPrepareV107', 'ahBodyDeleteOwnV107', 'ahBodyCycleExecuteV107'):
        _need('ahGMPostOwnControlV107(root,manager)' in _function(text,name), 'GM107_POST_OWN_CALL')
    _need('IMDObject&& sourceControl=ahGMSourceControlV107(s.root,s.manager)' in entry
          and 'IMDObject&& control=ahGMSourceControlV107(s.root,s.manager)' in entry,
          'GM107_FINAL_SOURCE_CONTROL')
    post = _function(text, 'ahGMPostOwnControlV107')
    _need('control=ahGMSourceControlV107(root,manager);return control !is null;' in post
          and '||' not in post, 'GM107_POST_OWN_CONTROL_RESULT')
    disjoint = _function(text, 'ahBodyDisjointV107')
    labels = ('input','currentRoot','sourceControl','requiredHandles','referenceHandle','referenceAlias','ready')
    _need(all('ahGMCanonicalGateV107="'+gate+'"' in disjoint for gate in labels)
          and [disjoint.index('ahGMCanonicalGateV107="'+gate+'"') for gate in labels]
              == sorted(disjoint.index('ahGMCanonicalGateV107="'+gate+'"') for gate in labels)
          and 'control=ahGMSourceControlV107(root,manager)' in disjoint
          and 'if(others[i]==0){ahGMCanonicalGateV107="referenceHandle";return false;}' in disjoint
          and 'if(others[i]==candidate){ahGMCanonicalGateV107="referenceAlias";return false;}' in disjoint,
          'GM107_CANONICAL_DIAGNOSTIC')
    _need('string ahGMCanonicalGateV107="notEntered";' in text
          and '\\"canonicalGate\\":\\""+ahGMCanonicalGateV107' in _function(text,'ahBodyCycleJsonV107')
          and 'queryIface(' not in disjoint, 'GM107_CANONICAL_DIAGNOSTIC_SCOPE')
    _need(entry.index('terminalResult=false;attemptedWrites=0;') < entry.index('ahGMPermitV107(operation)')
          < entry.index('consumed=true;') < entry.index('ahOwnTypeFactoryV107('), 'GM107_PERMISSION_ORDER')
    _need('&&s.processing=null;&&s.form=null;' in entry
          and 'if(!cycle && s.body.bodies>0)ahGMUnknownV107=true;' in entry,
          'GM107_UNKNOWN_RETENTION')
    factory = _function(text, 'ahOwnTypeFactoryV107')
    _need(factory.index('beforeProcessingFactory') < factory.index('count++;')
          < factory.index('ahOwnTypeProcessingFactoryV107(self,output.bytes+16)')
          < factory.index('uint receiver=processing?0x8caf18:0x8cb258;')
          < factory.index('IUnknown&& pin=toIUnknown(created)')
          < factory.index('object.id=id') < factory.index('afterProcessingFactory'), 'GM107_FACTORY_ORDER')
    graph = _function(text, 'ahOwnTypeGraphV107')
    _need('ahGMRootV107(root,manager)' in graph and 'ahGMCountBeforeV107+1' in graph,
          'GM107_LIVE_GRAPH')
    helper = _function(text, 'ahBodyHelperOwnedV107')
    _need(helper.index('ahBodyHelperAbiV107(helper)') < helper.index('helper.getMDObj()'), 'GM107_HELPER_ORDER')
    external = _function(text, 'ahBodyExternalAbiV107')
    _need(external.index('0xf18f50') < external.index('external.url(url)'), 'GM107_URL_ORDER')
    resource = _function(text, 'ahGMLayeredResourceV107')
    _need(resource.index('0xede0a4') < resource.index('0xe553cc')
          < resource.index('beforeLayeredResourceRead') < resource.index('ahGMResourceGetterV107(manager.self,output.bytes+16,url.self,0)'),
          'GM107_RESOURCE_ORDER')
    _need(OWN_FORM + '.0' in resource and 'toIUnknown(pointer)' in resource,
          'GM107_RESOURCE_SCOPE')
    delete = _function(text, 'ahBodyDeleteOwnV107')
    _need('ahGMUnknownV107' in delete and 'ahGMControlV107(root,manager)' in delete
          and 'count==ahGMCountBeforeV107' in delete, 'GM107_DELETE_SCOPE')
    # There are no automatic calls. Literal counters/strings and null delegate
    # caches are allowed; the real vendor compile remains an independent gate.
    masked = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"', '', text, flags=re.S)
    depth = 0; definitions = set()
    lines = masked.splitlines()
    for index, line in enumerate(lines):
        # Constructor-style locals such as Guid iid(...) terminate with ';'.
        # A function definition must reach its body before any semicolon.
        definition = re.match(r'[ \t]*(?:bool|string|uint|Guid|int_ptr|IMDObject&&)\s+(\w+)\s*\([^;{}]*\)\s*\{',
                              '\n'.join(lines[index:]), flags=re.S)
        if definition:
            _need(depth == 0 and definition[1] not in definitions, 'GM107_NESTED_DUPLICATE_FUNCTION')
            definitions.add(definition[1])
        if depth == 0:
            _need(re.search(r'=\s*\w+\s*\(', line) is None, 'GM107_GLOBAL_EXECUTION')
        depth += line.count('{') - line.count('}')
        _need(depth >= 0, 'GM107_SOURCE_BALANCE')
    _need(depth == 0, 'GM107_SOURCE_BALANCE')
    return dict(functionOnly=True, sourceSafetyVerified=True, goldStarted=False,
                managedFormRuntimeVerified=False, persistenceRuntimeVerified=False,
                postOwnSourceControlVerified=True, canonicalDiagnosticRuntimeMeasured=False)


def verify_static():
    """Read fixed prerequisites only. Does not create a runtime or execute AS."""
    from repository_pe_probe import PE
    for name, expected in BASE_SHAS.items():
        _need(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == expected, 'GM107_PREREQUISITE_SHA')
    reports = [importlib.import_module(Path(name).stem).verify_static() for name in BASE_SHAS]
    pes = {name: PE(name) for name in {row[0] for row in RANGES.values()}}
    slices = {name: pe.data[pe.offset(pe.base + rva):pe.offset(pe.base + rva) + size]
              for name, (module, rva, size, _sha) in RANGES.items() for pe in (pes[module],)}
    validate_ranges(slices, {name: pe.base for name, pe in pes.items()})
    raw = SOURCE.read_bytes()
    _need(hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'GM107_SOURCE_SHA')
    validate_source(raw)
    return dict(version='8.3.18.1208', staticVerified=True, pinnedRanges=len(RANGES),
                prerequisites=len(reports), sourceSha256=SOURCE_SHA256,
                resourceGetterPublished=False, resourceGetterBinaryAbiVerified=True,
                liveFormHelperRuntimeVerified=False, managedFormRuntimeVerified=False,
                repositoryWrites=0, goldCalls=0, configurationSaveAuthorized=False)
