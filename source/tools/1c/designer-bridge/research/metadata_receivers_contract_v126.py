"""Fixed source/SDK/PE prerequisite for uninvoked typed receiver inventory.

Published @+ ownership is normal engine-counted usage, not raw adoption.
Getters and matching GUIDs alone do not prove Main/DB roles or permit Save.
"""
import hashlib
from pathlib import Path
import re
import struct

from metadata_receiver_inventory_v126 import verify_static as verify_primary
from repository_pe_probe import PE

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'tests/NativeMetadataReceiversV126.as'
SOURCE_SHA = 'd341959ab7a297c9d5a3b5555a8d559e8426016bf3354c14fe6bae018dbed3b0'
REFERENCE = HERE.parent / 'tests/NativeRepositoryObserve.as'
REFERENCE_SHA = 'd7ac427467016667ac2b9e84a97a92727ef6955a2bf5dc439d4da36871bff16d'
PRIMARY_SOURCE = HERE / 'metadata_receiver_inventory_v126.py'
PRIMARY_SOURCE_SHA = '3d27fb68f4f62cb3961f11b623c4472051cd807881f65e13b12d18a57d3c56a7'
ROOT_TABLE = (0xf15214, 240, '2e6a784b342415d24b52a949d19d8dceac0e0f8327e51f2b9f45cdcfe7fc5acc')
ROOT_SLOTS = {0: 0xb51be1, 1: 0x995305, 2: 0x9952bf, 3: 0x5c5940,
              5: 0x30acc0, 49: 0x5c8590, 59: 0x5c8d40}
OWN_ID = 'e65cf9ac-3af8-42f2-bd9d-68542f5e1b09'


def need(ok, code):
    if not ok:
        raise ValueError('V126_RECEIVER_STATIC_' + code)


def verify_source(raw):
    """Inspect only NEW source; forbid writers/private calls/handle escapes."""
    need(type(raw) is bytes and 0 < len(raw) <= 32768, 'SOURCE_REJECTED')
    try:
        text = raw.decode('utf8')
    except UnicodeError:
        raise ValueError('V126_RECEIVER_STATIC_SOURCE_REJECTED') from None
    code = re.sub(r'//[^\n]*|/\*.*?\*/', '', text, flags=re.S)
    need(not re.search(r'\b(?:createByClsid|connectConfig|setMdPropVal|set_id|setModified|'
                      r'queryIface|toIUnknown|initFuncDefFromAddress|GetService|LoadLibrary|'
                      r'connectString|subscribe|unsubscribe|notify|saveConfig|serialize|deserialize|'
                      r'load|transmitCommand|getName|getClassName|presentation|ahCycleDurable)\s*\(', code),
         'FORBIDDEN_CALL')
    need('.unk' not in code and 'funcdef ' not in code and '&#' not in code,
         'RAW_HANDLE_OR_SOURCE_REJECTED')
    need('bool ahMetadataReceiversConsumedV126=false;' in code
         and 'if(ahMetadataReceiversConsumedV126)return ' in code
         and 'ahMetadataReceiversConsumedV126=true;' in code, 'ONE_SHOT_REJECTED')
    need('IMDEditService&& edit;IInfoBaseService&& baseService;IInfoBase&& base;' in code
         and 'AhMetadataReceiverRowV126 currentRow,templateRow,baseRow;' in code
         and 'CppCatch caught(' in code
         and 'bool handlesExited=true;bool after=ahMetadataReceiversScopeV126(version,controller,provider);' in code,
         'LIFETIME_REJECTED')
    need('if(currentRow.uiAbi){currentRow.uiRootCalls++;&&currentRow.root=currentRow.ui.getMDCont();}' in code
         and 'if(editAbi){templateUiCalls++;edit.getTemplatesMainConfigMngrUI(templateRow.ui);}' in code
         and 'if(templateRow.uiAbi){templateRow.uiRootCalls++;&&templateRow.root=templateRow.ui.getMDCont();}' in code
         and 'if(baseServiceReturned){defaultCalls++;&&base=baseService.getDefault();}' in code
         and 'if(baseAbi){baseManagerCalls++;&&baseRow.manager=base.getConfigMgr();}' in code
         and 'if(baseRow.managerAbi){baseRootCalls++;&&baseRow.root=baseRow.manager.getMDCont(0);}' in code,
         'PUBLISHED_PATH_REJECTED')
    need(code.count('getMDEditService(') == 1 and code.count('currentProcess().getService(') == 1
         and code.count('.getDefault(') == 1 and code.count('.getConfigMgr(') == 1
         and code.count('.getTemplatesMainConfigMngrUI(') == 1
         and code.count('row.root.objById(') == 1
         and code.count('ahMetadataReceiverReadV126(currentRow);') == 1
         and code.count('ahMetadataReceiverReadV126(templateRow);') == 1
         and code.count('ahMetadataReceiverReadV126(baseRow);') == 1, 'CALL_SCOPE_REJECTED')
    need('row.rootAbi=ahMetadataReceiverRootV126(row.root);if(!row.rootAbi)return;' in code
         and code.index('if(!row.rootAbi)return;') < code.index('Guid id=row.root.id;')
         < code.index('row.root.getConfigMngr()') < code.index('row.root.objById(')
         and 'if(row.managerAbi){' in code
         and code.index('if(row.managerAbi){') < code.index('row.manager.getMDCont(0)'),
         'GETTER_GATE_ORDER_REJECTED')
    need('ahPermissionReadable(self,4) && ahPermissionReadable(mem::int_ptr[self],count*4)' in code
         and '"frntend.dll",0xc0e458,27' in code and '"backend.dll",0xede0a4,86' in code
         and '"backend.dll",0xf15214,60' in code and '"rclient.dll",0x670bc,66' in code
         and '"frntend.dll",0xc4848c,17' in code, 'TABLE_BOUNDS_REJECTED')
    for slot, rva in ROOT_SLOTS.items():
        token = f'mem::int_ptr[table+{slot}*4],"backend.dll",0x{rva:x}' if slot > 2 else \
                f'mem::int_ptr[table{("+"+str(slot*4)) if slot else ""}],"backend.dll",0x{rva:x}'
        need(token in code, 'ROOT_SLOT_REJECTED')
    need(code.count('{'+OWN_ID+'}') == 2
         and 'templateRow.root.self==baseRow.root.self' in code
         and 'templateRow.manager.self==baseRow.manager.self' in code
         and 'templateRow.rootId==baseRow.rootId' in code, 'COMPARISON_SCOPE_REJECTED')
    for flag in ('canonicalIdentityVerified', 'templatesMainRoleVerified', 'infoBaseDatabaseRoleVerified',
                 'semanticMainDbRoleVerified', 'metadataEqualityVerified', 'pendingOwnOnlyVerified',
                 'saveAuthorized', 'databaseUpdateAuthorized', 'observerAuthorized', 'captureAuthorized', 'nativePermit'):
        need(flag+'\\":false' in text, 'FALSE_CLAIM_REJECTED')
    return dict(sourceVerified=True, publishedTypedPathsUsed=True, explicitQueryInterfaceCalls=0,
                rawAdoptions=0, sourceOnlyFunction=True, sdkCompiled=False,
                interfacePointerComparisonsOnly=True, canonicalIdentityVerified=False,
                semanticMainDbRoleVerified=False, nativePermit=False, saveAuthorized=False,
                databaseUpdateAuthorized=False, observerAuthorized=False, captureAuthorized=False)


def verify_root_slice(raw):
    """Verify fixed container table data; no getter is invoked or role inferred."""
    need(type(raw) is bytes and len(raw) == ROOT_TABLE[1]
         and hashlib.sha256(raw).hexdigest() == ROOT_TABLE[2], 'ROOT_TABLE_PIN_REJECTED')
    base = 0x1f400000
    need(all(struct.unpack_from('<I', raw, slot * 4)[0] == base + rva
             for slot, rva in ROOT_SLOTS.items()), 'ROOT_SLOTS_REJECTED')
    return dict(rootTypedGetterSlotsVerified=True, rootTableRva=ROOT_TABLE[0],
                rootSlots=dict(ROOT_SLOTS), semanticMainDbRoleVerified=False, nativePermit=False)


def verify_static():
    """Read only fixed sources/SDK/archive/PE; no loads, callbacks or runtime."""
    need(hashlib.sha256(SOURCE.read_bytes()).hexdigest() == SOURCE_SHA, 'SOURCE_PIN_CHANGED')
    need(hashlib.sha256(PRIMARY_SOURCE.read_bytes()).hexdigest() == PRIMARY_SOURCE_SHA,
         'PRIMARY_SOURCE_CHANGED')
    need(hashlib.sha256(REFERENCE.read_bytes()).hexdigest() == REFERENCE_SHA, 'REFERENCE_SOURCE_CHANGED')
    reference = REFERENCE.read_text(encoding='utf8')
    need('IInfoBaseService&& baseService = currentProcess().getService(IID_IInfoBaseService);' in reference
         and '&&base = baseService.getDefault();' in reference and '&&baseManager = base.getConfigMgr();' in reference
         and 'IMDContainer&& baseContainer = baseManager.getMDCont(0);' in reference,
         'MEASURED_PUBLISHED_REFERENCE_CHANGED')
    result = verify_source(SOURCE.read_bytes())
    primary = verify_primary()
    image = PE('backend.dll');at = image.offset(image.base + ROOT_TABLE[0])
    result.update(verify_root_slice(image.data[at:at + ROOT_TABLE[1]]))
    result.update(sourceSha256=SOURCE_SHA, referenceSourceSha256=REFERENCE_SHA,
                  primaryInventorySourceSha256=PRIMARY_SOURCE_SHA,
                  sdkAndPlatformPinsVerified=primary['archiveHashVerified'] and primary['platformModuleHashesVerified'],
                  autoHandleDeclared=primary['getterReturnAutoHandleDeclared'],
                  nativeGetterLacksAddRefIsOwnershipViolation=False,
                  runtimeReceiverInventoryVerified=False, pendingOwnOnlyVerified=False,
                  nextSemanticCheck='own-unsaved-constant-presence-current-template-IB-before-and-while-created',
                  independentPersistedComparison='/CompareCfg MainConfiguration DBConfiguration without export')
    return result
