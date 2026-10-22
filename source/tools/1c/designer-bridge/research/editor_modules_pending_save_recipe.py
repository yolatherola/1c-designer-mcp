"""Fixed stock Save3 source for two dirty module editors and a clean template.

Pure tool-source derivation. No native call, source body input, serialization,
Save authorization, staging or execution is implemented by this module.
"""
from pathlib import Path
import hashlib
import re
import sheet_notify_pending_save_recipe as base

HERE = Path(__file__).resolve().parent
BASE_RECIPE_SHA = '4edf3b7d11098e607a4933067c28ee4a51c73ea0e15034b8e63fd99184615518'
BASE_SOURCE_SHA = '16291011d4a6f5c2e3e8b90828ea4595ff954b99ee3de6b21a29c78a72c48330'
ENTRY = 'ahSaveDirtyModuleEditorsCleanTemplate'
PROFILE = 'MODULE_EDITORS_DIRTY_TEMPLATE_CLEAN_STOCK_SAVE3'

# Lexical locals only; strings/comments and member identifiers remain unchanged.
LOCAL_NAMES = '''scopeAdmitted pendingEditorsVerified saveOperation writerOperation packetSha scopeSha reason
attempted returned clean walkComplete preflight dispatches objectsVisited dirtyOwnMask dirtyAncestors
unknownDirty modulesVerified ownObjects ownDocuments catcher caught ui root ids expectedHashes service
i object helper parent document property body context header text employees rows row employee parameter
module editor flags editorValue helperValue bytes memory queue depth walkOkay at bit cls kinds k kind count
n child frame core legacyLayout receiver slots abi command commands description state same reserved status
proof output provider actor ownershipQueries statistic wanted versions'''.split()


def _need(ok, code):
    if not ok:
        raise ValueError('MODULE_EDITORS_SAVE_' + code)


def _rename_locals(text):
    names = {name: 'ems' + name[0].upper() + name[1:] for name in LOCAL_NAMES}
    tokens = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\b[A-Za-z_][A-Za-z0-9_]*\b')
    def replace(match):
        value = match.group()
        if value not in names or text[:match.start()].rstrip(' \t').endswith('.'):
            return value
        return names[value]
    renamed = tokens.sub(replace, text)
    # A bijective reverse over identifiers proves this phase changed no literals.
    inverse = {value: key for key, value in names.items()}
    def undo(match):
        value = match.group()
        if value not in inverse or renamed[:match.start()].rstrip(' \t').endswith('.'):
            return value
        return inverse[value]
    _need(tokens.sub(undo, renamed) == text, 'LEXICAL_REVERSE')
    return renamed


def derive_source():
    """Derive one stock command with observed mask6, no forced flags or content.

    The root controller separately binds actual writer proof, retained originals,
    stored template hash, native identity, lease and a fresh one-shot Save grant.
    A returned command and clean flags do not establish stored-resource equality.
    """
    _need(hashlib.sha256((HERE / 'sheet_notify_pending_save_recipe.py').read_bytes()).hexdigest()
          == BASE_RECIPE_SHA, 'BASE_RECIPE')
    raw = base.derive_source()
    _need(hashlib.sha256(raw).hexdigest() == BASE_SOURCE_SHA, 'BASE_SOURCE')
    original = raw.decode()
    text = original
    journal = []
    def edit(old, new, count=1):
        nonlocal text
        _need(text.count(old) == count and old != new, 'EXACT_ANCHOR')
        text = text.replace(old, new)
        journal.append((old, new, count))
    edit('void ahSaveKnownPendingEditors() {', 'void ' + ENTRY + '() {')
    edit('document.isModified()!=(i==0)', 'document.isModified()!=(i!=0)')
    edit('ownDocuments[i].isModified()!=(i==0)', 'ownDocuments[i].isModified()!=(i!=0)')
    edit('// Actual pendingREAD: metadata clean, module docs clean, template editor dirty.',
         '// Actual editor apply: metadata clean, both module docs dirty, template editor clean.')
    edit('KNOWN_PENDING_EDITORS_STOCK_SAVE3', PROFILE)
    edit('|| !ahCompactTableV108(document.self,"moxelui.dll",2155168,23) || !document.getConfigMode())break;',
         '|| !ahCompactTableV108(document.self,"moxelui.dll",2155168,23) || !document.getConfigMode()\n'
         '                        || document.isModified() || document.getReadOnly())break;')
    edit('array<IMDObject@> ownObjects;array<IDocument@> ownDocuments;',
         'array<IMDObject@> ownObjects;array<IDocument@> ownDocuments;\n'
         '    int_ptr provider=0;Guid actor;uint ownershipQueries=0;array<uint> versions={2272,1646};')
    edit('IMDEditService@ service=getMDEditService();reason="TARGETS";if(service is null)break;',
         'IMDEditService@ service=getMDEditService();reason="TARGETS";if(service is null)break;\n'
         '            // The bound provider is independent of tree selection.\n'
         '            provider=ahPlanProvider;reason="PROVIDER";\n'
         '            if(!ahCompactPageV108(provider,0x20))break;mem::memcpy(actor.self,provider+0x10,16);\n'
         '            if(!ahAccessProviderV232(provider,actor))break;\n'
         '            reason="FIXED_SOURCE_HASHES";\n'
         '            if(expectedHashes[0]!="90939ff38be12b52740f27153455e711b145086ee1aacb6e906eb897556f381a"\n'
         '                || expectedHashes[1]!="f64720f5118b2eaba03197f3de83a3ee93a68738e7177751fcd92cbb618e224a")break;')
    edit('IMDEditModuleHelper@ module=helper.unk;Guid property',
         'string statistic,wanted="{\\"queried\\":true,\\"verified\\":true,\\"version\\":"+versions[i-1]\n'
         '                        +",\\"revised\\":true,\\"ownerId\\":\\""+ahCatalogIdV218(actor)+"\\",\\"actorId\\":\\""+ahCatalogIdV218(actor)+"\\",\\"ownership\\":\\"OWN\\"}";\n'
         '                    reason="OWN_VERSION";\n'
         '                    if(!ahAccessStatisticV232(provider,actor,object.id,statistic) || statistic!=wanted)break;ownershipQueries++;\n'
         '                    IMDEditModuleHelper@ module=helper.unk;Guid property')
    edit('if(ownObjects.length!=3 || ownDocuments.length!=3 || modulesVerified!=2)break;',
         'if(ownObjects.length!=3 || ownDocuments.length!=3 || modulesVerified!=2 || ownershipQueries!=2)break;')
    edit('if(!same)break;preflight=true;',
         'if(!same || !ahAccessProviderV232(provider,actor))break;\n'
         '            // Query each exact module again immediately before the one stock Save.\n'
         '            for(uint i=1;i<3;i++){\n'
         '                string statistic,wanted="{\\"queried\\":true,\\"verified\\":true,\\"version\\":"+versions[i-1]\n'
         '                    +",\\"revised\\":true,\\"ownerId\\":\\""+ahCatalogIdV218(actor)+"\\",\\"actorId\\":\\""+ahCatalogIdV218(actor)+"\\",\\"ownership\\":\\"OWN\\"}";\n'
         '                reason="FRESH_OWN_VERSION";\n'
         '                if(!ahAccessStatisticV232(provider,actor,ownObjects[i].id,statistic) || statistic!=wanted)break;ownershipQueries++;\n'
         '            }\n'
         '            if(ownershipQueries!=4)break;preflight=true;')
    edit('+",\\"modulesVerified\\":"+modulesVerified+',
         '+",\\"ownershipQueries\\":"+ownershipQueries+",\\"expectedDocumentDirtyMask\\":6,\\"modulesVerified\\":"+modulesVerified+')
    restored = text
    for old, new, count in reversed(journal):
        _need(restored.count(new) == count, 'REVERSE_ANCHOR')
        restored = restored.replace(new, old)
    _need(restored == original, 'WHOLE_REVERSE')
    text = _rename_locals(text)
    _need(text.count('emsReceiver.transmitCommand(Command(emsCommand,0))') == 1, 'ONE_STOCK_COMMAND')
    _need(len(text.encode()) <= 32768, 'SOURCE_BOUND')
    for forbidden in ('setModified(', 'setPropVal(', 'setSelectText(', 'setSelectionText(',
                      'ahSheetSnapshotV231(', 'clearCache(', 'ahRepoTreeContext(', 'ahAccessSelectionV232('):
        _need(forbidden not in text, 'FORBIDDEN_CALL')
    return text.encode()


def derivation_manifest():
    raw = derive_source()
    return dict(kind='MODULE_EDITORS_PENDING_SAVE_TOOL_PROFILE', entry=ENTRY, compositionProfile=PROFILE,
                baseRecipeSha256=BASE_RECIPE_SHA, baseSourceSha256=BASE_SOURCE_SHA,
                derivedSha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
                expectedDocumentDirtyMask=6, expectedMetadataDirtyMask=0,
                templateSerializedBeforeSave=False, savedMainVerified=False,
                executionImplemented=False, configurationSaveAuthorized=False,
                placeholders=sorted(set(re.findall(r'__[A-Z][A-Z0-9_]+__', raw.decode()))))
