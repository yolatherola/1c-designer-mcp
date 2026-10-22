"""Fixed tool-source composition only; no SDK, process, application body or CLI.

derive_source() returns unrendered AngelScript bytes in RAM. Admission booleans
are placeholders, never independent write authority. Root must seal a plan and
fresh template policy proof before any future execution; this module cannot run
the result. The compile-only consumer must substitute BOTH gates with false.
"""
import hashlib
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
MAX_BYTES = 65536
SOURCE_PINS = {
    'NativeRamPacketV240.as': 'ac1ce2fbf13c7f735813b74d966f0ed691e877e12ddc68d053a5d5125a942922',
    'NativeRunnerSheetApplyV242.as': '3c96f437e59d042bedb6b3c616fdaf9f940dd9dd78774bcab4731ac677326631',
    'NativeRunnerModuleApplyV244.as': '5cca664d04c4cd612d8e5a24d018c953a8888dfa56d0f30c8ba83a37fc11aa3c',
}
MAIN_PIN = '64d37425553b75c6465aef5c194f327fb7e75399ec682f686fa7b658f7a4ad66'
LIVE_RUNTIME = ROOT / 'build/designer-v43-6c5fb1ffca5d42a0ac3c4d2f42f1ba3f/runtime/modules/snegopat'
RUNTIME_PINS = {
    'engine/main.as': MAIN_PIN,
    'v8api/ah_capture_status.v': '109cd5e33d48a38b116854398337875bdc2c9335a8010942b6a26f7efe6d20ef',
    'v8api/textmgr.v': '61c83d8fd9a3c78f3ed573b649074b3aa8e646d8ff54f40aa296d5f4e992a75a',
}
PLACEHOLDERS = frozenset(('PAYLOAD_ADDRESS', 'PAYLOAD_LENGTH', 'PAYLOAD_SHA256', 'OPERATION_ID',
                          'TEMPLATE_POLICY_ADMITTED', 'WRITER_PLAN_ADMITTED', 'PACKET_PROOF_PATH',
                          'SHEET_PROOF_PATH', 'COMPOSITE_PROOF_PATH', 'PREWRITE_INTENT_PATH'))
_NATIVE_FREE = {
    'ahGetCurrentProcessId': 'stdcall uint ahGetCurrentProcessId()|GetCurrentProcessId',
    'ahGetCurrentThreadId': 'stdcall uint ahGetCurrentThreadId()|GetCurrentThreadId',
}
_NATIVE_METHODS = {
    'ahOwnedActionBeginV63': 'bool ahOwnedActionBeginV63(int kind, const TextPosition&in start, const TextPosition&in stop, IUnknown@ external)|?createNewAction@TextManager@core@@UAE_NW4DocActionType@2@ABVTextPosition@2@1PAUIUnknown@@@Z',
    'ahOwnedActionCloseV63': 'void ahOwnedActionCloseV63(const TextPosition&in start, const TextPosition&in stop)|?closeNewAction@TextManager@core@@UAEXABVTextPosition@2@0@Z',
    'ahWholeSelectedTextV65': 'int_ptr ahWholeSelectedTextV65()|?getSelectText@TextManager@core@@QAEPB_SXZ',
}


def _need(value, reason):
    if not value:
        raise ValueError('V249_' + reason)


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _unwrap(source, name):
    header = 'void ' + name + '() {\n'
    _need(source.count(header) == 1 and source.endswith('\n}\n'), 'FUNCTION_FRAME')
    preamble, body = source.split(header, 1)
    body = body[:-3]
    _need(preamble + header + body + '\n}\n' == source, 'FUNCTION_REVERSE')
    return body


def _edit(text, old, new, journal, label):
    _need(old and new and text.count(old) == 1, 'EDIT_' + label)
    changed = text.replace(old, new, 1)
    _need(changed.count(new) == 1 and changed.replace(new, old, 1) == text, 'EDIT_REVERSE_' + label)
    journal.append((label, old, new))
    return changed


def _reverse(text, journal):
    for label, old, new in reversed(journal):
        _need(text.count(new) == 1, 'REVERSE_' + label)
        text = text.replace(new, old, 1)
    return text


def verify_closure(source, main, identity_sdk, text_sdk):
    """Verify definitions, not manifest membership or surviving call sites."""
    calls = set(re.findall(r'(?<![.A-Za-z0-9_])\b(ah\w+)\s*\(', source)) - {'ahRunnerCompositeV249'}
    definitions = set(re.findall(r'(?m)^\s*[A-Za-z_]\w*(?:<[^>\n]+>)?\s*[@&]*\s+'
                                 r'(ah\w+)\s*\([^;{}]*\)\s*\{', main))
    _need(calls <= definitions | set(_NATIVE_FREE), 'MAIN_CLOSURE')
    normalized = re.sub(r'\s+', '', identity_sdk)
    for name in calls & set(_NATIVE_FREE):
        _need(re.sub(r'\s+', '', _NATIVE_FREE[name]) in normalized, 'IDENTITY_DECLARATION')
    methods = set(re.findall(r'\.\s*(ah\w+)\s*\(', source))
    _need(methods <= set(_NATIVE_METHODS), 'METHOD_ALIAS')
    normalized = re.sub(r'\s+', '', text_sdk)
    for name in methods:
        _need(re.sub(r'\s+', '', _NATIVE_METHODS[name]) in normalized, 'METHOD_DECLARATION')
    return len(calls), len(methods)


_PROLOGUE = '''    // Composite state survives every nested native catch and partial return.
    bool compositeWriterPlanAdmitted=__WRITER_PLAN_ADMITTED__;
    bool compositeTemplatePolicyAdmitted=__TEMPLATE_POLICY_ADMITTED__;
    bool compositePacketProofWritten=false,compositePacketPreflight=false,compositeSheetProofWritten=false;
    bool compositeSheetVerified=false,compositeSheetAttempted=false,compositeCheckpointRetained=false,compositeDocumentRetained=false;
    bool compositeReferenceAttempted=false;
    bool compositeModulePrepared=false,compositeModuleApplied=false,compositeModuleUnknown=false,compositeSelectionsRestored=false;
    bool compositeFinalVerified=false,compositeModulesDirty=false;
    uint compositeModuleBeginCalls=0,compositeModuleWriteCalls=0,compositeModuleCloseCalls=0,compositeModulesApplied=0;
    uint compositeSheetMergeAttempts=0,compositeSheetSetterAttempts=0,compositeSheetMerges=0,compositeSheetSetters=0;
    int_ptr compositeRetainedCheckpoint=0,compositeRetainedDocument=0;
    string compositeReason="PACKET",compositeSheetReason="NOT_RUN",compositeSheetStatus="NOT_RUN",compositeModuleStatus="NOT_RUN";
    string compositePacketProofPath="__PACKET_PROOF_PATH__";
    IDocument@ compositeSheetDocument;IFileEx@ compositeSheetCheckpoint;
    IMDObject@ compositeSheetObject;IMDContainer@ compositeSheetRoot;
'''

_PACKET_PROOF = '''
            // Phase-only zero-write proof is durable BEFORE any application mutation.
            string packetReadProof="{\\"version\\":240,\\"phase\\":\\"PACKET_PREFLIGHT\\",\\"status\\":\\"VALIDATED\\",\\"reason\\":\\"NONE\\""
                +",\\"packetBytes\\":"+packetBytes+",\\"snapshotReady\\":"+snapshotReady+",\\"wholeHashVerified\\":"+wholeHashVerified
                +",\\"packetSha256\\":\\""+packetSha+"\\",\\"parsedRecords\\":"+parsedRecords+",\\"checkedBodies\\":"+checkedBodies
                +",\\"utf8Bodies\\":"+utf8Bodies+",\\"bodySha256\\":"+bodyHashes+"]"
                +",\\"sourceWrites\\":0,\\"metadataWrites\\":0,\\"configurationSaves\\":0,\\"databaseUpdates\\":0,\\"repositoryMutations\\":0,\\"writerAuthorized\\":false}";
            ExceptionCatcher packetProofCatch;
            {CppCatch caught("class core::Exception",ExceptionHandler(packetProofCatch.handle));
                if(packetReadProof.toUtf8().length<=4096)compositePacketProofWritten=ahWriteSample(compositePacketProofPath,packetReadProof);
            }
            if(packetProofCatch.hasException || !compositePacketProofWritten){compositeReason="PACKET_PROOF";break;}
            compositePacketPreflight=true;
            if(!compositeWriterPlanAdmitted){compositeReason="WRITER_PLAN_UNRESOLVED";break;}
            if(!compositeTemplatePolicyAdmitted){compositeReason="TEMPLATE_POLICY_UNRESOLVED";break;}
            string compositeOperation=operation,compositePacketSha=expectedSha;
'''

_SHEET_EXPORT = '''    // Export every attempt/ref before constructing the nested sheet proof.
    compositeSheetVerified=verified;compositeSheetAttempted=writeAttempted;
    compositeCheckpointRetained=checkpointRetained;compositeDocumentRetained=documentRetained;
    if(retainedCheckpoint!=0)compositeRetainedCheckpoint=retainedCheckpoint;
    if(retainedDocument!=0)compositeRetainedDocument=retainedDocument;
    compositeSheetMergeAttempts=realMergeAttempts;compositeSheetSetterAttempts=realSetterAttempts;
    compositeSheetMerges=realMergeCompleted;compositeSheetSetters=realSetterCompleted;
    compositeSheetStatus=status;compositeSheetReason=reason;
    @compositeSheetDocument=document;@compositeSheetCheckpoint=checkpoint;
    @compositeSheetObject=object;@compositeSheetRoot=root;
'''

_MODULE_EXPORT_AND_FINAL = '''
            // Cleanup in244 has already run, including sheet-refusal paths.
            compositeModulePrepared=modulePrepared;compositeModuleApplied=moduleApplied;compositeModuleUnknown=moduleUnknown;
            compositeModuleBeginCalls=moduleBeginCalls;compositeModuleWriteCalls=moduleWriteCalls;compositeModuleCloseCalls=moduleCloseCalls;
            compositeModulesApplied=moduleAppliedCount;compositeSelectionsRestored=moduleSelectionsRestored && moduleTreeSelectionRestored;
            compositeModuleStatus=moduleStatus;
            if(!modulePrepared){compositeReason="MODULE_PREPARE_"+moduleReason;break;}
            if(!compositeSheetVerified){compositeReason="SHEET_"+compositeSheetReason;break;}
            if(!compositeSheetProofWritten){compositeReason="SHEET_PROOF";break;}
            if(!moduleApplied || moduleUnknown){compositeReason="MODULE_APPLY_"+moduleReason;break;}
            if(!compositeSelectionsRestored){compositeReason="SELECTION_RESTORE";break;}
            compositeReason="FINAL_METADATA";
            if(!ahPipeScopeAlive() || ahStatusUi !is moduleUi || !ahCatalogEditableV218(moduleRoot)
                || !ahCatalogSameV218(moduleUi.getMDCont().unk,moduleRoot.unk)
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211
                || !moduleRoot.isModified() || !moduleUi.isModified() || !ahAccessSelectionV232(moduleSeed))break;
            bool finalModules=true;
            for(uint index=0;index<2;index++){
                IMDObject@ finalObject=moduleRoot.objById(Guid("{"+moduleIds[index]+"}"));v8string editorAfter,helperAfter;
                if(finalObject is null || !ahCatalogSameV218(finalObject.unk,moduleObjects[index].unk)
                    || !moduleObjectModified[index] || !finalObject.isModified() || !moduleDocuments[index].isModified()
                    || moduleDocuments[index].getReadOnly() || !ahCatalogSameV218(moduleHelpers[index].getMDObj().unk,finalObject.unk)
                    || !moduleTexts[index].getTextManager().save(editorAfter) || editorAfter.str!=replacementTexts[index]
                    || !moduleModules[index].textOfModule(moduleProperty,false,helperAfter) || helperAfter.str!=replacementTexts[index]){
                    finalModules=false;break;
                }
            }
            if(!finalModules)break;compositeModulesDirty=true;
            if(compositeSheetDocument is null || compositeSheetObject is null || compositeSheetRoot is null
                || !compositeSheetDocument.isModified() || compositeSheetDocument.getReadOnly()
                || !compositeSheetDocument.getConfigMode() || !compositeSheetObject.isModified()
                || !ahCatalogSameV218(compositeSheetRoot.unk,moduleRoot.unk)
                || !ahCatalogSameV218(moduleRoot.objById(Guid("{8daef957-4ae2-48a1-bf6c-b88163a076f5}")).unk,compositeSheetObject.unk))break;
            compositeFinalVerified=true;compositeReason="NONE";
'''

_FINAL_PROOF = '''
    if(catcher.hasException){packetValid=false;compositeFinalVerified=false;compositeReason="NATIVE_EXCEPTION";}
    if(!compositePacketPreflight && compositeReason=="PACKET")compositeReason=reason;
    bool compositeMutationPossible=compositeSheetAttempted || compositeModuleBeginCalls!=0 || compositeModuleWriteCalls!=0;
    bool compositeRetain=compositeReferenceAttempted || compositeCheckpointRetained || compositeDocumentRetained || compositeMutationPossible;
    bool compositeComplete=packetValid && compositePacketPreflight && compositePacketProofWritten && compositeWriterPlanAdmitted
        && compositeTemplatePolicyAdmitted && compositeModulePrepared && compositeSheetVerified && compositeSheetProofWritten
        && compositeModuleApplied && !compositeModuleUnknown && compositeModulesDirty && compositeSelectionsRestored && compositeFinalVerified;
    string compositeStatus=compositeComplete?"COMPOSITE_APPLIED_RAM":(compositeMutationPossible?"COMPOSITE_UNKNOWN_RETAIN"
        :(compositeRetain?"COMPOSITE_REFUSED_RETAIN":"COMPOSITE_REFUSED"));
    string compositeProof="{\\"version\\":249,\\"phase\\":\\"COMPOSITE_FINAL\\",\\"status\\":\\""+compositeStatus+"\\",\\"reason\\":\\""+compositeReason
        +"\\",\\"operationId\\":\\""+operation+"\\",\\"packetSha256\\":\\""+expectedSha+"\\",\\"packetBytes\\":"+packetBytes
        +",\\"packetPreflightVerified\\":"+compositePacketPreflight+",\\"packetProofWritten\\":"+compositePacketProofWritten
        +",\\"writerPlanAdmitted\\":"+compositeWriterPlanAdmitted+",\\"templatePolicyAdmitted\\":"+compositeTemplatePolicyAdmitted
        +",\\"modulesPrepared\\":"+compositeModulePrepared+",\\"sheetVerified\\":"+compositeSheetVerified+",\\"sheetProofWritten\\":"+compositeSheetProofWritten
        +",\\"sheetStatus\\":\\""+compositeSheetStatus+"\\",\\"moduleStatus\\":\\""+compositeModuleStatus+"\\",\\"modulesApplied\\":"+compositeModulesApplied
        +",\\"moduleMetadataDirtyVerified\\":"+compositeModulesDirty+",\\"selectionRestored\\":"+compositeSelectionsRestored
        +",\\"moduleActionBeginCalls\\":"+compositeModuleBeginCalls+",\\"moduleWriteCalls\\":"+compositeModuleWriteCalls+",\\"moduleActionCloseCalls\\":"+compositeModuleCloseCalls
        +",\\"sheetMergeAttempts\\":"+compositeSheetMergeAttempts+",\\"sheetSetterAttempts\\":"+compositeSheetSetterAttempts
        +",\\"sheetMergesCompleted\\":"+compositeSheetMerges+",\\"sheetSettersCompleted\\":"+compositeSheetSetters
        +",\\"mutationPossible\\":"+compositeMutationPossible+",\\"retentionRequired\\":"+compositeRetain
        +",\\"referenceLeaseAttempted\\":"+compositeReferenceAttempted
        +",\\"checkpointReferenceRetained\\":"+compositeCheckpointRetained+",\\"documentReferenceRetained\\":"+compositeDocumentRetained
        +",\\"checkpointPointer\\":"+uint(compositeRetainedCheckpoint)+",\\"documentPointer\\":"+uint(compositeRetainedDocument)
        +",\\"configurationSaves\\":0,\\"databaseUpdates\\":0,\\"repositoryMutations\\":0,\\"configurationSavedVerified\\":false"
        +",\\"writerAuthorized\\":"+(compositeWriterPlanAdmitted && compositeTemplatePolicyAdmitted && compositeModulePrepared && compositePacketPreflight)+"}";
    ExceptionCatcher compositeOutput;
    {CppCatch caught("class core::Exception",ExceptionHandler(compositeOutput.handle));
        if(compositeProof.toUtf8().length<=8192)ahWriteSample("__COMPOSITE_PROOF_PATH__",compositeProof);
    }
'''


def _compose(raw_sources, main, identity_sdk, text_sdk):
    _need(set(raw_sources) == set(SOURCE_PINS), 'SOURCE_SET')
    for name, expected in SOURCE_PINS.items():
        _need(type(raw_sources[name]) is bytes and _sha(raw_sources[name]) == expected, 'SOURCE_PIN')
    bodies = {name: _unwrap(raw_sources[name].decode('utf-8'), function) for name, function in (
        ('NativeRamPacketV240.as', 'ahRamPacketV240'), ('NativeRunnerSheetApplyV242.as', 'ahRunnerSheetApplyV242'),
        ('NativeRunnerModuleApplyV244.as', 'ahRunnerModuleApplyV244'))}
    packet_original, sheet_original, module_original = (bodies[name] for name in SOURCE_PINS)
    packet_edits, sheet_edits, module_edits = [], [], []
    sheet = _edit(sheet_original, 'string operation="__OPERATION_ID__",packetSha="__PAYLOAD_SHA256__";',
                  'string operation=compositeOperation,packetSha=compositePacketSha;', sheet_edits, 'SHEET_METADATA_ALIAS')
    sheet = _edit(sheet, '__FULL_PACKET_PREFLIGHT__',
                  '(packetValid && modulePrepared && compositeTemplatePolicyAdmitted && compositeWriterPlanAdmitted)', sheet_edits, 'SHEET_PREFLIGHT')
    sheet = _edit(sheet, '    string proof=', _SHEET_EXPORT + '    string proof=', sheet_edits, 'SHEET_EXPORT')
    sheet = _edit(sheet, 'checkpoint.AddRef();checkpointRetained=true;retainedCheckpoint=checkpoint.self;',
                  'compositeReferenceAttempted=true;compositeRetainedCheckpoint=checkpoint.self;\n'
                  '            checkpoint.AddRef();checkpointRetained=true;retainedCheckpoint=checkpoint.self;compositeCheckpointRetained=true;',
                  sheet_edits, 'CHECKPOINT_LEASE_ATTEMPT')
    sheet = _edit(sheet, 'document.AddRef();documentRetained=true;retainedDocument=document.self;',
                  'compositeReferenceAttempted=true;compositeRetainedDocument=document.self;\n'
                  '            document.AddRef();documentRetained=true;retainedDocument=document.self;compositeDocumentRetained=true;',
                  sheet_edits, 'DOCUMENT_LEASE_ATTEMPT')
    sheet = _edit(sheet, 'writeAttempted=true;realMergeAttempts++;',
                  'writeAttempted=true;compositeSheetAttempted=true;realMergeAttempts++;compositeSheetMergeAttempts++;', sheet_edits, 'SHEET_ATTEMPT_MIRROR')
    sheet = _edit(sheet, 'realSetterAttempts++;', 'realSetterAttempts++;compositeSheetSetterAttempts++;', sheet_edits, 'SHEET_SETTER_ATTEMPT_MIRROR')
    sheet = _edit(sheet, 'realMergeCompleted++;', 'realMergeCompleted++;compositeSheetMerges++;', sheet_edits, 'SHEET_MERGE_COMPLETED_MIRROR')
    sheet = _edit(sheet, 'realSetterCompleted++;', 'realSetterCompleted++;compositeSheetSetters++;', sheet_edits, 'SHEET_SETTER_COMPLETED_MIRROR')
    sheet = _edit(sheet, 'if(proof.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",proof);',
                  'if(proof.toUtf8().length<=8192)compositeSheetProofWritten=ahWriteSample("__SHEET_PROOF_PATH__",proof);',
                  sheet_edits, 'SHEET_PROOF_RESULT')
    module = _edit(module_original, '    __VALIDATED_PACKET_PREFIX__\n    bool moduleCompositeAdmitted=false',
                   '    bool moduleCompositeAdmitted=false', module_edits, 'MODULE_VALIDATED_PREFIX')
    module = _edit(module, 'moduleBeginCalls++;', 'moduleBeginCalls++;compositeModuleBeginCalls++;', module_edits, 'MODULE_BEGIN_MIRROR')
    module = _edit(module, 'moduleWriteCalls++;moduleUnknown=true;',
                   'moduleWriteCalls++;compositeModuleWriteCalls++;moduleUnknown=true;', module_edits, 'MODULE_WRITE_MIRROR')
    module = _edit(module, 'moduleCloseCalls++;', 'moduleCloseCalls++;compositeModuleCloseCalls++;', module_edits, 'MODULE_CLOSE_MIRROR')
    module = _edit(module, 'moduleAppliedCount++;', 'moduleAppliedCount++;compositeModulesApplied++;', module_edits, 'MODULE_COMPLETED_MIRROR')
    splice = ('            // V244_PREPARE_END\n' + '\n            // V249_SHEET_BLOCK_BEGIN\n            {\n' + sheet
              + '\n            }\n            // V249_SHEET_BLOCK_END\n'
              + '            moduleCompositeAdmitted=packetValid && modulePrepared && compositeSheetVerified && compositeSheetProofWritten\n'
              + '                && compositeTemplatePolicyAdmitted && compositeWriterPlanAdmitted;\n')
    splice = splice.replace('// V249_SHEET_BLOCK_BEGIN\n            {\n',
                            '// V249_SHEET_BLOCK_BEGIN\n            {\n'
                            '                compositeSheetStatus="ENTERED";compositeSheetReason="INTERRUPTED";\n', 1)
    module = _edit(module, '            // V244_PREPARE_END\n', splice, module_edits, 'SHEET_AFTER_BOTH_PREPARED')
    anchor = '            packetValid=true;reason="NONE";\n'
    packet = _edit(packet_original, anchor, anchor + _PACKET_PROOF + '\n            // V249_MODULE_BLOCK_BEGIN\n'
                   + module + '\n            // V249_MODULE_BLOCK_END\n' + _MODULE_EXPORT_AND_FINAL,
                   packet_edits, 'COMPOSITE_WHILE_PACKET_LIVE')
    tail_anchor = '    if(catcher.hasException){packetValid=false;reason="NATIVE_EXCEPTION";}bodyHashes+="]";\n'
    _need(packet_original.count(tail_anchor) == 1, 'PACKET_TAIL')
    old_tail = packet_original[packet_original.index(tail_anchor):]
    packet = _edit(packet, old_tail, _FINAL_PROOF, packet_edits, 'FINAL_COMPOSITE_PROOF')
    state_anchor = '    string reason="OWNER",packetSha="",bodyHashes="[",digits="0123456789abcdef";'
    packet = _edit(packet, state_anchor, _PROLOGUE + state_anchor, packet_edits, 'COMPOSITE_STATE')
    _need(_reverse(sheet, sheet_edits) == sheet_original, 'SHEET_REVERSE')
    _need(_reverse(module, module_edits) == module_original, 'MODULE_REVERSE')
    _need(_reverse(packet, packet_edits) == packet_original, 'PACKET_REVERSE')
    source = '// FIXED TOOL COMPOSITION249; no execution without sealed root plan and fresh policy.\nvoid ahRunnerCompositeV249() {\n' + packet + '\n}\n'
    raw = source.encode('utf-8')
    _need(len(raw) <= MAX_BYTES, 'SOURCE_BOUND')
    _need(re.findall(r'^void (\w+)\(', source, re.M) == ['ahRunnerCompositeV249'], 'ONE_FUNCTION')
    names = re.findall(r'__([A-Z0-9_]+)__', source)
    _need(set(names) == PLACEHOLDERS and len(names) == len(PLACEHOLDERS), 'PLACEHOLDERS')
    dependencies, methods = verify_closure(source, main, identity_sdk, text_sdk)
    _need(source.index('packetValid=true;reason="NONE";') < source.index('packetReadProof=')
          < source.index('V244_PREPARE_BEGIN') < source.index('V244_PREPARE_END')
          < source.index('V249_SHEET_BLOCK_BEGIN') < source.index('V249_SHEET_BLOCK_END')
          < source.index('V244_APPLY_BEGIN') < source.index('V244_APPLY_END')
          < source.index('Cleanup in244 has already run'), 'PHASE_ORDER')
    proof = {'version': 249, 'sourceSha256': _sha(raw), 'sourceBytes': len(raw), 'sourcePins': dict(SOURCE_PINS),
             'mainSha256': _sha(main.encode('utf-8')), 'freeDependencies': dependencies, 'nativeMethodAliases': methods,
             'reverseVerified': True, 'replacements': {name: [item[0] for item in journal] for name, journal in
             (('packet', packet_edits), ('sheet', sheet_edits), ('modules', module_edits))},
             'runtimeExecuted': False, 'writerAuthorized': False}
    return raw, proof


def _runtime_root(runtime):
    # An explicit technical directory is the sole new input, never main text,
    # application bytes, source hashes, SDK declarations or a recursive scan.
    _need(runtime is None or type(runtime) is str or isinstance(runtime, Path), 'RUNTIME_TYPE')
    path = LIVE_RUNTIME if runtime is None else Path(runtime)
    build = ROOT / 'build'
    _need(path.is_absolute() and build in path.parents and '..' not in path.parts, 'RUNTIME_BOUNDARY')
    parts = path.relative_to(build).parts
    _need(4 <= len(parts) <= 8 and re.fullmatch(r'designer-[a-z0-9-]{1,96}', parts[0]) is not None
          and tuple(value.lower() for value in parts[-3:]) == ('runtime', 'modules', 'snegopat'), 'RUNTIME_LAYOUT')
    _plain_runtime_path(path, directory=True)
    return path


def _plain_runtime_path(path, *, directory=False):
    _need(path.is_absolute() and ROOT / 'build' in path.parents, 'RUNTIME_BOUNDARY')
    try:
        for part in (path, *path.parents):
            info = part.lstat()
            _need(not part.is_symlink() and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'RUNTIME_REPARSE')
            if part == ROOT:
                break
        _need(path.resolve(strict=True) == path, 'RUNTIME_REDIRECT')
        _need(path.is_dir() if directory else path.is_file(), 'RUNTIME_KIND')
    except OSError:
        raise ValueError('V249_RUNTIME_UNAVAILABLE') from None


def _runtime_sources(runtime):
    path = _runtime_root(runtime)
    files = {}
    for key, pin in RUNTIME_PINS.items():
        target = path / key
        _plain_runtime_path(target)
        _need(0 < target.stat().st_size <= 2097152, 'RUNTIME_SIZE')
        with target.open('rb') as stream:
            raw = stream.read(2097153)
        _need(0 < len(raw) <= 2097152 and _sha(raw) == pin, 'RUNTIME_PIN')
        _plain_runtime_path(target)
        files[key] = raw
    return files


def _derive(runtime=None):
    checked = _runtime_sources(runtime)
    sources = {name: (HERE / name).read_bytes() for name in SOURCE_PINS}
    source, proof = _compose(sources, checked['engine/main.as'].decode('utf-8'),
                             checked['v8api/ah_capture_status.v'].decode('utf-8'), checked['v8api/textmgr.v'].decode('utf-8'))
    proof['runtimeSourcePins'] = dict(RUNTIME_PINS)
    return source, proof


def derive_source(runtime=None):
    """Return fixed tool AS in RAM from exact-pinned SDK files at own runtime.

    runtime is an absolute owned designer runtime directory below project build.
    None preserves the historical default. Root verifies live ownership/plan;
    this pure reader verifies technical path layout, full files and AS closure.
    """
    return _derive(runtime)[0]


def derivation_proof(runtime=None):
    """Hashes/counts/transformation labels only; no generated or application body."""
    return _derive(runtime)[1]
