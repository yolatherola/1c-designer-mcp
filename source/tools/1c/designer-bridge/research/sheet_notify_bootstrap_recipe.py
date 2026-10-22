"""Pure future TOOL bootstrap/composite derivation. No staging, SDK or live CLI.

Baseline536 remains a separate, unchanged closure. The returned extension needs
its own root review and actual-main publication; it is not an old211/263 plan.
Application bodies/addresses/connections are never accepted as input.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
PARENT_SHA='3488fae0cb8cbe7f683d6569b25031471a1436c0b425357533520327e3227a66'
HELPER_SHA='c277f10b630004a2f25a9a4a1b175794f6ff097b9fe23b8e2663105fd8507910'
COMPOSER_SHA='a27af50b026f444f16aa66feaabc7cbfb842126d1b8f87eae53c38e802cfcf4d'
COMPOSITE_SHA='64fb6aeabcc5e1c24f091e81bbdd85e7fe8821a3a621fcced4c521ab6e130b07'
NATIVE_CONTRACT_SHA='22e9dff4003e04588f7afd0bb6d2a0b416f74fdbb7680cefda19d02724b7d111'


def need(ok,code):
    if not ok:raise ValueError('SHEET_BOOTSTRAP_'+code)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def source_snapshot():
    pins={'run_live_mcp_bootstrap_v211.py':PARENT_SHA,'NativeSheetChangeFixed.as':HELPER_SHA,
          'NativeSheetDocumentChange.c':NATIVE_CONTRACT_SHA,'runner_composite_v249.py':COMPOSER_SHA}
    prefix='tools/1c/designer-bridge/'
    result={prefix+'research/'+name:sha(fixed(name,pin)) for name,pin in pins.items()}
    result[prefix+'research/sheet_notify_bootstrap_recipe.py']=sha(Path(__file__).read_bytes())
    result[prefix+'tests/test_sheet_notify_bootstrap_recipe.py']=sha((HERE.parent/'tests/test_sheet_notify_bootstrap_recipe.py').read_bytes())
    return result


def fixed(name,pin):
    path=HERE/name;raw=path.read_bytes()
    need(sha(raw)==pin,'SOURCE_PIN_'+name.replace('.','_'))
    return raw


def load_fixed(name,pin):
    raw=fixed(name,pin);label='_sheet_bootstrap_'+name.replace('.','_')
    need(label not in sys.modules,'IMPORT_BUSY')
    spec=importlib.util.spec_from_file_location(label,HERE/name)
    module=importlib.util.module_from_spec(spec);sys.modules[label]=module
    try:exec(compile(raw,str(HERE/name),'exec'),module.__dict__)
    finally:del sys.modules[label]
    return module


def edit(text,old,new,journal,label):
    need(text.count(old)==1 and old!=new,'ANCHOR_'+label)
    changed=text.replace(old,new,1)
    need(changed.count(new)==1 and changed.replace(new,old,1)==text,'REVERSE_'+label)
    journal.append((label,old,new));return changed


def reverse(text,journal):
    for label,old,new in reversed(journal):
        need(text.count(new)==1,'REVERSE_COUNT_'+label);text=text.replace(new,old,1)
    return text


_BODY_GATES='''    // The complete fixed C22e9 contract, expressed as borrowed AS reads.
    // No slot20/44/377/417 native method is dispatched by these checks.
    reason="BODY_GATE_ABI";
    if(!ahCompactAddressV108(mem::int_ptr[table+20*4],"moxelui.dll",0x5b400))return false;
    int_ptr model=mem::int_ptr[receiver+0x5ec];
    if(model<12 || !ahCompactPageV108(model-12,0x6cd)
        || (!ahCompactTableV108(model,"moxel.dll",0x4adbd4,418)
            && !ahCompactTableV108(model,"moxel.dll",0x4d83f0,418)))return false;
    int_ptr modelTable=mem::int_ptr[model];
    array<uint> bodySlots={44,377,417},bodyRvas={0x35fdd0,0x38e300,0xe0120},bodyLengths={16,18,19};
    array<string> bodyHashes={"10e8735d29a908aff8ea85e8527b5b184a86ff1e9a15733098f75f73afbf3367",
        "d33bba7b097a9291416dd3cb44e7bd196fe738a7bd86fb03ad276f7ede869186",
        "7f9ae1847de5deb27fda8be890045caeb98da3a734c58f268cb3eb7957aa7d4e"};
    for(uint slot=0;slot<3;slot++){
        int_ptr entry=mem::int_ptr[modelTable+bodySlots[slot]*4];
        if(!ahCompactAddressV108(entry,"moxel.dll",bodyRvas[slot]) || !ahCompactPageV108(entry,bodyLengths[slot]))return false;
        MemoryBuffer bodyCode(bodyLengths[slot]);mem::memcpy(bodyCode.bytes,entry,bodyLengths[slot]);
        if(ahTemplateRamShaV202(bodyCode,bodyLengths[slot])!=bodyHashes[slot])return false;
    }
    int_ptr gate=mem::int_ptr[table+20*4];
    if(!ahCompactPageV108(gate,63))return false;
    MemoryBuffer gateCode(63);mem::memcpy(gateCode.bytes,gate,63);
    uint uiBase=uint(callback)-0x512e0;
    if(mem::dword[gateCode.bytes+13]!=uiBase+0x15a40)return false;
    mem::dword[gateCode.bytes+13]=0x17435a40;
    if(ahTemplateRamShaV202(gateCode,63)!="a48d4cc5e116e2f350e8942dce32aa1866a87935aa0ef232957beb98913075eb")return false;
    reason="BODY_BRANCH_UNPROVEN";
    if(mem::byte[model+0x2f6]!=0 || mem::byte[receiver+0x20c]!=0
        || (mem::byte[model-4]!=0 && mem::dword[model-8]!=0))return false;
'''

_PREPARED='''
// Own counted view references stay in this one writer callback. No serialized
// descriptor or caller address can recreate this typed preparation object.
class AhSheetNotifyPrepared {
    IDocument@ document;IDocumentView@ view;array<IUnknown@> countedViews;
    uint registrations=0,nativeCalls=0;bool reused=false,ready=false,consumed=false,pendingReferences=false;
    int_ptr viewPointer=0,windowPointer=0,receiverPointer=0;
    string reason="NOT_PREPARED";
}

bool ahSheetNotifyPrepare(IDocument@ document,AhSheetNotifyPrepared@&out prepared) {
    @prepared=AhSheetNotifyPrepared();@prepared.document=document;
    if(document is null){prepared.reason="DOCUMENT";return false;}
    Vector views;document.enumAllViews(views);prepared.pendingReferences=true;
    if(views.start==0 || views.end<=views.start || views.end-views.start>64*4
        || (views.end-views.start)%4!=0 || views.allocated<views.end
        || !ahCompactPageV108(views.start,uint(views.end-views.start))){prepared.reason="VIEWS_UNKNOWN";return false;}
    uint count=uint(views.end-views.start)/4;
    for(uint i=0;i<count;i++){
        int_ptr pointer=mem::int_ptr[views.start+i*4];
        if(pointer==0){prepared.countedViews.insertLast(null);continue;}
        IUnknown@ counted=toIUnknown(pointer);
        if(counted is null){prepared.reason="ADOPTION_UNKNOWN";return false;}
        prepared.countedViews.insertLast(counted);
    }
    prepared.pendingReferences=false;
    if(count!=1 || prepared.countedViews[0] is null){prepared.reason="ONE_VIEW_REQUIRED";return false;}
    @prepared.view=prepared.countedViews[0];
    if(prepared.view is null){prepared.reason="VIEW_TYPE";return false;}
    if(!ahSheetNotifyPhaseFixed(document,prepared.view,true,prepared.nativeCalls,prepared.registrations,prepared.reused,prepared.reason)
        || prepared.nativeCalls!=0)return false;
    prepared.viewPointer=prepared.view.self;
    if(!ahCompactPageV108(prepared.viewPointer-0x20,0x60))return false;
    prepared.windowPointer=mem::int_ptr[prepared.viewPointer-0x20+0x5c];
    prepared.receiverPointer=prepared.windowPointer+0x1a0;
    prepared.ready=true;return true;
}

bool ahSheetNotifyInvokeVerifiedBinding(AhSheetNotifyPrepared@ prepared) {
    if(prepared is null || !prepared.ready || prepared.consumed || prepared.pendingReferences
        || prepared.document is null || prepared.view is null)return false;
    prepared.consumed=true;prepared.reason="PREPARED_BINDING_CHANGED";
    if(prepared.view.self!=prepared.viewPointer || prepared.viewPointer<0x20
        || !ahCompactPageV108(prepared.viewPointer-0x20,0x60)
        || mem::int_ptr[prepared.viewPointer-0x20+0x5c]!=prepared.windowPointer
        || prepared.receiverPointer!=prepared.windowPointer+0x1a0)return false;
    uint registrationAttempt=0;bool reused=false;
    bool success=ahSheetNotifyPhaseFixed(prepared.document,prepared.view,false,
        prepared.nativeCalls,registrationAttempt,reused,prepared.reason);
    // Invoke is forbidden from registering even if the cache unexpectedly vanished.
    if(registrationAttempt!=0 || !reused || prepared.nativeCalls!=1)return false;
    return success;
}
'''


def derive_helper():
    """Return fixed TOOL declarations/helpers; no arbitrary source arguments."""
    fixed('NativeSheetDocumentChange.c',NATIVE_CONTRACT_SHA)
    original=fixed('NativeSheetChangeFixed.as',HELPER_SHA).decode('utf-8-sig').replace('\r\n','\n')
    source=original;journal=[]
    source=edit(source,'bool ahSheetChangeFixed(IDocument@ expectedDocument,IDocumentView@ expectedView,',
        'bool ahSheetNotifyPhaseFixed(IDocument@ expectedDocument,IDocumentView@ expectedView,bool prepareOnly,',journal,'PHASE')
    source=edit(source,'        IDocument@ viewDocument;expectedView.document(viewDocument);',
        '        if(expectedView.self<4 || !ahCompactTableV108(expectedView.self,"moxelui.dll",0x20d778,23)\n'
        '            || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[expectedView.self]+22*4],"moxelui.dll",0x11e200)\n'
        '            || !ahCompactPageV108(expectedView.self-4,4)\n'
        '            || mem::int_ptr[expectedView.self-4]+0xb8!=document.self)return false;\n'
        '        IDocument@ viewDocument;expectedView.document(viewDocument);',journal,'PRIMARY_DOCUMENT_JOIN')
    source=edit(source,'    // Dedicated cache belongs only to this fixed helper.',
        _BODY_GATES+'    // Dedicated cache belongs only to this fixed helper.',journal,'BODY_GATES')
    source=edit(source,'    if(ahSheetChangeNativeFixedCache is null){',
        '    if(ahSheetChangeNativeFixedCache is null){\n        if(!prepareOnly)return false;',journal,'REGISTER_PREPARE_ONLY')
    source=edit(source,'    reason="STOCK_CHANGE_CALL";nativeCalls++;',
        '    if(prepareOnly){reason="BINDING_PREPARED";return true;}\n    reason="STOCK_CHANGE_CALL";nativeCalls++;',journal,'NO_CALL_PREPARE')
    source=edit(source,'    if(!afterDocument.isModified() || !object.isModified() || !parent.isModified()\n'
        '        || !root.isModified() || !ui.isModified())return false;\n'
        '    reason="DIRTY_OBSERVED_RAM";return true;',
        '    // Actual stock notify gives document/UI pending dirty before metadata flush.\n'
        '    // Object/root flags are observations, not prerequisites for that lifecycle.\n'
        '    if(!afterDocument.isModified() || !ui.isModified() || afterDocument.getReadOnly()\n'
        '        || !afterDocument.getConfigMode())return false;\n'
        '    reason="DOCUMENT_UI_PENDING_UNSAVED";return true;',journal,'OBSERVED_EDITOR_PENDING_STATE')
    need(reverse(source,journal)==original,'HELPER_WHOLE_REVERSE')
    raw=(source+_PREPARED).encode()
    need(len(raw)<32768 and raw.count(b'initFuncDefFromAddress(')==1,'HELPER_BOUND')
    return raw


def derive_composite():
    """Return a NEW composite identity in RAM; frozen249 is never changed."""
    parent=load_fixed('runner_composite_v249.py',COMPOSER_SHA)
    original=parent.derive_source();need(sha(original)==COMPOSITE_SHA,'COMPOSITE_PIN')
    text=original.decode();journal=[]
    text=edit(text,'void ahRunnerCompositeV249() {','void ahRunnerCompositeSheetNotify() {\n'
        '    AhSheetNotifyPrepared@ nativeNotify;uint notifyRegistrations=0,notifyCalls=0;\n'
        '    bool notifyPrepared=false,notifyReused=false;',journal,'ENTRY_AND_STATE')
    anchor='            compositeReferenceAttempted=true;compositeRetainedCheckpoint=checkpoint.self;'
    text=edit(text,anchor,'            reason="NOTIFY_PREBIND";\n'
        '            notifyPrepared=ahSheetNotifyPrepare(document,nativeNotify);\n'
        '            if(nativeNotify !is null){notifyRegistrations=nativeNotify.registrations;notifyReused=nativeNotify.reused;}\n'
        '            if(!notifyPrepared){if(nativeNotify !is null)reason+="_"+nativeNotify.reason;break;}\n'+anchor,journal,'PREBIND_BEFORE_WRITES')
    anchor='            reason="NATIVE_DIRTY";'
    text=edit(text,anchor,'            reason="NATIVE_NOTIFY";\n'
        '            bool notifyVerified=ahSheetNotifyInvokeVerifiedBinding(nativeNotify);\n'
        '            if(nativeNotify !is null)notifyCalls=nativeNotify.nativeCalls;\n'
        '            if(!notifyVerified){if(nativeNotify !is null)reason+="_"+nativeNotify.reason;break;}\n'+anchor,journal,'NOTIFY_AFTER_CAS')
    text=edit(text,'            if(!docDirty || !objectDirty || !rootDirty || !uiDirty || document.getReadOnly() || !document.getConfigMode())break;',
        '            if(!notifyVerified || notifyCalls!=1 || !docDirty || !uiDirty || document.getReadOnly() || !document.getConfigMode())break;',
        journal,'TEMPLATE_EDITOR_PENDING_NOT_MD_FLAGS')
    text=edit(text,'                || !compositeSheetDocument.getConfigMode() || !compositeSheetObject.isModified()',
        '                || !compositeSheetDocument.getConfigMode() || !notifyPrepared || notifyCalls!=1',
        journal,'FINAL_TEMPLATE_PENDING_ONLY')
    # Existing final JSON construction has one fixed version249 prefix. Add a
    # truthful new profile and counters; do not pretend this is frozen249 source.
    anchor='string compositeProof="{\\"version\\":249,'
    need(text.count(anchor)==1,'COMPOSITE_PROOF_ANCHOR')
    replacement='string compositeProof="{\\"compositionProfile\\":\\"SHEET_NOTIFY_BOOTSTRAP\\",\\"notifyPrepared\\":"+notifyPrepared' \
        '+",\\"notifyRegistrationCalls\\":"+notifyRegistrations+",\\"notifyReused\\":"+notifyReused' \
        '+",\\"nativeNotifyCalls\\":"+notifyCalls+",\\"version\\":249,'
    text=edit(text,anchor,replacement,journal,'PROFILE_AND_COUNTERS')
    text=edit(text,'    string compositeProof=',
        '    if(nativeNotify !is null){notifyCalls=nativeNotify.nativeCalls;notifyRegistrations=nativeNotify.registrations;notifyReused=nativeNotify.reused;}\n'
        '    string compositeProof=',journal,'LATE_COUNTER_SNAPSHOT')
    need(reverse(text,journal).encode()==original,'COMPOSITE_WHOLE_REVERSE')
    raw=text.encode();need(len(raw)<=65536,'COMPOSITE_BOUND')
    need(text.index('ahSheetNotifyPrepare(')<text.index('writeAttempted=true;compositeSheetAttempted=true;'),'PREBIND_ORDER')
    need(text.index('comparedProperties!=3750')<text.index('ahSheetNotifyInvokeVerifiedBinding(')<text.index('reason="NATIVE_DIRTY";'),'INVOKE_ORDER')
    return raw


def derivation_manifest():
    inputs=source_snapshot()
    helper=derive_helper();composite=derive_composite()
    need(source_snapshot()==inputs,'LATE_SOURCE_CHANGE')
    return dict(version=1,kind='SHEET_NOTIFY_BOOTSTRAP_EXTENSION',baselineUnchanged=True,
        baselineSourceCount=536,baselineControllerSha256=PARENT_SHA,
        extensionInputs={'NativeSheetChangeFixed.as':HELPER_SHA,'NativeSheetDocumentChange.c':NATIVE_CONTRACT_SHA,
                         'runner_composite_v249.py':COMPOSER_SHA},
        extensionSourceSha256=inputs,recipeSha256=inputs['tools/1c/designer-bridge/research/sheet_notify_bootstrap_recipe.py'],helperSha256=sha(helper),helperBytes=len(helper),
        parentCompositeSha256=COMPOSITE_SHA,compositeSha256=sha(composite),compositeBytes=len(composite),
        prepareBeforeFirstSetter=True,invokeAfterFullCas=True,registrationInInvokeAuthorized=False,
        templateEditorPendingSupported=True,templateMetadataDirtyBeforeFlushRequired=False,
        commonModuleMetadataGuardsUnchanged=True,saveProfileStillRequiresSeparateDerivation=True,
        bootstrapDeclarationsRequired=True,baseline211PlanReusable=False,writerAuthorized=False,
        applicationExecutionAuthorized=False,applicationWrites=0,configurationSaves=0,databaseUpdates=0,repositoryMutations=0)


def derive_private(native_plan):
    """Validate a stock211 plan and return a future private profile, no writes.

    This is a review package, NOT a plan accepted by old211.stage_private or262.
    A future root controller must admit the extension manifest separately and
    verify the actual compiled main/private bytes before any writer.
    """
    parent=load_fixed('run_live_mcp_bootstrap_v211.py',PARENT_SHA);module=parent._composed()
    module.valid(native_plan)
    need(native_plan['sourceCount']==536,'BASELINE536')
    files,_=module.render_private(native_plan['basePlan'],native_plan['sourceManifestSha256'])
    need({name:sha(raw) for name,raw in files.items()}==native_plan['privateSha256'],'BASELINE_PRIVATE')
    original=files['NativeCommandSession.as'];helper=derive_helper();prefix=helper+b'\n'
    need(b'ahSheetNotifyPrepare(' not in original and b'AhSheetChangeNativeFixed' not in original,'NAMESPACE_COLLISION')
    derived=prefix+original;need(derived[len(prefix):]==original and derived.count(prefix)==1,'PRIVATE_WHOLE_REVERSE')
    result=dict(files);result['NativeCommandSession.as']=derived
    manifest=derivation_manifest();manifest.update(baselinePlanSha256=sha(canonical(native_plan)),
        baselineSourceManifestSha256=native_plan['sourceManifestSha256'],
        baselinePrivateSha256=dict(native_plan['privateSha256']),
        privateSha256={name:sha(raw) for name,raw in result.items()},
        originalCommandSha256=sha(original),derivedCommandSha256=sha(derived),privatePrefixBytes=len(prefix),
        actualCompiledMainSha256=None,actualMainPublicationRequired=True)
    module.valid(native_plan)
    need(source_snapshot()==manifest['extensionSourceSha256'],'LATE_PRIVATE_SOURCE_CHANGE')
    return result,manifest
