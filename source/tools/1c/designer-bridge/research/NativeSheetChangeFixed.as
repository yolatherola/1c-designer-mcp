// TOOL-ONLY candidate, not wired to a live key or writer. It is never executed
// by cold CHECK. A future root carrier must authorize the exact write and pin
// whole moxelui.dll ff7320903400d8fa7dacb0c1ed2e6fb70fd00e14aabf2a1044bd64603a7d5fe7
// and core_as.dll before using these deliberately new bootstrap declarations.
// No caller-supplied native target, address, body or file path is accepted.
funcdef void AhSheetChangeNativeFixed(int_ptr viewReceiver);
AhSheetChangeNativeFixed@ ahSheetChangeNativeFixedCache;
bool ahSheetChangeNativeFixedInitAttempted=false;
int_ptr ahSheetChangeNativeFixedTarget=0;

// Invokes only the stock exact-template view change handler after repeated
// receiver/document binding. Both typed references must remain owned by the
// calling writer. Side effects: stock document/view notifications and metadata
// dirty tracking in RAM; no Save, DB update, repository operation or raw flags.
// A false return after nativeCalls=1 is UNKNOWN_RETAIN, never permission to retry.
bool ahSheetChangeFixed(IDocument@ expectedDocument,IDocumentView@ expectedView,
    uint &out nativeCalls,uint &out registrations,bool &out reused,string &out reason) {
    nativeCalls=0;registrations=0;reused=false;reason="OWNER";
    if(sizeof_ptr!=4 || expectedDocument is null || expectedView is null
        || ahStatusUi is null || !ahPipeScopeAlive()
        || ahGetCurrentProcessId()!=ahFrameOwnerPidV211
        || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)return false;
    IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();
    reason="ROOT";
    if(!ahCatalogEditableV218(root)
        || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
        || root.isModified() || ui.isModified())return false;
    Guid target("{8daef957-4ae2-48a1-bf6c-b88163a076f5}");
    Guid property("{8eb4fad1-1fa6-403e-970f-2c12dbb43e23}");
    IMDObject@ object=root.objById(target);reason="TARGET";
    if(object is null || object.id!=target || object.isModified() || object.mdClass is null
        || object.mdClass.id!=Guid("{3daea016-69b7-4ed4-9453-127911372fe6}")
        || object.mdParentLink is null)return false;
    IMDObject@ parent=object.mdParentLink.getMDObject();
    if(parent is null || parent.id!=Guid("{686a3dbe-be94-45e7-9e8b-dd93f0cd579c}")
        || parent.isModified() || !ahCatalogLinkV218(object,parent,root))return false;
    IMDEditService@ service=getMDEditService();IMDEditHelper@ helper;reason="HELPER";
    if(service is null)return false;service.getEditHelper(helper,object);
    if(helper is null || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
        || !ahCompactTableV108(helper.self,"frntend.dll",12897096,37)
        || helper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))return false;
    int_ptr receiver=0,table=0,callback=0,internalView=0,nativeWindow=0;
    for(uint pass=0;pass<2;pass++){
        IUnknown@ body;helper.extProp(body,property,false);IDocument@ document=body;
        reason="DOCUMENT";
        if(document is null || !ahCatalogSameV218(document.unk,expectedDocument.unk)
            || !ahCompactTableV108(document.self,"moxelui.dll",2155168,23)
            || document.isModified() || document.getReadOnly() || !document.getConfigMode())return false;
        IDocument@ viewDocument;expectedView.document(viewDocument);
        if(viewDocument is null || !ahCatalogSameV218(viewDocument.unk,document.unk))return false;
        reason="VIEW_LAYOUT";int_ptr returnedView=expectedView.self;
        if(returnedView<0x20)return false;
        int_ptr currentInternal=returnedView-0x20;
        if(!ahCompactPageV108(currentInternal,0x60))return false;
        int_ptr currentWindow=mem::int_ptr[currentInternal+0x5c];
        if(currentWindow==0 || currentWindow>int_ptr(0x7fffffff)-0xc00
            || !ahCompactPageV108(currentWindow,0xc00))return false;
        int_ptr currentReceiver=currentWindow+0x1a0;reason="RECEIVER_TABLE";
        if(!ahCompactTableV108(currentReceiver,"moxelui.dll",2167336,90)
            && !ahCompactTableV108(currentReceiver,"moxelui.dll",2174000,90))return false;
        int_ptr currentTable=mem::int_ptr[currentReceiver];
        if(mem::int_ptr[currentReceiver+0x784]!=currentInternal)return false;
        int_ptr currentCallback=mem::int_ptr[currentTable+89*4];reason="CALLBACK_ABI";
        if(!ahCompactAddressV108(currentCallback,"moxelui.dll",332512)
            || !ahCompactAddressV108(mem::int_ptr[currentTable+10*4],"moxelui.dll",88640)
            || !ahCompactPageV108(currentCallback,579))return false;
        MemoryBuffer code(579);mem::memcpy(code.bytes,currentCallback,579);
        array<uint> offsets={6,24,49,80,377};
        array<uint> targets={0x1f7188,0x24e008,0x15a40,0x15a40,0x20e37c};
        uint moduleBase=uint(currentCallback)-332512;
        for(uint i=0;i<5;i++){
            if(mem::dword[code.bytes+offsets[i]]!=moduleBase+targets[i])return false;
            mem::dword[code.bytes+offsets[i]]=0x17420000+targets[i];
        }
        if(ahTemplateRamShaV202(code,579)!="e748d3fc4f6818aea0ceb1615c2361d6f5bcf65d6c9ad01a965a28a1b25afa42")return false;
        if(pass==0){receiver=currentReceiver;table=currentTable;callback=currentCallback;
            internalView=currentInternal;nativeWindow=currentWindow;}
        else if(receiver!=currentReceiver || table!=currentTable || callback!=currentCallback
            || internalView!=currentInternal || nativeWindow!=currentWindow)return false;
        reason="STATE_CHANGED";IMDContainer@ freshRoot=ui.getMDCont();
        if(freshRoot is null || !ahCatalogSameV218(freshRoot.unk,root.unk)
            || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
            || object.isModified() || parent.isModified() || root.isModified() || ui.isModified())return false;
    }
    // Dedicated cache belongs only to this fixed helper. An attempted failed
    // registration is not retried, even if its handle stayed null. Never erase
    // or overwrite a nonnull handle whose native descriptor does not match.
    reason="CACHE_STATE";reused=ahSheetChangeNativeFixedCache !is null;
    if(ahSheetChangeNativeFixedCache is null){
        if(ahSheetChangeNativeFixedInitAttempted || ahSheetChangeNativeFixedTarget!=0)return false;
        ahSheetChangeNativeFixedInitAttempted=true;registrations++;
        initFuncDefFromAddress(callback,@ahSheetChangeNativeFixedCache,asCALL_STDCALL);
        if(ahSheetChangeNativeFixedCache is null)return false;
        ahSheetChangeNativeFixedTarget=callback;
    }
    if(!ahSheetChangeNativeFixedInitAttempted || ahSheetChangeNativeFixedTarget!=callback)return false;
    int_ptr address=mem::addressOf(@ahSheetChangeNativeFixedCache);reason="CACHED_TARGET";
    if(!ahCompactPageV108(address,4))return false;
    int_ptr function=mem::int_ptr[address];
    if(!ahCompactTableV108(function,"core_as.dll",0x28f45c,40)
        || !ahCompactPageV108(function,0xd4))return false;
    int_ptr nativeInterface=mem::int_ptr[function+0xd0];
    if(!ahCompactPageV108(nativeInterface,0x54)
        || mem::int_ptr[nativeInterface]!=callback || mem::dword[nativeInterface+8]!=4)return false;
    reason="PRECALL_CHANGED";
    if(mem::int_ptr[receiver]!=table || mem::int_ptr[table+89*4]!=callback
        || mem::int_ptr[receiver+0x784]!=internalView
        || mem::int_ptr[internalView+0x5c]!=nativeWindow)return false;
    // Future authorized writer dispatches exactly once here, after its model
    // CAS/recipe has succeeded. This source is presently cold-compile only.
    reason="STOCK_CHANGE_CALL";nativeCalls++;
    ahSheetChangeNativeFixedCache(receiver);
    reason="POSTCALL_CHANGED";
    if(mem::int_ptr[address]!=function || mem::int_ptr[function+0xd0]!=nativeInterface
        || mem::int_ptr[nativeInterface]!=callback || mem::dword[nativeInterface+8]!=4
        || ahSheetChangeNativeFixedTarget!=callback || !ahSheetChangeNativeFixedInitAttempted
        || mem::int_ptr[receiver]!=table || mem::int_ptr[table+89*4]!=callback
        || mem::int_ptr[receiver+0x784]!=internalView)return false;
    IUnknown@ afterBody;helper.extProp(afterBody,property,false);IDocument@ afterDocument=afterBody;
    IMDContainer@ afterRoot=ui.getMDCont();IDocument@ afterViewDocument;expectedView.document(afterViewDocument);
    if(afterDocument is null || afterViewDocument is null || afterRoot is null
        || !ahCatalogSameV218(afterDocument.unk,expectedDocument.unk)
        || !ahCatalogSameV218(afterViewDocument.unk,expectedDocument.unk)
        || !ahCatalogSameV218(afterRoot.unk,root.unk)
        || !ahCatalogSameV218(helper.getMDObj().unk,object.unk))return false;
    reason="NATIVE_DIRTY_UNPROVEN";
    if(!afterDocument.isModified() || !object.isModified() || !parent.isModified()
        || !root.isModified() || !ui.isModified())return false;
    reason="DIRTY_OBSERVED_RAM";return true;
}
