// Two direct reads of the exact live module stay in RAM. The proof contains
// counts and state only; opening its editor may change UI/cache. No source writes.
void ahLiveModuleReadOnly() {
    bool admitted=__LIVE_READONLY_SCOPE_ADMITTED__;
    if(!admitted)return;
    string operation="__OPERATION_ID__",scope="__SCOPE_SHA256__",nonce="__LIVE_READONLY_NONCE__",reason="SCOPE";
    bool intent=false,opened=false,openReturned=false,readVerified=false,statesEqual=false,refsCleared=false,exception=false;
    bool firstReturned=false,secondReturned=false,independentOutputs=false,warmupDocumentModified=false;
    uint opens=0,saves=0,bridgeCalls=0,chars=0,compared=0,firstAddress=0,secondAddress=0,warmupReads=0;
    uint uiAddress=0,rootAddress=0,objectAddress=0,helperAddress=0,textAddress=0,editorAddress=0,documentAddress=0,tmAddress=0;
    uint openCode=0,openFlags=0x10101,caretCodeBefore=0,caretCodeAfter=0;
    array<uint> before,after;
    IConfigMngrUI@ ui;IMDContainer@ root;IMDObject@ object;IMDEditService@ service;
    IMDEditHelper@ helper;IMDEditModuleHelper@ module;
    IMDContainer@ freshRoot;IMDObject@ freshObject,boundObject;
    ITextManager@ text,linked;ITextEditor@ editor;IDocument@ document;
    AhRepositoryStatusRead@ stateBridge;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(operation.length!=32 || scope.length!=64 || nonce.length!=32
                || sizeof_ptr!=4 || !ahPipeScopeAlive() || ahStatusUi is null
                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            bool hexKnown=true;
            for(uint n=0;n<64;n++){
                uint a=scope[n];
                if(!((a>=48 && a<=57)||(a>=97 && a<=102)))hexKnown=false;
                if(n<32){uint c=operation[n],d=nonce[n];
                    if(!((c>=48 && c<=57)||(c>=97 && c<=102)) || !((d>=48 && d<=57)||(d>=97 && d<=102)))hexKnown=false;}
            }
            if(!hexKnown)break;
            @ui=ahStatusUi;@root=ui.getMDCont();reason="ROOT";
            if(root is null || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}") || !ahCatalogEditableV218(root))break;
            Guid target("{176e2552-fd8b-4823-afc0-d17431f2fb7b}"),property("{d5963243-262e-4398-b4d7-fb16d06484f6}");
            @object=root.objById(target);reason="EXACT_COMMON_MODULE";
            if(object is null || object.id!=target || object.mdClass is null
                || object.mdClass.id!=Guid("{0fe48980-252d-11d6-a3c7-0050bae0a776}") || object.mdParentLink is null
                || !ahCatalogSameV218(object.mdParentLink.getMDObject().unk,root.unk))break;
            string propertyName;reason="COMMON_MODULE_PROPERTY";
            if(!ahModulePropertyV225(object,property,propertyName) || propertyName!="Module")break;
            reason="HELPERSERVICE";@service=getMDEditService();if(service is null)break;
            reason="HELPER_NULL";service.getEditHelper(helper,object);if(helper is null)break;
            reason="HELPER_TABLE";
            if(!ahCompactTableV108(helper.self,"frntend.dll",0xc4046c,24)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[helper.self]+23*4],"frntend.dll",0x296460))break;
            reason="MODULE_QI";@module=helper.unk;if(module is null)break;
            reason="MODULE_TABLE";
            if(!ahCompactTableV108(module.self,"frntend.dll",0xc4042c,12)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[module.self]+11*4],"frntend.dll",0x2da340))break;
            reason="BOUND_OBJECT";@boundObject=helper.getMDObj();
            if(boundObject is null || !ahCatalogSameV218(boundObject.unk,object.unk))break;
            reason="OWN_BRIDGE";int_ptr ownDll=GetModuleHandle("__OWN_DLL_PATH__".cstr);
            if(ownDll==0)break;int_ptr bridgeAddress=GetProcAddress(ownDll,"AhReadOwnedTextManagerStateV1".toUtf8().ptr);
            if(bridgeAddress==0)break;initFuncDefFromAddress(bridgeAddress,@stateBridge,asCALL_CDECL);
            if(stateBridge is null)break;
            intent=ahWriteSample("__LIVE_READONLY_INTENT_PATH__","{\"kind\":\"LIVE_MODULE_READONLY_INTENT\",\"operationId\":\""+operation
                +"\",\"scopeSha256\":\""+scope+"\",\"nonce\":\""+nonce
                +"\",\"maximumOpenCalls\":1,\"maximumDirectSaveCalls\":2,\"maximumStateBridgeCalls\":2,\"maximumSourceUtf16Units\":131072,\"maximumWarmupGetterReads\":1,\"stateInitializationAllowed\":true,\"runtimeCachePossible\":true,\"configurationSourceWrites\":0,\"sourceBodyIncluded\":false,\"sourceFrameIncluded\":false}");
            if(!intent)break;
            reason="OPEN_EXACT_MODULE";opens++;
            openCode=module.openModule(text,property,openFlags,editor);openReturned=true;opened=text !is null && editor !is null;
            if(!opened || !ahCompactTableV108(text.self,"txtedt.dll",0x46dc4,11)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[text.self]+10*4],"txtedt.dll",0x2dcf0)
                || !ahCompactTableV108(editor.self,"txtedui.dll",0x10db3c,18)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[editor.self]],"txtedui.dll",0xe4680)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[editor.self]+3*4],"txtedui.dll",0xa2020))break;
            editor.getITextManager(linked);@document=text.unk;reason="COUNTED_BINDINGS";
            if(linked is null || linked.self!=text.self || document is null
                || !ahCompactTableV108(document.self,"txtedui.dll",0x109978,23)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[document.self]+8*4],"txtedui.dll",0x74450)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[document.self]+22*4],"txtedui.dll",0x7d7d0)
                || mem::addressOf(linked.getTextManager())!=mem::addressOf(text.getTextManager()))break;
            // The published getter may create the internal dirty-state cache.
            // Preservation below starts after this explicit, permitted warmup.
            reason="STATE_CACHE_WARMUP";warmupDocumentModified=document.isModified();warmupReads++;
            uiAddress=uint(ui.self);rootAddress=uint(root.self);objectAddress=uint(object.self);helperAddress=uint(helper.self);
            textAddress=uint(text.self);editorAddress=uint(editor.self);documentAddress=uint(document.self);
            tmAddress=uint(mem::addressOf(text.getTextManager()));
            // The second snapshot follows both output destructors. State values
            // are observations; dirty/read-only/no-Undo editors remain eligible.
            for(uint pass=0;pass<2;pass++){
                reason="FRESH_BINDINGS";
                if(!ahPipeScopeAlive() || ahStatusUi !is ui)break;
                @freshRoot=ui.getMDCont();@freshObject=root.objById(target);@boundObject=null;@boundObject=helper.getMDObj();
                if(freshRoot is null || freshObject is null || boundObject is null)break;
                if(!ahPipeScopeAlive() || ahStatusUi !is ui || uint(ui.self)!=uiAddress || uint(root.self)!=rootAddress
                    || !ahCatalogSameV218(freshRoot.unk,root.unk)
                    || !ahCatalogSameV218(freshObject.unk,object.unk)
                    || !ahCatalogSameV218(boundObject.unk,object.unk)
                    || uint(object.self)!=objectAddress || uint(helper.self)!=helperAddress
                    || uint(text.self)!=textAddress || uint(editor.self)!=editorAddress || uint(document.self)!=documentAddress
                    || uint(mem::addressOf(text.getTextManager()))!=tmAddress)break;
                @linked=null;editor.getITextManager(linked);
                if(linked is null || linked.self!=text.self || uint(mem::addressOf(linked.getTextManager()))!=tmAddress)break;
                TextPosition caret,selectionStart,selectionStop;
                uint caretCode=editor.getCaretPosition(caret,false);editor.getSelection(selectionStart,selectionStop,false);
                if(pass==0)caretCodeBefore=caretCode;else caretCodeAfter=caretCode;
                MemoryBuffer packet(96);if(packet.bytes==0)break;
                for(uint n=0;n<24;n++)mem::dword[packet.bytes+n*4]=0;
                mem::dword[packet.bytes]=0x31534d54;mem::dword[packet.bytes+4]=1;mem::dword[packet.bytes+8]=96;
                for(uint n=0;n<32;n++)mem::byte[packet.bytes+64+n]=uint8(operation[n]);
                mem::dword[packet.bytes+60]=0xa17e5afe;reason="READONLY_TM_STATE";bridgeCalls++;
                uint bridgeStatus=stateBridge(tmAddress,packet.bytes);
                bool operationSame=true;for(uint n=0;n<32;n++)if(mem::byte[packet.bytes+64+n]!=uint8(operation[n]))operationSame=false;
                if(!operationSame || bridgeStatus!=1 || bridgeStatus!=mem::dword[packet.bytes+12]
                    || mem::dword[packet.bytes]!=0x31534d54 || mem::dword[packet.bytes+4]!=1 || mem::dword[packet.bytes+8]!=96
                    || mem::dword[packet.bytes+12]!=1 || mem::dword[packet.bytes+16]!=0
                    || mem::dword[packet.bytes+20]>1 || mem::dword[packet.bytes+24]>1
                    || (mem::dword[packet.bytes+24]==0 && mem::dword[packet.bytes+28]!=0xffffffff)
                    || mem::dword[packet.bytes+32]!=1 || mem::dword[packet.bytes+36]!=1
                    || mem::dword[packet.bytes+40]!=1 || mem::dword[packet.bytes+44]!=1
                    || mem::dword[packet.bytes+48]!=2 || mem::dword[packet.bytes+52]!=8292
                    || mem::dword[packet.bytes+56]!=0x31534d54 || mem::dword[packet.bytes+60]!=0xa17e5afe)break;
                array<uint> state={uiAddress,rootAddress,objectAddress,helperAddress,textAddress,editorAddress,documentAddress,tmAddress,
                    root.isModified()?1:0,ui.isModified()?1:0,object.isModified()?1:0,document.isModified()?1:0,document.getReadOnly()?1:0,
                    caret.line,caret.col,selectionStart.line,selectionStart.col,selectionStop.line,selectionStop.col,
                    mem::dword[packet.bytes+20],mem::dword[packet.bytes+24],mem::dword[packet.bytes+28]};
                if(pass==0){
                    before=state;reason="TWO_FRESH_DIRECT_SAVES";
                    {v8string first;v8string second;
                        firstAddress=uint(first.self);secondAddress=uint(second.self);
                        if(firstAddress==secondAddress || first.length!=0 || second.length!=0)break;
                        saves++;bool firstOk=text.getTextManager().save(first);firstReturned=true;if(!firstOk)break;
                        if(first.length>131072)break;
                        saves++;bool secondOk=text.getTextManager().save(second);secondReturned=true;if(!secondOk)break;
                        if(second.length!=first.length || second.length>131072)break;
                        chars=first.length;
                        independentOutputs=firstAddress!=0 && secondAddress!=0 && firstAddress!=secondAddress
                            && (chars==0 || (first.cstr!=0 && second.cstr!=0 && first.cstr!=second.cstr));
                        if(!independentOutputs)break;
                        bool textEqual=true;
                        for(uint n=0;n<chars;n++){
                            if(mem::word[first.cstr+n*2]!=mem::word[second.cstr+n*2])textEqual=false;
                            compared++;
                        }
                        readVerified=textEqual && compared==chars;
                    }
                    // first/second have left scope here, including matched SDK
                    // v8string destructors; next pass observes their effects too.
                }else after=state;
            }
            reason="READ_STATE_COMPARISON";
            statesEqual=readVerified && before.length==22 && after.length==22;
            if(statesEqual)for(uint n=0;n<22;n++)if(before[n]!=after[n])statesEqual=false;
            if(!statesEqual || saves!=2 || bridgeCalls!=2)break;
            reason="NONE";
        }while(false);
        exception=catcher.hasException;
        @stateBridge=null;@document=null;@linked=null;@editor=null;@text=null;
        @boundObject=null;@freshObject=null;@freshRoot=null;@module=null;@helper=null;@service=null;@object=null;@root=null;@ui=null;
    }
    refsCleared=stateBridge is null && document is null && linked is null && editor is null && text is null
        && module is null && helper is null && service is null && boundObject is null && freshObject is null && freshRoot is null
        && object is null && root is null && ui is null;
    bool verified=admitted && intent && openReturned && readVerified && statesEqual && !exception && refsCleared
        && opens==1 && saves==2 && bridgeCalls==2 && warmupReads==1 && firstReturned && secondReturned && independentOutputs;
    string beforeJson="[",afterJson="[";
    for(uint n=0;n<before.length;n++)beforeJson+=(n==0?"":",")+before[n];beforeJson+="]";
    for(uint n=0;n<after.length;n++)afterJson+=(n==0?"":",")+after[n];afterJson+="]";
    ahWriteSample("__LIVE_READONLY_PROOF_PATH__","{\"kind\":\"LIVE_MODULE_READONLY_NATIVE\",\"operationId\":\""+operation
        +"\",\"scopeSha256\":\""+scope+"\",\"nonce\":\""+nonce+"\",\"verified\":"+verified+",\"reason\":\""+reason
        +"\",\"objectId\":\"176e2552-fd8b-4823-afc0-d17431f2fb7b\",\"modulePropertyId\":\"d5963243-262e-4398-b4d7-fb16d06484f6\""
        +",\"sourceDomain\":\"editor_live\",\"readEqualityVerified\":"+readVerified+",\"stateEqualityVerified\":"+statesEqual
        +",\"openCalls\":"+opens+",\"openReturned\":"+openReturned+",\"openReturnCode\":"+openCode+",\"openFlagsAfter\":"+openFlags
        +",\"directSaveCalls\":"+saves+",\"stateBridgeCalls\":"+bridgeCalls+",\"firstSaveReturned\":"+firstReturned+",\"secondSaveReturned\":"+secondReturned
        +",\"sourceUtf16Units\":"+chars+",\"comparedUtf16Units\":"+compared+",\"firstOutputAddress\":"+firstAddress+",\"secondOutputAddress\":"+secondAddress
        +",\"independentOutputsVerified\":"+independentOutputs+",\"caretReturnCodes\":["+caretCodeBefore+","+caretCodeAfter+"],\"beforeState\":"+beforeJson+",\"afterState\":"+afterJson
        +",\"warmupReads\":"+warmupReads+",\"warmupDocumentModifiedObserved\":"+(warmupReads==1)
        +",\"warmupDocumentModified\":"+(warmupReads==1?(warmupDocumentModified?"true":"false"):"null")
        +",\"stateInitializationAllowed\":true,\"runtimeCachePossible\":true,\"baselineAfterWarmup\":"+(warmupReads==1)
        +",\"nativeException\":"+exception+",\"ownedTypedHandlesCleared\":"+refsCleared+",\"sourceBodyIncluded\":false,\"sourceFrameIncluded\":false,\"helperTextReads\":0"
        +",\"repositoryOwnerVerified\":false,\"fullUndoHistoryVerified\":false,\"configurationSourceWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"businessCalls\":0,\"dirtyFlagWrites\":0}");
}
