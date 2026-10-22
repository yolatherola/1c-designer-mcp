// Owned fixture only. Source remains RAM; metadata-only proof is not an MCP
// editor_live binding. Existing V63 scratch methods must be pinned by Root.
void ahOwnedLiveModuleRead() {
    bool admitted=__OWNED_LIVE_SCOPE_ADMITTED__,fixtureAuthorized=__OWNED_LIVE_FIXTURE_MUTATION_AUTHORIZED__;
    string operation="__OPERATION_ID__",scope="__SCOPE_SHA256__",nonce="__LIVE_NONCE__";
    string expectedSha="__LIVE_EXPECTED_SHA256__",reason="SCOPE";
    bool intent=false,opened=false,baseline=false,began=false,inserted=false,closed=false;
    bool readVerified=false,statesEqual=false,undone=false,restored=false,refsCleared=false,exception=false,proofWritten=false;
    uint opens=0,begins=0,inserts=0,closes=0,saves=0,bridgeCalls=0,undos=0;
    uint chars=0,utf8Bytes=0,firstAddress=0,secondAddress=0;
    uint uiAddress=0,rootAddress=0,objectAddress=0,helperAddress=0,textAddress=0,editorAddress=0,documentAddress=0,tmAddress=0;
    uint openCode=0,openFlags=0x10101,caretCodeBefore=0,caretCodeAfter=0;
    bool rootBaseline=false,uiBaseline=false,objectBaseline=false;
    bool baselineDocumentModified=false,baselineDocumentReadOnly=false,baselineManagerEmpty=false;
    uint baselineDocumentModifiedReads=0,baselineDocumentReadOnlyReads=0,baselineManagerEmptyReads=0;
    array<uint> before,after;
    IConfigMngrUI@ ui;IMDContainer@ root;IMDObject@ object;IMDEditService@ service;
    IMDEditHelper@ helper;IMDEditModuleHelper@ module;
    ITextManager@ text,linked;ITextEditor@ editor;IDocument@ document;
    IUnknown@ noExternal,external;
    AhRepositoryStatusRead@ stateBridge;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(!admitted || !fixtureAuthorized || operation.length!=32 || scope.length!=64 || nonce.length!=32 || expectedSha.length!=64
                || sizeof_ptr!=4 || !ahPipeScopeAlive() || ahStatusUi is null
                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            bool hexKnown=true;
            for(uint n=0;n<64;n++){
                uint a=scope[n],b=expectedSha[n];
                if(!((a>=48 && a<=57)||(a>=97 && a<=102)) || !((b>=48 && b<=57)||(b>=97 && b<=102)))hexKnown=false;
                if(n<32){uint c=operation[n],d=nonce[n];
                    if(!((c>=48 && c<=57)||(c>=97 && c<=102)) || !((d>=48 && d<=57)||(d>=97 && d<=102)))hexKnown=false;}
            }
            if(!hexKnown)break;
            @ui=ahStatusUi;@root=ui.getMDCont();reason="ROOT";
            if(root is null || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}") || !ahCatalogEditableV218(root))break;
            Guid target("{d593e80d-b70c-400b-9955-d02f7a4c89e9}"),property("{a637f77f-3840-441d-a1c3-699c8c5cb7e0}");
            @object=root.objById(target);reason="EXACT_OWNED_PROCESSING";
            if(object is null || object.id!=target || object.mdClass is null
                || object.mdClass.id!=Guid("{bf845118-327b-4682-b5c6-285d2a0eb296}") || object.mdParentLink is null
                || !ahCatalogSameV218(object.mdParentLink.getMDObject().unk,root.unk))break;
            string propertyName;reason="OBJECT_MODULE_PROPERTY";
            if(!ahModulePropertyV225(object,property,propertyName) || propertyName!="ObjectModule")break;
            rootBaseline=root.isModified();uiBaseline=ui.isModified();objectBaseline=object.isModified();
            if(rootBaseline || uiBaseline || objectBaseline)break;
            @service=getMDEditService();reason="HELPER";if(service is null)break;
            service.getEditHelper(helper,object);if(helper is null)break;@module=helper.unk;
            if(module is null || !ahCompactTableV108(helper.self,"basicui.dll",0x60ae54,24)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[helper.self]+23*4],"basicui.dll",0xf3b70)
                || !ahCompactTableV108(module.self,"basicui.dll",0x60ad5c,12)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[module.self]+5*4],"basicui.dll",0x35c470)
                || !ahCatalogSameV218(helper.getMDObj().unk,object.unk))break;
            reason="OWN_BRIDGE";int_ptr ownDll=GetModuleHandle("__OWN_DLL_PATH__".cstr);
            if(ownDll==0)break;int_ptr bridgeAddress=GetProcAddress(ownDll,"AhReadOwnedTextManagerStateV1".toUtf8().ptr);
            if(bridgeAddress==0)break;initFuncDefFromAddress(bridgeAddress,@stateBridge,asCALL_CDECL);
            if(stateBridge is null)break;
            intent=ahWriteSample("__LIVE_INTENT_PATH__","{\"kind\":\"OWNED_LIVE_MODULE_READ_INTENT\",\"operationId\":\""+operation
                +"\",\"scopeSha256\":\""+scope+"\",\"nonce\":\""+nonce
                +"\",\"maximumOpenCalls\":1,\"maximumInsertions\":1,\"maximumUndoCalls\":1,\"maximumDirectSaveCalls\":2,\"sourceBodyIncluded\":false}");
            if(!intent)break;
            reason="OPEN_EXACT_OWNED_MODULE";opens++;
            openCode=module.openModule(text,property,openFlags,editor);opened=text !is null && editor !is null;
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
            reason="CLEAN_EMPTY_WRITABLE_BASELINE";
            // Observe each independent gate once: short-circuiting the combined
            // condition hid whether the old refusal meant dirty, locked or full.
            // A counter advances only after the getter returns, so unobserved
            // defaults are never reported as known clean/writable/empty values.
            baselineDocumentModified=document.isModified();baselineDocumentModifiedReads++;
            baselineDocumentReadOnly=document.getReadOnly();baselineDocumentReadOnlyReads++;
            baselineManagerEmpty=text.getTextManager().empty();baselineManagerEmptyReads++;
            if(baselineDocumentModifiedReads!=1 || baselineDocumentReadOnlyReads!=1 || baselineManagerEmptyReads!=1
                || baselineDocumentModified || baselineDocumentReadOnly || !baselineManagerEmpty)break;
            baseline=true;
            uiAddress=uint(ui.self);rootAddress=uint(root.self);objectAddress=uint(object.self);helperAddress=uint(helper.self);
            textAddress=uint(text.self);editorAddress=uint(editor.self);documentAddress=uint(document.self);
            tmAddress=uint(mem::addressOf(text.getTextManager()));
            TextPosition originalCaret,originalStart,originalStop;
            editor.getCaretPosition(originalCaret,false);editor.getSelection(originalStart,originalStop,false);
            string expected="// AH1C_OWNED_LIVE:"+nonce+"\r\n// ";
            for(uint n=0;n<2300;n++)expected+="X";expected+=":END\r\n";
            TextPosition start(1,1),end(3,1),undoStart,undoStop;
            reason="OWN_ACTION_BEGIN";text.getTextManager().setSelectRange(start,start);begins++;
            began=text.getTextManager().ahOwnedActionBeginV63(0,start,start,noExternal);if(!began)break;
            {v8string seed=expected;reason="OWN_INSERTION";inserts++;
                text.getTextManager().setSelectText(seed.cstr,true);inserted=true;}
            text.getTextManager().setSelectRange(end,end);closes++;
            text.getTextManager().ahOwnedActionCloseV63(end,end);closed=true;
            // These snapshots precede and follow both output destructors. Never
            // repair dirty/caret/selection before their equality is evaluated.
            for(uint pass=0;pass<2;pass++){
                reason="FRESH_BINDINGS";
                if(!ahPipeScopeAlive() || ahStatusUi !is ui || uint(ui.self)!=uiAddress || uint(root.self)!=rootAddress
                    || !ahCatalogSameV218(ui.getMDCont().unk,root.unk)
                    || !ahCatalogSameV218(root.objById(target).unk,object.unk)
                    || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
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
                    || mem::dword[packet.bytes+20]!=1 || mem::dword[packet.bytes+24]!=1
                    || mem::dword[packet.bytes+32]!=1 || mem::dword[packet.bytes+36]!=1
                    || mem::dword[packet.bytes+40]!=1 || mem::dword[packet.bytes+44]!=1
                    || mem::dword[packet.bytes+48]!=2 || mem::dword[packet.bytes+52]!=8292
                    || mem::dword[packet.bytes+56]!=0x31534d54 || mem::dword[packet.bytes+60]!=0xa17e5afe)break;
                array<uint> state={uiAddress,rootAddress,objectAddress,helperAddress,textAddress,editorAddress,documentAddress,tmAddress,
                    root.isModified()?1:0,ui.isModified()?1:0,object.isModified()?1:0,document.isModified()?1:0,document.getReadOnly()?1:0,
                    caret.line,caret.col,selectionStart.line,selectionStart.col,selectionStop.line,selectionStop.col,
                    mem::dword[packet.bytes+20],mem::dword[packet.bytes+24],mem::dword[packet.bytes+28]};
                if(state[11]!=1 || state[12]!=0)break;
                if(pass==0){
                    before=state;reason="TWO_FRESH_DIRECT_SAVES";
                    {v8string first;v8string second;
                        firstAddress=uint(first.self);secondAddress=uint(second.self);
                        if(firstAddress==secondAddress || first.length!=0 || second.length!=0)break;
                        saves++;bool firstOk=text.getTextManager().save(first);if(!firstOk)break;
                        if(first.length>8192 || first.length<2300)break;
                        saves++;bool secondOk=text.getTextManager().save(second);if(!secondOk)break;
                        if(second.length!=first.length || first.cstr==second.cstr || first.str!=expected || second.str!=expected)break;
                        chars=first.length;utf8Bytes=first.str.length;readVerified=true;
                    }
                    // first/second have left scope here, including matched SDK
                    // v8string destructors; next pass observes their effects too.
                }else after=state;
            }
            reason="READ_STATE_COMPARISON";
            statesEqual=readVerified && before.length==22 && after.length==22;
            if(statesEqual)for(uint n=0;n<22;n++)if(before[n]!=after[n])statesEqual=false;
            if(!statesEqual || saves!=2 || bridgeCalls!=2)break;
            // One owned action only. This establishes a single Undo witness;
            // it does not prove arbitrary earlier Undo/Redo history equivalence.
            reason="ONE_OWN_UNDO";undos++;
            undone=text.getTextManager().ahOwnedActionUndoV63(undoStart,undoStop,external,0);
            if(!undone || external !is null || !ahPipeScopeAlive() || ahStatusUi !is ui
                || !ahCatalogSameV218(root.objById(target).unk,object.unk)
                || uint(mem::addressOf(text.getTextManager()))!=tmAddress)break;
            restored=text.getTextManager().empty() && !document.isModified() && !document.getReadOnly()
                && root.isModified()==rootBaseline && ui.isModified()==uiBaseline && object.isModified()==objectBaseline;
            if(!restored)break;
            // Fixture cleanup follows the completed read comparison and Undo.
            editor.setSelection(originalStart,originalStop,false,false);editor.setCaretPosition(originalCaret,false);
            TextPosition finalCaret,finalStart,finalStop;
            editor.getCaretPosition(finalCaret,false);editor.getSelection(finalStart,finalStop,false);
            restored=finalCaret==originalCaret && finalStart==originalStart && finalStop==originalStop
                && text.getTextManager().empty() && !document.isModified() && !document.getReadOnly()
                && root.isModified()==rootBaseline && ui.isModified()==uiBaseline && object.isModified()==objectBaseline
                && ahPipeScopeAlive() && ahStatusUi is ui && ahCatalogSameV218(ui.getMDCont().unk,root.unk)
                && ahCatalogSameV218(root.objById(target).unk,object.unk)
                && uint(mem::addressOf(text.getTextManager()))==tmAddress;
            expected="";reason=restored?"NONE":"FIXTURE_UI_RESTORE";
        }while(false);
        exception=catcher.hasException;
        @external=null;@stateBridge=null;@document=null;@linked=null;@editor=null;@text=null;
        @module=null;@helper=null;@service=null;@object=null;@root=null;@ui=null;
    }
    refsCleared=stateBridge is null && document is null && linked is null && editor is null && text is null
        && module is null && helper is null && service is null && object is null && root is null && ui is null;
    bool verified=admitted && fixtureAuthorized && intent && baseline && began && inserted && closed && readVerified
        && statesEqual && undone && restored && !exception && refsCleared && opens==1 && begins==1 && inserts==1 && closes==1 && saves==2 && undos==1;
    string beforeJson="[",afterJson="[";
    for(uint n=0;n<before.length;n++)beforeJson+=(n==0?"":",")+before[n];beforeJson+="]";
    for(uint n=0;n<after.length;n++)afterJson+=(n==0?"":",")+after[n];afterJson+="]";
    proofWritten=ahWriteSample("__LIVE_PROOF_PATH__","{\"kind\":\"OWNED_LIVE_MODULE_READ_NATIVE\",\"operationId\":\""+operation
        +"\",\"scopeSha256\":\""+scope+"\",\"nonce\":\""+nonce+"\",\"verified\":"+verified+",\"reason\":\""+reason
        +"\",\"sourceDomain\":\"editor_live\",\"expectedSourceSha256\":\""+expectedSha+"\",\"expectedSeedMatched\":"+readVerified
        +",\"openCalls\":"+opens+",\"openReturnCode\":"+openCode+",\"openFlagsAfter\":"+openFlags+",\"actionBeginCalls\":"+begins
        +",\"insertionCalls\":"+inserts+",\"actionCloseCalls\":"+closes+",\"directSaveCalls\":"+saves+",\"stateBridgeCalls\":"+bridgeCalls
        +",\"undoCalls\":"+undos+",\"singleOwnUndoVerified\":"+(undone && restored)+",\"fullUndoHistoryVerified\":false,\"stateEqualityVerified\":"+statesEqual
        +",\"sourceUtf16Units\":"+chars+",\"sourceUtf8Bytes\":"+utf8Bytes+",\"firstOutputAddress\":"+firstAddress+",\"secondOutputAddress\":"+secondAddress
        +",\"caretReturnCodes\":["+caretCodeBefore+","+caretCodeAfter+"],\"beforeState\":"+beforeJson+",\"afterState\":"+afterJson
        +",\"baselineDocumentModifiedReads\":"+baselineDocumentModifiedReads+",\"baselineDocumentReadOnlyReads\":"+baselineDocumentReadOnlyReads
        +",\"baselineManagerEmptyReads\":"+baselineManagerEmptyReads
        +",\"baselineDocumentModifiedObserved\":"+(baselineDocumentModifiedReads==1)
        +",\"baselineDocumentReadOnlyObserved\":"+(baselineDocumentReadOnlyReads==1)+",\"baselineManagerEmptyObserved\":"+(baselineManagerEmptyReads==1)
        +",\"baselineDocumentModified\":"+(baselineDocumentModifiedReads==1?(baselineDocumentModified?"true":"false"):"null")
        +",\"baselineDocumentReadOnly\":"+(baselineDocumentReadOnlyReads==1?(baselineDocumentReadOnly?"true":"false"):"null")
        +",\"baselineManagerEmpty\":"+(baselineManagerEmptyReads==1?(baselineManagerEmpty?"true":"false"):"null")
        +",\"nativeException\":"+exception+",\"ownedTypedHandlesCleared\":"+refsCleared+",\"sourceBodyIncluded\":false,\"sourceFrameIncluded\":false,\"helperTextReads\":0"
        +",\"repositoryOwnerVerified\":false,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"businessCalls\":0,\"dirtyFlagWrites\":0}");
}
