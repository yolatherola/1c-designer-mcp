// Read one C-owned resident job. The packet contains metadata, never source bytes.
// COMMITTED is a candidate: the worker must still seal actual SDK/epoch closure.
void ahLiveCommonModuleBound(int_ptr envelope) {
    bool admitted=__LIVE_RESIDENT_SCOPE_ADMITTED__;
    if(!admitted)return;
    string operation="__OPERATION_ID__",scope="__SCOPE_SHA256__",reader="__LIVE_RESIDENT_READER_SHA__";
    string nonce="",uuidHex="",digits="0123456789abcdef",reason="SCOPE";
    uint jobSequence=0;bool packetOwned=false;MemoryBuffer inputHeader(256);
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
    uint captureCalls=0,commitCalls=0,capturedUtf16Units=0;
    bool captureReturned=false,commitReturned=false;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            // The address comes only from SetArgDWord on our own SDK context.
            // Validate it through the DLL before dereferencing any packet field.
            if(sizeof_ptr!=4 || uint(envelope)<65536 || inputHeader.bytes==0)break;
            if(__LIVE_BOUND_VALIDATE__(envelope,704)!=1)break;
            packetOwned=true;mem::memcpy(inputHeader.bytes,envelope,256);
            if(mem::dword[envelope]!=0x324a564c || mem::dword[envelope+4]!=2 || mem::dword[envelope+8]!=704
                || mem::dword[envelope+240]!=0x91d4a63b || mem::dword[envelope+244]!=1
                || mem::dword[envelope+248]!=262144 || mem::dword[envelope+252]!=0
                || mem::dword[envelope+504]!=0 || mem::dword[envelope+508]!=0x6b5c28e7)break;
            jobSequence=mem::dword[envelope+12];if(jobSequence<1 || jobSequence>64)break;
            bool inputsValid=operation.length==32 && scope.length==64 && reader.length==64;
            if(inputsValid){
                for(uint n=0;n<32;n++){
                    uint a=mem::byte[envelope+16+n],b=mem::byte[envelope+48+n];
                    if(!((a>=48 && a<=57)||(a>=97 && a<=102)) || !((b>=48 && b<=57)||(b>=97 && b<=102))){inputsValid=false;break;}
                    nonce+=digits.substr(a<=57?a-48:a-87,1);uuidHex+=digits.substr(b<=57?b-48:b-87,1);
                    if(mem::byte[envelope+80+n]!=uint8(operation[n]))inputsValid=false;
                }
                for(uint n=0;n<64;n++)if(mem::byte[envelope+112+n]!=uint8(scope[n]) || mem::byte[envelope+176+n]!=uint8(reader[n]))inputsValid=false;
            }
            if(!inputsValid || nonce.length!=32 || uuidHex.length!=32 || nonce=="00000000000000000000000000000000"
                || uuidHex=="00000000000000000000000000000000")break;
            intent=true;
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
            Guid target("{"+uuidHex.substr(0,8)+"-"+uuidHex.substr(8,4)+"-"+uuidHex.substr(12,4)+"-"+uuidHex.substr(16,4)+"-"+uuidHex.substr(20,12)+"}");
            Guid property("{d5963243-262e-4398-b4d7-fb16d06484f6}");
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
            // Fixed op-specific globals are installed and verified by C before
            // CompileFunction. No AS address lookup or dynamic registration.
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
                int_ptr packet=envelope+512+pass*96;
                for(uint n=0;n<24;n++)mem::dword[packet+n*4]=0;
                mem::dword[packet]=0x31534d54;mem::dword[packet+4]=2;mem::dword[packet+8]=96;
                for(uint n=0;n<32;n++)mem::byte[packet+64+n]=uint8(nonce[n]);
                mem::dword[packet+60]=0xa17e5afe;reason="READONLY_TM_STATE";bridgeCalls++;
                uint bridgeStatus=__LIVE_BOUND_STATE__(tmAddress,packet);
                bool operationSame=true;for(uint n=0;n<32;n++)if(mem::byte[packet+64+n]!=uint8(nonce[n]))operationSame=false;
                if(!operationSame || bridgeStatus!=1 || bridgeStatus!=mem::dword[packet+12]
                    || mem::dword[packet]!=0x31534d54 || mem::dword[packet+4]!=2 || mem::dword[packet+8]!=96
                    || mem::dword[packet+12]!=1 || mem::dword[packet+16]!=0
                    || mem::dword[packet+20]>1 || mem::dword[packet+24]>1
                    || (mem::dword[packet+24]==0 && mem::dword[packet+28]!=0xffffffff)
                    || mem::dword[packet+32]!=1 || mem::dword[packet+36]!=1
                    || mem::dword[packet+40]!=1 || mem::dword[packet+44]!=1
                    || mem::dword[packet+48]!=2 || mem::dword[packet+52]!=8292
                    || mem::dword[packet+56]!=0x31534d54 || mem::dword[packet+60]!=0xa17e5afe)break;
                array<uint> state={uiAddress,rootAddress,objectAddress,helperAddress,textAddress,editorAddress,documentAddress,tmAddress,
                    root.isModified()?1:0,ui.isModified()?1:0,object.isModified()?1:0,document.isModified()?1:0,document.getReadOnly()?1:0,
                    caret.line,caret.col,selectionStart.line,selectionStart.col,selectionStop.line,selectionStop.col,
                    mem::dword[packet+20],mem::dword[packet+24],mem::dword[packet+28]};
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
                        // Candidate copy is not publication. Both SDK strings
                        // remain alive through this synchronous bounded copy.
                        if(readVerified){
                            reason="CAPTURE_CANDIDATE";captureCalls++;
                            mem::dword[envelope+280]=chars;mem::int_ptr[envelope+324]=first.cstr;
                            captureReturned=__LIVE_BOUND_CAPTURE__(envelope,jobSequence)==1;
                            if(captureReturned)capturedUtf16Units=chars;
                            readVerified=readVerified && captureReturned;
                        }
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
        @document=null;@linked=null;@editor=null;@text=null;
        @boundObject=null;@freshObject=null;@freshRoot=null;@module=null;@helper=null;@service=null;@object=null;@root=null;@ui=null;
    }
    refsCleared=document is null && linked is null && editor is null && text is null
        && module is null && helper is null && service is null && boundObject is null && freshObject is null && freshRoot is null
        && object is null && root is null && ui is null;
    bool verified=admitted && intent && openReturned && readVerified && statesEqual && !exception && refsCleared
        && opens==1 && saves==2 && bridgeCalls==2 && warmupReads==1 && firstReturned && secondReturned && independentOutputs;
    verified=verified && captureCalls==1 && captureReturned && capturedUtf16Units==chars;
    // Publish only whitelisted numeric facts in this job's own RAM. The SDK
    // closure remains the worker's responsibility after this function returns.
    bool ownedNow=packetOwned && __LIVE_BOUND_VALIDATE__(envelope,704)==1;
    bool headerSame=ownedNow;
    if(headerSame)for(uint n=0;n<256;n++)if(mem::byte[envelope+n]!=mem::byte[inputHeader.bytes+n])headerSame=false;
    verified=verified && headerSame;
    // If validation refuses, retain the C failure facts and leave cleanup to
    // the worker. A successful initial validation is not renewed authority.
    if(ownedNow){
        mem::dword[envelope+260]=verified?0:1;
        mem::dword[envelope+264]=opens;mem::dword[envelope+268]=saves;mem::dword[envelope+272]=bridgeCalls;
        mem::dword[envelope+276]=warmupReads;mem::dword[envelope+280]=chars;mem::dword[envelope+284]=compared;
        mem::dword[envelope+288]=refsCleared?1:0;mem::dword[envelope+292]=independentOutputs?1:0;
        mem::dword[envelope+296]=readVerified?1:0;mem::dword[envelope+300]=statesEqual?1:0;
        mem::dword[envelope+304]=exception?1:0;mem::dword[envelope+308]=firstReturned?1:0;
        mem::dword[envelope+312]=secondReturned?1:0;mem::dword[envelope+316]=warmupDocumentModified?1:0;
        mem::dword[envelope+320]=warmupReads==1?1:0;mem::dword[envelope+324]=0;
        if(before.length==22 && after.length==22)for(uint n=0;n<22;n++){
            mem::dword[envelope+328+n*4]=before[n];mem::dword[envelope+416+n*4]=after[n];
        }
        // Only the C export writes status1, after validating all facts. It is
        // a committed candidate, never a claim that SDK resources are closed.
        if(verified){commitCalls++;commitReturned=__LIVE_BOUND_COMMIT__(envelope,jobSequence)==1;}
    }
    // Engine-owned globals deliberately remain registered until native exit.
    verified=verified && commitReturned && commitCalls==1;
    if(ownedNow && !verified){
        if(mem::dword[envelope+260]==0)mem::dword[envelope+260]=1;
        mem::dword[envelope+256]=2;
    }
}
