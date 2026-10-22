// Own new runtime comparison only. No configuration save/update/repository call.
void ahOwnedHeadlessComparison() {
    bool ohcScope=__HEADLESS_SCOPE_ADMITTED__,ohcIntent=false,ohcBefore=false,ohcAfter=false,ohcCleanup=false,ohcUnknown=false;
    uint ohcBeforeCount=0,ohcAfterCount=0,ohcAttempts=0,ohcReturned=0;string ohcReason="SCOPE";
    string ohcOperation="__OPERATION_ID__",ohcScopeSha="__SCOPE_SHA256__";
    int_ptr ohcDll=0,ohcFunction=0;IConfigMngrUI@ ohcUi;IMDContainer@ ohcRoot;IConfigMngr@ ohcManager;IUnknown@ ohcService;ITopLevelFrame@ ohcShell;
    array<IMDObject@> ohcObjects(3);array<string> ohcIds={"8daef957-4ae2-48a1-bf6c-b88163a076f5","176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
    AhProcessingLoadV69@ ohcBridge;ExceptionCatcher ohcCatcher;
    {CppCatch ohcCaught("class core::Exception",ExceptionHandler(ohcCatcher.handle));
        do {
            if(!ohcScope || ohcOperation.length!=32 || ohcScopeSha.length!=64 || sizeof_ptr!=4
                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292 || !ahPipeScopeAlive()
                || ahStatusUi is null || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            @ohcUi=ahStatusUi;@ohcRoot=ohcUi.getMDCont();ohcReason="ROOT";
            if(ohcRoot is null || ohcRoot.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}") || !ahCatalogEditableV218(ohcRoot)
                || ohcRoot.isModified() || ohcUi.isModified() || uint(mem::addressOf(ohcRoot))!=344510268)break;
            for(uint ohcI=0;ohcI<3;ohcI++){
                IMDObject@ ohcObject=ohcRoot.objById(Guid("{"+ohcIds[ohcI]+"}"));
                if(ohcObject is null || ohcObject.isModified())break;@ohcObjects[ohcI]=ohcObject;ohcBeforeCount++;
            }
            if(ohcBeforeCount!=3)break;ohcBefore=true;ohcReason="MANAGERS";@ohcManager=ohcRoot.getConfigMngr();
            if(ohcManager is null || uint(mem::addressOf(ohcManager))!=340051296)break;
            @ohcShell=ahObservedMainFrameV211;
            if(ohcShell is null || !ahCompactTableV108(ohcShell.self,"config.dll",0x2b9474,32))break;
            int_ptr ohcCanonical=ohcShell.self-8;
            if(!ahCompactPageV108(ohcCanonical,0x2c) || mem::dword[ohcCanonical+36]!=177913256
                || !ahCompactPageV108(177913256,0x70) || mem::dword[177913256+100]!=344760440
                || !ahCompactPageV108(344760440,0x30) || mem::dword[344760440+0x1c]!=340051296 || mem::dword[344760440+0x24]!=100051712)break;
            ohcReason="SERVICE";@ohcService=currentProcess().getService(Guid("{5c54d1a0-d0df-4550-bfc6-7deed8622790}"));
            if(ohcService is null || !ahCompactTableV108(mem::addressOf(ohcService),"frntend.dll",0xc0daa4,12))break;
            ohcReason="OWN_BRIDGE";ohcDll=GetModuleHandle("__OWN_DLL_PATH__".cstr);
            if(ohcDll==0)break;ohcFunction=GetProcAddress(ohcDll,"_ahHeadlessComparisonBridge@16".toUtf8().ptr);
            if(ohcFunction==0)break;initFuncDefFromAddress(ohcFunction,@ohcBridge,asCALL_STDCALL);
            if(ohcBridge is null)break;ohcReason="DURABLE_INTENT";
            ohcIntent=ahWriteSample("__NATIVE_HEADLESS_INTENT_PATH__","{\"kind\":\"OWNED_HEADLESS_COMPARISON_INTENT\",\"operationId\":\""+ohcOperation
                +"\",\"scopeSha256\":\""+ohcScopeSha+"\",\"configurationReadOnly\":true,\"maximumFactoryCalls\":1,\"maximumExecutions\":1,\"sourceWrites\":0,\"databaseUpdates\":0,\"repositoryMutations\":0}");
            if(!ohcIntent)break;ohcUnknown=true;ohcAttempts=1;ohcReason="BRIDGE_CALL";
            ohcBridge(mem::addressOf(ohcService),mem::addressOf(ohcManager),100051712,uint(mem::addressOf(ohcRoot)));
            ohcReturned=1;ohcReason="NONE";
        }while(false);
    }
    ExceptionCatcher ohcFinalCatcher;
    {CppCatch ohcFinalCaught("class core::Exception",ExceptionHandler(ohcFinalCatcher.handle));
        if(ohcBefore && ahPipeScopeAlive() && ahStatusUi is ohcUi && !ohcRoot.isModified() && !ohcUi.isModified()
            && ahCatalogSameV218(ohcUi.getMDCont().unk,ohcRoot.unk)){
            for(uint ohcI=0;ohcI<3;ohcI++){
                IMDObject@ ohcFresh=ohcRoot.objById(Guid("{"+ohcIds[ohcI]+"}"));
                if(ohcFresh is null || ohcFresh.isModified() || ohcObjects[ohcI].isModified()
                    || !ahCatalogSameV218(ohcFresh.unk,ohcObjects[ohcI].unk))break;ohcAfterCount++;
            }
            ohcAfter=ohcAfterCount==3;
        }
    }
    ExceptionCatcher ohcCleanupCatcher;
    {CppCatch ohcCleanupCaught("class core::Exception",ExceptionHandler(ohcCleanupCatcher.handle));
        @ohcBridge=null;@ohcService=null;@ohcManager=null;@ohcShell=null;
        for(uint ohcI=0;ohcI<3;ohcI++)@ohcObjects[ohcI]=null;@ohcRoot=null;@ohcUi=null;ohcCleanup=true;
    }
    if(ohcCatcher.hasException || ohcFinalCatcher.hasException || ohcCleanupCatcher.hasException || !ohcCleanup){
        ohcUnknown=true;ohcReason="NATIVE_EXCEPTION_OR_CLEANUP";
    }else ohcUnknown=false;
    string ohcProof="{\"kind\":\"OWNED_HEADLESS_COMPARISON_AS_NATIVE\",\"operationId\":\""+ohcOperation+"\",\"scopeSha256\":\""+ohcScopeSha
        +"\",\"reason\":\""+ohcReason+"\",\"nativeIntentWritten\":"+ohcIntent+",\"bridgeAttempts\":"+ohcAttempts+",\"bridgeReturned\":"+ohcReturned
        +",\"beforeRootAndTargetsClean\":"+ohcBefore+",\"afterRootAndTargetsClean\":"+ohcAfter+",\"beforeTargetsClean\":"+ohcBeforeCount+",\"afterTargetsClean\":"+ohcAfterCount
        +",\"typedHandlesCleared\":"+ohcCleanup+",\"unknownRetain\":"+ohcUnknown+",\"dllPointer\":"+uint(ohcDll)+",\"bridgePointer\":"+uint(ohcFunction)
        +",\"fullPendingVerified\":false,\"databaseUpdateAuthorized\":false,\"nativeCommands\":0,\"sourceWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0}";
    ahWriteSample("__PROOF_PATH__",ohcProof);
}
