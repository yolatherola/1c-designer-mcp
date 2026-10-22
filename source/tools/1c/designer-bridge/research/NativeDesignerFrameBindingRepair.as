// Bind the missing stock frame context. No constructor, hooks or DB command.
void ahDesignerFrameBindingRepair() {
    bool fbrAdmitted=__FRAME_BINDING_REPAIR_SCOPE_ADMITTED__,fbrBefore=false,fbrAfter=false,fbrPrefix=false,fbrClean=false,fbrUnknown=false,fbrIntent=false;
    uint fbrBindings=0,fbrBeforeCount=0,fbrAfterCount=0;string fbrReason="SCOPE";
    string fbrOperation="__OPERATION_ID__",fbrScope="__SCOPE_SHA256__";
    IConfigMngrUI@ fbrUi;IMDContainer@ fbrRoot;ITopLevelFrame@ fbrShell,fbrCore;
    Designer@ fbrDesigner;ProfileStore@ fbrProfile;Snegopat@ fbrSnegopat;IHotKeys@ fbrHotkeys;IEventConnector@ fbrEvents;IDispatch@ fbrDispatch;
    array<IMDObject@> fbrObjects(3);array<string> fbrIds={"8daef957-4ae2-48a1-bf6c-b88163a076f5","176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
    uint fbrShellPointer=0,fbrCorePointer=0,fbrMainAfter=0,fbrCoreAfter=0;ExceptionCatcher fbrCatcher;
    {CppCatch fbrCaught("class core::Exception",ExceptionHandler(fbrCatcher.handle));
        do {
            if(!fbrAdmitted || fbrOperation.length!=32 || fbrScope.length!=64 || sizeof_ptr!=4
                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292 || !ahPipeScopeAlive()
                || ahStatusUi is null || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            @fbrUi=ahStatusUi;@fbrRoot=fbrUi.getMDCont();fbrReason="ROOT";
            if(fbrRoot is null || fbrRoot.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}") || !ahCatalogEditableV218(fbrRoot)
                || fbrRoot.isModified() || fbrUi.isModified())break;
            for(uint fbrI=0;fbrI<3;fbrI++){
                IMDObject@ fbrObject=fbrRoot.objById(Guid("{"+fbrIds[fbrI]+"}"));
                if(fbrObject is null || fbrObject.isModified())break;@fbrObjects[fbrI]=fbrObject;fbrBeforeCount++;
            }
            if(fbrBeforeCount!=3)break;fbrBefore=true;fbrReason="PARTIAL_PREFIX";
            if(oneDesigner is null || oneAddinMgr !is null || dspWindows is null || mainFrame !is null || coreMainFrame !is null)break;
            @fbrDesigner=oneDesigner;@fbrProfile=fbrDesigner._profileRoot;@fbrSnegopat=fbrDesigner._snegopat;
            @fbrHotkeys=fbrDesigner._hotkeys;@fbrEvents=fbrDesigner._events;@fbrDispatch=dspWindows;
            if(fbrProfile is null || fbrSnegopat is null || fbrHotkeys is null || fbrEvents is null
                || fbrDesigner._windows !is null || fbrDesigner._metadata !is null || fbrDesigner._v8files !is null
                || fbrDesigner._develop !is null || fbrDesigner._env !is null || fbrDesigner._cmdService !is null
                || fbrDesigner._winApi !is null || fbrDesigner._starterIpc !is null || fbrDesigner._addins !is null)break;
            fbrReason="OWN_FRAME";@fbrShell=ahObservedMainFrameV211;
            if(fbrShell is null || fbrShell.frameType()!=eTLFT_Main || uint(fbrShell.self)!=165503944)break;
            fbrShell.getCoreTopLevelFrame(fbrCore);
            if(fbrCore is null || !ahAccessLegacyLayoutV232(fbrShell,fbrCore))break;
            fbrShellPointer=uint(fbrShell.self);fbrCorePointer=uint(fbrCore.self);
            fbrReason="DURABLE_INTENT";
            fbrIntent=ahWriteSample("__NATIVE_FRAME_BINDING_INTENT_PATH__","{\"kind\":\"DESIGNER_FRAME_BINDING_REPAIR_NATIVE_INTENT\",\"operationId\":\""+fbrOperation
                +"\",\"scopeSha256\":\""+fbrScope+"\",\"maximumFrameBindings\":2,\"constructorCalls\":0,\"sourceWrites\":0,\"databaseUpdates\":0,\"repositoryMutations\":0}");
            if(!fbrIntent)break;fbrUnknown=true;fbrReason="BIND_FRAMES";
            // Normal counted-handle assignments retain the same validated
            // frame objects. There is no raw memory write or event replay.
            @mainFrame=fbrShell;fbrBindings++;
            @coreMainFrame=fbrCore;fbrBindings++;
            fbrReason="NONE";
        }while(false);
    }
    ExceptionCatcher fbrFinalCatcher;
    {CppCatch fbrFinalCaught("class core::Exception",ExceptionHandler(fbrFinalCatcher.handle));
        if(fbrBindings==2 && mainFrame is fbrShell && coreMainFrame is fbrCore){
            fbrMainAfter=uint(mainFrame.self);fbrCoreAfter=uint(coreMainFrame.self);
            fbrPrefix=oneDesigner is fbrDesigner && dspWindows is fbrDispatch && oneAddinMgr is null
                && fbrDesigner._profileRoot is fbrProfile && fbrDesigner._snegopat is fbrSnegopat
                && fbrDesigner._hotkeys is fbrHotkeys && fbrDesigner._events is fbrEvents
                && fbrDesigner._windows is null && fbrDesigner._metadata is null && fbrDesigner._v8files is null
                && fbrDesigner._develop is null && fbrDesigner._env is null && fbrDesigner._cmdService is null
                && fbrDesigner._winApi is null && fbrDesigner._starterIpc is null && fbrDesigner._addins is null;
        }
        if(fbrBefore && ahPipeScopeAlive() && ahStatusUi is fbrUi && !fbrRoot.isModified() && !fbrUi.isModified()
            && ahCatalogSameV218(fbrUi.getMDCont().unk,fbrRoot.unk)){
            for(uint fbrI=0;fbrI<3;fbrI++){
                IMDObject@ fbrFresh=fbrRoot.objById(Guid("{"+fbrIds[fbrI]+"}"));
                if(fbrFresh is null || fbrFresh.isModified() || fbrObjects[fbrI].isModified()
                    || !ahCatalogSameV218(fbrFresh.unk,fbrObjects[fbrI].unk))break;fbrAfterCount++;
            }
            fbrAfter=fbrAfterCount==3;
        }
    }
    ExceptionCatcher fbrCleanupCatcher;
    {CppCatch fbrCleanupCaught("class core::Exception",ExceptionHandler(fbrCleanupCatcher.handle));
        @fbrDispatch=null;@fbrEvents=null;@fbrHotkeys=null;@fbrSnegopat=null;@fbrProfile=null;@fbrDesigner=null;
        @fbrCore=null;@fbrShell=null;for(uint fbrI=0;fbrI<3;fbrI++)@fbrObjects[fbrI]=null;@fbrRoot=null;@fbrUi=null;fbrClean=true;
    }
    if(fbrCatcher.hasException || fbrFinalCatcher.hasException || fbrCleanupCatcher.hasException || !fbrClean
        || (fbrBindings!=0 && !(fbrBindings==2 && fbrPrefix && fbrAfter))){fbrUnknown=true;fbrReason="PARTIAL_OR_EXCEPTION_RETAIN";}
    else fbrUnknown=false;
    string fbrProof="{\"kind\":\"DESIGNER_FRAME_BINDING_REPAIR_NATIVE\",\"operationId\":\""+fbrOperation+"\",\"scopeSha256\":\""+fbrScope
        +"\",\"reason\":\""+fbrReason+"\",\"nativeIntentWritten\":"+fbrIntent+",\"frameBindings\":"+fbrBindings
        +",\"beforeTargetsClean\":"+fbrBeforeCount+",\"afterTargetsClean\":"+fbrAfterCount+",\"beforeRootAndTargetsClean\":"+fbrBefore+",\"afterRootAndTargetsClean\":"+fbrAfter
        +",\"shellPointer\":"+fbrShellPointer+",\"corePointer\":"+fbrCorePointer+",\"mainFrameAfter\":"+fbrMainAfter+",\"coreMainFrameAfter\":"+fbrCoreAfter
        +",\"designerPrefixPreserved\":"+fbrPrefix+",\"typedHandlesCleared\":"+fbrClean+",\"unknownRetain\":"+fbrUnknown
        +",\"globalBindingsIntentionallyRetained\":"+fbrBindings+",\"constructorCalls\":0,\"hookInstallCalls\":0,\"nativeCommands\":0,\"manualReferenceCalls\":0"
        +",\"sourceWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"fullPendingVerified\":false,\"databaseUpdateAuthorized\":false}";
    ahWriteSample("__PROOF_PATH__",fbrProof);
}
