// Exact saved-resource and pending guards before one cancel-only Update29 preview.

void ahUpdatePreview() {

    bool upvAdmitted=__UPDATE_PREVIEW_SCOPE_ADMITTED__,upvBefore=false,upvAfter=false,upvPrefix=false,upvClean=false,upvIntent=false;

    uint upvBeforeCount=0,upvAfterCount=0,upvAttempts=0,upvReturned=0;bool upvEntered=false,upvLeft=false,upvCreated=false,upvDisconnected=false,upvFinished=false,upvResourcesVerified=false,upvComparisonBoundaryVerified=false;

    uint upvBridgeCalls=0,upvBridgeStatus=0xffffffff,upvBridgePhase=0;
    IDispatch@ upvModalSink,upvMessageSink,upvModalNodeDispatch,upvMessageNodeDispatch;
    HandlerNode@ upvModalNode,upvMessageNode;Variant upvModalOwned,upvMessageOwned,upvEmpty;
    MemoryBuffer upvInput(12),upvOutput(64);ICommandReceiver@ upvReceiver;CommandState@ upvUpdateState,upvSaveState;

    AhProcessingLoadV69@ upvBridge;

    uint upvPersistentBefore=0,upvSingleBefore=0,upvPersistentAfter=0,upvSingleAfter=0;string upvReason="SCOPE";

    string upvOperation="__OPERATION_ID__",upvScope="__SCOPE_SHA256__";

    IConfigMngrUI@ upvUi;IMDContainer@ upvRoot;

    Designer@ upvDesigner;ProfileStore@ upvProfile;Snegopat@ upvSnegopat;IHotKeys@ upvHotkeys;IEventConnector@ upvEvents;IDispatch@ upvDispatch;

    ITopLevelFrame@ upvShell,upvCore;array<IMDObject@> upvObjects(3);

    array<string> upvIds={"8daef957-4ae2-48a1-bf6c-b88163a076f5","176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};

    ExceptionCatcher upvCatcher;

    {CppCatch upvCaught("class core::Exception",ExceptionHandler(upvCatcher.handle));

        do {

            if(!upvAdmitted || upvOperation.length!=32 || upvScope.length!=64 || sizeof_ptr!=4

                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292 || !ahPipeScopeAlive()

                || ahStatusUi is null || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;

            @upvUi=ahStatusUi;@upvRoot=upvUi.getMDCont();upvReason="ROOT";

            if(upvRoot is null || upvRoot.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}") || !ahCatalogEditableV218(upvRoot)

                || upvRoot.isModified() || upvUi.isModified())break;

            for(uint upvI=0;upvI<3;upvI++){

                IMDObject@ upvObject=upvRoot.objById(Guid("{"+upvIds[upvI]+"}"));

                if(upvObject is null || upvObject.isModified())break;@upvObjects[upvI]=upvObject;upvBeforeCount++;

            }

            if(upvBeforeCount!=3)break;upvBefore=true;upvReason="PARTIAL_PREFIX";

            if(oneDesigner is null || oneAddinMgr !is null || dspWindows is null || mainFrame is null || coreMainFrame is null)break;

            @upvDesigner=oneDesigner;@upvProfile=upvDesigner._profileRoot;@upvSnegopat=upvDesigner._snegopat;

            @upvHotkeys=upvDesigner._hotkeys;@upvEvents=upvDesigner._events;@upvDispatch=dspWindows;

            @upvShell=mainFrame;@upvCore=coreMainFrame;

            if(upvProfile is null || upvSnegopat is null || upvHotkeys is null || upvEvents is null

                || upvDesigner._windows !is null || upvDesigner._metadata !is null || upvDesigner._v8files !is null

                || upvDesigner._develop !is null || upvDesigner._env !is null || upvDesigner._cmdService !is null

                || upvDesigner._winApi !is null || upvDesigner._starterIpc !is null || upvDesigner._addins !is null

                || uint(upvShell.self)!=165503944 || uint(upvCore.self)!=345260260)break;

            upvReason="SUBSCRIBERS";

            if(upvEvents._hasHandlers(upvDispatch,"onMessageBox") || upvEvents._hasHandlers(upvDispatch,"onDoModal"))break;

            upvPersistentBefore=idleHandlers.length;upvSingleBefore=idleHandlersSingle.length;

            upvReason="NONEMPTY_IDLE";if(upvPersistentBefore!=0 || upvSingleBefore!=0)break;

            upvReason="TRAPS";
            if(trMsgBox.state!=trapEnabled || trDoModal1.state!=trapEnabled || trDoModal2.state!=trapEnabled)break;
            {
__FAST_RESOURCES_BODY__
            }
            upvReason="SAVED_RESOURCE_HASHES";if(!upvResourcesVerified)break;
            {
__HEADLESS_COMPARE_BODY__
            }
            upvReason="COMPARISON_BOUNDARY";if(!upvComparisonBoundaryVerified)break;
            upvReason="CORE_RECEIVER";upvCore.commandReceiver(upvReceiver);
            if(!ahAccessLegacyReceiverV232(upvReceiver) || uint(upvReceiver.self)!=345260244)break;
            CommandID upvUpdateId(Guid("{F10CBB81-F679-11D4-9DD3-0050BAE2BC79}"),29);
            CommandID upvSaveId(Guid("{F10CBB81-F679-11D4-9DD3-0050BAE2BC79}"),3);
            if(!upvReceiver.hasHandler(upvUpdateId) || !upvReceiver.hasHandler(upvSaveId))break;
            @upvUpdateState=getCommandState(upvUpdateId,0,upvReceiver);@upvSaveState=getCommandState(upvSaveId,0,upvReceiver);
            upvReason="COMMAND_STATES";
            if(upvUpdateState is null || upvSaveState is null || !upvUpdateState.cmdState.bEnable || upvSaveState.cmdState.bEnable)break;
            int_ptr upvDll=GetModuleHandle("__OWN_DLL_PATH__".cstr);
            int_ptr upvFunction=upvDll==0?0:GetProcAddress(upvDll,"_ahUpdatePreviewBridge@16".toUtf8().ptr);
            upvReason="BRIDGE_EXPORT";if(upvFunction==0)break;initFuncDefFromAddress(upvFunction,@upvBridge,asCALL_STDCALL);
            for(uint upvB=0;upvB<64;upvB++)mem::byte[upvOutput.bytes+upvB]=0;
            mem::dword[upvOutput.bytes]=64;mem::dword[upvOutput.bytes+4]=0xffffffff;
            mem::dword[upvInput.bytes]=12;mem::dword[upvInput.bytes+4]=uint(mem::addressOf(upvModalOwned));mem::dword[upvInput.bytes+8]=uint(mem::addressOf(upvMessageOwned));
            upvReason="CREATE_ALLOWLIST_GATE";upvBridgeCalls++;upvBridge(1,0x55505831,uint(upvInput.bytes),uint(upvOutput.bytes));
            upvBridgeStatus=mem::dword[upvOutput.bytes+4];upvBridgePhase=mem::dword[upvOutput.bytes+8];
            if(upvBridgeStatus!=0 || upvBridgePhase!=1 || upvModalOwned.vt!=VT_DISPATCH || upvMessageOwned.vt!=VT_DISPATCH)break;
            upvCreated=true;@upvModalSink=upvModalOwned.getDispatch();@upvMessageSink=upvMessageOwned.getDispatch();
            if(upvModalSink is null || upvMessageSink is null)break;
            @upvModalNode=upvEvents.connect(upvDispatch,"onDoModal",upvModalSink,"onDoModal");
            @upvMessageNode=upvEvents.connect(upvDispatch,"onMessageBox",upvMessageSink,"onMessageBox");
            if(upvModalNode is null || upvMessageNode is null)break;
            @upvModalNodeDispatch=createDispatchFromAS(@upvModalNode);@upvMessageNodeDispatch=createDispatchFromAS(@upvMessageNode);
            if(upvModalNodeDispatch is null || upvMessageNodeDispatch is null)break;
            mem::dword[upvInput.bytes]=12;mem::dword[upvInput.bytes+4]=uint(mem::addressOf(upvModalNodeDispatch));mem::dword[upvInput.bytes+8]=uint(mem::addressOf(upvMessageNodeDispatch));
            upvReason="NODES";upvBridgeCalls++;upvBridge(2,0x55505831,uint(upvInput.bytes),uint(upvOutput.bytes));
            if(mem::dword[upvOutput.bytes+4]!=0 || mem::dword[upvOutput.bytes+8]!=2)break;
            upvReason="INTENT";
            upvIntent=ahWriteSample("__NATIVE_UPDATE_PREVIEW_INTENT_PATH__","{\"kind\":\"UPDATE_PREVIEW_INTENT\",\"operationId\":\""+upvOperation
                +"\",\"scopeSha256\":\""+upvScope+"\",\"command\":29,\"maximumDispatchAttempts\":1,\"maximumModalCancels\":1,\"maximumMessageCancels\":1,\"positiveAnswers\":0,\"sourceWrites\":0,\"configurationSaves\":0,\"repositoryMutations\":0,\"databaseApplyPossible\":true}");
            if(!upvIntent)break;
            upvReason="FINAL_DIRTY_GUARD";
            if(!ahPipeScopeAlive() || ahStatusUi !is upvUi || upvRoot.isModified() || upvUi.isModified()
                || oneDesigner !is upvDesigner || dspWindows !is upvDispatch || idleHandlers.length!=0 || idleHandlersSingle.length!=0)break;
            uint upvFinalClean=0;for(uint upvI=0;upvI<3;upvI++)if(!upvObjects[upvI].isModified())upvFinalClean++;
            if(upvFinalClean!=3)break;
            upvReason="ENTER29";upvBridgeCalls++;upvBridge(3,0x55505831,uint(upvReceiver.self),uint(upvOutput.bytes));
            if(mem::dword[upvOutput.bytes+4]!=0 || mem::dword[upvOutput.bytes+8]!=3)break;upvEntered=true;
            // Count before the one native command; cancel/exception never retries.
            upvReason="COMMAND29";upvAttempts++;upvReceiver.transmitCommand(Command(upvUpdateId,0));upvReturned++;
            upvReason="LEAVE29";upvBridgeCalls++;upvBridge(4,0x55505831,0,uint(upvOutput.bytes));
            upvLeft=mem::dword[upvOutput.bytes+4]==0 && mem::dword[upvOutput.bytes+8]==4;
            if(upvLeft)upvReason="NONE";



        }while(false);

    }

    ExceptionCatcher upvSinkCleanupCatcher;
    {CppCatch upvSinkCleanupCaught("class core::Exception",ExceptionHandler(upvSinkCleanupCatcher.handle));
        if(upvCreated && upvBridge !is null){
            upvBridgeCalls++;upvBridge(5,0x55505831,0,uint(upvOutput.bytes));
            if(mem::dword[upvOutput.bytes+4]==0){
                if(upvModalNode !is null)upvEvents.disconnectNode(upvModalNode);
                if(upvMessageNode !is null)upvEvents.disconnectNode(upvMessageNode);
                // Only our disconnected HandlerNodes; avoid cached wrapper cycles.
                if(upvModalNode !is null)@upvModalNode.handler=null;if(upvMessageNode !is null)@upvMessageNode.handler=null;
                upvDisconnected=!upvEvents._hasHandlers(upvDispatch,"onDoModal") && !upvEvents._hasHandlers(upvDispatch,"onMessageBox");
                @upvModalNodeDispatch=null;@upvMessageNodeDispatch=null;@upvModalNode=null;@upvMessageNode=null;
                @upvModalSink=null;@upvMessageSink=null;upvModalOwned=upvEmpty;upvMessageOwned=upvEmpty;
                upvBridgeCalls++;upvBridge(6,0x55505831,0,uint(upvOutput.bytes));
                if(upvDisconnected && mem::dword[upvOutput.bytes+4]==0){
                    upvBridgeCalls++;upvBridge(7,0x55505831,0,uint(upvOutput.bytes));
                    upvBridgeStatus=mem::dword[upvOutput.bytes+4];upvBridgePhase=mem::dword[upvOutput.bytes+8];
                    upvFinished=upvBridgeStatus==0 && upvBridgePhase==5 && mem::dword[upvOutput.bytes+12]==0
                        && mem::dword[upvOutput.bytes+16]==0 && mem::dword[upvOutput.bytes+44]==0;
                }
            }
        }
    }
    ExceptionCatcher upvFinalCatcher;

    {CppCatch upvFinalCaught("class core::Exception",ExceptionHandler(upvFinalCatcher.handle));

        upvPersistentAfter=idleHandlers.length;upvSingleAfter=idleHandlersSingle.length;

        if(upvBefore){

            upvPrefix=oneDesigner is upvDesigner && dspWindows is upvDispatch && oneAddinMgr is null

                && mainFrame is upvShell && coreMainFrame is upvCore

                && upvDesigner._profileRoot is upvProfile && upvDesigner._snegopat is upvSnegopat

                && upvDesigner._hotkeys is upvHotkeys && upvDesigner._events is upvEvents

                && upvDesigner._windows is null && upvDesigner._metadata is null && upvDesigner._v8files is null

                && upvDesigner._develop is null && upvDesigner._env is null && upvDesigner._cmdService is null

                && upvDesigner._winApi is null && upvDesigner._starterIpc is null && upvDesigner._addins is null;

        }

        if(upvBefore && ahPipeScopeAlive() && ahStatusUi is upvUi && !upvRoot.isModified() && !upvUi.isModified()

            && ahCatalogSameV218(upvUi.getMDCont().unk,upvRoot.unk)){

            for(uint upvI=0;upvI<3;upvI++){

                IMDObject@ upvFresh=upvRoot.objById(Guid("{"+upvIds[upvI]+"}"));

                if(upvFresh is null || upvFresh.isModified() || upvObjects[upvI].isModified()

                    || !ahCatalogSameV218(upvFresh.unk,upvObjects[upvI].unk))break;upvAfterCount++;

            }

            upvAfter=upvAfterCount==3;

        }

    }

    ExceptionCatcher upvCleanupCatcher;

    {CppCatch upvCleanupCaught("class core::Exception",ExceptionHandler(upvCleanupCatcher.handle));

        @upvUpdateState=null;@upvSaveState=null;@upvReceiver=null;@upvBridge=null;@upvDispatch=null;@upvEvents=null;@upvHotkeys=null;@upvSnegopat=null;@upvProfile=null;@upvDesigner=null;

        @upvCore=null;@upvShell=null;for(uint upvI=0;upvI<3;upvI++)@upvObjects[upvI]=null;@upvRoot=null;@upvUi=null;upvClean=true;

    }

    bool upvException=upvCatcher.hasException || upvSinkCleanupCatcher.hasException || upvFinalCatcher.hasException || upvCleanupCatcher.hasException;

    bool upvHooks=trMsgBox.state==trapEnabled && trDoModal1.state==trapEnabled && trDoModal2.state==trapEnabled;
    bool upvPassed=upvReason=="NONE" && upvBefore && upvAfter && upvPrefix && upvClean && !upvException && upvHooks
        && upvResourcesVerified && upvEntered && upvLeft && upvCreated && upvDisconnected && upvFinished && upvAttempts==1 && upvReturned==1
        && upvPersistentBefore==0 && upvPersistentAfter==0 && upvSingleBefore==0 && upvSingleAfter==0;
    string upvProof="{\"kind\":\"UPDATE_PREVIEW_NATIVE\",\"operationId\":\""+upvOperation+"\",\"scopeSha256\":\""+upvScope
        +"\",\"reason\":\""+upvReason+"\",\"verified\":"+upvPassed+",\"nativeIntentWritten\":"+upvIntent+",\"beforeRootAndTargetsClean\":"+upvBefore
        +",\"afterRootAndTargetsClean\":"+upvAfter+",\"beforeTargetsClean\":"+upvBeforeCount+",\"afterTargetsClean\":"+upvAfterCount
        +",\"designerPrefixPreserved\":"+upvPrefix+",\"typedHandlesCleared\":"+upvClean+",\"exceptionObserved\":"+upvException+",\"hooksPreserved\":"+upvHooks
        +",\"resourcesVerified\":"+upvResourcesVerified+",\"entered\":"+upvEntered+",\"left\":"+upvLeft+",\"sinksCreated\":"+upvCreated+",\"subscribersDisconnected\":"+upvDisconnected+",\"sinksFinished\":"+upvFinished
        +",\"commandAttempts\":"+upvAttempts+",\"commandReturned\":"+upvReturned+",\"bridgeCalls\":"+upvBridgeCalls+",\"bridgeStatus\":"+upvBridgeStatus+",\"bridgePhase\":"+upvBridgePhase
        +",\"persistentBefore\":"+upvPersistentBefore+",\"persistentAfter\":"+upvPersistentAfter+",\"singleBefore\":"+upvSingleBefore+",\"singleAfter\":"+upvSingleAfter
        +",\"sourceWrites\":0,\"configurationSaves\":0,\"repositoryMutations\":0,\"positiveAnswers\":0,\"databaseApplyPossible\":true,\"databaseApplyVerified\":false}";
    ahWriteSample("__PROOF_PATH__",upvProof);
}
