// Exercise only our own subscription with synthetic scalar event objects.
// No native dialog, source edit, database command or application execution.
void ahSyntheticEventsRoundtripNormal() {
    bool syrAdmitted=__SYNTHETIC_EVENTS_SCOPE_ADMITTED__,syrIntent=false,syrBefore=false,syrAfter=false,syrCleanup=false,syrUnknown=false;
    bool syrCreated=false,syrDisconnected=false,syrFinished=false,syrCases=false,syrPrefix=false;
    uint syrBeforeCount=0,syrAfterCount=0,syrEvents=0,syrBridgeCalls=0,syrAnswers=0,syrModal=0,syrMessages=0,syrRejected=0,syrMutations=0,syrRefs=0,syrPhase=0;
    uint syrCreateStatus=0xffffffff,syrCreateVariantType=0xffffffff,syrFinishStatus=0xffffffff;
    string syrOperation="__OPERATION_ID__",syrScope="__SCOPE_SHA256__",syrReason="SCOPE";
    IConfigMngrUI@ syrUi;IMDContainer@ syrRoot;ITopLevelFrame@ syrShell,syrCore;
    Designer@ syrDesigner;IEventConnector@ syrConnector;IDispatch@ syrSource,syrSink,syrMessageNodeDispatch,syrModalNodeDispatch,syrPayload;
    HandlerNode@ syrMessageNode,syrModalNode;AhProcessingLoadV69@ syrBridge;
    Variant syrOwnedVariant,syrEmptyVariant;MemoryBuffer syrInput(12),syrOutput(104);
    array<IMDObject@> syrObjects(3);array<string> syrIds={"8daef957-4ae2-48a1-bf6c-b88163a076f5","176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
    ExceptionCatcher syrCatcher;
    {CppCatch syrCaught("class core::Exception",ExceptionHandler(syrCatcher.handle));
        do {
            if(!syrAdmitted || syrOperation.length!=32 || syrScope.length!=64 || sizeof_ptr!=4
                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292 || !ahPipeScopeAlive()
                || ahStatusUi is null || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            @syrUi=ahStatusUi;@syrRoot=syrUi.getMDCont();syrReason="ROOT";
            if(syrRoot is null || syrRoot.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}") || !ahCatalogEditableV218(syrRoot)
                || syrRoot.isModified() || syrUi.isModified())break;
            for(uint syrI=0;syrI<3;syrI++){
                IMDObject@ syrObject=syrRoot.objById(Guid("{"+syrIds[syrI]+"}"));
                if(syrObject is null || syrObject.isModified())break;@syrObjects[syrI]=syrObject;syrBeforeCount++;
            }
            if(syrBeforeCount!=3)break;syrBefore=true;syrReason="EVENT_CONTEXT";
            if(oneDesigner is null || oneAddinMgr !is null || dspWindows is null || mainFrame is null || coreMainFrame is null)break;
            @syrDesigner=oneDesigner;@syrConnector=syrDesigner._events;@syrSource=dspWindows;
            if(syrConnector is null || syrDesigner._profileRoot is null || syrDesigner._snegopat is null || syrDesigner._hotkeys is null
                || syrDesigner._windows !is null || syrDesigner._metadata !is null || syrDesigner._v8files !is null || syrDesigner._develop !is null
                || syrDesigner._env !is null || syrDesigner._cmdService !is null || syrDesigner._winApi !is null || syrDesigner._starterIpc !is null || syrDesigner._addins !is null)break;
            @syrShell=ahObservedMainFrameV211;
            if(syrShell is null || uint(syrShell.self)!=165503944 || mainFrame !is syrShell)break;
            syrShell.getCoreTopLevelFrame(syrCore);
            if(syrCore is null || uint(syrCore.self)!=345260260 || coreMainFrame !is syrCore || !ahAccessLegacyLayoutV232(syrShell,syrCore))break;
            if(trMsgBox.state!=trapEnabled || trDoModal1.state!=trapEnabled || trDoModal2.state!=trapEnabled)break;
            // The stock bus prepends one HandlerNode per subscriber. Reject
            // other subscribers rather than deliver synthetic events to them.
            if(syrConnector._hasHandlers(syrSource,"onMessageBox") || syrConnector._hasHandlers(syrSource,"onDoModal"))break;
            syrReason="OWN_BRIDGE";
            int_ptr syrDll=GetModuleHandle("__OWN_DLL_PATH__".cstr);
            if(syrDll==0)break;int_ptr syrFunction=GetProcAddress(syrDll,"_ahSyntheticEventBridge@16".toUtf8().ptr);
            if(syrFunction==0)break;initFuncDefFromAddress(syrFunction,@syrBridge,asCALL_STDCALL);
            if(syrBridge is null || syrInput.bytes==0 || syrInput._length!=12 || syrOutput.bytes==0 || syrOutput._length!=104)break;
            for(uint syrB=0;syrB<12;syrB++)mem::byte[syrInput.bytes+syrB]=0;
            for(uint syrB=0;syrB<104;syrB++)mem::byte[syrOutput.bytes+syrB]=0;
            mem::dword[syrOutput.bytes]=104;syrReason="DURABLE_INTENT";
            syrIntent=ahWriteSample("__NATIVE_SYNTHETIC_EVENTS_INTENT_PATH__","{\"kind\":\"SYNTHETIC_EVENTS_NATIVE_INTENT\",\"operationId\":\""+syrOperation
                +"\",\"scopeSha256\":\""+syrScope+"\",\"maximumSyntheticEvents\":7,\"maximumSubscribers\":2,\"nativeCommands\":0,\"sourceWrites\":0,\"databaseUpdates\":0,\"repositoryMutations\":0}");
            if(!syrIntent)break;syrUnknown=true;syrReason="CREATE_SINK";
            mem::dword[syrInput.bytes]=8;mem::dword[syrInput.bytes+4]=uint(mem::addressOf(syrOwnedVariant));
            syrBridgeCalls++;syrBridge(1,0x53454231,uint(syrInput.bytes),uint(syrOutput.bytes));
            syrCreateStatus=mem::dword[syrOutput.bytes+8];syrCreateVariantType=uint(syrOwnedVariant.vt);
            if(mem::dword[syrOutput.bytes+8]!=0 || syrOwnedVariant.vt!=VT_DISPATCH)break;syrCreated=true;
            @syrSink=syrOwnedVariant.getDispatch();if(syrSink is null)break;
            syrReason="CONNECT_OWN_NODES";
            @syrMessageNode=syrConnector.connect(syrSource,"onMessageBox",syrSink,"onMessageBox");
            @syrModalNode=syrConnector.connect(syrSource,"onDoModal",syrSink,"onDoModal");
            if(syrMessageNode is null || syrModalNode is null)break;
            @syrMessageNodeDispatch=createDispatchFromAS(@syrMessageNode);@syrModalNodeDispatch=createDispatchFromAS(@syrModalNode);
            if(syrMessageNodeDispatch is null || syrModalNodeDispatch is null)break;
            mem::dword[syrInput.bytes]=12;mem::dword[syrInput.bytes+4]=uint(mem::addressOf(syrMessageNodeDispatch));mem::dword[syrInput.bytes+8]=uint(mem::addressOf(syrModalNodeDispatch));
            syrBridgeCalls++;syrBridge(2,0x53454231,uint(syrInput.bytes),uint(syrOutput.bytes));if(mem::dword[syrOutput.bytes+8]!=0)break;
            syrReason="SYNTHETIC_MESSAGE_CASES";bool syrMessageCases=true;
            for(uint syrCase=0;syrCase<3;syrCase++){
                IMsgBoxHook syrMessage;syrMessage._text=syrCase==0?"AH1C_SYNTHETIC_UNKNOWN":"AH1C_SYNTHETIC_EVENT";
                syrMessage._caption="AH1C synthetic only";syrMessage._type=36;syrMessage._timeout=0;syrMessage.cancel=false;syrMessage.result=mbaCancel;
                @syrPayload=createDispatchFromAS(@syrMessage);
                mem::dword[syrInput.bytes]=12;mem::dword[syrInput.bytes+4]=1;mem::dword[syrInput.bytes+8]=uint(mem::addressOf(syrPayload));
                syrBridgeCalls++;syrBridge(3,0x53454231,uint(syrInput.bytes),uint(syrOutput.bytes));
                if(mem::dword[syrOutput.bytes+8]!=0){syrMessageCases=false;break;}
                array<Variant> syrArgs(1);syrArgs[0].setDispatch(syrPayload);
                syrEvents++;syrConnector.fireEvent(syrSource,"onMessageBox",syrArgs);
                if(syrCase==1){if(!syrMessage.cancel || syrMessage.result!=mbaYes)syrMessageCases=false;}
                else if(syrMessage.cancel || syrMessage.result!=mbaCancel)syrMessageCases=false;
                @syrPayload=null;
            }
            if(!syrMessageCases || syrEvents!=3)break;syrReason="SYNTHETIC_MODAL_STAGES";
            for(uint syrStage=0;syrStage<4;syrStage++){
                IDoModalHook syrModalHook(null);syrModalHook._stage=DoModalHookStages(syrStage);
                @syrPayload=createDispatchFromAS(@syrModalHook);
                mem::dword[syrInput.bytes]=12;mem::dword[syrInput.bytes+4]=2;mem::dword[syrInput.bytes+8]=uint(mem::addressOf(syrPayload));
                syrBridgeCalls++;syrBridge(3,0x53454231,uint(syrInput.bytes),uint(syrOutput.bytes));if(mem::dword[syrOutput.bytes+8]!=0)break;
                array<Variant> syrModalArgs(1);syrModalArgs[0].setDispatch(syrPayload);
                syrEvents++;syrConnector.fireEvent(syrSource,"onDoModal",syrModalArgs);
                if(syrModalHook.cancel || syrModalHook.result!=0)break;@syrPayload=null;
            }
            if(syrEvents!=7)break;
            syrBridgeCalls++;syrBridge(4,0x53454231,0,uint(syrOutput.bytes));
            syrAnswers=mem::dword[syrOutput.bytes+72];syrModal=mem::dword[syrOutput.bytes+60];syrMessages=mem::dword[syrOutput.bytes+68];
            syrRejected=mem::dword[syrOutput.bytes+76];syrMutations=mem::dword[syrOutput.bytes+80];
            syrCases=mem::dword[syrOutput.bytes+8]==0 && mem::dword[syrOutput.bytes+56]==7 && syrAnswers==1 && syrModal==4
                && syrMessages==3 && syrRejected==2 && syrMutations==1 && mem::dword[syrOutput.bytes+84]==0 && mem::dword[syrOutput.bytes+64]==3;
            syrReason=syrCases?"NONE":"CALLBACK_COUNTERS";
        }while(false);
    }
    ExceptionCatcher syrCleanupCatcher;
    {CppCatch syrCleanCaught("class core::Exception",ExceptionHandler(syrCleanupCatcher.handle));
        if(syrCreated && syrBridge !is null){
            syrBridgeCalls++;syrBridge(5,0x53454231,0,uint(syrOutput.bytes));
            if(mem::dword[syrOutput.bytes+8]==0){
                if(syrMessageNode !is null)syrConnector.disconnectNode(syrMessageNode);
                if(syrModalNode !is null)syrConnector.disconnectNode(syrModalNode);
                // AS wrapper caching can keep a HandlerNode alive. Break only
                // our disconnected nodes' counted handler links explicitly.
                if(syrMessageNode !is null)@syrMessageNode.handler=null;
                if(syrModalNode !is null)@syrModalNode.handler=null;
                syrDisconnected=!syrConnector._hasHandlers(syrSource,"onMessageBox") && !syrConnector._hasHandlers(syrSource,"onDoModal");
                @syrMessageNodeDispatch=null;@syrModalNodeDispatch=null;@syrMessageNode=null;@syrModalNode=null;@syrPayload=null;
                @syrSink=null;syrOwnedVariant=syrEmptyVariant;
                mem::dword[syrInput.bytes]=12;mem::dword[syrInput.bytes+4]=0;mem::dword[syrInput.bytes+8]=0;
                syrBridgeCalls++;syrBridge(3,0x53454231,uint(syrInput.bytes),uint(syrOutput.bytes));
                syrBridgeCalls++;syrBridge(2,0x53454231,uint(syrInput.bytes),uint(syrOutput.bytes));
                if(syrDisconnected){syrBridgeCalls++;syrBridge(6,0x53454231,0,uint(syrOutput.bytes));
                    syrFinishStatus=mem::dword[syrOutput.bytes+8];
                    syrPhase=mem::dword[syrOutput.bytes+12];syrRefs=mem::dword[syrOutput.bytes+24];
                    syrFinished=mem::dword[syrOutput.bytes+8]==0 && syrPhase==3 && syrRefs==0 && mem::dword[syrOutput.bytes+100]==1;
                }
            }
        }
        syrPrefix=oneDesigner is syrDesigner && oneDesigner !is null && oneDesigner._events is syrConnector && dspWindows is syrSource
            && mainFrame is syrShell && coreMainFrame is syrCore;
        if(syrBefore && ahPipeScopeAlive() && ahStatusUi is syrUi && !syrRoot.isModified() && !syrUi.isModified()
            && ahCatalogSameV218(syrUi.getMDCont().unk,syrRoot.unk)){
            for(uint syrI=0;syrI<3;syrI++){
                IMDObject@ syrFresh=syrRoot.objById(Guid("{"+syrIds[syrI]+"}"));
                if(syrFresh is null || syrFresh.isModified() || syrObjects[syrI].isModified()
                    || !ahCatalogSameV218(syrFresh.unk,syrObjects[syrI].unk))break;syrAfterCount++;
            }
            syrAfter=syrAfterCount==3;
        }
        @syrPayload=null;@syrBridge=null;@syrSource=null;@syrConnector=null;@syrDesigner=null;@syrShell=null;@syrCore=null;
        for(uint syrI=0;syrI<3;syrI++)@syrObjects[syrI]=null;@syrRoot=null;@syrUi=null;syrCleanup=true;
    }
    syrUnknown=syrCatcher.hasException || syrCleanupCatcher.hasException || !syrCleanup || (syrCreated && !(syrDisconnected && syrFinished));
    string syrProof="{\"kind\":\"SYNTHETIC_EVENTS_ROUNDTRIP_NATIVE\",\"operationId\":\""+syrOperation+"\",\"scopeSha256\":\""+syrScope
        +"\",\"reason\":\""+syrReason+"\",\"nativeIntentWritten\":"+syrIntent+",\"sinkCreated\":"+syrCreated+",\"subscribersDisconnected\":"+syrDisconnected
        +",\"sinkFinished\":"+syrFinished+",\"casesVerified\":"+syrCases+",\"syntheticEvents\":"+syrEvents+",\"bridgeCalls\":"+syrBridgeCalls
        +",\"answers\":"+syrAnswers+",\"modalSeen\":"+syrModal+",\"messagesSeen\":"+syrMessages+",\"rejected\":"+syrRejected+",\"mutations\":"+syrMutations+",\"finalRefs\":"+syrRefs+",\"finalPhase\":"+syrPhase
        +",\"beforeRootAndTargetsClean\":"+syrBefore+",\"afterRootAndTargetsClean\":"+syrAfter+",\"beforeTargetsClean\":"+syrBeforeCount+",\"afterTargetsClean\":"+syrAfterCount
        +",\"designerPrefixPreserved\":"+syrPrefix+",\"typedHandlesCleared\":"+syrCleanup+",\"unknownRetain\":"+syrUnknown
        +",\"nativeDialogs\":0,\"nativeCommands\":0,\"sourceWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"fullPendingVerified\":false,\"databaseUpdateAuthorized\":false}";
    syrProof=syrProof.substr(0,syrProof.length-1)+",\"createBridgeStatus\":"+syrCreateStatus+",\"createVariantType\":"+syrCreateVariantType+",\"finishBridgeStatus\":"+syrFinishStatus+"}";
    ahWriteSample("__PROOF_PATH__",syrProof);
}
