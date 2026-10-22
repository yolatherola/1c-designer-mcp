// Separate read-only candidate collector; actual Update29 routing stays unproved.
void ahDesignerEventsInitialize() {
    bool uorAdmitted=__DESIGNER_EVENTS_INITIALIZE_SCOPE_ADMITTED__,uorIntent=false,uorBeforeClean=false,uorAfterClean=false;
    bool uorCandidate=false,uorCleanup=false,uorUnknown=false;
    uint deiAttempts=0,deiReturned=0,deiAddins=0;bool deiBeforeAbsent=false,deiReady=false;
    uint qcsReceiverPointer=0,qcsQueries=0;bool qcsUpdatePresent=false,qcsUpdateEnabled=false,qcsSavePresent=false,qcsSaveEnabled=false,qcsMessageHandlers=false,qcsModalHandlers=false,qcsEvents=false;
    ICommandReceiver@ qcsReceiver;CommandState@ qcsUpdate,qcsSave;
    uint uorBeforeTargets=0,uorAfterTargets=0,uorQiAttempts=0,uorQiReturned=0,uorPasses=0;
    string uorOperation="__OPERATION_ID__",uorScope="__SCOPE_SHA256__",uorStatus="DESIGNER_EVENTS_INITIALIZE_REFUSED",uorReason="SCOPE";
    int_ptr uorCanonical=0,uorOwner=0,uorDelegate=0,uorMainEntry=0;
    uint uorShellPointer=0,uorTargetPointer=0;
    IConfigMngrUI@ uorUi;IMDContainer@ uorRoot;ITopLevelFrame@ uorShell,uorCore;ICommandTarget@ uorTarget;
    array<IMDObject@> uorObjects(3);array<uint> uorFirst(6,0);
    array<string> uorIds={"8daef957-4ae2-48a1-bf6c-b88163a076f5","176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
    ExceptionCatcher uorCatcher;
    {CppCatch uorCaught("class core::Exception",ExceptionHandler(uorCatcher.handle));
        do {
            if(!uorAdmitted || uorOperation.length!=32 || uorScope.length!=64 || sizeof_ptr!=4
                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211
                || ahStatusUi is null || !ahPipeScopeAlive())break;
            @uorUi=ahStatusUi;@uorRoot=uorUi.getMDCont();uorReason="ROOT";
            if(uorRoot is null || uorRoot.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
                || !ahCatalogEditableV218(uorRoot) || uorRoot.isModified() || uorUi.isModified())break;
            uorReason="TARGETS_CLEAN";
            for(uint uorI=0;uorI<3;uorI++){
                Guid uorId("{"+uorIds[uorI]+"}");IMDObject@ uorObject=uorRoot.objById(uorId);
                if(uorObject is null || uorObject.id!=uorId || uorObject.isModified())break;
                @uorObjects[uorI]=uorObject;uorBeforeTargets++;
            }
            if(uorBeforeTargets!=3)break;uorBeforeClean=true;uorReason="SHELL";@uorShell=ahObservedMainFrameV211;
            // Reuse the existing owned shell; no discovery or view enumeration.
            if(uorShell is null || uorShell.frameType()!=eTLFT_Main)break;uorShell.getCoreTopLevelFrame(uorCore);
            if(uorCore is null || !ahAccessLegacyLayoutV232(uorShell,uorCore)
                || !ahCompactTableV108(uorShell.self,"config.dll",0x2b9474,32)
                || uint(uorShell.self)<65544 || uint64(uint(uorShell.self))+0x24>0x100000000)break;
            uorShellPointer=uint(uorShell.self);uorCanonical=uorShell.self-8;
            if(!ahCompactPageV108(uorCanonical,0x2c)
                || !ahCompactTableV108(uorCanonical,"config.dll",0x2b9568,7)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[uorCanonical]+6*4],"config.dll",0xa3170))break;
            uorReason="DURABLE_NATIVE_INTENT";
            uorIntent=ahWriteSample("__NATIVE_DESIGNER_EVENTS_INTENT_PATH__","{\"kind\":\"DESIGNER_EVENTS_INITIALIZE_NATIVE_INTENT\",\"operationId\":\""+uorOperation
                +"\",\"scopeSha256\":\""+uorScope+"\",\"configurationReadOnly\":true,\"runtimeInitAndStatusOnly\":true,\"databaseUpdates\":0,\"repositoryMutations\":0}");
            if(!uorIntent)break;
            uorUnknown=true;uorStatus="UNKNOWN_RETAIN";uorReason="PUBLISHED_TYPED_QI";uorQiAttempts=1;
            @uorTarget=uorShell.unk;uorQiReturned=1;
            if(uorTarget is null)break;uorTargetPointer=uint(uorTarget.self);uorReason="TARGET_ABI";
            if(uint64(uorShellPointer)+8>0xffffffff || uorTargetPointer!=uorShellPointer+8
                || !ahCompactPageV108(uorTarget.self,0x1c)
                || !ahCompactTableV108(uorTarget.self,"config.dll",0x2b945c,6))break;
            array<uint> uorMethods={0x23c2d7,0x23c1ce,0x23c360,0x142c80,0x142cc0,0x142d10};bool uorAbi=true;
            for(uint uorM=0;uorM<6;uorM++)if(!ahCompactAddressV108(mem::int_ptr[mem::int_ptr[uorTarget.self]+uorM*4],"config.dll",uorMethods[uorM]))uorAbi=false;
            if(!uorAbi)break;
            for(uint uorPass=0;uorPass<2;uorPass++){
                uorReason="SNAPSHOT_BINDING";
                if(!ahPipeScopeAlive() || ahStatusUi !is uorUi || ahObservedMainFrameV211 !is uorShell
                    || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292
                    || !ahCompactPageV108(uorCanonical,0x2c)
                    || !ahCompactTableV108(uorCanonical,"config.dll",0x2b9568,7)
                    || !ahCompactPageV108(uorTarget.self,0x1c)
                    || !ahCompactTableV108(uorTarget.self,"config.dll",0x2b945c,6))break;
                int_ptr uorNextOwner=mem::int_ptr[uorCanonical+0x24],uorNextDelegate=mem::int_ptr[uorTarget.self+0x18];
                uorReason="OWNER_PAGE";
                if(uint(uorNextOwner)<65536 || uint(uorNextOwner)%4!=0 || uint64(uint(uorNextOwner))+0x70>0x100000000
                    || !ahCompactPageV108(uorNextOwner,0x70))break;
                int_ptr uorNextMain=mem::int_ptr[uorNextOwner+0x64];
                if(uint(uorNextMain)<65536 || uint(uorNextMain)%4!=0 || uint64(uint(uorNextMain))+0x30>0x100000000
                    || !ahCompactPageV108(uorNextMain,0x30))break;
                array<uint> uorNow={uorShellPointer,uint(uorCanonical),uorTargetPointer,uint(uorNextOwner),uint(uorNextDelegate),uint(uorNextMain)};
                bool uorSame=true;for(uint uorK=0;uorK<6;uorK++){
                    if(uorPass==0)uorFirst[uorK]=uorNow[uorK];else if(uorFirst[uorK]!=uorNow[uorK])uorSame=false;
                }
                uorReason="SNAPSHOT_CHANGED";if(!uorSame)break;
                uorOwner=uorNextOwner;uorDelegate=uorNextDelegate;uorMainEntry=uorNextMain;uorPasses++;
            }
            if(uorPasses!=2)break;
            // Status queries follow the published receiver; explicit target
            // ownership is recorded separately and is not permission to apply.
            uorReason="CORE_RECEIVER";uorCore.commandReceiver(qcsReceiver);
            if(!ahAccessLegacyReceiverV232(qcsReceiver))break;qcsReceiverPointer=uint(qcsReceiver.self);
            uorReason="COMMAND_STATES";
            CommandID qcsUpdateId(Guid("{F10CBB81-F679-11D4-9DD3-0050BAE2BC79}"),29);
            CommandID qcsSaveId(Guid("{F10CBB81-F679-11D4-9DD3-0050BAE2BC79}"),3);
            qcsUpdatePresent=qcsReceiver.hasHandler(qcsUpdateId);qcsSavePresent=qcsReceiver.hasHandler(qcsSaveId);
            if(!qcsUpdatePresent || !qcsSavePresent)break;
            qcsQueries++;@qcsUpdate=getCommandState(qcsUpdateId,0,qcsReceiver);
            qcsQueries++;@qcsSave=getCommandState(qcsSaveId,0,qcsReceiver);
            if(qcsUpdate is null || qcsSave is null)break;
            qcsUpdateEnabled=qcsUpdate.cmdState.bEnable;qcsSaveEnabled=qcsSave.cmdState.bEnable;
            uorReason="RUNTIME_BEFORE";
            deiBeforeAbsent=oneDesigner is null && oneAddinMgr is null && dspWindows is null;
            if(!deiBeforeAbsent)break;
            // Construct the shipped API root exactly once. initAddins would
            // additionally load external std/main.js; it must not be called.
            uorReason="RUNTIME_CONSTRUCTOR";deiAttempts=1;Designer();deiReturned=1;
            deiReady=oneDesigner !is null && oneDesigner._events !is null && oneDesigner._windows !is null
                && oneAddinMgr !is null && dspWindows !is null;
            if(!deiReady)break;deiAddins=oneAddinMgr.get_count();if(deiAddins>128)break;
            qcsEvents=oneDesigner !is null && dspWindows !is null;
            if(qcsEvents){
                qcsMessageHandlers=oneDesigner._events._hasHandlers(dspWindows,"onMessageBox");
                qcsModalHandlers=oneDesigner._events._hasHandlers(dspWindows,"onDoModal");
            }
            uorCandidate=true;uorReason="NONE";
        }while(false);
    }
    ExceptionCatcher uorFinalCatcher;
    {CppCatch uorFinalCaught("class core::Exception",ExceptionHandler(uorFinalCatcher.handle));
        if(uorBeforeClean && ahPipeScopeAlive() && ahStatusUi is uorUi
            && ahGetCurrentProcessId()==48936 && ahGetCurrentThreadId()==8292
            && !uorRoot.isModified() && !uorUi.isModified()
            && ahCatalogSameV218(uorUi.getMDCont().unk,uorRoot.unk)){
            for(uint uorI=0;uorI<3;uorI++){
                IMDObject@ uorFresh=uorRoot.objById(Guid("{"+uorIds[uorI]+"}"));
                if(uorFresh is null || uorFresh.isModified() || uorObjects[uorI].isModified()
                    || !ahCatalogSameV218(uorFresh.unk,uorObjects[uorI].unk))break;uorAfterTargets++;
            }
            uorAfterClean=uorAfterTargets==3;
        }
    }
    ExceptionCatcher uorCleanupCatcher;
    {CppCatch uorCleanupCaught("class core::Exception",ExceptionHandler(uorCleanupCatcher.handle));
        @qcsUpdate=null;@qcsSave=null;@qcsReceiver=null;@uorTarget=null;@uorCore=null;@uorShell=null;
        for(uint uorI=0;uorI<3;uorI++)@uorObjects[uorI]=null;
        @uorRoot=null;@uorUi=null;uorCleanup=true;
    }
    if(uorCatcher.hasException || uorFinalCatcher.hasException || uorCleanupCatcher.hasException || !uorCleanup){
        uorUnknown=true;uorCandidate=false;uorStatus="UNKNOWN_RETAIN";uorReason="NATIVE_EXCEPTION_OR_CLEANUP";
    }else{
        uorUnknown=false;uorCandidate=uorCandidate && uorBeforeClean && uorAfterClean && uorPasses==2 && qcsQueries==2 && deiReady && deiAttempts==1 && deiReturned==1;
        uorStatus=uorCandidate?"DESIGNER_EVENTS_INITIALIZED_CLEAN":"DESIGNER_EVENTS_INITIALIZE_REFUSED";
        if(!uorAfterClean && uorReason=="NONE")uorReason="POST_ROOT_NOT_CLEAN";
    }
    string uorProof="{\"kind\":\"DESIGNER_EVENTS_INITIALIZE_NATIVE\",\"operationId\":\""+uorOperation+"\",\"scopeSha256\":\""+uorScope
        +"\",\"status\":\""+uorStatus+"\",\"reason\":\""+uorReason+"\",\"readOnly\":false,\"configurationReadOnly\":true"
        +",\"commandStatesReadVerified\":"+uorCandidate+",\"actualUpdate29OwnerVerified\":false,\"updateAdmissionGranted\":false"
        +",\"shellPointer\":"+uorShellPointer+",\"canonicalPointer\":"+uint(uorCanonical)+",\"targetPointer\":"+uorTargetPointer
        +",\"ownerPointer\":"+uint(uorOwner)+",\"delegatePointer\":"+uint(uorDelegate)+",\"mainEntryPointer\":"+uint(uorMainEntry)
        +",\"snapshotPasses\":"+uorPasses+",\"beforeTargetsClean\":"+uorBeforeTargets+",\"afterTargetsClean\":"+uorAfterTargets
        +",\"beforeRootAndTargetsClean\":"+uorBeforeClean+",\"afterRootAndTargetsClean\":"+uorAfterClean+",\"typedHandlesCleared\":"+uorCleanup
        +",\"publishedTypedQiAttempts\":"+uorQiAttempts+",\"publishedTypedQiReturned\":"+uorQiReturned+",\"nativeIntentWritten\":"+uorIntent
        +",\"unknownRetain\":"+uorUnknown+",\"nativeCalls\":0,\"directNativeFunctionCalls\":0,\"nativeCommandCalls\":0"
        +",\"enumerations\":0,\"manualReferenceCalls\":0,\"listProjections\":0,\"sourceWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0}";
    uorProof=uorProof.substr(0,uorProof.length-1)+",\"coreReceiverPointer\":"+qcsReceiverPointer+",\"statusQueries\":"+qcsQueries+",\"updateHandlerPresent\":"+qcsUpdatePresent
        +",\"updateEnabled\":"+qcsUpdateEnabled+",\"saveHandlerPresent\":"+qcsSavePresent+",\"saveEnabled\":"+qcsSaveEnabled
        +",\"eventConnectorAvailable\":"+qcsEvents+",\"messageBoxHandlersPresent\":"+qcsMessageHandlers+",\"modalHandlersPresent\":"+qcsModalHandlers+"}";
    uorProof=uorProof.substr(0,uorProof.length-1)+",\"runtimeConstructorAttempts\":"+deiAttempts+",\"runtimeConstructorReturned\":"+deiReturned
        +",\"runtimeWasAbsent\":"+deiBeforeAbsent+",\"runtimeReady\":"+deiReady+",\"registeredAddins\":"+deiAddins
        +",\"explicitExternalAddinLoads\":0}";
    ahWriteSample("__PROOF_PATH__",uorProof);
}
