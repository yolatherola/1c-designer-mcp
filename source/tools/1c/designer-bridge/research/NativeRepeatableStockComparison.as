// TWO NEW owned vectors bracket one Compare30. Historical windows/references stay untouched.
void ahRepeatableStockComparison() {
    bool rscAdmitted=__REPEATABLE_STOCK_COMPARE_SCOPE_ADMITTED__,rscIntent=false,rscUnknown=false;
    bool rscBeforeClean=false,rscAfterClean=false,rscCommandReturned=false,rscPreSetKnown=false,rscAfterSetKnown=false;
    bool rscFreshBinding=false,rscCoherent=false,rscKnownState=false,rscSelectedCounterBalanced=false;
    bool rscResultGuidNull=false,rscEngineGuidNull=false;
    uint rscCompareAttempts=0,rscEnumAttempts=0,rscBeforeTargets=0,rscAfterTargets=0,rscFreshCandidates=0,rscPasses=0;
    uint rscPreResultCount=0,rscPreComparisonViews=0,rscNewResultCount=0,rscSelectedMatchedSlots=0;
    uint rscOldCountBefore=0,rscSelectedCountDuring=0,rscSelectedCountAfter=0;
    uint rscCompletionFlag=0,rscSelectedObjects=0,rscVisitedObjects=0,rscEngineScope=255,rscTypeBypass=255,rscResourceBranch=255;
    string rscOperation="__OPERATION_ID__",rscScope="__SCOPE_SHA256__",rscStatus="REFUSED_BEFORE_ENUM",rscReason="SCOPE",rscPhaseName="PRECHECK",rscSnapshotSha="";
    int_ptr rscOldView=572472988,rscOldResult=0,rscSelectedView=0,rscSelectedResult=0,rscEngine=0,rscMainSource=0,rscDatabaseSource=0;
    uint rscRootKind=0,rscRootChange=0;bool rscRootChild=false,rscRootPayload=false;
    array<bool> rscEnumReturned(2,false),rscHeaderKnown(2,false),rscVectorKnown(2,false),rscDrainReturned(2,false),rscCounterBalanced(2,false),rscCheckpointClean(2,false);
    array<uint> rscSlots(2,0),rscNonNull(2,0),rscValidated(2,0),rscAdoptAttempts(2,0),rscReleased(2,0),rscCleared(2,0);
    array<uint> rscOldBeforeEnum(2,0),rscOldDuringEnum(2,0),rscOldAfterDrain(2,0),rscOldMatchedSlots(2,0);
    array<uint> rscPreResults(128,0),rscNewResults(128,0),rscPointers(128,0);
    IConfigMngrUI@ rscUi;IMDContainer@ rscRoot;ITopLevelFrame@ rscShell,rscCore;ICommandReceiver@ rscReceiver;
    array<IMDObject@> rscObjects(3);
    array<string> rscIds={"8daef957-4ae2-48a1-bf6c-b88163a076f5","176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
    Vector rscBeforeViews,rscAfterViews;IUnknown@ rscHandle;ExceptionCatcher rscCatcher;
    {CppCatch rscCaught("class core::Exception",ExceptionHandler(rscCatcher.handle));
        do {
            if(!rscAdmitted || rscOperation.length!=32 || rscScope.length!=64 || sizeof_ptr!=4
                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211
                || ahStatusUi is null || !ahPipeScopeAlive())break;
            @rscUi=ahStatusUi;@rscRoot=rscUi.getMDCont();rscReason="ROOT";
            if(rscRoot is null || rscRoot.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
                || !ahCatalogEditableV218(rscRoot) || rscRoot.isModified() || rscUi.isModified())break;
            rscReason="TARGETS_CLEAN";
            for(uint rscI=0;rscI<3;rscI++){
                Guid rscId("{"+rscIds[rscI]+"}");IMDObject@ rscObject=rscRoot.objById(rscId);
                if(rscObject is null || rscObject.id!=rscId || rscObject.isModified())break;
                @rscObjects[rscI]=rscObject;rscBeforeTargets++;
            }
            if(rscBeforeTargets!=3)break;rscReason="CORE_RECEIVER";@rscShell=ahObservedMainFrameV211;
            if(rscShell is null || rscShell.frameType()!=eTLFT_Main)break;rscShell.getCoreTopLevelFrame(rscCore);
            if(rscCore is null || !ahAccessLegacyLayoutV232(rscShell,rscCore)
                || !ahCompactTableV108(rscCore.self,"frame.dll",0xa69cd0,16)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[rscCore.self]+15*4],"frame.dll",0x8a6920))break;
            rscCore.commandReceiver(rscReceiver);if(!ahAccessLegacyReceiverV232(rscReceiver))break;
            CommandID rscCommand(Guid("{F10CBB81-F679-11D4-9DD3-0050BAE2BC79}"),30);
            if(!rscReceiver.hasHandler(rscCommand))break;CommandState@ rscState=getCommandState(rscCommand,0,rscReceiver);
            if(rscState is null || !rscState.cmdState.bEnable)break;
            rscReason="OLD_RESULT_BASELINE";
            if(!ahCompactPageV108(rscOldView,0x50) || !ahCompactTableV108(rscOldView,"frntend.dll",0xc0e18c,3))break;
            array<uint> rscRefRvas={0x96446c,0x8ede40,0x9642a9};bool rscOldKnown=true;
            for(uint rscI=0;rscI<3;rscI++)if(!ahCompactAddressV108(mem::int_ptr[mem::int_ptr[rscOldView]+rscI*4],"frntend.dll",rscRefRvas[rscI]))rscOldKnown=false;
            if(!rscOldKnown)break;rscOldCountBefore=mem::dword[rscOldView+8];if(rscOldCountBefore!=10)break;
            rscOldResult=mem::int_ptr[rscOldView+0x4c];
            if(uint(rscOldResult)<65536 || uint64(uint(rscOldResult))+4>0x100000000 || !ahCompactPageV108(rscOldResult,4)
                || !ahCompactTableV108(rscOldResult,"frntend.dll",0xc0df98,12))break;
            if(!ahPipeScopeAlive() || ahStatusUi !is rscUi || rscRoot.isModified() || rscUi.isModified()
                || !ahCatalogSameV218(rscUi.getMDCont().unk,rscRoot.unk))break;rscBeforeClean=true;
            string rscReserved="{\"kind\":\"REPEATABLE_STOCK_COMPARISON_RESERVED\",\"operationId\":\""+rscOperation+"\",\"scopeSha256\":\""+rscScope
                +"\",\"commandGroup\":\"f10cbb81-f679-11d4-9dd3-0050bae2bc79\",\"commandId\":30,\"subCommand\":0,\"maximumStockComparisons\":1,\"maximumEnumerations\":2,\"maximumOwnedSlotsPerVector\":128,\"maximumPreexistingResults\":128"
                +",\"stockCompareAuthorized\":true,\"newOwnedSlotsOnly\":true,\"historicalReferenceCleanupAuthorized\":false,\"oldReferenceCountBefore\":"+rscOldCountBefore
                +",\"readOnly\":false,\"configurationReadOnly\":true,\"runtimeCacheMutationPossible\":true,\"runtimeUiMutationPossible\":true,\"sourceWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0}";
            rscReason="DURABLE_NATIVE_INTENT";rscIntent=ahWriteSample("__NATIVE_COMPARE_INTENT_PATH__",rscReserved);if(!rscIntent)break;
            for(uint rscPhase=0;rscPhase<2;rscPhase++){
                int_ptr rscStart=0,rscEnd=0,rscAllocated=0;
                rscPhaseName=rscPhase==0?"BEFORE_ENUM":"AFTER_ENUM";
                ExceptionCatcher rscScanCatcher;
                {CppCatch rscScanCaught("class core::Exception",ExceptionHandler(rscScanCatcher.handle));
                    do {
                        if(!ahCompactPageV108(rscOldView,12) || !ahCompactTableV108(rscOldView,"frntend.dll",0xc0e18c,3))break;
                        rscOldBeforeEnum[rscPhase]=mem::dword[rscOldView+8];
                        if(rscOldBeforeEnum[rscPhase]==0 || rscOldBeforeEnum[rscPhase]>0x7ffffffe
                            || (rscPhase==0 && rscOldBeforeEnum[0]!=10))break;
                        rscUnknown=true;rscStatus="UNKNOWN_RETAIN";rscEnumAttempts++;rscReason="OWNED_ENUM_CALL";
                        if(rscPhase==0){rscCore.enumAllViews(rscBeforeViews);rscStart=rscBeforeViews.start;rscEnd=rscBeforeViews.end;rscAllocated=rscBeforeViews.allocated;}
                        else{rscCore.enumAllViews(rscAfterViews);rscStart=rscAfterViews.start;rscEnd=rscAfterViews.end;rscAllocated=rscAfterViews.allocated;}
                        rscEnumReturned[rscPhase]=true;
                        uint64 rscA=uint(rscStart),rscB=uint(rscEnd),rscC=uint(rscAllocated);
                        if(rscA<65536 || rscA>rscB || rscB>rscC || rscB-rscA>128*4 || rscC-rscA>1048576
                            || rscA%4!=0 || rscB%4!=0 || rscC%4!=0 || !ahCompactPageV108(rscStart,uint(rscB-rscA)))break;
                        rscHeaderKnown[rscPhase]=true;rscSlots[rscPhase]=uint((rscB-rscA)/4);rscReason="OWNED_POINTERS";
                        for(uint rscIndex=0;rscIndex<rscSlots[rscPhase];rscIndex++){
                            int_ptr rscPointer=mem::int_ptr[rscStart+rscIndex*4];rscPointers[rscIndex]=uint(rscPointer);
                            if(rscPointer==0){rscValidated[rscPhase]++;continue;}
                            if(uint(rscPointer)<65536 || uint(rscPointer)%4!=0 || uint64(uint(rscPointer))+4>0x100000000 || !ahCompactPageV108(rscPointer,4))break;
                            int_ptr rscTable=mem::int_ptr[rscPointer];if(uint(rscTable)<65536 || uint64(uint(rscTable))+12>0x100000000 || !ahCompactPageV108(rscTable,12))break;
                            bool rscMethodsKnown=true;for(uint rscMethod=0;rscMethod<3;rscMethod++)if(!ahCompactPageV108(mem::int_ptr[rscTable+rscMethod*4],1))rscMethodsKnown=false;
                            if(!rscMethodsKnown)break;rscNonNull[rscPhase]++;if(rscPointer==rscOldView)rscOldMatchedSlots[rscPhase]++;rscValidated[rscPhase]++;
                        }
                        if(rscValidated[rscPhase]!=rscSlots[rscPhase])break;rscVectorKnown[rscPhase]=true;
                        rscOldDuringEnum[rscPhase]=mem::dword[rscOldView+8];rscReason="RESULT_SET_SELECTION";
                        bool rscResultsKnown=true;
                        for(uint rscIndex=0;rscIndex<rscSlots[rscPhase];rscIndex++){
                            int_ptr rscPointer=rscPointers[rscIndex];if(rscPointer==0 || !ahCompactTableV108(rscPointer,"frntend.dll",0xc0e18c,3))continue;
                            if(!ahCompactPageV108(rscPointer,0x50)){rscResultsKnown=false;break;}
                            int_ptr rscResult=mem::int_ptr[rscPointer+0x4c];
                            if(uint(rscResult)<65536 || uint64(uint(rscResult))+4>0x100000000 || !ahCompactPageV108(rscResult,4)
                                || !ahCompactTableV108(rscResult,"frntend.dll",0xc0df98,12)
                                || mem::int_ptr[rscPointer+0x4c]!=rscResult){rscResultsKnown=false;break;}
                            bool rscPreexisting=false;for(uint rscI=0;rscI<rscPreResultCount;rscI++)if(rscPreResults[rscI]==uint(rscResult))rscPreexisting=true;
                            if(rscPhase==0){rscPreComparisonViews++;if(!rscPreexisting){if(rscPreResultCount>=128){rscResultsKnown=false;break;}rscPreResults[rscPreResultCount++]=uint(rscResult);}}
                            else if(!rscPreexisting){
                                bool rscAlreadyNew=false;for(uint rscI=0;rscI<rscNewResultCount;rscI++)if(rscNewResults[rscI]==uint(rscResult))rscAlreadyNew=true;
                                if(!rscAlreadyNew){if(rscNewResultCount>=128){rscResultsKnown=false;break;}rscNewResults[rscNewResultCount++]=uint(rscResult);rscSelectedView=rscPointer;rscSelectedResult=rscResult;}
                            }
                        }
                        if(!rscResultsKnown)break;
                        if(rscPhase==0){
                            // A complete empty set is valid; retained old resources need not own an open window.
                            rscPreSetKnown=true;break;
                        }
                        rscAfterSetKnown=true;rscFreshCandidates=rscNewResultCount;
                        if(rscFreshCandidates!=1){rscSelectedView=0;rscSelectedResult=0;break;}
                        for(uint rscI=0;rscI<rscSlots[1];rscI++)if(rscPointers[rscI]==uint(rscSelectedView))rscSelectedMatchedSlots++;
                        if(rscSelectedMatchedSlots==0 || !ahCompactPageV108(rscSelectedView,12))break;
                        rscSelectedCountDuring=mem::dword[rscSelectedView+8];
            array<uint> rscFirst;
            array<uint> rscResultRvas={9845264,9549744,9845296,1272944,1275232,1275264,1275408,1275440,1275472,1275504,1277840,1277344};
            rscReason="FRESH_BINDING_OBSERVATION";
            for(uint rscPass=0;rscPass<2;rscPass++){
                if(uint64(uint(rscSelectedView))+0x50>0x100000000 || uint64(uint(rscSelectedResult))+0x330>0x100000000
                    || !ahCompactPageV108(rscSelectedView,0x50) || !ahCompactTableV108(rscSelectedView,"frntend.dll",0xc0e18c,3)
                    || mem::int_ptr[rscSelectedView+0x4c]!=rscSelectedResult || !ahCompactPageV108(rscSelectedResult,0x330)
                    || !ahCompactTableV108(rscSelectedResult,"frntend.dll",0xc0df98,12))break;
                int_ptr rscResultTable=mem::int_ptr[rscSelectedResult];rscEngine=mem::int_ptr[rscSelectedResult+0x210];
                if(uint(rscEngine)<65536 || uint64(uint(rscEngine))+0xe0>0x100000000 || !ahCompactPageV108(rscEngine,0xe0))break;
                array<uint> rscCurrent={uint(rscSelectedView),uint(rscSelectedResult),uint(rscResultTable),uint(rscEngine)};
                bool rscSnapshotKnown=true;
                for(uint rscI=0;rscI<12;rscI++){
                    int_ptr rscMethod=mem::int_ptr[rscResultTable+rscI*4];rscCurrent.insertLast(uint(rscMethod));
                    if(!ahCompactAddressV108(rscMethod,"frntend.dll",rscResultRvas[rscI]))rscSnapshotKnown=false;
                }
                for(uint rscI=0;rscI<9;rscI++)rscCurrent.insertLast(mem::dword[rscSelectedResult+0x1a0+rscI*4]);
                for(uint rscI=0;rscI<4;rscI++)rscCurrent.insertLast(mem::dword[rscSelectedResult+0x58+rscI*4]);
                for(uint rscI=0;rscI<4;rscI++)rscCurrent.insertLast(mem::dword[rscEngine+0xd0+rscI*4]);
                rscCurrent.insertLast(mem::byte[rscSelectedResult+0x274]);rscCurrent.insertLast(mem::dword[rscSelectedResult+0x298]);rscCurrent.insertLast(mem::dword[rscSelectedResult+0x29c]);
                rscCurrent.insertLast(mem::byte[rscSelectedResult+0x320]);rscCurrent.insertLast(mem::byte[rscSelectedResult+0x32c]);rscCurrent.insertLast(mem::byte[rscEngine+0xc8]);
                rscCurrent.insertLast(mem::dword[rscSelectedResult+0x34]);rscCurrent.insertLast(mem::dword[rscSelectedResult+0x38]);
                if(rscPass==0)rscFirst=rscCurrent;
                else{if(rscFirst.length!=rscCurrent.length)break;for(uint rscI=0;rscI<rscFirst.length;rscI++)if(rscFirst[rscI]!=rscCurrent[rscI])rscSnapshotKnown=false;}
                if(!rscSnapshotKnown || mem::int_ptr[rscSelectedView+0x4c]!=rscSelectedResult || mem::int_ptr[rscSelectedResult+0x210]!=rscEngine)break;
                rscPasses++;
            }
            if(rscPasses!=2 || rscFirst.length!=41)break;
            MemoryBuffer rscDigest(rscFirst.length*4);if(rscDigest.bytes==0 || rscDigest._length!=rscFirst.length*4)break;
            for(uint rscI=0;rscI<rscFirst.length;rscI++)mem::dword[rscDigest.bytes+rscI*4]=rscFirst[rscI];
            rscSnapshotSha=ahTemplateRamShaV202(rscDigest,rscFirst.length*4);if(rscSnapshotSha.length!=64)break;
            rscRootKind=(rscFirst[22]>>8)&255;rscRootChange=(rscFirst[22]>>16)&255;rscRootChild=rscFirst[17]!=0;rscRootPayload=rscFirst[21]!=0;
            rscResultGuidNull=true;for(uint rscI=25;rscI<29;rscI++)if(rscFirst[rscI]!=0)rscResultGuidNull=false;
            rscEngineGuidNull=true;for(uint rscI=29;rscI<33;rscI++)if(rscFirst[rscI]!=0)rscEngineGuidNull=false;
            rscCompletionFlag=rscFirst[33];rscSelectedObjects=rscFirst[34];rscVisitedObjects=rscFirst[35];
            rscResourceBranch=rscFirst[36];rscTypeBypass=rscFirst[37];rscEngineScope=rscFirst[38];rscMainSource=rscFirst[39];rscDatabaseSource=rscFirst[40];
            rscFreshBinding=true;rscCoherent=true;
            rscKnownState=rscCompletionFlag==1 && rscSelectedObjects>0 && rscSelectedObjects==rscVisitedObjects
                && rscResultGuidNull && rscEngineGuidNull && rscEngineScope==0 && rscTypeBypass==0 && rscResourceBranch==0
                && rscMainSource!=0 && rscDatabaseSource!=0 && rscMainSource!=rscDatabaseSource;
                    }while(false);
                }
                // A failed observation never suppresses cleanup of validated NEW slots.
                rscPhaseName=rscPhase==0?"BEFORE_DRAIN":"AFTER_DRAIN";ExceptionCatcher rscDrainCatcher;
                {CppCatch rscDrainCaught("class core::Exception",ExceptionHandler(rscDrainCatcher.handle));
                    if(rscEnumReturned[rscPhase] && rscHeaderKnown[rscPhase]){
                        for(uint rscIndex=0;rscIndex<rscValidated[rscPhase];rscIndex++){
                            int_ptr rscAt=rscStart+rscIndex*4,rscPointer=mem::int_ptr[rscAt];
                            if(uint(rscPointer)!=rscPointers[rscIndex])break;
                            if(rscPointer==0){rscCleared[rscPhase]++;continue;}
                            rscAdoptAttempts[rscPhase]++;@rscHandle=toIUnknown(rscPointer);if(rscHandle is null || rscHandle.self!=rscPointer)break;
                            @rscHandle=null;rscReleased[rscPhase]++;mem::int_ptr[rscAt]=0;rscCleared[rscPhase]++;
                        }
                        rscDrainReturned[rscPhase]=rscVectorKnown[rscPhase] && rscReleased[rscPhase]==rscNonNull[rscPhase]
                            && rscCleared[rscPhase]==rscSlots[rscPhase] && rscHandle is null;
                    }
                }
                if(rscDrainReturned[rscPhase] && !rscDrainCatcher.hasException && ahCompactPageV108(rscOldView,12)
                    && ahCompactTableV108(rscOldView,"frntend.dll",0xc0e18c,3)){
                    rscOldAfterDrain[rscPhase]=mem::dword[rscOldView+8];
                    rscCounterBalanced[rscPhase]=rscOldAfterDrain[rscPhase]==rscOldBeforeEnum[rscPhase]
                        && uint64(rscOldDuringEnum[rscPhase])==uint64(rscOldBeforeEnum[rscPhase])+rscOldMatchedSlots[rscPhase];
                }
                if(ahPipeScopeAlive() && ahStatusUi is rscUi && !rscRoot.isModified() && !rscUi.isModified()
                    && ahCatalogSameV218(rscUi.getMDCont().unk,rscRoot.unk)){
                    uint rscTargets=0;for(uint rscI=0;rscI<3;rscI++){
                        Guid rscId("{"+rscIds[rscI]+"}");IMDObject@ rscFresh=rscRoot.objById(rscId);
                        if(rscFresh is null || rscFresh.isModified() || rscObjects[rscI].isModified()
                            || !ahCatalogSameV218(rscFresh.unk,rscObjects[rscI].unk))break;rscTargets++;
                    }
                    rscCheckpointClean[rscPhase]=rscTargets==3;if(rscPhase==1){rscAfterTargets=rscTargets;rscAfterClean=rscTargets==3;}
                }
                if(rscScanCatcher.hasException || rscDrainCatcher.hasException){rscReason="NATIVE_EXCEPTION";break;}
                if(!rscDrainReturned[rscPhase] || !rscCounterBalanced[rscPhase] || !rscCheckpointClean[rscPhase]){rscReason="ENUM_DRAIN_OR_CLEAN_UNKNOWN";break;}
                if(rscPhase==0){
                    if(!rscPreSetKnown){rscStatus="BEFORE_ENUM_DRAINED_REFUSED";rscUnknown=false;rscReason="PRE_RESULT_SET_UNPROVEN";break;}
                    // No command can run until ALL first-vector owned references have drained.
                    rscPhaseName="COMPARE_CALL";rscCompareAttempts=1;rscUnknown=true;rscStatus="UNKNOWN_RETAIN";rscReason="COMPARE_CALL";
                    rscReceiver.transmitCommand(Command(rscCommand,0));rscCommandReturned=true;
                }else{
                    rscPhaseName="POST_DRAIN";
                    if(rscFreshBinding && ahCompactPageV108(rscSelectedView,0x50)
                        && ahCompactTableV108(rscSelectedView,"frntend.dll",0xc0e18c,3)
                        && mem::int_ptr[rscSelectedView+0x4c]==rscSelectedResult){
                        rscSelectedCountAfter=mem::dword[rscSelectedView+8];
                        rscSelectedCounterBalanced=rscSelectedCountDuring>rscSelectedMatchedSlots
                            && rscSelectedCountAfter==rscSelectedCountDuring-rscSelectedMatchedSlots;
                    }
                    if(rscCommandReturned && rscBeforeClean && rscAfterClean){
                        if(rscAfterSetKnown && rscFreshCandidates!=1){rscStatus="COMPARE_RETURNED_NO_FRESH_RESULT_CLEAN";rscUnknown=false;rscReason="NO_UNIQUE_FRESH_RESULT";}
                        else if(rscFreshBinding && rscCoherent && rscKnownState && rscSelectedCounterBalanced){
                            rscStatus="REPEATABLE_COMPARE_OBSERVED_DRAINED_CLEAN";rscUnknown=false;rscReason="NONE";
                        }
                    }
                }
            }
        }while(false);
    }
    if(rscCatcher.hasException){rscReason="NATIVE_EXCEPTION";if(rscEnumAttempts>0 || rscCompareAttempts>0){rscUnknown=true;rscStatus="UNKNOWN_RETAIN";}}
    string rscEnums="[";
    for(uint rscI=0;rscI<2;rscI++)rscEnums+=(rscI==0?"":",")+"{\"phase\":"+rscI+",\"callReturned\":"+rscEnumReturned[rscI]+",\"headerKnown\":"+rscHeaderKnown[rscI]
        +",\"vectorKnown\":"+rscVectorKnown[rscI]+",\"slots\":"+rscSlots[rscI]+",\"nonNullSlots\":"+rscNonNull[rscI]+",\"validatedSlots\":"+rscValidated[rscI]
        +",\"adoptionAttempts\":"+rscAdoptAttempts[rscI]+",\"releasedSlots\":"+rscReleased[rscI]+",\"clearedSlots\":"+rscCleared[rscI]+",\"drainReturned\":"+rscDrainReturned[rscI]
        +",\"oldCountBefore\":"+rscOldBeforeEnum[rscI]+",\"oldCountDuring\":"+rscOldDuringEnum[rscI]+",\"oldCountAfter\":"+rscOldAfterDrain[rscI]
        +",\"oldMatchedSlots\":"+rscOldMatchedSlots[rscI]+",\"counterBalanced\":"+rscCounterBalanced[rscI]+",\"rootTargetsClean\":"+rscCheckpointClean[rscI]+"}";
    rscEnums+="]";string rscPreSet="[";for(uint rscI=0;rscI<rscPreResultCount;rscI++)rscPreSet+=(rscI==0?"":",")+rscPreResults[rscI];rscPreSet+="]";
    string rscProof="{\"kind\":\"REPEATABLE_STOCK_COMPARISON\",\"operationId\":\""+rscOperation+"\",\"scopeSha256\":\""+rscScope+"\",\"status\":\""+rscStatus+"\",\"reason\":\""+rscReason
        +"\",\"phase\":\""+rscPhaseName+"\",\"commandGroup\":\"f10cbb81-f679-11d4-9dd3-0050bae2bc79\",\"commandId\":30,\"subCommand\":0,\"stockCompareAuthorized\":"+rscAdmitted+",\"nativeIntentWritten\":"+rscIntent
        +",\"maximumStockComparisons\":1,\"maximumEnumerations\":2,\"maximumOwnedSlotsPerVector\":128,\"maximumPreexistingResults\":128,\"compareAttempts\":"+rscCompareAttempts+",\"commandReturned\":"+rscCommandReturned+",\"enumerationAttempts\":"+rscEnumAttempts+",\"enumerations\":"+rscEnums
        +",\"preexistingResultSetVerified\":"+rscPreSetKnown+",\"afterResultSetVerified\":"+rscAfterSetKnown+",\"preexistingComparisonViews\":"+rscPreComparisonViews+",\"preexistingResultCount\":"+rscPreResultCount+",\"preexistingResultPointers\":"+rscPreSet
        +",\"freshCandidates\":"+rscFreshCandidates+",\"freshBindingVerified\":"+rscFreshBinding+",\"passes\":"+rscPasses+",\"coherent\":"+rscCoherent+",\"knownStateObserved\":"+rscKnownState+",\"bindingSnapshotSha256\":\""+rscSnapshotSha
        +"\",\"oldViewPointer\":"+uint(rscOldView)+",\"oldResultBeforePointer\":"+uint(rscOldResult)+",\"selectedViewPointer\":"+uint(rscSelectedView)+",\"selectedResultPointer\":"+uint(rscSelectedResult)
        +",\"oldReferenceCountBefore\":"+rscOldCountBefore+",\"selectedReferenceCountDuring\":"+rscSelectedCountDuring+",\"selectedReferenceCountAfter\":"+rscSelectedCountAfter+",\"selectedMatchedSlots\":"+rscSelectedMatchedSlots+",\"selectedCounterBalanced\":"+rscSelectedCounterBalanced
        +",\"completionFlag\":"+rscCompletionFlag+",\"selectedObjectCount\":"+rscSelectedObjects+",\"visitedObjectCount\":"+rscVisitedObjects+",\"resultScopeGuidNull\":"+rscResultGuidNull+",\"engineScopeGuidNull\":"+rscEngineGuidNull+",\"engineScopeEnabled\":"+rscEngineScope+",\"propertyTypeBypass\":"+rscTypeBypass+",\"resourceDetailBranch\":"+rscResourceBranch
        +",\"mainSourcePointer\":"+uint(rscMainSource)+",\"databaseSourcePointer\":"+uint(rscDatabaseSource)+",\"rootKind\":"+rscRootKind+",\"rootRawChangeCode\":"+rscRootChange+",\"rootChildPresent\":"+rscRootChild+",\"rootPayloadPresent\":"+rscRootPayload
        +",\"rootCleanBefore\":"+rscBeforeClean+",\"rootCleanAfter\":"+rscAfterClean+",\"targetsCleanBefore\":"+rscBeforeTargets+",\"targetsCleanAfter\":"+rscAfterTargets+",\"unknownRetained\":"+rscUnknown
        +",\"readOnly\":false,\"configurationReadOnly\":true,\"runtimeUiMutationPossible\":true,\"runtimeCacheMutationPossible\":true,\"newOwnedSlotsOnly\":true,\"historicalReferenceCleanupAuthorized\":false,\"historicalReferencesRetained\":true"
        +",\"explicitReferenceAcquireCalls\":0,\"explicitReferenceReleaseCalls\":0,\"explicitResultMethodCalls\":0,\"explicitResultQueries\":0,\"sourceWrites\":0,\"metadataWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"applicationTextOutputBytes\":0"
        +",\"nativeMainDbDirectionVerified\":false,\"completionEpochVerified\":false,\"comparisonCompletionVerified\":false,\"fullUuidPropertyDeltaVerified\":false,\"onlyOwnPendingVerified\":false,\"retryAuthorized\":false,\"retentionRequired\":true}";
    ExceptionCatcher rscOutput;
    {CppCatch rscOutputCaught("class core::Exception",ExceptionHandler(rscOutput.handle));if(rscProof.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",rscProof);}
}
