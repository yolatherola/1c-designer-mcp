// NEW Compare30 epoch plus ONE owned enumeration. Historical references stay retained.
void ahFreshStockComparison() {
    bool fscAdmitted=__FRESH_STOCK_COMPARE_SCOPE_ADMITTED__,fscIntent=false,fscBeforeClean=false,fscAfterClean=false;
    bool fscCommandReturned=false,fscEnumReturned=false,fscVectorKnown=false,fscDrainReturned=false,fscUnknown=false;
    bool fscFreshBinding=false,fscCoherent=false,fscKnownState=false,fscOldCounterRestored=false,fscSelectedCounterBalanced=false;
    bool fscResultGuidNull=false,fscEngineGuidNull=false;
    uint fscCompareAttempts=0,fscEnumAttempts=0,fscSlots=0,fscNonNull=0,fscValidated=0,fscAdoptAttempts=0,fscReleased=0,fscCleared=0;
    uint fscBeforeTargets=0,fscAfterTargets=0,fscFreshCandidates=0,fscPasses=0;
    uint fscOldCountBefore=0,fscOldCountBeforeEnum=0,fscOldCountDuringEnum=0,fscOldMatchedSlots=0,fscOldCountAfter=0,fscSelectedCountDuring=0,fscSelectedCountAfter=0;
    uint fscCompletionFlag=0,fscSelectedObjects=0,fscVisitedObjects=0,fscEngineScope=255,fscTypeBypass=255,fscResourceBranch=255;
    string fscOperation="__OPERATION_ID__",fscScope="__SCOPE_SHA256__",fscStatus="REFUSED_BEFORE_COMPARE",fscReason="SCOPE",fscSnapshotSha="";
    int_ptr fscOldView=572472988,fscOldResult=0,fscSelectedView=0,fscSelectedResult=0,fscEngine=0,fscMainSource=0,fscDatabaseSource=0;
    uint fscRootKind=0,fscRootChange=0;bool fscRootChild=false,fscRootPayload=false;
    IConfigMngrUI@ fscUi;IMDContainer@ fscRoot;ITopLevelFrame@ fscShell,fscCore;ICommandReceiver@ fscReceiver;
    array<IMDObject@> fscObjects(3);
    array<string> fscIds={"8daef957-4ae2-48a1-bf6c-b88163a076f5","176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
    Vector fscViews;IUnknown@ fscHandle;ExceptionCatcher fscCatcher;
    {CppCatch fscCaught("class core::Exception",ExceptionHandler(fscCatcher.handle));
        do {
            if(!fscAdmitted || fscOperation.length!=32 || fscScope.length!=64 || sizeof_ptr!=4
                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211
                || ahStatusUi is null || !ahPipeScopeAlive())break;
            @fscUi=ahStatusUi;@fscRoot=fscUi.getMDCont();fscReason="ROOT";
            if(fscRoot is null || fscRoot.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
                || !ahCatalogEditableV218(fscRoot) || fscRoot.isModified() || fscUi.isModified())break;
            fscReason="TARGETS_CLEAN";
            for(uint fscI=0;fscI<3;fscI++){
                Guid fscId("{"+fscIds[fscI]+"}");IMDObject@ fscObject=fscRoot.objById(fscId);
                if(fscObject is null || fscObject.id!=fscId || fscObject.isModified())break;
                @fscObjects[fscI]=fscObject;fscBeforeTargets++;
            }
            if(fscBeforeTargets!=3)break;fscReason="CORE_RECEIVER";@fscShell=ahObservedMainFrameV211;
            if(fscShell is null || fscShell.frameType()!=eTLFT_Main)break;fscShell.getCoreTopLevelFrame(fscCore);
            if(fscCore is null || !ahAccessLegacyLayoutV232(fscShell,fscCore)
                || !ahCompactTableV108(fscCore.self,"frame.dll",0xa69cd0,16)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[fscCore.self]+15*4],"frame.dll",0x8a6920))break;
            fscCore.commandReceiver(fscReceiver);if(!ahAccessLegacyReceiverV232(fscReceiver))break;
            CommandID fscCommand(Guid("{F10CBB81-F679-11D4-9DD3-0050BAE2BC79}"),30);
            if(!fscReceiver.hasHandler(fscCommand))break;CommandState@ fscState=getCommandState(fscCommand,0,fscReceiver);
            if(fscState is null || !fscState.cmdState.bEnable)break;
            fscReason="OLD_RESULT_BASELINE";
            if(!ahCompactPageV108(fscOldView,0x50) || !ahCompactTableV108(fscOldView,"frntend.dll",0xc0e18c,3))break;
            array<uint> fscRefRvas={0x96446c,0x8ede40,0x9642a9};bool fscOldKnown=true;
            for(uint fscI=0;fscI<3;fscI++)if(!ahCompactAddressV108(mem::int_ptr[mem::int_ptr[fscOldView]+fscI*4],"frntend.dll",fscRefRvas[fscI]))fscOldKnown=false;
            if(!fscOldKnown)break;fscOldCountBefore=mem::dword[fscOldView+8];if(fscOldCountBefore!=10)break;
            fscOldResult=mem::int_ptr[fscOldView+0x4c];
            if(uint(fscOldResult)<65536 || uint64(uint(fscOldResult))+4>0x100000000 || !ahCompactPageV108(fscOldResult,4)
                || !ahCompactTableV108(fscOldResult,"frntend.dll",0xc0df98,12))break;
            if(!ahPipeScopeAlive() || ahStatusUi !is fscUi || fscRoot.isModified() || fscUi.isModified()
                || !ahCatalogSameV218(fscUi.getMDCont().unk,fscRoot.unk))break;fscBeforeClean=true;
            string fscReserved="{\"kind\":\"FRESH_STOCK_COMPARISON_RESERVED\",\"operationId\":\""+fscOperation+"\",\"scopeSha256\":\""+fscScope
                +"\",\"commandGroup\":\"f10cbb81-f679-11d4-9dd3-0050bae2bc79\",\"commandId\":30,\"subCommand\":0,\"stockCompareAuthorized\":true,\"maximumStockComparisons\":1,\"maximumEnumerations\":1,\"maximumOwnedSlots\":128"
                +",\"newOwnedSlotsOnly\":true,\"historicalReferenceCleanupAuthorized\":false,\"oldReferenceCountBefore\":"+fscOldCountBefore+",\"oldResultBeforePointer\":"+uint(fscOldResult)
                +",\"readOnly\":false,\"configurationReadOnly\":true,\"runtimeCacheMutationPossible\":true,\"runtimeUiMutationPossible\":true,\"sourceWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0}";
            fscReason="DURABLE_NATIVE_INTENT";fscIntent=ahWriteSample("__NATIVE_COMPARE_INTENT_PATH__",fscReserved);if(!fscIntent)break;
            // Root independently watches the whole Execute epoch. Return alone proves no clean epoch.
            fscCompareAttempts=1;fscUnknown=true;fscStatus="UNKNOWN_RETAIN";fscReason="COMPARE_CALL";
            fscReceiver.transmitCommand(Command(fscCommand,0));fscCommandReturned=true;
            // Compare may close/reuse the old UI view. Drain balances the post-command baseline.
            if(!ahCompactPageV108(fscOldView,12) || !ahCompactTableV108(fscOldView,"frntend.dll",0xc0e18c,3))break;
            fscOldCountBeforeEnum=mem::dword[fscOldView+8];if(fscOldCountBeforeEnum==0 || fscOldCountBeforeEnum>0x7ffffffe)break;
            fscEnumAttempts=1;fscReason="OWNED_ENUM_CALL";fscCore.enumAllViews(fscViews);fscEnumReturned=true;
            uint64 fscStart=uint(fscViews.start),fscEnd=uint(fscViews.end),fscLimit=uint(fscViews.allocated);
            if(fscStart<65536 || fscStart>fscEnd || fscEnd>fscLimit || fscEnd-fscStart>128*4 || fscLimit-fscStart>1048576
                || fscStart%4!=0 || fscEnd%4!=0 || fscLimit%4!=0 || !ahCompactPageV108(fscViews.start,uint(fscEnd-fscStart)))break;
            fscSlots=uint((fscEnd-fscStart)/4);fscReason="OWNED_POINTERS";
            for(int_ptr fscAt=fscViews.start;fscAt<fscViews.end;fscAt+=4){
                int_ptr fscPointer=mem::int_ptr[fscAt];if(fscPointer==0){fscValidated++;continue;}
                if(uint(fscPointer)<65536 || uint(fscPointer)%4!=0 || uint64(uint(fscPointer))+4>0x100000000 || !ahCompactPageV108(fscPointer,4))break;
                int_ptr fscTable=mem::int_ptr[fscPointer];if(uint(fscTable)<65536 || uint64(uint(fscTable))+12>0x100000000 || !ahCompactPageV108(fscTable,12))break;
                bool fscMethodsKnown=true;for(uint fscMethod=0;fscMethod<3;fscMethod++)if(!ahCompactPageV108(mem::int_ptr[fscTable+fscMethod*4],1))fscMethodsKnown=false;
                if(!fscMethodsKnown)break;fscNonNull++;if(fscPointer==fscOldView)fscOldMatchedSlots++;fscValidated++;
            }
            if(fscValidated!=fscSlots)break;fscVectorKnown=true;fscReason="FRESH_RESULT_SELECTION";
            if(ahCompactPageV108(fscOldView,12) && ahCompactTableV108(fscOldView,"frntend.dll",0xc0e18c,3))fscOldCountDuringEnum=mem::dword[fscOldView+8];
            for(int_ptr fscAt=fscViews.start;fscAt<fscViews.end;fscAt+=4){
                int_ptr fscPointer=mem::int_ptr[fscAt];if(fscPointer==0 || !ahCompactTableV108(fscPointer,"frntend.dll",0xc0e18c,3))continue;
                if(!ahCompactPageV108(fscPointer,0x50))continue;int_ptr fscResult=mem::int_ptr[fscPointer+0x4c];
                if(fscResult==fscOldResult || uint(fscResult)<65536 || uint64(uint(fscResult))+4>0x100000000 || !ahCompactPageV108(fscResult,4)
                    || !ahCompactTableV108(fscResult,"frntend.dll",0xc0df98,12))continue;
                fscFreshCandidates++;fscSelectedView=fscPointer;fscSelectedResult=fscResult;
            }
            if(fscFreshCandidates!=1){fscSelectedView=0;fscSelectedResult=0;break;}
            array<uint> fscFirst;
            array<uint> fscResultRvas={9845264,9549744,9845296,1272944,1275232,1275264,1275408,1275440,1275472,1275504,1277840,1277344};
            fscReason="FRESH_BINDING_OBSERVATION";
            for(uint fscPass=0;fscPass<2;fscPass++){
                if(uint64(uint(fscSelectedView))+0x50>0x100000000 || uint64(uint(fscSelectedResult))+0x330>0x100000000
                    || !ahCompactPageV108(fscSelectedView,0x50) || !ahCompactTableV108(fscSelectedView,"frntend.dll",0xc0e18c,3)
                    || mem::int_ptr[fscSelectedView+0x4c]!=fscSelectedResult || !ahCompactPageV108(fscSelectedResult,0x330)
                    || !ahCompactTableV108(fscSelectedResult,"frntend.dll",0xc0df98,12))break;
                int_ptr fscResultTable=mem::int_ptr[fscSelectedResult];fscEngine=mem::int_ptr[fscSelectedResult+0x210];
                if(uint(fscEngine)<65536 || uint64(uint(fscEngine))+0xe0>0x100000000 || !ahCompactPageV108(fscEngine,0xe0))break;
                array<uint> fscCurrent={uint(fscSelectedView),uint(fscSelectedResult),uint(fscResultTable),uint(fscEngine)};
                bool fscSnapshotKnown=true;
                for(uint fscI=0;fscI<12;fscI++){
                    int_ptr fscMethod=mem::int_ptr[fscResultTable+fscI*4];fscCurrent.insertLast(uint(fscMethod));
                    if(!ahCompactAddressV108(fscMethod,"frntend.dll",fscResultRvas[fscI]))fscSnapshotKnown=false;
                }
                for(uint fscI=0;fscI<9;fscI++)fscCurrent.insertLast(mem::dword[fscSelectedResult+0x1a0+fscI*4]);
                for(uint fscI=0;fscI<4;fscI++)fscCurrent.insertLast(mem::dword[fscSelectedResult+0x58+fscI*4]);
                for(uint fscI=0;fscI<4;fscI++)fscCurrent.insertLast(mem::dword[fscEngine+0xd0+fscI*4]);
                fscCurrent.insertLast(mem::byte[fscSelectedResult+0x274]);fscCurrent.insertLast(mem::dword[fscSelectedResult+0x298]);fscCurrent.insertLast(mem::dword[fscSelectedResult+0x29c]);
                fscCurrent.insertLast(mem::byte[fscSelectedResult+0x320]);fscCurrent.insertLast(mem::byte[fscSelectedResult+0x32c]);fscCurrent.insertLast(mem::byte[fscEngine+0xc8]);
                fscCurrent.insertLast(mem::dword[fscSelectedResult+0x34]);fscCurrent.insertLast(mem::dword[fscSelectedResult+0x38]);
                if(fscPass==0)fscFirst=fscCurrent;
                else{if(fscFirst.length!=fscCurrent.length)break;for(uint fscI=0;fscI<fscFirst.length;fscI++)if(fscFirst[fscI]!=fscCurrent[fscI])fscSnapshotKnown=false;}
                if(!fscSnapshotKnown || mem::int_ptr[fscSelectedView+0x4c]!=fscSelectedResult || mem::int_ptr[fscSelectedResult+0x210]!=fscEngine)break;
                fscPasses++;
            }
            if(fscPasses!=2 || fscFirst.length!=41)break;
            MemoryBuffer fscDigest(fscFirst.length*4);if(fscDigest.bytes==0 || fscDigest._length!=fscFirst.length*4)break;
            for(uint fscI=0;fscI<fscFirst.length;fscI++)mem::dword[fscDigest.bytes+fscI*4]=fscFirst[fscI];
            fscSnapshotSha=ahTemplateRamShaV202(fscDigest,fscFirst.length*4);if(fscSnapshotSha.length!=64)break;
            fscRootKind=(fscFirst[22]>>8)&255;fscRootChange=(fscFirst[22]>>16)&255;fscRootChild=fscFirst[17]!=0;fscRootPayload=fscFirst[21]!=0;
            fscResultGuidNull=true;for(uint fscI=25;fscI<29;fscI++)if(fscFirst[fscI]!=0)fscResultGuidNull=false;
            fscEngineGuidNull=true;for(uint fscI=29;fscI<33;fscI++)if(fscFirst[fscI]!=0)fscEngineGuidNull=false;
            fscCompletionFlag=fscFirst[33];fscSelectedObjects=fscFirst[34];fscVisitedObjects=fscFirst[35];
            fscResourceBranch=fscFirst[36];fscTypeBypass=fscFirst[37];fscEngineScope=fscFirst[38];fscMainSource=fscFirst[39];fscDatabaseSource=fscFirst[40];
            if(!ahCompactPageV108(fscSelectedView,12))break;fscSelectedCountDuring=mem::dword[fscSelectedView+8];
            fscFreshBinding=true;fscCoherent=true;
            fscKnownState=fscCompletionFlag==1 && fscSelectedObjects>0 && fscSelectedObjects==fscVisitedObjects
                && fscResultGuidNull && fscEngineGuidNull && fscEngineScope==0 && fscTypeBypass==0 && fscResourceBranch==0
                && fscMainSource!=0 && fscDatabaseSource!=0 && fscMainSource!=fscDatabaseSource;
        }while(false);
    }
    // Cleanup runs even when no/multiple fresh results or observation is unproven.
    ExceptionCatcher fscDrainCatcher;
    {CppCatch fscDrainCaught("class core::Exception",ExceptionHandler(fscDrainCatcher.handle));
        if(fscEnumReturned && fscVectorKnown && !fscCatcher.hasException){
            for(int_ptr fscAt=fscViews.start;fscAt<fscViews.end;fscAt+=4){
                int_ptr fscPointer=mem::int_ptr[fscAt];if(fscPointer==0){fscCleared++;continue;}
                fscAdoptAttempts++;@fscHandle=toIUnknown(fscPointer);if(fscHandle is null || fscHandle.self!=fscPointer)break;
                @fscHandle=null;fscReleased++;mem::int_ptr[fscAt]=0;fscCleared++;
            }
            fscDrainReturned=fscReleased==fscNonNull && fscCleared==fscSlots;
        }
    }
    ExceptionCatcher fscFinalCatcher;
    {CppCatch fscFinalCaught("class core::Exception",ExceptionHandler(fscFinalCatcher.handle));
        if(fscDrainReturned && !fscDrainCatcher.hasException && fscHandle is null){
            fscReason="POST_DRAIN_CLEAN";
            if(ahCompactPageV108(fscOldView,12) && ahCompactTableV108(fscOldView,"frntend.dll",0xc0e18c,3)){
                fscOldCountAfter=mem::dword[fscOldView+8];fscOldCounterRestored=fscOldCountAfter==fscOldCountBeforeEnum
                    && uint64(fscOldCountDuringEnum)==uint64(fscOldCountBeforeEnum)+fscOldMatchedSlots;
            }
            if(fscFreshBinding && ahCompactPageV108(fscSelectedView,0x50) && ahCompactTableV108(fscSelectedView,"frntend.dll",0xc0e18c,3)
                && mem::int_ptr[fscSelectedView+0x4c]==fscSelectedResult){
                fscSelectedCountAfter=mem::dword[fscSelectedView+8];
                fscSelectedCounterBalanced=fscSelectedCountDuring>=2 && fscSelectedCountAfter==fscSelectedCountDuring-1;
            }
            if(ahPipeScopeAlive() && ahStatusUi is fscUi && !fscRoot.isModified() && !fscUi.isModified()
                && ahCatalogSameV218(fscUi.getMDCont().unk,fscRoot.unk)){
                for(uint fscI=0;fscI<3;fscI++){
                    Guid fscId("{"+fscIds[fscI]+"}");IMDObject@ fscFresh=fscRoot.objById(fscId);
                    if(fscFresh is null || fscFresh.isModified() || fscObjects[fscI].isModified()
                        || !ahCatalogSameV218(fscFresh.unk,fscObjects[fscI].unk))break;fscAfterTargets++;
                }
                fscAfterClean=fscAfterTargets==3;
            }
            if(fscCommandReturned && fscBeforeClean && fscAfterClean && fscOldCounterRestored && !fscCatcher.hasException){
                if(fscFreshCandidates!=1){fscStatus="COMPARE_RETURNED_NO_FRESH_RESULT_CLEAN";fscUnknown=false;fscReason="NO_UNIQUE_FRESH_RESULT";}
                else if(fscFreshBinding && fscCoherent && fscKnownState && fscSelectedCounterBalanced){fscStatus="FRESH_COMPARE_OBSERVED_DRAINED_CLEAN";fscUnknown=false;fscReason="NONE";}
            }
        }
    }
    if(fscCatcher.hasException || fscDrainCatcher.hasException || fscFinalCatcher.hasException){fscReason="NATIVE_EXCEPTION";if(fscCompareAttempts==1){fscUnknown=true;fscStatus="UNKNOWN_RETAIN";}}
    string fscProof="{\"kind\":\"FRESH_STOCK_COMPARISON\",\"operationId\":\""+fscOperation+"\",\"scopeSha256\":\""+fscScope+"\",\"status\":\""+fscStatus+"\",\"reason\":\""+fscReason
        +"\",\"commandGroup\":\"f10cbb81-f679-11d4-9dd3-0050bae2bc79\",\"commandId\":30,\"subCommand\":0,\"stockCompareAuthorized\":"+fscAdmitted+",\"nativeIntentWritten\":"+fscIntent
        +",\"maximumStockComparisons\":1,\"maximumEnumerations\":1,\"maximumOwnedSlots\":128,\"compareAttempts\":"+fscCompareAttempts+",\"commandReturned\":"+fscCommandReturned+",\"enumerationAttempts\":"+fscEnumAttempts+",\"enumCallReturned\":"+fscEnumReturned
        +",\"newOwnedSlots\":"+fscSlots+",\"nonNullSlots\":"+fscNonNull+",\"validatedSlots\":"+fscValidated+",\"adoptionAttempts\":"+fscAdoptAttempts+",\"releasedSlots\":"+fscReleased+",\"clearedSlots\":"+fscCleared+",\"drainReturned\":"+fscDrainReturned
        +",\"freshCandidates\":"+fscFreshCandidates+",\"freshBindingVerified\":"+fscFreshBinding+",\"passes\":"+fscPasses+",\"coherent\":"+fscCoherent+",\"knownStateObserved\":"+fscKnownState+",\"bindingSnapshotSha256\":\""+fscSnapshotSha
        +"\",\"oldViewPointer\":"+uint(fscOldView)+",\"oldResultBeforePointer\":"+uint(fscOldResult)+",\"selectedViewPointer\":"+uint(fscSelectedView)+",\"selectedResultPointer\":"+uint(fscSelectedResult)
        +",\"oldReferenceCountBefore\":"+fscOldCountBefore+",\"oldReferenceCountBeforeEnumeration\":"+fscOldCountBeforeEnum+",\"oldReferenceCountDuringEnumeration\":"+fscOldCountDuringEnum+",\"matchedOldViewSlots\":"+fscOldMatchedSlots+",\"oldReferenceCountAfter\":"+fscOldCountAfter+",\"oldCounterRestored\":"+fscOldCounterRestored+",\"selectedReferenceCountDuring\":"+fscSelectedCountDuring+",\"selectedReferenceCountAfter\":"+fscSelectedCountAfter+",\"selectedCounterBalanced\":"+fscSelectedCounterBalanced
        +",\"completionFlag\":"+fscCompletionFlag+",\"selectedObjectCount\":"+fscSelectedObjects+",\"visitedObjectCount\":"+fscVisitedObjects+",\"resultScopeGuidNull\":"+fscResultGuidNull+",\"engineScopeGuidNull\":"+fscEngineGuidNull+",\"engineScopeEnabled\":"+fscEngineScope+",\"propertyTypeBypass\":"+fscTypeBypass+",\"resourceDetailBranch\":"+fscResourceBranch
        +",\"mainSourcePointer\":"+uint(fscMainSource)+",\"databaseSourcePointer\":"+uint(fscDatabaseSource)+",\"rootKind\":"+fscRootKind+",\"rootRawChangeCode\":"+fscRootChange+",\"rootChildPresent\":"+fscRootChild+",\"rootPayloadPresent\":"+fscRootPayload
        +",\"rootCleanBefore\":"+fscBeforeClean+",\"rootCleanAfter\":"+fscAfterClean+",\"targetsCleanBefore\":"+fscBeforeTargets+",\"targetsCleanAfter\":"+fscAfterTargets+",\"unknownRetained\":"+fscUnknown
        +",\"readOnly\":false,\"configurationReadOnly\":true,\"runtimeUiMutationPossible\":true,\"runtimeCacheMutationPossible\":true,\"newOwnedSlotsOnly\":true,\"historicalReferenceCleanupAuthorized\":false,\"historicalReferencesRetained\":true"
        +",\"explicitReferenceAcquireCalls\":0,\"explicitReferenceReleaseCalls\":0,\"explicitResultMethodCalls\":0,\"explicitResultQueries\":0,\"sourceWrites\":0,\"metadataWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"applicationTextOutputBytes\":0"
        +",\"nativeMainDbDirectionVerified\":false,\"completionEpochVerified\":false,\"comparisonCompletionVerified\":false,\"fullUuidPropertyDeltaVerified\":false,\"onlyOwnPendingVerified\":false,\"retryAuthorized\":false,\"retentionRequired\":true}";
    ExceptionCatcher fscOutput;
    {CppCatch fscOutputCaught("class core::Exception",ExceptionHandler(fscOutput.handle));if(fscProof.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",fscProof);}
}
