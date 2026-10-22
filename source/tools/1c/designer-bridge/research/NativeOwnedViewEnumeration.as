// One NEW owned enumeration; historical b12 references are never adopted here.
void ahOwnedViewEnumeration() {
    bool oenAdmitted=__OWNED_VIEW_ENUM_SCOPE_ADMITTED__,oenIntent=false,oenBeforeClean=false,oenAfterClean=false;
    bool oenEnumReturned=false,oenVectorKnown=false,oenDrainReturned=false,oenUnknown=false,oenCounterRestored=false;
    uint oenEnumAttempts=0,oenSlots=0,oenNonNull=0,oenMatches=0,oenValidated=0,oenAdoptAttempts=0,oenReleased=0,oenCleared=0;
    uint oenBeforeCount=0,oenDuringCount=0,oenAfterCount=0,oenBeforeTargets=0,oenAfterTargets=0;
    string oenOperation="__OPERATION_ID__",oenScope="__SCOPE_SHA256__",oenStatus="REFUSED_BEFORE_ENUM",oenReason="SCOPE";
    int_ptr oenKnownView=572472988;
    IConfigMngrUI@ oenUi;IMDContainer@ oenRoot;ITopLevelFrame@ oenShell,oenCore;
    array<IMDObject@> oenObjects(3);
    array<string> oenIds={"8daef957-4ae2-48a1-bf6c-b88163a076f5","176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
    Vector oenViews;IUnknown@ oenHandle;ExceptionCatcher oenCatcher;
    {CppCatch oenCaught("class core::Exception",ExceptionHandler(oenCatcher.handle));
        do {
            if(!oenAdmitted || oenOperation.length!=32 || oenScope.length!=64 || sizeof_ptr!=4
                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211
                || ahStatusUi is null || !ahPipeScopeAlive())break;
            @oenUi=ahStatusUi;@oenRoot=oenUi.getMDCont();oenReason="ROOT";
            if(oenRoot is null || oenRoot.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
                || !ahCatalogEditableV218(oenRoot) || oenRoot.isModified() || oenUi.isModified())break;
            oenReason="TARGETS_CLEAN";
            for(uint oenI=0;oenI<3;oenI++){
                Guid oenId("{"+oenIds[oenI]+"}");IMDObject@ oenObject=oenRoot.objById(oenId);
                if(oenObject is null || oenObject.id!=oenId || oenObject.isModified())break;
                @oenObjects[oenI]=oenObject;oenBeforeTargets++;
            }
            if(oenBeforeTargets!=3)break;oenReason="CORE_FRAME";@oenShell=ahObservedMainFrameV211;
            // No fallback discovery: it might perform another owned enumeration.
            if(oenShell is null || oenShell.frameType()!=eTLFT_Main)break;oenShell.getCoreTopLevelFrame(oenCore);
            if(oenCore is null || !ahAccessLegacyLayoutV232(oenShell,oenCore)
                || !ahCompactTableV108(oenCore.self,"frame.dll",0xa69cd0,16)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[oenCore.self]+15*4],"frame.dll",0x8a6920))break;
            oenReason="KNOWN_VIEW_BASELINE";
            if(!ahCompactPageV108(oenKnownView,12) || !ahCompactTableV108(oenKnownView,"frntend.dll",0xc0e18c,3))break;
            array<uint> oenRefRvas={0x96446c,0x8ede40,0x9642a9};bool oenRefKnown=true;
            for(uint oenI=0;oenI<3;oenI++)if(!ahCompactAddressV108(mem::int_ptr[mem::int_ptr[oenKnownView]+oenI*4],"frntend.dll",oenRefRvas[oenI]))oenRefKnown=false;
            if(!oenRefKnown)break;oenBeforeCount=mem::dword[oenKnownView+8];if(oenBeforeCount!=10)break;
            if(!ahPipeScopeAlive() || ahStatusUi !is oenUi || oenRoot.isModified() || oenUi.isModified()
                || !ahCatalogSameV218(oenUi.getMDCont().unk,oenRoot.unk))break;
            oenBeforeClean=true;
            string oenRecord="{\"kind\":\"OWNED_VIEW_ENUMERATION_RESERVED\",\"operationId\":\""+oenOperation+"\",\"scopeSha256\":\""+oenScope
                +"\",\"maximumEnumerations\":1,\"newOwnedSlotsOnly\":true,\"historicalReferenceCleanupAuthorized\":false,\"referenceCountBefore\":"+oenBeforeCount
                +",\"readOnly\":false,\"configurationReadOnly\":true,\"runtimeCacheMutationPossible\":true,\"sourceWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0}";
            oenReason="DURABLE_NATIVE_INTENT";oenIntent=ahWriteSample("__NATIVE_ENUM_INTENT_PATH__",oenRecord);if(!oenIntent)break;
            // This call returns one counted reference per nonnull slot, not borrowed pointers.
            oenEnumAttempts=1;oenUnknown=true;oenStatus="UNKNOWN_RETAIN";oenReason="ENUM_CALL";
            oenCore.enumAllViews(oenViews);oenEnumReturned=true;
            uint64 oenStart=uint(oenViews.start),oenEnd=uint(oenViews.end),oenLimit=uint(oenViews.allocated);
            oenReason="OWNED_VECTOR_BOUNDS";
            if(oenStart<65536 || oenStart>oenEnd || oenEnd>oenLimit || oenEnd-oenStart>128*4 || oenLimit-oenStart>1048576
                || oenStart%4!=0 || oenEnd%4!=0 || oenLimit%4!=0 || !ahCompactPageV108(oenViews.start,uint(oenEnd-oenStart)))break;
            oenSlots=uint((oenEnd-oenStart)/4);oenReason="OWNED_POINTERS";
            for(int_ptr oenAt=oenViews.start;oenAt<oenViews.end;oenAt+=4){
                int_ptr oenPointer=mem::int_ptr[oenAt];
                if(oenPointer==0){oenValidated++;continue;}
                if(uint(oenPointer)<65536 || uint(oenPointer)%4!=0 || uint64(uint(oenPointer))+4>0x100000000 || !ahCompactPageV108(oenPointer,4))break;
                int_ptr oenTable=mem::int_ptr[oenPointer];if(uint(oenTable)<65536 || uint64(uint(oenTable))+12>0x100000000 || !ahCompactPageV108(oenTable,12))break;
                bool oenMethodsKnown=true;
                for(uint oenMethod=0;oenMethod<3;oenMethod++)if(!ahCompactPageV108(mem::int_ptr[oenTable+oenMethod*4],1))oenMethodsKnown=false;
                if(!oenMethodsKnown)break;
                oenNonNull++;if(oenPointer==oenKnownView)oenMatches++;oenValidated++;
            }
            if(oenValidated!=oenSlots)break;oenVectorKnown=true;
            if(ahCompactTableV108(oenKnownView,"frntend.dll",0xc0e18c,3) && ahCompactPageV108(oenKnownView,12))oenDuringCount=mem::dword[oenKnownView+8];
        }while(false);
    }
    // Drain ALL and ONLY this call's owned slots, including duplicate addresses.
    ExceptionCatcher oenDrainCatcher;
    {CppCatch oenDrainCaught("class core::Exception",ExceptionHandler(oenDrainCatcher.handle));
        if(oenEnumReturned && oenVectorKnown && !oenCatcher.hasException){
            for(int_ptr oenAt=oenViews.start;oenAt<oenViews.end;oenAt+=4){
                int_ptr oenPointer=mem::int_ptr[oenAt];
                if(oenPointer==0){oenCleared++;continue;}
                oenAdoptAttempts++;@oenHandle=toIUnknown(oenPointer);
                if(oenHandle is null || oenHandle.self!=oenPointer)break;
                @oenHandle=null;oenReleased++;
                // Clear only AFTER registered typed-handle Release has returned.
                mem::int_ptr[oenAt]=0;oenCleared++;
            }
            oenDrainReturned=oenCleared==oenSlots && oenReleased==oenNonNull;
        }
    }
    ExceptionCatcher oenFinalCatcher;
    {CppCatch oenFinalCaught("class core::Exception",ExceptionHandler(oenFinalCatcher.handle));
        if(oenDrainReturned && !oenDrainCatcher.hasException && oenHandle is null){
            oenReason="POST_DRAIN_BASELINE";
            if(ahCompactPageV108(oenKnownView,12) && ahCompactTableV108(oenKnownView,"frntend.dll",0xc0e18c,3)){
                oenAfterCount=mem::dword[oenKnownView+8];oenCounterRestored=oenAfterCount==oenBeforeCount;
            }
            if(ahPipeScopeAlive() && ahStatusUi is oenUi && !oenRoot.isModified() && !oenUi.isModified()
                && ahCatalogSameV218(oenUi.getMDCont().unk,oenRoot.unk)){
                for(uint oenI=0;oenI<3;oenI++){
                    Guid oenId("{"+oenIds[oenI]+"}");IMDObject@ oenFresh=oenRoot.objById(oenId);
                    if(oenFresh is null || oenFresh.isModified() || oenObjects[oenI].isModified()
                        || !ahCatalogSameV218(oenFresh.unk,oenObjects[oenI].unk))break;oenAfterTargets++;
                }
                oenAfterClean=oenAfterTargets==3;
            }
            if(oenCounterRestored && oenBeforeClean && oenAfterClean && oenMatches==1
                && oenDuringCount==oenBeforeCount+oenMatches && !oenCatcher.hasException){
                oenUnknown=false;oenStatus="OWNED_ENUM_DRAINED_CLEAN";oenReason="NONE";
            }
        }
    }
    if(oenCatcher.hasException || oenDrainCatcher.hasException || oenFinalCatcher.hasException){oenReason="NATIVE_EXCEPTION";if(oenEnumAttempts==1){oenUnknown=true;oenStatus="UNKNOWN_RETAIN";}}
    string oenProof="{\"kind\":\"OWNED_VIEW_ENUMERATION\",\"operationId\":\""+oenOperation+"\",\"scopeSha256\":\""+oenScope+"\",\"status\":\""+oenStatus+"\",\"reason\":\""+oenReason
        +"\",\"nativeIntentWritten\":"+oenIntent+",\"enumerationAttempts\":"+oenEnumAttempts+",\"enumCallReturned\":"+oenEnumReturned+",\"newOwnedSlots\":"+oenSlots+",\"nonNullSlots\":"+oenNonNull
        +",\"validatedSlots\":"+oenValidated+",\"matchedKnownView\":"+oenMatches+",\"adoptionAttempts\":"+oenAdoptAttempts+",\"releasedSlots\":"+oenReleased+",\"clearedSlots\":"+oenCleared+",\"drainReturned\":"+oenDrainReturned
        +",\"referenceCountBefore\":"+oenBeforeCount+",\"referenceCountDuringEnumeration\":"+oenDuringCount+",\"referenceCountAfter\":"+oenAfterCount+",\"counterRestored\":"+oenCounterRestored
        +",\"rootCleanBefore\":"+oenBeforeClean+",\"rootCleanAfter\":"+oenAfterClean+",\"targetsCleanBefore\":"+oenBeforeTargets+",\"targetsCleanAfter\":"+oenAfterTargets+",\"unknownRetained\":"+oenUnknown
        +",\"maximumEnumerations\":1,\"newOwnedSlotsOnly\":true,\"historicalReferenceCleanupAuthorized\":false,\"historicalReferencesRetained\":true,\"readOnly\":false,\"configurationReadOnly\":true,\"runtimeCacheMutationPossible\":true"
        +",\"explicitReferenceAcquireCalls\":0,\"explicitReferenceReleaseCalls\":0,\"commandDispatches\":0,\"sourceWrites\":0,\"metadataWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0"
        +",\"applicationTextOutputBytes\":0,\"comparisonCompletionVerified\":false,\"fullUuidPropertyDeltaVerified\":false,\"onlyOwnPendingVerified\":false,\"retryAuthorized\":false,\"retentionRequired\":true}";
    ExceptionCatcher oenOutput;
    {CppCatch oenOutputCaught("class core::Exception",ExceptionHandler(oenOutput.handle));if(oenProof.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",oenProof);}
}
