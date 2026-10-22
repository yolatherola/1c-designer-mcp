// Passive attribution of the exact primary createByClsid provider chain.
// Stable borrowed pages do not prove lifetime or permit any provider call.
void ahCurrentComparisonProviderObserve() {
    bool pvoAdmitted=__PROVIDER_SCOPE_ADMITTED__,pvoCoherent=false,pvoPresent=false,pvoNeedsFallback=false;
    string pvoOperation="__OPERATION_ID__",pvoScope="__SCOPE_SHA256__",pvoReason="OWNER",pvoStatus="REFUSED";
    string pvoTableType="null",pvoFactoryType="null",pvoSlotTypes="[]",pvoSnapshotSha="",pvoNullAt="";
    uint pvoPasses=0,pvoKnownProcessGetterCalls=0;array<uint> pvoFirst;SCOM_Process@ pvoProcess;
    ExceptionCatcher pvoCatcher;
    {CppCatch pvoCaught("class core::Exception",ExceptionHandler(pvoCatcher.handle));
        do {
            if(!pvoAdmitted || pvoOperation.length!=32 || pvoScope.length!=64 || sizeof_ptr!=4 || ahStatusUi is null || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            IConfigMngrUI@ pvoUi=ahStatusUi;IMDContainer@ pvoRoot=pvoUi.getMDCont();pvoReason="ROOT";
            if(pvoRoot is null || pvoRoot.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
                || !ahCatalogEditableV218(pvoRoot) || pvoRoot.isModified() || pvoUi.isModified())break;
            // The same published current_process getter used by the actual
            // factory shim supplies this receiver; no cached global alias.
            pvoKnownProcessGetterCalls++;@pvoProcess=currentProcess();if(pvoProcess is null)break;
            int_ptr pvoReceiver=mem::addressOf(pvoProcess);pvoReason="PROCESS_ABI";
            if(uint(pvoReceiver)<65536 || uint64(uint(pvoReceiver))+0x88>0x100000000
                || !ahCompactPageV108(pvoReceiver,0x88) || !ahCompactTableV108(pvoReceiver,"core83.dll",0x2d5120,15))break;
            int_ptr pvoProcessTable=mem::int_ptr[pvoReceiver];bool pvoKnown=true;
            array<uint> pvoProcessSlots={0x1e11c0,0x2ccf0,0x2ccf0,0x1585a0,0x158670,0x158600};
            for(uint pvoI=0;pvoI<6;pvoI++)if(!ahCompactAddressV108(mem::int_ptr[pvoProcessTable+pvoI*4],"core83.dll",pvoProcessSlots[pvoI]))pvoKnown=false;
            if(!pvoKnown)break;
            for(uint pvoPass=0;pvoPass<2;pvoPass++){
                pvoReason="PROCESS_CHANGED";
                if(!ahPipeScopeAlive() || !ahCompactPageV108(pvoReceiver,0x88) || mem::int_ptr[pvoReceiver]!=pvoProcessTable
                    || ahStatusUi !is pvoUi || pvoRoot.isModified() || pvoUi.isModified())break;
                int_ptr pvoContext=mem::int_ptr[pvoReceiver+0x84],pvoProvider=0,pvoInterface=0,pvoTable=0;
                string pvoObservedNull="PRIMARY_CONTEXT_NULL",pvoObservedType="null",pvoObservedFactory="null",pvoObservedSlots="[]";
                array<uint> pvoTargets(6,0);bool pvoObservedPresent=false;
                if(pvoContext!=0){
                    pvoReason="CONTEXT_PAGE";
                    if(uint(pvoContext)<65536 || uint64(uint(pvoContext))+0x18>0x100000000 || !ahCompactPageV108(pvoContext,0x18))break;
                    pvoProvider=mem::int_ptr[pvoContext+0x14];pvoObservedNull="PRIMARY_PROVIDER_NULL";
                    if(pvoProvider!=0){
                        pvoReason="PROVIDER_PAGE";
                        if(uint(pvoProvider)<65536 || uint64(uint(pvoProvider))+8>0x100000000 || !ahCompactPageV108(pvoProvider,8))break;
                        // +4 is an inline secondary-interface address, not a
                        // pointer to dereference and then advance again.
                        pvoInterface=int_ptr(uint(pvoProvider)+4);pvoTable=mem::int_ptr[pvoInterface];pvoObservedNull="PRIMARY_TABLE_NULL";
                        if(pvoTable!=0){
                            pvoReason="PROVIDER_TABLE_PAGE";
                            if(uint(pvoTable)<65536 || uint64(uint(pvoTable))+24>0x100000000 || !ahCompactPageV108(pvoTable,24))break;
                            pvoObservedType=ahRepoAddress(pvoTable);pvoObservedSlots="[";
                            for(uint pvoI=0;pvoI<6;pvoI++){
                                pvoTargets[pvoI]=mem::dword[pvoTable+pvoI*4];
                                pvoObservedSlots+=(pvoI==0?"":",")+ahRepoAddress(int_ptr(pvoTargets[pvoI]));
                                if(pvoI==5)pvoObservedFactory=ahRepoAddress(int_ptr(pvoTargets[pvoI]));
                            }
                            pvoObservedSlots+="]";pvoObservedPresent=true;pvoObservedNull="";
                        }
                    }
                }
                pvoReason="POINTER_CHANGED";
                if(!ahCompactPageV108(pvoReceiver,0x88) || mem::int_ptr[pvoReceiver]!=pvoProcessTable
                    || mem::int_ptr[pvoReceiver+0x84]!=pvoContext)break;
                if(pvoContext!=0 && (!ahCompactPageV108(pvoContext,0x18) || mem::int_ptr[pvoContext+0x14]!=pvoProvider))break;
                if(pvoProvider!=0 && (!ahCompactPageV108(pvoProvider,8) || mem::int_ptr[pvoInterface]!=pvoTable))break;
                if(pvoTable!=0){
                    if(!ahCompactPageV108(pvoTable,24))break;bool pvoTableStable=true;
                    for(uint pvoI=0;pvoI<6;pvoI++)if(mem::dword[pvoTable+pvoI*4]!=pvoTargets[pvoI])pvoTableStable=false;
                    if(!pvoTableStable)break;
                }
                array<uint> pvoSnapshot={uint(pvoReceiver),uint(pvoProcessTable),uint(pvoContext),uint(pvoProvider),uint(pvoInterface),uint(pvoTable)};
                for(uint pvoI=0;pvoI<6;pvoI++)pvoSnapshot.insertLast(pvoTargets[pvoI]);
                if(pvoPass==0)pvoFirst=pvoSnapshot;
                else{
                    if(pvoFirst.length!=pvoSnapshot.length)break;bool pvoSame=true;
                    for(uint pvoI=0;pvoI<pvoFirst.length;pvoI++)if(pvoFirst[pvoI]!=pvoSnapshot[pvoI])pvoSame=false;
                    if(!pvoSame)break;
                }
                // needsFallback requests further primary/fallback research;
                // it does not prove that native TLS fallback was taken.
                pvoPresent=pvoObservedPresent;pvoNeedsFallback=!pvoObservedPresent;pvoNullAt=pvoObservedNull;
                pvoTableType=pvoObservedType;pvoFactoryType=pvoObservedFactory;pvoSlotTypes=pvoObservedSlots;pvoPasses++;
            }
            if(pvoPasses!=2 || pvoRoot.isModified() || pvoUi.isModified() || !ahPipeScopeAlive() || ahStatusUi !is pvoUi
                || !ahCatalogSameV218(pvoUi.getMDCont().unk,pvoRoot.unk))break;
            pvoKnownProcessGetterCalls++;if(mem::addressOf(currentProcess())!=pvoReceiver)break;
            pvoReason="SNAPSHOT_HASH";uint pvoBytes=pvoFirst.length*4;
            if(pvoBytes!=48)break;MemoryBuffer pvoDigest(pvoBytes);
            if(pvoDigest.bytes==0 || pvoDigest._length!=pvoBytes)break;
            for(uint pvoI=0;pvoI<pvoFirst.length;pvoI++)mem::dword[pvoDigest.bytes+pvoI*4]=pvoFirst[pvoI];
            pvoSnapshotSha=ahTemplateRamShaV202(pvoDigest,pvoBytes);if(pvoSnapshotSha.length!=64)break;
            pvoCoherent=true;pvoStatus=pvoPresent?"PRIMARY_PROVIDER_OBSERVED":"PRIMARY_PROVIDER_ABSENT";pvoReason="NONE";
        }while(false);
    }
    if(pvoCatcher.hasException){pvoCoherent=false;pvoStatus="REFUSED";pvoReason="NATIVE_EXCEPTION";}
    string pvoProof="{\"kind\":\"CURRENT_COMPARISON_PROVIDER_OBSERVATION\",\"operationId\":\""+pvoOperation+"\",\"scopeSha256\":\""+pvoScope
        +"\",\"status\":\""+pvoStatus+"\",\"reason\":\""+pvoReason+"\",\"passes\":"+pvoPasses+",\"coherent\":"+pvoCoherent
        +",\"primaryProviderPresent\":"+pvoPresent+",\"needsFallback\":"+pvoNeedsFallback+",\"nullAt\":\""+pvoNullAt+"\",\"providerInterfaceType\":"+pvoTableType
        +",\"providerSlot5Type\":"+pvoFactoryType+",\"providerSlotTypes\":"+pvoSlotTypes+",\"snapshotSha256\":\""+pvoSnapshotSha
        +"\",\"knownCurrentProcessGetterCalls\":"+pvoKnownProcessGetterCalls+",\"secondaryInterfaceOffset\":4,\"secondaryInterfaceIsInline\":true"
        +",\"providerCalls\":0,\"unknownInterfaceQueries\":0,\"unknownReferenceCalls\":0,\"fallbackReads\":0,\"fallbackTakenVerified\":false,\"resultAcquired\":false"
        +",\"lifetimeVerified\":false,\"raceFreeLifetimeVerified\":false,\"providerCallable\":false,\"constructorTypeVerified\":false,\"fullUuidPropertyDeltaVerified\":false,\"onlyOwnPendingVerified\":false"
        +",\"applicationTextOutputBytes\":0,\"sourceWrites\":0,\"metadataWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"writerAuthorized\":false}";
    ExceptionCatcher pvoOutput;
    {CppCatch pvoOutputCaught("class core::Exception",ExceptionHandler(pvoOutput.handle));
        if(pvoProof.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",pvoProof);}
}
