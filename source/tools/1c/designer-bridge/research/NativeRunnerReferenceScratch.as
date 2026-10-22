// Creates ONLY two synthetic MemoryFiles. No metadata body/root/source reads.
// Each successful explicit AddRef leaves ONE root-owned native lease after the
// local typed handle is destroyed. Root must later release exactly those leases.
void ahRunnerReferenceScratch() {
    string operation="",proofPath="__PROOF_PATH__",reason="OWNER",rows="[";
    bool verified=false,intentWritten=false;uint created=0,retainAttempts=0,retains=0;
    array<IFileEx@> files(2);array<int_ptr> pointers(2,0),tables(2,0),addrefs(2,0),releases(2,0);
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            int operationAt=proofPath.find("designer-hot-v233-");if(operationAt<0)break;
            operation=proofPath.substr(operationAt+18,32);string hex="0123456789abcdef";bool operationOkay=operation.length==32;
            for(uint n=0;operationOkay && n<operation.length;n++)if(hex.find(operation.substr(n,1))<0)operationOkay=false;
            if(sizeof_ptr!=4 || !operationOkay || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            for(uint index=0;index<2;index++){
                reason="OWN_MEMORY_FILE";currentProcess().createByClsid(CLSID_MemoryFile,IID_IFileEx,files[index]);
                IFileEx@ file=files[index];IFile@ stream;if(file !is null)@stream=file.unk;
                if(file is null || stream is null || file.seek(0,fsEnd)!=0)break;
                MemoryBuffer marker(4);if(marker.bytes==0 || marker._length!=4)break;mem::dword[marker.bytes]=0x53465200+index;
                stream.write(marker.bytes,4);stream.flush();
                if(file.seek(0,fsEnd)!=4 || file.seek(0,fsBegin)!=0)break;
                MemoryBuffer readback(4);
                if(readback.bytes==0 || readback._length!=4)break;
                if(stream.read(readback.bytes,4)!=4 || mem::dword[readback.bytes]!=0x53465200+index)break;
                pointers[index]=file.self;reason="OWN_MEMORY_FILE_ABI";
                if(!ahCompactPageV108(file.self,4))break;tables[index]=mem::int_ptr[file.self];
                if(!ahCompactPageV108(tables[index],9*4))break;
                addrefs[index]=mem::int_ptr[tables[index]+4];releases[index]=mem::int_ptr[tables[index]+8];
                if(ahRepoAddress(tables[index])=="null" || ahRepoAddress(addrefs[index])=="null"
                    || ahRepoAddress(releases[index])=="null")break;
                created++;
            }
            if(created!=2 || pointers[0]==pointers[1] || tables[0]!=tables[1]
                || addrefs[0]!=addrefs[1] || releases[0]!=releases[1])break;
            string intent="{\"version\":1,\"kind\":\"SCRATCH_MEMORY_FILES_ONLY\",\"operationId\":\""+operation
                +"\",\"processId\":"+ahFrameOwnerPidV211+",\"threadId\":"+ahFrameOwnerTidV211
                +",\"checkpointPointer\":"+uint(pointers[0])+",\"documentPointer\":"+uint(pointers[1])
                +",\"retainsAttempted\":0,\"original249References\":0}";
            reason="OWNERSHIP_INTENT";utf8string intentBytes=intent.toUtf8();
            uint handle=CreateFile((proofPath+".intent.json").cstr,0x40000000,1,0,1,0x80000080,0);
            if(handle==0xffffffff)break;uint written=0;
            bool okay=WriteFile(handle,intentBytes.ptr,intentBytes.length,mem::addressOf(written),0)!=0;
            bool closed=CloseHandle(handle)!=0;if(!okay || !closed || written!=intentBytes.length)break;intentWritten=true;
            for(uint index=0;index<2;index++){
                reason="OWN_REFERENCE_RETAIN";retainAttempts++;files[index].AddRef();retains++;
            }
            for(uint index=0;index<2;index++){
                if(index!=0)rows+=",";
                rows+="{\"kind\":\"IFileEx\",\"pointer\":"+uint(pointers[index])+",\"tableAddress\":"+uint(tables[index])+",\"table\":"+ahRepoAddress(tables[index])
                    +",\"addRefTarget\":"+ahRepoAddress(addrefs[index])+",\"releaseTarget\":"+ahRepoAddress(releases[index])+"}";
            }
            verified=retains==2;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){verified=false;reason="NATIVE_EXCEPTION";}rows+="]";
    // Locals release only the factory/QI references. No explicit Release call
    // consumes the two newly retained root leases, even after a refused proof.
    string proof="{\"version\":1,\"kind\":\"SCRATCH_MEMORY_FILES_ONLY\",\"status\":\""+(verified?"SCRATCH_RETAINED":"UNKNOWN_RETAIN")
        +"\",\"reason\":\""+reason+"\",\"operationId\":\""+operation+"\",\"processId\":"+ahFrameOwnerPidV211
        +",\"threadId\":"+ahFrameOwnerTidV211+",\"created\":"+created+",\"retainAttempts\":"+retainAttempts
        +",\"retains\":"+retains+",\"ownershipIntentWritten\":"+intentWritten+",\"files\":"+rows
        +",\"original249References\":0,\"applicationWrites\":0,\"configurationSaves\":0,\"repositoryMutations\":0}";
    ExceptionCatcher proofCatch;
    {CppCatch caught("class core::Exception",ExceptionHandler(proofCatch.handle));
        if(proof.toUtf8().length<=4096)ahWriteSample(proofPath,proof);
    }
}
