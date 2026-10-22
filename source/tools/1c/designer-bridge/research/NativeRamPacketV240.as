// Readonly V237 RAM snapshot preflight. Allocation ownership/lifetime is the
// sealed transport's responsibility; page readability alone grants no authority.
void ahRamPacketV240() {
    string reason="OWNER",packetSha="",bodyHashes="[",digits="0123456789abcdef";
    string expectedSha="__PAYLOAD_SHA256__",operation="__OPERATION_ID__";
    uint64 requestedAddress=__PAYLOAD_ADDRESS__,requestedLength=__PAYLOAD_LENGTH__;
    uint packetBytes=0,copiedPages=0,parsedRecords=0,checkedBodies=0,utf8Bodies=0;
    bool packetValid=false,snapshotReady=false,wholeHashVerified=false;
    array<uint> starts(5,0),lengths(5,0),hashOffsets(5,0);
    array<uint> originalOffsets(2,0),replacementOffsets(2,0),originalLengths(2,0),replacementLengths(2,0);
    array<string> originalTexts(2),replacementTexts(2);
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(ahStatusUi is null || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();reason="ROOT";
            if(!ahCatalogEditableV218(root) || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}"))break;
            reason="PAYLOAD_BOUNDS";
            if(requestedLength<288 || requestedLength>4194304 || requestedAddress<65536
                || requestedAddress>0xffffffff || requestedAddress+requestedLength>0x100000000)break;
            reason="SEALED_METADATA";
            if(expectedSha.length!=64 || operation.length!=32)break;
            packetBytes=uint(requestedLength);MemoryBuffer packet(packetBytes);
            reason="SNAPSHOT_ALLOCATION";
            if(packet.bytes==0 || packet._length!=packetBytes)break;
            uint copied=0;reason="PAYLOAD_PAGE";
            while(copied<packetBytes){
                uint at=uint(requestedAddress+copied),chunk=4096-(at&4095);
                if(chunk>packetBytes-copied)chunk=packetBytes-copied;
                if(!ahCompactPageV108(int_ptr(at),chunk))break;
                mem::memcpy(packet.bytes+copied,int_ptr(at),chunk);copied+=chunk;copiedPages++;
            }
            if(copied!=packetBytes)break;snapshotReady=true;lengths[0]=packetBytes;
            // Existing V202 recipe caps input at256 KiB and rejects empty spans.
            // This identical uint32 compression streams synthetic padding so all
            // agreed V237 spans, including SHA256(empty), use no extra native ABI.
            array<uint> k={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
            for(uint job=0;job<5;job++){
                uint start=starts[job],count=lengths[job];reason="SPAN_BOUNDS";
                if(start>packetBytes || count>packetBytes-start || (job!=0 && count>1048576))break;
                if(job!=0){
                    // Canonical UTF8 scanner: second-byte restrictions exclude
                    // overlong sequences, UTF16 surrogates and values>U+10FFFF.
                    uint cursor=0;bool utf8=true;reason="BODY_UTF8";
                    while(cursor<count){
                        uint lead=mem::byte[packet.bytes+start+cursor];cursor++;
                        if(lead==0){utf8=false;break;}
                        if(lead<128)continue;
                        uint need=0,low=128,high=191;
                        if(lead>=194 && lead<=223)need=1;
                        else if(lead>=224 && lead<=239){need=2;if(lead==224)low=160;if(lead==237)high=159;}
                        else if(lead>=240 && lead<=244){need=3;if(lead==240)low=144;if(lead==244)high=143;}
                        else{utf8=false;break;}
                        if(need>count-cursor){utf8=false;break;}
                        uint second=mem::byte[packet.bytes+start+cursor];
                        if(second<low || second>high){utf8=false;break;}
                        for(uint continuation=1;continuation<need;continuation++){
                            uint b=mem::byte[packet.bytes+start+cursor+continuation];
                            if(b<128 || b>191){utf8=false;break;}
                        }
                        if(!utf8)break;cursor+=need;
                    }
                    if(!utf8)break;utf8Bodies++;
                }
                array<uint> hash={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
                uint padded=((count+72)/64)*64,bitCount=count*8;
                for(uint block=0;block<padded;block+=64){
                    array<uint> w(64,0);
                    for(uint i=0;i<16;i++)for(uint j=0;j<4;j++){
                        uint position=block+i*4+j,value=0;
                        if(position<count)value=mem::byte[packet.bytes+start+position];
                        else if(position==count)value=128;
                        else if(position>=padded-4)value=(bitCount>>(8*(padded-1-position)))&255;
                        w[i]=(w[i]<<8)|value;
                    }
                    for(uint i=16;i<64;i++){
                        uint x=w[i-15],y=w[i-2];
                        w[i]=w[i-16]+(ahTemplateRamRotateV202(x,7)^ahTemplateRamRotateV202(x,18)^(x>>3))
                            +w[i-7]+(ahTemplateRamRotateV202(y,17)^ahTemplateRamRotateV202(y,19)^(y>>10));
                    }
                    uint a=hash[0],b=hash[1],c=hash[2],d=hash[3],e=hash[4],f=hash[5],g=hash[6],h=hash[7];
                    for(uint i=0;i<64;i++){
                        uint t1=h+(ahTemplateRamRotateV202(e,6)^ahTemplateRamRotateV202(e,11)^ahTemplateRamRotateV202(e,25))
                            +((e&f)^((~e)&g))+k[i]+w[i];
                        uint t2=(ahTemplateRamRotateV202(a,2)^ahTemplateRamRotateV202(a,13)^ahTemplateRamRotateV202(a,22))
                            +((a&b)^(a&c)^(b&c));
                        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
                    }
                    hash[0]+=a;hash[1]+=b;hash[2]+=c;hash[3]+=d;hash[4]+=e;hash[5]+=f;hash[6]+=g;hash[7]+=h;
                }
                string digest="";for(uint i=0;i<8;i++)for(int j=7;j>=0;j--)digest+=digits.substr((hash[i]>>(j*4))&15,1);
                if(job!=0){
                    bool same=true;reason="BODY_HASH";
                    for(uint i=0;i<32;i++){
                        uint b=mem::byte[packet.bytes+hashOffsets[job]+i];
                        if(digest.substr(i*2,2)!=digits.substr(b>>4,1)+digits.substr(b&15,1)){same=false;break;}
                    }
                    if(!same)break;
                    // The pinned SDK conversion used by V107 is allowed only
                    // after canonical UTF8 and digest checks. No BOM removal,
                    // newline normalization or body output; exact roundtrip.
                    string decoded="";reason="BODY_ROUNDTRIP";
                    if(count!=0)decoded=string().fromUtf8(utf8string(packet.bytes+start,count));
                    utf8string back=decoded.toUtf8();same=back.length==count;
                    for(uint i=0;same && i<count;i++)same=mem::byte[back.ptr+i]==mem::byte[packet.bytes+start+i];
                    if(!same)break;
                    if((job&1)!=0)originalTexts[(job-1)/2]=decoded;else replacementTexts[(job-1)/2]=decoded;
                    if(checkedBodies!=0)bodyHashes+=",";bodyHashes+="\""+digest+"\"";checkedBodies++;
                    continue;
                }
                reason="PACKET_HASH";packetSha=digest;if(digest!=expectedSha)break;wholeHashVerified=true;
                // Nothing derived from the untrusted header is used before the
                // complete owned snapshot matches the sealed external digest.
                reason="MAGIC_VERSION";array<uint> magic={65,72,49,67,82,50,51,55};bool header=true;
                for(uint i=0;i<8;i++)if(mem::byte[packet.bytes+i]!=magic[i])header=false;
                if(!header || mem::dword[packet.bytes+8]!=237)break;
                reason="OPERATION";
                for(uint i=0;i<32;i++){
                    uint b=mem::byte[packet.bytes+12+i],index=0;
                    if(b>=48 && b<=57)index=b-48;else if(b>=97 && b<=102)index=b-87;else{header=false;break;}
                    if(operation.substr(i,1)!=digits.substr(index,1)){header=false;break;}
                }
                if(!header)break;
                Guid wireRoot,wireTemplate;mem::memcpy(wireRoot.self,packet.bytes+44,16);
                mem::memcpy(wireTemplate.self,packet.bytes+60,16);reason="HEADER_TARGET";
                if(wireRoot!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
                    || wireTemplate!=Guid("{8daef957-4ae2-48a1-bf6c-b88163a076f5}")
                    || mem::dword[packet.bytes+76]!=2)break;
                array<string> modules={"{176e2552-fd8b-4823-afc0-d17431f2fb7b}","{28ecdfc7-083e-4082-b272-efbf7152de5c}"};
                uint offset=80;
                for(uint record=0;record<2;record++){
                    reason="RECORD_BOUNDS";if(offset>packetBytes || packetBytes-offset<104)break;
                    Guid module,property;mem::memcpy(module.self,packet.bytes+offset,16);
                    mem::memcpy(property.self,packet.bytes+offset+16,16);reason="RECORD_TARGET";
                    if(module!=Guid(modules[record]) || property!=Guid("{d5963243-262e-4398-b4d7-fb16d06484f6}"))break;
                    uint original=mem::dword[packet.bytes+offset+32],replacement=mem::dword[packet.bytes+offset+36];
                    reason="BODY_BOUNDS";
                    if(original>1048576 || replacement>1048576)break;
                    uint content=offset+104,remaining=packetBytes-content;
                    if(original>remaining || replacement>remaining-original)break;
                    uint first=1+record*2;starts[first]=content;lengths[first]=original;hashOffsets[first]=offset+40;
                    starts[first+1]=content+original;lengths[first+1]=replacement;hashOffsets[first+1]=offset+72;
                    originalOffsets[record]=content;replacementOffsets[record]=content+original;
                    originalLengths[record]=original;replacementLengths[record]=replacement;
                    reason="UNCHANGED_MODULE";bool changed=original!=replacement;
                    if(!changed)for(uint i=0;i<original;i++)if(mem::byte[packet.bytes+content+i]
                        !=mem::byte[packet.bytes+content+original+i]){changed=true;break;}
                    if(!changed)break;
                    offset=content+original+replacement;parsedRecords++;
                }
                if(parsedRecords!=2)break;reason="TRAILING_BYTES";if(offset!=packetBytes)break;
            }
            if(!wholeHashVerified || parsedRecords!=2 || checkedBodies!=4 || utf8Bodies!=4)break;
            reason="ROOT_CHANGED";IMDContainer@ freshRoot=ui.getMDCont();
            if(!ahPipeScopeAlive() || ahStatusUi is null || ahStatusUi !is ui || !ahCatalogEditableV218(freshRoot)
                || !ahCatalogSameV218(freshRoot.unk,root.unk) || ahGetCurrentProcessId()!=ahFrameOwnerPidV211
                || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            packetValid=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){packetValid=false;reason="NATIVE_EXCEPTION";}bodyHashes+="]";
    string result="{\"version\":240,\"status\":\""+(packetValid?"VALIDATED":"REFUSED")+"\",\"reason\":\""+reason
        +"\",\"packetBytes\":"+packetBytes+",\"snapshotReady\":"+snapshotReady+",\"copiedPageChunks\":"+copiedPages
        +",\"wholeHashVerified\":"+wholeHashVerified+",\"packetSha256\":\""+packetSha+"\",\"parsedRecords\":"+parsedRecords
        +",\"checkedBodies\":"+checkedBodies+",\"utf8Bodies\":"+utf8Bodies+",\"bodySha256\":"+bodyHashes
        +",\"localMemoryOnly\":true,\"sourceWrites\":0,\"metadataWrites\":0,\"configurationSaves\":0"
        +",\"databaseUpdates\":0,\"repositoryMutations\":0,\"writerAuthorized\":false}";
    ExceptionCatcher proof;
    {CppCatch caught("class core::Exception",ExceptionHandler(proof.handle));if(result.toUtf8().length<=4096)ahWriteSample("__PROOF_PATH__",result);}
}
