// Fixed saved-resource fingerprint. Application bytes stay in bounded RAM.
// Source fields and detached template bodies stay in RAM; no payload export or configuration Save.
void ahSavedResourceFingerprintV264() {
    string reason="OWNER",rows="[",managerTable="null",innerTable="null",sourceTable="null",targetTable="null",getterCode="null";
    bool verified=false,storageKnown=false;uint passes=0,propertyReads=0,urlReads=0;
    uint fileOpens=0,adoptedFiles=0,plainReads=0,resourcesRead=0;
    bool pendingFileReference=false,getterInitialized=false;
    array<uint> plainLengths(3,0);array<string> plainHashes(3,""),profiles(3,""),codeMatches(3,"");
    array<bool> utf8Flags(3,false),bomFlags(3,false),lfFlags(3,false);array<uint> crlfCounts(3,0);

    uint moduleDecodedPasses=0,storageOpens=0,coldLoads=0,coldSnapshots=0,templateComparisons=0;
    string templateCanonicalHash="";
    array<uint> textLengths(3,0),textCrlfCounts(3,0);array<string> textHashes(3,""),lfHashes(3,""),textMatches(3,"");
    array<bool> textBom(3,false),textLf(3,false);
    array<string> ids={"8daef957-4ae2-48a1-bf6c-b88163a076f5","176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
    array<string> keys(3,"");array<uint> keyCharacters(3,0),urlCodes(6,0);array<int> propertyCodes(6,0);
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(ahStatusUi is null || !ahPipeScopeAlive() || ahGetCurrentProcessId()!=ahFrameOwnerPidV211
                || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();reason="ROOT";
            if(!ahCatalogEditableV218(root) || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
                || root.isModified() || ui.isModified())break;
            // Published SDK return is @+: this counted manager keeps its
            // owning source/target filesystem fields alive in this callback.
            IConfigMngr@ manager=root.getConfigMngr();reason="MANAGER";if(manager is null)break;
            int_ptr managerAddress=mem::addressOf(manager),firstInner=0,firstSource=0,firstTarget=0,firstGetter=0;
            array<IMDObject@> objects(3),parents(3);
            for(uint pass=0;pass<2;pass++){
                reason="FRAME_CHANGED";
                if(ahStatusUi !is ui || !ahPipeScopeAlive() || ahGetCurrentProcessId()!=ahFrameOwnerPidV211
                    || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
                IMDContainer@ freshRoot=ui.getMDCont();reason="ROOT_CHANGED";
                if(freshRoot is null || !ahCatalogSameV218(freshRoot.unk,root.unk) || root.isModified() || ui.isModified())break;
                IConfigMngr@ freshManager=freshRoot.getConfigMngr();reason="MANAGER_CHANGED";
                if(freshManager is null || !ahCatalogSameV218(freshManager.unk,manager.unk)
                    || mem::addressOf(freshManager)!=managerAddress)break;
                reason="MANAGER_PAGE";if(!ahCompactPageV108(managerAddress,0xd0))break;
                managerTable=ahRepoAddress(mem::int_ptr[managerAddress]);reason="MANAGER_ABI";
                if(!ahCompactTableV108(managerAddress,"backend.dll",15589540,86))break;
                int_ptr inner=mem::int_ptr[managerAddress+0xcc];reason="INNER_PAGE";
                if(!ahCompactPageV108(inner,0x174))break;
                innerTable=ahRepoAddress(mem::int_ptr[inner]);reason="INNER_ABI";
                if(!ahCompactTableV108(inner,"backend.dll",15029196,43))break;
                int_ptr source=mem::int_ptr[inner+0x16c],target=mem::int_ptr[inner+0x170];reason="FILESYSTEM_SCOPE";
                if(source==0 || target==0 || source==target)break;
                reason="SOURCE_PAGE";if(!ahCompactTableV108(source,"backend.dll",15576968,5)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[source]+4*4],"backend.dll",2573152))break;
                int_ptr sourceVtable=mem::int_ptr[source];if(!ahCompactPageV108(sourceVtable,8*4))break;
                sourceTable=ahRepoAddress(sourceVtable);reason="TARGET_PAGE";
                if(!ahCompactPageV108(target,4))break;
                targetTable=ahRepoAddress(mem::int_ptr[target]);reason="TARGET_ABI";
                if(!ahCompactTableV108(target,"backend.dll",15576968,5))break;
                int_ptr getter=mem::int_ptr[mem::int_ptr[managerAddress]+79*4];getterCode=ahRepoAddress(getter);reason="GETTER_ABI";
                if(!ahCompactAddressV108(getter,"backend.dll",2788960)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[inner]+15*4],"backend.dll",217376)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[target]+4*4],"backend.dll",2573152))break;
                // Layered manager79 is stdcall(self,smart IFileEx*,URL*,
                // nullable IUnknown provider), ret16. Provider0 selects no callback.
                reason="FILESYSTEM_CHANGED";
                if(pass==0){firstInner=inner;firstSource=source;firstTarget=target;firstGetter=getter;}
                else if(inner!=firstInner || source!=firstSource || target!=firstTarget || getter!=firstGetter)break;
                uint mapped=0;
                for(uint index=0;index<3;index++){
                    Guid targetId("{"+ids[index]+"}");
                    Guid property(index==0?"{8eb4fad1-1fa6-403e-970f-2c12dbb43e23}":"{d5963243-262e-4398-b4d7-fb16d06484f6}");
                    IMDObject@ object=root.objById(targetId);reason="OBJECT";
                    if(object is null || object.id!=targetId || object.mdClass is null || object.mdParentLink is null || object.isModified())break;
                    IMDObject@ parent=object.mdParentLink.getMDObject();reason="PARENT";
                    if(parent is null || parent.id!=(index==0?Guid("{686a3dbe-be94-45e7-9e8b-dd93f0cd579c}"):root.id)
                        || parent.isModified() || !ahCatalogLinkV218(object,parent,root))break;
                    if(pass==0){@objects[index]=object;@parents[index]=parent;}
                    else if(!ahCatalogSameV218(object.unk,objects[index].unk) || !ahCatalogSameV218(parent.unk,parents[index].unk))break;
                    reason="PROPERTY";
                    if(index==0){
                        if(object.mdClass.id!=Guid("{3daea016-69b7-4ed4-9453-127911372fe6}"))break;
                        IMDEditService@ service=getMDEditService();IMDEditHelper@ helper;
                        if(service is null)break;service.getEditHelper(helper,object);
                        if(helper is null || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                            || helper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))break;
                    }else{
                        string name;if(!ahModulePropertyV225(object,property,name) || name!="Module")break;
                    }
                    Value value;reason="PROPERTY_VALUE";propertyReads++;
                    uint sample=pass*3+index;propertyCodes[sample]=object.mdPropVal(property,value);
                    if(value.pValue is null)break;
                    IMDExtObj@ external=value.pValue.unk;reason="EXTERNAL_VALUE_INTERFACE";if(external is null)break;
                    URL url;reason="PROPERTY_URL";urlReads++;urlCodes[sample]=external.url(url);
                    string key=url.url;keyCharacters[index]=key.length;reason="URL_SHAPE";
                    if(key.length<36 || key.length>45 || !ahModuleUuidV225(key.substr(0,36).lowered()))break;
                    bool shape=true;
                    if(key.length>36){
                        if(key.length<38 || key[36]!=46)shape=false;
                        for(uint i=37;shape && i<key.length;i++)if(key[i]<48 || key[i]>57)shape=false;
                    }
                    if(!shape)break;reason="URL_CHANGED";
                    if(pass==0)keys[index]=key;
                    else if(key!=keys[index] || propertyCodes[sample]!=propertyCodes[index] || urlCodes[sample]!=urlCodes[index])break;
                    reason="TARGET_CHANGED";
                    if(object.isModified() || parent.isModified() || root.isModified() || ui.isModified())break;
                    mapped++;
                }
                if(mapped!=3)break;
                reason="FILESYSTEM_AFTER_CHANGED";
                if(!ahCompactPageV108(managerAddress,0xd0) || !ahCompactPageV108(inner,0x174)
                    || mem::int_ptr[managerAddress+0xcc]!=inner || mem::int_ptr[inner+0x16c]!=source
                    || mem::int_ptr[inner+0x170]!=target || !ahCompactTableV108(target,"backend.dll",15576968,5)
                    || mem::int_ptr[mem::int_ptr[managerAddress]+79*4]!=getter
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[inner]+15*4],"backend.dll",217376)
                    || root.isModified() || ui.isModified())break;
                passes++;
            }
            if(passes!=2)break;storageKnown=true;
            // The sole existing global adapter has the exact proven getter ABI.
            // Never register an already initialized address/type a second time.
            reason="SAVED_GETTER";
            if(ahGMResourceGetterV107 is null){
                initFuncDefFromAddress(firstGetter,@ahGMResourceGetterV107,asCALL_STDCALL);getterInitialized=true;
            }
            if(ahGMResourceGetterV107 is null)break;
            for(uint index=0;index<3;index++){
                uint readPasses=0;
                for(uint pass=0;pass<2;pass++){
                    reason="SAVED_STORAGE_CHANGED";
                    if(!ahCompactPageV108(managerAddress,0xd0) || !ahCompactPageV108(firstInner,0x174)
                        || mem::int_ptr[managerAddress+0xcc]!=firstInner || mem::int_ptr[firstInner+0x170]!=firstTarget
                        || mem::int_ptr[firstInner+0x16c]!=firstSource
                        || !ahCompactTableV108(managerAddress,"backend.dll",15589540,86)
                        || !ahCompactTableV108(firstInner,"backend.dll",15029196,43)
                        || !ahCompactTableV108(firstSource,"backend.dll",15576968,5)
                        || !ahCompactTableV108(firstTarget,"backend.dll",15576968,5)
                        || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[firstSource]+4*4],"backend.dll",2573152)
                        || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[firstTarget]+4*4],"backend.dll",2573152)
                        || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[firstInner]+15*4],"backend.dll",217376)
                        || mem::int_ptr[mem::int_ptr[managerAddress]+79*4]!=firstGetter)break;
                    MemoryBuffer output(36);for(uint n=0;n<36;n++)mem::byte[output.bytes+n]=0xa5;
                    mem::int_ptr[output.bytes+16]=0;v8string name=keys[index];URL filename(name);
                    reason="SAVED_OPEN";pendingFileReference=true;fileOpens++;
                    int_ptr returned=ahGMResourceGetterV107(managerAddress,output.bytes+16,filename.self,0);
                    bool canaries=true;
                    for(uint n=0;n<16;n++)if(mem::byte[output.bytes+n]!=0xa5 || mem::byte[output.bytes+20+n]!=0xa5)canaries=false;
                    reason="SAVED_OUTPUT_CANARY";if(!canaries)break;
                    reason="SAVED_RETURN_ADDRESS";if(returned!=output.bytes+16)break;
                    int_ptr address=mem::int_ptr[output.bytes+16];reason="SAVED_MISSING";
                    if(address==0){pendingFileReference=false;break;}
                    // Getter returns one owned smart reference. Adoption consumes
                    // that reference, not a borrowed filesystem/metadata pointer.
                    IUnknown@ pin=toIUnknown(address);pendingFileReference=false;adoptedFiles++;
                    mem::int_ptr[output.bytes+16]=0;IFileEx@ file=pin;reason="SAVED_FILE_INTERFACE";
                    if(file is null)break;
                    uint64 plainSize=file.seek(0,fsEnd);reason="SAVED_PLAIN_BOUND";
                    if(plainSize==0 || plainSize>262144 || file.seek(0,fsBegin)!=0)break;
                    uint total=uint(plainSize);MemoryBuffer expanded(total);reason="SAVED_PLAIN_READ";plainReads++;
                    if(file.read(expanded.bytes,total)!=total || file.seek(0,fsCurrent)!=plainSize)break;
                    // Manager79 already resolves base/delta and returns its plain
                    // resource stream. A second inflate would corrupt this route.
                    string expandedHash=ahTemplateRamShaV202(expanded,total);if(expandedHash.length!=64)break;
                    string profile="UNRECOGNIZED";
                    if(total>=16 && mem::dword[expanded.bytes]==0x7fffffff && mem::dword[expanded.bytes+4]==512
                        && (mem::dword[expanded.bytes+8]==1 || mem::dword[expanded.bytes+8]==2)
                        && mem::dword[expanded.bytes+12]==0)profile="FORMAT15_HEADER_ONLY";
                    bool utf8=true;uint cursor=0,crlf=0;
                    for(uint n=0;n+1<total;n++)if(mem::byte[expanded.bytes+n]==13 && mem::byte[expanded.bytes+n+1]==10)crlf++;
                    while(cursor<total){
                        uint lead=mem::byte[expanded.bytes+cursor];cursor++;
                        if(lead<128)continue;
                        uint need=0,low=128,high=191;
                        if(lead>=194 && lead<=223)need=1;
                        else if(lead>=224 && lead<=239){need=2;if(lead==224)low=160;if(lead==237)high=159;}
                        else if(lead>=240 && lead<=244){need=3;if(lead==240)low=144;if(lead==244)high=143;}
                        else{utf8=false;break;}
                        if(need>total-cursor){utf8=false;break;}
                        uint second=mem::byte[expanded.bytes+cursor];if(second<low || second>high){utf8=false;break;}
                        for(uint n=1;n<need;n++){uint value=mem::byte[expanded.bytes+cursor+n];if(value<128 || value>191){utf8=false;break;}}
                        if(!utf8)break;cursor+=need;
                    }
                    if(profile=="UNRECOGNIZED" && utf8)profile="UTF8_UNCONFIRMED_SCHEMA";
                    bool bom=total>=3 && mem::byte[expanded.bytes]==239 && mem::byte[expanded.bytes+1]==187 && mem::byte[expanded.bytes+2]==191;
                    bool lf=mem::byte[expanded.bytes+total-1]==10;
                    string codeMatch="UNCONFIRMED_FORMAT";
                    if(index==1 && utf8){
                        if(expandedHash=="506fe9bd7d1ade475a54dd4bfabb22f82d91a634b2477f44fdcc38b96f9417b6")codeMatch="ORIGINAL_EXACT_UTF8_BYTES";
                        else if(expandedHash=="90939ff38be12b52740f27153455e711b145086ee1aacb6e906eb897556f381a")codeMatch="CANDIDATE_EXACT_UTF8_BYTES";
                    }else if(index==2 && utf8){
                        if(expandedHash=="c5b596a38e554aa34e1e1adba527e45db35516b8e72772c6724645ed481b81ba")codeMatch="ORIGINAL_EXACT_UTF8_BYTES";
                        else if(expandedHash=="f64720f5118b2eaba03197f3de83a3ee93a68738e7177751fcd92cbb618e224a")codeMatch="CANDIDATE_EXACT_UTF8_BYTES";
                    }
        // Isolate the previously read bytes before any native parser.
        IFileEx@ plainMemory;reason="PLAIN_MEMORY";
        if(!currentProcess().createByClsid(CLSID_MemoryFile,IID_IFileEx,plainMemory)
            || plainMemory is null || plainMemory.seek(0,fsEnd)!=0)break;
        plainMemory.write(expanded.bytes,total);
        if(plainMemory.seek(0,fsEnd)!=total || plainMemory.seek(0,fsBegin)!=0)break;
        if(index!=0){
            reason="MODULE_VOLUME";if(profile!="FORMAT15_HEADER_ONLY")break;
            array<uint> pageAt,pageSize,pageCap,pageNext;array<bool> owned;
            uint at=16;bool valid=true;
            while(at<total){
                if(pageAt.length>=4096 || total-at<31){valid=false;break;}
                int_ptr h=expanded.bytes+at;
                if(mem::byte[h]!=13 || mem::byte[h+1]!=10 || mem::byte[h+10]!=32 || mem::byte[h+19]!=32
                    || mem::byte[h+28]!=32 || mem::byte[h+29]!=13 || mem::byte[h+30]!=10){valid=false;break;}
                array<uint> values(3,0);array<uint> starts={2,11,20};
                for(uint field=0;field<3 && valid;field++)for(uint digit=0;digit<8;digit++){
                    uint ch=mem::byte[h+starts[field]+digit],n=16;
                    if(ch>=48 && ch<=57)n=ch-48;else if(ch>=65 && ch<=70)n=ch-55;else if(ch>=97 && ch<=102)n=ch-87;
                    if(n==16){valid=false;break;}values[field]=(values[field]<<4)|n;
                }
                if(!valid || values[0]>262144 || values[1]==0 || values[1]>total-at-31){valid=false;break;}
                pageAt.insertLast(at);pageSize.insertLast(values[0]);pageCap.insertLast(values[1]);pageNext.insertLast(values[2]);
                owned.insertLast(false);at+=31+values[1];
            }
            if(!valid || at!=total || pageAt.length<5)break;
            array<uint> starts={16,0,0,0,0};array<uint8> expectedInfo,expectedText;
            bool seenInfo=false,seenText=false;string entryName="";
            reason="MODULE_CHAINS";
            for(uint part=0;part<5 && valid;part++){
                uint address=starts[part],done=0,wanted=0;bool first=true;array<uint8> assembled;
                while(address!=0x7fffffff){
                    int page=-1;for(uint n=0;n<pageAt.length;n++)if(pageAt[n]==address){page=int(n);break;}
                    if(page<0 || owned[uint(page)]){valid=false;break;}
                    uint n=uint(page);owned[n]=true;
                    if(first){wanted=pageSize[n];if(wanted==0 || wanted>262144){valid=false;break;}assembled.resize(wanted);first=false;}
                    else if(done>=wanted){valid=false;break;}
                    uint take=pageCap[n];if(take>wanted-done)take=wanted-done;
                    if(take>0)mem::memcpy(mem::addressOf(assembled[done]),expanded.bytes+pageAt[n]+31,take);
                    done+=take;address=pageNext[n];
                }
                if(!valid || first || done!=wanted){valid=false;break;}
                if(part==0){
                    if(wanted!=24){valid=false;break;}
                    int_ptr toc=mem::addressOf(assembled[0]);
                    if(mem::dword[toc+8]!=0x7fffffff || mem::dword[toc+20]!=0x7fffffff){valid=false;break;}
                    starts[1]=mem::dword[toc];starts[2]=mem::dword[toc+4];starts[3]=mem::dword[toc+12];starts[4]=mem::dword[toc+16];
                }else if(part==1 || part==3){
                    if(wanted<24 || wanted>128 || (wanted&1)!=0){valid=false;break;}
                    int_ptr nameBytes=mem::addressOf(assembled[0]);
                    if(mem::dword[nameBytes+wanted-4]!=0){valid=false;break;}
                    uint chars=(wanted-24)/2;
                    while(chars>0 && mem::word[nameBytes+20+(chars-1)*2]==0)chars--;
                    if(chars!=4){valid=false;break;}
                    array<uint> infoLetters={105,110,102,111},textLetters={116,101,120,116};bool info=true,text=true;
                    for(uint c=0;c<4;c++){uint letter=mem::word[nameBytes+20+c*2];if(letter!=infoLetters[c])info=false;if(letter!=textLetters[c])text=false;}
                    if(info && !seenInfo){entryName="info";seenInfo=true;}
                    else if(text && !seenText){entryName="text";seenText=true;}
                    else{valid=false;break;}
                }else if(entryName=="info"){
                    if(wanted>1024){valid=false;break;}expectedInfo=assembled;
                }else if(entryName=="text")expectedText=assembled;
                else{valid=false;break;}
            }
            for(uint n=0;n<owned.length;n++)if(!owned[n])valid=false;
            if(!valid || !seenInfo || !seenText || expectedInfo.length==0 || expectedText.length==0)break;
            // SDK parser sees only our validated bounded volume. It
            // opens exactly these two keys, never find/enumeration.
            reason="MODULE_STORAGE";IStorageRW@ storage;
            if(!currentProcess().createByClsid(CLSID_StorageRW,IID_IStorageRW,storage) || storage is null)break;
            storage.initFromFile(plainMemory,scfNone);
            array<string> names={"info","text"};bool entriesOkay=true;
            string textHash="",lfHash="",textMatch="UNMATCHED";uint textLength=0,textCrlf=0;bool bom=false,endsLf=false;
            for(uint part=0;part<2 && entriesOkay;part++){
                reason="MODULE_ENTRY";IFileEx@ entry;storageOpens++;
                storage.open(entry,v8string(names[part]),FileOpenModes(fomIn|fomShareRead));
                if(entry is null){entriesOkay=false;break;}
                uint64 size=entry.seek(0,fsEnd);uint count=part==0?expectedInfo.length:expectedText.length;
                if(size!=count || count==0 || count>262144 || entry.seek(0,fsBegin)!=0){entriesOkay=false;break;}
                MemoryBuffer bytes(count);if(entry.read(bytes.bytes,count)!=count || entry.seek(0,fsCurrent)!=count){entriesOkay=false;break;}
                for(uint n=0;n<count;n++)if(mem::byte[bytes.bytes+n]!=(part==0?expectedInfo[n]:expectedText[n])){entriesOkay=false;break;}
                // Strict UTF8 before any framing or newline projection.
                for(uint n=0;n<count && entriesOkay;){
                    uint lead=mem::byte[bytes.bytes+n++];if(lead==0){entriesOkay=false;break;}if(lead<128)continue;
                    uint need=0,lo=128,hi=191;
                    if(lead>=194 && lead<=223)need=1;else if(lead>=224 && lead<=239){need=2;if(lead==224)lo=160;if(lead==237)hi=159;}
                    else if(lead>=240 && lead<=244){need=3;if(lead==240)lo=144;if(lead==244)hi=143;}else{entriesOkay=false;break;}
                    if(need>count-n){entriesOkay=false;break;}uint next=mem::byte[bytes.bytes+n];
                    if(next<lo || next>hi){entriesOkay=false;break;}
                    for(uint c=1;c<need;c++){next=mem::byte[bytes.bytes+n+c];if(next<128 || next>191)entriesOkay=false;}n+=need;
                }
                if(!entriesOkay || part==0)continue;
                textLength=count;textHash=ahTemplateRamShaV202(bytes,count);
                bom=count>=3 && mem::byte[bytes.bytes]==239 && mem::byte[bytes.bytes+1]==187 && mem::byte[bytes.bytes+2]==191;
                endsLf=mem::byte[bytes.bytes+count-1]==10;
                for(uint n=0;n+1<count;n++)if(mem::byte[bytes.bytes+n]==13 && mem::byte[bytes.bytes+n+1]==10)textCrlf++;
                uint skip=bom?3:0,projected=count-skip-textCrlf;if(projected==0){entriesOkay=false;break;}
                MemoryBuffer lf(projected);uint written=0;
                for(uint n=skip;n<count;n++){
                    if(mem::byte[bytes.bytes+n]==13 && n+1<count && mem::byte[bytes.bytes+n+1]==10)continue;
                    mem::byte[lf.bytes+written++]=mem::byte[bytes.bytes+n];
                }
                if(written!=projected){entriesOkay=false;break;}lfHash=ahTemplateRamShaV202(lf,projected);
                string original=index==1?"506fe9bd7d1ade475a54dd4bfabb22f82d91a634b2477f44fdcc38b96f9417b6":"c5b596a38e554aa34e1e1adba527e45db35516b8e72772c6724645ed481b81ba";
                string candidate=index==1?"90939ff38be12b52740f27153455e711b145086ee1aacb6e906eb897556f381a":"f64720f5118b2eaba03197f3de83a3ee93a68738e7177751fcd92cbb618e224a";
                if(textHash==original)textMatch="ORIGINAL_EXACT_BYTES";else if(textHash==candidate)textMatch="CANDIDATE_EXACT_BYTES";
                else if(lfHash==original)textMatch="ORIGINAL_LF_NO_BOM_PROJECTION";else if(lfHash==candidate)textMatch="CANDIDATE_LF_NO_BOM_PROJECTION";
            }
            reason="MODULE_ENTRY_MISMATCH";if(!entriesOkay || textHash.length!=64 || lfHash.length!=64)break;
            if(pass==0){textLengths[index]=textLength;textHashes[index]=textHash;lfHashes[index]=lfHash;textMatches[index]=textMatch;
                textBom[index]=bom;textLf[index]=endsLf;textCrlfCounts[index]=textCrlf;}
            else if(textLengths[index]!=textLength || textHashes[index]!=textHash || lfHashes[index]!=lfHash
                || textMatches[index]!=textMatch || textBom[index]!=bom || textLf[index]!=endsLf || textCrlfCounts[index]!=textCrlf)break;
            moduleDecodedPasses++;
        }else{
            reason="TEMPLATE_COLD_HELPER";IMDEditService@ service=getMDEditService();IMDEditHelper@ helper;
            if(service is null)break;service.getEditHelper(helper,objects[0]);
            Guid property("{8eb4fad1-1fa6-403e-970f-2c12dbb43e23}");
            if(helper is null || !ahCatalogSameV218(helper.getMDObj().unk,objects[0].unk)
                || helper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))break;
            IUnknown@ liveBody;helper.extProp(liveBody,property,false);
            IDocument@ liveDocument=liveBody;IValue@ liveValue=liveBody;IContext@ liveContext=liveBody;
            if(liveDocument is null || liveValue is null || liveContext is null || liveDocument.isModified())break;
            bool wasReadOnly=liveDocument.getReadOnly();IType@ type=liveValue.getType();reason="TEMPLATE_COLD_FACTORY";
            if(type is null || string(type.getTypeString(0))!="SpreadsheetDocument")break;
            IValue@ coldValue;type.createValue(coldValue);
            if(coldValue is null || ahCatalogSameV218(coldValue.unk,liveBody))break;
            IPersistableDocument@ coldDocument=coldValue.unk;IContext@ coldContext=coldValue.unk;IFile@ input=plainMemory.unk;
            if(coldDocument is null || coldContext is null || input is null || plainMemory.seek(0,fsBegin)!=0)break;
            reason="TEMPLATE_COLD_LOAD";coldLoads++;coldDocument.load(input);
            IFileEx@ canonical;string digest;reason="TEMPLATE_COLD_SNAPSHOT";coldSnapshots++;
            if(!ahSheetSnapshotV231(coldDocument,canonical,digest) || digest.length!=64)break;
            int coldHeight=0,coldWidth=0,liveHeight=0,liveWidth=0;
            if(!ahCellNumberV230(coldContext,"TableHeight",coldHeight) || !ahCellNumberV230(coldContext,"TableWidth",coldWidth)
                || !ahCellNumberV230(liveContext,"TableHeight",liveHeight) || !ahCellNumberV230(liveContext,"TableWidth",liveWidth)
                || coldHeight!=25 || coldWidth!=10 || liveHeight!=coldHeight || liveWidth!=coldWidth)break;
            array<string> names={"Text","Parameter","FillType","Font","BackColor","TextColor","LeftBorder","TopBorder",
                "RightBorder","BottomBorder","ColumnWidth","RowHeight","VerticalAlign","HorizontalAlign","Format"};
            uint compared=0;bool same=true;reason="TEMPLATE_COLD_PROPERTIES";
            for(int row=1;row<=25 && same;row++)for(int col=1;col<=10 && same;col++){
                IContext@ a=ahSheetAreaV231(coldContext,row,col,col),b=ahSheetAreaV231(liveContext,row,col,col);
                if(a is null || b is null){same=false;break;}
                for(uint n=0;n<names.length;n++){
                    Value x,y;if(!ahSheetGetV231(a,names[n],x) || !ahSheetGetV231(b,names[n],y) || !ahSheetEqualV231(x,y)){same=false;break;}compared++;
                }
            }
            templateComparisons+=compared;
            if(!same || compared!=3750 || liveDocument.isModified() || liveDocument.getReadOnly()!=wasReadOnly
                || objects[0].isModified() || parents[0].isModified() || root.isModified() || ui.isModified())break;
            if(pass==0)templateCanonicalHash=digest;else if(templateCanonicalHash!=digest)break;
        }
                    reason="SAVED_RESOURCE_CHANGED";
                    if(pass==0){plainLengths[index]=total;plainHashes[index]=expandedHash;profiles[index]=profile;
                        utf8Flags[index]=utf8;bomFlags[index]=bom;lfFlags[index]=lf;crlfCounts[index]=crlf;codeMatches[index]=codeMatch;}
                    else if(plainLengths[index]!=total || plainHashes[index]!=expandedHash || profiles[index]!=profile || utf8Flags[index]!=utf8 || bomFlags[index]!=bom || lfFlags[index]!=lf
                        || crlfCounts[index]!=crlf || codeMatches[index]!=codeMatch)break;
                    if(root.isModified() || ui.isModified())break;readPasses++;
                    // Counted file handles release when this read scope ends.
                }
                if(readPasses!=2)break;resourcesRead++;
            }
            if(resourcesRead!=3 || moduleDecodedPasses!=4 || coldLoads!=2 || coldSnapshots!=2 || templateComparisons!=7500)break;reason="FINAL_STATE";
            IMDContainer@ afterRoot=ui.getMDCont();IConfigMngr@ afterManager=root.getConfigMngr();
            if(!ahPipeScopeAlive() || ahStatusUi !is ui || afterRoot is null || afterManager is null
                || !ahCatalogSameV218(afterRoot.unk,root.unk) || !ahCatalogSameV218(afterManager.unk,manager.unk)
                || root.isModified() || ui.isModified() || ahGetCurrentProcessId()!=ahFrameOwnerPidV211
                || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            verified=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){verified=false;reason="NATIVE_EXCEPTION";}
    for(uint index=0;index<3;index++){
        string key=storageKnown?keys[index]:"";
        string property=index==0?"8eb4fad1-1fa6-403e-970f-2c12dbb43e23":"d5963243-262e-4398-b4d7-fb16d06484f6";
        rows+=(index==0?"":",")+"{\"objectId\":\""+ids[index]+"\",\"propertyId\":\""+property+"\",\"resourceKey\":\""+key
            +"\",\"urlCharacters\":"+keyCharacters[index]+",\"propertyReturnCodes\":["+propertyCodes[index]+","+propertyCodes[3+index]
            +"],\"urlReturnCodes\":["+urlCodes[index]+","+urlCodes[3+index]+"]"
            +",\"plainBytes\":"+plainLengths[index]+",\"plainSha256\":\""+plainHashes[index]+"\",\"headerProfile\":\""+profiles[index]
            +"\",\"validUtf8\":"+utf8Flags[index]+",\"bomPresent\":"+bomFlags[index]
            +",\"endsLf\":"+lfFlags[index]+",\"crlfCount\":"+crlfCounts[index]+",\"moduleByteMatch\":\""+codeMatches[index]+"\""
            +",\"textBytes\":"+textLengths[index]+",\"textRawSha256\":\""+textHashes[index]+"\",\"textLfNoBomSha256\":\""+lfHashes[index]
            +"\",\"textMatch\":\""+textMatches[index]+"\",\"textBomPresent\":"+textBom[index]+",\"textEndsLf\":"+textLf[index]+",\"textCrlfCount\":"+textCrlfCounts[index]+"}";
    }
    rows+="]";
    string result="{\"version\":264,\"status\":\""+(verified?"SAVED_RESOURCE_FINGERPRINTED":(pendingFileReference?"UNKNOWN_FILE_REFERENCE":"REFUSED"))+"\",\"reason\":\""+reason
        +"\",\"stablePasses\":"+passes+",\"storageAbiObserved\":"+storageKnown+",\"managerTable\":"+managerTable+",\"innerTable\":"+innerTable
        +",\"sourceTable\":"+sourceTable+",\"targetTable\":"+targetTable+",\"getterCode\":"+getterCode+",\"targets\":"+rows
        +",\"propertyReads\":"+propertyReads+",\"urlReads\":"+urlReads+",\"sourceTablePinned\":"+storageKnown+",\"plannedReadOpenMode\":264"
        +",\"phase\":\"RESOURCE_FINGERPRINT\",\"getterInitialized\":"+getterInitialized+",\"getterDispatches\":"+fileOpens+",\"adoptedFiles\":"+adoptedFiles
        +",\"resourcesRead\":"+resourcesRead+",\"savedFileExistenceVerified\":"+verified+",\"resourceSizesObserved\":"+verified
        +",\"pendingFileReference\":"+pendingFileReference+",\"plainReads\":"+plainReads+",\"unpackReads\":0"
        +",\"readShape\":\"LAYERED_MANAGER_PLAIN\",\"inflationPerformed\":false,\"optionalProviderNull\":true"
        +",\"ramTransportReady\":false,\"decodedModuleSchemaVerified\":"+(verified && moduleDecodedPasses==4)
        +",\"templateColdCloneVerified\":"+(verified && coldLoads==2 && coldSnapshots==2 && templateComparisons==7500)
        +",\"moduleDecodedPasses\":"+moduleDecodedPasses+",\"storageEntryOpens\":"+storageOpens+",\"coldLoads\":"+coldLoads+",\"coldSnapshots\":"+coldSnapshots
        +",\"templatePropertyComparisons\":"+templateComparisons+",\"templateCanonicalSha256\":\""+templateCanonicalHash+"\",\"liveDocumentSerializations\":0"
        +",\"moduleTextReads\":"+moduleDecodedPasses+",\"moduleHelperTextReads\":0,\"editorOpens\":0"
        +",\"sourceWrites\":0,\"metadataWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"writerAuthorized\":false}";
    ExceptionCatcher output;
    {CppCatch caught("class core::Exception",ExceptionHandler(output.handle));if(result.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",result);}
}
