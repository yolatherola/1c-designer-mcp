// DATABASE_SAVED only. The C caller seals ownership/private-RW/lifetime of
// envelope384/body4MiB; readable pages alone never grant write authority.
// No helper/editor/source-file output, native commands or configuration writes.
void ahSafeSavedModuleRam(int_ptr envelope) {
    bool smAdmitted=__SAFE_SAVED_MODULE_RAM_SCOPE_ADMITTED__,smOwned=false,smRead=false,smBefore=false,smAfter=false,smPrefix=false,smClean=false,smPending=false;
    if(!smAdmitted)return;
    uint smReason=1,smSelector=0,smRevisionLow=0,smRevisionHigh=0,smCapacity=0,smBytes=0,smPoints=0,smCrlf=0,smPasses=0,smProperties=0,smOpens=0,smAdopts=0,smStoredBytes=0;
    uint smPersistent=0,smSingle=0,smUiAddress=0,smDesignerAddress=0,smDispatchAddress=0,smShellAddress=0,smCoreAddress=0;
    bool smBom=false,smLf=false,smFinalException=false;
    int_ptr smBody=0,smInner=0,smSource=0,smTarget=0,smGetter=0;
    string smNonce="",smKey="",smBodyHash="",smStoredHash="",smDigits="0123456789abcdef";
    array<uint8> smFirstBody;MemoryBuffer smHeader(68);
    IConfigMngrUI@ smUi;IMDContainer@ smMain,smDb,smFreshMain,smFreshDb;
    IInfoBase@ smIb;IConfigMngr@ smManager,smRoundtrip;
    IMDObject@ smMainObject,smObject,smParent,smFreshObject,smFreshParent,smFreshMainObject;
    Designer@ smDesigner;IDispatch@ smDispatch;ITopLevelFrame@ smShell,smCore;
    IUnknown@ smPin;IFileEx@ smFile,smMemory,smEntry;IStorageRW@ smStorage;
    ExceptionCatcher smCatcher;
    {CppCatch smCaught("class core::Exception",ExceptionHandler(smCatcher.handle));
        do {
            if(!smAdmitted || sizeof_ptr!=4 || uint(envelope)<65536 || uint64(uint(envelope))+384>0x100000000
                || !ahCompactPageV108(envelope,384))break;
            if(mem::dword[envelope]!=0x31524d53 || mem::dword[envelope+4]!=1 || mem::dword[envelope+8]!=384
                || mem::dword[envelope+64]!=0x91d4a63b || mem::dword[envelope+380]!=0x6b5c28e7)break;
            smSelector=mem::dword[envelope+12];smRevisionLow=mem::dword[envelope+48];smRevisionHigh=mem::dword[envelope+52];
            smBody=mem::int_ptr[envelope+56];smCapacity=mem::dword[envelope+60];
            if((smSelector!=1 && smSelector!=2) || smRevisionHigh>0x1fffff || (smRevisionLow==0 && smRevisionHigh==0)
                || smCapacity!=4194304 || uint(smBody)<65536 || uint64(uint(smBody))+smCapacity>0x100000000
                || (uint64(uint(smBody))<uint64(uint(envelope))+384 && uint64(uint(envelope))<uint64(uint(smBody))+smCapacity))break;
            bool smNonceValid=true;
            for(uint smN=0;smN<32;smN++){
                uint smCh=mem::byte[envelope+16+smN];
                if(!((smCh>=48 && smCh<=57)||(smCh>=97 && smCh<=102))){smNonceValid=false;break;}
                smNonce+=smDigits.substr(smCh<=57?smCh-48:smCh-87,1);
            }
            if(!smNonceValid || smNonce.length!=32)break;
            mem::memcpy(smHeader.bytes,envelope,68);smOwned=true;
            for(uint smN=68;smN<380;smN++)mem::byte[envelope+smN]=0;
            smReason=2;
            if(ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292 || !ahPipeScopeAlive()
                || ahStatusUi is null || ahFrameOwnerPidV211!=48936 || ahFrameOwnerTidV211!=8292)break;
            @smUi=ahStatusUi;@smMain=smUi.getMDCont();smReason=3;
            if(!ahCatalogEditableV218(smMain) || smMain.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}") || smMain.isModified() || smUi.isModified())break;
            Guid smId(smSelector==1?"{176e2552-fd8b-4823-afc0-d17431f2fb7b}":"{28ecdfc7-083e-4082-b272-efbf7152de5c}");
            Guid smProperty("{d5963243-262e-4398-b4d7-fb16d06484f6}"),smClass("{0fe48980-252d-11d6-a3c7-0050bae0a776}");
            @smMainObject=smMain.objById(smId);smReason=4;
            if(smMainObject is null || smMainObject.id!=smId || smMainObject.mdClass is null || smMainObject.mdClass.id!=smClass
                || smMainObject.mdParentLink is null || smMainObject.isModified() || !ahCatalogLinkV218(smMainObject,smMain,smMain))break;
            smReason=5;
            if(oneDesigner is null || oneAddinMgr !is null || dspWindows is null || mainFrame is null || coreMainFrame is null
                || oneDesigner._windows !is null || oneDesigner._metadata !is null || oneDesigner._develop !is null)break;
            @smDesigner=oneDesigner;@smDispatch=dspWindows;@smShell=mainFrame;@smCore=coreMainFrame;
            smUiAddress=uint(mem::addressOf(smUi));smDesignerAddress=uint(mem::addressOf(smDesigner));smDispatchAddress=uint(mem::addressOf(smDispatch));
            smShellAddress=uint(mem::addressOf(smShell));smCoreAddress=uint(mem::addressOf(smCore));
            smPersistent=idleHandlers.length;smSingle=idleHandlersSingle.length;if(smPersistent!=0 || smSingle!=0)break;
            @smIb=getDefaultInfoBase();smReason=6;if(smIb is null)break;
            @smManager=smIb.getConfigMgr();if(smManager is null || uint(mem::addressOf(smManager))!=100051712)break;
            @smDb=smManager.getMDCont(0);smReason=7;
            if(smDb is null || uint(mem::addressOf(smDb))!=1383504556 || smDb.id!=smMain.id || smDb.isModified()
                || !ahCompactTableV108(mem::addressOf(smDb),"backend.dll",15815188,60))break;
            @smRoundtrip=smDb.getConfigMngr();if(smRoundtrip is null || !ahCatalogSameV218(smRoundtrip.unk,smManager.unk))break;@smRoundtrip=null;
            @smObject=smDb.objById(smId);smReason=8;
            if(smObject is null || smObject.id!=smId || smObject.mdClass is null || smObject.mdClass.id!=smClass
                || smObject.mdParentLink is null || smObject.isModified())break;
            @smParent=smObject.mdParentLink.getMDObject();
            if(smParent is null || smParent.id!=smDb.id || smParent.isModified() || !ahCatalogLinkV218(smObject,smParent,smDb))break;
            smBefore=true;
            int_ptr smManagerAt=mem::addressOf(smManager);smReason=9;
            if(!ahCompactPageV108(smManagerAt,0xd0) || !ahCompactTableV108(smManagerAt,"backend.dll",15589540,86))break;
            smInner=mem::int_ptr[smManagerAt+0xcc];if(!ahCompactPageV108(smInner,0x174)
                || !ahCompactTableV108(smInner,"backend.dll",15029196,43))break;
            smSource=mem::int_ptr[smInner+0x16c];smTarget=mem::int_ptr[smInner+0x170];
            if(smSource==0 || smTarget==0 || smSource==smTarget || !ahCompactTableV108(smSource,"backend.dll",15576968,5)
                || !ahCompactTableV108(smTarget,"backend.dll",15576968,5))break;
            smGetter=mem::int_ptr[mem::int_ptr[smManagerAt]+79*4];
            if(!ahCompactAddressV108(smGetter,"backend.dll",2788960)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[smInner]+15*4],"backend.dll",217376)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[smSource]+4*4],"backend.dll",2573152)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[smTarget]+4*4],"backend.dll",2573152))break;
            if(ahGMResourceGetterV107 is null)initFuncDefFromAddress(smGetter,@ahGMResourceGetterV107,asCALL_STDCALL);
            if(ahGMResourceGetterV107 is null)break;
            for(uint smPass=0;smPass<2;smPass++){
                smReason=10;
                if(!ahPipeScopeAlive() || ahStatusUi !is smUi || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292
                    || smUi.isModified() || smMain.isModified() || smMainObject.isModified() || smDb.isModified() || smObject.isModified() || smParent.isModified())break;
                @smFreshMain=smUi.getMDCont();@smFreshDb=smManager.getMDCont(0);
                if(smFreshMain is null || smFreshDb is null || !ahCatalogSameV218(smFreshMain.unk,smMain.unk)
                    || !ahCatalogSameV218(smFreshDb.unk,smDb.unk))break;
                @smFreshObject=smFreshDb.objById(smId);@smFreshMainObject=smFreshMain.objById(smId);
                if(smFreshObject is null || smFreshMainObject is null || !ahCatalogSameV218(smFreshObject.unk,smObject.unk)
                    || !ahCatalogSameV218(smFreshMainObject.unk,smMainObject.unk) || smFreshObject.mdClass is null || smFreshObject.mdClass.id!=smClass)break;
                if(!ahCompactPageV108(smManagerAt,0xd0) || !ahCompactPageV108(smInner,0x174)
                    || mem::int_ptr[smManagerAt+0xcc]!=smInner || mem::int_ptr[smInner+0x16c]!=smSource || mem::int_ptr[smInner+0x170]!=smTarget
                    || !ahCompactTableV108(smManagerAt,"backend.dll",15589540,86) || !ahCompactTableV108(smInner,"backend.dll",15029196,43)
                    || !ahCompactTableV108(smSource,"backend.dll",15576968,5) || !ahCompactTableV108(smTarget,"backend.dll",15576968,5)
                    || mem::int_ptr[mem::int_ptr[smManagerAt]+79*4]!=smGetter)break;
                Value smValue;smProperties++;smObject.mdPropVal(smProperty,smValue);
                if(smValue.pValue is null)break;IMDExtObj@ smExternal=smValue.pValue.unk;if(smExternal is null)break;
                URL smUrl;smExternal.url(smUrl);string smObservedKey=smUrl.url;
                smReason=11;
                if(smObservedKey.length<36 || smObservedKey.length>45 || !ahModuleUuidV225(smObservedKey.substr(0,36).lowered()))break;
                bool smKeyValid=true;
                if(smObservedKey.length>36){
                    if(smObservedKey.length<38 || smObservedKey[36]!=46)smKeyValid=false;
                    for(uint smN=37;smKeyValid && smN<smObservedKey.length;smN++)if(smObservedKey[smN]<48 || smObservedKey[smN]>57)smKeyValid=false;
                }
                if(!smKeyValid)break;if(smPass==0)smKey=smObservedKey;else if(smKey!=smObservedKey)break;
                // Manager79 returns exactly one counted smartref; never adopt
                // borrowed metadata/filesystem pointers. Provider0 has no callback.
                MemoryBuffer smOut(36);for(uint smN=0;smN<36;smN++)mem::byte[smOut.bytes+smN]=0xa5;mem::int_ptr[smOut.bytes+16]=0;
                v8string smName=smKey;URL smFileName(smName);smReason=12;smPending=true;smOpens++;
                int_ptr smReturned=ahGMResourceGetterV107(smManagerAt,smOut.bytes+16,smFileName.self,0);
                bool smCanary=true;for(uint smN=0;smN<16;smN++)if(mem::byte[smOut.bytes+smN]!=0xa5 || mem::byte[smOut.bytes+20+smN]!=0xa5)smCanary=false;
                if(!smCanary || smReturned!=smOut.bytes+16)break;
                int_ptr smAddress=mem::int_ptr[smOut.bytes+16];if(smAddress==0){smPending=false;break;}
                @smPin=toIUnknown(smAddress);smPending=false;smAdopts++;mem::int_ptr[smOut.bytes+16]=0;@smFile=smPin;
                if(smFile is null)break;uint64 smSize=smFile.seek(0,fsEnd);smReason=13;
                if(smSize<16 || smSize>8388608 || smFile.seek(0,fsBegin)!=0)break;
                uint smTotal=uint(smSize);MemoryBuffer smExpanded(smTotal);
                if(smFile.read(smExpanded.bytes,smTotal)!=smTotal || smFile.seek(0,fsCurrent)!=smSize)break;
                if(mem::dword[smExpanded.bytes]!=0x7fffffff || mem::dword[smExpanded.bytes+4]!=512
                    || (mem::dword[smExpanded.bytes+8]!=1 && mem::dword[smExpanded.bytes+8]!=2) || mem::dword[smExpanded.bytes+12]!=0)break;
                array<uint> smPageAt,smPageSize,smPageCap,smPageNext;array<bool> smPageOwned;
                uint smAt=16;bool smValid=true;smReason=14;
                while(smAt<smTotal){
                    if(smPageAt.length>=4096 || smTotal-smAt<31){smValid=false;break;}
                    int_ptr smH=smExpanded.bytes+smAt;
                    if(mem::byte[smH]!=13 || mem::byte[smH+1]!=10 || mem::byte[smH+10]!=32 || mem::byte[smH+19]!=32
                        || mem::byte[smH+28]!=32 || mem::byte[smH+29]!=13 || mem::byte[smH+30]!=10){smValid=false;break;}
                    array<uint> smValues(3,0);array<uint> smFields={2,11,20};
                    for(uint smField=0;smField<3 && smValid;smField++)for(uint smDigit=0;smDigit<8;smDigit++){
                        uint smCh=mem::byte[smH+smFields[smField]+smDigit],smNibble=16;
                        if(smCh>=48 && smCh<=57)smNibble=smCh-48;else if(smCh>=65 && smCh<=70)smNibble=smCh-55;else if(smCh>=97 && smCh<=102)smNibble=smCh-87;
                        if(smNibble==16){smValid=false;break;}smValues[smField]=(smValues[smField]<<4)|smNibble;
                    }
                    if(!smValid || smValues[0]>8388608 || smValues[1]==0 || smValues[1]>smTotal-smAt-31){smValid=false;break;}
                    smPageAt.insertLast(smAt);smPageSize.insertLast(smValues[0]);smPageCap.insertLast(smValues[1]);smPageNext.insertLast(smValues[2]);smPageOwned.insertLast(false);smAt+=31+smValues[1];
                }
                if(!smValid || smAt!=smTotal || smPageAt.length<5)break;
                array<uint> smStarts={16,0,0,0,0};array<uint8> smInfo,smText;
                bool smSeenInfo=false,smSeenText=false;string smEntryName="";smReason=15;
                for(uint smPart=0;smPart<5 && smValid;smPart++){
                    uint smAddressAt=smStarts[smPart],smDone=0,smWanted=0;bool smFirst=true;array<uint8> smAssembled;
                    while(smAddressAt!=0x7fffffff){
                        int smPage=-1;for(uint smN=0;smN<smPageAt.length;smN++)if(smPageAt[smN]==smAddressAt){smPage=int(smN);break;}
                        if(smPage<0 || smPageOwned[uint(smPage)]){smValid=false;break;}uint smN=uint(smPage);smPageOwned[smN]=true;
                        if(smFirst){
                            smWanted=smPageSize[smN];
                            if(smWanted>4194304 || (smWanted==0 && !(smPart>0 && (smPart&1)==0 && smEntryName=="text"))){smValid=false;break;}
                            smAssembled.resize(smWanted);smFirst=false;
                        }else if(smDone>=smWanted){smValid=false;break;}
                        uint smTake=smPageCap[smN];if(smTake>smWanted-smDone)smTake=smWanted-smDone;
                        if(smTake>0)mem::memcpy(mem::addressOf(smAssembled[smDone]),smExpanded.bytes+smPageAt[smN]+31,smTake);
                        smDone+=smTake;smAddressAt=smPageNext[smN];
                    }
                    if(!smValid || smFirst || smDone!=smWanted){smValid=false;break;}
                    if(smPart==0){
                        if(smWanted!=24){smValid=false;break;}int_ptr smToc=mem::addressOf(smAssembled[0]);
                        if(mem::dword[smToc+8]!=0x7fffffff || mem::dword[smToc+20]!=0x7fffffff){smValid=false;break;}
                        smStarts[1]=mem::dword[smToc];smStarts[2]=mem::dword[smToc+4];smStarts[3]=mem::dword[smToc+12];smStarts[4]=mem::dword[smToc+16];
                    }else if(smPart==1 || smPart==3){
                        if(smWanted<24 || smWanted>128 || (smWanted&1)!=0){smValid=false;break;}
                        int_ptr smNameAt=mem::addressOf(smAssembled[0]);if(mem::dword[smNameAt+smWanted-4]!=0){smValid=false;break;}
                        uint smChars=(smWanted-24)/2;while(smChars>0 && mem::word[smNameAt+20+(smChars-1)*2]==0)smChars--;
                        if(smChars!=4){smValid=false;break;}array<uint> smInfoLetters={105,110,102,111},smTextLetters={116,101,120,116};bool smIsInfo=true,smIsText=true;
                        for(uint smC=0;smC<4;smC++){uint smLetter=mem::word[smNameAt+20+smC*2];if(smLetter!=smInfoLetters[smC])smIsInfo=false;if(smLetter!=smTextLetters[smC])smIsText=false;}
                        if(smIsInfo && !smSeenInfo){smEntryName="info";smSeenInfo=true;}else if(smIsText && !smSeenText){smEntryName="text";smSeenText=true;}else{smValid=false;break;}
                    }else if(smEntryName=="info"){
                        if(smWanted==0 || smWanted>1024){smValid=false;break;}smInfo=smAssembled;
                    }else if(smEntryName=="text")smText=smAssembled;
                    else{smValid=false;break;}
                }
                for(uint smN=0;smN<smPageOwned.length;smN++)if(!smPageOwned[smN])smValid=false;
                if(!smValid || !smSeenInfo || !smSeenText || smInfo.length==0 || smText.length>smCapacity)break;
                smReason=16;
                if(!currentProcess().createByClsid(CLSID_MemoryFile,IID_IFileEx,smMemory) || smMemory is null || smMemory.seek(0,fsEnd)!=0)break;
                smMemory.write(smExpanded.bytes,smTotal);if(smMemory.seek(0,fsEnd)!=smTotal || smMemory.seek(0,fsBegin)!=0)break;
                if(!currentProcess().createByClsid(CLSID_StorageRW,IID_IStorageRW,smStorage) || smStorage is null)break;
                smStorage.initFromFile(smMemory,scfNone);array<string> smNames={"info","text"};bool smEntries=true;
                for(uint smPart=0;smPart<2 && smEntries;smPart++){
                    smStorage.open(smEntry,v8string(smNames[smPart]),FileOpenModes(fomIn|fomShareRead));
                    if(smEntry is null){smEntries=false;break;}uint smCount=smPart==0?smInfo.length:smText.length;
                    if(smEntry.seek(0,fsEnd)!=smCount || smEntry.seek(0,fsBegin)!=0){smEntries=false;break;}
                    MemoryBuffer smEntryBytes(smCount==0?1:smCount);
                    if((smCount>0 && smEntry.read(smEntryBytes.bytes,smCount)!=smCount) || smEntry.seek(0,fsCurrent)!=smCount){smEntries=false;break;}
                    for(uint smN=0;smN<smCount;smN++)if(mem::byte[smEntryBytes.bytes+smN]!=(smPart==0?smInfo[smN]:smText[smN])){smEntries=false;break;}
                    @smEntry=null;
                }
                if(!smEntries)break;
                uint smCursor=0,smCodePoints=0,smTextCrlf=0;smReason=17;
                while(smCursor<smText.length){
                    uint smLead=smText[smCursor++];smCodePoints++;if(smLead==0 || smCodePoints>1048576){smValid=false;break;}if(smLead<128)continue;
                    uint smNeed=0,smLo=128,smHi=191;
                    if(smLead>=194 && smLead<=223)smNeed=1;else if(smLead>=224 && smLead<=239){smNeed=2;if(smLead==224)smLo=160;if(smLead==237)smHi=159;}
                    else if(smLead>=240 && smLead<=244){smNeed=3;if(smLead==240)smLo=144;if(smLead==244)smHi=143;}else{smValid=false;break;}
                    if(smNeed>smText.length-smCursor){smValid=false;break;}uint smSecond=smText[smCursor];if(smSecond<smLo || smSecond>smHi){smValid=false;break;}
                    for(uint smC=1;smC<smNeed;smC++)if(smText[smCursor+smC]<128 || smText[smCursor+smC]>191){smValid=false;break;}
                    if(!smValid)break;smCursor+=smNeed;
                }
                if(!smValid)break;
                for(uint smN=0;smN+1<smText.length;smN++)if(smText[smN]==13 && smText[smN+1]==10)smTextCrlf++;
                bool smTextBom=smText.length>=3 && smText[0]==239 && smText[1]==187 && smText[2]==191;
                bool smTextLf=smText.length>0 && smText[smText.length-1]==10;
                // Inline V240 SHA recipe streams padding: supports empty text
                // and large spans without invoking the frozen256KiB helper.
                array<uint> smK={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
                array<string> smHashes(2,"");smReason=18;
                for(uint smJob=0;smJob<2;smJob++){
                    uint smHashCount=smJob==0?smTotal:smText.length;
                    int_ptr smHashData=smExpanded.bytes;if(smJob==1 && smHashCount>0)smHashData=mem::addressOf(smText[0]);
                    array<uint> smHashState={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
                uint smPadded=((smHashCount+72)/64)*64,smBitCount=smHashCount*8;
                for(uint smBlock=0;smBlock<smPadded;smBlock+=64){
                    array<uint> smWords(64,0);
                    for(uint smI=0;smI<16;smI++)for(uint smJ=0;smJ<4;smJ++){
                        uint smPosition=smBlock+smI*4+smJ,smHashByte=0;
                        if(smPosition<smHashCount)smHashByte=mem::byte[smHashData+smPosition];
                        else if(smPosition==smHashCount)smHashByte=128;
                        else if(smPosition>=smPadded-4)smHashByte=(smBitCount>>(8*(smPadded-1-smPosition)))&255;
                        smWords[smI]=(smWords[smI]<<8)|smHashByte;
                    }
                    for(uint smI=16;smI<64;smI++){
                        uint smX=smWords[smI-15],smY=smWords[smI-2];
                        smWords[smI]=smWords[smI-16]+(ahTemplateRamRotateV202(smX,7)^ahTemplateRamRotateV202(smX,18)^(smX>>3))
                            +smWords[smI-7]+(ahTemplateRamRotateV202(smY,17)^ahTemplateRamRotateV202(smY,19)^(smY>>10));
                    }
                    uint smA=smHashState[0],smB=smHashState[1],smC=smHashState[2],smD=smHashState[3],smE=smHashState[4],smF=smHashState[5],smG=smHashState[6],smH=smHashState[7];
                    for(uint smI=0;smI<64;smI++){
                        uint t1=smH+(ahTemplateRamRotateV202(smE,6)^ahTemplateRamRotateV202(smE,11)^ahTemplateRamRotateV202(smE,25))
                            +((smE&smF)^((~smE)&smG))+smK[smI]+smWords[smI];
                        uint t2=(ahTemplateRamRotateV202(smA,2)^ahTemplateRamRotateV202(smA,13)^ahTemplateRamRotateV202(smA,22))
                            +((smA&smB)^(smA&smC)^(smB&smC));
                        smH=smG;smG=smF;smF=smE;smE=smD+t1;smD=smC;smC=smB;smB=smA;smA=t1+t2;
                    }
                    smHashState[0]+=smA;smHashState[1]+=smB;smHashState[2]+=smC;smHashState[3]+=smD;smHashState[4]+=smE;smHashState[5]+=smF;smHashState[6]+=smG;smHashState[7]+=smH;
                }
                string smDigest="";for(uint smI=0;smI<8;smI++)for(int smJ=7;smJ>=0;smJ--)smDigest+=smDigits.substr((smHashState[smI]>>(smJ*4))&15,1);
                    smHashes[smJob]=smDigest;
                }
                if(smHashes[0].length!=64 || smHashes[1].length!=64)break;
                if(smPass==0){smFirstBody=smText;smStoredBytes=smTotal;smStoredHash=smHashes[0];smBodyHash=smHashes[1];smPoints=smCodePoints;smCrlf=smTextCrlf;smBom=smTextBom;smLf=smTextLf;}
                else{
                    if(smTotal!=smStoredBytes || smHashes[0]!=smStoredHash || smHashes[1]!=smBodyHash || smFirstBody.length!=smText.length
                        || smCodePoints!=smPoints || smTextCrlf!=smCrlf || smTextBom!=smBom || smTextLf!=smLf)break;
                    bool smSameBody=true;for(uint smN=0;smN<smText.length;smN++)if(smText[smN]!=smFirstBody[smN]){smSameBody=false;break;}if(!smSameBody)break;
                }
                @smEntry=null;@smStorage=null;@smMemory=null;@smFile=null;@smPin=null;
                smPasses++;
            }
            if(smPasses!=2)break;smBytes=smFirstBody.length;smRead=true;smReason=0;
        }while(false);
    }
    if(!smOwned)return;
    if(smCatcher.hasException)smReason=19;
    {ExceptionCatcher smFinalCatcher;CppCatch smFinalCaught("class core::Exception",ExceptionHandler(smFinalCatcher.handle));
        smPrefix=smDesigner !is null && oneDesigner is smDesigner && dspWindows is smDispatch && mainFrame is smShell && coreMainFrame is smCore
            && oneAddinMgr is null && smDesigner._windows is null && smDesigner._metadata is null && smDesigner._develop is null
            && idleHandlers.length==smPersistent && idleHandlersSingle.length==smSingle;
        if(smUi !is null && smMain !is null && smDb !is null && smManager !is null && smObject !is null && smMainObject !is null && smParent !is null
            && ahStatusUi is smUi && ahPipeScopeAlive() && ahGetCurrentProcessId()==48936 && ahGetCurrentThreadId()==8292
            && !smUi.isModified() && !smMain.isModified() && !smDb.isModified() && !smObject.isModified() && !smMainObject.isModified() && !smParent.isModified()){
            @smFreshMain=smUi.getMDCont();@smFreshDb=smManager.getMDCont(0);
            if(smFreshMain !is null && smFreshDb !is null && ahCatalogSameV218(smFreshMain.unk,smMain.unk) && ahCatalogSameV218(smFreshDb.unk,smDb.unk)){
                @smFreshObject=smFreshDb.objById(smObject.id);@smFreshMainObject=smFreshMain.objById(smMainObject.id);
                if(smFreshObject !is null && smFreshMainObject !is null && smFreshObject.mdParentLink !is null){
                    @smFreshParent=smFreshObject.mdParentLink.getMDObject();
                    smAfter=ahCatalogSameV218(smFreshObject.unk,smObject.unk) && ahCatalogSameV218(smFreshMainObject.unk,smMainObject.unk)
                        && smFreshParent !is null && ahCatalogSameV218(smFreshParent.unk,smParent.unk)
                        && !smFreshObject.isModified() && !smFreshMainObject.isModified() && !smFreshParent.isModified();
                }
            }
        }
        if(smFinalCatcher.hasException){smAfter=false;smFinalException=true;}
    }
    // Counted handles (including failed branches) end before body publication.
    @smEntry=null;@smStorage=null;@smMemory=null;@smFile=null;@smPin=null;
    @smFreshObject=null;@smFreshParent=null;@smFreshMainObject=null;@smObject=null;@smMainObject=null;@smParent=null;
    @smFreshMain=null;@smFreshDb=null;@smDb=null;@smMain=null;@smRoundtrip=null;@smManager=null;@smIb=null;@smUi=null;
    @smDesigner=null;@smDispatch=null;@smShell=null;@smCore=null;
    smClean=smEntry is null && smStorage is null && smMemory is null && smFile is null && smPin is null && smFreshObject is null && smFreshParent is null
        && smFreshMainObject is null && smObject is null && smMainObject is null && smParent is null && smFreshMain is null && smFreshDb is null && smDb is null
        && smMain is null && smRoundtrip is null && smManager is null && smIb is null && smUi is null && smDesigner is null && smDispatch is null && smShell is null && smCore is null;
    // Releasing our handles grants no opportunity to publish a snapshot under
    // a changed global owner/prefix. This probe creates no new owned handles.
    {ExceptionCatcher smPostCatcher;CppCatch smPostCaught("class core::Exception",ExceptionHandler(smPostCatcher.handle));
        bool smPostOwner=ahPipeScopeAlive() && ahGetCurrentProcessId()==48936 && ahGetCurrentThreadId()==8292
            && ahStatusUi !is null && uint(mem::addressOf(ahStatusUi))==smUiAddress && !ahStatusUi.isModified();
        smPrefix=smPrefix && smPostOwner && oneDesigner !is null && dspWindows !is null && mainFrame !is null && coreMainFrame !is null
            && uint(mem::addressOf(oneDesigner))==smDesignerAddress && uint(mem::addressOf(dspWindows))==smDispatchAddress
            && uint(mem::addressOf(mainFrame))==smShellAddress && uint(mem::addressOf(coreMainFrame))==smCoreAddress
            && oneAddinMgr is null && oneDesigner._windows is null && oneDesigner._metadata is null && oneDesigner._develop is null
            && idleHandlers.length==smPersistent && idleHandlersSingle.length==smSingle;
        if(smPostCatcher.hasException){smPrefix=false;smFinalException=true;}
    }
    bool smVerified=smRead && smReason==0 && smBefore && smAfter && smPrefix && smClean && !smPending && !smCatcher.hasException && !smFinalException;
    if(!smOwned || !ahCompactPageV108(envelope,384))return;
    bool smHeaderSame=mem::dword[envelope+380]==0x6b5c28e7;
    for(uint smN=0;smN<68;smN++)if(mem::byte[envelope+smN]!=mem::byte[smHeader.bytes+smN])smHeaderSame=false;
    if(!smHeaderSame)return;
    // Page checks cover only the exact write span; C has already sealed its
    // full capacity and tailguard. No partial source copy on a guard failure.
    if(smVerified){
        uint smChecked=0;
        while(smChecked<smBytes){uint smChunk=4096-((uint(smBody)+smChecked)&4095);if(smChunk>smBytes-smChecked)smChunk=smBytes-smChecked;
            if(!ahCompactPageV108(smBody+smChecked,smChunk))break;smChecked+=smChunk;}
        if(smChecked!=smBytes){smVerified=false;smReason=20;}
    }
    if(!smVerified && smReason==0)smReason=21;
    mem::dword[envelope+72]=smReason;mem::dword[envelope+80]=smVerified?smPoints:0;mem::dword[envelope+84]=smVerified?smCrlf:0;
    mem::dword[envelope+88]=smVerified && smBom?1:0;mem::dword[envelope+92]=smVerified && smLf?1:0;
    mem::dword[envelope+96]=smPasses;mem::dword[envelope+100]=smProperties;mem::dword[envelope+104]=smOpens;mem::dword[envelope+108]=smAdopts;
    mem::dword[envelope+112]=smPending?1:0;mem::dword[envelope+116]=smBefore?1:0;mem::dword[envelope+120]=smAfter?1:0;
    mem::dword[envelope+124]=smPrefix?1:0;mem::dword[envelope+128]=smClean?1:0;mem::dword[envelope+132]=smCatcher.hasException || smFinalException?1:0;
    mem::dword[envelope+136]=smVerified?smStoredBytes:0;mem::dword[envelope+140]=smVerified?1383504556:0;mem::dword[envelope+144]=smVerified?100051712:0;
    for(uint smN=0;smN<32;smN++)mem::byte[envelope+288+smN]=mem::byte[smHeader.bytes+16+smN];
    mem::dword[envelope+320]=smRevisionLow;mem::dword[envelope+324]=smRevisionHigh;mem::dword[envelope+328]=smSelector;
    if(smVerified){
        for(uint smN=0;smN<64;smN++){mem::byte[envelope+160+smN]=uint8(smBodyHash[smN]);mem::byte[envelope+224+smN]=uint8(smStoredHash[smN]);}
        if(smBytes>0)mem::memcpy(smBody,mem::addressOf(smFirstBody[0]),smBytes);
        mem::dword[envelope+76]=smBytes;
        mem::dword[envelope+68]=1; // COMPLETE last: never before exact bodycopy.
    }else mem::dword[envelope+68]=2;
}
