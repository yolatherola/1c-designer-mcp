// Fixed technical observation: saved/live serialization of one known template.
// All bodies and byte values remain in RAM. Only offsets/counts/hashes leave it.
void ahTemplateSerializationDiff() {
    string reason="OWNER",paths="[",pairs="[",key="";bool verified=false,pendingReference=false;
    uint bindings=0,opens=0,adopted=0,liveSnapshots=0,coldLoads=0,coldSnapshots=0;
    array<IFileEx@> readings(4);array<uint> lengths(4,0);array<string> hashes(4,"");
    array<bool> modeKnown(4,false),modes(4,false);array<string> labels={"SAVED_PLAIN","LIVE_CLEAN","COLD_SAVED","COLD_LIVE"};
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(ahStatusUi is null || !ahPipeScopeAlive() || ahGetCurrentProcessId()!=ahFrameOwnerPidV211
                || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();reason="ROOT";
            if(!ahCatalogEditableV218(root) || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
                || root.isModified() || ui.isModified())break;
            IConfigMngr@ manager=root.getConfigMngr();if(manager is null)break;
            int_ptr managerAddress=manager.self,firstInner=0,firstSource=0,firstTarget=0,firstGetter=0;
            Guid id("{8daef957-4ae2-48a1-bf6c-b88163a076f5}"),property("{8eb4fad1-1fa6-403e-970f-2c12dbb43e23}");
            IMDObject@ object=root.objById(id);reason="OBJECT";
            if(object is null || object.id!=id || object.mdClass is null || object.mdParentLink is null
                || object.mdClass.id!=Guid("{3daea016-69b7-4ed4-9453-127911372fe6}") || object.isModified())break;
            IMDObject@ parent=object.mdParentLink.getMDObject();
            if(parent is null || parent.id!=Guid("{686a3dbe-be94-45e7-9e8b-dd93f0cd579c}")
                || parent.isModified() || !ahCatalogLinkV218(object,parent,root))break;
            IMDEditService@ service=getMDEditService();IMDEditHelper@ helper;reason="HELPER";
            if(service is null)break;service.getEditHelper(helper,object);
            if(helper is null || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                || helper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))break;
            for(uint pass=0;pass<2;pass++) {
                reason="BINDING";
                IConfigMngr@ freshManager=root.getConfigMngr();
                IMDObject@ freshObject=root.objById(id);
                if(!ahCatalogSameV218(ui.getMDCont().unk,root.unk) || freshManager is null || freshManager.self!=managerAddress
                    || freshObject is null || !ahCatalogSameV218(freshObject.unk,object.unk)
                    || root.isModified() || ui.isModified() || object.isModified() || parent.isModified())break;
                if(!ahCompactTableV108(managerAddress,"backend.dll",15589540,86) || !ahCompactPageV108(managerAddress,0xd0))break;
                int_ptr inner=mem::int_ptr[managerAddress+0xcc];reason="INNER";
                if(!ahCompactTableV108(inner,"backend.dll",15029196,43) || !ahCompactPageV108(inner,0x174))break;
                int_ptr source=mem::int_ptr[inner+0x16c],target=mem::int_ptr[inner+0x170];reason="FILESYSTEM";
                if(source==target || !ahCompactTableV108(source,"backend.dll",15576968,5)
                    || !ahCompactTableV108(target,"backend.dll",15576968,5))break;
                int_ptr getter=mem::int_ptr[mem::int_ptr[managerAddress]+79*4];reason="LAYERED_GETTER";
                if(!ahCompactAddressV108(getter,"backend.dll",2788960)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[inner]+15*4],"backend.dll",217376)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[source]+4*4],"backend.dll",2573152)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[target]+4*4],"backend.dll",2573152))break;
                Value value;object.mdPropVal(property,value);reason="PROPERTY_URL";
                if(value.pValue is null)break;IMDExtObj@ external=value.pValue.unk;if(external is null)break;
                URL url;external.url(url);string observed=url.url;
                // This exact key was observed in actual b230/0901; never derive a suffix.
                if(observed!="8daef957-4ae2-48a1-bf6c-b88163a076f5.0")break;
                if(pass==0){key=observed;firstInner=inner;firstSource=source;firstTarget=target;firstGetter=getter;}
                else if(observed!=key || inner!=firstInner || source!=firstSource || target!=firstTarget || getter!=firstGetter)break;
                bindings++;
            }
            if(bindings!=2)break;reason="SAVED_GETTER";
            if(ahGMResourceGetterV107 is null)initFuncDefFromAddress(firstGetter,@ahGMResourceGetterV107,asCALL_STDCALL);
            if(ahGMResourceGetterV107 is null)break;
            MemoryBuffer output(36);for(uint n=0;n<36;n++)mem::byte[output.bytes+n]=0xa5;mem::int_ptr[output.bytes+16]=0;
            v8string name=key;URL filename(name);pendingReference=true;opens++;
            int_ptr returned=ahGMResourceGetterV107(managerAddress,output.bytes+16,filename.self,0);
            bool canaries=true;for(uint n=0;n<16;n++)if(mem::byte[output.bytes+n]!=0xa5 || mem::byte[output.bytes+20+n]!=0xa5)canaries=false;
            reason="SAVED_REFERENCE";if(!canaries || returned!=output.bytes+16)break;
            int_ptr address=mem::int_ptr[output.bytes+16];if(address==0){pendingReference=false;break;}
            IUnknown@ pin=toIUnknown(address);pendingReference=false;adopted++;mem::int_ptr[output.bytes+16]=0;
            @readings[0]=pin;if(readings[0] is null)break;
            IUnknown@ liveBody;helper.extProp(liveBody,property,false);
            IDocument@ liveDocument=liveBody;IPersistableDocument@ livePersistent=liveBody;IValue@ liveValue=liveBody;
            reason="LIVE_DOCUMENT";
            if(liveDocument is null || livePersistent is null || liveValue is null || liveDocument.isModified()
                || !ahCompactTableV108(liveDocument.self,"moxelui.dll",2155168,23)
                || root.isModified() || ui.isModified() || object.isModified() || parent.isModified())break;
            bool readOnly=liveDocument.getReadOnly();modeKnown[1]=true;modes[1]=liveDocument.getConfigMode();
            // Exactly one serialization of the real, still-clean body. Nothing
            // in this callback mutates the body or clears an existing dirty flag.
            reason="LIVE_CLEAN_SNAPSHOT";liveSnapshots++;
            if(!ahSheetSnapshotV231(livePersistent,readings[1],hashes[1]) || liveDocument.isModified()
                || root.isModified() || ui.isModified() || object.isModified() || parent.isModified())break;
            IType@ type=liveValue.getType();reason="TYPE";
            if(type is null || string(type.getTypeString(0))!="SpreadsheetDocument")break;
            IValue@ firstCold;
            for(uint branch=0;branch<2;branch++) {
                uint at=branch+2;reason="COLD_FACTORY";IValue@ cold;type.createValue(cold);
                if(cold is null || ahCatalogSameV218(cold.unk,liveBody)
                    || (firstCold !is null && ahCatalogSameV218(cold.unk,firstCold.unk)))break;
                if(branch==0)@firstCold=cold;
                IPersistableDocument@ persistent=cold.unk;IDocument@ modeDocument=cold.unk;
                IFile@ input=readings[branch].unk;
                if(persistent is null || input is null || readings[branch].seek(0,fsBegin)!=0)break;
                reason="COLD_LOAD";coldLoads++;persistent.load(input);
                if(modeDocument !is null){modeKnown[at]=true;modes[at]=modeDocument.getConfigMode();}
                reason="COLD_SNAPSHOT";coldSnapshots++;
                if(!ahSheetSnapshotV231(persistent,readings[at],hashes[at]))break;
            }
            if(coldLoads!=2 || coldSnapshots!=2 || readings[2] is null || readings[3] is null)break;
            reason="BOUNDED_READ";
            for(uint index=0;index<4;index++) {
                uint64 length=readings[index].seek(0,fsEnd);
                if(length==0 || length>262144 || readings[index].seek(0,fsBegin)!=0)break;
                MemoryBuffer bytes(uint(length));
                if(readings[index].read(bytes.bytes,uint(length))!=length || readings[index].seek(0,fsCurrent)!=length)break;
                string hash=ahTemplateRamShaV202(bytes,uint(length));if(hash.length!=64 || (index>0 && hash!=hashes[index]))break;
                hashes[index]=hash;lengths[index]=uint(length);
            }
            if(lengths[0]==0 || lengths[1]==0 || lengths[2]==0 || lengths[3]==0)break;
            array<uint> left={0,0,1},right={1,2,3};array<string> pairNames={"SAVED_VS_LIVE","SAVED_ROUNDTRIP","LIVE_ROUNDTRIP"};
            uint comparedPairs=0;
            for(uint pair=0;pair<3;pair++) {
                uint a=left[pair],b=right[pair],aSize=lengths[a],bSize=lengths[b];
                MemoryBuffer x(aSize),y(bSize);reason="PAIR_READ";
                if(readings[a].seek(0,fsBegin)!=0 || readings[b].seek(0,fsBegin)!=0
                    || readings[a].read(x.bytes,aSize)!=aSize || readings[b].read(y.bytes,bSize)!=bSize
                    || ahTemplateRamShaV202(x,aSize)!=hashes[a] || ahTemplateRamShaV202(y,bSize)!=hashes[b])break;
                uint common=aSize<bSize?aSize:bSize,maximum=aSize>bSize?aSize:bSize;
                uint differences=0,runs=0,prefix=0,suffix=0,runStart=0,bothDigits=0,lineBreaks=0,whitespace=0,nonAscii=0;
                bool inRun=false;string ranges="[";
                for(uint offset=0;offset<maximum;offset++) {
                    bool different=offset>=common || mem::byte[x.bytes+offset]!=mem::byte[y.bytes+offset];
                    if(different){
                        differences++;if(!inRun){runStart=offset;inRun=true;}
                        if(offset<common){
                            uint l=mem::byte[x.bytes+offset],r=mem::byte[y.bytes+offset];
                            if(l>=48 && l<=57 && r>=48 && r<=57)bothDigits++;
                            if(l==10 || l==13 || r==10 || r==13)lineBreaks++;
                            if(l==9 || l==32 || r==9 || r==32)whitespace++;
                            if(l>=128 || r>=128)nonAscii++;
                        }
                    }
                    if(inRun && (!different || offset+1==maximum)){
                        uint stop=different?offset+1:offset;
                        if(runs<16)ranges+=(runs==0?"":",")+"{\"offset\":"+runStart+",\"length\":"+(stop-runStart)+"}";
                        runs++;inRun=false;
                    }
                }
                while(prefix<common && mem::byte[x.bytes+prefix]==mem::byte[y.bytes+prefix])prefix++;
                while(suffix<common-prefix && mem::byte[x.bytes+aSize-1-suffix]==mem::byte[y.bytes+bSize-1-suffix])suffix++;
                ranges+="]";
                pairs+=(pair==0?"":",")+"{\"pair\":\""+pairNames[pair]+"\",\"differentBytes\":"+differences+",\"differentRuns\":"+runs
                    +",\"equal\":"+(aSize==bSize && differences==0)+",\"commonPrefixBytes\":"+prefix+",\"commonSuffixBytes\":"+suffix
                    +",\"bothAsciiDigits\":"+bothDigits+",\"lineBreakDifferences\":"+lineBreaks+",\"whitespaceDifferences\":"+whitespace
                    +",\"nonAsciiDifferences\":"+nonAscii+",\"rangeListComplete\":"+(runs<=16)+",\"ranges\":"+ranges+"}";
                comparedPairs++;
            }
            if(comparedPairs!=3)break;reason="FINAL_STATE";
            IConfigMngr@ finalManager=root.getConfigMngr();IUnknown@ finalBody;helper.extProp(finalBody,property,false);
            Value finalValue;object.mdPropVal(property,finalValue);IMDExtObj@ finalExternal;
            if(finalValue.pValue !is null)@finalExternal=finalValue.pValue.unk;URL finalUrl;
            if(finalExternal is null)break;finalExternal.url(finalUrl);string finalKey=finalUrl.url;
            if(ahStatusUi !is ui || !ahPipeScopeAlive() || ahGetCurrentProcessId()!=ahFrameOwnerPidV211
                || ahGetCurrentThreadId()!=ahFrameOwnerTidV211 || finalManager is null || finalManager.self!=managerAddress
                || !ahCompactTableV108(managerAddress,"backend.dll",15589540,86) || !ahCompactPageV108(managerAddress,0xd0)
                || mem::int_ptr[managerAddress+0xcc]!=firstInner || !ahCompactPageV108(firstInner,0x174)
                || mem::int_ptr[firstInner+0x16c]!=firstSource || mem::int_ptr[firstInner+0x170]!=firstTarget
                || mem::int_ptr[mem::int_ptr[managerAddress]+79*4]!=firstGetter
                || !ahCatalogSameV218(ui.getMDCont().unk,root.unk) || !ahCatalogSameV218(root.objById(id).unk,object.unk)
                || !ahCatalogSameV218(helper.getMDObj().unk,object.unk) || finalBody is null || !ahCatalogSameV218(finalBody,liveBody)
                || finalKey!=key || liveDocument.isModified() || liveDocument.getReadOnly()!=readOnly
                || liveDocument.getConfigMode()!=modes[1] || root.isModified() || ui.isModified() || object.isModified() || parent.isModified())break;
            verified=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){verified=false;reason="NATIVE_EXCEPTION";}
    for(uint index=0;index<4;index++)paths+=(index==0?"":",")+"{\"path\":\""+labels[index]+"\",\"bytes\":"+lengths[index]
        +",\"sha256\":\""+hashes[index]+"\",\"documentModeKnown\":"+modeKnown[index]+",\"configMode\":"+modes[index]+"}";
    paths+="]";pairs+="]";
    string proof="{\"version\":264,\"phase\":\"TEMPLATE_SERIALIZATION_DIFF\",\"status\":\""
        +(verified?"OBSERVED":(pendingReference?"UNKNOWN_REFERENCE":"REFUSED"))+"\",\"reason\":\""+reason+"\",\"bindingPasses\":"+bindings
        +",\"templateId\":\"8daef957-4ae2-48a1-bf6c-b88163a076f5\""
        +",\"resourceOpens\":"+opens+",\"adoptedFiles\":"+adopted+",\"pendingReference\":"+pendingReference+",\"liveCleanSnapshots\":"+liveSnapshots
        +",\"coldLoads\":"+coldLoads+",\"coldSnapshots\":"+coldSnapshots+",\"paths\":"+paths+",\"pairs\":"+pairs
        +",\"byteValuesOutput\":0,\"applicationBodyOutputBytes\":0,\"metadataWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"writerAuthorized\":false}";
    ExceptionCatcher output;
    {CppCatch caught("class core::Exception",ExceptionHandler(output.handle));if(proof.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",proof);}
}
