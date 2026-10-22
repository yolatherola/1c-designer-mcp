// Fixed native clone recipe. Real metadata body is only an identity/type witness.
// Expected saved bytes never leave RAM; output is hashes/counts, not content.
void ahExpectedSavedTemplate() {
    string reason="OWNER",key="",resourceHash="",baselineHash="",expectedHash="",roundHash="";
    bool verified=false,pendingReference=false;uint bindings=0,opens=0,adopted=0;
    uint resourceBytes=0,expectedBytes=0,coldLoads=0,coldSnapshots=0,merges=0,setters=0,outsideComparisons=0,roundComparisons=0;
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
            IFileEx@ saved=pin;if(saved is null)break;
            IUnknown@ liveBody;helper.extProp(liveBody,property,false);
            IDocument@ liveDocument=liveBody;IValue@ liveValue=liveBody;
            reason="LIVE_DOCUMENT";
            if(liveDocument is null || liveValue is null || liveDocument.isModified()
                || !ahCompactTableV108(liveDocument.self,"moxelui.dll",2155168,23)
                || root.isModified() || ui.isModified() || object.isModified() || parent.isModified())break;
            bool readOnly=liveDocument.getReadOnly(),liveMode=liveDocument.getConfigMode();
            reason="SAVED_BASELINE";uint64 size=saved.seek(0,fsEnd);
            if(size==0 || size>262144 || saved.seek(0,fsBegin)!=0)break;
            resourceBytes=uint(size);MemoryBuffer resource(resourceBytes);
            if(saved.read(resource.bytes,resourceBytes)!=resourceBytes || saved.seek(0,fsCurrent)!=size)break;
            resourceHash=ahTemplateRamShaV202(resource,resourceBytes);
            // Fixed current baseline witnessed in b230/0901. Do not silently
            // build an expected candidate from somebody else's changed body.
            if(resourceBytes!=5706 || resourceHash!="4927cf433c0b913f2b56b413f4edbb85655dc5d85d520802aae237694ec3ba6d")break;
            IFileEx@ checkpoint;reason="OWN_BASELINE_MEMORY";
            if(!currentProcess().createByClsid(CLSID_MemoryFile,IID_IFileEx,checkpoint)
                || checkpoint is null || checkpoint.seek(0,fsEnd)!=0)break;
            checkpoint.write(resource.bytes,resourceBytes);
            if(checkpoint.seek(0,fsEnd)!=resourceBytes || checkpoint.seek(0,fsBegin)!=0)break;
            IFile@ input=checkpoint.unk;IType@ type=liveValue.getType();reason="TYPE";
            if(input is null || type is null || string(type.getTypeString(0))!="SpreadsheetDocument")break;
            array<IValue@> values(3);array<IPersistableDocument@> documents(3);array<IContext@> contexts(3);
            uint made=0;
            for(uint index=0;index<2;index++) {
                reason="COLD_FACTORY";IValue@ value;type.createValue(value);
                if(value is null || ahCatalogSameV218(value.unk,liveBody)
                    || (index==1 && ahCatalogSameV218(value.unk,values[0].unk)))break;
                @values[index]=value;@documents[index]=value.unk;@contexts[index]=value.unk;
                if(documents[index] is null || contexts[index] is null || checkpoint.seek(0,fsBegin)!=0)break;
                reason="COLD_BASELINE_LOAD";coldLoads++;documents[index].load(input);made++;
            }
            if(made!=2)break;
            IFileEx@ baseline;reason="BASELINE_CANONICAL";coldSnapshots++;
            if(!ahSheetSnapshotV231(documents[0],baseline,baselineHash) || baselineHash!=resourceHash)break;
            int height=0,width=0;
            if(!ahCellNumberV230(contexts[0],"TableHeight",height) || !ahCellNumberV230(contexts[0],"TableWidth",width)
                || height!=25 || width!=10)break;
            array<int> rows={11,13,16};bool recipe=true;
            reason="FIXED_RECIPE";
            for(uint index=0;index<rows.length;index++) {
                string serviceText,staffText,serviceParameter,staffParameter;
                IContext@ serviceArea=ahSheetAreaV231(contexts[0],rows[index],2,4),staffArea=ahSheetAreaV231(contexts[0],rows[index],5,7);
                if(serviceArea is null || staffArea is null || !ahSheetStringV231(serviceArea,"Text",serviceText)
                    || !ahSheetStringV231(staffArea,"Text",staffText) || !ahSheetStringV231(serviceArea,"Parameter",serviceParameter)
                    || !ahSheetStringV231(staffArea,"Parameter",staffParameter)){recipe=false;break;}
                if((index==0 && (serviceText!="Услуга / занятие" || staffText!="Специалист" || serviceParameter!="" || staffParameter!=""))
                    || (index>0 && (serviceParameter!="Услуга" || staffParameter!="Сотрудник"))){recipe=false;break;}
                uint writes=0;string why;
                if(!ahSheetMergeCopyV231(contexts[1],contexts[0],rows[index],writes,why)){recipe=false;reason="RECIPE_"+why;break;}
                merges++;setters+=writes;
            }
            if(!recipe || merges!=3 || setters!=36)break;
            reason="EXPECTED_CANONICAL";IFileEx@ expected;coldSnapshots++;
            if(!ahSheetSnapshotV231(documents[1],expected,expectedHash) || expectedHash==baselineHash)break;
            uint64 expectedSize=expected.seek(0,fsEnd);
            if(expectedSize==0 || expectedSize>262144)break;expectedBytes=uint(expectedSize);
            IValue@ roundValue;type.createValue(roundValue);reason="ROUND_FACTORY";
            if(roundValue is null || ahCatalogSameV218(roundValue.unk,liveBody)
                || ahCatalogSameV218(roundValue.unk,values[0].unk) || ahCatalogSameV218(roundValue.unk,values[1].unk))break;
            @values[2]=roundValue;@documents[2]=roundValue.unk;@contexts[2]=roundValue.unk;
            IFile@ expectedInput=expected.unk;
            if(documents[2] is null || contexts[2] is null || expectedInput is null || expected.seek(0,fsBegin)!=0)break;
            reason="ROUND_LOAD";coldLoads++;documents[2].load(expectedInput);
            IFileEx@ round;reason="ROUND_CANONICAL";coldSnapshots++;
            if(!ahSheetSnapshotV231(documents[2],round,roundHash) || roundHash!=expectedHash || round.seek(0,fsEnd)!=expectedSize)break;
            array<string> names={"Text","Parameter","FillType","Font","BackColor","TextColor","LeftBorder","TopBorder",
                "RightBorder","BottomBorder","ColumnWidth","RowHeight","VerticalAlign","HorizontalAlign","Format"};
            bool same=true;reason="PROPERTIES";
            for(int row=1;row<=25 && same;row++)for(int col=1;col<=10 && same;col++) {
                IContext@ baselineArea=ahSheetAreaV231(contexts[0],row,col,col),expectedArea=ahSheetAreaV231(contexts[1],row,col,col);
                IContext@ roundArea=ahSheetAreaV231(contexts[2],row,col,col);
                if(baselineArea is null || expectedArea is null || roundArea is null){same=false;break;}
                bool changedCell=(row==11 || row==13 || row==16) && col>=2 && col<=7;
                for(uint propertyIndex=0;propertyIndex<names.length;propertyIndex++) {
                    Value expectedValue,roundCellValue,originalValue;
                    if(!ahSheetGetV231(expectedArea,names[propertyIndex],expectedValue)
                        || !ahSheetGetV231(roundArea,names[propertyIndex],roundCellValue) || !ahSheetEqualV231(expectedValue,roundCellValue)){same=false;break;}
                    roundComparisons++;
                    if(!changedCell){
                        if(!ahSheetGetV231(baselineArea,names[propertyIndex],originalValue)
                            || !ahSheetEqualV231(originalValue,expectedValue)){same=false;break;}outsideComparisons++;
                    }
                }
            }
            if(!same || roundComparisons!=3750 || outsideComparisons!=3480)break;
            reason="DIMENSIONS_AND_PARAMETERS";
            for(uint index=1;index<3;index++) {
                int h=0,w=0;string header;
                if(!ahCellNumberV230(contexts[index],"TableHeight",h) || !ahCellNumberV230(contexts[index],"TableWidth",w)
                    || h!=25 || w!=10 || !ahSheetStringV231(ahSheetAreaV231(contexts[index],11,2,7),"Text",header)
                    || header!="Специалист"){same=false;break;}
                for(uint n=1;n<rows.length;n++){
                    string parameter;if(!ahSheetStringV231(ahSheetAreaV231(contexts[index],rows[n],2,7),"Parameter",parameter)
                        || parameter!="Сотрудник"){same=false;break;}
                }
            }
            if(!same || coldLoads!=3 || coldSnapshots!=3)break;
            reason="BASELINE_RESOURCE_CHANGED";MemoryBuffer finalResource(resourceBytes);
            if(saved.seek(0,fsEnd)!=resourceBytes || saved.seek(0,fsBegin)!=0
                || saved.read(finalResource.bytes,resourceBytes)!=resourceBytes
                || ahTemplateRamShaV202(finalResource,resourceBytes)!=resourceHash)break;
            reason="FINAL_STATE";
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
                || liveDocument.getConfigMode()!=liveMode || root.isModified() || ui.isModified() || object.isModified() || parent.isModified())break;
            verified=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){verified=false;reason="NATIVE_EXCEPTION";}
    string proof="{\"version\":264,\"phase\":\"EXPECTED_SAVED_TEMPLATE\",\"status\":\""
        +(verified?"EXPECTED_RESOURCE_VIEW_VERIFIED":(pendingReference?"UNKNOWN_REFERENCE":"REFUSED"))+"\",\"reason\":\""+reason+"\""
        +",\"templateId\":\"8daef957-4ae2-48a1-bf6c-b88163a076f5\",\"bindingPasses\":"+bindings
        +",\"resourceBytes\":"+resourceBytes+",\"resourceSha256\":\""+resourceHash+"\",\"baselineCanonicalSha256\":\""+baselineHash
        +"\",\"expectedSavedCanonicalSha256\":\""+expectedHash+"\",\"roundCanonicalSha256\":\""+roundHash+"\",\"expectedSavedBytes\":"+expectedBytes
        +",\"resourceOpens\":"+opens+",\"adoptedFiles\":"+adopted+",\"pendingReference\":"+pendingReference
        +",\"coldLoads\":"+coldLoads+",\"coldSnapshots\":"+coldSnapshots+",\"cloneMerges\":"+merges+",\"cloneSetters\":"+setters
        +",\"roundtripPropertyComparisons\":"+roundComparisons+",\"untouchedPropertyComparisons\":"+outsideComparisons
        +",\"realDocumentSerializations\":0,\"realDocumentSetters\":0,\"applicationBodyOutputBytes\":0,\"metadataWrites\":0"
        +",\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"physicalPersistenceVerified\":false,\"writerAuthorized\":false}";
    ExceptionCatcher output;
    {CppCatch caught("class core::Exception",ExceptionHandler(output.handle));if(proof.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",proof);}
}
