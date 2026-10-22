// Fixed stock metadata-policy query. Only the known current UI entry is called.
// Its five listener classes are pinned; no listener is directly dispatched.
// Scratch/lazy cache writes inside the stock query are possible. No writer permit.
void ahTemplatePolicyCurrentQuery() {
    string reason="OWNER",receiverTable="null",slot53Target="null",uiTable="null";
    bool observed=false,repeated=false,documentKnown=false,configMode=false,readOnly=true,documentDirty=false;
    bool sameAsUi=false,sameAsUiCanonical=false,selectionUnchanged=false;
    bool policyIdentityTruncated=false,policyReturned=false,policyReadOnly=true;
    uint policyCalls=0,querySetupAttempts=0;
    uint delegateRegistrationCalls=0;bool legacyPolicyDisabled=false,delegateTargetVerified=false,delegateReused=false;
    uint readinessBefore=0,readinessAfter=0,templateMemorySerializations=0,explicitModuleStatisticQueries=0;
    string readinessRows="[]",templateHash="";bool readinessVerified=false;
    array<string> readyIds={"176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
    array<string> readyHashes={"506fe9bd7d1ade475a54dd4bfabb22f82d91a634b2477f44fdcc38b96f9417b6","c5b596a38e554aa34e1e1adba527e45db35516b8e72772c6724645ed481b81ba"};
    array<uint> readyLengths={102426,39129},readyVersions={2272,1646};
    array<IMDObject@> readyObjects(2);array<IMDEditHelper@> readyHelpers(2);
    array<IMDEditModuleHelper@> readyModules(2);array<ITextManager@> readyTexts(2);
    array<ITextEditor@> readyEditors(2);array<IDocument@> readyDocuments(2);
    array<v8string> readyBefore(2);int_ptr readyProvider=0;Guid readyActor;
    array<string> expectedModules={"frntend.dll","config.dll","config.dll","frntend.dll","frntend.dll"};
    array<uint> expectedTables={12643676,2855428,2857460,12894004,12894240};
    array<uint> expectedTargets={1384496,1063376,1295936,4390624,4394960};
    uint passes=0,connectionSlots=0,matchedSinks=0,policyPasses=0,policyListenerCount=0;
    string aggregateTable="null",aggregateTarget="null",policyRows="[]";
    int_ptr policyBegin=0,policyEnd=0;uint policyScratch=0;
    array<int_ptr> firstListeners,firstListenerTables,firstListenerTargets;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(sizeof_ptr!=4 || ahStatusUi is null || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            reason="LEGACY_POLICY_ENABLED";if(ahObjectV57Enabled)break;legacyPolicyDisabled=true;
            Guid seed("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}");
            if(!ahAccessSelectionV232(seed))break;
            IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();reason="ROOT";
            if(!ahCatalogEditableV218(root) || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
                || root.isModified() || ui.isModified())break;
            Guid target("{8daef957-4ae2-48a1-bf6c-b88163a076f5}");
            Guid property("{8eb4fad1-1fa6-403e-970f-2c12dbb43e23}");
            IMDObject@ object=root.objById(target);reason="TARGET";
            if(object is null || object.id!=target || object.isModified() || object.mdClass is null
                || object.mdClass.id!=Guid("{3daea016-69b7-4ed4-9453-127911372fe6}") || object.mdParentLink is null)break;
            IMDObject@ parent=object.mdParentLink.getMDObject();
            if(parent is null || parent.id!=Guid("{686a3dbe-be94-45e7-9e8b-dd93f0cd579c}")
                || parent.isModified() || !ahCatalogLinkV218(object,parent,root))break;
            IMDEditService@ service=getMDEditService();IMDEditHelper@ helper;reason="HELPER";
            if(service is null)break;service.getEditHelper(helper,object);
            if(helper is null || helper.getMDObj() is null || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                || !ahCompactTableV108(helper.self,"frntend.dll",12897096,37)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[helper.self]+36*4],"frntend.dll",4529728)
                || helper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))break;
            // Closed stock wrapper and getMDObj getter prove the same primary
            // owner adjustment and its metadata object/receiver fields.
            int_ptr owner=helper.self-0x7c,metadataObject=helper.getMDObj().self;reason="OWNER_LAYOUT";
            if(owner==0 || !ahCompactPageV108(owner,0x34)
                || mem::int_ptr[owner+0x1c]!=metadataObject)break;
            int_ptr receiver=mem::int_ptr[owner+0x30];reason="RECEIVER_PAGE";
            if(receiver==0 || !ahCompactPageV108(receiver,4))break;
            int_ptr table=mem::int_ptr[receiver];
            if(table==0 || !ahCompactPageV108(table,54*4))break;
            int_ptr target53=mem::int_ptr[table+53*4];
            receiverTable=ahRepoAddress(table);slot53Target=ahRepoAddress(target53);
            // Numeric comparison is not a QueryInterface claim about receiver.
            sameAsUi=receiver==ui.self;
            if(!ahCompactPageV108(ui.self,4))break;uiTable=ahRepoAddress(mem::int_ptr[ui.self]);
            Guid canonical("{00000000-0000-0000-c000-000000000046}");IUnknown@ uiIdentity;
            reason="KNOWN_UI_IDENTITY";
            if(ui.queryIface(canonical,uiIdentity)!=0 || uiIdentity is null)break;
            sameAsUiCanonical=receiver==uiIdentity.self;
            // The stock slot53 wrapper addresses this member only on the
            // known UI receiver. Unknown receivers remain numbers throughout.
            reason="POLICY_RECEIVER";
            if(!sameAsUi || !ahCompactTableV108(receiver,"frntend.dll",0xc0e458,54)
                || !ahCompactAddressV108(target53,"frntend.dll",0x149900)
                || !ahCompactPageV108(receiver,0xfc))break;
            int_ptr aggregate=receiver+0xec;
            IUnknown@ body;helper.extProp(body,property,false);IDocument@ document=body;reason="DOCUMENT";
            if(document is null || !ahCompactTableV108(document.self,"moxelui.dll",2155168,23))break;
            documentKnown=true;configMode=document.getConfigMode();readOnly=document.getReadOnly();documentDirty=document.isModified();
            // Only these two existing CommonModules may query TCP ownership.
            // No statistic request is made for the new template.
            reason="READINESS_PROVIDER";string access=ahTargetAccessV232();
            if(access.length>131072 || access.find("\"status\":\"OBSERVED\"")<0
                || access.find("\"providerBound\":true")<0 || access.find("\"providerBoundAfterContext\":true")<0
                || !ahAccessSelectionV232(seed))break;
            readyProvider=ahPlanProvider;
            if(!ahCompactPageV108(readyProvider,0x20))break;
            mem::memcpy(readyActor.self,readyProvider+0x10,16);
            if(!ahAccessProviderV232(readyProvider,readyActor))break;
            Guid readyProperty("{d5963243-262e-4398-b4d7-fb16d06484f6}");
            for(uint index=0;index<2;index++){
                reason="READINESS_MODULE";Guid id("{"+readyIds[index]+"}");
                IMDObject@ item=root.objById(id);string propertyName;
                if(item is null || item.id!=id || item.isModified() || item.mdParentLink is null
                    || !ahModulePropertyV225(item,readyProperty,propertyName) || propertyName!="Module")break;
                IMDObject@ itemParent=item.mdParentLink.getMDObject();
                if(itemParent is null || itemParent.id!=root.id || !ahCatalogLinkV218(item,itemParent,root))break;
                string statistic,expected="{\"queried\":true,\"verified\":true,\"version\":"+readyVersions[index]
                    +",\"revised\":true,\"ownerId\":\""+ahCatalogIdV218(readyActor)+"\",\"actorId\":\""+ahCatalogIdV218(readyActor)+"\",\"ownership\":\"OWN\"}";
                reason="READINESS_OWN_VERSION";
                explicitModuleStatisticQueries++;
                if(!ahAccessStatisticV232(readyProvider,readyActor,id,statistic) || statistic!=expected)break;
                IMDEditHelper@ itemHelper;service.getEditHelper(itemHelper,item);IMDEditModuleHelper@ itemModule;
                if(itemHelper !is null)@itemModule=itemHelper.unk;
                if(itemHelper is null || itemModule is null || !ahCatalogSameV218(itemHelper.getMDObj().unk,item.unk))break;
                v8string helperSource;reason="READINESS_MODULE_HASH";
                if(!itemModule.textOfModule(readyProperty,true,helperSource))break;
                utf8string encoded=helperSource.str.toUtf8();
                if(encoded.length!=readyLengths[index])break;
                MemoryBuffer bytes(encoded.length);if(bytes.bytes==0 || bytes._length!=encoded.length)break;
                mem::memcpy(bytes.bytes,encoded.ptr,encoded.length);
                if(ahTemplateRamShaV202(bytes,encoded.length)!=readyHashes[index])break;
                ITextManager@ text;ITextEditor@ editor;uint32 openFlags=0x10101;
                itemModule.openModule(text,readyProperty,openFlags,editor);reason="READINESS_MODULE_EDITOR_ABI";
                if(text is null || editor is null || !ahCompactTableV108(text.self,"txtedt.dll",0x46dc4,11)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[text.self]+10*4],"txtedt.dll",0x2dcf0)
                    || !ahCompactTableV108(editor.self,"txtedui.dll",0x10db3c,4)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[editor.self]],"txtedui.dll",0xe4680)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[editor.self]+3*4],"txtedui.dll",0xa2020))break;
                ITextManager@ linked;editor.getITextManager(linked);IDocument@ itemDocument=text.unk;
                if(linked is null || linked.self!=text.self
                    || mem::addressOf(linked.getTextManager())!=mem::addressOf(text.getTextManager())
                    || itemDocument is null || !ahCompactTableV108(itemDocument.self,"txtedui.dll",0x109978,23)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[itemDocument.self]+8*4],"txtedui.dll",0x74450)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[itemDocument.self]+22*4],"txtedui.dll",0x7d7d0))break;
                v8string editorSource,helperAgain;reason="READINESS_MODULE_STATE";
                if(itemDocument.isModified() || itemDocument.getReadOnly() || !text.getTextManager().save(editorSource)
                    || editorSource.str!=helperSource.str || !itemModule.textOfModule(readyProperty,true,helperAgain)
                    || helperAgain.str!=helperSource.str || item.isModified() || root.isModified() || ui.isModified())break;
                @readyObjects[index]=item;@readyHelpers[index]=itemHelper;@readyModules[index]=itemModule;
                @readyTexts[index]=text;@readyEditors[index]=editor;@readyDocuments[index]=itemDocument;
                readyBefore[index]=helperSource;readinessBefore++;
            }
            if(readinessBefore!=2)break;
            IConnectionPointContainer@ container=document.unk;IUnknown@ connection;reason="DOCUMENT_CONNECTION";
            if(container is null || container.FindConnectionPoint(IID_IDocumentSink,connection)!=0 || connection is null)break;
            int_ptr cp=connection.self;array<uint> cpSlots={748336,1187729,1187067,1167968,1167936,751456,751664,751792};
            int_ptr firstData=0;uint firstCount=0;array<int_ptr> firstEntries;
            for(uint pass=0;pass<4;pass++){
                reason="CONNECTION_ABI";
                if(!ahCompactTableV108(cp,"moxelui.dll",2155136,8) || !ahCompactPageV108(cp,12))break;
                bool known=true;int_ptr cpTable=mem::int_ptr[cp];
                for(uint i=0;i<8;i++)if(!ahCompactAddressV108(mem::int_ptr[cpTable+i*4],"moxelui.dll",cpSlots[i]))known=false;
                if(!known)break;int_ptr data=mem::int_ptr[cp+4];uint count=mem::dword[cp+8];reason="CONNECTION_BOUNDS";
                if(count==0 || count>16 || !ahCompactPageV108(data,count*4))break;
                uint matches=0;array<int_ptr> entries;
                for(uint i=0;i<count;i++){
                    int_ptr sink=mem::int_ptr[data+i*4];entries.insertLast(sink);if(sink==0)continue;
                    if(!ahCompactPageV108(sink,4)){known=false;break;}
                    if(!ahCompactTableV108(sink,"frntend.dll",12837396,7))continue;
                    if(!ahCompactPageV108(sink,36)
                        || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[sink]+3*4],"frntend.dll",2716288)){known=false;break;}
                    Guid storedProperty;mem::memcpy(storedProperty.self,sink+20,16);
                    if(storedProperty==property && mem::int_ptr[sink+16]==owner)matches++;
                }
                reason="DOCUMENT_BINDING";if(!known || matches!=1)break;
                if(pass==0){firstData=data;firstCount=count;firstEntries=entries;}
                else{
                    if(data!=firstData || count!=firstCount || entries.length!=firstEntries.length)break;
                    for(uint i=0;i<entries.length;i++)if(entries[i]!=firstEntries[i])known=false;
                    if(!known)break;
                }
                // Read only the same guarded unknown receiver/table again.
                reason="RECEIVER_CHANGED";
                if(!ahCompactPageV108(owner,0x34) || mem::int_ptr[owner+0x30]!=receiver
                    || !ahCompactPageV108(receiver,4) || mem::int_ptr[receiver]!=table
                    || !ahCompactPageV108(table,54*4) || mem::int_ptr[table+53*4]!=target53
                    || mem::int_ptr[owner+0x1c]!=metadataObject)break;
                // Pinned 143770 walks [aggregate+8,aggregate+12) in 4-byte
                // strides and dispatches listener.slot7. We only read it.
                reason="POLICY_AGGREGATE";
                if(receiver!=ui.self || !ahCompactPageV108(aggregate,16)
                    || !ahCompactTableV108(aggregate,"frntend.dll",0xc0e304,16))break;
                int_ptr aggregateVtable=mem::int_ptr[aggregate];
                int_ptr aggregateSlot8=mem::int_ptr[aggregateVtable+8*4];
                if(!ahCompactAddressV108(aggregateSlot8,"frntend.dll",0x143770))break;
                aggregateTable=ahRepoAddress(aggregateVtable);aggregateTarget=ahRepoAddress(aggregateSlot8);
                int_ptr begin=mem::int_ptr[aggregate+8],end=mem::int_ptr[aggregate+12];
                uint scratch=mem::byte[aggregate+6];reason="POLICY_VECTOR_BOUNDS";
                if(uint(end)<uint(begin) || uint(end-begin)>16*4 || uint(end-begin)%4!=0
                    || (begin!=end && (begin==0 || !ahCompactPageV108(begin,uint(end-begin)))))break;
                uint listeners=uint(end-begin)/4;reason="EXACT_FIVE_LISTENERS";
                if(listeners!=5 || scratch!=0)break;
                array<int_ptr> listenerPointers,listenerTables,listenerTargets;
                string rows="[";known=true;reason="POLICY_LISTENER_PAGE";
                for(uint i=0;i<listeners;i++){
                    int_ptr listener=mem::int_ptr[begin+i*4];
                    if(listener==0 || !ahCompactPageV108(listener,4)){known=false;break;}
                    int_ptr listenerTable=mem::int_ptr[listener];
                    if(listenerTable==0 || !ahCompactPageV108(listenerTable,8*4)){known=false;break;}
                    int_ptr listenerTarget=mem::int_ptr[listenerTable+7*4];
                    if(listenerTarget==0 || !ahCompactTableV108(listener,expectedModules[i],expectedTables[i],8)
                        || !ahCompactAddressV108(listenerTarget,expectedModules[i],expectedTargets[i])){known=false;break;}
                    listenerPointers.insertLast(listener);listenerTables.insertLast(listenerTable);listenerTargets.insertLast(listenerTarget);
                    string tableInfo=ahRepoAddress(listenerTable),targetInfo=ahRepoAddress(listenerTarget);
                    if(tableInfo.toUtf8().length>128){tableInfo="null";policyIdentityTruncated=true;}
                    if(targetInfo.toUtf8().length>128){targetInfo="null";policyIdentityTruncated=true;}
                    if(i!=0)rows+=",";
                    rows+="{\"index\":"+i+",\"pointer\":"+uint(listener)
                        +",\"table\":"+tableInfo+",\"slot7Target\":"+targetInfo+"}";
                }
                if(!known)break;rows+="]";reason="POLICY_VECTOR_CHANGED";
                if(pass==0){
                    policyBegin=begin;policyEnd=end;policyScratch=scratch;policyListenerCount=listeners;
                    firstListeners=listenerPointers;firstListenerTables=listenerTables;firstListenerTargets=listenerTargets;
                }else{
                    if(begin!=policyBegin || end!=policyEnd || scratch!=policyScratch || listeners!=policyListenerCount)break;
                    for(uint i=0;i<listeners;i++)if(listenerPointers[i]!=firstListeners[i]
                        || listenerTables[i]!=firstListenerTables[i] || listenerTargets[i]!=firstListenerTargets[i])known=false;
                    if(!known)break;
                }
                if(pass==3){
                    reason="READINESS_POST_QUERY";
                    for(uint index=0;index<2;index++){
                        IMDObject@ item=readyObjects[index];IMDEditHelper@ itemHelper=readyHelpers[index];
                        IMDEditModuleHelper@ itemModule=readyModules[index];ITextManager@ text=readyTexts[index];
                        ITextEditor@ editor=readyEditors[index];IDocument@ itemDocument=readyDocuments[index];
                        IMDObject@ freshItem=root.objById(Guid("{"+readyIds[index]+"}"));
                        ITextManager@ linked;editor.getITextManager(linked);IDocument@ currentItemDocument=text.unk;
                        v8string helperSource,editorSource;
                        if(freshItem is null || !ahCatalogSameV218(freshItem.unk,item.unk)
                            || !ahCatalogSameV218(itemHelper.getMDObj().unk,item.unk) || linked is null || linked.self!=text.self
                            || currentItemDocument is null || !ahCatalogSameV218(currentItemDocument.unk,itemDocument.unk)
                            || mem::addressOf(linked.getTextManager())!=mem::addressOf(text.getTextManager())
                            || !ahCompactTableV108(itemDocument.self,"txtedui.dll",0x109978,23)
                            || item.isModified() || itemDocument.isModified() || itemDocument.getReadOnly()
                            || !itemModule.textOfModule(readyProperty,true,helperSource) || !text.getTextManager().save(editorSource)
                            || helperSource.str!=readyBefore[index].str || editorSource.str!=readyBefore[index].str)break;
                        string statistic,expected="{\"queried\":true,\"verified\":true,\"version\":"+readyVersions[index]
                            +",\"revised\":true,\"ownerId\":\""+ahCatalogIdV218(readyActor)+"\",\"actorId\":\""+ahCatalogIdV218(readyActor)+"\",\"ownership\":\"OWN\"}";
                        explicitModuleStatisticQueries++;
                        if(!ahAccessStatisticV232(readyProvider,readyActor,freshItem.id,statistic) || statistic!=expected)break;
                        readinessAfter++;
                    }
                    if(readinessAfter!=2)break;
                }
                reason="CONTEXT_CHANGED";IMDObject@ fresh=root.objById(target);
                IUnknown@ currentBody;helper.extProp(currentBody,property,false);IDocument@ currentDocument=currentBody;
                if(ahStatusUi !is ui || !ahPipeScopeAlive() || fresh is null
                    || currentDocument is null || !ahCatalogSameV218(currentDocument.unk,document.unk)
                    || !ahCatalogSameV218(fresh.unk,object.unk) || !ahCatalogSameV218(ui.getMDCont().unk,root.unk)
                    || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                    || root.isModified() || ui.isModified() || object.isModified() || parent.isModified()
                    || document.getConfigMode()!=configMode || document.getReadOnly()!=readOnly
                    || document.isModified()!=documentDirty || !ahAccessSelectionV232(seed)
                    || mem::int_ptr[cp+4]!=data || mem::dword[cp+8]!=count
                    || mem::int_ptr[aggregate]!=aggregateVtable || mem::int_ptr[aggregateVtable+8*4]!=aggregateSlot8
                    || mem::int_ptr[aggregate+8]!=begin || mem::int_ptr[aggregate+12]!=end
                    || mem::byte[aggregate+6]!=scratch)break;
                for(uint i=0;i<listeners;i++){
                    int_ptr listener=listenerPointers[i],listenerTable=listenerTables[i];
                    if(mem::int_ptr[begin+i*4]!=listener || !ahCompactPageV108(listener,4)
                        || mem::int_ptr[listener]!=listenerTable || !ahCompactPageV108(listenerTable,8*4)
                        || mem::int_ptr[listenerTable+7*4]!=listenerTargets[i])known=false;
                }
                if(!known)break;
                for(uint i=0;i<count;i++)if(mem::int_ptr[data+i*4]!=entries[i])known=false;
                if(!known)break;
                policyRows=rows;policyPasses++;connectionSlots=count;matchedSinks=matches;passes++;
                if(pass==1){
                    // Native sheet serialization clears dirty; it is allowed
                    // only here, before any query/write and already clean.
                    reason="READINESS_TEMPLATE_CHECKPOINT";
                    if(root.isModified() || ui.isModified() || object.isModified() || parent.isModified()
                        || document.isModified() || document.getReadOnly())break;
                    IPersistableDocument@ persistent=document.unk;IFileEx@ memory;
                    if(persistent is null)break;templateMemorySerializations++;
                    if(!ahSheetSnapshotV231(persistent,memory,templateHash)
                        || templateHash!="6d20f90eed3d8656fb669dcbd2701155eb481e839af968398597f6959a4842ed"
                        || memory is null || memory.seek(0,fsEnd)!=5706 || memory.seek(0,fsBegin)!=0
                        || document.isModified() || object.isModified() || root.isModified() || ui.isModified())break;
                    // Existing published-to-the-tool funcdef matches the
                    // stock stdcall(self, metadataObject, uint32 mode), AL bool.
                    // CoreAs initFuncDef registers a global native function;
                    // repeating it poisons the engine. Reuse the existing V57
                    // cache ONLY in this closed profile with legacy disabled.
                    // Legacy uses a DIFFERENT state.slot7 and must stay off.
                    reason="LEGACY_POLICY_ENABLED";
                    if(ahObjectV57Enabled)break;legacyPolicyDisabled=true;
                    reason="STOCK_QUERY_BIND";
                    querySetupAttempts++;
                    delegateReused=ahObjectPolicyV57 !is null;
                    if(ahObjectPolicyV57 is null){
                        delegateRegistrationCalls++;
                        initFuncDefFromAddress(target53,@ahObjectPolicyV57,asCALL_STDCALL);
                    }
                    if(ahObjectPolicyV57 is null)break;
                    // Pinned CoreAs: addressOf returns &handle; constructor
                    // table28f45c, function+d0 owns sysInterface, sys[0] is the
                    // registered native target, sys+8 is native stdcall=4.
                    int_ptr handleAddress=mem::addressOf(@ahObjectPolicyV57);
                    reason="CACHED_POLICY_TARGET";
                    if(!ahCompactPageV108(handleAddress,4))break;
                    int_ptr cachedFunction=mem::int_ptr[handleAddress];
                    if(!ahCompactTableV108(cachedFunction,"core_as.dll",0x28f45c,40)
                        || !ahCompactPageV108(cachedFunction,0xd4))break;
                    int_ptr nativeInterface=mem::int_ptr[cachedFunction+0xd0];
                    if(!ahCompactPageV108(nativeInterface,0x54) || mem::int_ptr[nativeInterface]!=target53
                        || mem::dword[nativeInterface+8]!=4 || ahObjectV57Enabled)break;
                    delegateTargetVerified=true;
                    reason="STOCK_QUERY_CALL";policyCalls++;
                    policyReadOnly=ahObjectPolicyV57(ui.self,metadataObject,0);policyReturned=true;
                    if(ahObjectV57Enabled || mem::int_ptr[handleAddress]!=cachedFunction
                        || mem::int_ptr[cachedFunction+0xd0]!=nativeInterface
                        || mem::int_ptr[nativeInterface]!=target53 || mem::dword[nativeInterface+8]!=4){
                        delegateTargetVerified=false;reason="CACHED_POLICY_CHANGED";break;
                    }
                }
            }
            if(passes!=4 || policyPasses!=4 || policyCalls!=1 || !policyReturned || readinessAfter!=2
                || !legacyPolicyDisabled || ahObjectV57Enabled || !delegateTargetVerified)break;
            readinessRows="[{\"objectId\":\"8daef957-4ae2-48a1-bf6c-b88163a076f5\",\"propertyId\":\"8eb4fad1-1fa6-403e-970f-2c12dbb43e23\""
                +",\"helperSha256\":\""+templateHash+"\",\"editorSha256\":\""+templateHash+"\",\"sourceBytes\":5706"
                +",\"objectClean\":true,\"editorClean\":true,\"readOnly\":"+readOnly+",\"editorBound\":true,\"ownership\":\"UNKNOWN\",\"repositoryVersion\":0}";
            for(uint index=0;index<2;index++)readinessRows+=",{\"objectId\":\""+readyIds[index]+"\",\"propertyId\":\"d5963243-262e-4398-b4d7-fb16d06484f6\""
                +",\"helperSha256\":\""+readyHashes[index]+"\",\"editorSha256\":\""+readyHashes[index]+"\",\"sourceBytes\":"+readyLengths[index]
                +",\"objectClean\":true,\"editorClean\":true,\"readOnly\":false,\"editorBound\":true,\"ownership\":\"OWN\",\"repositoryVersion\":"+readyVersions[index]+"}";
            readinessRows+="]";readinessVerified=true;repeated=true;observed=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){observed=false;reason="NATIVE_EXCEPTION";}
    selectionUnchanged=ahAccessSelectionV232(Guid("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}"));
    if(!selectionUnchanged){observed=false;reason="SELECTION_CHANGED";}
    string result="{\"version\":1,\"probe\":\"TEMPLATE_POLICY_CURRENT_QUERY\",\"status\":\""+(observed?"OBSERVED":"REFUSED")+"\",\"reason\":\""+reason
        +"\",\"receiverTable\":"+receiverTable+",\"slot53Target\":"+slot53Target+",\"uiTable\":"+uiTable
        +",\"numericSameAsUi\":"+sameAsUi+",\"numericSameAsUiCanonical\":"+sameAsUiCanonical
        +",\"repeatedIdentity\":"+repeated+",\"bindingPasses\":"+passes+",\"documentBindingVerified\":"+observed
        +",\"connectionSlots\":"+connectionSlots+",\"matchedSinks\":"+matchedSinks+",\"documentKnown\":"+documentKnown
        +",\"configMode\":"+configMode+",\"documentReadOnly\":"+readOnly+",\"documentModified\":"+documentDirty
        +",\"policyAggregateTable\":"+aggregateTable+",\"policyAggregateSlot8Target\":"+aggregateTarget
        +",\"policyPasses\":"+policyPasses+",\"policyListenerCount\":"+policyListenerCount
        +",\"policyScratchByte\":"+policyScratch+",\"policyListeners\":"+policyRows
        +",\"policyIdentityTruncated\":"+policyIdentityTruncated
        +",\"unknownListenerCalls\":0,\"unknownListenerQueries\":0"
        +",\"selectionUnchanged\":"+selectionUnchanged+",\"unknownReceiverCalls\":0,\"unknownReceiverQueries\":0"
        +",\"querySetupAttempts\":"+querySetupAttempts+",\"policyCalls\":"+policyCalls
        +",\"delegateRegistrationCalls\":"+delegateRegistrationCalls+",\"delegateReused\":"+delegateReused
        +",\"legacyPolicyDisabled\":"+legacyPolicyDisabled+",\"delegateTargetVerified\":"+delegateTargetVerified
        +",\"policyReturned\":"+policyReturned+",\"stockReadOnly\":"+(policyReturned?(policyReadOnly?"true":"false"):"null")
        +",\"preBindingPasses\":"+(passes>2?2:passes)+",\"postBindingPasses\":"+(passes>2?passes-2:0)
        +",\"queryMode\":0,\"policyMeaningVerified\":"+(observed && policyReturned)
        +",\"stockPolicyMayWriteScratch\":true,\"stockPolicyMayResolveLazyCache\":true,\"forcedFlagWrites\":0"
        +",\"readinessVerified\":"+(observed && readinessVerified)+",\"readinessBefore\":"+readinessBefore+",\"readinessAfter\":"+readinessAfter
        +",\"targets\":"+readinessRows+",\"templateMemorySerializations\":"+templateMemorySerializations
        +",\"templateStatisticQueries\":0,\"explicitModuleStatisticQueries\":"+explicitModuleStatisticQueries+",\"moduleSourceOutputBytes\":0"
        +",\"permissionGranted\":false,\"configurationExports\":0,\"configurationImports\":0"
        +",\"sourceWrites\":0,\"metadataWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"writerAuthorized\":false}";
    ExceptionCatcher output;
    {CppCatch caught("class core::Exception",ExceptionHandler(output.handle));if(result.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",result);}
}
