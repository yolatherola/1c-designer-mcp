// Fixed readonly ABI observation. Unknown policy receiver is never dispatched,
// converted to an interface or queried for IUnknown. No permission is inferred.
void ahTemplatePolicyReceiverV250() {
    string reason="OWNER",receiverTable="null",slot53Target="null",uiTable="null";
    bool observed=false,repeated=false,documentKnown=false,configMode=false,readOnly=true,documentDirty=false;
    bool sameAsUi=false,sameAsUiCanonical=false,selectionUnchanged=false;
    bool policyIdentityTruncated=false;
    uint passes=0,connectionSlots=0,matchedSinks=0,policyPasses=0,policyListenerCount=0;
    string aggregateTable="null",aggregateTarget="null",policyRows="[]";
    int_ptr policyBegin=0,policyEnd=0;uint policyScratch=0;
    array<int_ptr> firstListeners,firstListenerTables,firstListenerTargets;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(sizeof_ptr!=4 || ahStatusUi is null || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
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
            IConnectionPointContainer@ container=document.unk;IUnknown@ connection;reason="DOCUMENT_CONNECTION";
            if(container is null || container.FindConnectionPoint(IID_IDocumentSink,connection)!=0 || connection is null)break;
            int_ptr cp=connection.self;array<uint> cpSlots={748336,1187729,1187067,1167968,1167936,751456,751664,751792};
            int_ptr firstData=0;uint firstCount=0;array<int_ptr> firstEntries;
            for(uint pass=0;pass<2;pass++){
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
                uint listeners=uint(end-begin)/4;array<int_ptr> listenerPointers,listenerTables,listenerTargets;
                string rows="[";known=true;reason="POLICY_LISTENER_PAGE";
                for(uint i=0;i<listeners;i++){
                    int_ptr listener=mem::int_ptr[begin+i*4];
                    if(listener==0 || !ahCompactPageV108(listener,4)){known=false;break;}
                    int_ptr listenerTable=mem::int_ptr[listener];
                    if(listenerTable==0 || !ahCompactPageV108(listenerTable,8*4)){known=false;break;}
                    int_ptr listenerTarget=mem::int_ptr[listenerTable+7*4];
                    if(listenerTarget==0){known=false;break;}
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
                policyRows=rows;policyPasses++;connectionSlots=count;matchedSinks=matches;passes++;
            }
            if(passes!=2 || policyPasses!=2)break;repeated=true;observed=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){observed=false;reason="NATIVE_EXCEPTION";}
    selectionUnchanged=ahAccessSelectionV232(Guid("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}"));
    if(!selectionUnchanged){observed=false;reason="SELECTION_CHANGED";}
    string result="{\"version\":250,\"revision\":2,\"status\":\""+(observed?"OBSERVED":"REFUSED")+"\",\"reason\":\""+reason
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
        +",\"policyCalls\":0,\"policyMeaningVerified\":false,\"permissionGranted\":false,\"configurationExports\":0,\"configurationImports\":0"
        +",\"sourceWrites\":0,\"metadataWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"writerAuthorized\":false}";
    ExceptionCatcher output;
    {CppCatch caught("class core::Exception",ExceptionHandler(output.handle));if(result.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",result);}
}
