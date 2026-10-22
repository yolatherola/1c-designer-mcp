// Fixed readonly metadata binding of the already opened template document.
void ahTemplateBindingV236() {
    string reason="ROOT",beforeHash="",afterHash="",uncachedHash="",sinkTables="[]";
    bool bound=false,repeated=false,checkpoint=false,helperMatch=false,canonicalMatch=false,ownerMatch=false;
    bool configMode=false,readOnly=true,clean=false,selectionUnchanged=false;
    uint connectionSlots=0,nonNullSinks=0,matchedSinks=0,passes=0,viewCount=0;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(ahStatusUi is null || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            Guid seed("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}");
            if(!ahAccessSelectionV232(seed))break;
            IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();
            if(!ahCatalogEditableV218(root) || root.isModified() || ui.isModified())break;
            IConfigMngr@ manager=root.getConfigMngr();if(manager is null)break;
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
            if(helper is null || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                || !ahCompactTableV108(helper.self,"frntend.dll",12897096,37)
                || helper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))break;
            Guid canonical("{00000000-0000-0000-c000-000000000046}");IUnknown@ helperIdentity;
            if(helper.queryIface(canonical,helperIdentity)!=0 || helperIdentity is null)break;
            IUnknown@ body;helper.extProp(body,property,false);
            IDocument@ document=body;IPersistableDocument@ persistent=body;reason="DOCUMENT";
            if(document is null || persistent is null || !ahCompactTableV108(document.self,"moxelui.dll",2155168,23))break;
            configMode=document.getConfigMode();readOnly=document.getReadOnly();clean=!document.isModified();
            if(!configMode || readOnly || !clean)break;
            Vector views;document.enumAllViews(views);
            if(views.end<=views.start || views.end-views.start>64*4 || (views.end-views.start)%4!=0)break;
            viewCount=uint(views.end-views.start)/4;
            IFileEx@ beforeMemory;reason="CHECKPOINT";
            if(!ahSheetSnapshotV231(persistent,beforeMemory,beforeHash)
                || beforeHash!="6d20f90eed3d8656fb669dcbd2701155eb481e839af968398597f6959a4842ed")break;
            IConnectionPointContainer@ container=document.unk;IUnknown@ connection;reason="CONNECTION_POINT";
            if(container is null || container.FindConnectionPoint(IID_IDocumentSink,connection)!=0 || connection is null)break;
            int_ptr cp=connection.self;
            // This closed CP implementation's stock Unadvise/EnumConnections
            // prove pointer+4/capacity+8 and four-byte slots. No CP method is
            // dispatched through a numeric address and no sink is converted.
            array<uint> expectedSlots={748336,1187729,1187067,1167968,1167936,751456,751664,751792};
            array<int_ptr> beforeEntries;int_ptr firstData=0;uint firstSlots=0;
            for(uint pass=0;pass<2;pass++){
                reason="CP_ABI";
                if(!ahCompactTableV108(cp,"moxelui.dll",2155136,8) || !ahCompactPageV108(cp,12))break;
                int_ptr table=mem::int_ptr[cp];bool slotsKnown=true;
                for(uint i=0;i<8;i++)if(!ahCompactAddressV108(mem::int_ptr[table+i*4],"moxelui.dll",expectedSlots[i]))slotsKnown=false;
                if(!slotsKnown)break;
                int_ptr data=mem::int_ptr[cp+4];uint count=mem::dword[cp+8];reason="CP_BOUNDS";
                if(count==0 || count>16 || !ahCompactPageV108(data,count*4))break;
                if(pass==0){firstData=data;firstSlots=count;}else if(data!=firstData || count!=firstSlots)break;
                uint matches=0,nonNull=0;bool rawMatch=false,canonicalRawMatch=false,primaryOwnerMatch=false,entriesKnown=true;
                array<int_ptr> entries;string tables="[";
                for(uint i=0;i<count;i++){
                    int_ptr sink=mem::int_ptr[data+i*4];entries.insertLast(sink);if(sink==0)continue;
                    if(!ahCompactPageV108(sink,4)){entriesKnown=false;break;}
                    if(nonNull++!=0)tables+=",";tables+=ahRepoAddress(mem::int_ptr[sink]);
                    // Only this primary-proven DocSink class permits reading
                    // helper+16 and Guid+20. Other registered sinks are opaque.
                    if(!ahCompactTableV108(sink,"frntend.dll",12837396,7))continue;
                    if(!ahCompactAddressV108(mem::int_ptr[mem::int_ptr[sink]+3*4],"frntend.dll",2716288)){entriesKnown=false;break;}
                    if(!ahCompactPageV108(sink,36)){entriesKnown=false;break;}
                    int_ptr storedHelper=mem::int_ptr[sink+16];Guid storedProperty;mem::memcpy(storedProperty.self,sink+20,16);
                    bool direct=storedHelper==helper.self,canonicalSame=storedHelper==helperIdentity.self;
                    // The stock sink's slot3 adds0x7c to its held owner to get
                    // IMDEditHelper; editProperty36 subtracts the same offset.
                    // Compare numbers only; never cast or call the raw owner.
                    bool primaryOwner=storedHelper==helper.self-0x7c;
                    if(storedProperty==property && (direct || canonicalSame || primaryOwner)){
                        matches++;rawMatch=rawMatch || direct;canonicalRawMatch=canonicalRawMatch || canonicalSame;
                        primaryOwnerMatch=primaryOwnerMatch || primaryOwner;
                    }
                }
                tables+="]";reason="SINK_BINDING";
                if(pass==0){beforeEntries=entries;sinkTables=tables;connectionSlots=count;nonNullSinks=nonNull;
                    matchedSinks=matches;helperMatch=rawMatch;canonicalMatch=canonicalRawMatch;ownerMatch=primaryOwnerMatch;}
                if(!entriesKnown || matches!=1)break;
                if(pass!=0){
                    bool same=entries.length==beforeEntries.length && tables==sinkTables
                        && nonNull==nonNullSinks && rawMatch==helperMatch && canonicalRawMatch==canonicalMatch
                        && primaryOwnerMatch==ownerMatch;
                    for(uint i=0;same && i<entries.length;i++)same=entries[i]==beforeEntries[i];
                    if(!same)break;
                }
                reason="STATE_CHANGED";
                if(mem::int_ptr[cp+4]!=data || mem::dword[cp+8]!=count || root.isModified() || ui.isModified()
                    || object.isModified() || parent.isModified() || document.isModified() || document.getReadOnly()
                    || !document.getConfigMode() || !ahAccessSelectionV232(seed))break;
                passes++;
            }
            if(passes!=2)break;repeated=true;
            IUnknown@ freshBody;helper.extProp(freshBody,property,false);IDocument@ freshDocument=freshBody;
            IPersistableDocument@ freshPersistent=freshBody;IFileEx@ afterMemory;reason="AFTER_CHECKPOINT";
            if(freshDocument is null || freshPersistent is null || !ahCatalogSameV218(freshDocument.unk,document.unk)
                || !ahSheetSnapshotV231(freshPersistent,afterMemory,afterHash) || beforeHash!=afterHash)break;
            IUnknown@ uncachedBody;helper.extProp(uncachedBody,property,true);IPersistableDocument@ uncached=uncachedBody;
            IFileEx@ uncachedMemory;
            if(uncached is null || !ahSheetSnapshotV231(uncached,uncachedMemory,uncachedHash) || uncachedHash!=beforeHash)break;
            IMDContainer@ freshRoot=ui.getMDCont();IMDObject@ freshObject=root.objById(target);
            if(freshRoot is null || freshObject is null || !ahCatalogSameV218(freshRoot.unk,root.unk)
                || !ahCatalogSameV218(freshObject.unk,object.unk) || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                || root.isModified() || ui.isModified() || object.isModified() || parent.isModified()
                || document.isModified() || document.getReadOnly() || !document.getConfigMode())break;
            checkpoint=true;bound=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){bound=false;reason="NATIVE_EXCEPTION";}
    selectionUnchanged=ahAccessSelectionV232(Guid("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}"));
    if(!selectionUnchanged){bound=false;reason="SELECTION_CHANGED";}
    string result="{\"version\":236,\"status\":\""+(bound?"BOUND":"REFUSED")+"\",\"reason\":\""+reason
        +"\",\"templateId\":\"8daef957-4ae2-48a1-bf6c-b88163a076f5\",\"propertyId\":\"8eb4fad1-1fa6-403e-970f-2c12dbb43e23\""
        +",\"metadataBindingVerified\":"+bound+",\"repeatedBindingVerified\":"+repeated+",\"checkpointUnchanged\":"+checkpoint
        +",\"checkpointSha256\":\""+(checkpoint?afterHash:"")+"\",\"configMode\":"+configMode+",\"documentReadOnly\":"+readOnly
        +",\"documentClean\":"+clean+",\"editorViewCount\":"+viewCount+",\"connectionSlots\":"+connectionSlots
        +",\"nonNullSinks\":"+nonNullSinks+",\"matchedSinks\":"+matchedSinks+",\"sinkTables\":"+sinkTables
        +",\"storedHelperMatchesInterface\":"+helperMatch+",\"storedHelperMatchesCanonical\":"+canonicalMatch
        +",\"storedHelperMatchesPrimaryOwner\":"+ownerMatch
        +",\"selectionUnchanged\":"+selectionUnchanged+",\"editPropertyCalls\":0,\"enumConnectionsCalls\":0,\"unknownSinkDispatches\":0"
        +",\"metadataWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"writerAuthorized\":false}";
    ExceptionCatcher proof;
    {CppCatch caught("class core::Exception",ExceptionHandler(proof.handle));if(result.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",result);}
}
