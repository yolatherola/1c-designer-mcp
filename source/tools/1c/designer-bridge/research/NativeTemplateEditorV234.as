// RAW AS continuation: stock editProperty only; no resource writes or view close.
void ahTemplateEditorV234() {
    string why="ROOT",beforeHash="",afterHash="",cachedHash="";
    string helperTable="null",editPropertyTarget="null",documentTable="null";
    string connectionTable="null",standardConnectionTable="null",enumConnectionsTarget="null";
    uint editRequests=0,viewVectorBytes=0;bool observed=false,selected=false;
    bool configMode=false,readOnly=true,documentClean=false,checkpointUnchanged=false;
    bool connectionPointFound=false,standardConnectionPoint=false,selectionRestored=false;
    bool rootCleanBefore=false,rootCleanAfter=false,objectCleanBefore=false,objectCleanAfter=false;
    ITopLevelFrame@ savedFrame=ahRepositoryFrame;
    IConfigMngrUI@ ui=ahStatusUi;
    Guid initial("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}");
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(ui is null || !ahPipeScopeAlive() || !ahAccessSelectionV232(initial))break;
            IMDContainer@ root=ui.getMDCont();
            if(root is null || !ahCatalogEditableV218(root))break;
            rootCleanBefore=!root.isModified() && !ui.isModified();if(!rootCleanBefore)break;
            Guid target("{8daef957-4ae2-48a1-bf6c-b88163a076f5}");
            Guid property("{8eb4fad1-1fa6-403e-970f-2c12dbb43e23}");
            IMDObject@ object=root.objById(target);why="TARGET";
            if(object is null || object.id!=target || object.mdClass is null
                || object.mdClass.id!=Guid("{3daea016-69b7-4ed4-9453-127911372fe6}") || object.mdParentLink is null)break;
            IMDObject@ parent=object.mdParentLink.getMDObject();
            if(parent is null || parent.id!=Guid("{686a3dbe-be94-45e7-9e8b-dd93f0cd579c}")
                || !ahCatalogLinkV218(object,parent,root))break;
            objectCleanBefore=!object.isModified();if(!objectCleanBefore)break;
            IMDEditService@ service=getMDEditService();IMDEditHelper@ helper;why="HELPER";
            if(service is null)break;service.getEditHelper(helper,object);
            if(helper is null || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                || helper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))break;
            if(!ahCompactPageV108(helper.self,4) || !ahCompactPageV108(mem::int_ptr[helper.self],37*4))break;
            helperTable=ahRepoAddress(mem::int_ptr[helper.self]);
            editPropertyTarget=ahRepoAddress(mem::int_ptr[mem::int_ptr[helper.self]+36*4]);
            // This template uses the actual frntend helper, not the basicui
            // helper observed on other metadata classes. Its slot36 is the
            // published stdcall editProperty(self,constGuid*) wrapper (ret8).
            if(!ahCompactTableV108(helper.self,"frntend.dll",12897096,37)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[helper.self]+36*4],"frntend.dll",4529728))break;
            IUnknown@ original;helper.extProp(original,property,false);IDocument@ originalDocument=original;
            IPersistableDocument@ persistence=original;why="CHECKPOINT";
            if(originalDocument is null || persistence is null || originalDocument.isModified())break;
            IFileEx@ checkpoint;if(!ahSheetSnapshotV231(persistence,checkpoint,beforeHash)
                || beforeHash!="6d20f90eed3d8656fb669dcbd2701155eb481e839af968398597f6959a4842ed")break;
            why="SELECTION";selected=true;ui.mdTreeShow(true,true);ui.activateObjInTree(target,IID_NULL,true);
            string selectedTree=ahRepoTreeContext(ui);if(!ahAccessSelectionV232(target))break;
            why="EDIT_PROPERTY";editRequests++;helper.editProperty(property);
            // This is the cached metadata-bound candidate after stock opening,
            // not an independently created SpreadsheetDocument value.
            IUnknown@ cached;helper.extProp(cached,property,false);IDocument@ document=cached;
            IPersistableDocument@ cachedPersistence=cached;why="EDITOR_DOCUMENT";
            if(document is null || cachedPersistence is null)break;
            configMode=document.getConfigMode();readOnly=document.getReadOnly();documentClean=!document.isModified();
            if(!ahCompactPageV108(document.self,4))break;documentTable=ahRepoAddress(mem::int_ptr[document.self]);
            IFileEx@ cachedMemory;if(!ahSheetSnapshotV231(cachedPersistence,cachedMemory,cachedHash) || cachedHash!=beforeHash)break;
            Vector views;document.enumAllViews(views);why="VIEW_VECTOR";
            if(views.end<views.start || views.end-views.start>64*4 || (views.end-views.start)%4!=0)break;
            viewVectorBytes=uint(views.end-views.start);
            // Only published QI/FindConnectionPoint run. No private CP fields,
            // EnumConnections slot dispatch or unknown sink callbacks follow.
            IConnectionPointContainer@ container=document.unk;why="CONNECTION_POINT";
            if(container !is null){
                IUnknown@ connection;
                uint hr=container.FindConnectionPoint(IID_IDocumentSink,connection);
                if(hr==0 && connection !is null && ahCompactPageV108(connection.self,4)){
                    connectionPointFound=true;connectionTable=ahRepoAddress(mem::int_ptr[connection.self]);
                    IUnknown@ standard;uint queried=connection.queryIface(Guid("{B196B286-BAB4-101A-B69C-00AA00341D07}"),standard);
                    if(queried==0 && standard !is null && ahCompactPageV108(standard.self,4)
                        && ahCompactPageV108(mem::int_ptr[standard.self],8*4)){
                        standardConnectionPoint=true;int_ptr table=mem::int_ptr[standard.self];
                        standardConnectionTable=ahRepoAddress(table);enumConnectionsTarget=ahRepoAddress(mem::int_ptr[table+7*4]);
                    }
                }
            }
            why="AFTER_CHECKPOINT";IUnknown@ freshBody;helper.extProp(freshBody,property,true);
            IPersistableDocument@ freshPersistence=freshBody;IFileEx@ afterMemory;
            if(freshPersistence is null || !ahSheetSnapshotV231(freshPersistence,afterMemory,afterHash))break;
            checkpointUnchanged=afterHash==beforeHash && cachedHash==beforeHash;
            IMDContainer@ freshRoot=ui.getMDCont();IMDObject@ fresh=root.objById(target);
            if(freshRoot is null || !ahCatalogSameV218(freshRoot.unk,root.unk) || fresh is null
                || !ahCatalogSameV218(fresh.unk,object.unk) || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                || !ahAccessSelectionV232(target))break;
            rootCleanAfter=!root.isModified() && !ui.isModified();objectCleanAfter=!fresh.isModified();
            if(!checkpointUnchanged || !documentClean || !rootCleanAfter || !objectCleanAfter)break;
            observed=true;why="NONE";
        } while(false);
    }
    if(catcher.hasException){observed=false;why="NATIVE_EXCEPTION";}
    // Restore counted global references and the exact original seed selection,
    // including after a failed stock opening. Never close the real editor here.
    @ahRepositoryFrame=savedFrame;
    if(selected && ui !is null){
        ExceptionCatcher restore;
        {CppCatch caught("class core::Exception",ExceptionHandler(restore.handle));
            ui.mdTreeShow(true,true);ui.activateObjInTree(initial,IID_NULL,true);string tree=ahRepoTreeContext(ui);
        }
        selectionRestored=!restore.hasException && ahAccessSelectionV232(initial);
    } else if(ui !is null)selectionRestored=ahAccessSelectionV232(initial);
    if(!selectionRestored){observed=false;why="SELECTION_RESTORE";}
    string proof="{\"version\":234,\"status\":\""+(observed?"ABI_DISCOVERY":"REFUSED")+"\",\"reason\":\""+why
        +"\",\"templateId\":\"8daef957-4ae2-48a1-bf6c-b88163a076f5\",\"editPropertyCalls\":"+editRequests
        +",\"helperTable\":"+helperTable+",\"editPropertyTarget\":"+editPropertyTarget+",\"documentTable\":"+documentTable
        +",\"configMode\":"+configMode+",\"documentReadOnly\":"+readOnly+",\"documentClean\":"+documentClean
        +",\"rootCleanBefore\":"+rootCleanBefore+",\"rootCleanAfter\":"+rootCleanAfter
        +",\"objectCleanBefore\":"+objectCleanBefore+",\"objectCleanAfter\":"+objectCleanAfter
        +",\"beforeSha256\":\""+beforeHash+"\",\"afterSha256\":\""+afterHash+"\",\"checkpointUnchanged\":"+checkpointUnchanged
        +",\"viewVectorBytes\":"+viewVectorBytes+",\"connectionPointFound\":"+connectionPointFound
        +",\"connectionPointTable\":"+connectionTable+",\"standardConnectionPoint\":"+standardConnectionPoint
        +",\"standardConnectionPointTable\":"+standardConnectionTable+",\"enumConnectionsTarget\":"+enumConnectionsTarget
        +",\"selectionRestored\":"+selectionRestored+",\"editorBoundVerified\":false,\"sinkBindingVerified\":false"
        +",\"privateConnectionPointReads\":0,\"enumConnectionsCalls\":0,\"codeWrites\":0,\"metadataWrites\":0"
        +",\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"writerAuthorized\":false}";
    if(proof.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",proof);
}
