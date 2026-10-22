// Fixed readonly lifecycle witness. Dirty is observed, never an admission gate.
void ahSheetDirtyState() {
    string reason="OWNER",documentTable="null";
    bool observed=false,documentDirty=false,objectDirty=false,parentDirty=false,rootDirty=false,uiDirty=false;
    bool configMode=false,readOnly=false;uint documentPointer=0,passes=0;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(ahStatusUi is null || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211
                || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();reason="ROOT";
            if(!ahCatalogEditableV218(root) || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}"))break;
            Guid target("{8daef957-4ae2-48a1-bf6c-b88163a076f5}");
            Guid property("{8eb4fad1-1fa6-403e-970f-2c12dbb43e23}");
            IMDObject@ object=root.objById(target);reason="TARGET";
            if(object is null || object.id!=target || object.mdClass is null || object.mdParentLink is null
                || object.mdClass.id!=Guid("{3daea016-69b7-4ed4-9453-127911372fe6}"))break;
            IMDObject@ parent=object.mdParentLink.getMDObject();reason="PARENT";
            if(parent is null || parent.id!=Guid("{686a3dbe-be94-45e7-9e8b-dd93f0cd579c}")
                || !ahCatalogLinkV218(object,parent,root))break;
            IMDEditService@ service=getMDEditService();IMDEditHelper@ helper;reason="HELPER";
            if(service is null)break;service.getEditHelper(helper,object);
            if(helper is null || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                || !ahCompactTableV108(helper.self,"frntend.dll",12897096,37)
                || helper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))break;
            IUnknown@ body;helper.extProp(body,property,false);IDocument@ document=body;reason="DOCUMENT";
            if(document is null || !ahCompactTableV108(document.self,"moxelui.dll",2155168,23))break;
            documentPointer=uint(document.self);
            documentTable=ahRepoAddress(mem::int_ptr[document.self]);
            for(uint pass=0;pass<2;pass++){
                reason="BINDING_CHANGED";
                if(!ahPipeScopeAlive() || ahStatusUi !is ui
                    || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
                IMDContainer@ freshRoot=ui.getMDCont();IMDObject@ freshObject=root.objById(target);
                if(freshRoot is null || freshObject is null || freshRoot.id!=root.id || freshObject.id!=target
                    || !ahCatalogEditableV218(freshRoot) || !ahCatalogSameV218(freshRoot.unk,root.unk)
                    || !ahCatalogSameV218(freshObject.unk,object.unk)
                    || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                    || !ahCatalogLinkV218(object,parent,root))break;
                IUnknown@ freshBody;helper.extProp(freshBody,property,false);IDocument@ freshDocument=freshBody;
                if(freshDocument is null || uint(freshDocument.self)!=documentPointer
                    || !ahCatalogSameV218(freshDocument.unk,document.unk)
                    || !ahCompactTableV108(freshDocument.self,"moxelui.dll",2155168,23))break;
                bool nextDocument=document.isModified(),nextObject=object.isModified(),nextParent=parent.isModified();
                bool nextRoot=root.isModified(),nextUi=ui.isModified();
                bool nextMode=document.getConfigMode(),nextReadOnly=document.getReadOnly();
                if(pass==0){documentDirty=nextDocument;objectDirty=nextObject;parentDirty=nextParent;
                    rootDirty=nextRoot;uiDirty=nextUi;configMode=nextMode;readOnly=nextReadOnly;}
                else if(documentDirty!=nextDocument || objectDirty!=nextObject || parentDirty!=nextParent
                    || rootDirty!=nextRoot || uiDirty!=nextUi || configMode!=nextMode || readOnly!=nextReadOnly){
                    reason="STATE_CHANGED";break;
                }
                passes++;
            }
            if(passes!=2)break;
            observed=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){observed=false;reason="NATIVE_EXCEPTION";}
    string result="{\"version\":1,\"phase\":\"SHEET_DIRTY_STATE\",\"operationId\":\"__OPERATION_ID__\",\"status\":\""
        +(observed?"OBSERVED":"REFUSED")+"\",\"reason\":\""+reason+"\",\"templateId\":\"8daef957-4ae2-48a1-bf6c-b88163a076f5\""
        +",\"passes\":"+passes+",\"documentPointer\":"+documentPointer+",\"documentTable\":"+documentTable
        +",\"documentDirty\":"+documentDirty+",\"objectDirty\":"+objectDirty+",\"parentDirty\":"+parentDirty
        +",\"rootDirty\":"+rootDirty+",\"uiDirty\":"+uiDirty+",\"configMode\":"+configMode+",\"readOnly\":"+readOnly
        +",\"dirtyIsAdmissionGate\":false,\"nativeGetterObservationOnly\":true,\"snapshots\":0,\"viewEnumerations\":0"
        +",\"callbackInvocations\":0,\"rawFlagWrites\":0,\"metadataWrites\":0,\"configurationSaves\":0"
        +",\"databaseUpdates\":0,\"repositoryMutations\":0,\"applicationBodyOutputBytes\":0,\"writerAuthorized\":false}";
    ExceptionCatcher output;
    {CppCatch caught("class core::Exception",ExceptionHandler(output.handle));
        if(result.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",result);
    }
}
