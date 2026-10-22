// Diagnostic-only: exact Processing.ObjectModule editor, three boolean reads.
// Opening its editor may touch UI/cache. No module body is obtained or changed.
void ahOwnedEditorBaseline() {
    bool admitted=__OWNED_BASELINE_SCOPE_ADMITTED__;
    if(!admitted)return;
    string operation="__OPERATION_ID__",scope="__SCOPE_SHA256__",nonce="__BASELINE_NONCE__",reason="SCOPE";
    bool intent=false,openReturned=false,observed=false,identityVerified=false,metadataFlagsPreserved=false,exception=false;
    bool documentModified=false,documentReadOnly=false,textManagerEmpty=false,refsCleared=false;
    uint opens=0,openCode=0,openFlags=0x10101,modifiedReads=0,readOnlyReads=0,emptyReads=0;
    array<uint> identitiesBefore,identitiesAfter,metadataBefore,metadataAfter;
    IConfigMngrUI@ ui;IMDContainer@ root,freshRoot;
    IMDObject@ object,freshObject,boundObject;
    IMDEditService@ service;IMDEditHelper@ helper;IMDEditModuleHelper@ module;
    ITextManager@ text,linked;ITextEditor@ editor;IDocument@ document;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(operation.length!=32 || scope.length!=64 || nonce.length!=32 || sizeof_ptr!=4 || !ahPipeScopeAlive()
                || ahStatusUi is null || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            bool hexKnown=true;
            for(uint n=0;n<64;n++){
                uint a=scope[n];if(!((a>=48 && a<=57)||(a>=97 && a<=102)))hexKnown=false;
                if(n<32){uint b=operation[n],c=nonce[n];
                    if(!((b>=48 && b<=57)||(b>=97 && b<=102)) || !((c>=48 && c<=57)||(c>=97 && c<=102)))hexKnown=false;}
            }
            if(!hexKnown)break;
            @ui=ahStatusUi;@root=ui.getMDCont();reason="ROOT";
            if(root is null || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}") || !ahCatalogEditableV218(root))break;
            Guid target("{d593e80d-b70c-400b-9955-d02f7a4c89e9}"),property("{a637f77f-3840-441d-a1c3-699c8c5cb7e0}");
            @object=root.objById(target);reason="EXACT_PROCESSING";
            if(object is null || object.id!=target || object.mdClass is null
                || object.mdClass.id!=Guid("{bf845118-327b-4682-b5c6-285d2a0eb296}") || object.mdParentLink is null
                || !ahCatalogSameV218(object.mdParentLink.getMDObject().unk,root.unk))break;
            string propertyName;reason="OBJECT_MODULE_PROPERTY";
            if(!ahModulePropertyV225(object,property,propertyName) || propertyName!="ObjectModule")break;
            metadataBefore={root.isModified()?1:0,ui.isModified()?1:0,object.isModified()?1:0};
            intent=ahWriteSample("__BASELINE_INTENT_PATH__","{\"kind\":\"OWNED_EDITOR_BASELINE_INTENT\",\"operationId\":\""+operation
                +"\",\"scopeSha256\":\""+scope+"\",\"nonce\":\""+nonce
                +"\",\"maximumOpenCalls\":1,\"maximumDocumentModifiedReads\":1,\"maximumDocumentReadOnlyReads\":1,\"maximumTextManagerEmptyReads\":1"
                +",\"configurationSourceWrites\":0,\"sourceBodyIncluded\":false,\"sourceFrameIncluded\":false}");
            if(!intent)break;
            @service=getMDEditService();reason="HELPER";if(service is null)break;
            service.getEditHelper(helper,object);if(helper is null)break;@module=helper.unk;
            if(module is null || !ahCompactTableV108(helper.self,"basicui.dll",0x60ae54,24)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[helper.self]+23*4],"basicui.dll",0xf3b70)
                || !ahCompactTableV108(module.self,"basicui.dll",0x60ad5c,12)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[module.self]+5*4],"basicui.dll",0x35c470))break;
            @boundObject=helper.getMDObj();
            if(boundObject is null || !ahCatalogSameV218(boundObject.unk,object.unk))break;
            reason="OPEN_EXACT_MODULE";opens++;
            openCode=module.openModule(text,property,openFlags,editor);openReturned=true;
            if(text is null || editor is null || !ahCompactTableV108(text.self,"txtedt.dll",0x46dc4,11)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[text.self]+10*4],"txtedt.dll",0x2dcf0)
                || !ahCompactTableV108(editor.self,"txtedui.dll",0x10db3c,4)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[editor.self]],"txtedui.dll",0xe4680)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[editor.self]+3*4],"txtedui.dll",0xa2020))break;
            editor.getITextManager(linked);@document=text.unk;reason="COUNTED_BINDINGS";
            if(linked is null || linked.self!=text.self || document is null
                || !ahCompactTableV108(document.self,"txtedui.dll",0x109978,23)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[document.self]+8*4],"txtedui.dll",0x74450)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[document.self]+22*4],"txtedui.dll",0x7d7d0)
                || mem::addressOf(linked.getTextManager())!=mem::addressOf(text.getTextManager()))break;
            identitiesBefore={uint(ui.self),uint(root.self),uint(object.self),uint(helper.self),uint(text.self),
                uint(editor.self),uint(document.self),uint(mem::addressOf(text.getTextManager()))};
            reason="DOCUMENT_MODIFIED";documentModified=document.isModified();modifiedReads++;
            reason="DOCUMENT_READONLY";documentReadOnly=document.getReadOnly();readOnlyReads++;
            reason="TEXT_MANAGER_EMPTY";textManagerEmpty=text.getTextManager().empty();emptyReads++;
            // Values are observations, never an admission to read/change text.
            // A read-only/nonempty/dirty editor is a valid diagnostic outcome.
            reason="FRESH_IDENTITIES";
            if(!ahPipeScopeAlive() || ahStatusUi !is ui)break;
            @freshRoot=ui.getMDCont();
            if(freshRoot is null || !ahCatalogSameV218(freshRoot.unk,root.unk))break;
            @freshObject=freshRoot.objById(target);@boundObject=null;@boundObject=helper.getMDObj();
            if(freshObject is null || boundObject is null || !ahCatalogSameV218(freshObject.unk,object.unk)
                || !ahCatalogSameV218(boundObject.unk,object.unk))break;
            @linked=null;editor.getITextManager(linked);
            if(linked is null || linked.self!=text.self || mem::addressOf(linked.getTextManager())!=mem::addressOf(text.getTextManager()))break;
            identitiesAfter={uint(ui.self),uint(root.self),uint(object.self),uint(helper.self),uint(text.self),
                uint(editor.self),uint(document.self),uint(mem::addressOf(text.getTextManager()))};
            identityVerified=identitiesBefore.length==8 && identitiesAfter.length==8;
            if(identityVerified)for(uint n=0;n<8;n++)if(identitiesBefore[n]!=identitiesAfter[n])identityVerified=false;
            metadataAfter={root.isModified()?1:0,ui.isModified()?1:0,object.isModified()?1:0};
            metadataFlagsPreserved=metadataBefore.length==3 && metadataAfter.length==3;
            if(metadataFlagsPreserved)for(uint n=0;n<3;n++)if(metadataBefore[n]!=metadataAfter[n])metadataFlagsPreserved=false;
            observed=identityVerified && metadataFlagsPreserved && modifiedReads==1 && readOnlyReads==1 && emptyReads==1;
            reason=observed?"NONE":"IDENTITY_OR_METADATA_CHANGED";
        }while(false);
        exception=catcher.hasException;
        @document=null;@linked=null;@editor=null;@text=null;@module=null;@helper=null;@service=null;
        @boundObject=null;@freshObject=null;@object=null;@freshRoot=null;@root=null;@ui=null;
    }
    refsCleared=document is null && linked is null && editor is null && text is null && module is null
        && helper is null && service is null && boundObject is null && freshObject is null && object is null
        && freshRoot is null && root is null && ui is null;
    observed=admitted && intent && openReturned && opens==1 && observed && !exception && refsCleared;
    string idsBefore="[",idsAfter="[",flagsBefore="[",flagsAfter="[";
    for(uint n=0;n<identitiesBefore.length;n++)idsBefore+=(n==0?"":",")+identitiesBefore[n];idsBefore+="]";
    for(uint n=0;n<identitiesAfter.length;n++)idsAfter+=(n==0?"":",")+identitiesAfter[n];idsAfter+="]";
    for(uint n=0;n<metadataBefore.length;n++)flagsBefore+=(n==0?"":",")+metadataBefore[n];flagsBefore+="]";
    for(uint n=0;n<metadataAfter.length;n++)flagsAfter+=(n==0?"":",")+metadataAfter[n];flagsAfter+="]";
    ahWriteSample("__BASELINE_PROOF_PATH__","{\"kind\":\"OWNED_EDITOR_BASELINE_NATIVE\",\"operationId\":\""+operation
        +"\",\"scopeSha256\":\""+scope+"\",\"nonce\":\""+nonce+"\",\"observed\":"+observed+",\"reason\":\""+reason
        +"\",\"objectId\":\"d593e80d-b70c-400b-9955-d02f7a4c89e9\",\"modulePropertyId\":\"a637f77f-3840-441d-a1c3-699c8c5cb7e0\""
        +",\"documentModified\":"+(modifiedReads==1?(documentModified?"true":"false"):"null")
        +",\"documentReadOnly\":"+(readOnlyReads==1?(documentReadOnly?"true":"false"):"null")
        +",\"textManagerEmpty\":"+(emptyReads==1?(textManagerEmpty?"true":"false"):"null")
        +",\"documentModifiedObserved\":"+(modifiedReads==1)+",\"documentReadOnlyObserved\":"+(readOnlyReads==1)+",\"textManagerEmptyObserved\":"+(emptyReads==1)
        +",\"getterCounts\":{\"documentModified\":"+modifiedReads+",\"documentReadOnly\":"+readOnlyReads+",\"textManagerEmpty\":"+emptyReads+"}"
        +",\"openCalls\":"+opens+",\"openReturned\":"+openReturned+",\"openReturnCode\":"+openCode+",\"openFlagsAfter\":"+openFlags
        +",\"identityVerified\":"+identityVerified+",\"metadataFlagsPreserved\":"+metadataFlagsPreserved
        +",\"identitiesBefore\":"+idsBefore+",\"identitiesAfter\":"+idsAfter+",\"metadataFlagsBefore\":"+flagsBefore+",\"metadataFlagsAfter\":"+flagsAfter
        +",\"nativeException\":"+exception+",\"ownedTypedHandlesCleared\":"+refsCleared+",\"sourceBodyIncluded\":false,\"sourceFrameIncluded\":false"
        +",\"repositoryOwnerVerified\":false,\"configurationSourceWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"businessCalls\":0}");
}
