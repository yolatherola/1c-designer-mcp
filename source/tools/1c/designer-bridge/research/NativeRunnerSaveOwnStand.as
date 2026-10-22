// First application only: private46756 stand, recorded clean history, fixed3.
// This is not a general pending iterator or general configuration Save API.
void ahRunnerSaveOwnStand() {
    bool scopeAdmitted=__OWN_STAND_SCOPE_ADMITTED__,writerVerified=__WRITER_VERIFIED_ADMITTED__;
    string saveOperation="__SAVE_OPERATION_ID__",writerOperation="__WRITER_OPERATION_ID__";
    string packetSha="__WRITER_PACKET_SHA256__",scopeSha="__FOLLOWUP_SCOPE_SHA256__";
    string reason="SCOPE";bool attempted=false,returned=false,clean=false,walkComplete=false,preflight=false;
    uint dispatches=0,objectsVisited=0,dirtyOwnMask=0,dirtyAncestors=0,unknownDirty=0,modulesVerified=0;
    array<IMDObject@> ownObjects;array<IDocument@> ownDocuments;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(!scopeAdmitted || !writerVerified || saveOperation.length!=32 || writerOperation.length!=32
                || saveOperation==writerOperation || packetSha.length!=64 || scopeSha.length!=64
                || sizeof_ptr!=4 || ahStatusUi is null || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=46756 || ahFrameOwnerPidV211!=46756
                || ahGetCurrentThreadId()!=40236 || ahFrameOwnerTidV211!=40236)break;
            IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();reason="ROOT";
            if(!ahCatalogEditableV218(root) || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
                || !root.isModified() || !ui.isModified())break;
            array<string> ids={"8daef957-4ae2-48a1-bf6c-b88163a076f5","176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
            array<string> expectedHashes={"__PRINT_SHA256__","__REGISTRAR_SHA256__"};
            IMDEditService@ service=getMDEditService();reason="TARGETS";if(service is null)break;
            for(uint i=0;i<3;i++){
                IMDObject@ object=root.objById(Guid("{"+ids[i]+"}"));IMDEditHelper@ helper;
                if(object is null || !object.isModified() || object.mdParentLink is null)break;
                IMDObject@ parent=object.mdParentLink.getMDObject();
                if(parent is null || parent.id!=(i==0?Guid("{686a3dbe-be94-45e7-9e8b-dd93f0cd579c}"):root.id)
                    || !ahCatalogLinkV218(object,parent,root))break;
                service.getEditHelper(helper,object);IDocument@ document;
                if(helper is null || !ahCatalogSameV218(helper.getMDObj().unk,object.unk))break;
                if(i==0){
                    Guid property("{8eb4fad1-1fa6-403e-970f-2c12dbb43e23}");IUnknown@ body;
                    if(helper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))break;
                    helper.extProp(body,property,false);@document=body;IContext@ context=body;
                    if(document is null || context is null || uint(document.self)!=__EXPECTED_TEMPLATE_DOCUMENT__
                        || !ahCompactTableV108(document.self,"moxelui.dll",2155168,23) || !document.getConfigMode())break;
                    // Read bound cells only. Never persist/serialize/snapshot the edited template here.
                    IContext@ header=ahSheetAreaV231(context,11,2,7);string text;
                    if(header is null || !ahSheetStringV231(header,"Text",text) || text!="Специалист")break;
                    bool employees=true;array<int> rows={13,16};
                    for(uint row=0;row<rows.length;row++){
                        IContext@ employee=ahSheetAreaV231(context,rows[row],2,7);string parameter;
                        if(employee is null || !ahSheetStringV231(employee,"Parameter",parameter) || parameter!="Сотрудник")employees=false;
                    }
                    if(!employees)break;
                }else{
                    IMDEditModuleHelper@ module=helper.unk;Guid property("{d5963243-262e-4398-b4d7-fb16d06484f6}");
                    ITextManager@ text;ITextEditor@ editor;uint32 flags=0x10101;
                    if(module is null)break;module.openModule(text,property,flags,editor);
                    if(text is null || editor is null || !ahCompactTableV108(text.self,"txtedt.dll",0x46dc4,11)
                        || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[text.self]+10*4],"txtedt.dll",0x2dcf0))break;
                    @document=text.unk;
                    if(document is null || !ahCompactTableV108(document.self,"txtedui.dll",0x109978,23))break;
                    v8string editorValue,helperValue;
                    if(!text.getTextManager().save(editorValue) || !module.textOfModule(property,false,helperValue)
                        || editorValue.str!=helperValue.str)break;
                    utf8string bytes=editorValue.str.toUtf8();if(bytes.length==0 || bytes.length>262144)break;
                    MemoryBuffer memory(bytes.length);if(memory.bytes==0 || memory._length!=bytes.length)break;
                    mem::memcpy(memory.bytes,bytes.ptr,bytes.length);
                    if(ahTemplateRamShaV202(memory,bytes.length)!=expectedHashes[i-1])break;modulesVerified++;
                }
                if(document is null || !document.isModified() || document.getReadOnly())break;
                ownObjects.insertLast(object);ownDocuments.insertLast(document);
            }
            if(ownObjects.length!=3 || ownDocuments.length!=3 || modulesVerified!=2)break;
            // Structural dirty walk only: no module/property values, no claim about hidden editor/root-property deltas.
            reason="DIRTY_WALK";array<IMDObject@> queue={root};array<uint> depth={0};bool walkOkay=true;
            for(uint at=0;at<queue.length;at++){
                if(at>=65536 || depth[at]>64){walkOkay=false;break;}
                IMDObject@ object=queue[at];objectsVisited++;
                if(object is null || object.mdClass is null){walkOkay=false;break;}
                if(object.isModified()){
                    uint bit=0;for(uint i=0;i<3;i++)if(object.id==ownObjects[i].id)bit=1<<i;
                    if(bit!=0){if((dirtyOwnMask&bit)!=0){walkOkay=false;break;}dirtyOwnMask|=bit;}
                    else if(object.id==root.id || object.id==Guid("{686a3dbe-be94-45e7-9e8b-dd93f0cd579c}"))dirtyAncestors++;
                    else{unknownDirty++;walkOkay=false;break;}
                }
                IMDClass@ cls=object.mdClass;uint kinds=cls.childClassesCount();
                if(kinds>256){walkOkay=false;break;}
                for(uint k=0;k<kinds;k++){
                    Guid kind=cls.childClassIDAt(k);uint count=object.childCount(kind);
                    if(count>65536 || queue.length+count>65536){walkOkay=false;break;}
                    for(uint n=0;n<count;n++){
                        IMDObject@ child=object.childAt(kind,n);
                        if(child is null || child.mdParentLink is null
                            || !ahCatalogSameV218(child.mdParentLink.getMDObject().unk,object.unk)
                            || !ahCatalogSameV218(root.objById(child.id).unk,child.unk)){walkOkay=false;break;}
                        queue.insertLast(child);depth.insertLast(depth[at]+1);
                    }
                    if(!walkOkay || object.childCount(kind)!=count){walkOkay=false;break;}
                }
                if(!walkOkay)break;
            }
            if(!walkOkay || dirtyOwnMask!=7 || unknownDirty!=0)break;walkComplete=true;
            reason="COMMAND_RECEIVER";
            ITopLevelFrame@ frame=ahObservedMainFrameV211;ITopLevelFrame@ core;
            if(frame is null || frame.frameType()!=eTLFT_Main)break;frame.getCoreTopLevelFrame(core);
            if(core is null || !ahFrameReceiverLayoutV211(frame,core))break;
            // Getter31 returns the out-parameter address, not an HRESULT (stock1fd7b0/8a6f60).
            ICommandReceiver@ receiver;frame.commandReceiver(receiver);if(receiver is null
                || !ahCompactTableV108(receiver.self,"frame.dll",0xa6a4f8,6))break;
            array<uint> slots={0x82c7a0,0x82c810,0x82ca00};bool abi=true;
            for(uint i=0;i<3;i++)if(!ahCompactAddressV108(mem::int_ptr[mem::int_ptr[receiver.self]+(i+3)*4],"frame.dll",slots[i]))abi=false;
            if(!abi)break;
            CommandID command(Guid("{F10CBB81-F679-11D4-9DD3-0050BAE2BC79}"),3);
            ICommandService@ commands=currentProcess().getService(IID_ICommandService);ICmdDescription@ description;
            if(commands is null || !receiver.hasHandler(command))break;commands.commandDescription(description,command);
            CommandState@ state=getCommandState(command,0,receiver);reason="COMMAND_STATE";
            if(description is null || string(description.text())!="Сохранить конфигурацию"
                || state is null || !state.cmdState.bEnable)break;
            reason="FRESH_BEFORE_SAVE";
            if(!ahPipeScopeAlive() || ahStatusUi !is ui || !ahCatalogSameV218(ui.getMDCont().unk,root.unk)
                || !root.isModified() || !ui.isModified())break;
            bool same=true;for(uint i=0;i<3;i++)if(!ahCatalogSameV218(root.objById(ownObjects[i].id).unk,ownObjects[i].unk)
                || !ownObjects[i].isModified() || !ownDocuments[i].isModified() || ownDocuments[i].getReadOnly())same=false;
            if(!same)break;preflight=true;
            string reserved="{\"kind\":\"SAVE_RESERVED\",\"saveOperationId\":\""+saveOperation+"\",\"writerOperationId\":\""+writerOperation
                +"\",\"packetSha256\":\""+packetSha+"\",\"scopeSha256\":\""+scopeSha+"\",\"command\":3,\"dispatchAttempts\":0}";
            reason="SAVE_RESERVED_PROOF";if(!ahWriteSample("__SAVE_RESERVED_PATH__",reserved))break;
            // Count BEFORE the call. Exception/cancel/unknown never authorizes a second command.
            attempted=true;dispatches=1;reason="SAVE_UNKNOWN";receiver.transmitCommand(Command(command,0));returned=true;
            clean=!root.isModified() && !ui.isModified();
            for(uint i=0;i<3;i++)if(ownObjects[i].isModified() || ownDocuments[i].isModified())clean=false;
            reason=clean?"NONE":"NATIVE_DIRTY_AFTER_RETURN";
        }while(false);
    }
    if(catcher.hasException){returned=false;clean=false;reason="NATIVE_EXCEPTION";}
    string status=!attempted?"SAVE_REFUSED":(!returned?"SAVE_UNKNOWN_RETAIN":
        (clean?"SAVE_RETURNED_CLEAN_PENDING_COLD_READ":"SAVE_RETURNED_UNCLEAN_RETAIN"));
    string proof="{\"kind\":\"OWN_STAND_SAVE3_RECEIPT\",\"status\":\""+status+"\",\"reason\":\""+reason
        +"\",\"saveOperationId\":\""+saveOperation+"\",\"writerOperationId\":\""+writerOperation+"\",\"packetSha256\":\""+packetSha
        +"\",\"scopeSha256\":\""+scopeSha+"\",\"preflightVerified\":"+preflight+",\"structuralDirtyWalkComplete\":"+walkComplete
        +",\"objectsVisited\":"+objectsVisited+",\"dirtyOwnMask\":"+dirtyOwnMask+",\"dirtyAncestors\":"+dirtyAncestors+",\"unknownDirty\":"+unknownDirty
        +",\"modulesVerified\":"+modulesVerified+",\"command\":3,\"dispatchAttempts\":"+dispatches+",\"commandReturned\":"+returned
        +",\"nativeCleanAfterReturn\":"+clean+",\"fullPendingIteratorVerified\":false,\"rootPropertyDeltaCovered\":false,\"hiddenEditorCoverageVerified\":false"
        +",\"saveCompletionEventObserved\":false,\"savedMainVerified\":false,\"templateSerializedBeforeSave\":false,\"databaseUpdates\":0,\"repositoryMutations\":0"
        +",\"releasePacketAllowed\":false,\"releaseRefsAllowed\":false,\"retryAuthorized\":false}";
    ExceptionCatcher output;
    {CppCatch caught("class core::Exception",ExceptionHandler(output.handle));if(proof.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",proof);}
}
