// HOT FUNCTION ONLY: local cache policy observations, never write authority.
void ahTemplatePolicyV233() {
    string reason="SCOPE",ancestorKind="UNKNOWN",beforeHash="",afterHash="";
    bool okay=false,initialSelection=false,selectionTouched=false,selectionRestored=false;
    bool registered=false,binding=false,stable=false,checkpoint=false,ancestorVerified=false;
    bool adapterInitialized=false;uint cacheReads=0,ancestorReads=0,checkpointReads=0,ancestorInitAttempts=0,passes=0;
    array<uint> modes(3,0),repeatModes(3,0);array<int_ptr> baselinePointers;
    array<string> ids={"8daef957-4ae2-48a1-bf6c-b88163a076f5","686a3dbe-be94-45e7-9e8b-dd93f0cd579c","218b5d00-7e10-486f-874c-73c2368ed5da"};
    Guid templateId("{8daef957-4ae2-48a1-bf6c-b88163a076f5}"),parentId("{686a3dbe-be94-45e7-9e8b-dd93f0cd579c}");
    Guid rootId("{218b5d00-7e10-486f-874c-73c2368ed5da}"),seedId("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}"),actor;
    IConfigMngrUI@ ui;IMDContainer@ root;IConfigMngr@ manager;IMDObject@ templ;IMDObject@ parent;IMDObject@ rootObject;
    ITopLevelFrame@ wrapper;ITopLevelFrame@ core;ICommandReceiver@ receiver;
    IMDEditService@ service;IMDEditHelper@ helper;IUnknown@ body;IDocument@ document;IPersistableDocument@ persistent;
    IFileEx@ beforeMemory;IFileEx@ afterMemory;ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(sizeof_ptr!=4 || ahFrameOwnerPidV211==0 || ahFrameOwnerTidV211==0
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211
                || currentProcess() is null || ahStatusUi is null || !ahPipeScopeAlive())break;
            @ui=ahStatusUi;@root=ui.getMDCont();reason="ROOT";
            if(!ahCatalogEditableV218(root) || root.id!=rootId || root.isModified() || ui.isModified())break;
            @manager=root.getConfigMngr();if(manager is null)break;
            IMDContainer@ linked=manager.getMDCont();if(linked is null || mem::addressOf(linked)!=mem::addressOf(root))break;
            @templ=root.objById(templateId);@parent=root.objById(parentId);@rootObject=root.objById(rootId);reason="TARGET";
            if(templ is null || parent is null || rootObject is null || templ.id!=templateId || parent.id!=parentId || rootObject.id!=rootId
                || templ.mdClass is null || parent.mdClass is null
                || templ.mdClass.id!=Guid("{3daea016-69b7-4ed4-9453-127911372fe6}")
                || parent.mdClass.id!=Guid("{bf845118-327b-4682-b5c6-285d2a0eb296}")
                || !ahCatalogLinkV218(templ,parent,root) || !ahCatalogLinkV218(parent,rootObject,root)
                || templ.isModified() || parent.isModified() || rootObject.isModified())break;
            reason="INITIAL_SELECTION";if(!ahAccessSelectionV232(seedId))break;initialSelection=true;
            @wrapper=ahObservedMainFrameV211;
            if(wrapper is null || wrapper.frameType()!=eTLFT_Main)@wrapper=ahFindOwnMainFrame();
            reason="FRAME";
            if(wrapper is null || !ahCompactTableV108(mem::addressOf(wrapper),"config.dll",2856052,32)
                || wrapper.frameType()!=eTLFT_Main)break;
            int_ptr wrapperTable=mem::int_ptr[mem::addressOf(wrapper)];
            if(!ahCompactAddressV108(mem::int_ptr[wrapperTable+16*4],"config.dll",0xfd6d0))break;
            wrapper.getCoreTopLevelFrame(core);if(!ahAccessLegacyLayoutV232(wrapper,core))break;
            core.commandReceiver(receiver);if(!ahAccessLegacyReceiverV232(receiver))break;
            reason="SELECTION";selectionTouched=true;ui.mdTreeShow(true,true);ui.activateObjInTree(templateId,IID_NULL,true);
            string tree=ahRepoTreeContext(ui);
            if(!ahAccessSelectionV232(templateId) || ahRepoSelectionVerified)break;
            @service=getMDEditService();reason="BODY";if(service is null)break;service.getEditHelper(helper,templ);
            Guid property("{8eb4fad1-1fa6-403e-970f-2c12dbb43e23}");
            if(helper is null || helper.getMDObj() is null || mem::addressOf(helper.getMDObj())!=mem::addressOf(templ)
                || helper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))break;
            helper.extProp(body,property,true);@document=body;@persistent=body;
            if(document is null || persistent is null || document.isModified())break;
            reason="CHECKPOINT";checkpointReads++;
            if(!ahSheetSnapshotV231(persistent,beforeMemory,beforeHash)
                || beforeHash!="6d20f90eed3d8656fb669dcbd2701155eb481e839af968398597f6959a4842ed")break;
            reason="LOCAL_READ_ABI";if(ahRepositoryStatusRead is null)break;
            if(ahPolicyAncestorV58 is null){ancestorInitAttempts++;adapterInitialized=ahPolicyAncestorV58Init();}
            if(ahPolicyAncestorV58 is null)break;
            for(uint pass=0;pass<2;pass++){
                reason="UI_MANAGER";
                int_ptr uiPointer=mem::addressOf(ui),managerPointer=mem::addressOf(manager),rootPointer=mem::addressOf(root);
                int_ptr direct=mem::addressOf(receiver);
                if(!ahAccessSelectionV232(templateId) || ahRepoSelectionVerified || !ahAccessLegacyReceiverV232(receiver)
                    || !ahCompactTableV108(uiPointer,"frntend.dll",12641368,27) || !ahCompactPageV108(uiPointer,0x11c)
                    || !ahCompactTableV108(managerPointer,"backend.dll",15589540,86) || !ahCompactPageV108(managerPointer,0x88)
                    || mem::int_ptr[uiPointer+0x118]!=managerPointer || mem::int_ptr[managerPointer+0x84]!=rootPointer
                    || !ahCompactPageV108(direct-4,0x90))break;
                reason="FRAME_ACTIVE";int_ptr active=mem::int_ptr[direct-4+0x8c];
                if(!ahCompactTableV108(active,"config.dll",2856028,3)
                    || !ahCompactTableV108(active-0x10,"config.dll",2856296,3)
                    || !ahCompactPageV108(active-0x10,0x28))break;
                reason="CONTEXT";int_ptr context=mem::int_ptr[active-0x10+0x24];
                if(!ahCompactTableV108(context,"config.dll",2853408,3)
                    || !ahCompactTableV108(context+0x1c,"config.dll",2853360,3) || !ahCompactPageV108(context,0x68))break;
                reason="PLAIN";int_ptr plain=mem::int_ptr[context+0x64];
                if(!ahCompactPageV108(plain,0x78) || mem::int_ptr[plain+0x1c]!=managerPointer)break;
                reason="CONTROLLER";int_ptr holder=mem::int_ptr[plain+0x74];if(!ahCompactPageV108(holder,12))break;
                int_ptr controller=mem::int_ptr[holder+8];
                if(!ahCompactTableV108(controller,"devtool.dll",1629148,3)
                    || !ahCompactTableV108(controller+8,"devtool.dll",1628956,3)
                    || !ahCompactPageV108(controller,0x3c) || mem::int_ptr[controller+0x34]!=managerPointer)break;
                reason="PROVIDER";int_ptr provider=mem::int_ptr[controller+0x30];
                if(provider==0 || provider!=mem::int_ptr[plain+0x6c]
                    || !ahCompactTableV108(provider,"devtool.dll",1599932,41) || !ahCompactPageV108(provider,0x15c))break;
                int_ptr providerTable=mem::int_ptr[provider],depot=mem::int_ptr[provider+0x124],connection=mem::int_ptr[provider+0x158];
                if(!ahCompactAddressV108(mem::int_ptr[providerTable+40*4],"devtool.dll",106016)
                    || !ahCompactTableV108(depot,"crcore.dll",1180752,3) || !ahCompactPageV108(connection,4)
                    || !ahCompactPageV108(mem::int_ptr[connection],12) || !ahCompactConnectionCodeV108(mem::int_ptr[connection]))break;
                reason="ACTOR";Guid currentActor;mem::memcpy(currentActor.self,provider+0x10,16);
                if(currentActor==IID_NULL || (pass!=0 && currentActor!=actor))break;if(pass==0)actor=currentActor;
                reason="LISTENERS";int_ptr registry=controller+0x14;
                int_ptr listeners=mem::int_ptr[registry+4];uint listenerCount=mem::dword[registry+8];
                if(listenerCount==0 || listenerCount>16 || !ahCompactPageV108(listeners,listenerCount*4))break;
                int_ptr listener=0;uint listenerMatches=0;bool listenersKnown=true;
                for(uint i=0;i<listenerCount;i++){
                    int_ptr candidate=mem::int_ptr[listeners+i*4];if(candidate==0)continue;
                    if(!ahCompactTableV108(candidate,"config.dll",2855532,5)){listenersKnown=false;break;}
                    int_ptr table=mem::int_ptr[candidate];
                    if(!ahCompactAddressV108(mem::int_ptr[table+3*4],"config.dll",1062912)
                        || !ahCompactAddressV108(mem::int_ptr[table+4*4],"config.dll",1062880)){listenersKnown=false;break;}
                    listener=candidate;listenerMatches++;
                }
                if(!listenersKnown || listenerMatches!=1 || !ahCompactPageV108(listener,20))break;
                reason="STATE";int_ptr state=mem::int_ptr[listener+16];
                if(!ahCompactTableV108(state,"config.dll",2855428,8) || !ahCompactPageV108(state,36))break;
                int_ptr stateTable=mem::int_ptr[state],attached=mem::int_ptr[state+20];
                if(!ahCompactAddressV108(mem::int_ptr[stateTable+7*4],"config.dll",1063376) || attached==0)break;
                reason="UI_GUARDS";int_ptr guards=mem::int_ptr[uiPointer+0xf4],guardEnd=mem::int_ptr[uiPointer+0xf8];
                if(guardEnd<=guards || guardEnd-guards>64 || (guardEnd-guards)%4!=0 || !ahCompactPageV108(guards,uint(guardEnd-guards)))break;
                uint guardMatches=0;array<int_ptr> guardPointers;
                for(int_ptr at=guards;at<guardEnd;at+=4){int_ptr item=mem::int_ptr[at];guardPointers.insertLast(item);if(item==state)guardMatches++;}
                if(guardMatches!=1)break;
                reason="CACHE_ABI";int_ptr cache=mem::int_ptr[state+32];
                if(!ahCompactTableV108(cache,"crcore.dll",1193888,17))break;
                int_ptr cacheTable=mem::int_ptr[cache],cacheSlot=mem::int_ptr[cacheTable+16*4];
                if(!ahCompactAddressV108(cacheSlot,"crcore.dll",724432))break;
                array<int_ptr> pointers={uiPointer,managerPointer,rootPointer,direct,active,context,plain,holder,controller,provider,
                    depot,connection,listeners,int_ptr(listenerCount),listener,state,attached,guards,guardEnd,cache,cacheTable,cacheSlot};
                for(uint i=0;i<guardPointers.length;i++)pointers.insertLast(guardPointers[i]);
                if(pass==0)baselinePointers=pointers;
                else {bool same=pointers.length==baselinePointers.length;for(uint i=0;same && i<pointers.length;i++)same=pointers[i]==baselinePointers[i];if(!same)break;}
                binding=true;registered=true;reason="LOCAL_CACHE";
                for(uint i=0;i<3;i++){
                    Guid id("{"+ids[i]+"}");cacheReads++;uint value=ahRepositoryStatusRead(cache,id.self);
                    if(pass==0)modes[i]=value;else repeatModes[i]=value;
                }
                reason="ANCESTOR";ancestorReads++;int_ptr ancestor=ahPolicyAncestorV58(mem::addressOf(templ));
                string kind=ancestor==mem::addressOf(templ)?"TEMPLATE":(ancestor==mem::addressOf(parent)?"PARENT":(ancestor==mem::addressOf(rootObject)?"ROOT":"UNKNOWN"));
                if(kind=="UNKNOWN" || (pass!=0 && kind!=ancestorKind))break;if(pass==0)ancestorKind=kind;
                reason="SOURCE_CHANGED";IMDContainer@ freshRoot=ui.getMDCont();IConfigMngr@ freshManager=root.getConfigMngr();
                IMDObject@ freshTemplate=root.objById(templateId);IMDObject@ freshParent=root.objById(parentId);
                if(freshRoot is null || freshManager is null || freshTemplate is null || freshParent is null
                    || mem::addressOf(freshRoot)!=rootPointer || mem::addressOf(freshManager)!=managerPointer
                    || mem::addressOf(freshTemplate)!=mem::addressOf(templ) || mem::addressOf(freshParent)!=mem::addressOf(parent)
                    || root.isModified() || ui.isModified() || templ.isModified() || parent.isModified() || document.isModified()
                    || !ahAccessSelectionV232(templateId) || ahRepoSelectionVerified)break;
                reason="BINDING_CHANGED";Guid finalActor;mem::memcpy(finalActor.self,provider+0x10,16);
                if(finalActor!=actor || mem::int_ptr[controller+0x30]!=provider || mem::int_ptr[controller+0x34]!=managerPointer
                    || mem::int_ptr[registry+4]!=listeners || mem::dword[registry+8]!=listenerCount
                    || mem::int_ptr[listener+16]!=state || mem::int_ptr[state+20]!=attached || mem::int_ptr[state+32]!=cache
                    || mem::int_ptr[uiPointer+0xf4]!=guards || mem::int_ptr[uiPointer+0xf8]!=guardEnd
                    || mem::int_ptr[cache]!=cacheTable || mem::int_ptr[cacheTable+16*4]!=cacheSlot)break;
                bool guardsSame=true;for(uint i=0;i<guardPointers.length;i++)if(mem::int_ptr[guards+i*4]!=guardPointers[i])guardsSame=false;
                if(!guardsSame)break;
                passes++;
            }
            if(passes!=2)break;
            reason="LOCAL_MODE_CHANGED";stable=true;for(uint i=0;i<3;i++)if(modes[i]!=repeatModes[i])stable=false;
            if(!stable)break;ancestorVerified=true;reason="CHECKPOINT";
            IMDEditHelper@ freshHelper;service.getEditHelper(freshHelper,templ);
            if(freshHelper is null || freshHelper.getMDObj() is null || mem::addressOf(freshHelper.getMDObj())!=mem::addressOf(templ)
                || freshHelper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))break;
            IUnknown@ freshBody;freshHelper.extProp(freshBody,property,true);IDocument@ freshDocument=freshBody;IPersistableDocument@ freshPersistent=freshBody;
            if(freshDocument is null || freshPersistent is null || freshDocument.isModified())break;checkpointReads++;
            if(!ahSheetSnapshotV231(freshPersistent,afterMemory,afterHash) || beforeHash!=afterHash)break;
            checkpoint=true;reason="SOURCE_CHANGED";
            if(root.isModified() || ui.isModified() || templ.isModified() || parent.isModified() || document.isModified()
                || freshDocument.isModified() || !ahCatalogEditableV218(root))break;
            okay=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){okay=false;reason="NATIVE_EXCEPTION";}
    // The diagnostic restores its original fixed seed selection even on refusal.
    if(initialSelection && selectionTouched && ui !is null){
        ExceptionCatcher restore;
        {CppCatch caught("class core::Exception",ExceptionHandler(restore.handle));
            ui.mdTreeShow(true,true);ui.activateObjInTree(seedId,IID_NULL,true);string tree=ahRepoTreeContext(ui);
            selectionRestored=ahAccessSelectionV232(seedId) && root !is null && !root.isModified() && !ui.isModified()
                && templ !is null && !templ.isModified() && parent !is null && !parent.isModified()
                && document !is null && !document.isModified();
        }
        if(restore.hasException)selectionRestored=false;
    }else selectionRestored=initialSelection && !selectionTouched;
    if(selectionTouched && !selectionRestored){okay=false;reason="SELECTION_RESTORE";}
    string result="{\"version\":233,\"status\":\""+(okay?"OBSERVED":"REFUSED")+"\",\"reason\":\""+reason
        +"\",\"rootId\":\"218b5d00-7e10-486f-874c-73c2368ed5da\",\"parentId\":\"686a3dbe-be94-45e7-9e8b-dd93f0cd579c\",\"templateId\":\"8daef957-4ae2-48a1-bf6c-b88163a076f5\""
        +",\"registeredGuardVerified\":"+registered+",\"bindingVerified\":"+binding+",\"bindingUnchanged\":"+(passes==2)
        +",\"checkpointUnchanged\":"+checkpoint+",\"checkpointSha256\":\""+(checkpoint?afterHash:"")+"\",\"ancestorVerified\":"+ancestorVerified
        +",\"ancestorKind\":\""+ancestorKind+"\",\"modes\":["+modes[0]+","+modes[1]+","+modes[2]+"],\"repeatModes\":["+repeatModes[0]+","+repeatModes[1]+","+repeatModes[2]+"]"
        +",\"selectionTouched\":"+selectionTouched+",\"selectionRestored\":"+selectionRestored+",\"adapterInitialized\":"+adapterInitialized+",\"ancestorInitAttempts\":"+ancestorInitAttempts
        +",\"cacheReads\":"+cacheReads+",\"additionalBindingCacheReads\":0,\"ancestorReads\":"+ancestorReads+",\"checkpointReads\":"+checkpointReads
        +",\"registeredGuardCanonicalQueryPerformed\":false,\"modeMeaningVerified\":false,\"localPolicyOnly\":true,\"writerAuthorized\":false"
        +",\"serverStatisticCalls\":0,\"objectInfoCalls\":0,\"plannerCalls\":0,\"notificationCalls\":0,\"metadataWrites\":0,\"repositoryMutations\":0,\"databaseUpdates\":0}";
    if(result.toUtf8().length>8192)result="{\"version\":233,\"status\":\"REFUSED\",\"reason\":\"REPORT_BOUND\",\"localPolicyOnly\":true,\"writerAuthorized\":false}";
    ExceptionCatcher proof;
    {CppCatch caught("class core::Exception",ExceptionHandler(proof.handle));ahWriteSample("__PROOF_PATH__",result);}
}
