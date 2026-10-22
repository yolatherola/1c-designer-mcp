// OFFLINE COMPOSITION FRAGMENT ONLY. Prefix must admit the complete V240 RAM
// packet, retain its checkpoint allocation and provide packetValid plus both
// originalTexts/replacementTexts arrays. Never dispatch this skeleton directly.
void ahRunnerModuleApplyV244() {
    __VALIDATED_PACKET_PREFIX__
    bool moduleCompositeAdmitted=false,modulePrepared=false,moduleApplied=false,moduleUnknown=false;
    string moduleReason="PACKET",moduleStatus="REFUSED";
    uint modulePreparedCount=0,moduleWriteCalls=0,moduleBeginCalls=0,moduleCloseCalls=0,moduleAppliedCount=0;
    bool moduleSelectionsRestored=true,moduleTreeSelectionRestored=false;
    IConfigMngrUI@ moduleUi;IMDContainer@ moduleRoot;IMDEditService@ moduleService;
    array<IMDObject@> moduleObjects(2);array<IMDEditHelper@> moduleHelpers(2);
    array<IMDEditModuleHelper@> moduleModules(2);array<ITextManager@> moduleTexts(2);
    array<ITextEditor@> moduleEditors(2);array<IDocument@> moduleDocuments(2);
    array<TextPosition> moduleSavedStart(2),moduleSavedStop(2);
    array<bool> moduleSelectionSaved(2,false),moduleActionBegan(2,false),moduleActionClosed(2,false);
    array<bool> moduleObjectModified(2,false);
    array<string> moduleIds={"176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
    array<string> moduleOriginalHashes={"506fe9bd7d1ade475a54dd4bfabb22f82d91a634b2477f44fdcc38b96f9417b6","c5b596a38e554aa34e1e1adba527e45db35516b8e72772c6724645ed481b81ba"};
    array<uint> moduleOriginalBytes={102426,39129},moduleVersions={2272,1646};
    Guid moduleProperty("{d5963243-262e-4398-b4d7-fb16d06484f6}"),moduleActor;
    int_ptr moduleProvider=0;Guid moduleSeed("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}");
    ExceptionCatcher moduleCatch;
    {CppCatch caught("class core::Exception",ExceptionHandler(moduleCatch.handle));
        do {
            // V244_PREPARE_BEGIN
            if(!packetValid || originalTexts.length!=2 || replacementTexts.length!=2)break;
            moduleReason="OWNER";
            if(ahStatusUi is null || !ahPipeScopeAlive() || ahGetCurrentProcessId()!=ahFrameOwnerPidV211
                || ahGetCurrentThreadId()!=ahFrameOwnerTidV211 || !ahAccessSelectionV232(moduleSeed))break;
            @moduleUi=ahStatusUi;@moduleRoot=moduleUi.getMDCont();moduleReason="ROOT";
            if(!ahCatalogEditableV218(moduleRoot) || moduleRoot.isModified() || moduleUi.isModified())break;
            // Full232 performs the already verified core/UI/provider joins and
            // restores tree selection. Do not synthesize a bound flag or call
            // legacy context with a physically false seed-selection claim.
            string access=ahTargetAccessV232();moduleReason="REPOSITORY_BINDING";
            if(access.length>131072 || access.find("\"status\":\"OBSERVED\"")<0
                || access.find("\"providerBound\":true")<0 || access.find("\"providerBoundAfterContext\":true")<0
                || !ahAccessSelectionV232(moduleSeed))break;
            moduleProvider=ahPlanProvider;
            if(!ahCompactPageV108(moduleProvider,0x20))break;mem::memcpy(moduleActor.self,moduleProvider+0x10,16);
            if(!ahAccessProviderV232(moduleProvider,moduleActor))break;
            @moduleService=getMDEditService();if(moduleService is null)break;
            for(uint index=0;index<2;index++){
                moduleReason="PACKET_ORIGINAL";utf8string originalBytes=originalTexts[index].toUtf8();
                if(originalBytes.length!=moduleOriginalBytes[index] || originalTexts[index].length==0
                    || originalTexts[index]==replacementTexts[index] || replacementTexts[index].length==0
                    || replacementTexts[index].toUtf8().length>1048576)break;
                MemoryBuffer originalMemory(originalBytes.length);
                if(originalMemory.bytes==0 || originalMemory._length!=originalBytes.length)break;
                mem::memcpy(originalMemory.bytes,originalBytes.ptr,originalBytes.length);
                if(ahTemplateRamShaV202(originalMemory,originalBytes.length)!=moduleOriginalHashes[index])break;
                v8string original=originalTexts[index],replacement=replacementTexts[index];
                // Only the primary-proven LF EOF selection is admitted here.
                if(mem::word[original.cstr+(original.length-1)*2]!=10
                    || mem::word[replacement.cstr+(replacement.length-1)*2]!=10)break;
                Guid target("{"+moduleIds[index]+"}");IMDObject@ object=moduleRoot.objById(target);moduleReason="MODULE_TARGET";
                if(object is null || object.id!=target || object.isModified() || object.mdClass is null || object.mdParentLink is null)break;
                IMDObject@ parent=object.mdParentLink.getMDObject();string propertyName;
                if(parent is null || parent.id!=moduleRoot.id || !ahCatalogLinkV218(object,parent,moduleRoot)
                    || !ahModulePropertyV225(object,moduleProperty,propertyName) || propertyName!="Module")break;
                string statistic,expected="{\"queried\":true,\"verified\":true,\"version\":"+moduleVersions[index]
                    +",\"revised\":true,\"ownerId\":\""+ahCatalogIdV218(moduleActor)+"\",\"actorId\":\""+ahCatalogIdV218(moduleActor)+"\",\"ownership\":\"OWN\"}";
                moduleReason="MODULE_OWN_VERSION";
                if(!ahAccessStatisticV232(moduleProvider,moduleActor,target,statistic) || statistic!=expected)break;
                IMDEditHelper@ helper;moduleService.getEditHelper(helper,object);IMDEditModuleHelper@ module;
                if(helper !is null)@module=helper.unk;moduleReason="MODULE_HELPER";
                if(helper is null || module is null || !ahCatalogSameV218(helper.getMDObj().unk,object.unk))break;
                Vector present;module.hasModule(moduleProperty,present);if(present.end<=present.start)break;
                v8string helperBefore;moduleReason="HELPER_SOURCE";
                if(!module.textOfModule(moduleProperty,true,helperBefore) || helperBefore.str!=originalTexts[index])break;
                ITextManager@ text;ITextEditor@ editor;uint32 flags=0x10101;moduleReason="OPEN_MODULE";
                module.openModule(text,moduleProperty,flags,editor);
                if(text is null || editor is null)break;
                moduleReason="TEXT_EDITOR_ABI";
                if(!ahCompactTableV108(text.self,"txtedt.dll",0x46dc4,11)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[text.self]+10*4],"txtedt.dll",0x2dcf0)
                    || !ahCompactTableV108(editor.self,"txtedui.dll",0x10db3c,4)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[editor.self]],"txtedui.dll",0xe4680)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[editor.self]+3*4],"txtedui.dll",0xa2020))break;
                ITextManager@ editorText;editor.getITextManager(editorText);moduleReason="EDITOR_BINDING";
                if(editorText is null || editorText.self!=text.self
                    || mem::addressOf(editorText.getTextManager())!=mem::addressOf(text.getTextManager()))break;
                IDocument@ document=text.unk;moduleReason="DOCUMENT_ABI";
                if(document is null || !ahCompactTableV108(document.self,"txtedui.dll",0x109978,23)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[document.self]+8*4],"txtedui.dll",0x74450)
                    || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[document.self]+22*4],"txtedui.dll",0x7d7d0))break;
                v8string editorBefore,helperAgain;moduleReason="EDITOR_SOURCE";
                if(document.isModified() || document.getReadOnly() || !text.getTextManager().save(editorBefore)
                    || editorBefore.str!=originalTexts[index] || !module.textOfModule(moduleProperty,true,helperAgain)
                    || helperAgain.str!=helperBefore.str || !ahCatalogSameV218(helper.getMDObj().unk,object.unk))break;
                text.getTextManager().getSelectRange(moduleSavedStart[index],moduleSavedStop[index]);moduleSelectionSaved[index]=true;
                @moduleObjects[index]=object;@moduleHelpers[index]=helper;@moduleModules[index]=module;
                @moduleTexts[index]=text;@moduleEditors[index]=editor;@moduleDocuments[index]=document;
                // Verify EOF selection for BOTH modules before the composite
                // may edit the sheet or either module; restore immediately.
                int prepareLines=text.getTextManager().getLinesCount();moduleReason="PREPARE_WHOLE_SELECTION";
                if(prepareLines<1 || prepareLines>100000)break;
                int prepareLength=text.getTextManager().getLineLength(prepareLines,true);
                if(prepareLength<0 || prepareLength>1048576)break;
                text.getTextManager().setSelectRange(1,1,prepareLines+1,1);
                int_ptr prepareSelected=text.getTextManager().ahWholeSelectedTextV65();
                bool prepareExact=prepareSelected!=0 && ahWholeModuleV65Readable(prepareSelected,(original.length+1)*2);
                for(uint i=0;prepareExact && i<original.length;i++)prepareExact=mem::word[prepareSelected+i*2]==mem::word[original.cstr+i*2];
                prepareExact=prepareExact && mem::word[prepareSelected+original.length*2]==0;
                text.getTextManager().setSelectRange(moduleSavedStart[index],moduleSavedStop[index]);
                TextPosition prepareStart,prepareStop;text.getTextManager().getSelectRange(prepareStart,prepareStop);
                if(!prepareExact || prepareStart!=moduleSavedStart[index] || prepareStop!=moduleSavedStop[index])break;
                modulePreparedCount++;
            }
            if(modulePreparedCount!=2)break;
            if(moduleTexts[0].self==moduleTexts[1].self || moduleDocuments[0].self==moduleDocuments[1].self)break;
            moduleReason="PREPARE_ROOT_CHANGED";
            if(moduleRoot.isModified() || moduleUi.isModified() || !ahAccessSelectionV232(moduleSeed)
                || !ahCatalogSameV218(moduleUi.getMDCont().unk,moduleRoot.unk))break;
            modulePrepared=true;moduleStatus="PREPARED";moduleReason="NONE";
            // V244_PREPARE_END

            // Root places sheet APPLY only after the PREPARE above completes.
            // This false default must be replaced by a separately sealed full
            // three-object admission, never by a user payload or raw AS text.
            if(!modulePrepared || !moduleCompositeAdmitted)break;
            // V244_APPLY_BEGIN
            // Revalidate BOTH modules before first mutation. A preceding own
            // sheet mutation may legitimately make the whole root dirty.
            uint freshModules=0;
            for(uint index=0;index<2;index++){
                moduleReason="FRESH_OWNER";
                if(!ahPipeScopeAlive() || ahStatusUi !is moduleUi || !ahCatalogEditableV218(moduleRoot)
                    || !ahCatalogSameV218(moduleUi.getMDCont().unk,moduleRoot.unk)
                    || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
                IMDObject@ fresh=moduleRoot.objById(Guid("{"+moduleIds[index]+"}"));v8string liveHelper,liveEditor;
                moduleReason="FRESH_MODULE";
                if(fresh is null || !ahCatalogSameV218(fresh.unk,moduleObjects[index].unk) || fresh.isModified()
                    || !ahCatalogSameV218(moduleHelpers[index].getMDObj().unk,fresh.unk)
                    || moduleDocuments[index].isModified() || moduleDocuments[index].getReadOnly()
                    || !moduleModules[index].textOfModule(moduleProperty,true,liveHelper)
                    || !moduleTexts[index].getTextManager().save(liveEditor)
                    || liveHelper.str!=originalTexts[index] || liveEditor.str!=originalTexts[index])break;
                string statistic,expected="{\"queried\":true,\"verified\":true,\"version\":"+moduleVersions[index]
                    +",\"revised\":true,\"ownerId\":\""+ahCatalogIdV218(moduleActor)+"\",\"actorId\":\""+ahCatalogIdV218(moduleActor)+"\",\"ownership\":\"OWN\"}";
                moduleReason="FRESH_OWN_VERSION";
                if(!ahAccessStatisticV232(moduleProvider,moduleActor,fresh.id,statistic) || statistic!=expected)break;
                freshModules++;
            }
            if(freshModules!=2)break;
            for(uint index=0;index<2;index++){
                ITextManager@ text=moduleTexts[index];IDocument@ document=moduleDocuments[index];
                v8string original=originalTexts[index],replacement=replacementTexts[index],immediate;moduleReason="IMMEDIATE_SOURCE";
                if(document.isModified() || document.getReadOnly() || !text.getTextManager().save(immediate)
                    || immediate.str!=originalTexts[index] || !ahAccessProviderV232(moduleProvider,moduleActor))break;
                int lines=text.getTextManager().getLinesCount();moduleReason="WHOLE_SELECTION";
                if(lines<1 || lines>100000)break;
                int lastLength=text.getTextManager().getLineLength(lines,true);if(lastLength<0 || lastLength>1048576)break;
                text.getTextManager().setSelectRange(1,1,lines+1,1);TextPosition first,last;
                text.getTextManager().getSelectRange(first,last);
                int_ptr selected=text.getTextManager().ahWholeSelectedTextV65();
                bool exact=selected!=0 && ahWholeModuleV65Readable(selected,(original.length+1)*2);
                for(uint i=0;exact && i<original.length;i++)exact=mem::word[selected+i*2]==mem::word[original.cstr+i*2];
                exact=exact && mem::word[selected+original.length*2]==0;if(!exact)break;
                IUnknown@ noExternal;moduleReason="ACTION_BEGIN";moduleBeginCalls++;
                moduleActionBegan[index]=text.getTextManager().ahOwnedActionBeginV63(0,first,last,noExternal);
                if(!moduleActionBegan[index])break;
                moduleReason="WHOLE_WRITE";moduleWriteCalls++;moduleUnknown=true;
                text.getTextManager().setSelectText(replacement.cstr,true);
                v8string after;bool readback=text.getTextManager().save(after) && after.str==replacementTexts[index];
                // Close a successful exact write using the proved LF EOF path.
                // Never close/undo an arbitrary partial write or failed getter.
                if(!readback)break;
                int afterLines=text.getTextManager().getLinesCount();if(afterLines<1 || afterLines>100000)break;
                TextPosition afterPosition(afterLines+1,1);text.getTextManager().setSelectRange(afterPosition,afterPosition);
                moduleReason="ACTION_CLOSE";moduleCloseCalls++;
                text.getTextManager().ahOwnedActionCloseV63(afterPosition,afterPosition);moduleActionClosed[index]=true;
                v8string finalEditor,finalHelper;moduleReason="AFTER_TEXT";
                if(!document.isModified() || document.getReadOnly() || !text.getTextManager().save(finalEditor)
                    || finalEditor.str!=replacementTexts[index]
                    || !moduleModules[index].textOfModule(moduleProperty,false,finalHelper)
                    || finalHelper.str!=replacementTexts[index]
                    || !ahCatalogSameV218(moduleHelpers[index].getMDObj().unk,moduleObjects[index].unk))break;
                moduleObjectModified[index]=moduleObjects[index].isModified();
                moduleAppliedCount++;
            }
            if(moduleAppliedCount!=2)break;
            moduleApplied=true;moduleUnknown=false;moduleStatus="APPLIED_RAM";moduleReason="NONE";
            // V244_APPLY_END
        }while(false);
    }
    if(moduleCatch.hasException){moduleReason="NATIVE_EXCEPTION";moduleUnknown=moduleBeginCalls!=0 || moduleWriteCalls!=0;}
    if(!moduleApplied && (moduleBeginCalls!=0 || moduleWriteCalls!=0))moduleUnknown=true;
    // Restore each module's original selection even after a partial refusal.
    // Selection failure is UNKNOWN after a mutation, never a discard signal.
    ExceptionCatcher moduleRestore;
    {CppCatch caught("class core::Exception",ExceptionHandler(moduleRestore.handle));
        for(uint index=0;index<2;index++)if(moduleSelectionSaved[index] && moduleTexts[index] !is null){
            moduleTexts[index].getTextManager().setSelectRange(moduleSavedStart[index],moduleSavedStop[index]);
            TextPosition currentStart,currentStop;moduleTexts[index].getTextManager().getSelectRange(currentStart,currentStop);
            if(currentStart!=moduleSavedStart[index] || currentStop!=moduleSavedStop[index])moduleSelectionsRestored=false;
        }
        if(moduleUi !is null && ahPipeScopeAlive()){
            moduleUi.mdTreeShow(true,true);moduleUi.activateObjInTree(moduleSeed,IID_NULL,true);
            string restoredTree=ahRepoTreeContext(moduleUi);moduleTreeSelectionRestored=ahAccessSelectionV232(moduleSeed);
        }
    }
    if(moduleRestore.hasException)moduleSelectionsRestored=false;
    if(moduleUi !is null && !moduleTreeSelectionRestored)moduleSelectionsRestored=false;
    if(!moduleSelectionsRestored){moduleReason="SELECTION_RESTORE";moduleUnknown=moduleBeginCalls!=0 || moduleWriteCalls!=0;moduleApplied=false;}
    if(moduleUnknown){moduleStatus="UNKNOWN_RETAIN";moduleApplied=false;}
    else if(!moduleApplied && (!modulePrepared || moduleReason!="NONE"))moduleStatus="REFUSED";
    // No proof file sink, native dispatch, save, dirty-flag reset or automatic
    // Undo is installed by this fragment. Root composes bounded counts/status
    // into its proof and must retain the original transport checkpoint on UNKNOWN.
}
