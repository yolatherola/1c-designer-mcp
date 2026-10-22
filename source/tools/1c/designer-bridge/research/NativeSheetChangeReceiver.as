// Fixed readonly observer. The root carrier must independently verify the whole
// moxelui.dll SHA ff7320903400d8fa7dacb0c1ed2e6fb70fd00e14aabf2a1044bd64603a7d5fe7.
// This callback never dispatches the discovered native change method.
void ahSheetChangeReceiver() {
    string reason="ROOT",entries="[]",callbackHash="";
    bool verified=false,pendingNativeReferences=false,cleanupKnown=false;
    uint viewCount=0,adoptedViews=0,releasedViews=0,passes=0,matchedViews=0;
    array<IUnknown@> heldViews;
    Vector views;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(ahStatusUi is null || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211
                || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();
            if(!ahCatalogEditableV218(root) || root.isModified() || ui.isModified())break;
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
            IUnknown@ body;helper.extProp(body,property,false);
            IDocument@ document=body;reason="DOCUMENT";
            if(document is null || !ahCompactTableV108(document.self,"moxelui.dll",2155168,23)
                || document.isModified() || document.getReadOnly() || !document.getConfigMode())break;
            document.enumAllViews(views);pendingNativeReferences=true;reason="VIEW_BOUNDS";
            if(views.start==0 || views.end<=views.start || views.end-views.start>64*4
                || (views.end-views.start)%4!=0 || views.allocated<views.end
                || !ahCompactPageV108(views.start,uint(views.end-views.start)))break;
            viewCount=uint(views.end-views.start)/4;
            // enumAllViews adds one native reference per nonnull element. Vector
            // only frees its storage, so adopt exactly these counted references.
            for(uint i=0;i<viewCount;i++){
                int_ptr returnedView=mem::int_ptr[views.start+i*4];
                if(returnedView==0){heldViews.insertLast(null);continue;}
                IUnknown@ counted=toIUnknown(returnedView);
                if(counted is null)break;
                heldViews.insertLast(counted);adoptedViews++;
            }
            if(heldViews.length!=viewCount)break;
            pendingNativeReferences=false;
            array<int_ptr> firstReceivers;array<int_ptr> firstTables;
            array<int_ptr> firstWindows;array<int_ptr> firstInternalViews;
            int_ptr expectedCallback=0;
            for(uint pass=0;pass<2;pass++){
                uint matches=0;bool valid=true;string observed="[";
                for(uint i=0;i<viewCount;i++){
                    reason="VIEW_NULL";
                    if(heldViews[i] is null){valid=false;break;}
                    int_ptr returnedView=heldViews[i].self;
                    if(returnedView<0x20){valid=false;break;}
                    int_ptr internalView=returnedView-0x20;reason="VIEW_LAYOUT";
                    if(!ahCompactPageV108(internalView,0x60)){valid=false;break;}
                    int_ptr nativeWindow=mem::int_ptr[internalView+0x5c];
                    if(nativeWindow==0 || nativeWindow>int_ptr(0x7fffffff)-0xc00
                        || !ahCompactPageV108(nativeWindow,0xc00)){valid=false;break;}
                    int_ptr receiver=nativeWindow+0x1a0;reason="RECEIVER_TABLE";
                    bool standard=ahCompactTableV108(receiver,"moxelui.dll",2167336,90);
                    bool derived=ahCompactTableV108(receiver,"moxelui.dll",2174000,90);
                    if(!standard && !derived){valid=false;break;}
                    int_ptr table=mem::int_ptr[receiver];
                    reason="RECEIVER_BACK_JOIN";
                    if(mem::int_ptr[receiver+0x784]!=internalView){valid=false;break;}
                    reason="CALLBACK_ABI";
                    int_ptr callback=mem::int_ptr[table+89*4];
                    if(!ahCompactAddressV108(callback,"moxelui.dll",332512)
                        || !ahCompactAddressV108(mem::int_ptr[table+10*4],"moxelui.dll",88640)
                        || !ahCompactPageV108(callback,579)){valid=false;break;}
                    MemoryBuffer code(579);mem::memcpy(code.bytes,callback,579);
                    // The sealed PE contains five HIGHLOW relocations here.
                    // Validate the loaded operands, then canonicalize only our
                    // owned copy to the preferred image base before hashing.
                    array<uint> relocationOffsets={6,24,49,80,377};
                    array<uint> relocationTargets={0x1f7188,0x24e008,0x15a40,0x15a40,0x20e37c};
                    uint moduleBase=uint(callback)-332512;bool relocationsKnown=true;
                    for(uint relocation=0;relocation<5;relocation++){
                        uint offset=relocationOffsets[relocation],targetRva=relocationTargets[relocation];
                        if(mem::dword[code.bytes+offset]!=moduleBase+targetRva){relocationsKnown=false;break;}
                        mem::dword[code.bytes+offset]=0x17420000+targetRva;
                    }
                    reason="CALLBACK_RELOCATIONS";
                    if(!relocationsKnown){valid=false;break;}
                    string hash=ahTemplateRamShaV202(code,579);
                    if(hash!="e748d3fc4f6818aea0ceb1615c2361d6f5bcf65d6c9ad01a965a28a1b25afa42"){
                        valid=false;break;
                    }
                    if(expectedCallback!=0 && callback!=expectedCallback){valid=false;break;}
                    expectedCallback=callback;callbackHash=hash;
                    IDocumentView@ typedView=heldViews[i];IDocument@ viewDocument;reason="DOCUMENT_VIEW";
                    if(typedView is null){valid=false;break;}
                    typedView.document(viewDocument);
                    if(viewDocument is null || !ahCatalogSameV218(viewDocument.unk,document.unk)){
                        valid=false;break;
                    }
                    if(pass==0){firstReceivers.insertLast(receiver);firstTables.insertLast(table);
                        firstWindows.insertLast(nativeWindow);firstInternalViews.insertLast(internalView);}
                    else if(receiver!=firstReceivers[i] || table!=firstTables[i]
                        || nativeWindow!=firstWindows[i] || internalView!=firstInternalViews[i]){valid=false;break;}
                    if(i!=0)observed+=",";
                    observed+="{\"index\":"+i+",\"receiverTable\":"+ahRepoAddress(table)
                        +",\"documentPointer\":"+uint(document.self)+",\"returnedViewPointer\":"+uint(returnedView)
                        +",\"internalViewPointer\":"+uint(internalView)+",\"nativeWindowPointer\":"+uint(nativeWindow)
                        +",\"receiverPointer\":"+uint(receiver)+",\"backJoin\":true,\"documentJoin\":true,\"callbackSlot\":89}";
                    matches++;
                }
                observed+="]";
                if(!valid || matches!=viewCount)break;
                reason="STATE_CHANGED";
                IUnknown@ freshBody;helper.extProp(freshBody,property,false);IDocument@ freshDocument=freshBody;
                IMDContainer@ freshRoot=ui.getMDCont();
                if(freshRoot is null || !ahCatalogSameV218(freshRoot.unk,root.unk)
                    || freshDocument is null || !ahCatalogSameV218(freshDocument.unk,document.unk)
                    || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                    || document.isModified() || document.getReadOnly() || !document.getConfigMode()
                    || root.isModified() || ui.isModified() || object.isModified() || parent.isModified())break;
                passes++;entries=observed;matchedViews=matches;
            }
            if(passes!=2)break;
            verified=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){verified=false;reason="NATIVE_EXCEPTION";}
    ExceptionCatcher cleanup;
    {CppCatch caught("class core::Exception",ExceptionHandler(cleanup.handle));
        for(uint i=0;i<heldViews.length;i++)if(heldViews[i]!is null){@heldViews[i]=null;releasedViews++;}
        cleanupKnown=!pendingNativeReferences && releasedViews==adoptedViews;
    }
    if(cleanup.hasException || !cleanupKnown){verified=false;reason="REFERENCE_CLEANUP_UNKNOWN";}
    string result="{\"version\":1,\"phase\":\"SHEET_CHANGE_RECEIVER\",\"operationId\":\"__OPERATION_ID__\",\"status\":\""
        +(verified?"OBSERVED":(!cleanupKnown?"UNKNOWN_REFERENCE":"REFUSED"))+"\",\"reason\":\""+reason
        +"\",\"templateId\":\"8daef957-4ae2-48a1-bf6c-b88163a076f5\",\"viewCount\":"+viewCount
        +",\"matchedViews\":"+matchedViews+",\"passes\":"+passes+",\"adoptedViews\":"+adoptedViews
        +",\"releasedViews\":"+releasedViews+",\"pendingNativeReferences\":"+pendingNativeReferences
        +",\"cleanupKnown\":"+cleanupKnown+",\"callbackSha256\":\""+callbackHash+"\",\"entries\":"+entries
        +",\"callbackHashRepresentation\":\"PE32_PREFERRED_BASE\",\"callbackHighlowRelocations\":5"
        +",\"wholeModulePinVerifiedByCallback\":false,\"callbackInvocations\":0,\"rawFlagWrites\":0"
        +",\"metadataWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0"
        +",\"applicationBodyOutputBytes\":0,\"writerAuthorized\":false}";
    ExceptionCatcher output;
    {CppCatch caught("class core::Exception",ExceptionHandler(output.handle));
        if(result.toUtf8().length<=16384)ahWriteSample("__PROOF_PATH__",result);
    }
}
