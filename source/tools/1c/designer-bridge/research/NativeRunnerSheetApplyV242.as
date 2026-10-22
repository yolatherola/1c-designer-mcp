// TOOL ONLY, OFFLINE UNADMITTED FRAGMENT. Root must prepare all three objects
// and seal a writer plan before substituting FULL_PACKET_PREFLIGHT=true.
// A retained checkpoint/document reference belongs to root until independently
// verified save or recovery. Never serialize the real document after mutation.
void ahRunnerSheetApplyV242() {
    string reason="OWNER",status="REFUSED",beforeHash="",expectedHash="";
    string operation="__OPERATION_ID__",packetSha="__PAYLOAD_SHA256__";
    // Integration placeholder ONLY, not standalone write authority. The final
    // composite must execute fresh module/editor checks before this section.
    bool fullPacketAdmitted=__FULL_PACKET_PREFLIGHT__;
    bool bound=false,cloneReady=false,intentWritten=false,writeAttempted=false,verified=false;
    bool checkpointRetained=false,documentRetained=false,selectionUnchanged=false,dirtyObserved=false;
    bool docDirty=false,objectDirty=false,parentDirty=false,rootDirty=false,uiDirty=false;
    uint bindingPasses=0,realMergeAttempts=0,realMergeCompleted=0,realSetterAttempts=0,realSetterCompleted=0;
    uint cloneSetters=0,comparedProperties=0;int_ptr retainedCheckpoint=0,retainedDocument=0;
    IConfigMngrUI@ ui;IMDContainer@ root;IMDObject@ object;IMDObject@ parent;
    IDocument@ document;IPersistableDocument@ persistent;IFileEx@ checkpoint;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(sizeof_ptr!=4 || ahStatusUi is null || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            reason="WRITER_ADMISSION";
            if(!fullPacketAdmitted || operation.length!=32 || packetSha.length!=64)break;
            string digits="0123456789abcdef";bool metadataValid=true;
            for(uint i=0;i<operation.length;i++){
                bool found=false;for(uint j=0;j<16;j++)if(operation.substr(i,1)==digits.substr(j,1))found=true;
                if(!found)metadataValid=false;
            }
            for(uint i=0;i<packetSha.length;i++){
                bool found=false;for(uint j=0;j<16;j++)if(packetSha.substr(i,1)==digits.substr(j,1))found=true;
                if(!found)metadataValid=false;
            }
            if(!metadataValid)break;
            Guid seed("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}");
            if(!ahAccessSelectionV232(seed))break;
            @ui=ahStatusUi;@root=ui.getMDCont();reason="ROOT";
            if(!ahCatalogEditableV218(root) || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}")
                || root.isModified() || ui.isModified())break;
            Guid target("{8daef957-4ae2-48a1-bf6c-b88163a076f5}");
            Guid property("{8eb4fad1-1fa6-403e-970f-2c12dbb43e23}");
            @object=root.objById(target);reason="TARGET";
            if(object is null || object.id!=target || object.isModified() || object.mdClass is null
                || object.mdClass.id!=Guid("{3daea016-69b7-4ed4-9453-127911372fe6}") || object.mdParentLink is null)break;
            @parent=object.mdParentLink.getMDObject();
            if(parent is null || parent.id!=Guid("{686a3dbe-be94-45e7-9e8b-dd93f0cd579c}") || parent.isModified()
                || parent.mdClass is null || parent.mdClass.id!=Guid("{bf845118-327b-4682-b5c6-285d2a0eb296}")
                || !ahCatalogLinkV218(object,parent,root))break;
            IMDEditService@ service=getMDEditService();IMDEditHelper@ helper;reason="HELPER";
            if(service is null)break;service.getEditHelper(helper,object);
            if(helper is null || !ahCatalogSameV218(helper.getMDObj().unk,object.unk)
                || !ahCompactTableV108(helper.self,"frntend.dll",12897096,37)
                || helper.extPropCLSID(property)!=Guid("{2f19fc86-c5b4-437e-96b6-864940b8aa55}"))break;
            IUnknown@ body;helper.extProp(body,property,false);
            @document=body;@persistent=body;IContext@ actual=body;IValue@ originalValue=body;reason="DOCUMENT";
            if(document is null || persistent is null || actual is null || originalValue is null
                || !ahCompactTableV108(document.self,"moxelui.dll",2155168,23)
                || document.getReadOnly() || !document.getConfigMode() || document.isModified())break;
            Vector views;document.enumAllViews(views);
            if(views.end<=views.start || views.end-views.start>64*4 || (views.end-views.start)%4!=0)break;
            int height=0,width=0;
            if(!ahCellNumberV230(actual,"TableHeight",height) || !ahCellNumberV230(actual,"TableWidth",width)
                || height!=25 || width!=10)break;
            IConnectionPointContainer@ container=document.unk;IUnknown@ connection;reason="CONNECTION_POINT";
            if(container is null || container.FindConnectionPoint(IID_IDocumentSink,connection)!=0 || connection is null)break;
            int_ptr cp=connection.self,firstData=0;uint firstSlots=0;array<int_ptr> firstEntries;
            array<uint> expectedSlots={748336,1187729,1187067,1167968,1167936,751456,751664,751792};
            for(uint pass=0;pass<2;pass++){
                reason="CP_ABI";
                if(!ahCompactTableV108(cp,"moxelui.dll",2155136,8) || !ahCompactPageV108(cp,12))break;
                int_ptr table=mem::int_ptr[cp];bool slotsKnown=true;
                for(uint i=0;i<8;i++)if(!ahCompactAddressV108(mem::int_ptr[table+i*4],"moxelui.dll",expectedSlots[i]))slotsKnown=false;
                if(!slotsKnown)break;
                int_ptr data=mem::int_ptr[cp+4];uint count=mem::dword[cp+8];reason="CP_BOUNDS";
                if(count==0 || count>16 || !ahCompactPageV108(data,count*4))break;
                if(pass==0){firstData=data;firstSlots=count;}else if(data!=firstData || count!=firstSlots)break;
                uint matches=0;bool entriesKnown=true;array<int_ptr> entries;
                for(uint i=0;i<count;i++){
                    int_ptr sink=mem::int_ptr[data+i*4];entries.insertLast(sink);if(sink==0)continue;
                    if(!ahCompactPageV108(sink,4)){entriesKnown=false;break;}
                    if(!ahCompactTableV108(sink,"frntend.dll",12837396,7))continue;
                    if(!ahCompactAddressV108(mem::int_ptr[mem::int_ptr[sink]+3*4],"frntend.dll",2716288)
                        || !ahCompactPageV108(sink,36)){entriesKnown=false;break;}
                    int_ptr storedHelper=mem::int_ptr[sink+16];Guid storedProperty;mem::memcpy(storedProperty.self,sink+20,16);
                    if(storedProperty==property && storedHelper==helper.self-0x7c)matches++;
                }
                reason="SINK_BINDING";if(!entriesKnown || matches!=1)break;
                if(pass==0)firstEntries=entries;
                else{
                    bool same=entries.length==firstEntries.length;
                    for(uint i=0;same && i<entries.length;i++)same=entries[i]==firstEntries[i];
                    if(!same)break;
                }
                if(mem::int_ptr[cp+4]!=data || mem::dword[cp+8]!=count || root.isModified() || ui.isModified()
                    || object.isModified() || parent.isModified() || document.isModified() || document.getReadOnly()
                    || !document.getConfigMode() || !ahAccessSelectionV232(seed))break;
                bindingPasses++;
            }
            if(bindingPasses!=2)break;bound=true;
            // The real serialization happens ONLY before any real mutation.
            reason="CLEAN_CHECKPOINT";
            if(document.isModified() || !ahSheetSnapshotV231(persistent,checkpoint,beforeHash)
                || beforeHash!="6d20f90eed3d8656fb669dcbd2701155eb481e839af968398597f6959a4842ed")break;
            IType@ type=originalValue.getType();IValue@ cloneValue;reason="CLONE";
            if(type is null || string(type.getTypeString(0))!="SpreadsheetDocument")break;
            type.createValue(cloneValue);
            if(cloneValue is null || ahCatalogSameV218(cloneValue.unk,body))break;
            IPersistableDocument@ cloneDocument=cloneValue.unk;IContext@ expected=cloneValue.unk;
            IFile@ originalFile=checkpoint.unk;
            if(cloneDocument is null || expected is null || originalFile is null || checkpoint.seek(0,fsBegin)!=0)break;
            cloneDocument.load(originalFile);
            array<int> rows={11,13,16};bool cloneOkay=true;reason="CLONE_RECIPE";
            for(uint n=0;n<rows.length;n++){
                uint setters=0;string why;
                if(!ahSheetMergeCopyV231(expected,actual,rows[n],setters,why)){cloneOkay=false;break;}
                cloneSetters+=setters;
            }
            if(!cloneOkay || cloneSetters!=36)break;
            IFileEx@ expectedMemory;reason="EXPECTED_CLONE";
            if(!ahSheetSnapshotV231(cloneDocument,expectedMemory,expectedHash)
                || expectedHash!="3f413e18fe4e6f6bb8eeec10e8e2b7f54e1b0449f441779f8f861be1ab6d6ea7")break;
            IValue@ roundValue;type.createValue(roundValue);
            if(roundValue is null || ahCatalogSameV218(roundValue.unk,body) || ahCatalogSameV218(roundValue.unk,cloneValue.unk))break;
            IPersistableDocument@ roundDocument=roundValue.unk;IContext@ roundContext=roundValue.unk;
            IFile@ expectedFile=expectedMemory.unk;
            if(roundDocument is null || roundContext is null || expectedFile is null || expectedMemory.seek(0,fsBegin)!=0)break;
            roundDocument.load(expectedFile);IFileEx@ roundMemory;string roundHash;
            if(!ahSheetSnapshotV231(roundDocument,roundMemory,roundHash) || roundHash!=expectedHash)break;
            // Collect every source style before writes; do not read a mutated source.
            array<string> writeNames={"FillType","Parameter","Text","Font","VerticalAlign","HorizontalAlign","BackColor",
                "TextColor","Format","LeftBorder","TopBorder","RightBorder","BottomBorder"};
            array<Value> styleValues(39);array<bool> useStyle(39,false);bool prepared=true;
            array<IContext@> destinations;
            for(uint n=0;n<rows.length;n++){
                IContext@ source=ahSheetAreaV231(actual,rows[n],5,7),destination=ahSheetAreaV231(actual,rows[n],2,7);
                if(source is null || destination is null){prepared=false;break;}
                destinations.insertLast(destination);string parameter;
                if(!ahSheetStringV231(source,"Parameter",parameter) || (n==0 && parameter!="")
                    || (n!=0 && parameter!="Сотрудник")){prepared=false;break;}
                int merge=destination.findMethod(v8string("Merge"));
                if(merge<0 || destination.paramsCount(merge)!=0 || destination.hasRetVal(merge)){prepared=false;break;}
                for(uint p=0;p<writeNames.length;p++){
                    if((writeNames[p]=="Text" && parameter.length!=0) || (writeNames[p]=="Parameter" && parameter.length==0))continue;
                    int index=destination.findProp(v8string(writeNames[p]));
                    if(index<0 || !destination.isPropWritable(index) || !ahSheetGetV231(source,writeNames[p],styleValues[n*13+p])){
                        prepared=false;break;}
                    useStyle[n*13+p]=true;
                }
                if(!prepared)break;
            }
            if(!prepared || destinations.length!=3)break;cloneReady=true;
            IUnknown@ currentBody;helper.extProp(currentBody,property,false);IDocument@ currentDocument=currentBody;
            reason="PREWRITE_FRESHNESS";
            if(currentDocument is null || !ahCatalogSameV218(currentDocument.unk,document.unk)
                || !ahCatalogSameV218(ui.getMDCont().unk,root.unk) || !ahCatalogSameV218(root.objById(target).unk,object.unk)
                || !ahCatalogSameV218(helper.getMDObj().unk,object.unk) || root.isModified() || ui.isModified()
                || object.isModified() || parent.isModified() || document.isModified() || document.getReadOnly()
                || !document.getConfigMode() || !ahAccessSelectionV232(seed)
                || mem::int_ptr[cp+4]!=firstData || mem::dword[cp+8]!=firstSlots)break;
            bool entriesStill=true;uint freshMatches=0;
            for(uint i=0;i<firstEntries.length;i++){
                int_ptr sink=mem::int_ptr[firstData+i*4];if(sink!=firstEntries[i])entriesStill=false;
                if(sink==0)continue;
                if(!ahCompactPageV108(sink,4)){entriesStill=false;break;}
                if(!ahCompactTableV108(sink,"frntend.dll",12837396,7))continue;
                if(!ahCompactPageV108(sink,36)){entriesStill=false;break;}
                Guid storedProperty;mem::memcpy(storedProperty.self,sink+20,16);
                if(storedProperty==property && mem::int_ptr[sink+16]==helper.self-0x7c)freshMatches++;
            }
            if(!entriesStill || freshMatches!=1)break;
            IFileEx@ freshMemory;string freshHash;
            if(document.isModified() || !ahSheetSnapshotV231(persistent,freshMemory,freshHash) || freshHash!=beforeHash)break;
            // Own explicit reference leases survive local handle destruction.
            // Root must release exactly these refs only after terminal evidence.
            checkpoint.AddRef();checkpointRetained=true;retainedCheckpoint=checkpoint.self;
            document.AddRef();documentRetained=true;retainedDocument=document.self;
            string intent="{\"version\":242,\"status\":\"SHEET_WRITE_RESERVED\",\"operationId\":\""+operation
                +"\",\"packetSha256\":\""+packetSha+"\",\"templateId\":\"8daef957-4ae2-48a1-bf6c-b88163a076f5\""
                +",\"checkpointPointer\":"+uint(retainedCheckpoint)+",\"documentPointer\":"+uint(retainedDocument)
                +",\"processId\":"+ahFrameOwnerPidV211+",\"threadId\":"+ahFrameOwnerTidV211
                +",\"checkpointSha256\":\""+beforeHash+"\",\"expectedSha256\":\""+expectedHash
                +"\",\"checkpointReferenceRetained\":true,\"documentReferenceRetained\":true,\"writerAuthorized\":true,\"metadataWriteAttempts\":0}";
            reason="INTENT";utf8string intentBytes=intent.toUtf8();
            uint file=CreateFile("__PREWRITE_INTENT_PATH__".cstr,0x40000000,1,0,1,0x80000080,0);
            if(file==0xffffffff)break;
            uint intentCount=0;bool intentOkay=WriteFile(file,intentBytes.ptr,intentBytes.length,mem::addressOf(intentCount),0)!=0;
            bool intentClosed=CloseHandle(file)!=0;
            if(!intentOkay || !intentClosed || intentCount!=intentBytes.length)break;
            intentWritten=true;
            // BEGIN REAL MUTATION. No save/load/snapshot of document is allowed
            // below this boundary. Attempts include calls that might throw.
            reason="REAL_MERGE";bool applied=true;
            for(uint n=0;n<rows.length;n++){
                IContext@ destination=destinations[n];int merge=destination.findMethod(v8string("Merge"));
                if(merge<0){applied=false;break;}
                ValueParamsVector noArgs(0);Value ignored;writeAttempted=true;realMergeAttempts++;
                if(!destination.callMeth(merge,ignored,noArgs.args)){applied=false;break;}realMergeCompleted++;
                for(uint p=0;p<writeNames.length;p++){
                    if(!useStyle[n*13+p])continue;
                    reason="REAL_PROPERTY";int index=destination.findProp(v8string(writeNames[p]));
                    if(index<0 || !destination.isPropWritable(index)){applied=false;break;}
                    realSetterAttempts++;
                    if(!destination.setPropVal(index,styleValues[n*13+p])){applied=false;break;}realSetterCompleted++;
                }
                if(!applied)break;
            }
            if(!applied || realMergeCompleted!=3 || realSetterCompleted!=36)break;
            reason="VERIFY_PROPERTIES";
            array<string> compareNames={"Text","Parameter","FillType","Font","BackColor","TextColor","LeftBorder","TopBorder",
                "RightBorder","BottomBorder","ColumnWidth","RowHeight","VerticalAlign","HorizontalAlign","Format"};
            bool equal=true;
            // All250 cells, including date/separator rows12/14/15/17 inside the
            // old outside-comparison exclusion, must equal the expected clone.
            for(int row=1;row<=25 && equal;row++)for(int col=1;col<=10 && equal;col++){
                IContext@ a=ahSheetAreaV231(actual,row,col,col),b=ahSheetAreaV231(expected,row,col,col);
                if(a is null || b is null){equal=false;break;}
                for(uint p=0;p<compareNames.length;p++){
                    Value x,y;if(!ahSheetGetV231(a,compareNames[p],x) || !ahSheetGetV231(b,compareNames[p],y)
                        || !ahSheetEqualV231(x,y)){equal=false;break;}comparedProperties++;
                }
            }
            if(!equal || comparedProperties!=3750)break;
            string header;
            if(!ahSheetStringV231(ahSheetAreaV231(actual,11,2,7),"Text",header) || header!="Специалист")break;
            for(uint n=1;n<rows.length;n++){
                string parameter;if(!ahSheetStringV231(ahSheetAreaV231(actual,rows[n],2,7),"Parameter",parameter)
                    || parameter!="Сотрудник")equal=false;
            }
            if(!equal || !ahCellNumberV230(actual,"TableHeight",height) || !ahCellNumberV230(actual,"TableWidth",width)
                || height!=25 || width!=10)break;
            reason="NATIVE_DIRTY";
            docDirty=document.isModified();objectDirty=object.isModified();parentDirty=parent.isModified();
            rootDirty=root.isModified();uiDirty=ui.isModified();dirtyObserved=true;
            // Tracking must occur naturally. Do not force flags or call an
            // uncontracted sink/helper notification if any observation is false.
            if(!docDirty || !objectDirty || !rootDirty || !uiDirty || document.getReadOnly() || !document.getConfigMode())break;
            if(!ahAccessSelectionV232(seed) || !ahCatalogSameV218(helper.getMDObj().unk,object.unk))break;
            verified=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){verified=false;reason="NATIVE_EXCEPTION";}
    // Never auto-release retained recovery refs, restore guessed flags, repeat a
    // setter, or save after an uncertain native result.
    selectionUnchanged=ahAccessSelectionV232(Guid("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}"));
    if(!selectionUnchanged){verified=false;reason="SELECTION_CHANGED";}
    status=verified?"WROTE_VERIFIED":(writeAttempted?"UNKNOWN_RETAIN":(checkpointRetained || documentRetained?"REFUSED_RETAIN":"REFUSED"));
    string proof="{\"version\":242,\"status\":\""+status+"\",\"reason\":\""+reason+"\",\"operationId\":\""+operation
        +"\",\"packetSha256\":\""+packetSha+"\",\"templateId\":\"8daef957-4ae2-48a1-bf6c-b88163a076f5\""
        +",\"fullPacketPreflight\":"+fullPacketAdmitted+",\"metadataBindingVerified\":"+bound+",\"bindingPasses\":"+bindingPasses+",\"expectedCloneVerified\":"+cloneReady
        +",\"beforeSha256\":\""+beforeHash+"\",\"expectedSha256\":\""+expectedHash+"\",\"intentWritten\":"+intentWritten
        +",\"mutationPossible\":"+writeAttempted+",\"metadataMutationsVerified\":"+verified
        +",\"realMergeAttempts\":"+realMergeAttempts+",\"realMergesCompleted\":"+realMergeCompleted
        +",\"realSetterAttempts\":"+realSetterAttempts+",\"realSettersCompleted\":"+realSetterCompleted
        +",\"metadataWriteAttempts\":"+(realMergeAttempts+realSetterAttempts)+",\"metadataWrites\":"+(realMergeCompleted+realSetterCompleted)
        +",\"comparedProperties\":"+comparedProperties+",\"nativeDirtyObserved\":"+dirtyObserved+",\"documentModified\":"+docDirty+",\"objectModified\":"+objectDirty
        +",\"parentModified\":"+parentDirty+",\"rootModified\":"+rootDirty+",\"uiModified\":"+uiDirty
        +",\"checkpointReferenceRetained\":"+checkpointRetained+",\"documentReferenceRetained\":"+documentRetained
        +",\"checkpointPointer\":"+uint(retainedCheckpoint)+",\"documentPointer\":"+uint(retainedDocument)
        +",\"selectionUnchanged\":"+selectionUnchanged+",\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0"
        +",\"realPostwriteSerializations\":0,\"dirtyFlagWrites\":0,\"undoCalls\":0,\"configurationSavedVerified\":false,\"writerAuthorized\":true}";
    ExceptionCatcher output;
    {CppCatch caught("class core::Exception",ExceptionHandler(output.handle));if(proof.toUtf8().length<=8192)ahWriteSample("__PROOF_PATH__",proof);}
}
