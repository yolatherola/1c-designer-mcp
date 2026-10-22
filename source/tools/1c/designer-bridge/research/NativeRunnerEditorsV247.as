// Fixed readonly CommonModule editor preparation. No application text output.
void ahRunnerEditorsV247() {
    string reason="OWNER",rows="[";bool verified=false;
    uint observed=0,commandsBefore=ahCommandSeen.length,commandsAfter=commandsBefore;
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(ahStatusUi is null || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();reason="ROOT";
            if(!ahCatalogEditableV218(root) || root.isModified() || ui.isModified()
                || !ahAccessSelectionV232(Guid("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}")))break;
            array<string> ids={"176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
            for(uint i=0;i<2;i++){
                string why="OBJECT";bool okay=false,exact=false;
                do {
                    Guid target("{"+ids[i]+"}"),property("{d5963243-262e-4398-b4d7-fb16d06484f6}");
                    IMDObject@ object=root.objById(target);string propertyName;
                    if(object is null || object.id!=target || object.isModified()
                        || !ahModulePropertyV225(object,property,propertyName) || propertyName!="Module")break;
                    why="HELPER";IMDEditService@ service=getMDEditService();IMDEditHelper@ helper;
                    if(service is null)break;service.getEditHelper(helper,object);IMDEditModuleHelper@ module;
                    if(helper !is null)@module=helper.unk;
                    if(helper is null || module is null || !ahCatalogSameV218(helper.getMDObj().unk,object.unk))break;
                    v8string before;why="HELPER_SOURCE";
                    if(!module.textOfModule(property,true,before) || before.str.toUtf8().length>1048576)break;
                    ITextManager@ text;ITextEditor@ editor;uint32 flags=0x10101;why="OPEN_MODULE";
                    module.openModule(text,property,flags,editor);
                    if(text is null || editor is null)break;why="TEXT_ABI";
                    if(!ahCompactTableV108(text.self,"txtedt.dll",0x46dc4,11)
                        || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[text.self]+10*4],"txtedt.dll",0x2dcf0))break;
                    why="EDITOR_ABI";
                    if(!ahCompactTableV108(editor.self,"txtedui.dll",0x10db3c,4)
                        || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[editor.self]],"txtedui.dll",0xe4680)
                        || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[editor.self]+3*4],"txtedui.dll",0xa2020))break;
                    ITextManager@ linked;editor.getITextManager(linked);why="EDITOR_BINDING";
                    if(linked is null || linked.self!=text.self
                        || mem::addressOf(linked.getTextManager())!=mem::addressOf(text.getTextManager()))break;
                    IDocument@ document=text.unk;why="DOCUMENT_ABI";
                    if(document is null || !ahCompactTableV108(document.self,"txtedui.dll",0x109978,23)
                        || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[document.self]+8*4],"txtedui.dll",0x74450)
                        || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[document.self]+22*4],"txtedui.dll",0x7d7d0))break;
                    v8string first,second,after;why="EDITOR_SOURCE";
                    if(!text.getTextManager().save(first) || !text.getTextManager().save(second)
                        || first.str!=second.str || !module.textOfModule(property,true,after))break;
                    okay=true;exact=first.str==before.str && after.str==before.str && !document.isModified()
                        && !document.getReadOnly() && !object.isModified() && !root.isModified() && !ui.isModified()
                        && ahCatalogSameV218(root.objById(target).unk,object.unk)
                        && ahCatalogSameV218(helper.getMDObj().unk,object.unk);
                    why=exact?"NONE":"EDITOR_STATE";
                }while(false);
                rows+=(i==0?"":",")+"{\"objectId\":\""+ids[i]+"\",\"callSucceeded\":"+okay
                    +",\"cleanWritableEqual\":"+exact+",\"reason\":\""+why+"\"}";
                reason=okay?(exact?"NONE":"EDITOR_STATE"):why;
                if(!exact)break;observed++;
            }
            if(observed!=2)break;
            reason="STATE_CHANGED";
            if(root.isModified() || ui.isModified() || !ahPipeScopeAlive()
                || !ahAccessSelectionV232(Guid("{88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d}")))break;
            verified=true;reason="NONE";
        }while(false);
    }
    if(catcher.hasException){verified=false;reason="NATIVE_EXCEPTION";}
    commandsAfter=ahCommandSeen.length;rows+="]";
    string result="{\"version\":247,\"status\":\""+(verified?"EDITORS_READY":"REFUSED")+"\",\"reason\":\""+reason
        +"\",\"editorsVerified\":"+observed+",\"targets\":"+rows+",\"protectedCommandsBefore\":"+commandsBefore
        +",\"protectedCommandsAfter\":"+commandsAfter+",\"protectedCommandLimit\":126"
        +",\"sourceWrites\":0,\"metadataWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0"
        +",\"repositoryMutations\":0,\"writerAuthorized\":false}";
    ExceptionCatcher output;
    {CppCatch caught("class core::Exception",ExceptionHandler(output.handle));if(result.toUtf8().length<=4096)ahWriteSample("__PROOF_PATH__",result);}
}
