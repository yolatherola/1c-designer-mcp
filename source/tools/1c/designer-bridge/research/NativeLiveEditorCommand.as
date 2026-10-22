// Exactly one CompileFunction callback in the existing resident owner.
// V3 C bindings own the nonreentrant job/phase gate and all source buffers.
// No Save, module-body file, forced dirty flag, Begin/Close wrapper or retry.
void ahLiveEditorCommand(int_ptr envelope) {
    bool admitted=__LIVE_RESIDENT_SCOPE_ADMITTED__;
    if(!admitted)return;
    string operation="__OPERATION_ID__",scope="__SCOPE_SHA256__",source="__LIVE_RESIDENT_READER_SHA__",nonce="",digits="0123456789abcdef";
    bool owned=false,exception=false,cleared=false,verified=false,restoredStateMismatch=false,selectionTouched=false,writeArmed=false,applyEdit=false;
    uint sequence=0,opcode=0,policy=0,reason=1,version=0;
    MemoryBuffer header(512);array<uint> identity,before,after;
    IConfigMngrUI@ ui;IMDContainer@ root,freshRoot;IMDObject@ object,bound,freshObject;
    IMDEditService@ service;IMDEditHelper@ helper;IMDEditModuleHelper@ module;
    ITextManager@ text,linked;ITextEditor@ editor;IDocument@ document;
    TextPosition caret,start,stop,applyFirst,applyLast;v8string baseline,readback,restored,replacement;
    __LIVE_EDITOR_PROVIDER_DECLARATIONS__
    AhRepositoryStatisticRead@ statistic;
    __LIVE_EDITOR_REPOSITORY_DECLARATIONS__
    ExceptionCatcher catcher;
    {CppCatch caught("class core::Exception",ExceptionHandler(catcher.handle));
        do {
            if(sizeof_ptr!=4 || uint(envelope)<65536 || header.bytes==0 || __LIVE_BOUND_VALIDATE__(envelope,1536)!=1)break;
            owned=true;mem::memcpy(header.bytes,envelope,512);
            if(mem::dword[envelope]!=0x334a564c || mem::dword[envelope+4]!=3 || mem::dword[envelope+8]!=1536
                || mem::dword[envelope+240]!=0x91d4a63b || mem::dword[envelope+248]!=262144
                || mem::dword[envelope+508]!=0x6b5c28e7 || mem::dword[envelope+1532]!=0x6b5c28e7)break;
            sequence=mem::dword[envelope+12];opcode=mem::dword[envelope+244];policy=mem::dword[envelope+252];
            if(sequence<1 || sequence>64 || (opcode!=1 && opcode!=2 && opcode!=4)
                || (opcode==2 && policy!=1 && policy!=3) || (opcode==1 && policy!=0 && policy!=2) || (opcode==4 && policy!=0))break;
            applyEdit=opcode==2 && policy==3;
            bool valid=operation.length==32 && scope.length==64 && source.length==64;
            string target="d593e80db70c400b9955d02f7a4c89e9",kind="bf845118327b4682b5c6285d2a0eb296",propertyHex="a637f77f3840441da1c3699c8c5cb7e0";
            for(uint n=0;valid && n<32;n++){
                uint a=mem::byte[envelope+16+n];if(!((a>=48 && a<=57)||(a>=97 && a<=102))){valid=false;break;}
                nonce+=digits.substr(a<=57?a-48:a-87,1);
                if(mem::byte[envelope+48+n]!=uint8(target[n]) || mem::byte[envelope+80+n]!=uint8(operation[n])
                    || mem::byte[envelope+256+n]!=uint8(kind[n]) || mem::byte[envelope+288+n]!=uint8(propertyHex[n]))valid=false;
            }
            for(uint n=0;valid && n<64;n++)if(mem::byte[envelope+112+n]!=uint8(scope[n]) || mem::byte[envelope+176+n]!=uint8(source[n]))valid=false;
            if(!valid || nonce=="00000000000000000000000000000000" || !ahPipeScopeAlive() || ahStatusUi is null
                || ahGetCurrentProcessId()!=__LIVE_EDITOR_PROCESS_ID__ || ahGetCurrentThreadId()!=__LIVE_EDITOR_GUI_THREAD_ID__
                || ahGetCurrentProcessId()!=ahFrameOwnerPidV211 || ahGetCurrentThreadId()!=ahFrameOwnerTidV211)break;
            reason=2;@ui=ahStatusUi;@root=ui.getMDCont();
            if(root is null || root.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}") || !ahCatalogEditableV218(root))break;
            Guid targetId("{d593e80d-b70c-400b-9955-d02f7a4c89e9}"),property("{a637f77f-3840-441d-a1c3-699c8c5cb7e0}");
            @object=root.objById(targetId);
            if(object is null || object.id!=targetId || object.mdClass is null || object.mdClass.id!=Guid("{bf845118-327b-4682-b5c6-285d2a0eb296}")
                || object.mdParentLink is null || !ahCatalogSameV218(object.mdParentLink.getMDObject().unk,root.unk))break;
            string propertyName;if(!ahModulePropertyV225(object,property,propertyName) || propertyName!="ObjectModule")break;
            if(opcode==4){
                __LIVE_EDITOR_REPOSITORY_READ__
                break;
            }
            reason=3;@service=getMDEditService();if(service is null)break;
            service.getEditHelper(helper,object);if(helper is null)break;@module=helper.unk;
            if(module is null || !ahCompactTableV108(helper.self,"basicui.dll",0x60ae54,24)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[helper.self]+23*4],"basicui.dll",0xf3b70)
                || !ahCompactTableV108(module.self,"basicui.dll",0x60ad5c,12)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[module.self]+5*4],"basicui.dll",0x35c470))break;
            @bound=helper.getMDObj();if(bound is null || !ahCatalogSameV218(bound.unk,object.unk))break;
            reason=4;uint flags=0x10101;mem::dword[envelope+520]=mem::dword[envelope+520]+1;
            module.openModule(text,property,flags,editor);
            if(text is null || editor is null || !ahCompactTableV108(text.self,"txtedt.dll",0x46dc4,11)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[text.self]+10*4],"txtedt.dll",0x2dcf0)
                || !ahCompactTableV108(editor.self,"txtedui.dll",0x10db3c,22))break;
            array<uint> slots={0,3,17,18,19,21},rvas={0xe4680,0xa2020,0xa2850,0xa29c0,0xa2ae0,0xa2bc0};valid=true;
            for(uint n=0;n<slots.length;n++)if(!ahCompactAddressV108(mem::int_ptr[mem::int_ptr[editor.self]+slots[n]*4],"txtedui.dll",rvas[n]))valid=false;
            if(!valid)break;
            editor.getITextManager(linked);@document=text.unk;
            if(linked is null || linked.self!=text.self || document is null
                || !ahCompactTableV108(document.self,"txtedui.dll",0x109978,23)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[document.self]+8*4],"txtedui.dll",0x74450)
                || !ahCompactAddressV108(mem::int_ptr[mem::int_ptr[document.self]+22*4],"txtedui.dll",0x7d7d0)
                || mem::addressOf(linked.getTextManager())!=mem::addressOf(text.getTextManager()))break;
            // The published getter may create a dirty-state cache. Preserve
            // observations only after this explicitly counted permitted warmup.
            document.isModified();mem::dword[envelope+600]=mem::dword[envelope+600]+1;
            identity={uint(ui.self),uint(root.self),uint(object.self),uint(helper.self),uint(text.self),
                uint(editor.self),uint(document.self),uint(mem::addressOf(text.getTextManager()))};
            // Context READ does not query repository ownership. UNKNOWN is
            // distinct from FREE and cannot provide an EDIT actor/version latch.
            if(opcode==1 && policy==0){
                mem::dword[envelope+560]=3;mem::dword[envelope+564]=0;mem::dword[envelope+568]=0;
                for(uint n=0;n<32;n++)mem::byte[envelope+652+n]=0;
                mem::dword[envelope+684]=0;mem::dword[envelope+688]=0;
            }
            uint phases=opcode==2 && !applyEdit?3:2,completed=0;
            for(uint phase=0;phase<phases;phase++){
                reason=5;
                if(!ahPipeScopeAlive() || ahStatusUi !is ui)break;
                @freshRoot=ui.getMDCont();@freshObject=root.objById(targetId);@bound=helper.getMDObj();
                if(freshRoot is null || freshObject is null || bound is null || !ahCatalogSameV218(freshRoot.unk,root.unk)
                    || !ahCatalogSameV218(freshObject.unk,object.unk) || !ahCatalogSameV218(bound.unk,object.unk))break;
                @linked=null;editor.getITextManager(linked);
                if(linked is null || linked.self!=text.self || uint(mem::addressOf(linked.getTextManager()))!=identity[7])break;
                // Separate exact-fixture statistic, using the existing slot40
                // decoder ABI. The historical two-CM whitelist is not widened.
                if((opcode==1 && policy==2 && phase==0) || (opcode==2 && (phase==2 || (applyEdit && phase==1)))){
                    reason=7;
                    __LIVE_EDITOR_PROVIDER_RESOLVE__
                    if(!epReady){reason=100+epReason;break;}int_ptr provider=epProvider;Guid actor=epActor;
                    string actorHex="";for(uint n=0;n<16;n++){
                        uint b=mem::byte[envelope+476+n];actorHex+=digits.substr(b>>4,1)+digits.substr(b&15,1);
                    }
                    Guid expectedActor("{"+actorHex.substr(0,8)+"-"+actorHex.substr(8,4)+"-"+actorHex.substr(12,4)+"-"+actorHex.substr(16,4)+"-"+actorHex.substr(20,12)+"}");
                    if(opcode==2 && actor!=expectedActor)break;
                    int_ptr address=mem::int_ptr[mem::int_ptr[provider]+40*4];
                    if(ahRepositoryStatisticRead is null)initFuncDefFromAddress(address,@ahRepositoryStatisticRead,asCALL_STDCALL);
                    @statistic=ahRepositoryStatisticRead;
                    if(statistic is null || statistic !is ahRepositoryStatisticRead)break;
                    array<uint8> bytes(64,0xa5);for(uint n=16;n<48;n++)bytes[n]=0;
                    int_ptr output=mem::addressOf(bytes[16]);mem::dword[output]=0xffffffff;
                    mem::dword[envelope+684]=mem::dword[envelope+684]+1;
                    statistic(provider,output,targetId.self);@statistic=null;
                    __LIVE_EDITOR_PROVIDER_AFTER_RPC__
                    if(!epReady){reason=200+epReason;break;}
                    valid=true;for(uint n=0;n<16;n++)if(bytes[n]!=0xa5 || bytes[n+48]!=0xa5)valid=false;
                    if(!valid || bytes[20]>1)break;
                    int observed=int(mem::dword[output]);Guid owner;mem::memcpy(owner.self,output+8,16);
                    bool revised=bytes[20]==1;
                    if(observed<0 || revised==(owner==IID_NULL))break;
                    if(opcode==2 && (owner==IID_NULL || owner!=actor || !revised || uint(observed)!=mem::dword[envelope+448]))break;
                    string actorWire=ahCatalogIdV218(actor).replaced("-",""),ownerWire=ahCatalogIdV218(owner).replaced("-","");
                    if(actorWire.length!=32 || ownerWire.length!=32)break;
                    valid=true;for(uint n=0;n<16;n++){
                        uint a=0,b=0;for(uint k=0;k<2;k++){
                            uint x=actorWire[n*2+k],y=ownerWire[n*2+k];
                            if(!((x>=48 && x<=57)||(x>=97 && x<=102)) || !((y>=48 && y<=57)||(y>=97 && y<=102))){valid=false;break;}
                            a=(a<<4)|(x<=57?x-48:x-87);b=(b<<4)|(y<=57?y-48:y-87);
                        }
                        if(!valid)break;mem::byte[envelope+652+n]=uint8(a);mem::byte[envelope+668+n]=uint8(b);
                    }
                    if(!valid)break;
                    version=uint(observed);mem::dword[envelope+560]=revised?(owner==actor?1:2):0;
                    mem::dword[envelope+564]=version;mem::dword[envelope+568]=revised && owner==actor?1:0;
                    mem::dword[envelope+688]=1;
                }
                // The ownership RPC may call native callbacks. Refresh the
                // complete identities after it, never rely on old handles alone.
                if(!ahPipeScopeAlive() || ahStatusUi !is ui)break;
                @freshRoot=ui.getMDCont();@freshObject=root.objById(targetId);@bound=helper.getMDObj();
                if(freshRoot is null || freshObject is null || bound is null || !ahCatalogSameV218(freshRoot.unk,root.unk)
                    || !ahCatalogSameV218(freshObject.unk,object.unk) || !ahCatalogSameV218(bound.unk,object.unk))break;
                @linked=null;editor.getITextManager(linked);
                if(linked is null || linked.self!=text.self || uint(mem::addressOf(linked.getTextManager()))!=identity[7])break;
                if(opcode==2 && phase==2){
                    reason=13;mem::dword[envelope+524]=mem::dword[envelope+524]+1;
                    if(!text.getTextManager().save(restored) || restored.length>131072 || restored.str!=baseline.str)break;
                    editor.setSelection(start,stop,caret==start,false);selectionTouched=false;
                    TextPosition a,b,c;editor.getCaretPosition(c,false);editor.getSelection(a,b,false);
                    if(a!=start || b!=stop || c!=caret)break;
                }
                int_ptr tmPacket=envelope+1056+phase*96;
                for(uint n=0;n<24;n++)mem::dword[tmPacket+n*4]=0;
                mem::dword[tmPacket]=0x31534d54;mem::dword[tmPacket+4]=3;mem::dword[tmPacket+8]=96;
                for(uint n=0;n<32;n++)mem::byte[tmPacket+64+n]=uint8(nonce[n]);mem::dword[tmPacket+60]=0xa17e5afe;
                uint nativeState=__LIVE_BOUND_STATE__(identity[7],tmPacket);
                if(nativeState!=1 || mem::dword[tmPacket+12]!=1 || mem::dword[tmPacket+16]!=0
                    || mem::dword[tmPacket]!=0x31534d54 || mem::dword[tmPacket+4]!=3 || mem::dword[tmPacket+8]!=96
                    || mem::dword[tmPacket+20]>1 || mem::dword[tmPacket+24]>1
                    || (mem::dword[tmPacket+24]==0 && mem::dword[tmPacket+28]!=0xffffffff)
                    || mem::dword[tmPacket+32]!=1 || mem::dword[tmPacket+36]!=1 || mem::dword[tmPacket+40]!=1
                    || mem::dword[tmPacket+44]!=1 || mem::dword[tmPacket+48]!=2
                    || mem::dword[tmPacket+52]!=__LIVE_EDITOR_GUI_THREAD_ID__ || mem::dword[tmPacket+56]!=0x31534d54
                    || mem::dword[tmPacket+60]!=0xa17e5afe)break;
                valid=true;for(uint n=0;n<32;n++)if(mem::byte[tmPacket+64+n]!=uint8(nonce[n]))valid=false;
                if(!valid)break;
                TextPosition observedCaret,observedStart,observedStop;editor.getCaretPosition(observedCaret,false);editor.getSelection(observedStart,observedStop,false);
                array<uint> state=identity;
                array<uint> rest={root.isModified()?1:0,ui.isModified()?1:0,object.isModified()?1:0,
                    document.isModified()?1:0,document.getReadOnly()?1:0,uint(observedCaret.line),uint(observedCaret.col),
                    uint(observedStart.line),uint(observedStart.col),uint(observedStop.line),uint(observedStop.col),
                    mem::dword[tmPacket+20],mem::dword[tmPacket+24],mem::dword[tmPacket+28]};
                for(uint n=0;n<rest.length;n++)state.insertLast(rest[n]);
                for(uint n=0;n<22;n++)mem::dword[envelope+768+phase*88+n*4]=state[n];
                if(phase==0){before=state;caret=observedCaret;start=observedStart;stop=observedStop;}
                if(opcode==1 && phase==1){after=state;completed++;break;}
                if(opcode==2 && phase==2){
                    mem::dword[envelope+544]=uint(restored.cstr);mem::dword[envelope+548]=restored.length;mem::dword[envelope+552]=2;
                    if(__LIVE_BOUND_CAPTURE__(envelope,sequence)!=1)break;
                    after=state;completed++;continue;
                }
                v8string current;mem::dword[envelope+524]=mem::dword[envelope+524]+1;
                if(!text.getTextManager().save(current) || current.length>131072)break;
                mem::dword[envelope+544]=uint(current.cstr);mem::dword[envelope+548]=current.length;mem::dword[envelope+552]=phase;
                if(__LIVE_BOUND_CAPTURE__(envelope,sequence)!=1)break;
                if(phase==0){
                    baseline=current;
                    v8string independent;mem::dword[envelope+524]=mem::dword[envelope+524]+1;
                    if(!text.getTextManager().save(independent) || independent.str!=baseline.str || independent.self==baseline.self
                        || (baseline.length!=0 && independent.cstr==baseline.cstr))break;
                    mem::dword[envelope+596]=1;
                    if(opcode==1){completed++;continue;}
                    // VERIFY needs empty history. APPLY observes existing Redo;
                    // only the stock setter may invalidate it, never a raw clear.
                    // The 22-value snapshot contains no Redo claim.
                    if(state[12]!=0 || (!applyEdit && (state[11]!=0 || state[19]!=0 || state[20]!=0 || state[21]!=0xffffffff
                        || mem::dword[envelope+620]!=0 || mem::dword[envelope+624]!=0xffffffff))
                        || mem::dword[envelope+628]!=1 || mem::dword[envelope+632]!=1 || (caret!=start && caret!=stop))break;
                    if(applyEdit){
                        uint rangeStart=mem::dword[envelope+496],rangeStop=mem::dword[envelope+500],replacementUnits=mem::dword[envelope+504];
                        if(mem::dword[envelope+492]!=0x31474e52 || rangeStart>rangeStop || rangeStop>baseline.length
                            || replacementUnits>131072 || rangeStart+replacementUnits>mem::dword[envelope+456])break;
                        // Native Prepare already proved the exact UTF16 splice.
                        // Map only its immutable offsets, using logical coordinates.
                        array<uint> offsets={rangeStart,rangeStop},rows(2),columns(2);
                        for(uint k=0;k<2;k++){
                            uint row=1,column=1,n=0;
                            while(n<offsets[k]){
                                uint ch=mem::word[baseline.cstr+n*2];
                                if(ch==13){n+=n+1<offsets[k] && mem::word[baseline.cstr+(n+1)*2]==10?2:1;row++;column=1;}
                                else if(ch==10){n++;row++;column=1;}else{n++;column++;}
                            }
                            rows[k]=row;columns[k]=column;
                        }
                        if(rows[0]!=rows[1])break;
                        applyFirst.line=rows[0];applyFirst.col=columns[0];applyLast.line=rows[1];applyLast.col=columns[1];
                        v8string rangeReplacement(mem::dword[envelope+464]+rangeStart*2,replacementUnits);replacement=rangeReplacement;
                        editor.setSelection(applyFirst,applyLast,false,false);selectionTouched=true;
                        TextPosition selectedStart,selectedStop;editor.getSelection(selectedStart,selectedStop,false);
                        v8string selected;editor.getSelectionText(selected);
                        if(selectedStart!=applyFirst || selectedStop!=applyLast || selected.length!=rangeStop-rangeStart)break;
                        valid=true;for(uint n=0;n<selected.length;n++)if(mem::word[selected.cstr+n*2]!=mem::word[baseline.cstr+(rangeStart+n)*2])valid=false;
                        if(!valid)break;
                    }else{
                        TextPosition first(1,1);editor.setSelection(first,first,false,false);selectionTouched=true;
                        v8string selected;editor.getSelectionText(selected);if(selected.length!=0)break;
                    }
                    mem::dword[envelope+572]=1;
                }else if(phase==1){
                    readback=current;
                    if(!applyEdit && (current.str!="// AH1C OWNED EDITOR PROBE "+operation+" "+baseline.str || state[20]!=1 || state[21]!=4))break;
                    if(applyEdit){
                        if(current.length!=mem::dword[envelope+456])break;
                        valid=true;for(uint n=0;n<current.length;n++)if(mem::word[current.cstr+n*2]!=mem::word[mem::dword[envelope+464]+n*2])valid=false;
                        if(!valid)break;
                    }
                    // Stock published setter creates its own EditAction(kind4,
                    // null external). No explicit Begin/Close action is nested.
                    // Native transitive message pumping is not claimed proven.
                }
                // EDIT last-check: all preliminary source reads and selection
                // preparation precede this phase's sole ownership RPC.
                // Separate exact-fixture statistic, using the existing slot40
                // decoder ABI. The historical two-CM whitelist is not widened.
                if(opcode==2 && (!applyEdit || phase==0)){
                    reason=7;
                    __LIVE_EDITOR_PROVIDER_RESOLVE__
                    if(!epReady){reason=100+epReason;break;}int_ptr provider=epProvider;Guid actor=epActor;
                    string actorHex="";for(uint n=0;n<16;n++){
                        uint b=mem::byte[envelope+476+n];actorHex+=digits.substr(b>>4,1)+digits.substr(b&15,1);
                    }
                    Guid expectedActor("{"+actorHex.substr(0,8)+"-"+actorHex.substr(8,4)+"-"+actorHex.substr(12,4)+"-"+actorHex.substr(16,4)+"-"+actorHex.substr(20,12)+"}");
                    if(actor!=expectedActor)break;
                    int_ptr address=mem::int_ptr[mem::int_ptr[provider]+40*4];
                    if(ahRepositoryStatisticRead is null)initFuncDefFromAddress(address,@ahRepositoryStatisticRead,asCALL_STDCALL);
                    @statistic=ahRepositoryStatisticRead;
                    if(statistic is null || statistic !is ahRepositoryStatisticRead)break;
                    array<uint8> bytes(64,0xa5);for(uint n=16;n<48;n++)bytes[n]=0;
                    int_ptr output=mem::addressOf(bytes[16]);mem::dword[output]=0xffffffff;
                    mem::dword[envelope+684]=mem::dword[envelope+684]+1;
                    statistic(provider,output,targetId.self);@statistic=null;
                    __LIVE_EDITOR_PROVIDER_AFTER_RPC__
                    if(!epReady){reason=200+epReason;break;}
                    valid=true;for(uint n=0;n<16;n++)if(bytes[n]!=0xa5 || bytes[n+48]!=0xa5)valid=false;
                    if(!valid || bytes[20]>1)break;
                    int observed=int(mem::dword[output]);Guid owner;mem::memcpy(owner.self,output+8,16);
                    bool revised=bytes[20]==1;
                    if(observed<0 || revised==(owner==IID_NULL))break;
                    if(opcode==2 && (owner==IID_NULL || owner!=actor || !revised || uint(observed)!=mem::dword[envelope+448]))break;
                    string actorWire=ahCatalogIdV218(actor).replaced("-",""),ownerWire=ahCatalogIdV218(owner).replaced("-","");
                    if(actorWire.length!=32 || ownerWire.length!=32)break;
                    valid=true;for(uint n=0;n<16;n++){
                        uint a=0,b=0;for(uint k=0;k<2;k++){
                            uint x=actorWire[n*2+k],y=ownerWire[n*2+k];
                            if(!((x>=48 && x<=57)||(x>=97 && x<=102)) || !((y>=48 && y<=57)||(y>=97 && y<=102))){valid=false;break;}
                            a=(a<<4)|(x<=57?x-48:x-87);b=(b<<4)|(y<=57?y-48:y-87);
                        }
                        if(!valid)break;mem::byte[envelope+652+n]=uint8(a);mem::byte[envelope+668+n]=uint8(b);
                    }
                    if(!valid)break;
                    version=uint(observed);mem::dword[envelope+560]=revised?(owner==actor?1:2):0;
                    mem::dword[envelope+564]=version;mem::dword[envelope+568]=revised && owner==actor?1:0;
                    mem::dword[envelope+688]=1;
                }
                // The ownership RPC may call native callbacks. Refresh the
                // complete identities after it, never rely on old handles alone.
                if(!ahPipeScopeAlive() || ahStatusUi !is ui)break;
                @freshRoot=ui.getMDCont();@freshObject=root.objById(targetId);@bound=helper.getMDObj();
                if(freshRoot is null || freshObject is null || bound is null || !ahCatalogSameV218(freshRoot.unk,root.unk)
                    || !ahCatalogSameV218(freshObject.unk,object.unk) || !ahCatalogSameV218(bound.unk,object.unk))break;
                @linked=null;editor.getITextManager(linked);
                if(linked is null || linked.self!=text.self || uint(mem::addressOf(linked.getTextManager()))!=identity[7])break;
                if(phase==0){
                    v8string fresh;mem::dword[envelope+524]=mem::dword[envelope+524]+1;
                    // APPLY may extend an already dirty buffer. Preserve its
                    // exact observed dirty state; VERIFY still requires clean.
                    if(!text.getTextManager().save(fresh) || fresh.str!=baseline.str || document.getReadOnly()
                        || document.isModified()!=(applyEdit?(before[11]!=0):false)
                        || !ahPipeScopeAlive() || ahStatusUi !is ui || !ahCatalogSameV218(ui.getMDCont().unk,root.unk)
                        || !ahCatalogSameV218(root.objById(targetId).unk,object.unk) || !ahCatalogSameV218(helper.getMDObj().unk,object.unk))break;
                    if(applyEdit){
                        TextPosition selectedStart,selectedStop;editor.getSelection(selectedStart,selectedStop,false);
                        v8string selected;editor.getSelectionText(selected);
                        if(selectedStart!=applyFirst || selectedStop!=applyLast || selected.length!=mem::dword[envelope+500]-mem::dword[envelope+496])break;
                        valid=true;for(uint n=0;n<selected.length;n++)if(mem::word[selected.cstr+n*2]!=mem::word[baseline.cstr+(mem::dword[envelope+496]+n)*2])valid=false;
                        if(!valid)break;
                    }
                    mem::dword[envelope+576]=1;mem::dword[envelope+608]=1;
                    reason=8;if(__LIVE_BOUND_COMMIT__(envelope,sequence)!=1)break;
                    writeArmed=true;
                    // Both replacements are newline-free: the stock setter's
                    // EOL conversion cannot normalize untouched source bytes.
                    v8string marker="// AH1C OWNED EDITOR PROBE "+operation+" ";
                    reason=9;mem::dword[envelope+528]=mem::dword[envelope+528]+1;
                    if(applyEdit)editor.setSelectionText(replacement);else editor.setSelectionText(marker);
                    mem::dword[envelope+532]=mem::dword[envelope+532]+1;
                }else if(phase==1){
                    v8string witness;mem::dword[envelope+524]=mem::dword[envelope+524]+1;
                    if(!text.getTextManager().save(witness) || witness.str!=readback.str
                        || (applyEdit && (witness.self==readback.self || (witness.length!=0 && witness.cstr==readback.cstr))) || document.getReadOnly()
                        || !ahPipeScopeAlive() || ahStatusUi !is ui || !ahCatalogSameV218(ui.getMDCont().unk,root.unk)
                        || !ahCatalogSameV218(root.objById(targetId).unk,object.unk) || !ahCatalogSameV218(helper.getMDObj().unk,object.unk))break;
                    if(applyEdit){
                        after=state;for(uint n=0;n<22;n++)mem::dword[envelope+944+n*4]=state[n];
                        completed++;continue;
                    }
                    mem::dword[envelope+616]=1;mem::dword[envelope+608]=2;
                    reason=11;if(__LIVE_BOUND_COMMIT__(envelope,sequence)!=1)break;
                    TextPosition undoStart,undoStop;IUnknown@ external;
                    reason=12;mem::dword[envelope+536]=mem::dword[envelope+536]+1;
                    bool undone=text.getTextManager().ahOwnedActionUndoV63(undoStart,undoStop,external,0);
                    if(undone)mem::dword[envelope+540]=mem::dword[envelope+540]+1;
                    mem::dword[envelope+612]=external is null?0:1;
                    if(!undone || external !is null)break;
                }
                completed++;
            }
            if(completed!=phases)break;
            verified=before.length==22 && after.length==22;
            // Own Undo necessarily leaves our own Redo(kind4). The text/caret/
            // selected 22-state comparison is not full history restoration.
            for(uint n=0;verified && n<22;n++)if(before[n]!=after[n])verified=false;
            // The global UI dirty latch can remain set after our own Undo.
            // Report that exact failure separately; do not clear the UI flag
            // or accept any other state difference as restored verification.
            restoredStateMismatch=opcode==2 && !applyEdit && before.length==22 && after.length==22 && before[9]==0 && after[9]==1;
            for(uint n=0;restoredStateMismatch && n<22;n++)if(n!=9 && before[n]!=after[n])restoredStateMismatch=false;
            mem::dword[envelope+604]=verified?1:0;reason=verified?0:14;
            if(applyEdit){verified=before.length==22 && after.length==22;reason=verified?0:14;}
        }while(false);
        // A pre-setter refusal may restore selection. Unknown writes never
        // trigger a compensating setter or a blind/repeated Undo.
        if(owned && !writeArmed && selectionTouched && mem::dword[envelope+528]==0 && editor !is null)editor.setSelection(start,stop,caret==start,false);
        @statistic=null;
        @rsReader=null;@rsFile=null;@rsFilePin=null;@rsObject=null;@rsRoot=null;
        __LIVE_EDITOR_PROVIDER_CLEANUP__
        @document=null;@editor=null;@linked=null;@text=null;@module=null;@helper=null;@service=null;
        @bound=null;@freshObject=null;@object=null;@freshRoot=null;@root=null;@ui=null;
    }
    // Cleanup can invoke native Release; include its caught exception too.
    exception=catcher.hasException;
    cleared=document is null && editor is null && linked is null && text is null && module is null && helper is null
        && service is null && bound is null && freshObject is null && object is null && freshRoot is null && root is null && ui is null
        && rsReader is null && rsFile is null && rsFilePin is null && rsObject is null && rsRoot is null
        && statistic is null && epDirect is null && epCore is null && epShell is null && epManagerRoot is null
        && epFreshRoot is null && epManager is null && !epReady && epProvider==0 && epController==0 && epActor==IID_NULL && epWitness.length==0;
    // Validation is one-use. The carrier retains this packet through callback
    // return; only COMMIT revalidates the phase and owned lifetime after entry.
    if(owned){
        bool same=true;for(uint n=0;n<512;n++)if(mem::byte[envelope+n]!=mem::byte[header.bytes+n])same=false;
        mem::dword[envelope+588]=cleared?1:0;mem::dword[envelope+592]=exception?1:0;
        mem::dword[envelope+516]=exception?15:reason;
        bool repositoryUnknown=false;
        if(opcode==4 && rsBackingReady){
            __LIVE_EDITOR_REPOSITORY_KNOWN_CLEANUP__
            repositoryUnknown=exception || rsException || rsRetainRequired || mem::dword[rsLedger+12]!=0
                || mem::dword[rsOutput]!=0 || mem::dword[rsLedger+48]==1 || mem::dword[rsLedger+48]==2;
            mem::dword[rsLedger+64]=cleared && !repositoryUnknown?1:0;
            mem::dword[rsLedger+68]=exception || rsException?1:0;mem::dword[rsLedger+120]=exception?15:reason;
            if(!verified){mem::dword[rsLedger+52]=0;mem::dword[rsLedger+56]=0;}
        }
        if(verified && !exception && cleared && same){
            if(applyEdit)mem::dword[envelope+512]=5;
            mem::dword[envelope+608]=3;__LIVE_BOUND_COMMIT__(envelope,sequence);}
        else if(restoredStateMismatch && !exception && cleared && same){
            mem::dword[envelope+512]=4;
            mem::dword[envelope+608]=3;__LIVE_BOUND_COMMIT__(envelope,sequence);
        }
        else{
            mem::dword[envelope+512]=repositoryUnknown || writeArmed || mem::dword[envelope+528]>0?3:2;
            if(mem::dword[envelope+512]==2 && !exception && cleared && same){
                mem::dword[envelope+608]=3;__LIVE_BOUND_COMMIT__(envelope,sequence);
            }
        }
    }
}
