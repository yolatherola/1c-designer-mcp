"""Pure Save3 TOOL profile for verified sheet-notify + two-module writers.

Does not admit, stage or execute a Save. Source and packet originals remain
owned by the separate writer route until actual saved-resource verification.
"""
from pathlib import Path
import hashlib
import re

HERE=Path(__file__).resolve().parent
SOURCE_SHA='3776472cdbae4f0da7fbef69af07957d357624350677bd4cb69c79eb31ac1045'


def need(ok,code):
    if not ok:raise ValueError('SHEET_NOTIFY_SAVE_'+code)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def derive_source():
    """Return one fixed symbolic TOOL function; no caller code or addresses."""
    raw=(HERE/'NativeRunnerSaveOwnStand.as').read_bytes();need(sha(raw)==SOURCE_SHA,'SOURCE_PIN')
    original=raw.decode('utf-8-sig');text=original;journal=[]
    def edit(old,new):
        nonlocal text
        need(text.count(old)==1 and old!=new,'EXACT_ANCHOR')
        text=text.replace(old,new,1);journal.append((old,new))
    edit('// First application only: private46756 stand, recorded clean history, fixed3.',
         '// Fixed3 followup only: exact writer-linked stand; notification-aware template.')
    edit('void ahRunnerSaveOwnStand() {','void ahRunnerSaveSheetNotify() {')
    edit('ahGetCurrentProcessId()!=46756 || ahFrameOwnerPidV211!=46756',
         'ahGetCurrentProcessId()!=__SAVE_NATIVE_PID__ || ahFrameOwnerPidV211!=__SAVE_NATIVE_PID__')
    edit('ahGetCurrentThreadId()!=40236 || ahFrameOwnerTidV211!=40236',
         'ahGetCurrentThreadId()!=__SAVE_GUI_THREAD__ || ahFrameOwnerTidV211!=__SAVE_GUI_THREAD__')
    edit('if(object is null || !object.isModified() || object.mdParentLink is null)break;',
         'if(object is null || (i!=0 && !object.isModified()) || object.mdParentLink is null)break;')
    edit('if(!walkOkay || dirtyOwnMask!=7 || unknownDirty!=0)break;walkComplete=true;',
         '// Template editor pending is observed before Save flush; both common modules must already be MD-dirty.\n'
         '            if(!walkOkay || (dirtyOwnMask!=6 && dirtyOwnMask!=7) || unknownDirty!=0)break;walkComplete=true;')
    edit('|| !ownObjects[i].isModified() || !ownDocuments[i].isModified() || ownDocuments[i].getReadOnly())same=false;',
         '|| (i!=0 && !ownObjects[i].isModified()) || !ownDocuments[i].isModified() || ownDocuments[i].getReadOnly())same=false;')
    start=text.index('            ITopLevelFrame@ frame=ahObservedMainFrameV211;ITopLevelFrame@ core;')
    stop=text.index('            if(!abi)break;',start)+len('            if(!abi)break;')
    old=text[start:stop]
    replacement='''            ITopLevelFrame@ frame=ahObservedMainFrameV211;ITopLevelFrame@ core;
            if(frame is null || frame.frameType()!=eTLFT_Main)@frame=ahFindOwnMainFrame();
            if(frame is null || frame.frameType()!=eTLFT_Main)break;frame.getCoreTopLevelFrame(core);
            if(core is null)break;
            bool legacyLayout=ahAccessLegacyLayoutV232(frame,core);
            if(!legacyLayout && !ahFrameReceiverLayoutV211(frame,core))break;
            ICommandReceiver@ receiver;
            if(legacyLayout)core.commandReceiver(receiver);else frame.commandReceiver(receiver);
            if(legacyLayout){if(!ahAccessLegacyReceiverV232(receiver))break;}
            else {
                if(receiver is null || !ahCompactTableV108(receiver.self,"frame.dll",0xa6a4f8,6))break;
                array<uint> slots={0x82c7a0,0x82c810,0x82ca00};bool abi=true;
                for(uint i=0;i<3;i++)if(!ahCompactAddressV108(mem::int_ptr[mem::int_ptr[receiver.self]+(i+3)*4],"frame.dll",slots[i]))abi=false;
                if(!abi)break;
            }'''
    edit(old,replacement)
    edit('string proof="{\\"kind\\":\\"OWN_STAND_SAVE3_RECEIPT\\",',
         'string proof="{\\"compositionProfile\\":\\"SHEET_NOTIFY_EDITOR_PENDING\\",\\"kind\\":\\"OWN_STAND_SAVE3_RECEIPT\\",')
    reversed_text=text
    for old,new in reversed(journal):
        need(reversed_text.count(new)==1,'REVERSE_ANCHOR');reversed_text=reversed_text.replace(new,old,1)
    need(reversed_text==original and len(text.encode())<32768,'WHOLE_REVERSE')
    need(text.count('receiver.transmitCommand(Command(command,0))')==1,'ONE_STOCK_SAVE')
    need('setModified(' not in text and 'setPropVal(' not in text,'NO_FORCED_FLAGS_OR_CONTENT')
    return text.encode('utf-8')


def derivation_manifest():
    raw=derive_source()
    return dict(kind='SHEET_NOTIFY_SAVE_TOOL_PROFILE',sourceSha256=SOURCE_SHA,derivedSha256=sha(raw),bytes=len(raw),
        entry='ahRunnerSaveSheetNotify',templateEditorPendingSupported=True,commonModuleDirtyGuardsUnchanged=True,
        actualLegacyReceiverObserved=True,wholeReverseVerified=True,configurationSaveAuthorized=False,
        databaseUpdateAuthorized=False,repositoryMutationAuthorized=False,executionImplemented=False,
        placeholders=sorted(set(re.findall(r'__[A-Z][A-Z0-9_]+__',raw.decode()))))
