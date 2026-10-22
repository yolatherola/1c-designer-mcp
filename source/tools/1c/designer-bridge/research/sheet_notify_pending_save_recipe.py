"""Fixed stock Save3 for the independently observed partial writer state."""
from pathlib import Path
import hashlib
import sheet_notify_save_recipe as base

HERE=Path(__file__).resolve().parent
BASE_RECIPE_SHA='4470f05508b92173c034c0adc919919f7938b5656c1a0c7c28fe25683e7f7864'
BASE_SOURCE_SHA='aff05f993e8d91953a523ddf4f2f4ca113acc2c7f843aabc30e6b49c55918210'


def derive_source():
    """Return one stock Save command with exact observed flags, not forced flags.

    A separate root Save grant and current SHA-only editor checks are mandatory.
    Native return/clean flags never prove the three resources were persisted.
    """
    if hashlib.sha256((HERE/'sheet_notify_save_recipe.py').read_bytes()).hexdigest()!=BASE_RECIPE_SHA:
        raise ValueError('PENDING_SAVE_BASE_RECIPE')
    raw=base.derive_source()
    if hashlib.sha256(raw).hexdigest()!=BASE_SOURCE_SHA:raise ValueError('PENDING_SAVE_BASE_SOURCE')
    original=raw.decode();text=original;journal=[]
    def edit(old,new,count=1):
        nonlocal text
        if text.count(old)!=count or old==new:raise ValueError('PENDING_SAVE_ANCHOR')
        text=text.replace(old,new);journal.append((old,new,count))
    edit('void ahRunnerSaveSheetNotify() {','void ahSaveKnownPendingEditors() {')
    edit('__WRITER_VERIFIED_ADMITTED__','__PENDING_EDITORS_VERIFIED_ADMITTED__')
    edit('writerVerified','pendingEditorsVerified',2)
    edit('|| !root.isModified() || !ui.isModified()',
         '|| root.isModified() || !ui.isModified()',2)
    edit('object is null || (i!=0 && !object.isModified()) || object.mdParentLink is null',
         'object is null || object.isModified() || object.mdParentLink is null')
    edit('if(document is null || !document.isModified() || document.getReadOnly())break;',
         'if(document is null || document.isModified()!=(i==0) || document.getReadOnly())break;')
    edit('// Template editor pending is observed before Save flush; both common modules must already be MD-dirty.\n'
         '            if(!walkOkay || (dirtyOwnMask!=6 && dirtyOwnMask!=7) || unknownDirty!=0)break;walkComplete=true;',
         '// Actual pendingREAD: metadata clean, module docs clean, template editor dirty.\n'
         '            // Reject ANY metadata change beyond that recorded state before stock Save.\n'
         '            if(!walkOkay || dirtyOwnMask!=0 || dirtyAncestors!=0 || unknownDirty!=0)break;walkComplete=true;')
    edit('|| (i!=0 && !ownObjects[i].isModified()) || !ownDocuments[i].isModified() || ownDocuments[i].getReadOnly()',
         '|| ownObjects[i].isModified() || ownDocuments[i].isModified()!=(i==0) || ownDocuments[i].getReadOnly()')
    edit('SHEET_NOTIFY_EDITOR_PENDING','KNOWN_PENDING_EDITORS_STOCK_SAVE3')
    restored=text
    for old,new,count in reversed(journal):
        if restored.count(new)!=count:raise ValueError('PENDING_SAVE_REVERSE_ANCHOR')
        restored=restored.replace(new,old)
    if restored!=original:raise ValueError('PENDING_SAVE_WHOLE_REVERSE')
    if text.count('receiver.transmitCommand(Command(command,0))')!=1 or len(text.encode())>32768:
        raise ValueError('PENDING_SAVE_ONE_STOCK_COMMAND')
    if 'setModified(' in text or 'setPropVal(' in text or 'setSelectText(' in text:
        raise ValueError('PENDING_SAVE_NO_SOURCE_OR_FLAG_WRITES')
    return text.encode()
