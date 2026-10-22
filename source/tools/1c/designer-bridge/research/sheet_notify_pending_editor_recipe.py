"""Fixed pending-editor observation TOOL source; no dispatch or Save API."""
from pathlib import Path
import hashlib
import re

HERE=Path(__file__).resolve().parent
BASE_SHA='aefd6e34b44fcdfa67eb4a7f245797f0f11d2eda24666a0e2cb12fc3d0731e2f'


def derive_source():
    """Observe two fixed module editors, emitting flags and hashes only.

    The returned source is not permission to execute against a pending writer.
    A separate root-owned read carrier must validate its exact unsaved owner.
    """
    raw=(HERE/'NativeRunnerEditorsV247.as').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=BASE_SHA:raise ValueError('PENDING_EDITORS_BASE_PIN')
    original=raw.decode();text=original;journal=[]
    def edit(old,new):
        nonlocal text
        if text.count(old)!=1 or old==new:raise ValueError('PENDING_EDITORS_ANCHOR')
        text=text.replace(old,new,1);journal.append((old,new))
    edit('void ahRunnerEditorsV247() {','void ahPendingCommonModuleEditors() {')
    edit('    uint observed=0,commandsBefore=',
         '    bool rootDirty=false,uiDirty=false;\n    uint observed=0,commandsBefore=')
    edit('if(!ahCatalogEditableV218(root) || root.isModified() || ui.isModified()',
         'if(!ahCatalogEditableV218(root)')
    edit('            array<string> ids=',
         '            rootDirty=root.isModified();uiDirty=ui.isModified();\n            array<string> ids=')
    edit('string why="OBJECT";bool okay=false,exact=false;',
         'string why="OBJECT",sourceHash="";bool okay=false,exact=false,objectDirty=false,documentDirty=false;')
    edit('object is null || object.id!=target || object.isModified()',
         'object is null || object.id!=target')
    edit('                    v8string before;why="HELPER_SOURCE";',
         '                    objectDirty=object.isModified();\n                    v8string before;why="HELPER_SOURCE";')
    edit('                    v8string first,second,after;why="EDITOR_SOURCE";',
         '                    documentDirty=document.isModified();\n                    v8string first,second,after;why="EDITOR_SOURCE";')
    edit('okay=true;exact=first.str==before.str && after.str==before.str && !document.isModified()\n'
         '                        && !document.getReadOnly() && !object.isModified() && !root.isModified() && !ui.isModified()',
         'utf8string bytes=first.str.toUtf8();if(bytes.length==0 || bytes.length>1048576)break;\n'
         '                    MemoryBuffer memory(bytes.length);if(memory.bytes==0 || memory._length!=bytes.length)break;\n'
         '                    mem::memcpy(memory.bytes,bytes.ptr,bytes.length);sourceHash=ahTemplateRamShaV202(memory,bytes.length);\n'
         '                    okay=true;exact=first.str==before.str && after.str==before.str\n'
         '                        && document.isModified()==documentDirty && !document.getReadOnly()\n'
         '                        && object.isModified()==objectDirty && root.isModified()==rootDirty && ui.isModified()==uiDirty')
    edit('+",\\"cleanWritableEqual\\":"+exact+',
         '+",\\"objectDirty\\":"+objectDirty+",\\"documentDirty\\":"+documentDirty\n'
         '                    +",\\"sourceSha256\\":\\""+sourceHash+"\\",\\"stableWritableEqual\\":"+exact+')
    edit('if(root.isModified() || ui.isModified() || !ahPipeScopeAlive()',
         'if(root.isModified()!=rootDirty || ui.isModified()!=uiDirty || !ahPipeScopeAlive()')
    edit('(verified?"EDITORS_READY":"REFUSED")','(verified?"PENDING_EDITORS_OBSERVED":"REFUSED")')
    edit(',\\"editorsVerified\\":',
         ',\\"rootDirty\\":"+rootDirty+",\\"uiDirty\\":"+uiDirty+",\\"editorsVerified\\":')
    restored=text
    for old,new in reversed(journal):
        if restored.count(new)!=1:raise ValueError('PENDING_EDITORS_REVERSE_ANCHOR')
        restored=restored.replace(new,old,1)
    if restored!=original or len(text.encode())>16384:raise ValueError('PENDING_EDITORS_WHOLE_REVERSE')
    if set(re.findall(r'__[A-Z][A-Z0-9_]+__',text))!={'__PROOF_PATH__'}:
        raise ValueError('PENDING_EDITORS_PLACEHOLDERS')
    return text.encode()
