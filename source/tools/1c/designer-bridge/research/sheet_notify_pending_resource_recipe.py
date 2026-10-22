"""Read stored resource bytes while own editors are pending; no live snapshot."""
from pathlib import Path
import hashlib

HERE=Path(__file__).resolve().parent
BASE_SHA='7c45c44839e5938288c0c39da31acebd079034d098a4ccd1b29df1017dfee24b'


def derive_source():
    """Return fixed SHA-only resource observer with the original264 decoders.

    This explicitly does not verify persisted state or compare a live template.
    It reads the configuration manager resource view without saving any editor.
    """
    raw=(HERE/'NativeSavedResourceFingerprintV264.as').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=BASE_SHA:raise ValueError('PENDING_RESOURCES_BASE_PIN')
    original=raw.decode();text=original;journal=[]
    def edit(old,new,count=1):
        nonlocal text
        if text.count(old)!=count or old==new:raise ValueError('PENDING_RESOURCES_ANCHOR')
        text=text.replace(old,new);journal.append((old,new,count))
    edit('void ahSavedResourceFingerprintV264() {','void ahPendingStoredResources() {')
    edit('bool verified=false,storageKnown=false;', 'bool verified=false,storageKnown=false,pendingUiDirty=false;')
    edit('IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();reason="ROOT";',
         'IConfigMngrUI@ ui=ahStatusUi;IMDContainer@ root=ui.getMDCont();reason="ROOT";pendingUiDirty=ui.isModified();')
    # Remove the entire detached-template vs LIVE comparison. No helper/extProp,
    # live document getter or snapshot belongs in this stored-resource probe.
    start=text.index('        }else{\n            reason="TEMPLATE_COLD_HELPER";')
    stop=text.index('\n                    reason="SAVED_RESOURCE_CHANGED";',start)
    edit(text[start:stop],'        } // Stored resources only: no live template access.\n')
    count=text.count('root.isModified() || ui.isModified()')
    if count!=6:raise ValueError('PENDING_RESOURCES_DIRTY_GUARD_COUNT')
    edit('root.isModified() || ui.isModified()',
         'root.isModified() || ui.isModified()!=pendingUiDirty',count)
    edit('resourcesRead!=3 || moduleDecodedPasses!=4 || coldLoads!=2 || coldSnapshots!=2 || templateComparisons!=7500',
         'resourcesRead!=3 || moduleDecodedPasses!=4 || coldLoads!=0 || coldSnapshots!=0 || templateComparisons!=0')
    edit('SAVED_RESOURCE_FINGERPRINTED','STORED_RESOURCES_OBSERVED')
    restored=text
    for old,new,count in reversed(journal):
        if restored.count(new)!=count:raise ValueError('PENDING_RESOURCES_REVERSE_ANCHOR')
        restored=restored.replace(new,old)
    if restored!=original:raise ValueError('PENDING_RESOURCES_WHOLE_REVERSE')
    if 'ahSheetSnapshotV231(' in text or 'helper.extProp(' in text or 'liveDocument.' in text:
        raise ValueError('PENDING_RESOURCES_LIVE_EDITOR_FORBIDDEN')
    return text.encode()
