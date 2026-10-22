"""Pinned DB-root resource reads followed by a separate full native comparison."""
from pathlib import Path
import hashlib
from update_preview_source import _body

HERE=Path(__file__).resolve().parent
PINS={
 'NativeDatabaseSavedResourcesFastGate.as':'4ba489acccc9de4a0c60780e14100e79e39fdc078924cd0ff32483d5ff26ed1c',
 'NativeOwnedHeadlessComparisonUtf8.as':'489d99eb6b0b1153f78eca2480fc0d429ea6b6c5d219ad38e7fd41d2b822d18d',
}


def compose_source():
    parts={}
    for name,pin in PINS.items():
        raw=(HERE/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('POST_UPDATE_SOURCE_PIN '+name)
        parts[name]=raw.decode('utf-8').replace('\r','')
    fast=_body(parts['NativeDatabaseSavedResourcesFastGate.as'],'bool ahDatabaseSavedResourcesFastGate() {')
    old='return verified && proofWritten && !output.hasException;'
    if fast.count(old)!=1:raise ValueError('POST_UPDATE_FAST_RETURN')
    fast=fast.replace(old,'postResourcesVerified=verified && proofWritten && !output.hasException;',1)
    compare=_body(parts['NativeOwnedHeadlessComparisonUtf8.as'],'void ahOwnedHeadlessComparison() {')
    return ('// DB readback only; no commands, setters, save or update.\n'
        +'void ahPostUpdateReadback() {\n if(!__HEADLESS_SCOPE_ADMITTED__)return;\n bool postResourcesVerified=false;\n {\n'+fast+'\n }\n {\n'
        +compare+'\n }\n}\n').encode('utf-8')
