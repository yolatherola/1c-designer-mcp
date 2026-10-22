"""Compose only pinned technical guards; no application body or target reads."""
from pathlib import Path
import hashlib

HERE=Path(__file__).resolve().parent
PINS={
 'NativeUpdatePreview.as':'c107d81f13bdbc006180a2993b7cd9e127778498ba3ed9645ada08eb3c995e3b',
 'NativeSavedResourcesFastGate.as':'022c9e566551052c09fe5638e10e6bfba86b8cf8f94c663749daadc99bfcf6a9',
 'NativeOwnedHeadlessComparisonUtf8.as':'489d99eb6b0b1153f78eca2480fc0d429ea6b6c5d219ad38e7fd41d2b822d18d',
}


def _body(source,declaration):
    if source.count(declaration)!=1:raise ValueError('UPDATE_PREVIEW_BODY_DECLARATION')
    start=source.index(declaration)+len(declaration)
    if source[source.rfind('}')+1:].strip():raise ValueError('UPDATE_PREVIEW_BODY_TRAILER')
    return source[start:source.rfind('}')]


def compose_source():
    """Return one fixed AS function; all scope/path tokens remain unadmitted."""
    source={}
    for name,pin in PINS.items():
        raw=(HERE/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('UPDATE_PREVIEW_SOURCE_PIN '+name)
        source[name]=raw.decode('utf-8').replace('\r','')
    fast=_body(source['NativeSavedResourcesFastGate.as'],'bool ahSavedResourcesFastGate() {')
    old='return verified && proofWritten && !output.hasException;'
    if fast.count(old)!=1:raise ValueError('UPDATE_PREVIEW_FAST_RETURN')
    fast=fast.replace(old,'upvResourcesVerified=verified && proofWritten && !output.hasException;',1)
    comparison=_body(source['NativeOwnedHeadlessComparisonUtf8.as'],'void ahOwnedHeadlessComparison() {')
    if comparison.count('__PROOF_PATH__')!=1:raise ValueError('UPDATE_PREVIEW_COMPARISON_PROOF')
    comparison=comparison.replace('__PROOF_PATH__','__HEADLESS_PROOF_PATH__',1)
    comparison+='\nupvComparisonBoundaryVerified=ohcBefore && ohcAfter && ohcCleanup && !ohcUnknown && ohcReason=="NONE" && ohcAttempts==1 && ohcReturned==1;\n'
    outer=source['NativeUpdatePreview.as']
    for token,body in [('__FAST_RESOURCES_BODY__',fast),('__HEADLESS_COMPARE_BODY__',comparison)]:
        if outer.count(token)!=1:raise ValueError('UPDATE_PREVIEW_BODY_TOKEN')
        outer=outer.replace(token,body,1)
    return outer.encode('utf-8')
