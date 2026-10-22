"""Compare both exact Document module resources; report hashes, never source."""
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from native_source_codec import decode_module_packet,normalize_editor_text

OBJECT='88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'
PROPERTIES={'a637f77f-3840-441d-a1c3-699c8c5cb7e0':'0',
            'd1b64a2c-8078-4982-8190-8f81aefda192':'2'}

def compare_modules(observed,read_bytes,expected_version,live_object):
    """Validate native scope and both contexts, then compare complete texts.

    read_bytes accepts only the six fixed local basenames selected here. Empty
    code is valid; its repository container must still decode without guessing.
    Changes to whitespace other than newline representation reject equality.
    """
    if (observed.get('status')!='MODULES_OBSERVED' or observed.get('bindingAndVersionUnchanged') is not True
        or observed.get('allPropertiesEnumerated') is not True or type(observed.get('version')) is not int
        or observed['version']!=expected_version or type(observed.get('hasModuleCalls')) is not int
        or not 2<=observed['hasModuleCalls']<=256 or observed.get('textOfModuleCalls')!=4
        or any(type(observed.get(k)) is not int or observed[k]!=0 for k in ('sourceWrites','repositoryWrites','goldSaves'))):
        raise ValueError('V48_MODULE_SCOPE_REJECTED')
    rows=observed.get('rows')
    if not isinstance(rows,list) or len(rows)!=2:raise ValueError('V48_MODULE_COUNT_REJECTED')
    results=[];seen=set()
    for row in rows:
        property_id=row.get('propertyId','').strip('{}').lower()
        if property_id not in PROPERTIES or property_id in seen:raise ValueError('V48_MODULE_PROPERTY_REJECTED')
        seen.add(property_id);suffix=PROPERTIES[property_id];repository=row.get('repository') or {}
        if (row.get('resource')!=OBJECT+'.'+suffix or type(row.get('contextCount')) is not int
            or not 1<=row['contextCount']<=16 or row.get('liveModesEqual') is not True
            or repository.get('verified') is not True or repository.get('version')!=expected_version
            or type(repository.get('fileBytes')) is not int or not 1<=repository['fileBytes']<=1048576):
            raise ValueError('V48_MODULE_RESOURCE_REJECTED')
        prefix='document-modules-v48-'+suffix+'-'
        packet=read_bytes(prefix+'repository.bin')
        if len(packet)!=repository['fileBytes']:raise ValueError('V48_MODULE_RESOURCE_LENGTH')
        texts=[read_bytes(prefix+mode+'.bsl').decode('utf-8-sig') for mode in ('false','true')]
        # Core.As/1C strings on this Windows platform count UTF-16 code units.
        if (texts[0]!=texts[1] or len(texts[0].encode('utf-16-le'))//2!=row.get('liveFalseCharacters')
            or len(texts[1].encode('utf-16-le'))//2!=row.get('liveTrueCharacters')):raise ValueError('V48_MODULE_CONTEXT_CHANGED')
        result=decode_module_packet(packet).summary(texts[0])
        if not result['normalizedLineEndingsEqual']:raise ValueError('V48_MODULE_SOURCE_CHANGED')
        if suffix=='0' and normalize_editor_text(texts[0])!=normalize_editor_text(live_object):
            raise ValueError('V48_OBJECT_EDITOR_CHANGED')
        results.append(dict(propertyId=property_id,resource=row['resource'],contextCount=row['contextCount'],
            helperElapsedUs=row.get('helperElapsedUs'),repositoryElapsedUs=repository.get('elapsedUs'),
            liveModesEqual=True,**result))
    return dict(verified=True,version=expected_version,modules=results,documentModuleTextsComplete=True,
        allPropertiesEnumerated=True,sourceWrites=0,repositoryWrites=0,goldSaves=0,
        externalChildBodiesVerified=False,persistedGoldReadbackVerified=False)
