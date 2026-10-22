"""Fixed SDK/PE prerequisite for a read-only class inventory, no dispatch."""
import hashlib
from pathlib import Path
import re
import struct
import uuid
import zipfile

from repository_pe_probe import PE

HERE=Path(__file__).resolve().parent
SOURCE=HERE.parent/'tests/NativeOwnedEmptyClassInventoryV125.as'
SOURCE_SHA='7db4a63d927e32b5e970806023f032d266a69ee74e72edc804ab271ca7ca5ab2'
SDK=HERE.parents[3]/'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40/snegopat.zip'
SDK_MEMBER='modules/snegopat/v8api/metadata.v'
SDK_SHA='d362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed'
DOC='061d872a-5787-460e-95ac-ed74ea3a3e84'
CATALOG='cf4abea6-37b2-11d4-940f-008048da11f9'
RANGES={
    'documentClassTable':(0x8c7fcc,48,'f88af22d8420f52fcd7fbdc80dd575d7c1428bccc86f0d58b3ef23f77fe26b91'),
    'documentFactory':(0x4c2410,184,'683a21ea7a8a6c504b3895918eb0c2f08e9bbd7287a0a886f96daa24e1d9558c'),
    'documentIdGetter':(0x4b7350,13,'221f1d834ec433fb37abbc19366a68e5f2b7d8672aa2381dbf1a8e6669473cfd'),
    'documentNameGetter':(0x4a3220,17,'818918d6132bb971f606701d4ff2621562c5da4a7c1f4b92b42a76cd16679253'),
    'documentClassNameGetter':(0x4c23d0,17,'71bcf4b5a51e4d7a3a79b37c2c3ec0e809e16f1c2d19c4028e6a7f80c9e1b447'),
    'documentGuid':(0x883d24,16,'72ffe5777d048568d7e4c8edf329ab65dd1ca614165d7831f060ed4f78b983cf'),
    'catalogGuidLiteral':(0x884e78,16,'d1e43922f8a72affdd00ace141bdb0c344ff50f28a76def9fcf9ba87a0d9f01e'),
}


def need(ok,code):
    if not ok:raise ValueError('V125_STATIC_'+code)


def verify_source(raw):
    need(type(raw) is bytes and 0<len(raw)<=65536,'SOURCE_REJECTED')
    try:source=raw.decode('utf8')
    except UnicodeError:raise ValueError('V125_STATIC_SOURCE_REJECTED') from None
    code=re.sub(r'//[^\n]*|/\*.*?\*/','',source,flags=re.S)
    need(not re.search(r'\b(?:createByClsid|connectConfig|setMdPropVal|queryIface|toIUnknown|initFuncDefFromAddress|'
         r'getName|getClassName|presentation|transmitCommand|setModified|saveConfig|load|deserialize|serialize|'
         r'LoadLibrary|GetService|currentProcess)\s*\(',code),'FORBIDDEN_CALL')
    need('serviceRequests++;IMDService&& service=getMDService();' in code
         and 'lookupCalls++;&&document=service.mdClass(Guid("{061D872A-5787-460E-95AC-ED74EA3A3E84}"));' in code
         and 'lookupCalls++;&&catalog=service.mdClass(Guid("{CF4ABEA6-37B2-11D4-940F-008048DA11F9}"));' in code,
         'TYPED_LOOKUP_REJECTED')
    need(code.count('service.mdClass(')==2 and code.count('getMDService(')==1
         and 'Guid id=cls.id;idReads++;idRead=true;' in code,'CALL_COUNT_REJECTED')
    # CoreAs Guid's dynamic string argument needs braces, as independently
    # measured for both IDs. Keep native Guid equality; no string fallback.
    need(code.count('idMatch=id==Guid("{"+requested+"}");')==1
         and not re.search(r'\bGuid\s*\(\s*requested\s*\)',code),'GUID_CANONICAL_FORMAT_REJECTED')
    need('array<uint> indexes={0,1,2,3,4,6,8};' in code and
         'page=ahPermissionReadable(self,4);' in code and 'tablePage=ahPermissionReadable(table,36);' in code
         and code.index('if(page){')<code.index('int_ptr table=mem::int_ptr[self]')
         and code.index('if(tablePage){')<code.index('mem::int_ptr[table+indexes[i]*4]'),'READ_BOUND_REJECTED')
    need('IMDClass&& document;IMDClass&& catalog;' in code and 'CppCatch caught(' in code
         and 'scopeExited=true;bool after=ahEmptyClassScopeV125(version,controller,provider);' in code
         and 'ahEmptyClassInventoryConsumedV125=true;' in code,'LIFETIME_REJECTED')
    need('classNameReads\\\":0' in source and 'objectFactoryCalls\\\":0' in source
         and 'nativePermit\\\":false' in source and 'writerAuthorized\\\":false' in source,'FALSE_CLAIM_REJECTED')
    return dict(sourceVerified=True,classLookupApi='published-typed-IMDService.mdClass',
                classIdApi='published-typed-IMDClass.id',newRawNativeCalls=0,nativePermit=False)


def verify_slices(read):
    need(callable(read),'READER_REJECTED');bodies={}
    for name,(rva,size,digest) in RANGES.items():
        body=read(rva,size)
        need(type(body) is bytes and len(body)==size and hashlib.sha256(body).hexdigest()==digest,'PE_SPAN_REJECTED')
        bodies[name]=body
    base=0x228b0000
    need(struct.unpack_from('<I',bodies['documentClassTable'],8*4)[0]==base+0x4c2410,'DOC_FACTORY_SLOT_REJECTED')
    need(bodies['documentFactory'][-3:]==bytes.fromhex('c2 08 00')
         and bodies['documentFactory'][0x6e:0x71]==bytes.fromhex('8d 4e 4c')
         and bodies['documentFactory'][0x78:0x7a]==bytes.fromhex('89 0f')
         and bodies['documentFactory'][0x85:0x8b]==bytes.fromhex('8b 01 51 ff 50 04'),
         'DOC_FACTORY_OUTPUT_REJECTED')
    need(bodies['documentGuid']==uuid.UUID(DOC).bytes_le
         and bodies['catalogGuidLiteral']==uuid.UUID(CATALOG).bytes_le,'GUID_REJECTED')
    return dict(documentFactoryStaticObserved=True,catalogGuidLiteralObserved=True,
                catalogClassRegistrationVerified=False,catalogFactoryAbiVerified=False,
                nativePermit=False,emptyCrudVerified=False)


def verify_static():
    raw=SOURCE.read_bytes();need(hashlib.sha256(raw).hexdigest()==SOURCE_SHA,'SOURCE_PIN_CHANGED')
    result=verify_source(raw)
    with zipfile.ZipFile(SDK) as archive:metadata=archive.read(SDK_MEMBER)
    need(hashlib.sha256(metadata).hexdigest()==SDK_SHA,'SDK_CHANGED')
    text=metadata.decode('utf-8-sig')
    service=text[text.index(':service IMDService '):text.index(':iface IConfigMngrUI ')]
    cls=text[text.index(':iface IMDClass '):text.index(':iface IConfigMngr ')]
    need('IMDClass@+ mdClass(const Guid& id)' in service and 'Guid& get_id()' in cls
         and ':iface IMDClass {12BFDDD1-36CC-11D4-940F-008048DA11F9}' in cls,'SDK_SURFACE_CHANGED')
    image=PE('basic.dll')
    result.update(verify_slices(lambda r,n:image.data[image.offset(image.base+r):image.offset(image.base+r)+n]))
    result.update(sourceSha256=SOURCE_SHA,sdkMemberSha256=SDK_SHA,publishedSdkBindingVerified=True,
                  typedLookupReusesMeasuredV82V99V107=True,scopeRuntimeVerified=False)
    return result
