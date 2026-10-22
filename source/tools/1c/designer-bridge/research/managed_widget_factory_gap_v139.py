"""Concrete static negative proof for two name-linked managed runtime facades.

These nonaggregated factory results expose IValue/IContext, not persistence.
The separate existing record helper requests IPersistableObject directly.
No generic inventory, dynamic factory, widget builder or native permit exists.
"""
import hashlib
from pathlib import Path
import struct
import uuid
import zipfile

from repository_pe_probe import PE

ROOT=Path(__file__).resolve().parents[4]
ARCHIVE=ROOT/'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40/snegopat.zip'
ARCHIVE_SHA='464256ea84009d66f2d177ce92cb128479ba634da6a493a93aef579410710fde'
BASE=0x36c20000
PERSIST='45b81b41-9540-11d4-9427-008048da11f9'
SDK_SHAS={
 'modules/snegopat/v8api/document.v':'b1c12ef6a2d4ea9d655bd9057c7a605b2497bb6c22ddb9f6323efc3ad21c369e',
 'modules/snegopat/v8api/process.v':'92458b3e1a862051bf9b1d8b0cac750de5fddc62294324ca70a94820cdb1a9ef',
 'modules/snegopat/v8api/value.v':'c99b23ab9d0f81493f138f7bac66b96019ab9c69fd121202beab352772534288',
 'modules/snegopat/v8api/typeinfos.v':'ab473e3f2f3a6e0b9bbdfbf811466a4da89d376f55c68a9dd2b9f7b85d2c3922',
}
RANGES={
 'inputDescriptor':(0x75bf60,56,'e1048e5f8eb1d45794b49a6ad05a541c4be082d9001cb3c3dc9f4197aa240ac6'),
 'decorationDescriptor':(0x75b320,56,'4eb70e4f0a377adb87049b8d1c76d583ae986cd28c136b1aa13988497b4aaf9d'),
 'inputPrimary':(0x674bcc,28,'a32c7fc8e35f8859ab83a8841483dfedabe92e31a323b5de775556a45335a8ba'),
 'decorationPrimary':(0x66df00,40,'a9a1174b1cf90e574069d3266e871bb49d56e8ff3740508c779c841c34be73ee'),
 'inputMap':(0x668dd8,60,'504c157f79e97a8b8e8bebe355ce724c040eca89e4da010616ba5b720d4cf93c'),
 'decorationMap':(0x66e56c,60,'1b8f0bd7406fe43d674d91455c764b682cfc1df7b2e5f54781d3b687e18e7d21'),
 'inputQI':(0x2f57e0,26,'f86eb4b1b160900e83cdbb985b7b8ffd055e98b63343ace7ff33f610e4808c87'),
 'decorationQI':(0x33c390,26,'6fc8dd74f3f74641ea8393e7679a16012dd6ff2d79e4a1fbb66b1a79d5ae954e'),
 'inputName':(0x363d10,72,'5d9a5ea177afaa42572362655fff7e709f57db80c01e16fd451a59e4f9c862be'),
 'decorationName':(0x320d00,72,'dd648d11db9a86594953d9adb5d12b2e09854476cc585d69e9c0266436681c1a'),
 'inputCallback':(0x383d30,34,'b266c0da11ed087a270dcb286867920465a73df10542d883b00d237ef6be275f'),
 'decorationCallback':(0x33c490,34,'56007791fff048dc75fdc6bae6fc37a881d1ffaa31bfb776a8b09d892eb25a73'),
 'inputCreate':(0x3868a0,112,'aa67b8504e623fabd0b76c1b8fa6366c3171702659a8f1c3a6457a43cffad2ef'),
 'decorationCreate':(0x33d4c0,112,'514c4842c09c0f3d932b538a93e0f9f22a3128a50804d3e535246bd9d02f1e56'),
 'inputCtor':(0x383d60,92,'cc809f2b4c1bc4010f6099e2af6d1ec4cfd1cd5da44a74602c344a65f9477134'),
 'decorationCtor':(0x33c4c0,106,'d8518b09e79889fed5993753bc3f7c4b4ff9d181ec06e6eb970268d7628e6d77'),
 'inputFacadeClsid':(0x66e410,16,'5a7437157ed8c5d05108034b7788264f3896a281c6ef8962307d3e70534c264e'),
 'decorationFacadeClsid':(0x66e0b0,16,'54f972e887950c921f5d042ead46d4c274269f332f91310308d3daa8f69abbb9'),
 'commonQI':(0x8e9e0,234,'97a0568cd952f0c443fe52096f4962424e7a235baf1f8f6788ed7728941f4d7f'),
 'unknownDetector':(0x8e9b0,48,'595d8cfdd27660f94dba10cc8c33aa2404e2e86fab71223893013a9ead9de028'),
 'currentProcessRecordHelper':(0xaa190,37,'cdfd634b00d17fb6991c67b65728e4e8266c590405e83a9716fa8d539bc00ad4'),
 'recordCreateProcess':(0xac560,123,'aeab3f27139ec7cb70d7aaca2afdb3a72dc38e739ca086550d0229da8ff26b9d'),
 'inputInterfaceIID':(0x668e24,16,'ea23508da9c34a9d386279d61f2c9b85add9ee7b195517b85e4cc6585b26cbd8'),
 'decorationInterfaceIID':(0x627d50,16,'eddbe0c19dc575e83a182ac8cafad30e403c75cf5fd1fc79d18ef4f2be17cfee'),
 'valueIID':(0x61f9ec,16,'cd8a01df2b7a99a4dcccac84af05cdfc0e3af23ecceb29cb9e6d5bc59727fc98'),
 'contextIID':(0x61f9cc,16,'abb51393b21e9184f3834d126282abdd608f79eb6bb409967229785fea7959a3'),
 'otherFacetIID':(0x61fee4,16,'3552722c58ea655a3e7eeab8b38dadca7d5f8c719dbf3dd940c6a78a52e5eab6'),
 'persistIID':(0x61fb44,16,'d7f314ba806fb8e22105965ae7dde9bd0800eae824233aca05c3cfe1295b15c2'),
 'inputNamePair':(0x75f9a0,8,'51eebe122ef68bc7442b118476495f3efc6898ae10300d20e1aa3c5cc95eac1b'),
 'decorationNamePair':(0x75e180,8,'064d74863b110df1fa2749f483a364d6c85b17452f35289ba88bac0fb856859e'),
 'currentProcessIat':(0x61cd20,4,'2713d9dbcd9adf88369e2e12ad1975b379928fbc30737e98f1039e368603936e'),
 'currentProcessImportName':(0x7408ec,46,'a4327f933c8c7a91313e2a3e87bb42a31139e7aaa3d0f51b210f9259ff8c072d'),
}
PROFILES=(
 ('input','FormInputField','4a3e78c0-e57c-4e1f-9a3c-5d19e90755eb',0x674bcc,0x668dd8,(0,0x10,0x18,0x20)),
 ('decoration','FormDecoration','d5bf0c3c-f363-42ae-b0ac-7738cc5458f8',0x66df00,0x66e56c,(0,0x14,0x1c,0x24)),
)


def need(ok,code):
    if not ok:raise ValueError('V139_'+code)


def word(raw,offset):
    need(type(raw)is bytes and type(offset)is int and 0<=offset<=len(raw)-4,'WORD_BOUND')
    return struct.unpack_from('<I',raw,offset)[0]


def rel(raw,at,start):
    need(type(raw)is bytes and type(at)is int and type(start)is int
         and 0<=at<=len(raw)-5 and raw[at]==0xe8,'CALL_BOUND')
    return start+at+5+struct.unpack_from('<i',raw,at+1)[0]


def verify_sdk(members):
    need(type(members)is dict and members.keys()==SDK_SHAS.keys(),'SDK_SET')
    for name,sha in SDK_SHAS.items():
        b=members[name];need(type(b)is bytes and 0<len(b)<=65536
                           and hashlib.sha256(b).hexdigest()==sha,'SDK_HASH')
    document,process,value,typeinfo=(members[n].decode('utf-8-sig')for n in SDK_SHAS)
    need(':iface IPersistableObject {45B81B41-9540-11D4-9427-008048DA11F9}'in document
         and 'void serialize(IOutPersistenceStorage@+ storage)'in document
         and 'void deserialize(IInPersistenceStorage@+ storage)'in document,'PERSIST_SDK')
    need('bool createByClsid(const Guid&in clsid, const Guid&in iid, IUnknown@&out ppObject)'in process,
         'PROCESS_SDK')
    need(':iface IValue {FD7B6CC3-DC8E-11D2-B8D0-008048DA0335}'in value
         and ':iface IContext {FD7B6CC2-DC8E-11D2-B8D0-008048DA0335}'in typeinfo,'VALUE_CONTEXT_SDK')


def verify_linkage(bodies):
    """Closed map negative result applies only to the pinned nonaggregate path."""
    need(type(bodies)is dict and bodies.keys()==RANGES.keys(),'SPAN_SET')
    for name,(_,n,_)in RANGES.items():need(type(bodies[name])is bytes and len(bodies[name])==n,'SPAN_SIZE')
    iid=lambda n:str(uuid.UUID(bytes_le=bodies[n]))
    need(iid('persistIID')==PERSIST and iid('valueIID')=='fd7b6cc3-dc8e-11d2-b8d0-008048da0335'
         and iid('contextIID')=='fd7b6cc2-dc8e-11d2-b8d0-008048da0335','PUBLISHED_IID')
    rows=[]
    for prefix,name,clsid,primary,qimap,offsets in PROFILES:
        desc=bodies[prefix+'Descriptor'];name_rva=RANGES[prefix+'Name'][0]
        callback_rva=RANGES[prefix+'Callback'][0];create_rva=RANGES[prefix+'Create'][0]
        ctor_rva=RANGES[prefix+'Ctor'][0];guid_rva=RANGES[prefix+'FacadeClsid'][0]
        need(word(desc,24)==BASE+name_rva and word(desc,40)==BASE+guid_rva
             and word(desc,52)==BASE+callback_rva and iid(prefix+'FacadeClsid')==clsid,'NAME_FACTORY_DESCRIPTOR')
        name_pair=RANGES[prefix+'NamePair'][0]
        need(bodies[prefix+'Name'].count(b'\x68'+struct.pack('<I',BASE+name_pair))==2
             and bodies[prefix+'Name'][-1:]==b'\xc3','NAME_GETTER')
        callback=bodies[prefix+'Callback'];create=bodies[prefix+'Create'];ctor=bodies[prefix+'Ctor']
        need(callback[12:16]==bytes.fromhex('85c97509')and rel(callback,16,callback_rva)==create_rva
             and callback[-3:]==b'\xc2\x0c\x00','NONAGGREGATE_CALLBACK')
        need(rel(create,0x3e,create_rva)==ctor_rva and create[0x54:0x56]==b'\xff\x10'
             and create[-3:]==b'\xc2\x04\x00'
             and b'\xc7\x03'+struct.pack('<I',BASE+primary)in ctor
             and ctor[-3:]==b'\xc2\x04\x00','RETURNED_PRIMARY')
        qi_rva=RANGES[prefix+'QI'][0];qi=bodies[prefix+'QI']
        need(word(bodies[prefix+'Primary'],0)==BASE+qi_rva
             and word(qi,10)==BASE+qimap and rel(qi,17,qi_rva)==0x8e9e0
             and qi[-3:]==b'\xc2\x0c\x00','PRIMARY_QI')
        mapped=bodies[prefix+'Map'];names=(prefix+'InterfaceIID','valueIID','contextIID','otherFacetIID')
        ids=[]
        for i,n in enumerate(names):
            ptr,offset,handler=struct.unpack_from('<III',mapped,i*12)
            need(ptr==BASE+RANGES[n][0]and offset==offsets[i]and handler==1,'CLOSED_QI_MAP')
            ids.append(iid(n))
        need(mapped[48:]==b'\0'*12 and PERSIST not in ids,'NO_PERSISTENCE_FACET')
        rows.append(dict(name=name,descriptorFactoryClassId=clsid,callbackRva=callback_rva,
                         constructorRva=ctor_rva,primaryTableRva=primary,queryInterfaceRva=qi_rva,
                         closedQiMapRva=qimap,mapIids=ids,persistenceSupportedStatic=False,
                         persistenceClsid=None,ownWidgetRoundtripEligible=False))
    qi=bodies['commonQI']
    need(qi[0xac:0xb1]==bytes.fromhex('b802400080')
         and qi[0xb7:0xbd]==bytes.fromhex('c70100000000')
         and qi[0x67:0x85]==bytes.fromhex('8b073b0375378b47043b4304752f8b47083b430875278b470c3b430c751f'),
         'QI_NEGATIVE')
    return rows


def verify(read,members):
    need(callable(read),'READER_REQUIRED');verify_sdk(members);bodies={}
    for name,(rva,n,sha)in RANGES.items():
        try:b=read(rva,n)
        except Exception:raise ValueError('V139_SPAN_UNAVAILABLE')from None
        need(type(b)is bytes and len(b)==n and hashlib.sha256(b).hexdigest()==sha,'SPAN_HASH')
        bodies[name]=b
    rows=verify_linkage(bodies)
    helper=bodies['currentProcessRecordHelper'];process=bodies['recordCreateProcess']
    need(helper[12:18]==b'\xff\x15'+struct.pack('<I',BASE+0x61cd20)
         and rel(helper,22,0xaa190)==0xac560,'RECORD_CREATE_CURRENT_PROCESS')
    need(word(bodies['currentProcessIat'],0)+2==0x7408ec
         and bodies['currentProcessImportName']==b'?current_process@core@@YAPAVSCOM_Process@1@XZ\0',
         'CURRENT_PROCESS_IMPORT')
    need(b'\x68'+struct.pack('<I',BASE+0x61fb44)in process
         and bytes.fromhex('ff5014')in process and process[-1:]==b'\xc3','PUBLISHED_RECORD_CREATE')
    return dict(negativeFactoryRouteVerified=True,rows=rows,spanCount=len(bodies),
                persistedRecordCreateHelperRva=0xaa190,persistedRecordCreateProcessRva=0xac560,
                persistedRecordCreateSlot=5,persistedRecordCreateIid=PERSIST,
                expectedNonaggregatePersistenceHresult=0x80004002,expectedPersistenceOutputNull=True,
                facadeDescriptorBoundStatic=True,activeProcessRegistrationVerified=False,
                targetPersistedRecordRegistrationVerified=False,ownWidgetRoundtripVerified=False,
                nativePermit=False,writerAuthorized=False,exceptionUnwindVerified=False,
                fullTransitiveCtorEffectsVerified=False,aggregationPathCovered=False)


def verify_static():
    """Explicit local static reads; never call a factory/QI or load any DLL."""
    need(hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()==ARCHIVE_SHA,'SDK_ARCHIVE')
    with zipfile.ZipFile(ARCHIVE)as z:
        for n in SDK_SHAS:need(sum(x.filename==n for x in z.infolist())==1
                              and 0<z.getinfo(n).file_size<=65536,'SDK_MEMBER')
        members={n:z.read(n)for n in SDK_SHAS}
    pe=PE('mngcore.dll')
    def read(r,n):
        at=pe.offset(pe.base+r);return pe.data[at:at+n]
    return verify(read,members)
