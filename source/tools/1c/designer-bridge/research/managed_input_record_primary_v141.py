"""Static InputField kind8 -> outer record -> persistence payload, no permit.

Import is inert. Only verify_static performs explicit fixed local reads; DLLs
are never loaded. The outer field record and its kind8 payload are distinct.
No saved Input template, default subtype, property encoding or native runtime
capability is established by the static linkage.
"""
import hashlib
from pathlib import Path
import struct
import uuid
import zipfile

from repository_pe_probe import PE

ROOT=Path(__file__).resolve().parents[4]
BASE=0x36c20000
PERSIST='45b81b41-9540-11d4-9427-008048da11f9'
FACADE='4a3e78c0-e57c-4e1f-9a3c-5d19e90755eb'
MODEL_IID='6774a26f-4f00-41be-9d77-c5f07054837f'
PAYLOAD='f9177e1e-8eee-43a1-a2b6-e7b0aeab28e3'
OUTER='77ffcc29-7f2d-4223-b22f-19666e7250ba'
ARCHIVE=ROOT/'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40/snegopat.zip'
ARCHIVE_SHA='464256ea84009d66f2d177ce92cb128479ba634da6a493a93aef579410710fde'
SDK_SHAS={
 'modules/snegopat/v8api/document.v':'b1c12ef6a2d4ea9d655bd9057c7a605b2497bb6c22ddb9f6323efc3ad21c369e',
 'modules/snegopat/v8api/process.v':'92458b3e1a862051bf9b1d8b0cac750de5fddc62294324ca70a94820cdb1a9ef',
 'modules/snegopat/v8api/typeinfos.v':'ab473e3f2f3a6e0b9bbdfbf811466a4da89d376f55c68a9dd2b9f7b85d2c3922',
}
FACADE_PROOF=Path(__file__).with_name('managed_widget_factory_gap_v139.py')
FACADE_PROOF_SHA='df03abfc33c5206eb43210667e5ce869da0ac043d99ce06c47d57991ace8e0f5'
RANGES={
 'inputFacadeDescriptor':(0x75bf60,56,'e1048e5f8eb1d45794b49a6ad05a541c4be082d9001cb3c3dc9f4197aa240ac6'),
 'inputFacadeGuid':(0x66e410,16,'5a7437157ed8c5d05108034b7788264f3896a281c6ef8962307d3e70534c264e'),
 'inputFacadePrimary':(0x674bcc,28,'a32c7fc8e35f8859ab83a8841483dfedabe92e31a323b5de775556a45335a8ba'),
 'inputContextTable':(0x674aa8,80,'4f011a4a0b124b7200d757ab11bb15b3dbb9de53882a10f471e558fc3313b2e3'),
 'inputGetPropPrefix':(0x377070,104,'7a505c0264eeffcb8b0c2214a9b86d2a2e9b727adb064af996cacb9d9e7bdb20'),
 'inputModelQIHelper':(0x383400,39,'65871abba6f84a03ebb75aa4fad85b6f216688f0ac0bcb7f5e1742c1a975245f'),
 'modelIID':(0x669410,16,'783a12c4fe5ca4a09ce636f3027b1fa9681c8b307e472eec94903cf5e38a5c37'),
 'facadeKindDispatch':(0x33b6d0,646,'1613526325d4d6799bb8bcfe8c777b0c7b8c28490bf412bfd54442970ae45819'),
 'facadeKindJump':(0x33b958,80,'2de210bfa9c9eaae4a9543b3e7f45c10f72373200e84913ccebec88767ab8c82'),
 'fieldKindDispatch':(0x349e20,1521,'e572fc3c6d40d459c9091945fc6fde2e236c2c36d0421fad9622baca06593a3b'),
 'fieldKindJump':(0x34a414,76,'426c809f52697b69c3a90ea38e5b67d8530274633c924eb56ee114eecd3d3d6f'),
 'payloadGuid':(0x671f3c,16,'cd8cbd32e1e03f693f021bbdb6650862e32d6e2638a22010780c3afca580acb9'),
 'payloadRegistration':(0x75b930,16,'e4961073921ed66ed4519008ca32c9e35a7572619a3f9bd767bf9edc443f9b60'),
 'payloadCallback':(0x35f260,34,'7dd387469fb2658d6f9b26e9baa9c8b69d9668e059710a32e301bf25837a09b1'),
 'payloadCreate':(0x360710,225,'3a4562df1e0e4e6a04e956299092bcf25a0e26dd9af1944de759ecb60e5c4a1c'),
 'payloadCtor':(0x35a780,218,'e80036ab39f2af6acf0071a8c3014dfb072bbdcaa9ccaa1d2dc76e02db6450be'),
 'payloadPrimary':(0x66fdcc,212,'a692c16bc2a7f2a48f87cf201bfd11b6cd8c55a52e257bc59070f75820dcd1c9'),
 'payloadPersist':(0x66fea0,24,'30aaf5e634e2941bd659574f5c72a42fddaf0c55ded60d53553de4f9bb195368'),
 'payloadQI':(0x34fe50,26,'83396b601d9b6484fdb9781ff98fd859b0228bbc1b146ced0929da3552d17be7'),
 'payloadMap':(0x67076c,60,'46bea3dbcff0be80af99cb1016f9b0f0ded01aded8576d957d75ae43f10e9a2f'),
 'payloadQIThunk':(0x351d68,10,'8f8ecb95c09e7a7f95e5545becb3865eb063efdbad353336fde8a60adb1d175f'),
 'payloadClsidGetter':(0x35af70,8,'4c4bce1e157fd09998a8f8dce333359432330578d271e326906956fb8b3f6f22'),
 'payloadSerialize':(0x35af80,382,'3b1be678a3f8718418c84aaa3a500076d463a08aa51ae241a75718b4577db7d7'),
 'payloadDeserialize':(0x35b100,695,'50cdf44030c60553f46fc227552840e5a7ce2c312d50e28b78e81a4e4681355a'),
 'outerGuid':(0x6694f8,16,'93dc7160ada11b11627694f20e52c5e1c47ac31efed9b35dc1d413dc0e954adb'),
 'outerRegistration':(0x75b6c8,16,'d9a8c5dd924e0872a28f7c71112f4e077dbcb1847330946f33778dfee23722ec'),
 'outerCallback':(0x350050,34,'cf80aa85fac47b58dc93e886baad7bbffbbabbbe4a742c5a4a11ec600dafab81'),
 'outerCreate':(0x350f60,230,'3ed1e80df329ceada994ee6f744efc7dfd6656661a25d00eb8f5cb1bf19c3be2'),
 'outerCtor':(0x3500f0,86,'542d8011e506541614acb3027cd59d8ee6b83804ade1aa4687eecacd3c877e2a'),
 'outerPrimary':(0x66f218,484,'fee4a92a135cab86e04dc10fad21cf1ffa72db94cd1e99f0b509e5136b2f6457'),
 'outerPersist':(0x66f200,24,'30f62feb3f2b637d2534d92c32a5f6928376c8c89acb58d8fa02921caf09318b'),
 'outerQI':(0x350080,26,'a1cbb311ba99d3547c590a9763a7874f59c108dd20572a2509f6913df3f68c3b'),
 'outerMap':(0x670a38,144,'d84bddd1e7d42533b0a0075eda624f205003f45bd79f363ea26843b0ff16dcd5'),
 'outerQIThunk':(0x351f70,10,'3e541d7ad0376870eae1055711407a35e93d4a3a2dbd6cb71c5217bfd6c9313b'),
 'outerClsidGetter':(0x34bed0,8,'6130e9d38b3e5f9e30ba37ed24c0070688bddc19a3b2e2dbd1b847c314e86002'),
 'outerSerialize':(0x34bee0,1382,'f3c74826f3ad522bccb140ca26a46b297bfb232439f8bf578810d11d74ed6dbf'),
 'persistIID':(0x61fb44,16,'d7f314ba806fb8e22105965ae7dde9bd0800eae824233aca05c3cfe1295b15c2'),
 'commonQI':(0x8e9e0,234,'97a0568cd952f0c443fe52096f4962424e7a235baf1f8f6788ed7728941f4d7f'),
}


def need(ok,code):
    if not ok:raise ValueError('V141_'+code)


def word(raw,at):
    need(type(raw)is bytes and type(at)is int and 0<=at<=len(raw)-4,'WORD_BOUND')
    return struct.unpack_from('<I',raw,at)[0]


def relative(raw,at,rva,opcode=0xe8):
    need(type(raw)is bytes and type(at)is int and type(rva)is int and 0<=at<=len(raw)-5
         and raw[at]==opcode,'CALL_BOUND')
    return rva+at+5+struct.unpack_from('<i',raw,at+1)[0]


def verify_sdk(members):
    need(type(members)is dict and members.keys()==SDK_SHAS.keys(),'SDK_SET')
    for name,sha in SDK_SHAS.items():
        raw=members[name];need(type(raw)is bytes and 0<len(raw)<=65536
                              and hashlib.sha256(raw).hexdigest()==sha,'SDK_HASH')
    doc,process,context=(members[n].decode('utf-8-sig')for n in SDK_SHAS)
    need('const Guid& getCLSID()'in doc and 'void serialize(IOutPersistenceStorage@+ storage)'in doc
         and 'void deserialize(IInPersistenceStorage@+ storage)'in doc,'SDK_PERSIST')
    need('bool createByClsid(const Guid&in clsid, const Guid&in iid, IUnknown@&out ppObject)'in process,'SDK_FACTORY')
    need(':iface IContext {FD7B6CC2-DC8E-11D2-B8D0-008048DA0335}'in context
         and 'bool getPropVal(int prop, Value& value)'in context,'SDK_CONTEXT')


def verify_linkage(bodies):
    """Verify exact model/kind/factory edges, never grant calls or adoption."""
    need(type(bodies)is dict and bodies.keys()==RANGES.keys(),'SPAN_SET')
    for name,(_,n,_)in RANGES.items():need(type(bodies[name])is bytes and len(bodies[name])==n,'SPAN_SIZE')
    guid=lambda name:str(uuid.UUID(bytes_le=bodies[name]))
    need((guid('inputFacadeGuid'),guid('modelIID'),guid('payloadGuid'),guid('outerGuid'),guid('persistIID'))
         ==(FACADE,MODEL_IID,PAYLOAD,OUTER,PERSIST),'CLASS_ROLE')
    need(word(bodies['inputFacadeDescriptor'],40)==BASE+0x66e410
         and word(bodies['inputFacadePrimary'],5*4)==BASE+0x383120
         and word(bodies['inputContextTable'],17*4)==BASE+0x377070,'INPUT_FACADE_CONTEXT')
    prefix=bodies['inputGetPropPrefix'];helper=bodies['inputModelQIHelper']
    need(b'\x8d\x79\xec'in prefix and relative(prefix,0x61,0x377070)==0x383400
         and helper[0x18:0x1d]==b'\x68'+struct.pack('<I',BASE+0x669410)
         and helper[-3:]==b'\xc2\x04\x00','INPUT_MODEL_QI')
    # Exactly kind8 chooses the input facade and constructs its own payload.
    need(word(bodies['facadeKindJump'],8*4)==BASE+0x33b79a
         and bodies['facadeKindDispatch'][0xca:0xcf]==b'\xb8'+struct.pack('<I',BASE+0x66e410)
         and word(bodies['fieldKindJump'],(8-1)*4)==BASE+0x34a18a,'KIND8')
    d=bodies['fieldKindDispatch'];at=0x34a18a-0x349e20
    need(d[0x2a:0x2e]==bytes.fromhex('8b437848')
         and relative(d,at+0x1b,0x349e20)==0x35a780
         and b'\xc7\x06'+struct.pack('<I',BASE+0x66fdcc)in d[at:at+57]
         and d[0x72:0x78]==bytes.fromhex('8dbb30010000'),'KIND8_PAYLOAD')
    m=bodies['payloadMap']
    need(struct.unpack_from('<III',m,12)==(BASE+0x669410,0,1)
         and struct.unpack_from('<III',m,24)==(BASE+0x61fb44,8,1)
         and m[-12:]==b'\0'*12,'PAYLOAD_MAP')
    need(word(bodies['payloadPrimary'],0)==BASE+0x34fe50
         and word(bodies['payloadQI'],10)==BASE+0x67076c
         and relative(bodies['payloadQI'],17,0x34fe50)==0x8e9e0
         and bodies['payloadQIThunk'][:5]==bytes.fromhex('836c240408')
         and relative(bodies['payloadQIThunk'],5,0x351d68,0xe9)==0x34fe50,'PAYLOAD_QI')
    for prefix,offset,create,ctor,callback,table,getter,serialize,deserialize in (
       ('payload',8,0x360710,0x35a780,0x35f260,0x66fdcc,0x35af70,0x35af80,0x35b100),
       ('outer',0x14,0x350f60,0x3500f0,0x350050,0x66f218,0x34bed0,0x34bee0,None)):
        need(word(bodies[prefix+'Registration'],0)==BASE+RANGES[prefix+'Guid'][0]
             and word(bodies[prefix+'Registration'],12)==BASE+callback,'REGISTRATION')
        cb=bodies[prefix+'Callback'];factory=bodies[prefix+'Create']
        need(cb[12:16]==bytes.fromhex('85c97509') and relative(cb,16,callback)==create
             and cb[-3:]==b'\xc2\x0c\x00' and factory[-3:]==b'\xc2\x04\x00','NORMAL_FACTORY')
        call_at=0x7d if prefix=='payload' else 0x7c
        need(relative(factory,call_at,create)==ctor and word(bodies[prefix+'Primary'],0)==BASE+RANGES[prefix+'QI'][0], 'FACTORY_CTOR')
        # The internal nonaggregate creator returns the requested QI HRESULT;
        # Process.createByClsid is a separate published bool API. Neither is
        # treated as a native runtime success certificate.
        qi_at=0xb2 if prefix=='payload' else 0xb7
        self_push=b'\x56'if prefix=='payload'else b'\x57'
        need(factory[qi_at:qi_at+7]==b'\x53\xff\x75\xec'+self_push+b'\xff\x10'
             and b'\xb8\x03\x40\x00\x80'in factory
             and b'\xc7\x03\x00\x00\x00\x00'in factory,'REQUESTED_QI_OUTPUT')
        persist=bodies[prefix+'Persist']
        need(word(persist,12)==BASE+getter and word(persist,16)==BASE+serialize
             and bodies[prefix+'ClsidGetter']==b'\xb8'+struct.pack('<I',BASE+RANGES[prefix+'Guid'][0])+b'\xc2\x04\x00','PERSIST_CLASS')
        if deserialize is not None:
            need(word(persist,20)==BASE+deserialize
                 and bodies[prefix+'Deserialize'][0x2b:0x2e]==bytes.fromhex('8d4ff8')
                 and bodies[prefix+'Deserialize'][0x2ac:0x2af]==b'\xc2\x08\x00','DESERIALIZE_ABI')
        need(bodies[prefix+'Serialize'][-3:]==b'\xc2\x08\x00','SERIALIZE_ABI')
    # Outer persistence self=wrapper+14: its saved payload slot self+11c is
    # exactly wrapper+130 written by the kind dispatch above.
    outer=bodies['outerSerialize'];start=0x34c18a-0x34bee0
    need(relative(outer,start+12,0x34bee0)==0x349e20
         and bytes.fromhex('8b8f1c010000')in outer[start:start+111]
         and b'\x68'+struct.pack('<I',BASE+0x61fb44)in outer[start:start+111]
         and bytes.fromhex('8b085650ff5110')in outer[start:start+111], 'OUTER_SAVES_PAYLOAD')
    need(struct.unpack_from('<III',bodies['outerMap'],7*12)==(BASE+0x61fb44,0x14,1)
         and bodies['outerQIThunk'][:5]==bytes.fromhex('836c240414')
         and relative(bodies['outerQIThunk'],5,0x351f70,0xe9)==0x350080,'OUTER_PERSIST_FACET')
    need(bodies['commonQI'][0xc3:0xd4]==bytes.fromhex('8b76fc0375fc568b06ff50048b450c8930'),'COUNTED_QI')
    return dict(inputFieldModelLinkStaticVerified=True,inputKindCode=8,
       outerFieldRecordClassId=OUTER,inputModelPayloadClassId=PAYLOAD,
       modelInterfaceId=MODEL_IID,payloadPersistenceOffset=8,outerPersistenceOffset=0x14,
       payloadPrimaryTableRva=0x66fdcc,payloadPersistenceTableRva=0x66fea0,
       outerPersistenceTableRva=0x66f200,normalNonaggregateFactoryStaticVerified=True,
       outerSerializerCallsPayloadStaticVerified=True,serializerArgumentBytes=8,
       getClsidArgumentBytes=4,normalCallbackArgumentBytes=12,innerCreatorArgumentBytes=4,
       normalCallbackReturnsHresult=True,publicCreateReturnsBool=True,primarySpanCount=len(bodies),
       activeProcessRegistrationVerified=False,countedAdoptionRuntimeVerified=False,
       savedInputRecordTemplateVerified=False,defaultOuterInputKindVerified=False,
       readOnlyMultilineEncodingVerified=False,booleanFieldSubtypeVerified=False,
       reportInputRuntimeVerified=False,wholeTransitiveCtorEffectsVerified=False,
       exceptionUnwindVerified=False,aggregationPathCovered=False,
       candidateNativePermit=False,nativePermit=False,writerAuthorized=False)


def verify(read,members):
    need(callable(read),'READER_REQUIRED');verify_sdk(members);bodies={}
    for name,(r,n,sha)in RANGES.items():
        try:raw=read(r,n)
        except Exception:raise ValueError('V141_SPAN_UNAVAILABLE')from None
        need(type(raw)is bytes and len(raw)==n and hashlib.sha256(raw).hexdigest()==sha,'SPAN_HASH')
        bodies[name]=raw
    return verify_linkage(bodies)


def sdk_members():
    need(hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()==ARCHIVE_SHA,'SDK_ARCHIVE')
    with zipfile.ZipFile(ARCHIVE)as z:
        for name in SDK_SHAS:need(sum(x.filename==name for x in z.infolist())==1
           and 0<z.getinfo(name).file_size<=65536,'SDK_MEMBER')
        return {name:z.read(name)for name in SDK_SHAS}


def verify_static():
    """Read fixed existing PE/SDK only, no extraction/loader/factory/Gold."""
    need(hashlib.sha256(FACADE_PROOF.read_bytes()).hexdigest()==FACADE_PROOF_SHA,'FACADE_PROOF_CHANGED')
    from managed_widget_factory_gap_v139 import verify_static as facade_proof
    negative=facade_proof()
    need(negative['rows'][0]['name']=='FormInputField'
         and negative['rows'][0]['persistenceSupportedStatic']is False,'FACADE_SEPARATION')
    image=PE('mngcore.dll')
    def read(r,n):
        at=image.offset(image.base+r);return image.data[at:at+n]
    return verify(read,sdk_members())
