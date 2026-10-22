"""Inert fixed primary/source contract for DISABLED detached Input roundtrip.

Explicit verify_static reads pinned PE/SDK/source bytes only; never loads DLLs,
executes SDK/native processes or grants a writer. Public Process wrapper and
normal counted QI outputs are distinct from private registration callbacks.
"""
import hashlib
from pathlib import Path
import struct
import uuid
import zipfile

from repository_pe_probe import PE
import managed_input_record_primary_v141 as v141
import managed_input_outer_kind_abi_v144 as v144

HERE=Path(__file__).resolve().parent
NATIVE=HERE.parent/'tests/NativeManagedInputRecordV145.as'
SOURCE_SHA='120df31299aaeb774ee84cb19b0e316001f9856f15339f6fd806e5a8de6e5ce1'
PINS={
 'managed_input_record_primary_v141.py':'3211798062afb584ed80aa3425daa708bf38c3f63dda8faf51f71b014917b45d',
 'managed_input_outer_kind_abi_v144.py':'e6ac2923c26bb8c19e8f25d7bbda4053a4c5d68a5c4c5e09a3096406f629cb97',
 '../tests/NativeGoldWriterInventory.as':'23abeb8a7b10a46502d8930c993f718af4e35202b5c932e2105e0b61413a680c',
 '../tests/NativeRepositoryObserve.as':'d7ac427467016667ac2b9e84a97a92727ef6955a2bf5dc439d4da36871bff16d',
 '../tests/NativeCaptureCycle.as':'e48c215b2ba914f97d4d346ffa38f8b9643176766a40277d9d6b070498ba40ab',
}
SDK_FILE='modules/snegopat/v8api/file.v'
SDK_FILE_SHA='c41ffff5ba6d270e143bbd779dcdd8d9b03d9b624611b785266ad80f05f3218a'
RANGES={
 'processGetter':('core83.dll',0x1df6c0,13,'350ffc6e1613ad41ba15f029b1fea8ff364933d736c06002d0e0636d814aaa6d'),
 'processTable':('core83.dll',0x2d5120,24,'8dc75cf294b5a71eb836a588afb96e14831b6a05edf0ab0d909d602d4361eb72'),
 'processQI':('core83.dll',0x1e11c0,26,'5666816ab2241ad9828e0bdb1ed33048a0dcbdac0347aa1ce765a39d7c1b8d39'),
 'processRef':('core83.dll',0x2ccf0,3,'6979575acd802b5cf86a70f25a2aebf671cb5f62cf3fd0c60db4af2871cf5be6'),
 'processFactory':('core83.dll',0x158600,99,'103972e414d37962d47a8c8d17db3eb002299fb8028ee8746025c7b56b2eebb4'),
 'processContextCtor':('core83.dll',0x1df800,325,'ae22634c76d0a14be9d5f6ad51c6934a91f48fef59ce90020a1ab8b7e04450be'),
 'registryCtor':('core83.dll',0x15a670,171,'1e8ae410d78a5155df04257cde6ed0cacce4acbf6968b52ac172bf75bbad9546'),
 'registryPrimary':('core83.dll',0x2ce820,12,'95117a4993035c80aea9d727423bf49846700503989fcf1bc6f043a9e877b941'),
 'registryFactoryTable':('core83.dll',0x2ce838,24,'eae5f2fb400ba747dbad08cf9436ae4eb91661371b10c18ef44a2c18f450f398'),
 'registryFactory':('core83.dll',0x15ae20,109,'e9bc32ac1aed7901fce7c5fa2a34a83d1c3c669080b4b9012678e68d5d767a12'),
 'memoryPrimary':('core83.dll',0x2c5dfc,36,'ccc4809ccc2a1afae3a07f374f0bfb3e3cbc2208e97868f14da973ed4feec705'),
 'memoryMap':('core83.dll',0x2c61c0,48,'5db75f66f122661cb035d106e6b5e37abd5656f19209727903287101131cad4e'),
 'memoryQI':('core83.dll',0x10ef20,26,'004102ff01aa87934942df9fa0c2989180cf8bf863990db630983ce5ccab5cd1'),
 'memoryCallback':('core83.dll',0x10eef0,34,'6920cc6c64ec7c06f360e4d960d1c74f6486519dfeec4163138de0dc74d2b904'),
 'memoryFactory':('core83.dll',0x10ff60,117,'f89ba2fc31b9d6481ad66fb3b3ac852360103526819ef7716c87e4fd2bdc52f5'),
 'outPrimary':('core83.dll',0x2c8c34,12,'4bc4e1db2d302ffc5f6df5cb184e4e47a46d7d9c63e92d832348fc90d80cbb35'),
 'outStream':('core83.dll',0x2c8c1c,24,'e1bf8ae3c7a7aaade43da8cf03ed88c746adf05aff4c4124829632c960192cf6'),
 'outMap':('core83.dll',0x2c9000,36,'1298791906d3af3e344b9d456f97bb20d90d2a5a01276feba8cf588f857a1152'),
 'outQI':('core83.dll',0x12ba20,26,'a4ccea805399e203231cd8cffede8b77aea73c39842b622924173126ca3b9521'),
 'outCallback':('core83.dll',0x12abe0,34,'63914d7d86834adb5d098f2b55e13ce00515f3adfc68bbf55bc12672d94ba601'),
 'outFactory':('core83.dll',0x12b3a0,159,'2766f3cfb283493495aa03d5af57c32702a35a66354fdf04a05f497a0ab5f84e'),
 'inPrimary':('core83.dll',0x2c8c80,12,'eb0c25806f8d2c76e7090692cf6ac43c6400a1f11316ebf1e765b1411db1616b'),
 'inStream':('core83.dll',0x2c8c04,24,'3cc75de62486185c7d6dc2b0f94fdd19a91cfe86533572fe6b8d629dbcff6ead'),
 'inMap':('core83.dll',0x2c8f50,36,'8b5849c26838883d030c6ca50e89ad1ec9fd561ea33c0a762d5573d7963f1b30'),
 'inQI':('core83.dll',0x12b980,26,'52aeca808cf04f8d282fc62b1f41bc49ca1a0ca864f6522bb44972017dd3cb40'),
 'inCallback':('core83.dll',0x12abb0,34,'a5dd0233265b0ec8ebc5dcc28ab0b43abfd6d5003d2e3a75ca11fc82a95a8999'),
 'inFactory':('core83.dll',0x12b230,152,'21a4e21564eba3b8a351dee64c8830848c0bb1f91e10e7996348c78629f4b4ba'),
 'coreCommonQI':('core83.dll',0x2ea10,234,'97a0568cd952f0c443fe52096f4962424e7a235baf1f8f6788ed7728941f4d7f'),
 'outSetFile':('core83.dll',0x128cc0,268,'831959986f913dc8642ad85d3a4307318f664b4a15438d8db30bf14e4baac7e4'),
 'inSetFile':('core83.dll',0x129280,264,'044b1a7b81c981132c1fe7f381402d1c3d43c4ebc2fc8bc806f11cab713e8fae'),
 'storageClose':('core83.dll',0x1285c0,18,'27264fd4e44d9a54d76c2ba903b31f6880c3b0938368a056209dc9f706ea26dc'),
 'outerDeserialize':('mngcore.dll',0x34c450,2745,'6b33ba0db00560871d3f349b573406ffa51d65e994fa53762d1011b2f1610036'),
}

def need(ok,code):
    if not ok:raise ValueError('V145_'+code)


def verify_source(raw,check_hash=True):
    need(type(raw)is bytes and 0<len(raw)<=65536,'SOURCE_BOUND')
    if check_hash:need(hashlib.sha256(raw).hexdigest()==SOURCE_SHA,'SOURCE_CHANGED')
    try:s=raw.decode('utf-8-sig')
    except UnicodeError:raise ValueError('V145_SOURCE_ENCODING')from None
    need('const bool ahManagedInputRecordEnabledV145=false;'in s
         and 'if(!ahManagedInputRecordEnabledV145)return ahInputResultV145(s);'in s,'DISABLED_GATE')
    need('if(ahManagedInputStartedV145 || s.consumed || s.unknown'in s,'ONE_SHOT')
    need('s.output.resize(36)'in s and 'owned!=expected || !outputKnown'in s
         and 'if(!made || !known){s.unknown=true;return 0;}'in s,'CANARY_OUTPUT_GATES')
    need('funcdef void AhInputSetKindV145(int_ptr self,int kind);'in s
         and s.count('s.setter(sp-0x14,8);')==1,'SETTER_VOID_ONCE')
    need('if(catcher.hasException){s.exception=true;s.unknown=true;return ahInputResultV145(s);}'in s
         and 'if(!s.complete || s.unknown)return ahInputResultV145(s);'in s,'UNKNOWN_RETENTION')
    need('while(s.pins.length>0)s.pins.removeLast();'in s and 'bool known=ahInputContextV145(s);'in s,'KNOWN_REVERSE_RELEASE')
    need(not any(t in s for t in ('createByName(','getMDService(','connectConfig(','mdPropVal(','setMdPropVal(',
        'ahStatusUi','ahPlanController','LoadLibrary','queryIface(','MemoryBuffer','setReadOnly(','terminate(')),'FORBIDDEN_CALL')
    return dict(disabled=True,functionOnly=True,nativePermit=False,writerAuthorized=False)


def verify_linkage(b):
    need(type(b)is dict and b.keys()==RANGES.keys(),'SPAN_SET')
    for name,(_,_,n,_)in RANGES.items():need(type(b[name])is bytes and len(b[name])==n,'SPAN_SIZE')
    word=lambda data,at:struct.unpack_from('<I',data,at)[0]
    core=0x10020000
    need(tuple(x-core for x in struct.unpack('<6I',b['processTable']))
         ==(0x1e11c0,0x2ccf0,0x2ccf0,0x1585a0,0x158670,0x158600),'PROCESS_SLOTS')
    wrapper=b['processFactory']
    need(wrapper[:18]==bytes.fromhex('558bec8b4508ff7514ff75108b8084000000')
         and wrapper[0x29:0x2c]==b'\xc2\x10\x00' and wrapper[-3:]==b'\xc2\x10\x00'
         and bytes.fromhex('ff6014')in wrapper,'PUBLIC_WRAPPER_ABI')
    ctor=b['processContextCtor'];reg=b['registryCtor']
    need(b'\x89\x7b\x18'in ctor and b'\x89\x9f\x84\x00\x00\x00'in ctor,'CONTEXT_OWNER')
    need(b'\xc7\x06'+struct.pack('<I',core+0x2ce820)in reg
         and b'\xc7\x46\x04'+struct.pack('<I',core+0x2ce838)in reg,'DEFAULT_REGISTRY')
    for prefix,qi,map_rva in (('memory',0x10ef20,0x2c61c0),('out',0x12ba20,0x2c9000),('in',0x12b980,0x2c8f50)):
        body=b[prefix+'QI']
        need(word(body,10)==core+map_rva and v141.relative(body,17,qi)==0x2ea10
             and body[-3:]==b'\xc2\x0c\x00','CORE_REQUESTED_QI')
    for prefix,primary,stream,qi,add,release,map_rva in (
        ('out',0x2c8c34,0x2c8c1c,0x12ba20,0x3e2d0,0xd8500,0x2c9000),
        ('in',0x2c8c80,0x2c8c04,0x12b980,0x3e2d0,0x3e2a0,0x2c8f50)):
        need(tuple(x-core for x in struct.unpack('<3I',b[prefix+'Primary']))==(qi,add,release),'STORAGE_012')
        need(struct.unpack_from('<II',b[prefix+'Map'],16)==(4,1)
             and b[prefix+'Map'][-12:]==b'\0'*12,'STORAGE_FACET_OFFSET')
        create=b[prefix+'Factory'];callback=b[prefix+'Callback']
        need(callback[-3:]==b'\xc2\x0c\x00' and create[-3:]==b'\xc2\x04\x00'
             and b'\xc7\x06'+struct.pack('<I',core+primary)in create
             and b'\xc7\x46\x04'+struct.pack('<I',core+stream)in create,'NORMAL_COUNTED_STORAGE')
        need(b[prefix+'SetFile'][-3:]==b'\xc2\x08\x00','STORAGE_SETFILE_ABI')
    memory=b['memoryFactory']
    need(b'\xc7\x06'+struct.pack('<I',core+0x2c5dfc)in memory
         and memory[-3:]==b'\xc2\x04\x00' and b['memoryMap'][-12:]==b'\0'*12,'MEMORY_NORMAL')
    common=b['coreCommonQI']
    need(common[0xc9:0xcf]==bytes.fromhex('568b06ff5004')
         and common[0xcf:0xd4]==bytes.fromhex('8b450c8930') and common[-3:]==b'\xc2\x08\x00','COMMON_QI_COUNTED')
    load=b['outerDeserialize']
    need(load[0x34:0x37]==bytes.fromhex('8d7bec') and load[2710:2713]==b'\xc2\x08\x00'
         and load[-8:]==bytes.fromhex('51ffd0e9c3feffff'),'OUTER_LOAD_WHOLE')
    return dict(publishedFactoryArgumentBytes=16,factoryBoolInAL=True,defaultContextOwnerBackrefOffset=0x18,
        processDefaultRegistryStatic=True,factoryFallbackBranchIncluded=True,factoryFallbackNotInvokedVerified=False,
        rawQIArgumentBytes=12,rawQIStaticCounted=True,ownMemoryFactoryStaticCounted=True,
        outerDeserializeWholeBytes=2745,outerDeserializeArgumentBytes=8,
        runtimeProcessContextVerified=False,runtimeCanaryVerified=False,templateVerified=False,
        independentBackingVerified=False,nativePermit=False,writerAuthorized=False)


def verify_static():
    """Only explicit fixed local primary reads; no loader, subprocess or Gold."""
    for name,sha in PINS.items():need(hashlib.sha256((HERE/name).read_bytes()).hexdigest()==sha,'PIN_CHANGED')
    verify_source(NATIVE.read_bytes());previous=v144.verify_static()
    need(previous['outerKindNativeAbiStaticVerified']is True,'PREVIOUS_CONTRACT')
    with zipfile.ZipFile(v141.ARCHIVE)as archive:
        need(0<archive.getinfo(SDK_FILE).file_size<=65536,'SDK_BOUND');raw=archive.read(SDK_FILE)
    need(hashlib.sha256(raw).hexdigest()==SDK_FILE_SHA,'SDK_FILE_CHANGED')
    text=raw.decode('utf-8-sig');need(':base IFile'in text and 'uint64 seek(int64 pos, FileSeekMode mode)'in text,'SDK_FILE_LAYOUT')
    images={m:PE(m)for m in ('core83.dll','mngcore.dll')};b={}
    for name,(module,r,n,sha)in RANGES.items():
        p=images[module];start=p.offset(p.base+r);raw=p.data[start:start+n]
        need(len(raw)==n and hashlib.sha256(raw).hexdigest()==sha,'PRIMARY_CHANGED');b[name]=raw
    proof=verify_linkage(b)
    return dict(stage='V145DetachedInputRecordStaticContract',platform='8.3.18.1208',staticCompatible=True,
        nativeSourceSha256=SOURCE_SHA,primaryNewSpans=len(RANGES),priorPrimarySpans=43,**proof)
