"""Exact detached outer77ff kind setter ABI, static only and no native permit.

Reuse frozen141 model/factory/persistence proof. The native model setter is
not declared by the selected SDK members. Runtime receiver, owner-null,
canary/lifetimes, serialized template and report flags still need a scoped
OWN MemoryFile experiment; there is no callable adapter or record builder.
"""
import hashlib
from pathlib import Path
import struct
import uuid

from repository_pe_probe import PE
import managed_input_record_primary_v141 as previous

BASE=previous.BASE
MODEL_IID='21c27390-7ec5-4b11-a2fa-a2e44d4dab82'
PREVIOUS_PATH=Path(__file__).with_name('managed_input_record_primary_v141.py')
PREVIOUS_SHA='3211798062afb584ed80aa3425daa708bf38c3f63dda8faf51f71b014917b45d'
RANGES={
 'baseCtor':(0x349500,566,'9c56e09386dc95abbd98c616b14414de76dcf7247e4e640f7ada8fbecc2ef505'),
 'resetState':(0x3499d0,1097,'fbecefc16ae1de2122b5c52a06ef519b68ad17468b71867bf8d66876a5eb18c1'),
 'kindGetter':(0x24a640,13,'c2a89c8fe30a2e5f176cb1a2011fc9704cd3e90ee8b4fab413feab6bd7d8efc7'),
 'kindSetter':(0x34a830,52,'c086f673130d01f5fcc6289b0b41e794c5bf5dc55215499f14aae63dd8210df8'),
 'modelIID':(0x6661a0,16,'459cbeda4686603aefbb619b1b5cd5106d89ffbd66255e61847327b713afe898'),
}


def need(ok,code):
    if not ok:raise ValueError('V144_'+code)


def verify_linkage(bodies,old):
    need(type(bodies)is dict and bodies.keys()==RANGES.keys(),'SPAN_SET')
    for name,(_,n,_)in RANGES.items():need(type(bodies[name])is bytes and len(bodies[name])==n,'SPAN_SIZE')
    prerequisite=previous.verify_linkage(old)
    ctor=bodies['baseCtor'];getter=bodies['kindGetter'];setter=bodies['kindSetter']
    need(ctor[184:191]==bytes.fromhex('c7475400000000')
         and ctor[221:228]==bytes.fromhex('c7477801000000') and ctor[-1:]==b'\xc3','CONSTRUCTOR_DEFAULT')
    need(previous.relative(old['outerCtor'],10,0x3500f0)==0x349500
         and previous.relative(old['outerCreate'],0xa9,0x350f60)==0x3499d0
         and bodies['resetState'][-1:]==b'\xc3','FACTORY_INIT')
    need(str(uuid.UUID(bytes_le=bodies['modelIID']))==MODEL_IID
         and struct.unpack_from('<III',old['outerMap'],2*12)==(BASE+0x6661a0,0,1)
         and previous.word(old['outerPrimary'],42*4)==BASE+0x24a640
         and previous.word(old['outerPrimary'],43*4)==BASE+0x34a830,'MODEL_SLOTS')
    need(getter==bytes.fromhex('558bec8b45088b40785dc20400'),'GETTER_ABI')
    need(setter[:13]==bytes.fromhex('558bec8b450c568b7508394678')
         and setter[13:15]==bytes.fromhex('7420')
         and setter[17:20]==bytes.fromhex('894678')
         and previous.relative(setter,20,0x34a830)==0x349e20
         and setter[-3:]==b'\xc2\x08\x00','SCALAR_SETTER_ABI')
    need(setter[25:32]==bytes.fromhex('8b4e5485c9740f')
         and setter[32:47]==bytes.fromhex('8b0151ff50206a4556508b08ff5140')
         and setter[47:49]==bytes.fromhex('5e5d'),'NULL_OWNER_BRANCH')
    # Same native scalar is serialized at persistence self+64; the QI map
    # already proves persistence self=primary+14, hence the primary field+78.
    save=old['outerSerialize'];at=0x34bfba-0x34bee0
    need(save[at:at+11]==bytes.fromhex('ff77648bcbff159ccc2337'),'SERIALIZED_KIND_SCALAR')
    need(prerequisite['inputKindCode']==8 and prerequisite['outerSerializerCallsPayloadStaticVerified']is True,
         'KIND8_PERSISTENCE_LINK')
    return dict(outerKindNativeAbiStaticVerified=True,constructorKindStaticValue=1,
       constructorOwnerStaticNull=True,requestedModelInterfaceId=MODEL_IID,modelQIStaticOffset=0,
       modelPrimaryTableRva=0x66f218,kindGetterSlot=42,kindGetterRva=0x24a640,
       kindSetterSlot=43,kindSetterRva=0x34a830,kindGetterArgumentBytes=4,kindSetterArgumentBytes=8,
       targetInputKind=8,kindSetterBuildsPayloadStatic=True,notificationGuardOffset=0x54,
       notificationOnlyWhenOwnerNonNullStatic=True,serializerKindSameScalarStatic=True,
       normalFactoryQIStaticCounted=True,prerequisiteSpanCount=len(previous.RANGES),newSpanCount=len(bodies),
       selectedSdkKindSetterDeclared=False,setterReturnValueMeaningVerified=False,
       returnedDefaultKindRuntimeVerified=False,receiverOwnershipRuntimeVerified=False,
       ownerNullRuntimeVerified=False,canaryRuntimeVerified=False,templateReadbackVerified=False,
       reportFlagsSemanticEncodingVerified=False,readOnlyMultilineEncodingVerified=False,
       noTransitiveUiEffectsVerified=False,fullTransitiveCtorEffectsVerified=False,
       exceptionUnwindVerified=False,candidateNativePermit=False,nativePermit=False,writerAuthorized=False)


def verify(read,members):
    need(callable(read),'READER_REQUIRED');previous.verify_sdk(members);old={};bodies={}
    for target,ranges in ((old,previous.RANGES),(bodies,RANGES)):
        for name,(r,n,sha)in ranges.items():
            try:raw=read(r,n)
            except Exception:raise ValueError('V144_SPAN_UNAVAILABLE')from None
            need(type(raw)is bytes and len(raw)==n and hashlib.sha256(raw).hexdigest()==sha,'SPAN_HASH')
            target[name]=raw
    return verify_linkage(bodies,old)


def verify_static():
    """Explicit local PE/SDK reads; no native adapter, loader, SDK runtime or IB."""
    need(hashlib.sha256(PREVIOUS_PATH.read_bytes()).hexdigest()==PREVIOUS_SHA,'PREREQUISITE_CHANGED')
    # Existing facade exclusion/name/persistence evidence remains fixed too.
    previous.verify_static()
    image=PE('mngcore.dll')
    def read(r,n):
        at=image.offset(image.base+r);return image.data[at:at+n]
    return verify(read,previous.sdk_members())
