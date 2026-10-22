"""Pure bounded V145 own-memory proof, with no native or filesystem authority.

Trusted readers are supplied by a future dedicated controller. This guard
never acquires handles, reads a connection, loads a DLL or invokes a command.
"""
import hashlib
import json
import re

PHASES=('beforeProcess','afterProcess','beforeSourceFactory','afterSourceFactory',
 'beforeSourceQI','afterSourceQI','beforeSourceInspect','afterSourceInspect','beforeSourceRegistry','afterSourceRegistry',
 'beforeTypeSetter','afterTypeSetter','beforeSourceReadback','afterSourceReadback','beforeSourceSerialize','afterSourceSerialize',
 'beforeCloneFactory','afterCloneFactory','beforeCloneQI','afterCloneQI','beforeCloneInspect','afterCloneInspect',
 'beforeCloneRegistry','afterCloneRegistry','beforeDeserialize','afterDeserialize','beforeCloneReadback','afterCloneReadback',
 'beforeCloneSerialize','afterCloneSerialize','beforeCompare','afterCompare','beforeKnownRelease','afterKnownRelease','beforeScopeExit','afterScopeExit')
MARKER_LIMIT=1024
RESULT_LIMIT=32768
BINARY_LIMIT=1048576
PREFIX='owned-managed-input-record-v145-'
REGISTRIES=(PREFIX+'source-registry.json',PREFIX+'clone-registry.json')
BINARIES=(PREFIX+'source.bin',PREFIX+'clone.bin')
OUTER='77ffcc29-7f2d-4223-b22f-19666e7250ba'
PAYLOAD='f9177e1e-8eee-43a1-a2b6-e7b0aeab28e3'
MODEL='21c27390-7ec5-4b11-a2fa-a2e44d4dab82'
ZERO_COUNTERS=('goldSourceWrites','goldSaves','repositoryWrites','databaseUpdates','businessCalls','metadataWrites')
FALSE_CLAIMS=('nativeException','returnUnknown','nativePermit','writerAuthorized','runtimeVerified','templateVerified',
 'flagsVerified','independentBackingVerified','fallbackNotInvokedVerified','transitiveEffectsVerified')
SUCCESS_BOOLS=('consumed','ownRoundtripVerified','ownScopeExited','processContextVerified','factoryCanaryVerified',
 'queryCanaryVerified','sourceRegistryVerified','cloneRegistryVerified','sourcePayloadVerified','clonePayloadVerified','bytesEqual','inputConsumed')
COUNTERS={'processCalls':1,'outerFactoryCalls':2,'memoryFactoryCalls':2,'outStorageFactoryCalls':2,'inStorageFactoryCalls':1,
 'rawQueryCalls':9,'countedAdoptions':16,'kindSetterCalls':1,'serializeCalls':2,'deserializeCalls':1,
 'storageCloseCalls':3,'bufferReadCalls':2,'clsidCalls':8,'kindGetterCalls':12}
KINDS={'sourceBeforeKind':1,'sourceAfterKind':8,'cloneBeforeKind':1,'cloneAfterKind':8}
IDENTITIES=('sourcePrimary','sourcePersistence','clonePrimary','clonePersistence','sourceMemory','cloneMemory')
STRINGS=('status','operationId','gate','platform','outerClassId','payloadClassId','modelInterfaceId')
FIELDS=set(STRINGS+ZERO_COUNTERS+FALSE_CLAIMS+SUCCESS_BOOLS+IDENTITIES+('sourceBytes','cloneBytes','lifecycle'))|set(COUNTERS)|set(KINDS)
GATES={'disabled','process','sourceFactory','sourceQI','sourceInspect','setter','sourceSerialize','cloneFactory','cloneQI',
 'cloneInspect','deserialize','cloneSerialize','compare','complete'}


def need(ok,code):
    if not ok:raise ValueError('V145_'+code)


def _pairs(pairs):
    value={}
    for key,item in pairs:
        need(key not in value,'DUPLICATE_JSON_KEY');value[key]=item
    return value


def _json(raw,limit):
    need(type(raw)is bytes and 0<len(raw)<=limit,'FILE_BOUND')
    try:
        value=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=_pairs,
            parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
    except Exception:raise ValueError('V145_JSON_REJECTED')from None
    need(type(value)is dict,'JSON_OBJECT');return value


def parse_result(raw):
    value=_json(raw,RESULT_LIMIT);need(value.keys()==FIELDS,'RESULT_FIELDS')
    need(all(type(value[k])is str for k in STRINGS),'STRING_TYPE')
    need(value['status']in ('OWN_INPUT_RECORD_DISABLED_V145','OWN_INPUT_RECORD_UNVERIFIED_V145','OWN_INPUT_RECORD_ROUNDTRIP_VERIFIED_V145')
         and value['gate']in GATES and value['platform']=='8.3.18.1208','RESULT_ENUM')
    need(value['outerClassId']==OUTER and value['payloadClassId']==PAYLOAD and value['modelInterfaceId']==MODEL,'CLASS_ROLE')
    need(value['operationId']=='' or re.fullmatch('[0-9a-f]{32}',value['operationId'])is not None,'OPERATION_ID')
    need(all(type(value[k])is bool for k in FALSE_CLAIMS+SUCCESS_BOOLS),'BOOLEAN_TYPE')
    need(all(type(value[k])is int and value[k]==0 for k in ZERO_COUNTERS),'WRITE_COUNTER')
    need(all(type(value[k])is int and 0<=value[k]<=0xffffffff for k in IDENTITIES),'IDENTITY_TYPE')
    need(all(type(value[k])is int and 0<=value[k]<=maximum for k,maximum in COUNTERS.items()),'CALL_BUDGET')
    need(all(type(value[k])is int and value[k]in (-1,1,8) for k in KINDS),'KIND_TYPE')
    need(all(type(value[k])is int and 0<=value[k]<=BINARY_LIMIT for k in ('sourceBytes','cloneBytes')),'BYTE_BOUND')
    need(type(value['lifecycle'])is list and len(value['lifecycle'])==len(PHASES)
         and all(type(v)is bool for v in value['lifecycle']),'LIFECYCLE_TYPE')
    need(all(value[k]is False for k in ('nativePermit','writerAuthorized','runtimeVerified','templateVerified',
        'flagsVerified','independentBackingVerified','fallbackNotInvokedVerified','transitiveEffectsVerified')),'FALSE_CLAIM')
    if value['nativeException']or value['returnUnknown']:
        need(not value['ownRoundtripVerified'] and not value['ownScopeExited'],'UNKNOWN_RELEASE')
    return value


def marker_filename(phase):
    need(phase in PHASES,'PHASE_UNKNOWN');return PREFIX+phase+'.json'


def _read(reader,name,limit):
    need(callable(reader),'READER_REQUIRED')
    try:raw=reader(name)
    except Exception:raise ValueError('V145_PHYSICAL_MISSING')from None
    return _json(raw,limit),hashlib.sha256(raw).hexdigest()


def verify(info,read_marker,read_binary):
    """Full own record proof only, never a form/type/Gold/capture permit."""
    need(type(info)is dict,'RESULT_OBJECT')
    info=parse_result(json.dumps(info,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8'))
    need(info['status']=='OWN_INPUT_RECORD_ROUNDTRIP_VERIFIED_V145' and info['gate']=='complete','NOT_COMPLETE')
    need(all(info[k]is False for k in FALSE_CLAIMS) and all(info[k]is True for k in SUCCESS_BOOLS),'TERMINAL_FLAGS')
    need(info['operationId']!='' and all(info[k]==v for k,v in COUNTERS.items())
         and all(info[k]==v for k,v in KINDS.items()) and all(info['lifecycle']),'EXACT_COUNTS')
    need(all(info[k]>0 for k in IDENTITIES)
         and len({info[k]for k in IDENTITIES})==6
         and info['sourcePersistence']==info['sourcePrimary']+0x14
         and info['clonePersistence']==info['clonePrimary']+0x14,'OWN_IDENTITY')
    need(info['sourceBytes']==info['cloneBytes'] and info['sourceBytes']>0,'BYTE_LENGTH')
    hashes={}
    for index,phase in enumerate(PHASES):
        name=marker_filename(phase);value,sha=_read(read_marker,name,MARKER_LIMIT)
        need(value.keys()==set(('operationId','phase','index')+ZERO_COUNTERS[:5]),'MARKER_FIELDS')
        need(value['operationId']==info['operationId'] and value['phase']==phase
             and type(value['index'])is int and value['index']==index
             and all(type(value[k])is int and value[k]==0 for k in ZERO_COUNTERS[:5]),'MARKER_SCOPE')
        hashes[name]=sha
    for index,label in enumerate(('source','clone')):
        value,sha=_read(read_marker,REGISTRIES[index],MARKER_LIMIT)
        fields={'operationId','stage','createdOnly','record','classId','primary','persistence','kind','ownerNull','factoryCalls'}|set(ZERO_COUNTERS[:5])
        need(value.keys()==fields and value['operationId']==info['operationId']
             and value['stage']=='beforeOwnWrite' and value['createdOnly']is True and value['record']==label
             and value['classId']==OUTER and value['ownerNull']is True,'REGISTRY_SCOPE')
        need(type(value['primary'])is int and value['primary']==info[label+'Primary']
             and type(value['persistence'])is int and value['persistence']==info[label+'Persistence']
             and type(value['kind'])is int and value['kind']==1
             and type(value['factoryCalls'])is int and value['factoryCalls']==1
             and all(type(value[k])is int and value[k]==0 for k in ZERO_COUNTERS[:5]),'REGISTRY_IDENTITY')
        hashes[REGISTRIES[index]]=sha
    need(callable(read_binary),'BINARY_READER_REQUIRED');binaries=[]
    for label,name in zip(('source','clone'),BINARIES):
        try:raw=read_binary(name)
        except Exception:raise ValueError('V145_BINARY_MISSING')from None
        need(type(raw)is bytes and len(raw)==info[label+'Bytes'] and 0<len(raw)<=BINARY_LIMIT,'BINARY_BOUND')
        hashes[name]=hashlib.sha256(raw).hexdigest();binaries.append(raw)
    need(binaries[0]==binaries[1],'WHOLE_BYTES_DIFFERENT')
    return dict(verified=True,ownMemoryRoundtripVerified=True,physicalReceipts=len(PHASES)+2,
        wholeByteEqualityVerified=True,bytes=len(binaries[0]),physicalHashes=hashes,
        formVerified=False,templateVerified=False,flagsVerified=False,independentBackingVerified=False,
        runtimeVerified=False,nativePermit=False,writerAuthorized=False)
