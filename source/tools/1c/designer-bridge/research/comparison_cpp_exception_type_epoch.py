"""Fixed x86 MSVC metadata-only exception epoch; pure source generation/tests.

Never reads ExceptionInformation[1] (the thrown object). Only exact image-backed
type metadata is decoded. Diagnostic hashes never decide the blocked class.
"""
import hashlib
from pathlib import Path
import re
import struct
import comparison_cpp_exception_epoch as original
from repository_pe_probe import PE

ORIGINAL_SHA='310a2a9ef7bd51c21d6ddc88240cca396c3be147c5a9141f853bd8f3e1df4881'
PROFILE='X86_MSVC_IMAGE_TYPES_LISTSTREAM_CATCHABLE_BASES'
BLOCKED_NAME=b'.?AVListStreamException@core@@'
MAX_EVENTS=32
MAX_TYPES=16
MAX_NAME=96  # Includes terminating NUL; names longer than 95 bytes are unknown.
PRIMARY_URLS=(
 'https://devblogs.microsoft.com/oldnewthing/20100730-00/?p=13273%2F',
 'https://devblogs.microsoft.com/oldnewthing/20160915-00/?p=94316',
 'https://github.com/microsoft/STL/blob/main/stl/src/excptptr.cpp',
 'https://learn.microsoft.com/en-us/windows/win32/api/winnt/nc-winnt-pvectored_exception_handler',
 'https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory',
 'https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery')

TYPE_CODE=r'''
/* Fixed x86 absolute MSVC metadata recipe, NOT a portable EH ABI guarantee.
   No exception object/address/message/what() is read. All candidate reads use
   public safe-copy APIs and require committed readable MEM_IMAGE pages. */
typedef struct {
 DWORD count,hashes[16];BOOL decoded,blocked;
} AhCppTypeEvent;
static AhCppTypeEvent ahCppTypeEvents[32];
static volatile LONG ahCppTypeEventCount=0,ahCppTypeUnknown=0,ahCppTypeDecoded=0;
static volatile LONG ahCppTypeBlocked=0,ahCppTypeOverflow=0,ahCppTypeDecoding=0,ahCppTypeReentry=0;

static BOOL ahCppTypeReadImage(DWORD address,void *destination,DWORD length){
 MEMORY_BASIC_INFORMATION info;SIZE_T copied=0;DWORD protection;
 if(address<65536 || !length || length>96 || (ULONGLONG)address+length>0x100000000ULL)return FALSE;
 if(VirtualQuery((LPCVOID)(uintptr_t)address,&info,sizeof(info))!=sizeof(info)
   || info.State!=MEM_COMMIT || info.Type!=MEM_IMAGE || (info.Protect&(PAGE_GUARD|PAGE_NOACCESS)))return FALSE;
 protection=info.Protect&0xff;
 if(protection!=PAGE_READONLY && protection!=PAGE_READWRITE && protection!=PAGE_WRITECOPY
   && protection!=PAGE_EXECUTE_READ && protection!=PAGE_EXECUTE_READWRITE && protection!=PAGE_EXECUTE_WRITECOPY)return FALSE;
 if((ULONGLONG)address<(ULONGLONG)(uintptr_t)info.BaseAddress
   || (ULONGLONG)address+length>(ULONGLONG)(uintptr_t)info.BaseAddress+info.RegionSize)return FALSE;
 return ReadProcessMemory(GetCurrentProcess(),(LPCVOID)(uintptr_t)address,destination,length,&copied) && copied==length;
}

static BOOL ahCppTypeDecode(DWORD parameters,ULONG_PTR magic,ULONG_PTR throwInfo,AhCppTypeEvent *event){
 DWORD array,count,i,catchable,descriptor,j,hash;unsigned char character;BOOL ended,match;
 static const unsigned char blocked[]=".?AVListStreamException@core@@";
 if(sizeof(void*)!=4 || parameters!=3 || magic!=0x19930520UL || !throwInfo || throwInfo>0xffffffffUL)return FALSE;
 if(!ahCppTypeReadImage((DWORD)throwInfo+12,&array,4) || !ahCppTypeReadImage(array,&count,4) || !count || count>16)return FALSE;
 event->count=count;
 for(i=0;i<count;i++){
  if(!ahCppTypeReadImage(array+4+4*i,&catchable,4) || !ahCppTypeReadImage(catchable+4,&descriptor,4))return FALSE;
  hash=2166136261UL;ended=FALSE;match=TRUE;
  for(j=0;j<96;j++){
   if(!ahCppTypeReadImage(descriptor+8+j,&character,1))return FALSE;
   if(!character){ended=TRUE;if(!j)return FALSE;break;}
   if(character<32 || character>126 || (!j && character!='.'))return FALSE;
   hash=(hash^character)*16777619UL;
   if(j>=sizeof(blocked)-1 || character!=blocked[j])match=FALSE;
  }
  if(!ended)return FALSE;
  event->hashes[i]=hash;
  if(match && j==sizeof(blocked)-1)event->blocked=TRUE;
 }
 event->decoded=TRUE;return TRUE;
}

/* No formatting, file/UI calls, allocation, callback/QI or unknown method call.
   Other-thread throws are conservatively unknown and never mutate event rows.
   A nested decoder marks the epoch unknown, then continues exception search. */
static LONG CALLBACK ahCppEpochHandler(PEXCEPTION_POINTERS details){
 DWORD savedError=GetLastError();
 if(InterlockedCompareExchange(&ahCppEpochActive,0,0) && details && details->ExceptionRecord){
  DWORD thread=GetCurrentThreadId();LONG count,index;AhCppTypeEvent *event;
  if(details->ExceptionRecord->ExceptionCode==0xe06d7363UL){
   count=InterlockedIncrement(&ahCppEpochCpp);
   if(thread==ahCppEpochThread){
    InterlockedIncrement(&ahCppEpochCppGui);index=InterlockedIncrement(&ahCppTypeEventCount)-1;
    if(index<0 || index>=32){InterlockedExchange(&ahCppTypeOverflow,1);InterlockedIncrement(&ahCppTypeUnknown);}
    else if(InterlockedCompareExchange(&ahCppTypeDecoding,1,0)!=0){InterlockedExchange(&ahCppTypeReentry,1);InterlockedIncrement(&ahCppTypeUnknown);}
    else{
     event=&ahCppTypeEvents[index];
     if(ahCppTypeDecode(details->ExceptionRecord->NumberParameters,details->ExceptionRecord->ExceptionInformation[0],
          details->ExceptionRecord->ExceptionInformation[2],event)){
      InterlockedIncrement(&ahCppTypeDecoded);if(event->blocked)InterlockedIncrement(&ahCppTypeBlocked);
     }else InterlockedIncrement(&ahCppTypeUnknown);
     InterlockedExchange(&ahCppTypeDecoding,0);
    }
   }else{InterlockedIncrement(&ahCppEpochCppOther);InterlockedIncrement(&ahCppTypeUnknown);}
  }else{
   count=InterlockedIncrement(&ahCppEpochOther);
   if(thread==ahCppEpochThread)InterlockedIncrement(&ahCppEpochOtherGui);
   else InterlockedIncrement(&ahCppEpochOtherOther);
  }
  if(count<=0)InterlockedExchange(&ahCppEpochOverflow,1);
 }
 SetLastError(savedError);return EXCEPTION_CONTINUE_SEARCH;
}

/* Called only BEFORE Execute or AFTER callback return/removal; never in VEH.
   Every format call is bounded by a small fixed row. No symbol text is emitted. */
static int ahCppTypeAppendReceipt(char *output,int capacity,int used){
 LONG i,j,count=ahCppTypeEventCount;int added;
 if(used<0 || used>capacity-1024)return -1;
 added=wsprintfA(output+used,
  "\"typeDecoderProfile\":\"X86_MSVC_IMAGE_TYPES_LISTSTREAM_CATCHABLE_BASES\",\"typeMetadataOnly\":true,\"exceptionObjectRead\":false,"
  "\"hashAlgorithm\":\"FNV1A32_OBSERVATION_ONLY\",\"maximumTypeEvents\":32,\"maximumCatchableTypes\":16,\"maximumNameBytes\":96,"
  "\"typeEventCount\":%ld,\"decodedCppThrows\":%ld,\"unknownCppThrows\":%ld,\"listStreamCompatibleThrows\":%ld,\"typeEventOverflow\":%s,\"typeDecoderReentry\":%s,"
  "\"allCppExceptionFree\":false,\"listStreamPathExceptionFreeVerified\":false,\"typeEvents\":[",
  count,ahCppTypeDecoded,ahCppTypeUnknown,ahCppTypeBlocked,ahCppTypeOverflow?"true":"false",ahCppTypeReentry?"true":"false");
 if(added<=0 || added>=1024)return -1;used+=added;
 if(count<0)return -1;if(count>32)count=32;
 for(i=0;i<count;i++){
  AhCppTypeEvent *event=&ahCppTypeEvents[i];
  if(used>capacity-1024)return -1;
  added=wsprintfA(output+used,"%s{\"decoded\":%s,\"allCatchableTypesExamined\":%s,\"listStreamCompatible\":%s,\"catchableTypeCount\":%lu,\"primaryTypeNameHash\":\"%08lx\",\"typeNameHashes\":[",
   i?",":"",event->decoded?"true":"false",event->decoded?"true":"false",event->blocked?"true":"false",event->count,event->hashes[0]);
  if(added<=0 || added>=1024)return -1;used+=added;
  for(j=0;j<(LONG)event->count && j<16;j++){
   if(used>capacity-32)return -1;
   added=wsprintfA(output+used,"%s\"%08lx\"",j?",":"",event->hashes[j]);
   if(added<=0 || added>=32)return -1;used+=added;
  }
  if(used>capacity-4)return -1;output[used++]=']';output[used++]='}';
 }
 if(used>capacity-4)return -1;output[used++]=']';output[used++]='}';output[used]=0;return used;
}
'''


def need(ok,code):
    if not ok:raise ValueError('CPP_EXCEPTION_TYPE_EPOCH_'+code)


def verify_primary():
    need(hashlib.sha256(Path(original.__file__).read_bytes()).hexdigest()==ORIGINAL_SHA,'ORIGINAL_PIN')
    pe=PE('frntend.dll');at=pe.offset(pe.base+0xe0ba48);raw=pe.data[at:at+39]
    need(hashlib.sha256(raw).hexdigest()=='242b9b5442fdb3e311cc985741d7b579b32ce77f7e4a9c2d6b39f8c5975b1fe7'
         and raw[8:]==BLOCKED_NAME+b'\0','CAUGHT_SYMBOL_PIN')
    return dict(pointerBits=32,throwInfoArrayOffset=12,arrayFirstOffset=4,catchableDescriptorOffset=4,
                descriptorNameOffset=8,targetSymbolSha256=hashlib.sha256(BLOCKED_NAME).hexdigest(),
                implementationDetail=True,liveVerified=False)


def render():
    """Return a NEW fixed C derivative; never write, compile, load or run it."""
    verify_primary();source=original.render().decode()
    start=source.index('static LONG CALLBACK ahCppEpochHandler(')
    end=source.index('static BOOL ahCppEpochHex(',start)
    source=source[:start]+TYPE_CODE+'\n'+source[end:]
    changes=(
      ('COMPARISON_CPP_EXCEPTION_EPOCH','COMPARISON_CPP_EXCEPTION_TYPE_EPOCH'),
      ('char output[2048]','char output[32768]'),
      ('\\"databaseUpdateAuthorized\\":false}', '\\"databaseUpdateAuthorized\\":false,'),
      ('length+=tail;\n zero.QuadPart=0;',
       'length+=tail;\n length=ahCppTypeAppendReceipt(output,sizeof(output),length);if(length<=0)return FALSE;\n zero.QuadPart=0;'),
      ('static BOOL ahCppEpochBegin(void) {\n HMODULE kernel;',
       'static BOOL ahCppEpochBegin(void) {\n HMODULE kernel;\n if(sizeof(void*)!=4)return FALSE;'))
    for old,new in changes:
        need(source.count(old)==1,'FIXED_ANCHOR');source=source.replace(old,new,1)
    return source.encode()


def _fnv(raw):
    value=2166136261
    for byte in raw:value=((value^byte)*16777619)&0xffffffff
    return f'{value:08x}'


def decode_x86_metadata(read_image,*,code,parameters):
    """Pure model using an image-only bounded reader; returns hashes, no names.

    This is a synthetic/offline testing interface, not a live address API.
    The caller's reader must reject non-image or inaccessible memory.
    """
    need(type(code) is int and code==0xe06d7363 and type(parameters) in (tuple,list)
         and len(parameters)==3 and type(parameters[0]) is int and parameters[0]==0x19930520,'NON_MSVC_X86')
    def read(address,length):
        need(type(address) is int and 65536<=address<=0xffffffff and 1<=length<=96
             and address+length<=0x100000000,'METADATA_RANGE')
        raw=read_image(address,length)
        need(type(raw) is bytes and len(raw)==length,'METADATA_UNREADABLE')
        return raw
    def word(address):return struct.unpack('<I',read(address,4))[0]
    need(type(parameters[2]) is int and parameters[2]>0,'NULL_THROWINFO')
    array=word(parameters[2]+12);count=word(array)
    need(1<=count<=MAX_TYPES,'CATCHABLE_BOUND')
    hashes=[];blocked=False
    for index in range(count):
        catchable=word(array+4+4*index);descriptor=word(catchable+4);name=bytearray()
        for offset in range(MAX_NAME):
            byte=read(descriptor+8+offset,1)[0]
            if byte==0:break
            need(32<=byte<=126 and (offset!=0 or byte==46),'TYPE_NAME_FORMAT');name.append(byte)
        else:raise ValueError('CPP_EXCEPTION_TYPE_EPOCH_NAME_BOUND')
        need(bool(name),'EMPTY_NAME')
        blocked=blocked or bytes(name)==BLOCKED_NAME;hashes.append(_fnv(name))
    return dict(decoded=True,allCatchableTypesExamined=True,listStreamCompatible=blocked,
                catchableTypeCount=count,primaryTypeNameHash=hashes[0],typeNameHashes=hashes)


def classify_type_epoch(receipt,*,operation_id,scope_sha256,process_id,execute_thread_id,
                        callback_known,callback_sdk_rc,target_identity_verified):
    """Prove only absence of the ListStream catch-compatible class in this epoch."""
    need(type(receipt) is dict and type(operation_id) is str and type(scope_sha256) is str
         and re.fullmatch('[0-9a-f]{32}',operation_id) is not None
         and re.fullmatch('[0-9a-f]{64}',scope_sha256) is not None
         and receipt.get('kind')=='COMPARISON_CPP_EXCEPTION_TYPE_EPOCH'
         and receipt.get('operationId')==operation_id and receipt.get('scopeSha256')==scope_sha256,'BINDING')
    need(type(process_id) is int and process_id>0 and type(execute_thread_id) is int and execute_thread_id>0
         and type(receipt.get('processId')) is int and receipt['processId']==process_id
         and type(receipt.get('executeThreadId')) is int and receipt['executeThreadId']==execute_thread_id
         and callback_known is True and target_identity_verified is True and type(callback_sdk_rc) is int
         and callback_sdk_rc==0,'IDENTITY_OR_CALLBACK')
    need(receipt.get('phase')=='EXECUTE_RETURNED' and type(receipt.get('sdkExecuteRc')) is int and receipt['sdkExecuteRc']==0
         and all(receipt.get(k) is True for k in ('handlerRegistered','handlerRemoved','executeEntered','executeReturned',
             'selfReferenceRetained','dllMustRemainLoadedUntilProcessExit','typeMetadataOnly')),'LIFECYCLE')
    need(receipt.get('handlerReturn')=='CONTINUE_SEARCH' and receipt.get('epochCoverage')=='synchronous_context_Execute'
         and receipt.get('typeDecoderProfile')==PROFILE and receipt.get('hashAlgorithm')=='FNV1A32_OBSERVATION_ONLY'
         and all(receipt.get(k) is False for k in ('counterOverflow','typeEventOverflow','typeDecoderReentry',
             'futureOtherThreadBarrierVerified','exceptionDetailsCaptured','exceptionObjectRead','scopeSourceBindingVerified',
             'fullPendingVerified','databaseUpdateAuthorized','allCppExceptionFree','listStreamPathExceptionFreeVerified')),'COVERAGE_OR_EXCESS_CLAIM')
    for key,value in (('maximumTypeEvents',MAX_EVENTS),('maximumCatchableTypes',MAX_TYPES),('maximumNameBytes',MAX_NAME)):
        need(type(receipt.get(key)) is int and receipt[key]==value,'FIXED_LIMITS')
    zero=('cppThrowsOtherThreads','otherExceptions','otherExceptionsExecuteThread','otherExceptionsOtherThreads',
          'unknownCppThrows','listStreamCompatibleThrows')
    need(all(type(receipt.get(k)) is int and receipt[k]==0 for k in zero),'UNKNOWN_OR_BLOCKED_THROW')
    counts=('cppThrows','cppThrowsExecuteThread','typeEventCount','decodedCppThrows')
    need(all(type(receipt.get(k)) is int for k in counts) and 0<=receipt['cppThrows']<=MAX_EVENTS
         and all(receipt[k]==receipt['cppThrows'] for k in counts),'EVENT_COUNTS')
    rows=receipt.get('typeEvents');need(type(rows) is list and len(rows)==receipt['cppThrows'],'EVENT_ROWS')
    primary_counts={}
    for row in rows:
        need(type(row) is dict and row.get('decoded') is True and row.get('allCatchableTypesExamined') is True
             and row.get('listStreamCompatible') is False and type(row.get('catchableTypeCount')) is int
             and 1<=row['catchableTypeCount']<=MAX_TYPES,'UNKNOWN_EVENT')
        hashes=row.get('typeNameHashes')
        need(type(hashes) is list and len(hashes)==row['catchableTypeCount'] and all(type(h) is str
             and re.fullmatch('[0-9a-f]{8}',h) is not None for h in hashes)
             and row.get('primaryTypeNameHash')==hashes[0],'TYPE_HASH_ROWS')
        primary_counts[hashes[0]]=primary_counts.get(hashes[0],0)+1
    return dict(listStreamPathExceptionFree=True,allCppExceptionFree=False,
                otherKnownTypedCppThrows=receipt['cppThrows'],futureOtherThreadBarrierVerified=False,
                sourceBindingVerified=False,fullPendingVerified=False,databaseUpdateAuthorized=False,
                dllRetainedUntilProcessExit=True,primaryTypeCounts=primary_counts,
                typeHashesSecurityAuthority=False)
