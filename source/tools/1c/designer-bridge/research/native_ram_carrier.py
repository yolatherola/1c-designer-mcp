"""Fixed two-request native RAM carrier rendering; no loading or target I/O.

The DLL executes only its fixed reader on the owned GUI thread. A worker sends
the completed C-owned output afterwards. Rendering itself is pure/offline.
"""
from pathlib import Path
import hashlib
import json
import math
import re
import struct

import comparison_cpp_exception_type_epoch as epoch
from core_as_sdk_probe import Image

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CORE = ROOT / 'build/designer-v43-013dc010bd784e859b1e3ba4def25f3c/runtime/lib/x86/core_as.dll'
EPOCH_SHA = 'e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4'
BODY_CAPACITY = 4194304
HEADER_SIZE = 384
TARGETS = ('176e2552-fd8b-4823-afc0-d17431f2fb7b', '28ecdfc7-083e-4082-b272-efbf7152de5c')
PROPERTY = 'd5963243-262e-4398-b4d7-fb16d06484f6'
IDENTITY_KEYS = {'processId', 'birth', 'guiThreadId', 'engineAddress', 'moduleAddress'}
SLOT_KEYS = {'operationId', 'scopeSha256', 'requestId', 'revision', 'issuedAt', 'validUntil',
             'binding', 'target', 'pipePath', 'serverPid', 'serverBirth', 'epochPath',
             'resultPath', 'armPath', 'callbackPath', 'proofPath'}
BINDING_KEYS = {'root_uuid', 'session_id', 'process_id', 'birth', 'generation', 'source_domain', 'valid_until'}


def need(ok, code):
    if not ok:
        raise ValueError('NATIVE_RAM_CARRIER_' + code)


def _hex(value, size):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None


def _uuid(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None and value != '00000000-0000-0000-0000-000000000000'


def _uint(value):
    return type(value) is int and 0 < value < 2**32


def _time(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def validate_inputs(source, slots, identity):
    """Reject ambiguous joins, excess TTL, bool integers and non-fixed paths."""
    need(type(source) is bytes and 0 < len(source) <= 131072 and b'\0' not in source, 'SOURCE')
    text = source.decode('utf-8', 'strict')
    need(text.count('void ahSafeSavedModuleRam(int_ptr envelope)') == 1, 'SOURCE_ENTRY')
    need(type(identity) is dict and identity.keys() == IDENTITY_KEYS, 'IDENTITY_SCHEMA')
    need(all(_uint(identity[k]) for k in ('processId', 'guiThreadId', 'engineAddress', 'moduleAddress'))
         and _hex(identity['birth'], 16) and identity['birth'] != '0' * 16, 'IDENTITY')
    need(type(slots) is tuple and len(slots) == 2, 'TWO_SLOTS')
    paths = set()
    receipt_parent = None
    for index, slot in enumerate(slots):
        need(type(slot) is dict and slot.keys() == SLOT_KEYS, 'SLOT_SCHEMA')
        need(all(_hex(slot[k], n) for k, n in (('operationId', 32), ('scopeSha256', 64), ('requestId', 32), ('serverBirth', 16)))
             and slot['serverBirth'] != '0' * 16 and _uint(slot['serverPid']), 'SLOT_IDENTITY')
        need(type(slot['revision']) is int and 1 <= slot['revision'] < 2**53, 'REVISION')
        need(_time(slot['issuedAt']) and _time(slot['validUntil'])
             and 0 < slot['validUntil'] - slot['issuedAt'] <= 60, 'TTL')
        binding, target = slot['binding'], slot['target']
        need(type(binding) is dict and binding.keys() == BINDING_KEYS, 'BINDING_SCHEMA')
        need(binding['root_uuid'] == '218b5d00-7e10-486f-874c-73c2368ed5da' and _hex(binding['session_id'], 32) and binding['session_id'] != '0'*32
             and binding['process_id'] == identity['processId'] and type(binding['process_id']) is int
             and binding['birth'] == identity['birth'] and type(binding['generation']) is int
             and 1 <= binding['generation'] < 2**53 and binding['source_domain'] == 'database_saved'
             and _time(binding['valid_until']) and binding['valid_until'] >= slot['validUntil'], 'BINDING_JOIN')
        need(type(target) is dict and target.keys() == {'object_uuid', 'property_uuid'}
             and target['object_uuid'] == TARGETS[index] and target['property_uuid'] == PROPERTY, 'TARGET_JOIN')
        need(type(slot['pipePath']) is str and re.fullmatch(r'\\\\\.\\pipe\\AH1C-RAM-[0-9a-f]{32}', slot['pipePath']) is not None,
             'PIPE_PATH')
        for key in ('epochPath', 'resultPath', 'armPath', 'callbackPath', 'proofPath'):
            path = slot[key]
            need(type(path) is str and re.fullmatch(r'[A-Za-z]:/[A-Za-z0-9_./-]{1,400}', path) is not None
                 and '..' not in path.split('/') and path not in paths, 'RECEIPT_PATH')
            resolved = Path(path).resolve()
            need(resolved.is_relative_to((ROOT/'build').resolve()), 'RECEIPT_BOUNDARY')
            if receipt_parent is None:
                receipt_parent = resolved.parent
            need(resolved.parent == receipt_parent, 'RECEIPT_PARENT')
            paths.add(path)
    need(slots[0]['requestId'] != slots[1]['requestId'] and slots[0]['operationId'] == slots[1]['operationId']
         and slots[0]['scopeSha256'] == slots[1]['scopeSha256']
         and slots[0]['pipePath'] != slots[1]['pipePath'], 'DISTINCT_REQUESTS')
    need(slots[0]['binding'] == slots[1]['binding'] and slots[0]['serverPid'] == slots[1]['serverPid']
         and slots[0]['serverBirth'] == slots[1]['serverBirth'], 'SESSION_JOIN')
    return hashlib.sha256(source).hexdigest()


def _literal(value):
    raw = value.encode('utf-8') if type(value) is str else value
    return '"' + ''.join(chr(c) if 32 <= c < 127 and c not in (34, 92) else '\\%03o' % c for c in raw) + '"'


def _primary():
    need(hashlib.sha256(Path(epoch.__file__).read_bytes()).hexdigest() == EPOCH_SHA, 'EPOCH_PIN')
    image = Image(CORE)
    units = []
    for name, rva, size, pin in (
        ('ahRamSetterCode', 0x984e0, 191, 'fb4fb48e9605d17376238d4adb238551752483313e0c5a38e42d311224be7171'),
    ):
        at = image.offset(rva)
        raw = image.data[at:at + size]
        need(hashlib.sha256(raw).hexdigest() == pin, 'PRIMARY_CODE')
        units.append('static const unsigned char ' + name + '[]={' + ','.join(map(str, raw)) + '};')
    at = image.offset(0x28dd8c)
    for slot, rva in ((1, 0x96eb0), (3, 0x97990), (5, 0x98b40), (15, 0x984e0)):
        need(struct.unpack_from('<I', image.data, at + 4 * slot)[0] == image.base + rva, 'PRIMARY_SLOT')
    at = image.offset(0x28f45c)
    need(struct.unpack_from('<I', image.data, at+8)[0] == image.base+0xd7df0, 'FUNCTION_RELEASE_SLOT')
    return '\n'.join(units)


def _fixed(source, slots, identity):
    rows = []
    for index, slot in enumerate(slots):
        prefix = dict(binding=slot['binding'], target=slot['target'], request_id=slot['requestId'], revision=slot['revision'], valid_until=slot['validUntil'])
        metadata = json.dumps(prefix, separators=(',', ':'), ensure_ascii=True)[:-1] + ','
        values = [_literal(slot[k]) for k in ('operationId', 'scopeSha256', 'requestId')]
        values += [str(slot['revision'] & 0xffffffff) + 'u', str(slot['revision'] >> 32) + 'u', str(index + 1),
                   repr(float(slot['issuedAt'])), repr(float(slot['validUntil']))]
        values += ['L' + _literal(slot['pipePath']), str(slot['serverPid']) + 'u', '0x' + slot['serverBirth'] + 'ULL']
        values += ['L' + _literal(slot[k]) for k in ('epochPath', 'resultPath', 'armPath', 'callbackPath', 'proofPath')]
        values += [_literal(metadata)]
        rows.append('{' + ','.join(values) + '}')
    return r'''
#include <stdio.h>
#include <string.h>
#include <stdint.h>
typedef struct {
 const char *operation,*scope,*nonce;DWORD revisionLow,revisionHigh,selector;
 double issued,valid;const wchar_t *pipe;DWORD serverPid;ULONGLONG serverBirth;
 const wchar_t *epoch,*result,*arm,*callback,*proof;const char *metadata;
} AhRamSlot;
static const AhRamSlot ahRamSlots[2]={''' + ',\n'.join(rows) + r'''};
static const char ahRamSource[]=''' + _literal(source) + r''';
static volatile LONG ahRamCurrent=0;
static volatile LONG ahRamSdkChainEntered=0,ahRamSdkChainReturned=0,ahRamSdkChainComplete=0;
static int ahRamSdkChainRc=-2147483647,ahRamActualExecuteRc=-2147483647;
#undef AH_CPP_EPOCH_OPERATION_ID
#undef AH_CPP_EPOCH_SCOPE_SHA256
#undef AH_CPP_EPOCH_RECEIPT_FILE
#define AH_CPP_EPOCH_OPERATION_ID (ahRamSlots[ahRamCurrent].operation)
#define AH_CPP_EPOCH_SCOPE_SHA256 (ahRamSlots[ahRamCurrent].scope)
#define AH_CPP_EPOCH_RECEIPT_FILE (ahRamSlots[ahRamCurrent].epoch)
typedef char AhRamIdentityPid[(AH_SDK_TARGET_PID==''' + str(identity['processId']) + r''')?1:-1];
typedef char AhRamIdentityBirthLow[(AH_SDK_BIRTH_LOW==''' + str(int(identity['birth'][8:], 16)) + r'''u)?1:-1];
typedef char AhRamIdentityBirthHigh[(AH_SDK_BIRTH_HIGH==''' + str(int(identity['birth'][:8], 16)) + r'''u)?1:-1];
typedef char AhRamIdentityEngine[(AH_SDK_ENGINE_ADDRESS==''' + str(identity['engineAddress']) + r'''u)?1:-1];
typedef char AhRamIdentityModule[(AH_SDK_MODULE_ADDRESS==''' + str(identity['moduleAddress']) + r'''u)?1:-1];
#define AH_RAM_GUI_THREAD ''' + str(identity['guiThreadId']) + '\n'


CARRIER = r'''
/* Fixed bounded two-job session. No SDK method is called on the worker. */
#define AH_RAM_CAPACITY 4194304UL
static volatile LONG ahRamBusy=0,ahRamNext=0,ahRamPoison=0,ahRamCallback=0;
static void *ahRamFunction=0,*ahRamContext=0;
static DWORD ahRamCompiles=0,ahRamContexts=0,ahRamSdkRc=999,ahRamWorkerThread=0;
static HHOOK ahRamHook=0;
static unsigned char *ahRamHeaderBase=0,*ahRamBodyBase=0,*ahRamHeader=0,*ahRamBody=0;
static unsigned char ahRamPrefix[68];
static unsigned char ahRamCompleted[384];
static double ahRamSampled=0;
static DWORD ahRamMetadataBytes=0,ahRamSent=0;
static BOOL ahRamPeerVerified=FALSE,ahRamHookRemoved=FALSE,ahRamBuffersFreed=FALSE;
static BOOL ahRamPipeClosed=TRUE,ahRamDrainCompleted=TRUE;
static BOOL ahRamOutputValid=FALSE;
static BOOL ahRamReadyVerified=FALSE;
/* All possible pending-I/O storage outlives a worker that returns UNKNOWN. */
static OVERLAPPED ahRamIo;
static HANDLE ahRamRetainedPipe=INVALID_HANDLE_VALUE,ahRamRetainedEvent=0;
static unsigned char ahRamReady[40];
static DWORD ahRamFrameHeader[4]={0x43314841,0x314d4152,0,0};
static char ahRamMetadata[16384];
static DWORD ahRamWord(unsigned offset){return *(DWORD*)(ahRamHeader+offset);}
static double ahRamNow(void){LARGE_INTEGER a,b;if(!QueryPerformanceCounter(&a)||!QueryPerformanceFrequency(&b)||b.QuadPart<=0)return -1;return (double)a.QuadPart/(double)b.QuadPart;}
static BOOL ahRamIdentity(void){FILETIME b,e,k,u;return GetCurrentProcessId()==AH_SDK_TARGET_PID
 && GetProcessTimes(GetCurrentProcess(),&b,&e,&k,&u)&&b.dwLowDateTime==AH_SDK_BIRTH_LOW&&b.dwHighDateTime==AH_SDK_BIRTH_HIGH;}
static BOOL ahRamWriteNew(const wchar_t *path,const void *bytes,DWORD length){
 DWORD n=0;BOOL okay;HANDLE h=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
 if(h==INVALID_HANDLE_VALUE)return FALSE;okay=WriteFile(h,bytes,length,&n,0)&&n==length&&FlushFileBuffers(h);CloseHandle(h);return okay;
}
static BOOL ahRamEpochReset(void){
 if(ahCppEpochHandlerToken||ahCppEpochActive||ahCppEpochReceipt!=INVALID_HANDLE_VALUE)return FALSE;
 if(ahRamCurrent && !ahCppEpochRemoved)return FALSE;
 ahCppEpochOnce=ahCppEpochOverflow=ahCppEpochCpp=ahCppEpochCppGui=ahCppEpochCppOther=0;
 ahCppEpochOther=ahCppEpochOtherGui=ahCppEpochOtherOther=0;
 ahCppEpochRegistered=ahCppEpochRemoved=ahCppEpochEntered=ahCppEpochReturned=0;
 ahRamSdkChainEntered=ahRamSdkChainReturned=ahRamSdkChainComplete=0;ahRamSdkChainRc=ahRamActualExecuteRc=-2147483647;
 ahCppTypeEventCount=ahCppTypeUnknown=ahCppTypeDecoded=ahCppTypeBlocked=0;
 ahCppTypeOverflow=ahCppTypeDecoding=ahCppTypeReentry=0;
 memset(ahCppTypeEvents,0,sizeof(ahCppTypeEvents));return TRUE;
}
static BOOL ahRamEpochClean(void){return ahCppEpochReturned&&ahCppEpochRemoved&&!ahCppEpochHandlerToken&&!ahCppEpochActive
 &&ahRamSdkChainEntered&&ahRamSdkChainReturned&&ahRamSdkChainComplete&&!ahRamSdkChainRc&&!ahRamActualExecuteRc
 &&!ahCppEpochOverflow&&!ahCppEpochCpp&&!ahCppEpochOther&&!ahCppTypeUnknown&&!ahCppTypeBlocked&&!ahCppTypeOverflow&&!ahCppTypeReentry;}
static BOOL ahRamAllocate(void){
 unsigned i;const AhRamSlot *s=&ahRamSlots[ahRamCurrent];
 ahRamHeaderBase=VirtualAlloc(0,12288,MEM_RESERVE,PAGE_NOACCESS);
 ahRamBodyBase=VirtualAlloc(0,AH_RAM_CAPACITY+12288,MEM_RESERVE,PAGE_NOACCESS);
 if(!ahRamHeaderBase||!ahRamBodyBase)return FALSE;
 if(!VirtualAlloc(ahRamHeaderBase+4096,4096,MEM_COMMIT,PAGE_READWRITE)
  ||!VirtualAlloc(ahRamBodyBase+4096,AH_RAM_CAPACITY+4096,MEM_COMMIT,PAGE_READWRITE))return FALSE;
 memset(ahRamHeaderBase+4096,0xa5,4096);memset(ahRamBodyBase+4096,0xa5,AH_RAM_CAPACITY+4096);
 ahRamHeader=ahRamHeaderBase+4096+32;ahRamBody=ahRamBodyBase+4096+32;memset(ahRamHeader,0,384);
 *(DWORD*)(ahRamHeader+0)=0x31524d53;*(DWORD*)(ahRamHeader+4)=1;*(DWORD*)(ahRamHeader+8)=384;
 *(DWORD*)(ahRamHeader+12)=s->selector;memcpy(ahRamHeader+16,s->nonce,32);
 *(DWORD*)(ahRamHeader+48)=s->revisionLow;*(DWORD*)(ahRamHeader+52)=s->revisionHigh;
 *(DWORD*)(ahRamHeader+56)=(DWORD)ahRamBody;*(DWORD*)(ahRamHeader+60)=AH_RAM_CAPACITY;
 *(DWORD*)(ahRamHeader+64)=0x91d4a63b;*(DWORD*)(ahRamHeader+380)=0x6b5c28e7;
 memcpy(ahRamPrefix,ahRamHeader,68);return TRUE;
}
static void ahRamFree(void){
 if(ahRamHeaderBase){if(ahRamHeader)SecureZeroMemory(ahRamHeaderBase+4096,4096);VirtualFree(ahRamHeaderBase,0,MEM_RELEASE);}
 if(ahRamBodyBase){if(ahRamBody)SecureZeroMemory(ahRamBodyBase+4096,AH_RAM_CAPACITY+4096);VirtualFree(ahRamBodyBase,0,MEM_RELEASE);}
 ahRamHeaderBase=ahRamBodyBase=ahRamHeader=ahRamBody=0;ahRamBuffersFreed=TRUE;
}
/* Seal BEFORE every unhook/free. A prechecked late callback cannot enter SDK. */
static BOOL ahRamUnhookSealed(void){
 LONG state=InterlockedCompareExchange(&ahRamCallback,2,0);
 BOOL quiescent=state==0||state==2||(state==1&&InterlockedCompareExchange(&callbackDone,0,0));
 if(ahRamHook){ahRamHookRemoved=UnhookWindowsHookEx(ahRamHook);if(ahRamHookRemoved)ahRamHook=0;}
 return quiescent&&!ahRamHook;
}
/* SHA256 on C-owned completed bytes. No provider/library or application call. */
static DWORD ahRamRor(DWORD x,unsigned n){return (x>>n)|(x<<(32-n));}
static void ahRamSha(const unsigned char *body,DWORD length,char out[65]){
 static const DWORD k[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
 DWORD h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 DWORD w[64],v[8],i,j,block,t1,t2,a;unsigned char bytes[64];DWORD blocks=(length+72)/64;
 for(block=0;block<blocks;block++){
  for(i=0;i<64;i++){a=block*64+i;bytes[i]=a<length?body[a]:(a==length?128:0);}
  if(block+1==blocks){ULONGLONG bits=(ULONGLONG)length*8;for(i=0;i<8;i++)bytes[63-i]=(unsigned char)(bits>>(8*i));}
  for(i=0;i<16;i++)w[i]=((DWORD)bytes[4*i]<<24)|((DWORD)bytes[4*i+1]<<16)|((DWORD)bytes[4*i+2]<<8)|bytes[4*i+3];
  for(i=16;i<64;i++)w[i]=w[i-16]+(ahRamRor(w[i-15],7)^ahRamRor(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(ahRamRor(w[i-2],17)^ahRamRor(w[i-2],19)^(w[i-2]>>10));
  memcpy(v,h,sizeof(v));for(i=0;i<64;i++){
   t1=v[7]+(ahRamRor(v[4],6)^ahRamRor(v[4],11)^ahRamRor(v[4],25))+((v[4]&v[5])^(~v[4]&v[6]))+k[i]+w[i];
   t2=(ahRamRor(v[0],2)^ahRamRor(v[0],13)^ahRamRor(v[0],22))+((v[0]&v[1])^(v[0]&v[2])^(v[1]&v[2]));
   for(j=7;j>0;j--)v[j]=v[j-1];v[4]+=t1;v[0]=t1+t2;
  }for(i=0;i<8;i++)h[i]+=v[i];
 }for(i=0;i<32;i++){unsigned c=(h[i/4]>>(24-8*(i%4)))&255;out[2*i]="0123456789abcdef"[c>>4];out[2*i+1]="0123456789abcdef"[c&15];}out[64]=0;
}
static BOOL ahRamHex64(const unsigned char *p){unsigned i;for(i=0;i<64;i++)if(!((p[i]>='0'&&p[i]<='9')||(p[i]>='a'&&p[i]<='f')))return FALSE;return TRUE;}
static BOOL ahRamValidateOutput(void){
 const AhRamSlot *s=&ahRamSlots[ahRamCurrent];DWORD n,points=0,crlf=0,i=0;char hash[65];
 if(!ahRamHeader||!ahRamBody||memcmp(ahRamHeader,ahRamPrefix,68)||ahRamWord(380)!=0x6b5c28e7)return FALSE;
 for(n=0;n<32;n++)if(ahRamHeaderBase[4096+n]!=0xa5||ahRamBodyBase[4096+n]!=0xa5)return FALSE;
 for(n=32+384;n<4096;n++)if(ahRamHeaderBase[4096+n]!=0xa5)return FALSE;
 for(n=32;n<4096;n++)if(ahRamBodyBase[4096+AH_RAM_CAPACITY+n]!=0xa5)return FALSE;
 for(n=148;n<160;n++)if(ahRamHeader[n])return FALSE;
 for(n=332;n<380;n++)if(ahRamHeader[n])return FALSE;
 if(ahRamWord(68)!=1||ahRamWord(72)||ahRamWord(76)>AH_RAM_CAPACITY
  ||ahRamWord(96)!=2||ahRamWord(100)!=2||ahRamWord(104)!=2||ahRamWord(108)!=2||ahRamWord(112)
  ||ahRamWord(116)!=1||ahRamWord(120)!=1||ahRamWord(124)!=1||ahRamWord(128)!=1||ahRamWord(132)
  ||!ahRamWord(136)||ahRamWord(136)>8388608||ahRamWord(140)!=1383504556||ahRamWord(144)!=100051712
  ||memcmp(ahRamHeader+288,s->nonce,32)||ahRamWord(320)!=s->revisionLow||ahRamWord(324)!=s->revisionHigh||ahRamWord(328)!=s->selector
  ||!ahRamHex64(ahRamHeader+160)||!ahRamHex64(ahRamHeader+224))return FALSE;
 n=ahRamWord(76);while(i<n){DWORD lead=ahRamBody[i++],need=0,lo=128,hi=191,c;
  if(!lead)return FALSE;points++;if(points>1048576)return FALSE;if(lead<128)continue;
  if(lead>=194&&lead<=223)need=1;else if(lead>=224&&lead<=239){need=2;if(lead==224)lo=160;if(lead==237)hi=159;}
  else if(lead>=240&&lead<=244){need=3;if(lead==240)lo=144;if(lead==244)hi=143;}else return FALSE;
  if(need>n-i||ahRamBody[i]<lo||ahRamBody[i]>hi)return FALSE;
  for(c=1;c<need;c++)if(ahRamBody[i+c]<128||ahRamBody[i+c]>191)return FALSE;i+=need;
 }
 for(i=0;i+1<n;i++)if(ahRamBody[i]==13&&ahRamBody[i+1]==10)crlf++;
 if(points!=ahRamWord(80)||crlf!=ahRamWord(84)
  ||ahRamWord(88)!=(n>=3&&ahRamBody[0]==239&&ahRamBody[1]==187&&ahRamBody[2]==191)
  ||ahRamWord(92)!=(n>0&&ahRamBody[n-1]==10))return FALSE;
 ahRamSha(ahRamBody,n,hash);return !memcmp(hash,ahRamHeader+160,64);
}
static int ahRamExecute(void){
 HMODULE core=GetModuleHandleW(L"core_as.dll"),snego=GetModuleHandleW(L"snegopat.dll");
 typedef void *(__cdecl *ActiveContext)(void);ActiveContext active;
 void *engine,*module;uint32_t args[5];int rc=0;BOOL contextProven=FALSE,functionProven=FALSE;
 const AhRamSlot *s=&ahRamSlots[ahRamCurrent];double now=ahRamNow();
 if(!ahRamIdentity()||GetCurrentThreadId()!=AH_RAM_GUI_THREAD||now<s->issued||now>s->valid)return 201;
 active=core?(ActiveContext)GetProcAddress(core,"asGetActiveContext"):0;engine=snego?*(void**)((char*)snego+0x37674):0;
 if(!core||!active||engine!=(void*)AH_SDK_ENGINE_ADDRESS)return 202;
 if(!pinned(engine,0x28f184,49,0xc8d00,(unsigned char*)core)||!pinned(engine,0x28f184,50,0xc8d10,(unsigned char*)core)
  ||!pinned(engine,0x28f184,58,0xc8d60,(unsigned char*)core))return 203;
 if(memcmp((char*)core+0x984e0,ahRamSetterCode,sizeof(ahRamSetterCode)))return 205;
 if(!ahRamEpochReset()||!ahCppEpochBegin())return 211;
 ahRamSdkChainEntered=1;InterlockedExchange(&ahCppEpochActive,1);
 if(active()){rc=202;goto sdk_done;}
 if(call(engine,49,0,0)!=1||ahSdkAbiFault){rc=203;goto sdk_done;}
 args[0]=0;module=(void*)call(engine,50,1,args);
 if(ahSdkAbiFault||module!=(void*)AH_SDK_MODULE_ADDRESS||!pinned(module,0x28e454,6,0xa9020,(unsigned char*)core)){rc=204;goto sdk_done;}
 if(!ahRamFunction){
  if(ahRamCompiles){rc=206;goto sdk_done;}args[0]=(uint32_t)"AH1C_FIXED_RAM_READER_V1";args[1]=(uint32_t)ahRamSource;args[2]=args[3]=0;args[4]=(uint32_t)&ahRamFunction;
  rc=(int)call(module,6,5,args);ahRamCompiles++;if(rc<0||!ahRamFunction||ahSdkAbiFault){rc=207;goto sdk_done;}
 }
 functionProven=pinned(ahRamFunction,0x28f45c,2,0xd7df0,(unsigned char*)core);
 if(!functionProven){rc=230;goto sdk_done;}
 ahRamContext=(void*)call(engine,58,0,0);if(!ahRamContext||ahSdkAbiFault){rc=208;goto sdk_done;}ahRamContexts++;
 if(!pinned(ahRamContext,0x28dd8c,15,0x984e0,(unsigned char*)core)||!pinned(ahRamContext,0x28dd8c,3,0x97990,(unsigned char*)core)
  ||!pinned(ahRamContext,0x28dd8c,5,0x98b40,(unsigned char*)core)||!pinned(ahRamContext,0x28dd8c,1,0x96eb0,(unsigned char*)core)){rc=209;goto sdk_done;}
 contextProven=TRUE;
 args[0]=(uint32_t)ahRamFunction;rc=(int)call(ahRamContext,3,1,args);
 if(rc>=0&&!ahSdkAbiFault){args[0]=0;args[1]=(uint32_t)ahRamHeader;rc=(int)call(ahRamContext,15,2,args);}
 if(rc>=0&&!ahSdkAbiFault){
  InterlockedExchange(&ahCppEpochEntered,1);
  rc=(int)call(ahRamContext,5,0,0);ahRamActualExecuteRc=rc;InterlockedExchange(&ahCppEpochReturned,1);
 }else rc=211;
 sdk_done:
 if(ahRamContext&&contextProven&&!ahSdkAbiFault){call(ahRamContext,1,0,0);if(!ahSdkAbiFault)ahRamContext=0;}
 if((ahRamCurrent==1||rc!=0)&&functionProven&&!ahSdkAbiFault&&ahRamFunction){call(ahRamFunction,2,0,0);if(!ahSdkAbiFault)ahRamFunction=0;}
 if(ahSdkAbiFault)rc=212;
 ahRamSdkChainRc=rc;ahRamSdkChainReturned=1;
 ahRamSdkChainComplete=!ahSdkAbiFault&&!ahRamContext&&((ahRamCurrent==0&&rc==0)?ahRamFunction!=0:ahRamFunction==0);
 if(!ahCppEpochEnd(ahRamActualExecuteRc))rc=210;
 if(rc==0){ahRamOutputValid=ahRamEpochClean()&&ahRamValidateOutput();if(!ahRamOutputValid)rc=213;}
 ahRamSampled=ahRamNow();if(ahRamSampled<s->issued||ahRamSampled>s->valid)rc=214;
 return rc;
}
static BOOL ahRamBuildMetadata(void){
 const AhRamSlot *s=&ahRamSlots[ahRamCurrent];int n;
 n=snprintf(ahRamMetadata,sizeof(ahRamMetadata),
  "%s\"sampled_at\":%.9f,\"source_sha256\":\"%.64s\",\"saved_resource_sha256\":\"%.64s\","
  "\"byte_count\":%lu,\"crlf_count\":%lu,\"bom_present\":%s,\"ends_lf\":%s,\"identity_verified\":true,"
  "\"repeated_read_verified\":true,\"schema_verified\":true,\"dirty_before\":\"clean\",\"dirty_after\":\"clean\","
  "\"decoder_profile\":\"FORMAT15_RAM\",\"helper_calls\":0,\"source_writes\":0,\"configuration_saves\":0,\"database_updates\":0,\"repository_mutations\":0}",
  s->metadata,ahRamSampled,ahRamHeader+160,ahRamHeader+224,ahRamWord(76),ahRamWord(84),ahRamWord(88)?"true":"false",ahRamWord(92)?"true":"false");
 if(n<=0||n>=sizeof(ahRamMetadata))return FALSE;ahRamMetadataBytes=(DWORD)n;return TRUE;
}
typedef BOOL (WINAPI *AhRamServerPid)(HANDLE,PULONG);
typedef BOOL (WINAPI *AhRamCancel)(HANDLE,LPOVERLAPPED);
static BOOL ahRamServerLive(HANDLE h){FILETIME b,e,k,u;const AhRamSlot *s=&ahRamSlots[ahRamCurrent];
 return h&&WaitForSingleObject(h,0)==WAIT_TIMEOUT&&GetProcessTimes(h,&b,&e,&k,&u)&&(((ULONGLONG)b.dwHighDateTime<<32)|b.dwLowDateTime)==s->serverBirth;}
static BOOL ahRamDrain(HANDLE h,DWORD *n){
 BOOL okay=GetOverlappedResult(h,&ahRamIo,n,TRUE);DWORD error=okay?0:GetLastError();
 ahRamDrainCompleted=okay||error==ERROR_OPERATION_ABORTED||error==ERROR_BROKEN_PIPE||error==ERROR_NO_DATA||error==ERROR_PIPE_NOT_CONNECTED;
 return okay;
}
static BOOL ahRamTransfer(HANDLE h,unsigned char *bytes,DWORD length,HANDLE event,AhRamCancel cancel,double deadline,BOOL reading){
 DWORD at=0,n,error,wait;double left,now;BOOL okay;
 while(at<length){now=ahRamNow();if(now<0)return FALSE;left=deadline-now;if(left<=0)return FALSE;memset(&ahRamIo,0,sizeof(ahRamIo));ahRamIo.hEvent=event;if(!ResetEvent(event))return FALSE;
  n=0;if(reading)okay=ReadFile(h,bytes+at,length-at>65536?65536:length-at,&n,&ahRamIo);
  else okay=WriteFile(h,bytes+at,length-at>65536?65536:length-at,&n,&ahRamIo);
  if(!okay){error=GetLastError();if(error!=ERROR_IO_PENDING)return FALSE;ahRamDrainCompleted=FALSE;
   now=ahRamNow();left=now<0?0:deadline-now;wait=left<=0?0:(DWORD)(left*1000);if(wait>30000)wait=30000;
   if(!wait||WaitForSingleObject(event,wait)!=WAIT_OBJECT_0){
    cancel(h,&ahRamIo);ahRamDrain(h,&n);return FALSE;
   }
   okay=ahRamDrain(h,&n);if(!okay)return FALSE;
  }if(!n||n>length-at)return FALSE;at+=n;if(!reading)ahRamSent+=n;
 }return TRUE;
}
static BOOL ahRamWriteOverlapped(HANDLE h,const unsigned char *bytes,DWORD length,HANDLE event,AhRamCancel cancel,double deadline){
 return ahRamTransfer(h,(unsigned char*)bytes,length,event,cancel,deadline,FALSE);
}
static BOOL ahRamSend(void){
 const AhRamSlot *s=&ahRamSlots[ahRamCurrent];HMODULE kernel=GetModuleHandleW(L"kernel32.dll");
 AhRamServerPid pid=(AhRamServerPid)GetProcAddress(kernel,"GetNamedPipeServerProcessId");
 AhRamCancel cancel=(AhRamCancel)GetProcAddress(kernel,"CancelIoEx");HANDLE process=0,pipe=INVALID_HANDLE_VALUE,event=0;
 DWORD observed=0;BOOL okay=FALSE;double now=ahRamNow(),deadline=now+30;
 if(deadline>s->valid)deadline=s->valid;
 if(GetCurrentThreadId()==AH_RAM_GUI_THREAD||!pid||!cancel||now<0||ahRamNow()>=deadline||!ahRamBuildMetadata())return FALSE;
 process=OpenProcess(0x1000|SYNCHRONIZE,FALSE,s->serverPid);if(!ahRamServerLive(process))goto done;
 pipe=CreateFileW(s->pipe,GENERIC_READ|GENERIC_WRITE|0x80,0,0,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|0x00110000,0);
 if(pipe==INVALID_HANDLE_VALUE)goto done;ahRamPipeClosed=FALSE;
 if(!pid(pipe,&observed)||observed!=s->serverPid||!ahRamServerLive(process))goto done;ahRamPeerVerified=TRUE;
 event=CreateEventW(0,TRUE,FALSE,0);if(!event)goto done;
 if(!ahRamTransfer(pipe,ahRamReady,40,event,cancel,deadline,TRUE)
  ||memcmp(ahRamReady,"AH1CRDY1",8)||memcmp(ahRamReady+8,s->nonce,32)||!ahRamServerLive(process))goto done;
 ahRamReadyVerified=TRUE;ahRamFrameHeader[2]=ahRamMetadataBytes;ahRamFrameHeader[3]=ahRamWord(76);
 okay=ahRamWriteOverlapped(pipe,(unsigned char*)ahRamFrameHeader,16,event,cancel,deadline)
  &&ahRamWriteOverlapped(pipe,(unsigned char*)ahRamMetadata,ahRamMetadataBytes,event,cancel,deadline)
  &&ahRamWriteOverlapped(pipe,ahRamBody,ahRamWord(76),event,cancel,deadline)
  &&ahRamServerLive(process)&&ahRamNow()<=deadline;
 done:if(ahRamDrainCompleted){if(event)CloseHandle(event);if(pipe!=INVALID_HANDLE_VALUE){CloseHandle(pipe);ahRamPipeClosed=TRUE;}}
 else{ahRamRetainedPipe=pipe;ahRamRetainedEvent=event;}
 if(process)CloseHandle(process);return okay;
}
static BOOL ahRamProof(DWORD rc){
 char out[2048];int n;const AhRamSlot *s=&ahRamSlots[ahRamCurrent];
 n=snprintf(out,sizeof(out),"{\"kind\":\"NATIVE_RAM_CARRIER\",\"operationId\":\"%s\",\"scopeSha256\":\"%s\",\"requestId\":\"%s\","
  "\"job\":%ld,\"processId\":%lu,\"guiThreadId\":%u,\"workerThreadId\":%lu,\"sdkRc\":%lu,\"compileCount\":%lu,\"contextCount\":%lu,"
  "\"contextCleared\":%s,\"functionRetained\":%s,\"handlerRemoved\":%s,\"epochClean\":%s,\"hookRemoved\":%s,\"peerVerified\":%s,"
  "\"pipeClosed\":%s,\"drainCompleted\":%s,\"buffersFreed\":%s,\"readyVerified\":%s,\"frameBytesWritten\":%lu,\"sampledAt\":%.9f,\"terminalRc\":%lu,"
  "\"nativeStatus\":%lu,\"nativeReason\":%lu,\"bodyBytes\":%lu,\"pendingReference\":%lu,\"typedCleared\":%lu,\"nativeException\":%lu,"
  "\"nativeEnvelopeValid\":%s,\"codePoints\":%lu,\"crlfCount\":%lu,\"bomPresent\":%lu,\"endsLf\":%lu,\"passes\":%lu,\"propertyReads\":%lu,\"fileOpens\":%lu,\"adoptedFiles\":%lu,"
  "\"beforeClean\":%lu,\"afterClean\":%lu,\"prefixPreserved\":%lu,\"storedBytes\":%lu,\"databaseRoot\":%lu,\"databaseManager\":%lu,\"sourceSha256\":\"%.64s\",\"savedResourceSha256\":\"%.64s\"}",
  s->operation,s->scope,s->nonce,ahRamCurrent,GetCurrentProcessId(),AH_RAM_GUI_THREAD,ahRamWorkerThread,ahRamSdkRc,ahRamCompiles,ahRamContexts,
  ahRamContext?"false":"true",ahRamFunction?"true":"false",ahCppEpochRemoved?"true":"false",ahRamEpochClean()?"true":"false",ahRamHookRemoved?"true":"false",
  ahRamPeerVerified?"true":"false",ahRamPipeClosed?"true":"false",ahRamDrainCompleted?"true":"false",ahRamBuffersFreed?"true":"false",ahRamReadyVerified?"true":"false",ahRamSent,ahRamSampled,rc,
  *(DWORD*)(ahRamCompleted+68),*(DWORD*)(ahRamCompleted+72),*(DWORD*)(ahRamCompleted+76),*(DWORD*)(ahRamCompleted+112),*(DWORD*)(ahRamCompleted+128),*(DWORD*)(ahRamCompleted+132),
  ahRamOutputValid?"true":"false",*(DWORD*)(ahRamCompleted+80),*(DWORD*)(ahRamCompleted+84),*(DWORD*)(ahRamCompleted+88),*(DWORD*)(ahRamCompleted+92),
  *(DWORD*)(ahRamCompleted+96),*(DWORD*)(ahRamCompleted+100),*(DWORD*)(ahRamCompleted+104),*(DWORD*)(ahRamCompleted+108),*(DWORD*)(ahRamCompleted+116),*(DWORD*)(ahRamCompleted+120),
  *(DWORD*)(ahRamCompleted+124),*(DWORD*)(ahRamCompleted+136),*(DWORD*)(ahRamCompleted+140),*(DWORD*)(ahRamCompleted+144),
  ahRamOutputValid?(char*)ahRamCompleted+160:"",ahRamOutputValid?(char*)ahRamCompleted+224:"");
 return n>0&&n<sizeof(out)&&ahRamWriteNew(s->proof,out,(DWORD)n);
}
__declspec(dllexport) LRESULT CALLBACK ahSdkHook(int code,WPARAM w,LPARAM l){
 if(code>=0&&l&&ahRamIdentity()&&((MSG*)l)->message==AH_SDK_MESSAGE&&GetCurrentThreadId()==AH_RAM_GUI_THREAD
  &&InterlockedCompareExchange(&ahRamCallback,1,0)==0){
  DWORD fields[6]={GetCurrentProcessId(),GetCurrentThreadId(),(DWORD)code,((MSG*)l)->message,AH_RAM_GUI_THREAD,1};
  if(!ahRamWriteNew(ahRamSlots[ahRamCurrent].callback,fields,sizeof(fields)))ahRamSdkRc=215;
  else ahRamSdkRc=(DWORD)ahRamExecute();InterlockedExchange(&callbackDone,1);
 }return CallNextHookEx(0,code,w,l);
}
__declspec(dllexport) DWORD WINAPI ahSdkArmOwnThread(LPVOID argument){
 DWORD arm[2]={0,0},thread=(DWORD)argument,started,rc=216;HANDLE h;MSG msg;HMODULE kernel;
 typedef DWORD (WINAPI *ThreadOwner)(HANDLE);ThreadOwner owner;
 if(InterlockedCompareExchange(&ahRamBusy,1,0)!=0)return 217;
 if(ahRamPoison||!ahRamIdentity()||thread!=AH_RAM_GUI_THREAD||ahRamNext>=2){InterlockedExchange(&ahRamBusy,0);return 218;}
 ahRamCurrent=ahRamNext++;ahRamWorkerThread=GetCurrentThreadId();callbackDone=0;ahRamCallback=0;ahRamSdkRc=999;
 memset(ahRamCompleted,0,sizeof(ahRamCompleted));
 ahRamPeerVerified=ahRamHookRemoved=ahRamBuffersFreed=ahRamOutputValid=ahRamReadyVerified=FALSE;ahRamPipeClosed=ahRamDrainCompleted=TRUE;ahRamSent=0;ahRamSampled=0;
 if(!ahCppEpochSelfReference&&!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(LPCWSTR)(uintptr_t)&ahSdkHook,&ahCppEpochSelfReference)){rc=229;goto done;}
 if(!ahRamAllocate()){rc=219;goto done;}
 h=OpenThread(0x0040,FALSE,thread);kernel=GetModuleHandleW(L"kernel32.dll");owner=(ThreadOwner)GetProcAddress(kernel,"GetProcessIdOfThread");
 if(!h||!owner||owner(h)!=GetCurrentProcessId()){if(h)CloseHandle(h);rc=220;goto done;}CloseHandle(h);
 ahRamHook=SetWindowsHookExW(3,ahSdkHook,0,thread);if(!ahRamHook){arm[0]=3;arm[1]=GetLastError();rc=221;}
 if(!ahRamWriteNew(ahRamSlots[ahRamCurrent].arm,arm,8)){rc=222;goto done;}if(!ahRamHook)goto done;
 started=GetTickCount();while(!callbackDone&&GetTickCount()-started<30000){
  while(PeekMessageW(&msg,0,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessageW(&msg);}Sleep(1);
 }
 if(!callbackDone){rc=223;goto done;}
 if(!ahRamUnhookSealed()||!ahRamHookRemoved||ahRamSdkRc||ahRamContext||!ahRamEpochClean()){rc=224;goto done;}
 if(!ahRamSend()){rc=225;goto done;}rc=0;
 done:if(ahRamUnhookSealed()&&!ahRamContext&&!ahSdkAbiFault&&ahRamDrainCompleted){if(ahRamHeader)memcpy(ahRamCompleted,ahRamHeader,384);ahRamFree();}else rc=226;
 if(rc)InterlockedExchange(&ahRamPoison,1);
 if(!ahRamProof(rc))rc=227;
 if(!ahRamWriteNew(ahRamSlots[ahRamCurrent].result,&rc,4))rc=228;
 if(rc)InterlockedExchange(&ahRamPoison,1);InterlockedExchange(&ahRamBusy,0);return rc?2:1;
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved){if(reason==DLL_PROCESS_ATTACH)sdkInstance=instance;return TRUE;}
'''


def render(source: bytes, *, slots: tuple, identity: dict) -> bytes:
    """Emit one compile-fixed two-request DLL source, without any file write."""
    validate_inputs(source, slots, identity)
    primary = _primary()
    parent = epoch.render().decode('utf-8')
    at = parent.index('static int execute(')
    prefix = parent[:at]
    anchor = '#include "sdk_probe_params.h"'
    need(prefix.count(anchor) == 1, 'INCLUDE_ANCHOR')
    prefix = prefix.replace(anchor, anchor + '\n' + _fixed(source, slots, identity) + primary, 1)
    anchor = 'if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,'
    need(prefix.count(anchor) == 1, 'SELF_REFERENCE_ANCHOR')
    prefix = prefix.replace(anchor, 'if(!ahCppEpochSelfReference && !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,', 1)
    for old,new in (
        ('COMPARISON_CPP_EXCEPTION_TYPE_EPOCH','NATIVE_RAM_SDK_CHAIN_CPP_EXCEPTION_TYPE_EPOCH'),
        ('synchronous_context_Execute','synchronous_gui_sdk_chain'),
        ('"EXECUTE_RESERVED"','"SDK_CHAIN_RESERVED"'),
        ('"EXECUTE_RETURNED"','"SDK_CHAIN_RETURNED"'),
        (' InterlockedExchange(&ahCppEpochReturned,1);\n',''),
        (' removed=ahCppEpochRemove();\n',' removed=ahCppEpochRemove();\n if(!removed)ahRamSdkChainComplete=0;\n'),
    ):
        need(prefix.count(old)==1,'SDK_CHAIN_SCHEMA_ANCHOR')
        prefix=prefix.replace(old,new,1)
    anchor=' added=wsprintfA(output+used,\n  "\\\"typeDecoderProfile'
    need(prefix.count(anchor)==1,'SDK_CHAIN_FIELDS_ANCHOR')
    prefix=prefix.replace(anchor,
        ' added=wsprintfA(output+used,"\\\"sdkChainEntered\\\":%s,\\\"sdkChainReturned\\\":%s,\\\"sdkChainComplete\\\":%s,\\\"sdkChainRc\\\":%d,",\n'
        '  ahRamSdkChainEntered?"true":"false",ahRamSdkChainReturned?"true":"false",ahRamSdkChainComplete?"true":"false",ahRamSdkChainRc);\n'
        ' if(added<=0||added>=256)return -1;used+=added;\n'+anchor,1)
    return (prefix + '\n' + CARRIER).encode('utf-8')


def classify_epoch(row, *, operation_id, scope_sha256, process_id, execute_thread_id,
                   callback_known, callback_sdk_rc, target_identity_verified):
    """Validate NEW whole-SDK-chain scope, then reuse common EH checks privately.

    Normalization is only a local validator adapter. No original receipt is
    relabelled or written, and an old Execute-only receipt is always rejected.
    """
    need(type(row) is dict and row.get('kind')=='NATIVE_RAM_SDK_CHAIN_CPP_EXCEPTION_TYPE_EPOCH'
         and row.get('phase')=='SDK_CHAIN_RETURNED' and row.get('epochCoverage')=='synchronous_gui_sdk_chain'
         and all(row.get(k) is True for k in ('sdkChainEntered','sdkChainReturned','sdkChainComplete'))
         and type(row.get('sdkChainRc')) is int and row['sdkChainRc']==0, 'SDK_CHAIN_EPOCH')
    for key in ('cppThrows','cppThrowsExecuteThread','cppThrowsOtherThreads','otherExceptions',
                'otherExceptionsExecuteThread','otherExceptionsOtherThreads','typeEventCount','decodedCppThrows',
                'unknownCppThrows','listStreamCompatibleThrows'):
        need(type(row.get(key)) is int and row[key]==0,'SDK_CHAIN_EXCEPTION')
    need(type(row.get('typeEvents')) is list and row['typeEvents']==[], 'SDK_CHAIN_EVENTS')
    normalized=dict(row,kind='COMPARISON_CPP_EXCEPTION_TYPE_EPOCH',phase='EXECUTE_RETURNED',
                    epochCoverage='synchronous_context_Execute')
    epoch.classify_type_epoch(normalized,operation_id=operation_id,scope_sha256=scope_sha256,
        process_id=process_id,execute_thread_id=execute_thread_id,callback_known=callback_known,
        callback_sdk_rc=callback_sdk_rc,target_identity_verified=target_identity_verified)
    return dict(sdkChainExceptionFree=True,synchronousExecuteExceptionFree=True,
                dllRetainedUntilProcessExit=True,futureOtherThreadBarrierVerified=False,
                sourceBindingVerified=False,fullPendingVerified=False,databaseUpdateAuthorized=False)
