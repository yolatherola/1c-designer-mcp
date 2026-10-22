"""Offline/supplied-copy FileException facts; never a runtime/cleanup permit.

Only two pinned primary ThrowInfo chains and identity PMD are supported. The
reader is supplied by the caller: it must safely copy or refuse, never blindly
dereference. No live reader, VEH, OS API or producer integration is provided.
"""
from dataclasses import dataclass, field
import hashlib
import struct

FILE_NAME=b'.?AVFileException@core@@\0'
BASE_NAME=b'.?AVException@core@@\0'
# size, ThrowInfo, CTA, primaryCT, primaryTD, copy, baseCT, baseTD,
# baseCopy, unwind. All addresses here are image RVAs, not process pointers.
LAYOUTS={
 'core83.dll':(0x3b5000,0x31a93c,0x31a914,0x31a920,0x378854,0x34160,
               0x31a73c,0x378704,0x9580,0x34120),
 'frntend.dll':(0xf54000,0xdcf0bc,0xdcf094,0xdcf0a0,0xe0b9c8,0x945530,
                0xdced88,0xe0b988,0xb11f94,0x945500),
}
HASHES={
 'core83.dll':'46e7019a142a01367d27c28b646ce8defea54ad60afe9fc467738b75c8663f14',
 'frntend.dll':'9556defc1ccd1cd8b05ed63d4b0287f40fac2bccba42a68fc229927c8b5fc8a5',
}
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('SAVED_NULL_CERTIFICATE_'+code)


def admitted(value):
    need(type(value) is bool and value,'LOCAL_ADMISSION')


def u32(value):return type(value) is int and 0<=value<=0xffffffff


@dataclass(frozen=True)
class Module:
    name:str
    base:int=field(repr=False)
    _issuer:object=field(repr=False,compare=False)


def module_from_image(name,raw,base):
    """Pin supplied PE bytes; performs no file/OS reads or runtime attestation."""
    need(type(name) is str and name in HASHES and type(raw) is bytes,'MODULE')
    need(hashlib.sha256(raw).hexdigest()==HASHES[name],'MODULE_SHA')
    need(u32(base) and base>=65536 and base+LAYOUTS[name][0]<=0x100000000,'MODULE_RANGE')
    return Module(name,base,_ISSUER)


@dataclass(frozen=True)
class ObjectSpan:
    base:int=field(repr=False)
    size:int
    committed:bool=True
    readable:bool=True
    guard:bool=False


@dataclass(frozen=True)
class TypedFileException:
    _object:int=field(repr=False)
    _issuer:object=field(repr=False,compare=False)


@dataclass(frozen=True)
class ReasonFact:
    reason:int
    _issuer:object=field(repr=False,compare=False)


def _copy(reader,address,length,start,size):
    need(u32(address) and address>=65536 and type(length) is int and 1<=length<=96
         and address+length<=0x100000000 and start<=address and address+length<=start+size,'COPY_RANGE')
    try:raw=reader(address,length)
    except Exception:raise ValueError('SAVED_NULL_CERTIFICATE_COPY_FAILED') from None
    need(type(raw) is bytes and len(raw)==length,'COPY_FAILED')
    return raw


def decode_type(read_image,*,module,code,parameters,scope_admitted=False):
    """Read only pinned image metadata. Never read the thrown object's bytes."""
    admitted(scope_admitted)
    need(type(module) is Module and module._issuer is _ISSUER and module.name in LAYOUTS,'PROVENANCE')
    need(type(parameters) is tuple and len(parameters)==3 and all(u32(x) for x in parameters)
         and type(code) is int and code==0xe06d7363 and parameters[0]==0x19930520,'MSVC_X86')
    size,ti,cta,ct,td,copy,bct,btd,bcopy,unwind=LAYOUTS[module.name];base=module.base
    need(parameters[2]==base+ti and parameters[1]>=65536 and parameters[1]+196<=0x100000000,'PRIMARY_THROW')
    read=lambda r,n:_copy(read_image,base+r,n,base,size)
    need(read(ti,16)==struct.pack('<4I',0,base+unwind,0,base+cta),'THROWINFO')
    need(read(cta,12)==struct.pack('<3I',2,base+ct,base+bct),'ARRAY')
    for r,d,c,n in ((ct,td,copy,196),(bct,btd,bcopy,128)):
        # No virtual adjustment, copying, destructor or application methods.
        need(read(r,28)==struct.pack('<IIiiiII',0,base+d,0,-1,0,n,base+c),'IDENTITY_PMD')
    need(read(td+8,len(FILE_NAME))==FILE_NAME and read(btd+8,len(BASE_NAME))==BASE_NAME,'EXACT_TYPE')
    return TypedFileException(parameters[1],_ISSUER)


def extract_reason(read_object,*,typed,span,scope_admitted=False):
    """Copy exactly reason DWORD after type/identity-PMD proof; no raw access."""
    admitted(scope_admitted)
    need(type(typed) is TypedFileException and typed._issuer is _ISSUER,'TYPED')
    need(type(span) is ObjectSpan and u32(span.base) and type(span.size) is int and span.size==196
         and span.base>=65536 and span.base+span.size<=0x100000000
         and span.base==typed._object and span.committed is True and span.readable is True
         and span.guard is False,'OBJECT_SPAN')
    reason=struct.unpack('<I',_copy(read_object,typed._object+0x80,4,span.base,span.size))[0]
    return ReasonFact(reason,_ISSUER)


LEDGER_KEYS=frozenset(('before','after','whole','gui','getter_attempts','getter_returns',
 'return_slot_equal','null_output','owners','allocations','frees','pending','unknown',
 'other','other_thread','overflow','reentry','escaped','callback_quiescent','full22_equal',
 'source_cas','second_own','refs_closed'))


def validate_interval(ledger,events,*,scope_admitted=False):
    """Validate supplied facts only. Never close a job or alter a CPP counter."""
    admitted(scope_admitted)
    need(type(ledger) is dict and ledger.keys()==LEDGER_KEYS and type(events) is tuple,'LEDGER')
    need(all(u32(ledger[k]) for k in LEDGER_KEYS),'FIELD_TYPES')
    need(ledger['before']==0 and 1<=ledger['after']==ledger['whole']<=32
         and len(events)==ledger['whole'] and ledger['gui']>0,'INTERVAL')
    need(ledger['getter_attempts']==ledger['getter_returns']==1 and all(ledger[k]==1 for k in
         ('return_slot_equal','null_output','callback_quiescent','full22_equal','source_cas','second_own','refs_closed')),'RETURN_CLOSURE')
    need(all(ledger[k]==0 for k in ('owners','pending','unknown','other','other_thread','overflow','reentry','escaped'))
         and ledger['allocations']==ledger['frees'],'UNCERTAIN')
    for index,event in enumerate(events):
        need(type(event) is tuple and len(event)==3 and u32(event[0]) and u32(event[1])
             and event[:2]==(index,ledger['gui']) and type(event[2]) is ReasonFact
             and event[2]._issuer is _ISSUER and event[2].reason==1,'EVENT')
    return dict(kind='LOCAL_SAVED_NULL_INTERVAL_FACT',typedReasonOneEvents=len(events),
        getterReturnedNull=True,runtimeVerified=False,savedBExistenceVerified=False,
        savedBReadSuccess=False,sourceJoinVerified=False,writerAuthorized=False,
        cleanupAuthorized=False,nativePermit=False,retryAuthorized=False)


def render(*,scope_admitted=False):
    """Emit pure C callback consumer; default denied, no OS or native calls."""
    need(type(scope_admitted) is bool,'ADMISSION_TYPE')
    need(C.count('__LAYOUTS__')==C.count('__HASHES__')==C.count('__ADMITTED__')==1,'TEMPLATE')
    layouts=',\n '.join('{'+','.join(hex(x) for x in row)+'}' for row in LAYOUTS.values())
    hashes=',\n '.join('{'+','.join(f'0x{x:02x}' for x in bytes.fromhex(HASHES[name]))+'}' for name in LAYOUTS)
    return C.replace('__LAYOUTS__',layouts).replace('__HASHES__',hashes).replace('__ADMITTED__',str(int(scope_admitted))).encode('ascii')


C=r'''
#include <stdint.h>
#include <string.h>
#define AH_NULL_CERT_ADMITTED __ADMITTED__
/* Caller owns valid, nonaliased output structs. Initialize BOTH facts per event
   and check BOTH returns. Every attempted decoder/extractor clears its own out;
   typed=1 is a private fact, never a capability or runtime authorization. */
typedef uint32_t (*AhNullCopy)(void*,uint32_t,uint32_t,unsigned char*);
typedef struct {uint32_t base,module;unsigned char sha[32];}AhNullImage;
typedef struct {uint32_t object,typed;}AhNullType;
typedef struct {uint32_t base,size,committed,readable,guard;}AhNullSpan;
typedef struct {uint32_t reason,typed;}AhNullReason;
typedef struct {uint32_t index,thread;AhNullReason fact;}AhNullEvent;
typedef struct {uint32_t before,after,whole,gui,ga,gr,returned,nullOut,owners,aa,fr,pending,unknown;
 uint32_t other,otherThread,overflow,reentry,escaped,quiet,full22,cas,secondOwn,refsClosed;}AhNullLedger;
static int ahNullRead(AhNullCopy copy,void*ctx,uint32_t at,uint32_t n,uint32_t base,uint32_t size,unsigned char*out){
 if(!copy||!out||at<65536||!n||n>96||(uint64_t)at+n>0x100000000ull
 ||at<base||(uint64_t)at+n>(uint64_t)base+size)return 0;
 return copy(ctx,at,n,out)==1;}
static int ahNullWords(AhNullCopy cb,void*ctx,uint32_t at,uint32_t n,uint32_t base,uint32_t size,const uint32_t*w){
 unsigned char b[96];return ahNullRead(cb,ctx,at,n,base,size,b)&&!memcmp(b,w,n);}
static int ahNullTypeDecode(AhNullCopy cb,void*ctx,const AhNullImage*m,uint32_t code,const uint32_t*p,uint32_t count,AhNullType*out){
 static const uint32_t layouts[2][10]={__LAYOUTS__};
 static const unsigned char hashes[2][32]={
 __HASHES__};
 const uint32_t*l;uint32_t b,w[7],i;unsigned char name[32];
 if(out){out->object=0;out->typed=0;}
 if(!AH_NULL_CERT_ADMITTED||!m||!p||!out||m->module>1||count!=3||code!=0xe06d7363u||p[0]!=0x19930520u)return 0;
 l=layouts[m->module];b=m->base;
 if(b<65536||(uint64_t)b+l[0]>0x100000000ull||memcmp(m->sha,hashes[m->module],32)
 ||p[2]!=b+l[1]||p[1]<65536||(uint64_t)p[1]+196>0x100000000ull)return 0;
 w[0]=0;w[1]=b+l[9];w[2]=0;w[3]=b+l[2];
 if(!ahNullWords(cb,ctx,b+l[1],16,b,l[0],w))return 0;
 w[0]=2;w[1]=b+l[3];w[2]=b+l[6];if(!ahNullWords(cb,ctx,b+l[2],12,b,l[0],w))return 0;
 for(i=0;i<2;i++){w[0]=0;w[1]=b+l[i?7:4];w[2]=0;w[3]=0xffffffffu;w[4]=0;w[5]=i?128:196;w[6]=b+l[i?8:5];
  if(!ahNullWords(cb,ctx,b+l[i?6:3],28,b,l[0],w))return 0;}
 if(!ahNullRead(cb,ctx,b+l[4]+8,sizeof(".?AVFileException@core@@"),b,l[0],name)
 ||memcmp(name,".?AVFileException@core@@",sizeof(".?AVFileException@core@@")))return 0;
 if(!ahNullRead(cb,ctx,b+l[7]+8,sizeof(".?AVException@core@@"),b,l[0],name)
 ||memcmp(name,".?AVException@core@@",sizeof(".?AVException@core@@")))return 0;
 out->object=p[1];out->typed=1;return 1;}
static int ahNullReasonExtract(AhNullCopy cb,void*ctx,const AhNullType*t,const AhNullSpan*s,AhNullReason*out){
 unsigned char b[4];
 if(out){out->reason=0;out->typed=0;}
 if(!AH_NULL_CERT_ADMITTED||!t||!s||!out||t->typed!=1||s->base!=t->object||s->size!=196
 ||s->base<65536||(uint64_t)s->base+s->size>0x100000000ull
 ||s->committed!=1||s->readable!=1||s->guard||!ahNullRead(cb,ctx,s->base+128,4,s->base,s->size,b))return 0;
 memcpy(&out->reason,b,4);out->typed=1;return 1;}
static int ahNullIntervalValidate(const AhNullLedger*l,const AhNullEvent*e,uint32_t count){uint32_t i;
 if(!AH_NULL_CERT_ADMITTED||!l||!e||l->before||!l->after||l->after>32||l->after!=l->whole||count!=l->whole||!l->gui
 ||l->ga!=1||l->gr!=1||l->returned!=1||l->nullOut!=1||l->quiet!=1||l->full22!=1||l->cas!=1||l->secondOwn!=1||l->refsClosed!=1
 ||l->owners||l->pending||l->unknown||l->other||l->otherThread||l->overflow||l->reentry||l->escaped||l->aa!=l->fr)return 0;
 for(i=0;i<count;i++)if(e[i].index!=i||e[i].thread!=l->gui||e[i].fact.typed!=1||e[i].fact.reason!=1)return 0;
 return 1;}
'''
