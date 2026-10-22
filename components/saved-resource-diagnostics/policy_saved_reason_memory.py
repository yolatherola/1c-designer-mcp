"""Emit a diagnostic-only DWORD copy adapter; never load or invoke WinAPI here.

Integration must supply a private trusted window only after its separately
pinned CT decoder. This adapter neither identifies a C++ type nor grants an
exception waiver, operation retry, native cleanup or ownership authority.
"""

C = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define AH_SAVED_REASON_MEMORY_ADMITTED __ADMITTED__
typedef struct AhSavedReasonMemoryWindow {
 uint32_t objectBase,objectBytes,guiThread;
 uint32_t active,opened,getAttempted,getReturned,unknown;
 uint32_t beginEventIndex,eventIndex,endEventIndex,attemptedEventMask;
} AhSavedReasonMemoryWindow;

/* Only the four reason bytes are copied. All ctx/output bytes are owned by
   the integrating handler; trusted type/span admission belongs to its issuer. */
static uint32_t ahSavedReasonMemoryCopy(void*ctx,uint32_t at,uint32_t n,unsigned char*out){
 DWORD saved=GetLastError();uint32_t ok=0,base,region,end,word=0,bit;SIZE_T copied=0;
 AhSavedReasonMemoryWindow*w=(AhSavedReasonMemoryWindow*)ctx;MEMORY_BASIC_INFORMATION m;
 if(!AH_SAVED_REASON_MEMORY_ADMITTED||!w||!out||n!=4)goto done;
 if(w->active!=1||w->opened!=1||w->getAttempted!=1||w->getReturned||w->unknown
 ||!w->guiThread||GetCurrentThreadId()!=w->guiThread||w->endEventIndex
 ||w->eventIndex>=32||w->beginEventIndex>w->eventIndex)goto done;
 base=w->objectBase;
 if(base<65536u||w->objectBytes!=196u||base>0xffffffffu-196u||at!=base+128u)goto done;
 bit=1u<<w->eventIndex;if(w->attemptedEventMask&bit)goto done;
 /* One attempt per event, including failed reads: at most 32 DWORDs/interval. */
 w->attemptedEventMask|=bit;
 memset(&m,0,sizeof(m));
 if(VirtualQuery((const void*)(uintptr_t)base,&m,sizeof(m))!=sizeof(m)
 ||m.State!=MEM_COMMIT||(m.Protect&(PAGE_GUARD|PAGE_NOACCESS)))goto done;
 if((m.Protect&255u)!=PAGE_READONLY&&(m.Protect&255u)!=PAGE_READWRITE
 &&(m.Protect&255u)!=PAGE_WRITECOPY&&(m.Protect&255u)!=PAGE_EXECUTE_READ
 &&(m.Protect&255u)!=PAGE_EXECUTE_READWRITE&&(m.Protect&255u)!=PAGE_EXECUTE_WRITECOPY)goto done;
 /* Reject a split/overflowing span before RPM. No source object dereference. */
 if((uintptr_t)m.BaseAddress>0xffffffffu||m.RegionSize>0xffffffffu)goto done;
 region=(uint32_t)(uintptr_t)m.BaseAddress;
 if(!m.RegionSize||region>0xffffffffu-(uint32_t)m.RegionSize||region>base)goto done;
 end=region+(uint32_t)m.RegionSize;
 if(base>end||196u>end-base||at<base||at>end||4u>end-at)goto done;
 if(!ReadProcessMemory(GetCurrentProcess(),(const void*)(uintptr_t)at,&word,4,&copied)||copied!=4)goto done;
 memcpy(out,&word,4);ok=1;
 done:
 word=0;SetLastError(saved);return ok;
}
'''


def render(*, admitted=False):
    """Return technical C; only explicit bool admission enables its copy path."""
    if type(admitted) is not bool:
        raise ValueError('SAVED_REASON_MEMORY_ADMISSION')
    return C.replace('__ADMITTED__', '1' if admitted else '0').encode('ascii')
