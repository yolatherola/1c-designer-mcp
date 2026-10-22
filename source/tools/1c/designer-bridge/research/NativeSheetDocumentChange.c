/* OFFLINE CANDIDATE. No carrier/Plan/Gold route is provided by this file.
   A future root-owned carrier seals this header from an actual readonly view
   observation and holds the typed document/view references through terminal.
   Exactly one stock moxelui change callback may run; no SDK registration,
   metadata setters, Save, DB/repository calls or native dirty-byte stores.
   The root must review the callback's registered-sink closure before admission.
   DLL-local once is supplementary; unloading is NOT a durable replay barrier. */
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include "sheet_document_change_params.h"

#if AH_SHEET_PARAMS_VERSION != 1
#error AH_SHEET_CLOSED_PARAMS_REQUIRED
#endif

typedef void (__stdcall *AhStockSheetChange)(void *view_receiver);
typedef struct AhSheetChangeResult {
    uint32_t version, identity_verified, bindings_verified, body_gate_verified;
    uint32_t callback_attempted, callback_returned, terminal, reason_code;
    uint32_t core_dirty_known, core_dirty_after, post_bindings_verified;
    char operation_id[33], plan_sha256[65];
} AhSheetChangeResult;
static volatile LONG once=0;

/* Minimal published WinCrypt signatures: the pinned TCC distribution has no
   wincrypt.h/import library. Resolve only these fixed hash APIs from an already
   loaded system module; never load a DLL or accept a caller export/address. */
typedef ULONG_PTR HCRYPTPROV;
typedef ULONG_PTR HCRYPTHASH;
typedef BOOL (WINAPI *AhAcquire)(HCRYPTPROV*,LPCSTR,LPCSTR,DWORD,DWORD);
typedef BOOL (WINAPI *AhCreateHash)(HCRYPTPROV,DWORD,ULONG_PTR,DWORD,HCRYPTHASH*);
typedef BOOL (WINAPI *AhHashData)(HCRYPTHASH,const BYTE*,DWORD,DWORD);
typedef BOOL (WINAPI *AhGetHash)(HCRYPTHASH,DWORD,BYTE*,DWORD*,DWORD);
typedef BOOL (WINAPI *AhDestroyHash)(HCRYPTHASH);
typedef BOOL (WINAPI *AhRelease)(HCRYPTPROV,DWORD);
typedef struct AhCrypto {
    AhAcquire acquire;AhCreateHash create;AhHashData data;
    AhGetHash get;AhDestroyHash destroy;AhRelease release;
} AhCrypto;
static int crypto(AhCrypto *c) {
    HMODULE module=GetModuleHandleA("advapi32.dll");if(!module)return 0;
    c->acquire=(AhAcquire)GetProcAddress(module,"CryptAcquireContextA");
    c->create=(AhCreateHash)GetProcAddress(module,"CryptCreateHash");
    c->data=(AhHashData)GetProcAddress(module,"CryptHashData");
    c->get=(AhGetHash)GetProcAddress(module,"CryptGetHashParam");
    c->destroy=(AhDestroyHash)GetProcAddress(module,"CryptDestroyHash");
    c->release=(AhRelease)GetProcAddress(module,"CryptReleaseContext");
    return c->acquire && c->create && c->data && c->get && c->destroy && c->release;
}

static int readable(uintptr_t address,SIZE_T length) {
    MEMORY_BASIC_INFORMATION info;uintptr_t cursor=address,end=address+length;
    if(!address || !length || end<address)return 0;
    while(cursor<end) {
        if(VirtualQuery((void*)cursor,&info,sizeof(info))!=sizeof(info)
           || info.State!=MEM_COMMIT || (info.Protect&(PAGE_GUARD|PAGE_NOACCESS)))return 0;
        if(!(info.Protect&(PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)))return 0;
        uintptr_t next=(uintptr_t)info.BaseAddress+info.RegionSize;
        if(next<=cursor)return 0;cursor=next;
    }
    return 1;
}

static int digest_matches(AhCrypto *c,HCRYPTHASH hash,const char *expected) {
    BYTE value[32];DWORD length=32;unsigned i;
    static const char hex[]="0123456789abcdef";
    if(!c->get(hash,2,value,&length,0) || length!=32)return 0;
    for(i=0;i<32;i++)if(expected[i*2]!=hex[value[i]>>4] || expected[i*2+1]!=hex[value[i]&15])return 0;
    return expected[64]==0;
}

static int bytes_hash(const BYTE *bytes,DWORD length,const char *expected) {
    HCRYPTPROV provider=0;HCRYPTHASH hash=0;int matched=0;AhCrypto c;
    if(!crypto(&c) || !c.acquire(&provider,0,0,24,0xf0000000))return 0;
    if(c.create(provider,0x800c,0,0,&hash)
       && c.data(hash,bytes,length,0))matched=digest_matches(&c,hash,expected);
    if(hash)c.destroy(hash);c.release(provider,0);return matched;
}

/* Keep the exact loaded module's backing file open without write/delete sharing
   until after the callback. Paths are obtained from fixed loaded module names,
   never from a caller string. Mapped callback bytes are checked independently. */
static HANDLE module_file(const char *name,uintptr_t expected_base,const char *pin) {
    char path[4096];BYTE block[4096];DWORD count=0,total=0;
    HMODULE module=GetModuleHandleA(name);HCRYPTPROV provider=0;HCRYPTHASH hash=0;
    HANDLE file=INVALID_HANDLE_VALUE;int matched=0;AhCrypto c;
    if(!module || (uintptr_t)module!=expected_base)return INVALID_HANDLE_VALUE;
    count=GetModuleFileNameA(module,path,sizeof(path));
    if(!count || count>=sizeof(path))return INVALID_HANDLE_VALUE;
    file=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    if(file==INVALID_HANDLE_VALUE)return file;
    if(crypto(&c) && c.acquire(&provider,0,0,24,0xf0000000)
       && c.create(provider,0x800c,0,0,&hash)) {
        for(;;) {
            if(!ReadFile(file,block,sizeof(block),&count,0))break;
            if(!count){matched=total>0 && digest_matches(&c,hash,pin);break;}
            if(total>16777216-count || !c.data(hash,block,count,0))break;
            total+=count;
        }
    }
    if(hash)c.destroy(hash);if(provider)c.release(provider,0);
    if(!matched){CloseHandle(file);return INVALID_HANDLE_VALUE;}
    return file;
}

static int callback_matches(uintptr_t ui_base) {
    static const unsigned offsets[5]={6,24,49,80,377};
    static const uint32_t targets[5]={0x1f7188,0x24e008,0x15a40,0x15a40,0x20e37c};
    BYTE code[579];unsigned i;uint32_t word;
    uintptr_t entry=ui_base+0x512e0;
    if(!readable(entry,sizeof(code)))return 0;
    CopyMemory(code,(void*)entry,sizeof(code));
    for(i=0;i<5;i++) {
        CopyMemory(&word,code+offsets[i],4);
        if(word!=ui_base+targets[i])return 0;
        word=0x17420000+targets[i];CopyMemory(code+offsets[i],&word,4);
    }
    return bytes_hash(code,sizeof(code),"e748d3fc4f6818aea0ceb1615c2361d6f5bcf65d6c9ad01a965a28a1b25afa42");
}

static int policy_code_matches(uintptr_t ui_base,uintptr_t body_base) {
    BYTE code[63];uint32_t word;
    if(!readable(ui_base+0x5b400,63) || !readable(ui_base+0x15a40,16)
       || !readable(body_base+0x35fdd0,16) || !readable(body_base+0x38e300,18)
       || !readable(body_base+0xe0120,19))return 0;
    CopyMemory(code,(void*)(ui_base+0x5b400),63);CopyMemory(&word,code+13,4);
    if(word!=ui_base+0x15a40)return 0;
    word=0x17435a40;CopyMemory(code+13,&word,4);
    return bytes_hash(code,63,"a48d4cc5e116e2f350e8942dce32aa1866a87935aa0ef232957beb98913075eb")
        && bytes_hash((BYTE*)(ui_base+0x15a40),16,"cb025cea963c7ff9ba7387bf1270649cdd3a93d6859b5de98a392303f22558b8")
        && bytes_hash((BYTE*)(body_base+0x35fdd0),16,"10e8735d29a908aff8ea85e8527b5b184a86ff1e9a15733098f75f73afbf3367")
        && bytes_hash((BYTE*)(body_base+0x38e300),18,"d33bba7b097a9291416dd3cb44e7bd196fe738a7bd86fb03ad276f7ede869186")
        && bytes_hash((BYTE*)(body_base+0xe0120),19,"7f9ae1847de5deb27fda8be890045caeb98da3a734c58f268cb3eb7957aa7d4e");
}

/* Pinned IDocumentView.slot22 (11e200) reads Core at self-4 and returns Core+b8
   with a new reference. We only borrow those fields, never call/adopt/release it.
   Both typed references are held by the root caller throughout this continuation. */
static int document_join(uintptr_t view,uintptr_t document,uintptr_t ui_base) {
    BYTE getter[105];uint32_t word;uintptr_t table,core;
    if(view<4 || document<0xb8 || !readable(view-4,8) || !readable(document,4))return 0;
    table=*(uintptr_t*)view;core=*(uintptr_t*)(view-4);
    if(table!=ui_base+0x20d778 || !readable(table,23*4)
       || ((uintptr_t*)table)[22]!=ui_base+0x11e200
       || !core || core+0xb8!=document || !readable(core,0xbc)
       || *(uintptr_t*)document!=ui_base+2155168
       || !readable(ui_base+0x11e200,sizeof(getter)))return 0;
    CopyMemory(getter,(void*)(ui_base+0x11e200),sizeof(getter));
    CopyMemory(&word,getter+6,4);if(word!=ui_base+0x1e1330)return 0;
    word=0x17601330;CopyMemory(getter+6,&word,4);
    CopyMemory(&word,getter+19,4);if(word!=ui_base+0x24e008)return 0;
    word=0x1766e008;CopyMemory(getter+19,&word,4);
    return bytes_hash(getter,sizeof(getter),"112c51ba8c55814e1a1be07b675cbbb727747fa94bc3de3a85dc18b079d1637d");
}

static int bindings(uintptr_t ui_base,uintptr_t body_base) {
    uintptr_t view=AH_SHEET_VIEW,internal=AH_SHEET_INTERNAL_VIEW;
    uintptr_t receiver=AH_SHEET_RECEIVER,window=AH_SHEET_WINDOW;
    uintptr_t body=AH_SHEET_BODY,table,body_table;
    if(view!=internal+0x20 || receiver!=window+0x1a0
       || !readable(internal,0x60) || !readable(window,0xda0)
       || !readable(receiver,0xc00) || body<12 || !readable(body-12,0x6cd))return 0;
    if(*(uintptr_t*)(internal+0x5c)!=window || *(uintptr_t*)(receiver+0x784)!=internal
       || *(uintptr_t*)(receiver+0x5ec)!=body)return 0;
    table=*(uintptr_t*)receiver;body_table=*(uintptr_t*)body;
    if((table!=ui_base+0x211228 && table!=ui_base+0x212c30) || !readable(table,90*4)
       || (body_table!=body_base+0x4adbd4 && body_table!=body_base+0x4d83f0)
       || !readable(body_table,418*4))return 0;
    if(((uintptr_t*)table)[10]!=ui_base+0x15a40
       || ((uintptr_t*)table)[20]!=ui_base+0x5b400
       || ((uintptr_t*)table)[89]!=ui_base+0x512e0
       || ((uintptr_t*)body_table)[44]!=body_base+0x35fdd0
       || ((uintptr_t*)body_table)[377]!=body_base+0x38e300
       || ((uintptr_t*)body_table)[417]!=body_base+0xe0120)return 0;
    return document_join(view,AH_SHEET_DOCUMENT,ui_base);
}

__declspec(dllexport) int ahSheetDocumentChange(AhSheetChangeResult *result) {
    FILETIME created,exited,kernel,user;HANDLE ui_file=INVALID_HANDLE_VALUE,body_file=INVALID_HANDLE_VALUE;
    int reason=801;uintptr_t ui_base=AH_SHEET_UI_BASE,body_base=AH_SHEET_BODY_BASE;
    if(!result || sizeof(void*)!=4)return 800;
    ZeroMemory(result,sizeof(*result));result->version=1;
    CopyMemory(result->operation_id,AH_SHEET_OPERATION,33);CopyMemory(result->plan_sha256,AH_SHEET_PLAN_SHA256,65);
    if(InterlockedCompareExchange(&once,1,0)!=0)goto done;
    reason=802;
    if(GetCurrentProcessId()!=AH_SHEET_PID || GetCurrentThreadId()!=AH_SHEET_GUI
       || !GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user)
       || created.dwLowDateTime!=AH_SHEET_BIRTH_LOW || created.dwHighDateTime!=AH_SHEET_BIRTH_HIGH)goto done;
    reason=803;
    ui_file=module_file("moxelui.dll",ui_base,"ff7320903400d8fa7dacb0c1ed2e6fb70fd00e14aabf2a1044bd64603a7d5fe7");
    if(ui_file==INVALID_HANDLE_VALUE)goto done;
    body_file=module_file("moxel.dll",body_base,"9da850debb5e05a39999b35c6af0cac39dbe92f9ad3fad9929de06064a703111");
    if(body_file==INVALID_HANDLE_VALUE)goto done;
    result->identity_verified=1;reason=804;
    if(!callback_matches(ui_base) || !policy_code_matches(ui_base,body_base)
       || !bindings(ui_base,body_base) || !bindings(ui_base,body_base))goto done;
    result->bindings_verified=1;reason=805;
    if(*(BYTE*)(AH_SHEET_BODY+0x2f6)!=0 || *(BYTE*)(AH_SHEET_RECEIVER+0x20c)!=0
       || *(BYTE*)(AH_SHEET_DOCUMENT-0x90)!=0)goto done;
    /* Primary377 enters no registered sink if its body[-4] guard is zero, or
       if the signed listener count body[-8] is zero. Unknown positive-listener
       closure is never dispatched by this closed candidate. */
    if(*(BYTE*)(AH_SHEET_BODY-4)!=0 && *(int32_t*)(AH_SHEET_BODY-8)!=0)goto done;
    result->body_gate_verified=1;
    /* This is the only application-native invocation. Throws/interruptions after
       attempted=1 have no known terminal proof and MUST retain the root route. */
    result->callback_attempted=1;
    ((AhStockSheetChange)(ui_base+0x512e0))((void*)(uintptr_t)AH_SHEET_RECEIVER);
    result->callback_returned=1;reason=806;
    if(!bindings(ui_base,body_base))goto done;
    result->post_bindings_verified=1;reason=0;
    if(readable(AH_SHEET_DOCUMENT-0x90,1)) {
        result->core_dirty_known=1;result->core_dirty_after=*(BYTE*)(AH_SHEET_DOCUMENT-0x90)!=0;
    }
done:
    if(body_file!=INVALID_HANDLE_VALUE)CloseHandle(body_file);
    if(ui_file!=INVALID_HANDLE_VALUE)CloseHandle(ui_file);
    result->reason_code=reason;result->terminal=1;return reason;
}
