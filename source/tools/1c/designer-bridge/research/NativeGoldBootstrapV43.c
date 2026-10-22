/* Owned early GUI bootstrap. No work in DllMain, no global hook, no eval. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include "gold_bindings.h"
extern uint32_t ahSdkCall(void*,void*,uint32_t,uint32_t*);
int ahSdkAbiFault=0;
typedef struct {DWORD pid,tid,birthLow,birthHigh,version,fixture;} Binding;
static Binding bound;
static volatile LONG initialized=0,dispatched=0;
static HHOOK hook=NULL;
static HANDLE completed=NULL;
static DWORD result=0xffffffff;
static DWORD setterCalls=0;

static BOOL identity(void){
 FILETIME b,e,k,u;
 return GetCurrentProcessId()==bound.pid && GetProcessTimes(GetCurrentProcess(),&b,&e,&k,&u)
  && b.dwLowDateTime==bound.birthLow && b.dwHighDateTime==bound.birthHigh;
}
static DWORD sdk(void){
 typedef void *(__cdecl *GetModule)(const wchar_t*,const wchar_t*);
 HMODULE core=LoadLibraryA(AH_CORE_PATH);if(!core)return 501;
 GetModule get=(GetModule)GetProcAddress(core,"core_as_getModule");if(!get)return 502;
 wchar_t folder[MAX_PATH];unsigned i=0;
 while(AH_MODULE_PATH[i] && i<MAX_PATH-2){
  if((unsigned char)AH_MODULE_PATH[i]>127)return 503;
  folder[i]=(unsigned char)AH_MODULE_PATH[i];i++;
 }
 if(i>=MAX_PATH-2)return 503;folder[i++]=L'\\';folder[i]=0;
 void *module=get(L"Snegopat",folder);if(!module)return 504;
 /* Capture the actual interface before any new setter ABI call. Source
    declaration order alone does not establish MSVC overloaded vtable order. */
 uintptr_t base=(uintptr_t)core,table=*(uintptr_t*)module;
 if(table!=base+0x291124 || (*(uintptr_t**)module)[6]!=base+0xef930 ||
    (*(uintptr_t**)module)[7]!=base+0xed5b0 || (*(uintptr_t**)module)[8]!=base+0xed3e0)return 514;
 HANDLE layout=CreateFileA(AH_LAYOUT_PATH,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(layout==INVALID_HANDLE_VALUE)return 512;
 char layoutBody[384];DWORD layoutWritten=0;
 int layoutLength=snprintf(layoutBody,sizeof(layoutBody),"{\"nonce\":\"%s\",\"pid\":%lu,\"guiTid\":%lu,\"tableRva\":%lu,\"runRva\":%lu,\"slot7Rva\":%lu,\"slot8Rva\":%lu,\"goldStarted\":true}",
  AH_NONCE,GetCurrentProcessId(),GetCurrentThreadId(),(DWORD)(table-base),
  (DWORD)((*(uintptr_t**)module)[6]-base),(DWORD)((*(uintptr_t**)module)[7]-base),(DWORD)((*(uintptr_t**)module)[8]-base));
 BOOL layoutComplete=WriteFile(layout,layoutBody,layoutLength,&layoutWritten,NULL) && layoutWritten==layoutLength && FlushFileBuffers(layout);
 CloseHandle(layout);if(!layoutComplete)return 513;
 /* The two uint64 parameter setters mirror the public official loader.
    The query handle belongs to this process and lives until process teardown. */
 uint32_t arguments[3]={0,0,0};
#ifndef AH_WITHOUT_CORE_PARAMETERS
 HANDLE ownQuery=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,GetCurrentProcessId());
 if(!ownQuery)return 508;
 arguments[0]=(uint32_t)L"StarterWnd";
 setterCalls++;
 /* Actual pinned overloads: slot7 ret12 is uint64; slot8 ret8 is string.
    Stop immediately on a shim fault before any following SDK call. */
 ahSdkCall(module,(*(void***)module)[7],3,arguments);
 if(ahSdkAbiFault)return 509;
 arguments[0]=(uint32_t)L"ProcessHandle";arguments[1]=(uint32_t)ownQuery;
 setterCalls++;
 ahSdkCall(module,(*(void***)module)[7],3,arguments);
 if(ahSdkAbiFault)return 509;
#endif
 arguments[0]=arguments[1]=arguments[2]=0;
 if(!ahSdkCall(module,(*(void***)module)[6],3,arguments) || ahSdkAbiFault)return 505;
 return 0; // Actual native command readiness is verified separately, not inferred here.
}
static LRESULT CALLBACK early(int code,WPARAM wp,LPARAM lp){
 if(code==HCBT_CREATEWND && hook && identity() && GetCurrentThreadId()==bound.tid &&
    InterlockedCompareExchange(&dispatched,1,0)==0){
  BOOL unhooked=UnhookWindowsHookEx(hook);hook=NULL;
  DWORD sdkResult=sdk();result=sdkResult;
  BOOL parametersReadBack=FALSE;
#ifndef AH_WITHOUT_CORE_PARAMETERS
  parametersReadBack=FALSE; // Only a separate actual AS read-back receipt can prove this.
#endif
  HANDLE file=CreateFileA(AH_PROOF_PATH ".pending",GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
  if(file!=INVALID_HANDLE_VALUE){
   char body[768];DWORD written=0;
   int length=snprintf(body,sizeof(body),"{\"pid\":%lu,\"guiTid\":%lu,\"birth\":\"%08lx%08lx\",\"nonce\":\"%s\",\"hookCode\":%d,\"callbackCalls\":1,\"hookUnregistered\":%s,\"sdkTrialResult\":%lu,\"coreParameterSetters\":%lu,\"coreParameterReadBackVerified\":%s,\"goldStarted\":true,\"sourceWrites\":0}",
    GetCurrentProcessId(),GetCurrentThreadId(),bound.birthHigh,bound.birthLow,AH_NONCE,code,unhooked?"true":"false",sdkResult,setterCalls,parametersReadBack?"true":"false");
   BOOL flushed=WriteFile(file,body,length,&written,NULL) && written==length && FlushFileBuffers(file);
   CloseHandle(file);
   if(!flushed || !MoveFileExA(AH_PROOF_PATH ".pending",AH_PROOF_PATH,MOVEFILE_WRITE_THROUGH))result=510;
  }else result=511;
  SetEvent(completed);
 }
 return CallNextHookEx(NULL,code,wp,lp);
}
__declspec(dllexport) DWORD WINAPI ahEarlyInitialize(LPVOID parameter){
 if(!parameter)return 89;
 Binding candidate=*(Binding*)parameter;
 if(candidate.version!=43 || candidate.fixture!=0)return 88;
 if(GetCurrentProcessId()!=candidate.pid)return 90;
 FILETIME b,e,k,u;
 if(!GetProcessTimes(GetCurrentProcess(),&b,&e,&k,&u) || b.dwLowDateTime!=candidate.birthLow || b.dwHighDateTime!=candidate.birthHigh)return 91;
 typedef DWORD(WINAPI *Owner)(HANDLE);
 Owner owner=(Owner)GetProcAddress(GetModuleHandleA("kernel32.dll"),"GetProcessIdOfThread");
 HANDLE thread=OpenThread(THREAD_QUERY_INFORMATION,FALSE,candidate.tid);
 if(!thread || !owner || owner(thread)!=candidate.pid){if(thread)CloseHandle(thread);return 92;}
 CloseHandle(thread);
 wchar_t image[1024];
 DWORD imageLength=GetModuleFileNameW(NULL,image,1024);
 if(!imageLength || imageLength>=1024 || lstrcmpiW(image,L"C:\\Program Files (x86)\\1cv8\\8.3.18.1208\\bin\\1cv8.exe"))return 93;
 if(InterlockedCompareExchange(&initialized,1,0)!=0)return 95;
 bound=candidate;completed=CreateEventW(NULL,TRUE,FALSE,NULL);if(!completed)return 301;
 DWORD start=GetTickCount(),error=87;
 while(!hook && GetTickCount()-start<5000){
  hook=SetWindowsHookExW(WH_CBT,early,NULL,bound.tid);
  if(!hook){error=GetLastError();if(error!=87)break;Sleep(1);}
 }
 if(!hook){CloseHandle(completed);completed=NULL;return 1000+error;}
 /* Natural window creation in this own Designer; never post fixture or user messages. */
 DWORD waited=WaitForSingleObject(completed,5000);
 if(hook){UnhookWindowsHookEx(hook);hook=NULL;}
 CloseHandle(completed);completed=NULL;
 return waited==WAIT_OBJECT_0 && dispatched==1?result:4000;
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved){return TRUE;}
