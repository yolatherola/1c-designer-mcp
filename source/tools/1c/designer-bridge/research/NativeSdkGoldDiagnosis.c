/* Fixed readonly same-engine SDK probe. No source text is accepted at runtime.
   The private build supplies immutable target identity and diagnostic payload.
   DllMain does no SDK work. Calls occur only on the exact owned GUI thread. */
#include <windows.h>
#include <stdint.h>
#include "sdk_probe_params.h"
int ahSdkAbiFault=0;
extern uint32_t ahSdkCall(void*,void*,uint32_t,uint32_t*);
#if defined(AH_SDK_RECOVER_ENGINE_CONFIG) || defined(AH_SDK_RECOVERY_TEST)
extern int ahSdkRecoverOwnRuntime(void*,unsigned char*,uintptr_t);
extern int ahSdkRecoveryTest(void*,unsigned char*);
#endif
static void *trialEngine=0;
static volatile LONG once=0;
static volatile LONG callbackDone=0;
static volatile LONG observed=0;
static DWORD sdkGuiThread=0;
static HINSTANCE sdkInstance=0;
static uint32_t call(void *object,unsigned slot,unsigned argc,uint32_t *argv) {
 if(!object || ahSdkAbiFault)return 0;
 return ahSdkCall(object,(*(void***)object)[slot],argc,argv);
}
static int pinned(void *object,unsigned tableRva,unsigned slot,unsigned functionRva,unsigned char *core) {
 return object && *(unsigned char**)object==core+tableRva
  && (*(unsigned char***)object)[slot]==core+functionRva;
}
static int execute(void *engine,void *expectedModule,unsigned char *core,int test) {
 void *module=0,*fn=0,*context=0;uint32_t args[5];int rc=0;
 if(!pinned(engine,0x28f184,49,0xc8d00,core) || !pinned(engine,0x28f184,50,0xc8d10,core)
  || !pinned(engine,0x28f184,58,0xc8d60,core) || call(engine,49,0,0)!=1)return 101;
 args[0]=0;module=(void*)call(engine,50,1,args);
 if((expectedModule && module!=expectedModule) || !pinned(module,0x28e454,6,0xa9020,core))return 102;
 args[0]=(uint32_t)"AH1C_FIXED_SDK_DIAGNOSIS_V14";args[1]=(uint32_t)AH_SDK_FIXED_SOURCE;
 args[2]=0;args[3]=0;args[4]=(uint32_t)&fn;
 rc=(int)call(module,6,5,args);if(rc<0 || !fn || ahSdkAbiFault)return 103;
 context=(void*)call(engine,58,0,0);if(!context || ahSdkAbiFault)return 104;
 args[0]=(uint32_t)fn;rc=(int)call(context,3,1,args);
 if(rc>=0 && !ahSdkAbiFault)rc=(int)call(context,5,0,0);else rc=105;
#ifdef AH_SDK_EXCEPTION_FILE
 if(rc==3 && !ahSdkAbiFault){
  /* Public SDK GetExceptionString slot35. Keep bounded details private;
     callers report a sanitized classification, never a connection URL. */
  const char *message=(const char*)call(context,35,0,0);DWORD size=0;
  if(message){while(size<2048 && message[size])size++;
   HANDLE error=CreateFileW(AH_SDK_EXCEPTION_FILE,GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
   if(error!=INVALID_HANDLE_VALUE){DWORD n;WriteFile(error,message,size,&n,0);FlushFileBuffers(error);CloseHandle(error);}
  }
 }
#endif
 if(rc==0 && test && call(context,25,0,0)!=18)rc=106;
 if(!ahSdkAbiFault){call(context,1,0,0);call(fn,2,0,0);}else rc=107;
 return rc;
}
#ifdef AH_SDK_TEST_HOST
__declspec(dllexport) BOOL __cdecl moduleInit(void *iface,void *module,BOOL onlyCheck) {
 trialEngine=(void*)call(iface,0,0,0);return trialEngine!=0;
}
__declspec(dllexport) int __cdecl ahSdkTrial(void) {
 unsigned char *core=(unsigned char*)GetModuleHandleW(L"core_as.dll");
#ifdef AH_SDK_RECOVERY_TEST
 if(!core)return 108;
 int recovered=ahSdkRecoveryTest(trialEngine,core);if(recovered)return recovered;
#endif
 return core?execute(trialEngine,0,core,1):108;
}
#else
static BOOL identity(void) {
 FILETIME b,e,k,u;
 return GetCurrentProcessId()==AH_SDK_TARGET_PID && GetProcessTimes(GetCurrentProcess(),&b,&e,&k,&u)
  && b.dwLowDateTime==AH_SDK_BIRTH_LOW && b.dwHighDateTime==AH_SDK_BIRTH_HIGH;
}
static void result(int code) {
 HANDLE h=CreateFileW(AH_SDK_RESULT_FILE,GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
 if(h!=INVALID_HANDLE_VALUE){DWORD n;WriteFile(h,&code,4,&n,0);FlushFileBuffers(h);CloseHandle(h);}
}
__declspec(dllexport) LRESULT CALLBACK ahSdkHook(int code,WPARAM w,LPARAM l) {
 if(code>=0 && l && identity() && InterlockedCompareExchange(&observed,1,0)==0){
  DWORD fields[6]={GetCurrentProcessId(),GetCurrentThreadId(),(DWORD)code,((MSG*)l)->message,sdkGuiThread,(DWORD)identity()};
  HANDLE trace=CreateFileW(AH_SDK_CALLBACK_FILE,GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
  if(trace!=INVALID_HANDLE_VALUE){DWORD n;WriteFile(trace,fields,sizeof(fields),&n,0);FlushFileBuffers(trace);CloseHandle(trace);}
 }
 if(code>=0 && l && ((MSG*)l)->message==AH_SDK_MESSAGE && identity()
  && InterlockedCompareExchange(&once,1,0)==0){
  unsigned char *core=(unsigned char*)GetModuleHandleW(L"core_as.dll");
  unsigned char *snego=(unsigned char*)GetModuleHandleW(L"snegopat.dll");
  void *engine=snego?*(void**)(snego+0x37674):0;
  typedef void *(__cdecl *ActiveContext)(void);
  ActiveContext active=core?(ActiveContext)GetProcAddress((HMODULE)core,"asGetActiveContext"):0;
  int rc=109;
  if(GetCurrentThreadId()!=sdkGuiThread)rc=110;
  else if(core && snego && active && !active() && engine==(void*)AH_SDK_ENGINE_ADDRESS){
#ifdef AH_SDK_RECOVER_ENGINE_CONFIG
   rc=ahSdkRecoverOwnRuntime(engine,core,(uintptr_t)GetModuleHandleW(L"backend.dll"));
   if(rc==0)rc=execute(engine,(void*)AH_SDK_MODULE_ADDRESS,core,0);
#else
   rc=execute(engine,(void*)AH_SDK_MODULE_ADDRESS,core,0);
#endif
  }
  result(rc);
  InterlockedExchange(&callbackDone,1);
 }
 return CallNextHookEx(0,code,w,l);
}
__declspec(dllexport) HHOOK __cdecl ahSdkInstall(DWORD thread,DWORD *error) {
 HHOOK h=SetWindowsHookExW(3,ahSdkHook,sdkInstance,thread);
 *error=h?0:GetLastError();return h;
}
__declspec(dllexport) DWORD WINAPI ahSdkArmOwnThread(LPVOID argument) {
 DWORD diagnostic[2]={0,0};
 DWORD thread=(DWORD)argument;
 HANDLE h=OpenThread(0x0040,FALSE,thread);
 if(!h){diagnostic[0]=1;diagnostic[1]=GetLastError();}
 typedef DWORD (WINAPI *ThreadOwner)(HANDLE);
 ThreadOwner owner=(ThreadOwner)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"GetProcessIdOfThread");
 BOOL valid=h && identity() && owner && owner(h)==GetCurrentProcessId();if(h)CloseHandle(h);
 if(!valid && diagnostic[0]==0){diagnostic[0]=2;diagnostic[1]=GetLastError();}
 HHOOK hook=0;
 /* This worker and GUI thread now belong to the same original process.
    Win32 requires hMod=NULL for a hook associated with that process; our
    scoped preload retains the DLL containing the callback until owner exit. */
 if(valid){sdkGuiThread=thread;hook=SetWindowsHookExW(3,ahSdkHook,0,thread);if(!hook){diagnostic[0]=3;diagnostic[1]=GetLastError();}}
 HANDLE output=CreateFileW(AH_SDK_ARM_FILE,GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
 if(output!=INVALID_HANDLE_VALUE){DWORD n;WriteFile(output,diagnostic,8,&n,0);FlushFileBuffers(output);CloseHandle(output);}
 if(!hook)return 0;
 /* The registering worker must remain alive while its hook is in use.
    A short-lived installer thread loses the hook before the GUI dequeues
    our private message. Release it here only after the readonly callback. */
 DWORD started=GetTickCount();
 MSG message;
 while(!callbackDone && GetTickCount()-started<30000){
  while(PeekMessageW(&message,0,0,0,PM_REMOVE)){TranslateMessage(&message);DispatchMessageW(&message);}
  Sleep(1);
 }
 BOOL removed=UnhookWindowsHookEx(hook);
 return callbackDone && removed?1:2;
}
#endif
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved){if(reason==DLL_PROCESS_ATTACH)sdkInstance=instance;return TRUE;}
