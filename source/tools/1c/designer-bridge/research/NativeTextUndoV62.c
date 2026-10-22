/* Independent finite core::TextManager, never Designer/Gold/repository.
   No source/store/dirty-flag patches. Every exported address is pinned. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "text_undo_bindings_v62.h"
int ahSdkAbiFault=0;
extern uint32_t ahSdkCall(void*,void*,uint32_t,uint32_t*);
static void *functions[13];
static HMODULE ownCore;
static LONG CALLBACK ownFaultObserver(PEXCEPTION_POINTERS info){
 char path[MAX_PATH],body[240];HANDLE h;DWORD n;uintptr_t pc=(uintptr_t)info->ExceptionRecord->ExceptionAddress,base=(uintptr_t)ownCore;
 unsigned rva=pc>=base && pc<base+0x400000?(unsigned)(pc-base):0;
 if(info->ExceptionRecord->ExceptionCode!=EXCEPTION_ACCESS_VIOLATION)return EXCEPTION_CONTINUE_SEARCH;
 sprintf(path,"%s\\fault.json",AH_OUT);sprintf(body,"{\"code\":3221225477,\"coreRva\":%u,\"accessKind\":%u,\"targetNearNull\":%s}",rva,(unsigned)info->ExceptionRecord->ExceptionInformation[0],info->ExceptionRecord->ExceptionInformation[1]<4096?"true":"false");
 h=CreateFileA(path,GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
 if(h!=INVALID_HANDLE_VALUE){WriteFile(h,body,(DWORD)strlen(body),&n,0);FlushFileBuffers(h);CloseHandle(h);}
 return EXCEPTION_CONTINUE_SEARCH;
}
static uint32_t call(unsigned slot,void*self,unsigned count,uint32_t*args){
 if(ahSdkAbiFault)return 0;
 return ahSdkCall(self,functions[slot],count,args);
}
static int marker(const char *name){
 char path[MAX_PATH];HANDLE h;DWORD written;
 if(strlen(AH_OUT)+strlen(name)+2>=MAX_PATH)return 0;
 sprintf(path,"%s\\%s",AH_OUT,name);h=CreateFileA(path,GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
 if(h==INVALID_HANDLE_VALUE)return 0;
 WriteFile(h,name,(DWORD)strlen(name),&written,0);FlushFileBuffers(h);CloseHandle(h);return 1;
}
int main(void){
 HMODULE core;unsigned i;uint32_t args[4],code=0;void *external=0;
 unsigned char region[4096+32],positions[4][12];void*self=region+16;wchar_t*area=0;
 const wchar_t *text=L"// AH1C standalone Undo V62\r\n";
 LARGE_INTEGER f,a,b;int initial,inserted,undoAccepted,restored,canUndo,afterCanUndo,guards,initialModified,insertModified,restoreModified;
 BOOL (WINAPI *setOwnDllDirectory)(LPCSTR);
 PVOID (WINAPI *addOwnFaultObserver)(ULONG,PVECTORED_EXCEPTION_HANDLER);
 SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
 /* The pinned tinycc import library predates this Windows API. Resolve the
    documented export; the directory change applies only to this fixture. */
 setOwnDllDirectory=(void*)GetProcAddress(GetModuleHandleA("kernel32.dll"),"SetDllDirectoryA");
 if(!setOwnDllDirectory || !setOwnDllDirectory(AH_PLATFORM))return 10;
 core=LoadLibraryExA(AH_CORE,0,LOAD_WITH_ALTERED_SEARCH_PATH);if(!core)return 11;
 ownCore=core;addOwnFaultObserver=(void*)GetProcAddress(GetModuleHandleA("kernel32.dll"),"AddVectoredExceptionHandler");
 if(!addOwnFaultObserver || !addOwnFaultObserver(1,ownFaultObserver))return 23;
 for(i=0;i<13;i++){functions[i]=GetProcAddress(core,ahNames[i]);if(!functions[i] || functions[i]!=(void*)((unsigned char*)core+ahRvas[i]))return 12;}
 memset(region,0,sizeof(region));memset(region,0xa5,16);memset(region+sizeof(region)-16,0x5a,16);memset(positions,0,sizeof(positions));
 if(!marker("ctor-dispatched"))return 13;
 call(0,self,0,0);if(ahSdkAbiFault)return 14;
 initial=(call(4,self,0,0)&255)!=0;initialModified=(call(10,self,0,0)&255)!=0;if(!initial || initialModified)return 15;
 for(i=0;i<4;i++){args[0]=i<2?1:2;args[1]=1;call(2,positions[i],2,args);}
 args[0]=args[1]=args[2]=args[3]=1;call(5,self,4,args);
 args[0]=0;args[1]=(uint32_t)positions[0];args[2]=(uint32_t)positions[1];args[3]=0;
 if(!marker("action-begin-dispatched"))return 27;
 if(!(call(11,self,4,args)&255) || ahSdkAbiFault)return 28;
 args[0]=(uint32_t)text;args[1]=1;
 if(!marker("insert-dispatched"))return 16;
 call(6,self,2,args);if(ahSdkAbiFault)return 17;
 if(!marker("insert-returned"))return 24;
 /* The insertion ends at line2,col1. Read the exact own selection through
    the pinned borrowed-pointer getter; getTextArea is excluded after AV. */
 args[0]=1;args[1]=1;args[2]=2;args[3]=1;call(5,self,4,args);
 if(!marker("area-dispatched"))return 25;
 area=(wchar_t*)call(7,self,0,0);if(!marker("area-returned"))return 26;
 inserted=area && wcsncmp(area,text,wcslen(text)+1)==0 && !(call(4,self,0,0)&255);
 args[0]=2;args[1]=1;args[2]=2;args[3]=1;call(5,self,4,args);
 args[0]=(uint32_t)positions[2];args[1]=(uint32_t)positions[3];call(12,self,2,args);
 if(!marker("action-closed"))return 29;
 insertModified=(call(10,self,0,0)&255)!=0;
 args[0]=(uint32_t)&code;canUndo=(call(8,self,1,args)&255)!=0;
 if(!inserted || !canUndo || ahSdkAbiFault){
  unsigned selectedLength=0;if(area)while(selectedLength<128 && area[selectedLength])selectedLength++;
  printf("{\"preUndoRejected\":true,\"insertionExact\":%s,\"canUndoBefore\":%s,\"selectedTextNull\":%s,\"selectedLength\":%u,\"expectedLength\":%u,\"wcharBytes\":%u,\"insertModified\":%s,\"stackFault\":%s}\n",inserted?"true":"false",canUndo?"true":"false",area?"false":"true",selectedLength,(unsigned)wcslen(text),(unsigned)sizeof(wchar_t),insertModified?"true":"false",ahSdkAbiFault?"true":"false");
  return 18;
 }
 args[0]=(uint32_t)positions[0];args[1]=(uint32_t)positions[1];args[2]=(uint32_t)&external;args[3]=0;
 if(!marker("undo-dispatched"))return 19;
 QueryPerformanceFrequency(&f);QueryPerformanceCounter(&a);undoAccepted=(call(9,self,4,args)&255)!=0;QueryPerformanceCounter(&b);
 restored=(call(4,self,0,0)&255)!=0;restoreModified=(call(10,self,0,0)&255)!=0;args[0]=(uint32_t)&code;afterCanUndo=(call(8,self,1,args)&255)!=0;
 if(external)return 20;
 for(i=0;i<4;i++)call(3,positions[i],0,0);
 call(1,self,0,0);guards=1;
 for(i=0;i<16;i++)if(region[i]!=0xa5 || region[sizeof(region)-16+i]!=0x5a)guards=0;
 if(!marker("native-returned"))return 21;
 printf("{\"passed\":%s,\"initialEmpty\":%s,\"insertionExact\":%s,\"canUndoBefore\":%s,\"undoAccepted\":%s,\"restoredEmpty\":%s,\"canUndoAfter\":%s,\"externalObjectNull\":true,\"stackFault\":%s,\"canariesPreserved\":%s,\"undoUs\":%.3f,\"goldCalls\":0,\"platformDllLoaded\":true,\"documentCleanStateVerified\":false,\"textManagerInitialModified\":%s,\"textManagerInsertModified\":%s,\"textManagerRestoreModified\":%s}\n",undoAccepted&&restored&&!afterCanUndo&&guards&&!ahSdkAbiFault&&!restoreModified?"true":"false",initial?"true":"false",inserted?"true":"false",canUndo?"true":"false",undoAccepted?"true":"false",restored?"true":"false",afterCanUndo?"true":"false",ahSdkAbiFault?"true":"false",guards?"true":"false",f.QuadPart>0?(double)(b.QuadPart-a.QuadPart)*1000000.0/(double)f.QuadPart:-1.0,initialModified?"true":"false",insertModified?"true":"false",restoreModified?"true":"false");
 FreeLibrary(core);return undoAccepted&&restored&&!afterCanUndo&&guards&&!ahSdkAbiFault&&!restoreModified?0:22;
}
