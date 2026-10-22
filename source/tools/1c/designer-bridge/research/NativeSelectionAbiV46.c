/* Execute a standalone ABI fixture on private memory, never a platform DLL.
   The independent assembler callee validates all input pointers and argument
   positions before changing one DWORD in this process's guarded result. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

volatile uint32_t ahSdkAbiFault=0,ahFixtureCalls=0,ahFixtureAccepted=0;
uint32_t ahExpectedSelf=0,ahExpectedSelected=0,ahExpectedApplication=0;
uint32_t ahExpectedCapture=0,ahExpectedResult=0,ahExpectedReturn=0;
extern uint32_t ahSdkCall(void *self,void *target,unsigned argc,uint32_t *argv);
extern void ahSelectionFixture(void);
#include "selection_thunk_v46.h"

static unsigned passed=0,failed=0,stackFaultsDetected=0;
static unsigned char *adapter(unsigned char mutation) {
 unsigned char bytes[AH_SELECTION_ADAPTER_LENGTH];
 memcpy(bytes,ahSelectionAdapterTemplate,sizeof(bytes));
 *(uint32_t*)(bytes+19)=(uint32_t)&ahSelectionFixture;
 if(mutation==1)bytes[5]=12;       /* Wrong explicit self offset. */
 if(mutation==2)bytes[sizeof(bytes)-2]=16; /* Wrong stdcall stack pop. */
 unsigned char *code=VirtualAlloc(0,sizeof(bytes),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
 if(!code)return 0;memcpy(code,bytes,sizeof(bytes));
 DWORD old=0;
 if(!VirtualProtect(code,sizeof(bytes),PAGE_EXECUTE_READ,&old) || !FlushInstructionCache(GetCurrentProcess(),code,sizeof(bytes))) {
  VirtualFree(code,0,MEM_RELEASE);return 0;
 }
 return code;
}
static void test(unsigned mode) {
 uint32_t self=0x53454c46,selected=0x53454c31,application=0x41505032;
 unsigned char result[16+264+16];memset(result,0xa5,sizeof(result));memset(result+16,0,264);
 ahExpectedSelf=(uint32_t)&self;ahExpectedSelected=(uint32_t)&selected;
 ahExpectedApplication=(uint32_t)&application;ahExpectedResult=(uint32_t)(result+16);
 ahExpectedCapture=mode==1?0:1;ahExpectedReturn=mode==2?0xaabbcc00:0xaabbcc01;
 uint32_t args[5]={ahExpectedSelf,ahExpectedSelected,ahExpectedApplication,ahExpectedCapture,ahExpectedResult};
 if(mode==3)args[0]=(uint32_t)&application;
 if(mode==4)args[1]=(uint32_t)&self;
 if(mode==5)args[2]=(uint32_t)&selected;
 if(mode==6)args[3]=3;
 if(mode==7)args[4]=(uint32_t)(result+20);
 unsigned char *code=adapter(mode==8?1:mode==9?2:0);
 if(!code){failed++;return;}
 ahSdkAbiFault=0;uint32_t before=ahFixtureAccepted;
 uint32_t returned=ahSdkCall((void*)0xdeadbeef,code,5,args);
 unsigned accepted=ahFixtureAccepted-before;
 unsigned guards=1,i;
 for(i=0;i<16;i++)if(result[i]!=0xa5 || result[i+280]!=0xa5)guards=0;
 uint32_t magic=*(uint32_t*)(result+16);
 unsigned expectAccepted=(mode<3 || mode==9);
 unsigned ok=guards && accepted==expectAccepted && magic==(expectAccepted?0x46583634:0);
 if(mode==9){ok=ok && ahSdkAbiFault==1;stackFaultsDetected+=ahSdkAbiFault==1;}
 else ok=ok && ahSdkAbiFault==0;
 if(expectAccepted)ok=ok && returned==ahExpectedReturn && (unsigned char)returned==(mode==2?0:1);
 else ok=ok && returned==0;
 if(ok)passed++;else failed++;
 VirtualFree(code,0,MEM_RELEASE);
}
int main(void) {
 unsigned n;for(n=0;n<10;n++)test(n);
 printf("{\"passed\":%s,\"casesPassed\":%u,\"casesFailed\":%u,\"nativeCalls\":%u,\"accepted\":%u,\"stackFaultsDetected\":%u,\"resultBytes\":264,\"goldCalls\":0,\"platformDllLoaded\":false}\n",failed?"false":"true",passed,failed,ahFixtureCalls,ahFixtureAccepted,stackFaultsDetected);
 return failed?1:0;
}
