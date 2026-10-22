/* This independent fixture validates ABI and pointer-output boundaries only.
   Its synthetic map is never mutated; no 1C DLL or metadata API is linked. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
volatile uint32_t ahSdkAbiFault=0,ahFixtureCalls=0,ahFixtureAccepted=0;
uint32_t ahExpectedSelf=0,ahExpectedOutput=0,ahExpectedMap=0,ahExpectedHelper=0;
extern uint32_t ahSdkCall(void*,void*,unsigned,uint32_t*);
extern void ahFactoryFixture(void);
#include "factory_thunk_v49.h"
static unsigned passed=0,failed=0,faults=0;
static void test(unsigned mode) {
 uint32_t self=0x53454c46,map=0x4d41504b;
 unsigned char output[36],helper[36];memset(output,0xa5,36);memset(helper,0xa5,36);
 *(uint32_t*)(output+16)=0;*(uint32_t*)(helper+16)=mode==1?0x5052494f:0;
 ahExpectedSelf=(uint32_t)&self;ahExpectedOutput=(uint32_t)(output+16);
 ahExpectedMap=(uint32_t)&map;ahExpectedHelper=(uint32_t)(helper+16);
 uint32_t args[4]={ahExpectedSelf,ahExpectedOutput,ahExpectedMap,ahExpectedHelper};
 if(mode==2)args[0]=(uint32_t)&map;
 if(mode==3)args[1]+=(uint32_t)4;
 if(mode==4)args[2]=(uint32_t)&self;
 if(mode==5)args[3]+=(uint32_t)4;
 if(mode==8){args[1]=ahExpectedHelper;args[3]=ahExpectedOutput;}
 unsigned char bytes[AH_FACTORY_ADAPTER_LENGTH];memcpy(bytes,ahFactoryAdapterTemplate,sizeof(bytes));
 *(uint32_t*)(bytes+16)=(uint32_t)&ahFactoryFixture;
 if(mode==6)bytes[5]=12;
 if(mode==7)bytes[sizeof(bytes)-2]=12;
 unsigned char *code=VirtualAlloc(0,sizeof(bytes),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
 if(!code){failed++;return;}memcpy(code,bytes,sizeof(bytes));DWORD old=0;
 if(!VirtualProtect(code,sizeof(bytes),PAGE_EXECUTE_READ,&old)||!FlushInstructionCache(GetCurrentProcess(),code,sizeof(bytes))){failed++;VirtualFree(code,0,MEM_RELEASE);return;}
 ahSdkAbiFault=0;uint32_t before=ahFixtureAccepted;
 uint32_t returned=ahSdkCall((void*)0xdeadbeef,code,4,args);
 unsigned accepted=ahFixtureAccepted-before,expected=mode<2||mode==7,guards=1,i;
 for(i=0;i<16;i++)if(output[i]!=0xa5||output[i+20]!=0xa5||helper[i]!=0xa5||helper[i+20]!=0xa5)guards=0;
 unsigned ok=guards&&map==0x4d41504b&&accepted==expected;
 ok=ok&&returned==(expected?ahExpectedOutput:0)&&*(uint32_t*)(output+16)==(expected?0x53454354:0);
 ok=ok&&*(uint32_t*)(helper+16)==(expected?0x48454c50:0);
 if(mode==7){ok=ok&&ahSdkAbiFault==1;faults+=ahSdkAbiFault==1;}else ok=ok&&ahSdkAbiFault==0;
 if(ok)passed++;else failed++;VirtualFree(code,0,MEM_RELEASE);
}
int main(void){unsigned i;for(i=0;i<9;i++)test(i);printf("{\"passed\":%s,\"casesPassed\":%u,\"casesFailed\":%u,\"nativeCalls\":%u,\"accepted\":%u,\"stackFaultsDetected\":%u,\"goldCalls\":0,\"platformDllLoaded\":false}\n",failed?"false":"true",passed,failed,ahFixtureCalls,ahFixtureAccepted,faults);return failed?1:0;}
