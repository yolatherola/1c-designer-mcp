/* Fixed native comparison lifecycle. No OS, source-text I/O, or global pins.
 * Production supplies independently reviewed/pinned validators and call shim.
 * Manager getters return BORROWED source pointers: acquire sources explicitly
 * before passing their consuming smart-reference arguments to factory17.
 * A non-returning/ABI-unknown call retains state; never guess or retry cleanup.
 */
#ifndef AH1C_NATIVE_HEADLESS_COMPARISON_CORE_H
#define AH1C_NATIVE_HEADLESS_COMPARISON_CORE_H
#include <stdint.h>
#include <string.h>
#include "native_comparison_tree_projection.h"

enum AhHpcPhase {AH_HPC_NEW,AH_HPC_REFUSED,AH_HPC_PINNING,AH_HPC_FACTORY_IN_FLIGHT,
 AH_HPC_FACTORY_RETURNED,AH_HPC_EXECUTE_IN_FLIGHT,AH_HPC_EXECUTE_RETURNED,
 AH_HPC_PROJECTING,AH_HPC_KNOWN_CLEAN,AH_HPC_UNKNOWN_RETAIN};
enum AhHpcReason {AH_HPC_NONE,AH_HPC_SCOPE,AH_HPC_READ,AH_HPC_SOURCE_BINDING,
 AH_HPC_FACTORY_OUTPUT,AH_HPC_RESULT_TYPE,AH_HPC_RESULT_SOURCE,AH_HPC_VIEW_LINK,
 AH_HPC_INCOMPLETE,AH_HPC_PROJECTION,AH_HPC_POST_SCOPE,AH_HPC_CALL_UNKNOWN};

typedef struct {
 uint32_t attempts,repeated_attempts,phase,reason;
 uint32_t service,managers[2],manager_owned[2],sources[2],source_owned[2];
 uint32_t source_transfer_in_flight,source_transfer_consumed,result,result_owned,result_address;
 uint32_t factory_attempts,factory_returned,execute_attempts,execute_returned,projection_attempts;
 uint32_t getter_attempts,getter_returned,addref_attempts,release_attempts,call_attempts,call_returned,last_object,last_slot,last_argc;
 uint32_t completion,selected,visited,post_byte,view_pointer;
 uint32_t result_main,result_database,full_pending_verified,database_update_authorized;
 AH1CTreeResult tree;
} AhHpcState;
typedef struct {
 uint32_t (*read)(void *,uint32_t,void *,uint32_t);
 uint32_t (*validate)(void *,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
 uint32_t (*result_type)(void *,uint32_t);
 uint32_t (*invoke_slot)(void *,uint32_t,uint32_t,uint32_t,const uint32_t *,uint32_t *);
 uint32_t (*project)(void *,uint32_t,AH1CTreeResult *);
} AhHpcOps;

static int ah_hpc_range(uint32_t address,uint32_t size){
 return address>=65536u && !(address&3u) && (uint64_t)address+size<=UINT64_C(4294967296);
}
static int ah_hpc_word(const AhHpcOps *ops,void *ctx,uint32_t address,uint32_t *out){
 return address>=65536u && (uint64_t)address+4<=UINT64_C(4294967296) && ops->read(ctx,address,out,4)==4;
}
static int ah_hpc_call(const AhHpcOps *ops,void *ctx,AhHpcState *s,
 uint32_t object,uint32_t slot,uint32_t argc,const uint32_t *args,uint32_t *out){
 s->last_object=object;s->last_slot=slot;s->last_argc=argc;s->call_attempts++;
 if(!ops->invoke_slot(ctx,object,slot,argc,args,out)){
  s->reason=AH_HPC_CALL_UNKNOWN;s->phase=AH_HPC_UNKNOWN_RETAIN;return 0;
 }
 s->call_returned++;return 1;
}
static int ah_hpc_ref(const AhHpcOps *ops,void *ctx,AhHpcState *s,uint32_t object,uint32_t slot){
 uint32_t ignored,args[1];args[0]=object;
 if(slot==1)s->addref_attempts++;else s->release_attempts++;
 return ah_hpc_call(ops,ctx,s,object,slot,1,args,&ignored);
}
static int ah_hpc_cleanup(const AhHpcOps *ops,void *ctx,AhHpcState *s){
 uint32_t i;
 if(s->phase==AH_HPC_UNKNOWN_RETAIN || s->source_transfer_in_flight)return 0;
 if(s->result_owned){
  if(!ah_hpc_ref(ops,ctx,s,s->result,2))return 0;
  s->result_owned=0;s->result=0;
 }
 for(i=0;i<2;i++)if(s->source_owned[i]){
  if(!ah_hpc_ref(ops,ctx,s,s->sources[i],2))return 0;s->source_owned[i]=0;
 }
 for(i=0;i<2;i++)if(s->manager_owned[i]){
  if(!ah_hpc_ref(ops,ctx,s,s->managers[i],2))return 0;s->manager_owned[i]=0;
 }
 return 1;
}

/* One explicit invocation only. invoke_slot is a checked stdcall shim, not a
 * bool native method: false means ABI/return uncertainty and forbids cleanup.
 * validate phases0/1/2/3/4 bracket pinning, factory, execute, projection.
 * read must validate every readable page. project retains this owned result
 * across both passes; no successful tree independently grants a database write.
 */
static int ah_hpc_run(const AhHpcOps *ops,void *ctx,AhHpcState *s,
 uint32_t service,uint32_t main_manager,uint32_t database_manager,uint32_t expected_main){
 uint32_t i,cached=0,returned=0,args[17],exec_args[4],getter_args[2];uint8_t completed=0,zero_guid[16]={0},zero_descriptor[40]={0};
 if(!s)return 0;
 if(s->attempts){s->repeated_attempts++;return 0;}s->attempts=1;
 if(sizeof(void*)!=4 || !ops || !ops->read || !ops->validate || !ops->result_type || !ops->invoke_slot || !ops->project){
  s->phase=AH_HPC_REFUSED;s->reason=AH_HPC_SCOPE;return 0;
 }
 s->service=service;s->managers[0]=main_manager;s->managers[1]=database_manager;
 if(!ah_hpc_range(service,0xb0) || !ah_hpc_range(main_manager,0x88)
  || !ah_hpc_range(database_manager,0x88) || !ah_hpc_range(expected_main,4)){
  s->phase=AH_HPC_REFUSED;s->reason=AH_HPC_SCOPE;return 0;
 }
 if(!ops->validate(ctx,0,service,main_manager,database_manager,expected_main)){
  s->phase=AH_HPC_REFUSED;s->reason=AH_HPC_SCOPE;return 0;
 }
 s->phase=AH_HPC_PINNING;
 for(i=0;i<2;i++){
  if(!ah_hpc_ref(ops,ctx,s,s->managers[i],1))return 0;s->manager_owned[i]=1;
 }
 for(i=0;i<2;i++){
  if(!ah_hpc_word(ops,ctx,s->managers[i]+0x84,&cached)){s->reason=AH_HPC_READ;goto refuse;}
  if(cached<65536u || (cached&3u)){s->reason=AH_HPC_SOURCE_BINDING;goto refuse;}
  /* Follow the published getter's locking, with the same explicit AddRef as
   * the native stock caller. Its raw cached return is not a transferred ref. */
  getter_args[0]=s->managers[i];getter_args[1]=0;s->getter_attempts++;
  if(!ah_hpc_call(ops,ctx,s,s->managers[i],85,2,getter_args,&returned))return 0;
  s->getter_returned++;s->sources[i]=returned;
  if(returned!=cached){s->reason=AH_HPC_SOURCE_BINDING;goto refuse;}
  if(s->sources[i]<65536u || (s->sources[i]&3u) || (!i && s->sources[i]!=expected_main)){
   s->reason=AH_HPC_SOURCE_BINDING;goto refuse;
  }
  if(!ah_hpc_ref(ops,ctx,s,s->sources[i],1))return 0;s->source_owned[i]=1;
 }
 if(!ops->validate(ctx,1,service,main_manager,database_manager,expected_main)){
  s->reason=AH_HPC_POST_SCOPE;goto refuse;
 }
 args[0]=service;args[1]=(uint32_t)(uintptr_t)&s->result;args[2]=1;args[3]=2;
 args[4]=(uint32_t)(uintptr_t)zero_guid;args[5]=service+0x60;args[6]=service+0x88;
 args[7]=(uint32_t)(uintptr_t)zero_descriptor;args[8]=s->sources[0];args[9]=0;
 args[10]=s->sources[1];args[11]=0;args[12]=0;args[13]=0;args[14]=1;args[15]=0;args[16]=0;
 s->phase=AH_HPC_FACTORY_IN_FLIGHT;s->source_transfer_in_flight=1;s->factory_attempts=1;
 if(!ah_hpc_call(ops,ctx,s,service,7,17,args,&returned))return 0;
 if(returned!=(uint32_t)(uintptr_t)&s->result){s->reason=AH_HPC_FACTORY_OUTPUT;s->phase=AH_HPC_UNKNOWN_RETAIN;return 0;}
 s->factory_returned=1;s->source_transfer_in_flight=0;s->source_transfer_consumed=2;
 s->source_owned[0]=0;s->source_owned[1]=0;s->result_address=s->result;s->phase=AH_HPC_FACTORY_RETURNED;
 if(!s->result){s->reason=AH_HPC_FACTORY_OUTPUT;goto refuse;}
 if(!ah_hpc_range(s->result,0x5a4) || !ops->result_type(ctx,s->result)){
  s->reason=AH_HPC_RESULT_TYPE;s->phase=AH_HPC_UNKNOWN_RETAIN;return 0;
 }
 s->result_owned=1;
 if(!ah_hpc_word(ops,ctx,s->result+0x34,&s->result_main) || !ah_hpc_word(ops,ctx,s->result+0x38,&s->result_database)
  || !ah_hpc_word(ops,ctx,s->result+0x5a0,&s->view_pointer)){s->reason=AH_HPC_READ;goto refuse;}
 if(s->result_main!=s->sources[0] || s->result_database!=s->sources[1]){s->reason=AH_HPC_RESULT_SOURCE;goto refuse;}
 if(s->view_pointer){s->reason=AH_HPC_VIEW_LINK;goto refuse;}
 if(!ops->validate(ctx,2,service,main_manager,database_manager,expected_main)){s->reason=AH_HPC_POST_SCOPE;goto refuse;}
 exec_args[0]=s->result;exec_args[1]=0;exec_args[2]=(uint32_t)(uintptr_t)zero_guid;exec_args[3]=0;
 s->execute_attempts=1;s->phase=AH_HPC_EXECUTE_IN_FLIGHT;
 if(!ah_hpc_call(ops,ctx,s,s->result,11,4,exec_args,&returned))return 0;
 s->execute_returned=1;s->phase=AH_HPC_EXECUTE_RETURNED;
 if(ops->read(ctx,s->result+0x274,&completed,1)!=1
  || !ah_hpc_word(ops,ctx,s->result+0x298,&s->selected) || !ah_hpc_word(ops,ctx,s->result+0x29c,&s->visited)
  || !ah_hpc_word(ops,ctx,s->result+0x5a0,&s->view_pointer)){s->reason=AH_HPC_READ;goto refuse;}
 s->completion=completed;
 if(s->completion!=1 || !s->selected || s->selected>65536u || s->selected!=s->visited){s->reason=AH_HPC_INCOMPLETE;goto refuse;}
 if(s->view_pointer){s->reason=AH_HPC_VIEW_LINK;goto refuse;}
 if(!ops->validate(ctx,3,service,main_manager,database_manager,expected_main)){s->reason=AH_HPC_POST_SCOPE;goto refuse;}
 s->phase=AH_HPC_PROJECTING;s->projection_attempts=1;
 if(!ops->project(ctx,s->result,&s->tree) || !s->tree.coherent || !s->tree.traversal_complete
  || s->tree.passes_completed!=2 || !s->tree.all_object_flags_observed || s->tree.object_mask20_count){s->reason=AH_HPC_PROJECTION;goto refuse;}
 if(!ops->validate(ctx,4,service,main_manager,database_manager,expected_main)){s->reason=AH_HPC_POST_SCOPE;goto refuse;}
 if(!ah_hpc_cleanup(ops,ctx,s))return 0;
 s->phase=AH_HPC_KNOWN_CLEAN;s->reason=AH_HPC_NONE;return 1;
refuse:
 if(!ah_hpc_cleanup(ops,ctx,s))return 0;s->phase=AH_HPC_REFUSED;return 0;
}
#endif
