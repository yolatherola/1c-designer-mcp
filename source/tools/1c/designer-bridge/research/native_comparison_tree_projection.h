/* Pure technical tree reader, derived from frozen Python projection31a13.
 * No process APIs, I/O, native result calls, ownership acquisition or globals.
 * Caller must retain its newly owned result through BOTH complete passes and
 * supply an exact-read callback that independently validates readable pages.
 * Exact full technical-record equality is coherence, never DB permission. */
#ifndef AH1C_NATIVE_COMPARISON_TREE_PROJECTION_H
#define AH1C_NATIVE_COMPARISON_TREE_PROJECTION_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define AH1C_TREE_MAX_NODES 1048576u
#define AH1C_TREE_MAX_DEPTH 256u
#define AH1C_TREE_MAX_BYTES 134217728u
#define AH1C_TREE_MAX_WORKSPACE 134217728u
#define AH1C_TREE_MAX_ROWS 256u
#define AH1C_TREE_FRAME_COUNT 258u

typedef uint32_t (*AH1CTreeRead)(void *,uint32_t,void *,uint32_t);
typedef void *(*AH1CTreeAlloc)(void *,size_t);
typedef void (*AH1CTreeFree)(void *,void *);
typedef struct {uint32_t max_nodes,max_depth,max_bytes,max_rows,max_workspace_bytes;} AH1CTreeLimits;
enum AH1CTreeError {
 AH1C_TREE_OK=0,AH1C_TREE_LIMITS,AH1C_TREE_ADDRESS_BOUND,AH1C_TREE_BYTE_LIMIT,
 AH1C_TREE_SHORT_READ,AH1C_TREE_CYCLE_OR_DUPLICATE,AH1C_TREE_DEPTH_LIMIT,
 AH1C_TREE_NODE_LIMIT,AH1C_TREE_PARENT_OR_KIND,AH1C_TREE_ROOT_SHAPE,
 AH1C_TREE_PROPERTY_OWNER_OR_CHILD,AH1C_TREE_ROW_LIMIT,AH1C_TREE_INCOHERENT,
 AH1C_TREE_ALLOCATION_LIMIT,AH1C_TREE_ALLOCATION_FAILED,AH1C_TREE_STACK_LIMIT
};
typedef struct {
 uint32_t kind,raw_change_code,depth,has_object_pair;
 uint8_t object_pair[32],property_uuid[16],group_uuid[16];
} AH1CTreeRow;
typedef struct {
 uint32_t error,failure_pass,passes_completed,nodes_read,bytes_read,depth;
 uint32_t kind_counts[4],raw_code_counts[256],object_flags_observed,object_mask20_count;
 uint32_t row_count,max_read_bytes,traversal_complete,coherent,all_object_flags_observed;
 uint32_t ownership_verified,epoch_verified,full_pending_verified,database_update_authorized;
 uint32_t workspace_bytes;
 AH1CTreeRow rows[AH1C_TREE_MAX_ROWS];
} AH1CTreeResult;
typedef struct {
 uint32_t address;
 uint8_t header[36],payload[32],object_flags,payload_bytes;
 uint16_t depth;
} AH1CTreeRecord;
typedef char AH1CTreeRecordSizeMustBe76[(sizeof(AH1CTreeRecord)==76)?1:-1];
typedef struct {uint32_t address,parent,depth,has_owner;uint8_t owner[32];} AH1CTreeFrame;

static const char *ah1c_tree_error_name(uint32_t error){
 static const char *names[]={"OK","LIMITS","ADDRESS_BOUND","BYTE_LIMIT","SHORT_READ",
 "CYCLE_OR_DUPLICATE","DEPTH_LIMIT","NODE_LIMIT","PARENT_OR_KIND","ROOT_SHAPE",
 "PROPERTY_OWNER_OR_CHILD","ROW_LIMIT","INCOHERENT_SNAPSHOT","ALLOCATION_LIMIT",
 "ALLOCATION_FAILED","STACK_LIMIT"};
 return error<sizeof(names)/sizeof(names[0])?names[error]:"UNKNOWN";
}
static AH1CTreeLimits ah1c_tree_default_limits(void){
 AH1CTreeLimits value={AH1C_TREE_MAX_NODES,AH1C_TREE_MAX_DEPTH,AH1C_TREE_MAX_BYTES,
                     AH1C_TREE_MAX_ROWS,AH1C_TREE_MAX_WORKSPACE};return value;
}
static uint32_t ah1c_tree_word(const uint8_t *p){
 return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static int ah1c_tree_fail(AH1CTreeResult *out,uint32_t error){out->error=error;return 0;}
static int ah1c_tree_take(AH1CTreeRead read,void *context,uint64_t address,uint32_t length,
                        uint32_t byte_limit,void *destination,AH1CTreeResult *out){
 if(address<65536u || (address&3u) || !length || length>36u || address+length>UINT64_C(4294967296))
  return ah1c_tree_fail(out,AH1C_TREE_ADDRESS_BOUND);
 if((uint64_t)out->bytes_read+length>byte_limit)return ah1c_tree_fail(out,AH1C_TREE_BYTE_LIMIT);
 if(read(context,(uint32_t)address,destination,length)!=length)return ah1c_tree_fail(out,AH1C_TREE_SHORT_READ);
 out->bytes_read+=length;if(length>out->max_read_bytes)out->max_read_bytes=length;return 1;
}

/* Returns zero on ANY refusal. Failure exposes only bounded technical counters;
 * rows on failure are partial observations and must never be accepted as full. */
static int ah1c_tree_project_pair(AH1CTreeRead first,void *first_context,
 AH1CTreeRead second,void *second_context,uint32_t root,const AH1CTreeLimits *limits,
 AH1CTreeAlloc allocate,AH1CTreeFree release,void *memory_context,AH1CTreeResult *out){
 AH1CTreeRecord *records=0;uint32_t *seen=0,capacity=1,pass,first_count=0;
 AH1CTreeFrame pending[AH1C_TREE_FRAME_COUNT];uint64_t record_bytes,seen_bytes,total;
 int success=0;
 if(!out)return 0;memset(out,0,sizeof(*out));
 if(!first || !second || !allocate || !release || !limits || !limits->max_nodes
  || limits->max_nodes>AH1C_TREE_MAX_NODES || !limits->max_depth || limits->max_depth>AH1C_TREE_MAX_DEPTH
  || limits->max_bytes<36 || limits->max_bytes>AH1C_TREE_MAX_BYTES || !limits->max_rows
  || limits->max_rows>AH1C_TREE_MAX_ROWS || !limits->max_workspace_bytes
  || limits->max_workspace_bytes>AH1C_TREE_MAX_WORKSPACE)return ah1c_tree_fail(out,AH1C_TREE_LIMITS);
 if(root<65536u || (root&3u) || (uint64_t)root+36u>UINT64_C(4294967296))
  return ah1c_tree_fail(out,AH1C_TREE_ADDRESS_BOUND);
 while(capacity<limits->max_nodes*2u)capacity<<=1;
 record_bytes=(uint64_t)limits->max_nodes*sizeof(*records);seen_bytes=(uint64_t)capacity*sizeof(*seen);
 total=record_bytes+seen_bytes+sizeof(pending);
 if(total>limits->max_workspace_bytes || record_bytes>(size_t)-1 || seen_bytes>(size_t)-1)
  return ah1c_tree_fail(out,AH1C_TREE_ALLOCATION_LIMIT);
 out->workspace_bytes=(uint32_t)total;
 records=(AH1CTreeRecord*)allocate(memory_context,(size_t)record_bytes);
 if(!records){ah1c_tree_fail(out,AH1C_TREE_ALLOCATION_FAILED);goto cleanup;}
 seen=(uint32_t*)allocate(memory_context,(size_t)seen_bytes);
 if(!seen){ah1c_tree_fail(out,AH1C_TREE_ALLOCATION_FAILED);goto cleanup;}
 for(pass=1;pass<=2;pass++){
  uint32_t pending_count=1;
  AH1CTreeRead read=pass==1?first:second;void *context=pass==1?first_context:second_context;
  out->failure_pass=pass;out->nodes_read=out->bytes_read=out->depth=out->row_count=0;
  out->object_flags_observed=out->object_mask20_count=0;
  memset(out->kind_counts,0,sizeof(out->kind_counts));memset(out->raw_code_counts,0,sizeof(out->raw_code_counts));
  memset(seen,0,(size_t)seen_bytes);memset(&pending[0],0,sizeof(pending[0]));pending[0].address=root;
  while(pending_count){
   AH1CTreeFrame frame=pending[--pending_count],child_frame,sibling_frame;
   AH1CTreeRecord record;AH1CTreeRow row;uint32_t slot,parent,child,sibling,payload,kind,change,index;
   out->depth=frame.depth;
   slot=((frame.address>>2)*2654435761u)&(capacity-1);
   while(seen[slot] && seen[slot]!=frame.address)slot=(slot+1)&(capacity-1);
   if(seen[slot]){ah1c_tree_fail(out,AH1C_TREE_CYCLE_OR_DUPLICATE);goto cleanup;}
   if(frame.depth>limits->max_depth){ah1c_tree_fail(out,AH1C_TREE_DEPTH_LIMIT);goto cleanup;}
   if(out->nodes_read>=limits->max_nodes){ah1c_tree_fail(out,AH1C_TREE_NODE_LIMIT);goto cleanup;}
   seen[slot]=frame.address;memset(&record,0,sizeof(record));record.address=frame.address;record.depth=(uint16_t)frame.depth;
   if(!ah1c_tree_take(read,context,frame.address,36,limits->max_bytes,record.header,out))goto cleanup;
   index=out->nodes_read++;parent=ah1c_tree_word(record.header);child=ah1c_tree_word(record.header+4);
   sibling=ah1c_tree_word(record.header+8);payload=ah1c_tree_word(record.header+20);
   kind=record.header[25];change=record.header[26];
   if(parent!=frame.parent || kind>3){ah1c_tree_fail(out,AH1C_TREE_PARENT_OR_KIND);goto cleanup;}
   if(!frame.depth && (kind!=1 || frame.parent || sibling)){ah1c_tree_fail(out,AH1C_TREE_ROOT_SHAPE);goto cleanup;}
   memset(&row,0,sizeof(row));row.kind=kind;row.raw_change_code=change;row.depth=frame.depth;
   sibling_frame=frame;child_frame=frame;
   if(kind==1){
    if(!ah1c_tree_take(read,context,(uint64_t)payload+8,32,limits->max_bytes,record.payload,out)
     || !ah1c_tree_take(read,context,payload,1,limits->max_bytes,&record.object_flags,out))goto cleanup;
    record.payload_bytes=32;row.has_object_pair=1;memcpy(row.object_pair,record.payload,32);
    child_frame.has_owner=1;memcpy(child_frame.owner,record.payload,32);
    out->object_flags_observed++;if(record.object_flags&0x20)out->object_mask20_count++;
   }else if(kind==3){
    if(!frame.has_owner || child){ah1c_tree_fail(out,AH1C_TREE_PROPERTY_OWNER_OR_CHILD);goto cleanup;}
    if(!ah1c_tree_take(read,context,(uint64_t)payload+36,16,limits->max_bytes,record.payload,out))goto cleanup;
    record.payload_bytes=16;row.has_object_pair=1;memcpy(row.object_pair,frame.owner,32);memcpy(row.property_uuid,record.payload,16);
   }else if(kind==0){
    if(!ah1c_tree_take(read,context,payload,16,limits->max_bytes,record.payload,out))goto cleanup;
    record.payload_bytes=16;memcpy(row.group_uuid,record.payload,16);
   }
   if(pass==1)records[index]=record;
   else if(index>=first_count || memcmp(&record,&records[index],sizeof(record))){ah1c_tree_fail(out,AH1C_TREE_INCOHERENT);goto cleanup;}
   out->kind_counts[kind]++;out->raw_code_counts[change]++;
   if(change){
    if(out->row_count>=limits->max_rows){ah1c_tree_fail(out,AH1C_TREE_ROW_LIMIT);goto cleanup;}
    out->rows[out->row_count++]=row;
   }
   if(sibling){
    if(pending_count>=AH1C_TREE_FRAME_COUNT){ah1c_tree_fail(out,AH1C_TREE_STACK_LIMIT);goto cleanup;}
    sibling_frame.address=sibling;pending[pending_count++]=sibling_frame;
   }
   if(child){
    if(pending_count>=AH1C_TREE_FRAME_COUNT){ah1c_tree_fail(out,AH1C_TREE_STACK_LIMIT);goto cleanup;}
    child_frame.address=child;child_frame.parent=frame.address;child_frame.depth=frame.depth+1;
    pending[pending_count++]=child_frame;
   }
  }
  if(pass==1)first_count=out->nodes_read;
  else if(out->nodes_read!=first_count){ah1c_tree_fail(out,AH1C_TREE_INCOHERENT);goto cleanup;}
  out->passes_completed=pass;
 }
 out->failure_pass=0;out->traversal_complete=out->coherent=out->all_object_flags_observed=1;success=1;
cleanup:
 if(seen)release(memory_context,seen);if(records)release(memory_context,records);return success;
}
#endif
