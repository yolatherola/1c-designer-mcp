/* Fixed synthetic bus bridge, x86 only. Root owns the ONE 4-DWORD WINAPI export.
 * Root validates caller RAM pages before this function; no target-process IO.
 * Frozen sink is included unchanged. No event connector/trap/Gold calls here.
 */
#ifndef AH_NATIVE_SYNTHETIC_EVENT_BRIDGE_H
#define AH_NATIVE_SYNTHETIC_EVENT_BRIDGE_H
#include "native_update_event_sink.h"
enum {AH_SEB_CREATE=1,AH_SEB_SET_NODES=2,AH_SEB_SET_PAYLOAD=3,AH_SEB_SNAPSHOT=4,AH_SEB_DISARM=5,AH_SEB_FINISH=6};
enum {AH_SEB_OK=0,AH_SEB_REFUSED=1,AH_SEB_REFUSED_RETAIN=2,AH_SEB_BAD_INPUT=3,AH_SEB_ENVIRONMENT=4};
enum {AH_SEB_FRESH=0,AH_SEB_ACTIVE=1,AH_SEB_DISARMED=2,AH_SEB_FINISHED=3};
typedef struct AhSebCreate {DWORD size;AhEsVariant *empty_variant;} AhSebCreate;
typedef struct AhSebNodes {DWORD size;AhEsDispatch *message_node,*modal_node;} AhSebNodes;
typedef struct AhSebPayload {DWORD size,kind;AhEsDispatch *payload;} AhSebPayload;
typedef struct AhSebSnapshot {
    DWORD size,version,status,phase,operation,sink_pointer,refs,busy,armed,nodes_set,payload_set,payload_kind;
    DWORD guard_accepts,guard_rejects,admitted,modal_seen,last_stage,message_seen,answers,rejected;
    DWORD mutations,poisoned,last_error,reentrant,property_calls,finished;
} AhSebSnapshot;
typedef BOOL (*AhSebEnvironment)(void*,DWORD);
typedef struct AhSebBridge {
    /* Caller initializes only these four root-owned lifetime dependencies. */
    AhSebEnvironment environment;void *environment_context;AhEsClear clear;AhEsStringLen string_len;
    /* All remaining members start zero; do not edit after the first CREATE. */
    DWORD phase,operation;AhEventSink *sink;AhEsDispatch *message_node,*modal_node,*payload;
    DWORD payload_kind,guard_accepts,guard_rejects;AhEsState final_state;
} AhSebBridge;
AH_ES_ASSERT(seb_create,sizeof(AhSebCreate)==8);
AH_ES_ASSERT(seb_nodes,sizeof(AhSebNodes)==12 && offsetof(AhSebNodes,modal_node)==8);
AH_ES_ASSERT(seb_payload,sizeof(AhSebPayload)==12 && offsetof(AhSebPayload,payload)==8);
AH_ES_ASSERT(seb_snapshot,sizeof(AhSebSnapshot)==104 && offsetof(AhSebSnapshot,refs)==24
    && offsetof(AhSebSnapshot,guard_accepts)==48 && offsetof(AhSebSnapshot,finished)==100);

static BOOL ah_seb_guard(void *context,ULONG operation,LONG member,const AhEsParams *params,UINT *selected){
    AhSebBridge *b=(AhSebBridge*)context;AhEsDispatch *node;UINT i,payloads=0,nodes=0;
    if(!b || b->phase!=AH_SEB_ACTIVE || !b->sink || operation!=b->operation
        || !b->environment || !b->environment(b->environment_context,operation)
        || !b->payload || b->payload_kind!=(DWORD)member || !params || !params->args || params->count!=2
        || params->named_count || params->named)goto rejected;
    node=member==AH_ES_MSG?b->message_node:member==AH_ES_MODAL?b->modal_node:NULL;
    if(!node || node==b->payload)goto rejected;
    for(i=0;i<params->count;i++){
        AhEsVariant *v=&params->args[i];
        if(v->vt!=AH_ES_VT_DISPATCH || v->r1 || v->r2 || v->r3)goto rejected;
        if(v->value.dispatch==b->payload){*selected=i;payloads++;}
        else if(v->value.dispatch==node)nodes++;
        else goto rejected;
    }
    if(payloads!=1 || nodes!=1)goto rejected;b->guard_accepts++;return TRUE;
rejected:
    if(b)b->guard_rejects++;return FALSE;
}
static DWORD ah_seb_snapshot(AhSebBridge *b,AhSebSnapshot *out,DWORD status){
    AhEsState *state=&b->final_state;AhEventSink *sink=b->sink;
    memset(out,0,sizeof(*out));out->size=sizeof(*out);out->version=1;out->status=status;
    out->phase=b->phase;out->operation=b->operation;out->sink_pointer=(DWORD)(uintptr_t)sink;
    if(sink){
        out->refs=(DWORD)InterlockedCompareExchange(&sink->refs,0,0);
        out->busy=(DWORD)InterlockedCompareExchange(&sink->busy,0,0);
        out->armed=(DWORD)InterlockedCompareExchange(&sink->armed,0,0);state=&sink->state;
    }
    out->nodes_set=b->message_node && b->modal_node;out->payload_set=b->payload!=NULL;out->payload_kind=b->payload_kind;
    out->guard_accepts=b->guard_accepts;out->guard_rejects=b->guard_rejects;out->admitted=state->admitted;
    out->modal_seen=state->modal_seen;out->last_stage=state->last_stage;out->message_seen=state->message_seen;
    out->answers=state->answers;out->rejected=state->rejected;out->mutations=state->mutation_attempts;
    out->poisoned=state->poisoned;out->last_error=state->last_error;out->reentrant=state->reentrant;
    out->property_calls=state->property_calls;out->finished=b->phase==AH_SEB_FINISHED;return status;
}
/* Signature of root wrapper:
 * DWORD WINAPI bridge(DWORD command,DWORD operation,DWORD input,DWORD output) {
 *   root_page_checks(...); return ahSyntheticEventBridgeCall(&rootStatic,...);
 * }
 * The AS void4DWORD delegate may ignore return: status is in the snapshot.
 */
static DWORD ahSyntheticEventBridgeCall(AhSebBridge *b,DWORD command,DWORD operation,DWORD input,DWORD output){
    AhSebSnapshot *out=(AhSebSnapshot*)(uintptr_t)output;AhEventSink *sink;DWORD status=AH_SEB_REFUSED;
    if(!b || !out || out->size!=sizeof(*out))return AH_SEB_BAD_INPUT;
    if(!operation || !b->environment || !b->environment(b->environment_context,operation))return ah_seb_snapshot(b,out,AH_SEB_ENVIRONMENT);
    if((command==AH_SEB_SNAPSHOT || command==AH_SEB_DISARM || command==AH_SEB_FINISH) && input)
        return ah_seb_snapshot(b,out,AH_SEB_BAD_INPUT);
    if(command==AH_SEB_CREATE){
        AhSebCreate *create=(AhSebCreate*)(uintptr_t)input;AhEsConfig config;AhEsVariant empty;
        if(b->phase!=AH_SEB_FRESH || b->operation || b->sink)return ah_seb_snapshot(b,out,AH_SEB_REFUSED_RETAIN);
        memset(&empty,0,sizeof(empty));
        if(!create || create->size!=sizeof(*create) || !create->empty_variant || !b->clear || !b->string_len
            || memcmp(create->empty_variant,&empty,sizeof(empty)))return ah_seb_snapshot(b,out,AH_SEB_BAD_INPUT);
        memset(&config,0,sizeof(config));config.operation=operation;config.guard=ah_seb_guard;config.guard_context=b;
        config.clear=b->clear;config.string_len=b->string_len;config.rule_count=1;config.max_callbacks=32;
        config.rules[0].text=L"AH1C_SYNTHETIC_EVENT";
        config.rules[0].length=(sizeof(L"AH1C_SYNTHETIC_EVENT")/sizeof(WCHAR))-1;
        config.rules[0].type=36;config.rules[0].timeout=0;config.rules[0].answer=6;
        sink=ahEventSinkCreate(&config);if(!sink)return ah_seb_snapshot(b,out,AH_SEB_REFUSED);
        b->sink=sink;b->operation=operation;b->phase=AH_SEB_ACTIVE;
        create->empty_variant->vt=AH_ES_VT_DISPATCH;create->empty_variant->value.dispatch=&sink->dispatch;
        sink->dispatch.lpVtbl->AddRef(&sink->dispatch); /* distinct caller VARIANT ownership */
        return ah_seb_snapshot(b,out,AH_SEB_OK);
    }
    if(operation!=b->operation)return ah_seb_snapshot(b,out,AH_SEB_ENVIRONMENT);
    if(command==AH_SEB_SNAPSHOT)return ah_seb_snapshot(b,out,AH_SEB_OK);
    if(b->phase==AH_SEB_FRESH || b->phase==AH_SEB_FINISHED || !b->sink)return ah_seb_snapshot(b,out,AH_SEB_REFUSED);
    sink=b->sink;
    if(command==AH_SEB_DISARM){
        ahEventSinkDisarm(sink);b->phase=AH_SEB_DISARMED;return ah_seb_snapshot(b,out,AH_SEB_OK);
    }
    if(InterlockedCompareExchange(&sink->busy,0,0))return ah_seb_snapshot(b,out,AH_SEB_REFUSED_RETAIN);
    if(command==AH_SEB_SET_NODES){
        AhSebNodes *nodes=(AhSebNodes*)(uintptr_t)input;
        if(!nodes || nodes->size!=sizeof(*nodes))status=AH_SEB_BAD_INPUT;
        else if(!nodes->message_node && !nodes->modal_node && b->phase==AH_SEB_DISARMED){
            b->message_node=NULL;b->modal_node=NULL;status=AH_SEB_OK;
        }else if(b->phase==AH_SEB_ACTIVE && !b->message_node && !b->modal_node && nodes->message_node && nodes->modal_node
            && nodes->message_node!=nodes->modal_node && nodes->message_node!=&sink->dispatch && nodes->modal_node!=&sink->dispatch
            && nodes->message_node!=b->payload && nodes->modal_node!=b->payload){
            b->message_node=nodes->message_node;b->modal_node=nodes->modal_node;status=AH_SEB_OK;
        }
    }else if(command==AH_SEB_SET_PAYLOAD){
        AhSebPayload *payload=(AhSebPayload*)(uintptr_t)input;
        if(!payload || payload->size!=sizeof(*payload))status=AH_SEB_BAD_INPUT;
        else if(!payload->kind && !payload->payload){b->payload=NULL;b->payload_kind=0;status=AH_SEB_OK;}
        else if(b->phase==AH_SEB_ACTIVE && b->message_node && b->modal_node && !sink->state.poisoned
            && (payload->kind==AH_ES_MSG || payload->kind==AH_ES_MODAL) && payload->payload
            && payload->payload!=b->message_node && payload->payload!=b->modal_node && payload->payload!=&sink->dispatch){
            b->payload=payload->payload;b->payload_kind=payload->kind;
            if(!sink->ever_armed && !ahEventSinkArm(sink))status=AH_SEB_REFUSED_RETAIN;
            else status=sink->armed?AH_SEB_OK:AH_SEB_REFUSED_RETAIN;
        }
    }else if(command==AH_SEB_FINISH){
        if(b->phase!=AH_SEB_DISARMED || b->message_node || b->modal_node || b->payload
            || InterlockedCompareExchange(&sink->refs,0,0)!=1 || sink->armed)return ah_seb_snapshot(b,out,AH_SEB_REFUSED_RETAIN);
        b->final_state=sink->state;b->sink=NULL;b->phase=AH_SEB_FINISHED;
        sink->dispatch.lpVtbl->Release(&sink->dispatch);status=AH_SEB_OK;
    }else status=AH_SEB_BAD_INPUT;
    return ah_seb_snapshot(b,out,status);
}
#endif
