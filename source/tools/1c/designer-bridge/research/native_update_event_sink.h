/* Offline-built x86 COM sink; no hook installation, event discovery or Update.
 * Compact ABI subset from Microsoft Learn oaidl VARIANT/DISPPARAMS/EXCEPINFO,
 * IDispatch::Invoke/GetIDsOfNames (links and limits in task card).
 * Root must admit ONE exact event payload via guard before any event COM call.
 * No argument-position assumption: guard examines bounded raw arguments only.
 */
#ifndef AH_NATIVE_UPDATE_EVENT_SINK_H
#define AH_NATIVE_UPDATE_EVENT_SINK_H
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define AH_ES_ASSERT(n,x) typedef char ah_es_assert_##n[(x)?1:-1]
#define AH_ES_METHOD 1
#define AH_ES_GET 2
#define AH_ES_PUT 4
#define AH_ES_UNKNOWN (-1)
#define AH_ES_PROPERTYPUT (-3)
#define AH_ES_MSG 1
#define AH_ES_MODAL 2
#define AH_ES_MAX_ARGS 16
#define AH_ES_MAX_RULES 8
#define AH_ES_MAX_TEXT 512
#define AH_ES_VT_EMPTY 0
#define AH_ES_VT_I4 3
#define AH_ES_VT_BSTR 8
#define AH_ES_VT_DISPATCH 9
#define AH_ES_VT_BOOL 11
#define AH_ES_VT_UI4 19
#define AH_ES_BADCOUNT ((HRESULT)0x8002000eL)
#define AH_ES_BADTYPE ((HRESULT)0x80020005L)
#define AH_ES_BADMEMBER ((HRESULT)0x80020003L)
#define AH_ES_BADNAME ((HRESULT)0x80020006L)
#define AH_ES_BADINTERFACE ((HRESULT)0x80020001L)
typedef struct AhEsDispatch AhEsDispatch;
typedef struct AhEsVariant {
    WORD vt,r1,r2,r3;
    union { LONG i4; ULONG ui4; SHORT boolean; WCHAR *bstr; AhEsDispatch *dispatch;
            double force8; ULONGLONG u64; struct {void *record,*info;} record; } value;
} AhEsVariant;
typedef struct AhEsParams { AhEsVariant *args; LONG *named; UINT count,named_count; } AhEsParams;
typedef struct AhEsException {
    WORD code,reserved; WCHAR *source,*description,*help; DWORD context;
    void *reserved_ptr; HRESULT (WINAPI *deferred)(struct AhEsException*); LONG scode;
} AhEsException;
typedef struct AhEsVtbl {
    HRESULT (WINAPI *QueryInterface)(AhEsDispatch*,const GUID*,void**);
    ULONG (WINAPI *AddRef)(AhEsDispatch*);
    ULONG (WINAPI *Release)(AhEsDispatch*);
    HRESULT (WINAPI *GetTypeInfoCount)(AhEsDispatch*,UINT*);
    HRESULT (WINAPI *GetTypeInfo)(AhEsDispatch*,UINT,LCID,void**);
    HRESULT (WINAPI *GetIDsOfNames)(AhEsDispatch*,const GUID*,WCHAR**,UINT,LCID,LONG*);
    HRESULT (WINAPI *Invoke)(AhEsDispatch*,LONG,const GUID*,LCID,WORD,AhEsParams*,AhEsVariant*,AhEsException*,UINT*);
} AhEsVtbl;
struct AhEsDispatch { const AhEsVtbl *lpVtbl; };
AH_ES_ASSERT(x86,sizeof(void*)==4);
AH_ES_ASSERT(guid,sizeof(GUID)==16 && offsetof(GUID,Data4)==8);
AH_ES_ASSERT(variant,sizeof(AhEsVariant)==16 && offsetof(AhEsVariant,value)==8);
AH_ES_ASSERT(params,sizeof(AhEsParams)==16 && offsetof(AhEsParams,count)==8 && offsetof(AhEsParams,named_count)==12);
AH_ES_ASSERT(exception,sizeof(AhEsException)==32 && offsetof(AhEsException,source)==4 && offsetof(AhEsException,scode)==28);
AH_ES_ASSERT(vtable,sizeof(AhEsVtbl)==28 && offsetof(AhEsVtbl,Invoke)==24);
static const GUID ah_es_null={0};
static const GUID ah_es_iunknown={0,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID ah_es_idispatch={0x00020400,0,0,{0xc0,0,0,0,0,0,0,0x46}};
typedef HRESULT (WINAPI *AhEsClear)(AhEsVariant*);
typedef UINT (WINAPI *AhEsStringLen)(WCHAR*);
/* Guard MUST check operation/PID/GUI/own subscription node and choose exactly
 * one admitted dispatch argument. It must not call COM on other arguments.
 * Repeated guard calls use the same raw DISPPARAMS, before property mutations.
 */
typedef BOOL (*AhEsGuard)(void*,ULONG,LONG,const AhEsParams*,UINT*);
typedef struct AhEsRule { const WCHAR *text; UINT length; ULONG type,timeout; LONG answer; } AhEsRule;
typedef struct AhEsConfig {
    ULONG operation; AhEsGuard guard; void *guard_context; AhEsClear clear; AhEsStringLen string_len;
    UINT rule_count,max_callbacks; AhEsRule rules[AH_ES_MAX_RULES];
} AhEsConfig;
typedef struct AhEsState {
    ULONG admitted,modal_seen,message_seen,rejected,answers,mutation_attempts,property_calls;
    ULONG poisoned,reentrant,last_error,last_stage;
} AhEsState;
typedef struct AhEventSink {
    AhEsDispatch dispatch; volatile LONG refs,busy,armed,ever_armed;
    AhEsConfig config; AhEsState state; ULONG used_rules;
    WCHAR texts[AH_ES_MAX_RULES][AH_ES_MAX_TEXT];
} AhEventSink;

static int ah_es_equal_guid(const GUID *a,const GUID *b){return a && !memcmp(a,b,16);}
static int ah_es_name(const WCHAR *a,const WCHAR *b){
    UINT i; if(!a)return 0;
    for(i=0;i<32;i++){WCHAR x=a[i],y=b[i];if(x>='A'&&x<='Z')x+=32;if(y>='A'&&y<='Z')y+=32;
        if(x!=y)return 0;if(!y)return 1;}return 0;
}
static ULONG WINAPI ah_es_addref(AhEsDispatch *d){return (ULONG)InterlockedIncrement(&((AhEventSink*)d)->refs);}
static ULONG WINAPI ah_es_release(AhEsDispatch *d){
    AhEventSink *s=(AhEventSink*)d;LONG refs=InterlockedDecrement(&s->refs);
    if(!refs){SecureZeroMemory(s,sizeof(*s));HeapFree(GetProcessHeap(),0,s);}return (ULONG)refs;
}
static HRESULT WINAPI ah_es_qi(AhEsDispatch *d,const GUID *id,void **out){
    if(!out)return E_POINTER;*out=NULL;
    if(!ah_es_equal_guid(id,&ah_es_iunknown)&&!ah_es_equal_guid(id,&ah_es_idispatch))return E_NOINTERFACE;
    *out=d;ah_es_addref(d);return S_OK;
}
static HRESULT WINAPI ah_es_type_count(AhEsDispatch *d,UINT *out){if(!out)return E_POINTER;*out=0;return S_OK;}
static HRESULT WINAPI ah_es_type(AhEsDispatch *d,UINT n,LCID locale,void **out){if(out)*out=NULL;return (HRESULT)0x8002000bL;}
static HRESULT WINAPI ah_es_names(AhEsDispatch *d,const GUID *iid,WCHAR **names,UINT count,LCID locale,LONG *ids){
    if(!ids || !names)return E_POINTER;
    if(count!=1)return AH_ES_BADCOUNT;ids[0]=AH_ES_UNKNOWN;
    if(!ah_es_equal_guid(iid,&ah_es_null))return AH_ES_BADINTERFACE;
    if(ah_es_name(names[0],L"onMessageBox"))ids[0]=AH_ES_MSG;
    else if(ah_es_name(names[0],L"onDoModal"))ids[0]=AH_ES_MODAL;
    return ids[0]==AH_ES_UNKNOWN?AH_ES_BADNAME:S_OK;
}
static int ah_es_gate(AhEventSink *s,LONG member,const AhEsParams *p,UINT *index){
    UINT selected=AH_ES_MAX_ARGS;
    if(!s->armed || s->state.poisoned || !s->config.guard(s->config.guard_context,s->config.operation,member,p,&selected)
        || selected>=p->count || p->args[selected].vt!=AH_ES_VT_DISPATCH || !p->args[selected].value.dispatch)return 0;
    *index=selected;return 1;
}
static int ah_es_property(AhEventSink *s,AhEsDispatch *event,const WCHAR *name,AhEsVariant *out,AhEsVariant *put){
    WCHAR *names[1];LONG id,property_put=AH_ES_PROPERTYPUT;AhEsParams params;HRESULT hr;
    names[0]=(WCHAR*)name;memset(&params,0,sizeof(params));
    hr=event->lpVtbl->GetIDsOfNames(event,&ah_es_null,names,1,0,&id);s->state.property_calls++;
    if(FAILED(hr))return 0;
    if(put){params.args=put;params.count=1;params.named=&property_put;params.named_count=1;}
    hr=event->lpVtbl->Invoke(event,id,&ah_es_null,0,put?AH_ES_PUT:AH_ES_GET,&params,out,NULL,NULL);
    s->state.property_calls++;
    return SUCCEEDED(hr) && (put || (out && !out->r1 && !out->r2 && !out->r3));
}
static int ah_es_number(AhEsVariant *v,ULONG *out){
    if(v->vt==AH_ES_VT_UI4){*out=v->value.ui4;return 1;}
    if(v->vt==AH_ES_VT_I4 && v->value.i4>=0){*out=(ULONG)v->value.i4;return 1;}return 0;
}
static void ah_es_poison(AhEventSink *s,ULONG error){s->state.poisoned=1;s->state.last_error=error;InterlockedExchange(&s->armed,0);}
static HRESULT WINAPI ah_es_invoke(AhEsDispatch *d,LONG member,const GUID *iid,LCID locale,WORD flags,
    AhEsParams *p,AhEsVariant *result,AhEsException *exception,UINT *arg_error){
    AhEventSink *s=(AhEventSink*)d;AhEsDispatch *event;AhEsVariant values[4],put;
    UINT i,index=0,again=0,matched=AH_ES_MAX_RULES,length;ULONG type=0,timeout=0,stage=0;
    if(result)memset(result,0,sizeof(*result));if(arg_error)*arg_error=0;
    if(!ah_es_equal_guid(iid,&ah_es_null))return AH_ES_BADINTERFACE;
    if(member!=AH_ES_MSG && member!=AH_ES_MODAL)return AH_ES_BADMEMBER;
    if(flags!=AH_ES_METHOD)return AH_ES_BADMEMBER;
    if(!p || !p->args || p->count<1 || p->count>AH_ES_MAX_ARGS)return AH_ES_BADCOUNT;
    if(p->named_count || p->named)return (HRESULT)0x80020007L;
    for(i=0;i<p->count;i++)if(p->args[i].vt!=AH_ES_VT_DISPATCH || !p->args[i].value.dispatch
        || p->args[i].r1 || p->args[i].r2 || p->args[i].r3){if(arg_error)*arg_error=i;return AH_ES_BADTYPE;}
    ah_es_addref(d);
    if(InterlockedCompareExchange(&s->busy,1,0)!=0){InterlockedIncrement((LONG*)&s->state.reentrant);ah_es_release(d);return S_OK;}
    memset(values,0,sizeof(values));memset(&put,0,sizeof(put));
    if(!ah_es_gate(s,member,p,&index)){s->state.rejected++;goto done;}
    if(s->state.admitted>=s->config.max_callbacks){ah_es_poison(s,1);goto done;}
    s->state.admitted++;event=p->args[index].value.dispatch;
    if(member==AH_ES_MODAL){
        if(ah_es_property(s,event,L"stage",&values[0],NULL)&&ah_es_number(&values[0],&stage)&&stage<=3){
            s->state.modal_seen++;s->state.last_stage=stage;
        }else{s->state.rejected++;s->state.last_error=2;}goto done;
    }
    s->state.message_seen++;
    if(!ah_es_property(s,event,L"cancel",&values[0],NULL) || values[0].vt!=AH_ES_VT_BOOL
        || values[0].value.boolean!=0)goto rejected;
    if(!ah_es_property(s,event,L"text",&values[1],NULL) || values[1].vt!=AH_ES_VT_BSTR || !values[1].value.bstr)goto rejected;
    length=s->config.string_len(values[1].value.bstr);if(!length || length>=AH_ES_MAX_TEXT)goto rejected;
    if(!ah_es_property(s,event,L"type",&values[2],NULL)||!ah_es_number(&values[2],&type))goto rejected;
    if(!ah_es_property(s,event,L"timeout",&values[3],NULL)||!ah_es_number(&values[3],&timeout))goto rejected;
    for(i=0;i<s->config.rule_count;i++){
        AhEsRule *r=&s->config.rules[i];
        if(r->length==length && r->type==type && r->timeout==timeout && !memcmp(r->text,values[1].value.bstr,length*2)){
            if(matched!=AH_ES_MAX_RULES)goto rejected;matched=i;
        }
    }
    if(matched==AH_ES_MAX_RULES || (s->used_rules&(1UL<<matched)))goto rejected;
    if(!ah_es_gate(s,member,p,&again)||again!=index)goto rejected;
    /* Consume BEFORE any put. Failed/partial puts are never retried or guessed undone. */
    s->used_rules|=1UL<<matched;s->state.mutation_attempts++;
    put.vt=AH_ES_VT_I4;put.value.i4=s->config.rules[matched].answer;
    if(!ah_es_property(s,event,L"result",NULL,&put)){ah_es_poison(s,3);goto done;}
    if(!ah_es_gate(s,member,p,&again)||again!=index){ah_es_poison(s,4);goto done;}
    put.vt=AH_ES_VT_BOOL;put.value.boolean=-1;
    if(!ah_es_property(s,event,L"cancel",NULL,&put)){ah_es_poison(s,5);goto done;}
    s->state.answers++;goto done;
rejected:
    s->state.rejected++;s->state.last_error=6;
done:
    for(i=0;i<4;i++)if(values[i].vt!=AH_ES_VT_EMPTY && FAILED(s->config.clear(&values[i])))ah_es_poison(s,7);
    InterlockedExchange(&s->busy,0);ah_es_release(d);return S_OK;
}
static const AhEsVtbl ah_es_vtable={ah_es_qi,ah_es_addref,ah_es_release,ah_es_type_count,ah_es_type,ah_es_names,ah_es_invoke};
static AhEventSink *ahEventSinkCreate(const AhEsConfig *config){
    AhEventSink *s;UINT i,j;
    if(!config || !config->operation || !config->guard || !config->clear || !config->string_len
        || config->rule_count>AH_ES_MAX_RULES || !config->max_callbacks || config->max_callbacks>64)return NULL;
    for(i=0;i<config->rule_count;i++){
        const AhEsRule *r=&config->rules[i];
        if(!r->text || !r->length || r->length>=AH_ES_MAX_TEXT || r->answer<1 || r->answer>7)return NULL;
        for(j=0;j<i;j++)if(config->rules[j].length==r->length && config->rules[j].type==r->type
            && config->rules[j].timeout==r->timeout && !memcmp(config->rules[j].text,r->text,r->length*2))return NULL;
    }
    s=(AhEventSink*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*s));if(!s)return NULL;
    s->dispatch.lpVtbl=&ah_es_vtable;s->refs=1;s->config=*config;
    for(i=0;i<config->rule_count;i++){
        memcpy(s->texts[i],config->rules[i].text,config->rules[i].length*2);s->config.rules[i].text=s->texts[i];
    }
    return s;
}
static int ahEventSinkArm(AhEventSink *s){
    if(!s || InterlockedCompareExchange(&s->ever_armed,1,0))return 0;
    InterlockedExchange(&s->armed,1);return 1;
}
/* Disarm before disconnect; root waits for quiescence and releases its own ref.
 * The event source owns its connected reference until it actually disconnects. */
static void ahEventSinkDisarm(AhEventSink *s){if(s)InterlockedExchange(&s->armed,0);}
#endif
