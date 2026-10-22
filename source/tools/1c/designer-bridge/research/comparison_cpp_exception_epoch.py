"""Derive one fixed C SDK carrier with a public VEH Execute exception epoch.

Pure rendering/classification only. Does not compile, load, run, or write files.
The baseline compiler and original C file stay unchanged.
"""
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[4]
BASELINE = ROOT / 'tools/1c/designer-bridge/research/NativeSdkGoldDiagnosis.c'
BASELINE_SHA = 'e22ea0a88316fdeca21e70c3e6509619624cbe3203c05d8315a7e241830d6d0c'
PROFILE = 'PUBLIC_VEH_SYNCHRONOUS_CONTEXT_EXECUTE_CPP_EPOCH'
HEADER_MACROS = ('AH_CPP_EPOCH_OPERATION_ID', 'AH_CPP_EPOCH_SCOPE_SHA256', 'AH_CPP_EPOCH_RECEIPT_FILE')
ANCHOR = 'if(rc>=0 && !ahSdkAbiFault)rc=(int)call(context,5,0,0);else rc=105;'

PRELUDE = r'''
/* New fixed epoch. Every API here is public Win32; no private code patch. */
#ifndef AH_CPP_EPOCH_OPERATION_ID
#error AH_CPP_EPOCH_OPERATION_ID_required
#endif
#ifndef AH_CPP_EPOCH_SCOPE_SHA256
#error AH_CPP_EPOCH_SCOPE_SHA256_required
#endif
#ifndef AH_CPP_EPOCH_RECEIPT_FILE
#error AH_CPP_EPOCH_RECEIPT_FILE_required
#endif
static volatile LONG ahCppEpochOnce=0,ahCppEpochActive=0,ahCppEpochOverflow=0;
static volatile LONG ahCppEpochCpp=0,ahCppEpochCppGui=0,ahCppEpochCppOther=0;
static volatile LONG ahCppEpochOther=0,ahCppEpochOtherGui=0,ahCppEpochOtherOther=0;
static volatile LONG ahCppEpochRegistered=0,ahCppEpochRemoved=0;
static volatile LONG ahCppEpochEntered=0,ahCppEpochReturned=0;
static DWORD ahCppEpochThread=0;
/* Exact public WINAPI ABI; the installed TCC import library omits these exports. */
typedef PVOID (WINAPI *AhCppEpochAddVeh)(ULONG,PVECTORED_EXCEPTION_HANDLER);
typedef ULONG (WINAPI *AhCppEpochRemoveVeh)(PVOID);
static AhCppEpochAddVeh ahCppEpochAddVeh=0;
static AhCppEpochRemoveVeh ahCppEpochRemoveVeh=0;
static PVOID ahCppEpochHandlerToken=0;
static HMODULE ahCppEpochSelfReference=0;
static HANDLE ahCppEpochReceipt=INVALID_HANDLE_VALUE;

/* SAME-thread ListStreamException is counted before stack handlers can catch it.
   Other-thread counts are conservative observations, NOT a future-thread barrier.
   Never inspect parameters, strings, application memory, or exception details. */
static LONG CALLBACK ahCppEpochHandler(PEXCEPTION_POINTERS details) {
 if(InterlockedCompareExchange(&ahCppEpochActive,0,0) && details && details->ExceptionRecord){
  DWORD thread=GetCurrentThreadId();LONG count;
  if(details->ExceptionRecord->ExceptionCode==0xe06d7363UL){
   count=InterlockedIncrement(&ahCppEpochCpp);
   if(thread==ahCppEpochThread)InterlockedIncrement(&ahCppEpochCppGui);
   else InterlockedIncrement(&ahCppEpochCppOther);
  }else{
   count=InterlockedIncrement(&ahCppEpochOther);
   if(thread==ahCppEpochThread)InterlockedIncrement(&ahCppEpochOtherGui);
   else InterlockedIncrement(&ahCppEpochOtherOther);
  }
  if(count<=0)InterlockedExchange(&ahCppEpochOverflow,1);
 }
 return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL ahCppEpochHex(const char *text,unsigned length) {
 unsigned i;
 if(!text)return FALSE;
 for(i=0;i<length;i++)if(!text[i] || !((text[i]>='0' && text[i]<='9') || (text[i]>='a' && text[i]<='f')))return FALSE;
 return text[length]==0;
}

/* Only this CREATE_NEW-owned file may be rewritten, never any previous receipt.
   Reserved JSON remains nonterminal if native unwinding bypasses EpochEnd. */
static BOOL ahCppEpochWrite(const char *phase,int executeRc) {
 char output[2048];DWORD written=0;LARGE_INTEGER zero;int length,tail;
 const char *registered=ahCppEpochRegistered?"true":"false";
 const char *removed=ahCppEpochRemoved?"true":"false";
 const char *entered=ahCppEpochEntered?"true":"false";
 const char *returned=ahCppEpochReturned?"true":"false";
 const char *overflow=ahCppEpochOverflow?"true":"false";
 const char *self=ahCppEpochSelfReference?"true":"false";
 if(ahCppEpochReceipt==INVALID_HANDLE_VALUE)return FALSE;
 length=wsprintfA(output,
  "{\"kind\":\"COMPARISON_CPP_EXCEPTION_EPOCH\",\"phase\":\"%s\",\"operationId\":\"%s\",\"scopeSha256\":\"%s\","
  "\"processId\":%lu,\"executeThreadId\":%lu,\"handlerRegistered\":%s,\"handlerRemoved\":%s,\"executeEntered\":%s,\"executeReturned\":%s,\"sdkExecuteRc\":%d,"
  "\"cppThrows\":%ld,\"cppThrowsExecuteThread\":%ld,\"cppThrowsOtherThreads\":%ld,\"otherExceptions\":%ld,\"otherExceptionsExecuteThread\":%ld,\"otherExceptionsOtherThreads\":%ld,\"counterOverflow\":%s,",
  phase,AH_CPP_EPOCH_OPERATION_ID,AH_CPP_EPOCH_SCOPE_SHA256,GetCurrentProcessId(),ahCppEpochThread,
  registered,removed,entered,returned,executeRc,
  ahCppEpochCpp,ahCppEpochCppGui,ahCppEpochCppOther,ahCppEpochOther,ahCppEpochOtherGui,ahCppEpochOtherOther,overflow);
 /* Each fixed wsprintfA segment is <1024 bytes even at maximum integer widths;
    operation/scope lengths were checked before this own receipt was opened. */
 if(length<=0 || length>=1024)return FALSE;
 tail=wsprintfA(output+length,
  "\"selfReferenceRetained\":%s,\"dllMustRemainLoadedUntilProcessExit\":true,\"handlerReturn\":\"CONTINUE_SEARCH\",\"epochCoverage\":\"synchronous_context_Execute\","
  "\"futureOtherThreadBarrierVerified\":false,\"exceptionDetailsCaptured\":false,\"scopeSourceBindingVerified\":false,\"fullPendingVerified\":false,\"databaseUpdateAuthorized\":false}",self);
 if(tail<=0 || tail>=1024 || length+tail>=(int)sizeof(output))return FALSE;
 length+=tail;
 zero.QuadPart=0;
 return SetFilePointerEx(ahCppEpochReceipt,zero,0,FILE_BEGIN)
  && WriteFile(ahCppEpochReceipt,output,(DWORD)length,&written,0) && written==(DWORD)length
  && SetEndOfFile(ahCppEpochReceipt) && FlushFileBuffers(ahCppEpochReceipt);
}

static BOOL ahCppEpochRemove(void) {
 InterlockedExchange(&ahCppEpochActive,0);
 if(!ahCppEpochHandlerToken)return TRUE;
 if(!ahCppEpochRemoveVeh || !ahCppEpochRemoveVeh(ahCppEpochHandlerToken))return FALSE;
 ahCppEpochHandlerToken=0;InterlockedExchange(&ahCppEpochRemoved,1);return TRUE;
}

static BOOL ahCppEpochBegin(void) {
 HMODULE kernel;
 if(InterlockedCompareExchange(&ahCppEpochOnce,1,0)!=0)return FALSE;
 if(!ahCppEpochHex(AH_CPP_EPOCH_OPERATION_ID,32) || !ahCppEpochHex(AH_CPP_EPOCH_SCOPE_SHA256,64))return FALSE;
 ahCppEpochThread=GetCurrentThreadId();
 ahCppEpochReceipt=CreateFileW(AH_CPP_EPOCH_RECEIPT_FILE,GENERIC_WRITE,FILE_SHARE_READ,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
 if(ahCppEpochReceipt==INVALID_HANDLE_VALUE)return FALSE;
 /* Explicit own DLL reference is NEVER freed: even a native unwind skipping
    End cannot leave the process calling an unloaded VEH. Retain until exit. */
 if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(LPCWSTR)(uintptr_t)&ahCppEpochHandler,&ahCppEpochSelfReference)){
  ahCppEpochWrite("BEFORE_EXECUTE_REFUSED",-2147483647);CloseHandle(ahCppEpochReceipt);ahCppEpochReceipt=INVALID_HANDLE_VALUE;return FALSE;
 }
 /* Resolve from the already loaded system module; no LoadLibrary/unload. Both
    functions must exist before registering any callback or executing SDK code. */
 kernel=GetModuleHandleW(L"kernel32.dll");
 if(kernel){
  ahCppEpochAddVeh=(AhCppEpochAddVeh)GetProcAddress(kernel,"AddVectoredExceptionHandler");
  ahCppEpochRemoveVeh=(AhCppEpochRemoveVeh)GetProcAddress(kernel,"RemoveVectoredExceptionHandler");
 }
 if(!ahCppEpochAddVeh || !ahCppEpochRemoveVeh){
  ahCppEpochWrite("BEFORE_EXECUTE_REFUSED",-2147483647);CloseHandle(ahCppEpochReceipt);ahCppEpochReceipt=INVALID_HANDLE_VALUE;return FALSE;
 }
 ahCppEpochHandlerToken=ahCppEpochAddVeh(1,ahCppEpochHandler);
 if(!ahCppEpochHandlerToken){
  ahCppEpochWrite("BEFORE_EXECUTE_REFUSED",-2147483647);CloseHandle(ahCppEpochReceipt);ahCppEpochReceipt=INVALID_HANDLE_VALUE;return FALSE;
 }
 InterlockedExchange(&ahCppEpochRegistered,1);
 if(!ahCppEpochWrite("EXECUTE_RESERVED",-2147483647)){
  ahCppEpochRemove();CloseHandle(ahCppEpochReceipt);ahCppEpochReceipt=INVALID_HANDLE_VALUE;return FALSE;
 }
 return TRUE;
}

static BOOL ahCppEpochEnd(int executeRc) {
 BOOL removed,written;
 InterlockedExchange(&ahCppEpochReturned,1);
 removed=ahCppEpochRemove();
 written=ahCppEpochWrite("EXECUTE_RETURNED",executeRc);
 if(ahCppEpochReceipt!=INVALID_HANDLE_VALUE){CloseHandle(ahCppEpochReceipt);ahCppEpochReceipt=INVALID_HANDLE_VALUE;}
 return removed && written;
}

/* Export reads only our own lifecycle flags, never cleans up or permits unload. */
__declspec(dllexport) DWORD __cdecl ahCppExceptionEpochRetainState(void) {
 return (ahCppEpochHandlerToken?1UL:0UL) | (ahCppEpochSelfReference?2UL:0UL)
  | (ahCppEpochEntered?4UL:0UL) | (ahCppEpochReturned?8UL:0UL);
}
'''

EXECUTE_BLOCK = r'''if(rc>=0 && !ahSdkAbiFault){
  if(!ahCppEpochBegin())rc=181;
  else{
   InterlockedExchange(&ahCppEpochEntered,1);InterlockedExchange(&ahCppEpochActive,1);
   rc=(int)call(context,5,0,0);
   if(!ahCppEpochEnd(rc))rc=182;
  }
 }else rc=105;'''


def need(ok, code):
    if not ok:
        raise ValueError('CPP_EXCEPTION_EPOCH_' + code)


def render(base_bytes=None):
    """Return a deterministic fixed derivative; reject any changed baseline."""
    raw = BASELINE.read_bytes() if base_bytes is None else base_bytes
    need(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == BASELINE_SHA, 'BASELINE_PIN')
    source = raw.decode('utf-8-sig').replace('\r\n', '\n')
    include = '#include "sdk_probe_params.h"'
    need(source.count(ANCHOR) == 1 and source.count(include) == 1, 'FIXED_ANCHORS')
    return source.replace(include, include + '\n' + PRELUDE, 1).replace(ANCHOR, EXECUTE_BLOCK, 1).encode('utf-8')


def classify_epoch(receipt, *, operation_id, scope_sha256, process_id, execute_thread_id,
                   callback_known, callback_sdk_rc, target_identity_verified):
    """Admit only the exception-free synchronous window, never a DB update."""
    need(type(operation_id) is str and type(scope_sha256) is str and
         re.fullmatch('[0-9a-f]{32}', operation_id) is not None and
         re.fullmatch('[0-9a-f]{64}', scope_sha256) is not None, 'EXPECTED_BINDING')
    need(type(receipt) is dict and receipt.get('kind') == 'COMPARISON_CPP_EXCEPTION_EPOCH'
         and receipt.get('operationId') == operation_id and receipt.get('scopeSha256') == scope_sha256, 'RECEIPT_BINDING')
    need(type(process_id) is int and process_id > 0 and type(execute_thread_id) is int and execute_thread_id > 0
         and type(receipt.get('processId')) is int and receipt['processId'] == process_id
         and type(receipt.get('executeThreadId')) is int and receipt['executeThreadId'] == execute_thread_id, 'TARGET_IDENTITY')
    need(callback_known is True and target_identity_verified is True and type(callback_sdk_rc) is int
         and callback_sdk_rc == 0, 'CALLBACK_UNKNOWN_OR_FAILED')
    need(receipt.get('phase') == 'EXECUTE_RETURNED' and
         all(receipt.get(key) is True for key in ('handlerRegistered', 'handlerRemoved', 'executeEntered',
                                                'executeReturned', 'selfReferenceRetained', 'dllMustRemainLoadedUntilProcessExit')),
         'INCOMPLETE_EPOCH_RETAIN_NO_RETRY')
    need(type(receipt.get('sdkExecuteRc')) is int and receipt['sdkExecuteRc'] == 0, 'SDK_EXECUTE_FAILED')
    need(receipt.get('counterOverflow') is False and all(type(receipt.get(key)) is int and receipt[key] == 0
         for key in ('cppThrows', 'cppThrowsExecuteThread', 'cppThrowsOtherThreads', 'otherExceptions',
                     'otherExceptionsExecuteThread', 'otherExceptionsOtherThreads')), 'EXCEPTION_OR_UNKNOWN_COUNT')
    need(receipt.get('handlerReturn') == 'CONTINUE_SEARCH' and
         receipt.get('epochCoverage') == 'synchronous_context_Execute' and
         all(receipt.get(key) is False for key in ('futureOtherThreadBarrierVerified', 'exceptionDetailsCaptured',
                                                 'scopeSourceBindingVerified', 'fullPendingVerified', 'databaseUpdateAuthorized')),
         'EXCESS_CLAIM_OR_WRONG_COVERAGE')
    return dict(synchronousExecuteExceptionFree=True, cppThrowsOnExecuteThread=0,
                futureOtherThreadBarrierVerified=False, sourceBindingVerified=False,
                fullPendingVerified=False, databaseUpdateAuthorized=False, dllRetainedUntilProcessExit=True)
