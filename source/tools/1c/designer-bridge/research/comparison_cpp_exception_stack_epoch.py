"""New bounded public backtrace derivative; matched ListStream still rejects Compare.

Only frntend.dll-relative return addresses leave the process. No exception
objects, application text, arbitrary stack reads, symbol API or native execution.
"""
import hashlib
from pathlib import Path
import re
import struct
import comparison_cpp_exception_type_epoch as typed
from repository_pe_probe import PE

TYPE_GENERATOR_SHA = 'e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4'
FRNTEND_SHA = '9556defc1ccd1cd8b05ed63d4b0287f40fac2bccba42a68fc229927c8b5fc8a5'
IMAGE_SIZE, PE_OFFSET, TIMESTAMP, CHECKSUM = 0xf54000, 0x118, 0x5fb432ea, 0xef4135
PROFILE = 'PUBLIC_BACKTRACE64_FRNTEND_RVA16_MATCHED_TYPES_ONLY'
MAX_EVENTS, MAX_FRAMES, MAX_RVAS, RECEIPT_CAPACITY = 32, 64, 16, 32768
AA090_START, AA090_END, PROPERTY_CALL_RETURN = 0xaa090, 0xab007, 0xa9a17
# Fixed segment upper bounds; the writer checks remaining capacity BEFORE each.
RECEIPT_UPPER_BOUND = 17540 + 1024 + 32 * (200 + 16 * 12 + 4) + 4

STACK_CODE = r'''
/* Public API alias from winbase.h; resolve BEFORE Execute, never in VEH. */
typedef USHORT (WINAPI *AhCppStackCaptureApi)(ULONG,ULONG,PVOID*,PULONG);
typedef struct {
 BOOL observed,failed,capped,truncated;
 DWORD captured,matched,retained,rvas[16];
} AhCppStackEvent;
static AhCppStackEvent ahCppStackEvents[32];
static AhCppStackCaptureApi ahCppStackCaptureApi=0;
static DWORD ahCppStackImageBase=0;
static BOOL ahCppStackPeMatched=FALSE,ahCppStackApiAvailable=FALSE;
static DWORD ahCppStackExecuteStart=0,ahCppStackExecuteElapsed=0;
static BOOL ahCppStackExecuteTimerObserved=FALSE;
static volatile LONG ahCppStackMatched=0,ahCppStackFailures=0,ahCppStackOverflow=0;

static BOOL ahCppStackPrepare(void){
 HMODULE kernel=GetModuleHandleW(L"kernel32.dll"),image=GetModuleHandleW(L"frntend.dll");
 IMAGE_DOS_HEADER dos;IMAGE_NT_HEADERS32 nt;SIZE_T copied=0;ULONGLONG base=(ULONGLONG)(uintptr_t)image;
 if(sizeof(void*)!=4 || !kernel || !image || base<65536 || base+0xf54000UL>0x100000000ULL)return FALSE;
 ahCppStackCaptureApi=(AhCppStackCaptureApi)GetProcAddress(kernel,"RtlCaptureStackBackTrace");
 if(!ahCppStackCaptureApi)ahCppStackCaptureApi=(AhCppStackCaptureApi)GetProcAddress(kernel,"CaptureStackBackTrace");
 if(!ahCppStackCaptureApi)return FALSE;ahCppStackApiAvailable=TRUE;
 /* Offline generator AND carrier root bind the exact disk image SHA separately.
    These runtime header checks are NOT a claim to hash relocated module memory. */
 if(!ReadProcessMemory(GetCurrentProcess(),image,&dos,sizeof(dos),&copied) || copied!=sizeof(dos)
   || dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew!=0x118)return FALSE;
 copied=0;
 if(!ReadProcessMemory(GetCurrentProcess(),(LPCVOID)(uintptr_t)(base+0x118),&nt,sizeof(nt),&copied)
   || copied!=sizeof(nt) || nt.Signature!=IMAGE_NT_SIGNATURE || nt.FileHeader.Machine!=0x14c
   || nt.FileHeader.SizeOfOptionalHeader!=224 || nt.FileHeader.TimeDateStamp!=0x5fb432eaUL
   || nt.OptionalHeader.Magic!=0x10b || nt.OptionalHeader.SizeOfImage!=0xf54000UL
   || nt.OptionalHeader.CheckSum!=0xef4135UL)return FALSE;
 ahCppStackImageBase=(DWORD)base;ahCppStackPeMatched=TRUE;return TRUE;
}

/* Called only for a fully decoded matching event while type-decoder reentry
   guard remains held. All raw addresses stay in this bounded transient array. */
static void ahCppStackCaptureEvent(LONG index){
 PVOID frames[64];USHORT captured;DWORD i;AhCppStackEvent *event;
 if(index<0 || index>=32){InterlockedExchange(&ahCppStackOverflow,1);return;}
 event=&ahCppStackEvents[index];event->observed=TRUE;InterlockedIncrement(&ahCppStackMatched);
 if(!ahCppStackApiAvailable || !ahCppStackPeMatched || !ahCppStackCaptureApi){
  event->failed=TRUE;InterlockedIncrement(&ahCppStackFailures);return;
 }
 for(i=0;i<64;i++)frames[i]=0;
 captured=ahCppStackCaptureApi(0,64,frames,0);event->captured=captured;
 if(!captured || captured>64){event->failed=TRUE;InterlockedIncrement(&ahCppStackFailures);return;}
 event->capped=captured==64;
 for(i=0;i<captured;i++){
  ULONGLONG address=(ULONGLONG)(uintptr_t)frames[i],base=ahCppStackImageBase;
  if(address>=base && address<base+0xf54000UL){
   event->matched++;
   if(event->retained<16)event->rvas[event->retained++]=(DWORD)(address-base);
   else event->truncated=TRUE;
  }
 }
}

/* Outside VEH only. Fixed row prefix <200, hash/RVA segment <32 bytes. */
static int ahCppStackAppendReceipt(char *output,int capacity,int used){
 int added;LONG i;DWORD j;BOOL first=TRUE;
 if(used<0 || used>capacity-1024)return -1;
 added=wsprintfA(output+used,
  "\"stackDecoderProfile\":\"PUBLIC_BACKTRACE64_FRNTEND_RVA16_MATCHED_TYPES_ONLY\",\"stackDiagnosticOnly\":true,"
  "\"stackRawAddressesOutput\":false,\"stackExceptionObjectRead\":false,\"stackRuntimeImageHashVerified\":false,"
  "\"stackFrntendExpectedImageSha256\":\"9556defc1ccd1cd8b05ed63d4b0287f40fac2bccba42a68fc229927c8b5fc8a5\","
  "\"stackFrntendImageSize\":16072704,\"stackFrntendPeMatched\":%s,\"stackCaptureApiAvailable\":%s,"
  "\"stackMaximumFrames\":64,\"stackMaximumRetainedFrntendRvas\":16,\"stackMaximumEvents\":32,"
  "\"stackMatchedEventCount\":%ld,\"stackCaptureFailures\":%ld,\"stackCaptureOverflow\":%s,"
  "\"nativeExecuteTimerObserved\":%s,\"nativeExecuteElapsedMs\":%lu,\"stackEvents\":[",
  ahCppStackPeMatched?"true":"false",ahCppStackApiAvailable?"true":"false",
  ahCppStackMatched,ahCppStackFailures,ahCppStackOverflow?"true":"false",
  ahCppStackExecuteTimerObserved?"true":"false",ahCppStackExecuteElapsed);
 if(added<=0 || added>=1024)return -1;used+=added;
 for(i=0;i<32;i++){
  AhCppStackEvent *event=&ahCppStackEvents[i];if(!event->observed)continue;
  if(used>capacity-200)return -1;
  added=wsprintfA(output+used,
   "%s{\"eventIndex\":%ld,\"capturedFrames\":%lu,\"frntendFrames\":%lu,\"retainedRvas\":%lu,\"captureFailed\":%s,\"captureCapped\":%s,\"rvaTruncated\":%s,\"frntendRvas\":[",
   first?"":",",i,event->captured,event->matched,event->retained,
   event->failed?"true":"false",event->capped?"true":"false",event->truncated?"true":"false");
  if(added<=0 || added>=200)return -1;used+=added;first=FALSE;
  for(j=0;j<event->retained && j<16;j++){
   if(used>capacity-32)return -1;
   added=wsprintfA(output+used,"%s\"%08lx\"",j?",":"",event->rvas[j]);
   if(added<=0 || added>=32)return -1;used+=added;
  }
  if(used>capacity-4)return -1;output[used++]=']';output[used++]='}';
 }
 if(used>capacity-4)return -1;output[used++]=']';output[used++]='}';output[used]=0;return used;
}
'''


def need(ok, code):
    if not ok:
        raise ValueError('CPP_EXCEPTION_STACK_EPOCH_' + code)


def verify_primary():
    need(hashlib.sha256(Path(typed.__file__).read_bytes()).hexdigest() == TYPE_GENERATOR_SHA, 'TYPE_GENERATOR_PIN')
    typed.verify_primary()
    pe = PE('frntend.dll')
    need(hashlib.sha256(pe.data).hexdigest() == FRNTEND_SHA, 'FRNTEND_PIN')
    nt = struct.unpack_from('<I', pe.data, 0x3c)[0]
    need(nt == PE_OFFSET and struct.unpack_from('<I', pe.data, nt + 8)[0] == TIMESTAMP
         and struct.unpack_from('<I', pe.data, nt + 24 + 56)[0] == IMAGE_SIZE
         and struct.unpack_from('<I', pe.data, nt + 24 + 64)[0] == CHECKSUM, 'EXACT_PE_HEADER')
    need(RECEIPT_UPPER_BOUND < RECEIPT_CAPACITY, 'RECEIPT_CAPACITY')
    return dict(frntendExpectedImageSha256=FRNTEND_SHA, imageSize=IMAGE_SIZE, peOffset=PE_OFFSET,
                maximumCapturedFrames=64, maximumRetainedFrntendRvas=16, maximumEvents=32,
                receiptUpperBound=RECEIPT_UPPER_BOUND, receiptCapacity=RECEIPT_CAPACITY,
                diagnosticOnly=True, exceptionObjectRead=False, arbitraryStackMemoryRead=False,
                runtimeImageHashVerified=False, liveVerified=False)


def render():
    """Return fixed C only; never compile, write a source file, load or invoke it."""
    verify_primary()
    source = typed.render().decode()
    changes = (
        ('static BOOL ahCppTypeReadImage(', STACK_CODE + '\nstatic BOOL ahCppTypeReadImage('),
        ('if(event->blocked)InterlockedIncrement(&ahCppTypeBlocked);',
         'if(event->blocked){InterlockedIncrement(&ahCppTypeBlocked);ahCppStackCaptureEvent(index);}'),
        ('COMPARISON_CPP_EXCEPTION_TYPE_EPOCH', 'COMPARISON_CPP_EXCEPTION_STACK_EPOCH'),
        ("if(used>capacity-4)return -1;output[used++]=']';output[used++]='}';output[used]=0;return used;\n}\n\nstatic BOOL ahCppEpochHex(",
         "if(used>capacity-4)return -1;output[used++]=']';output[used++]=',';return ahCppStackAppendReceipt(output,capacity,used);\n}\n\nstatic BOOL ahCppEpochHex("),
        ('kernel=GetModuleHandleW(L"kernel32.dll");',
         'if(!ahCppStackPrepare()){ahCppEpochWrite("BEFORE_EXECUTE_REFUSED",-2147483647);CloseHandle(ahCppEpochReceipt);ahCppEpochReceipt=INVALID_HANDLE_VALUE;return FALSE;}\n kernel=GetModuleHandleW(L"kernel32.dll");'),
        ('rc=(int)call(context,5,0,0);',
         'ahCppStackExecuteStart=GetTickCount();rc=(int)call(context,5,0,0);'
         'ahCppStackExecuteElapsed=GetTickCount()-ahCppStackExecuteStart;ahCppStackExecuteTimerObserved=TRUE;'),
    )
    for old, new in changes:
        need(source.count(old) == 1, 'FIXED_ANCHOR')
        source = source.replace(old, new, 1)
    return source.encode()


def classify_stack_epoch(receipt, *, operation_id, scope_sha256, process_id, execute_thread_id,
                         callback_known, callback_sdk_rc, target_identity_verified):
    """Validate diagnostic traces of rejected ListStream events; no reliability grant."""
    need(type(receipt) is dict and type(operation_id) is str and re.fullmatch('[0-9a-f]{32}', operation_id)
         and type(scope_sha256) is str and re.fullmatch('[0-9a-f]{64}', scope_sha256)
         and receipt.get('kind') == 'COMPARISON_CPP_EXCEPTION_STACK_EPOCH'
         and receipt.get('operationId') == operation_id and receipt.get('scopeSha256') == scope_sha256, 'BINDING')
    need(type(process_id) is int and process_id > 0 and type(execute_thread_id) is int and execute_thread_id > 0
         and type(receipt.get('processId')) is int and receipt['processId'] == process_id
         and type(receipt.get('executeThreadId')) is int and receipt['executeThreadId'] == execute_thread_id
         and callback_known is True and target_identity_verified is True and type(callback_sdk_rc) is int
         and callback_sdk_rc == 0, 'IDENTITY_OR_CALLBACK')
    need(receipt.get('phase') == 'EXECUTE_RETURNED' and type(receipt.get('sdkExecuteRc')) is int
         and receipt['sdkExecuteRc'] == 0 and all(receipt.get(k) is True for k in
         ('handlerRegistered', 'handlerRemoved', 'executeEntered', 'executeReturned', 'selfReferenceRetained',
          'dllMustRemainLoadedUntilProcessExit', 'typeMetadataOnly', 'stackDiagnosticOnly',
          'stackFrntendPeMatched', 'stackCaptureApiAvailable', 'nativeExecuteTimerObserved')), 'LIFECYCLE')
    need(type(receipt.get('nativeExecuteElapsedMs')) is int
         and 0 <= receipt['nativeExecuteElapsedMs'] <= 0xffffffff, 'NATIVE_EXECUTE_TIMER')
    need(receipt.get('handlerReturn') == 'CONTINUE_SEARCH' and receipt.get('epochCoverage') == 'synchronous_context_Execute'
         and receipt.get('typeDecoderProfile') == typed.PROFILE and receipt.get('hashAlgorithm') == 'FNV1A32_OBSERVATION_ONLY'
         and receipt.get('stackDecoderProfile') == PROFILE and receipt.get('stackFrntendExpectedImageSha256') == FRNTEND_SHA,
         'PROFILE')
    for key in ('counterOverflow', 'typeEventOverflow', 'typeDecoderReentry', 'futureOtherThreadBarrierVerified',
                'exceptionDetailsCaptured', 'exceptionObjectRead', 'scopeSourceBindingVerified', 'fullPendingVerified',
                'databaseUpdateAuthorized', 'allCppExceptionFree', 'listStreamPathExceptionFreeVerified',
                'stackRawAddressesOutput', 'stackExceptionObjectRead', 'stackRuntimeImageHashVerified', 'stackCaptureOverflow'):
        need(receipt.get(key) is False, 'EXCESS_CLAIM_OR_UNKNOWN')
    for key, value in (('maximumTypeEvents', 32), ('maximumCatchableTypes', 16), ('maximumNameBytes', 96),
                       ('stackMaximumFrames', 64), ('stackMaximumRetainedFrntendRvas', 16), ('stackMaximumEvents', 32),
                       ('stackFrntendImageSize', IMAGE_SIZE)):
        need(type(receipt.get(key)) is int and receipt[key] == value, 'FIXED_LIMITS')
    for key in ('cppThrowsOtherThreads', 'otherExceptions', 'otherExceptionsExecuteThread',
                'otherExceptionsOtherThreads', 'unknownCppThrows', 'stackCaptureFailures'):
        need(type(receipt.get(key)) is int and receipt[key] == 0, 'UNKNOWN_EVENT')
    count = receipt.get('cppThrows')
    need(type(count) is int and 1 <= count <= 32 and all(type(receipt.get(k)) is int and receipt[k] == count
         for k in ('cppThrowsExecuteThread', 'typeEventCount', 'decodedCppThrows')), 'EVENT_COUNTS')
    rows = receipt.get('typeEvents')
    need(type(rows) is list and len(rows) == count, 'EVENT_ROWS')
    blocked = set()
    for index, row in enumerate(rows):
        need(type(row) is dict and row.get('decoded') is True and row.get('allCatchableTypesExamined') is True
             and type(row.get('listStreamCompatible')) is bool and type(row.get('catchableTypeCount')) is int
             and 1 <= row['catchableTypeCount'] <= 16, 'TYPE_EVENT')
        hashes = row.get('typeNameHashes')
        need(type(hashes) is list and len(hashes) == row['catchableTypeCount'] and
             all(type(h) is str and re.fullmatch('[0-9a-f]{8}', h) for h in hashes)
             and row.get('primaryTypeNameHash') == hashes[0], 'TYPE_HASHES')
        if row['listStreamCompatible']:
            blocked.add(index)
    need(bool(blocked) and type(receipt.get('listStreamCompatibleThrows')) is int
         and receipt['listStreamCompatibleThrows'] == len(blocked)
         and type(receipt.get('stackMatchedEventCount')) is int and receipt['stackMatchedEventCount'] == len(blocked),
         'MATCHED_COUNTS')
    events = receipt.get('stackEvents')
    need(type(events) is list and len(events) == len(blocked), 'STACK_EVENTS')
    indices, positives, callers = set(), [], []
    for event in events:
        need(type(event) is dict and type(event.get('eventIndex')) is int and event['eventIndex'] in blocked
             and event['eventIndex'] not in indices and event.get('captureFailed') is False, 'STACK_EVENT_IDENTITY')
        index = event['eventIndex']; indices.add(index)
        captured, matched, retained = event.get('capturedFrames'), event.get('frntendFrames'), event.get('retainedRvas')
        need(all(type(v) is int for v in (captured, matched, retained)) and 1 <= captured <= 64
             and 0 <= matched <= captured and retained == min(matched, 16), 'STACK_FRAME_COUNTS')
        need(type(event.get('captureCapped')) is bool and event['captureCapped'] == (captured == 64)
             and type(event.get('rvaTruncated')) is bool and event['rvaTruncated'] == (matched > 16), 'TRUNCATION_FLAGS')
        rvas = event.get('frntendRvas')
        need(type(rvas) is list and len(rvas) == retained and all(type(rva) is str and re.fullmatch('[0-9a-f]{8}', rva)
             and 0 <= int(rva, 16) < IMAGE_SIZE for rva in rvas), 'RVA_BOUND')
        if any(AA090_START <= int(rva, 16) < AA090_END for rva in rvas):
            positives.append(index)
        if f'{PROPERTY_CALL_RETURN:08x}' in rvas:
            callers.append(index)
    need(indices == blocked, 'EVERY_MATCHED_EVENT_TRACED')
    return dict(status='DIAGNOSTIC_ONLY_COMPARISON_REJECTED', comparisonReliability='REJECTED',
                listStreamPathExceptionFree=False, allCppExceptionFree=False,
                matchedListStreamEvents=len(blocked), aa090PositiveEventIndices=positives,
                nativeExecuteElapsedMs=receipt['nativeExecuteElapsedMs'],
                propertyCallerPositiveEventIndices=callers, absenceOfAa090Proven=False,
                stackTracesDiagnosticOnly=True, typeHashesSecurityAuthority=False,
                sourceBindingVerified=False, fullPendingVerified=False, databaseUpdateAuthorized=False,
                futureOtherThreadBarrierVerified=False, dllRetainedUntilProcessExit=True)
