"""Bounded resident GUI SDK carrier renderer. Rendering performs no native I/O.

Only the separately pinned CommonModule reader is embedded. Commands contain
identity/time/UUID scalars, never source, paths, expressions or method names.
The installed DLL deliberately retains its own reference until process exit.
"""
from pathlib import Path
import hashlib
import json
import math
import re
import struct

import native_ram_carrier as fixed

FIXED_SHA256 = 'c75ca413a26e5cccb6f4ff68f9a3d4e88ae5b9b960560e408afa0b606cdf1301'
SOURCE_SHA256 = '1f6d544d1963a19e4da54a67f246457a63ce080a30151857472802acaa2d92e3'
SOURCE_TOKEN = b'__SAFE_COMMON_MODULE_RAM_SCOPE_ADMITTED__'
SECTION_ANCHOR = 'args[0]=(uint32_t)"AH1C_RESIDENT_COMMON_MODULE_V2";'
ROOT_UUID = '218b5d00-7e10-486f-874c-73c2368ed5da'
PROPERTY = fixed.PROPERTY
COMMAND_BYTES = 160
RESPONSE_BYTES = 32
ACK_BYTES = 16
MAX_COMMANDS = 64
MAX_SESSION_SECONDS = 600
CONFIG_KEYS = {'operationId', 'scopeSha256', 'sessionId', 'installNonce', 'serverPid',
               'serverBirth', 'pipePath', 'installedAt', 'sessionValidUntil', 'armPath', 'resultPath'}


def need(ok, code):
    if not ok:
        raise ValueError('PERSISTENT_RAM_' + code)


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def validate_configuration(configuration, identity):
    need(type(identity) is dict and identity.keys() == fixed.IDENTITY_KEYS, 'IDENTITY_SCHEMA')
    need(all(fixed._uint(identity[k]) for k in ('processId', 'guiThreadId', 'engineAddress', 'moduleAddress'))
         and fixed._hex(identity['birth'], 16) and identity['birth'] != '0'*16, 'IDENTITY')
    c = configuration
    need(type(c) is dict and c.keys() == CONFIG_KEYS, 'CONFIG_SCHEMA')
    need(all(fixed._hex(c[k], size) for k, size in (('operationId',32), ('scopeSha256',64),
             ('sessionId',32), ('installNonce',32), ('serverBirth',16)))
         and all(c[k] != '0'*len(c[k]) for k in ('operationId','sessionId','installNonce','serverBirth'))
         and fixed._uint(c['serverPid']), 'CONFIG_IDENTITY')
    need(_number(c['installedAt']) and _number(c['sessionValidUntil'])
         and 0 < c['sessionValidUntil']-c['installedAt'] <= MAX_SESSION_SECONDS, 'SESSION_TTL')
    need(type(c['pipePath']) is str and re.fullmatch(r'\\\\\.\\pipe\\AH1C-RAM-[0-9a-f]{32}', c['pipePath']) is not None, 'PIPE_PATH')
    parents = []
    for key in ('armPath','resultPath'):
        value = c[key]
        need(type(value) is str and re.fullmatch(r'[A-Za-z]:/[A-Za-z0-9_./-]{1,400}', value) is not None
             and '..' not in value.split('/'), 'BOOTSTRAP_PATH')
        path = Path(value).resolve()
        need(path.is_relative_to((fixed.ROOT/'build').resolve()), 'BOOTSTRAP_BOUNDARY')
        parents.append(path.parent)
    need(parents[0] == parents[1] and c['armPath'] != c['resultPath'], 'BOOTSTRAP_DISTINCT')


def _replace(source, old, new):
    need(source.count(old) == 1, 'FIXED_ANCHOR')
    return source.replace(old, new, 1)


def _piece(source, start, end):
    need(source.count(start) == 1 and source.count(end) == 1, 'PIECE_ANCHOR')
    return source[source.index(start):source.index(end)]


def render(source: bytes, *, configuration: dict, identity: dict) -> bytes:
    """Emit pinned resident source without compiling, loading or writing files."""
    return _render(source, configuration=configuration, identity=identity,
                   expected_source_sha256=SOURCE_SHA256)


def admitted_source(source: bytes) -> bytes:
    """Return the exact compile input after checking the frozen template pin."""
    need(type(source) is bytes and hashlib.sha256(source).hexdigest()==SOURCE_SHA256,'SOURCE_PIN')
    need(source.count(SOURCE_TOKEN)==1,'SOURCE_SCOPE_TOKEN')
    return source.replace(SOURCE_TOKEN,b'true',1)


def classify_epoch(row, *, operation_id, scope_sha256, process_id, execute_thread_id,
                   opcode, callback_known, callback_sdk_rc, target_identity_verified):
    """Strict resident chain check, including truthful no-Execute GUI CLOSE.

    Unlike the old Execute-only validator this does not synthesize Execute facts
    for CLOSE, rename a receipt or mutate the input dictionary.
    """
    need(type(row) is dict and fixed._hex(operation_id,32) and fixed._hex(scope_sha256,64)
         and row.get('kind')=='RESIDENT_RAM_SDK_CHAIN_CPP_EXCEPTION_TYPE_EPOCH'
         and row.get('operationId')==operation_id and row.get('scopeSha256')==scope_sha256,
         'EPOCH_BINDING')
    need(fixed._uint(process_id) and fixed._uint(execute_thread_id)
         and type(row.get('processId')) is int and row['processId']==process_id
         and type(row.get('executeThreadId')) is int and row['executeThreadId']==execute_thread_id
         and type(opcode) is int and opcode in (3,4,5) and callback_known is True
         and target_identity_verified is True and type(callback_sdk_rc) is int and callback_sdk_rc==0,
         'EPOCH_IDENTITY')
    need(row.get('phase')=='SDK_CHAIN_RETURNED' and row.get('epochCoverage')=='synchronous_gui_sdk_chain'
         and all(row.get(k) is True for k in ('sdkChainEntered','sdkChainReturned','sdkChainComplete',
                    'handlerRegistered','handlerRemoved','selfReferenceRetained','dllMustRemainLoadedUntilProcessExit','typeMetadataOnly'))
         and type(row.get('sdkChainRc')) is int and row['sdkChainRc']==0, 'EPOCH_CHAIN')
    need(row.get('executeEntered') is (opcode!=5) and row.get('executeReturned') is (opcode!=5)
         and type(row.get('sdkExecuteRc')) is int and row['sdkExecuteRc']==(-2147483647 if opcode==5 else 0),
         'EPOCH_EXECUTE')
    need(row.get('handlerReturn')=='CONTINUE_SEARCH' and row.get('typeDecoderProfile')==fixed.epoch.PROFILE
         and row.get('hashAlgorithm')=='FNV1A32_OBSERVATION_ONLY'
         and all(row.get(k) is False for k in ('counterOverflow','typeEventOverflow','typeDecoderReentry',
             'futureOtherThreadBarrierVerified','exceptionDetailsCaptured','exceptionObjectRead','scopeSourceBindingVerified',
             'fullPendingVerified','databaseUpdateAuthorized','allCppExceptionFree','listStreamPathExceptionFreeVerified')),
         'EPOCH_COVERAGE')
    for key,value in (('maximumTypeEvents',32),('maximumCatchableTypes',16),('maximumNameBytes',96)):
        need(type(row.get(key)) is int and row[key]==value,'EPOCH_LIMITS')
    for key in ('cppThrows','cppThrowsExecuteThread','cppThrowsOtherThreads','otherExceptions',
                'otherExceptionsExecuteThread','otherExceptionsOtherThreads','typeEventCount',
                'decodedCppThrows','unknownCppThrows','listStreamCompatibleThrows'):
        need(type(row.get(key)) is int and row[key]==0,'EPOCH_EXCEPTION')
    need(type(row.get('typeEvents')) is list and not row['typeEvents'],'EPOCH_EVENTS')
    return dict(sdkChainExceptionFree=True,synchronousExecuteExceptionFree=opcode!=5,
                guiFunctionReleaseVerified=opcode==5,dllRetainedUntilProcessExit=True,
                futureOtherThreadBarrierVerified=False,sourceBindingVerified=False,
                fullPendingVerified=False,databaseUpdateAuthorized=False)


def _render(source, *, configuration, identity, expected_source_sha256):
    """Private synthetic-fixture seam; production calls render's fixed pin."""
    validate_configuration(configuration, identity)
    need(hashlib.sha256(Path(fixed.__file__).read_bytes()).hexdigest() == FIXED_SHA256, 'FOUNDATION_PIN')
    need(type(source) is bytes and 0 < len(source) <= 131072 and b'\0' not in source
         and hashlib.sha256(source).hexdigest() == expected_source_sha256, 'SOURCE_PIN')
    text = source.decode('utf-8','strict')
    need(text.count('void ahSafeCommonModuleRam(int_ptr envelope)') == 1, 'SOURCE_ENTRY')
    if expected_source_sha256 == SOURCE_SHA256:
        source=admitted_source(source)
    # The verified c75 prefix supplies only pinned ABI/EH helpers. No original
    # two-job worker, paths, application target or entry is present afterwards.
    c = configuration
    binding = dict(root_uuid=ROOT_UUID, session_id=c['sessionId'], process_id=identity['processId'],
                   birth=identity['birth'], generation=1, source_domain='database_saved',
                   valid_until=c['installedAt']+30)
    slots=[]
    for index in range(2):
        row=dict(operationId=c['operationId'],scopeSha256=c['scopeSha256'],requestId=str(index+1)*32,
                 revision=index+1,issuedAt=c['installedAt'],validUntil=c['installedAt']+20,
                 binding=binding.copy(),target=dict(object_uuid=fixed.TARGETS[index],property_uuid=PROPERTY),
                 pipePath='\\\\.\\pipe\\AH1C-RAM-'+str(index+1)*32,
                 serverPid=c['serverPid'],serverBirth=c['serverBirth'])
        for key in ('epochPath','resultPath','armPath','callbackPath','proofPath'):
            row[key]=(Path(c['armPath']).parent/(str(index)+'-'+key+'.bin')).as_posix()
        slots.append(row)
    dummy=b'void ahSafeSavedModuleRam(int_ptr envelope){}'
    prefix=fixed.render(dummy,slots=tuple(slots),identity=identity).decode('utf-8')
    prefix=prefix[:prefix.index('/* Fixed bounded two-job session.')]
    declaration=fixed._fixed(dummy,tuple(slots),identity)
    new_declaration=_declarations(source,c,identity)
    prefix=_replace(prefix,declaration,new_declaration)
    # Epoch receipts remain exclusively RAM. Keep the existing bounded image
    # decoder and counter semantics, replacing only its own file sink/lifecycle.
    write=_piece(prefix,'static BOOL ahCppEpochWrite(', 'static BOOL ahCppEpochRemove(')
    write=_replace(write,'char output[32768];','char *output=ahResidentEpoch;')
    write=write.replace('sizeof(output)','sizeof(ahResidentEpoch)')
    write=_replace(write,' if(ahCppEpochReceipt==INVALID_HANDLE_VALUE)return FALSE;','')
    start=write.index(' zero.QuadPart=0;')
    write=write[:start]+' ahResidentEpochBytes=(DWORD)length;return TRUE;\n}\n\n'
    prefix=prefix[:prefix.index('static BOOL ahCppEpochWrite(')]+write+prefix[prefix.index('static BOOL ahCppEpochRemove('):]
    prefix=_replace(prefix,' ahCppEpochReceipt=CreateFileW(AH_CPP_EPOCH_RECEIPT_FILE,GENERIC_WRITE,FILE_SHARE_READ,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);\n if(ahCppEpochReceipt==INVALID_HANDLE_VALUE)return FALSE;',' ahResidentEpochBytes=0;')
    prefix=prefix.replace('CloseHandle(ahCppEpochReceipt);ahCppEpochReceipt=INVALID_HANDLE_VALUE;','')
    prefix=_replace(prefix,' if(ahCppEpochReceipt!=INVALID_HANDLE_VALUE){}','') if ' if(ahCppEpochReceipt!=INVALID_HANDLE_VALUE){}' in prefix else prefix
    prefix=prefix.replace('NATIVE_RAM_SDK_CHAIN_CPP_EXCEPTION_TYPE_EPOCH','RESIDENT_RAM_SDK_CHAIN_CPP_EXCEPTION_TYPE_EPOCH')
    prefix=_replace(prefix,'#ifndef AH_CPP_EPOCH_RECEIPT_FILE\n#error AH_CPP_EPOCH_RECEIPT_FILE_required\n#endif','')
    support=_support()
    result=(prefix+'\n'+support+'\n'+RESIDENT).encode('utf-8')
    need(b'AH_CPP_EPOCH_RECEIPT_FILE' not in result and b'ahRamSlots[2]' not in result
         and b'void ahSafeSavedModuleRam' not in result, 'OLD_ROUTE_RETAINED')
    return result


def _declarations(source,c,identity):
    lit=fixed._literal
    return r'''
#include <stdio.h>
#include <string.h>
#include <stdint.h>
typedef struct {
 const char *operation,*scope,*nonce;DWORD revisionLow,revisionHigh,selector;
 double issued,valid;const wchar_t *pipe;DWORD serverPid;ULONGLONG serverBirth;
 const wchar_t *epoch,*result,*arm,*callback,*proof;const char *metadata;
} AhRamSlot;
static const char ahRamSource[]='''+lit(source)+r''';
static const char ahResidentSession[]='''+lit(c['sessionId'])+r''';
static const char ahResidentInstallNonce[]='''+lit(c['installNonce'])+r''';
static const double ahResidentInstalled='''+repr(float(c['installedAt']))+r''',ahResidentExpires='''+repr(float(c['sessionValidUntil']))+r''';
static const wchar_t *ahResidentArmPath=L'''+lit(c['armPath'])+r''',*ahResidentResultPath=L'''+lit(c['resultPath'])+r''';
static char ahResidentNonce[33],ahResidentUuid[33];
static AhRamSlot ahRamSlots[1]={{'''+lit(c['operationId'])+','+lit(c['scopeSha256'])+r''',ahResidentNonce,0,0,0,0,0,L'''+lit(c['pipePath'])+','+str(c['serverPid'])+'u,0x'+c['serverBirth']+r'''ULL,0,0,0,0,0,0}};
static volatile LONG ahRamCurrent=0,ahRamSdkChainEntered=0,ahRamSdkChainReturned=0,ahRamSdkChainComplete=0;
static int ahRamSdkChainRc=-2147483647,ahRamActualExecuteRc=-2147483647;
static char ahResidentEpoch[32768];static DWORD ahResidentEpochBytes=0;
#undef AH_CPP_EPOCH_OPERATION_ID
#undef AH_CPP_EPOCH_SCOPE_SHA256
#define AH_CPP_EPOCH_OPERATION_ID (ahRamSlots[0].operation)
#define AH_CPP_EPOCH_SCOPE_SHA256 (ahRamSlots[0].scope)
typedef char AhResidentPid[(AH_SDK_TARGET_PID=='''+str(identity['processId'])+r''')?1:-1];
typedef char AhResidentBirthLow[(AH_SDK_BIRTH_LOW=='''+str(int(identity['birth'][8:],16))+r'''u)?1:-1];
typedef char AhResidentBirthHigh[(AH_SDK_BIRTH_HIGH=='''+str(int(identity['birth'][:8],16))+r'''u)?1:-1];
typedef char AhResidentEngine[(AH_SDK_ENGINE_ADDRESS=='''+str(identity['engineAddress'])+r'''u)?1:-1];
typedef char AhResidentModule[(AH_SDK_MODULE_ADDRESS=='''+str(identity['moduleAddress'])+r'''u)?1:-1];
#define AH_RAM_GUI_THREAD '''+str(identity['guiThreadId'])+'\n'


def _support():
    old=fixed.CARRIER
    helpers=_piece(old,'static DWORD ahRamWord(', 'static BOOL ahRamAllocate(')
    helpers=_replace(helpers,' if(ahRamCurrent && !ahCppEpochRemoved)return FALSE;',
                     ' if(ahCppEpochRegistered && !ahCppEpochRemoved)return FALSE;')
    helpers=_replace(helpers,'&&!ahRamActualExecuteRc',
                     '&&(ahResidentOpcode==5 || !ahRamActualExecuteRc)')
    helpers=_replace(helpers,'return ahCppEpochReturned&&ahCppEpochRemoved',
                     'return (ahResidentOpcode==5 || ahCppEpochReturned)&&ahCppEpochRemoved')
    digest=_piece(old,'static DWORD ahRamRor(', 'static int ahRamExecute(')
    digest=_replace(digest,'if(!ahRamHeader||!ahRamBody||memcmp(ahRamHeader,ahRamPrefix,68)',
                    'if(!ahRamHeader||memcmp(ahRamHeader,ahRamPrefix,68)||memcmp(ahRamHeader+332,ahResidentUuid,32)')
    digest=_replace(digest,' for(n=0;n<32;n++)if(ahRamHeaderBase[4096+n]!=0xa5||ahRamBodyBase[4096+n]!=0xa5)return FALSE;',
                    ' for(n=0;n<32;n++)if(ahRamHeaderBase[4096+n]!=0xa5||(ahRamBodyBase&&ahRamBodyBase[4096+n]!=0xa5))return FALSE;')
    digest=_replace(digest,' for(n=32;n<4096;n++)if(ahRamBodyBase[4096+AH_RAM_CAPACITY+n]!=0xa5)return FALSE;',
                    ' if(ahRamBodyBase)for(n=32;n<4096;n++)if(ahRamBodyBase[4096+AH_RAM_CAPACITY+n]!=0xa5)return FALSE;')
    digest=_replace(digest,' for(n=332;n<380;n++)if(ahRamHeader[n])return FALSE;',
                    ' for(n=364;n<380;n++)if(ahRamHeader[n])return FALSE;\n'+GUARD_VALIDATE)
    execute=_piece(old,'static int ahRamExecute(', 'static BOOL ahRamBuildMetadata(')
    execute=_replace(execute,'args[0]=(uint32_t)"AH1C_FIXED_RAM_READER_V1";',SECTION_ANCHOR)
    execute=_replace(execute,' if(!ahRamFunction){',' if(ahResidentOpcode==5)goto sdk_done;\n if(!ahRamFunction){')
    # CLOSE must prove the existing function before its release; it never creates
    # a context or fabricates an Execute call/return.
    execute=_replace(execute,' sdk_done:\n',' sdk_done:\n if(ahResidentOpcode==5&&ahRamFunction)functionProven=pinned(ahRamFunction,0x28f45c,2,0xd7df0,(unsigned char*)core);\n')
    execute=_replace(execute,'if((ahRamCurrent==1||rc!=0)&&functionProven',
                     'if((ahResidentOpcode==5||rc!=0)&&functionProven')
    execute=_replace(execute,'((ahRamCurrent==0&&rc==0)?ahRamFunction!=0:ahRamFunction==0)',
                     '((ahResidentOpcode!=5&&rc==0)?ahRamFunction!=0:ahRamFunction==0)')
    execute=_replace(execute,'ahRamEpochClean()&&ahRamValidateOutput()',
                     'ahRamEpochClean()&&(ahResidentOpcode==5 || ahRamValidateOutput())')
    io=_piece(old,'typedef BOOL (WINAPI *AhRamServerPid)', 'static BOOL ahRamSend(')
    io=_replace(io,'if(wait>30000)wait=30000;', 'if(wait>600000)wait=600000;')
    return GLOBALS+helpers+ALLOCATE+digest+execute+io


GUARD_VALIDATE=r'''
 if(ahResidentOpcode==4){
  if(ahRamBody||ahRamBodyBase||ahRamWord(56)||ahRamWord(60)||ahRamWord(68)!=1||ahRamWord(72)
   ||ahRamWord(112)||ahRamWord(116)!=1||ahRamWord(120)!=1||ahRamWord(124)!=1||ahRamWord(128)!=1||ahRamWord(132)
   ||ahRamWord(140)!=1383504556||ahRamWord(144)!=100051712||memcmp(ahRamHeader+288,s->nonce,32)
   ||ahRamWord(320)!=s->revisionLow||ahRamWord(324)!=s->revisionHigh||ahRamWord(328)!=4)return FALSE;
  for(n=76;n<112;n++)if(ahRamHeader[n])return FALSE;
  if(ahRamWord(136))return FALSE;for(n=160;n<288;n++)if(ahRamHeader[n])return FALSE;
  return TRUE;
 }
 if(!ahRamBody||!ahRamBodyBase||s->selector!=3)return FALSE;
'''

GLOBALS=r'''
#define AH_RAM_CAPACITY 4194304UL
static volatile LONG ahResidentStarted=0,ahResidentGate=0,ahResidentPoison=0;
static DWORD ahResidentSequence=0,ahResidentOpcode=0,ahResidentTag=0;
static ULONGLONG ahResidentGeneration=0;static double ahResidentBindingUntil=0;
static DWORD ahResidentGuardSequence=0;static ULONGLONG ahResidentGuardGeneration=0;
static double ahResidentGuardUntil=0,ahResidentGuardBindingUntil=0;static char ahResidentGuardUuid[33];
static unsigned char ahResidentCommand[160],ahResidentAck[16];
static DWORD ahResidentResponse[8];static char ahResidentProofJson[16384],ahResidentPrefix[2048];
static DWORD ahResidentProofBytes=0;static HANDLE ahResidentCallbackEvent=0;
static unsigned char ahResidentUsedNonces[64][32];
static void *ahRamFunction=0,*ahRamContext=0;static DWORD ahRamCompiles=0,ahRamContexts=0,ahRamSdkRc=999,ahRamWorkerThread=0;
static HHOOK ahRamHook=0;static BOOL ahRamHookRemoved=FALSE;
static unsigned char *ahRamHeaderBase=0,*ahRamBodyBase=0,*ahRamHeader=0,*ahRamBody=0;
static unsigned char ahRamPrefix[68],ahRamCompleted[384];static double ahRamSampled=0;
static DWORD ahRamMetadataBytes=0,ahRamSent=0;static char ahRamMetadata[16384];
static BOOL ahRamBuffersFreed=TRUE,ahRamOutputValid=FALSE,ahRamPeerVerified=FALSE,ahRamReadyVerified=FALSE;
static BOOL ahRamPipeClosed=TRUE,ahRamDrainCompleted=TRUE;
static OVERLAPPED ahRamIo;static HANDLE ahRamRetainedPipe=INVALID_HANDLE_VALUE,ahRamRetainedEvent=0;
static DWORD ahRamFrameHeader[4]={0x43314841,0x314d4152,0,0};
static double ahRamNow(void);
'''

ALLOCATE=r'''
static BOOL ahRamAllocate(void){
 AhRamSlot *s=&ahRamSlots[0];ahRamBuffersFreed=FALSE;
 if(s->selector==5)return TRUE;
 ahRamHeaderBase=VirtualAlloc(0,12288,MEM_RESERVE,PAGE_NOACCESS);
 if(!ahRamHeaderBase||!VirtualAlloc(ahRamHeaderBase+4096,4096,MEM_COMMIT,PAGE_READWRITE))return FALSE;
 memset(ahRamHeaderBase+4096,0xa5,4096);ahRamHeader=ahRamHeaderBase+4096+32;memset(ahRamHeader,0,384);
 if(s->selector==3){
  ahRamBodyBase=VirtualAlloc(0,AH_RAM_CAPACITY+12288,MEM_RESERVE,PAGE_NOACCESS);
  if(!ahRamBodyBase||!VirtualAlloc(ahRamBodyBase+4096,AH_RAM_CAPACITY+4096,MEM_COMMIT,PAGE_READWRITE))return FALSE;
  memset(ahRamBodyBase+4096,0xa5,AH_RAM_CAPACITY+4096);ahRamBody=ahRamBodyBase+4096+32;
 }
 *(DWORD*)(ahRamHeader+0)=0x31524d53;*(DWORD*)(ahRamHeader+4)=1;*(DWORD*)(ahRamHeader+8)=384;
 *(DWORD*)(ahRamHeader+12)=s->selector;memcpy(ahRamHeader+16,s->nonce,32);
 *(DWORD*)(ahRamHeader+48)=s->revisionLow;*(DWORD*)(ahRamHeader+52)=s->revisionHigh;
 *(DWORD*)(ahRamHeader+56)=(DWORD)ahRamBody;*(DWORD*)(ahRamHeader+60)=ahRamBody?AH_RAM_CAPACITY:0;
 *(DWORD*)(ahRamHeader+64)=0x91d4a63b;*(DWORD*)(ahRamHeader+380)=0x6b5c28e7;
 memcpy(ahRamHeader+332,ahResidentUuid,32);memcpy(ahRamPrefix,ahRamHeader,68);return TRUE;
}
static BOOL ahRamFree(void){
 BOOL okay=TRUE;
 if(ahRamHeaderBase){if(ahRamHeader)SecureZeroMemory(ahRamHeaderBase+4096,4096);
  if(VirtualFree(ahRamHeaderBase,0,MEM_RELEASE))ahRamHeaderBase=ahRamHeader=0;else okay=FALSE;}
 if(ahRamBodyBase){if(ahRamBody)SecureZeroMemory(ahRamBodyBase+4096,AH_RAM_CAPACITY+4096);
  if(VirtualFree(ahRamBodyBase,0,MEM_RELEASE))ahRamBodyBase=ahRamBody=0;else okay=FALSE;}
 ahRamBuffersFreed=okay&&!ahRamHeaderBase&&!ahRamBodyBase;return ahRamBuffersFreed;
}
'''

RESIDENT=r'''
/* Fixed-length commands, one active job, sequence-tagged admission. */
static BOOL ahResidentHex(const unsigned char *p,DWORD n,BOOL nonzero){DWORD i;BOOL any=FALSE;
 for(i=0;i<n;i++){if(!((p[i]>='0'&&p[i]<='9')||(p[i]>='a'&&p[i]<='f')))return FALSE;if(p[i]!='0')any=TRUE;}return !nonzero||any;}
static BOOL ahResidentFinite(double n){return n>=0&&n<=1.7976931348623157e308;}
static BOOL ahResidentParse(void){
 DWORD *w=(DWORD*)ahResidentCommand,i,op=w[3],seq=w[4];AhRamSlot *s=&ahRamSlots[0];
 ULONGLONG rev=*(ULONGLONG*)(ahResidentCommand+88),gen=*(ULONGLONG*)(ahResidentCommand+112);
 double issued=*(double*)(ahResidentCommand+96),valid=*(double*)(ahResidentCommand+104),binding=*(double*)(ahResidentCommand+120),now=ahRamNow();
 if(memcmp(w,"AH1CCMD2",8)||w[2]!=2||w[39]!=0x32444d43||seq!=ahResidentSequence+1||seq>64
  ||(op!=3&&op!=4&&op!=5)||(seq==64&&op!=5)||w[5]!=(op==5?0:op)
  ||!ahResidentHex(ahResidentCommand+24,32,TRUE)||(op!=5&&!ahResidentHex(ahResidentCommand+56,32,TRUE))
  ||!gen||gen>=0x20000000000000ULL||!ahResidentFinite(issued)||!ahResidentFinite(valid)||!ahResidentFinite(binding)
  ||issued<ahResidentInstalled||issued>now||now>=valid
  ||(op!=5&&(valid>binding||binding>ahResidentExpires||binding-issued>60||binding<=issued))
  ||valid-issued>60||valid<=issued||gen<ahResidentGeneration)return FALSE;
 for(i=132;i<156;i++)if(ahResidentCommand[i])return FALSE;
 for(i=0;i<ahResidentSequence;i++)if(!memcmp(ahResidentCommand+24,ahResidentUsedNonces[i],32))return FALSE;
 if(op==5){if(rev||w[32])return FALSE;for(i=56;i<88;i++)if(ahResidentCommand[i])return FALSE;
  if(ahResidentGeneration&&(gen!=ahResidentGeneration||binding!=ahResidentBindingUntil))return FALSE;}
 else if(op==4){if(rev||w[32])return FALSE;}
 else if(!rev||rev>=0x20000000000000ULL||w[32]!=ahResidentGuardSequence||w[32]!=seq-1||!w[32]
  ||gen!=ahResidentGuardGeneration||binding!=ahResidentGuardBindingUntil||valid>ahResidentGuardUntil
  ||memcmp(ahResidentCommand+56,ahResidentGuardUuid,32))return FALSE;
 if(gen==ahResidentGeneration&&ahResidentGeneration&&binding!=ahResidentBindingUntil)return FALSE;
 ahResidentSequence=seq;ahResidentOpcode=op;ahResidentGeneration=gen;ahResidentBindingUntil=binding;
 memcpy(ahResidentUsedNonces[seq-1],ahResidentCommand+24,32);
 memcpy(ahResidentNonce,ahResidentCommand+24,32);memcpy(ahResidentUuid,ahResidentCommand+56,32);
 /* GUARD has no ReadRequest revision. Its AS envelope uses the positive
    control ticket, because the pinned reader rejects an all-zero revision. */
 s->revisionLow=op==4?seq:(DWORD)rev;s->revisionHigh=op==4?0:(DWORD)(rev>>32);s->selector=op;s->issued=issued;s->valid=valid;
 ahResidentGuardSequence=0;return TRUE;
}
/* Binding expiry and request expiry remain distinct, round-trip exact doubles. */
static BOOL ahResidentMetadata(void){
 AhRamSlot *s=&ahRamSlots[0];char uuid[37];int n;
 snprintf(uuid,sizeof(uuid),"%.8s-%.4s-%.4s-%.4s-%.12s",ahResidentUuid,ahResidentUuid+8,ahResidentUuid+12,ahResidentUuid+16,ahResidentUuid+20);
 n=snprintf(ahResidentPrefix,sizeof(ahResidentPrefix),
  "\"binding\":{\"root_uuid\":\"218b5d00-7e10-486f-874c-73c2368ed5da\",\"session_id\":\"%s\",\"process_id\":%lu,\"birth\":\"%08lx%08lx\",\"generation\":%I64u,\"source_domain\":\"database_saved\",\"valid_until\":%.17g},"
  "\"target\":{\"object_uuid\":\"%s\",\"property_uuid\":\"d5963243-262e-4398-b4d7-fb16d06484f6\"}",
  ahResidentSession,GetCurrentProcessId(),(DWORD)AH_SDK_BIRTH_HIGH,(DWORD)AH_SDK_BIRTH_LOW,ahResidentGeneration,ahResidentBindingUntil,uuid);
 if(n<=0||n>=sizeof(ahResidentPrefix))return FALSE;
 if(ahResidentOpcode!=3)return TRUE;
 n=snprintf(ahRamMetadata,sizeof(ahRamMetadata),"{%s,\"request_id\":\"%s\",\"revision\":%I64u,\"sampled_at\":%.17g,\"valid_until\":%.17g,"
  "\"source_sha256\":\"%.64s\",\"saved_resource_sha256\":\"%.64s\",\"byte_count\":%lu,\"crlf_count\":%lu,\"bom_present\":%s,\"ends_lf\":%s,"
  "\"identity_verified\":true,\"repeated_read_verified\":true,\"schema_verified\":true,\"dirty_before\":\"clean\",\"dirty_after\":\"clean\","
  "\"decoder_profile\":\"FORMAT15_RAM\",\"helper_calls\":0,\"source_writes\":0,\"configuration_saves\":0,\"database_updates\":0,\"repository_mutations\":0}",
  ahResidentPrefix,s->nonce,((ULONGLONG)s->revisionHigh<<32)|s->revisionLow,ahRamSampled,s->valid,ahRamHeader+160,ahRamHeader+224,
  ahRamWord(76),ahRamWord(84),ahRamWord(88)?"true":"false",ahRamWord(92)?"true":"false");
 if(n<=0||n>=sizeof(ahRamMetadata))return FALSE;ahRamMetadataBytes=(DWORD)n;return TRUE;
}
static BOOL ahResidentProof(DWORD status,DWORD rc){
 int n;char guard[3072];AhRamSlot *s=&ahRamSlots[0];unsigned char *p=ahRamCompleted;
 strcpy(guard,"null");
 if(status==0&&ahResidentOpcode==4){
  n=snprintf(guard,sizeof(guard),"{%s,\"dirty_state\":\"clean\",\"checked_at\":%.17g,\"valid_until\":%.17g,\"identity_verified\":true}",ahResidentPrefix,ahRamSampled,s->valid);
  if(n<=0||n>=sizeof(guard))return FALSE;
 }
 n=snprintf(ahResidentProofJson,sizeof(ahResidentProofJson),
  "{\"kind\":\"RESIDENT_NATIVE_RAM_CARRIER\",\"operationId\":\"%s\",\"scopeSha256\":\"%s\",\"sessionId\":\"%s\",\"installNonce\":\"%s\",\"requestId\":\"%s\","
  "\"sequence\":%lu,\"opcode\":%lu,\"status\":%lu,\"terminalRc\":%lu,\"generation\":%I64u,\"bindingValidUntil\":%.17g,\"requestValidUntil\":%.17g,\"issuedAt\":%.17g,\"targetUuidHex\":\"%s\",\"guardSequence\":%lu,"
  "\"processId\":%lu,\"guiThreadId\":%u,\"workerThreadId\":%lu,\"sdkRc\":%lu,\"compileCount\":%lu,\"contextCount\":%lu,\"contextCleared\":%s,\"functionRetained\":%s,"
  "\"handlerRemoved\":%s,\"epochClean\":%s,\"hookRemoved\":%s,\"peerVerified\":%s,\"readyVerified\":%s,\"pipeClosed\":false,\"drainCompleted\":%s,\"buffersFreed\":%s,\"sampledAt\":%.17g,"
  "\"nativeStatus\":%lu,\"nativeReason\":%lu,\"nativeEnvelopeValid\":%s,\"bodyBytes\":%lu,\"codePoints\":%lu,\"crlfCount\":%lu,\"bomPresent\":%lu,\"endsLf\":%lu,"
  "\"passes\":%lu,\"propertyReads\":%lu,\"fileOpens\":%lu,\"adoptedFiles\":%lu,\"pendingReference\":%lu,\"beforeClean\":%lu,\"afterClean\":%lu,\"prefixPreserved\":%lu,\"typedCleared\":%lu,\"nativeException\":%lu,\"storedBytes\":%lu,\"databaseRoot\":%lu,\"databaseManager\":%lu,"
  "\"sourceSha256\":\"%.64s\",\"savedResourceSha256\":\"%.64s\",\"dllSelfReferenceRetained\":true,\"guardState\":%s}",
  s->operation,s->scope,ahResidentSession,ahResidentInstallNonce,s->nonce,ahResidentSequence,ahResidentOpcode,status,rc,ahResidentGeneration,ahResidentBindingUntil,s->valid,s->issued,ahResidentUuid,*(DWORD*)(ahResidentCommand+128),
  GetCurrentProcessId(),AH_RAM_GUI_THREAD,ahRamWorkerThread,ahRamSdkRc,ahRamCompiles,ahRamContexts,ahRamContext?"false":"true",ahRamFunction?"true":"false",
  ahCppEpochRemoved?"true":"false",ahRamEpochClean()?"true":"false",ahRamHookRemoved?"true":"false",ahRamPeerVerified?"true":"false",ahRamReadyVerified?"true":"false",ahRamDrainCompleted?"true":"false",ahRamBuffersFreed?"true":"false",ahRamSampled,
  *(DWORD*)(p+68),*(DWORD*)(p+72),(ahRamOutputValid&&ahResidentOpcode!=5)?"true":"false",*(DWORD*)(p+76),*(DWORD*)(p+80),*(DWORD*)(p+84),*(DWORD*)(p+88),*(DWORD*)(p+92),
  *(DWORD*)(p+96),*(DWORD*)(p+100),*(DWORD*)(p+104),*(DWORD*)(p+108),*(DWORD*)(p+112),*(DWORD*)(p+116),*(DWORD*)(p+120),*(DWORD*)(p+124),*(DWORD*)(p+128),*(DWORD*)(p+132),*(DWORD*)(p+136),*(DWORD*)(p+140),*(DWORD*)(p+144),
  (ahRamOutputValid&&ahResidentOpcode==3)?(char*)p+160:"",(ahRamOutputValid&&ahResidentOpcode==3)?(char*)p+224:"",guard);
 if(n<=0||n>=sizeof(ahResidentProofJson))return FALSE;ahResidentProofBytes=(DWORD)n;return TRUE;
}
static LONG ahResidentTicket(DWORD seq,LONG phase){return (LONG)((seq<<3)|(DWORD)phase);}
/* A stale prechecked callback can only CAS its old tagged sequence. */
__declspec(dllexport) LRESULT CALLBACK ahSdkHook(int code,WPARAM w,LPARAM l){
 MSG *m=(MSG*)l;DWORD seq;
 if(code>=0&&w==PM_REMOVE&&m&&m->message==AH_SDK_MESSAGE&&(DWORD)m->lParam==ahResidentTag
  &&GetCurrentThreadId()==AH_RAM_GUI_THREAD&&ahRamIdentity()){
  seq=(DWORD)m->wParam;
  if(seq&&seq<=65&&InterlockedCompareExchange(&ahResidentGate,ahResidentTicket(seq,1),ahResidentTicket(seq,0))==ahResidentTicket(seq,0)){
   ahRamSdkRc=(DWORD)ahRamExecute();
   InterlockedExchange(&ahResidentGate,ahResidentTicket(seq,3));SetEvent(ahResidentCallbackEvent);
  }
 }return CallNextHookEx(0,code,w,l);
}
static BOOL ahResidentSeal(void){
 LONG armed=ahResidentTicket(ahResidentSequence,0),state;
 state=InterlockedCompareExchange(&ahResidentGate,ahResidentTicket(ahResidentSequence,2),armed);
 return state==armed||state==ahResidentTicket(ahResidentSequence,2)||state==ahResidentTicket(ahResidentSequence,3);
}
static BOOL ahResidentUnhook(void){
 BOOL safe=ahResidentSeal();if(ahRamHook){ahRamHookRemoved=UnhookWindowsHookEx(ahRamHook);if(ahRamHookRemoved)ahRamHook=0;}
 return safe&&!ahRamHook;
}
static BOOL ahResidentDispatch(void){
 double now;DWORD wait;
 ahRamSdkRc=999;ahRamOutputValid=FALSE;ahRamSampled=0;ahResidentEpochBytes=0;
 memset(ahRamCompleted,0,sizeof(ahRamCompleted));
 if(!ahRamAllocate())return FALSE;
 if(!ResetEvent(ahResidentCallbackEvent))return FALSE;
 InterlockedExchange(&ahResidentGate,ahResidentTicket(ahResidentSequence,0));
 if(!PostThreadMessageW(AH_RAM_GUI_THREAD,AH_SDK_MESSAGE,ahResidentSequence,ahResidentTag))return FALSE;
 now=ahRamNow();wait=now<0||now>=ahRamSlots[0].valid?0:(DWORD)((ahRamSlots[0].valid-now)*1000);
 if(!wait||WaitForSingleObject(ahResidentCallbackEvent,wait)!=WAIT_OBJECT_0)return FALSE;
 return InterlockedCompareExchange(&ahResidentGate,0,0)==ahResidentTicket(ahResidentSequence,3);
}
static BOOL ahResidentSend(HANDLE pipe,HANDLE event,AhRamCancel cancel,DWORD status,DWORD rc){
 DWORD frame=0;double deadline=ahRamSlots[0].valid;
 if(ahRamHeader)memcpy(ahRamCompleted,ahRamHeader,384);
 if(!ahResidentMetadata()||!ahResidentProof(status,rc))return FALSE;
 if(status==0&&ahResidentOpcode==3){ahRamFrameHeader[2]=ahRamMetadataBytes;ahRamFrameHeader[3]=*(DWORD*)(ahRamCompleted+76);frame=16+ahRamMetadataBytes+ahRamFrameHeader[3];}
 memcpy(ahResidentResponse,"AH1CRSP2",8);ahResidentResponse[2]=ahResidentSequence;ahResidentResponse[3]=ahResidentOpcode;
 ahResidentResponse[4]=status;ahResidentResponse[5]=ahResidentProofBytes;ahResidentResponse[6]=ahResidentEpochBytes;ahResidentResponse[7]=frame;
 if(!ahRamWriteOverlapped(pipe,(unsigned char*)ahResidentResponse,32,event,cancel,deadline)
  ||!ahRamWriteOverlapped(pipe,(unsigned char*)ahResidentProofJson,ahResidentProofBytes,event,cancel,deadline)
  ||!ahRamWriteOverlapped(pipe,(unsigned char*)ahResidentEpoch,ahResidentEpochBytes,event,cancel,deadline))return FALSE;
 if(frame&&(!ahRamWriteOverlapped(pipe,(unsigned char*)ahRamFrameHeader,16,event,cancel,deadline)
  ||!ahRamWriteOverlapped(pipe,(unsigned char*)ahRamMetadata,ahRamMetadataBytes,event,cancel,deadline)
  ||!ahRamWriteOverlapped(pipe,ahRamBody,ahRamFrameHeader[3],event,cancel,deadline)))return FALSE;
 return ahRamTransfer(pipe,ahResidentAck,16,event,cancel,deadline,TRUE)&&!memcmp(ahResidentAck,"AH1CACK2",8)
  &&*(DWORD*)(ahResidentAck+8)==ahResidentSequence&&!*(DWORD*)(ahResidentAck+12);
}
/* Expiry/disconnect permits a fresh GUI release, never SDK on the worker.
   Internal ticket65 cannot revive any queued cancelled wire ticket1..64. */
static BOOL ahResidentCloseIdle(void){
 double now;if(!ahRamFunction)return TRUE;
 if(!ahResidentSeal()||ahRamContext||ahSdkAbiFault||ahCppEpochActive||ahCppEpochHandlerToken)return FALSE;
 if(!ahRamFree())return FALSE;
 now=ahRamNow();if(now<0||ahResidentSequence>=65)return FALSE;
 ahResidentSequence++;ahResidentOpcode=5;ahRamSlots[0].selector=5;
 ahRamSlots[0].issued=now;ahRamSlots[0].valid=now+5;
 return ahResidentDispatch()&&ahResidentSeal()&&!ahRamSdkRc&&!ahRamFunction&&!ahRamContext&&ahRamEpochClean();
}
__declspec(dllexport) DWORD WINAPI ahSdkArmOwnThread(LPVOID argument){
 HMODULE kernel=GetModuleHandleW(L"kernel32.dll");AhRamServerPid pid;AhRamCancel cancel;HANDLE peer=0,pipe=INVALID_HANDLE_VALUE,event=0,thread=0;
 typedef DWORD (WINAPI *Owner)(HANDLE);Owner owner;DWORD observed=0,rc=301,arm[2]={0,0},status;unsigned char ready[40];BOOL quiescent=TRUE,closed=FALSE;
 if(InterlockedCompareExchange(&ahResidentStarted,1,0)!=0)return 302;
 ahRamWorkerThread=GetCurrentThreadId();
 if(!ahRamIdentity()||(DWORD)argument!=AH_RAM_GUI_THREAD||ahRamWorkerThread==AH_RAM_GUI_THREAD
  ||ahRamNow()<ahResidentInstalled||ahRamNow()>=ahResidentExpires)goto done;
 if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(LPCWSTR)(uintptr_t)&ahSdkHook,&ahCppEpochSelfReference))goto done;
 pid=(AhRamServerPid)GetProcAddress(kernel,"GetNamedPipeServerProcessId");cancel=(AhRamCancel)GetProcAddress(kernel,"CancelIoEx");owner=(Owner)GetProcAddress(kernel,"GetProcessIdOfThread");
 thread=OpenThread(0x40,FALSE,AH_RAM_GUI_THREAD);if(!pid||!cancel||!owner||!thread||owner(thread)!=GetCurrentProcessId())goto done;CloseHandle(thread);thread=0;
 peer=OpenProcess(0x1000|SYNCHRONIZE,FALSE,ahRamSlots[0].serverPid);if(!ahRamServerLive(peer))goto done;
 pipe=CreateFileW(ahRamSlots[0].pipe,GENERIC_READ|GENERIC_WRITE|0x80,0,0,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|0x00110000,0);
 if(pipe==INVALID_HANDLE_VALUE||!pid(pipe,&observed)||observed!=ahRamSlots[0].serverPid||!ahRamServerLive(peer))goto done;
 ahRamPipeClosed=FALSE;ahRamPeerVerified=TRUE;event=CreateEventW(0,TRUE,FALSE,0);ahResidentCallbackEvent=CreateEventW(0,TRUE,FALSE,0);
 if(!event||!ahResidentCallbackEvent)goto done;
 if(!ahRamTransfer(pipe,ready,40,event,cancel,ahResidentExpires,TRUE)||memcmp(ready,"AH1CRDY1",8)||memcmp(ready+8,ahResidentInstallNonce,32))goto done;
 ahRamReadyVerified=TRUE;memcpy(&ahResidentTag,ahResidentInstallNonce,4);if(!ahResidentTag)goto done;
 ahRamHook=SetWindowsHookExW(3,ahSdkHook,0,AH_RAM_GUI_THREAD);if(!ahRamHook)goto done;
 if(!ahRamWriteNew(ahResidentArmPath,arm,8))goto done;
 while(ahResidentSequence<64&&!ahResidentPoison){
  if(!ahRamServerLive(peer)||!ahRamTransfer(pipe,ahResidentCommand,160,event,cancel,ahResidentExpires,TRUE)||!ahResidentParse()){rc=303;goto done;}
  if(!ahResidentDispatch()){rc=304;goto done;}
  if(!ahResidentSeal()){rc=305;goto done;}
  if(ahRamContext||ahSdkAbiFault||!ahRamEpochClean()||ahRamSdkRc||!ahRamOutputValid){
   /* Preserve the failed chain in a RAM UNKNOWN response before any separate
      cleanup epoch can reset counters. No body frame or guard lease follows. */
   rc=306;ahResidentSend(pipe,event,cancel,2,rc);goto done;
  }
  status=ahResidentOpcode==5?4:0;
  if(ahResidentOpcode==5){if(!ahResidentUnhook()){rc=307;goto done;}closed=TRUE;}
  if(!ahResidentSend(pipe,event,cancel,status,0)||!ahRamServerLive(peer)){rc=308;goto done;}
  if(ahResidentOpcode==4){ahResidentGuardSequence=ahResidentSequence;ahResidentGuardGeneration=ahResidentGeneration;
   ahResidentGuardUntil=ahRamSlots[0].valid;ahResidentGuardBindingUntil=ahResidentBindingUntil;memcpy(ahResidentGuardUuid,ahResidentUuid,33);}
  if(!ahRamFree()){rc=309;goto done;}
  if(closed){rc=0;break;}
 }
 done:if(rc&&ahRamFunction&&!ahResidentCloseIdle())InterlockedExchange(&ahResidentPoison,1);
 quiescent=ahResidentUnhook();if(rc)InterlockedExchange(&ahResidentPoison,1);
 ahResidentGuardSequence=0;
 if(quiescent&&!ahRamContext&&!ahSdkAbiFault&&ahRamDrainCompleted){ahRamFree();if(event)CloseHandle(event);
  if(pipe!=INVALID_HANDLE_VALUE){CloseHandle(pipe);ahRamPipeClosed=TRUE;}if(ahResidentCallbackEvent)CloseHandle(ahResidentCallbackEvent);ahResidentCallbackEvent=0;}
 else{ahRamRetainedPipe=pipe;ahRamRetainedEvent=event;rc=310;}
 if(peer)CloseHandle(peer);if(thread)CloseHandle(thread);
 if(!ahRamWriteNew(ahResidentResultPath,&rc,4))rc=311;
 return rc?2:1;
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved){if(reason==DLL_PROCESS_ATTACH)sdkInstance=instance;return TRUE;}
'''
