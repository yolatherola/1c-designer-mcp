"""Portable synthetic metadata: no platform image or live process is opened.

Expected SHA descriptors in synthetic C are not attestation. The Python image
attestor rejects fake bytes; all memory API calls below are fixture functions.
"""
import ctypes
import ctypes.util
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

COMPONENT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(COMPONENT))
with patch.object(ctypes,'WinDLL',side_effect=AssertionError('LIVE_API_FORBIDDEN'),create=True):
    import policy_saved_null_certificate as certificate
    import policy_saved_reason_memory as memory

PINS={
    'policy_saved_null_certificate.py':'8d9230b36e00a9add044bdf21400742f6d817e34ab631884e12ab1c5fee27511',
    'policy_saved_reason_memory.py':'96dc53266f0626b2190d021c3446e9cd960b95f6e03454d5114241a193acd576',
}


def compiler_command():
    configured=os.environ.get('CC')
    if configured:
        command=[configured] if Path(configured).is_file() else shlex.split(configured,posix=os.name!='nt')
        if not command or not (Path(command[0]).is_file() or shutil.which(command[0])):
            raise AssertionError('EXPLICIT_COMPILER_UNAVAILABLE')
    else:
        available=next((shutil.which(name) for name in ('cc','gcc','clang') if shutil.which(name)),None)
        if not available:raise unittest.SkipTest('C compiler required for complete qualification')
        command=[available]
    expected=os.environ.get('CC_SHA256')
    if expected:
        path=Path(shutil.which(command[0]) or command[0])
        if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise AssertionError('COMPILER_SHA')
    return command


def synthetic_chunks(name):
    """Fake relocated metadata only; not an image accepted as a real module."""
    _,ti,cta,ct,td,copy,bct,btd,bcopy,unwind=certificate.LAYOUTS[name]
    base=0x10000000
    return {
        base+ti:struct.pack('<4I',0,base+unwind,0,base+cta),
        base+cta:struct.pack('<3I',2,base+ct,base+bct),
        base+ct:struct.pack('<IIiiiII',0,base+td,0,-1,0,196,base+copy),
        base+bct:struct.pack('<IIiiiII',0,base+btd,0,-1,0,128,base+bcopy),
        base+td+8:certificate.FILE_NAME,base+btd+8:certificate.BASE_NAME,
    }


PRELUDE=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
__declspec(dllimport) uint32_t __stdcall SetErrorMode(uint32_t);
#define FIXTURE_START() ((void)SetErrorMode(0x8003u))
#else
#define FIXTURE_START() ((void)0)
#endif
typedef uint32_t DWORD;typedef size_t SIZE_T;typedef void*HANDLE;
typedef struct{void*BaseAddress;SIZE_T RegionSize;DWORD State,Protect;}MEMORY_BASIC_INFORMATION;
enum{MEM_COMMIT=0x1000,PAGE_NOACCESS=1,PAGE_READONLY=2,PAGE_READWRITE=4,
 PAGE_WRITECOPY=8,PAGE_EXECUTE=16,PAGE_EXECUTE_READ=32,PAGE_EXECUTE_READWRITE=64,
 PAGE_EXECUTE_WRITECOPY=128,PAGE_GUARD=256};
static uint32_t lastError=0x12345678u,currentThread=77,imageReads,rpmCalls,rpmBytes,reasonCalls;
static uint32_t reasonValue=1,pageFailure,copyFailure,shortCopy;
static DWORD GetLastError(void){return lastError;}
static void SetLastError(DWORD e){lastError=e;}
static DWORD GetCurrentThreadId(void){lastError=2;return currentThread;}
static HANDLE GetCurrentProcess(void){lastError=3;return (HANDLE)(uintptr_t)9;}
static SIZE_T VirtualQuery(const void*p,MEMORY_BASIC_INFORMATION*out,SIZE_T n){
 lastError=4;if((uintptr_t)p!=0x20000u||n!=sizeof(*out))return 0;
 memset(out,0,sizeof(*out));out->BaseAddress=(void*)(uintptr_t)0x20000u;
 out->RegionSize=pageFailure==2?195:4096;out->State=MEM_COMMIT;
 out->Protect=pageFailure==1?PAGE_GUARD|PAGE_READWRITE:PAGE_READWRITE;return sizeof(*out);}
static int ReadProcessMemory(HANDLE h,const void*p,void*out,SIZE_T n,SIZE_T*done){
 lastError=5;rpmCalls++;rpmBytes+=(uint32_t)n;
 if(h!=(HANDLE)(uintptr_t)9||(uintptr_t)p!=0x20080u||n!=4)return 0;
 memcpy(out,&reasonValue,4);*done=shortCopy?3:4;return !copyFailure;}
'''

DRIVER=r'''
typedef struct{uint32_t at,n;unsigned char b[96];}SyntheticChunk;
static SyntheticChunk chunks[]={__CHUNKS__};
static uint32_t imageCopy(void*ctx,uint32_t at,uint32_t n,unsigned char*out){uint32_t i;
 imageReads++;for(i=0;i<6;i++)if(chunks[i].at<=at&&(uint64_t)at+n<=chunks[i].at+chunks[i].n){
  memcpy(out,chunks[i].b+at-chunks[i].at,n);return 1;}return 0;}
static uint32_t reasonCopy(void*ctx,uint32_t at,uint32_t n,unsigned char*out){
 reasonCalls++;return ahSavedReasonMemoryCopy(ctx,at,n,out);}
int main(void){uint32_t mode,i,td,rd,valid,oldRpm,oldBytes,goodTypes,goodReasons;
 AhNullImage m={0x10000000,__MODULE__,{__SHA__}};
 uint32_t params[3]={0x19930520,0x20000,__TI__};
 AhNullSpan span;AhSavedReasonMemoryWindow window;AhNullLedger ledger;AhNullEvent events[2];
 FIXTURE_START();
 for(mode=0;mode<14;mode++){
  memset(&window,0,sizeof(window));window.objectBase=0x20000;window.objectBytes=196;window.guiThread=77;
  window.active=window.opened=window.getAttempted=1;
  memset(&ledger,0,sizeof(ledger));ledger.after=ledger.whole=2;ledger.gui=77;
  ledger.ga=ledger.gr=ledger.returned=ledger.nullOut=ledger.quiet=ledger.full22=ledger.cas=ledger.secondOwn=ledger.refsClosed=1;
  memset(events,0,sizeof(events));imageReads=rpmCalls=rpmBytes=reasonCalls=goodTypes=goodReasons=0;
  currentThread=77;reasonValue=1;pageFailure=copyFailure=shortCopy=0;
  for(i=0;i<2;i++){
   AhNullType typed={0};AhNullReason reason={0};uint32_t code=0xe06d7363u;
   span.base=0x20000;span.size=196;span.committed=span.readable=1;span.guard=0;
   events[i].index=i;events[i].thread=77;window.eventIndex=i;
   if(i){switch(mode){case 1:code=0;break;case 2:reasonValue=2;break;
    case 3:span.base++;break;case 4:currentThread=78;break;case 5:pageFailure=1;break;
    case 6:window.eventIndex=0;break;case 7:window.active=0;break;case 8:shortCopy=1;break;
    case 9:window.objectBase=0xffffff80u;break;case 10:copyFailure=1;break;
    case 11:window.getReturned=1;break;case 12:pageFailure=2;break;case 13:m.sha[0]^=1;break;}}
   lastError=0x12345678u;
   td=ahNullTypeDecode(imageCopy,0,&m,code,params,3,&typed);rd=0;
   if(td){goodTypes++;rd=ahNullReasonExtract(reasonCopy,&window,&typed,&span,&reason);}
   if(rd){goodReasons++;events[i].fact=reason;}
   if(lastError!=0x12345678u)return 10;
   if(!__ENABLED__&&(td||rd||rpmCalls||imageReads||reasonCalls))return 11;
   if(i&&mode!=0&&mode!=2&&(rd||events[i].fact.typed))return 12;
  }
  if(mode==13)m.sha[0]^=1;
  valid=ahNullIntervalValidate(&ledger,events,2);
  if(valid!=(uint32_t)(__ENABLED__&&mode==0))return 13;
  if(__ENABLED__){
   if(goodTypes!=(mode==1||mode==13?1u:2u))return 14;
   if(goodReasons!=(mode==0||mode==2?2u:1u))return 15;
   if(rpmCalls!=(mode==0||mode==2||mode==8||mode==10?2u:1u)||rpmBytes!=rpmCalls*4)return 16;
   if(reasonCalls!=(mode==1||mode==3||mode==13?1u:2u))return 21;
  }
  oldRpm=rpmCalls;oldBytes=rpmBytes;currentThread=77;window.active=1;window.getReturned=0;window.eventIndex=0;
  {unsigned char out[4]={9,9,9,9};if(ahSavedReasonMemoryCopy(&window,0x20080,4,out)||out[0]!=9)return 17;}
  if(rpmCalls!=oldRpm||rpmBytes!=oldBytes)return 18;
 }
 {AhNullType typed={0x20000,1};AhNullReason reason={1,1};
  if(ahNullTypeDecode(imageCopy,0,&m,0,params,3,&typed)||typed.typed||typed.object)return 19;
  span.base=0x20000;span.size=196;span.committed=span.readable=1;span.guard=0;
  if(ahNullReasonExtract(ahSavedReasonMemoryCopy,&window,&typed,&span,&reason)||reason.typed||reason.reason)return 20;}
 if(__ENABLED__){
  memset(&window,0,sizeof(window));window.objectBase=0x20000;window.objectBytes=196;window.guiThread=77;
  window.active=window.opened=window.getAttempted=1;
  currentThread=77;reasonValue=1;pageFailure=copyFailure=shortCopy=rpmCalls=rpmBytes=0;
  for(i=0;i<32;i++){unsigned char out[4]={0};window.eventIndex=i;
   if(ahSavedReasonMemoryCopy(&window,0x20080,4,out)!=1||out[0]!=1)return 22;}
  if(rpmCalls!=32||rpmBytes!=128||window.attemptedEventMask!=0xffffffffu)return 23;
  for(i=0;i<33;i++){unsigned char out[4]={9};window.eventIndex=i;
   if(ahSavedReasonMemoryCopy(&window,0x20080,4,out)||out[0]!=9)return 24;}
  if(rpmCalls!=32||rpmBytes!=128)return 25;
 }
 printf("synthetic cases=14 admission=%u\n",(unsigned)__ENABLED__);return 0;}
'''


class PythonContracts(unittest.TestCase):
    def test_byte_identical_helpers_and_inert_default(self):
        for name,pin in PINS.items():self.assertEqual(hashlib.sha256((COMPONENT/name).read_bytes()).hexdigest(),pin)
        self.assertIn(b'AH_NULL_CERT_ADMITTED 0',certificate.render())
        self.assertIn(b'AH_SAVED_REASON_MEMORY_ADMITTED 0',memory.render())
        for bad in (1,None,{},'yes'):
            with self.assertRaises(ValueError):memory.render(admitted=bad)
            with self.assertRaises(ValueError):certificate.render(scope_admitted=bad)

    def test_fake_images_never_become_attested_modules_or_authority(self):
        for name in certificate.LAYOUTS:
            with self.assertRaises(ValueError):certificate.module_from_image(name,b'plainly synthetic; not a PE',0x10000000)
        # Pure validator fixtures use its test issuer, never a live module.
        fact=certificate.ReasonFact(1,certificate._ISSUER)
        ledger={key:0 for key in certificate.LEDGER_KEYS}
        ledger.update(after=2,whole=2,gui=77,getter_attempts=1,getter_returns=1,return_slot_equal=1,
                      null_output=1,callback_quiescent=1,full22_equal=1,source_cas=1,second_own=1,refs_closed=1)
        result=certificate.validate_interval(ledger,((0,77,fact),(1,77,fact)),scope_admitted=True)
        for key in ('runtimeVerified','savedBExistenceVerified','savedBReadSuccess','sourceJoinVerified',
                    'writerAuthorized','cleanupAuthorized','nativePermit','retryAuthorized'):
            self.assertIs(result[key],False)
        with self.assertRaises(ValueError):certificate.validate_interval(ledger,((0,77,dict(reason=1)),),scope_admitted=True)
        with self.assertRaises(ValueError):certificate.validate_interval(dict(ledger,unknown=1),((0,77,fact),(1,77,fact)),scope_admitted=True)


class SyntheticCContracts(unittest.TestCase):
    def test_both_synthetic_layouts_and_admission_branches(self):
        compiler=compiler_command()
        with tempfile.TemporaryDirectory(prefix='saved-diagnostics-',dir=os.environ.get('SAVED_DIAGNOSTICS_TEST_TMPDIR')) as folder:
            folder=Path(folder)
            for module_id,name in enumerate(certificate.LAYOUTS):
                chunks=[]
                for at,raw in synthetic_chunks(name).items():
                    chunks.append('{%su,%su,{%s}}'%(at,len(raw),','.join(map(str,raw))))
                for admitted in (False,True):
                    with self.subTest(layout=name,admitted=admitted):
                        body=DRIVER.replace('__CHUNKS__',','.join(chunks)).replace('__MODULE__',str(module_id))
                        body=body.replace('__SHA__',','.join(map(str,bytes.fromhex(certificate.HASHES[name]))))
                        body=body.replace('__TI__',str(0x10000000+certificate.LAYOUTS[name][1])+'u')
                        body=body.replace('__ENABLED__',str(int(admitted)))
                        src=folder/('case'+str(module_id)+str(int(admitted))+'.c')
                        exe=src.with_suffix('.exe' if os.name=='nt' else '.out')
                        src.write_bytes(PRELUDE.encode()+certificate.render(scope_admitted=admitted)+memory.render(admitted=admitted)+body.encode())
                        command=compiler+['-o',str(exe),str(src)]
                        if os.name=='nt':command.append('-lkernel32')
                        built=subprocess.run(command,capture_output=True,timeout=30)
                        self.assertEqual(built.returncode,0,built.stderr.decode('utf8','replace')[-2000:])
                        ran=subprocess.run([str(exe)],capture_output=True,timeout=10)
                        self.assertEqual((ran.returncode,ran.stderr),(0,b''))
                        self.assertEqual(ran.stdout.decode().strip(),'synthetic cases=14 admission='+str(int(admitted)))


if __name__=='__main__':unittest.main()
