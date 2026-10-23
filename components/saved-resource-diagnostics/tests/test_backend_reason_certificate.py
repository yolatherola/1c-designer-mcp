"""Portable backend supplied-copy tests; no PE/platform/SDK/database fixtures.

Private Python issuers below are explicit synthetic test data, not image
attestation. C fixtures reuse the existing portable compiler and memory shims.
"""
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

COMPONENT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(COMPONENT))
import backend_reason_certificate as certificate
from test_saved_resource_diagnostics import compiler_command,PRELUDE,DRIVER,memory

CERT_SHA='19e54be23dbb6cbbc33549269e28fb981370a248a15191fa7bbe870a04e15e4d'
BASE=0x10000000;OBJ=0x20000

def synthetic_chunks():
    """Only fake relocated type records; no real module or file is opened."""
    _,ti,cta,ct,td,copy,bct,btd,bcopy,unwind=certificate.LAYOUTS['backend.dll']
    return {BASE+ti:struct.pack('<4I',0,BASE+unwind,0,BASE+cta),
      BASE+cta:struct.pack('<3I',2,BASE+ct,BASE+bct),
      BASE+ct:struct.pack('<IIiiiII',0,BASE+td,0,-1,0,196,BASE+copy),
      BASE+bct:struct.pack('<IIiiiII',0,BASE+btd,0,-1,0,128,BASE+bcopy),
      BASE+td+8:certificate.FILE_NAME,BASE+btd+8:certificate.BASE_NAME}

def fixture():
    chunks=synthetic_chunks();reads=[];object_reads=[]
    # Explicit private synthetic issuer. This bypasses image attestation ONLY
    # within this fixture; the public image factory rejects these fake bytes.
    module=certificate.Module('backend.dll',BASE,certificate._issuer)
    def image(at,n):
        reads.append((at,n))
        for start,raw in chunks.items():
            if start<=at and at+n<=start+len(raw):return raw[at-start:at-start+n]
        return None
    def body(at,n):
        object_reads.append((at,n))
        if (at,n)!=(OBJ+128,4):raise AssertionError('FOUR_BYTE_COPY_ONLY')
        return struct.pack('<I',1)
    params=(0x19930520,OBJ,BASE+certificate.LAYOUTS['backend.dll'][1])
    return module,chunks,reads,image,object_reads,body,params

def typed(parts):
    return certificate.decode_type(parts[3],module=parts[0],code=0xe06d7363,parameters=parts[6],scope_admitted=True)

class BackendPythonContracts(unittest.TestCase):
    def test_exact_copy_nine_codeobjects_isolated_globals_and_defaultdeny(self):
        self.assertEqual(hashlib.sha256((COMPONENT/'backend_reason_certificate.py').read_bytes()).hexdigest(),CERT_SHA)
        self.assertEqual(tuple(certificate.old.LAYOUTS),('core83.dll','frntend.dll'))
        self.assertNotIn('backend.dll',certificate.old.HASHES)
        for name in certificate.REUSED:
            self.assertIs(certificate._functions[name].__code__,getattr(certificate.old,name).__code__)
            self.assertIsNot(certificate._functions[name].__globals__,certificate.old.__dict__)
        self.assertIn(b'AH_BACKEND_NULL_CERT_ADMITTED 0',certificate.render())
        parts=fixture()
        with self.assertRaises(ValueError):certificate.decode_type(parts[3],module=parts[0],code=0xe06d7363,parameters=parts[6])
        with self.assertRaises(ValueError):certificate.module_from_image('backend.dll',b'synthetic not PE',BASE)
        with self.assertRaises(ValueError):certificate.old.decode_type(parts[3],module=parts[0],code=0xe06d7363,parameters=parts[6],scope_admitted=True)

    def test_exact_type_before_fourbyte_reason_and_internal_enum_noauthority(self):
        parts=fixture();fact=typed(parts);self.assertEqual(parts[4],[])
        reason=certificate.extract_reason(parts[5],typed=fact,span=certificate.ObjectSpan(OBJ,196),scope_admitted=True)
        self.assertEqual(parts[4],[(OBJ+128,4)])
        row=certificate.reason_metadata(reason)
        self.assertEqual((row['reason'],row['reasonNamespace']),(1,'core::FileException::Error'))
        for key in ('osErrorCodeInterpreted','osNotFoundProven','runtimeVerified','sourceJoinVerified','sdkAccepted',
                    'writerAuthorized','retryAuthorized','cleanupAuthorized','nativePermit'):self.assertFalse(row[key])
        with self.assertRaises(ValueError):certificate.reason_metadata(certificate.ReasonFact(1,certificate.old._ISSUER))

    def test_wrong_metadata_identity_copy_name_hash_and_shortread_refuse(self):
        for index,offset,value in ((2,0,1),(2,8,4),(2,12,0),(2,20,128),(2,24,BASE+1),(3,4,BASE+1),(0,0,1),(1,0,3)):
            parts=fixture();at=list(parts[1])[index];raw=bytearray(parts[1][at]);struct.pack_into('<I',raw,offset,value);parts[1][at]=bytes(raw)
            with self.subTest(index=index,offset=offset),self.assertRaises(ValueError):typed(parts)
            self.assertEqual(parts[4],[])
        parts=fixture();at=list(parts[1])[4];parts[1][at]=b'X'+parts[1][at][1:]
        with self.assertRaises(ValueError):typed(parts)
        with self.assertRaises(ValueError):certificate.decode_type(lambda a,n:b'\0',module=parts[0],code=0xe06d7363,parameters=parts[6],scope_admitted=True)
        with self.assertRaises(ValueError):certificate.decode_type(parts[3],module=replace(parts[0],_issuer=object()),code=0xe06d7363,parameters=parts[6],scope_admitted=True)

    def test_reason_span_guard_shortcopy_and_reason_two_do_not_gain_authority(self):
        parts=fixture();fact=typed(parts)
        for change in (dict(size=195),dict(base=OBJ+4),dict(guard=True),dict(readable=False),dict(committed=False)):
            before=len(parts[4])
            with self.subTest(change=change),self.assertRaises(ValueError):certificate.extract_reason(parts[5],typed=fact,
                span=replace(certificate.ObjectSpan(OBJ,196),**change),scope_admitted=True)
            self.assertEqual(len(parts[4]),before)
        for reader in (lambda a,n:b'\0',lambda a,n:None):
            with self.assertRaises(ValueError):certificate.extract_reason(reader,typed=fact,span=certificate.ObjectSpan(OBJ,196),scope_admitted=True)
        ledger={key:0 for key in certificate.LEDGER_KEYS}
        ledger.update(after=2,whole=2,gui=77,getter_attempts=1,getter_returns=1,return_slot_equal=1,null_output=1,
            callback_quiescent=1,full22_equal=1,source_cas=1,second_own=1,refs_closed=1)
        for value in (1,2):
            reason=certificate.extract_reason(lambda a,n:struct.pack('<I',value),typed=fact,span=certificate.ObjectSpan(OBJ,196),scope_admitted=True)
            if value==2:
                with self.assertRaises(ValueError):certificate.validate_interval(ledger,((0,77,reason),(1,77,reason)),scope_admitted=True)
            else:
                row=certificate.validate_interval(ledger,((0,77,reason),(1,77,reason)),scope_admitted=True)
                for key in ('runtimeVerified','sourceJoinVerified','writerAuthorized','cleanupAuthorized','nativePermit','retryAuthorized'):self.assertFalse(row[key])

class BackendSyntheticCContracts(unittest.TestCase):
    def test_prefixed_backend_default_and_scalar_memory_contracts(self):
        compiler=compiler_command()
        with tempfile.TemporaryDirectory(prefix='backend-diagnostics-',dir=os.environ.get('SAVED_DIAGNOSTICS_TEST_TMPDIR')) as folder:
            folder=Path(folder);chunks=[]
            for at,raw in synthetic_chunks().items():chunks.append('{%su,%su,{%s}}'%(at,len(raw),','.join(map(str,raw))))
            for admitted in (False,True):
                with self.subTest(admitted=admitted):
                    body=DRIVER.replace('AhNull','AhBackendNull').replace('ahNull','ahBackendNull')
                    body=body.replace('__CHUNKS__',','.join(chunks)).replace('__MODULE__','0')
                    body=body.replace('__SHA__',','.join(map(str,bytes.fromhex(certificate.BACKEND_SHA))))
                    body=body.replace('__TI__',str(BASE+certificate.LAYOUTS['backend.dll'][1])+'u').replace('__ENABLED__',str(int(admitted)))
                    src=folder/('backend'+str(int(admitted))+'.c');exe=src.with_suffix('.exe' if os.name=='nt' else '.out')
                    src.write_bytes(PRELUDE.encode()+certificate.render(scope_admitted=admitted)+memory.render(admitted=admitted)+body.encode())
                    command=compiler+['-o',str(exe),str(src)]
                    if os.name=='nt':command.append('-lkernel32')
                    built=subprocess.run(command,capture_output=True,timeout=30)
                    self.assertEqual(built.returncode,0,built.stderr.decode('utf8','replace')[-2000:])
                    ran=subprocess.run([str(exe)],capture_output=True,timeout=10)
                    self.assertEqual((ran.returncode,ran.stderr),(0,b''))
                    self.assertEqual(ran.stdout.decode().strip(),'synthetic cases=14 admission='+str(int(admitted)))

if __name__=='__main__':unittest.main()
