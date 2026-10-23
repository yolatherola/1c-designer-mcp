"""Backend-only supplied-copy certificate; no live binder, reader or authority.

The old exact decoder/extractor/ledger code is reused in an isolated namespace.
The only new type data is the pinned backend chain; reason is an internal enum,
not an operating-system error. This module neither changes global SDK guards
nor permits any native publication, Save, retry or cleanup.
"""
import hashlib
from pathlib import Path
import re
from types import FunctionType

import policy_saved_null_certificate as old

OLD_SHA='8d9230b36e00a9add044bdf21400742f6d817e34ab631884e12ab1c5fee27511'
BACKEND_SHA='498664a61cee45d979bd4d8eacfddf20e7510780df52daaeacd5314bce22e739'
LAYOUTS={'backend.dll':(0x1356000,0x11220a0,0x1122094,0x1122078,0x1172970,0x98a5c0,
                        0x1121e64,0x1172754,0xd22142,0x98a590)}
HASHES={'backend.dll':BACKEND_SHA}
FILE_NAME=old.FILE_NAME;BASE_NAME=old.BASE_NAME
Module=old.Module;ObjectSpan=old.ObjectSpan;TypedFileException=old.TypedFileException;ReasonFact=old.ReasonFact
LEDGER_KEYS=old.LEDGER_KEYS
_LOADED_SHA=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

def need(ok,code):
    if not ok:raise ValueError('BACKEND_REASON_CERTIFICATE_'+code)

def pins():
    need(hashlib.sha256(Path(old.__file__).read_bytes()).hexdigest()==OLD_SHA,'OLD_PIN')
    need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==_LOADED_SHA,'SOURCE_PIN')

def _c_variant():
    """Finite reversible template adaptation; exact decoder logic is retained."""
    pins();text=old.C
    edits=(('layouts[2][10]','layouts[1][10]'),('hashes[2][32]','hashes[1][32]'),('m->module>1','m->module!=0'))
    for a,b in edits:need(text.count(a)==1,'C_ANCHOR');text=text.replace(a,b,1)
    text=re.sub(r'\bAhNull', 'AhBackendNull',text)
    text=re.sub(r'\bahNull', 'ahBackendNull',text)
    text=text.replace('AH_NULL_CERT_ADMITTED','AH_BACKEND_NULL_CERT_ADMITTED')
    reverse=text.replace('AH_BACKEND_NULL_CERT_ADMITTED','AH_NULL_CERT_ADMITTED')
    reverse=re.sub(r'\bahBackendNull','ahNull',reverse);reverse=re.sub(r'\bAhBackendNull','AhNull',reverse)
    for a,b in reversed(edits):need(reverse.count(b)==1,'C_REVERSE_ANCHOR');reverse=reverse.replace(b,a,1)
    need(reverse==old.C,'C_REVERSE');return text

C=_c_variant()
# Functions retain bytecode, defaults and closure, but all cross-calls resolve
# inside this separate dictionary. The frozen old module's globals stay intact.
_issuer=object()
_environment=dict(vars(old),LAYOUTS=LAYOUTS,HASHES=HASHES,C=C,_ISSUER=_issuer)
REUSED=('need','admitted','u32','module_from_image','_copy','decode_type','extract_reason','validate_interval','render')
_functions={}
for _name in REUSED:
    _source=getattr(old,_name)
    _fn=FunctionType(_source.__code__,_environment,_source.__name__,_source.__defaults__,_source.__closure__)
    _fn.__kwdefaults__=_source.__kwdefaults__;_functions[_name]=_fn
_environment.update(_functions)

def module_from_image(*args,**kwargs):
    pins();return _functions['module_from_image'](*args,**kwargs)

def decode_type(*args,**kwargs):
    pins();return _functions['decode_type'](*args,**kwargs)

def extract_reason(*args,**kwargs):
    pins();return _functions['extract_reason'](*args,**kwargs)

def validate_interval(*args,**kwargs):
    """Inherited numeric predicate only; never accept SDK416/CPP or close refs."""
    pins();return _functions['validate_interval'](*args,**kwargs)

def render(*args,**kwargs):
    """Emit the backend-only prefixed C; default admission remains denied."""
    pins();return _functions['render'](*args,**kwargs)

def reason_metadata(fact):
    """Describe a private scalar fact without inferring OS/not-found semantics."""
    pins();need(type(fact) is ReasonFact and fact._issuer is _issuer,'REASON_ISSUER')
    return dict(kind='BACKEND_FILEEXCEPTION_SCALAR_FACT',reason=fact.reason,
        reasonNamespace='core::FileException::Error',osErrorCodeInterpreted=False,osNotFoundProven=False,
        runtimeVerified=False,sourceJoinVerified=False,sdkAccepted=False,writerAuthorized=False,
        retryAuthorized=False,cleanupAuthorized=False,nativePermit=False)
