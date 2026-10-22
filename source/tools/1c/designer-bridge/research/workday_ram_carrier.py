"""Pinned v234 workday renderer. Pure generation; no compile/load/native calls.

The v233 SDK/ownership code is cloned into private globals. Only fixed protocol,
finite total limits and bounded replay storage change. Sequence tickets never
reset; the loaded DLL retains its original self-reference until process exit.
"""
import hashlib
from pathlib import Path
from types import FunctionType

import persistent_ram_carrier as previous

PREVIOUS_SHA256='5fede18cce44dd9a1f465907deccdcbeffd209c5d43f2dcc022cb54f82feaf04'
SOURCE_SHA256=previous.SOURCE_SHA256
SOURCE_TOKEN=previous.SOURCE_TOKEN
COMMAND_BYTES=160
RESPONSE_BYTES=32
ACK_BYTES=16
MAX_COMMANDS=4096
MAX_SESSION_SECONDS=28800
NONCE_WINDOW=256
MAX_CALLBACK_TICKET=4097
SECTION_ANCHOR='args[0]=(uint32_t)"AH1C_WORKDAY_COMMON_MODULE_V3";'
CONFIG_KEYS=frozenset(previous.CONFIG_KEYS)


def need(ok,code):
    if not ok:raise ValueError('WORKDAY_RAM_'+code)


def _namespace():
    raw=Path(previous.__file__).read_bytes()
    need(hashlib.sha256(raw).hexdigest()==PREVIOUS_SHA256,'PREVIOUS_PIN')
    ns=dict(previous.__dict__,MAX_COMMANDS=MAX_COMMANDS,MAX_SESSION_SECONDS=MAX_SESSION_SECONDS)
    for name,function in previous.__dict__.items():
        if type(function) is FunctionType and function.__globals__ is previous.__dict__:
            ns[name]=FunctionType(function.__code__,ns,function.__name__,function.__defaults__,function.__closure__)
    return ns


def _replace(raw,old,new):
    need(type(raw) is str and raw.count(old)==1,'EXACT_C_ANCHOR')
    return raw.replace(old,new,1)


REPLACEMENTS=(
    # Transfer waits once, then cancels on timeout. Its cap must cover the
    # granted idle lifetime; the caller's shorter per-request deadline still wins.
    ('if(wait>600000)wait=600000;', 'if(wait>28800000)wait=28800000;'),
    ('static unsigned char ahResidentUsedNonces[64][32];',
     'static unsigned char ahResidentUsedNonces[256][32];\nstatic DWORD ahResidentNonceUsed=0,ahResidentNonceHead=0;'),
    ('if(memcmp(w,"AH1CCMD2",8)||w[2]!=2||w[39]!=0x32444d43||seq!=ahResidentSequence+1||seq>64',
     'if(memcmp(w,"AH1CCMD3",8)||w[2]!=3||w[39]!=0x33444d43||seq!=ahResidentSequence+1||seq>4096'),
    ('||(op!=3&&op!=4&&op!=5)||(seq==64&&op!=5)||w[5]!=(op==5?0:op)',
     '||(op!=3&&op!=4&&op!=5)||(seq==4096&&op!=5)||w[5]!=(op==5?0:op)'),
    ('for(i=0;i<ahResidentSequence;i++)if(!memcmp(ahResidentCommand+24,ahResidentUsedNonces[i],32))return FALSE;',
     'for(i=0;i<ahResidentNonceUsed;i++)if(!memcmp(ahResidentCommand+24,ahResidentUsedNonces[i],32))return FALSE;'),
    ('memcpy(ahResidentUsedNonces[seq-1],ahResidentCommand+24,32);',
     'memcpy(ahResidentUsedNonces[ahResidentNonceHead],ahResidentCommand+24,32);\n'
     ' ahResidentNonceHead=(ahResidentNonceHead+1)%256;if(ahResidentNonceUsed<256)ahResidentNonceUsed++;'),
    ('if(seq&&seq<=65&&InterlockedCompareExchange',
     'if(seq&&seq<=4097&&InterlockedCompareExchange'),
    ('Internal ticket65 cannot revive any queued cancelled wire ticket1..64.',
     'Internal ticket4097 cannot revive any queued cancelled wire ticket1..4096.'),
    ('if(now<0||ahResidentSequence>=65)return FALSE;',
     'if(now<0||ahResidentSequence>=4097)return FALSE;'),
    ('while(ahResidentSequence<64&&!ahResidentPoison){',
     'while(ahResidentSequence<4096&&!ahResidentPoison){'),
    ('memcpy(ahResidentResponse,"AH1CRSP2",8);','memcpy(ahResidentResponse,"AH1CRSP3",8);'),
    ('!memcmp(ahResidentAck,"AH1CACK2",8)','!memcmp(ahResidentAck,"AH1CACK3",8)'),
    (r'{\"kind\":\"RESIDENT_NATIVE_RAM_CARRIER\",\"operationId\":',
     r'{\"kind\":\"RESIDENT_NATIVE_RAM_CARRIER\",\"version\":3,\"operationId\":'),
    (previous.SECTION_ANCHOR,SECTION_ANCHOR),
)


def validate_configuration(configuration,identity):
    return _namespace()['validate_configuration'](configuration,identity)


def _render(source,*,configuration,identity,expected_source_sha256):
    ns=_namespace()
    raw=ns['_render'](source,configuration=configuration,identity=identity,expected_source_sha256=expected_source_sha256).decode('utf8')
    for old,new in REPLACEMENTS:raw=_replace(raw,old,new)
    need('AH1CCMD2' not in raw and 'AH1CRSP2' not in raw and 'AH1CACK2' not in raw,'OLD_PROTOCOL')
    need(raw.count('static DWORD ahResidentSequence=0,')==1 and raw.count('ahResidentSequence=seq;')==1,'SEQUENCE_RESET')
    need(raw.count('static unsigned char ahResidentUsedNonces[256][32];')==1,'NONCE_BOUND')
    return raw.encode('utf8')


def render(source:bytes,*,configuration:dict,identity:dict)->bytes:
    """Emit one exact-reader C carrier; outer scope must grant this workday."""
    return _render(source,configuration=configuration,identity=identity,expected_source_sha256=SOURCE_SHA256)


def admitted_source(source:bytes)->bytes:
    return _namespace()['admitted_source'](source)


def classify_epoch(*args,**kwargs):
    return _namespace()['classify_epoch'](*args,**kwargs)
