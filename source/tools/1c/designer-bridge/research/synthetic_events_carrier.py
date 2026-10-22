"""Fixed synthetic event sink/adapter added to the existing typed epoch DLL.

Pure source generation; no compilation, process access or application IO.
"""
from pathlib import Path
import hashlib
import comparison_cpp_exception_type_epoch as epoch

HERE=Path(__file__).resolve().parent
PINS={
 'native_update_event_sink.h':'56e0cef5da00f1c3b5a8e660cb00709d121c8e1a6128ae99c2e66a16225bb53d',
 'native_synthetic_event_bridge.h':'3ef49713aeaee6b3e78ff6101c2c35f053c47b9588c3123490706ed61abd8102',
 'NativeSyntheticEventBridge.c.inc':'2038fdf0cc22cb9e6e42c46ff1041f36b4062421c83f5a92a1a2aa2983407c92'}


def render():
 if hashlib.sha256(Path(epoch.__file__).read_bytes()).hexdigest()!='e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4':raise ValueError('SYNTHETIC_CARRIER_EPOCH_PIN')
 parts={}
 for name,pin in PINS.items():
  raw=(HERE/name).read_bytes()
  if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('SYNTHETIC_CARRIER_INPUT_PIN')
  parts[name]=raw.decode('utf-8')
 bridge=parts['native_synthetic_event_bridge.h']
 anchor='#include "native_update_event_sink.h"'
 if bridge.count(anchor)!=1:raise ValueError('SYNTHETIC_CARRIER_INCLUDE')
 return (epoch.render().decode()+'\n'+parts['native_update_event_sink.h']+'\n'+bridge.replace(anchor,'',1)
  +'\n'+parts['NativeSyntheticEventBridge.c.inc']).encode('utf-8')
