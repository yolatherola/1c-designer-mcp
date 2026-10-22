"""Reuse the reviewed resident lifecycle with the fixed register-once reader.

Functions share this module's namespace, but have fresh issuer/seal identities.
The frozen base remains unchanged, including all healthy SDK and physical
ownership guards. This module does not admit recovery or reset SDK flags.
"""
from pathlib import Path
from types import FunctionType
import hashlib

import live_resident_diagnostic_operation as _base_controller

_BASE_SHA='d1ce841a49469c3595304a7bd2f245ae18a5c8e9c9f759aebde7c1c9fbbd688c'
_BOUND_CARRIER_SHA='a3755bb06e4b64bdb2445f528781e61a6ff03a68f425099ac97f07493a6a3d87'
_BINDINGS_SHA='c05c4236556dd313cc1bedb9fe552d091d62a892b1d3ceefe4715d2c5ee2bd8e'
if hashlib.sha256(Path(_base_controller.__file__).read_bytes()).hexdigest()!=_BASE_SHA:
    raise ValueError('LIVE_RESIDENT_BOUND_BASE_PIN')

# Reuse code, not a second copy of the seven-hundred-line lifecycle. Imported
# base functions remain private to their modules; controller functions receive
# our actual namespace so normal instrumentation/patching cannot go unnoticed.
for _name,_value in tuple(vars(_base_controller).items()):
    if _name.startswith('__'):continue
    if isinstance(_value,FunctionType) and _value.__globals__ is vars(_base_controller):
        _copy=FunctionType(_value.__code__,globals(),_name,_value.__defaults__,_value.__closure__)
        _copy.__kwdefaults__=_value.__kwdefaults__
        _copy.__annotations__=dict(_value.__annotations__)
        globals()[_name]=_copy
    else:globals()[_name]=_value

PROFILE='COMMON_MODULE_LIVE_RESIDENT_BOUND'
SCOPE_KIND='ROOT_LIVE_RESIDENT_BOUND_SCOPE'
RUN_KIND='ROOT_LIVE_RESIDENT_BOUND_RUN'
SOURCE_NAME='NativeLiveCommonModuleBound.as'
SOURCE_SHA='855081cd4688d2432e67357ae239b939c340b931d5d55ffafaae97b5e752e29d'
CARRIER_SHA=_BOUND_CARRIER_SHA
TRUE_AUTH=TRUE_AUTH+('nativeGlobalBindingsInstallAuthorized',)
_ISSUER=object()
_SEAL_ISSUER=object()
_SEALS={}
_inherited_validate_scope=validate_scope


def _module(name,pin):
    # Only the fixed carrier name in inherited render/admit code is remapped.
    # Every other dependency, prior audit and wire remains independently pinned.
    if name=='live_resident_diagnostic_carrier':
        need(pin==CARRIER_SHA,'BOUND_CARRIER_PIN')
        name='live_resident_bound_carrier'
    return _base_controller._module(name,pin)


def _pins():
    need(c.digest(c.read(Path(_base_controller.__file__)))==_BASE_SHA,'BOUND_BASE_PIN')
    _base_controller._pins()
    carrier=_module('live_resident_bound_carrier',CARRIER_SHA)
    carrier._pins()
    need(c.digest(c.read(HERE/SOURCE_NAME,32768))==SOURCE_SHA,'BOUND_SOURCE_PIN')
    _module('live_native_global_bindings',_BINDINGS_SHA)


def validate_scope(row):
    _inherited_validate_scope(row)
    need(row.get('nativeGlobalBindingsSha256')==_BINDINGS_SHA,'BOUND_SCOPE_BINDINGS')


def _admitted(s):
    return _module('live_resident_bound_carrier',CARRIER_SHA).admit_source(
        c.read(HERE/SOURCE_NAME,32768),operation_id=s.plan['operationId'],
        scope_sha256=s.scope_sha256,scope_admitted=True,identity=_identity(s))
