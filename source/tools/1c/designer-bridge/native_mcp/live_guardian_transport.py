"""LIVE grammar over the pinned guardian's protected Windows transport.

Reuse its peer/ACL/HMAC/handle implementation in private function namespaces.
Saved classes and module globals remain unchanged. EOF drains only this relay.
"""
import hashlib
from pathlib import Path
from types import FunctionType

from . import guardian_client as _client
from . import guardian_service as _service
from . import windows_guardian_pipe as _pipe
from . import live_guardian_wire as wire
from .live_host_slot import LiveHostSlot

CODE_PINS = {
    'windows_guardian_pipe.py': 'c0c7a7a6a03e43d59fd29965a3b227ff337b212a577702cc5db2c76cca25e8b3',
    'guardian_client.py': 'a8b76c3a6c314c3bccbe07c9a56d90898d5bb01a9dd4f0839b219cd78e110ce9',
    'guardian_service.py': '4c350782bc9cef3d5d0b74574471abee95c56faf547acd2e1424e47251b57e04',
    'guardian_wire.py': '3ca907c8f4df783cba01f63fb002e86c9cb2a262f504b785f50a9276c938a456',
    'windows_ram_pipe.py': '54dd9a45064f34930a2dc6441c3c78cdaaeefbdf02138fcb2459830f1c57ec1e',
    'live_guardian_wire.py': '3cce7c5358391ab42e067d60272362cb2c9f8648790a28ccd6ae4d1b157ca2a3',
    'live_host_slot.py': '43cb29d6bb9522289a76bb0b8ba1208f9bffa9d043a7126aff21cd7dcf4db075',
}


def _pins():
    here = Path(__file__).resolve().parent
    if any(hashlib.sha256((here / name).read_bytes()).hexdigest() != sha
           for name, sha in CODE_PINS.items()):
        raise ValueError('LIVE_GUARDIAN_TRANSPORT_SOURCE_PIN')


_pins()


def _function(fn, namespace):
    result = FunctionType(fn.__code__, namespace, fn.__name__, fn.__defaults__, fn.__closure__)
    result.__kwdefaults__ = fn.__kwdefaults__
    result.__annotations__ = dict(fn.__annotations__)
    result.__doc__ = fn.__doc__
    return result


def _namespace(module, **overrides):
    namespace = dict(vars(module), **overrides)
    for name, value in tuple(vars(module).items()):
        if type(value) is FunctionType and value.__module__ == module.__name__:
            namespace[name] = _function(value, namespace)
    namespace.update(overrides)
    return namespace


def _methods(target, original, namespace, *, omit=()):
    for name, value in vars(original).items():
        if name not in omit and type(value) is FunctionType:
            setattr(target, name, _function(value, namespace))


_pipe_ns = _namespace(_pipe, wire=wire)
PREFIX = _pipe.PREFIX
GuardianPipeRefusal = _pipe.GuardianPipeRefusal
GuardianRpcRefusal = _client.GuardianRpcRefusal
GuardianServiceRefusal = _service.GuardianServiceRefusal


def validate_endpoint(row):
    """Validate confidential endpoint metadata; no connection or native read."""
    _pins()
    _pipe_ns['validate_endpoint'](row)


class LivePipeServer(_pipe.GuardianPipeServer):
    def __init__(self, *, timeout=5.0, capability=None):
        _pins()
        super().__init__(timeout=timeout, capability=capability)


class LivePipeClient(_pipe.GuardianPipeClient):
    def __init__(self, endpoint, *, timeout=10.0):
        _pins()
        super().__init__(endpoint, timeout=timeout)


for _cls, _original in ((LivePipeServer, _pipe.GuardianPipeServer),
                        (LivePipeClient, _pipe.GuardianPipeClient)):
    _methods(_cls, _pipe._Link, _pipe_ns, omit=('__init__',))
    _methods(_cls, _original, _pipe_ns, omit=('__init__',))


def _physical(endpoint):
    return LivePipeClient(endpoint)


_client_ns = _namespace(_client, wire=wire, _physical=_physical)


class LiveRpcClient(_client.GuardianRpcClient):
    def __init__(self, endpoint, *, transport_factory=None):
        _pins()
        _client_init(self, endpoint, transport_factory=transport_factory)


_client_init = _function(_client.GuardianRpcClient.__init__, _client_ns)
_methods(LiveRpcClient, _client.GuardianRpcClient, _client_ns, omit=('__init__',))


def _make_pipe(timeout):
    return LivePipeServer(timeout=timeout)


_service_ns = _namespace(_service, wire=wire, HostSlot=LiveHostSlot, _make_pipe=_make_pipe)


class LiveGuardianService(_service.GuardianService):
    """Protected relay around a Root-issued LIVE slot; never bootstraps 1C."""
    def __init__(self, slot, *, pipe_timeout=5.0, startup_timeout=5.0):
        _pins()
        _service_init(self, slot, pipe_timeout=pipe_timeout, startup_timeout=startup_timeout)


_service_init = _function(_service.GuardianService.__init__, _service_ns)
_methods(LiveGuardianService, _service.GuardianService, _service_ns, omit=('__init__',))
