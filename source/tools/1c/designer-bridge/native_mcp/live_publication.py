"""Separate LIVE publication: ciphertext on disk, capability only in RAM.

Readers never import a native controller. Only a root-issued READY operation
may publish; unknown native closure retains both index and opaque lease.
"""
from dataclasses import dataclass, field
from contextlib import contextmanager
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import time
from types import FunctionType
from uuid import uuid4

from . import guardian_descriptor as descriptor
from . import active_publication as saved

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
ALLOWED = ROOT / 'artifacts/designer-bridge'
INDEX = ALLOWED / 'live-guardian-active.json'
LOCK = ALLOWED / 'live-guardian-active-lock.json'
PROFILE = 'AH1C_ACTIVE_EDITOR_LIVE_GUARDIAN_V1'
DOMAIN = 'editor_live_at_capture'
DESCRIPTOR_SHA = '244a2cecfbd7e12796807aa10ad3d13f9b87f11de74a82cc3ed30405aca3a0b3'
SAVED_SHA = '9361cdce7f6fb74a5ff212510c68d6aa58999df72a42f6f7101502a3c83300cb'
CONTROLLER_SHA = '6a3ff6a02a72413fdafcd5667bfe2060d68a1ced18744271c0d488c4fc9c5279'
SELF_SHA = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
_ISSUER = object()
_LEASES = {}
_REMOVALS = {}
_DEPENDENCIES = {}
_KEYS = frozenset(('kind version profile publicationId operationId sourceDomain '
    'ownerPid ownerBirth publishedAt validUntil endpointFileName endpointCipherSha256 '
    'readerSha256 codePins').split())


class PublicationRefusal(ValueError):
    """Fixed refusal; no capability, path or native diagnostic is reflected."""


def need(ok, code):
    if not ok:
        raise PublicationRefusal('LIVE_PUBLICATION_' + code)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(row):
    return json.dumps(row, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')


def _hex(value, count):
    return (type(value) is str and re.fullmatch('[0-9a-f]{'+str(count)+'}', value)
            is not None and value != '0'*count)


def _pins():
    need(_digest(Path(descriptor.__file__).read_bytes()) == DESCRIPTOR_SHA
         and _digest(Path(saved.__file__).read_bytes()) == SAVED_SHA
         and _digest(Path(__file__).read_bytes()) == SELF_SHA, 'CODE_PIN')
    descriptor._pins()
    for relative, expected in _DEPENDENCIES.items():
        need(_digest((HERE.parent/relative).read_bytes()) == expected, 'LIVE_CODE_PIN')


def _live_dependencies():
    # Capture a revision once, then reject source changes for this process.
    # The frontend imports transport/wire only, never a native owner.
    if not _DEPENDENCIES:
        revision = {}
        for name in ('native_mcp/live_guardian_wire.py', 'native_mcp/live_guardian_transport.py'):
            revision[name] = _digest((HERE.parent/name).read_bytes())
        _DEPENDENCIES.update(revision)
    _pins()
    return dict(_DEPENDENCIES)


def _endpoint(row):
    transport = importlib.import_module('.live_guardian_transport', __package__)
    transport.validate_endpoint(row)


def _entropy(public):
    return hashlib.sha256(b'AH1C_EDITOR_LIVE_ENDPOINT_V1\0' + _canonical(public)).digest()


class _Files(saved._Files):
    """Reuse pinned ACL/identity/file checks; keep a separate LIVE lock."""
    def open(self, path, *, new=False, cleanup=False):
        # A ciphertext guard disallows deletion across hash + decrypt + reread.
        handle, size, identity = descriptor._Crypto.open(self, path, new=new, cleanup=cleanup)
        try:
            self._verify_file_acl(handle)
            return handle, size, identity
        except BaseException:
            self.w.CloseHandle(handle)
            raise

    def read(self, path):
        return self.read_public(path)[0]

    def write_new(self, path, raw):
        return self.write_public_new(path, raw)

    def remove_owned(self, path, identity):
        raw, current = self.read_public(path)
        need(current == identity, 'ENDPOINT_IDENTITY')
        self.remove_public_owned(path, identity, raw)


# The pinned algorithms are reused with a distinct profile, pins and entropy.
# No saved module globals or original methods are modified.
_lock_globals = dict(vars(saved), LOCK=LOCK)
_lock_generator = saved._Files.publication_lock.__wrapped__
_Files.publication_lock = contextmanager(FunctionType(_lock_generator.__code__,
    _lock_globals, 'publication_lock', _lock_generator.__defaults__,
    _lock_generator.__closure__))


def _descriptor_functions():
    namespace = dict(vars(descriptor), PROFILE=PROFILE, CODE_PINS=_live_dependencies(),
        _Crypto=_Files, validate_endpoint=_endpoint, _pins=_pins, _entropy=_entropy)
    for name in ('_public', 'write_endpoint', 'read_endpoint'):
        original = getattr(descriptor, name)
        namespace[name] = FunctionType(original.__code__, namespace, name,
            original.__defaults__, original.__closure__)
    return namespace['write_endpoint'], namespace['read_endpoint']


def _validate(row):
    need(type(row) is dict and row.keys() == _KEYS, 'SCHEMA')
    need(row['kind'] == 'LIVE_ACTIVE_GUARDIAN_PUBLICATION'
         and type(row['version']) is int and row['version'] == 1
         and row['profile'] == PROFILE and row['sourceDomain'] == DOMAIN, 'DOMAIN')
    need(_hex(row['publicationId'], 32) and _hex(row['operationId'], 32)
         and _hex(row['ownerBirth'], 16) and type(row['ownerPid']) is int
         and 0 < row['ownerPid'] < 2**32, 'IDENTITY')
    need(type(row['publishedAt']) is float and type(row['validUntil']) is float
         and math.isfinite(row['publishedAt']) and math.isfinite(row['validUntil'])
         and 0 <= row['publishedAt'] < row['validUntil'] <= row['publishedAt'] + 600, 'EXPIRY')
    need(row['readerSha256'] == SELF_SHA and row['codePins'] == _live_dependencies()
         and _hex(row['endpointCipherSha256'], 64), 'PINS')
    need(row['endpointFileName'] == 'live-guardian-endpoint-'+row['operationId']+'.json', 'ENDPOINT_PATH')


def _parse(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 8192, 'BOUND')
    row = json.loads(raw.decode('ascii'), object_pairs_hook=descriptor._pairs,
                     parse_constant=descriptor._constant)
    _validate(row)
    need(_canonical(row) == raw, 'CANONICAL')
    return row


def _read_index(api):
    descriptor._path(INDEX, existing=False)
    if not INDEX.exists():
        return None
    raw, identity = api.read_public(INDEX)
    return _parse(raw), raw, identity


def _metadata(row, raw):
    return dict(publicationId=row['publicationId'], operationId=row['operationId'],
        publicationSha256=_digest(raw), validUntil=row['validUntil'],
        ownerPid=row['ownerPid'], ownerBirth=row['ownerBirth'], sourceDomain=DOMAIN)


def current_publication(metadata):
    """Check a selected owner/index without decrypting or attaching a channel."""
    try:
        _pins()
        need(type(metadata) is dict and metadata.keys() == {'publicationId', 'operationId',
             'publicationSha256', 'validUntil', 'ownerPid', 'ownerBirth', 'sourceDomain'}, 'METADATA')
        need(metadata['sourceDomain'] == DOMAIN and _hex(metadata['publicationId'], 32)
             and _hex(metadata['operationId'], 32) and _hex(metadata['publicationSha256'], 64)
             and _hex(metadata['ownerBirth'], 16) and type(metadata['ownerPid']) is int
             and 0 < metadata['ownerPid'] < 2**32 and type(metadata['validUntil']) is float
             and math.isfinite(metadata['validUntil']), 'DOMAIN')
        descriptor._path(INDEX, existing=False)
        if not INDEX.exists():
            return False
        api = _Files()
        current = _read_index(api)
        if current is None:
            return False
        row, raw, _ = current
        return (metadata == _metadata(row, raw) and time.monotonic() < row['validUntil']
                and api.owner_current(row['ownerPid'], row['ownerBirth']))
    except Exception:
        pass
    raise PublicationRefusal('LIVE_PUBLICATION_CURRENT_REFUSED') from None


def resolve_active():
    """Resolve without native imports or writes; missing/expired/dead is None."""
    endpoint = None
    guard = api = None
    try:
        _pins()
        descriptor._path(INDEX, existing=False)
        if not INDEX.exists():
            return None
        api = _Files()
        snapshot = _read_index(api)
        if snapshot is None:
            return None
        row, raw, identity = snapshot
        if time.monotonic() >= row['validUntil']:
            return None
        if not api.owner_current(row['ownerPid'], row['ownerBirth']):
            return None
        path = ALLOWED/row['endpointFileName']
        guard, _, _ = api.open(path)
        need(_digest(api.read(path)) == row['endpointCipherSha256'], 'CIPHER_PIN')
        _, read_endpoint = _descriptor_functions()
        endpoint = read_endpoint(path)
        need((endpoint['guardian_pid'], endpoint['guardian_birth']) ==
             (row['ownerPid'], row['ownerBirth']), 'ENDPOINT_OWNER')
        current = _read_index(api)
        need(current is not None and current[1:] == (raw, identity)
             and time.monotonic() < row['validUntil'], 'CHANGED')
        metadata = _metadata(row, raw)
        result, endpoint = (metadata, endpoint), None
        return result
    except Exception:
        if type(endpoint) is dict:
            endpoint.clear()
    finally:
        if guard is not None:
            api.w.CloseHandle(guard)
    raise PublicationRefusal('LIVE_PUBLICATION_RESOLVE_REFUSED') from None


@dataclass(frozen=True, slots=True)
class PublicationLease:
    issuer: object = field(repr=False)
    operation: object = field(repr=False)
    row: dict = field(repr=False)
    raw: bytes = field(repr=False)
    identity: tuple = field(repr=False)
    endpoint_raw: bytes = field(repr=False)
    endpoint_identity: tuple = field(repr=False)


def _root(operation, *, closed=False):
    g = importlib.import_module('live_resident_guard_operation')
    need(_digest(Path(g.__file__).read_bytes()) == CONTROLLER_SHA
         and type(operation) is g.LiveResidentOperation and operation.issuer is g._ISSUER,
         'ROOT_ISSUER')
    if not closed:
        need(operation.phase == 'READY' and not operation.inflight, 'ROOT_READY')
        g._fresh_identity_gate(operation)
        operation.binding.validate()
        need(operation.binding.operation_id == operation.plan['operationId'], 'ROOT_BINDING')
    return g


def retained_lease(operation):
    """Root-only ownership recovery after publication readback failure."""
    lease = _LEASES.get(id(operation))
    need(lease is None or (type(lease) is PublicationLease and lease.issuer is _ISSUER
         and lease.operation is operation), 'LEASE')
    return lease


def publish_host(operation, endpoint):
    """Publish an already-issued READY owner; never install or replace an owner."""
    api = path = cipher = endpoint_identity = None
    committed = False
    try:
        _pins()
        _root(operation)
        _endpoint(endpoint)
        need(id(operation) not in _LEASES, 'ONCE')
        cfg = operation.plan['liveResidentConfiguration']
        need((endpoint['guardian_pid'], endpoint['guardian_birth']) ==
             (cfg['serverPid'], cfg['serverBirth']), 'ROOT_ENDPOINT')
        api = _Files()
        now = float(time.monotonic())
        until = float(operation.binding.valid_until)
        need(now < until <= now + 600, 'BINDING_EXPIRY')
        with api.publication_lock():
            need(_read_index(api) is None, 'EXISTING_OWNER')
            path = ALLOWED/('live-guardian-endpoint-'+operation.plan['operationId']+'.json')
            write_endpoint, _ = _descriptor_functions()
            write_endpoint(path, endpoint)
            cipher, endpoint_identity = api.read_public(path)
            row = dict(kind='LIVE_ACTIVE_GUARDIAN_PUBLICATION', version=1, profile=PROFILE,
                publicationId=uuid4().hex, operationId=operation.plan['operationId'],
                sourceDomain=DOMAIN, ownerPid=endpoint['guardian_pid'], ownerBirth=endpoint['guardian_birth'],
                publishedAt=now, validUntil=until, endpointFileName=path.name,
                endpointCipherSha256=_digest(cipher), readerSha256=SELF_SHA, codePins=_live_dependencies())
            _validate(row)
            raw = _canonical(row)
            pending = ALLOWED/('live-guardian-active-pending-'+uuid4().hex+'.json')
            identity = api.write_public_new(pending, raw)
            try:
                os.rename(pending, INDEX)
            except BaseException:
                api.remove_public_owned(pending, identity, raw)
                raise
            committed = True
            lease = PublicationLease(_ISSUER, operation, row, raw, identity, cipher, endpoint_identity)
            _LEASES[id(operation)] = lease
            _REMOVALS[id(operation)] = dict(lease=lease, indexRemoved=False, endpointRemoved=False)
            observed = _read_index(api)
            need(observed is not None and observed[1:] == (raw, identity), 'READBACK')
            return lease
    except Exception:
        pass
    if not committed and endpoint_identity is not None:
        try:
            api.remove_public_owned(path, endpoint_identity, cipher)
        except Exception:
            # Never delete a replaced file. Only encrypted technical metadata
            # may remain if even exact ownership cleanup cannot be proved.
            pass
    raise PublicationRefusal('LIVE_PUBLICATION_PUBLISH_REFUSED') from None


def unpublish_host(operation, lease):
    """Remove only our exact index and descriptor after proven native closure."""
    try:
        _pins()
        g = _root(operation, closed=True)
        need(type(lease) is PublicationLease and lease.issuer is _ISSUER
             and lease.operation is operation and _LEASES.get(id(operation)) is lease, 'LEASE')
        cleanup = _REMOVALS.get(id(operation))
        need(type(cleanup) is dict and cleanup.get('lease') is lease
             and type(cleanup.get('indexRemoved')) is bool
             and type(cleanup.get('endpointRemoved')) is bool, 'CLEANUP_PROOF')
        need(operation.phase == 'CLOSED' and operation.channel.closed is True
             and operation.host is not None and type(operation.host.returncode) is int
             and operation.host.returncode == 0 and not g._reservation(operation).exists(), 'ROOT_CLOSED')
        result = g.c.parse(g.c.read(Path(operation.plan['outputDirectory'])/'result.json', 8192))
        need(type(result) is dict and result.get('knownTerminal') is True
             and result.get('resourcesClosed') is True and result.get('operationId') == lease.row['operationId']
             and all(type(result.get(k)) is int and result[k] == 0
                     for k in ('sdkResult', 'workerResult', 'hostExitCode')), 'NATIVE_CLOSED')
        need(_canonical(lease.row) == lease.raw, 'LEASE_DRIFT')
        api = _Files()
        with api.publication_lock():
            current = _read_index(api)
            if cleanup['indexRemoved']:
                # Only this retained RAM receipt proves that an absent index
                # is our completed first step. A newer owner is never removed.
                need(current is None, 'SUCCESSOR_INDEX')
            else:
                need(current is not None and current[1:] == (lease.raw, lease.identity), 'OWN_INDEX')
            path = ALLOWED/lease.row['endpointFileName']
            if cleanup['endpointRemoved']:
                need(not path.exists(), 'SUCCESSOR_ENDPOINT')
            else:
                cipher, identity = api.read_public(path)
                need(cipher == lease.endpoint_raw and identity == lease.endpoint_identity, 'OWN_ENDPOINT')
            if not cleanup['indexRemoved']:
                api.remove_public_owned(INDEX, lease.identity, lease.raw)
                cleanup['indexRemoved'] = True
            if not cleanup['endpointRemoved']:
                api.remove_public_owned(path, lease.endpoint_identity, lease.endpoint_raw)
                cleanup['endpointRemoved'] = True
            need(not INDEX.exists() and not path.exists(), 'REMOVE_READBACK')
        del _LEASES[id(operation)]
        del _REMOVALS[id(operation)]
        return True
    except Exception:
        pass
    raise PublicationRefusal('LIVE_PUBLICATION_UNPUBLISH_REFUSED') from None
