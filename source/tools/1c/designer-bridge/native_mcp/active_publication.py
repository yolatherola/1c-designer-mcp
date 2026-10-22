"""Root-owned active guardian index. No native installer or source-file API.

The index contains public technical metadata only. The endpoint capability is
decrypted by the existing descriptor reader into RAM and never put in the index.
Only explicit open in the stable gateway selects an installation.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import ctypes
from ctypes import wintypes as W
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time
from uuid import uuid4

from . import guardian_descriptor as descriptor
from .windows_ram_pipe import _SA, _AclSize

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
ALLOWED = ROOT / 'artifacts/designer-bridge'
INDEX = ALLOWED / 'workday-guardian-active.json'
LOCK = ALLOWED / 'workday-guardian-active-lock.json'
ROOT_UUID = '218b5d00-7e10-486f-874c-73c2368ed5da'
PROFILE = 'AH1C_ACTIVE_SAVED_GUARDIAN_V1'
LIMIT = 8192
DESCRIPTOR_SHA = '244a2cecfbd7e12796807aa10ad3d13f9b87f11de74a82cc3ed30405aca3a0b3'
SELF_SHA = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
_ISSUER = object()
_LEASES = {}
_KEYS = frozenset(('kind version profile publicationId operationId rootUuid sourceDomain '
    'ownerPid ownerBirth nativePid nativeBirth publishedAt validUntil endpointFileName '
    'endpointCipherSha256 scopeSha256 planSha256 controllerSha256 hostSha256 lifecycleSha256 '
    'workerSha256 readerSha256 predecessorSha256').split())


class PublicationRefusal(ValueError):
    """Fixed local refusal; never reflects a path, body or capability."""


def need(ok, code):
    if not ok:
        raise PublicationRefusal('ACTIVE_PUBLICATION_' + code)


def _hex(value, size):
    return (type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None
            and value != '0' * size)


def _int(value, low=1, high=2**32-1):
    return type(value) is int and low <= value <= high


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _pins():
    need(_digest(Path(descriptor.__file__).read_bytes()) == DESCRIPTOR_SHA, 'DESCRIPTOR_PIN')
    descriptor._pins()
    need(_digest(Path(__file__).read_bytes()) == SELF_SHA, 'READER_PIN')


def validate_publication(row):
    """Validate bounded public metadata; it does not authorize an install."""
    need(type(row) is dict and row.keys() == _KEYS, 'SCHEMA')
    need(row['kind'] == 'WORKDAY_ACTIVE_GUARDIAN_PUBLICATION'
         and type(row['version']) is int and row['version'] == 1
         and row['profile'] == PROFILE and row['rootUuid'] == ROOT_UUID
         and row['sourceDomain'] == 'database_saved', 'PROFILE')
    need(all(_hex(row[k], 32) for k in ('publicationId', 'operationId'))
         and all(_hex(row[k], 16) for k in ('ownerBirth', 'nativeBirth'))
         and all(_int(row[k]) for k in ('ownerPid', 'nativePid')), 'IDENTITY')
    need(all(_hex(row[k], 64) for k in ('endpointCipherSha256', 'scopeSha256', 'planSha256',
         'controllerSha256', 'hostSha256', 'lifecycleSha256', 'workerSha256', 'readerSha256'))
         and row['readerSha256'] == SELF_SHA, 'PINS')
    need(row['predecessorSha256'] == '' or _hex(row['predecessorSha256'], 64), 'PREDECESSOR')
    need(_finite(row['publishedAt']) and _finite(row['validUntil'])
         and 0 <= row['publishedAt'] < row['validUntil'] <= row['publishedAt'] + 28800, 'EXPIRY')
    need(row['endpointFileName'] == 'workday-guardian-endpoint-'+row['operationId']+'.json',
         'ENDPOINT_PATH')
    need(len(_canonical(row)) <= LIMIT, 'BOUND')


def _json(raw):
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT, 'BOUND')
    row = json.loads(raw.decode('ascii'), object_pairs_hook=descriptor._pairs,
                     parse_constant=descriptor._constant)
    validate_publication(row)
    need(_canonical(row) == raw, 'CANONICAL')
    return row


class _Files(descriptor._Crypto):
    """Same-handle checks plus actor/System DACL and delete-on-close lock."""
    def __init__(self):
        super().__init__()
        self.actor = self.actor_sid()

    def _verify_file_acl(self, handle):
        security, acl = W.LPVOID(), W.LPVOID()
        # SE_FILE_OBJECT is1; the pipe helper uses SE_KERNEL_OBJECT instead.
        need(self.a.GetSecurityInfo(handle, 1, 4, None, None, ctypes.byref(acl), None,
                                    ctypes.byref(security)) == 0, 'ACL_READ')
        try:
            control, revision = W.WORD(), W.DWORD()
            need(self.a.GetSecurityDescriptorControl(security, ctypes.byref(control), ctypes.byref(revision))
                 and control.value & 0x1000 and acl.value, 'ACL_PROTECTED')
            info = _AclSize()
            need(self.a.GetAclInformation(acl, ctypes.byref(info), ctypes.sizeof(info), 2), 'ACL_INFO')
            expected, observed = {self.actor, 'S-1-5-18'}, set()
            need(info.ace_count == len(expected), 'ACL_COUNT')
            for index in range(info.ace_count):
                ace = W.LPVOID()
                need(self.a.GetAce(acl, index, ctypes.byref(ace)) and ace.value, 'ACL_ACE')
                need(ctypes.c_ubyte.from_address(ace.value).value == 0
                     and ctypes.c_ubyte.from_address(ace.value + 1).value == 0, 'ACL_RULE')
                need(W.DWORD.from_address(ace.value + 4).value & 0x1f01ff == 0x1f01ff, 'ACL_RIGHTS')
                observed.add(self.sid_string(ace.value + 8))
            need(observed == expected, 'ACL_IDENTITIES')
        finally:
            self.k.LocalFree(security)

    def _open_protected(self, path, *, new=False, delete_on_close=False, cleanup=False):
        descriptor._path(path, existing=not new)
        sd = W.LPVOID()
        if new:
            actors = sorted({self.actor, 'S-1-5-18'})
            need(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                'D:P'+''.join('(A;;FA;;;'+actor+')' for actor in actors),
                1, ctypes.byref(sd), None), 'DACL')
        try:
            sa = _SA(ctypes.sizeof(_SA), sd, False)
            access = (0x40000000 if new else 0x80000000) | (0x10000 if new or cleanup else 0)
            # Readers share deletion, allowing an atomic replacement while a
            # reader consumes its already-open immutable snapshot; never write.
            share = 0 if new else 5
            handle = self.k.CreateFileW(str(path), access, share,
                ctypes.byref(sa) if new else None, 1 if new else 3,
                0x200080 | (0x04000000 if delete_on_close else 0), None)
        finally:
            if sd: self.k.LocalFree(sd)
        need(handle not in (None, ctypes.c_void_p(-1).value), 'OPEN')
        try:
            info, final = descriptor._FileInfo(), ctypes.create_unicode_buffer(32768)
            need(self.k.GetFileInformationByHandle(handle, ctypes.byref(info)), 'FILE_INFO')
            need(not info.attributes & (0x400 | 0x10) and info.links == 1, 'FILE_KIND')
            n = self.k.GetFinalPathNameByHandleW(handle, final, len(final), 0)
            need(0 < n < len(final) and final.value.startswith('\\\\?\\')
                 and Path(final.value[4:]) == path, 'FINAL_PATH')
            size = (info.size_high << 32) | info.size_low
            need(size == 0 if new else 0 < size <= LIMIT, 'FILE_SIZE')
            self._verify_file_acl(handle)
            return handle, size, (info.volume, info.index_high, info.index_low)
        except BaseException:
            try:
                if new: self._delete(handle)
            finally:
                self.w.CloseHandle(handle)
            raise

    def read_public(self, path):
        handle, size, identity = self._open_protected(path)
        try:
            data, done = ctypes.create_string_buffer(size), W.DWORD()
            need(self.k.ReadFile(handle, data, size, ctypes.byref(done), None)
                 and done.value == size, 'READ')
            return data.raw, identity
        finally:
            self.w.CloseHandle(handle)

    def write_public_new(self, path, raw):
        need(type(raw) is bytes and 0 < len(raw) <= LIMIT, 'BOUND')
        handle, _, identity = self._open_protected(path, new=True)
        try:
            done = W.DWORD()
            need(self.k.WriteFile(handle, raw, len(raw), ctypes.byref(done), None)
                 and done.value == len(raw) and self.k.FlushFileBuffers(handle), 'WRITE')
            return identity
        except BaseException:
            self._delete(handle)
            raise
        finally:
            self.w.CloseHandle(handle)

    def remove_public_owned(self, path, identity, expected_raw):
        handle, size, current = self._open_protected(path, cleanup=True)
        try:
            data, done = ctypes.create_string_buffer(size), W.DWORD()
            need(current == identity and self.k.ReadFile(handle, data, size, ctypes.byref(done), None)
                 and done.value == size and data.raw == expected_raw, 'OWNERSHIP')
            self._delete(handle)
        finally:
            self.w.CloseHandle(handle)

    @contextmanager
    def publication_lock(self):
        handle, _, _ = self._open_protected(LOCK, new=True, delete_on_close=True)
        try:
            yield
        finally:
            self.w.CloseHandle(handle)

    def owner_current(self, pid, birth):
        ctypes.set_last_error(0)
        handle = self.k.OpenProcess(0x101000, False, pid)
        if not handle:
            need(ctypes.get_last_error() == 87, 'IDENTITY_UNPROVEN')
            return False
        try:
            wait = self.w.WaitForSingleObject(handle, 0)
            need(wait in (0, 258), 'IDENTITY_WAIT_UNPROVEN')
            return wait == 258 and self.birth(handle) == birth
        finally:
            self.w.CloseHandle(handle)


def _read_index(api):
    descriptor._path(INDEX, existing=False)
    if not INDEX.exists():
        return None
    raw, identity = api.read_public(INDEX)
    return _json(raw), raw, identity


def resolve_active():
    """Resolve a READY publication without a native call, install or file write.

    None means missing, expired or kernel-confirmed inactive owner. Malformed,
    inaccessible or changed metadata refuses. The returned endpoint capability
    is RAM-only; its caller must clear the transient dictionary after copying.
    """
    endpoint = None; guard = None; api = None
    try:
        _pins()
        descriptor._path(INDEX, existing=False)
        if not INDEX.exists(): return None
        api = _Files(); snapshot = _read_index(api)
        if snapshot is None: return None
        row, raw, _ = snapshot
        if time.monotonic() >= row['validUntil']:
            return None
        if not api.owner_current(row['ownerPid'], row['ownerBirth']):
            return None
        path = ALLOWED / row['endpointFileName']
        # Hold the descriptor's no-write/no-delete sharing handle across both
        # independent reads. Otherwise a same-owner capability substitution
        # between the hash and DPAPI read would evade the ciphertext binding.
        guard, _, _ = api.open(path)
        # Endpoint ciphertext is independently bound to the publication. The
        # descriptor reader then verifies DPAPI entropy, code and live identity.
        need(_digest(api.read(path)) == row['endpointCipherSha256'], 'CIPHER_PIN')
        endpoint = descriptor.read_endpoint(path)
        need(endpoint['guardian_pid'] == row['ownerPid']
             and endpoint['guardian_birth'] == row['ownerBirth'], 'ENDPOINT_IDENTITY')
        current = _read_index(api)
        need(current is not None and current[1] == raw
             and time.monotonic() < row['validUntil'], 'PUBLICATION_CHANGED')
        metadata = dict(publicationId=row['publicationId'], operationId=row['operationId'],
            publicationSha256=_digest(raw), validUntil=row['validUntil'],
            ownerPid=row['ownerPid'], ownerBirth=row['ownerBirth'])
        result, endpoint = (metadata, endpoint), None
        return result
    except Exception:
        if type(endpoint) is dict: endpoint.clear()
    finally:
        if guard is not None:
            api.w.CloseHandle(guard)
    raise PublicationRefusal('ACTIVE_PUBLICATION_RESOLVE_REFUSED') from None


@dataclass(frozen=True, slots=True)
class PublicationLease:
    issuer: object = field(repr=False)
    host: object = field(repr=False)
    row: dict = field(repr=False)
    raw: bytes = field(repr=False)
    identity: tuple


def retained_lease(host):
    """Root recovery only: retain a committed publication after readback failure."""
    lease = _LEASES.get(id(host))
    need(lease is None or (type(lease) is PublicationLease and lease.issuer is _ISSUER
         and lease.host is host), 'LEASE')
    return lease


def _host_ready(host):
    # This import belongs only to the root publisher, never the frontend path.
    from workday_guardian_host import WorkdayGuardianHost, root
    need(type(host) is WorkdayGuardianHost and host.started is True and host.closed is False
         and host.operation.phase == 'READY' and host.service.state == 'RUNNING'
         and host.root_result is None, 'ROOT_READY')
    root._fresh_identity_gate(host.operation)
    return root


def _verify_predecessor(row, root, scope):
    """A caller's expected hash never substitutes for native closure proof."""
    op = row['operationId']
    plan = root.reader._json(ROOT/'build'/('designer-hot-v234-'+op)/'plan.json')
    need(_digest(root.c.canonical(plan)) == row['planSha256']
         and scope['approvedPriorWorkdayPlans'].get(op) == row['planSha256'], 'PREDECESSOR_PLAN')
    import workday_guardian_closure_audit as audit
    need(_digest(Path(audit.__file__).read_bytes()) == root.CLOSURE_AUDIT_SHA, 'AUDITOR_PIN')
    revision = dict(controller=row['controllerSha256'], host=row['hostSha256'],
                    runtime=row['lifecycleSha256'], worker=row['workerSha256'])
    proof = audit.audit_closed(plan, approved_revision=revision)
    need(proof.get('resourcesClosed') is True, 'PREDECESSOR_CLOSURE')
    root.admission._prior_owner_gone(plan, proof)


def publish_host(host, *, expected_sha256=None):
    """Publish only an exact ready root host, with serialized compare-and-swap.

    No installer is called. A present predecessor requires the caller's exact
    expected hash, its approved plan, full closure and fresh owner exit. Returns
    an opaque lease needed for removal; no MCP tool accepts this lease or host.
    """
    _pins(); root = _host_ready(host)
    need(id(host) not in _LEASES, 'ONE_PUBLICATION')
    need(expected_sha256 is None or _hex(expected_sha256, 64), 'EXPECTED_HASH')
    p, scope = host.operation.plan, host.operation.scope
    op = p['operationId']; cfg = p['residentConfiguration']
    need(host.endpoint_path == ALLOWED/('workday-guardian-endpoint-'+op+'.json'), 'ROOT_ENDPOINT')
    api = _Files(); temporary = None; temporary_identity = None; temporary_raw = None
    try:
        with api.publication_lock():
            current = _read_index(api)
            need((current is None and expected_sha256 is None)
                 or (current is not None and expected_sha256 == _digest(current[1])), 'CAS')
            if current is not None:
                need(current[0]['operationId'] != op, 'PREDECESSOR_SELF')
                _verify_predecessor(current[0], root, scope)
            cipher = api.read(host.endpoint_path)
            row = dict(kind='WORKDAY_ACTIVE_GUARDIAN_PUBLICATION', version=1, profile=PROFILE,
                publicationId=uuid4().hex, operationId=op, rootUuid=ROOT_UUID, sourceDomain='database_saved',
                ownerPid=cfg['serverPid'], ownerBirth=cfg['serverBirth'],
                nativePid=p['context']['processId'], nativeBirth=p['context']['birth'],
                publishedAt=time.monotonic(), validUntil=cfg['sessionValidUntil'],
                endpointFileName=host.endpoint_path.name, endpointCipherSha256=_digest(cipher),
                scopeSha256=host.operation.scope_sha256, planSha256=_digest(host.operation.plan_raw),
                controllerSha256=p['workdayControllerSha256'], hostSha256=scope['workdayGuardianHostSha256'],
                lifecycleSha256=scope['workdayLifecycleSha256'], workerSha256=scope['workdayGuardianWorkerSha256'],
                readerSha256=SELF_SHA, predecessorSha256='' if current is None else _digest(current[1]))
            validate_publication(row)
            need(api.owner_current(row['ownerPid'], row['ownerBirth']), 'ROOT_OWNER')
            raw = _canonical(row)
            temporary = ALLOWED/('workday-guardian-active-pending-'+uuid4().hex+'.json')
            temporary_raw = raw; temporary_identity = api.write_public_new(temporary, raw)
            if current is None: os.rename(temporary, INDEX)
            else: os.replace(temporary, INDEX)
            temporary = None
            # The atomic commit is already real. Publish ownership BEFORE the
            # fallible readback, so known closure can still remove this exact
            # index after a local observation error, without a second publish.
            lease = PublicationLease(_ISSUER, host, row, raw, temporary_identity)
            _LEASES[id(host)] = lease
            observed = _read_index(api)
            need(observed is not None and observed[1] == raw
                 and observed[2] == temporary_identity, 'PUBLISH_READBACK')
            return lease
    finally:
        if temporary is not None and temporary_identity is not None:
            api.remove_public_owned(temporary, temporary_identity, temporary_raw)


def unpublish_host(host, lease):
    """Remove only our matching publication after proven native closure.

    No source, process, descriptor or foreign publication is removed. A changed
    publication is retained and refused, even when the old host is closed.
    """
    need(type(lease) is PublicationLease and lease.issuer is _ISSUER
         and lease.host is host and _LEASES.get(id(host)) is lease, 'LEASE')
    result = host.root_result
    need(host.operation.phase == 'CLOSED' and type(result) is dict
         and result.get('knownTerminal') is True and type(result.get('sdkResult')) is int
         and result['sdkResult'] == 0 and host.operation.channel.closed
         and host.finalizer_calls == 1 and type(host.operation.host.returncode) is int
         and host.operation.host.returncode == 0, 'ROOT_CLOSED')
    need(_canonical(lease.row) == lease.raw, 'LEASE_DRIFT')
    api = _Files()
    with api.publication_lock():
        current = _read_index(api)
        if current is not None:
            need(current[1] == lease.raw and current[2] == lease.identity, 'OWN_PUBLICATION')
            api.remove_public_owned(INDEX, lease.identity, lease.raw)
        need(not INDEX.exists(), 'REMOVE_READBACK')
    del _LEASES[id(host)]
    return True
