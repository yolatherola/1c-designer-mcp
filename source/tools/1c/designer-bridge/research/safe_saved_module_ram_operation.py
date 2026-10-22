"""Two bounded saved-DB reads into authenticated RAM, never configuration files.

No API accepts application source, a command, or a connection. The first live
acceptance has two compile-fixed targets/requests; it is not a permanent MCP.
The prior UNKNOWN is retained. Its exact read closure is recognized privately,
with a fresh original-process check and the existing owned route lease.
"""
from dataclasses import dataclass, asdict
from pathlib import Path
from types import FunctionType, SimpleNamespace
import hashlib
import ctypes
import importlib
import inspect
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import uuid

import database_startup_metadata_operation as prior
import startup_metadata_refusal_audit as closed_metadata
import sdk_compiler_section_identity as section_identity

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(HERE.parent))
from native_mcp.saved_source import SourceBinding, Target, ReadRequest, validate_snapshot
from native_mcp.windows_ram_pipe import _Api
from native_mcp.ram_wire import parse_frame

c, reader, base = prior.c, prior.reader, prior.base
SOURCE_NAME = 'NativeSafeSavedModuleRam.as'
SOURCE_SHA = 'df1711a1f39c84c38f87e844eb6c218e80ef638d6f55a3bb45aee23db0f36319'
CARRIER_SHA = 'c75ca413a26e5cccb6f4ff68f9a3d4e88ae5b9b960560e408afa0b606cdf1301'
PRIOR_SHA = '8d10da05e34553e77e11e090e473823d820417711be46f02acdfb53b317acd5f'
AUDIT_SHA = '5dfc07b84a6295431ef1d43da844cf44bd47990ae6fa77d5e005a127b87a05f2'
PROFILE = 'TWO_DATABASE_SAVED_MODULES_RAM_ONLY'
MAIN_SHA = prior.MAIN_SHA
TARGETS = prior.COMMON_MODULES
PROPERTY = 'd5963243-262e-4398-b4d7-fb16d06484f6'
TRUE_AUTH = prior.TRUE_AUTH + ('runtimeDatabaseResourcesReadAuthorized', 'sourceBodyReadsAuthorized',
                              'nativeOwnedRamOutputAuthorized', 'scopedRamPipeTransferAuthorized')
FALSE_AUTH = tuple(k for k in prior.FALSE_AUTH if k not in TRUE_AUTH)
_ISSUER = object()


def need(ok, code):
    if not ok:
        raise ValueError('SAFE_SAVED_RAM_' + code)


def limits():
    return dict(maximumNativeCommands=0, maximumTypeEvents=32, maximumEnumerations=0,
                maximumRequests=2, maximumBodyBytes=4194304, maximumCodePoints=1048576,
                maximumPlainResourceBytes=8388608, maximumFileOpensPerRequest=2,
                maximumStorageEntryOpensPerRequest=4)


def authority(row):
    return (all(row.get(k) is True for k in TRUE_AUTH) and all(row.get(k) is False for k in FALSE_AUTH)
            and all(type(row.get(k)) is int and row[k] == value for k, value in limits().items())
            and type(row.get('expectedDatabaseSource')) is int and row['expectedDatabaseSource'] == 1383504556)


def validate_scope(row):
    need(type(row) is dict and row.get('kind') == 'ROOT_SAFE_SAVED_RAM_SCOPE' and row.get('passed') is True
         and row.get('profile') == PROFILE and row.get('actualSourceSha256') == SOURCE_SHA
         and authority(row), 'SCOPE')


def _source():
    raw = c.read(HERE / SOURCE_NAME, 32768)
    need(c.digest(raw) == SOURCE_SHA, 'SOURCE_PIN')
    token = b'__SAFE_SAVED_MODULE_RAM_SCOPE_ADMITTED__'
    need(raw.count(token) == 1 and set(re.findall(rb'__[A-Z0-9_]+__', raw)) == {token}, 'SOURCE_TOKENS')
    return raw.replace(token, b'true')


def _carrier():
    need(type(CARRIER_SHA) is str and re.fullmatch('[a-f0-9]{64}', CARRIER_SHA), 'CARRIER_NOT_FROZEN')
    path = HERE / 'native_ram_carrier.py'
    need(c.digest(c.read(path)) == CARRIER_SHA, 'CARRIER_PIN')
    return importlib.import_module('native_ram_carrier')


def _pins():
    need(c.digest(c.read(Path(prior.__file__))) == PRIOR_SHA, 'PARENT_PIN')
    need(c.digest(c.read(Path(closed_metadata.__file__))) == AUDIT_SHA, 'CLOSED_AUDIT_PIN')
    prior._pins()
    _source()
    _carrier()
    for name, pin in {
        'saved_source.py': '6aae709b2eb6e112ebc049f4776811325877166fc5fc35f87369b224571facdc',
        'ram_wire.py': '4aa2e5c4555850633f1a2af7a0a1944b03e1c01d780f3b150e31a7b725d1776a',
        'windows_ram_pipe.py': '54dd9a45064f34930a2dc6441c3c78cdaaeefbdf02138fcb2459830f1c57ec1e',
        'windows_ready_ram_pipe.py': '1821d8603d72bab9dd836ff7ae4ee43ef78ea5dc19fd87eef7e8faf594325119',
    }.items():
        need(c.digest(c.read(HERE.parent / 'native_mcp' / name)) == pin, 'RAM_DEPENDENCY_PIN')


def _private_factory(factory, **overrides):
    """Rehome this factory's own helpers together, preserving imported globals.

    The historical audit_partial shares the factory's validate_scope binding.
    Cloning only the entry point would leave that audit in the old scope and
    reject a new profile. Imported functions and the old namespace stay intact.
    """
    original = factory.__globals__
    private = dict(original, **overrides)
    for name, value in original.items():
        if isinstance(value, FunctionType) and value.__globals__ is original:
            private[name] = FunctionType(value.__code__, private, value.__name__, value.__defaults__, value.__closure__)
            private[name].__kwdefaults__ = value.__kwdefaults__
    return FunctionType(factory.__code__, private, factory.__name__, factory.__defaults__, factory.__closure__)


def prepare_parent(path, pin):
    """Compose one new audit in private globals; never patch loaded modules."""
    factory = prior.maintenance.private_prepare()
    original_reader = factory.__globals__['reader']
    original_inspect = factory.__globals__['inspect']
    def audit(plan):
        result = closed_metadata.audit_closed(plan)
        base._lease(SimpleNamespace(plan=plan))
        c._fresh(base._carrier_view(plan))
        return result
    def namespace(parent):
        ns = original_reader._namespace(parent)
        ns.update(__closed_metadata_operation=closed_metadata.OP, __closed_metadata_audit=audit)
        return ns
    def getsource(target):
        text = original_inspect.getsource(target)
        if target is c._no_pending:
            anchor = '        if prior_identity!=identity: continue\n'
            need(text.count(anchor) == 1, 'CLOSED_AUDIT_ANCHOR')
            text = text.replace(anchor, anchor +
                '        if operation==__closed_metadata_operation:\n            __closed_metadata_audit(prior);continue\n', 1)
        return text
    reader_proxy = SimpleNamespace(**dict(original_reader.__dict__))
    reader_proxy._namespace = namespace
    inspect_proxy = SimpleNamespace(**dict(original_inspect.__dict__))
    inspect_proxy.getsource = getsource
    local = _private_factory(factory, reader=reader_proxy, inspect=inspect_proxy)
    maintenance_proxy = SimpleNamespace(**dict(prior.maintenance.__dict__))
    maintenance_proxy.private_prepare = lambda: local
    parent_fn = FunctionType(prior.prepare_parent.__code__,
        dict(prior.prepare_parent.__globals__, maintenance=maintenance_proxy, validate_scope=validate_scope),
        prior.prepare_parent.__name__, prior.prepare_parent.__defaults__, prior.prepare_parent.__closure__)
    return parent_fn(path, pin)


class PipeOwner:
    """One inbox owner thread; bodies never leave RAM or enter diagnostics."""
    def __init__(self, request):
        self.request = request
        self.ready, self.start, self.abort, self.done = (threading.Event() for _ in range(4))
        self.path = None
        self.packet = None
        self.frame_bytes = 0
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        need(self.ready.wait(5) and self.path is not None and self.error is None, 'INBOX_START')
    def _run(self):
        try:
            from native_mcp.windows_ready_ram_pipe import NativeReadyRamInbox
            with NativeReadyRamInbox(48936, request_id=self.request.request_id,
                                    expected_birth='01dd5d0180299126', timeout=30) as inbox:
                self.path = inbox.path
                self.ready.set()
                self.start.wait()
                if not self.abort.is_set():
                    frame = inbox.receive_frame()
                    try:
                        self.frame_bytes = len(frame)
                        self.packet = parse_frame(frame, self.request, time.monotonic())
                    finally:
                        frame = None
        except Exception:
            self.error = 'RAM_INBOX_REFUSED'  # No exception text, packet, or source.
        finally:
            self.ready.set()
            self.done.set()
    def close_before_dispatch(self):
        self.abort.set()
        self.start.set()
        self.thread.join(5)
        need(not self.thread.is_alive(), 'INBOX_CLOSE')


@dataclass(slots=True)
class ReadSession:
    issuer: object
    parent: object
    scope_path: Path
    scope_sha256: str
    scope: dict
    plan: dict
    plan_raw: bytes
    private: dict
    endpoints: tuple
    phase: str = 'PREPARED'
    next_job: int = 0
    host: object = None


def _claim_path(s):
    return ROOT / 'artifacts/designer-bridge' / ('safe-saved-ram-claim-' + s.scope_sha256 + '.json')


def _claim(s):
    owner = reader._check_owner(s.parent)
    return dict(kind='SAFE_SAVED_RAM_CLAIM', operationId=s.plan['operationId'], scopeSha256=s.scope_sha256,
                controllerSha256=s.plan['updatePreviewControllerSha256'], actualSourceSha256=SOURCE_SHA,
                writerOperationId=owner['operationId'], packetSha256=owner['packetSha256'],
                sessionNonce=s.plan['context']['heldNonce'], pid=48936, birth='01dd5d0180299126')


def _check(s):
    need(type(s) is ReadSession and s.issuer is _ISSUER, 'ISSUED')
    _pins()
    p = s.plan
    need(c.canonical(p) == s.plan_raw and p['updatePreviewControllerSha256'] == c.digest(c.read(Path(__file__)))
         and p['updatePreviewProfile'] == PROFILE and p['actualSourceSha256'] == SOURCE_SHA
         and p['nativeRamCarrierSha256'] == CARRIER_SHA and p['context'] == s.parent.plan['context']
         and authority(p) and p['writerAuthorized'] is False and p['captureAuthorized'] is False
         and type(p['applicationWrites']) is int and p['applicationWrites'] == 0, 'PLAN')
    scope = reader._json(s.scope_path, s.scope_sha256)
    validate_scope(scope)
    need(scope == s.scope and scope['targets'] == reader._check_owner(s.parent)['targets']
         and scope['readScopeSha256'] == s.parent.review_sha256
         and Path(scope['readScopePath']).resolve() == s.parent.review_path.resolve()
         and (scope['sessionNonce'], scope['pid'], scope['birth'], scope['guiThreadId'], scope['mainSha256']) ==
             ('013dc010bd784e859b1e3ba4def25f3c', 48936, '01dd5d0180299126', 8292, MAIN_SHA), 'SCOPE_JOIN')
    base._lease(SimpleNamespace(plan=p))
    if s.phase in ('PREPARED', 'STAGED'):
        need(not _claim_path(s).exists(), 'ALREADY_CLAIMED')
    else:
        need(reader._json(_claim_path(s)) == _claim(s), 'CLAIM')


def prepare_root(path, pin):
    _pins()
    scope_path = c._plain(path, ROOT / 'artifacts/designer-bridge')
    scope = reader._json(scope_path, pin)
    validate_scope(scope)
    parent = prepare_parent(scope_path, pin)
    p = dict(parent.plan)
    op = uuid.uuid4().hex
    out = ROOT / 'build' / ('designer-hot-v233-' + op)
    for key in ('pendingReadProfile', 'actualReadSourceSha256', 'pendingReadControllerSha256', 'pendingScopeSha256'):
        p.pop(key, None)
    p.update(operationId=op, outputDirectory=str(out), updatePreviewProfile=PROFILE,
             updatePreviewControllerSha256=c.digest(c.read(Path(__file__))), actualSourceSha256=SOURCE_SHA,
             nativeRamCarrierSha256=CARRIER_SHA, updatePreviewScopeSha256=pin,
             readScopeSha256=parent.review_sha256, writerAuthorized=False, captureAuthorized=False,
             applicationWrites=0, expectedDatabaseSource=1383504556, **limits(),
             **{k: True for k in TRUE_AUTH}, **{k: False for k in FALSE_AUTH})
    p['goldLeaseOwner'], p['goldLeaseBootstrapSha256'] = base.owner_base._lease_binding(p['context'])
    check_clock()
    # C emits time fields at nine decimal places. Six-decimal request times
    # preserve exact float joins after JSON decoding without extending TTL.
    now = round(time.monotonic(), 6)
    binding = SourceBinding('218b5d00-7e10-486f-874c-73c2368ed5da', p['context']['heldNonce'],
                            48936, '01dd5d0180299126', 1, 'database_saved', now + 60)
    endpoints, slots = [], []
    api = _Api()
    server_birth = api.birth(api.k.GetCurrentProcess())
    try:
        for index, target_id in enumerate(TARGETS):
            request = ReadRequest(binding, Target(target_id, PROPERTY), uuid.uuid4().hex,
                                  index + 1, now, now + 60)
            endpoint = PipeOwner(request)
            endpoints.append(endpoint)
            slots.append(dict(operationId=op, scopeSha256=pin, requestId=request.request_id,
                revision=request.revision, issuedAt=now, validUntil=now+60,
                binding=asdict(binding), target=asdict(request.target), pipePath=endpoint.path,
                serverPid=os.getpid(), serverBirth=server_birth,
                epochPath=(out / f'slot{index}-epoch.json').as_posix(),
                resultPath=(out / f'slot{index}-sdk-result.bin').as_posix(),
                armPath=(out / f'slot{index}-arm.bin').as_posix(),
                callbackPath=(out / f'slot{index}-callback.bin').as_posix(),
                proofPath=(out / f'slot{index}-native.json').as_posix()))
        p['nativeRamSlots'] = slots
        s = ReadSession(_ISSUER, parent, scope_path, pin, scope, p, c.canonical(p), {}, tuple(endpoints))
        _check(s)
        ns = parent.private
        ns['__pending_read_operation'] = op
        def fresh(plan):
            _check(s)
            need(plan == s.plan, 'FRESH_PLAN')
            c._fresh(base._carrier_view(plan))
        def render(plan, raw):
            need(plan == s.plan, 'RENDER_PLAN')
            return _render(s)
        ns.update(_fresh=fresh, render=render)
        s.private = ns
        ns['_no_pending'](context=p['context'])
        return s
    except BaseException:
        for endpoint in endpoints:
            endpoint.close_before_dispatch()
        raise


def _render(s):
    _check(s)
    p, out = s.plan, Path(s.plan['outputDirectory'])
    files = c.render(base._carrier_view(p), c.read(HERE / c._probe_spec(reader.PROBE)[0], 32768))
    header = files['sdk_probe_params.h'].decode()
    values = {}
    for name in ('ENGINE_ADDRESS', 'MODULE_ADDRESS'):
        match = re.search(r'^#define AH_SDK_' + name + r' (0x[0-9a-fA-F]+)U$', header, re.M)
        need(match is not None, 'SDK_ADDRESS')
        values[name] = int(match[1], 16)
    need(values == dict(ENGINE_ADDRESS=0x34554a0, MODULE_ADDRESS=0x34fc380), 'SDK_ADDRESS_PIN')
    identity = dict(processId=48936, birth='01dd5d0180299126', guiThreadId=8292,
                    engineAddress=values['ENGINE_ADDRESS'], moduleAddress=values['MODULE_ADDRESS'])
    source = _source()
    source_line = next(line for line in header.splitlines() if line.startswith('#define AH_SDK_FIXED_SOURCE '))
    files['sdk_probe_params.h'] = c._replace_once(header, source_line,
        '#define AH_SDK_FIXED_SOURCE ' + json.dumps(source.decode(), ensure_ascii=False)).encode()
    files['Continuation.c'] = _carrier().render(source, slots=tuple(p['nativeRamSlots']), identity=identity)
    # The frozen generic section helper names the original SDK anchor. Adapt
    # only this new derivative's one literal; all emitted executable code and
    # source bytes stay covered by the operation's ordinary build fingerprints.
    new_anchor = b'args[0]=(uint32_t)"AH1C_FIXED_RAM_READER_V1";'
    need(files['Continuation.c'].count(new_anchor) == 1, 'RAM_SECTION_ANCHOR')
    files['Continuation.c'] = files['Continuation.c'].replace(new_anchor, section_identity.ANCHOR, 1)
    original_attach = files['OwnedSdkReadonlyAttach.cs'].decode('utf-8-sig')
    original_ps = files['run-fixed.ps1'].decode('utf-8-sig')
    for index in range(2):
        attach_name = 'OwnedSdkReadonlyAttach.cs' if index == 0 else 'OwnedSdkReadonlyAttachSlot1.cs'
        ps_name = 'run-fixed.ps1' if index == 0 else 'run-slot1.ps1'
        attach = c._replace_once(original_attach, '"arm-result.bin"', f'"slot{index}-arm.bin"')
        ps = original_ps.replace(str(out / 'OwnedSdkReadonlyAttach.cs'), str(out / attach_name))
        ps = ps.replace(str(out / 'sdk-result.bin'), str(out / f'slot{index}-sdk-result.bin'))
        ps = ps.replace(str(out / 'host-result.json'), str(out / f'slot{index}-host-result.json'))
        need(f'slot{index}-sdk-result.bin' in ps and f'slot{index}-host-result.json' in ps, 'HOST_PATHS')
        auth = 'version=233;writerAuthorized=$false;safeSavedRamProfile=' + json.dumps(PROFILE) + ';'
        auth += 'nativeRamJob=' + str(index) + ';'
        need(ps.count('version=233;') == 2, 'HOST_AUTHORITY_ANCHOR')
        ps = ps.replace('version=233;', auth)
        files[attach_name] = attach.encode('utf-8-sig')
        files[ps_name] = ps.encode('utf-8-sig')
    files, _ = section_identity.with_section_identity(files, operation_kind='SAFE_SAVED_MODULE_RAM',
                                                     operation_id=p['operationId'])
    return files


def _stage_root(s):
    _check(s)
    need(s.phase == 'PREPARED', 'STAGE_PHASE')
    files = _render(s)
    s.private['FILES'] = tuple(files)
    proof = s.private['stage_private'](s.plan, dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',
        rootAuthorized=True, planSha256=c.digest(s.plan_raw)))
    out = Path(s.plan['outputDirectory'])
    compiler, pin = c._carrier_compiler()
    extra = out / 'OwnedCarrierSlot1Preflight.dll'
    result = subprocess.run([str(compiler), '/nologo', '/target:library', '/platform:x86',
        '/out:' + str(extra), str(out / 'OwnedSdkDiagnosisHook.cs'), str(out / 'OwnedSdkReadonlyAttachSlot1.cs')],
        cwd=out, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    need(result.returncode == 0 and extra.is_file() and c._carrier_compiler() == (compiler, pin), 'SECOND_PREFLIGHT')
    c.write_new(out / 'second-carrier-build-proof.json', dict(kind='SAFE_SAVED_RAM_SECOND_PREFLIGHT',
        passed=True, compileExitCode=0, assemblyExecuted=False, compilerSha256=pin,
        assemblySha256=c.digest(c.read(extra)), planSha256=c.digest(s.plan_raw),
        sourceSha256={name: c.digest(c.read(out / name)) for name in
            ('OwnedSdkDiagnosisHook.cs', 'OwnedSdkReadonlyAttachSlot1.cs')}))
    s.phase = 'STAGED'
    return proof


def abort_unstarted(s):
    """Close only never-dispatched inboxes, on their own owner threads."""
    need(type(s) is ReadSession and s.issuer is _ISSUER, 'ABORT_SCOPE')
    for endpoint in s.endpoints:
        if not endpoint.start.is_set():
            endpoint.close_before_dispatch()


def stage_root(s):
    try:
        return _stage_root(s)
    except BaseException:
        abort_unstarted(s)
        raise


def _require_stage(s):
    _check(s)
    proof = s.private['require_stage'](s.plan)
    out = Path(s.plan['outputDirectory'])
    extra = reader._json(out / 'second-carrier-build-proof.json')
    need(extra.get('kind') == 'SAFE_SAVED_RAM_SECOND_PREFLIGHT' and extra.get('passed') is True
         and type(extra.get('compileExitCode')) is int and extra['compileExitCode'] == 0
         and extra.get('assemblyExecuted') is False and extra.get('planSha256') == c.digest(s.plan_raw)
         and extra.get('compilerSha256') == c._carrier_compiler()[1]
         and extra.get('assemblySha256') == c.digest(c.read(out / 'OwnedCarrierSlot1Preflight.dll'))
         and extra.get('sourceSha256') == {name: c.digest(c.read(out / name)) for name in
            ('OwnedSdkDiagnosisHook.cs', 'OwnedSdkReadonlyAttachSlot1.cs')}, 'SECOND_STAGE_PINS')
    return proof, extra


def require_stage(s):
    try:
        return _require_stage(s)
    except BaseException:
        abort_unstarted(s)
        raise


def check_clock():
    """Prove this Python clock shares the native worker's Windows QPC base."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    qpc, frequency = ctypes.c_longlong(), ctypes.c_longlong()
    before = time.monotonic()
    need(kernel.QueryPerformanceCounter(ctypes.byref(qpc))
         and kernel.QueryPerformanceFrequency(ctypes.byref(frequency)) and frequency.value > 0, 'CLOCK_QPC')
    after = time.monotonic()
    need(time.get_clock_info('monotonic').implementation == 'QueryPerformanceCounter()'
         and before - .001 <= qpc.value / frequency.value <= after + .001, 'CLOCK_BASE')


def validate_native(row, slot, job, packet, request, now, frame_bytes):
    """Match technical closure to the exact RAM packet. Never return source text."""
    need(type(row) is dict and row.get('kind') == 'NATIVE_RAM_CARRIER'
         and row.get('operationId') == slot['operationId'] and row.get('scopeSha256') == slot['scopeSha256']
         and row.get('requestId') == slot['requestId'], 'NATIVE_JOIN')
    expected = dict(job=job, processId=48936, guiThreadId=8292, sdkRc=0, terminalRc=0,
                    compileCount=1, contextCount=job+1, nativeStatus=1, nativeReason=0,
                    pendingReference=0, typedCleared=1, nativeException=0,
                    passes=2, propertyReads=2, fileOpens=2, adoptedFiles=2,
                    beforeClean=1, afterClean=1, prefixPreserved=1,
                    databaseRoot=1383504556, databaseManager=100051712)
    need(all(type(row.get(k)) is int and row[k] == value for k, value in expected.items()), 'NATIVE_COUNTS')
    need(all(row.get(k) is True for k in ('contextCleared', 'handlerRemoved', 'epochClean', 'hookRemoved', 'nativeEnvelopeValid',
        'peerVerified', 'readyVerified', 'pipeClosed', 'drainCompleted', 'buffersFreed'))
        and row.get('functionRetained') is (job == 0), 'NATIVE_CLOSURE')
    need(type(row.get('workerThreadId')) is int and row['workerThreadId'] > 0
         and row['workerThreadId'] != 8292, 'WORKER_THREAD')
    points = len(validate_snapshot(packet, request, now))
    r = packet.receipt
    need(type(row.get('bodyBytes')) is int and row['bodyBytes'] == r.byte_count
         and row.get('sourceSha256') == r.source_sha256 and row.get('savedResourceSha256') == r.saved_resource_sha256
         and type(row.get('codePoints')) is int and row['codePoints'] == points
         and type(row.get('crlfCount')) is int and row['crlfCount'] == r.crlf_count
         and type(row.get('bomPresent')) is int and row['bomPresent'] == int(r.bom_present)
         and type(row.get('endsLf')) is int and row['endsLf'] == int(r.ends_lf)
         and type(row.get('sampledAt')) in (int, float) and row['sampledAt'] == r.sampled_at
         and type(row.get('storedBytes')) is int and 0 < row['storedBytes'] <= 8388608
         and type(row.get('frameBytesWritten')) is int and row['frameBytesWritten'] == frame_bytes
         and r.byte_count + 16 < frame_bytes <= r.byte_count + 16 + 16384, 'PACKET_JOIN')
    return 'NATIVE_DATABASE_SAVED_MODULE_RAM_VERIFIED'


def _unknown(s, reason):
    abort_unstarted(s)
    row = dict(kind='SAFE_SAVED_RAM_UNKNOWN', version=233, operationId=s.plan['operationId'],
        status='UNKNOWN_RETAIN', knownTerminal=False, reason=reason, retryAuthorized=False,
        nativeSourceBindingVerified=False, applicationWrites=0, configurationExports=0,
        configurationImports=0, configurationSaves=0, databaseUpdates=0, repositoryMutations=0)
    path = Path(s.plan['outputDirectory']) / 'unknown.json'
    if not path.exists():
        c.write_new(path, row)
    s.phase = 'UNKNOWN_RETAIN'
    return row


def _run_slot_once(s, review_path, review_pin):
    """Run exactly the next sealed request; retain every uncertain live handle."""
    _check(s)
    need(s.phase in ('STAGED', 'FIRST_VERIFIED') and s.next_job in (0, 1), 'RUN_PHASE')
    job, p = s.next_job, s.plan
    out, slot = Path(p['outputDirectory']), p['nativeRamSlots'][job]
    build, second = require_stage(s)
    review = reader._json(c._plain(review_path, ROOT / 'artifacts/designer-bridge'), review_pin)
    need(review.get('kind') == 'ROOT_SAFE_SAVED_RAM_RUN' and review.get('passed') is True
         and authority(review) and review.get('planSha256') == c.digest(s.plan_raw)
         and review.get('buildSha256') == c.digest(c.canonical(build))
         and review.get('secondBuildSha256') == c.digest(c.canonical(second))
         and review.get('scopeSha256') == s.scope_sha256 and review.get('actualSourceSha256') == SOURCE_SHA
         and review.get('nativeRamCarrierSha256') == CARRIER_SHA, 'ROOT_RUN')
    s.private['_no_pending'](context=p['context'])
    need(time.monotonic() + 1 < slot['validUntil'], 'REQUEST_EXPIRED_BEFORE_DISPATCH')
    need(not any((out / f'slot{job}-{name}').exists() for name in
        ('intent.json', 'host-result.json', 'sdk-result.bin', 'arm.bin', 'callback.bin', 'native.json', 'epoch.json', 'result.json')),
        'ONE_ATTEMPT')
    if job == 0:
        c.write_new(_claim_path(s), _claim(s))
        c.write_new(out / 'intent.json', dict(kind='SAFE_SAVED_RAM_INTENT', operationId=p['operationId'],
            scopeSha256=s.scope_sha256, planSha256=c.digest(s.plan_raw), rootRunSha256=review_pin,
            applicationWrites=0, configurationExports=0, configurationImports=0, repositoryMutations=0))
    s.phase = 'DISPATCHED_RETAIN'
    c.write_new(out / f'slot{job}-intent.json', dict(kind='SAFE_SAVED_RAM_JOB_INTENT',
        operationId=p['operationId'], requestId=slot['requestId'], job=job, rootRunSha256=review_pin,
        planSha256=c.digest(s.plan_raw)))
    s.private['_fresh'](p)
    endpoint = s.endpoints[job]
    endpoint.start.set()
    script = out / ('run-fixed.ps1' if job == 0 else 'run-slot1.ps1')
    s.host = subprocess.Popen([str(reader.writer.PS), '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(script)],
        cwd=out, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    c.write_new(out / f'slot{job}-host-identity.json', reader.writer._host_identity(s.host))
    deadline = time.monotonic() + 55
    while time.monotonic() < deadline:
        host_path = out / f'slot{job}-host-result.json'
        if host_path.is_file():
            try:
                host = reader._json(host_path, bound=8192)
            except (ValueError, OSError):
                time.sleep(.05)
                continue
            if host.get('knownTerminal') is not True or host.get('hookWorkersReleased') is not True:
                break
            try:
                s.host.wait(timeout=5)
                need(s.host.returncode == 0 and type(host.get('sdkResult')) is int and host['sdkResult'] == 0
                     and type(host.get('threadId')) is int and host['threadId'] == 8292
                     and type(host.get('nativeRamJob')) is int and host['nativeRamJob'] == job
                     and host.get('safeSavedRamProfile') == PROFILE, 'HOST_TERMINAL')
                need(endpoint.done.wait(5) and endpoint.error is None and endpoint.packet is not None
                     and not endpoint.thread.is_alive(), 'RAM_TERMINAL')
                native = reader._json(Path(slot['proofPath']), bound=8192)
                status = validate_native(native, slot, job, endpoint.packet, endpoint.request,
                                         time.monotonic(), endpoint.frame_bytes)
                ep = reader._json(Path(slot['epochPath']), bound=32768)
                _carrier().classify_epoch(ep, operation_id=p['operationId'], scope_sha256=s.scope_sha256,
                    process_id=48936, execute_thread_id=8292, callback_known=True, callback_sdk_rc=0,
                    target_identity_verified=True)
                need(type(ep.get('cppThrows')) is int and ep['cppThrows'] == 0
                     and type(ep.get('otherExceptions')) is int and ep['otherExceptions'] == 0, 'EPOCH_ZERO')
                s.private['_fresh'](p)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                return _unknown(s, 'SDK_RAM_OR_CLOSURE_UNPROVEN')
            result = dict(kind='SAFE_SAVED_RAM_JOB_RESULT', version=233, status=status, knownTerminal=True,
                operationId=p['operationId'], job=job, requestId=slot['requestId'],
                planSha256=c.digest(s.plan_raw), nativeProofSha256=c.digest(c.read(Path(slot['proofPath']))),
                epochSha256=c.digest(c.read(Path(slot['epochPath']))), sourceSha256=endpoint.packet.receipt.source_sha256,
                savedResourceSha256=endpoint.packet.receipt.saved_resource_sha256,
                bodyBytes=endpoint.packet.receipt.byte_count, sourceBodyFilesCreated=0,
                applicationWrites=0, configurationExports=0, configurationImports=0, configurationSaves=0,
                databaseUpdates=0, repositoryMutations=0, sdkResult=0, hookWorkersReleased=True,
                nativeSavedRamReadVerified=True, permanentMcpBindingVerified=False, retryAuthorized=False)
            c.write_new(out / f'slot{job}-result.json', result)
            s.next_job += 1
            s.phase = 'FIRST_VERIFIED' if job == 0 else 'TWO_VERIFIED'
            if job == 1:
                c.write_new(out / 'result.json', dict(kind='SAFE_SAVED_RAM_SESSION_RESULT', version=233,
                    operationId=p['operationId'], status='TWO_NATIVE_DATABASE_SAVED_MODULES_RAM_VERIFIED',
                    knownTerminal=True, sourceBodyFilesCreated=0, sdkCompilations=1, sdkContexts=2,
                    sameLibraryAndFunctionReused=True, permanentMcpBindingVerified=False,
                    nativeSavedRamReadVerified=True, databaseUpdates=0, repositoryMutations=0, retryAuthorized=False))
            return result
        if s.host.poll() is not None:
            break
        time.sleep(.05)
    return _unknown(s, 'HOST_OR_WORKER_TERMINAL_UNPROVEN')


def run_slot_once(s, review_path, review_pin):
    try:
        return _run_slot_once(s, review_path, review_pin)
    except BaseException:
        abort_unstarted(s)
        raise
