"""Root-only orchestration of one bounded resident saved-module MCP session.

No application source files, configuration loads/saves, business code, or
repository commands. The opaque live object belongs to its issuing RAM owner.
An uncertain native start/command/close is retained, never implicitly retried.
"""
from dataclasses import dataclass
import importlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
from types import FunctionType, SimpleNamespace
import uuid

import safe_saved_module_ram_operation as previous
import saved_ram_session_closure_audit as closed_read
import resident_managed_carrier as managed
import sdk_compiler_section_identity as section_identity

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(HERE.parent))
from native_mcp.windows_ram_pipe import _Api
from native_mcp.session_lifecycle import SessionIdentity, SessionBroker

c, reader, base = previous.c, previous.reader, previous.base
SOURCE_NAME = 'NativeSafeCommonModuleRam.as'
SOURCE_SHA = '1f6d544d1963a19e4da54a67f246457a63ce080a30151857472802acaa2d92e3'
ADMITTED_SHA = '819038a386ae34fcfec0de8fa234b3b1f4415520b4615bb19c7884df8c43e48a'
CARRIER_SHA = '5fede18cce44dd9a1f465907deccdcbeffd209c5d43f2dcc022cb54f82feaf04'
PROVIDER_SHA = 'bc69ba0ed58a3e77b96ca47a1165c2eec26685a7bf727126acbdc5d63f953a20'
PROFILE = 'RESIDENT_DATABASE_SAVED_COMMON_MODULES'
MAIN_SHA = previous.MAIN_SHA
PROPERTY = previous.PROPERTY
TRUE_AUTH = previous.TRUE_AUTH + ('residentSdkReuseAuthorized', 'residentSdkFunctionCloseAuthorized',
                                 'arbitraryCommonModuleSelectionAuthorized', 'protectedControlChannelAuthorized')
FALSE_AUTH = previous.FALSE_AUTH
_ISSUER = object()
PINS = {
    'research/safe_saved_module_ram_operation.py': '6e3d115c9b3423c930c903707f9f548ce7e61fab4e1ce142ee8061149b4293fe',
    'research/saved_ram_session_closure_audit.py': 'f88100f76c9b1663d163cd50f62078a0ea214d157ed3095599f856bb3db573d6',
    'research/resident_managed_carrier.py': 'df071e91f3e0fe2bea80b5a850e2407bd3bed4e29322bf9ba5027f122dbe44e8',
    'research/persistent_ram_carrier.py': CARRIER_SHA,
    'research/NativeSafeCommonModuleRam.as': SOURCE_SHA,
    'native_mcp/saved_source.py': '6aae709b2eb6e112ebc049f4776811325877166fc5fc35f87369b224571facdc',
    'native_mcp/server.py': '77f7bb7fcc8a372a25384c797224e87c223f66d1f585bf00e53372a31bc23e36',
    'native_mcp/session_lifecycle.py': '458ef6898abad4623ed96ad0a246929828df3c1a33b2d0be257c460945fc4b3e',
    'native_mcp/resident_server.py': '459a2f393faabc359b31aab0579d9bb6a2cd46889a911e424e0090644fc163df',
    'native_mcp/resident_wire.py': '6d6089671de1fb7cc9fddca88fc43eb44c55bbcc5eeb766fed8387fa32966e2d',
    'native_mcp/resident_channel.py': '91420eddd9240bb9d28e1a626f0e320edcd7efe17d6d5d00f041b1d8834b388f',
    'native_mcp/windows_resident_pipe.py': 'fb10fac3ad1d976e1b17e018dc139da0ef4322197ba2af52d230a46d905cbaac',
}


def need(ok, code):
    if not ok:
        raise ValueError('RESIDENT_OPERATION_'+code)


def limits():
    return dict(maximumNativeCommands=0, maximumTypeEvents=32, maximumEnumerations=0,
                maximumResidentControlCommands=64, maximumRequests=63, maximumSessionSeconds=600,
                maximumBodyBytes=4194304, maximumCodePoints=1048576,
                maximumPlainResourceBytes=8388608, maximumFileOpensPerRequest=2,
                maximumStorageEntryOpensPerRequest=4)


def authority(row):
    return (all(row.get(k) is True for k in TRUE_AUTH) and all(row.get(k) is False for k in FALSE_AUTH)
            and all(type(row.get(k)) is int and row[k] == n for k, n in limits().items())
            and type(row.get('expectedDatabaseSource')) is int and row['expectedDatabaseSource'] == 1383504556)


def validate_scope(row):
    need(type(row) is dict and row.get('kind') == 'ROOT_RESIDENT_SAVED_RAM_SCOPE'
         and row.get('passed') is True and row.get('profile') == PROFILE
         and row.get('actualSourceSha256') == SOURCE_SHA and authority(row)
         and row.get('allowedReadClasses') == ['CommonModule']
         and row.get('modulePropertyId') == PROPERTY, 'SCOPE')


def _pins(require_provider=True):
    for name, pin in PINS.items():
        need(c.digest(c.read(HERE.parent/name)) == pin, 'SOURCE_PIN')
    previous._pins()
    if require_provider:
        need(type(PROVIDER_SHA) is str and re.fullmatch('[0-9a-f]{64}', PROVIDER_SHA), 'PROVIDER_NOT_FROZEN')
        need(c.digest(c.read(HERE.parent/'native_mcp/resident_provider.py')) == PROVIDER_SHA, 'PROVIDER_PIN')


def _carrier():
    need(c.digest(c.read(HERE/'persistent_ram_carrier.py')) == CARRIER_SHA, 'CARRIER_PIN')
    return importlib.import_module('persistent_ram_carrier')


def _source():
    raw = c.read(HERE/SOURCE_NAME, 32768)
    need(c.digest(raw) == SOURCE_SHA, 'SOURCE_PIN')
    admitted = _carrier().admitted_source(raw)
    need(c.digest(admitted) == ADMITTED_SHA, 'ADMITTED_SOURCE_PIN')
    return raw, admitted


def prepare_parent(path, pin):
    """Private historical-audit recognition plus fresh process/lease checks."""
    factory = previous.prior.maintenance.private_prepare()
    original_reader, original_inspect = factory.__globals__['reader'], factory.__globals__['inspect']
    def checked_audit(fn, plan):
        result = fn(plan)
        base._lease(SimpleNamespace(plan=plan))
        c._fresh(base._carrier_view(plan))
        return result
    def namespace(parent):
        ns = original_reader._namespace(parent)
        ns.update(__closed_metadata_operation=previous.closed_metadata.OP,
            __closed_metadata_audit=lambda plan: checked_audit(previous.closed_metadata.audit_closed, plan),
            __closed_saved_operation=closed_read.OPERATION,
            __closed_saved_audit=lambda plan: checked_audit(closed_read.audit_closed, plan))
        return ns
    def getsource(target):
        source = original_inspect.getsource(target)
        if target is c._no_pending:
            anchor = '        if prior_identity!=identity: continue\n'
            need(source.count(anchor) == 1, 'CLOSED_AUDIT_ANCHOR')
            source = source.replace(anchor, anchor+
                '        if operation==__closed_metadata_operation:\n            __closed_metadata_audit(prior);continue\n'+
                '        if operation==__closed_saved_operation:\n            __closed_saved_audit(prior);continue\n', 1)
        return source
    reader_proxy = SimpleNamespace(**dict(original_reader.__dict__)); reader_proxy._namespace = namespace
    inspect_proxy = SimpleNamespace(**dict(original_inspect.__dict__)); inspect_proxy.getsource = getsource
    local = previous._private_factory(factory, reader=reader_proxy, inspect=inspect_proxy)
    maintenance_proxy = SimpleNamespace(**dict(previous.prior.maintenance.__dict__))
    maintenance_proxy.private_prepare = lambda: local
    prepare = FunctionType(previous.prior.prepare_parent.__code__,
        dict(previous.prior.prepare_parent.__globals__, maintenance=maintenance_proxy, validate_scope=validate_scope),
        previous.prior.prepare_parent.__name__, previous.prior.prepare_parent.__defaults__,
        previous.prior.prepare_parent.__closure__)
    return prepare(path, pin)


@dataclass(slots=True)
class ResidentOperation:
    issuer: object
    parent: object
    scope_path: Path
    scope_sha256: str
    scope: dict
    plan: dict
    plan_raw: bytes
    private: dict
    channel: object
    phase: str = 'PREPARED'
    host: object = None
    provider: object = None
    broker: object = None
    join_attempted: bool = False


def _claim_path(s):
    return ROOT/'artifacts/designer-bridge'/('resident-saved-ram-claim-'+s.scope_sha256+'.json')


def _claim(s):
    owner = reader._check_owner(s.parent)
    return dict(kind='RESIDENT_SAVED_RAM_CLAIM', operationId=s.plan['operationId'], scopeSha256=s.scope_sha256,
                controllerSha256=s.plan['updatePreviewControllerSha256'], actualSourceSha256=SOURCE_SHA,
                writerOperationId=owner['operationId'], packetSha256=owner['packetSha256'],
                sessionNonce=s.plan['context']['heldNonce'], pid=48936, birth='01dd5d0180299126')


def _check(s):
    need(type(s) is ResidentOperation and s.issuer is _ISSUER, 'ISSUED')
    _pins()
    p = s.plan
    need(c.canonical(p) == s.plan_raw and p['updatePreviewControllerSha256'] == c.digest(c.read(Path(__file__)))
         and p['updatePreviewProfile'] == PROFILE and p['actualSourceSha256'] == SOURCE_SHA
         and p['admittedSourceSha256'] == ADMITTED_SHA and p['nativeRamCarrierSha256'] == CARRIER_SHA
         and p['residentProviderSha256'] == PROVIDER_SHA and p['context'] == s.parent.plan['context']
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
    scope_path = c._plain(path, ROOT/'artifacts/designer-bridge')
    scope = reader._json(scope_path, pin); validate_scope(scope)
    parent = prepare_parent(scope_path, pin)
    p = dict(parent.plan)
    op = uuid.uuid4().hex; out = ROOT/'build'/('designer-hot-v233-'+op)
    for key in ('pendingReadProfile', 'actualReadSourceSha256', 'pendingReadControllerSha256', 'pendingScopeSha256'):
        p.pop(key, None)
    p.update(operationId=op, outputDirectory=str(out), updatePreviewProfile=PROFILE,
        updatePreviewControllerSha256=c.digest(c.read(Path(__file__))), actualSourceSha256=SOURCE_SHA,
        admittedSourceSha256=ADMITTED_SHA, nativeRamCarrierSha256=CARRIER_SHA, residentProviderSha256=PROVIDER_SHA,
        updatePreviewScopeSha256=pin, readScopeSha256=parent.review_sha256, writerAuthorized=False,
        captureAuthorized=False, applicationWrites=0, expectedDatabaseSource=1383504556,
        **limits(), **{k: True for k in TRUE_AUTH}, **{k: False for k in FALSE_AUTH})
    p['goldLeaseOwner'], p['goldLeaseBootstrapSha256'] = base.owner_base._lease_binding(p['context'])
    previous.check_clock()
    from native_mcp.resident_channel import NativeResidentChannel
    nonce = uuid.uuid4().hex
    channel = NativeResidentChannel(48936, install_nonce=nonce, expected_birth='01dd5d0180299126', timeout=15)
    try:
        api = _Api(); now = time.monotonic()
        configuration = dict(operationId=op, scopeSha256=pin, sessionId=p['context']['heldNonce'],
            installNonce=nonce, serverPid=os.getpid(), serverBirth=api.birth(api.k.GetCurrentProcess()),
            pipePath=channel.path, installedAt=now, sessionValidUntil=now+600,
            armPath=(out/'resident-arm.bin').as_posix(), resultPath=(out/'resident-sdk-result.bin').as_posix())
        p['residentConfiguration'] = configuration
        s = ResidentOperation(_ISSUER, parent, scope_path, pin, scope, p, c.canonical(p), {}, channel)
        _check(s)
        ns = parent.private; ns['__pending_read_operation'] = op
        def fresh(plan):
            _check(s); need(plan == s.plan, 'FRESH_PLAN'); c._fresh(base._carrier_view(plan))
        def render(plan, raw):
            need(plan == s.plan, 'RENDER_PLAN'); return _render(s)
        ns.update(_fresh=fresh, render=render); s.private = ns
        ns['_no_pending'](context=p['context'])
        return s
    except BaseException:
        channel.abort_before_connect(); channel.wait_closed()
        raise


def _identity(s):
    ctx = s.plan['context']
    return dict(processId=ctx['processId'], birth=ctx['birth'], guiThreadId=ctx['guiThreadId'],
                engineAddress=0x34554a0, moduleAddress=0x34fc380)


def _render(s):
    _check(s); p = s.plan
    files = c.render(base._carrier_view(p), c.read(HERE/c._probe_spec(reader.PROBE)[0], 32768))
    header = files['sdk_probe_params.h'].decode()
    for name, expected in (('ENGINE_ADDRESS', 0x34554a0), ('MODULE_ADDRESS', 0x34fc380)):
        found = re.search(r'^#define AH_SDK_'+name+r' (0x[0-9a-fA-F]+)U$', header, re.M)
        need(found is not None and int(found[1], 16) == expected, 'SDK_ADDRESS')
    raw, admitted = _source()
    line = next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
    files['sdk_probe_params.h'] = c._replace_once(header, line,
        '#define AH_SDK_FIXED_SOURCE '+json.dumps(admitted.decode(), ensure_ascii=False)).encode()
    files['Continuation.c'] = _carrier().render(raw, configuration=p['residentConfiguration'], identity=_identity(s))
    anchor = _carrier().SECTION_ANCHOR.encode('ascii')
    need(files['Continuation.c'].count(anchor) == 1, 'SECTION_ANCHOR')
    files['Continuation.c'] = files['Continuation.c'].replace(anchor, section_identity.ANCHOR, 1)
    files.pop('run-fixed.ps1')
    files.update(managed.render(p['residentConfiguration'], _identity(s)))
    files, receipt = section_identity.with_section_identity(files,
        operation_kind='RESIDENT_SAVED_RAM', operation_id=p['operationId'])
    need(receipt['actualSourceSha256'] == ADMITTED_SHA, 'COMPILED_SOURCE_JOIN')
    return files


def abort_before_start(s):
    need(type(s) is ResidentOperation and s.issuer is _ISSUER, 'ABORT_SCOPE')
    if s.phase in ('PREPARED', 'STAGED'):
        if not s.channel.closed and not s.channel.sealed:
            s.channel.abort_before_connect()
        need(s.channel.wait_closed(), 'UNSTARTED_OWNER_CLOSE')


def stage_root(s):
    try:
        _check(s); need(s.phase == 'PREPARED', 'STAGE_PHASE')
        s.private['FILES'] = tuple(_render(s))
        proof = s.private['stage_private'](s.plan, dict(mode='ROOT_STAGE_SEALED_CONTINUATION_V233',
            rootAuthorized=True, planSha256=c.digest(s.plan_raw)))
        s.phase = 'STAGED'; return proof
    except BaseException:
        abort_before_start(s); raise


def require_stage(s):
    try:
        _check(s)
        return s.private['require_stage'](s.plan)
    except BaseException:
        abort_before_start(s); raise


def _unknown(s, reason):
    s.phase = 'UNKNOWN_RETAIN'
    row = dict(kind='RESIDENT_SAVED_RAM_UNKNOWN', version=233, operationId=s.plan['operationId'],
        status=s.phase, knownTerminal=False, retryAuthorized=False, reason=reason,
        permanentMcpBindingVerified=False, configurationExports=0, configurationImports=0,
        configurationSaves=0, databaseUpdates=0, repositoryMutations=0)
    path = Path(s.plan['outputDirectory'])/'unknown.json'
    if not path.exists():
        c.write_new(path, row)
    return row


def _fresh_identity_gate(s):
    # The initial heavyweight admission checks all retained operations and VM
    # pins. During this exclusive intent, cheap OS/lease checks accompany each
    # request; AS independently checks root/UUID/type/clean/prefix twice.
    need(s.phase in ('READY', 'CLOSING'), 'LIVE_PHASE')
    _check(s)
    api = _Api(); handle = api.pin_process(48936, '01dd5d0180299126')
    try:
        api.live_process(handle, '01dd5d0180299126')
        main = Path(s.plan['context']['buildDirectory'])/'runtime/modules/snegopat/engine/main.as'
        need(c.digest(c.read(main)) == MAIN_SHA, 'LIVE_MAIN_PIN')
    finally:
        api.w.CloseHandle(handle)
    return SessionIdentity('218b5d00-7e10-486f-874c-73c2368ed5da',
        s.plan['context']['heldNonce'], 48936, '01dd5d0180299126', 'database_saved')


def _managed_join(s):
    need(s.phase in ('READY', 'CLOSING') and not s.join_attempted and s.channel.closed, 'JOIN_PHASE')
    s.join_attempted = True; s.phase = 'CLOSING'
    need(s.host is not None and s.host.poll() is None and s.host.stdin is not None, 'HOST_LIVE')
    s.host.stdin.write(b'JOIN_VERIFIED_CLOSE\n'); s.host.stdin.flush(); s.host.stdin.close()
    out = Path(s.plan['outputDirectory']); deadline = time.monotonic()+25
    while time.monotonic() < deadline:
        path = out/'resident-host-result.json'
        if path.is_file():
            try:
                row = reader._json(path, bound=4096)
            except (OSError, ValueError):
                time.sleep(.02); continue
            need(row.get('kind') == 'RESIDENT_MANAGED_TERMINAL'
                 and row.get('operationId') == s.plan['operationId'] and row.get('knownTerminal') is True
                 and row.get('hookWorkersReleased') is True and row.get('writerAuthorized') is False
                 and type(row.get('sdkResult')) is int and row['sdkResult'] == 0
                 and type(row.get('threadId')) is int and row['threadId'] == 8292, 'HOST_CLOSURE')
            s.host.wait(timeout=5)
            need(s.host.returncode == 0 and s.channel.wait_closed(), 'HOST_EXIT')
            raw = c.read(out/'resident-sdk-result.bin', 4)
            need(raw == struct.pack('<I', 0), 'NATIVE_BOOTSTRAP_RC')
            _fresh_identity_gate(s)
            return dict(row, processId=48936, processExitCode=0, rawSdkResult=0)
        if s.host.poll() is not None:
            break
        time.sleep(.02)
    raise ValueError('RESIDENT_OPERATION_HOST_JOIN_UNKNOWN')


def _start_root_once(s, review_path, review_pin):
    """Start one reviewed fixed resident host; never executes business methods."""
    _check(s); need(s.phase == 'STAGED', 'START_PHASE')
    build = require_stage(s)
    review = reader._json(c._plain(review_path, ROOT/'artifacts/designer-bridge'), review_pin)
    need(review.get('kind') == 'ROOT_RESIDENT_SAVED_RAM_RUN' and review.get('passed') is True
         and authority(review) and review.get('planSha256') == c.digest(s.plan_raw)
         and review.get('buildSha256') == c.digest(c.canonical(build))
         and review.get('scopeSha256') == s.scope_sha256 and review.get('actualSourceSha256') == SOURCE_SHA
         and review.get('admittedSourceSha256') == ADMITTED_SHA
         and review.get('nativeRamCarrierSha256') == CARRIER_SHA
         and review.get('residentProviderSha256') == PROVIDER_SHA, 'ROOT_RUN')
    s.private['_no_pending'](context=s.plan['context']); c._fresh(base._carrier_view(s.plan))
    need(time.monotonic()+30 < s.plan['residentConfiguration']['sessionValidUntil'], 'INSTALL_EXPIRED')
    out = Path(s.plan['outputDirectory'])
    need(not any((out/name).exists() for name in ('intent.json', 'resident-arm.bin', 'resident-sdk-result.bin',
             'resident-host-ready.json', 'resident-host-result.json', 'unknown.json')), 'ONE_ATTEMPT')
    c.write_new(_claim_path(s), _claim(s))
    c.write_new(out/'intent.json', dict(kind='RESIDENT_SAVED_RAM_INTENT', operationId=s.plan['operationId'],
        scopeSha256=s.scope_sha256, planSha256=c.digest(s.plan_raw), rootRunSha256=review_pin,
        applicationWrites=0, configurationExports=0, configurationImports=0, repositoryMutations=0))
    s.phase = 'STARTING_RETAIN'
    try:
        s.host = subprocess.Popen([str(reader.writer.PS), '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', str(out/'run-resident.ps1')], cwd=out, stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        c.write_new(out/'host-identity.json', reader.writer._host_identity(s.host))
        # Start() waits for C's arm receipt AFTER C authenticates this pipe.
        # Waiting for managed ready before connect would deadlock that handshake.
        s.channel.connect()
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            path = out/'resident-host-ready.json'
            if path.is_file():
                try:
                    ready_row = reader._json(path, bound=4096)
                except (OSError, ValueError):
                    time.sleep(.02); continue
                need(ready_row.get('kind') == 'RESIDENT_MANAGED_READY'
                     and ready_row.get('operationId') == s.plan['operationId']
                     and type(ready_row.get('processId')) is int and ready_row['processId'] == 48936
                     and type(ready_row.get('threadId')) is int and ready_row['threadId'] == 8292
                     and ready_row.get('nativeSourceBindingVerified') is False
                     and ready_row.get('workerExpectedAlive') is True and s.host.poll() is None
                     and c.read(out/'resident-arm.bin', 8) == b'\0'*8, 'HOST_READY')
                s.phase = 'READY'
                _fresh_identity_gate(s)
                module = importlib.import_module('native_mcp.resident_provider')
                s.provider = module.NativeResidentProvider(s.channel, s.plan['residentConfiguration'], _identity(s),
                    fresh_identity_gate=lambda: _fresh_identity_gate(s), managed_join=lambda: _managed_join(s))
                s.broker = SessionBroker(_fresh_identity_gate(s), s.provider.make_ports, s.provider.close)
                c.write_new(out/'connected.json', dict(kind='RESIDENT_SAVED_RAM_CONNECTED',
                    operationId=s.plan['operationId'], knownTerminal=False, nativeSourceBindingVerified=False,
                    providerReady=True, sourceBodyFilesCreated=0, applicationWrites=0))
                return dict(status='CONNECTED', operationId=s.plan['operationId'], knownTerminal=False,
                            sourceBodyFilesCreated=0, nativeSourceBindingVerified=False)
            if s.host.poll() is not None or (out/'resident-host-result.json').is_file():
                break
            time.sleep(.02)
        return _unknown(s, 'MANAGED_READY_UNPROVEN')
    except Exception:
        return _unknown(s, 'START_OR_CHANNEL_UNPROVEN')


def start_root_once(s, review_path, review_pin):
    try:
        return _start_root_once(s, review_path, review_pin)
    except BaseException:
        abort_before_start(s)
        raise


def close_root(s):
    """Close through native proof/ACK/EOF and the owned managed host join."""
    _check(s); need(s.phase in ('READY', 'CLOSING') and s.broker is not None, 'CLOSE_PHASE')
    try:
        need(s.broker.close() == 'CLOSED' and s.join_attempted and s.host.returncode == 0
             and s.channel.closed, 'FINAL_CLOSURE')
        s.phase = 'CLOSED'
        result = dict(kind='RESIDENT_SAVED_RAM_SESSION_RESULT', version=233,
            operationId=s.plan['operationId'], status='RESIDENT_SAVED_RAM_CLOSED', knownTerminal=True,
            planSha256=c.digest(s.plan_raw), sdkResult=0, hookWorkersReleased=True,
            targetIdentityVerified=True, nativeInjectionPerformed=True, sourceBodyFilesCreated=0,
            configurationExports=0, configurationImports=0, configurationSaves=0,
            databaseUpdates=0, repositoryMutations=0, retryAuthorized=False,
            permanentMcpBindingVerified=False)
        c.write_new(Path(s.plan['outputDirectory'])/'result.json', result)
        return result
    except Exception:
        return _unknown(s, 'NATIVE_OR_HOST_CLOSURE_UNPROVEN')
