"""One verified stock capture/source/cancel cycle; no source setters or retries.

The caller supplies the existing authenticated native transport. A cancel permit
can be created only by the opaque capability returned from the complete fresh
descriptor/two-module comparison in this same Python process.
"""
import base64
import ctypes as c
import json
import os
from pathlib import Path
import re
import sqlite3
import uuid
from datetime import datetime, timezone

from capture_fresh_guard_v81 import (FILENAMES, INTENT_FILENAME, LIMIT, MARKER_LIMIT,
    PREPARE_PHASES, TERMINAL_PHASES, marker_filename, make_prepare_permit,
    make_cancel_permit, parse_result, verify_prepared, verify_terminal)
from pending_operation_inspector import contained
from prepare_gold_startup_v43 import sha, sources

ROOT = Path(__file__).resolve().parents[4]
BRIDGE = Path(__file__).resolve().parents[1]
PREPARE_PERMIT = 'capture-fresh-v81-prepare.permit'
CANCEL_PERMIT = 'capture-fresh-v81-verify-cancel.permit'


def need(ok, code):
    if not ok:
        raise ValueError('V81_CLIENT_' + code)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'DUPLICATE_KEY')
        value[key] = item
    return value


def _json(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 16384, 'JSON_BOUND')
    try:
        info = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('V81_CLIENT_JSON_CONSTANT')))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('V81_CLIENT_JSON_ENCODING') from None
    need(type(info) is dict, 'JSON_SCHEMA')
    return info


def validate_role(info, *, process_id, birth, session_id, lease_owner):
    """Validate a dedicated role before its private token can format a permit."""
    fixed = dict(version=2,target='Gold',platform='8.3.18.1208',
        rootId='218b5d00-7e10-486f-874c-73c2368ed5da',objectId='88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d',
        readOnlyGold=False,captureFreshV81=True,selectionInputsV46=True,
        uiControllerCaptureV44=False,captureNotificationV56=False,captureWriteAllowed=False,
        captureScope='none',pilotScope='none',goldOwnObjectModuleV78=False)
    need(type(info) is dict and all(type(info.get(k)) is type(v) and info[k] == v
        for k,v in fixed.items()), 'ROLE_REJECTED')
    need(type(process_id) is int and 0 < process_id <= 0x7fffffff
        and type(birth) is str and re.fullmatch('[0-9a-f]{16}',birth) is not None and int(birth,16)>0
        and type(session_id) is str and re.fullmatch('[0-9a-f]{32}',session_id) is not None
        and type(lease_owner) is str and re.fullmatch('[0-9a-f]{32}',lease_owner) is not None,
        'EXPECTED_IDENTITY')
    for key,value in dict(processId=process_id,processCreationFileTimeUtc=birth,
                          sessionId=session_id,leaseOwner=lease_owner).items():
        need(type(info.get(key)) is type(value) and info[key] == value,'IDENTITY_CHANGED')
    need(info.get('pipeName')=='AH1C-'+session_id,'PIPE_REJECTED')
    need(type(info.get('captureFreshTokenV81')) is str
        and re.fullmatch('[0-9a-f]{32}',info['captureFreshTokenV81']) is not None,'TOKEN_REJECTED')


def _unprotect(raw):
    """DPAPI current-user decryption. Never return token data through tool output."""
    need(type(raw) is bytes and 0 < len(raw) <= 16384,'SEALED_BOUND')
    class Blob(c.Structure):
        _fields_ = [('size',c.c_uint32),('data',c.POINTER(c.c_ubyte))]
    crypt = c.WinDLL('crypt32',use_last_error=True)
    kernel = c.WinDLL('kernel32',use_last_error=True)
    crypt.CryptUnprotectData.argtypes = [c.POINTER(Blob),c.c_void_p,c.POINTER(Blob),
        c.c_void_p,c.c_void_p,c.c_uint32,c.POINTER(Blob)]
    crypt.CryptUnprotectData.restype = c.c_int
    kernel.LocalFree.argtypes = [c.c_void_p]
    kernel.LocalFree.restype = c.c_void_p
    data = (c.c_ubyte * len(raw)).from_buffer_copy(raw)
    purpose = b'AH1C-NATIVE-COMMAND-V2'
    entropy = (c.c_ubyte * len(purpose)).from_buffer_copy(purpose)
    source = Blob(len(raw),data); salt = Blob(len(purpose),entropy); target = Blob()
    need(crypt.CryptUnprotectData(c.byref(source),None,c.byref(salt),None,None,1,c.byref(target)) != 0,
        'SEAL_REJECTED')
    try:
        need(0 < target.size <= 16384 and bool(target.data),'UNSEALED_BOUND')
        return c.string_at(target.data,target.size)
    finally:
        kernel.LocalFree(c.cast(target.data,c.c_void_p))


def read_file(session, name):
    """Fixed witnesses only; configuration files and path traversal are refused."""
    names = set(FILENAMES) | {INTENT_FILENAME} | {
        marker_filename(p) for p in PREPARE_PHASES + TERMINAL_PHASES}
    need(type(name) is str and name in names,'WITNESS_NAME')
    minimum = 0 if name.endswith('.bsl') else 1
    limit = LIMIT if name in FILENAMES else 32 if name == INTENT_FILENAME else MARKER_LIMIT
    session = Path(session)
    path = contained(session/name,session)
    need(path.parent == session and minimum <= path.stat().st_size <= limit,'WITNESS_BOUND')
    with path.open('rb') as stream:
        raw = stream.read(limit+1)
    need(minimum <= len(raw) <= limit,'WITNESS_BOUND')
    return raw


def _kernel_identity(process_id,birth):
    """Check the original kernel birth before publishing any writer permit."""
    k = c.WinDLL('kernel32',use_last_error=True)
    k.OpenProcess.argtypes = [c.c_uint32,c.c_int,c.c_uint32]; k.OpenProcess.restype = c.c_void_p
    k.GetProcessTimes.argtypes = [c.c_void_p] + [c.POINTER(c.c_uint64)]*4
    k.CloseHandle.argtypes = [c.c_void_p]
    handle = k.OpenProcess(0x1000,False,process_id)
    need(bool(handle),'ORIGINAL_UNAVAILABLE')
    try:
        values = [c.c_uint64() for _ in range(4)]
        need(k.GetProcessTimes(handle,*(c.byref(v) for v in values)) != 0
            and f'{values[0].value:016x}' == birth,'ORIGINAL_CHANGED')
    finally:
        k.CloseHandle(handle)


def _lease(owner):
    state = Path(os.environ.get('AH1C_BRIDGE_STATE_DIR') or
        (Path(os.environ['LOCALAPPDATA'])/'AH_1C/bridge'))/'state.db'
    with sqlite3.connect(state.as_uri()+'?mode=ro',uri=True) as db:
        rows = db.execute("SELECT owner_operation_id,expires_utc FROM execution_leases WHERE resource='ah1c-write'").fetchall()
    need(len(rows)==1 and rows[0][0]==owner and type(rows[0][1]) is str,'LEASE_CHANGED')
    try:
        expiry = datetime.fromisoformat(rows[0][1])
        need(expiry.tzinfo is not None and expiry>datetime.now(timezone.utc),'LEASE_EXPIRED')
    except (TypeError,ValueError):
        raise ValueError('V81_CLIENT_LEASE_EXPIRED') from None


def _context(connection_file, expected):
    path = Path(connection_file)
    need(path.name=='command-connection.json' and re.fullmatch('session-[0-9a-f]{32}',path.parent.name)
        and re.fullmatch('designer-v43-[0-9a-f]{32}',path.parent.parent.name), 'PATH_REJECTED')
    build = contained(path.parent.parent,ROOT/'build')
    need(build.parent==ROOT/'build','PATH_REJECTED')
    session = contained(path.parent,build); path = contained(path,session)
    need(session.name=='session-'+expected['session_id'] and path.parent==session
        and 0<path.stat().st_size<=12288,'CONNECTION_REJECTED')
    outer = _json(path.read_bytes())
    need(type(outer.get('sealVersion')) is int and outer['sealVersion']==1
        and type(outer.get('protectedConnection')) is str,'SEAL_REJECTED')
    try:
        sealed = base64.b64decode(outer['protectedConnection'],validate=True)
    except ValueError:
        raise ValueError('V81_CLIENT_SEAL_REJECTED') from None
    info = _json(_unprotect(sealed)); validate_role(info,**expected)
    checks = {
        'captureFreshSourceSha256V81':BRIDGE/'tests/NativeCaptureFreshV81.as',
        'captureFreshContractSha256V81':BRIDGE/'research/capture_fresh_contract_v81.py',
        'captureFreshGuardSha256V81':BRIDGE/'research/capture_fresh_guard_v81.py',
        'captureFreshClientSha256V81':BRIDGE/'Invoke-CaptureFreshV81.ps1',
        'captureFreshPreparedManifestSha256V81':build/'v43-prepared.json',
        'clientSourceSha256':BRIDGE/'NativeCommandClient.cs','clientDllSha256':build/'NativeCommandClient.dll'}
    for key,file in checks.items():
        need(type(info.get(key)) is str and re.fullmatch('[a-f0-9]{64}',info[key]) is not None
            and sha(contained(file,build if file.is_relative_to(build) else BRIDGE))==info[key],'SOURCE_CHANGED')
    prepared = _json_large(contained(build/'v43-prepared.json',build))
    need(prepared.get('passed') is True and prepared.get('goldStarted') is False
        and prepared.get('sourceSha256')==sources(),'PREPARED_SOURCE_CHANGED')
    _lease(expected['lease_owner']); _kernel_identity(expected['process_id'],expected['birth'])
    return session, info


def _json_large(path):
    need(0<path.stat().st_size<=1048576,'PREPARED_BOUND')
    with path.open('rb') as stream:
        raw=stream.read(1048577)
    need(0<len(raw)<=1048576,'PREPARED_BOUND')
    return json.loads(raw.decode('utf-8-sig'),object_pairs_hook=_unique)


def _permit(session,name,body):
    need(name in (PREPARE_PERMIT,CANCEL_PERMIT) and type(body) is bytes and 0<len(body)<=256,'PERMIT_BOUND')
    path=contained(session/name,session)
    need(path.parent==session,'PERMIT_PATH')
    with path.open('xb') as stream:
        stream.write(body); stream.flush(); os.fsync(stream.fileno())


def run_cycle(connection_file, *, process_id, birth, session_id, lease_owner, call):
    """Capture once, compare actual fresh content, then cancel only this capture.

    call(command, operation_id) is the existing authenticated native transport
    and returns (safe transport metadata, UTF-8 native JSON body). Any failure
    propagates without automatic retry, cancellation, close or lease removal.
    """
    need(callable(call),'TRANSPORT_REQUIRED')
    expected=dict(process_id=process_id,birth=birth,session_id=session_id,lease_owner=lease_owner)
    session,context=_context(connection_file,expected)
    capture=uuid.uuid4().hex; cancel=uuid.uuid4().hex
    _permit(session,PREPARE_PERMIT,make_prepare_permit(context['captureFreshTokenV81'],capture,session_id,process_id,birth))
    row,body=call('CAPTURE_FRESH_PREPARE_V81',capture)
    prepared=parse_result(body.encode('utf-8') if type(body) is str else body)
    cap=verify_prepared(prepared,lambda name:read_file(session,name),
        session_id=session_id,process_id=process_id,birth=birth,operation_id=capture)
    # Fresh protected role, current source pins, exact lease and original process
    # are required again after the complete independent content comparison.
    current_session,current=_context(connection_file,expected)
    need(current_session==session and current['captureFreshTokenV81']==context['captureFreshTokenV81'],'SESSION_CHANGED')
    _permit(session,CANCEL_PERMIT,make_cancel_permit(cap,current['captureFreshTokenV81'],cancel))
    terminal_row,terminal_body=call('CAPTURE_FRESH_VERIFY_CANCEL_V81',cancel)
    terminal=parse_result(terminal_body.encode('utf-8') if type(terminal_body) is str else terminal_body)
    summary=verify_terminal(terminal,cap,lambda name:read_file(session,name),cancel_operation_id=cancel)
    return dict(captureFreshVerified=True,preparedNative=prepared,preparedComparison=cap.summary(),
        terminalNative=terminal,terminalComparison=summary,captureOperationId=capture,cancelOperationId=cancel,
        configurationSaves=0,databaseUpdates=0,sourceSetterCalls=0,repositoryPlacement=0,businessCalls=0,
        repositoryMutations=2,externalChildBodiesVerified=False,staleRefreshVerified=False)
