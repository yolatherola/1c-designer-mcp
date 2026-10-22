"""Bounded syntax-only LSP analysis of one RAM document, never a 1C execution.

Only technical configuration/cache metadata may reach our private directory.
The pinned backend's sole persistent source-derived cache is the typo checker;
it is excluded, rather than assuming compressed cache bytes hide no source.
Diagnostics/logs are untrusted RAM data; their messages and token data never
leave this boundary. This is neither platform compilation nor semantic debug.
"""
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import subprocess
import tempfile
import threading
import time
from uuid import uuid4
from zipfile import ZipFile

from .editor_command import ModuleText

ROOT = Path(__file__).resolve().parents[4]
BACKEND = ROOT/'tools/1c/vendor/bsl-language-server/1.0.5/package/bsl-language-server'
EXE = BACKEND/'bsl-language-server.exe'
JAR = BACKEND/'app/bsl-language-server-1.0.5-exec.jar'
CFG = BACKEND/'app/bsl-language-server.cfg'
EXE_SHA = '5be5f92ccdc5c8315ad205329d084dd878f463583c1971e2457e19573d3bf7fd'
JAR_SHA = '55deae18cd479a1dff04db5cae5f30c4f7dc6e51272ed5df752595043d9dc0b8'
CFG_SHA = 'e08f59fd1b7bc2937be869911f994049a343c752081b2ab764ce86782942336a'
PREFIX = 'BOOT-INF/classes/com/github/_1c_syntax/bsl/languageserver/'
CODES = ('ParseError', 'InvalidCharacterInFile')
MAX_FRAME, MAX_DIAGNOSTICS, MAX_MESSAGES = 1048576, 256, 64
CONFIGURATION = dict(sendErrors='never', traceLog='', configurationRoot=None, excludePaths=['**'],
    diagnostics=dict(mode='only', parameters=dict(ParseError=True, InvalidCharacterInFile=True, Typo=False),
                     computeTrigger='onType', analyzeOnStart=False))


class RamBslRefusal(ValueError):
    """A fixed code, never a backend exception, message or source excerpt."""


class _Rejected(Exception):
    pass


def _need(ok, code):
    if not ok:
        raise _Rejected(code)


@dataclass(frozen=True, slots=True)
class SyntaxDiagnostic:
    code: str
    severity: int
    start_line: int
    start_character: int
    end_line: int
    end_character: int


@dataclass(frozen=True, slots=True)
class RamSyntaxResult:
    source_sha256: str
    version: int
    diagnostics: tuple[SyntaxDiagnostic, ...]


def _backend():
    """Reject backend drift, including additions to the persistent cache path."""
    _need(hashlib.sha256(EXE.read_bytes()).hexdigest() == EXE_SHA
          and hashlib.sha256(JAR.read_bytes()).hexdigest() == JAR_SHA
          and hashlib.sha256(CFG.read_bytes()).hexdigest() == CFG_SHA, 'BACKEND_PIN')
    with ZipFile(JAR) as archive:
        classes = {name[len(PREFIX):]: archive.read(name) for name in archive.namelist()
                   if name.startswith(PREFIX) and name.endswith('.class')}
        registrars = {name for name, data in classes.items() if b'infrastructure/EhcacheRegistrar' in data}
        consumers = {name for name, data in classes.items() if b'typoCache' in data}
        word_clients = {name for name, data in classes.items() if b'diagnostics/typo/CheckedWordsHolder' in data}
        _need(registrars == {'diagnostics/typo/TypoCacheRegistrar.class', 'infrastructure/CacheConfiguration.class',
                             'infrastructure/EhcacheRegistrar.class'}
              and consumers == {'diagnostics/typo/CheckedWordsHolder.class', 'diagnostics/typo/TypoCacheRegistrar.class'}
              and word_clients == {'diagnostics/TypoDiagnostic.class', 'diagnostics/typo/CheckedWordsHolder.class'},
              'CACHE_STRUCTURE')


def _json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            _need(key not in value, 'JSON_DUPLICATE')
            value[key] = item
        return value
    return json.loads(raw.decode('utf8'), object_pairs_hook=pairs, parse_constant=lambda _: (_need(False, 'JSON_NUMBER')))


def _read_frame(stream):
    header, length = 0, None
    while True:
        line = stream.readline(1025)
        if not line and header == 0:
            raise EOFError()
        _need(line and len(line) <= 1024 and line.endswith(b'\r\n'), 'FRAME_HEADER')
        header += len(line); _need(header <= 2048, 'FRAME_HEADER')
        if line == b'\r\n':
            break
        if line.startswith(b'Content-Length: '):
            number = line[16:-2]
            _need(length is None and re.fullmatch(b'[1-9][0-9]{0,6}', number), 'FRAME_LENGTH')
            length = int(number)
        else:
            _need(line.lower() == b'content-type: application/vscode-jsonrpc; charset=utf-8\r\n', 'FRAME_HEADER')
    _need(type(length) is int and length <= MAX_FRAME, 'FRAME_LENGTH')
    raw = bytearray()
    while len(raw) < length:
        piece = stream.read(length-len(raw)); _need(piece, 'FRAME_TRUNCATED'); raw.extend(piece)
    row = _json(bytes(raw))
    _need(type(row) is dict and row.get('jsonrpc') == '2.0', 'FRAME_JSON')
    return row


class _Job:
    """Private kernel job assigned before our suspended launcher can run.

    No breakaway permission is set. Every launcher descendant therefore stays
    in this job. Thread discovery is used only for this held, suspended process;
    GetProcessIdOfThread and the still-live Popen handle must agree before resume.
    """
    def __init__(self):
        import ctypes as c
        from ctypes import wintypes as w
        self.c, self.w, self.closed, self.active_end = c, w, False, None
        self.k = k = c.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'CreateJobObjectW': ([c.c_void_p, w.LPCWSTR], w.HANDLE),
            'SetInformationJobObject': ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
            'QueryInformationJobObject': ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p], w.BOOL),
            'AssignProcessToJobObject': ([w.HANDLE, w.HANDLE], w.BOOL),
            'TerminateJobObject': ([w.HANDLE, w.UINT], w.BOOL),
            'CreateToolhelp32Snapshot': ([w.DWORD, w.DWORD], w.HANDLE),
            'Thread32First': ([w.HANDLE, c.c_void_p], w.BOOL),
            'Thread32Next': ([w.HANDLE, c.c_void_p], w.BOOL),
            'OpenThread': ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            'GetProcessIdOfThread': ([w.HANDLE], w.DWORD),
            'ResumeThread': ([w.HANDLE], w.DWORD),
            'CloseHandle': ([w.HANDLE], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(k, name); function.argtypes, function.restype = args, result
        class Basic(c.Structure):
            _fields_ = [('processTime', c.c_int64), ('jobTime', c.c_int64), ('flags', w.DWORD),
                ('minimum', c.c_size_t), ('maximum', c.c_size_t), ('active', w.DWORD),
                ('affinity', c.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]
        class Limits(c.Structure):
            _fields_ = [('basic', Basic), ('io', c.c_uint64*6), ('memory', c.c_size_t*4)]
        self.handle = k.CreateJobObjectW(None, None)
        _need(self.handle, 'JOB_CREATE')
        limits = Limits(); limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE only; no breakaway.
        if not k.SetInformationJobObject(self.handle, 9, c.byref(limits), c.sizeof(limits)):
            k.CloseHandle(self.handle); self.handle = None; _need(False, 'JOB_LIMIT')

    def attach_resume(self, process):
        c, w, k = self.c, self.w, self.k
        _need(process.poll() is None and k.AssignProcessToJobObject(self.handle, int(process._handle)), 'JOB_ASSIGN')
        class Thread(c.Structure):
            _fields_ = [('size', w.DWORD), ('usage', w.DWORD), ('tid', w.DWORD),
                       ('pid', w.DWORD), ('base', w.LONG), ('delta', w.LONG), ('flags', w.DWORD)]
        snapshot = k.CreateToolhelp32Snapshot(4, 0)
        _need(snapshot not in (None, c.c_void_p(-1).value), 'JOB_THREADS')
        tids = []
        try:
            entry = Thread(); entry.size = c.sizeof(entry); okay = k.Thread32First(snapshot, c.byref(entry))
            _need(okay, 'JOB_THREADS')
            count = 0
            while okay:
                count += 1; _need(count <= 65536, 'JOB_THREADS')
                if entry.pid == process.pid:
                    tids.append(entry.tid)
                okay = k.Thread32Next(snapshot, c.byref(entry))
            _need(c.get_last_error() == 18, 'JOB_THREADS')  # ERROR_NO_MORE_FILES, not a partial snapshot.
        finally:
            k.CloseHandle(snapshot)
        _need(len(tids) == 1 and process.poll() is None, 'JOB_PRIMARY_THREAD')
        thread = k.OpenThread(0x802, False, tids[0])  # SUSPEND_RESUME | QUERY_LIMITED_INFORMATION
        _need(thread, 'JOB_PRIMARY_THREAD')
        try:
            _need(process.poll() is None and k.GetProcessIdOfThread(thread) == process.pid, 'JOB_THREAD_JOIN')
            _need(k.ResumeThread(thread) == 1, 'JOB_RESUME')
        finally:
            k.CloseHandle(thread)

    def process_ids(self):
        c = self.c
        raw = c.create_string_buffer(8+256*c.sizeof(c.c_size_t))
        _need(self.k.QueryInformationJobObject(self.handle, 3, raw, len(raw), None), 'JOB_QUERY')
        assigned, count = c.cast(raw, c.POINTER(c.c_uint32))[0:2]
        _need(assigned == count and count <= 256, 'JOB_PROCESS_BOUND')
        return tuple((c.c_size_t*count).from_buffer(raw, 8))

    def close(self):
        if self.closed:
            return
        k = self.k
        try:
            if self.process_ids():
                _need(k.TerminateJobObject(self.handle, 1), 'JOB_TERMINATE')
            deadline = time.monotonic()+5
            while self.process_ids() and time.monotonic() < deadline:
                time.sleep(.01)
            _need(not self.process_ids(), 'JOB_MEMBERS_RETAINED')
            self.active_end = 0
        finally:
            k.CloseHandle(self.handle); self.handle = None; self.closed = True


def _cleanup(process, *, job, threads=(), suspended=False):
    """Attempt every owned cleanup stage, then expose one fixed failure code."""
    failed = False
    try:
        try:
            if suspended and process is not None and process.poll() is None:
                process.kill()
        except Exception:
            failed = True
    finally:
        try:
            try:
                job.close()  # Its finally closes KILL_ON_JOB_CLOSE even on query failure.
            except Exception:
                failed = True
        finally:
            try:
                try:
                    if process is not None:
                        process.wait(timeout=5)
                except Exception:
                    failed = True
            finally:
                try:
                    if process is not None:
                        for name in ('stdin', 'stdout', 'stderr'):
                            try:
                                getattr(process, name).close()
                            except Exception:
                                failed = True
                finally:
                    for thread in threads:
                        try:
                            thread.join(timeout=1)
                            if thread.is_alive():
                                failed = True
                        except Exception:
                            failed = True
    _need(not failed, 'PIPE_CLEANUP')


class _Pipe:
    """Own process only; worker output is bounded and never logged/persisted."""
    def __init__(self, process, options):
        self.process, self.messages = process, queue.Queue(maxsize=MAX_MESSAGES)
        self.failed = threading.Event()
        self.ended = threading.Event()
        self.options_seen = threading.Event()
        self.options_line = b'Picked up JAVA_TOOL_OPTIONS: '+options.encode('utf8')
        self.threads = [threading.Thread(target=self._stdout, daemon=True),
                        threading.Thread(target=self._stderr, daemon=True)]
        started = []
        try:
            for thread in self.threads:
                thread.start(); started.append(thread)
        except Exception:
            _cleanup(process, job=process._ram_job, threads=started)
            raise

    def _stdout(self):
        try:
            while True:
                self.messages.put_nowait(_read_frame(self.process.stdout))
        except EOFError:
            self.ended.set()
        except Exception:
            self.failed.set()

    def _stderr(self):
        total, startup = 0, bytearray()
        try:
            while piece := self.process.stderr.read(4096):
                total += len(piece)
                if total > 65536:
                    self.failed.set(); break
                if not self.options_seen.is_set():
                    startup.extend(piece)
                    while b'\n' in startup:
                        line, _, tail = startup.partition(b'\n'); startup = bytearray(tail)
                        if line.rstrip(b'\r') == self.options_line:
                            self.options_seen.set(); startup.clear(); break
        except Exception:
            self.failed.set()

    def send(self, row, deadline):
        _need(time.monotonic() < deadline, 'TIMEOUT')
        raw = json.dumps(dict(jsonrpc='2.0', **row), ensure_ascii=False, allow_nan=False).encode('utf8')
        _need(len(raw) <= MAX_FRAME, 'SEND_BOUND')
        packet = b'Content-Length: '+str(len(raw)).encode()+b'\r\n\r\n'+raw
        done, failed = threading.Event(), threading.Event()
        def write():
            try:
                offset = 0
                while offset < len(packet):
                    count = self.process.stdin.write(packet[offset:])
                    if not count:
                        failed.set(); break
                    offset += count
                self.process.stdin.flush()
            except Exception:
                failed.set()
            finally:
                done.set()
        writer = threading.Thread(target=write, daemon=True)
        self.threads.append(writer); writer.start()
        _need(done.wait(timeout=max(0, deadline-time.monotonic())), 'TIMEOUT')
        _need(not failed.is_set(), 'PIPE_WRITE')

    def receive(self, deadline):
        while time.monotonic() < deadline:
            try:
                return self.messages.get(timeout=min(.05, max(.001, deadline-time.monotonic())))
            except queue.Empty:
                _need(not self.failed.is_set() and not self.ended.is_set() and self.process.poll() is None, 'PIPE_FAILED')
        _need(False, 'TIMEOUT')

    def response(self, request, deadline):
        for _ in range(MAX_MESSAGES):
            row = self.receive(deadline)
            if 'id' in row:
                _need(type(row['id']) is int and row['id'] == request and 'result' in row and 'error' not in row,
                      'RESPONSE_JOIN')
                return row['result']
            _need(row.get('method') in ('window/logMessage', 'window/showMessage', '$/progress'), 'RESPONSE_METHOD')
        _need(False, 'MESSAGE_BOUND')

    def dispose(self):
        # The launcher spawns a separate JVM: a Popen-only kill is insufficient.
        # This private job contains only our atomically assigned child family.
        _cleanup(self.process, job=self.process._ram_job, threads=self.threads)


def _diagnostics(params, *, uri, source, version):
    _need(type(params) is dict and params.get('uri') == uri
          and type(params.get('version')) is int and params['version'] == version, 'DIAGNOSTIC_JOIN')
    values = params.get('diagnostics')
    _need(type(values) is list and len(values) <= MAX_DIAGNOSTICS, 'DIAGNOSTIC_BOUND')
    lines = re.split('\r\n|\r|\n', source.utf8.decode('utf8'))
    lengths = [len(line.encode('utf-16-le'))//2 for line in lines]
    result = []
    for row in values:
        _need(type(row) is dict and type(row.get('code')) is str and row['code'] in CODES
              and type(row.get('severity')) is int and 1 <= row['severity'] <= 4, 'DIAGNOSTIC_KIND')
        span = row.get('range'); _need(type(span) is dict, 'DIAGNOSTIC_RANGE')
        positions = []
        for key in ('start', 'end'):
            point = span.get(key); _need(type(point) is dict, 'DIAGNOSTIC_RANGE')
            line, char = point.get('line'), point.get('character')
            _need(type(line) is int and type(char) is int and 0 <= line < len(lines)
                  and 0 <= char <= lengths[line], 'DIAGNOSTIC_RANGE')
            positions.append((line, char))
        _need(positions[0] <= positions[1], 'DIAGNOSTIC_RANGE')
        value = SyntaxDiagnostic(row['code'], row['severity'], *positions[0], *positions[1])
        _need(value not in result, 'DIAGNOSTIC_DUPLICATE'); result.append(value)
    return RamSyntaxResult(source.sha256, version, tuple(result))


def _launch(folder, config):
    # Override both global/project paths before Spring starts: existing user or
    # repository settings must not enable trace files or extra diagnostics.
    options = {'sentry.enabled': 'false', 'sentry.dsn': '', 'logging.level.root': 'OFF',
               'app.configuration.path': config.as_posix(), 'app.globalConfiguration.path': config.as_posix(),
               'app.cache.fullPath': (folder/'cache').as_posix(), 'app.platform-context.enabled': 'false',
               'user.home': folder.as_posix()}
    env = dict(os.environ)
    for name in tuple(env):
        if name.upper().startswith(('JAVA_', '_JAVA_', 'JDK_JAVA_', 'SPRING_', 'SENTRY_', 'LOGGING_', 'APP_')):
            env.pop(name)
    env['JAVA_TOOL_OPTIONS'] = ' '.join('"-D'+key+'='+value+'"' for key, value in options.items())
    job = _Job(); process = None
    try:
        process = subprocess.Popen([str(EXE), 'lsp', '-c', str(config)], cwd=folder, env=env, bufsize=0,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0) | 4)  # CREATE_SUSPENDED
        process._ram_job = job
        job.attach_resume(process)
    except Exception:
        # Assignment/lookup failure never resumes the launcher. Its original
        # stored handle is the authority even if assignment itself was refused.
        _cleanup(process, job=job, suspended=True)
        raise
    return process, env['JAVA_TOOL_OPTIONS']


def _run(source, version, timeout):
    _backend()
    deadline = time.monotonic()+timeout
    with tempfile.TemporaryDirectory(prefix='ram-bsl-', dir=ROOT/'build') as temporary:
        folder = Path(temporary); config = folder/'syntax.json'
        config.write_text(json.dumps(CONFIGURATION, sort_keys=True), encoding='utf8')
        uri = (folder/('ram-'+uuid4().hex+'.bsl')).as_uri()  # Identifier only; never create this file.
        process, options = _launch(folder, config); pipe = None
        try:
            pipe = _Pipe(process, options)
            # A private empty workspace is needed for this backend to load the
            # syntax configuration. It cannot enumerate project/home sources.
            pipe.send(dict(id=1, method='initialize', params=dict(processId=None, rootUri=folder.as_uri(), workspaceFolders=[],
                capabilities=dict(textDocument=dict(publishDiagnostics=dict(versionSupport=True))))), deadline)
            init = pipe.response(1, deadline)
            _need(type(init) is dict and init.get('serverInfo', {}).get('version') == '1.0.5', 'INITIALIZE')
            _need(pipe.options_seen.wait(timeout=max(.001, deadline-time.monotonic())), 'JVM_OPTIONS')
            pipe.send(dict(method='initialized', params={}), deadline)
            pipe.send(dict(method='textDocument/didOpen', params=dict(textDocument=dict(
                uri=uri, languageId='bsl', version=version, text=source.utf8.decode('utf8')))), deadline)
            result = None
            for _ in range(MAX_MESSAGES):
                row = pipe.receive(deadline)
                _need('id' not in row, 'DIAGNOSTIC_RESPONSE')
                if row.get('method') == 'textDocument/publishDiagnostics':
                    result = _diagnostics(row.get('params'), uri=uri, source=source, version=version); break
                _need(row.get('method') in ('window/logMessage', 'window/showMessage', '$/progress'), 'DIAGNOSTIC_METHOD')
            _need(result is not None, 'MESSAGE_BOUND')
            pipe.send(dict(method='textDocument/didClose', params=dict(textDocument=dict(uri=uri))), deadline)
            pipe.send(dict(id=2, method='shutdown', params=None), deadline)
            # didClose publishes one empty diagnostic row before shutdown.
            closed = False
            for _ in range(MAX_MESSAGES):
                row = pipe.receive(deadline)
                if 'id' in row:
                    # This pinned backend returns Boolean.TRUE for shutdown.
                    _need(type(row['id']) is int and row['id'] == 2 and row.get('result') is True
                          and 'error' not in row, 'SHUTDOWN'); break
                if row.get('method') == 'textDocument/publishDiagnostics':
                    params = row.get('params', {})
                    _need(type(params) is dict and params.get('uri') == uri
                          and not closed and params.get('diagnostics') == []
                          and (params.get('version') is None or
                               (type(params.get('version')) is int and params['version'] == version)), 'LATE_DIAGNOSTIC')
                    closed = True
                else:
                    _need(row.get('method') in ('window/logMessage', 'window/showMessage', '$/progress'), 'SHUTDOWN_METHOD')
            else:
                _need(False, 'MESSAGE_BOUND')
            pipe.send(dict(method='exit', params=None), deadline); process.stdin.close()
            _need(process.wait(timeout=max(.001, deadline-time.monotonic())) == 0, 'PROCESS_EXIT')
            pipe.threads[0].join(timeout=1); pipe.threads[1].join(timeout=1)
            _need(pipe.ended.is_set() and not pipe.failed.is_set() and pipe.messages.empty(), 'LATE_FRAME')
            return result
        finally:
            if pipe is not None:
                pipe.dispose()
            else:
                _cleanup(process, job=process._ram_job)


def analyze_syntax(source, *, version, timeout=45.):
    """Analyze one immutable RAM revision; return only safe syntax metadata.

    Starts one owned offline LSP child. Creates/removes only private technical
    JSON and empty typo-cache metadata. Only its private empty workspace may be
    enumerated; never the project/home. No save, MCP or 1C call.
    A timeout/protocol ambiguity is refused; no implicit restart/retry occurs.
    """
    failure = None; result = None
    try:
        _need(type(source) is ModuleText, 'SOURCE'); source.validate()
        _need(type(version) is int and 1 <= version <= 0x7fffffff, 'VERSION')
        _need(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 120, 'TIMEOUT_BOUND')
        result = _run(source, version, timeout)
    except _Rejected as error:
        failure = str(error)
    except Exception:
        failure = 'BACKEND_FAILURE'
    if failure is not None:
        # Raise outside the handler so codec/process errors retain no raw cause
        # or context (UnicodeError.object and subprocess output can hold text).
        raise RamBslRefusal('RAM_BSL_'+failure)
    return result
