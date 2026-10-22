"""Explicit reusable RAM syntax owner; the frozen one-shot analyzer is unchanged."""
import json
import math
from pathlib import Path
import tempfile
import threading
import time
from uuid import uuid4

from .ram_bsl_analysis import (
    CONFIGURATION, MAX_MESSAGES, ROOT, ModuleText, RamBslRefusal,
    _Rejected, _need, _backend, _launch, _cleanup, _Pipe, _diagnostics,
)


class PersistentRamSyntaxAnalyzer:
    """Opt-in syntax-only JVM owner; each call opens and retires one RAM revision.

    Use as a context manager or call close(). No snapshots/results are cached.
    Concurrent calls are refused. A timeout or protocol ambiguity closes the
    entire private job permanently; there is no implicit restart or retry.
    The existing one-shot analyze_syntax entry point is unchanged.
    """
    def __init__(self, *, timeout=45.):
        self._lock = threading.Lock()
        self._directory = self._process = self._pipe = None
        self._closed, self._request = False, 1
        failure = None
        try:
            self._timeout(timeout)
            _backend()
            deadline = time.monotonic()+timeout
            self._directory = tempfile.TemporaryDirectory(prefix='ram-bsl-persistent-', dir=ROOT/'build')
            self._folder = Path(self._directory.name)
            config = self._folder/'syntax.json'
            config.write_text(json.dumps(CONFIGURATION, sort_keys=True), encoding='utf8')
            self._process, options = _launch(self._folder, config)
            self._pipe = _Pipe(self._process, options)
            self._pipe.send(dict(id=1, method='initialize', params=dict(processId=None,
                rootUri=self._folder.as_uri(), workspaceFolders=[], capabilities=dict(
                    textDocument=dict(publishDiagnostics=dict(versionSupport=True))))), deadline)
            init = self._pipe.response(1, deadline)
            _need(type(init) is dict and init.get('serverInfo', {}).get('version') == '1.0.5', 'INITIALIZE')
            _need(self._pipe.options_seen.wait(timeout=max(.001, deadline-time.monotonic())), 'JVM_OPTIONS')
            self._pipe.send(dict(method='initialized', params={}), deadline)
        except _Rejected as error:
            failure = str(error)
        except Exception:
            failure = 'BACKEND_FAILURE'
        if failure is not None:
            try:
                self._dispose()
            except Exception:
                failure = 'PIPE_CLEANUP'
            raise RamBslRefusal('RAM_BSL_'+failure)

    @staticmethod
    def _timeout(timeout):
        _need(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 120, 'TIMEOUT_BOUND')

    def _dispose(self):
        self._closed = True
        try:
            if self._pipe is not None:
                self._pipe.dispose()
            elif self._process is not None:
                _cleanup(self._process, job=self._process._ram_job)
        finally:
            # Only technical metadata was ever written into this owned folder.
            if self._directory is not None:
                self._directory.cleanup()

    def _notice(self, row):
        _need('id' not in row and row.get('method') in
              ('window/logMessage', 'window/showMessage', '$/progress'), 'DIAGNOSTIC_METHOD')

    def analyze_syntax(self, source, *, version, timeout=45.):
        """Return safe metadata for this exact source/version, then retire its URI.

        Repeated caller versions are valid: every invocation has a fresh URI.
        didClose must publish its empty diagnostic before a request barrier;
        another document's diagnostics can never satisfy the current call.
        """
        failure = result = None
        acquired = self._lock.acquire(blocking=False)
        if not acquired:
            raise RamBslRefusal('RAM_BSL_BUSY')
        try:
            _need(not self._closed, 'CLOSED')
            _need(type(source) is ModuleText, 'SOURCE'); source.validate()
            _need(type(version) is int and 1 <= version <= 0x7fffffff, 'VERSION')
            self._timeout(timeout)
            deadline = time.monotonic()+timeout
            pipe = self._pipe
            _need(not pipe.failed.is_set() and not pipe.ended.is_set()
                  and self._process.poll() is None, 'PIPE_FAILED')
            uri = (self._folder/('ram-'+uuid4().hex+'-'+str(self._request)+'.bsl')).as_uri()
            pipe.send(dict(method='textDocument/didOpen', params=dict(textDocument=dict(
                uri=uri, languageId='bsl', version=version, text=source.utf8.decode('utf8')))), deadline)
            for _ in range(MAX_MESSAGES):
                row = pipe.receive(deadline)
                if row.get('method') == 'textDocument/publishDiagnostics':
                    _need('id' not in row, 'DIAGNOSTIC_RESPONSE')
                    result = _diagnostics(row.get('params'), uri=uri, source=source, version=version)
                    break
                self._notice(row)
            _need(result is not None, 'MESSAGE_BOUND')
            pipe.send(dict(method='textDocument/didClose', params=dict(textDocument=dict(uri=uri))), deadline)
            for _ in range(MAX_MESSAGES):
                row = pipe.receive(deadline)
                if row.get('method') == 'textDocument/publishDiagnostics':
                    params = row.get('params')
                    _need('id' not in row and type(params) is dict and params.get('uri') == uri
                          and params.get('diagnostics') == [] and (params.get('version') is None or
                          (type(params.get('version')) is int and params['version'] == version)), 'LATE_DIAGNOSTIC')
                    break
                self._notice(row)
            else:
                _need(False, 'MESSAGE_BOUND')
            # The workspace is our empty technical folder. Querying a unique
            # nonexistent symbol acknowledges retirement without source input.
            self._request += 1
            pipe.send(dict(id=self._request, method='workspace/symbol', params=dict(query=uuid4().hex)), deadline)
            _need(pipe.response(self._request, deadline) == [], 'RETIREMENT_BARRIER')
            # Completed writer threads retain no packet; discard their wrappers
            # so a long-lived process has bounded Python bookkeeping as well.
            pipe.threads[:] = [thread for thread in pipe.threads if thread.is_alive()]
        except _Rejected as error:
            failure = str(error)
        except Exception:
            failure = 'BACKEND_FAILURE'
        finally:
            if failure is not None and not self._closed:
                try:
                    self._dispose()
                except Exception:
                    failure = 'PIPE_CLEANUP'
            self._lock.release()
        if failure is not None:
            raise RamBslRefusal('RAM_BSL_'+failure)
        return result

    def close(self, *, timeout=5.):
        """Retire this explicit owner and join every private job descendant."""
        failure = None
        with self._lock:
            if self._closed:
                return
            try:
                self._timeout(timeout)
                deadline = time.monotonic()+timeout
                self._request += 1
                self._pipe.send(dict(id=self._request, method='shutdown', params=None), deadline)
                _need(self._pipe.response(self._request, deadline) is True, 'SHUTDOWN')
                self._pipe.send(dict(method='exit', params=None), deadline)
                self._process.stdin.close()
            except _Rejected as error:
                failure = str(error)
            except Exception:
                failure = 'BACKEND_FAILURE'
            finally:
                try:
                    # The pinned JVM can keep executor threads alive after its
                    # acknowledged shutdown. Retire the whole private job;
                    # waiting for the launcher alone would retain descendants.
                    self._dispose()
                    if failure is None:
                        _need(self._pipe.ended.is_set() and not self._pipe.failed.is_set()
                              and self._pipe.messages.empty(), 'LATE_FRAME')
                except Exception:
                    failure = 'PIPE_CLEANUP'
        if failure is not None:
            raise RamBslRefusal('RAM_BSL_'+failure)

    def __enter__(self):
        if self._closed:
            raise RamBslRefusal('RAM_BSL_CLOSED')
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        # Explicit close is required for observable errors. If an owner is
        # abandoned, still attempt to retire only its private process family.
        if not getattr(self, '_closed', True):
            try:
                self._dispose()
            except Exception:
                pass
