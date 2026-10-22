"""Protected V3 editor channel; one handle owner, no native installation.

Only explicitly supplied commands/capabilities are authoritative. A timeout
seals the channel; it never reconnects, repeats a setter or releases native RAM.
Root must independently prove SDK/worker/host closure after this local channel.
"""
from dataclasses import dataclass, field
import hashlib
import inspect
import math
from pathlib import Path
import queue
import threading
import time
from uuid import uuid4

from . import editor_command as command_wire
from . import editor_transport as wire
from . import editor_repository_transport as repository_wire
from . import editor_capture_transport as capture_wire
from . import editor_activation_transport as activation_wire
from . import windows_live_ram_pipe as primitive

PRIMITIVE_SHA = '6bc066d3860bd3cda9b657459979f08e83a985c8e488c7b616d819e767564c1c'
TRANSPORT_SHA = '772567491fad6a0ce5f019b140eb61255a03fe3698c558d80a99f54804a74b2c'
COMMAND_SHA = 'b56fa3499b7d59546c8b0a5bd68407e8437679b546c0093f0870f4881942a82c'
REPOSITORY_TRANSPORT_SHA = '5b4a923288a97a7bcc02c166775e605ad0d9acb8a890d2dd60fbc8925026804d'
CAPTURE_TRANSPORT_SHA = 'bca7ecb0de3414cf68ce22a7ff3321b367aab42f6ffaac049452900e8aec958e'
ACTIVATION_TRANSPORT_SHA = '155c9d2bca98a7d4c68f7f460d054bcb614989080b7af96b5f55650cab8645b0'


class EditorPipeRefusal(RuntimeError):
    """Fixed error code; never reflect body, peer, OS or callback details."""


def _need(ok, code):
    if not ok:
        raise EditorPipeRefusal('EDITOR_PIPE_' + code)


def _duration(value, maximum):
    return type(value) in (int, float) and math.isfinite(value) and .001 <= value <= maximum


def _accepted(validator, value):
    answer = validator(value)
    if inspect.isawaitable(answer):
        if inspect.iscoroutine(answer):
            answer.close()
        raise EditorPipeRefusal('EDITOR_PIPE_ASYNC_VALIDATOR')
    _need(answer is True, 'VALIDATOR_REFUSED')


class _Pipe(primitive._Inbox):
    def __init__(self, pid, birth):
        self._api = primitive.ready._DuplexApi()
        self._owner_thread = threading.get_ident()
        self._pid, self._birth = pid, birth
        self._handle = self._process = None
        self._path = '\\\\.\\pipe\\AH1C-LIVE-RESIDENT-' + uuid4().hex
        try:
            self._process = self._api.pin_process(pid, birth)
            self._handle = self._api.create(self._path)
        except BaseException:
            self.close()
            raise

    def identity(self):
        row = super().identity('0' * 32)
        return {key: row[key] for key in ('pipePath', 'serverPid', 'serverBirth')}

    def _write_exact(self, raw, deadline):
        # The frozen primitive checks its wait deadline after issuing I/O.
        # Commands and ACKs additionally require admission before each write.
        offset = 0
        while offset < len(raw):
            _need(time.monotonic() < deadline, 'DEADLINE_BEFORE_WRITE')
            ov, _ = self._api.w.WriteFile(self._handle, raw[offset:], overlapped=True)
            count, error = self._complete(ov, deadline)
            _need(error == 0 and 0 < count <= len(raw) - offset, 'WRITE')
            offset += count

    def connect_editor(self, binding, deadline, abandoned):
        ov = self._api.w.ConnectNamedPipe(self._handle, overlapped=True)
        _, error = self._complete(ov, deadline)
        _need(error == 0, 'CONNECT')
        self._live()
        _need(not abandoned(), 'ABANDONED')
        raw = self._read_exact(wire.READY_BYTES, deadline)
        self._live()
        _need(not abandoned(), 'ABANDONED')
        return wire.parse_ready(raw, binding=binding, now=time.monotonic())

    def exchange_editor(self, raw, command, installation, previous, nonces,
                        capability, totals, validator, deadline, abandoned):
        ack_sha = None
        accepted = False
        capture = None
        def context():
            return dict(binding=command.binding, installation=installation,
                        command=command, now=time.monotonic(), previous_sequence=previous,
                        capability=capability, used_nonces=nonces)
        try:
            self._live()
            _need(not abandoned(), 'ABANDONED')
            self._write_exact(raw, deadline)
            header = self._read_exact(wire.HEADER_BYTES, deadline)
            sizes = wire.parse_response_header(header, command=command)
            raw = header + self._read_exact(sizes.metadata_length + sizes.body_length, deadline)
            self._live()
            _need(not abandoned(), 'ABANDONED')
            if command.opcode == command_wire.CLOSE:
                capture = wire.parse_close_frame(raw, expected_totals=totals, **context())
                ack_sha = wire.EMPTY_SHA256
                canonical = wire.build_close_frame(capture, expected_totals=totals, **context())
                _accepted(validator, capture)
                _need(wire.build_close_frame(capture, expected_totals=totals, **context()) == canonical,
                      'VALIDATOR_MUTATION')
                self._live()
                _need(not abandoned(), 'ABANDONED')
                self._write_exact(wire.build_ack(command, ack_sha, accepted=True), deadline)
                accepted = True
                wire.parse_release(self._read_exact(wire.RELEASE_BYTES, deadline),
                                   capture=capture, expected_totals=totals, **context())
                _need(not self._read(1, deadline), 'TRAILING_CLOSE')
                self._live()
                _need(not abandoned(), 'ABANDONED')
                return capture
            capture = wire.parse_editor_frame(raw, **context())
            refused = type(capture) is wire.EditorReadRefusal
            if command.opcode == 4:
                build_frame, finish = repository_wire.build_repository_frame, repository_wire.finish_repository
            elif command.opcode == command_wire.CAPTURE_ONLY:
                build_frame, finish = capture_wire.build_capture_only_frame, capture_wire.finish_capture_only
            elif command.opcode == command_wire.ACTIVATE_OWN6:
                build_frame, finish = activation_wire.build_activation_frame, activation_wire.finish_activation
            else:
                mismatch = type(capture) is wire.EditorRestoredStateMismatch
                applied = type(capture) is wire.EditorApplied
                build_frame = (wire.build_applied_frame if applied
                               else wire.build_restored_state_mismatch_frame if mismatch
                               else wire.build_refusal_frame if refused else wire.build_capture_frame)
                finish = (wire.finish_applied if applied
                          else wire.finish_restored_state_mismatch if mismatch
                          else wire.finish_refusal if refused else wire.finish_capture)
            ack_sha = wire.EMPTY_SHA256 if refused else capture.body_sha256
            canonical = build_frame(capture, **context())
            raw = None
            _accepted(validator, capture)
            _need(build_frame(capture, **context()) == canonical, 'VALIDATOR_MUTATION')
            self._live()
            _need(not abandoned() and time.monotonic() <= deadline, 'ABANDONED')
            self._write_exact(wire.build_ack(command, ack_sha, accepted=True), deadline)
            accepted = True
            release_raw = self._read_exact(wire.RELEASE_BYTES, deadline)
            released = wire.parse_release(release_raw, capture=capture, **context())
            self._live()
            _need(not abandoned(), 'ABANDONED')
            return finish(capture, released, **context())
        except BaseException:
            if not accepted and ack_sha is not None:
                try:
                    self._write_exact(wire.build_ack(command, ack_sha, accepted=False), deadline)
                except BaseException:
                    pass
            raise
        finally:
            capture = None
            raw = None


@dataclass(slots=True)
class _Job:
    kind: str
    command: object = field(default=None, repr=False)
    raw: bytes | None = field(default=None, repr=False)
    capability: object = field(default=None, repr=False)
    validator: object = field(default=None, repr=False)
    done: threading.Event = field(default_factory=threading.Event, repr=False)
    result: object = field(default=None, repr=False)
    error: str | None = None
    abandoned: bool = False


class EditorChannel:
    """Reserve a local protected pipe; connect only after explicit RootRun.

    Commands, validation, ACK and release are serialized on a dedicated thread.
    EOF and timeout prove no native outcome. No automatic installation or retry.
    """
    def __init__(self, binding, *, timeout=60.0, wait_timeout=75.0):
        for module, pin in ((wire, TRANSPORT_SHA), (command_wire, COMMAND_SHA),
                            (repository_wire, REPOSITORY_TRANSPORT_SHA),
                            (capture_wire, CAPTURE_TRANSPORT_SHA),
                            (activation_wire, ACTIVATION_TRANSPORT_SHA),
                            (primitive, PRIMITIVE_SHA)):
            _need(hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() == pin, 'DEPENDENCY_PIN')
        _need(type(binding) is command_wire.EditorBinding, 'BINDING')
        binding.validate()
        _need(_duration(timeout, 90) and _duration(wait_timeout, 120), 'TIMEOUT')
        self._binding = binding
        self._timeout, self._wait_timeout = float(timeout), float(wait_timeout)
        self._lock = threading.Lock()
        self._queue = queue.Queue(maxsize=1)
        self._ready, self._exited, self._stop = threading.Event(), threading.Event(), threading.Event()
        self._identity = self._installation = None
        self._last_sequence, self._nonces = 0, set()
        self._totals = wire.EditorTotals()
        self._busy = self._sealed = self._connect_submitted = False
        self._close_only = False
        self._edit_attempted = self._after_applied = False
        self._handles_closed = self._startup_error = False
        self._thread = threading.Thread(target=self._owner, name='AH1C V3 editor pipe owner', daemon=True)
        try:
            self._thread.start()
            _need(self._ready.wait(5), 'RESERVE_UNKNOWN')
            _need(self._identity is not None and not self._startup_error, 'RESERVE')
        except BaseException:
            with self._lock:
                self._sealed = True
                self._stop.set()
                try:
                    self._queue.put_nowait(None)
                except queue.Full:
                    pass
            raise

    @property
    def identity(self):
        return dict(self._identity)

    @property
    def path(self):
        return self._identity['pipePath']

    @property
    def sealed(self):
        with self._lock:
            return self._sealed

    @property
    def close_only(self):
        with self._lock:
            return self._close_only

    @property
    def closed(self):
        return self._exited.is_set() and self._handles_closed

    @property
    def owner_thread_alive(self):
        return self._thread.is_alive()

    @property
    def last_sequence(self):
        with self._lock:
            return self._last_sequence

    @property
    def totals(self):
        with self._lock:
            return self._totals

    def _abandoned(self, job):
        with self._lock:
            return job.abandoned or self._stop.is_set()

    def _abandon(self, job):
        with self._lock:
            job.abandoned = True
            job.result = None
            self._sealed = True
            self._stop.set()
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass

    def _submit(self, job):
        queued = False
        try:
            with self._lock:
                _need(not self._sealed and not self._exited.is_set(), 'SEALED')
                _need(not self._close_only or (job.kind == 'close'
                      and job.command.opcode == command_wire.CLOSE), 'RESTORED_MISMATCH_CLOSE_ONLY')
                _need(not self._after_applied or (job.kind in ('exchange', 'close')
                      and job.command.opcode in (command_wire.READ_MODULE, command_wire.CLOSE)),
                      'APPLIED_READ_CLOSE_ONLY')
                _need(not self._busy, 'BUSY')
                if job.kind == 'connect':
                    _need(not self._connect_submitted, 'CONNECT_PHASE')
                    queued = True
                    self._connect_submitted = True
                else:
                    _need(self._installation is not None, 'CONNECT_REQUIRED')
                    _need(not self._edit_attempted or job.command.opcode != command_wire.EDIT_MODULE,
                          'ONE_EDIT_ONLY')
                    job.raw = command_wire.build_command(job.command, binding=self._binding,
                        previous_sequence=self._last_sequence, capability=job.capability,
                        used_nonces=tuple(self._nonces))
                    command_wire.parse_command(job.raw, binding=self._binding,
                        expected_command=job.command, previous_sequence=self._last_sequence,
                        capability=job.capability, used_nonces=tuple(self._nonces))
                    _need((job.command.opcode == command_wire.CLOSE) == (job.kind == 'close'), 'OPCODE')
                    if job.command.opcode == command_wire.EDIT_MODULE:
                        # Latch an accepted attempt, never infer it from mutable
                        # public totals or a later restored/APPLIED outcome.
                        self._edit_attempted = True
                self._busy = True
                self._queue.put_nowait(job)
                queued = True
            if not job.done.wait(self._wait_timeout):
                with self._lock:
                    _need(job.done.is_set(), 'ACTIVE_UNKNOWN')
            if job.error is not None:
                raise EditorPipeRefusal(job.error)
            with self._lock:
                result, job.result = job.result, None
            return result
        except BaseException:
            if queued:
                self._abandon(job)
            raise

    def connect(self):
        return self._submit(_Job('connect'))

    def exchange(self, command, validator, *, capability=None):
        _need(callable(validator) and not inspect.iscoroutinefunction(validator), 'VALIDATOR')
        return self._submit(_Job('exchange', command=command, capability=capability, validator=validator))

    def close(self, command, validator):
        _need(callable(validator) and not inspect.iscoroutinefunction(validator), 'VALIDATOR')
        result = self._submit(_Job('close', command=command, validator=validator))
        _need(self.wait_closed(5) and self.closed, 'LOCAL_CLOSE')
        return result

    def abort_before_connect(self):
        with self._lock:
            _need(not self._connect_submitted and not self._busy and not self._sealed, 'ABORT_PHASE')
            self._sealed = True
            self._stop.set()
            self._queue.put_nowait(None)

    def wait_closed(self, timeout=5.0):
        _need(type(timeout) in (int, float) and math.isfinite(timeout) and 0 <= timeout <= 120, 'WAIT_TIMEOUT')
        _need(threading.get_ident() != self._thread.ident, 'OWNER_WAIT')
        return self._exited.wait(timeout)

    def _owner(self):
        pipe = job = result = command = None
        try:
            try:
                pipe = _Pipe(self._binding.process_id, self._binding.birth)
                with self._lock:
                    self._identity = pipe.identity()
            except BaseException:
                with self._lock:
                    self._startup_error = self._sealed = True
                return
            finally:
                self._ready.set()
            while not self._stop.is_set():
                job = self._queue.get()
                if job is None:
                    return
                terminal, result, error = False, None, None
                try:
                    _need(not self._abandoned(job), 'ABANDONED')
                    deadline = time.monotonic() + self._timeout
                    if job.kind == 'connect':
                        result = pipe.connect_editor(self._binding, deadline, lambda: self._abandoned(job))
                        _need(not self._abandoned(job), 'ABANDONED')
                        with self._lock:
                            self._installation = result
                    else:
                        command = command_wire.parse_command(job.raw, binding=self._binding,
                            expected_command=job.command, previous_sequence=self._last_sequence,
                            capability=job.capability, used_nonces=tuple(self._nonces))
                        _need(not self._close_only or (job.kind == 'close'
                              and command.opcode == command_wire.CLOSE), 'RESTORED_MISMATCH_CLOSE_ONLY')
                        _need(not self._after_applied or command.opcode in
                              (command_wire.READ_MODULE, command_wire.CLOSE), 'APPLIED_READ_CLOSE_ONLY')
                        deadline = min(deadline, self._installation.valid_until +
                                       (60 if job.kind == 'close' else 0))
                        result = pipe.exchange_editor(job.raw, command, self._installation,
                            self._last_sequence, tuple(self._nonces), job.capability, self._totals,
                            job.validator, deadline, lambda: self._abandoned(job))
                        _need(not self._abandoned(job), 'ABANDONED')
                        with self._lock:
                            self._nonces.add(command.nonce)
                            if job.kind != 'close':
                                self._last_sequence = command.sequence
                                self._totals = wire.advance_totals(self._totals, result)
                                if type(result) is wire.EditorRestoredStateMismatchSnapshot:
                                    # A known functional mismatch still completes release;
                                    # retain this owner solely for its ordinary CLOSE.
                                    self._close_only = True
                                elif type(result) is wire.EditorAppliedSnapshot:
                                    self._after_applied = True
                        terminal = job.kind == 'close'
                except BaseException:
                    terminal, error, result = True, 'EDITOR_PIPE_TRANSACTION_UNPROVEN', None
                if terminal:
                    try:
                        pipe.close()
                        self._handles_closed = True
                    except BaseException:
                        error, result = 'EDITOR_PIPE_LOCAL_CLOSE_UNPROVEN', None
                with self._lock:
                    terminal = terminal or job.abandoned or self._stop.is_set()
                    if terminal:
                        self._sealed = True
                    job.result = None if job.abandoned or error else result
                    job.error = 'EDITOR_PIPE_ACTIVE_UNKNOWN' if job.abandoned else error
                    job.raw = job.command = job.capability = job.validator = None
                    self._busy = False
                    job.done.set()
                job = result = command = None
                if terminal:
                    return
        finally:
            result = command = None
            if pipe is not None:
                try:
                    pipe.close()
                    self._handles_closed = True
                except BaseException:
                    self._handles_closed = False
            with self._lock:
                self._sealed = True
            self._ready.set()
            self._exited.set()
