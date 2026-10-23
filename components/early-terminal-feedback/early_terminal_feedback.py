"""Explicit early-terminal feedback for an existing single-reader pipe.

This standalone helper installs nothing and never grants native closure,
retry, source-write or cleanup authority. A trusted owner supplies the callback.
"""
from dataclasses import dataclass
import inspect
import time
from . import editor_command as command_wire

class EditorPipeRefusal(RuntimeError):
    """Fixed error code; never reflect body, peer, OS or callback details."""


class EditorTerminalUnknown(EditorPipeRefusal):
    """Bound final failure observed; never native closure or retry authority."""


@dataclass(frozen=True, slots=True)
class _TerminalUnknownFeedback:
    binding: command_wire.EditorBinding
    sequence: int
    opcode: int
    diagnostic_sha256: str
    result_sha256: str
    resources_closed: bool = False
    no_authority: bool = True
    retry_authorized: bool = False
    native_cleanup_authorized: bool = False
    sdk_epoch_clean: bool = False
    worker_terminal_verified: bool = False


def _terminal_feedback(value, command):
    return (type(value) is _TerminalUnknownFeedback and value.binding is command.binding
        and type(value.sequence) is int and value.sequence == command.sequence
        and type(value.opcode) is int and value.opcode == command.opcode
        and all(type(v) is str and len(v) == 64 and v != '0' * 64 and all(ch in '0123456789abcdef' for ch in v)
            for v in (value.diagnostic_sha256, value.result_sha256))
        and value.no_authority is True and all(v is False for v in (value.resources_closed,
            value.retry_authorized, value.native_cleanup_authorized, value.sdk_epoch_clean,
            value.worker_terminal_verified)))


def _need(ok, code):
    if not ok:
        raise EditorPipeRefusal('EDITOR_PIPE_' + code)


class HeaderObserver:
    def _read_header_observed(self, count, deadline, abandoned, observer, command):
        """Observe only before empty header reads; never cancel pending I/O.

        One owner consumes this pipe. Peek counts bytes without copying them;
        the frozen read primitive runs only when those bytes are available.
        Advisory callback errors/foreign values keep the original deadline.
        """
        value = bytearray()
        while len(value) < count:
            _need(not abandoned(), 'ABANDONED')
            _need(time.monotonic() < deadline, 'DEADLINE_BEFORE_READ')
            available, left = self._api.w.PeekNamedPipe(self._handle, 0)
            _need(type(available) is int and 0 <= available <= 0xffffffff
                  and type(left) is int and 0 <= left <= 0xffffffff, 'PEEK')
            if available:
                raw = self._read(min(available, count - len(value)), deadline)
                _need(type(raw) is bytes and 0 < len(raw) <= min(available, count - len(value)), 'TRUNCATED')
                value.extend(raw)
                continue
            feedback = None;known = False
            try:
                feedback = observer()
                if inspect.isawaitable(feedback):
                    if inspect.iscoroutine(feedback): feedback.close()
                    feedback = None
                known = _terminal_feedback(feedback, command)
            except Exception:
                feedback = None
            if known:
                raise EditorTerminalUnknown('EDITOR_PIPE_TERMINAL_UNKNOWN')
            time.sleep(max(0, min(.05, deadline - time.monotonic())))
        return bytes(value)

TerminalUnknownFeedback = _TerminalUnknownFeedback
