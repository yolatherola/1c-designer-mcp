# Early terminal feedback for a pipe header wait

This experimental component stops an empty response-header wait when a trusted
owner supplies bound terminal-failure feedback. It checks available bytes with
`PeekNamedPipe` before issuing a read. Available data takes priority; incomplete,
foreign, asynchronous or failed callback results retain the original deadline.

The component does not install a bridge, launch a native worker, authenticate a
diagnostic file, close native references, retry a command or permit a write.
The integrating owner must independently validate the diagnostic and result,
including their exact operation, command, state and immutable publication.
`EditorTerminalUnknown` means uncertainty remains. It is not successful resource
closure or proof that the worker exited.

## Explicit integration

Load `early_terminal_feedback.py` as `native_mcp.early_terminal_feedback` beside
the existing source snapshot's `native_mcp.editor_command`. The snapshot is
unchanged. This component is not automatically wired into its editor channel.

Call `HeaderObserver._read_header_observed(pipe, header_bytes, deadline,
abandoned, observer, command)` from the pipe's single owner thread. The supplied
pipe must expose `_handle`, `_api.w.PeekNamedPipe(handle, 0)` returning available
and remaining byte counts, and `_read(count, deadline)` returning bytes. Only
bytes already reported available are requested. Never introduce a second reader.

The synchronous observer returns `None` while evidence is insufficient, or an
exact `TerminalUnknownFeedback` bound to the same `command.binding` object,
sequence, opcode and nonzero diagnostic/result SHA256 values. The integrator
must preserve the ordinary transaction deadline and its separate recovery
policy when catching `EditorTerminalUnknown`. SHA values and the feedback
object alone are not native authority. Leave the original header reader in use
when this opt-in path is not explicitly enabled.

## Reproducible checks

```sh
python -B -m unittest discover -s components/early-terminal-feedback/tests -p 'test_*.py' -v
```

The tests run on the standard library with fake clocks and fake pipes. They
neither call Windows APIs nor launch processes, connect to an infobase or load
private captures. The half-second feedback scenario measures simulated time,
not production latency. Live-platform latency for this published component has
not been verified. These checks do not establish standalone runtime readiness.

## Origin and scope

The feedback types, validator and header-reader method are exact source
extractions from our reviewed pipe implementation. Public snapshot command
bindings are reused. This isolates the header-wait change from unrelated editor
session and transport changes in the working backend. No third-party source or
SDK/binary payload is added. The repository's existing license status remains
unchanged; this is source publication, not a licensed runtime release.
