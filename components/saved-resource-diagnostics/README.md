# Saved-resource diagnostics (experimental)

Three standalone Python emitters produce bounded C diagnostics for supplied x86
MSVC C++ metadata and a four-byte exception reason. They use Python's standard
library and default to denied mode. Importing them does not load native code.

- `policy_saved_null_certificate.py` checks supplied metadata against two fixed
  type layouts, extracts a reason through a caller-provided safe copy callback,
  and validates numeric interval facts. Its results grant no native permission,
  cleanup, retry, source read, save or write authority.
- `policy_saved_reason_memory.py` emits a Win32 copy adapter for an integrating
  handler's private trusted window. It copies four bytes per eligible event,
  preserves LastError, refuses repeat attempts, and caps one interval at 32
  events / 128 bytes. The integrator must independently attest loaded images,
  establish ownership and lifetime, and retain uncertain resources.
- `backend_reason_certificate.py` adds one exact backend metadata layout in an
  isolated namespace. It reuses nine unchanged code objects from the pinned
  certificate and adapts its C template reversibly; the old layouts and globals
  remain unchanged. Its default is denied. A numeric reason belongs to the
  internal `core::FileException::Error` enum and is not interpreted as a Win32
  error or proof of a missing file. The tests use supplied synthetic bytes only.

This addition publishes the supplied-copy certificate, not the private live
source composer or a backend handler. The integrating collector's two-event /
eight-byte limit and live image qualification are not provided by this portable
module. The generic copy adapter's existing 32-event / 128-byte limit remains
unchanged. No live exception has been accepted by these portable tests.

Run the portable tests with Python 3.12+ and a C compiler:

```sh
CC=cc python -B -m unittest discover -s components/saved-resource-diagnostics/tests -v
```

`CC` may name a compiler explicitly; otherwise tests find `cc`, `gcc` or `clang`.
Missing compilers skip the C tests and do not constitute full qualification.
Tests compile and run only their own synthetic executables in temporary folders.
Their Win32 API shims and module metadata are explicitly fake: no platform DLL,
PE file, SDK, live process, database or application source is read. A successful
fixture does **not** attest a loaded module. Separate primary-binary qualification
and runtime integration remain necessary and are not reproduced by these tests.

Runtime integration, configuration saving and database updates are unverified by
this component. The code adapts existing MSVC exception-metadata and Win32 safe
copy patterns; no new third-party implementation is included. The repository's
license status applies. No install, launcher, live handler or automatic recovery
is provided.
