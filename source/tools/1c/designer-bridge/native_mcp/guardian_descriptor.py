"""Current-user encrypted guardian bootstrap, never an application source file.

The descriptor conveys one local endpoint; it neither launches a guardian nor
grants native authority. DPAPI binds the capability to this Windows user and
the exact public metadata. Kernel peer checks remain mandatory on connect.
"""
import base64
import ctypes
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import stat
from uuid import uuid4

from .windows_guardian_pipe import validate_endpoint
from .windows_ram_pipe import _Api

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
ALLOWED = ROOT / 'artifacts/designer-bridge'
PROFILE = 'AH1C_GUARDIAN_DATABASE_SAVED_READ_V1'
LIMIT = 8192
CODE_PINS = {
    'native_mcp/windows_ram_pipe.py': '54dd9a45064f34930a2dc6441c3c78cdaaeefbdf02138fcb2459830f1c57ec1e',
    'native_mcp/guardian_wire.py': '3ca907c8f4df783cba01f63fb002e86c9cb2a262f504b785f50a9276c938a456',
    'native_mcp/windows_guardian_pipe.py': 'c0c7a7a6a03e43d59fd29965a3b227ff337b212a577702cc5db2c76cca25e8b3',
    'native_mcp/guardian_client.py': 'a8b76c3a6c314c3bccbe07c9a56d90898d5bb01a9dd4f0839b219cd78e110ce9',
    'native_mcp/guardian_relay_server.py': '09f0adf1ac100787c00d9554527c5aaa76e4b493edf05b03dfcc53d5c90dfbfa',
    'research/run_guardian_stdio_mcp.py': 'bca07e2dd7f0f50e4aa4e2f39028ea36e84c423f663e8e9dcda5e93cfeb5b360',
}


class GuardianDescriptorRefusal(ValueError):
    """Stable metadata-only refusal; no path, capability or OS diagnostic."""


def _need(ok, code):
    if not ok:
        raise GuardianDescriptorRefusal('GUARDIAN_DESCRIPTOR_' + code)


def _canonical(row):
    return json.dumps(row, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode('ascii')


def _pairs(pairs):
    row = {}
    for key, value in pairs:
        _need(key not in row, 'DUPLICATE_KEY')
        row[key] = value
    return row


def _constant(_):
    raise GuardianDescriptorRefusal('GUARDIAN_DESCRIPTOR_NONFINITE')


def _pins():
    for relative, expected in CODE_PINS.items():
        _need(hashlib.sha256((HERE.parent / relative).read_bytes()).hexdigest() == expected, 'CODE_PIN')


def _path(path, *, existing):
    _need(isinstance(path, Path) and path.is_absolute(), 'PATH')
    _need(path.name not in ('', '.', '..') and path.suffix == '.json', 'PATH')
    _need(path.is_relative_to(ALLOWED) and path != ALLOWED, 'PATH')
    # Check every lexical component as well as final handle path. Opening with
    # OPEN_REPARSE_POINT alone does not protect against a reparse parent.
    for current in reversed((path if existing else path.parent, *(path if existing else path.parent).parents)):
        info = current.lstat()
        _need(not info.st_file_attributes & 0x400 and not stat.S_ISLNK(info.st_mode), 'REPARSE')
    _need(path.parent.resolve(strict=True) == path.parent, 'PATH')
    if existing:
        _need(path.resolve(strict=True) == path, 'PATH')
    return path


class _Blob(ctypes.Structure):
    _fields_ = [('size', W.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]


class _FileInfo(ctypes.Structure):
    _fields_ = [('attributes', W.DWORD), ('created', W.FILETIME), ('accessed', W.FILETIME),
                ('written', W.FILETIME), ('volume', W.DWORD), ('size_high', W.DWORD),
                ('size_low', W.DWORD), ('links', W.DWORD), ('index_high', W.DWORD), ('index_low', W.DWORD)]


class _Crypto(_Api):
    def __init__(self):
        super().__init__()
        self.c = ctypes.WinDLL('crypt32', use_last_error=True)
        self._bind(self.c, 'CryptProtectData', W.BOOL, [ctypes.POINTER(_Blob), W.LPCWSTR,
            ctypes.POINTER(_Blob), W.LPVOID, W.LPVOID, W.DWORD, ctypes.POINTER(_Blob)])
        self._bind(self.c, 'CryptUnprotectData', W.BOOL, [ctypes.POINTER(_Blob), W.LPVOID,
            ctypes.POINTER(_Blob), W.LPVOID, W.LPVOID, W.DWORD, ctypes.POINTER(_Blob)])
        self._bind(self.k, 'CreateFileW', W.HANDLE, [W.LPCWSTR, W.DWORD, W.DWORD,
            W.LPVOID, W.DWORD, W.DWORD, W.HANDLE])
        self._bind(self.k, 'GetFileInformationByHandle', W.BOOL, [W.HANDLE, ctypes.POINTER(_FileInfo)])
        self._bind(self.k, 'GetFinalPathNameByHandleW', W.DWORD, [W.HANDLE, W.LPWSTR, W.DWORD, W.DWORD])
        self._bind(self.k, 'ReadFile', W.BOOL, [W.HANDLE, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD), W.LPVOID])
        self._bind(self.k, 'WriteFile', W.BOOL, [W.HANDLE, W.LPCVOID, W.DWORD, ctypes.POINTER(W.DWORD), W.LPVOID])
        self._bind(self.k, 'FlushFileBuffers', W.BOOL, [W.HANDLE])
        self._bind(self.k, 'SetFileInformationByHandle', W.BOOL, [W.HANDLE, ctypes.c_int, W.LPVOID, W.DWORD])

    def crypt(self, payload, entropy, *, decrypt=False):
        _need(type(payload) is bytes and 0 < len(payload) <= LIMIT and len(entropy) == 32, 'BLOB')
        source = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
        salt = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy)
        src, extra, out = _Blob(len(payload), source), _Blob(len(entropy), salt), _Blob()
        try:
            # UI_FORBIDDEN only. LOCAL_MACHINE is deliberately absent.
            if decrypt:
                ok = self.c.CryptUnprotectData(ctypes.byref(src), None, ctypes.byref(extra),
                    None, None, 1, ctypes.byref(out))
            else:
                ok = self.c.CryptProtectData(ctypes.byref(src), 'AH1C guardian capability',
                    ctypes.byref(extra), None, None, 1, ctypes.byref(out))
            _need(ok and out.data and 0 < out.size <= LIMIT, 'DPAPI')
            return ctypes.string_at(out.data, out.size)
        finally:
            ctypes.memset(source, 0, len(payload))
            if out.data:
                ctypes.memset(out.data, 0, out.size)
                self.k.LocalFree(ctypes.cast(out.data, W.HLOCAL))

    def identity(self, endpoint):
        handle = self.k.OpenProcess(0x101000, False, endpoint['guardian_pid'])
        _need(handle, 'PROCESS_IDENTITY')
        try:
            _need(self.w.WaitForSingleObject(handle, 0) == 258
                  and self.birth(handle) == endpoint['guardian_birth'], 'PROCESS_IDENTITY')
        finally:
            self.w.CloseHandle(handle)

    def _delete(self, handle):
        # FILE_DISPOSITION_INFO has a BOOLEAN (one byte), not a Windows BOOL.
        # Microsoft Learn: winbase/ns-winbase-file_disposition_info.
        disposition = ctypes.c_ubyte(1)
        _need(self.k.SetFileInformationByHandle(handle, 4, ctypes.byref(disposition), 1), 'OWNED_CLEANUP')

    def open(self, path, *, new=False, cleanup=False):
        # No write/delete sharing; final-path/attributes are checked on the
        # same held handle used for I/O, rather than reopening after stat.
        access = (0x40000000 if new else 0x80000000) | (0x10000 if new or cleanup else 0)
        handle = self.k.CreateFileW(str(path), access,
            0 if new or cleanup else 1, None, 1 if new else 3, 0x200080, None)
        _need(handle not in (None, ctypes.c_void_p(-1).value), 'OPEN')
        try:
            info, final = _FileInfo(), ctypes.create_unicode_buffer(32768)
            _need(self.k.GetFileInformationByHandle(handle, ctypes.byref(info)), 'FILE_INFO')
            _need(not info.attributes & (0x400 | 0x10) and info.links == 1, 'FILE_KIND')
            length = self.k.GetFinalPathNameByHandleW(handle, final, len(final), 0)
            _need(0 < length < len(final) and final.value.startswith('\\\\?\\'), 'FINAL_PATH')
            _need(Path(final.value[4:]) == path, 'FINAL_PATH')
            size = (info.size_high << 32) | info.size_low
            _need(size == 0 if new else 0 < size <= LIMIT, 'FILE_SIZE')
            return handle, size, (info.volume, info.index_high, info.index_low)
        except BaseException:
            try:
                if new:
                    self._delete(handle)
            finally:
                self.w.CloseHandle(handle)
            raise

    def read(self, path):
        handle, size, _ = self.open(path)
        try:
            buffer, copied = ctypes.create_string_buffer(size), W.DWORD()
            _need(self.k.ReadFile(handle, buffer, size, ctypes.byref(copied), None)
                  and copied.value == size, 'READ')
            return buffer.raw
        finally:
            self.w.CloseHandle(handle)

    def write_new(self, path, payload):
        handle, _, identity = self.open(path, new=True)
        try:
            copied = W.DWORD()
            _need(self.k.WriteFile(handle, payload, len(payload), ctypes.byref(copied), None)
                  and copied.value == len(payload) and self.k.FlushFileBuffers(handle), 'WRITE')
            return identity
        except BaseException:
            self._delete(handle)
            raise
        finally:
            self.w.CloseHandle(handle)

    def remove_owned(self, path, identity):
        handle, _, current = self.open(_path(path, existing=True), cleanup=True)
        try:
            _need(current == identity, 'OWNED_IDENTITY')
            self._delete(handle)
        finally:
            self.w.CloseHandle(handle)


def _entropy(public):
    return hashlib.sha256(b'AH1C_GUARDIAN_ENDPOINT_V1\0' + _canonical(public)).digest()


def _public(endpoint):
    return dict(version=1, profile=PROFILE, code_pins=dict(CODE_PINS),
                endpoint={k: v for k, v in endpoint.items() if k != 'capability'})


def write_endpoint(path: Path, endpoint: dict) -> None:
    """Publish a new encrypted endpoint atomically; never overwrite a file.

    Only technical ciphertext/identity/pins are persisted. No guardian or
    native request is started. The caller retains its original RAM capability.
    """
    failed, temporary, identity = False, None, None
    try:
        path = _path(path, existing=False)
        validate_endpoint(endpoint)
        _pins()
        api = _Crypto()
        api.identity(endpoint)
        public = _public(endpoint)
        sealed = api.crypt(endpoint['capability'], _entropy(public))
        payload = _canonical(dict(public, sealed_capability=base64.b64encode(sealed).decode('ascii')))
        _need(len(payload) <= LIMIT and not path.exists(), 'EXISTS')
        temporary = path.with_name(path.stem + '.pending-' + uuid4().hex + '.json')
        identity = api.write_new(temporary, payload)
        # Windows rename is atomic and refuses an existing destination.
        os.rename(temporary, path)
        temporary = None
    except Exception:
        failed = True
    finally:
        if temporary is not None and identity is not None:
            try:
                api.remove_owned(temporary, identity)
            except Exception:
                # Never delete a colliding/replaced path. A failed cleanup
                # retains only encrypted technical metadata, with fixed error.
                failed = True
    if failed:
        raise GuardianDescriptorRefusal('GUARDIAN_DESCRIPTOR_WRITE_REFUSED')


def read_endpoint(path: Path) -> dict:
    """Validate/decrypt one endpoint, with fresh PID/birth; no pipe/native I/O."""
    failed, result = False, None
    try:
        path = _path(path, existing=True)
        _pins()
        api = _Crypto()
        data = api.read(path)
        row = json.loads(data.decode('ascii'), object_pairs_hook=_pairs, parse_constant=_constant)
        _need(type(row) is dict and row.keys() == {'version', 'profile', 'code_pins', 'endpoint', 'sealed_capability'}, 'SCHEMA')
        _need(type(row['version']) is int and row['version'] == 1 and row['profile'] == PROFILE
              and row['code_pins'] == CODE_PINS, 'PROFILE')
        _need(type(row['endpoint']) is dict and 'capability' not in row['endpoint'], 'ENDPOINT')
        endpoint = dict(row['endpoint'], capability=b'X' * 32)
        validate_endpoint(endpoint)
        _need(type(row['sealed_capability']) is str and len(row['sealed_capability']) <= 4096, 'CIPHER')
        sealed = base64.b64decode(row['sealed_capability'], validate=True)
        public = {key: row[key] for key in ('version', 'profile', 'code_pins', 'endpoint')}
        endpoint['capability'] = api.crypt(sealed, _entropy(public), decrypt=True)
        validate_endpoint(endpoint)
        api.identity(endpoint)
        result = endpoint
    except Exception:
        failed = True
    if failed:
        raise GuardianDescriptorRefusal('GUARDIAN_DESCRIPTOR_READ_REFUSED')
    return result
