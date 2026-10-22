"""Read one fixed owned runtime's command owner and other-manager metadata.

Only OS query/VM_READ calls; no SDK callback, target execution, reference
operation, source getter, save, or update. Every output is technical metadata.
An observed explicit-target binding is not permission to dispatch Update29.
"""
from pathlib import Path
from types import SimpleNamespace
import ctypes as ct
from ctypes import wintypes as w
import hashlib
import json
import struct
import sys
import uuid

# The frozen route's existing read-only lease checker is still under tests/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))

import update_owner_read as parent
import update_owner_config_route_primary as route
import update_owner_delegate_rejection_primary as delegate
import comparison_update_other_managers_read as other_managers

ROOT = parent.ROOT
PARENT = 'e88eb211f0d24104b5dc1b309a92b79e'
PARENT_NATIVE_SHA = '3818fd080975e46605efec94205b996f3618aa5d4902377c90f47c911c735c15'
PID = 48936
BIRTH = '01dd5d0180299126'
PLATFORM = Path('C:/Program Files (x86)/1cv8/8.3.18.1208/bin')


def need(ok, code):
    if not ok: raise ValueError('UPDATE_OWNER_RUNTIME_' + code)


def sha(value): return hashlib.sha256(value).hexdigest()


class VmRead:
    """Query and exact bounded reads; handles are closed on every exit."""
    def __init__(self):
        self.k = ct.WinDLL('kernel32', use_last_error=True); k = self.k
        k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]; k.OpenProcess.restype = w.HANDLE
        k.CloseHandle.argtypes = [w.HANDLE]; k.CloseHandle.restype = w.BOOL
        k.GetProcessTimes.argtypes = [w.HANDLE] + [ct.POINTER(w.FILETIME)] * 4; k.GetProcessTimes.restype = w.BOOL
        k.ReadProcessMemory.argtypes = [w.HANDLE, ct.c_void_p, ct.c_void_p, ct.c_size_t, ct.POINTER(ct.c_size_t)]
        k.ReadProcessMemory.restype = w.BOOL
        k.VirtualQueryEx.argtypes = [w.HANDLE, ct.c_void_p, ct.c_void_p, ct.c_size_t]; k.VirtualQueryEx.restype = ct.c_size_t
        k.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]; k.CreateToolhelp32Snapshot.restype = w.HANDLE

        class Entry(ct.Structure):
            _fields_ = [('dwSize', w.DWORD), ('th32ModuleID', w.DWORD), ('th32ProcessID', w.DWORD),
                        ('GlblcntUsage', w.DWORD), ('ProccntUsage', w.DWORD), ('modBaseAddr', ct.c_void_p),
                        ('modBaseSize', w.DWORD), ('hModule', w.HMODULE), ('szModule', w.WCHAR * 256), ('szExePath', w.WCHAR * 260)]
        self.Entry = Entry
        k.Module32FirstW.argtypes = [w.HANDLE, ct.POINTER(Entry)]; k.Module32FirstW.restype = w.BOOL
        k.Module32NextW.argtypes = [w.HANDLE, ct.POINTER(Entry)]; k.Module32NextW.restype = w.BOOL

        class Page(ct.Structure):
            _fields_ = [('BaseAddress', ct.c_void_p), ('AllocationBase', ct.c_void_p), ('AllocationProtect', w.DWORD),
                        ('RegionSize', ct.c_size_t), ('State', w.DWORD), ('Protect', w.DWORD), ('Type', w.DWORD)]
        self.Page = Page
        self.handle = k.OpenProcess(0x410, False, PID)
        need(bool(self.handle), 'OPEN_VM_READ')

    def close(self):
        if self.handle: self.k.CloseHandle(self.handle); self.handle = None

    def identity(self):
        times = [w.FILETIME() for _ in range(4)]
        need(self.k.GetProcessTimes(self.handle, *[ct.byref(x) for x in times]), 'PROCESS_TIMES')
        need(f'{(times[0].dwHighDateTime << 32) | times[0].dwLowDateTime:016x}' == BIRTH, 'BIRTH')

    def modules(self):
        snapshot = self.k.CreateToolhelp32Snapshot(0x18, PID)
        need(snapshot not in (None, ct.c_void_p(-1).value), 'MODULE_SNAPSHOT')
        result = {}
        try:
            entry = self.Entry(); entry.dwSize = ct.sizeof(entry)
            ok = self.k.Module32FirstW(snapshot, ct.byref(entry)); count = 0
            need(ok, 'MODULE_FIRST')
            while ok:
                count += 1; need(count <= 512, 'MODULE_BOUND')
                name = entry.szModule.lower()
                if name in ('config.dll', 'frntend.dll'):
                    need(name not in result and Path(entry.szExePath).resolve() == (PLATFORM / name).resolve(), 'MODULE_IDENTITY')
                    result[name] = int(entry.modBaseAddr)
                ok = self.k.Module32NextW(snapshot, ct.byref(entry))
            need(set(result) == {'config.dll', 'frntend.dll'}, 'MODULE_SET')
            return result
        finally: self.k.CloseHandle(snapshot)

    def read(self, address, length):
        need(type(address) is int and type(length) is int and 0x10000 <= address
             and 0 < length <= 48 and address + length <= 0x100000000, 'READ_BOUND')
        cursor = address
        while cursor < address + length:
            page = self.Page()
            need(self.k.VirtualQueryEx(self.handle, cursor, ct.byref(page), ct.sizeof(page)) == ct.sizeof(page), 'PAGE_QUERY')
            end = int(page.BaseAddress or 0) + page.RegionSize
            need(page.State == 0x1000 and not page.Protect & 0x100 and page.Protect & 255 in (2, 4, 8, 0x20, 0x40, 0x80)
                 and int(page.BaseAddress or 0) <= cursor < end, 'READABLE_PAGE')
            cursor = min(end, address + length)
        buffer = ct.create_string_buffer(length); done = ct.c_size_t()
        need(self.k.ReadProcessMemory(self.handle, address, buffer, length, ct.byref(done)) and done.value == length, 'EXACT_READ')
        return buffer.raw

    def chunked(self, address, length):
        return b''.join(self.read(address + at, min(48, length - at)) for at in range(0, length, 48))

    def word(self, address): return struct.unpack('<I', self.read(address, 4))[0]


def collect_root():
    """Write a new point-in-time binding receipt and a bounded list result.

    Only this exact previously prepared owned process is accepted. The result
    cannot authorize a command; its data must be refreshed before any writer.
    """
    folder = ROOT / 'build' / ('designer-hot-v233-' + PARENT)
    native_raw = (folder / parent.NATIVE_FILE).read_bytes()
    need(sha(native_raw) == PARENT_NATIVE_SHA, 'PARENT_PIN')
    native = json.loads(native_raw); sdk = parent._json(folder / 'sdk-receipt.json'); plan = parent._json(folder / 'plan.json')
    need(native['status'] == 'OWNER_READ_REFUSED' and native['reason'] == 'DELEGATED_TARGET_UNRESOLVED'
         and native['typedHandlesCleared'] is True, 'PARENT_STATUS')
    need(sdk['sdkResult'] == 0 and sdk['knownTerminal'] is True and sdk['hookWorkersReleased'] is True, 'PARENT_TERMINAL')

    def fresh():
        parent._pins(); parent.base._lease(SimpleNamespace(plan=plan)); parent.c._fresh(parent.base._carrier_view(plan))

    fresh()
    primary, config_bodies = route.verify_primary()
    delegate_primary, delegate_bodies, delegate_keys = delegate.verify_primary()
    other_primary = other_managers.verify_primary()
    other_image = route.PE('config.dll')
    other_bodies = {}
    for name, (rva, size, _) in other_managers.SPANS.items():
        at = other_image.offset(other_image.base + rva)
        other_bodies[name] = other_image.data[at:at + size]
    other_managers.verify_primary_units(other_bodies)
    operation = uuid.uuid4().hex
    reader = VmRead()
    try:
        reader.identity(); modules = reader.modules()
        need(modules['config.dll'] == route.BASE and modules['frntend.dll'] == delegate.PE('frntend.dll').base, 'IMAGE_BASE')
        cb, fb = modules['config.dll'], modules['frntend.dll']

        def snapshot():
            word = reader.word
            shell, canonical, target = (native[k] for k in ('shellPointer', 'canonicalPointer', 'targetPointer'))
            need(target - 16 == canonical == shell - 8, 'FACET_OFFSETS')
            need(word(shell) == cb + 0x2b9474 and word(canonical) == cb + 0x2b9568 and word(target) == cb + 0x2b945c, 'FACET_TABLES')
            owner, delegated = word(canonical + 36), word(target + 24)
            need(owner == native['ownerPointer'] and delegated == native['delegatePointer'], 'OBJECT_BINDING')
            main = word(owner + 100); need(main == native['mainEntryPointer'], 'MAIN_BINDING')
            need(word(delegated) == fb + delegate_primary['delegateFacetRva'], 'DELEGATE_FACET')
            need(word(delegated - 24) == fb + delegate_primary['canonicalFacetRva']
                 and word(word(delegated - 24) + 16) == fb + delegate_primary['dispatchRva'], 'DELEGATE_DISPATCH')
            live_config = {name: reader.chunked(cb + rva, size) for name, (rva, size, _) in route.SPANS.items()}
            live_delegate = {name: reader.chunked(fb + rva, size) for name, (rva, size, _) in delegate.SPANS.items()}
            live_keys = {rva: reader.chunked(fb + rva, 20) for rva, _ in delegate.KEYS}
            live_other = {name: reader.chunked(cb + rva, size) for name, (rva, size, _) in other_managers.SPANS.items()}
            need(live_config == config_bodies and live_delegate == delegate_bodies and live_keys == delegate_keys, 'RUNTIME_CODE_AND_KEYS')
            need(live_other == other_bodies, 'RUNTIME_OTHER_MANAGER_TRAVERSAL')
            need(reader.read(word(canonical), 28) == live_config['modeTable']
                 and reader.read(word(target), 24) == live_config['targetTable'], 'RUNTIME_TABLES')
            route.verify_units(live_config); delegate.verify_units(live_delegate, live_keys)
            data = struct.pack('<6I', shell, canonical, target, owner, delegated, main)
            data += b''.join(live_config[k] for k in sorted(live_config))
            data += b''.join(live_delegate[k] for k in sorted(live_delegate))
            data += b''.join(live_keys[k] for k in sorted(live_keys))
            data += b''.join(live_other[k] for k in sorted(live_other))
            return data

        first = snapshot(); need(snapshot() == first, 'TWO_PASS_CHANGED')
        reader.identity(); fresh()
        binding_proof = dict(kind='UPDATE29_OWNER_BINDING_VM_READ', operationId=operation,
            parentOperationId=PARENT, parentNativeSha256=PARENT_NATIVE_SHA,
            processId=PID, birth=BIRTH, processAccessMask=0x410,
            sourcePrimarySha256=sha(Path(route.__file__).read_bytes()),
            delegatePrimarySha256=sha(Path(delegate.__file__).read_bytes()),
            readerSourceSha256=sha(Path(__file__).read_bytes()),
            commandGroup=route.GROUP, commandId=29, endpoint='previously_observed_explicit_ICommandTarget_only',
            shellPointer=native['shellPointer'], canonicalPointer=native['canonicalPointer'], targetPointer=native['targetPointer'],
            ownerPointer=native['ownerPointer'], mainEntryPointer=native['mainEntryPointer'],
            actualUpdate29OwnerVerified=True, delegatedTargetResolved=True, runtimeCodeAndKeysMatched=True,
            otherManagerTraversalRuntimeMatched=True,
            twoIdenticalPasses=True, readablePagesValidated=True, snapshotSha256=sha(first),
            bindingLifetime='point_in_time_observation_refresh_before_dispatch',
            activeCoreReceiverBindingVerified=False, sdkCommandStatusQueried=False,
            updateModeResolved=False, permissionChecksPassed=False, fullPendingVerified=False,
            databaseUpdateAuthorized=False, nativeCallbacks=0, nativeCommands=0, referenceCalls=0,
            sourceWrites=0, configurationSaves=0, databaseUpdates=0, repositoryMutations=0, applicationTextOutputBytes=0)
        out = ROOT / 'artifacts/designer-bridge' / ('update-owner-binding-vm-read-' + operation + '.json')
        parent.c.write_new(out, binding_proof); binding_sha = sha(out.read_bytes())
        binding = dict(kind='PREBOUND_UPDATE29_OWNER', platformVersion='8.3.18.1208',
            ownerPointer=native['ownerPointer'], mainEntryPointer=native['mainEntryPointer'],
            actualUpdate29OwnerVerified=True, delegatedTargetResolved=True, readablePagesValidated=True, proofSha256=binding_sha)
        need(snapshot() == first, 'PRE_LIST_BINDING_CHANGED')
        try:
            projection = other_managers.project_other_managers(reader.read, owner=native['ownerPointer'],
                main_entry=native['mainEntryPointer'], binding=binding, primary_proof=other_primary)
            result = dict(status='OTHER_MANAGERS_READ', projection=projection)
        except ValueError as exc:
            reason = str(exc)
            need(reason.startswith('UPDATE_OTHER_MANAGERS_') and len(reason) < 120, 'LIST_FAILURE_CLASS')
            result = dict(status='OTHER_MANAGERS_READ_REFUSED', reason=reason)
        need(snapshot() == first, 'POST_LIST_BINDING_CHANGED')
        reader.identity(); fresh()
        result.update(kind='UPDATE_OTHER_MANAGERS_VM_READ', operationId=operation,
            bindingProofPath=str(out), bindingProofSha256=binding_sha, bindingRecheckedBeforeAndAfter=True,
            readerSourceSha256=sha(Path(__file__).read_bytes()), processId=PID, birth=BIRTH,
            fullPendingVerified=False, databaseUpdateAuthorized=False, nativeCommands=0,
            sourceWrites=0, configurationSaves=0, databaseUpdates=0, repositoryMutations=0, applicationTextOutputBytes=0)
        result_out = ROOT / 'artifacts/designer-bridge' / ('update-other-managers-vm-read-' + operation + '.json')
        parent.c.write_new(result_out, result)
        return dict(operationId=operation, ownerBindingProofSha256=binding_sha,
                    resultProofSha256=sha(result_out.read_bytes()), result=result)
    finally: reader.close()


if __name__ == '__main__': print(json.dumps(collect_root(), sort_keys=True))
