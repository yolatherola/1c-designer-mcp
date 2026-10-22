"""Root-only fixed SDK continuation of the retained ad2 process.

Import/CLI are inert. Preparation reads the owned process but never injects.
Only run_root_once, with a separate review-bound grant, loads the fixed helper.
No application code, connection payload, environment file or runtime eval input.
"""
from __future__ import annotations

import ctypes as ct
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
NONCE = 'ad2c90cb107e43d898c06b583691788d'
BUILD = ROOT / 'build' / ('designer-v43-' + NONCE)
REGISTRY = ROOT / 'artifacts/designer-bridge' / ('v232-held-read-session-' + NONCE + '.json')
TARGET_RESERVATION = ROOT / 'build' / ('designer-hot-v233-target-' + NONCE + '.json')
PROBE = HERE / 'NativeTemplatePolicyV233.as'
PROBE_NAME = 'TEMPLATE_POLICY_V233'
PROBE_SHA = '6027ae9669f53b52fb6a37e781ec181dbb1e3e50ccd229d8c6e128667676f5ed'
FIXED_PROBES = {
    'TEMPLATE_POLICY_V233': ('NativeTemplatePolicyV233.as', 'ahTemplatePolicyV233',
        PROBE_SHA, 'policy-proof.json'),
    'TEMPLATE_EDITOR_V234': ('NativeTemplateEditorV234.as', 'ahTemplateEditorV234',
        'c55a46c7189a10baa48e0d8cf4489d83c948b4afed3b392a886c6313662a471a', 'editor-proof.json'),
    'TEMPLATE_BINDING_V236': ('NativeTemplateBindingV236.as', 'ahTemplateBindingV236',
        '93ebbac2478f8a693c8e9e602fc3bc672db33ee953c5a50f3f6cffd24702b35f', 'binding-proof.json'),
    'RUNNER_EDITORS_V247': ('NativeRunnerEditorsV247.as', 'ahRunnerEditorsV247',
        'aefd6e34b44fcdfa67eb4a7f245797f0f11d2eda24666a0e2cb12fc3d0731e2f', 'runner-editors-proof.json'),
    'TEMPLATE_POLICY_RECEIVER_V250': ('NativeTemplatePolicyReceiverV250.as', 'ahTemplatePolicyReceiverV250',
        '705eb73c1027c2e1fcaa503e0e899d5673ad8328c1194d1104a7880a639d4f4d', 'policy-receiver-proof.json'),
    'TEMPLATE_POLICY_CURRENT_QUERY': ('NativeTemplatePolicyCurrentQuery.as', 'ahTemplatePolicyCurrentQuery',
        '875bad29a19d3667f2c1bb5bac9e39cc8772ecfb47d4affd308aa96cedbcd97c', 'current-policy-proof.json'),
    'SAVED_RESOURCE_FINGERPRINT_V264': ('NativeSavedResourceFingerprintV264.as', 'ahSavedResourceFingerprintV264',
        '7c45c44839e5938288c0c39da31acebd079034d098a4ccd1b29df1017dfee24b', 'saved-resource-proof.json'),
    'TEMPLATE_SERIALIZATION_DIFF': ('NativeTemplateSerializationDiff.as', 'ahTemplateSerializationDiff',
        '99e113e59eca1aa00e90a37a5594ea560795aa89c47fd79a90961076bb419b2b', 'template-serialization-diff-proof.json'),
    'EXPECTED_SAVED_TEMPLATE': ('NativeExpectedSavedTemplate.as', 'ahExpectedSavedTemplate',
        '84c6917fbe609dbbd16bea2d383220221d3a89c6f12a44af13f7af4dda27b459', 'expected-saved-template-proof.json'),
    'REFERENCE_SCRATCH': ('NativeRunnerReferenceScratch.as', 'ahRunnerReferenceScratch',
        '2410c191fe7a17d907ced30e906c9254f0f2410ca7d80acda5a059c2daaef50f', 'reference-scratch-proof.json'),
    'SHEET_CHANGE_RECEIVER': ('NativeSheetChangeReceiver.as', 'ahSheetChangeReceiver',
        '5fdd69f591646f6bddcc0b9ea43870800740ae45c09430a8d5f9ab97502acc73', 'sheet-change-receiver-proof.json'),
    'SHEET_DIRTY_STATE': ('NativeSheetDirtyState.as', 'ahSheetDirtyState',
        'f7e014a41f53ffd35a62859a68c65ae5c0fa9e82fb43ac9f2e7abeaa274fe8e3', 'sheet-dirty-state-proof.json'),
    'SHEET_SAVE_COMMAND_STATE': ('NativeSheetSaveCommandState.as', 'ahSheetSaveCommandState',
        '45baac8242bde4202003c647d6abe1d03958851aea2982306c01d86b736194b9', 'sheet-save-command-state-proof.json'),
    'RAM_PACKET_V240': ('NativeRamPacketV240.as', 'ahRamPacketV240',
        'ac1ce2fbf13c7f735813b74d966f0ed691e877e12ddc68d053a5d5125a942922', 'ram-packet-proof.json'),
}
RAM_PROBE = 'RAM_PACKET_V240'
RAM_SOURCE_PINS = {
    'ram_payload_v237.py': '453df9a9c41ee4bb5068b15e058a2449c6f88ee9405b7300c24cf58b8421ee79',
    'ram_transport_v238.py': '47c1609b8993ca3e32491aaecbf0c45658fd7fa9789987a92dbed8306030e4bc',
}
RAM_PLACEHOLDERS = ('__PAYLOAD_ADDRESS__', '__PAYLOAD_LENGTH__',
                    '__PAYLOAD_SHA256__', '__OPERATION_ID__')
IMAGE = Path('C:/Program Files (x86)/1cv8/8.3.18.1208/bin/1cv8.exe')
IMAGE_SHA = 'c49e36e4e1ca2f6db2c1b51228161297fd79b42d3d0c6dd046551e06d0a51e12'
CORE_SHA = '7867174add6fb4f52b8b8c9288c1daea2193fc679621d773a6d355d780d30541'
SNEGO_SHA = 'f348e965eacd90b94a1c51a2cde6f510038d313665c66a67a300e60a6aaa3c32'
TCC_SHA = '11b86934bb2833f57fa0453a605ca342aee9207e193faea9b973baa2b2b4c35b'
SOURCE_PINS = {
    'NativeSdkGoldDiagnosis.c': 'e22ea0a88316fdeca21e70c3e6509619624cbe3203c05d8315a7e241830d6d0c',
    'NativeSdkCall.s': 'ab5c81990fe2838b366a3cde486e5b06c0650a1bc9bc9b85f43774eb47699374',
    'OwnedSdkReadonlyAttach.cs': '112007654805351263fee5c8f9c08d27d2a665eee8d9202f1d7bc0c45d1b62a4',
    'OwnedSdkDiagnosisHook.cs': '33fa5dc780b670dd28ff69b8bc29519c681a80eb44ade8ebb4f30d78155cb7f7',
}
CORE_FIELD_SPANS = {
    0xa906a: bytes.fromhex('8b461480b830050000000f8549010000c68030050000018b4e14e8675a02008b4e1480b9f803000000743f'),
    0xceb10: bytes.fromhex('807e04000f85ee01000080bef8030000000f85e1010000'),
    0xced04: bytes.fromhex('c6460401'),
}
FILES = ('sdk_probe_params.h', 'Continuation.c', 'OwnedSdkReadonlyAttach.cs',
         'OwnedSdkDiagnosisHook.cs', 'run-fixed.ps1')
HEX32 = re.compile(r'[a-f0-9]{32}\Z')
HEX64 = re.compile(r'[a-f0-9]{64}\Z')


def need(ok, code):
    if not ok:
        raise ValueError('V233_' + code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _plain(path, boundary=ROOT):
    path, boundary = Path(path), Path(boundary)
    need(path.is_absolute() and boundary.is_absolute()
         and '..' not in path.parts and '..' not in boundary.parts, 'ABSOLUTE_NO_DOTDOT')
    need(path == boundary or boundary in path.parents, 'PATH_BOUNDARY')
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            info = item.lstat()
            need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                 'PATH_REPARSE')
        if item == boundary:
            break
    return path


def read(path, maximum=16 * 1024 * 1024):
    path = _plain(path)
    need(path.is_file() and 0 < path.stat().st_size <= maximum, 'READ_BOUND')
    raw = path.read_bytes()
    need(0 < len(raw) <= maximum, 'READ_BOUND')
    return raw


def _pairs(rows):
    out = {}
    for key, value in rows:
        need(key not in out, 'DUPLICATE_JSON')
        out[key] = value
    return out


def parse(raw):
    return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_pairs,
                      parse_constant=lambda _: need(False, 'NONFINITE'))


def write_new(path, value):
    path = _plain(path)
    raw = canonical(value) + b'\n'
    with path.open('xb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    need(read(path) == raw, 'WRITE_READBACK')


def _sdk_proof_prefix(version):
    prefixes={232:'v232-sdk-',235:'v235-sdk-',262:'v262-sdk-'}
    need(type(version) is int and version in prefixes,'SDK_PROOF_VERSION')
    return prefixes[version]


def _context(held_nonce=NONCE):
    """Re-read complete536/current main/retained identities, no connection read."""
    need(type(held_nonce) is str and HEX32.fullmatch(held_nonce), 'HELD_NONCE')
    build = ROOT / 'build' / ('designer-v43-' + held_nonce)
    registry_path = ROOT / 'artifacts/designer-bridge' / ('v232-held-read-session-' + held_nonce + '.json')
    registry_raw = read(registry_path, 16384)
    registry = parse(registry_raw)
    need(registry.get('version') == 232 and registry.get('nonce') == held_nonce
         and registry.get('state') == 'HELD_FOR_NEXT_ACTIVE_GOAL_STAGE'
         and registry.get('writerAuthorized') is False and type(registry.get('applicationWrites')) is int
         and registry['applicationWrites'] == 0 and registry.get('goalComplete') is False,
         'HELD_REGISTRY')
    sdk_prefix=_sdk_proof_prefix(registry.get('sdkProofVersion'))
    need(Path(registry['buildDirectory']) == build and Path(registry['image']) == IMAGE,
         'REGISTRY_SCOPE')
    need(type(registry['processId']) is int and registry['processId'] > 0
         and re.fullmatch('[a-f0-9]{16}', registry['birth']) is not None, 'REGISTRY_IDENTITY')
    parent_plan = parse(read(build / ('v208-private-' + held_nonce) / 'plan.json'))
    pins = parent_plan['sourceSha256']
    need(type(pins) is dict and len(pins) == 536 and parent_plan['sourceCount'] == 536
         and digest(canonical(pins)) == registry['sourceManifestSha256']
         == parent_plan['sourceManifestSha256'], 'SOURCE536')
    for name, pin in pins.items():
        need(type(name) is str and name.startswith(('tools/','artifacts/designer-bridge/')) and '\\' not in name
             and '..' not in Path(name).parts and not any(p.startswith('.') for p in Path(name).parts)
             and type(pin) is str and HEX64.fullmatch(pin), 'SOURCE_KEY')
        need(digest(read(ROOT / name)) == pin, 'SOURCE536_PIN')
    main = build / 'runtime/modules/snegopat/engine/main.as'
    need(digest(read(main)) == registry['mainSha256'], 'CURRENT_MAIN_PIN')
    for filename, pin in SOURCE_PINS.items():
        need(digest(read(HERE / filename)) == pin, 'SDK_DRIVER_SOURCE_PIN')
    core = build / 'runtime/lib/x86/core_as.dll'
    snego = build / 'runtime/modules/snegopat/lib/x86/snegopat.dll'
    need(digest(read(core)) == CORE_SHA and digest(read(snego)) == SNEGO_SHA, 'SDK_DLL_PIN')
    callback = parse(read(build / 'early-callback.json', 8192))
    owner = parse(read(build / 'owned-process-v43.json', 8192))
    need(callback.get('pid') == owner.get('pid') == registry['processId']
         and callback.get('birth') == owner.get('birth') == registry['birth']
         and callback.get('nonce') == held_nonce and callback.get('goldStarted') is True
         and type(callback.get('sourceWrites')) is int and callback['sourceWrites'] == 0
         and type(callback.get('guiTid')) is int and callback['guiTid'] > 0, 'OWNED_CALLBACK')
    sdk = parse(read(ROOT / 'artifacts/designer-bridge' / (sdk_prefix + held_nonce + '.json')))
    need(sdk.get('compileVerified') is True and type(sdk.get('exitCode')) is int and sdk['exitCode'] == 0
         and sdk.get('sourceCount') == 536 and sdk.get('sourceManifestSha256') == registry['sourceManifestSha256'],
         'BASELINE_SDK_PROOF')
    return dict(heldNonce=held_nonce,buildDirectory=str(build),registrySha256=digest(registry_raw), processId=registry['processId'], birth=registry['birth'],
                guiThreadId=callback['guiTid'], sourceManifestSha256=registry['sourceManifestSha256'],
                mainSha256=registry['mainSha256'], corePath=str(core), snegopatPath=str(snego))


def _verify_core_fields(raw):
    """Primary byte joins: +4 is preparation cache, +530 is compile-in-progress.

    CompileFunction calls PrepareEngine then checks configFailed+3f8. The
    prepare worker skips work for +4!=0 and writes +4=1 on completion. Reading
    +4 as 'an active prepared context' would wrongly reject valid subsequent
    continuations. No SDK flag is written by this controller.
    """
    import struct
    need(digest(raw)==CORE_SHA,'CORE_FIELD_IMAGE_PIN')
    nt=struct.unpack_from('<I',raw,0x3c)[0];opt=nt+24
    need(raw[nt:nt+4]==b'PE\0\0' and struct.unpack_from('<H',raw,opt)[0]==0x10b,'CORE_PE32')
    sections=opt+struct.unpack_from('<H',raw,nt+20)[0]
    count=struct.unpack_from('<H',raw,nt+6)[0];need(0<count<=96,'CORE_SECTIONS')
    for rva,wanted in CORE_FIELD_SPANS.items():
        found=None
        for i in range(count):
            virtual,start,size,offset=struct.unpack_from('<IIII',raw,sections+40*i+8)
            if start<=rva and rva+len(wanted)<=start+size:
                found=raw[offset+rva-start:offset+rva-start+len(wanted)];break
        need(found==wanted,'CORE_FIELD_PRIMARY')


def inspect_owned(context):
    """Bounded QUERY/VM_READ only; never allocate, write, load or execute remotely."""
    need(os.name == 'nt', 'WINDOWS_REQUIRED')
    from ctypes import wintypes as w
    k, u = ct.WinDLL('kernel32', use_last_error=True), ct.WinDLL('user32', use_last_error=True)
    k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]; k.OpenProcess.restype = w.HANDLE
    k.CloseHandle.argtypes = [w.HANDLE]; k.CloseHandle.restype = w.BOOL
    k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]; k.WaitForSingleObject.restype = w.DWORD
    k.GetProcessTimes.argtypes = [w.HANDLE] + [ct.POINTER(ct.c_uint64)] * 4
    k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, ct.POINTER(w.DWORD)]
    k.ReadProcessMemory.argtypes = [w.HANDLE, ct.c_void_p, ct.c_void_p, ct.c_size_t, ct.POINTER(ct.c_size_t)]
    k.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]; k.CreateToolhelp32Snapshot.restype = w.HANDLE
    handle = k.OpenProcess(0x101010, False, context['processId'])
    need(bool(handle), 'OWN_PROCESS_QUERY')
    def identity():
        times = [ct.c_uint64() for _ in range(4)]
        need(k.GetProcessTimes(handle, *(ct.byref(x) for x in times))
             and f'{times[0].value:016x}' == context['birth'] and k.WaitForSingleObject(handle, 0) == 258,
             'LIVE_PID_BIRTH')
        size = w.DWORD(32768); buffer = ct.create_unicode_buffer(size.value)
        need(k.QueryFullProcessImageNameW(handle, 0, buffer, ct.byref(size))
             and Path(buffer.value) == IMAGE, 'PROCESS_IMAGE')
    def memory(address, count):
        need(type(address) is int and 65536 <= address < 2**32 and 0 < count <= 512
             and address + count <= 2**32, 'MEMORY_BOUND')
        data = (ct.c_ubyte * count)(); done = ct.c_size_t()
        need(k.ReadProcessMemory(handle, address, data, count, ct.byref(done)) and done.value == count,
             'OWN_MEMORY_READ')
        return bytes(data)
    def words(address, count):
        import struct
        return struct.unpack('<' + 'I' * count, memory(address, 4 * count))
    try:
        identity()
        need(digest(IMAGE.read_bytes()) == IMAGE_SHA, 'PROCESS_IMAGE_PIN')
        class Entry(ct.Structure):
            _fields_ = [('dwSize',w.DWORD),('th32ModuleID',w.DWORD),('th32ProcessID',w.DWORD),
                        ('GlblcntUsage',w.DWORD),('ProccntUsage',w.DWORD),('modBaseAddr',ct.c_void_p),
                        ('modBaseSize',w.DWORD),('hModule',w.HMODULE),('szModule',w.WCHAR*256),('szExePath',w.WCHAR*260)]
        k.Module32FirstW.argtypes = [w.HANDLE,ct.POINTER(Entry)]; k.Module32NextW.argtypes = [w.HANDLE,ct.POINTER(Entry)]
        snapshot = k.CreateToolhelp32Snapshot(0x18, context['processId'])
        need(snapshot not in (None, ct.c_void_p(-1).value), 'MODULE_SNAPSHOT')
        modules = {}
        try:
            item = Entry(); item.dwSize = ct.sizeof(item); okay = k.Module32FirstW(snapshot,ct.byref(item)); count = 0
            while okay:
                count += 1; need(count <= 512, 'MODULE_COUNT_BOUND')
                if item.szModule.lower() in ('core_as.dll','snegopat.dll'):
                    need(item.szModule.lower() not in modules, 'DUPLICATE_SDK_MODULE')
                    modules[item.szModule.lower()] = (int(item.modBaseAddr), Path(item.szExePath))
                okay = k.Module32NextW(snapshot,ct.byref(item))
        finally:
            k.CloseHandle(snapshot)
        need(set(modules) == {'core_as.dll','snegopat.dll'}, 'LOADED_SDK_MODULES')
        for name,key,pin in [('core_as.dll','corePath',CORE_SHA),('snegopat.dll','snegopatPath',SNEGO_SHA)]:
            need(modules[name][1] == Path(context[key]) and digest(read(modules[name][1])) == pin, 'LOADED_SDK_PATH_PIN')
        core, snego = modules['core_as.dll'][0], modules['snegopat.dll'][0]
        engine = words(snego + 0x37674, 1)[0]
        table = words(engine, 1)[0]; slots = words(table, 64)
        need(table == core + 0x28f184 and all(slots[i] == core+r for i,r in [(49,0xc8d00),(50,0xc8d10),(58,0xc8d60)]),
             'ENGINE_ABI')
        vector,count = words(engine + 0x518,2); need(count == 1,'ONE_EXISTING_MODULE')
        module = words(vector,1)[0]; module_table = words(module,1)[0]
        need(module_table == core + 0x28e454 and words(module_table+6*4,1)[0] == core + 0xa9020,'MODULE_ABI')
        _verify_core_fields(read(Path(context['corePath'])))
        need(memory(engine+0x3f8,1)==b'\0' and memory(engine+0x530,1)==b'\0','SDK_NOT_POISONED_OR_COMPILING')
        need(memory(engine+4,1) in (b'\0',b'\1'),'SDK_PREPARE_CACHE_BOOL')
        k.OpenThread.argtypes=[w.DWORD,w.BOOL,w.DWORD]; k.OpenThread.restype=w.HANDLE
        k.GetProcessIdOfThread.argtypes=[w.HANDLE]; k.GetProcessIdOfThread.restype=w.DWORD
        thread=k.OpenThread(0x100040,False,context['guiThreadId']); need(bool(thread),'GUI_THREAD_QUERY')
        try: need(k.GetProcessIdOfThread(thread)==context['processId'],'GUI_THREAD_OWNER')
        finally: k.CloseHandle(thread)
        callback_type=ct.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM); windows=[]
        u.GetWindowThreadProcessId.argtypes=[w.HWND,ct.POINTER(w.DWORD)];u.GetWindowThreadProcessId.restype=w.DWORD
        u.GetClassNameW.argtypes=[w.HWND,w.LPWSTR,ct.c_int]
        @callback_type
        def window(hwnd,_):
            pid=w.DWORD(); tid=u.GetWindowThreadProcessId(hwnd,ct.byref(pid))
            if pid.value==context['processId'] and tid==context['guiThreadId']:
                name=ct.create_unicode_buffer(256);u.GetClassNameW(hwnd,name,256)
                if name.value in ('V8TopLevelFrame','V8NewLocalFrameBaseWnd'): windows.append(int(hwnd))
            return True
        u.EnumWindows.argtypes=[callback_type,w.LPARAM];need(u.EnumWindows(window,0) and windows,'OWN_MAIN_WINDOW')
        identity()
        return dict(engineAddress=engine,moduleAddress=module,coreBase=core,snegopatBase=snego,
                    engineTableRva=0x28f184,moduleTableRva=0x28e454,moduleCount=1,guiThreadId=context['guiThreadId'])
    finally:
        k.CloseHandle(handle)


def _probe_spec(name):
    need(type(name) is str and name in FIXED_PROBES, 'FIXED_PROBE_KEY')
    return FIXED_PROBES[name]


def _probe_source(raw, probe_name=PROBE_NAME):
    function_name=_probe_spec(probe_name)[1]
    need(type(raw) is bytes and 1 <= len(raw) <= 32768, 'FIXED_PROBE_BOUND')
    text=raw.decode('utf-8-sig')
    need(text.count('void '+function_name+'()') == 1 and text.count('__PROOF_PATH__') == 1
         and '\0' not in text, 'FIXED_PROBE_SIGNATURE')
    need(all(text.count(token)==(1 if probe_name==RAM_PROBE
             or probe_name in ('SHEET_CHANGE_RECEIVER','SHEET_DIRTY_STATE','SHEET_SAVE_COMMAND_STATE') and token=='__OPERATION_ID__' else 0)
             for token in RAM_PLACEHOLDERS), 'FIXED_PAYLOAD_PLACEHOLDERS')
    # No client-supplied code: root hashes/reviews this one fixed path. Enforce
    # one top-level function, with comments/string literals excluded from braces.
    stripped=re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"',lambda m:'""' if m.group().startswith('"') else '',text,flags=re.S)
    need(re.fullmatch(r'\s*void '+re.escape(function_name)+r'\(\)\s*\{.*\}\s*',stripped,re.S), 'ONE_FUNCTION')
    depth=0
    for i,char in enumerate(stripped):
        if char=='{': depth+=1
        elif char=='}':
            depth-=1;need(depth>=0 and (depth>0 or not stripped[i+1:].strip()),'ONE_FUNCTION')
    need(depth==0, 'ONE_FUNCTION')
    for bad in ('transmitCommand(', 'setMdPropVal(', 'setPropVal(', 'setModuleText(',
                'setModified(', 'setReadOnly(', 'ahScopePlan(',
                'ahRepoStatistic(', 'ahPlanObjectInfo(', 'ahRepositoryStatisticRead(', 'AH_SDK_RECOVER'):
        need(bad not in stripped, 'READONLY_PROBE')
    return text


def _ram_source_pins():
    """Validate inert codec/transport sources before importing Receipt's class."""
    for name,pin in RAM_SOURCE_PINS.items():
        need(digest(read(HERE/name))==pin,'RAM_SOURCE_PIN')


def _payload_scope(payload, operation_id, context):
    """Technical metadata only; never accepts payload bytes or application text."""
    keys={'operationId','processId','birth','address','length','sha256',
          'codecSha256','transportSha256'}
    need(type(payload) is dict and set(payload)==keys,'PAYLOAD_SCOPE')
    need(payload['operationId']==operation_id and type(payload['operationId']) is str
         and HEX32.fullmatch(payload['operationId'])
         and type(payload['processId']) is int and payload['processId']==context['processId']
         and type(payload['birth']) is str and re.fullmatch('[a-f0-9]{16}',payload['birth'])
         and payload['birth']==context['birth'],'PAYLOAD_IDENTITY')
    need(type(payload['address']) is int and 65536<=payload['address']<2**32
         and type(payload['length']) is int and 288<=payload['length']<=4*1024*1024
         and payload['address']+payload['length']<=2**32,'PAYLOAD_BOUNDS')
    need(type(payload['sha256']) is str and HEX64.fullmatch(payload['sha256']),'PAYLOAD_SHA256')
    need(payload['codecSha256']==RAM_SOURCE_PINS['ram_payload_v237.py']
         and payload['transportSha256']==RAM_SOURCE_PINS['ram_transport_v238.py'],'PAYLOAD_SOURCE_PINS')
    _ram_source_pins()
    return payload


def _payload_from_receipt(receipt, operation_id, context):
    # Receipt is a frozen metadata observation, not proof of lease ownership.
    # Root retains and dispatches its originating live V238 lease separately.
    _ram_source_pins()
    from ram_transport_v238 import Receipt
    need(type(receipt) is Receipt,'PAYLOAD_RECEIPT_TYPE')
    return _payload_scope(dict(operationId=receipt.operation_id,processId=receipt.pid,
        birth=receipt.birth,address=receipt.address,length=receipt.size,sha256=receipt.sha256,
        codecSha256=RAM_SOURCE_PINS['ram_payload_v237.py'],
        transportSha256=RAM_SOURCE_PINS['ram_transport_v238.py']),operation_id,context)


def _plan_payload(plan):
    if plan['probe']==RAM_PROBE:
        return _payload_scope(plan.get('payload'),plan['operationId'],plan['context'])
    need('payload' not in plan,'UNEXPECTED_PAYLOAD')
    return None


def _grant(plan,grant,mode,review=False):
    keys={'mode','rootAuthorized','planSha256'} | ({'reviewPath','reviewSha256'} if review else set())
    need(type(grant) is dict and set(grant)==keys and grant['mode']==mode and grant['rootAuthorized'] is True
         and grant['planSha256']==digest(canonical(plan)), 'ROOT_GRANT')
    if review:
        path=_plain(grant['reviewPath'],ROOT/'artifacts/designer-bridge')
        raw=read(path);need(digest(raw)==grant['reviewSha256'],'REVIEW_PIN')
        evidence=parse(raw)
        need(evidence.get('version')==233 and evidence.get('passed') is True and evidence.get('goldStarted') is False
             and evidence.get('planSha256')==grant['planSha256'],'REVIEW_CONTEXT')


def _reservation(context=None):
    if context is None: return TARGET_RESERVATION
    nonce=context.get('heldNonce',NONCE)
    need(type(nonce) is str and HEX32.fullmatch(nonce),'HELD_NONCE')
    return ROOT/'build'/('designer-hot-v233-target-'+nonce+'.json')


def _writer_hash(value):
    return type(value) is str and HEX64.fullmatch(value) is not None


def _audit_writer_pending(identity):
    """Read263 metadata only; SDK terminal never releases an unsaved writer.

    Root publishes exact258 metadata as intent.json and a separately reviewed
    ROOT_WRITER_FINALIZATION_V263 result. This audit does not free RAM/refs or
    prove those actions happened. It cannot dispatch or admit a writer.
    """
    for out in (ROOT/'build').glob('designer-writer-v263-*'):
        operation=out.name.removeprefix('designer-writer-v263-')
        if not HEX32.fullmatch(operation) or not out.is_dir():continue
        _plain(out,ROOT/'build')
        if not (out/'intent.json').exists():continue  # Render/stage alone never dispatches.
        prior=parse(read(out/'intent.json',32768))
        intent_keys=set(('version route operationId sessionNonce pid birth guiThread generation revision '
            'packetAddress packetBytes packetSha256 rootId targets originalCodeSha256 replacementCodeSha256 '
            'originalTemplateSha256 expectedTemplateSha256 compositeSha256 codecSha256 transportSha256 '
            'mainSha256 mainClosureProofSha256 reviewSha256 compileProofSha256 readinessProofSha256 compileMode compileFunctionReleased '
            'compileStandalonePid compileStandaloneBirth compileStandaloneExit compileStandaloneTerminalGone '
            'compileNoScriptRun compileLiveContextUsed compileStandaloneSynchronousWait readinessSequence '
            'templatePolicyProofSha256 templatePolicyReaderSha256 writerAuthorized configurationSaves databaseUpdates '
            'repositoryMutations configurationExports configurationImports oneShot baselineCoverage '
            'globalPendingIteratorVerified packetOriginalsRetainUntil templateCheckpointState '
            'releaseOnSdkOrHooksTerminal unknownRequiresRetention').split())
        notify=type(prior) is dict and prior.get('route')=='RUNNER_SHEET_NOTIFY_WRITE'
        if notify:intent_keys|={'compositionProfile','compositeEntry'}
        need(type(prior) is dict and set(prior)==intent_keys
             and type(prior.get('version')) is int and prior['version']==258
             and prior.get('route') in ('RUNNER_COMPOSITE_V249_WRITE','RUNNER_SHEET_NOTIFY_WRITE') and prior.get('operationId')==operation
             and prior.get('writerAuthorized') is True,'WRITER_INTENT_SCOPE')
        if notify:
            need(prior.get('compositionProfile')=='SHEET_NOTIFY'
                 and prior.get('compositeEntry')=='ahRunnerCompositeSheetNotify'
                 and prior.get('compositeSha256')=='307ea65c71871347cc63d3b305bc0c2ba057d3a5076a3b7cd04346f0022286bb'
                 and _writer_hash(prior.get('mainClosureProofSha256')),'WRITER_NOTIFY_PROFILE')
        prior_identity=(prior.get('pid'),prior.get('birth'))
        need(type(prior_identity[0]) is int and 0<prior_identity[0]<2**32
             and type(prior_identity[1]) is str and re.fullmatch('[a-f0-9]{16}',prior_identity[1])
             and int(prior_identity[1],16)>0 and type(prior.get('sessionNonce')) is str
             and HEX32.fullmatch(prior['sessionNonce']),'WRITER_INTENT_IDENTITY')
        need(_writer_hash(prior.get('packetSha256')) and _writer_hash(prior.get('compositeSha256'))
             and type(prior.get('originalCodeSha256')) is list and len(prior['originalCodeSha256'])==2
             and type(prior.get('replacementCodeSha256')) is list and len(prior['replacementCodeSha256'])==2
             and all(_writer_hash(v) for v in prior['originalCodeSha256']+prior['replacementCodeSha256'])
             and _writer_hash(prior.get('originalTemplateSha256'))
             and _writer_hash(prior.get('expectedTemplateSha256')),'WRITER_INTENT_BASELINE')
        need(_writer_hash(prior.get('mainSha256'))
             and (prior.get('mainClosureProofSha256') is None if prior['mainSha256']==
                  '64d37425553b75c6465aef5c194f327fb7e75399ec682f686fa7b658f7a4ad66'
                  else _writer_hash(prior.get('mainClosureProofSha256'))),'WRITER_INTENT_MAIN_CLOSURE')
        if prior_identity!=identity:continue
        # No allow_operation bypass: a readonly233 operation with the same ID
        # must not hide an earlier UNKNOWN/UNSAVED writer after marker loss.
        need((out/'result.json').is_file(),'WRITER_UNKNOWN_OR_UNSAVED_RETAIN')
        result=parse(read(out/'result.json',8192))
        need(type(result) is dict and type(result.get('version')) is int and result['version']==263
             and result.get('kind')=='ROOT_WRITER_FINALIZATION_V263'
             and result.get('operationId')==operation and type(result.get('pid')) is int
             and result['pid']==prior_identity[0] and result.get('birth')==prior_identity[1]
             and result.get('sessionNonce')==prior['sessionNonce']
             and result.get('packetSha256')==prior['packetSha256']
             and result.get('compositeSha256')==prior['compositeSha256']
             and result.get('intentSha256')==digest(canonical(prior))
             and result.get('knownTerminal') is True and result.get('hookWorkersReleased') is True
             and result.get('targetIdentityVerified') is True and result.get('releasePacketAllowed') is True,
             'WRITER_UNKNOWN_OR_UNSAVED_RETAIN')
        status=result.get('status')
        if status in ('SAVED_MAIN_VERIFIED','ROLLBACK_VERIFIED'):
            expected=([prior['expectedTemplateSha256']]+prior['replacementCodeSha256'] if status=='SAVED_MAIN_VERIFIED'
                      else [prior['originalTemplateSha256']]+prior['originalCodeSha256'])
            need(result.get('releaseRefsAllowed') is True and result.get('referencesAccounted') is True
                 and type(result.get('targetHashes')) is list and result['targetHashes']==expected
                 and _writer_hash(result.get('rootResolutionProofSha256')),'WRITER_RESOLUTION_REQUIRED')
        elif status=='REFUSED_BEFORE_MUTATION':
            need(result.get('releaseRefsAllowed') is False and result.get('referencesAbsentVerified') is True
                 and result.get('referenceAttempted') is False and result.get('checkpointRetained') is False
                 and result.get('documentRetained') is False
                 and type(result.get('sourceMutationAttempts')) is int and result['sourceMutationAttempts']==0
                 and type(result.get('metadataMutationAttempts')) is int and result['metadataMutationAttempts']==0
                 and _writer_hash(result.get('rootRefusalProofSha256')),'WRITER_REFUSAL_REQUIRED')
        else:need(False,'WRITER_UNKNOWN_OR_UNSAVED_RETAIN')


def _audit_native_reference_pending(identity):
    """Require independently accounted native counters; an SDK receipt is insufficient.

    This reads only bounded technical metadata and never releases a reference
    or bypasses the target reservation. Missing markers do not hide an intent.
    """
    intent_keys=set(('kind operationId pid birth nonce referencePlanSha256 packageSha256 '
                     'buildSha256 scopeKind sdkAttempted applicationMutationAuthorized').split())
    writer_keys={'writerOperationId','writerIntentSha256','packetSha256'}
    native_keys=set(('version operationId planSha256 identityVerified checkpointAttempted '
                     'checkpointCompleted documentAttempted documentCompleted checkpointReturn '
                     'documentReturn terminal').split())
    for out in (ROOT/'build').glob('designer-native-reference-*'):
        operation=out.name.removeprefix('designer-native-reference-')
        if not HEX32.fullmatch(operation) or not out.is_dir():continue
        _plain(out,ROOT/'build')
        if not (out/'intent.json').exists():continue
        prior=parse(read(out/'intent.json',8192))
        writer=type(prior) is dict and prior.get('scopeKind')=='WRITER'
        need(type(prior) is dict and set(prior)==intent_keys|(writer_keys if writer else set())
             and prior.get('kind')=='NATIVE_REFERENCE_INTENT' and prior.get('operationId')==operation
             and type(prior.get('pid')) is int and prior['pid']>0
             and type(prior.get('birth')) is str and re.fullmatch('[a-f0-9]{16}',prior['birth'])
             and type(prior.get('nonce')) is str and HEX32.fullmatch(prior['nonce'])
             and prior.get('scopeKind') in ('SCRATCH','WRITER') and prior.get('sdkAttempted') is False
             and prior.get('applicationMutationAuthorized') is False
             and all(_writer_hash(prior.get(k)) for k in ('referencePlanSha256','packageSha256','buildSha256')),
             'NATIVE_REFERENCE_INTENT_SCOPE')
        if writer:
            need(type(prior.get('writerOperationId')) is str and HEX32.fullmatch(prior['writerOperationId'])
                 and all(_writer_hash(prior.get(k)) for k in ('writerIntentSha256','packetSha256')),
                 'NATIVE_REFERENCE_WRITER_SCOPE')
        if (prior['pid'],prior['birth'])!=identity:continue
        if writer:
            original=parse(read(ROOT/'build'/('designer-writer-v263-'+prior['writerOperationId'])/'intent.json',32768))
            need(type(original) is dict and type(original.get('pid')) is int
                 and digest(canonical(original))==prior['writerIntentSha256']
                 and original.get('operationId')==prior['writerOperationId']
                 and original.get('packetSha256')==prior['packetSha256']
                 and (original.get('pid'),original.get('birth'),original.get('sessionNonce'))==
                     (prior['pid'],prior['birth'],prior['nonce']),'NATIVE_REFERENCE_ORIGINAL_WRITER_JOIN')
        need((out/'result.json').is_file(),'NATIVE_REFERENCE_UNKNOWN_RETAIN')
        result=parse(read(out/'result.json',8192))
        need(type(result) is dict and result.get('kind')=='NATIVE_REFERENCE_ACCOUNTED_TERMINAL'
             and result.get('operationId')==operation and result.get('intentSha256')==digest(canonical(prior))
             and result.get('referencePlanSha256')==prior['referencePlanSha256']
             and type(result.get('pid')) is int and (result['pid'],result.get('birth'),result.get('nonce'))==
                 (prior['pid'],prior['birth'],prior['nonce'])
             and all(result.get(k) is True for k in ('knownTerminal','hookWorkersReleased',
                 'targetIdentityVerified','accountingVerified')) and result.get('sdkAttempted') is False
             and all(_writer_hash(result.get(k)) for k in ('nativeProofSha256','accountingProofSha256')),
             'NATIVE_REFERENCE_ACCOUNTING_REQUIRED')
        if writer:
            need(all(result.get(k)==prior[k] for k in writer_keys),'NATIVE_REFERENCE_WRITER_RESULT_JOIN')
        native_raw=read(out/'native-proof.json',8192);account_raw=read(out/'accounting-proof.json',8192)
        need(digest(native_raw)==result['nativeProofSha256']
             and digest(account_raw)==result['accountingProofSha256'],'NATIVE_REFERENCE_PROOF_PIN')
        native=parse(native_raw);account=parse(account_raw)
        need(type(native) is dict and set(native)==native_keys and type(native.get('version')) is int
             and native['version']==1 and native.get('operationId')==operation
             and native.get('planSha256')==prior['referencePlanSha256']
             and all(native.get(k) is True for k in ('identityVerified','terminal'))
             and all(type(native.get(k)) is int and native[k]==1 for k in ('checkpointAttempted',
                 'checkpointCompleted','documentAttempted','documentCompleted'))
             and all(type(native.get(k)) is int and 0<=native[k]<2**32 for k in ('checkpointReturn','documentReturn')),
             'NATIVE_REFERENCE_COUNTERS_REQUIRED')
        need(type(account) is dict and account.get('kind')=='NATIVE_REFERENCE_ACCOUNTING'
             and account.get('operationId')==operation and account.get('referencePlanSha256')==prior['referencePlanSha256']
             and account.get('nativeProofSha256')==result['nativeProofSha256'] and account.get('phase')=='COMPLETED'
             and account.get('knownTerminal') is True and account.get('hooksReleased') is True,
             'NATIVE_REFERENCE_LEDGER_REQUIRED')
        if writer:
            need(all(account.get(k)==prior[k] for k in writer_keys),'NATIVE_REFERENCE_WRITER_ACCOUNT_JOIN')


def _audit_runner_rollback_pending(identity):
    """A rollback SDK receipt cannot replace independent alias accounting.

    This audit proves only that the two additional aliases were disposed.
    Original writer finalization still requires its separate full resolution.
    """
    keys=set(('version kind operationId writerOperationId writerIntentSha256 referenceTransferId packetSha256 '
              'pid birth sessionNonce guiThreadId packageSha256 buildSha256 sourceSha256 callbackSha256 '
              'rootScopeSha256 bindingSha256 oneShot rollbackAuthorized configurationSavesAuthorized '
              'databaseUpdatesAuthorized repositoryMutationsAuthorized').split())
    for out in (ROOT/'build').glob('designer-runner-rollback-*'):
        operation=out.name.removeprefix('designer-runner-rollback-')
        if not HEX32.fullmatch(operation) or not out.is_dir():continue
        _plain(out,ROOT/'build')
        if not (out/'intent.json').exists():continue
        prior=parse(read(out/'intent.json',8192))
        need(type(prior) is dict and set(prior)==keys and type(prior.get('version')) is int and prior['version']==1
             and prior.get('kind')=='RUNNER_ROLLBACK_INTENT' and prior.get('operationId')==operation
             and all(type(prior.get(k)) is str and HEX32.fullmatch(prior[k]) for k in
                 ('writerOperationId','referenceTransferId','sessionNonce'))
             and type(prior.get('pid')) is int and prior['pid']>0
             and type(prior.get('guiThreadId')) is int and prior['guiThreadId']>0
             and type(prior.get('birth')) is str and re.fullmatch('[a-f0-9]{16}',prior['birth'])
             and all(_writer_hash(prior.get(k)) for k in ('writerIntentSha256','packetSha256','packageSha256',
                 'buildSha256','sourceSha256','rootScopeSha256','bindingSha256'))
             and prior.get('callbackSha256')=='23fb150cd403ac1875d3ca4b40b3a36c1f57aab90b820d1f274202cd4b8bb6c0'
             and prior.get('oneShot') is True and prior.get('rollbackAuthorized') is True
             and all(prior.get(k) is False for k in ('configurationSavesAuthorized',
                 'databaseUpdatesAuthorized','repositoryMutationsAuthorized')),'ROLLBACK_INTENT_SCOPE')
        if (prior['pid'],prior['birth'])!=identity:continue
        need((out/'result.json').is_file(),'ROLLBACK_UNKNOWN_OR_UNACCOUNTED_RETAIN')
        result=parse(read(out/'result.json',8192))
        need(type(result) is dict and result.get('kind')=='RUNNER_ROLLBACK_ACCOUNTED_TERMINAL'
             and all(result.get(k) is True for k in ('knownTerminal','hookWorkersReleased',
                 'targetIdentityVerified','accountingVerified','originalReferencesRetained','packetRetained'))
             and result.get('restoredPropertiesVerified') is False and result.get('savedMainVerified') is False
             and type(result.get('pid')) is int
             and (result.get('pid'),result.get('birth'),result.get('sessionNonce'))==
                 (prior['pid'],prior['birth'],prior['sessionNonce'])
             and result.get('packageSha256')==prior['packageSha256']
             and all(_writer_hash(result.get(k)) for k in ('sdkReceiptSha256','nativeProofSha256','accountingProofSha256')),
             'ROLLBACK_ALIAS_ACCOUNTING_REQUIRED')
        sdk_raw=read(out/'sdk-receipt.json',8192);account_raw=read(out/'accounting-proof.json',8192)
        native_path=ROOT/'build'/('designer-v43-'+prior['sessionNonce'])/('rollback-proof-'+operation+'.json')
        native_raw=read(native_path,8192)
        need(digest(sdk_raw)==result['sdkReceiptSha256'] and digest(native_raw)==result['nativeProofSha256']
             and digest(account_raw)==result['accountingProofSha256'],'ROLLBACK_PROOF_PIN')
        sdk=parse(sdk_raw);account=parse(account_raw);native=parse(native_raw)
        joins={k:prior[k] for k in ('operationId','writerOperationId','writerIntentSha256','referenceTransferId','packetSha256')}
        joins['rollbackIntentSha256']=digest(canonical(prior))
        need(all(type(row) is dict and all(row.get(k)==v for k,v in joins.items())
                 for row in (result,sdk,account)),'ROLLBACK_IDENTITY_JOIN')
        need(sdk.get('kind')=='RUNNER_ROLLBACK_SDK_RECEIPT' and sdk.get('status')=='SDK_TERMINAL_UNSAVED_RETAIN'
             and type(sdk.get('sdkResult')) is int and sdk['sdkResult']==0
             and type(sdk.get('pid')) is int and type(sdk.get('guiThreadId')) is int
             and all(sdk.get(k) is True for k in ('knownTerminal','hookWorkersReleased','targetIdentityVerified'))
             and (sdk.get('pid'),sdk.get('birth'),sdk.get('sessionNonce'),sdk.get('guiThreadId'))==
                 (prior['pid'],prior['birth'],prior['sessionNonce'],prior['guiThreadId'])
             and all(sdk.get(k) is False for k in ('releaseRefsAllowed','releasePacketAllowed','savedMainVerified','retryAuthorized')),
             'ROLLBACK_SDK_TERMINAL_REQUIRED')
        need(type(native) is dict and type(native.get('version')) is int and native['version']==1
             and native.get('rollbackOperationId')==operation and native.get('writerOperationId')==prior['writerOperationId']
             and native.get('writerProvenanceSha256')==prior['writerIntentSha256']
             and native.get('packetSha256')==prior['packetSha256']
             and native.get('referenceTransferId')==prior['referenceTransferId']
             and all(type(native.get(k)) is int and native[k]==2 for k in ('aliasAdoptions','aliasReleases'))
             and all(native.get(k) is False for k in ('originalReferencesReleased','releasePacketAllowed','savedVerified'))
             and all(type(native.get(k)) is int and native[k]==0 for k in
                 ('configurationSaves','databaseUpdates','repositoryMutations','forcedFlagWrites')),
             'ROLLBACK_NATIVE_ALIAS_PROOF_REQUIRED')
        need(account.get('kind')=='RUNNER_ROLLBACK_ALIAS_ACCOUNTING'
             and account.get('sdkReceiptSha256')==result['sdkReceiptSha256']
             and account.get('nativeProofSha256')==result['nativeProofSha256']
             and all(account.get(k) is True for k in ('knownTerminal','hookWorkersReleased','targetIdentityVerified','packetRetained'))
             and all(account.get(k) is False for k in ('originalReferencesReleased','restoredPropertiesVerified'))
             and all(type(account.get(k)) is int and account[k]==v for k,v in
                 (('aliasAdoptions',2),('aliasReleases',2),('aliasesRemaining',0),('originalReferencesRemaining',2),
                  ('configurationSaves',0),('databaseUpdates',0),('repositoryMutations',0))),
             'ROLLBACK_LEDGER_REQUIRED')


def _audit_sheet_notification_pending(identity):
    """Known callback accounting permits reads; it never proves a saved object.

    Inspect durable intents even when the shared reservation was lost. This
    verifier is independent of the issuing transport and never invokes it.
    """
    keys=set('kind operationId pid birth nonce gui notificationPlanSha256 packageSha256 buildSha256 sealedObservationSha256 borrowedPreflightSha256 sdkAttempted'.split())
    native_keys=set('version identityVerified bindingsVerified bodyGateVerified callbackAttempted callbackReturned terminal reasonCode coreDirtyKnown coreDirtyAfter postBindingsVerified operationId planSha256'.split())
    for out in (ROOT/'build').glob('designer-sheet-notify-*'):
        op=out.name.removeprefix('designer-sheet-notify-')
        if not HEX32.fullmatch(op) or not out.is_dir():continue
        _plain(out,ROOT/'build')
        if not (out/'intent.json').exists():continue
        intent=parse(read(out/'intent.json',8192))
        need(type(intent) is dict and set(intent)==keys and intent.get('kind')=='SHEET_NOTIFICATION_INTENT'
             and intent.get('operationId')==op and type(intent.get('pid')) is int and intent['pid']>0
             and type(intent.get('gui')) is int and intent['gui']>0
             and type(intent.get('birth')) is str and re.fullmatch('[a-f0-9]{16}',intent['birth'])
             and type(intent.get('nonce')) is str and HEX32.fullmatch(intent['nonce'])
             and intent.get('sdkAttempted') is False
             and intent.get('sealedObservationSha256')=='449e1d9ce93855a829f2432ed2259cb90b6416a50678b6763a4b4e61e9ffe0ce'
             and intent.get('borrowedPreflightSha256')=='1ce686b80075c57aa231f92289b76755c2a76a8e6a2d3127955ef03d794d0f3d'
             and all(_writer_hash(intent.get(k)) for k in ('notificationPlanSha256','packageSha256','buildSha256')),
             'SHEET_NOTIFY_INTENT_SCOPE')
        if (intent['pid'],intent['birth'])!=identity:continue
        need((out/'result.json').is_file(),'SHEET_NOTIFY_UNKNOWN_RETAIN')
        result=parse(read(out/'result.json',8192))
        need(type(result) is dict and result.get('kind')=='SHEET_NOTIFICATION_ACCOUNTED_TERMINAL'
             and all(result.get(k) is True for k in ('knownTerminal','hookWorkersReleased','targetIdentityVerified','accountingVerified'))
             and all(result.get(k) is False for k in ('sdkAttempted','savedMainVerified','retryAuthorized'))
             and all(type(result.get(k)) is int and result[k]==0 for k in ('configurationSaves','databaseUpdates','repositoryMutations'))
             and type(result.get('pid')) is int and result['pid']==intent['pid']
             and all(result.get(k)==intent[k] for k in ('operationId','birth','nonce','notificationPlanSha256'))
             and result.get('intentSha256')==digest(canonical(intent)), 'SHEET_NOTIFY_ACCOUNTING_REQUIRED')
        receipt_raw=read(out/'native-receipt.json',8192);native_raw=read(out/'native-proof.json',8192)
        need(digest(receipt_raw)==result.get('nativeReceiptSha256') and digest(native_raw)==result.get('nativeProofSha256'),
             'SHEET_NOTIFY_PROOF_PIN')
        receipt=parse(receipt_raw);native=parse(native_raw)
        need(type(receipt) is dict and receipt.get('kind')=='SHEET_NOTIFICATION_RECEIPT'
             and receipt.get('status')=='NATIVE_TERMINAL_RETAIN' and receipt.get('sdkAttempted') is False
             and all(receipt.get(k) is True for k in ('knownTerminal','hookWorkersReleased','targetIdentityVerified'))
             and all(receipt.get(k)==intent[k] for k in ('operationId','birth','nonce','notificationPlanSha256'))
             and type(receipt.get('pid')) is int and receipt['pid']==intent['pid']
             and receipt.get('intentSha256')==result['intentSha256'] and type(receipt.get('nativeResult')) is int
             and _writer_hash(receipt.get('hostResultSha256')), 'SHEET_NOTIFY_RECEIPT_REQUIRED')
        stage=parse(read(out/'stage-package.json'));build=parse(read(out/'build-proof.json'))
        need(type(stage) is dict and type(build) is dict
             and stage.get('kind')=='SHEET_NOTIFICATION_PACKAGE' and stage.get('operationId')==op
             and stage.get('notificationPlanSha256')==intent['notificationPlanSha256']
             and digest(canonical(stage))==intent['packageSha256'] and digest(canonical(build))==intent['buildSha256']
             and build.get('packageSha256')==intent['packageSha256'], 'SHEET_NOTIFY_PACKAGE_JOIN')
        host_raw=read(out/'host-result.json',8192);host=parse(host_raw)
        need(digest(host_raw)==receipt['hostResultSha256'] and type(host) is dict
             and host.get('kind')=='SHEET_NOTIFICATION_HOST' and host.get('operationId')==op
             and host.get('notificationPlanSha256')==intent['notificationPlanSha256']
             and host.get('bindingSha256')==stage.get('bindingSha256') and _writer_hash(stage.get('bindingSha256'))
             and type(host.get('targetPid')) is int and type(host.get('threadId')) is int
             and (host.get('targetPid'),host.get('targetBirth'),host.get('heldNonce'),host.get('threadId'))==
                 (intent['pid'],intent['birth'],intent['nonce'],intent['gui'])
             and type(host.get('nativeResult')) is int and host['nativeResult']==receipt['nativeResult']
             and all(host.get(k) is True for k in ('knownTerminal','hookWorkersReleased'))
             and host.get('sdkAttempted') is False and host.get('scriptExecutionAttempted') is False,
             'SHEET_NOTIFY_HOST_JOIN')
        need(type(native) is dict and set(native)==native_keys
             and all(type(native[k]) is int for k in native_keys-{'operationId','planSha256'})
             and native['version']==1 and native['terminal']==1 and native['operationId']==op
             and native['planSha256']==intent['notificationPlanSha256'] and native['reasonCode']==receipt['nativeResult']
             and all(native[k] in (0,1) for k in native_keys-{'operationId','planSha256','version','reasonCode'}),
             'SHEET_NOTIFY_NATIVE_SCHEMA')
        if native['reasonCode']==0:
            need(all(native[k]==1 for k in ('identityVerified','bindingsVerified','bodyGateVerified','callbackAttempted',
                 'callbackReturned','postBindingsVerified','coreDirtyKnown')) and result.get('status')=='NOTIFIED_UNSAVED',
                 'SHEET_NOTIFY_NATIVE_COUNTERS')
        else:
            need(native['reasonCode'] in range(801,806) and native['callbackAttempted']==0
                 and native['callbackReturned']==0 and result.get('status')=='REFUSED_BEFORE_CALLBACK',
                 'SHEET_NOTIFY_PARTIAL_RETAIN')
            prefix={'identityVerified':int(native['reasonCode']>=804),
                    'bindingsVerified':int(native['reasonCode']>=805)}
            need(all(native[k]==v for k,v in prefix.items())
                 and all(native[k]==0 for k in ('bodyGateVerified','coreDirtyKnown','coreDirtyAfter','postBindingsVerified')),
                 'SHEET_NOTIFY_REFUSAL_PREFIX')
        need(all(type(result.get(k)) is int and result[k]==native[k] for k in ('callbackAttempted','callbackReturned')),
             'SHEET_NOTIFY_COUNTER_JOIN')


def _no_pending(allow_operation=None, context=None):
    """One target-wide reservation plus retained intents prevent UNKNOWN retry.

    The readonly233 namespace and separate writer263 metadata are inspected.
    An orphan/invalid intent is a refusal, never an invitation to remove a lock.
    """
    reservation_path=_reservation(context)
    nonce=NONCE if context is None else context.get('heldNonce',NONCE)
    identity=(41748,'01dd5c5d0f530273') if context is None else (context['processId'],context['birth'])
    if reservation_path.exists():
        lock=parse(read(reservation_path,8192))
        need(lock.get('version')==233 and lock.get('nonce')==nonce
             and lock.get('operationId')==allow_operation and allow_operation is not None,
             'TARGET_PENDING_RETAIN')
    for out in (ROOT/'build').glob('designer-hot-v233-*'):
        operation=out.name.removeprefix('designer-hot-v233-')
        if not HEX32.fullmatch(operation) or not out.is_dir() or operation==allow_operation:
            continue
        _plain(out,ROOT/'build')
        if not (out/'intent.json').exists():
            continue
        prior=parse(read(out/'plan.json'))
        need(prior.get('version')==233 and prior.get('probe') in FIXED_PROBES, 'PRIOR_INTENT_SCOPE')
        prior_identity=(prior.get('context',{}).get('processId'),prior.get('context',{}).get('birth'))
        need(type(prior_identity[0]) is int and prior_identity[0]>0
             and type(prior_identity[1]) is str and re.fullmatch('[a-f0-9]{16}',prior_identity[1]),
             'PRIOR_INTENT_IDENTITY')
        if prior_identity!=identity: continue
        need((out/'result.json').is_file(), 'PRIOR_UNKNOWN_RETAIN')
        result=parse(read(out/'result.json',8192))
        need(result.get('version')==233 and result.get('knownTerminal') is True
             and result.get('hookWorkersReleased') is True and result.get('targetIdentityVerified') is True
             and result.get('planSha256')==digest(canonical(prior)), 'PRIOR_UNKNOWN_RETAIN')
        sdk_terminal=(type(result.get('sdkResult')) is int and result.get('nativeInjectionPerformed') is True
                      and result.get('sdkAttempted') is not False)
        prestart_terminal=(result.get('status')=='CARRIER_BUILD_FAILED_BEFORE_START'
            and result.get('failureStage')=='V233_PHASE_CARRIER_BUILD' and result.get('sdkResult') is None
            and 'sdkResult' in result and result.get('sdkAttempted') is False
            and result.get('nativeInjectionPerformed') is False and result.get('noStartVerified') is True
            and result.get('hostGoneVerified') is True and result.get('targetStillRunningVerified') is True
            and _writer_hash(result.get('rootRecoveryProofSha256')))
        need(sdk_terminal or prestart_terminal,'PRIOR_UNKNOWN_RETAIN')
    _audit_writer_pending(identity)
    _audit_native_reference_pending(identity)
    _audit_runner_rollback_pending(identity)
    _audit_sheet_notification_pending(identity)


def make_plan(operation_id, *, held_nonce=NONCE, probe_name=PROBE_NAME,
              payload_receipt=None):
    """Fixed readonly probe; V240 requires an exact, target-bound V238 receipt.

    Receipt is not a lifetime capability. Root must retain its opaque RAM lease,
    mark it dispatched before run_root_once, and release only after a known
    terminal native result with hook workers/context/consumers released.
    UNKNOWN must retain both lease/allocation and the shared route reservation.
    """
    need(type(operation_id) is str and HEX32.fullmatch(operation_id),'OPERATION')
    spec=_probe_spec(probe_name)
    need(payload_receipt is None if probe_name!=RAM_PROBE else payload_receipt is not None,
         'PAYLOAD_REQUIRED' if probe_name==RAM_PROBE else 'UNEXPECTED_PAYLOAD')
    context=_context(held_nonce);_no_pending(context=context)
    payload=_payload_from_receipt(payload_receipt,operation_id,context) if probe_name==RAM_PROBE else None
    identity=inspect_owned(context); raw=read(HERE/spec[0],32768)
    need(digest(raw)==spec[2],'FIXED_PROBE_PIN');_probe_source(raw,probe_name)
    out=ROOT/'build'/('designer-hot-v233-'+operation_id)
    need(not _plain(out,ROOT/'build').exists(),'NEW_OUTPUT')
    plan=dict(version=233,probe=probe_name,operationId=operation_id,outputDirectory=str(out),context=context,
                sdkIdentity=identity,probeSha256=digest(raw),controllerSha256=digest(read(Path(__file__))),
                testSha256=digest(read(HERE.parent/'tests/test_live_sdk_continuation_v233.py')),
                nativeDriverPins=dict(SOURCE_PINS),writerAuthorized=False,captureAuthorized=False,
                applicationWrites=0,configurationExports=0,configurationImports=0,oneShot=True,
                loadedDllRequiresTargetExitBeforeCleanup=True)
    if payload is not None: plan['payload']=payload
    return plan


def _fresh(plan):
    need(type(plan) is dict and plan.get('version')==233 and plan.get('probe') in FIXED_PROBES
         and type(plan.get('operationId')) is str and HEX32.fullmatch(plan['operationId'])
         and Path(plan['outputDirectory'])==ROOT/'build'/('designer-hot-v233-'+plan['operationId']), 'PLAN_SCOPE')
    need(plan.get('writerAuthorized') is False and plan.get('captureAuthorized') is False
         and all(type(plan.get(k)) is int and plan[k]==0 for k in ('applicationWrites','configurationExports','configurationImports'))
         and plan.get('oneShot') is True and plan.get('loadedDllRequiresTargetExitBeforeCleanup') is True,'PLAN_AUTHORITY')
    _plan_payload(plan)
    need(_context(plan['context'].get('heldNonce',NONCE))==plan['context'] and inspect_owned(plan['context'])==plan['sdkIdentity'],'CURRENT_OWN_IDENTITY')
    spec=_probe_spec(plan['probe'])
    need(digest(read(HERE/spec[0],32768))==plan['probeSha256']==spec[2] and digest(read(Path(__file__)))==plan['controllerSha256']
         and digest(read(HERE.parent/'tests/test_live_sdk_continuation_v233.py'))==plan['testSha256']
         and plan['nativeDriverPins']==SOURCE_PINS,'CONTINUATION_SOURCE_PIN')


def _replace_once(raw,old,new):
    need(raw.count(old)==1 and new not in raw,'DERIVATION_ANCHOR')
    changed=raw.replace(old,new,1);need(changed.replace(new,old,1)==raw,'WHOLE_REVERSE');return changed


def render(plan,raw):
    """Generate fixed tool-only files; no script text argument is accepted live."""
    spec=_probe_spec(plan['probe'])
    text=_probe_source(raw,plan['probe']);need(digest(raw)==plan['probeSha256'],'PROBE_PIN')
    payload=_plan_payload(plan)
    out=Path(plan['outputDirectory']);target=plan['context'];sdk=plan['sdkIdentity']
    source=text.replace('__PROOF_PATH__',(out/spec[3]).as_posix())
    need('__PROOF_PATH__' not in source,'PROOF_PATH_REPLACED')
    if plan['probe'] in ('SHEET_CHANGE_RECEIVER','SHEET_DIRTY_STATE','SHEET_SAVE_COMMAND_STATE'):
        need(source.count('__OPERATION_ID__')==1,'OBSERVER_OPERATION_ANCHOR')
        source=source.replace('__OPERATION_ID__',plan['operationId'],1)
    if payload is not None:
        values=(hex(payload['address']),str(payload['length']),payload['sha256'],plan['operationId'])
        for token,value in zip(RAM_PLACEHOLDERS,values):
            need(source.count(token)==1,'PAYLOAD_RENDER_ANCHOR')
            source=source.replace(token,value,1)
        need(not any(token in source for token in RAM_PLACEHOLDERS),'PAYLOAD_REPLACED')
    b=int(target['birth'],16)
    defs=dict(AH_SDK_TARGET_PID=str(target['processId'])+'U',AH_SDK_BIRTH_LOW=hex(b&0xffffffff)+'U',
              AH_SDK_BIRTH_HIGH=hex(b>>32)+'U',AH_SDK_ENGINE_ADDRESS=hex(sdk['engineAddress'])+'U',
              AH_SDK_MODULE_ADDRESS=hex(sdk['moduleAddress'])+'U',AH_SDK_MESSAGE='0x83d2U',
              AH_SDK_EXPECTED_GUI_THREAD=str(target['guiThreadId'])+'U',
              AH_SDK_RESULT_FILE='L'+json.dumps((out/'sdk-result.bin').as_posix()),
              AH_SDK_ARM_FILE='L'+json.dumps((out/'arm-result.bin').as_posix()),
              AH_SDK_CALLBACK_FILE='L'+json.dumps((out/'callback-observe.bin').as_posix()),
              AH_SDK_FIXED_SOURCE=json.dumps(source,ensure_ascii=False))
    header='\n'.join('#define '+k+' '+v for k,v in defs.items())+'\n'
    native=read(HERE/'NativeSdkGoldDiagnosis.c').decode().replace('\r\n','\n')
    native=_replace_once(native,'if(GetCurrentThreadId()!=sdkGuiThread)rc=110;',
                         'if(GetCurrentThreadId()!=sdkGuiThread || sdkGuiThread!=AH_SDK_EXPECTED_GUI_THREAD)rc=110;')
    native=_replace_once(native,'if(!valid && diagnostic[0]==0)',
                         'if(thread!=AH_SDK_EXPECTED_GUI_THREAD)valid=FALSE;\n if(!valid && diagnostic[0]==0)')
    hook=read(HERE/'OwnedSdkDiagnosisHook.cs').decode().replace('\r\n','\n')
    hook=_replace_once(hook,'foreach(uint value in threads)tid=value;',
                       'foreach(uint value in threads)tid=value; Require(tid=='+str(target['guiThreadId'])+'U,"V233_GUI_THREAD");')
    hook=_replace_once(hook,'attachment.BeginLoad(pid,birth,fixedLibrary,dllHash);\n  while(!attachment.WaitLoad(10000))Thread.Sleep(10);',
                       'attachment.BeginLoad(pid,birth,fixedLibrary,dllHash);\n  Require(attachment.WaitLoad(10000),"V233_LOAD_UNKNOWN_RETAIN");')
    # CREATE_NEW exposes the ARM filename before its nonshared native handle
    # closes. Retry only that read; a successful ready record permits one post.
    hook=_replace_once(hook,
        'var armed=Stopwatch.StartNew();\n  while(!attachment.ArmReady){if(attachment.ArmFinished || armed.ElapsedMilliseconds>10000)throw new InvalidOperationException("SDK_ARM_READY_UNKNOWN");Thread.Sleep(10);}',
        'var armed=Stopwatch.StartNew();\n  while(true){\n'
        '   bool armReadyObservedV252=false;\n'
        '   try{armReadyObservedV252=attachment.ArmReady;}catch(IOException){ }\n'
        '   if(attachment.ArmFinished || armed.ElapsedMilliseconds>=10000)throw new InvalidOperationException("SDK_ARM_READY_UNKNOWN");\n'
        '   if(armReadyObservedV252)break;\n'
        '   Thread.Sleep(10);\n'
        '  }')
    hook=_replace_once(hook,'if(attachment.LoadAttempted && !attachment.LoadFinished)while(!attachment.WaitLoad(10000))Thread.Sleep(10);',
                       'if(attachment.LoadAttempted && !attachment.LoadFinished)Require(attachment.WaitLoad(10000),"V233_LOAD_UNKNOWN_RETAIN");')
    hook=_replace_once(hook,'if(attachment.ArmAttempted && !attachment.ArmFinished)while(!attachment.WaitArm(10000))Thread.Sleep(10);',
                       'if(attachment.ArmAttempted && !attachment.ArmFinished)Require(attachment.WaitArm(10000),"V233_ARM_UNKNOWN_RETAIN");')
    def q(path):
        need("'" not in str(path) and '\n' not in str(path),'PS_PATH');return "'"+str(path)+"'"
    ps=("$ErrorActionPreference='Stop'\nif([IntPtr]::Size -ne 4){throw 'V233_X86_REQUIRED'}\n"
        +"$phase='V233_PHASE_CARRIER_BUILD'\n$hook=$null\ntry {\n"
        +" Add-Type -Path @("+q(out/'OwnedSdkDiagnosisHook.cs')+","+q(out/'OwnedSdkReadonlyAttach.cs')+")\n"
        +" $hook=New-Object OwnedSdkDiagnosisHook\n $phase='V233_PHASE_START'\n"
        +" $hook.Start("+str(target['processId'])+",'"+target['birth']+"',"+q(out/'Continuation.dll')+")\n"
        +" $phase='V233_PHASE_WAIT_RESULT'\n"
        +" $code=$hook.WaitReadonlyResult("+q(out/'sdk-result.bin')+",20000)\n"
        +" $phase='V233_PHASE_DISPOSE'\n"
        +" $hook.Dispose()\n"
        +" $r=@{version=233;knownTerminal=$true;sdkResult=$code;threadId=$hook.ThreadId;hookWorkersReleased=$true}\n"
        +"} catch {\n $failureType='V233_TYPE_OTHER';$failureCode='V233_SDK_UNKNOWN_RETAIN'\n"
        +" $inner=$_.Exception\n"
        +" for($depth=0;$depth -lt 4 -and $null -ne $inner;$depth++){\n"
        +"  if($inner -is [IO.IOException]){$failureType='V233_TYPE_IO'}\n"
        +"  elseif($inner -is [InvalidOperationException]){$failureType='V233_TYPE_INVALID_OPERATION'}\n"
        +"  elseif($inner -is [TimeoutException]){$failureType='V233_TYPE_TIMEOUT'}\n"
        +"  elseif($inner -is [ComponentModel.Win32Exception]){$failureType='V233_TYPE_WIN32'}\n"
        +"  if($inner.Message -cmatch '\\A(?:SDK_|V233_)[A-Z0-9_]{1,96}\\z'){$failureCode=$inner.Message}\n"
        +"  $inner=$inner.InnerException\n }\n"
        +" $r=@{version=233;knownTerminal=$false;errorCode='V233_SDK_UNKNOWN_RETAIN';hookWorkersReleased=$false;failureStage=$phase;failureType=$failureType;failureCode=$failureCode}\n}\n"
        +"$b=[Text.Encoding]::UTF8.GetBytes(($r | ConvertTo-Json -Compress))\n"
        +"$s=[IO.File]::Open("+q(out/'host-result.json')+",[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)\n"
        +"try{$s.Write($b,0,$b.Length);$s.Flush($true)}finally{$s.Dispose()}\n"
        +"if(!$r.knownTerminal){while($true){[Threading.Thread]::Sleep(1000)}}\n")
    return {'sdk_probe_params.h':header.encode(),'Continuation.c':native.encode(),
            'OwnedSdkReadonlyAttach.cs':read(HERE/'OwnedSdkReadonlyAttach.cs'),
            'OwnedSdkDiagnosisHook.cs':hook.encode(),'run-fixed.ps1':ps.encode('utf-8-sig')}


def _carrier_compiler():
    # Fixed .NET compiler path, outside application/project sources. Read/hash
    # only: no assembly instantiation and no native helper load occurs here.
    compiler=Path('C:/Windows/Microsoft.NET/Framework/v4.0.30319/csc.exe')
    _plain(compiler,Path('C:/Windows'))
    need(compiler.is_file() and 0<compiler.stat().st_size<=16*1024*1024,'CARRIER_COMPILER')
    raw=compiler.read_bytes();need(0<len(raw)<=16*1024*1024,'CARRIER_COMPILER')
    return compiler,digest(raw)


def stage_private(plan,grant):
    """Compile C# preflight and native tool helper; never loads either assembly."""
    _grant(plan,grant,'ROOT_STAGE_SEALED_CONTINUATION_V233');_no_pending(context=plan['context']);_fresh(plan)
    out=_plain(plan['outputDirectory'],ROOT/'build');need(not out.exists(),'NEW_OUTPUT')
    files=render(plan,read(HERE/_probe_spec(plan['probe'])[0],32768));out.mkdir()
    write_new(out/'plan.json',plan)
    for name,raw in files.items():
        with (out/name).open('xb') as handle: handle.write(raw);handle.flush();os.fsync(handle.fileno())
        need(read(out/name)==raw,'DERIVED_READBACK')
    compiler=Path(plan['context'].get('buildDirectory',BUILD))/'compiler/tcc/tcc.exe';need(digest(read(compiler))==TCC_SHA,'COMPILER_PIN')
    command=[str(compiler),'-shared','-I'+str(out),str(out/'Continuation.c'),str(HERE/'NativeSdkCall.s'),
             '-lkernel32','-luser32','-o',str(out/'Continuation.dll')]
    try:
        carrier_compiler,carrier_compiler_sha=_carrier_compiler()
        carrier_library=out/'OwnedCarrierPreflight.dll'
        carrier_command=[str(carrier_compiler),'/nologo','/target:library','/platform:x86',
                         '/out:'+str(carrier_library),str(out/'OwnedSdkDiagnosisHook.cs'),str(out/'OwnedSdkReadonlyAttach.cs')]
        carrier_result=subprocess.run(carrier_command,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
                                      creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        need(carrier_result.returncode==0 and len(carrier_result.stdout)+len(carrier_result.stderr)<=16384,'CARRIER_COMPILE')
        need(carrier_library.is_file(),'CARRIER_LIBRARY')
        carrier_library_sha=digest(read(carrier_library))
        need(_carrier_compiler()==(carrier_compiler,carrier_compiler_sha),'CARRIER_COMPILER_CHANGED')
        need(all(read(out/name)==files[name] for name in ('OwnedSdkDiagnosisHook.cs','OwnedSdkReadonlyAttach.cs')),
             'CARRIER_SOURCE_DRIFT')
        result=subprocess.run(command,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
                              creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=16384,'HELPER_COMPILE')
        need((out/'Continuation.dll').is_file(),'HELPER_LIBRARY')
        _fresh(plan)
        proof=dict(version=233,passed=True,goldStarted=False,planSha256=digest(canonical(plan)),
                   derivedSha256={name:digest(read(out/name)) for name in FILES},
                   librarySha256=digest(read(out/'Continuation.dll')),compilerSha256=TCC_SHA,
                   compileExitCode=0,nativeInjectionPerformed=False,
                   carrierCompilerSha256=carrier_compiler_sha,carrierAssemblySha256=carrier_library_sha,
                   carrierCompileExitCode=0,carrierPreflightOnly=True,carrierAssemblyExecuted=False)
        write_new(out/'build-proof.json',proof);return proof
    finally:
        _fresh(plan)


def require_stage(plan):
    _fresh(plan);out=_plain(plan['outputDirectory'],ROOT/'build')
    need(parse(read(out/'plan.json'))==plan,'STAGED_PLAN')
    proof=parse(read(out/'build-proof.json'))
    need(proof.get('version')==233 and proof.get('passed') is True and proof.get('goldStarted') is False
         and proof.get('planSha256')==digest(canonical(plan)) and proof.get('nativeInjectionPerformed') is False
         and proof.get('compilerSha256')==TCC_SHA and type(proof.get('compileExitCode')) is int and proof['compileExitCode']==0,'BUILD_PROOF')
    need(proof.get('carrierPreflightOnly') is True and proof.get('carrierAssemblyExecuted') is False
         and type(proof.get('carrierCompileExitCode')) is int and proof['carrierCompileExitCode']==0
         and _carrier_compiler()[1]==proof.get('carrierCompilerSha256')
         and digest(read(out/'OwnedCarrierPreflight.dll'))==proof.get('carrierAssemblySha256'),'CARRIER_BUILD_PROOF')
    files=render(plan,read(HERE/_probe_spec(plan['probe'])[0],32768))
    need(set(proof['derivedSha256'])==set(FILES) and all(read(out/n)==raw and digest(raw)==proof['derivedSha256'][n]
         for n,raw in files.items()) and digest(read(out/'Continuation.dll'))==proof['librarySha256'],'STAGE_PINS')
    return proof


_HELD_HOSTS={}


def run_root_once(plan,grant):
    """Only explicit root/review-bound dispatch; UNKNOWN host/target are retained."""
    _grant(plan,grant,'ROOT_RUN_SEALED_CONTINUATION_V233',review=True)
    _no_pending(context=plan['context']);proof=require_stage(plan);out=Path(plan['outputDirectory'])
    attempt_files={'intent.json','sdk-result.bin','host-result.json','arm-result.bin','callback-observe.bin'}
    attempt_files.update(spec[3] for spec in FIXED_PROBES.values())
    need(not any((out/n).exists() for n in attempt_files),'ONE_ATTEMPT')
    reservation_path=_reservation(plan['context'])
    reservation=dict(version=233,nonce=plan['context'].get('heldNonce',NONCE),operationId=plan['operationId'],planSha256=digest(canonical(plan)),
                     processId=plan['context']['processId'],birth=plan['context']['birth'])
    write_new(reservation_path,reservation)
    _no_pending(allow_operation=plan['operationId'],context=plan['context'])
    write_new(out/'intent.json',dict(version=233,operationId=plan['operationId'],planSha256=digest(canonical(plan)),
              librarySha256=proof['librarySha256'],state='RESERVED_BEFORE_REMOTE_LOAD',probe=plan['probe']))
    ps=Path('C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell.exe')
    need(ps.is_file(),'X86_POWERSHELL')
    host=subprocess.Popen([str(ps),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(out/'run-fixed.ps1')],
                          cwd=out,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                          creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    _HELD_HOSTS[plan['operationId']]=host
    # Store the host's birth before waiting. This permits exact owned recovery;
    # timeout never terminates it or retries the native message.
    k=ct.WinDLL('kernel32',use_last_error=True);from ctypes import wintypes as w
    k.GetProcessTimes.argtypes=[w.HANDLE]+[ct.POINTER(ct.c_uint64)]*4
    times=[ct.c_uint64() for _ in range(4)]
    need(k.GetProcessTimes(int(host._handle),*(ct.byref(x) for x in times)),'HOST_BIRTH_UNKNOWN_RETAIN')
    write_new(out/'host-identity.json',dict(processId=host.pid,birth=f'{times[0].value:016x}',target=plan['context']['processId']))
    deadline=time.monotonic()+55
    while time.monotonic()<deadline:
        path=out/'host-result.json'
        if path.exists():
            try: result=parse(read(path,4096))
            except (OSError,ValueError): time.sleep(.05);continue
            need(result.get('version')==233,'HOST_RESULT')
            if result.get('knownTerminal') is True and result.get('hookWorkersReleased') is True:
                try: host.wait(timeout=5)
                except subprocess.TimeoutExpired: break
                need(host.returncode==0 and result.get('threadId')==plan['context']['guiThreadId'],'HOST_TERMINAL')
                _fresh(plan)
                need(type(result.get('sdkResult')) is int,'SDK_RESULT')
                result.update(planSha256=digest(canonical(plan)),targetIdentityVerified=True,
                              policyProofPresent=(out/'policy-proof.json').is_file(),
                              probe=plan['probe'],probeProofPresent=(out/_probe_spec(plan['probe'])[3]).is_file(),
                              nativeInjectionPerformed=True)
                write_new(out/'result.json',result)
                need(parse(read(reservation_path,8192))==reservation,'TARGET_RESERVATION_CHANGED')
                reservation_path.unlink()
                return result
            break
        if host.poll() is not None: break
        time.sleep(.05)
    result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,hostProcessId=host.pid,
                targetProcessId=plan['context']['processId'],retryAuthorized=False,nativeInjectionPerformed=True)
    write_new(out/'unknown.json',result);return result


if __name__=='__main__':
    raise SystemExit('V233_ROOT_ONLY_NO_CLI')
