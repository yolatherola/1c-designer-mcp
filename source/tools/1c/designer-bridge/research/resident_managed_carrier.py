"""Pure derivatives of the proven attach templates for one resident host.

No compilation, loading, process creation, or 1C call occurs in this module.
The parent must first validate CLOSE/epoch/EOF, then explicitly release this
host's join gate. An uncertain load/arm/result retains original owned handles.
"""
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT/'build/designer-hot-v233-120b286802e1465094e1252a3b3ab5af'
PINS = {'OwnedSdkDiagnosisHook.cs': '4cb409f9b74769de2ed69ac25006e22745bb3dc12f4e26e440f3e237d6e59152',
        'OwnedSdkReadonlyAttach.cs': 'a7de6eca80102baac65f7b08970cfa65444d4be89990ad7b225d1e9dbff9e87e'}


def need(ok, code):
    if not ok:
        raise ValueError('RESIDENT_MANAGED_'+code)


def replace_once(source, old, new):
    need(source.count(old) == 1, 'TEMPLATE_ANCHOR')
    return source.replace(old, new, 1)


def render(configuration, identity):
    """Return two pinned C# derivatives and one bounded-lifecycle PS script."""
    for name in ('processId', 'guiThreadId'):
        need(type(identity.get(name)) is int and 0 < identity[name] < 2**32, 'IDENTITY')
    need(identity['guiThreadId'] == 8292
         and type(identity.get('birth')) is str and identity['birth'] != '0'*16
         and re.fullmatch('[0-9a-f]{16}', identity['birth']) is not None, 'FIXED_THREAD')
    paths = [Path(configuration[k]).resolve() for k in ('armPath', 'resultPath')]
    out = paths[0].parent
    need(out.is_relative_to((ROOT/'build').resolve()) and paths[1].parent == out
         and paths[0] != paths[1] and paths[0].name == 'resident-arm.bin'
         and paths[1].name == 'resident-sdk-result.bin', 'PATHS')
    need(re.fullmatch('[0-9a-f]{32}', configuration.get('operationId', '')) is not None,
         'OPERATION')
    files = {}
    for name, pin in PINS.items():
        raw = (BASE/name).read_bytes()
        need(hashlib.sha256(raw).hexdigest() == pin, 'TEMPLATE_PIN')
        files[name] = raw.decode('utf-8-sig')
    attach = replace_once(files['OwnedSdkReadonlyAttach.cs'], '"slot0-arm.bin"', '"resident-arm.bin"')
    hook = replace_once(files['OwnedSdkDiagnosisHook.cs'],
        'Require(PostThreadMessage(tid,0x83d2,IntPtr.Zero,IntPtr.Zero),"SDK_PRIVATE_MESSAGE_FAILED");dispatched=true;',
        '// The resident C worker exclusively posts sequence-tagged messages.\n  dispatched=true;')
    files = {'OwnedSdkReadonlyAttach.cs': attach.encode('utf-8-sig'),
             'OwnedSdkDiagnosisHook.cs': hook.encode('utf-8-sig')}
    # Paths are launcher-owned fixed files. Reject PowerShell quote/newline
    # characters instead of interpolating arbitrary client strings into code.
    for path in (out, *paths):
        need(re.fullmatch(r'[A-Za-z]:[\\/A-Za-z0-9_.-]+', str(path)) is not None, 'SHELL_PATH')
    def quoted(path):
        return "'"+str(path)+"'"
    script = """$ErrorActionPreference='Stop'
if([IntPtr]::Size -ne 4){throw 'RESIDENT_X86_REQUIRED'}
$phase='BUILD';$hook=$null
function WriteOwnedJson([string]$path,$row){
 $bytes=[Text.Encoding]::UTF8.GetBytes(($row | ConvertTo-Json -Compress))
 $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
try {
 Add-Type -Path @(__HOOK__,__ATTACH__)
 $hook=New-Object OwnedSdkDiagnosisHook
 $phase='START'
 $hook.Start(__PID__,'__BIRTH__',__DLL__)
 $phase='RESIDENT_WAITING'
 WriteOwnedJson __READY__ @{kind='RESIDENT_MANAGED_READY';operationId='__OP__';processId=__PID__;threadId=$hook.ThreadId;nativeSourceBindingVerified=$false;workerExpectedAlive=$true}
 # Closing stdin or an arbitrary line is not a verified native CLOSE.
 $gate=[Console]::ReadLine()
 if($gate -cne 'JOIN_VERIFIED_CLOSE'){throw 'RESIDENT_JOIN_REQUIRED'}
 $phase='NATIVE_RESULT'
 $code=$hook.WaitReadonlyResult(__SDK__,20000)
 if($code -ne 0){throw 'RESIDENT_NATIVE_TERMINAL_NONZERO'}
 $phase='JOIN_WORKER'
 $hook.Dispose()
 $row=@{kind='RESIDENT_MANAGED_TERMINAL';operationId='__OP__';knownTerminal=$true;sdkResult=$code;threadId=$hook.ThreadId;hookWorkersReleased=$true;writerAuthorized=$false}
} catch {
 $failure='RESIDENT_UNKNOWN_RETAIN'
 $inner=$_.Exception
 for($n=0;$n -lt 4 -and $null -ne $inner;$n++){
  if($inner.Message -cmatch '\\A(?:SDK_|V233_|RESIDENT_)[A-Z0-9_]{1,96}\\z'){$failure=$inner.Message}
  $inner=$inner.InnerException
 }
 $row=@{kind='RESIDENT_MANAGED_TERMINAL';operationId='__OP__';knownTerminal=$false;hookWorkersReleased=$false;writerAuthorized=$false;failureStage=$phase;failureCode=$failure}
}
try{WriteOwnedJson __TERMINAL__ $row}
finally{if(!$row.knownTerminal){while($true){[Threading.Thread]::Sleep(1000)}}}
"""
    replacements = {'__HOOK__': quoted(out/'OwnedSdkDiagnosisHook.cs'),
        '__ATTACH__': quoted(out/'OwnedSdkReadonlyAttach.cs'), '__PID__': str(identity['processId']),
        '__BIRTH__': identity['birth'], '__DLL__': quoted(out/'Continuation.dll'),
        '__READY__': quoted(out/'resident-host-ready.json'), '__OP__': configuration['operationId'],
        '__SDK__': quoted(paths[1]), '__TERMINAL__': quoted(out/'resident-host-result.json')}
    for key, value in replacements.items():
        script = script.replace(key, value)
    need(re.search(r'__[A-Z_]+__', script) is None, 'SCRIPT_TOKENS')
    files['run-resident.ps1'] = script.encode('utf-8-sig')
    return files
