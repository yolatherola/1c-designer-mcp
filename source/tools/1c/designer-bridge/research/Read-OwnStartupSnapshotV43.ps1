param([Parameter(Mandatory)][string]$BuildDirectory)
$ErrorActionPreference='Stop'
if([IntPtr]::Size -ne 4){throw 'X86_SNAPSHOT_DIAG_REQUIRED'}
$build=[IO.Path]::GetFullPath($BuildDirectory)
if($build -cnotmatch '^F:\\Projects\\AH_1C\\build\\designer-v43-[a-f0-9]{32}$'){throw 'V43_OWN_SCOPE_REQUIRED'}
$identity=[IO.File]::ReadAllText((Join-Path $build 'owned-process-v43.json'))|ConvertFrom-Json
$process=Get-Process -Id $identity.pid -ErrorAction Stop
if($process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString('x16') -cne $identity.birth){throw 'V43_OWN_BIRTH_CHANGED'}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SnapshotV43 {
 [DllImport("kernel32",SetLastError=true)]static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint pid);
 [DllImport("kernel32")]static extern bool CloseHandle(IntPtr h);
 public static int Probe(uint pid){
  IntPtr snapshot=CreateToolhelp32Snapshot(0x18,pid);
  if(snapshot==new IntPtr(-1))return Marshal.GetLastWin32Error();
  CloseHandle(snapshot);return 0;
 }
}
'@
$errorNumber=[SnapshotV43]::Probe([uint32]$identity.pid)
if($process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString('x16') -cne $identity.birth){throw 'V43_OWN_BIRTH_CHANGED'}
[ordered]@{pid=$identity.pid;birth=$identity.birth;callerX86=$true;snapshotError=$errorNumber;sourceWrites=0}|ConvertTo-Json -Compress
