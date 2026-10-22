param([Parameter(Mandatory)][string]$ConnectionFile,[Parameter(Mandatory)][string]$ExpectedSha256)
$ErrorActionPreference='Stop'
if([IntPtr]::Size -ne 4 -or $ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'V43_BENCH_CALLER_REJECTED'}
$path=[IO.Path]::GetFullPath($ConnectionFile)
if($path -cnotmatch '^F:\\Projects\\AH_1C\\build\\designer-v43-[a-f0-9]{32}\\session-[a-f0-9]{32}\\command-connection.json$'){throw 'V43_BENCH_OWN_SCOPE_REQUIRED'}
foreach($candidate in @($path,(Split-Path $path -Parent),(Split-Path (Split-Path $path -Parent) -Parent))){
 if((Get-Item -LiteralPath $candidate).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V43_BENCH_PATH_REJECTED'}
}
Add-Type -AssemblyName System.Security
$published=[IO.File]::ReadAllText($path)|ConvertFrom-Json
$payload=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($published.protectedConnection),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-COMMAND-V2'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
$connection=(New-Object Text.UTF8Encoding($false,$true)).GetString($payload)|ConvertFrom-Json
if($connection.readOnlyGold -ne $true -or $connection.pilotScope -cne 'none' -or $connection.captureWriteAllowed -eq $true -or $connection.target -cne 'Gold' -or $connection.platform -cne '8.3.18.1208'){throw 'V43_BENCH_READ_ONLY_REQUIRED'}
$build=Split-Path (Split-Path $path -Parent) -Parent
$dll=Join-Path $build 'NativeCommandClient.dll'
$crypto=[Security.Cryptography.SHA256]::Create()
try {
 $hash=[BitConverter]::ToString($crypto.ComputeHash([IO.File]::ReadAllBytes($dll))).Replace('-','').ToLowerInvariant()
 if($hash -cne $connection.clientDllSha256){throw 'V43_BENCH_CLIENT_IMAGE_CHANGED'}
 $null=[Reflection.Assembly]::LoadFrom($dll)
 $client=[NativeCommandClient]::OpenSession($connection.pipeName,[uint32]$connection.processId,$connection.processCreationFileTimeUtc,$connection.sessionId)
 try {
  $roundTrips=@();$bytesCount=0
  for($n=0;$n -lt 20;$n++){
   $watch=[Diagnostics.Stopwatch]::StartNew()
   $reply=$client.Send([guid]::NewGuid().ToString('N'),'READLIVE')
   $elapsed=$watch.Elapsed.TotalMilliseconds
   if($reply.Kind -cne 'READLIVE' -or $reply.Replayed){throw 'V43_BENCH_READ_REJECTED'}
   $bytes=[Text.Encoding]::UTF8.GetBytes($reply.Body)
   $hash=[BitConverter]::ToString($crypto.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()
   if($hash -cne $ExpectedSha256){throw 'V43_BENCH_MODULE_CHANGED'}
   $roundTrips+=$elapsed;$bytesCount=$bytes.Length
  }
  $ordered=@($roundTrips|Sort-Object)
  [ordered]@{passed=$true;reads=20;oneConnection=$true;processId=$connection.processId;birth=$connection.processCreationFileTimeUtc;bytes=$bytesCount;sha256=$ExpectedSha256;nativeRoundTripsMs=$roundTrips;medianMs=(($ordered[9]+$ordered[10])/2);p95Ms=$ordered[18];goldWrites=0;repositoryMutations=0}|ConvertTo-Json -Compress
 } finally {$client.Dispose()}
} finally {$crypto.Dispose()}
