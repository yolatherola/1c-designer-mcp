param([Parameter(Mandatory)][string]$ConnectionFile,[Parameter(Mandatory)][string]$ExpectedSha256)
$ErrorActionPreference='Stop'
if([IntPtr]::Size -ne 4 -or $ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'V45_CALLER_REJECTED'}
$path=[IO.Path]::GetFullPath($ConnectionFile)
if($path -cnotmatch '^F:\\Projects\\AH_1C\\build\\designer-v43-[a-f0-9]{32}\\session-[a-f0-9]{32}\\command-connection.json$'){throw 'V45_PATH_REJECTED'}
$session=Split-Path $path -Parent;$build=Split-Path $session -Parent
foreach($p in @($path,$session,$build)){if((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V45_REPARSE_REJECTED'}}
Add-Type -AssemblyName System.Security
$published=[IO.File]::ReadAllText($path)|ConvertFrom-Json
$payload=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($published.protectedConnection),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-COMMAND-V2'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
$connection=(New-Object Text.UTF8Encoding($false,$true)).GetString($payload)|ConvertFrom-Json
if($connection.version -ne 2 -or $connection.readOnlyGold -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.pilotScope -cne 'none' -or $connection.captureScope -cne 'none' -or $connection.captureWriteAllowed -ne $false -or $connection.target -cne 'Gold' -or $connection.platform -cne '8.3.18.1208'){throw 'V45_ROLE_REJECTED'}
$crypto=[Security.Cryptography.SHA256]::Create()
try{
 function HashBytes([byte[]]$Bytes){return [BitConverter]::ToString($crypto.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}
 $dll=Join-Path $build 'NativeCommandClient.dll'
 if((HashBytes ([IO.File]::ReadAllBytes($dll))) -cne $connection.clientDllSha256 -or (HashBytes ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '../NativeCommandClient.cs')))) -cne $connection.clientSourceSha256){throw 'V45_CLIENT_CHANGED'}
 $null=[Reflection.Assembly]::LoadFrom($dll)
 function OpenClient(){return [NativeCommandClient]::OpenSession($connection.pipeName,[uint32]$connection.processId,$connection.processCreationFileTimeUtc,$connection.sessionId)}
 $client=OpenClient
 try{$before=$client.Send([guid]::NewGuid().ToString('N'),'STATUS').Body|ConvertFrom-Json}finally{$client.Dispose()}
 if($before.scopeAlive -ne $true -or $before.dirty.refreshAllowed -ne $true){throw 'V45_DIRTY_BEFORE'}
 $rows=@()
 for($n=0;$n -lt 8;$n++){
  $operation=[guid]::NewGuid().ToString('N');$drop=OpenClient
  try{$drop.SendReadAndDisconnect($operation)}finally{$drop.Dispose()}
  Start-Sleep -Milliseconds 70
  $client=OpenClient
  try{$reply=$client.Send($operation,'READLIVE')}finally{$client.Dispose()}
  if($reply.Kind -cne 'READLIVE' -or (HashBytes ([Text.Encoding]::UTF8.GetBytes($reply.Body))) -cne $ExpectedSha256){throw 'V45_READ_REPLAY_CHANGED'}
  $rows+=@{operationId=$operation;replayed=[bool]$reply.Replayed;sha256=$ExpectedSha256}
 }
 $client=OpenClient
 try{$after=$client.Send([guid]::NewGuid().ToString('N'),'STATUS').Body|ConvertFrom-Json}finally{$client.Dispose()}
 if($after.scopeAlive -ne $true -or $after.dirty.refreshAllowed -ne $true -or $after.repositoryMutations -ne 0 -or $after.goldConfigurationWrites -ne 0){throw 'V45_DIRTY_AFTER'}
 $delta=$after.transport.syncResponseDisconnects-$before.transport.syncResponseDisconnects
 [ordered]@{passed=$true;syncWriteDisconnectBranchVerified=($delta -gt 0);syncResponseDisconnects=$delta;exactReplays=@($rows|Where-Object {$_.replayed}).Count;trials=$rows;processId=$connection.processId;birth=$connection.processCreationFileTimeUtc;sourceWrites=0;repositoryMutations=0;beforeCommands=$before.commandsExecuted;afterCommands=$after.commandsExecuted}|ConvertTo-Json -Depth 6 -Compress
}finally{$crypto.Dispose()}
