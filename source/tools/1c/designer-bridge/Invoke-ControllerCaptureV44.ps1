param([Parameter(Mandatory)][string]$ConnectionFile,
 [Parameter(Mandatory)][ValidateSet('PING','STATUS','READLIVE','SOURCE_ONCE','UI_CAPTURE_CYCLE_V44','CLOSE_SAFE')][string]$Command,
 [string]$OperationId=([guid]::NewGuid().ToString('N')),
 [switch]$ReplayExistingCapture)
$ErrorActionPreference='Stop'
try {
 if([IntPtr]::Size -ne 4 -or $OperationId -cnotmatch '^[a-f0-9]{32}$'){throw 'V44_CLIENT_SCOPE'}
 $path=[IO.Path]::GetFullPath($ConnectionFile);$session=Split-Path $path -Parent;$build=Split-Path $session -Parent
 if($path -cnotmatch '^F:\\Projects\\AH_1C\\build\\designer-v43-[a-f0-9]{32}\\session-[a-f0-9]{32}\\command-connection.json$'){throw 'V44_CLIENT_PATH'}
 foreach($p in @($path,$session,$build)){if((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V44_CLIENT_REPARSE'}}
 function Sha([string]$File){
  # The x86 worker may inherit a PS7 module path. Hash through .NET so the
  # protected client does not depend on PowerShell module auto-loading.
  $stream=[IO.File]::OpenRead($File);$algorithm=[Security.Cryptography.SHA256]::Create()
  try{return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}
  finally{$algorithm.Dispose();$stream.Dispose()}
 }
 Add-Type -AssemblyName System.Security
 $record=[IO.File]::ReadAllText($path)|ConvertFrom-Json
 $payload=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($record.protectedConnection),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-COMMAND-V2'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
 $c=(New-Object Text.UTF8Encoding($false,$true)).GetString($payload)|ConvertFrom-Json
 if($c.version -ne 2 -or $c.target -cne 'Gold' -or $c.platform -cne '8.3.18.1208' -or $c.rootId -cne '218b5d00-7e10-486f-874c-73c2368ed5da' -or $c.objectId -cne '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d' -or $c.uiControllerCaptureV44 -ne $true -or $c.readOnlyGold -ne $false -or $c.captureScope -cne 'none' -or $c.captureWriteAllowed -ne $false -or $c.pilotScope -cne 'none' -or $c.uiCaptureTokenV44 -cnotmatch '^[a-f0-9]{32}$'){throw 'V44_CLIENT_ROLE'}
 $source=Join-Path $PSScriptRoot 'tests/NativeControllerCaptureV44.as'
 if((Sha $source) -cne $c.uiCaptureSourceSha256 -or (Sha (Join-Path $PSScriptRoot 'NativeCommandClient.cs')) -cne $c.clientSourceSha256){throw 'V44_SOURCE_CHANGED'}
 $dll=Join-Path $build 'NativeCommandClient.dll';if((Sha $dll) -cne $c.clientDllSha256){throw 'V44_CLIENT_IMAGE_CHANGED'}
 $null=[Reflection.Assembly]::LoadFrom($dll)
 $client=[NativeCommandClient]::OpenSession($c.pipeName,[uint32]$c.processId,$c.processCreationFileTimeUtc,$c.sessionId)
 try {
  if($Command -ceq 'UI_CAPTURE_CYCLE_V44'){
   # Independent codec comparison is bound to the actual source packet and live text.
   $proofFile=Join-Path $session 'ui-v44-source-equality.json'
   $comparison=[IO.File]::ReadAllText($proofFile)|ConvertFrom-Json
   if($comparison.processId -ne $c.processId -or $comparison.birth -cne $c.processCreationFileTimeUtc -or $comparison.sessionId -cne $c.sessionId -or $comparison.normalizedLineEndingsEqual -ne $true -or $comparison.modulePacketSha256 -cne (Sha (Join-Path $session 'repository-module.bin'))){throw 'V44_SOURCE_EQUALITY_REQUIRED'}
   $permit=Join-Path $session 'ui-v44.permit';$bytes=[Text.Encoding]::ASCII.GetBytes($c.uiCaptureTokenV44+' '+$OperationId)
   if($ReplayExistingCapture){
    # An exact replay reads the native cached response, without inserting a
    # different command first. A consumed native operation cannot dispatch again.
    $prior=[IO.File]::ReadAllBytes($permit)
    if($prior.Length -ne 65 -or [Convert]::ToBase64String($prior) -cne [Convert]::ToBase64String($bytes) -or [IO.File]::ReadAllText((Join-Path $session 'ui-v44-capture-dispatched')) -cne $OperationId){throw 'V44_REPLAY_SCOPE'}
   }else{
   $live=$client.Send([guid]::NewGuid().ToString('N'),'READLIVE')
   $sha=[Security.Cryptography.SHA256]::Create()
   try{$liveHash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($live.Body))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
   if($live.Kind -cne 'READLIVE' -or $liveHash -cne $comparison.liveTextSha256){throw 'V44_LIVE_BASELINE_CHANGED'}
   $stream=[IO.File]::Open($permit,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
   try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
   }
  }elseif($ReplayExistingCapture){throw 'V44_REPLAY_COMMAND'}
  $reply=$client.Send($OperationId,$Command)
 }finally{$client.Dispose()}
 $result=Join-Path $session ('ui-client-'+$OperationId+'-'+[guid]::NewGuid().ToString('N')+'.txt')
 $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes($reply.Body)
 $stream=[IO.File]::Open($result,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
 if($Command -ceq 'CLOSE_SAFE' -and $reply.Kind -ceq 'CLOSE_SAFE' -and $reply.Body -ceq 'SAFE_CLOSE_PROPOSED'){
  $ack=[ordered]@{version=1;operationId=$OperationId;sessionId=$c.sessionId;processId=$c.processId;processCreationFileTimeUtc=$c.processCreationFileTimeUtc}
  $sealed=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes(($ack|ConvertTo-Json -Compress)),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-CLOSE-ACK-V1'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
  [IO.File]::WriteAllBytes((Join-Path $session 'command-close-ack.protected'),$sealed)
  [IO.File]::WriteAllText((Join-Path $session 'command-close-ack'),$OperationId,(New-Object Text.UTF8Encoding($false)))
 }
 [ordered]@{status=$reply.Kind;command=$Command;operationId=$OperationId;replayed=$reply.Replayed;processId=$c.processId;birth=$c.processCreationFileTimeUtc;resultFile=$result;bytes=$bytes.Length;sha256=(Sha $result)}|ConvertTo-Json -Compress
 if($reply.Kind -ceq 'ERROR'){exit 1}
}catch{
 # Never expose raw launch/connection exceptions. Source errors are local constant signatures.
 $diagnostic=$_.Exception
 while($diagnostic.InnerException){$diagnostic=$diagnostic.InnerException}
 $code=[regex]::Match($diagnostic.Message,'\b(?:V44|COMMAND|PIPE)_[A-Z_0-9]{3,63}\b')
 [ordered]@{status='V44_CLIENT_REJECTED';errorType=$_.Exception.GetType().Name;errorLine=$_.InvocationInfo.ScriptLineNumber;code=$(if($code.Success){$code.Value}else{'V44_CLIENT_FAILED'})}|ConvertTo-Json -Compress
 exit 85
}
