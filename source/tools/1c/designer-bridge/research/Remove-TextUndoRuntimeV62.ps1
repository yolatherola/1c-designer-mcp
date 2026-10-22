param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce)
$ErrorActionPreference='Stop'
$taskRoot='F:\Projects\AH_1C'
function Sha([string]$Path){$taskHash=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($taskHash.ComputeHash([IO.File]::ReadAllBytes($Path))).Replace('-','').ToLowerInvariant()}finally{$taskHash.Dispose()}}
$taskPath=[IO.Path]::GetFullPath((Join-Path $taskRoot ('build\native-text-undo-v62-'+$Nonce)))
if([IO.Path]::GetDirectoryName($taskPath) -cne (Join-Path $taskRoot 'build')){throw 'V62_BOUNDARY'}
$taskProofPath=Join-Path $taskRoot ('artifacts\designer-bridge\v62-independent-text-undo-'+$Nonce+'.json')
$taskProof=[IO.File]::ReadAllText($taskProofPath)|ConvertFrom-Json
$taskOwner=[IO.File]::ReadAllText((Join-Path $taskPath 'runtime-owner.json'))|ConvertFrom-Json
if($taskProof.stage -cne 'V62IndependentNativeTextUndo' -or $taskProof.nonce -cne $Nonce -or $taskProof.runtimeDirectory -cne $taskPath -or $taskProof.goldCalls -ne 0 -or $taskProof.repositoryMutations -ne 0 -or $taskProof.forcedStops -ne 0 -or !$taskProof.allOriginalsGone -or $taskOwner.task -cne 'DESIGNER-DIRECT-API/V62-TextUndo' -or $taskOwner.nonce -cne $Nonce){throw 'V62_CLEANUP_PROOF'}
foreach($taskPin in $taskProof.sourceSha256.PSObject.Properties){if((Sha (Join-Path $taskRoot $taskPin.Name)) -cne $taskPin.Value){throw 'V62_SOURCE_PIN_CHANGED'}}
foreach($taskIdentity in $taskProof.processes){
 try {$taskProcess=[Diagnostics.Process]::GetProcessById($taskIdentity.pid)} catch [ArgumentException] {continue}
 try {if($taskProcess.StartTime.ToUniversalTime().ToFileTimeUtc().ToString('x16') -ceq $taskIdentity.birth -and !$taskProcess.HasExited){throw 'V62_ORIGINAL_ALIVE'}}finally{$taskProcess.Dispose()}
}
foreach($taskItem in @((Get-Item -LiteralPath $taskPath))+@(Get-ChildItem -LiteralPath $taskPath -Recurse -Force)){
 if($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V62_REPARSE'}
 if(!$taskItem.PSIsContainer -and $taskItem.Extension -in '.dll','.exe'){$taskHandle=[IO.File]::Open($taskItem.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);$taskHandle.Dispose()}
}
$taskResult=[ordered]@{stage='V62IndependentFixtureCleanup';nonce=$Nonce;exactPath=$taskPath;originalsGone=$taskProof.processes.Count;sourcePinsVerified=$taskProof.sourceSha256.PSObject.Properties.Count;originalProofSha256=(Sha $taskProofPath);nativeTrialPassed=[bool]$taskProof.passed;goldCalls=0;forcedStops=0;deleted=$false}
Remove-Item -LiteralPath $taskPath -Recurse -Force
if(Test-Path -LiteralPath $taskPath){throw 'V62_DELETE_INCOMPLETE'}
$taskResult.deleted=$true
$taskOutput=Join-Path $taskRoot ('artifacts\designer-bridge\v62-fixture-cleanup-'+$Nonce+'.json')
$taskBytes=[Text.Encoding]::UTF8.GetBytes(($taskResult|ConvertTo-Json -Depth 4));$taskStream=[IO.File]::Open($taskOutput,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$taskStream.Write($taskBytes,0,$taskBytes.Length);$taskStream.Flush($true)}finally{$taskStream.Dispose()}
Write-Output 'V62_OWN_FIXTURE_REMOVED'
