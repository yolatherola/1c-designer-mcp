param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce)
# Only a verified own-module terminal receipt permits this exact cleanup.
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
$taskBuild=[IO.Path]::GetFullPath((Join-Path $taskRoot 'build'))
$taskPath=[IO.Path]::GetFullPath((Join-Path $taskBuild ('designer-v43-'+$Nonce)))
if([IO.Path]::GetDirectoryName($taskPath) -cne $taskBuild){throw 'GOM78_CLEANUP_BOUNDARY_REJECTED'}
$taskVerified=& python -B (Join-Path $PSScriptRoot 'completed_gold_own_module_v78.py') --nonce $Nonce
if($LASTEXITCODE -ne 0){throw 'GOM78_CLEANUP_KERNEL_REJECTED'}
$taskProof=$taskVerified|ConvertFrom-Json
if($taskProof.passed -ne $true -or $taskProof.nonce -cne $Nonce){throw 'GOM78_CLEANUP_PROOF_REJECTED'}
$taskItems=@(Get-Item -LiteralPath $taskPath)+@(Get-ChildItem -LiteralPath $taskPath -Recurse -Force)
if(@($taskItems|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'GOM78_CLEANUP_REPARSE_REJECTED'}
foreach($taskImage in @($taskItems|Where-Object {!$_.PSIsContainer -and $_.Extension -in '.dll','.exe'})){
    $taskStream=[IO.File]::Open($taskImage.FullName,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $taskStream.Dispose()
}
$taskRecord=@{stage='V78OwnModuleRuntimeCleanup';nonce=$Nonce;exactPath=$taskPath;exclusiveImageChecksPassed=$true;foreignProcessesModified=$false}
$taskIntent=Join-Path $taskRoot ('artifacts/designer-bridge/v78-own-module-cleanup-intent-'+$Nonce+'.json')
$taskBytes=[Text.Encoding]::UTF8.GetBytes(($taskRecord|ConvertTo-Json -Depth 5))
$taskStream=[IO.File]::Open($taskIntent,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$taskStream.Write($taskBytes,0,$taskBytes.Length);$taskStream.Flush($true)}finally{$taskStream.Dispose()}
Remove-Item -LiteralPath $taskPath -Recurse -Force
$taskRecord.allRemoved=!(Test-Path -LiteralPath $taskPath)
if(!$taskRecord.allRemoved){throw 'GOM78_CLEANUP_INCOMPLETE'}
$taskRecord|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $taskRoot ('artifacts/designer-bridge/v78-own-module-cleanup-'+$Nonce+'.json')) -Encoding UTF8
@{removedDirectories=1;allRemoved=$true;nonce=$Nonce}|ConvertTo-Json -Compress
