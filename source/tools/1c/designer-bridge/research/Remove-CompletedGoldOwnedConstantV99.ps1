param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce)
# The Python verifier is repeated read-only and writes no fixed preflight file.
# This script stops no process and mutates no route lease or configuration.
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
$taskBuild=[IO.Path]::GetFullPath((Join-Path $taskRoot 'build'))
$taskPath=[IO.Path]::GetFullPath((Join-Path $taskBuild ('designer-v43-'+$Nonce)))
if([IO.Path]::GetDirectoryName($taskPath) -cne $taskBuild){throw 'GC99_CLEANUP_BOUNDARY_REJECTED'}
$taskVerified=& python -B -X utf8 (Join-Path $PSScriptRoot 'completed_gold_owned_constant_v99.py') --nonce $Nonce 2>$null
if($LASTEXITCODE -ne 0){throw 'GC99_CLEANUP_VERIFIER_REJECTED'}
$taskProof=$taskVerified|ConvertFrom-Json
if($taskProof.passed -ne $true -or $taskProof.nonce -cne $Nonce){throw 'GC99_CLEANUP_PROOF_REJECTED'}
$taskPending=New-Object 'Collections.Generic.Stack[string]'
$taskImages=New-Object 'Collections.Generic.List[string]'
$taskItem=Get-Item -LiteralPath $taskPath -Force
if($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'GC99_CLEANUP_REPARSE_REJECTED'}
$taskPending.Push($taskPath)
while($taskPending.Count){
    foreach($taskItem in @(Get-ChildItem -LiteralPath $taskPending.Pop() -Force)){
        $taskFull=[IO.Path]::GetFullPath($taskItem.FullName)
        if(!$taskFull.StartsWith($taskPath+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){
            throw 'GC99_CLEANUP_BOUNDARY_REJECTED'
        }
        if($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'GC99_CLEANUP_REPARSE_REJECTED'}
        if($taskItem.PSIsContainer){$taskPending.Push($taskFull)}
        elseif($taskItem.Extension -in '.dll','.exe'){$taskImages.Add($taskFull)}
    }
}
foreach($taskImage in $taskImages){
    $taskStream=[IO.File]::Open($taskImage,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $taskStream.Dispose()
}
function Write-GC99Durable([string]$Path,[object]$Record){
    $taskBytes=[Text.Encoding]::UTF8.GetBytes(($Record|ConvertTo-Json -Depth 6))
    $taskStream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$taskStream.Write($taskBytes,0,$taskBytes.Length);$taskStream.Flush($true)}finally{$taskStream.Dispose()}
}
$taskRecord=@{stage='V99GoldOwnedConstantRuntimeCleanup';nonce=$Nonce;exactPath=$taskPath;knownTerminalVerified=$true;ownConstantVerified=$taskProof.ownConstantVerified;exclusiveImageChecksPassed=$true;foreignProcessesModified=$false}
Write-GC99Durable (Join-Path $taskRoot ('artifacts/designer-bridge/v99-owned-constant-cleanup-intent-'+$Nonce+'.json')) $taskRecord
Remove-Item -LiteralPath $taskPath -Recurse -Force
$taskRecord.allRemoved=!(Test-Path -LiteralPath $taskPath)
if(!$taskRecord.allRemoved){throw 'GC99_CLEANUP_INCOMPLETE'}
Write-GC99Durable (Join-Path $taskRoot ('artifacts/designer-bridge/v99-owned-constant-cleanup-'+$Nonce+'.json')) $taskRecord
@{removedDirectories=1;allRemoved=$true;nonce=$Nonce}|ConvertTo-Json -Compress
