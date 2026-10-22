param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce)
# The Python verifier is repeated read-only and writes no fixed preflight file.
# This script stops no process and mutates no route lease or configuration.
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
$taskBuild=[IO.Path]::GetFullPath((Join-Path $taskRoot 'build'))
$taskPath=[IO.Path]::GetFullPath((Join-Path $taskBuild ('designer-v43-'+$Nonce)))
if([IO.Path]::GetDirectoryName($taskPath) -cne $taskBuild){throw 'GD139_CLEANUP_BOUNDARY_REJECTED'}
$taskVerified=& python -B -X utf8 (Join-Path $PSScriptRoot 'completed_gold_owned_document_structure_v139.py') --nonce $Nonce 2>$null
if($LASTEXITCODE -ne 0){throw 'GD139_CLEANUP_VERIFIER_REJECTED'}
$taskProof=$taskVerified|ConvertFrom-Json
if($taskProof.passed -isnot [bool] -or !$taskProof.passed -or $taskProof.ownStructureVerified -isnot [bool] -or
    $taskProof.nonce -isnot [string] -or $taskProof.nonce -cne $Nonce -or
    $taskProof.originalIdentityCount -isnot [int] -or $taskProof.originalIdentityCount -le 0){throw 'GD139_CLEANUP_PROOF_REJECTED'}
function Assert-GD139CleanupPlainAncestors([string]$Path){
    $taskAncestors=New-Object 'Collections.Generic.Stack[string]'
    $taskCurrent=[IO.Path]::GetFullPath($Path)
    while($taskCurrent){
        $taskAncestors.Push($taskCurrent)
        $taskParent=[IO.Path]::GetDirectoryName($taskCurrent)
        if(!$taskParent -or $taskParent -ceq $taskCurrent){break}
        $taskCurrent=$taskParent
    }
    # Check from the volume root towards the exact owned directory, so a late
    # junction on any ancestor cannot redirect the following tree traversal.
    while($taskAncestors.Count){
        $taskAncestor=Get-Item -LiteralPath $taskAncestors.Pop() -Force
        if(!$taskAncestor.PSIsContainer -or ($taskAncestor.Attributes -band [IO.FileAttributes]::ReparsePoint)){
            throw 'GD139_CLEANUP_REPARSE_REJECTED'
        }
    }
}
$taskPending=New-Object 'Collections.Generic.Stack[string]'
$taskImages=New-Object 'Collections.Generic.List[string]'
$taskItem=Get-Item -LiteralPath $taskPath -Force
if($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'GD139_CLEANUP_REPARSE_REJECTED'}
$taskPending.Push($taskPath)
while($taskPending.Count){
    foreach($taskItem in @(Get-ChildItem -LiteralPath $taskPending.Pop() -Force)){
        $taskFull=[IO.Path]::GetFullPath($taskItem.FullName)
        if(!$taskFull.StartsWith($taskPath+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){
            throw 'GD139_CLEANUP_BOUNDARY_REJECTED'
        }
        if($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'GD139_CLEANUP_REPARSE_REJECTED'}
        if($taskItem.PSIsContainer){$taskPending.Push($taskFull)}
        elseif($taskItem.Extension -in '.dll','.exe'){$taskImages.Add($taskFull)}
    }
}
foreach($taskImage in $taskImages){
    $taskStream=[IO.File]::Open($taskImage,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $taskStream.Dispose()
}
function Write-GD139Durable([string]$Path,[object]$Record){
    $taskBytes=[Text.Encoding]::UTF8.GetBytes(($Record|ConvertTo-Json -Depth 6))
    $taskStream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$taskStream.Write($taskBytes,0,$taskBytes.Length);$taskStream.Flush($true)}finally{$taskStream.Dispose()}
}
$taskRecord=@{stage='V139GoldOwnedDocumentStructureRuntimeCleanup';nonce=$Nonce;exactPath=$taskPath;knownTerminalVerified=$true;ownStructureVerified=$taskProof.ownStructureVerified;exclusiveImageChecksPassed=$true;foreignProcessesModified=$false}
Write-GD139Durable (Join-Path $taskRoot ('artifacts/designer-bridge/v139-owned-document-structure-cleanup-intent-'+$Nonce+'.json')) $taskRecord
# Enumeration and exclusive-image checks are not a lasting certificate. Re-read
# the physical proof and all identities/route/source pins after that work, then
# reject a changed capability or any newly redirected path before deletion.
$taskLateVerified=& python -B -X utf8 (Join-Path $PSScriptRoot 'completed_gold_owned_document_structure_v139.py') --nonce $Nonce 2>$null
if($LASTEXITCODE -ne 0){throw 'GD139_CLEANUP_LATE_VERIFIER_REJECTED'}
$taskLateProof=$taskLateVerified|ConvertFrom-Json
if($taskLateProof.passed -isnot [bool] -or !$taskLateProof.passed -or
    $taskLateProof.nonce -isnot [string] -or $taskLateProof.nonce -cne $Nonce -or
    $taskLateProof.ownStructureVerified -isnot [bool] -or $taskLateProof.ownStructureVerified -cne $taskProof.ownStructureVerified -or
    $taskLateProof.originalIdentityCount -isnot [int] -or $taskLateProof.originalIdentityCount -ne $taskProof.originalIdentityCount){
    throw 'GD139_CLEANUP_LATE_PROOF_REJECTED'
}
if([IO.Path]::GetFullPath($taskPath) -cne $taskPath -or [IO.Path]::GetDirectoryName($taskPath) -cne $taskBuild){
    throw 'GD139_CLEANUP_BOUNDARY_REJECTED'
}
Assert-GD139CleanupPlainAncestors $taskPath
$taskLatePending=New-Object 'Collections.Generic.Stack[string]'
$taskLatePending.Push($taskPath)
while($taskLatePending.Count){
    $taskLateDirectory=$taskLatePending.Pop()
    $taskLateDirectoryItem=Get-Item -LiteralPath $taskLateDirectory -Force
    if(!$taskLateDirectoryItem.PSIsContainer -or ($taskLateDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        throw 'GD139_CLEANUP_REPARSE_REJECTED'
    }
    foreach($taskLateItem in @(Get-ChildItem -LiteralPath $taskLateDirectory -Force)){
        $taskLateFull=[IO.Path]::GetFullPath($taskLateItem.FullName)
        if(!$taskLateFull.StartsWith($taskPath+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){
            throw 'GD139_CLEANUP_BOUNDARY_REJECTED'
        }
        if($taskLateItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'GD139_CLEANUP_REPARSE_REJECTED'}
        if($taskLateItem.PSIsContainer){$taskLatePending.Push($taskLateFull)}
    }
}
Remove-Item -LiteralPath $taskPath -Recurse -Force
$taskRecord.allRemoved=!(Test-Path -LiteralPath $taskPath)
if(!$taskRecord.allRemoved){throw 'GD139_CLEANUP_INCOMPLETE'}
Write-GD139Durable (Join-Path $taskRoot ('artifacts/designer-bridge/v139-owned-document-structure-cleanup-'+$Nonce+'.json')) $taskRecord
@{removedDirectories=1;allRemoved=$true;nonce=$Nonce}|ConvertTo-Json -Compress
