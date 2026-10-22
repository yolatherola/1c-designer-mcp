param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce)
# Only the authenticated own-object terminal plus a separate fresh RO audit
# permits removal of this exact owned runtime. This script stops no process.
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
$taskBuild=[IO.Path]::GetFullPath((Join-Path $taskRoot 'build'))
$taskPath=[IO.Path]::GetFullPath((Join-Path $taskBuild ('designer-v43-'+$Nonce)))
if([IO.Path]::GetDirectoryName($taskPath) -cne $taskBuild){throw 'GOM82_CLEANUP_BOUNDARY_REJECTED'}
$taskVerified=& python -B (Join-Path $PSScriptRoot 'completed_gold_own_module_v82.py') --nonce $Nonce
if($LASTEXITCODE -ne 0){throw 'GOM82_CLEANUP_KERNEL_REJECTED'}
$taskProof=$taskVerified|ConvertFrom-Json
if($taskProof.passed -ne $true -or $taskProof.nonce -cne $Nonce){throw 'GOM82_CLEANUP_PROOF_REJECTED'}
# Inspect each child before descending, so recursive enumeration never follows
# a junction. Keep the validated list for the exclusive regular-image checks.
$taskItems=New-Object 'Collections.Generic.List[IO.FileSystemInfo]'
$taskPending=New-Object 'Collections.Generic.Stack[string]'
$taskRootItem=Get-Item -LiteralPath $taskPath -Force
if($taskRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'GOM82_CLEANUP_REPARSE_REJECTED'}
$taskItems.Add($taskRootItem)
$taskPending.Push($taskPath)
while($taskPending.Count){
    $taskDirectory=$taskPending.Pop()
    foreach($taskItem in @(Get-ChildItem -LiteralPath $taskDirectory -Force)){
        $taskFull=[IO.Path]::GetFullPath($taskItem.FullName)
        if(!$taskFull.StartsWith($taskPath+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){
            throw 'GOM82_CLEANUP_BOUNDARY_REJECTED'
        }
        if($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'GOM82_CLEANUP_REPARSE_REJECTED'}
        $taskItems.Add($taskItem)
        if($taskItem.PSIsContainer){$taskPending.Push($taskFull)}
    }
}
foreach($taskImage in @($taskItems|Where-Object {!$_.PSIsContainer -and $_.Extension -in '.dll','.exe'})){
    $taskStream=[IO.File]::Open($taskImage.FullName,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $taskStream.Dispose()
}
$taskRecord=@{stage='V82OwnModuleRuntimeCleanup';nonce=$Nonce;exactPath=$taskPath;exclusiveImageChecksPassed=$true;foreignProcessesModified=$false}
$taskIntent=Join-Path $taskRoot ('artifacts/designer-bridge/v82-own-module-cleanup-intent-'+$Nonce+'.json')
$taskBytes=[Text.Encoding]::UTF8.GetBytes(($taskRecord|ConvertTo-Json -Depth 5))
$taskStream=[IO.File]::Open($taskIntent,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$taskStream.Write($taskBytes,0,$taskBytes.Length);$taskStream.Flush($true)}finally{$taskStream.Dispose()}
Remove-Item -LiteralPath $taskPath -Recurse -Force
$taskRecord.allRemoved=!(Test-Path -LiteralPath $taskPath)
if(!$taskRecord.allRemoved){throw 'GOM82_CLEANUP_INCOMPLETE'}
$taskRecord|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $taskRoot ('artifacts/designer-bridge/v82-own-module-cleanup-'+$Nonce+'.json')) -Encoding UTF8
@{removedDirectories=1;allRemoved=$true;nonce=$Nonce}|ConvertTo-Json -Compress
