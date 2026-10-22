param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce)
# Historical terminal verification authorizes only this exact own path.
# No process stop, capture cancellation, lease release or native command.
$ErrorActionPreference='Stop'
try {
    $taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
    $taskBuild=[IO.Path]::GetFullPath((Join-Path $taskRoot 'build'))
    $taskPath=[IO.Path]::GetFullPath((Join-Path $taskBuild ('designer-v43-'+$Nonce)))
    if([IO.Path]::GetDirectoryName($taskPath) -cne $taskBuild){throw 'CAPF81_CLEANUP_BOUNDARY'}
    $taskVerified=& python -B -X utf8 (Join-Path $PSScriptRoot 'completed_capture_fresh_v81.py') --nonce $Nonce 2>$null
    if($LASTEXITCODE -ne 0){throw 'CAPF81_CLEANUP_KERNEL'}
    $taskProof=$taskVerified|ConvertFrom-Json
    if($taskProof.passed -isnot [bool] -or $taskProof.passed -ne $true -or $taskProof.nonce -cne $Nonce){throw 'CAPF81_CLEANUP_PROOF'}
    $taskItems=@(Get-Item -LiteralPath $taskPath)+@(Get-ChildItem -LiteralPath $taskPath -Recurse -Force)
    if(@($taskItems|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'CAPF81_CLEANUP_REPARSE'}
    foreach($taskImage in @($taskItems|Where-Object {!$_.PSIsContainer -and $_.Extension -in '.dll','.exe'})){
        $taskStream=[IO.File]::Open($taskImage.FullName,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $taskStream.Dispose()
    }
    $taskRecord=@{stage='V81CaptureFreshRuntimeCleanup';nonce=$Nonce;exactPath=$taskPath;exclusiveImageChecksPassed=$true;foreignProcessesModified=$false}
    $taskIntent=Join-Path $taskRoot ('artifacts/designer-bridge/v81-capture-fresh-cleanup-intent-'+$Nonce+'.json')
    $taskBytes=[Text.Encoding]::UTF8.GetBytes(($taskRecord|ConvertTo-Json -Depth 5))
    $taskStream=[IO.File]::Open($taskIntent,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$taskStream.Write($taskBytes,0,$taskBytes.Length);$taskStream.Flush($true)}finally{$taskStream.Dispose()}
    Remove-Item -LiteralPath $taskPath -Recurse -Force
    $taskRecord.allRemoved=!(Test-Path -LiteralPath $taskPath)
    if(!$taskRecord.allRemoved){throw 'CAPF81_CLEANUP_INCOMPLETE'}
    $taskCompleted=Join-Path $taskRoot ('artifacts/designer-bridge/v81-capture-fresh-cleanup-'+$Nonce+'.json')
    $taskBytes=[Text.Encoding]::UTF8.GetBytes(($taskRecord|ConvertTo-Json -Depth 5))
    $taskStream=[IO.File]::Open($taskCompleted,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$taskStream.Write($taskBytes,0,$taskBytes.Length);$taskStream.Flush($true)}finally{$taskStream.Dispose()}
    @{removedDirectories=1;allRemoved=$true;nonce=$Nonce}|ConvertTo-Json -Compress
} catch {
    @{passed=$false;code='CAPF81_CLEANUP_REJECTED'}|ConvertTo-Json -Compress
    exit 85
}
