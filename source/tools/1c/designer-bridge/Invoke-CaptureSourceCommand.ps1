param(
    [Parameter(Mandatory)][string]$ConnectionFile,
    [Parameter(Mandatory)][ValidateSet('PING','STATUS','READLIVE','CAPTURE_SOURCE_CYCLE','CLOSE_SAFE')][string]$Command,
    [string]$OperationId=([guid]::NewGuid().ToString('N')),
    [switch]$AllowCaptureAndCancel,
    [switch]$DeferCloseAck
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'tests/CaptureSourceSession.ps1')
try {
    if([IntPtr]::Size -ne 4 -or $OperationId -cnotmatch '^[a-f0-9]{32}$' -or
        ($AllowCaptureAndCancel -and $Command -ne 'CAPTURE_SOURCE_CYCLE') -or
        ($DeferCloseAck -and $Command -ne 'CLOSE_SAFE')){throw 'CAPTURE_CALLER_REJECTED'}
    $connection=Get-AhCaptureConnection $ConnectionFile
    $sessionDir=Split-Path ([IO.Path]::GetFullPath($ConnectionFile)) -Parent
    $build=Split-Path $sessionDir -Parent
    if($Command -eq 'CAPTURE_SOURCE_CYCLE'){
        if($connection.captureWriteAllowed -and !$AllowCaptureAndCancel){throw 'CAPTURE_EXPLICIT_WRITE_FLAG_REQUIRED'}
        # The permit precedes native dispatch and binds the exact operation.
        # An unknown reply never causes a second dispatch with a new ID.
        Write-AhCapturePermit $sessionDir $connection $OperationId
    }
    $null=[Reflection.Assembly]::LoadFrom((Join-Path $build 'NativeCommandClient.dll'))
    $client=[NativeCommandClient]::OpenSession($connection.pipeName,[uint32]$connection.processId,$connection.processCreationFileTimeUtc,$connection.sessionId)
    try {$reply=$client.Send($OperationId,$Command)} finally {$client.Dispose()}
    $output=Join-Path $sessionDir ('capture-client-'+$OperationId+'-'+[guid]::NewGuid().ToString('N')+'.txt')
    $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes($reply.Body)
    $stream=New-Object IO.FileStream($output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
    if(!$DeferCloseAck -and $reply.Kind -ceq 'CLOSE_SAFE' -and $reply.Body -ceq 'SAFE_CLOSE_PROPOSED'){
        Write-AhCaptureCloseAck $sessionDir $connection $OperationId
    }
    $summary=[ordered]@{status=$(if($reply.Kind -ceq 'ERROR'){'NATIVE_CAPTURE_COMMAND_REJECTED'}else{'NATIVE_CAPTURE_REPLY_RECEIVED'});
        command=$Command;operationId=$OperationId;replayed=$reply.Replayed;processId=$connection.processId;
        processCreationFileTimeUtc=$connection.processCreationFileTimeUtc;resultFile=$output;bytes=$bytes.Length;sha256=(Get-AhCaptureHash $output)}
    if($reply.Kind -ceq 'ERROR' -and $reply.Body -cmatch '^[A-Z][A-Z_0-9]{3,63}$'){$summary.code=$reply.Body}
    $summary|ConvertTo-Json -Compress
    if($reply.Kind -ceq 'ERROR'){exit 1}
} catch {
    $leaf=$_.Exception
    while($leaf.InnerException){$leaf=$leaf.InnerException}
    $code=if($leaf.Message -cmatch '^[A-Z][A-Z_0-9]{3,63}$'){$leaf.Message}else{'CAPTURE_COMMAND_CALL_FAILED'}
    [ordered]@{status='NATIVE_CAPTURE_RESULT_UNKNOWN';code=$code;operationId=$OperationId;errorType=$leaf.GetType().Name}|ConvertTo-Json -Compress
    exit 85
}
