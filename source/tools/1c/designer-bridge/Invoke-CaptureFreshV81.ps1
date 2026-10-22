param(
    [Parameter(Mandatory)][string]$ConnectionFile,
    [Parameter(Mandatory)][ValidateSet('PING','STATUS','READLIVE','SOURCE_ONCE','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','CAPTURE_FRESH_PREPARE_V81','CAPTURE_FRESH_VERIFY_CANCEL_V81','CLOSE_SAFE')][string]$Command,
    [string]$OperationId=([guid]::NewGuid().ToString('N')),
    [switch]$DeferCloseAck
)
$ErrorActionPreference='Stop'

function Assert-AhCaptureFreshV81Role($Connection){
    foreach($name in @('readOnlyGold','captureFreshV81','selectionInputsV46','uiControllerCaptureV44','captureNotificationV56','captureWriteAllowed')){
        if($Connection.$name -isnot [bool]){throw 'V81_CLIENT_ROLE_REJECTED'}
    }
    foreach($name in @('target','platform','rootId','objectId','captureScope','pilotScope','captureFreshTokenV81','sessionId','leaseOwner','processCreationFileTimeUtc','pipeName')){
        if($Connection.$name -isnot [string]){throw 'V81_CLIENT_ROLE_REJECTED'}
    }
    if($Connection.version -isnot [int] -or ($Connection.processId -isnot [int] -and $Connection.processId -isnot [long])){throw 'V81_CLIENT_ROLE_REJECTED'}
    if($Connection.version -ne 2 -or $Connection.target -cne 'Gold' -or $Connection.platform -cne '8.3.18.1208' -or
       $Connection.rootId -cne '218b5d00-7e10-486f-874c-73c2368ed5da' -or $Connection.objectId -cne '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d' -or
       $Connection.readOnlyGold -ne $false -or $Connection.captureFreshV81 -ne $true -or $Connection.selectionInputsV46 -ne $true -or
       $Connection.uiControllerCaptureV44 -ne $false -or $Connection.captureNotificationV56 -ne $false -or
       $Connection.captureScope -cne 'none' -or $Connection.captureWriteAllowed -ne $false -or $Connection.pilotScope -cne 'none' -or
       $Connection.captureFreshTokenV81 -cnotmatch '^[a-f0-9]{32}$' -or $Connection.sessionId -cnotmatch '^[a-f0-9]{32}$' -or
       $Connection.leaseOwner -cnotmatch '^[a-f0-9]{32}$' -or $Connection.processCreationFileTimeUtc -cnotmatch '^[a-f0-9]{16}$' -or
       $Connection.processCreationFileTimeUtc -ceq '0000000000000000' -or $Connection.pipeName -cne ('AH1C-'+$Connection.sessionId) -or
       $Connection.processId -le 0 -or $Connection.processId -gt [int]::MaxValue){throw 'V81_CLIENT_ROLE_REJECTED'}
}

function Assert-AhCaptureFreshV81Permit($Connection,[string]$Command,[string]$OperationId,[byte[]]$PermitBytes){
    # The controller alone issues these bytes after identity/lease validation and,
    # for cancellation, a complete pure comparison. This reader grants no permit.
    if($OperationId -cnotmatch '^[a-f0-9]{32}$' -or $null -eq $PermitBytes -or $PermitBytes.Length -eq 0 -or $PermitBytes.Length -gt 256){throw 'V81_CLIENT_PERMIT_REJECTED'}
    foreach($value in $PermitBytes){if($value -gt 127){throw 'V81_CLIENT_PERMIT_REJECTED'}}
    $body=[Text.Encoding]::ASCII.GetString($PermitBytes)
    if($Command -ceq 'CAPTURE_FRESH_PREPARE_V81'){
        $expected=$Connection.captureFreshTokenV81+' '+$OperationId+' '+$Connection.sessionId+' '+$Connection.processId+' '+$Connection.processCreationFileTimeUtc
        if($body -cne $expected){throw 'V81_CLIENT_PERMIT_REJECTED'}
        return
    }
    if($Command -cne 'CAPTURE_FRESH_VERIFY_CANCEL_V81'){throw 'V81_CLIENT_PERMIT_REJECTED'}
    $parts=$body.Split([char]' ')
    if($parts.Length -ne 7 -or $parts[0] -cne $Connection.captureFreshTokenV81 -or
       $parts[1] -cnotmatch '^[a-f0-9]{32}$' -or $parts[1] -ceq $OperationId -or $parts[2] -cne $OperationId -or
       $parts[3] -cne $Connection.sessionId -or $parts[4] -cne ([string]$Connection.processId) -or
       $parts[5] -cne $Connection.processCreationFileTimeUtc -or $parts[6] -cnotmatch '^(0|[1-9][0-9]{0,9})$'){
        throw 'V81_CLIENT_PERMIT_REJECTED'
    }
    if([long]$parts[6] -gt [int]::MaxValue){throw 'V81_CLIENT_PERMIT_REJECTED'}
}

function Read-AhCaptureFreshV81Permit([string]$File){
    if([IO.Path]::GetFileName($File) -cnotin @('capture-fresh-v81-prepare.permit','capture-fresh-v81-verify-cancel.permit')){throw 'V81_CLIENT_PERMIT_NAME_REJECTED'}
    if(!(Test-Path -LiteralPath $File -PathType Leaf)){throw 'V81_CLIENT_PERMIT_MISSING'}
    $item=Get-Item -LiteralPath $File
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V81_CLIENT_PERMIT_REPARSE_REJECTED'}
    if($item.Length -le 0 -or $item.Length -gt 256){throw 'V81_CLIENT_PERMIT_SIZE_REJECTED'}
    # FileShare.Read prevents a writer replacing contents while this handle reads.
    $stream=[IO.File]::Open($File,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        if($stream.Length -le 0 -or $stream.Length -gt 256){throw 'V81_CLIENT_PERMIT_SIZE_REJECTED'}
        $bytes=New-Object byte[] ([int]$stream.Length);$count=0
        while($count -lt $bytes.Length){
            $read=$stream.Read($bytes,$count,$bytes.Length-$count)
            if($read -le 0){throw 'V81_CLIENT_PERMIT_SIZE_REJECTED'}
            $count+=$read
        }
        if($stream.ReadByte() -ne -1){throw 'V81_CLIENT_PERMIT_SIZE_REJECTED'}
        return ,$bytes
    }finally{$stream.Dispose()}
}

function Get-AhCaptureFreshV81Sha([string]$File){
    if((Get-Item -LiteralPath $File).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V81_CLIENT_SOURCE_REPARSE_REJECTED'}
    $stream=[IO.File]::OpenRead($File);$hash=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}
    finally{$hash.Dispose();$stream.Dispose()}
}

try {
    if([IntPtr]::Size -ne 4 -or $OperationId -cnotmatch '^[a-f0-9]{32}$' -or ($DeferCloseAck -and $Command -cne 'CLOSE_SAFE')){throw 'V81_CLIENT_ARGUMENT_REJECTED'}
    $path=[IO.Path]::GetFullPath($ConnectionFile);$session=Split-Path $path -Parent;$build=Split-Path $session -Parent
    if($path -cnotmatch '^F:\\Projects\\AH_1C\\build\\designer-v43-[a-f0-9]{32}\\session-[a-f0-9]{32}\\command-connection.json$'){throw 'V81_CLIENT_PATH_REJECTED'}
    foreach($item in @($path,$session,$build)){
        if((Get-Item -LiteralPath $item).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V81_CLIENT_REPARSE_REJECTED'}
    }
    $connectionItem=Get-Item -LiteralPath $path
    if($connectionItem.Length -le 0 -or $connectionItem.Length -gt 12288){throw 'V81_CLIENT_CONNECTION_REJECTED'}
    Add-Type -AssemblyName System.Security
    $published=[IO.File]::ReadAllText($path)|ConvertFrom-Json
    if($published.sealVersion -isnot [int] -or $published.sealVersion -ne 1){throw 'V81_CLIENT_SEAL_REJECTED'}
    try{
        $payload=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($published.protectedConnection),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-COMMAND-V2'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
        if($payload.Length -eq 0 -or $payload.Length -gt 12288){throw 'V81_CLIENT_SEAL_REJECTED'}
        $connection=(New-Object Text.UTF8Encoding($false,$true)).GetString($payload)|ConvertFrom-Json
    }catch{throw 'V81_CLIENT_SEAL_REJECTED'}
    Assert-AhCaptureFreshV81Role $connection
    $checks=@(
        @((Join-Path $PSScriptRoot 'NativeCommandClient.cs'),$connection.clientSourceSha256),
        @((Join-Path $build 'NativeCommandClient.dll'),$connection.clientDllSha256),
        @($PSCommandPath,$connection.captureFreshClientSha256V81),
        @((Join-Path $PSScriptRoot 'tests/NativeCaptureFreshV81.as'),$connection.captureFreshSourceSha256V81),
        @((Join-Path $PSScriptRoot 'research/capture_fresh_contract_v81.py'),$connection.captureFreshContractSha256V81),
        @((Join-Path $PSScriptRoot 'research/capture_fresh_guard_v81.py'),$connection.captureFreshGuardSha256V81),
        @((Join-Path $build 'v43-prepared.json'),$connection.captureFreshPreparedManifestSha256V81)
    )
    foreach($pair in $checks){
        if($pair[1] -isnot [string] -or $pair[1] -cnotmatch '^[a-f0-9]{64}$' -or (Get-AhCaptureFreshV81Sha $pair[0]) -cne $pair[1]){throw 'V81_CLIENT_SOURCE_CHANGED'}
    }
    $null=[Reflection.Assembly]::LoadFrom((Join-Path $build 'NativeCommandClient.dll'))
    # Actual pipe PID and kernel birth are checked before inspecting a writer
    # permit or dispatching; the unprotected discovery fields carry no authority.
    $client=[NativeCommandClient]::OpenSession($connection.pipeName,[uint32]$connection.processId,$connection.processCreationFileTimeUtc,$connection.sessionId)
    try{
        if($Command -cin @('CAPTURE_FRESH_PREPARE_V81','CAPTURE_FRESH_VERIFY_CANCEL_V81')){
            $permitName=if($Command -ceq 'CAPTURE_FRESH_PREPARE_V81'){'capture-fresh-v81-prepare.permit'}else{'capture-fresh-v81-verify-cancel.permit'}
            [byte[]]$permitBytes=Read-AhCaptureFreshV81Permit (Join-Path $session $permitName)
            Assert-AhCaptureFreshV81Permit $connection $Command $OperationId $permitBytes
        }
        $reply=$client.Send($OperationId,$Command)
    }finally{$client.Dispose()}
    $result=Join-Path $session ('capture-fresh-client-'+$OperationId+'-'+[guid]::NewGuid().ToString('N')+'.txt')
    $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes($reply.Body)
    $stream=[IO.File]::Open($result,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    if($Command -ceq 'CLOSE_SAFE' -and !$DeferCloseAck -and $reply.Kind -ceq 'CLOSE_SAFE' -and $reply.Body -ceq 'SAFE_CLOSE_PROPOSED'){
        $ack=[ordered]@{version=1;operationId=$OperationId;sessionId=$connection.sessionId;processId=$connection.processId;processCreationFileTimeUtc=$connection.processCreationFileTimeUtc}
        $sealed=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes(($ack|ConvertTo-Json -Compress)),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-CLOSE-ACK-V1'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes((Join-Path $session 'command-close-ack.protected'),$sealed)
        [IO.File]::WriteAllText((Join-Path $session 'command-close-ack'),$OperationId,(New-Object Text.UTF8Encoding($false)))
    }
    [ordered]@{status=$reply.Kind;command=$Command;operationId=$OperationId;replayed=$reply.Replayed;processId=$connection.processId;processCreationFileTimeUtc=$connection.processCreationFileTimeUtc;birth=$connection.processCreationFileTimeUtc;resultFile=$result;bytes=$bytes.Length;sha256=(Get-AhCaptureFreshV81Sha $result)}|ConvertTo-Json -Compress
    if($reply.Kind -ceq 'ERROR'){exit 1}
}catch{
    $diagnostic=$_.Exception;while($diagnostic.InnerException){$diagnostic=$diagnostic.InnerException}
    $code=[regex]::Match($diagnostic.Message,'\b(?:V81|COMMAND|PIPE)_[A-Z_0-9]{3,63}\b')
    [ordered]@{status='V81_CLIENT_REJECTED';code=$(if($code.Success){$code.Value}else{'V81_CLIENT_FAILED'});errorType=$_.Exception.GetType().Name;errorLine=$_.InvocationInfo.ScriptLineNumber}|ConvertTo-Json -Compress
    exit 85
}
