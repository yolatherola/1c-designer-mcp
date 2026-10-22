param(
    [Parameter(Mandatory)][string]$ConnectionFile,
    [Parameter(Mandatory)][ValidateSet('PING','STATUS','READLIVE','SOURCE_ONCE','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','MANAGED_INPUT_RECORD_V145','CLOSE_SAFE')][string]$Command,
    [string]$OperationId=([guid]::NewGuid().ToString('N')),
    [switch]$DeferCloseAck
)
$ErrorActionPreference='Stop'

function Assert-AhManagedInputRecordV145Role($Connection){
    foreach($name in @('goldOwnedDocumentStructureV139','readOnlyGold','managedInputRecordV145','goldOwnedEmptyObjectsV130','goldOwnedManagedFormV107','goldOwnedConstantV99','goldOwnObjectModuleV82','goldOwnObjectModuleV78','captureFreshV81','selectionInputsV46','uiControllerCaptureV44','captureNotificationV56','captureWriteAllowed','objectNotificationV57','localBookkeepingV60','bufferApplyV61','bufferUndoV64','wholeModuleV65')){
        if($Connection.$name -isnot [bool]){throw 'V145_CLIENT_ROLE_REJECTED'}
    }
    foreach($name in @('target','platform','rootId','objectId','captureScope','pilotScope','managedInputRecordV145Token','sessionId','leaseOwner','processCreationFileTimeUtc','pipeName')){
        if($Connection.$name -isnot [string]){throw 'V145_CLIENT_ROLE_REJECTED'}
    }
    if($Connection.version -isnot [int] -or ($Connection.processId -isnot [int] -and $Connection.processId -isnot [long])){throw 'V145_CLIENT_ROLE_REJECTED'}
    if($Connection.version -ne 2 -or $Connection.target -cne 'Gold' -or $Connection.platform -cne '8.3.18.1208' -or
       $Connection.rootId -cne '218b5d00-7e10-486f-874c-73c2368ed5da' -or $Connection.objectId -cne '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d' -or
       $Connection.readOnlyGold -ne $true -or $Connection.managedInputRecordV145 -ne $true -or
       $Connection.goldOwnedDocumentStructureV139 -ne $false -or $Connection.goldOwnedEmptyObjectsV130 -ne $false -or $Connection.goldOwnedManagedFormV107 -isnot [bool] -or $Connection.goldOwnedManagedFormV107 -ne $false -or $Connection.goldOwnedConstantV99 -ne $false -or $Connection.goldOwnObjectModuleV82 -ne $false -or $Connection.goldOwnObjectModuleV78 -ne $false -or $Connection.captureFreshV81 -ne $false -or
       $Connection.objectNotificationV57 -ne $false -or $Connection.localBookkeepingV60 -ne $false -or $Connection.bufferApplyV61 -ne $false -or $Connection.bufferUndoV64 -ne $false -or $Connection.wholeModuleV65 -ne $false -or
       $Connection.selectionInputsV46 -ne $true -or $Connection.uiControllerCaptureV44 -ne $false -or $Connection.captureNotificationV56 -ne $false -or
       $Connection.captureScope -cne 'none' -or $Connection.captureWriteAllowed -ne $false -or $Connection.pilotScope -cne 'none' -or
       $Connection.managedInputRecordV145Token -cnotmatch '^[a-f0-9]{32}$' -or $Connection.sessionId -cnotmatch '^[a-f0-9]{32}$' -or
       $Connection.leaseOwner -cnotmatch '^[a-f0-9]{32}$' -or $Connection.processCreationFileTimeUtc -cnotmatch '^[a-f0-9]{16}$' -or
       $Connection.processCreationFileTimeUtc -ceq ('0'*16) -or $Connection.pipeName -cne ('AH1C-'+$Connection.sessionId) -or
       $Connection.processId -le 0 -or $Connection.processId -gt [int]::MaxValue){throw 'V145_CLIENT_ROLE_REJECTED'}
}

function Assert-AhManagedInputRecordV145Arguments([string]$OperationId,[string]$Command,[bool]$DeferCloseAck){
    if($OperationId -cnotmatch '^[a-f0-9]{32}$' -or $Command -cnotin @('PING','STATUS','READLIVE','SOURCE_ONCE','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','MANAGED_INPUT_RECORD_V145','CLOSE_SAFE') -or
       ($DeferCloseAck -and $Command -cne 'CLOSE_SAFE')){throw 'V145_CLIENT_ARGUMENT_REJECTED'}
}

function Assert-AhManagedInputRecordV145Path([string]$Path){
    if($Path -cnotmatch '^F:\\Projects\\AH_1C\\build\\designer-v43-[a-f0-9]{32}\\session-[a-f0-9]{32}\\command-connection\.json$'){
        throw 'V145_CLIENT_PATH_REJECTED'
    }
}

function Get-AhManagedInputRecordV145Sha([string]$File){
    Assert-AhManagedInputRecordV145PlainPath $File
    $item=Get-Item -LiteralPath $File -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'V145_CLIENT_SOURCE_REPARSE_REJECTED'}
    $stream=[IO.File]::Open($File,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}
    finally{$hash.Dispose();$stream.Dispose()}
}

function Assert-AhManagedInputRecordV145PlainPath([string]$File){
    $current=[IO.Path]::GetFullPath($File)
    while($current){
        if(Test-Path -LiteralPath $current){
            if((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V145_CLIENT_SOURCE_REPARSE_REJECTED'}
        }
        $parent=[IO.Path]::GetDirectoryName($current)
        if(!$parent -or $parent -ceq $current){break}
        $current=$parent
    }
}

function Assert-AhManagedInputRecordV145Source([string]$File,$Expected){
    if($Expected -isnot [string] -or $Expected -cnotmatch '^[a-f0-9]{64}$' -or (Get-AhManagedInputRecordV145Sha $File) -cne $Expected){
        throw 'V145_CLIENT_SOURCE_CHANGED'
    }
}

function Assert-AhManagedInputRecordV145Profile($Connection,[string]$Build,[string]$SourceRoot){
    $manifest=Join-Path $Build 'v43-prepared.json'
    $item=Get-Item -LiteralPath $manifest -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0 -or $item.Length -gt 131072){throw 'V145_CLIENT_PREPARED_BOUND_REJECTED'}
    Assert-AhManagedInputRecordV145Source $manifest $Connection.managedInputRecordV145PreparedManifestSha256
    $profile=[IO.File]::ReadAllText($manifest)|ConvertFrom-Json
    if($profile.passed -isnot [bool] -or !$profile.passed -or $profile.goldStarted -isnot [bool] -or $profile.goldStarted -or
       $profile.nonce -cne (Split-Path $Build -Leaf).Substring(13)){throw 'V145_CLIENT_PREPARED_SCOPE_REJECTED'}
    $keys=@('NativeCommandClient.cs','Invoke-ManagedInputRecordV145.ps1','tests/NativeManagedInputRecordV145.as',
        'research/managed_input_record_contract_v145.py','research/managed_input_record_guard_v145.py','research/managed_input_record_primary_v141.py','research/managed_input_outer_kind_abi_v144.py',
        'tests/NativeManagedInputRecordSessionV145.as','research/managed_input_record_controller_v145.py',
        'tests/NativeCommandSession.as','tests/Invoke-LiveReadProbe.ps1','tests/run_live_probe.py',
        'research/prepare_gold_startup_v43.py','research/run_gold_startup_v43.py')
    foreach($key in $keys){
        $relative='tools/1c/designer-bridge/'+$key
        $pins=@($profile.sourceSha256.PSObject.Properties|Where-Object {$_.Name.Replace('\','/') -ceq $relative})
        if($pins.Count -ne 1 -or $pins[0].Name -cne $relative){throw 'V145_CLIENT_CANONICAL_SOURCE_REJECTED'}
        Assert-AhManagedInputRecordV145Source (Join-Path $SourceRoot $key) $pins[0].Value
    }
}

function Write-AhManagedInputRecordV145Caller([string]$Session,[string]$OperationId,[string]$ExchangeId,[string]$Command,$Caller){
    Assert-AhManagedInputRecordV145Arguments $OperationId $Command $false
    Assert-AhManagedInputRecordV145Path (Join-Path $Session 'command-connection.json')
    Assert-AhManagedInputRecordV145PlainPath $Session
    if($ExchangeId -cnotmatch '^[a-f0-9]{32}$' -or $Caller.pid -isnot [int] -or $Caller.pid -le 0 -or
        $Caller.birth -isnot [string] -or $Caller.birth -cnotmatch '^[a-f0-9]{16}$' -or $Caller.birth -ceq ('0'*16)){throw 'V145_CLIENT_CALLER_REJECTED'}
    $path=Join-Path $Session ('managed-input-caller-v145-'+$OperationId+'-'+$ExchangeId+'.json')
    $record=[ordered]@{command=$Command;operationId=$OperationId;exchangeId=$ExchangeId;caller=$Caller}
    $bytes=[Text.Encoding]::UTF8.GetBytes(($record|ConvertTo-Json -Compress))
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    return $path
}

function Write-AhManagedInputRecordV145Response([string]$Session,[string]$OperationId,[string]$ExchangeId,[byte[]]$Bytes){
    Assert-AhManagedInputRecordV145Path (Join-Path $Session 'command-connection.json')
    Assert-AhManagedInputRecordV145PlainPath $Session
    if($OperationId -cnotmatch '^[a-f0-9]{32}$' -or $ExchangeId -cnotmatch '^[a-f0-9]{32}$' -or $Bytes.Length -gt 1048576){throw 'V145_CLIENT_RESPONSE_REJECTED'}
    $path=Join-Path $Session ('managed-input-client-v145-'+$OperationId+'-'+$ExchangeId+'.txt')
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    return $path
}

function Ensure-AhManagedInputRecordV145Permit($Connection,[string]$Session,[string]$OperationId){
    Assert-AhManagedInputRecordV145Arguments $OperationId 'MANAGED_INPUT_RECORD_V145' $false
    Assert-AhManagedInputRecordV145Path (Join-Path $Session 'command-connection.json')
    Assert-AhManagedInputRecordV145PlainPath $Session
    $permit=Join-Path $Session ('managed-input-record-v145-permit-'+$OperationId)
    $permitBytes=[Text.Encoding]::ASCII.GetBytes($Connection.managedInputRecordV145Token+'|'+$OperationId+'|MANAGED_INPUT_RECORD_V145')
    if(Test-Path -LiteralPath $permit){
        $item=Get-Item -LiteralPath $permit -Force
        if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne $permitBytes.Length){throw 'V145_CLIENT_EXISTING_PERMIT_REJECTED'}
        # The shared-read-only handle excludes replacement/content writers while
        # checking a cached same-operation permit. No changed bytes are reused.
        $stream=[IO.File]::Open($permit,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try{
            if($stream.Length -ne $permitBytes.Length){throw 'V145_CLIENT_EXISTING_PERMIT_REJECTED'}
            $actual=New-Object byte[] $permitBytes.Length;$count=0
            while($count -lt $actual.Length){
                $read=$stream.Read($actual,$count,$actual.Length-$count)
                if($read -le 0){throw 'V145_CLIENT_EXISTING_PERMIT_REJECTED'}
                $count+=$read
            }
            if($stream.ReadByte() -ne -1 -or [Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($permitBytes)){throw 'V145_CLIENT_EXISTING_PERMIT_REJECTED'}
        }finally{$stream.Dispose()}
    }else{
        $stream=[IO.File]::Open($permit,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$stream.Write($permitBytes,0,$permitBytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    }
}

try {
    if([IntPtr]::Size -ne 4){throw 'V145_CLIENT_ARCHITECTURE_REJECTED'}
    Assert-AhManagedInputRecordV145Arguments $OperationId $Command ([bool]$DeferCloseAck)
    $path=[IO.Path]::GetFullPath($ConnectionFile);$session=Split-Path $path -Parent;$build=Split-Path $session -Parent
    Assert-AhManagedInputRecordV145Path $path
    foreach($item in @($path,$session,$build)){
        if((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V145_CLIENT_REPARSE_REJECTED'}
    }
    $connectionItem=Get-Item -LiteralPath $path -Force
    if($connectionItem.Length -le 0 -or $connectionItem.Length -gt 8192){throw 'V145_CLIENT_CONNECTION_REJECTED'}
    Add-Type -AssemblyName System.Security
    $published=[IO.File]::ReadAllText($path)|ConvertFrom-Json
    if($published.sealVersion -isnot [int] -or $published.sealVersion -ne 1){throw 'V145_CLIENT_SEAL_REJECTED'}
    try{
        $payload=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($published.protectedConnection),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-COMMAND-V2'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
        if($payload.Length -eq 0 -or $payload.Length -gt 8192){throw 'V145_CLIENT_SEAL_REJECTED'}
        $connection=(New-Object Text.UTF8Encoding($false,$true)).GetString($payload)|ConvertFrom-Json
    }catch{throw 'V145_CLIENT_SEAL_REJECTED'}
    Assert-AhManagedInputRecordV145Role $connection
    Assert-AhManagedInputRecordV145Profile $connection $build $PSScriptRoot
    Assert-AhManagedInputRecordV145Source (Join-Path $PSScriptRoot 'NativeCommandClient.cs') $connection.clientSourceSha256
    Assert-AhManagedInputRecordV145Source (Join-Path $build 'NativeCommandClient.dll') $connection.clientDllSha256
    $null=[Reflection.Assembly]::LoadFrom((Join-Path $build 'NativeCommandClient.dll'))
    # Actual server PID and original kernel birth are checked in OpenSession
    # before a permit exists. The discovery envelope never grants this role.
    if($Command -ceq 'CLOSE_SAFE'){
        $physical=& python -B -X utf8 (Join-Path $PSScriptRoot 'research/managed_input_record_controller_v145.py') --verify-session $session 2>$null
        if($LASTEXITCODE -ne 0){throw 'V145_PHYSICAL_TERMINAL_REJECTED'}
    }
    $client=[NativeCommandClient]::OpenSession($connection.pipeName,[uint32]$connection.processId,$connection.processCreationFileTimeUtc,$connection.sessionId)
    try{
        $exchangeId=[guid]::NewGuid().ToString('N')
        $caller=[pscustomobject]@{pid=[int]$PID;birth=([Diagnostics.Process]::GetCurrentProcess().StartTime.ToFileTimeUtc().ToString('x16'))}
        $callerFile=Write-AhManagedInputRecordV145Caller $session $OperationId $exchangeId $Command $caller
        if($Command -ceq 'MANAGED_INPUT_RECORD_V145'){Ensure-AhManagedInputRecordV145Permit $connection $session $OperationId}
        $reply=$client.Send($OperationId,$Command)
    }finally{$client.Dispose()}
    $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes($reply.Body)
    $result=Write-AhManagedInputRecordV145Response $session $OperationId $exchangeId $bytes
    if($Command -ceq 'CLOSE_SAFE' -and !$DeferCloseAck -and $reply.Kind -ceq 'CLOSE_SAFE' -and $reply.Body -ceq 'SAFE_CLOSE_PROPOSED'){
        $ack=[ordered]@{version=1;operationId=$OperationId;sessionId=$connection.sessionId;processId=$connection.processId;processCreationFileTimeUtc=$connection.processCreationFileTimeUtc}
        $sealed=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes(($ack|ConvertTo-Json -Compress)),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-CLOSE-ACK-V1'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes((Join-Path $session 'command-close-ack.protected'),$sealed)
        [IO.File]::WriteAllText((Join-Path $session 'command-close-ack'),$OperationId,(New-Object Text.UTF8Encoding($false)))
    }
    if($Command -ceq 'MANAGED_INPUT_RECORD_V145'){
        $physical=& python -B -X utf8 (Join-Path $PSScriptRoot 'research/managed_input_record_controller_v145.py') --verify-session $session 2>$null
        if($LASTEXITCODE -ne 0){throw 'V145_PHYSICAL_RESULT_REJECTED'}
    }
    [ordered]@{status=$reply.Kind;command=$Command;operationId=$OperationId;exchangeId=$exchangeId;caller=$caller;callerWitnessFile=$callerFile;callerWitnessSha256=(Get-AhManagedInputRecordV145Sha $callerFile);replayed=$reply.Replayed;processId=$connection.processId;processCreationFileTimeUtc=$connection.processCreationFileTimeUtc;birth=$connection.processCreationFileTimeUtc;resultFile=$result;bytes=$bytes.Length;sha256=(Get-AhManagedInputRecordV145Sha $result)}|ConvertTo-Json -Compress
    if($reply.Kind -ceq 'ERROR'){exit 1}
}catch{
    $diagnostic=$_.Exception;while($diagnostic.InnerException){$diagnostic=$diagnostic.InnerException}
    $code=[regex]::Match($diagnostic.Message,'\b(?:V145|COMMAND|PIPE)_[A-Z_0-9]{3,63}\b')
    [ordered]@{status='V145_CLIENT_REJECTED';code=$(if($code.Success){$code.Value}else{'V145_CLIENT_FAILED'});errorType=$_.Exception.GetType().Name;errorLine=$_.InvocationInfo.ScriptLineNumber}|ConvertTo-Json -Compress
    exit 85
}
