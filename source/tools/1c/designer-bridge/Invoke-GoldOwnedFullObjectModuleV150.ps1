param(
    [Parameter(Mandatory)][string]$ConnectionFile,
    [Parameter(Mandatory)][ValidateSet('PING','STATUS','READLIVE','SOURCE_ONCE','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','GOLD_OWNED_FULL_OBJECT_MODULE_V150','CLOSE_SAFE')][string]$Command,
    [string]$OperationId=([guid]::NewGuid().ToString('N')),
    [switch]$DeferCloseAck
)
$ErrorActionPreference='Stop'

function Assert-AhGoldOwnedFullObjectModuleV150Role($Connection){
    foreach($name in @('managedInputRecordV145','goldOwnedDocumentStructureV139','readOnlyGold','goldOwnedFullObjectModuleV150','goldOwnedEmptyObjectsV130','goldOwnedManagedFormV107','goldOwnedConstantV99','goldOwnObjectModuleV82','goldOwnObjectModuleV78','captureFreshV81','selectionInputsV46','uiControllerCaptureV44','captureNotificationV56','captureWriteAllowed','objectNotificationV57','localBookkeepingV60','bufferApplyV61','bufferUndoV64','wholeModuleV65')){
        if($Connection.$name -isnot [bool]){throw 'V150_CLIENT_ROLE_REJECTED'}
    }
    foreach($name in @('target','platform','rootId','objectId','captureScope','pilotScope','goldOwnedFullObjectModuleV150Token','sessionId','leaseOwner','processCreationFileTimeUtc','pipeName')){
        if($Connection.$name -isnot [string]){throw 'V150_CLIENT_ROLE_REJECTED'}
    }
    if($Connection.version -isnot [int] -or ($Connection.processId -isnot [int] -and $Connection.processId -isnot [long])){throw 'V150_CLIENT_ROLE_REJECTED'}
    if($Connection.version -ne 2 -or $Connection.target -cne 'Gold' -or $Connection.platform -cne '8.3.18.1208' -or
       $Connection.rootId -cne '218b5d00-7e10-486f-874c-73c2368ed5da' -or $Connection.objectId -cne '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d' -or
       $Connection.managedInputRecordV145 -ne $false -or $Connection.goldOwnedDocumentStructureV139 -ne $false -or
       $Connection.readOnlyGold -ne $false -or $Connection.goldOwnedFullObjectModuleV150 -ne $true -or
       $Connection.goldOwnedEmptyObjectsV130 -ne $false -or $Connection.goldOwnedManagedFormV107 -isnot [bool] -or $Connection.goldOwnedManagedFormV107 -ne $false -or $Connection.goldOwnedConstantV99 -ne $false -or $Connection.goldOwnObjectModuleV82 -ne $false -or $Connection.goldOwnObjectModuleV78 -ne $false -or $Connection.captureFreshV81 -ne $false -or
       $Connection.objectNotificationV57 -ne $false -or $Connection.localBookkeepingV60 -ne $false -or $Connection.bufferApplyV61 -ne $false -or $Connection.bufferUndoV64 -ne $false -or $Connection.wholeModuleV65 -ne $false -or
       $Connection.selectionInputsV46 -ne $true -or $Connection.uiControllerCaptureV44 -ne $false -or $Connection.captureNotificationV56 -ne $false -or
       $Connection.captureScope -cne 'none' -or $Connection.captureWriteAllowed -ne $false -or $Connection.pilotScope -cne 'none' -or
       $Connection.goldOwnedFullObjectModuleV150Token -cnotmatch '^[a-f0-9]{32}$' -or $Connection.sessionId -cnotmatch '^[a-f0-9]{32}$' -or
       $Connection.leaseOwner -cnotmatch '^[a-f0-9]{32}$' -or $Connection.processCreationFileTimeUtc -cnotmatch '^[a-f0-9]{16}$' -or
       $Connection.processCreationFileTimeUtc -ceq ('0'*16) -or $Connection.pipeName -cne ('AH1C-'+$Connection.sessionId) -or
       $Connection.processId -le 0 -or $Connection.processId -gt [int]::MaxValue){throw 'V150_CLIENT_ROLE_REJECTED'}
}

function Assert-AhGoldOwnedFullObjectModuleV150Arguments([string]$OperationId,[string]$Command,[bool]$DeferCloseAck){
    if($OperationId -cnotmatch '^[a-f0-9]{32}$' -or $Command -cnotin @('PING','STATUS','READLIVE','SOURCE_ONCE','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','GOLD_OWNED_FULL_OBJECT_MODULE_V150','CLOSE_SAFE') -or
       ($DeferCloseAck -and $Command -cne 'CLOSE_SAFE')){throw 'V150_CLIENT_ARGUMENT_REJECTED'}
}

function Assert-AhGoldOwnedFullObjectModuleV150Path([string]$Path){
    if($Path -cnotmatch '^F:\\Projects\\AH_1C\\build\\designer-v43-[a-f0-9]{32}\\session-[a-f0-9]{32}\\command-connection\.json$'){
        throw 'V150_CLIENT_PATH_REJECTED'
    }
}

function Get-AhGoldOwnedFullObjectModuleV150Sha([string]$File){
    Assert-AhGoldOwnedFullObjectModuleV150PlainPath $File
    $item=Get-Item -LiteralPath $File -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'V150_CLIENT_SOURCE_REPARSE_REJECTED'}
    $stream=[IO.File]::Open($File,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}
    finally{$hash.Dispose();$stream.Dispose()}
}

function Assert-AhGoldOwnedFullObjectModuleV150PlainPath([string]$File){
    $current=[IO.Path]::GetFullPath($File)
    while($current){
        if(Test-Path -LiteralPath $current){
            if((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V150_CLIENT_SOURCE_REPARSE_REJECTED'}
        }
        $parent=[IO.Path]::GetDirectoryName($current)
        if(!$parent -or $parent -ceq $current){break}
        $current=$parent
    }
}

function Assert-AhGoldOwnedFullObjectModuleV150Source([string]$File,$Expected){
    if($Expected -isnot [string] -or $Expected -cnotmatch '^[a-f0-9]{64}$' -or (Get-AhGoldOwnedFullObjectModuleV150Sha $File) -cne $Expected){
        throw 'V150_CLIENT_SOURCE_CHANGED'
    }
}

function Assert-AhGoldOwnedFullObjectModuleV150Profile($Connection,[string]$Build,[string]$SourceRoot){
    $manifest=Join-Path $Build 'v43-prepared.json'
    $item=Get-Item -LiteralPath $manifest -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0 -or $item.Length -gt 131072){throw 'V150_CLIENT_PREPARED_BOUND_REJECTED'}
    Assert-AhGoldOwnedFullObjectModuleV150Source $manifest $Connection.goldOwnedFullObjectModuleV150PreparedManifestSha256
    $profile=[IO.File]::ReadAllText($manifest)|ConvertFrom-Json
    if($profile.passed -isnot [bool] -or !$profile.passed -or $profile.goldStarted -isnot [bool] -or $profile.goldStarted -or
       $profile.nonce -cne (Split-Path $Build -Leaf).Substring(13)){throw 'V150_CLIENT_PREPARED_SCOPE_REJECTED'}
    $keys=@('NativeCommandClient.cs','Invoke-GoldOwnedFullObjectModuleV150.ps1','tests/NativeGoldOwnedFullObjectModuleV150.as',
        'research/gold_owned_full_object_module_contract_v150.py','research/gold_owned_full_object_module_guard_v150.py',
        'tests/NativeGoldOwnedFullObjectModuleSessionV150.as','research/gold_owned_full_object_module_controller_v150.py',
        'tests/NativeOwnedModulePayloadV142.as','research/owned_module_payload_contract_v142.py',
        'tests/NativeCommandSession.as','tests/Invoke-LiveReadProbe.ps1','tests/run_live_probe.py',
        'research/prepare_gold_startup_v43.py','research/run_gold_startup_v43.py')
    foreach($key in $keys){
        $relative='tools/1c/designer-bridge/'+$key
        $pins=@($profile.sourceSha256.PSObject.Properties|Where-Object {$_.Name.Replace('\','/') -ceq $relative})
        if($pins.Count -ne 1 -or $pins[0].Name -cne $relative){throw 'V150_CLIENT_CANONICAL_SOURCE_REJECTED'}
        Assert-AhGoldOwnedFullObjectModuleV150Source (Join-Path $SourceRoot $key) $pins[0].Value
    }
    $payloadPins=@($profile.sourceSha256.PSObject.Properties|Where-Object {$_.Name.Replace('\','/') -ceq 'tools/data-anonymization/managed/ObjectModule.bsl'})
    if($payloadPins.Count -ne 1 -or $payloadPins[0].Name -cne 'tools/data-anonymization/managed/ObjectModule.bsl' -or
        $payloadPins[0].Value -cne '0320a444334420e1cecf3a0bc462add6365e014fd39b144a38889b04ce228aa7'){throw 'V150_CLIENT_PAYLOAD_PIN_REJECTED'}
}

function Write-AhGoldOwnedFullObjectModuleV150Caller([string]$Session,[string]$OperationId,[string]$ExchangeId,[string]$Command,$Caller){
    Assert-AhGoldOwnedFullObjectModuleV150Arguments $OperationId $Command $false
    Assert-AhGoldOwnedFullObjectModuleV150Path (Join-Path $Session 'command-connection.json')
    Assert-AhGoldOwnedFullObjectModuleV150PlainPath $Session
    if($ExchangeId -cnotmatch '^[a-f0-9]{32}$' -or $Caller.pid -isnot [int] -or $Caller.pid -le 0 -or
        $Caller.birth -isnot [string] -or $Caller.birth -cnotmatch '^[a-f0-9]{16}$' -or $Caller.birth -ceq ('0'*16)){throw 'V150_CLIENT_CALLER_REJECTED'}
    $path=Join-Path $Session ('owned-full-object-module-caller-v150-'+$OperationId+'-'+$ExchangeId+'.json')
    $record=[ordered]@{command=$Command;operationId=$OperationId;exchangeId=$ExchangeId;caller=$Caller}
    $bytes=[Text.Encoding]::UTF8.GetBytes(($record|ConvertTo-Json -Compress))
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    return $path
}

function Write-AhGoldOwnedFullObjectModuleV150Response([string]$Session,[string]$OperationId,[string]$ExchangeId,[byte[]]$Bytes){
    Assert-AhGoldOwnedFullObjectModuleV150Path (Join-Path $Session 'command-connection.json')
    Assert-AhGoldOwnedFullObjectModuleV150PlainPath $Session
    if($OperationId -cnotmatch '^[a-f0-9]{32}$' -or $ExchangeId -cnotmatch '^[a-f0-9]{32}$' -or $Bytes.Length -gt 1048576){throw 'V150_CLIENT_RESPONSE_REJECTED'}
    $path=Join-Path $Session ('owned-full-object-module-client-v150-'+$OperationId+'-'+$ExchangeId+'.txt')
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    return $path
}

function Ensure-AhGoldOwnedFullObjectModuleV150Permit($Connection,[string]$Session,[string]$OperationId){
    Assert-AhGoldOwnedFullObjectModuleV150Arguments $OperationId 'GOLD_OWNED_FULL_OBJECT_MODULE_V150' $false
    Assert-AhGoldOwnedFullObjectModuleV150Path (Join-Path $Session 'command-connection.json')
    Assert-AhGoldOwnedFullObjectModuleV150PlainPath $Session
    $permit=Join-Path $Session ('gold-owned-full-object-module-v150-permit-'+$OperationId)
    $permitBytes=[Text.Encoding]::ASCII.GetBytes($Connection.goldOwnedFullObjectModuleV150Token+'|'+$OperationId+'|GOLD_OWNED_FULL_OBJECT_MODULE_V150|0320a444334420e1cecf3a0bc462add6365e014fd39b144a38889b04ce228aa7|be276787-4261-50e8-9524-d748a29a81ad')
    if(Test-Path -LiteralPath $permit){
        $item=Get-Item -LiteralPath $permit -Force
        if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne $permitBytes.Length){throw 'V150_CLIENT_EXISTING_PERMIT_REJECTED'}
        # The shared-read-only handle excludes replacement/content writers while
        # checking a cached same-operation permit. No changed bytes are reused.
        $stream=[IO.File]::Open($permit,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try{
            if($stream.Length -ne $permitBytes.Length){throw 'V150_CLIENT_EXISTING_PERMIT_REJECTED'}
            $actual=New-Object byte[] $permitBytes.Length;$count=0
            while($count -lt $actual.Length){
                $read=$stream.Read($actual,$count,$actual.Length-$count)
                if($read -le 0){throw 'V150_CLIENT_EXISTING_PERMIT_REJECTED'}
                $count+=$read
            }
            if($stream.ReadByte() -ne -1 -or [Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($permitBytes)){throw 'V150_CLIENT_EXISTING_PERMIT_REJECTED'}
        }finally{$stream.Dispose()}
    }else{
        $stream=[IO.File]::Open($permit,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$stream.Write($permitBytes,0,$permitBytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    }
}

try {
    if([IntPtr]::Size -ne 4){throw 'V150_CLIENT_ARCHITECTURE_REJECTED'}
    Assert-AhGoldOwnedFullObjectModuleV150Arguments $OperationId $Command ([bool]$DeferCloseAck)
    $path=[IO.Path]::GetFullPath($ConnectionFile);$session=Split-Path $path -Parent;$build=Split-Path $session -Parent
    Assert-AhGoldOwnedFullObjectModuleV150Path $path
    foreach($item in @($path,$session,$build)){
        if((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V150_CLIENT_REPARSE_REJECTED'}
    }
    $connectionItem=Get-Item -LiteralPath $path -Force
    if($connectionItem.Length -le 0 -or $connectionItem.Length -gt 8192){throw 'V150_CLIENT_CONNECTION_REJECTED'}
    Add-Type -AssemblyName System.Security
    $published=[IO.File]::ReadAllText($path)|ConvertFrom-Json
    if($published.sealVersion -isnot [int] -or $published.sealVersion -ne 1){throw 'V150_CLIENT_SEAL_REJECTED'}
    try{
        $payload=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($published.protectedConnection),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-COMMAND-V2'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
        if($payload.Length -eq 0 -or $payload.Length -gt 8192){throw 'V150_CLIENT_SEAL_REJECTED'}
        $connection=(New-Object Text.UTF8Encoding($false,$true)).GetString($payload)|ConvertFrom-Json
    }catch{throw 'V150_CLIENT_SEAL_REJECTED'}
    Assert-AhGoldOwnedFullObjectModuleV150Role $connection
    Assert-AhGoldOwnedFullObjectModuleV150Profile $connection $build $PSScriptRoot
    Assert-AhGoldOwnedFullObjectModuleV150Source (Join-Path $PSScriptRoot 'NativeCommandClient.cs') $connection.clientSourceSha256
    Assert-AhGoldOwnedFullObjectModuleV150Source (Join-Path $build 'NativeCommandClient.dll') $connection.clientDllSha256
    $null=[Reflection.Assembly]::LoadFrom((Join-Path $build 'NativeCommandClient.dll'))
    # Actual server PID and original kernel birth are checked in OpenSession
    # before a permit exists. The discovery envelope never grants this role.
    $client=[NativeCommandClient]::OpenSession($connection.pipeName,[uint32]$connection.processId,$connection.processCreationFileTimeUtc,$connection.sessionId)
    try{
        $exchangeId=[guid]::NewGuid().ToString('N')
        $caller=[pscustomobject]@{pid=[int]$PID;birth=([Diagnostics.Process]::GetCurrentProcess().StartTime.ToFileTimeUtc().ToString('x16'))}
        $callerFile=Write-AhGoldOwnedFullObjectModuleV150Caller $session $OperationId $exchangeId $Command $caller
        if($Command -ceq 'GOLD_OWNED_FULL_OBJECT_MODULE_V150'){Ensure-AhGoldOwnedFullObjectModuleV150Permit $connection $session $OperationId}
        $reply=$client.Send($OperationId,$Command)
    }finally{$client.Dispose()}
    $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes($reply.Body)
    $result=Write-AhGoldOwnedFullObjectModuleV150Response $session $OperationId $exchangeId $bytes
    if($Command -ceq 'CLOSE_SAFE' -and !$DeferCloseAck -and $reply.Kind -ceq 'CLOSE_SAFE' -and $reply.Body -ceq 'SAFE_CLOSE_PROPOSED'){
        $ack=[ordered]@{version=1;operationId=$OperationId;sessionId=$connection.sessionId;processId=$connection.processId;processCreationFileTimeUtc=$connection.processCreationFileTimeUtc}
        $sealed=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes(($ack|ConvertTo-Json -Compress)),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-CLOSE-ACK-V1'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes((Join-Path $session 'command-close-ack.protected'),$sealed)
        [IO.File]::WriteAllText((Join-Path $session 'command-close-ack'),$OperationId,(New-Object Text.UTF8Encoding($false)))
    }
    [ordered]@{status=$reply.Kind;command=$Command;operationId=$OperationId;exchangeId=$exchangeId;caller=$caller;callerWitnessFile=$callerFile;callerWitnessSha256=(Get-AhGoldOwnedFullObjectModuleV150Sha $callerFile);replayed=$reply.Replayed;processId=$connection.processId;processCreationFileTimeUtc=$connection.processCreationFileTimeUtc;birth=$connection.processCreationFileTimeUtc;resultFile=$result;bytes=$bytes.Length;sha256=(Get-AhGoldOwnedFullObjectModuleV150Sha $result)}|ConvertTo-Json -Compress
    if($reply.Kind -ceq 'ERROR'){exit 1}
}catch{
    $diagnostic=$_.Exception;while($diagnostic.InnerException){$diagnostic=$diagnostic.InnerException}
    $code=[regex]::Match($diagnostic.Message,'\b(?:V150|COMMAND|PIPE)_[A-Z_0-9]{3,63}\b')
    [ordered]@{status='V150_CLIENT_REJECTED';code=$(if($code.Success){$code.Value}else{'V150_CLIENT_FAILED'});errorType=$_.Exception.GetType().Name;errorLine=$_.InvocationInfo.ScriptLineNumber}|ConvertTo-Json -Compress
    exit 85
}
