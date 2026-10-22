param(
    [Parameter(Mandatory)][string]$ConnectionFile,
    [Parameter(Mandatory)][ValidateSet('PING','STATUS','READLIVE','SOURCE_ONCE','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','GOLD_OWNED_CONSTANT_V99','CLOSE_SAFE')][string]$Command,
    [string]$OperationId=([guid]::NewGuid().ToString('N')),
    [switch]$DeferCloseAck
)
$ErrorActionPreference='Stop'

function Assert-AhGoldOwnedConstantV99Role($Connection){
    foreach($name in @('readOnlyGold','goldOwnedConstantV99','goldOwnObjectModuleV82','goldOwnObjectModuleV78','captureFreshV81','selectionInputsV46','uiControllerCaptureV44','captureNotificationV56','captureWriteAllowed')){
        if($Connection.$name -isnot [bool]){throw 'V99_CLIENT_ROLE_REJECTED'}
    }
    foreach($name in @('target','platform','rootId','objectId','captureScope','pilotScope','goldOwnedConstantV99Token','sessionId','leaseOwner','processCreationFileTimeUtc','pipeName')){
        if($Connection.$name -isnot [string]){throw 'V99_CLIENT_ROLE_REJECTED'}
    }
    if($Connection.version -isnot [int] -or ($Connection.processId -isnot [int] -and $Connection.processId -isnot [long])){throw 'V99_CLIENT_ROLE_REJECTED'}
    if($Connection.version -ne 2 -or $Connection.target -cne 'Gold' -or $Connection.platform -cne '8.3.18.1208' -or
       $Connection.rootId -cne '218b5d00-7e10-486f-874c-73c2368ed5da' -or $Connection.objectId -cne '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d' -or
       $Connection.readOnlyGold -ne $false -or $Connection.goldOwnedConstantV99 -ne $true -or
       $Connection.goldOwnObjectModuleV82 -ne $false -or $Connection.goldOwnObjectModuleV78 -ne $false -or $Connection.captureFreshV81 -ne $false -or
       $Connection.selectionInputsV46 -ne $true -or $Connection.uiControllerCaptureV44 -ne $false -or $Connection.captureNotificationV56 -ne $false -or
       $Connection.captureScope -cne 'none' -or $Connection.captureWriteAllowed -ne $false -or $Connection.pilotScope -cne 'none' -or
       $Connection.goldOwnedConstantV99Token -cnotmatch '^[a-f0-9]{32}$' -or $Connection.sessionId -cnotmatch '^[a-f0-9]{32}$' -or
       $Connection.leaseOwner -cnotmatch '^[a-f0-9]{32}$' -or $Connection.processCreationFileTimeUtc -cnotmatch '^[a-f0-9]{16}$' -or
       $Connection.processCreationFileTimeUtc -ceq ('0'*16) -or $Connection.pipeName -cne ('AH1C-'+$Connection.sessionId) -or
       $Connection.processId -le 0 -or $Connection.processId -gt [int]::MaxValue){throw 'V99_CLIENT_ROLE_REJECTED'}
}

function Assert-AhGoldOwnedConstantV99Arguments([string]$OperationId,[string]$Command,[bool]$DeferCloseAck){
    if($OperationId -cnotmatch '^[a-f0-9]{32}$' -or $Command -cnotin @('PING','STATUS','READLIVE','SOURCE_ONCE','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','GOLD_OWNED_CONSTANT_V99','CLOSE_SAFE') -or
       ($DeferCloseAck -and $Command -cne 'CLOSE_SAFE')){throw 'V99_CLIENT_ARGUMENT_REJECTED'}
}

function Assert-AhGoldOwnedConstantV99Path([string]$Path){
    if($Path -cnotmatch '^F:\\Projects\\AH_1C\\build\\designer-v43-[a-f0-9]{32}\\session-[a-f0-9]{32}\\command-connection\.json$'){
        throw 'V99_CLIENT_PATH_REJECTED'
    }
}

function Get-AhGoldOwnedConstantV99Sha([string]$File){
    $item=Get-Item -LiteralPath $File -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'V99_CLIENT_SOURCE_REPARSE_REJECTED'}
    $stream=[IO.File]::Open($File,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}
    finally{$hash.Dispose();$stream.Dispose()}
}

function Assert-AhGoldOwnedConstantV99Source([string]$File,$Expected){
    if($Expected -isnot [string] -or $Expected -cnotmatch '^[a-f0-9]{64}$' -or (Get-AhGoldOwnedConstantV99Sha $File) -cne $Expected){
        throw 'V99_CLIENT_SOURCE_CHANGED'
    }
}

function Ensure-AhGoldOwnedConstantV99Permit($Connection,[string]$Session,[string]$OperationId){
    Assert-AhGoldOwnedConstantV99Arguments $OperationId 'GOLD_OWNED_CONSTANT_V99' $false
    Assert-AhGoldOwnedConstantV99Path (Join-Path $Session 'command-connection.json')
    $permit=Join-Path $Session ('gold-owned-constant-v99-permit-'+$OperationId)
    $permitBytes=[Text.Encoding]::ASCII.GetBytes($Connection.goldOwnedConstantV99Token+'|'+$OperationId+'|GOLD_OWNED_CONSTANT_V99')
    if(Test-Path -LiteralPath $permit){
        $item=Get-Item -LiteralPath $permit -Force
        if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne $permitBytes.Length){throw 'V99_CLIENT_EXISTING_PERMIT_REJECTED'}
        # The shared-read-only handle excludes replacement/content writers while
        # checking a cached same-operation permit. No changed bytes are reused.
        $stream=[IO.File]::Open($permit,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try{
            if($stream.Length -ne $permitBytes.Length){throw 'V99_CLIENT_EXISTING_PERMIT_REJECTED'}
            $actual=New-Object byte[] $permitBytes.Length;$count=0
            while($count -lt $actual.Length){
                $read=$stream.Read($actual,$count,$actual.Length-$count)
                if($read -le 0){throw 'V99_CLIENT_EXISTING_PERMIT_REJECTED'}
                $count+=$read
            }
            if($stream.ReadByte() -ne -1 -or [Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($permitBytes)){throw 'V99_CLIENT_EXISTING_PERMIT_REJECTED'}
        }finally{$stream.Dispose()}
    }else{
        $stream=[IO.File]::Open($permit,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$stream.Write($permitBytes,0,$permitBytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    }
}

try {
    if([IntPtr]::Size -ne 4){throw 'V99_CLIENT_ARCHITECTURE_REJECTED'}
    Assert-AhGoldOwnedConstantV99Arguments $OperationId $Command ([bool]$DeferCloseAck)
    $path=[IO.Path]::GetFullPath($ConnectionFile);$session=Split-Path $path -Parent;$build=Split-Path $session -Parent
    Assert-AhGoldOwnedConstantV99Path $path
    foreach($item in @($path,$session,$build)){
        if((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V99_CLIENT_REPARSE_REJECTED'}
    }
    $connectionItem=Get-Item -LiteralPath $path -Force
    if($connectionItem.Length -le 0 -or $connectionItem.Length -gt 12288){throw 'V99_CLIENT_CONNECTION_REJECTED'}
    Add-Type -AssemblyName System.Security
    $published=[IO.File]::ReadAllText($path)|ConvertFrom-Json
    if($published.sealVersion -isnot [int] -or $published.sealVersion -ne 1){throw 'V99_CLIENT_SEAL_REJECTED'}
    try{
        $payload=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($published.protectedConnection),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-COMMAND-V2'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
        if($payload.Length -eq 0 -or $payload.Length -gt 12288){throw 'V99_CLIENT_SEAL_REJECTED'}
        $connection=(New-Object Text.UTF8Encoding($false,$true)).GetString($payload)|ConvertFrom-Json
    }catch{throw 'V99_CLIENT_SEAL_REJECTED'}
    Assert-AhGoldOwnedConstantV99Role $connection
    $checks=@(
        @((Join-Path $PSScriptRoot 'NativeCommandClient.cs'),$connection.clientSourceSha256),
        @((Join-Path $build 'NativeCommandClient.dll'),$connection.clientDllSha256),
        @($PSCommandPath,$connection.goldOwnedConstantV99ClientSourceSha256),
        @((Join-Path $PSScriptRoot 'tests/NativeGoldOwnedConstantV99.as'),$connection.goldOwnedConstantV99SourceSha256),
        @((Join-Path $PSScriptRoot 'research/gold_owned_constant_contract_v99.py'),$connection.goldOwnedConstantV99ContractSourceSha256),
        @((Join-Path $PSScriptRoot 'research/gold_owned_constant_guard_v99.py'),$connection.goldOwnedConstantV99GuardSourceSha256),
        @((Join-Path $PSScriptRoot 'tests/NativeGoldOwnedConstantSessionV102.as'),$connection.goldOwnedConstantSessionV102SourceSha256),
        @((Join-Path $PSScriptRoot 'research/gold_owned_constant_session_contract_v102.py'),$connection.goldOwnedConstantSessionContractV102SourceSha256),
        @((Join-Path $build 'v43-prepared.json'),$connection.goldOwnedConstantV99PreparedManifestSha256)
    )
    foreach($pair in $checks){Assert-AhGoldOwnedConstantV99Source $pair[0] $pair[1]}
    $null=[Reflection.Assembly]::LoadFrom((Join-Path $build 'NativeCommandClient.dll'))
    # Actual server PID and original kernel birth are checked in OpenSession
    # before a permit exists. The discovery envelope never grants this role.
    $client=[NativeCommandClient]::OpenSession($connection.pipeName,[uint32]$connection.processId,$connection.processCreationFileTimeUtc,$connection.sessionId)
    try{
        if($Command -ceq 'GOLD_OWNED_CONSTANT_V99'){Ensure-AhGoldOwnedConstantV99Permit $connection $session $OperationId}
        $reply=$client.Send($OperationId,$Command)
    }finally{$client.Dispose()}
    $result=Join-Path $session ('owned-constant-client-v99-'+$OperationId+'-'+[guid]::NewGuid().ToString('N')+'.txt')
    $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes($reply.Body)
    $stream=[IO.File]::Open($result,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    if($Command -ceq 'CLOSE_SAFE' -and !$DeferCloseAck -and $reply.Kind -ceq 'CLOSE_SAFE' -and $reply.Body -ceq 'SAFE_CLOSE_PROPOSED'){
        $ack=[ordered]@{version=1;operationId=$OperationId;sessionId=$connection.sessionId;processId=$connection.processId;processCreationFileTimeUtc=$connection.processCreationFileTimeUtc}
        $sealed=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes(($ack|ConvertTo-Json -Compress)),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-CLOSE-ACK-V1'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes((Join-Path $session 'command-close-ack.protected'),$sealed)
        [IO.File]::WriteAllText((Join-Path $session 'command-close-ack'),$OperationId,(New-Object Text.UTF8Encoding($false)))
    }
    [ordered]@{status=$reply.Kind;command=$Command;operationId=$OperationId;replayed=$reply.Replayed;processId=$connection.processId;processCreationFileTimeUtc=$connection.processCreationFileTimeUtc;birth=$connection.processCreationFileTimeUtc;resultFile=$result;bytes=$bytes.Length;sha256=(Get-AhGoldOwnedConstantV99Sha $result)}|ConvertTo-Json -Compress
    if($reply.Kind -ceq 'ERROR'){exit 1}
}catch{
    $diagnostic=$_.Exception;while($diagnostic.InnerException){$diagnostic=$diagnostic.InnerException}
    $code=[regex]::Match($diagnostic.Message,'\b(?:V99|COMMAND|PIPE)_[A-Z_0-9]{3,63}\b')
    [ordered]@{status='V99_CLIENT_REJECTED';code=$(if($code.Success){$code.Value}else{'V99_CLIENT_FAILED'});errorType=$_.Exception.GetType().Name;errorLine=$_.InvocationInfo.ScriptLineNumber}|ConvertTo-Json -Compress
    exit 85
}
