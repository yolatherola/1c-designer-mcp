param(
    [Parameter(Mandatory)][string]$ConnectionFile,
    [Parameter(Mandatory)][ValidateSet('PING','STATUS','READLIVE','SOURCE_ONCE','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','GOLD_OWN_OBJECT_MODULE_V82','CLOSE_SAFE')][string]$Command,
    [string]$OperationId=([guid]::NewGuid().ToString('N')),
    [switch]$DeferCloseAck
)
$ErrorActionPreference='Stop'

function Assert-AhGoldOwnObjectModuleV82Role($Connection){
    foreach($name in @('readOnlyGold','goldOwnObjectModuleV82','goldOwnObjectModuleV78','captureFreshV81','selectionInputsV46','uiControllerCaptureV44','captureNotificationV56','captureWriteAllowed')){
        if($Connection.$name -isnot [bool]){throw 'V82_OWN_MODULE_ROLE_REJECTED'}
    }
    if($Connection.version -isnot [int] -or ($Connection.processId -isnot [int] -and $Connection.processId -isnot [long])){throw 'V82_OWN_MODULE_ROLE_REJECTED'}
    if($Connection.version -ne 2 -or $Connection.target -cne 'Gold' -or $Connection.platform -cne '8.3.18.1208' -or
       $Connection.rootId -cne '218b5d00-7e10-486f-874c-73c2368ed5da' -or $Connection.objectId -cne '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d' -or
       $Connection.readOnlyGold -ne $false -or $Connection.goldOwnObjectModuleV82 -ne $true -or $Connection.goldOwnObjectModuleV78 -ne $false -or $Connection.captureFreshV81 -ne $false -or
       $Connection.selectionInputsV46 -ne $true -or $Connection.uiControllerCaptureV44 -ne $false -or
       $Connection.captureNotificationV56 -ne $false -or $Connection.captureScope -cne 'none' -or
       $Connection.captureWriteAllowed -ne $false -or $Connection.pilotScope -cne 'none' -or
       $Connection.goldOwnObjectModuleV82Token -cnotmatch '^[a-f0-9]{32}$' -or
       $Connection.sessionId -cnotmatch '^[a-f0-9]{32}$' -or $Connection.leaseOwner -cnotmatch '^[a-f0-9]{32}$' -or
       $Connection.processCreationFileTimeUtc -cnotmatch '^[a-f0-9]{16}$' -or $Connection.processId -le 0 -or $Connection.processId -gt 2147483647 -or $Connection.processCreationFileTimeUtc -ceq ('0'*16)){throw 'V82_OWN_MODULE_ROLE_REJECTED'}
}

function Get-AhGoldOwnModuleShaV82([string]$File){
    $stream=[IO.File]::OpenRead($File);$hash=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}
    finally{$hash.Dispose();$stream.Dispose()}
}

try {
    if([IntPtr]::Size -ne 4 -or $OperationId -cnotmatch '^[a-f0-9]{32}$' -or ($DeferCloseAck -and $Command -ne 'CLOSE_SAFE')){throw 'V82_OWN_MODULE_CLIENT_REJECTED'}
    $path=[IO.Path]::GetFullPath($ConnectionFile);$session=Split-Path $path -Parent;$build=Split-Path $session -Parent
    if($path -cnotmatch '^F:\\Projects\\AH_1C\\build\\designer-v43-[a-f0-9]{32}\\session-[a-f0-9]{32}\\command-connection.json$'){throw 'V82_OWN_MODULE_PATH_REJECTED'}
    foreach($item in @($path,$session,$build)){
        if((Get-Item -LiteralPath $item).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'V82_OWN_MODULE_REPARSE_REJECTED'}
    }
    if((Get-Item -LiteralPath $path).Length -gt 12288){throw 'V82_OWN_MODULE_CONNECTION_REJECTED'}
    Add-Type -AssemblyName System.Security
    $published=[IO.File]::ReadAllText($path)|ConvertFrom-Json
    if($published.sealVersion -ne 1){throw 'V82_OWN_MODULE_SEAL_REJECTED'}
    try {
        $payload=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($published.protectedConnection),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-COMMAND-V2'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
        $connection=(New-Object Text.UTF8Encoding($false,$true)).GetString($payload)|ConvertFrom-Json
    }catch{throw 'V82_OWN_MODULE_SEAL_REJECTED'}
    Assert-AhGoldOwnObjectModuleV82Role $connection
    $checks=@(
        @((Join-Path $PSScriptRoot 'NativeCommandClient.cs'),$connection.clientSourceSha256),
        @((Join-Path $build 'NativeCommandClient.dll'),$connection.clientDllSha256),
        @($PSCommandPath,$connection.goldOwnObjectModuleV82ClientSourceSha256),
        @((Join-Path $PSScriptRoot 'tests/NativeGoldOwnObjectModuleV82.as'),$connection.goldOwnObjectModuleV82SourceSha256),
        @((Join-Path $PSScriptRoot 'research/gold_own_object_module_contract_v82.py'),$connection.goldOwnObjectModuleV82ContractSourceSha256),
        @((Join-Path $PSScriptRoot 'research/gold_own_object_module_guard_v82.py'),$connection.goldOwnObjectModuleV82GuardSourceSha256),
        @((Join-Path $build 'v43-prepared.json'),$connection.goldOwnObjectModuleV82PreparedManifestSha256)
    )
    foreach($pair in $checks){
        if($pair[1] -cnotmatch '^[a-f0-9]{64}$' -or (Get-AhGoldOwnModuleShaV82 $pair[0]) -cne $pair[1]){throw 'V82_OWN_MODULE_SOURCE_CHANGED'}
    }
    $null=[Reflection.Assembly]::LoadFrom((Join-Path $build 'NativeCommandClient.dll'))
    # OpenSession checks the live kernel PID/birth before the durable writer
    # permit is created. The outer connection record never grants authority.
    $client=[NativeCommandClient]::OpenSession($connection.pipeName,[uint32]$connection.processId,$connection.processCreationFileTimeUtc,$connection.sessionId)
    try {
        if($Command -ceq 'GOLD_OWN_OBJECT_MODULE_V82'){
            $permit=Join-Path $session ('gold-own-object-module-v82-permit-'+$OperationId)
            $permitBytes=[Text.Encoding]::ASCII.GetBytes($connection.goldOwnObjectModuleV82Token+'|'+$OperationId+'|GOLD_OWN_OBJECT_MODULE_V82')
            if(Test-Path -LiteralPath $permit){
                $item=Get-Item -LiteralPath $permit
                if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne $permitBytes.Length -or [Convert]::ToBase64String([IO.File]::ReadAllBytes($permit)) -cne [Convert]::ToBase64String($permitBytes)){throw 'V82_OWN_MODULE_EXISTING_PERMIT_REJECTED'}
            }else{
                $stream=[IO.File]::Open($permit,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
                try{$stream.Write($permitBytes,0,$permitBytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
            }
        }
        $reply=$client.Send($OperationId,$Command)
    }finally{$client.Dispose()}
    $result=Join-Path $session ('own-module-client-v82-'+$OperationId+'-'+[guid]::NewGuid().ToString('N')+'.txt')
    $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes($reply.Body)
    $stream=[IO.File]::Open($result,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    if($Command -ceq 'CLOSE_SAFE' -and !$DeferCloseAck -and $reply.Kind -ceq 'CLOSE_SAFE' -and $reply.Body -ceq 'SAFE_CLOSE_PROPOSED'){
        $ack=[ordered]@{version=1;operationId=$OperationId;sessionId=$connection.sessionId;processId=$connection.processId;processCreationFileTimeUtc=$connection.processCreationFileTimeUtc}
        $sealed=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes(($ack|ConvertTo-Json -Compress)),[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-CLOSE-ACK-V1'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes((Join-Path $session 'command-close-ack.protected'),$sealed)
        [IO.File]::WriteAllText((Join-Path $session 'command-close-ack'),$OperationId,(New-Object Text.UTF8Encoding($false)))
    }
    [ordered]@{status=$reply.Kind;command=$Command;operationId=$OperationId;replayed=$reply.Replayed;processId=$connection.processId;processCreationFileTimeUtc=$connection.processCreationFileTimeUtc;birth=$connection.processCreationFileTimeUtc;resultFile=$result;bytes=$bytes.Length;sha256=(Get-AhGoldOwnModuleShaV82 $result)}|ConvertTo-Json -Compress
    if($reply.Kind -ceq 'ERROR'){exit 1}
}catch{
    $diagnostic=$_.Exception;while($diagnostic.InnerException){$diagnostic=$diagnostic.InnerException}
    $code=[regex]::Match($diagnostic.Message,'\b(?:V82|COMMAND|PIPE)_[A-Z_0-9]{3,63}\b')
    [ordered]@{status='V82_OWN_MODULE_CLIENT_REJECTED';code=$(if($code.Success){$code.Value}else{'V82_OWN_MODULE_CLIENT_FAILED'});errorType=$_.Exception.GetType().Name;errorLine=$_.InvocationInfo.ScriptLineNumber}|ConvertTo-Json -Compress
    exit 85
}
