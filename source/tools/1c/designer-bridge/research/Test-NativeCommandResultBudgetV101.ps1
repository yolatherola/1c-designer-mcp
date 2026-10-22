# Offline production-client regression. Creates only a unique own build and a
# local SELF message-pipe; never opens Gold or a protected connection file.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
$buildRoot=[IO.Path]::GetFullPath((Join-Path $taskRoot 'build'))
$taskNonce=[Guid]::NewGuid().ToString('N')
$taskDir=[IO.Path]::GetFullPath((Join-Path $buildRoot ('native-command-budget-v101-'+$taskNonce)))
if(!$taskDir.StartsWith($buildRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'V101_BUILD_PATH_REJECTED'}
$client=Join-Path $taskRoot 'tools/1c/designer-bridge/NativeCommandClient.cs'
$fixture=Join-Path $taskRoot 'tools/1c/designer-bridge/tests/TestNativeCommandResultBudgetV101.cs'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET/Framework/v4.0.30319/csc.exe'
$compilerProcess=$null;$fixtureProcess=$null;$ownedCreated=$false;$cleanupVerified=$false
$outcome=[ordered]@{passed=$false;checkCount=0;failureCode='V101_OFFLINE_FAILED';temporaryDirectory=$taskDir;temporaryDirectoryRemoved=$false}
function Get-V101Sha([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Test-V101Regular([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'V101_FILE_KIND_REJECTED'}
}
try{
    if([IO.Directory]::Exists($taskDir) -or [IO.File]::Exists($taskDir)){throw 'V101_BUILD_ALREADY_EXISTS'}
    Test-V101Regular $client;Test-V101Regular $fixture;Test-V101Regular $compiler
    $clientSha=Get-V101Sha $client;$fixtureSha=Get-V101Sha $fixture
    [IO.Directory]::CreateDirectory($taskDir)|Out-Null;$ownedCreated=$true
    [IO.File]::WriteAllText((Join-Path $taskDir 'owner.json'),('{"task":"V101","nonce":"'+$taskNonce+'"}'),[Text.UTF8Encoding]::new($false))
    $exe=Join-Path $taskDir 'NativeCommandResultBudgetV101.exe'
    $compilerOut=Join-Path $taskDir 'compiler.stdout.log';$compilerErr=Join-Path $taskDir 'compiler.stderr.log'
    $arguments=@('/nologo','/target:exe','/platform:x86','/r:System.Web.Extensions.dll',('/out:"'+$exe+'"'),('"'+$client+'"'),('"'+$fixture+'"'))
    $compilerProcess=Start-Process -FilePath $compiler -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $compilerOut -RedirectStandardError $compilerErr
    $null=$compilerProcess.Handle
    if(!$compilerProcess.WaitForExit(10000)){throw 'V101_COMPILER_RESULT_UNKNOWN'}
    $compilerProcess.WaitForExit()
    $outcome.compilerExitCode=$compilerProcess.ExitCode
    if($compilerProcess.ExitCode -ne 0){
        $diagnostic=[IO.File]::ReadAllText($compilerOut)+[IO.File]::ReadAllText($compilerErr)
        $outcome.compilerErrorIds=@([regex]::Matches($diagnostic,'\b(CS[0-9]{4})\b')|ForEach-Object {$_.Groups[1].Value}|Select-Object -Unique -First 16)
        $outcome.compilerErrorPositions=@([regex]::Matches($diagnostic,'\(([0-9]{1,5}),([0-9]{1,5})\): [^\r\n]*?\b(CS[0-9]{4})\b')|Select-Object -First 16|ForEach-Object {[ordered]@{line=[int]$_.Groups[1].Value;column=[int]$_.Groups[2].Value;code=$_.Groups[3].Value}})
        throw 'V101_COMPILER_FAILED'
    }
    if((Get-V101Sha $client) -cne $clientSha -or (Get-V101Sha $fixture) -cne $fixtureSha){throw 'V101_SOURCE_CHANGED'}
    Test-V101Regular $exe
    $fixtureOut=Join-Path $taskDir 'fixture.stdout.log';$fixtureErr=Join-Path $taskDir 'fixture.stderr.log'
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $fixtureProcess=Start-Process -FilePath $exe -WindowStyle Hidden -PassThru -RedirectStandardOutput $fixtureOut -RedirectStandardError $fixtureErr
    $null=$fixtureProcess.Handle
    $outcome.fixtureProcessId=$fixtureProcess.Id
    $outcome.fixtureProcessCreationFileTimeUtc=$fixtureProcess.StartTime.ToUniversalTime().ToFileTimeUtc().ToString('x16')
    if(!$fixtureProcess.WaitForExit(45000)){throw 'V101_FIXTURE_RESULT_UNKNOWN'}
    $fixtureProcess.WaitForExit()
    $outcome.fixtureExitCode=$fixtureProcess.ExitCode
    $fixtureSummary=[IO.File]::ReadAllText($fixtureOut).Trim()
    $outcome.fixtureStdoutCharacters=$fixtureSummary.Length
    $outcome.fixtureStderrBytes=(Get-Item -LiteralPath $fixtureErr).Length
    if($fixtureProcess.ExitCode -ne 0 -or $fixtureSummary -cne 'V101_PASS:7' -or (Get-Item -LiteralPath $fixtureErr).Length -ne 0){
        $failure=[regex]::Match($fixtureSummary,'\AV101_FAIL:(notEntered|policy|delayedV82|delayedV107|ordinaryRead|unknownCommand|wrongHeader|cachedReplay):((?:V101|COMMAND|PIPE)_[A-Z_0-9]{3,48})\z')
        if($failure.Success){$outcome.fixtureStage=$failure.Groups[1].Value;$outcome.fixtureCode=$failure.Groups[2].Value}
        $outcome.fixtureRuntimeTypes=@([regex]::Matches([IO.File]::ReadAllText($fixtureErr),'\b(?:System\.)?([A-Za-z]{3,48}Exception)\b')|ForEach-Object {$_.Groups[1].Value}|Select-Object -Unique -First 8)
        $outcome.fixtureRuntimeMethods=@([regex]::Matches([IO.File]::ReadAllText($fixtureErr),'\b(System\.[A-Za-z_][A-Za-z0-9_.]{2,120})\(')|ForEach-Object {$_.Groups[1].Value}|Select-Object -Unique -First 8)
        throw 'V101_FIXTURE_FAILED'
    }
    if((Get-V101Sha $client) -cne $clientSha -or (Get-V101Sha $fixture) -cne $fixtureSha){throw 'V101_SOURCE_CHANGED'}
    $outcome.passed=$true;$outcome.checkCount=7;$outcome.failureCode=$null
    $outcome.clientSourceSha256=$clientSha;$outcome.fixtureSourceSha256=$fixtureSha
    $outcome.offlineElapsedMs=[math]::Round($timer.Elapsed.TotalMilliseconds,1)
}catch{
    if($_.Exception.Message -cmatch '^V101_[A-Z_]{3,48}$'){$outcome.failureCode=$_.Exception.Message}
}finally{
    # Never kill a process or remove its executable after an unknown timeout.
    $allExited=(!$compilerProcess -or $compilerProcess.HasExited) -and (!$fixtureProcess -or $fixtureProcess.HasExited)
    if($ownedCreated -and $allExited){
        try{
            $directory=Get-Item -LiteralPath $taskDir -Force
            if(!$directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $directory.FullName -cne $taskDir){throw 'V101_CLEANUP_PATH_REJECTED'}
            $owner=Join-Path $taskDir 'owner.json';Test-V101Regular $owner
            if([IO.File]::ReadAllText($owner) -cne ('{"task":"V101","nonce":"'+$taskNonce+'"}')){throw 'V101_CLEANUP_OWNER_REJECTED'}
            $names=@('owner.json','NativeCommandResultBudgetV101.exe','compiler.stdout.log','compiler.stderr.log','fixture.stdout.log','fixture.stderr.log')
            $files=@(Get-ChildItem -LiteralPath $taskDir -Force)
            foreach($item in $files){
                if($item.Name -cnotin $names){throw 'V101_CLEANUP_ROSTER_REJECTED'}
                Test-V101Regular $item.FullName
            }
            foreach($item in $files){Remove-Item -LiteralPath $item.FullName -Force}
            Remove-Item -LiteralPath $taskDir
            $cleanupVerified=![IO.Directory]::Exists($taskDir)
        }catch{$outcome.passed=$false;$outcome.failureCode='V101_CLEANUP_REJECTED'}
    }
    if($compilerProcess){$compilerProcess.Dispose()};if($fixtureProcess){$fixtureProcess.Dispose()}
    $outcome.temporaryDirectoryRemoved=$cleanupVerified
    if($ownedCreated -and !$cleanupVerified){$outcome.passed=$false}
}
$outcome|ConvertTo-Json -Compress
if(!$outcome.passed){exit 1}
