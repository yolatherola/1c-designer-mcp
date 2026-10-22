param(
    [Parameter(Mandatory)][string]$ConnectionFile,
    [Parameter(Mandatory)][ValidateSet('PING','STATUS','WRITER_STATUS','READLIVE','SOURCE_ONCE','OWN_CYCLE','OWN_BUFFER_GUARD','SELECTION_INPUTS_V46','OBJECT_SNAPSHOT_V47','DOCUMENT_MODULES_V48','FACTORY_COPY_V49','FACTORY_VERIFY_V49','CAPTURE_LISTENERS_V51','CAPTURE_STATE_V52','STATISTIC_PACKET_V54','FREE_NOTIFICATION_V55','DETACHED_TEXT_UNDO_V63','VALUE_COPY_V67','VALUE_VERIFY_V67','VALUE_PERSIST_V68','PROCESSING_FORM_V69','OWN_PERSISTENCE_V71','OWN_FORM_TYPE_V72','OWN_FORM_TYPE_V74','OWN_MANAGED_BODY_V73','OWN_MANAGED_FORM_V75','MANAGED_BODY_FACTORY_V78','MANAGED_BODY_MODULE_V79','OWN_CONSTANT_V77','COMPACT_OWNER_V108','STOCK_SELECTION_INVENTORY_V106','EMPTY_CLASS_INVENTORY_V125','METADATA_RECEIVER_INVENTORY_V126','MANAGED_INPUT_RECORD_V145','CLOSE_SAFE')][string]$Command,
    [string]$OperationId=([guid]::NewGuid().ToString('N')),
    [switch]$DeferCloseAck
)
$ErrorActionPreference='Stop'
function Get-AhNativeSha256([string]$File){
    $sha=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($File))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
}
function Assert-AhReadDiagnosticSourceV109([object]$Record,[string]$BuildDirectory,[string]$CommandName,[string]$SourceRoot){
    if($CommandName -cnotin @('COMPACT_OWNER_V108','STOCK_SELECTION_INVENTORY_V106','EMPTY_CLASS_INVENTORY_V125','METADATA_RECEIVER_INVENTORY_V126')){throw 'V109_DIAGNOSTIC_COMMAND_REJECTED'}
    if($Record.PSObject.Properties.Name -contains 'managedInputRecordV145' -and ($Record.managedInputRecordV145 -isnot [bool] -or $Record.managedInputRecordV145)){throw 'V109_READONLY_ROLE_REQUIRED'}
    if($Record.goldOwnedFullObjectModuleV150 -isnot [bool] -or $Record.goldOwnedFullObjectModuleV150){throw 'V109_READONLY_ROLE_REQUIRED'}
    if($Record.PSObject.Properties.Name -contains 'goldOwnedDocumentStructureV139'){
        if($Record.goldOwnedDocumentStructureV139 -isnot [bool] -or $Record.goldOwnedDocumentStructureV139){throw 'V109_READONLY_ROLE_REQUIRED'}
    }
    if($Record.PSObject.Properties.Name -contains 'goldOwnedEmptyObjectsV130'){
        if($Record.goldOwnedEmptyObjectsV130 -isnot [bool] -or $Record.goldOwnedEmptyObjectsV130){throw 'V109_READONLY_ROLE_REQUIRED'}
    }
    if($Record.PSObject.Properties.Name -contains 'goldOwnedManagedFormV107'){
        if($Record.goldOwnedManagedFormV107 -isnot [bool] -or $Record.goldOwnedManagedFormV107){throw 'V109_READONLY_ROLE_REQUIRED'}
    }
    if($Record.readOnlyGold -isnot [bool] -or !$Record.readOnlyGold -or
        $Record.selectionInputsV46 -isnot [bool] -or !$Record.selectionInputsV46 -or
        $Record.uiControllerCaptureV44 -isnot [bool] -or $Record.uiControllerCaptureV44 -or
        $Record.captureNotificationV56 -isnot [bool] -or $Record.captureNotificationV56 -or
        $Record.pilotScope -cne 'none' -or
        $Record.genericReadDiagnosticsV109PreparedSha256 -isnot [string] -or
        $Record.genericReadDiagnosticsV109PreparedSha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'V109_READONLY_ROLE_REQUIRED'}
    if($CommandName -cin @('EMPTY_CLASS_INVENTORY_V125','METADATA_RECEIVER_INVENTORY_V126')){
        foreach($roleKey in @('goldOwnedFullObjectModuleV150','goldOwnedDocumentStructureV139','goldOwnedEmptyObjectsV130','goldOwnObjectModuleV78','goldOwnObjectModuleV82','goldOwnedConstantV99','goldOwnedManagedFormV107',
            'captureFreshV81','objectNotificationV57','localBookkeepingV60','bufferApplyV61','bufferUndoV64','wholeModuleV65','captureWriteAllowed')){
            if($Record.PSObject.Properties[$roleKey].Value -isnot [bool] -or $Record.PSObject.Properties[$roleKey].Value){throw 'V109_READONLY_ROLE_REQUIRED'}
        }
        if($Record.captureScope -cne 'none'){throw 'V109_READONLY_ROLE_REQUIRED'}
    }
    $diagnosticPrepared=Join-Path $BuildDirectory 'v43-prepared.json'
    $diagnosticItem=Get-Item -LiteralPath $diagnosticPrepared
    if($diagnosticItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or $diagnosticItem.Length -gt 131072 -or
        (Get-AhNativeSha256 $diagnosticPrepared) -cne $Record.genericReadDiagnosticsV109PreparedSha256){throw 'V109_PREPARED_PIN_REJECTED'}
    $diagnosticProof=[IO.File]::ReadAllText($diagnosticPrepared)|ConvertFrom-Json
    if($diagnosticProof.passed -isnot [bool] -or !$diagnosticProof.passed -or
        $diagnosticProof.goldStarted -isnot [bool] -or $diagnosticProof.goldStarted){throw 'V109_PREPARED_ROLE_REJECTED'}
    $diagnosticKeys=@('NativeCommandClient.cs','Invoke-NativeCommand.ps1','tests/NativeCommandSession.as',
        'tests/Invoke-LiveReadProbe.ps1','research/run_gold_startup_v43.py','research/prepare_gold_startup_v43.py')
    if($CommandName -ceq 'COMPACT_OWNER_V108'){
        $diagnosticKeys+=@('tests/NativeCompactOwnerV108.as','research/compact_owner_contract_v108.py','research/compact_owner_guard_v108.py')
    }elseif($CommandName -ceq 'STOCK_SELECTION_INVENTORY_V106'){
        $diagnosticKeys+=@('tests/NativeStockSelectionInventoryV106.as','research/stock_selection_inventory_contract_v106.py','research/stock_selection_inventory_guard_v106.py')
    }elseif($CommandName -ceq 'EMPTY_CLASS_INVENTORY_V125'){
        $diagnosticKeys+=@('tests/NativeOwnedEmptyClassInventoryV125.as','research/owned_empty_class_inventory_contract_v125.py','research/owned_empty_class_inventory_guard_v125.py')
    }else{
        $diagnosticKeys+=@('tests/NativeMetadataReceiversV126.as','research/metadata_receivers_contract_v126.py','research/metadata_receivers_guard_v126.py','research/metadata_receiver_inventory_v126.py')
    }
    foreach($diagnosticKey in $diagnosticKeys){
        $diagnosticSource=Join-Path $SourceRoot $diagnosticKey
        # The preparer pins include explicit POSIX names and Windows Path names.
        # Normalize only separators, require one match, and reject alias duplicates.
        $diagnosticRelative='tools/1c/designer-bridge/'+$diagnosticKey
        $diagnosticPins=@($diagnosticProof.sourceSha256.PSObject.Properties|Where-Object {$_.Name.Replace('\','/') -ceq $diagnosticRelative})
        if($diagnosticPins.Count -ne 1){throw 'V109_DIAGNOSTIC_SOURCE_CHANGED'}
        $diagnosticPin=$diagnosticPins[0]
        if($diagnosticPin.Value -isnot [string] -or
            $diagnosticPin.Value -cnotmatch '^[a-f0-9]{64}$' -or
            (Get-AhNativeSha256 $diagnosticSource) -cne $diagnosticPin.Value){throw 'V109_DIAGNOSTIC_SOURCE_CHANGED'}
    }
}
try {
    if($Command -eq 'GOLD_OWNED_FULL_OBJECT_MODULE_V150'){throw 'V150_DEDICATED_CLIENT_REQUIRED'}
    if($Command -eq 'MANAGED_INPUT_RECORD_V145'){throw 'V145_DEDICATED_CLIENT_REQUIRED'}
    if($Command -eq 'GOLD_OWNED_MANAGED_FORM_V107'){throw 'V107_DEDICATED_CLIENT_REQUIRED'}
    # A failed V69 native load has no verified outcome. This gate precedes
    # connection reads and protects callers using any ValidateSet casing.
    if($Command -eq 'PROCESSING_FORM_V69'){throw 'V69_PROCESSING_FORM_ROUTE_QUARANTINED'}
    if($Command -eq 'OWN_MANAGED_BODY_V73'){throw 'V73_CONFIG_EXPORT_ROUTE_DISABLED'}
    if([IntPtr]::Size -ne 4 -or $OperationId -cnotmatch '^[a-f0-9]{32}$' -or ($DeferCloseAck -and $Command -ne 'CLOSE_SAFE')){throw 'COMMAND_CALLER_REJECTED'}
    $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
    $buildRoot=[IO.Path]::GetFullPath((Join-Path $root 'build'))+[IO.Path]::DirectorySeparatorChar
    $path=[IO.Path]::GetFullPath($ConnectionFile)
    $sessionDir=Split-Path $path -Parent
    $build=Split-Path $sessionDir -Parent
    if(!$path.StartsWith($buildRoot,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $path -Leaf) -ne 'command-connection.json' -or (Split-Path $sessionDir -Leaf) -cnotmatch '^session-[a-f0-9]{32}$'){throw 'COMMAND_CONNECTION_PATH_REJECTED'}
    foreach($itemPath in @($path,$sessionDir,$build)){
        $item=Get-Item -LiteralPath $itemPath
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'COMMAND_CONNECTION_PATH_REJECTED'}
    }
    if((Get-Item -LiteralPath $path).Length -gt 8192){throw 'COMMAND_CONNECTION_REJECTED'}
    $published=[IO.File]::ReadAllText($path) | ConvertFrom-Json
    if($published.sealVersion -ne 1){throw 'COMMAND_CONNECTION_SEAL_REJECTED'}
    Add-Type -AssemblyName System.Security
    try {
        $purpose=[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-COMMAND-V2')
        $payload=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($published.protectedConnection),$purpose,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        $connection=(New-Object Text.UTF8Encoding($false,$true)).GetString($payload) | ConvertFrom-Json
    } catch {throw 'COMMAND_CONNECTION_SEAL_REJECTED'}
    if($connection.PSObject.Properties.Name -contains 'managedInputRecordV145' -and ($connection.managedInputRecordV145 -isnot [bool] -or $connection.managedInputRecordV145)){throw 'V145_DEDICATED_CLIENT_REQUIRED'}
    if($connection.goldOwnedFullObjectModuleV150 -isnot [bool] -or $connection.goldOwnedFullObjectModuleV150){throw 'V109_READONLY_ROLE_REQUIRED'}
    if($connection.goldOwnedDocumentStructureV139 -isnot [bool] -or $connection.goldOwnedDocumentStructureV139){throw 'V109_READONLY_ROLE_REQUIRED'}
    if($connection.version -ne 2 -or $connection.target -ne 'Gold' -or $connection.platform -ne '8.3.18.1208' -or $connection.readOnlyGold -ne $true -or $connection.rootId -ne '218b5d00-7e10-486f-874c-73c2368ed5da' -or $connection.objectId -ne '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d' -or $connection.sessionId -cnotmatch '^[a-f0-9]{32}$' -or $connection.processCreationFileTimeUtc -cnotmatch '^[a-f0-9]{16}$' -or $connection.leaseOwner -cnotmatch '^[a-f0-9]{32}$'){throw 'COMMAND_CONNECTION_REJECTED'}
    if($connection.captureScope -cne 'none' -or $connection.captureWriteAllowed -ne $false){throw 'COMMAND_CONNECTION_REJECTED'}
    if($Command -ceq 'SELECTION_INPUTS_V46' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeSelectionInputsV46.as')) -cne $connection.selectionInputsSourceSha256)){throw 'SELECTION_INPUT_CAPABILITY_REQUIRED'}
    if($Command -ceq 'OBJECT_SNAPSHOT_V47' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeObjectSnapshotV47.as')) -cne $connection.objectSnapshotSourceSha256)){throw 'OBJECT_SNAPSHOT_CAPABILITY_REQUIRED'}
    if($Command -ceq 'DOCUMENT_MODULES_V48' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeDocumentModulesV48.as')) -cne $connection.documentModulesSourceSha256)){throw 'DOCUMENT_MODULES_CAPABILITY_REQUIRED'}
    if($Command -in 'FACTORY_COPY_V49','FACTORY_VERIFY_V49' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeFactoryCopyV49.as')) -cne $connection.factoryCopySourceSha256)){throw 'FACTORY_COPY_CAPABILITY_REQUIRED'}
    if($Command -ceq 'CAPTURE_LISTENERS_V51' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeCaptureListenersV51.as')) -cne $connection.captureListenersSourceSha256)){throw 'CAPTURE_LISTENERS_CAPABILITY_REQUIRED'}
    if($Command -ceq 'CAPTURE_STATE_V52' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeCaptureStateV52.as')) -cne $connection.captureStateSourceSha256)){throw 'CAPTURE_STATE_CAPABILITY_REQUIRED'}
    if($Command -ceq 'STATISTIC_PACKET_V54' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeStatisticPacketV54.as')) -cne $connection.statisticPacketSourceSha256)){throw 'STATISTIC_PACKET_CAPABILITY_REQUIRED'}
    if($Command -in @('COMPACT_OWNER_V108','STOCK_SELECTION_INVENTORY_V106','EMPTY_CLASS_INVENTORY_V125','METADATA_RECEIVER_INVENTORY_V126')){Assert-AhReadDiagnosticSourceV109 $connection $build $Command $PSScriptRoot}
    if($Command -ceq 'DETACHED_TEXT_UNDO_V63' -and ($connection.readOnlyGold -ne $true -or $connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeDetachedTextUndoV63.as')) -cne $connection.detachedTextUndoV63SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeDetachedTextUndoV63.v')) -cne $connection.detachedTextUndoV63BindingsSha256)){throw 'DETACHED_TEXT_UNDO_CAPABILITY_REQUIRED'}
    if($Command -ceq 'FREE_NOTIFICATION_V55' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeFreeNotificationV55.as')) -cne $connection.freeNotificationSourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeMetadataDocumentPermission.as')) -cne $connection.metadataPermissionSourceSha256)){throw 'FREE_NOTIFICATION_CAPABILITY_REQUIRED'}
    if($Command -in 'VALUE_COPY_V67','VALUE_VERIFY_V67' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedValueLifetimeV67.as')) -cne $connection.ownedValueLifetimeV67SourceSha256)){throw 'OWNED_VALUE_CAPABILITY_REQUIRED'}
    if($Command -ceq 'PROCESSING_FORM_V69' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeProcessingFormV69.as')) -cne $connection.processingFormV69SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeProcessingFormV69.v')) -cne $connection.processingFormV69BindingSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedValueLifetimeV67.as')) -cne $connection.ownedValueLifetimeV67SourceSha256)){throw 'PROCESSING_FORM_CAPABILITY_REQUIRED'}
    if($Command -ceq 'VALUE_PERSIST_V68' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedValuePersistenceV68.as')) -cne $connection.ownedValuePersistenceV68SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedValueLifetimeV67.as')) -cne $connection.ownedValueLifetimeV67SourceSha256)){throw 'VALUE_PERSISTENCE_CAPABILITY_REQUIRED'}
    if($Command -eq 'OWN_PERSISTENCE_V71' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedPersistenceV71.as')) -cne $connection.ownedPersistenceV71SourceSha256)){throw 'OWNED_PERSISTENCE_CAPABILITY_REQUIRED'}
    if($Command -eq 'OWN_FORM_TYPE_V72' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeManagedFormTypeV72.as')) -cne $connection.ownedFormTypeV72SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeManagedFormTypeV72.v')) -cne $connection.ownedFormTypeV72BindingSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedValueLifetimeV67.as')) -cne $connection.ownedValueLifetimeV67SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedPersistenceV71.as')) -cne $connection.ownedPersistenceV71SourceSha256)){throw 'OWNED_FORM_TYPE_CAPABILITY_REQUIRED'}
    if($Command -eq 'OWN_FORM_TYPE_V74' -and ($connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeManagedFormTypeV74.as')) -cne $connection.ownedFormTypeV74SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeManagedFormTypeV72.v')) -cne $connection.ownedFormTypeV72BindingSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedValueLifetimeV67.as')) -cne $connection.ownedValueLifetimeV67SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedPersistenceV71.as')) -cne $connection.ownedPersistenceV71SourceSha256)){throw 'OWNED_FORM_TYPE_V74_CAPABILITY_REQUIRED'}
    if($Command -eq 'OWN_MANAGED_BODY_V73' -and ($connection.readOnlyGold -ne $true -or $connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedManagedBodyV73.as')) -cne $connection.ownedManagedBodyV73SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/fixtures/OwnedManagedForm/Module.bsl')) -cne $connection.ownedManagedBodyV73FixtureSha256 -or $connection.ownedManagedBodyV73FixtureSha256 -cne 'b8f4ce623dbccf3c952583208bedc580f913934e6f63f1f45376c0d3daf4d0db' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeManagedFormTypeV72.v')) -cne $connection.ownedFormTypeV72BindingSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedValueLifetimeV67.as')) -cne $connection.ownedValueLifetimeV67SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedPersistenceV71.as')) -cne $connection.ownedPersistenceV71SourceSha256)){throw 'OWNED_MANAGED_BODY_V73_CAPABILITY_REQUIRED'}
    if($Command -eq 'OWN_MANAGED_FORM_V75' -and ($connection.readOnlyGold -ne $true -or $connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedManagedFormV75.as')) -cne $connection.ownedManagedFormV75SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/fixtures/OwnedManagedForm/Module.bsl')) -cne $connection.ownedManagedFormV75FixtureSha256 -or $connection.ownedManagedFormV75FixtureSha256 -cne 'b8f4ce623dbccf3c952583208bedc580f913934e6f63f1f45376c0d3daf4d0db' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeManagedFormTypeV72.v')) -cne $connection.ownedFormTypeV72BindingSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedValueLifetimeV67.as')) -cne $connection.ownedValueLifetimeV67SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedPersistenceV71.as')) -cne $connection.ownedPersistenceV71SourceSha256)){throw 'OWNED_MANAGED_FORM_V75_CAPABILITY_REQUIRED'}
    if($Command -eq 'MANAGED_BODY_FACTORY_V78' -and ($connection.readOnlyGold -ne $true -or $connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeManagedBodyFactoryV78.as')) -cne $connection.managedBodyFactoryV78SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeManagedFormTypeV72.v')) -cne $connection.ownedFormTypeV72BindingSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedValueLifetimeV67.as')) -cne $connection.ownedValueLifetimeV67SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedPersistenceV71.as')) -cne $connection.ownedPersistenceV71SourceSha256)){throw 'MANAGED_BODY_FACTORY_V78_CAPABILITY_REQUIRED'}
    if($Command -eq 'MANAGED_BODY_MODULE_V79' -and ($connection.readOnlyGold -ne $true -or $connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeManagedBodyModuleV79.as')) -cne $connection.managedBodyModuleV79SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeManagedFormTypeV72.v')) -cne $connection.ownedFormTypeV72BindingSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedValueLifetimeV67.as')) -cne $connection.ownedValueLifetimeV67SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedPersistenceV71.as')) -cne $connection.ownedPersistenceV71SourceSha256)){throw 'MANAGED_BODY_MODULE_V79_CAPABILITY_REQUIRED'}
    if($Command -eq 'OWN_CONSTANT_V77' -and ($connection.readOnlyGold -ne $true -or $connection.selectionInputsV46 -ne $true -or $connection.uiControllerCaptureV44 -eq $true -or $connection.captureNotificationV56 -eq $true -or $connection.pilotScope -cne 'none' -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedConstantV77.as')) -cne $connection.ownedConstantV77SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedTypeHelpersV77.as')) -cne $connection.ownedConstantV77TypeHelpersSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedManagedFormV75.as')) -cne $connection.ownedManagedFormV75SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeManagedFormTypeV72.v')) -cne $connection.ownedFormTypeV72BindingSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedValueLifetimeV67.as')) -cne $connection.ownedValueLifetimeV67SourceSha256 -or (Get-AhNativeSha256 (Join-Path $PSScriptRoot 'tests/NativeOwnedPersistenceV71.as')) -cne $connection.ownedPersistenceV71SourceSha256)){throw 'OWN_CONSTANT_V77_CAPABILITY_REQUIRED'}
    if((Get-AhNativeSha256 (Join-Path $PSScriptRoot 'NativeCommandClient.cs')) -cne $connection.clientSourceSha256){throw 'COMMAND_CLIENT_SOURCE_CHANGED'}
    $clientPath=Join-Path $build 'NativeCommandClient.dll'
    if((Get-AhNativeSha256 $clientPath) -cne $connection.clientDllSha256){throw 'COMMAND_CLIENT_IMAGE_CHANGED'}
    $null=[Reflection.Assembly]::LoadFrom($clientPath)
    $client=[NativeCommandClient]::OpenSession($connection.pipeName,[uint32]$connection.processId,$connection.processCreationFileTimeUtc,$connection.sessionId)
    try {$reply=$client.Send($OperationId,$Command)} finally {$client.Dispose()}
    $output=Join-Path $sessionDir ('client-'+$OperationId+'-'+[guid]::NewGuid().ToString('N')+'.txt')
    $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes($reply.Body)
    # Each response has its own file; explicit operation replay never replaces
    # an earlier response (including a rejected command with the same ID).
    $stream=New-Object IO.FileStream($output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try {$stream.Write($bytes,0,$bytes.Length)} finally {$stream.Dispose()}
    if(!$DeferCloseAck -and $reply.Kind -eq 'CLOSE_SAFE' -and $reply.Body -ceq 'SAFE_CLOSE_PROPOSED'){
        $ack=[ordered]@{version=1;operationId=$OperationId;sessionId=$connection.sessionId;
            processId=$connection.processId;processCreationFileTimeUtc=$connection.processCreationFileTimeUtc}
        $ackPayload=[Text.Encoding]::UTF8.GetBytes(($ack | ConvertTo-Json -Compress))
        $ackPurpose=[Text.Encoding]::UTF8.GetBytes('AH1C-NATIVE-CLOSE-ACK-V1')
        $ackProtected=[Security.Cryptography.ProtectedData]::Protect($ackPayload,$ackPurpose,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes((Join-Path $sessionDir 'command-close-ack.protected'),$ackProtected)
        [IO.File]::WriteAllText((Join-Path $sessionDir 'command-close-ack'),$OperationId,(New-Object Text.UTF8Encoding($false)))
    }
    $summary=[ordered]@{status=$(if($reply.Kind -eq 'ERROR'){'NATIVE_COMMAND_REJECTED'}else{'NATIVE_COMMAND_VERIFIED'});
        command=$Command;operationId=$OperationId;replayed=$reply.Replayed;processId=$connection.processId;
        processCreationFileTimeUtc=$connection.processCreationFileTimeUtc;resultFile=$output;bytes=$bytes.Length;
        sha256=(Get-AhNativeSha256 $output)}
    if($reply.Kind -eq 'ERROR' -and $reply.Body -cmatch '^[A-Z][A-Z_0-9]{3,63}$'){$summary.code=$reply.Body}
    $summary | ConvertTo-Json -Compress
    if($reply.Kind -eq 'ERROR'){exit 1}
} catch {
    $leaf=$_.Exception
    while($leaf.InnerException){$leaf=$leaf.InnerException}
    $code=if($leaf.Message -cmatch '^[A-Z][A-Z_0-9]{3,63}$'){$leaf.Message}else{'NATIVE_COMMAND_CALL_FAILED'}
    [ordered]@{status='NATIVE_COMMAND_RESULT_UNKNOWN';code=$code;operationId=$OperationId;errorType=$leaf.GetType().Name} | ConvertTo-Json -Compress
    exit 85
}
