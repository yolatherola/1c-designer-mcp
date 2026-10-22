"""Build only the fixed owned Gold read-only adapter; preparation starts no 1C."""
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
import zipfile

ROOT=Path(__file__).resolve().parents[4]
HERE=Path(__file__).resolve().parent
TESTS=HERE.parent/'tests'
sys.path[:0]=[str(TESTS),str(HERE)]
from prepare_runtime_v40 import checked_cache,CACHE
from run_pipe_read import ARCHIVES,checked_extract
from pending_operation_inspector import contained
from process_identity import owned_process_gone
from stop_original_v40 import durable_new
from run_command_session import source_hashes as command_source_hashes
from source_dependency_closure_v124 import local_python_source_hashes

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def sources():
    files=[HERE/name for name in ('OwnedGoldLoaderV43.cs','NativeGoldBootstrapV43.c','OwnedGoldGuardV43.cs','NativeSdkCall.s')]
    files += [Path(__file__),TESTS/'Invoke-LiveReadProbe.ps1',TESTS/'run_live_probe.py']
    files += [HERE/'run_gold_startup_v43.py',HERE/'Measure-GoldChannelV43.ps1',HERE/'Read-OwnStartupSnapshotV43.ps1']
    files += [TESTS/'NativeControllerCaptureV44.as',HERE.parent/'Invoke-ControllerCaptureV44.ps1',HERE/'run_controller_capture_v44.py']
    files += [HERE/'Measure-PipeDisconnectV45.ps1']
    files += [TESTS/'NativeSelectionInputsV46.as',HERE/'selected_controller_thunk_v46.py',HERE/'run_selected_abi_v46.py',HERE/'NativeSelectionAbiV46.c',HERE/'NativeSelectionAbiV46.s']
    files += [TESTS/'NativeObjectSnapshotV47.as']
    files += [HERE/'metadata_descriptor_codec_v47.py',TESTS/'saved_pilot_codec.py',TESTS/'test_metadata_descriptor_codec_v47.py']
    files += [HERE/'completed_readonly_runtime_v47.py',HERE/'Remove-CompletedReadOnlyRuntimeV47.ps1']
    files += [HERE/'recover_readonly_comparison_v47.py']
    files += [TESTS/'NativeDocumentModulesV48.as',HERE/'document_module_guard_v48.py',TESTS/'test_document_module_guard_v48.py']
    files += [TESTS/'NativeFactoryCopyV49.as',HERE/'factory_copy_guard_v49.py',TESTS/'test_factory_copy_guard_v49.py',HERE/'factory_thunk_v49.py',HERE/'selection_transform_contract_v49.py',HERE/'run_factory_abi_v49.py',HERE/'NativeFactoryAbiV49.c',HERE/'NativeFactoryAbiV49.s']
    files += [TESTS/'NativeCaptureListenersV51.as',TESTS/'NativeCaptureListenersV51.v',HERE/'capture_listeners_guard_v51.py',TESTS/'test_capture_listeners_guard_v51.py',HERE/'result_processing_contract_v51.py']
    files += [TESTS/'NativeCaptureStateV52.as',HERE/'capture_state_guard_v52.py',TESTS/'test_capture_state_guard_v52.py']
    files += [TESTS/'NativeStatisticPacketV54.as',HERE/'statistic_packet_guard_v54.py',TESTS/'test_statistic_packet_guard_v54.py',HERE/'statistic_packet_contract_v54.py']
    files += [TESTS/'NativeFreeNotificationV55.as',TESTS/'NativeMetadataDocumentPermission.as',HERE/'free_notification_guard_v55.py',TESTS/'test_free_notification_guard_v55.py']
    files += [TESTS/'NativePolicyCacheV58.as',HERE/'policy_cache_guard_v58.py',TESTS/'test_policy_cache_guard_v58.py',HERE/'policy_cache_contract_v58.py']
    files += [TESTS/'NativePolicyModeV59.as',HERE/'policy_mode_guard_v59.py',TESTS/'test_policy_mode_guard_v59.py',HERE/'policy_mode_contract_v59.py']
    files += [TESTS/'NativeLocalBookkeepingV60.as',HERE/'local_bookkeeping_guard_v60.py',TESTS/'test_local_bookkeeping_guard_v60.py',HERE/'local_bookkeeping_contract_v60.py',HERE/'audit_local_bookkeeping_v60.py']
    files += [TESTS/'NativeBufferApplyV61.as',HERE/'buffer_apply_guard_v61.py',TESTS/'test_buffer_apply_guard_v61.py',HERE/'buffer_apply_contract_v61.py',HERE/'audit_buffer_apply_v61.py']
    files += [TESTS/'test_buffer_apply_quarantine_v62.py',HERE/'text_undo_contract_v62.py',HERE/'NativeTextUndoV62.c',HERE/'run_text_undo_v62.py',HERE/'Remove-TextUndoRuntimeV62.ps1',HERE/'audit_text_undo_v62.py']
    files += [TESTS/'NativeDetachedTextUndoV63.as',TESTS/'NativeDetachedTextUndoV63.v',HERE/'detached_text_undo_guard_v63.py',TESTS/'test_detached_text_undo_guard_v63.py']
    files += [TESTS/'NativeBufferUndoV64.as',HERE/'buffer_undo_guard_v64.py',TESTS/'test_buffer_undo_guard_v64.py']
    files += [TESTS/'NativeWholeModuleV65.as',TESTS/'NativeWholeModuleV65.v',HERE/'whole_module_guard_v65.py',TESTS/'test_whole_module_guard_v65.py']
    files += [TESTS/'AtomicCommandPublicationV66.ps1',TESTS/'Test-AtomicCommandPublicationV66.ps1']
    files += [TESTS/'NativeOwnedValueLifetimeV67.as',HERE/'owned_value_lifetime_guard_v67.py',TESTS/'test_owned_value_lifetime_guard_v67.py']
    files += [HERE/'owned_value_contract_v67.py',TESTS/'test_owned_value_contract_v67.py']
    files += [TESTS/'NativeOwnedValuePersistenceV68.as',HERE/'owned_value_persistence_guard_v68.py',TESTS/'test_owned_value_persistence_guard_v68.py']
    files += [HERE/'owned_value_persistence_contract_v68.py',TESTS/'test_owned_value_persistence_contract_v68.py']
    files += [TESTS/'NativeProcessingFormV69.as',TESTS/'NativeProcessingFormV69.v',HERE/'processing_form_guard_v69.py',TESTS/'test_processing_form_guard_v69.py',HERE/'processing_form_contract_v69.py',TESTS/'test_processing_form_contract_v69.py']
    files += [TESTS/'test_processing_form_quarantine_v70.py']
    files += [TESTS/'NativeOwnedPersistenceV71.as',HERE/'owned_persistence_contract_v71.py',TESTS/'test_owned_persistence_contract_v71.py',HERE/'owned_persistence_guard_v71.py',TESTS/'test_owned_persistence_guard_v71.py']
    files += [HERE/'recover_owned_persistence_v71.py',TESTS/'test_owned_persistence_routing_v71.py']
    files += [TESTS/'NativeManagedFormTypeV72.as',TESTS/'NativeManagedFormTypeV72.v',HERE/'managed_form_type_contract_v72.py',TESTS/'test_managed_form_type_contract_v72.py',HERE/'managed_form_type_guard_v72.py',TESTS/'test_managed_form_type_guard_v72.py',TESTS/'test_managed_form_type_routing_v72.py']
    files += [TESTS/'NativeManagedFormTypeV74.as',HERE/'managed_form_type_contract_v74.py',TESTS/'test_managed_form_type_contract_v74.py',HERE/'managed_form_type_guard_v74.py',TESTS/'test_managed_form_type_guard_v74.py',TESTS/'test_managed_form_type_routing_v74.py']
    files += [TESTS/'NativeOwnedManagedBodyV73.as',HERE/'owned_managed_body_contract_v73.py',TESTS/'test_owned_managed_body_contract_v73.py',HERE/'owned_managed_body_guard_v73.py',TESTS/'test_owned_managed_body_guard_v73.py',HERE/'owned_managed_cf_guard_v73.py',TESTS/'test_owned_managed_cf_guard_v73.py',TESTS/'test_owned_managed_body_routing_v73.py',TESTS/'fixtures/OwnedManagedForm/Module.bsl']
    files += [TESTS/'NativeOwnedManagedFormV75.as',HERE/'owned_managed_form_guard_v75.py',TESTS/'test_owned_managed_form_guard_v75.py',TESTS/'test_managed_form_no_config_export_v75.py',TESTS/'test_owned_managed_form_routing_v75.py']
    files += [TESTS/'NativeManagedBodyFactoryV78.as',HERE/'managed_body_factory_guard_v78.py',TESTS/'test_managed_body_factory_guard_v78.py',TESTS/'test_managed_body_factory_routing_v78.py']
    files += [TESTS/'NativeManagedBodyModuleV79.as',HERE/'managed_body_module_guard_v79.py',TESTS/'test_managed_body_module_guard_v79.py',TESTS/'test_managed_body_module_routing_v79.py']
    files += [TESTS/'NativeOwnedConstantV77.as',TESTS/'NativeOwnedTypeHelpersV77.as',HERE/'owned_constant_contract_v77.py',HERE/'owned_constant_guard_v77.py',TESTS/'test_owned_constant_contract_v77.py',TESTS/'test_owned_constant_guard_v77.py',TESTS/'test_owned_constant_routing_v77.py']
    files += [HERE/'capture_ownership_guard.py',TESTS/'test_capture_ownership_guard.py']
    files += [TESTS/'NativeGoldOwnObjectModuleV78.as',HERE/'gold_own_object_module_contract_v78.py',
        HERE/'gold_own_object_module_guard_v78.py',TESTS/'test_gold_own_object_module_contract_v78.py',
        TESTS/'test_gold_own_object_module_guard_v78.py',TESTS/'test_gold_own_object_module_routing_v78.py',
        HERE.parent/'Invoke-GoldOwnObjectModuleV78.ps1',HERE/'completed_gold_own_module_v78.py',
        HERE/'Remove-CompletedGoldOwnModuleV78.ps1']
    files += [TESTS/'NativeGoldOwnObjectModuleV82.as',HERE/'gold_own_object_module_contract_v82.py',
        HERE/'gold_own_object_module_guard_v82.py',TESTS/'test_gold_own_object_module_contract_v82.py',
        TESTS/'test_gold_own_object_module_guard_v82.py',TESTS/'test_gold_own_object_module_routing_v82.py',
        HERE.parent/'Invoke-GoldOwnObjectModuleV82.ps1',HERE/'completed_gold_own_module_v82.py',
        HERE/'Remove-CompletedGoldOwnModuleV82.ps1']
    files += [HERE/'processing_object_module_helper_contract_v94.py',
        TESTS/'test_processing_object_module_helper_contract_v94.py']
    files += [HERE/'processing_object_module_editor_contract_v98.py',
        TESTS/'test_processing_object_module_editor_contract_v98.py']
    files += [HERE/'native_compile_preflight_v83.py',TESTS/'test_native_compile_preflight_v83.py']
    files += [TESTS/'test_native_sdk_alias_preparation_v85.py']
    files += [TESTS/'NativeCaptureFreshV81.as',HERE/'capture_fresh_contract_v81.py',HERE/'capture_fresh_guard_v81.py',
        TESTS/'test_capture_fresh_contract_v81.py',TESTS/'test_capture_fresh_guard_v81.py',
        HERE.parent/'Invoke-CaptureFreshV81.ps1',TESTS/'test_capture_fresh_client_v81.py',
        HERE/'run_capture_fresh_client_v81.py',TESTS/'test_capture_fresh_routing_v81.py',
        HERE/'completed_capture_fresh_v81.py',HERE/'Remove-CompletedCaptureFreshV81.ps1',TESTS/'test_completed_capture_fresh_v81.py']
    files += [TESTS/'NativeObjectNotificationV57.as',HERE/'object_notification_contract_v57.py',HERE/'object_notification_guard_v57.py',TESTS/'test_object_notification_guard_v57.py']
    files += [TESTS/'NativeCaptureNotificationV56.as',HERE.parent/'Invoke-CaptureNotificationV56.ps1',HERE/'run_capture_notification_v56.py',HERE/'capture_notification_guard_v56.py',TESTS/'test_capture_notification_guard_v56.py',HERE/'completed_capture_runtime_v56.py',HERE/'Remove-CompletedCaptureRuntimeV56.ps1']
    files += [TESTS/'test_startup_source_manifest_v113.py',TESTS/'test_readonly_cleanup_receipt_v117.py']
    files += [TESTS/'NativeGoldOwnedConstantV99.as',HERE/'gold_owned_constant_contract_v99.py',
        HERE/'gold_owned_constant_guard_v99.py',TESTS/'test_gold_owned_constant_v99.py',
        TESTS/'NativeGoldOwnedConstantSessionV102.as',HERE/'gold_owned_constant_session_contract_v102.py',
        TESTS/'test_gold_owned_constant_session_v102.py',HERE.parent/'Invoke-GoldOwnedConstantV99.ps1',
        TESTS/'test_gold_owned_constant_client_v99.py',TESTS/'test_gold_owned_constant_routing_v99.py',
        HERE/'completed_original_wait_v103.py',TESTS/'test_completed_original_wait_v103.py',
        TESTS/'TestNativeCommandResultBudgetV101.cs',HERE/'Test-NativeCommandResultBudgetV101.ps1',
        HERE/'completed_gold_owned_constant_v99.py',HERE/'Remove-CompletedGoldOwnedConstantV99.ps1',
        TESTS/'test_completed_gold_owned_constant_v99.py']
    files += [TESTS/'NativeCompactOwnerV108.as',HERE/'compact_owner_contract_v108.py',
        HERE/'compact_owner_guard_v108.py',TESTS/'test_compact_owner_v108.py',
        TESTS/'NativeStockSelectionInventoryV106.as',HERE/'stock_selection_inventory_contract_v106.py',
        HERE/'stock_selection_inventory_guard_v106.py',TESTS/'test_stock_selection_inventory_v106.py',
        TESTS/'test_readonly_diagnostics_routing_v109.py']
    files += [TESTS/'NativeOwnedEmptyClassInventoryV125.as',HERE/'owned_empty_class_inventory_contract_v125.py',
        HERE/'owned_empty_class_inventory_guard_v125.py',TESTS/'test_owned_empty_class_inventory_v125.py']
    files += [TESTS/'NativeManagedInputRecordV145.as',HERE/'managed_input_record_contract_v145.py',HERE/'managed_input_record_guard_v145.py',TESTS/'test_managed_input_record_v145.py',
        HERE/'managed_input_record_primary_v141.py',TESTS/'test_managed_input_record_primary_v141.py',HERE/'managed_input_outer_kind_abi_v144.py',TESTS/'test_managed_input_outer_kind_abi_v144.py',
        TESTS/'NativeManagedInputRecordSessionV145.as',HERE/'managed_input_record_controller_v145.py',HERE.parent/'Invoke-ManagedInputRecordV145.ps1',
        TESTS/'test_managed_input_record_controller_v145.py',TESTS/'test_managed_input_record_routing_v145.py',TESTS/'test_managed_input_record_client_v145.py']
    files += [TESTS/'NativeGoldOwnedFullObjectModuleV150.as',HERE/'gold_owned_full_object_module_contract_v150.py',HERE/'gold_owned_full_object_module_guard_v150.py',TESTS/'test_gold_owned_full_object_module_v150.py']
    files += [TESTS/'NativeGoldOwnedFullObjectModuleSessionV150.as',HERE.parent/'Invoke-GoldOwnedFullObjectModuleV150.ps1',HERE/'gold_owned_full_object_module_controller_v150.py',HERE/'completed_gold_owned_full_object_module_v150.py',HERE/'Remove-CompletedGoldOwnedFullObjectModuleV150.ps1']
    files += [TESTS/'test_gold_owned_full_object_module_routing_v150.py',TESTS/'test_gold_owned_full_object_module_controller_v150.py',TESTS/'test_completed_gold_owned_full_object_module_v150.py',TESTS/'test_gold_owned_full_object_module_client_v150.py']
    files += [TESTS/'NativeOwnedModulePayloadV142.as',HERE/'owned_module_payload_contract_v142.py',ROOT/'tools/data-anonymization/managed/ObjectModule.bsl']
    files += [TESTS/'NativeGoldOwnedDocumentStructureV139.as',HERE/'gold_owned_document_structure_contract_v139.py',HERE/'gold_owned_document_structure_guard_v139.py',TESTS/'test_gold_owned_document_structure_v139.py']
    files += [TESTS/'NativeGoldOwnedDocumentStructureSessionV139.as',HERE.parent/'Invoke-GoldOwnedDocumentStructureV139.ps1',HERE/'gold_owned_document_structure_controller_v139.py',HERE/'completed_gold_owned_document_structure_v139.py',HERE/'Remove-CompletedGoldOwnedDocumentStructureV139.ps1']
    files += [TESTS/'test_gold_owned_document_structure_routing_v139.py',TESTS/'test_gold_owned_document_structure_controller_v139.py',TESTS/'test_completed_gold_owned_document_structure_v139.py',TESTS/'test_gold_owned_document_structure_client_v139.py']
    files += [TESTS/'NativeGoldOwnedEmptyObjectsV130.as',HERE/'gold_owned_empty_objects_contract_v130.py',HERE/'gold_owned_empty_objects_guard_v130.py',TESTS/'test_gold_owned_empty_objects_v130.py']
    files += [TESTS/'NativeGoldOwnedEmptyObjectsSessionV130.as',HERE.parent/'Invoke-GoldOwnedEmptyObjectsV130.ps1',HERE/'gold_owned_empty_objects_controller_v130.py',HERE/'completed_gold_owned_empty_objects_v130.py',HERE/'Remove-CompletedGoldOwnedEmptyObjectsV130.ps1']
    files += [TESTS/'test_gold_owned_empty_objects_routing_v130.py',TESTS/'test_gold_owned_empty_objects_controller_v130.py',TESTS/'test_completed_gold_owned_empty_objects_v130.py',TESTS/'test_gold_owned_empty_objects_client_v130.py']
    files += [TESTS/'NativeMetadataReceiversV126.as',HERE/'metadata_receivers_contract_v126.py',
        HERE/'metadata_receivers_guard_v126.py',TESTS/'test_metadata_receivers_v126.py']
    files += [TESTS/'NativeGoldOwnedManagedFormV107.as',HERE/'gold_owned_managed_form_contract_v107.py',
        HERE/'gold_owned_managed_form_guard_v107.py',TESTS/'test_gold_owned_managed_form_contract_v107.py',
        TESTS/'test_gold_owned_managed_form_guard_v107.py',TESTS/'NativeGoldOwnedManagedFormSessionV115.as',
        HERE/'gold_owned_managed_form_session_contract_v115.py',TESTS/'test_gold_owned_managed_form_session_v115.py',
        HERE.parent/'Invoke-GoldOwnedManagedFormV107.ps1',TESTS/'test_gold_owned_managed_form_client_v107.py',
        TESTS/'test_gold_owned_managed_form_routing_v115.py',HERE/'gold_owned_managed_form_controller_v116.py',
        TESTS/'test_gold_owned_managed_form_controller_v116.py']
    files += [HERE/'completed_gold_owned_managed_form_v107.py',HERE/'Remove-CompletedGoldOwnedManagedFormV107.ps1',
        TESTS/'test_completed_gold_owned_managed_form_v107.py']
    files += [HERE/'source_dependency_closure_v124.py',TESTS/'test_source_dependency_closure_v124.py']
    # One canonical key per source on Windows and other hosts; duplicate aliases
    # from command_source_hashes are merged using their identical POSIX names.
    pins=command_source_hashes()|{p.relative_to(ROOT).as_posix():sha(p) for p in files}
    # Discover imports as source text; running them here could execute a probe.
    # Rechecking existing hashes also rejects edits made during discovery.
    closure=local_python_source_hashes(
        [ROOT/name for name in pins if name.endswith('.py')],
        (HERE,TESTS,HERE.parent,HERE.parent.parent/'designer-agent'))
    for path,digest in closure.items():
        key=path.relative_to(ROOT).as_posix()
        if key in pins and pins[key]!=digest:
            raise ValueError('V43_SOURCE_CHANGED_DURING_CLOSURE')
        pins[key]=digest
    return pins

def verify_prepared(build):
    build=contained(build,ROOT/'build')
    if build.parent!=ROOT/'build' or re.fullmatch(r'designer-v43-[a-f0-9]{32}',build.name) is None:
        raise ValueError('V43_BUILD_SCOPE_REJECTED')
    proof=json.loads(contained(build/'v43-prepared.json',build).read_text(encoding='utf-8'))
    if (proof.get('passed') is not True or proof.get('goldStarted') is not False
        or proof.get('sourceSha256')!=sources()
        or proof.get('localGuard',{}).get('nativeCodes')!=[89,88,90,91,93]
        or proof.get('localGuard',{}).get('invalidStartsRejected')!=2
        or not all(owned_process_gone(p['pid'],p['birth']) for p in proof.get('processes',[]))):
        raise ValueError('V43_PREPARED_PROOF_REJECTED')
    for name,wanted in proof['assetSha256'].items():
        if sha(contained(build/name,build))!=wanted:raise ValueError('V43_ASSET_CHANGED')
    checked_cache()
    return proof

def main():
    checked_cache()
    from owned_value_contract_v67 import verify_static as verify_owned_value_static
    owned_value_static=verify_owned_value_static()
    from owned_value_persistence_contract_v68 import verify_static as verify_owned_value_persistence_static
    owned_value_persistence_static=verify_owned_value_persistence_static()
    from processing_form_contract_v69 import verify_static as verify_processing_form_static
    processing_form_static=verify_processing_form_static()
    from owned_persistence_contract_v71 import verify_static as verify_owned_persistence_static
    owned_persistence_static=verify_owned_persistence_static()
    from managed_form_type_contract_v72 import verify_static as verify_managed_form_type_static
    managed_form_type_static=verify_managed_form_type_static()
    from managed_form_type_contract_v74 import verify_static as verify_managed_form_type_static_v74
    managed_form_type_static_v74=verify_managed_form_type_static_v74()
    from owned_managed_body_contract_v73 import verify_static as verify_owned_managed_body_static_v73
    owned_managed_body_static_v73=verify_owned_managed_body_static_v73()
    from owned_constant_contract_v77 import verify_static as verify_owned_constant_static_v77
    owned_constant_static_v77=verify_owned_constant_static_v77()
    audit=json.loads((ROOT/'artifacts/designer-bridge/v42-final-local-audit-20261011.json').read_text(encoding='utf-8-sig'))
    if audit.get('passed') is not True:raise ValueError('V42_ACTUAL_EARLY_AUDIT_REQUIRED')
    # Keep the proven fixture implementation immutable; its current pins are checked.
    for name,wanted in audit['sourceSha256'].items():
        if sha(ROOT/name)!=wanted:raise ValueError('V42_SOURCE_CHANGED')
    pins=sources();nonce=uuid.uuid4().hex
    out=contained(ROOT/'build'/('designer-v43-'+nonce),ROOT/'build');out.mkdir()
    durable_new(out/'runtime-owner.json',dict(task='DESIGNER-DIRECT-API/V43',nonce=nonce,sourceSha256=pins))
    for name,_,wanted in ARCHIVES:
        shutil.copyfile(CACHE/name,out/name);checked_extract(out/name,out/'runtime')
        assert sha(out/name).upper()==wanted
    compiler=out/'compiler'
    archive=ROOT/'artifacts/designer-bridge/runtime-cache/tinycc-x86-v1/tcc-0.9.27-win32-bin.zip'
    assert sha(archive)=='02e2bfe8c272a549b15e4bfa4507bd7e05304692af1761db6c1e8e88af675651'
    with zipfile.ZipFile(archive) as package:
        for item in package.infolist():
            assert not Path(item.filename).is_absolute() and '..' not in Path(item.filename).parts and ':' not in item.filename and '\\' not in item.filename
            assert (item.external_attr>>16)&0o170000!=0o120000
        assert sum(i.file_size for i in package.infolist())<30*1024**2
        package.extractall(compiler)
    tcc=compiler/'tcc/tcc.exe'
    assert sha(tcc)=='11b86934bb2833f57fa0453a605ca342aee9207e193faea9b973baa2b2b4c35b'
    definitions=dict(AH_CORE_PATH=out/'runtime/lib/x86/core_as.dll',AH_MODULE_PATH=out/'runtime/modules/Snegopat',
        AH_PROOF_PATH=out/'early-callback.json',AH_LAYOUT_PATH=out/'sdk-layout.json',AH_NONCE=nonce)
    assert all(str(v).isascii() and len(str(v))<240 for v in definitions.values())
    (out/'gold_bindings.h').write_text(''.join('#define '+k+' '+json.dumps(str(v))+'\n' for k,v in definitions.items()),encoding='ascii')
    processes=[]
    def run(args):
        p=subprocess.Popen([str(a) for a in args],cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        kernel=c.WinDLL('kernel32',use_last_error=True)
        kernel.GetProcessTimes.argtypes=[c.c_void_p]+[c.POINTER(c.c_uint64)]*4
        times=[c.c_uint64() for _ in range(4)]
        if not kernel.GetProcessTimes(int(p._handle),*(c.byref(v) for v in times)):raise ValueError('V43_PARENT_IDENTITY_UNKNOWN')
        identity=dict(pid=p.pid,birth=f'{times[0].value:016x}')
        durable_new(out/f'started-{len(processes)}.json',identity)
        stdout,stderr=p.communicate(timeout=30)
        identity['exitCode']=p.returncode;processes.append(identity)
        durable_new(out/f'process-{len(processes)}.json',identity)
        if p.returncode:
            # Compiler-only output; credentials were never loaded at preparation.
            print((stdout+stderr)[:1200].decode('utf-8',errors='replace'))
            raise ValueError('V43_LOCAL_BUILD_FAILED')
        return stdout
    csc=Path(os.environ['WINDIR'])/'Microsoft.NET/Framework/v4.0.30319/csc.exe'
    run([tcc,'-shared','-I'+str(out),HERE/'NativeGoldBootstrapV43.c',HERE/'NativeSdkCall.s','-luser32','-o',out/'GoldBootstrap.dll'])
    run([csc,'/nologo','/platform:x86','/target:library','/out:'+str(out/'OwnedGoldLoaderV43.dll'),HERE/'OwnedGoldLoaderV43.cs'])
    run([csc,'/nologo','/platform:x86','/r:'+str(out/'OwnedGoldLoaderV43.dll'),'/out:'+str(out/'OwnedGoldGuard.exe'),HERE/'OwnedGoldGuardV43.cs'])
    guard=json.loads(run([out/'OwnedGoldGuard.exe']))
    assert guard['passed'] and all(owned_process_gone(p['pid'],p['birth']) for p in processes)
    assets=[out/'GoldBootstrap.dll',out/'OwnedGoldLoaderV43.dll',out/'gold_bindings.h',out/'core.zip',out/'snegopat.zip']
    assets += list((out/'runtime').rglob('*.dll'))+list((out/'runtime').rglob('*.exe'))
    proof=dict(stage='V43OwnedReadOnlyStartupPrepared',nonce=nonce,passed=True,goldStarted=False,localGuard=guard,
        ownedValueStaticContractV67=owned_value_static,
        ownedValuePersistenceStaticContractV68=owned_value_persistence_static,
        processingFormStaticContractV69=processing_form_static,
        ownedPersistenceStaticContractV71=owned_persistence_static,
        managedFormTypeStaticContractV72=managed_form_type_static,
        managedFormTypeStaticContractV74=managed_form_type_static_v74,
        ownedManagedBodyStaticContractV73=owned_managed_body_static_v73,
        sourceSha256=pins,assetSha256={str(p.relative_to(out)):sha(p) for p in assets},processes=processes)
    assert pins==sources()
    durable_new(out/'v43-prepared.json',proof);verify_prepared(out)
    durable_new(ROOT/'artifacts/designer-bridge'/('v43-prepared-'+nonce+'.json'),proof)
    print(json.dumps(dict(passed=True,runtimeDirectory=str(out),nonce=nonce,localGuard=guard,goldStarted=False)))
    return 0

if __name__=='__main__':raise SystemExit(main())
