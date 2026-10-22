"""One owned Gold read-only startup/read/verified-close trial, no business calls."""
import argparse
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[4]
HERE=Path(__file__).resolve().parent
TESTS=HERE.parent/'tests'
sys.path[:0]=[str(TESTS),str(HERE)]
from prepare_gold_startup_v43 import verify_prepared,sha
from repository_pe_probe import PLATFORM,HASHES
from process_identity import owned_process_gone
from run_repository_observe import lease_exists
from pending_operation_inspector import contained
from stop_original_v40 import durable_new
from completed_original_wait_v103 import wait_for_original_completion

def need(ok,code):
    if not ok:raise ValueError(code)
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def read_owned_form_marker_v72(session,name):
    from managed_form_type_guard_v72 import PHASES,MARKER_LIMIT,marker_filename
    need(type(name) is str and name in {marker_filename(phase) for phase in PHASES},'V72_MARKER_NAME_REJECTED')
    path=contained(session/name,session)
    need(path.parent==session and 0<path.stat().st_size<=MARKER_LIMIT,'V72_MARKER_SIZE_REJECTED')
    with path.open('rb') as stream:body=stream.read(MARKER_LIMIT+1)
    need(0<len(body)<=MARKER_LIMIT,'V72_MARKER_SIZE_REJECTED')
    return body
def read_owned_form_marker_v74(session,name):
    from managed_form_type_guard_v74 import PHASES,MARKER_LIMIT,REGISTRY_FILENAME,REGISTRY_LIMIT,marker_filename
    names={marker_filename(phase) for phase in PHASES}
    need(type(name) is str and (name in names or name==REGISTRY_FILENAME),'V74_MARKER_NAME_REJECTED')
    limit=REGISTRY_LIMIT if name==REGISTRY_FILENAME else MARKER_LIMIT
    path=contained(session/name,session)
    need(path.parent==session and 0<path.stat().st_size<=limit,'V74_MARKER_SIZE_REJECTED')
    with path.open('rb') as stream:body=stream.read(limit+1)
    need(0<len(body)<=limit,'V74_MARKER_SIZE_REJECTED')
    return body
def compare_prior_modules_v74(current,previous):
    """Compare complete readonly module profiles; elapsed timings may differ."""
    need(type(current) is dict and type(previous) is dict,'V74_PRIOR_MODULE_PROFILE_REJECTED')
    for profile in (current,previous):
        need(profile.get('verified') is True and profile.get('documentModuleTextsComplete') is True
            and profile.get('allPropertiesEnumerated') is True,'V74_PRIOR_MODULE_PROFILE_REJECTED')
        need(all(type(profile.get(key)) is int and profile[key]==0 for key in ('sourceWrites','repositoryWrites','goldSaves')),
            'V74_PRIOR_MODULE_PROFILE_REJECTED')
        need(type(profile.get('version')) is int and type(profile.get('modules')) is list and len(profile['modules'])==2,
            'V74_PRIOR_MODULE_PROFILE_REJECTED')
    need(current['version']==previous['version'],'V74_PRIOR_MODULE_VERSION_CHANGED')
    keys=('propertyId','resource','contextCount','liveModesEqual','packetSha256','containerBytes','textBytes',
        'sourceCharacters','liveCharacters','infoSha256','sourceNormalizedSha256','liveNormalizedSha256',
        'rawTextEqual','normalizedLineEndingsEqual','normalization')
    for left,right in zip(current['modules'],previous['modules']):
        need(type(left) is dict and type(right) is dict and all(key in left and key in right for key in keys),
            'V74_PRIOR_MODULE_PROFILE_REJECTED')
        need(all(type(left[key]) is type(right[key]) and left[key]==right[key] for key in keys),'V74_PRIOR_MODULE_CHANGED')
    return dict(verified=True,version=current['version'],completeDocumentModulesCompared=2,
        comparison='full-native-and-repository-module-profile-excluding-elapsed-timings',goldWrites=0)

def _read_owned_file_v73(session,name,names,limit,kind):
    """Read one fixed witness, bounded before and after open, without reparses."""
    need(type(name) is str and name in names,'V73_'+kind+'_NAME_REJECTED')
    try:
        path=contained(session/name,session)
        need(path.parent==session,'V73_'+kind+'_FILE_REJECTED')
        need(0<path.stat().st_size<=limit,'V73_'+kind+'_SIZE_REJECTED')
        with path.open('rb') as stream:body=stream.read(limit+1)
    except (OSError,ValueError) as error:
        if isinstance(error,ValueError) and str(error) in ('V73_'+kind+'_SIZE_REJECTED','V73_'+kind+'_FILE_REJECTED'):raise
        raise ValueError('V73_'+kind+'_FILE_REJECTED') from None
    need(0<len(body)<=limit,'V73_'+kind+'_SIZE_REJECTED')
    return body

def read_owned_form_marker_v73(session,name):
    from owned_managed_body_guard_v73 import PHASES,MARKER_LIMIT,REGISTRY_FILENAME,REGISTRY_LIMIT,marker_filename
    names={marker_filename(phase) for phase in PHASES}|{REGISTRY_FILENAME}
    return _read_owned_file_v73(session,name,names,REGISTRY_LIMIT if name==REGISTRY_FILENAME else MARKER_LIMIT,'MARKER')

def read_owned_form_binary_v73(session,name):
    from owned_managed_body_guard_v73 import BINARY_FILENAMES,BINARY_LIMIT
    return _read_owned_file_v73(session,name,BINARY_FILENAMES,BINARY_LIMIT,'BINARY')

def _read_owned_file_v75(session,name,names,limit,kind,prefix='V75'):
    """Read a fixed V75 own-body witness; no configuration-file reader."""
    need(type(name) is str and name in names,prefix+'_'+kind+'_NAME_REJECTED')
    try:
        path=contained(session/name,session)
        need(path.parent==session,prefix+'_'+kind+'_FILE_REJECTED')
        need(0<path.stat().st_size<=limit,prefix+'_'+kind+'_SIZE_REJECTED')
        with path.open('rb') as stream:body=stream.read(limit+1)
    except (OSError,ValueError) as error:
        if isinstance(error,ValueError) and str(error) in (prefix+'_'+kind+'_SIZE_REJECTED',prefix+'_'+kind+'_FILE_REJECTED'):raise
        raise ValueError(prefix+'_'+kind+'_FILE_REJECTED') from None
    need(0<len(body)<=limit,prefix+'_'+kind+'_SIZE_REJECTED')
    return body

def read_owned_form_marker_v75(session,name):
    from owned_managed_form_guard_v75 import PHASES,MARKER_LIMIT,REGISTRY_FILENAME,REGISTRY_LIMIT,marker_filename
    names={marker_filename(phase) for phase in PHASES}|{REGISTRY_FILENAME}
    return _read_owned_file_v75(session,name,names,REGISTRY_LIMIT if name==REGISTRY_FILENAME else MARKER_LIMIT,'MARKER')

def read_owned_form_binary_v75(session,name):
    from owned_managed_form_guard_v75 import BODY_FILENAME,BINARY_LIMIT
    return _read_owned_file_v75(session,name,{BODY_FILENAME},BINARY_LIMIT,'BINARY')

def read_owned_constant_marker_v77(session,name):
    from owned_constant_guard_v77 import PHASES,MARKER_LIMIT,REGISTRY_FILENAME,REGISTRY_LIMIT,marker_filename
    names={marker_filename(phase) for phase in PHASES}|{REGISTRY_FILENAME}
    return _read_owned_file_v75(session,name,names,REGISTRY_LIMIT if name==REGISTRY_FILENAME else MARKER_LIMIT,'MARKER','V77')

def read_gold_own_module_marker_v78(session,name):
    """Read fixed own-module witnesses; configuration files are never allowed."""
    from gold_own_object_module_guard_v78 import PHASES,MARKER_LIMIT,REGISTRY_FILENAME,REGISTRY_LIMIT,RESULT_FILENAME,RESULT_LIMIT,marker_filename
    names={marker_filename(phase) for phase in PHASES}|{REGISTRY_FILENAME,RESULT_FILENAME}
    limit=RESULT_LIMIT if name==RESULT_FILENAME else REGISTRY_LIMIT if name==REGISTRY_FILENAME else MARKER_LIMIT
    return _read_owned_file_v75(session,name,names,limit,'MARKER','GOM78')

def read_gold_own_module_marker_v82(session,name):
    """Read only fixed own-module V82 witnesses, with per-kind bounds."""
    from gold_own_object_module_guard_v82 import PHASES,MARKER_LIMIT,REGISTRY_FILENAME,REGISTRY_LIMIT,RESULT_FILENAME,RESULT_LIMIT,marker_filename
    names={marker_filename(phase) for phase in PHASES}|{REGISTRY_FILENAME,RESULT_FILENAME}
    limit=RESULT_LIMIT if name==RESULT_FILENAME else REGISTRY_LIMIT if name==REGISTRY_FILENAME else MARKER_LIMIT
    return _read_owned_file_v75(session,name,names,limit,'MARKER','GOM82')

def read_gold_owned_constant_marker_v99(session,name):
    """Read fixed, bounded Constant receipts; never a configuration payload."""
    from gold_owned_constant_guard_v99 import PHASES,MARKER_LIMIT,REGISTRY_FILENAME,REGISTRY_LIMIT,RESULT_FILENAME,RESULT_LIMIT,marker_filename
    names={marker_filename(phase) for phase in PHASES}|{REGISTRY_FILENAME,RESULT_FILENAME}
    limit=RESULT_LIMIT if name==RESULT_FILENAME else REGISTRY_LIMIT if name==REGISTRY_FILENAME else MARKER_LIMIT
    return _read_owned_file_v75(session,name,names,limit,'MARKER','GC99')

def owned_form_terminal_v75(marker_bodies):
    """Require physical source/scope receipts even after capability refusal."""
    from owned_managed_form_guard_v75 import _marker
    phases=('beforeScopeExit','afterScopeExit','beforeFinalSourceControl','afterFinalSourceControl')
    for phase in phases:_marker(lambda name:marker_bodies[name],phase)
    return dict(verified=True,physicalTerminalReceipts=4,capabilitySuccessGranted=False)

def read_managed_body_factory_marker_v78(session,name):
    from managed_body_factory_guard_v78 import PHASES,MARKER_LIMIT,marker_filename
    return _read_owned_file_v75(session,name,{marker_filename(phase) for phase in PHASES},MARKER_LIMIT,'MARKER','V78')


def read_managed_body_module_marker_v79(session,name):
    from managed_body_module_guard_v79 import PHASES,MARKER_LIMIT,marker_filename
    return _read_owned_file_v75(session,name,{marker_filename(phase) for phase in PHASES},MARKER_LIMIT,'MARKER','V79')

def startup_rejection_v73(build):
    """Observe one fixed own pre-command refusal; grant no stop or cleanup."""
    def unique_pairs(pairs):
        values={}
        for key,value in pairs:
            if key in values:raise ValueError('V73_STARTUP_DUPLICATE_KEY')
            values[key]=value
        return values
    try:
        candidates=list(build.glob('session-*/command-host-error.json'))
        if len(candidates)!=1:return None
        path=contained(candidates[0],build)
        if not 0<path.stat().st_size<=4096:return None
        with path.open('rb') as stream:body=stream.read(4097)
        if not 0<len(body)<=4096:return None
        value=json.loads(body.decode('utf-8-sig'),object_pairs_hook=unique_pairs)
    except (OSError,ValueError,UnicodeError,RecursionError):return None
    if (type(value) is not dict or value.get('stage')!='gold-read-only'
        or value.get('bridgeReady') is not False or value.get('connectionPublished') is not False
        or any(type(value.get(k)) is not int or value[k]!=0 for k in ('readCount','writeCount'))
        or value.get('clientCode')!='EARLY_SNEGOPAT_RUN_REJECTED'):return None
    result=dict(code='EARLY_SNEGOPAT_RUN_REJECTED',connectionPublished=False,readCount=0,writeCount=0)
    line=value.get('errorLine')
    if type(line) is int and 0<line<=10000:result['errorLine']=line
    if value.get('errorType')=='RuntimeException':result['errorType']='RuntimeException'
    return result
def identity(value):return value['processId'],value['processCreationFileTimeUtc']
def parent_identity(process):
    k=c.WinDLL('kernel32',use_last_error=True)
    k.GetProcessTimes.argtypes=[c.c_void_p]+[c.POINTER(c.c_uint64)]*4
    values=[c.c_uint64() for _ in range(4)]
    need(k.GetProcessTimes(int(process._handle),*(c.byref(v) for v in values)),'V43_ORIGINAL_PARENT_UNKNOWN')
    return dict(pid=process.pid,birth=f'{values[0].value:016x}')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared-runtime',type=Path,required=True)
    parser.add_argument('--check-disconnect',action='store_true',help='Read-only peer disconnect and exact replay control.')
    parser.add_argument('--check-selection-inputs',action='store_true',help='Read-only capture/cancel planner input inventory; never call handler.')
    parser.add_argument('--check-object-snapshot',action='store_true',help='Read-only object serializer availability and repeatability; no Gold save.')
    parser.add_argument('--compare-repository-object',action='store_true',help='Read exact TCP descriptor/module and compare; no capture/apply.')
    parser.add_argument('--compare-document-modules',action='store_true',help='Read and compare both Document module properties and contexts; no setter/save.')
    parser.add_argument('--check-factory-copy',action='store_true',help='Read-only native map copies, release and cross-callback lifetime; never call handler.')
    parser.add_argument('--check-capture-listeners',action='store_true',help='Read-only stock listener interfaces; only IUnknown QI/Release, never notification handlers.')
    parser.add_argument('--check-capture-state',action='store_true',help='Read-only exact stock listener attachment/canonical identities; no permission callbacks.')
    parser.add_argument('--check-statistic-packet',action='store_true',help='Read-only exact Doc devObjectsStatistic packet with native-owned outputs; no notification/capture.')
    parser.add_argument('--check-free-notification',action='store_true',help='Notify only the actual stock listener of exact FREE Doc; readonly getters, no capture/setters/save.')
    parser.add_argument('--check-detached-text-undo',action='store_true',help='One native Undo on a factory-created independent text document; Gold remains read-only.')
    parser.add_argument('--check-owned-value-lifetime',action='store_true',help='Copy and clear scoped native Value references across two callbacks; Gold remains read-only, no metadata setter.')
    parser.add_argument('--check-owned-value-persistence',action='store_true',help='Inspect FormType IPersistableObject support and serialize to owned memory; no unknown clone factory, deserialize or metadata setter.')
    parser.add_argument('--check-processing-form-descriptor',action='store_true',help='Clone one same-class form descriptor into own MemoryFile objects; Gold stays read-only, no body/save/delete.')
    parser.add_argument('--check-owned-persistence',action='store_true',help='Published serialize/deserialize pair on two fresh own MemoryFile Processing/Form graphs; no Gold writes.')
    parser.add_argument('--check-owned-form-type',action='store_true',help='Map native enum candidates against known managed FormType and set only a newly owned MemoryFile Form; no Gold writes or form body.')
    parser.add_argument('--check-owned-form-type-v74',action='store_true',help='Consume a verified readonly managed enum in one fresh own MemoryFile Form; no enum factory or Gold writes.')
    parser.add_argument('--check-owned-managed-body-v73',action='store_true',help='Own MemoryFile processing/form/module/group, physical CF reopen and exact own deletion; Gold stays read-only.')
    parser.add_argument('--check-owned-managed-form-v75',action='store_true',help='Own managed form body/module/group and exact own deletion; no configuration dump/load, Gold stays read-only.')
    parser.add_argument('--check-managed-body-factory-v78',action='store_true',help='Inspect one published managed-body factory result; no metadata graph or body writers/configuration dumps-loads.')
    parser.add_argument('--check-managed-body-module-v79',action='store_true',help='Read bounded default module lengths on one freshly factory-created managed body; no module text logging or writers.')
    parser.add_argument('--check-owned-constant-v77',action='store_true',help='Create/read/type/delete one exact Constant in own empty MemoryFile; no Gold metadata writes or configuration exports-imports.')
    parser.add_argument('--check-gold-own-object-module-v78',action='store_true',help='One new owned Processing in live Gold UI: ObjectModule comment/Undo/delete, no configuration save, DB update, repository placement or dumps-loads.')
    parser.add_argument('--check-gold-own-object-module-v82',action='store_true',help='One new owned Gold Processing: exact ObjectModule comment/Undo/delete and bounded helper observation; no save, DB update, repository placement or exports-imports.')
    parser.add_argument('--check-capture-fresh-v81',action='store_true',help='One stock Opros capture, fresh full descriptor/module comparison and own cancellation; no configuration dump/load or code writes.')
    parser.add_argument('--check-gold-owned-constant-v99',action='store_true',help='One new own Gold Constant: Boolean type/readback/delete, no save, DB/repository/business or configuration exports-imports.')
    parser.add_argument('--check-gold-owned-full-object-module-v150',action='store_true',help='Own NEW EMPTY Processing full ObjectModule text/readback/Undo/delete only; no BSL execution, save, DB, repository or business calls.')
    parser.add_argument('--check-gold-owned-document-structure-v139',action='store_true',help='Own empty Document/Attribute/TablePart/Column create/read/delete only; no save, DB, repository or business calls.')
    parser.add_argument('--check-gold-owned-empty-objects-v130',action='store_true',help='Own empty Document/Catalog create/read/delete only; no save, DB, repository or business calls.')
    parser.add_argument('--check-gold-owned-managed-form-v107',action='store_true',help='One new owned Gold Processing/managed form/body and exact deletion; no save, DB/repository/business or configuration exports-imports.')
    parser.add_argument('--check-compact-owner-v108',action='store_true',help='Read-only compact owner/version binding and measured parity with the full repository observation.')
    parser.add_argument('--check-stock-selection-inventory-v106',action='store_true',help='Read-only bounded stock selection dependency tables; no selection construction or capture.')
    parser.add_argument('--check-owned-empty-class-inventory-v125',action='store_true',help='Read-only typed Document/Catalog class lookup and bounded slot addresses; no object factories or writers.')
    parser.add_argument('--check-metadata-receivers-v126',action='store_true',help='Read-only typed current/templates/infobase receiver relations; no Main/DB, Save or writer authority.')
    parser.add_argument('--check-managed-input-record-v145',action='store_true',help='Detached Input record own MemoryFile roundtrip, no Gold writer.')
    args=parser.parse_args()
    if args.check_managed_input_record_v145 and any(value for name,value in vars(args).items() if name.startswith('check_') and name!='check_managed_input_record_v145'):
        parser.error('V145_EXCLUSIVE_READ_ROUTE_REQUIRED')
    if (args.check_compact_owner_v108 or args.check_stock_selection_inventory_v106) and any(value
        for name,value in vars(args).items() if name.startswith('check_')
        and name not in ('check_compact_owner_v108','check_stock_selection_inventory_v106')):
        parser.error('V109_EXCLUSIVE_READ_ROUTE_REQUIRED')
    if args.check_owned_empty_class_inventory_v125 and any(value
        for name,value in vars(args).items() if name.startswith('check_') and name!='check_owned_empty_class_inventory_v125'):
        parser.error('V109_EXCLUSIVE_READ_ROUTE_REQUIRED')
    if args.check_metadata_receivers_v126 and any(value
        for name,value in vars(args).items() if name.startswith('check_') and name!='check_metadata_receivers_v126'):
        parser.error('V109_EXCLUSIVE_READ_ROUTE_REQUIRED')
    if args.check_gold_owned_full_object_module_v150 and any(value for name,value in vars(args).items()
        if name.startswith('check_') and name!='check_gold_owned_full_object_module_v150'):
        parser.error('GD139_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    if args.check_gold_owned_document_structure_v139 and any(value for name,value in vars(args).items()
        if name.startswith('check_') and name!='check_gold_owned_document_structure_v139'):
        parser.error('GD139_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    if args.check_gold_owned_empty_objects_v130 and any(value for name,value in vars(args).items()
        if name.startswith('check_') and name!='check_gold_owned_empty_objects_v130'):
        parser.error('GE130_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    if args.check_gold_owned_managed_form_v107 and any(value for name,value in vars(args).items()
        if name.startswith('check_') and name!='check_gold_owned_managed_form_v107'):
        parser.error('GM107_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    if args.check_gold_owned_constant_v99 and any(value for name,value in vars(args).items()
        if name.startswith('check_') and name!='check_gold_owned_constant_v99'):
        parser.error('GC99_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    if args.check_gold_own_object_module_v82 and any(value for name,value in vars(args).items()
        if name.startswith('check_') and name!='check_gold_own_object_module_v82'):
        parser.error('GOM82_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    if args.check_capture_fresh_v81 and any(value for name,value in vars(args).items() if name.startswith('check_') and name!='check_capture_fresh_v81'):
        parser.error('V81_EXCLUSIVE_CAPTURE_ROUTE_REQUIRED')
    if args.check_gold_own_object_module_v78 and any(value for name,value in vars(args).items()
        if name.startswith('check_') and name!='check_gold_own_object_module_v78'):
        parser.error('GOM78_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    # V69 terminated the owned process without a native result. Refuse the
    # historical route before touching runtime, leases or Gold.
    if args.check_processing_form_descriptor:
        parser.error('V69_PROCESSING_FORM_ROUTE_QUARANTINED')
    if args.check_managed_body_module_v79 and any(getattr(args,key) for key in (
        'check_owned_constant_v77','check_managed_body_factory_v78','check_owned_managed_form_v75',
        'check_owned_managed_body_v73','check_owned_form_type_v74','check_owned_form_type',
        'check_owned_persistence','check_owned_value_lifetime','check_owned_value_persistence',
        'check_factory_copy','check_capture_listeners','check_capture_state','check_statistic_packet',
        'check_free_notification','check_detached_text_undo')):
        parser.error('V79_EXCLUSIVE_OBSERVER_ROUTE_REQUIRED')
    if args.check_owned_constant_v77 and any(getattr(args,key) for key in (
        'check_managed_body_factory_v78','check_owned_managed_form_v75','check_owned_managed_body_v73',
        'check_owned_form_type_v74','check_owned_form_type','check_owned_persistence',
        'check_owned_value_lifetime','check_owned_value_persistence','check_factory_copy',
        'check_capture_listeners','check_capture_state','check_statistic_packet',
        'check_free_notification','check_detached_text_undo')):
        parser.error('V77_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    if args.check_managed_body_factory_v78 and any(getattr(args,key) for key in (
        'check_owned_managed_form_v75','check_owned_managed_body_v73','check_owned_form_type_v74','check_owned_form_type',
        'check_owned_persistence','check_owned_value_lifetime','check_owned_value_persistence',
        'check_factory_copy','check_capture_listeners','check_capture_state','check_statistic_packet',
        'check_free_notification','check_detached_text_undo')):
        parser.error('V78_EXCLUSIVE_OBSERVER_ROUTE_REQUIRED')
    if args.check_owned_managed_form_v75 and any(getattr(args,key) for key in (
        'check_owned_managed_body_v73','check_owned_form_type_v74','check_owned_form_type',
        'check_owned_persistence','check_owned_value_lifetime','check_owned_value_persistence',
        'check_factory_copy','check_capture_listeners','check_capture_state','check_statistic_packet',
        'check_free_notification','check_detached_text_undo')):
        parser.error('V75_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    if args.check_owned_managed_body_v73 and any(getattr(args,key) for key in (
        'check_owned_form_type_v74','check_owned_form_type','check_owned_persistence',
        'check_owned_value_lifetime','check_owned_value_persistence','check_factory_copy',
        'check_capture_listeners','check_capture_state','check_statistic_packet',
        'check_free_notification','check_detached_text_undo')):
        parser.error('V73_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    if args.check_owned_form_type and any(getattr(args,key) for key in (
        'check_owned_persistence','check_owned_value_lifetime','check_owned_value_persistence',
        'check_factory_copy','check_capture_listeners','check_capture_state',
        'check_statistic_packet','check_free_notification','check_detached_text_undo')):
        parser.error('V72_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    if args.check_owned_form_type_v74 and any(getattr(args,key) for key in (
        'check_owned_form_type','check_owned_persistence','check_owned_value_lifetime','check_owned_value_persistence',
        'check_factory_copy','check_capture_listeners','check_capture_state',
        'check_statistic_packet','check_free_notification','check_detached_text_undo')):
        parser.error('V74_EXCLUSIVE_OWN_ROUTE_REQUIRED')
    # User scope now prohibits configuration export/import. V73 includes own
    # CF extraction/reopen, so it remains historical and cannot be launched.
    if args.check_owned_managed_body_v73:
        parser.error('V73_CONFIG_EXPORT_ROUTE_DISABLED')
    if args.check_managed_input_record_v145:args.compare_document_modules=args.compare_repository_object=True
    build=args.prepared_runtime.resolve()
    if args.check_compact_owner_v108 or args.check_stock_selection_inventory_v106 or args.check_owned_empty_class_inventory_v125 or args.check_metadata_receivers_v126:
        args.compare_document_modules=args.compare_repository_object=True
    if args.check_owned_persistence:args.compare_document_modules=args.compare_repository_object=True
    if args.check_owned_form_type:args.compare_document_modules=args.compare_repository_object=True
    if args.check_owned_form_type_v74:args.compare_document_modules=args.compare_repository_object=True
    if args.check_owned_managed_body_v73:args.compare_document_modules=args.compare_repository_object=True
    if args.check_owned_managed_form_v75:args.compare_document_modules=args.compare_repository_object=True
    if args.check_managed_body_factory_v78:args.compare_document_modules=args.compare_repository_object=True
    if args.check_managed_body_module_v79:args.compare_document_modules=args.compare_repository_object=True
    if args.check_owned_constant_v77:args.compare_document_modules=args.compare_repository_object=True
    if args.check_capture_fresh_v81:args.compare_document_modules=args.compare_repository_object=True
    if args.check_gold_own_object_module_v78:args.compare_document_modules=args.compare_repository_object=True
    if args.check_gold_own_object_module_v82:args.compare_document_modules=args.compare_repository_object=True
    if args.check_gold_owned_constant_v99:args.compare_document_modules=args.compare_repository_object=True
    if args.check_gold_owned_full_object_module_v150:args.compare_document_modules=args.compare_repository_object=True
    if args.check_gold_owned_document_structure_v139:args.compare_document_modules=args.compare_repository_object=True
    if args.check_gold_owned_empty_objects_v130:args.compare_document_modules=args.compare_repository_object=True
    if args.check_gold_owned_managed_form_v107:args.compare_document_modules=args.compare_repository_object=True
    if args.check_processing_form_descriptor:args.check_owned_value_lifetime=True
    if args.check_owned_value_persistence:args.check_owned_value_lifetime=True
    if args.check_owned_value_lifetime:args.check_capture_state=True
    if args.check_free_notification:args.check_statistic_packet=True
    if args.check_statistic_packet:args.check_capture_state=True
    if args.check_capture_state:args.check_capture_listeners=True
    if args.check_factory_copy or args.check_capture_listeners or args.check_detached_text_undo:args.compare_document_modules=args.compare_repository_object=True
    prepared=verify_prepared(build)
    if args.check_compact_owner_v108:
        from compact_owner_contract_v108 import verify_static as check_compact_static_v108
        compact_static_v108=check_compact_static_v108()
    if args.check_stock_selection_inventory_v106:
        from stock_selection_inventory_contract_v106 import verify_static as check_inventory_static_v106
        inventory_static_v106=check_inventory_static_v106()
    if args.check_owned_empty_class_inventory_v125:
        from owned_empty_class_inventory_contract_v125 import verify_static as check_empty_class_static_v125
        empty_class_static_v125=check_empty_class_static_v125()
    if args.check_managed_input_record_v145:
        from managed_input_record_controller_v145 import verify_static as verify_managed_input_static_v145
        managed_input_static_v145=verify_managed_input_static_v145()
    if args.check_metadata_receivers_v126:
        from metadata_receivers_contract_v126 import verify_static as check_metadata_receivers_static_v126
        metadata_receivers_static_v126=check_metadata_receivers_static_v126()
    if args.check_capture_fresh_v81:
        from capture_fresh_contract_v81 import verify_static as verify_capture_fresh_static_v81
        capture_fresh_static_v81=verify_capture_fresh_static_v81()
    if args.check_gold_own_object_module_v78:
        from gold_own_object_module_contract_v78 import verify_static as verify_gold_own_module_static_v78
        gold_own_module_static_v78=verify_gold_own_module_static_v78()
    if args.check_gold_owned_full_object_module_v150:
        from gold_owned_full_object_module_controller_v150 import verify_static as verify_gold_full_module_static_v150
        gold_full_module_static_v150=verify_gold_full_module_static_v150()
    if args.check_gold_owned_document_structure_v139:
        from gold_owned_document_structure_controller_v139 import verify_static as verify_gold_structure_static_v139
        gold_structure_static_v139=verify_gold_structure_static_v139()
    if args.check_gold_owned_empty_objects_v130:
        from gold_owned_empty_objects_controller_v130 import verify_static as verify_gold_empty_static_v130
        gold_empty_static_v130=verify_gold_empty_static_v130()
    if args.check_gold_owned_managed_form_v107:
        from gold_owned_managed_form_contract_v107 import verify_static as verify_gold_managed_static_v107
        from gold_owned_managed_form_session_contract_v115 import verify_static as verify_gold_managed_session_v115
        gold_managed_static_v107=verify_gold_managed_static_v107()
        gold_managed_session_v115=verify_gold_managed_session_v115()
    if args.check_gold_owned_constant_v99:
        from gold_owned_constant_contract_v99 import verify_static as verify_gold_constant_static_v99
        from gold_owned_constant_session_contract_v102 import verify_static as verify_gold_constant_session_static_v102
        gold_constant_static_v99=verify_gold_constant_static_v99()
        gold_constant_session_static_v102=verify_gold_constant_session_static_v102()
    if args.check_gold_own_object_module_v82:
        from gold_own_object_module_contract_v82 import verify_static as verify_gold_own_module_static_v82
        gold_own_module_static_v82=verify_gold_own_module_static_v82()
    if args.check_owned_persistence:
        from owned_persistence_contract_v71 import verify_static as verify_owned_persistence_static
        own_persistence_static=verify_owned_persistence_static()
    if args.check_owned_form_type:
        from managed_form_type_contract_v72 import verify_static as verify_managed_form_type_static
        form_type_static=verify_managed_form_type_static()
    if args.check_owned_form_type_v74 or args.check_owned_managed_body_v73 or args.check_owned_managed_form_v75 or args.check_managed_body_factory_v78 or args.check_owned_constant_v77 or args.check_managed_body_module_v79:
        from managed_form_type_contract_v74 import verify_static as verify_managed_form_type_static_v74
        form_type_static_v74=verify_managed_form_type_static_v74()
    if args.check_owned_constant_v77:
        from owned_constant_contract_v77 import verify_static as verify_owned_constant_static
        own_constant_static=verify_owned_constant_static()
    if args.check_owned_managed_body_v73 or args.check_owned_managed_form_v75 or args.check_managed_body_factory_v78 or args.check_managed_body_module_v79:
        from owned_managed_body_contract_v73 import verify_static as verify_owned_managed_body_static_v73
        owned_managed_body_static_v73=verify_owned_managed_body_static_v73()
    if args.check_owned_value_lifetime:
        from owned_value_contract_v67 import verify_static as verify_owned_value_static
        value_static=verify_owned_value_static()
    if args.check_owned_value_persistence:
        from owned_value_persistence_contract_v68 import verify_static as verify_owned_value_persistence_static
        persistence_static=verify_owned_value_persistence_static()
    if args.check_processing_form_descriptor:
        from processing_form_contract_v69 import verify_static as verify_processing_form_static
        processing_form_static=verify_processing_form_static()
    for name,wanted in HASHES.items():need(sha(PLATFORM/name).upper()==wanted,'V43_PLATFORM_CHANGED')
    need(not (build/'owned-gold-pid').exists() and not list(build.glob('session-*')),'V43_FRESH_RUNTIME_REQUIRED')
    controller=contained(build/('controller-'+uuid.uuid4().hex),build);controller.mkdir()
    proof=dict(stage='V43OwnedGoldReadOnlyStartup',nonce=prepared['nonce'],passed=False,runtimeDirectory=str(build),
        sourceSha256=prepared['sourceSha256']|{Path(__file__).relative_to(ROOT).as_posix():sha(Path(__file__))},
        goldConfigurationWrites=0,databaseUpdates=0,repositoryMutations=0,businessCalls=0,calls=[],startedCallers=[],runtimeRetained=True)
    if args.check_compact_owner_v108:proof['compactOwnerStaticContractV108']=compact_static_v108
    if args.check_stock_selection_inventory_v106:proof['stockSelectionInventoryStaticContractV106']=inventory_static_v106
    if args.check_owned_empty_class_inventory_v125:proof['ownedEmptyClassInventoryStaticContractV125']=empty_class_static_v125
    if args.check_managed_input_record_v145:proof['managedInputRecordStaticContractV145']=managed_input_static_v145
    if args.check_metadata_receivers_v126:proof['metadataReceiversStaticContractV126']=metadata_receivers_static_v126
    if args.check_capture_fresh_v81:
        proof.update(stage='V43CaptureFreshV81',captureFreshStaticContractV81=capture_fresh_static_v81,goldConfigurationSaves=0,normalDesignerExitClaimed=False)
    if args.check_gold_own_object_module_v78:
        proof.update(stage='V43GoldOwnObjectModuleV78',goldOwnObjectModuleStaticContractV78=gold_own_module_static_v78,
            goldConfigurationSaves=0,normalDesignerExitClaimed=False)
    if args.check_gold_own_object_module_v82:
        proof.update(stage='V43GoldOwnObjectModuleV82',goldOwnObjectModuleStaticContractV82=gold_own_module_static_v82,
            goldConfigurationSaves=0,normalDesignerExitClaimed=False)
    if args.check_gold_owned_constant_v99:
        proof.update(stage='V43GoldOwnedConstantV99',goldOwnedConstantStaticContractV99=gold_constant_static_v99,
            goldOwnedConstantSessionStaticContractV102=gold_constant_session_static_v102,
            goldConfigurationSaves=0,normalDesignerExitClaimed=False)
    if args.check_gold_owned_full_object_module_v150:
        proof.update(stage='V43GoldOwnedFullObjectModuleV150',goldOwnedFullObjectModuleStaticContractV150=gold_full_module_static_v150,
            goldConfigurationSaves=0,normalDesignerExitClaimed=False)
    if args.check_gold_owned_document_structure_v139:
        proof.update(stage='V43GoldOwnedDocumentStructureV139',goldOwnedDocumentStructureStaticContractV139=gold_structure_static_v139,
            goldConfigurationSaves=0,normalDesignerExitClaimed=False)
    if args.check_gold_owned_empty_objects_v130:
        proof.update(stage='V43GoldOwnedEmptyObjectsV130',goldOwnedEmptyObjectsStaticContractV130=gold_empty_static_v130,
            goldConfigurationSaves=0,normalDesignerExitClaimed=False)
    if args.check_gold_owned_managed_form_v107:
        proof.update(stage='V43GoldOwnedManagedFormV107',goldOwnedManagedFormStaticContractV107=gold_managed_static_v107,
            goldOwnedManagedFormSessionStaticContractV115=gold_managed_session_v115,
            goldConfigurationSaves=0,normalDesignerExitClaimed=False)
    if args.check_owned_value_lifetime:proof['ownedValueStaticContractV67']=value_static
    if args.check_owned_value_persistence:proof['ownedValuePersistenceStaticContractV68']=persistence_static
    if args.check_processing_form_descriptor:proof['processingFormStaticContractV69']=processing_form_static
    if args.check_owned_persistence:proof['ownedPersistenceStaticContractV71']=own_persistence_static
    if args.check_owned_form_type:proof['managedFormTypeStaticContractV72']=form_type_static
    if args.check_owned_form_type_v74:proof['managedFormTypeStaticContractV74']=form_type_static_v74
    if args.check_owned_managed_body_v73:
        proof['ownedManagedBodyStaticContractV73']=owned_managed_body_static_v73
        proof['managedFormTypeStaticContractV74']=form_type_static_v74
    if args.check_owned_managed_form_v75:
        # V73 verifies fixed body/helper/store byte contracts by PE reads only.
        # Its historical configuration-extraction command is disabled above.
        proof['managedBodyStaticPrerequisitesV75']=owned_managed_body_static_v73
        proof['managedFormTypeStaticContractV74']=form_type_static_v74
    if args.check_managed_body_factory_v78:
        proof['managedBodyFactoryStaticPrerequisitesV78']=owned_managed_body_static_v73
        proof['managedFormTypeStaticContractV74']=form_type_static_v74
    if args.check_managed_body_module_v79:
        proof['managedBodyModuleStaticPrerequisitesV79']=owned_managed_body_static_v73
        proof['managedFormTypeStaticContractV74']=form_type_static_v74
    if args.check_owned_constant_v77:
        proof['ownedConstantStaticContractV77']=own_constant_static
        proof['managedFormTypeStaticContractV74']=form_type_static_v74
    host=original=None;session=None;owner=None;native_identity=host_identity=None
    start=time.perf_counter();exit_code=1
    with (controller/'host-stdout.jsonl').open('w',encoding='utf-8') as output:
        try:
            host=subprocess.Popen([sys.executable,'-B',TESTS/'run_live_probe.py',build,
                'CaptureStatusRepositoryCommandOpros','--early-managed-input-record-v145-host' if args.check_managed_input_record_v145 else '--early-gold-owned-full-object-module-v150-host' if args.check_gold_owned_full_object_module_v150 else '--early-gold-owned-document-structure-v139-host' if args.check_gold_owned_document_structure_v139 else '--early-gold-owned-empty-objects-v130-host' if args.check_gold_owned_empty_objects_v130 else '--early-gold-owned-managed-form-v107-host' if args.check_gold_owned_managed_form_v107 else '--early-gold-owned-constant-v99-host' if args.check_gold_owned_constant_v99 else '--early-gold-own-object-module-v82-host' if args.check_gold_own_object_module_v82 else '--early-capture-fresh-v81-host' if args.check_capture_fresh_v81 else '--early-gold-own-object-module-v78-host' if args.check_gold_own_object_module_v78 else
                '--early-selection-input-host' if args.check_selection_inputs or args.check_object_snapshot or args.compare_repository_object or args.compare_document_modules else '--early-read-host'],stdout=output,stderr=subprocess.DEVNULL)
            original=parent_identity(host);proof['originalLauncher']=original
            durable_new(controller/'original-launcher.json',original)
            deadline=time.monotonic()+70
            while time.monotonic()<deadline and host.poll() is None:
                startup_failure=startup_rejection_v73(build)
                if startup_failure is not None:
                    proof['startupRejectionV73']=startup_failure
                    raise ValueError('V43_NATIVE_BOOTSTRAP_REJECTED')
                candidates=list(build.glob('session-*/command-connection.json'))
                if len(candidates)==1:
                    metadata=read(candidates[0]);session=candidates[0].parent
                    owner=metadata.get('leaseOwner');native_identity=identity(metadata)
                    host_identity=metadata['hostProcessId'],metadata['hostProcessCreationFileTimeUtc']
                    need(isinstance(owner,str) and re.fullmatch('[a-f0-9]{32}',owner) and lease_exists(owner)
                        and not owned_process_gone(*native_identity) and not owned_process_gone(*host_identity),'V43_READY_IDENTITY_REJECTED')
                    break
                time.sleep(.05)
            need(session is not None,'V43_NATIVE_HOST_NOT_READY')
            proof.update(processId=native_identity[0],processCreationFileTimeUtc=native_identity[1],
                hostProcessId=host_identity[0],hostProcessCreationFileTimeUtc=host_identity[1],
                leaseOwner=owner,startupToPublishedMs=round((time.perf_counter()-start)*1000,1))
            callback=read(build/'early-callback.json');layout=read(build/'sdk-layout.json')
            marker=(session/'early-parameters-readback').read_text(encoding='ascii')
            need(callback['pid']==native_identity[0] and callback['birth']==native_identity[1]
                and callback['nonce']==prepared['nonce'] and callback['hookCode']==3
                and callback['sdkTrialResult']==0 and callback['coreParameterSetters']==2
                and callback['hookUnregistered'] is True and callback['sourceWrites']==0
                and layout['nonce']==prepared['nonce'] and layout['pid']==native_identity[0]
                and marker=='STARTER_ZERO_PROCESS_NONZERO','V43_EARLY_ENTRY_REJECTED')
            proof.update(callback=callback,sdkLayout=layout,coreParameterReadBackVerified=True)
            shell=Path(os.environ['WINDIR'])/'SysWOW64/WindowsPowerShell/v1.0/powershell.exe'
            def call(command,op=None,defer=False):
                operation=op or uuid.uuid4().hex
                client_script='Invoke-ManagedInputRecordV145.ps1' if args.check_managed_input_record_v145 else 'Invoke-GoldOwnedFullObjectModuleV150.ps1' if args.check_gold_owned_full_object_module_v150 else 'Invoke-GoldOwnedDocumentStructureV139.ps1' if args.check_gold_owned_document_structure_v139 else 'Invoke-GoldOwnedEmptyObjectsV130.ps1' if args.check_gold_owned_empty_objects_v130 else 'Invoke-GoldOwnedManagedFormV107.ps1' if args.check_gold_owned_managed_form_v107 else 'Invoke-GoldOwnedConstantV99.ps1' if args.check_gold_owned_constant_v99 else 'Invoke-GoldOwnObjectModuleV82.ps1' if args.check_gold_own_object_module_v82 else 'Invoke-CaptureFreshV81.ps1' if args.check_capture_fresh_v81 else 'Invoke-GoldOwnObjectModuleV78.ps1' if args.check_gold_own_object_module_v78 else 'Invoke-NativeCommand.ps1'
                argv=[str(shell),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(TESTS.parent/client_script),
                    '-ConnectionFile',str(session/'command-connection.json'),'-Command',command,'-OperationId',operation]
                if defer:argv.append('-DeferCloseAck')
                timer=time.perf_counter();p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                caller=parent_identity(p);started=dict(command=command,operationId=operation,caller=caller)
                proof['startedCallers'].append(started)
                stdout,_=p.communicate(timeout=35 if command in ('GOLD_OWN_OBJECT_MODULE_V82','GOLD_OWNED_CONSTANT_V99','GOLD_OWNED_MANAGED_FORM_V107','GOLD_OWNED_EMPTY_OBJECTS_V130','GOLD_OWNED_DOCUMENT_STRUCTURE_V139','GOLD_OWNED_FULL_OBJECT_MODULE_V150','MANAGED_INPUT_RECORD_V145') else 12);started['heldOriginalExitCode']=p.returncode
                lines=[line for line in stdout.decode('utf-8-sig').splitlines() if line.startswith('{')]
                if p.returncode!=0 and len(lines)==1:
                    rejected=json.loads(lines[0]);code=rejected.get('code','')
                    if re.fullmatch('[A-Z][A-Z_0-9]{3,63}',code):started['nativeClientCode']=code
                need(p.returncode==0 and len(lines)==1,'V43_READ_CALL_REJECTED')
                reply=json.loads(lines[0]);need(identity(reply)==native_identity,'V43_CALL_IDENTITY_CHANGED')
                result=contained(Path(reply['resultFile']),session)
                result_prefix='managed-input-client-v145-' if args.check_managed_input_record_v145 else 'owned-full-object-module-client-v150-' if args.check_gold_owned_full_object_module_v150 else 'owned-document-structure-client-v139-' if args.check_gold_owned_document_structure_v139 else 'owned-empty-objects-client-v130-' if args.check_gold_owned_empty_objects_v130 else 'owned-managed-form-client-v107-' if args.check_gold_owned_managed_form_v107 else 'owned-constant-client-v99-' if args.check_gold_owned_constant_v99 else 'own-module-client-v82-' if args.check_gold_own_object_module_v82 else 'capture-fresh-client-' if args.check_capture_fresh_v81 else 'own-module-client-' if args.check_gold_own_object_module_v78 else 'client-'
                need(result.parent==session and re.fullmatch(result_prefix+'[a-f0-9]{32}-[a-f0-9]{32}\\.txt',result.name),'V43_RESULT_PATH_REJECTED')
                if args.check_managed_input_record_v145:
                    from managed_input_record_controller_v145 import verify_exchange
                    data=verify_exchange(reply,command,operation,caller,session,native_identity)
                    started.update(exchangeId=reply['exchangeId'],callerWitnessFile=reply['callerWitnessFile'],callerWitnessSha256=reply['callerWitnessSha256'])
                elif args.check_gold_owned_full_object_module_v150:
                    from gold_owned_full_object_module_controller_v150 import verify_exchange as verify_empty_exchange
                    data=verify_empty_exchange(reply,command,operation,caller,session,native_identity)
                    started.update(exchangeId=reply['exchangeId'],callerWitnessFile=reply['callerWitnessFile'],
                        callerWitnessSha256=reply['callerWitnessSha256'])
                elif args.check_gold_owned_document_structure_v139:
                    from gold_owned_document_structure_controller_v139 import verify_exchange as verify_empty_exchange
                    data=verify_empty_exchange(reply,command,operation,caller,session,native_identity)
                    started.update(exchangeId=reply['exchangeId'],callerWitnessFile=reply['callerWitnessFile'],
                        callerWitnessSha256=reply['callerWitnessSha256'])
                elif args.check_gold_owned_empty_objects_v130:
                    from gold_owned_empty_objects_controller_v130 import verify_exchange as verify_empty_exchange
                    data=verify_empty_exchange(reply,command,operation,caller,session,native_identity)
                    started.update(exchangeId=reply['exchangeId'],callerWitnessFile=reply['callerWitnessFile'],
                        callerWitnessSha256=reply['callerWitnessSha256'])
                elif args.check_gold_owned_managed_form_v107:
                    from gold_owned_managed_form_controller_v116 import verify_exchange
                    data=verify_exchange(reply,command,operation,caller,session)
                    started.update(exchangeId=reply['exchangeId'],callerWitnessFile=reply['callerWitnessFile'],
                        callerWitnessSha256=reply['callerWitnessSha256'])
                else:data=result.read_bytes()
                need(len(data)==reply['bytes'] and hashlib.sha256(data).hexdigest()==reply['sha256'],'V43_REPLY_HASH_REJECTED')
                need(owned_process_gone(caller['pid'],caller['birth']),'V43_CALLER_RETAINED')
                proof['calls'].append(dict(command=command,operationId=operation,replayed=reply['replayed'],
                    bytes=reply['bytes'],sha256=reply['sha256'],caller=caller,callerElapsedMs=round((time.perf_counter()-timer)*1000,1)))
                return reply,data.decode('utf-8-sig')
            call('PING')
            _,one=call('READLIVE');_,two=call('READLIVE');need(one==two and len(one)>0,'V43_LIVE_TEXT_CHANGED')
            _,status_text=call('STATUS')
            from capture_ownership_guard import parse_result as parse_ownership_status,verify as verify_ownership_status
            status=parse_ownership_status(status_text)
            proof['captureOwnership']=verify_ownership_status(status,'88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d')
            need(status.get('ownedObjectModuleV78IdAbsent') is True,'GOM78_OWN_ID_ALREADY_PRESENT')
            proof['ownedObjectModuleV78IdAbsentAtStartup']=True
            need(type(status.get('ownedFullObjectModuleV150Absent')) is bool,'GFM150_TYPED_ABSENCE_REQUIRED')
            proof['ownedFullObjectModuleV150AbsentAtStartup']=status['ownedFullObjectModuleV150Absent']
            if args.check_gold_owned_full_object_module_v150:need(status['ownedFullObjectModuleV150Absent'] is True,'GFM150_OWN_ID_ALREADY_PRESENT')
            for key in ('ownedStructureDocumentV139Absent','ownedStructureDocumentAttributeV139Absent','ownedStructureTablePartV139Absent','ownedStructureTablePartAttributeV139Absent'):
                need(type(status.get(key)) is bool,'GD139_OWN_ABSENCE_TYPE_REJECTED')
                proof[key+'AtStartup']=status[key]
                if args.check_gold_owned_document_structure_v139:need(status[key] is True,'GD139_OWN_ID_ALREADY_PRESENT')
            for key in ('ownedEmptyDocumentV130Absent','ownedEmptyCatalogV130Absent'):
                if type(status.get(key)) is bool:proof[key+'AtStartup']=status[key]
                if args.check_gold_owned_empty_objects_v130:need(status.get(key) is True,'GE130_OWN_ID_ALREADY_PRESENT')
            for key in ('ownedProcessingV107IdAbsent','ownedFormV107IdAbsent'):
                if type(status.get(key)) is bool:proof[key+'AtStartup']=status[key]
                if args.check_gold_owned_managed_form_v107:need(status.get(key) is True,'GM107_OWN_ID_ALREADY_PRESENT')
            if type(status.get('ownedConstantV99IdAbsent')) is bool:
                proof['ownedConstantV99IdAbsentAtStartup']=status['ownedConstantV99IdAbsent']
            if args.check_gold_owned_constant_v99:
                need(status.get('ownedConstantV99IdAbsent') is True,'GC99_OWN_ID_ALREADY_PRESENT')
            if type(status.get('ownedObjectModuleV82IdAbsent')) is bool:
                proof['ownedObjectModuleV82IdAbsentAtStartup']=status['ownedObjectModuleV82IdAbsent']
            if args.check_gold_own_object_module_v82:
                need(status.get('ownedObjectModuleV82IdAbsent') is True,'GOM82_OWN_ID_ALREADY_PRESENT')
                proof['ownedObjectModuleV82IdAbsentAtStartup']=True
            dirty=status.get('dirty',{})
            need(status.get('scopeAlive') is True and dirty.get('verified') is True and dirty.get('refreshAllowed') is True
                and all(dirty.get(k) is False for k in ('configurationModified','objectModified','bufferModified'))
                and status.get('goldConfigurationWrites')==0 and status.get('repositoryMutations')==0,'V43_CLEAN_SCOPE_REJECTED')
            proof.update(readCount=2,liveTextBytes=len(one.encode('utf-8')),liveTextSha256=hashlib.sha256(one.encode('utf-8')).hexdigest(),
                dirtyCleanVerified=True,rootAndSelectionVerified=status.get('selectionVerified') is True)
            if args.check_compact_owner_v108 or args.check_stock_selection_inventory_v106 or args.check_owned_empty_class_inventory_v125 or args.check_metadata_receivers_v126 or args.check_managed_input_record_v145:
                proof['benchmarkSkippedForReadonlyDiagnostic']=True
            elif args.check_gold_owned_full_object_module_v150 or args.check_gold_owned_document_structure_v139 or args.check_gold_owned_empty_objects_v130 or args.check_gold_owned_managed_form_v107 or args.check_gold_owned_constant_v99 or args.check_gold_own_object_module_v82 or args.check_gold_own_object_module_v78 or args.check_capture_fresh_v81:
                # This capability grants one own-object lifecycle. A readonly
                # throughput benchmark would use another role and adds no
                # evidence about the module write/Undo under test.
                proof['benchmarkSkippedForOwnedWriteScope']=True
            else:
                benchmark=subprocess.Popen([str(shell),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(HERE/'Measure-GoldChannelV43.ps1'),
                    '-ConnectionFile',str(session/'command-connection.json'),'-ExpectedSha256',proof['liveTextSha256']],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                benchmark_caller=parent_identity(benchmark);bench_stdout,_=benchmark.communicate(timeout=15)
                need(benchmark.returncode==0,'V43_BENCHMARK_REJECTED')
                bench=json.loads(bench_stdout.decode('utf-8-sig'))
                need(bench.get('passed') is True and bench.get('reads')==20 and bench.get('oneConnection') is True
                    and bench.get('processId')==native_identity[0] and bench.get('birth')==native_identity[1]
                    and bench.get('sha256')==proof['liveTextSha256'] and bench.get('bytes')==proof['liveTextBytes']
                    and owned_process_gone(benchmark_caller['pid'],benchmark_caller['birth']),'V43_BENCHMARK_IDENTITY_REJECTED')
                proof.update(benchmark=bench,benchmarkCaller=benchmark_caller)
            if args.check_selection_inputs:
                _,input_text=call('SELECTION_INPUTS_V46');inputs=json.loads(input_text);proof['selectionInputsV46']=inputs
                need(inputs['status']=='INPUTS_OBSERVED' and inputs['bindingAndVersionUnchanged'] is True
                    and inputs['retainedMapsStillBounded'] is True and inputs['handlerInvocations']==0
                    and inputs['sourceWrites']==0 and inputs['repositoryWrites']==0,'V46_INPUT_INVENTORY_UNVERIFIED')
                for phase,operation in (('capturePlan',1),('cancelPlan',3)):
                    plan=inputs[phase];need(plan['operation']==operation and plan['allMapsBoundedToRequested'] is True,'V46_INPUT_SCOPE_CHANGED')
                    for name in ('selected','filtered','application'):
                        part=plan[name];need(part['verified'] is True and part['count'] in (0,1),'V46_MAP_UNBOUNDED')
                        for row in part.get('records',[]):
                            need(row['key'].strip('{}').lower()=='88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'
                                and row['id']==row['key'],'V46_UNEXPECTED_METADATA_OBJECT')
                _,three=call('READLIVE');need(three==one,'V46_INPUT_INVENTORY_CHANGED_TEXT')
            if args.compare_repository_object or args.compare_document_modules:
                from run_repository_source import require_positive,source_summary
                _,source_text=call('SOURCE_ONCE');source=json.loads(source_text)
                need(require_positive(source),'V47_REPOSITORY_SOURCE_UNVERIFIED')
                proof['repositorySourceV47']=source_summary(source)
            if args.compare_document_modules:
                from document_module_guard_v48 import compare_modules
                _,modules_text=call('DOCUMENT_MODULES_V48');modules=json.loads(modules_text)
                proof['documentModulesNativeV48']=modules
                proof['documentModulesComparisonV48']=compare_modules(modules,
                    lambda name:contained(session/name,session).read_bytes(),source['sourceProbe']['fetch']['requestedVersion'],one)
                _,live_after_modules=call('READLIVE');need(live_after_modules==one,'V48_MODULE_READ_CHANGED_SOURCE')
                if args.check_owned_form_type_v74:
                    prior_path=ROOT/'artifacts/designer-bridge/v43-gold-startup-f728e5b5c7184f7a9b74140c124526d3.json'
                    need(sha(prior_path)=='5f45423468b72605ccd41fb4d9db7943193344f0f28a8ca89a8ff141e04ff8c4','V74_PRIOR_V72_PROOF_CHANGED')
                    prior=read(prior_path)
                    need(prior.get('passed') is True and prior.get('closeConfirmed') is True
                        and prior.get('ownedFormTypeVerifiedV72') is False,'V74_PRIOR_V72_PROOF_REJECTED')
                    proof['priorV72PostDocumentModulesComparison']=compare_prior_modules_v74(
                        proof['documentModulesComparisonV48'],prior['documentModulesComparisonV48'])
                    proof['priorV72PostDocumentModulesVerified']=True
                    proof['priorV72EvidenceSha256']=sha(prior_path)
            if args.check_capture_listeners:
                from capture_listeners_guard_v51 import verify as verify_listeners
                _,listener_text=call('CAPTURE_LISTENERS_V51');listeners=json.loads(listener_text)
                proof['captureListenersNativeV51']=listeners
                proof['captureListenersComparisonV51']=verify_listeners(listeners,source['sourceProbe']['fetch']['requestedVersion'])
                _,live_after_listeners=call('READLIVE');need(live_after_listeners==one,'V51_LISTENER_SOURCE_CHANGED')
            if args.check_capture_state:
                from capture_state_guard_v52 import verify as verify_state
                _,state_text=call('CAPTURE_STATE_V52');capture_state=json.loads(state_text)
                proof['captureStateNativeV52']=capture_state
                proof['captureStateComparisonV52']=verify_state(capture_state,source['sourceProbe']['fetch']['requestedVersion'])
                _,live_after_state=call('READLIVE');need(live_after_state==one,'V52_STATE_SOURCE_CHANGED')
            if args.check_factory_copy:
                from factory_copy_guard_v49 import verify_start,verify_finish
                _,factory_text=call('FACTORY_COPY_V49');factory=json.loads(factory_text)
                proof['factoryCopyNativeV49']=factory
                factory_start=verify_start(factory,source['sourceProbe']['fetch']['requestedVersion'])
            if args.check_statistic_packet:
                from statistic_packet_guard_v54 import verify as verify_packet
                _,packet_text=call('STATISTIC_PACKET_V54');packet=json.loads(packet_text)
                proof['statisticPacketNativeV54']=packet
                proof['statisticPacketComparisonV54']=verify_packet(packet,source['sourceProbe']['fetch']['requestedVersion'])
                _,live_after_packet=call('READLIVE');need(live_after_packet==one,'V54_PACKET_SOURCE_CHANGED')
            if args.check_free_notification:
                from free_notification_guard_v55 import verify as verify_notification
                _,notification_text=call('FREE_NOTIFICATION_V55');notification=json.loads(notification_text)
                proof['freeNotificationNativeV55']=notification
                proof['freeNotificationComparisonV55']=verify_notification(notification,source['sourceProbe']['fetch']['requestedVersion'])
                _,live_after_notification=call('READLIVE');need(live_after_notification==one,'V55_NOTIFY_SOURCE_CHANGED')
            value_baseline=None
            if args.check_owned_value_lifetime:
                from owned_value_lifetime_guard_v67 import verify as verify_value_lifetime, ZERO_COUNTERS
                _,value_baseline_text=call('OBJECT_SNAPSHOT_V47');value_baseline=json.loads(value_baseline_text)
                need(value_baseline.get('status')=='SNAPSHOT_OBSERVED'
                    and value_baseline.get('sequence')==1 and value_baseline.get('bindingAndVersionUnchanged') is True,
                    'V67_BASELINE_REJECTED')
                _,value_start_text=call('VALUE_COPY_V67');value_start=json.loads(value_start_text)
                proof['ownedValueStartNativeV67']=value_start
                # A separate dispatch occurs after all scoped source Values have
                # left the first callback. Retained IValue identity is shared.
                call('STATUS')
                _,value_finish_text=call('VALUE_VERIFY_V67');value_finish=json.loads(value_finish_text)
                proof['ownedValueFinishNativeV67']=value_finish
                value_calls=[entry for entry in proof['calls'] if entry['command'] in ('VALUE_COPY_V67','VALUE_VERIFY_V67')]
                need(len(value_calls)==2 and value_calls[0]['operationId']!=value_calls[1]['operationId']
                    and all(entry['replayed'] is False for entry in value_calls), 'V67_DISTINCT_CALLBACKS_REQUIRED')
                need(value_start.get('status') in ('VALUE_COPY_VERIFIED','VALUE_COPY_UNVERIFIED')
                    and value_finish.get('status') in ('VALUE_LIFETIME_VERIFIED','VALUE_LIFETIME_UNVERIFIED')
                    and value_finish.get('copyClearedToOriginalEmpty') is True
                    and all(phase.get('goldControlPreserved') is True
                        and all(type(phase.get(key)) is int and phase[key]==0 for key in ZERO_COUNTERS)
                        for phase in (value_start,value_finish)), 'V67_GOLD_CONTROL_REJECTED')
                try:
                    proof['ownedValueLifetimeComparisonV67']=verify_value_lifetime(value_start,value_finish,
                        source['sourceProbe']['fetch']['requestedVersion'])
                    proof['ownedValueLifetimeVerifiedV67']=True
                except ValueError as error:
                    proof['ownedValueLifetimeVerifiedV67']=False
                    proof['ownedValueLifetimeFailureV67']=str(error)
                _,live_after_value=call('READLIVE');need(live_after_value==one,'V67_GOLD_SOURCE_CHANGED')
            if args.check_owned_value_persistence and proof.get('ownedValueLifetimeVerifiedV67') is not True:
                # V67 already proved clean source and released its held copy,
                # but capability failure grants no additional native dispatch.
                proof.update(ownedValuePersistenceSkippedV68='V68_VALUE_LIFETIME_REQUIRED',
                    ownedValuePersistenceObservationVerifiedV68=False,ownedValueSerializationVerifiedV68=False)
            if args.check_owned_value_persistence and proof.get('ownedValueLifetimeVerifiedV67') is True:
                from owned_value_persistence_guard_v68 import verify as verify_value_persistence, ZERO_COUNTERS as V68_ZERO
                _,value_persist_text=call('VALUE_PERSIST_V68');value_persist=json.loads(value_persist_text)
                proof['ownedValuePersistenceNativeV68']=value_persist
                need(value_persist.get('status') in ('VALUE_PERSIST_OBSERVED','VALUE_PERSIST_UNAVAILABLE','VALUE_PERSIST_UNVERIFIED')
                    and value_persist.get('goldControlPreserved') is True
                    and value_persist.get('sourceIValueUnchanged') is True
                    and value_persist.get('sourceScopeExited') is True
                    and all(type(value_persist.get(k)) is int and value_persist[k]==0 for k in V68_ZERO),
                    'V68_GOLD_CONTROL_REJECTED')
                try:
                    proof['ownedValuePersistenceComparisonV68']=verify_value_persistence(value_persist,
                        source['sourceProbe']['fetch']['requestedVersion'],
                        lambda name:contained(session/name,session).read_bytes())
                    proof['ownedValuePersistenceObservationVerifiedV68']=True
                    proof['ownedValueSerializationVerifiedV68']=proof['ownedValuePersistenceComparisonV68']['serializationVerified']
                except ValueError as error:
                    proof['ownedValuePersistenceObservationVerifiedV68']=False
                    proof['ownedValueSerializationVerifiedV68']=False
                    proof['ownedValuePersistenceFailureV68']=str(error)
                _,live_after_persist=call('READLIVE');need(live_after_persist==one,'V68_GOLD_SOURCE_CHANGED')
            if args.check_processing_form_descriptor and proof.get('ownedValueLifetimeVerifiedV67') is not True:
                proof.update(processingFormSkippedV69='V69_VALUE_LIFETIME_REQUIRED',
                    processingFormObservationVerifiedV69=False,processingFormDescriptorCloneVerifiedV69=False)
            if args.check_processing_form_descriptor and proof.get('ownedValueLifetimeVerifiedV67') is True:
                from processing_form_guard_v69 import verify as verify_processing_form, ZERO_COUNTERS as V69_ZERO
                _,form_text=call('PROCESSING_FORM_V69');form=json.loads(form_text)
                proof['processingFormNativeV69']=form
                need(form.get('status') in ('PROCESSING_FORM_DESCRIPTOR_VERIFIED','PROCESSING_FORM_CLONE_UNAVAILABLE','PROCESSING_FORM_CLONE_UNVERIFIED')
                    and form.get('sourceControlPreserved') is True and form.get('sourceDescriptorUnchanged') is True
                    and form.get('ownScopeExited') is True and form.get('exception') is False
                    and all(type(form.get(k)) is int and form[k]==0 for k in V69_ZERO), 'V69_GOLD_CONTROL_REJECTED')
                try:
                    proof['processingFormComparisonV69']=verify_processing_form(form,source['sourceProbe']['fetch']['requestedVersion'])
                    proof['processingFormObservationVerifiedV69']=True
                    proof['processingFormDescriptorCloneVerifiedV69']=proof['processingFormComparisonV69']['descriptorCloneVerified']
                except ValueError as error:
                    proof.update(processingFormObservationVerifiedV69=False,processingFormDescriptorCloneVerifiedV69=False,
                        processingFormFailureV69=str(error))
                _,live_after_form=call('READLIVE');need(live_after_form==one,'V69_GOLD_SOURCE_CHANGED')
            if args.check_owned_persistence:
                from owned_persistence_guard_v71 import verify as verify_own_persistence
                if value_baseline is None:
                    _,own_baseline_text=call('OBJECT_SNAPSHOT_V47');value_baseline=json.loads(own_baseline_text)
                    need(value_baseline.get('status')=='SNAPSHOT_OBSERVED' and value_baseline.get('sequence')==1
                        and value_baseline.get('bindingAndVersionUnchanged') is True,'V71_BASELINE_REJECTED')
                _,own_persistence_text=call('OWN_PERSISTENCE_V71');own_persistence=json.loads(own_persistence_text)
                proof['ownedPersistenceNativeV71']=own_persistence
                need(own_persistence.get('status') in ('OWN_PERSISTENCE_ROUNDTRIP_VERIFIED','OWN_PERSISTENCE_ROUNDTRIP_UNVERIFIED')
                    and own_persistence.get('sourceControlPreserved') is True and own_persistence.get('nativeException') is False
                    and own_persistence.get('lifecycle',{}).get('afterScopeExit') is True,'V71_GOLD_CONTROL_REJECTED')
                try:
                    proof['ownedPersistenceComparisonV71']=verify_own_persistence(own_persistence,
                        source['sourceProbe']['fetch']['requestedVersion'],lambda name:contained(session/name,session).read_bytes())
                    proof['ownedPersistenceRoundTripVerifiedV71']=True
                except ValueError as error:
                    proof['ownedPersistenceRoundTripVerifiedV71']=False;proof['ownedPersistenceFailureV71']=str(error)
                _,live_after_own=call('READLIVE');need(live_after_own==one,'V71_GOLD_SOURCE_CHANGED')
                # V48 is intentionally single-use and its files are CreateNew.
                # Full post-module control belongs in a fresh readonly runtime;
                # do not replay the native own trial to repair this harness.
                proof['postDocumentModulesVerifiedV71']=False
                proof['postDocumentModulesFreshReadOnlyRequiredV71']=True
            if args.check_owned_form_type:
                from managed_form_type_guard_v72 import verify as verify_own_form_type,PHASES,ZERO_COUNTERS,marker_filename,_marker
                _,type_baseline_text=call('OBJECT_SNAPSHOT_V47');value_baseline=json.loads(type_baseline_text)
                need(value_baseline.get('status')=='SNAPSHOT_OBSERVED' and value_baseline.get('sequence')==1
                    and value_baseline.get('bindingAndVersionUnchanged') is True,'V72_BASELINE_REJECTED')
                _,form_type_text=call('OWN_FORM_TYPE_V72');form_type=json.loads(form_type_text)
                proof['ownedFormTypeNativeV72']=form_type
                need(form_type.get('status') in ('OWN_FORM_TYPE_VERIFIED','OWN_FORM_TYPE_UNVERIFIED')
                    and form_type.get('sourceControlPreserved') is True and form_type.get('sourceValueUnchanged') is True
                    and type(form_type.get('nativeException')) is bool
                    and all(type(form_type.get(key)) is int and form_type[key]==0 for key in ZERO_COUNTERS)
                    and form_type.get('lifecycle',{}).get('afterScopeExit') is True,'V72_GOLD_CONTROL_REJECTED')
                # A caught own-object exception may be safely closed after its
                # scope exits and exact Gold controls hold. It never becomes a
                # verified type transition: the strict guard still rejects it.
                marker_bodies={}
                for phase in PHASES:
                    name=marker_filename(phase)
                    if contained(session/name,session).exists():
                        marker_bodies[name]=read_owned_form_marker_v72(session,name)
                        _marker(lambda filename:marker_bodies[filename],phase)
                proof['ownedFormTypeMarkerReceiptsV72']={phase:json.loads(marker_bodies[marker_filename(phase)].decode('utf-8')) for phase in PHASES if marker_filename(phase) in marker_bodies}
                proof['ownedFormTypeMarkerSha256V72']={phase:hashlib.sha256(marker_bodies[marker_filename(phase)]).hexdigest() for phase in PHASES if marker_filename(phase) in marker_bodies}
                try:
                    proof['ownedFormTypeComparisonV72']=verify_own_form_type(form_type,
                        source['sourceProbe']['fetch']['requestedVersion'],lambda name:marker_bodies[name])
                    proof['ownedFormTypeVerifiedV72']=True
                except ValueError as error:
                    proof['ownedFormTypeVerifiedV72']=False;proof['ownedFormTypeFailureV72']=str(error)
                _,live_after_type=call('READLIVE');need(live_after_type==one,'V72_GOLD_SOURCE_CHANGED')
                proof['postDocumentModulesVerifiedV72']=False
                proof['postDocumentModulesFreshReadOnlyRequiredV72']=True
            if args.check_owned_form_type_v74:
                from managed_form_type_guard_v74 import verify as verify_own_form_type,PHASES,ZERO_COUNTERS,marker_filename,_marker,REGISTRY_FILENAME,_registry
                _,type_baseline_text=call('OBJECT_SNAPSHOT_V47');value_baseline=json.loads(type_baseline_text)
                need(value_baseline.get('status')=='SNAPSHOT_OBSERVED' and value_baseline.get('sequence')==1
                    and value_baseline.get('bindingAndVersionUnchanged') is True,'V74_BASELINE_REJECTED')
                _,form_type_text=call('OWN_FORM_TYPE_V74');form_type=json.loads(form_type_text)
                proof['ownedFormTypeNativeV74']=form_type
                need(form_type.get('status') in ('OWN_FORM_TYPE_VERIFIED_V74','OWN_FORM_TYPE_UNVERIFIED_V74')
                    and form_type.get('sourceControlPreserved') is True and form_type.get('sourceValueUnchanged') is True
                    and type(form_type.get('nativeException')) is bool
                    and all(type(form_type.get(key)) is int and form_type[key]==0 for key in ZERO_COUNTERS)
                    and form_type.get('lifecycle',{}).get('afterScopeExit') is True,'V74_GOLD_CONTROL_REJECTED')
                # A caught own-object exception may be safely closed after its
                # scope exits and exact Gold controls hold. It never becomes a
                # verified type transition: the strict guard still rejects it.
                marker_bodies={}
                for phase in PHASES:
                    name=marker_filename(phase)
                    if contained(session/name,session).exists():
                        marker_bodies[name]=read_owned_form_marker_v74(session,name)
                        _marker(lambda filename:marker_bodies[filename],phase)
                proof['ownedFormTypeMarkerReceiptsV74']={phase:json.loads(marker_bodies[marker_filename(phase)].decode('utf-8')) for phase in PHASES if marker_filename(phase) in marker_bodies}
                proof['ownedFormTypeMarkerSha256V74']={phase:hashlib.sha256(marker_bodies[marker_filename(phase)]).hexdigest() for phase in PHASES if marker_filename(phase) in marker_bodies}
                if contained(session/REGISTRY_FILENAME,session).exists():
                    registry_body=read_owned_form_marker_v74(session,REGISTRY_FILENAME)
                    marker_bodies[REGISTRY_FILENAME]=registry_body
                    _registry(lambda name:marker_bodies[name],form_type)
                    proof['ownedFormTypeRegistryReceiptV74']=json.loads(registry_body.decode('utf-8'))
                    proof['ownedFormTypeRegistrySha256V74']=hashlib.sha256(registry_body).hexdigest()
                try:
                    proof['ownedFormTypeComparisonV74']=verify_own_form_type(form_type,
                        source['sourceProbe']['fetch']['requestedVersion'],lambda name:marker_bodies[name])
                    proof['ownedFormTypeVerifiedV74']=True
                except ValueError as error:
                    proof['ownedFormTypeVerifiedV74']=False;proof['ownedFormTypeFailureV74']=str(error)
                _,live_after_type=call('READLIVE');need(live_after_type==one,'V74_GOLD_SOURCE_CHANGED')
                proof['postDocumentModulesVerifiedV74']=False
                proof['postDocumentModulesFreshReadOnlyRequiredV74']=True
            if args.check_managed_body_factory_v78:
                from managed_body_factory_guard_v78 import verify as verify_managed_body_factory,parse_result,PHASES,ZERO_COUNTERS,marker_filename,_marker
                _,factory_baseline_text=call('OBJECT_SNAPSHOT_V47');value_baseline=json.loads(factory_baseline_text)
                need(value_baseline.get('status')=='SNAPSHOT_OBSERVED' and value_baseline.get('sequence')==1
                    and value_baseline.get('bindingAndVersionUnchanged') is True,'V78_BASELINE_REJECTED')
                _,factory_text=call('MANAGED_BODY_FACTORY_V78');factory=parse_result(factory_text)
                proof['managedBodyFactoryNativeV78']=factory
                need(factory.get('status') in ('MANAGED_BODY_FACTORY_OBSERVED_V78','MANAGED_BODY_FACTORY_UNVERIFIED_V78')
                    and factory.get('sourceControlPreserved') is True and factory.get('sourceValueUnchanged') is True
                    and factory.get('nativeException') is False and factory.get('returnUnknown') is False
                    and all(type(factory.get(key)) is int and factory[key]==0 for key in ZERO_COUNTERS),'V78_GOLD_CONTROL_REJECTED')
                # Observation may verify an unavailable factory. Every source/
                # scope receipt is still mandatory before readonly host closure.
                markers={}
                for phase in PHASES:
                    name=marker_filename(phase)
                    markers[name]=read_managed_body_factory_marker_v78(session,name)
                    _marker(lambda filename:markers[filename],phase)
                proof['managedBodyFactoryComparisonV78']=verify_managed_body_factory(factory,
                    source['sourceProbe']['fetch']['requestedVersion'],lambda name:markers[name])
                proof['managedBodyFactoryObservationVerifiedV78']=True
                proof['managedBodyFactoryVerifiedV78']=factory['bodyFactoryVerified']
                proof['managedBodyFactoryMarkerReceiptsV78']={phase:json.loads(markers[marker_filename(phase)].decode('utf-8')) for phase in PHASES}
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v78-managed-body-factory-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir()
                witnesses={}
                for name,body in markers.items():
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:
                        stream.write(body);stream.flush();os.fsync(stream.fileno())
                    witnesses[name]=dict(path=str(destination.relative_to(ROOT)),bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
                proof['managedBodyFactoryWitnessesV78']=witnesses
                _,live_after_factory_observation=call('READLIVE');need(live_after_factory_observation==one,'V78_GOLD_SOURCE_CHANGED')
                proof['postDocumentModulesVerifiedV78']=False
                proof['postDocumentModulesFreshReadOnlyRequiredV78']=True
            if args.check_managed_body_module_v79:
                from managed_body_module_guard_v79 import verify as verify_managed_body_module,parse_result,PHASES,ZERO_COUNTERS,marker_filename,_marker
                _,factory_baseline_text=call('OBJECT_SNAPSHOT_V47');value_baseline=json.loads(factory_baseline_text)
                need(value_baseline.get('status')=='SNAPSHOT_OBSERVED' and value_baseline.get('sequence')==1
                    and value_baseline.get('bindingAndVersionUnchanged') is True,'V79_BASELINE_REJECTED')
                _,factory_text=call('MANAGED_BODY_MODULE_V79');factory=parse_result(factory_text)
                proof['managedBodyModuleNativeV79']=factory
                need(factory.get('status') in ('MANAGED_BODY_MODULE_OBSERVED_V79','MANAGED_BODY_MODULE_UNVERIFIED_V79')
                    and factory.get('sourceControlPreserved') is True and factory.get('sourceValueUnchanged') is True
                    and factory.get('nativeException') is False and factory.get('returnUnknown') is False
                    and all(type(factory.get(key)) is int and factory[key]==0 for key in ZERO_COUNTERS),'V79_GOLD_CONTROL_REJECTED')
                # Observation may verify an unavailable factory. Every source/
                # scope receipt is still mandatory before readonly host closure.
                markers={}
                for phase in PHASES:
                    name=marker_filename(phase)
                    markers[name]=read_managed_body_module_marker_v79(session,name)
                    _marker(lambda filename:markers[filename],phase)
                proof['managedBodyModuleComparisonV79']=verify_managed_body_module(factory,
                    source['sourceProbe']['fetch']['requestedVersion'],lambda name:markers[name])
                proof['managedBodyModuleObservationVerifiedV79']=True
                proof['managedBodyModuleFactoryVerifiedV79']=factory['bodyFactoryVerified']
                proof['managedBodyModuleVerifiedV79']=factory['moduleVerified']
                proof['managedBodyModuleMarkerReceiptsV79']={phase:json.loads(markers[marker_filename(phase)].decode('utf-8')) for phase in PHASES}
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v79-managed-body-module-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir()
                witnesses={}
                for name,body in markers.items():
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:
                        stream.write(body);stream.flush();os.fsync(stream.fileno())
                    witnesses[name]=dict(path=str(destination.relative_to(ROOT)),bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
                proof['managedBodyModuleWitnessesV79']=witnesses
                _,live_after_factory_observation=call('READLIVE');need(live_after_factory_observation==one,'V79_GOLD_SOURCE_CHANGED')
                proof['postDocumentModulesVerifiedV79']=False
                proof['postDocumentModulesFreshReadOnlyRequiredV79']=True
            if args.check_owned_constant_v77:
                from owned_constant_guard_v77 import verify as verify_owned_constant,parse_result,PHASES,TERMINAL_PHASES,ZERO_COUNTERS,marker_filename,REGISTRY_FILENAME
                _,constant_baseline_text=call('OBJECT_SNAPSHOT_V47');value_baseline=json.loads(constant_baseline_text)
                need(value_baseline.get('status')=='SNAPSHOT_OBSERVED' and value_baseline.get('sequence')==1
                    and value_baseline.get('bindingAndVersionUnchanged') is True,'V77_BASELINE_REJECTED')
                _,constant_text=call('OWN_CONSTANT_V77');constant=parse_result(constant_text)
                proof['ownedConstantNativeV77']=constant
                need(constant.get('status') in ('OWN_CONSTANT_VERIFIED_V77','OWN_CONSTANT_UNVERIFIED_V77')
                    and constant.get('sourceControlPreserved') is True and constant.get('sourceValueUnchanged') is True
                    and constant.get('nativeException') is False and constant.get('returnUnknown') is False
                    and all(type(constant.get(key)) is int and constant[key]==0 for key in ZERO_COUNTERS),'V77_GOLD_CONTROL_REJECTED')
                # Even a known capability refusal needs four physical terminal
                # receipts and the strict complete result schema before closure.
                phases=PHASES if constant['status']=='OWN_CONSTANT_VERIFIED_V77' else TERMINAL_PHASES
                names=[marker_filename(phase) for phase in phases]
                if constant['status']=='OWN_CONSTANT_VERIFIED_V77':names.append(REGISTRY_FILENAME)
                markers={name:read_owned_constant_marker_v77(session,name) for name in names}
                proof['ownedConstantComparisonV77']=verify_owned_constant(constant,
                    source['sourceProbe']['fetch']['requestedVersion'],lambda name:markers[name])
                proof['ownedConstantVerifiedV77']=constant['ownConstantVerified']
                proof['ownedConstantSourceObservationVerifiedV77']=True
                proof['ownedConstantSafeFailureCloseV77']=proof['ownedConstantComparisonV77']['safeFailureClose']
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v77-owned-constant-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir()
                witnesses={}
                for name,body in markers.items():
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:
                        stream.write(body);stream.flush();os.fsync(stream.fileno())
                    witnesses[name]=dict(path=str(destination.relative_to(ROOT)),bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
                proof['ownedConstantWitnessesV77']=witnesses
                _,live_after_constant=call('READLIVE');need(live_after_constant==one,'V77_GOLD_SOURCE_CHANGED')
                proof['postDocumentModulesVerifiedV77']=False
                proof['postDocumentModulesFreshReadOnlyRequiredV77']=True
            if args.check_owned_managed_form_v75:
                from owned_managed_form_guard_v75 import verify as verify_own_managed_form,parse_result,prewrite_gate,PHASES,ZERO_COUNTERS,marker_filename,_marker,REGISTRY_FILENAME,_registry,BODY_FILENAME
                _,form_baseline_text=call('OBJECT_SNAPSHOT_V47');value_baseline=json.loads(form_baseline_text)
                need(value_baseline.get('status')=='SNAPSHOT_OBSERVED' and value_baseline.get('sequence')==1
                    and value_baseline.get('bindingAndVersionUnchanged') is True,'V75_BASELINE_REJECTED')
                _,managed_form_text=call('OWN_MANAGED_FORM_V75');managed_form=parse_result(managed_form_text)
                proof['ownedManagedFormPrewriteGateV75']=prewrite_gate(managed_form['body'])
                proof['ownedManagedFormNativeV75']=managed_form
                need(managed_form.get('status') in ('OWN_MANAGED_FORM_VERIFIED_V75','OWN_MANAGED_FORM_UNVERIFIED_V75')
                    and managed_form.get('sourceControlPreserved') is True and managed_form.get('sourceValueUnchanged') is True
                    and managed_form.get('nativeException') is False and managed_form.get('returnUnknown') is False
                    and all(type(managed_form.get(key)) is int and managed_form[key]==0 for key in ZERO_COUNTERS)
                    and managed_form.get('lifecycle',{}).get('afterScopeExit') is True,'V75_GOLD_CONTROL_REJECTED')
                # Readonly host closure is independent of capability success.
                # Only the own inert form-body resource may be retained here.
                marker_bodies={};binary_bodies={};binary_failures={}
                for phase in PHASES:
                    name=marker_filename(phase)
                    if contained(session/name,session).exists():
                        marker_bodies[name]=read_owned_form_marker_v75(session,name)
                        _marker(lambda filename:marker_bodies[filename],phase)
                proof['ownedManagedFormMarkerReceiptsV75']={phase:json.loads(marker_bodies[marker_filename(phase)].decode('utf-8')) for phase in PHASES if marker_filename(phase) in marker_bodies}
                proof['ownedManagedFormMarkerSha256V75']={phase:hashlib.sha256(marker_bodies[marker_filename(phase)]).hexdigest() for phase in PHASES if marker_filename(phase) in marker_bodies}
                proof['ownedManagedFormTerminalV75']=owned_form_terminal_v75(marker_bodies)
                if contained(session/REGISTRY_FILENAME,session).exists():
                    registry_body=read_owned_form_marker_v75(session,REGISTRY_FILENAME)
                    marker_bodies[REGISTRY_FILENAME]=registry_body
                    _registry(lambda name:marker_bodies[name],managed_form)
                    proof['ownedManagedFormRegistryReceiptV75']=json.loads(registry_body.decode('utf-8'))
                    proof['ownedManagedFormRegistrySha256V75']=hashlib.sha256(registry_body).hexdigest()
                try:binary_bodies[BODY_FILENAME]=read_owned_form_binary_v75(session,BODY_FILENAME)
                except ValueError as error:binary_failures[BODY_FILENAME]=str(error)
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v75-own-managed-form-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir()
                witnesses={}
                for name,body in (marker_bodies|binary_bodies).items():
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:
                        stream.write(body);stream.flush();os.fsync(stream.fileno())
                    witnesses[name]=dict(path=str(destination.relative_to(ROOT)),bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
                proof['ownedManagedFormWitnessesV75']=witnesses
                proof['ownedManagedFormBinaryFailuresV75']=binary_failures
                try:
                    proof['ownedManagedFormComparisonV75']=verify_own_managed_form(managed_form,
                        source['sourceProbe']['fetch']['requestedVersion'],lambda name:marker_bodies[name],lambda name:binary_bodies[name])
                    proof['ownedManagedFormVerifiedV75']=True
                except ValueError as error:
                    proof['ownedManagedFormVerifiedV75']=False;proof['ownedManagedFormFailureV75']=str(error)
                _,live_after_form=call('READLIVE');need(live_after_form==one,'V75_GOLD_SOURCE_CHANGED')
                proof['postDocumentModulesVerifiedV75']=False
                proof['postDocumentModulesFreshReadOnlyRequiredV75']=True
            if args.check_owned_managed_body_v73:
                from owned_managed_body_guard_v73 import verify as verify_own_managed_body,PHASES,ZERO_COUNTERS,marker_filename,_marker,REGISTRY_FILENAME,_registry,BINARY_FILENAMES
                _,body_baseline_text=call('OBJECT_SNAPSHOT_V47');value_baseline=json.loads(body_baseline_text)
                need(value_baseline.get('status')=='SNAPSHOT_OBSERVED' and value_baseline.get('sequence')==1
                    and value_baseline.get('bindingAndVersionUnchanged') is True,'V73_BASELINE_REJECTED')
                _,managed_body_text=call('OWN_MANAGED_BODY_V73');managed_body=json.loads(managed_body_text)
                proof['ownedManagedBodyNativeV73']=managed_body
                need(managed_body.get('status') in ('OWN_MANAGED_BODY_VERIFIED','OWN_MANAGED_BODY_UNVERIFIED')
                    and managed_body.get('sourceControlPreserved') is True and managed_body.get('sourceValueUnchanged') is True
                    and type(managed_body.get('nativeException')) is bool
                    and all(type(managed_body.get(key)) is int and managed_body[key]==0 for key in ZERO_COUNTERS)
                    and managed_body.get('lifecycle',{}).get('afterScopeExit') is True,'V73_GOLD_CONTROL_REJECTED')
                # Safe host closure after an own-object refusal is independent
                # of capability success, which requires physical CF witnesses.
                marker_bodies={};binary_bodies={};binary_failures={}
                for phase in PHASES:
                    name=marker_filename(phase)
                    if contained(session/name,session).exists():
                        marker_bodies[name]=read_owned_form_marker_v73(session,name)
                        _marker(lambda filename:marker_bodies[filename],phase)
                proof['ownedManagedBodyMarkerReceiptsV73']={phase:json.loads(marker_bodies[marker_filename(phase)].decode('utf-8')) for phase in PHASES if marker_filename(phase) in marker_bodies}
                proof['ownedManagedBodyMarkerSha256V73']={phase:hashlib.sha256(marker_bodies[marker_filename(phase)]).hexdigest() for phase in PHASES if marker_filename(phase) in marker_bodies}
                if contained(session/REGISTRY_FILENAME,session).exists():
                    registry_body=read_owned_form_marker_v73(session,REGISTRY_FILENAME)
                    marker_bodies[REGISTRY_FILENAME]=registry_body
                    _registry(lambda name:marker_bodies[name],managed_body)
                    proof['ownedManagedBodyRegistryReceiptV73']=json.loads(registry_body.decode('utf-8'))
                    proof['ownedManagedBodyRegistrySha256V73']=hashlib.sha256(registry_body).hexdigest()
                for name in BINARY_FILENAMES:
                    try:binary_bodies[name]=read_owned_form_binary_v73(session,name)
                    except ValueError as error:binary_failures[name]=str(error)
                # Retain only these own fixed witnesses for later independent
                # verification. Runtime removal must not erase the CF proof.
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v73-own-managed-body-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir()
                witnesses={}
                for name,body in (marker_bodies|binary_bodies).items():
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:
                        stream.write(body);stream.flush();os.fsync(stream.fileno())
                    witnesses[name]=dict(path=str(destination.relative_to(ROOT)),bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
                proof['ownedManagedBodyWitnessesV73']=witnesses
                proof['ownedManagedBodyBinaryFailuresV73']=binary_failures
                try:
                    proof['ownedManagedBodyComparisonV73']=verify_own_managed_body(managed_body,
                        source['sourceProbe']['fetch']['requestedVersion'],lambda name:marker_bodies[name],lambda name:binary_bodies[name])
                    proof['ownedManagedBodyVerifiedV73']=True
                except ValueError as error:
                    proof['ownedManagedBodyVerifiedV73']=False;proof['ownedManagedBodyFailureV73']=str(error)
                _,live_after_body=call('READLIVE');need(live_after_body==one,'V73_GOLD_SOURCE_CHANGED')
                proof['postDocumentModulesVerifiedV73']=False
                proof['postDocumentModulesFreshReadOnlyRequiredV73']=True
            if args.check_object_snapshot or args.compare_repository_object:
                snapshots=[]
                for sequence in (1,2):
                    if sequence==1 and value_baseline is not None:snap=value_baseline
                    else:
                        _,body=call('OBJECT_SNAPSHOT_V47');snap=json.loads(body)
                    snapshots.append(snap)
                    need(snap.get('status') in ('SNAPSHOT_OBSERVED','SERIALIZER_UNAVAILABLE')
                        and snap.get('bindingAndVersionUnchanged') is True and snap.get('sequence')==sequence
                        and snap.get('sourceWrites')==0 and snap.get('repositoryWrites')==0 and snap.get('goldSaves')==0,
                        'V47_SNAPSHOT_DIAGNOSIS_UNVERIFIED')
                    if args.check_managed_input_record_v145 and sequence==1:
                        from managed_input_record_controller_v145 import inspect_physical,terminal_ready
                        from managed_input_record_guard_v145 import parse_result as parse_managed_input_v145
                        from metadata_descriptor_codec_v47 import compare_document_profiles
                        need(snap['status']=='SNAPSHOT_OBSERVED' and proof['documentModulesComparisonV48'].get('verified')is True,'V145_FULL_BASELINE_REQUIRED')
                        baseline_file=contained(session/'object-snapshot-v47-1.bin',session)
                        baseline_compare=compare_document_profiles(baseline_file.read_bytes(),(session/'repository-object.bin').read_bytes())
                        need(all(baseline_compare.get(k)is True for k in ('verified','descriptorEqual','serializationProfilesCompatible','repositoryObjectCaptureScopeVerified')),'V145_FULL_BASELINE_REQUIRED')
                        operation=uuid.uuid4().hex;proof['managedInputRecordOperationV145']=operation
                        _,input_body=call('MANAGED_INPUT_RECORD_V145',operation)
                        native,comparison,bodies=inspect_physical(session,operation,proof['documentModulesComparisonV48']['version'])
                        need(parse_managed_input_v145(input_body.encode('utf-8'))==native,'V145_PHYSICAL_RESULT_CHANGED')
                        proof.update(managedInputRecordNativeV145=native,managedInputRecordComparisonV145=comparison,managedInputRecordVerifiedV145=True)
                        evidence_root=ROOT/'artifacts/designer-bridge';witness_dir=contained(evidence_root/('v145-managed-input-record-'+prepared['nonce']),evidence_root)
                        witness_dir.mkdir();witnesses={}
                        for name,data in bodies.items():
                            destination=contained(witness_dir/name,witness_dir)
                            with destination.open('xb')as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
                            witnesses[name]=dict(path=str(destination),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
                        proof['managedInputRecordWitnessesV145']=witnesses
                        _,input_after=call('READLIVE');need(input_after==one,'V145_FOREIGN_SOURCE_CHANGED')
                probe=dict(observations=snapshots,serializerAvailable=snapshots[0]['serializerAvailable'],objectDescriptorSnapshotVerified=False,
                    externalResourceBodiesIncluded=False,persistedGoldReadbackVerified=False)
                if snapshots[0]['status']=='SNAPSHOT_OBSERVED':
                    need(snapshots[1]['status']=='SNAPSHOT_OBSERVED','V47_SERIALIZER_STATE_CHANGED')
                    left,right=(contained(session/('object-snapshot-v47-'+str(n)+'.bin'),session) for n in (1,2))
                    need(left.read_bytes()==right.read_bytes() and left.stat().st_size==snapshots[0]['bytes']
                        and right.stat().st_size==snapshots[1]['bytes'],'V47_OBJECT_STREAM_CHANGED')
                    probe.update(objectDescriptorSnapshotVerified=True,bytes=left.stat().st_size,sha256=sha(left))
                    if args.compare_repository_object:
                        from metadata_descriptor_codec_v47 import compare_document_profiles
                        from native_source_codec import decode_module_packet
                        probe['repositoryComparison']=compare_document_profiles(left.read_bytes(),(session/'repository-object.bin').read_bytes())
                        probe['objectModuleComparison']=decode_module_packet((session/'repository-module.bin').read_bytes()).summary(one)
                proof['objectSnapshotV47']=probe
                if args.check_managed_input_record_v145:
                    need(probe['objectDescriptorSnapshotVerified']is True,'V145_POST_DESCRIPTOR_REQUIRED')
                    proof.update(managedInputPostDescriptorSequenceV145=2,managedInputPostDescriptorSha256V145=sha(right),managedInputPostDescriptorBytesV145=right.stat().st_size)
                _,live_after=call('READLIVE');need(live_after==one,'V47_SERIALIZE_CHANGED_SOURCE')
            if args.check_compact_owner_v108 or args.check_stock_selection_inventory_v106 or args.check_owned_empty_class_inventory_v125 or args.check_metadata_receivers_v126:
                from completed_gold_own_module_v82 import _document_control
                _document_control(proof)  # Complete module and descriptor baseline, before diagnostics.
            if args.check_compact_owner_v108:
                from compact_owner_guard_v108 import parse_result as parse_compact_v108,verify as check_compact_v108
                _,body=call('COMPACT_OWNER_V108');native=parse_compact_v108(body)
                comparison=check_compact_v108(native,proof['documentModulesComparisonV48']['version'])
                # The strict verifier rejects unknown/exception/invalid results.
                # A known unsupported binding is still a clean readonly result;
                # record capability=false and complete preservation/close checks.
                proof.update(compactOwnerNativeV108=native,compactOwnerComparisonV108=comparison,
                    compactOwnerVerifiedV108=comparison['compactOwnerVerified'])
                _,after=call('READLIVE');need(after==one,'V108_FOREIGN_SOURCE_CHANGED')
            if args.check_stock_selection_inventory_v106:
                from stock_selection_inventory_guard_v106 import parse_result as parse_inventory_v106,verify as check_inventory_v106
                _,body=call('STOCK_SELECTION_INVENTORY_V106');native=parse_inventory_v106(body)
                comparison=check_inventory_v106(native,proof['documentModulesComparisonV48']['version'])
                need(comparison.get('verified') is True,'V106_INVENTORY_OBSERVATION_REJECTED')
                proof.update(stockSelectionInventoryNativeV106=native,stockSelectionInventoryComparisonV106=comparison)
                _,after=call('READLIVE');need(after==one,'V106_FOREIGN_SOURCE_CHANGED')
            if args.check_owned_empty_class_inventory_v125:
                from owned_empty_class_inventory_guard_v125 import parse_result as parse_empty_class_v125,verify as check_empty_class_v125
                _,body=call('EMPTY_CLASS_INVENTORY_V125');native=parse_empty_class_v125(body.encode('utf-8'))
                comparison=check_empty_class_v125(native,proof['documentModulesComparisonV48']['version'])
                # A bounded missing class is a known readonly observation, not
                # a factory capability. Unknown/exception/bad scope still raise.
                proof.update(ownedEmptyClassInventoryNativeV125=native,ownedEmptyClassInventoryComparisonV125=comparison,
                    ownedEmptyClassInventoryVerifiedV125=comparison['verified'])
                _,after=call('READLIVE');need(after==one,'V125_FOREIGN_SOURCE_CHANGED')
            if args.check_metadata_receivers_v126:
                from metadata_receivers_guard_v126 import parse_result as parse_metadata_receivers_v126,verify as check_metadata_receivers_v126
                _,body=call('METADATA_RECEIVER_INVENTORY_V126')
                payload=body.encode('utf-8') if type(body) is str else body
                native=parse_metadata_receivers_v126(payload)
                comparison=check_metadata_receivers_v126(native,proof['documentModulesComparisonV48']['version'])
                # Missing optional template/IB remains an honest readonly
                # observation; semantic Main/DB and Save claims stay false.
                proof.update(metadataReceiversNativeV126=native,metadataReceiversComparisonV126=comparison,
                    metadataReceiversObservedV126=comparison['receiverInventoryObserved'])
                _,after=call('READLIVE');need(after==one,'V126_FOREIGN_SOURCE_CHANGED')
            if args.check_factory_copy:
                call('STATUS')
                _,finish_text=call('FACTORY_VERIFY_V49');finish=json.loads(finish_text)
                proof['factoryLifetimeNativeV49']=finish
                proof['factoryCopyComparisonV49']=verify_finish(factory_start,finish)
                _,live_after_factory=call('READLIVE');need(live_after_factory==one,'V49_FACTORY_SOURCE_CHANGED')
            if args.check_detached_text_undo:
                from detached_text_undo_guard_v63 import verify as verify_detached_undo
                _,detached_text=call('DETACHED_TEXT_UNDO_V63');detached=json.loads(detached_text)
                proof['detachedTextUndoNativeV63']=detached
                # The host may safely close after a failed scratch capability;
                # never equate that host PASS with actual IDocument restoration.
                need(detached.get('status') in ('DETACHED_UNDO_VERIFIED','DETACHED_UNDO_UNVERIFIED')
                    and detached.get('goldControlPreserved') is True
                    and all(type(detached.get(k)) is int and detached[k]==0 for k in
                        ('goldSourceWrites','repositoryWrites','saveCalls','dirtyFlagWrites','databaseUpdates','businessCalls')),
                    'V63_GOLD_CONTROL_REJECTED')
                try:
                    proof['detachedTextUndoComparisonV63']=verify_detached_undo(detached,source['sourceProbe']['fetch']['requestedVersion'])
                    proof['detachedTextUndoVerifiedV63']=True
                except ValueError as error:
                    proof['detachedTextUndoVerifiedV63']=False
                    proof['detachedTextUndoFailureV63']=str(error)
                _,live_after_undo=call('READLIVE');need(live_after_undo==one,'V63_GOLD_SOURCE_CHANGED')
            if args.check_disconnect:
                peer=subprocess.Popen([str(shell),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(HERE/'Measure-PipeDisconnectV45.ps1'),
                    '-ConnectionFile',str(session/'command-connection.json'),'-ExpectedSha256',proof['liveTextSha256']],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                peer_caller=parent_identity(peer);durable_new(controller/'disconnect-caller.json',peer_caller)
                peer_stdout,_=peer.communicate(timeout=20)
                need(peer.returncode==0,'V45_DISCONNECT_CONTROL_FAILED')
                dropped=json.loads(peer_stdout.decode('utf-8-sig'))
                need(dropped['passed'] is True and dropped['syncWriteDisconnectBranchVerified'] is True
                    and dropped['exactReplays']>0 and dropped['processId']==native_identity[0]
                    and dropped['birth']==native_identity[1] and owned_process_gone(peer_caller['pid'],peer_caller['birth']),
                    'V45_SYNC_DISCONNECT_NOT_EXERCISED')
                proof.update(disconnectControl=dropped,disconnectCaller=peer_caller)
            if args.check_gold_own_object_module_v78:
                from gold_own_object_module_guard_v78 import (parse_result as parse_gold_own_module_v78,
                    verify as verify_gold_own_module_v78,PHASES,TERMINAL_PHASES,REGISTRY_FILENAME,RESULT_FILENAME,marker_filename)
                operation=uuid.uuid4().hex
                # A dispatched mutation with no verified result remains unknown.
                proof['goldConfigurationWrites']=None
                proof['goldOwnObjectModuleOperationV78']=operation
                _,module_text=call('GOLD_OWN_OBJECT_MODULE_V78',operation)
                native=parse_gold_own_module_v78(module_text)
                proof['goldOwnObjectModuleNativeV78']=native
                need(native['operationId']==operation,'GOM78_OPERATION_CHANGED')
                need(parse_gold_own_module_v78(read_gold_own_module_marker_v78(session,RESULT_FILENAME))==native,
                    'GOM78_PHYSICAL_RESULT_CHANGED')
                comparison=verify_gold_own_module_v78(native,proof['documentModulesComparisonV48']['version'],
                    lambda name:read_gold_own_module_marker_v78(session,name))
                proof.update(goldOwnObjectModuleComparisonV78=comparison,
                    goldOwnObjectModuleVerifiedV78=comparison['ownModuleUndoVerified'],goldConfigurationWrites=native['writeAttempts'],
                    postGoldFreshReadOnlyRequiredV78=True)
                phases=PHASES if comparison['ownModuleUndoVerified'] else TERMINAL_PHASES
                names=[marker_filename(phase) for phase in phases]+[RESULT_FILENAME]
                if native['attachCalls']:names.append(REGISTRY_FILENAME)
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v78-gold-own-module-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir()
                witnesses={}
                for name in names:
                    data=read_gold_own_module_marker_v78(session,name)
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:stream.write(data)
                    witnesses[name]=dict(path=str(destination),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
                proof['goldOwnObjectModuleWitnessesV78']=witnesses
                _,live_after_module=call('READLIVE');need(live_after_module==one,'GOM78_FOREIGN_SOURCE_CHANGED')
            if args.check_gold_own_object_module_v82:
                from gold_own_object_module_guard_v82 import (parse_result as parse_gold_own_module_v82,
                    verify as verify_gold_own_module_v82,PHASES,TERMINAL_PHASES,REGISTRY_FILENAME,RESULT_FILENAME,marker_filename)
                baseline=proof.get('objectSnapshotV47',{})
                descriptor=baseline.get('repositoryComparison',{})
                module=baseline.get('objectModuleComparison',{})
                need(baseline.get('objectDescriptorSnapshotVerified') is True
                    and descriptor.get('verified') is True and descriptor.get('descriptorEqual') is True
                    and descriptor.get('serializationProfilesCompatible') is True
                    and descriptor.get('repositoryObjectCaptureScopeVerified') is True
                    and module.get('normalizedLineEndingsEqual') is True
                    and module.get('liveNormalizedSha256')==module.get('sourceNormalizedSha256')==proof['liveTextSha256']
                    and proof['documentModulesComparisonV48'].get('verified') is True,
                    'GOM82_FULL_BASELINE_REQUIRED')
                operation=uuid.uuid4().hex
                # A dispatched mutation with no verified result remains unknown.
                proof['goldConfigurationWrites']=None
                proof['goldOwnObjectModuleOperationV82']=operation
                _,module_text=call('GOLD_OWN_OBJECT_MODULE_V82',operation)
                native=parse_gold_own_module_v82(module_text)
                proof['goldOwnObjectModuleNativeV82']=native
                need(native['operationId']==operation,'GOM82_OPERATION_CHANGED')
                need(parse_gold_own_module_v82(read_gold_own_module_marker_v82(session,RESULT_FILENAME))==native,
                    'GOM82_PHYSICAL_RESULT_CHANGED')
                comparison=verify_gold_own_module_v82(native,proof['documentModulesComparisonV48']['version'],
                    lambda name:read_gold_own_module_marker_v82(session,name))
                proof.update(goldOwnObjectModuleComparisonV82=comparison,
                    goldOwnObjectModuleVerifiedV82=comparison['ownModuleUndoVerified'],goldConfigurationWrites=native['writeAttempts'],
                    postGoldFreshReadOnlyRequiredV82=True)
                phases=PHASES if comparison['ownModuleUndoVerified'] else TERMINAL_PHASES
                names=[marker_filename(phase) for phase in phases]+[RESULT_FILENAME]
                if native['createdOnlyRegistryVerified']:names.append(REGISTRY_FILENAME)
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v82-gold-own-module-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir()
                witnesses={}
                for name in names:
                    data=read_gold_own_module_marker_v82(session,name)
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:stream.write(data)
                    witnesses[name]=dict(path=str(destination),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
                proof['goldOwnObjectModuleWitnessesV82']=witnesses
                # Descriptor baseline reads precede this own metadata lifecycle.
                # Attach/delete legitimately dirties the editable root, so the
                # general V47 clean gate remains unchanged. A separate fresh
                # read-only process must compare both foreign modules and the
                # descriptor after this host closes; its success is not implied.
                _,after_source=call('READLIVE');need(after_source==one,'GOM82_FOREIGN_SOURCE_CHANGED')
                proof['postGoldFreshReadOnlyVerifiedV82']=False
            if args.check_gold_owned_constant_v99:
                from gold_owned_constant_guard_v99 import (parse_result as parse_gold_constant_v99,
                    verify as verify_gold_constant_v99,PHASES,TERMINAL_PHASES,REGISTRY_FILENAME,RESULT_FILENAME,marker_filename,WRITER_PHASES)
                baseline=proof.get('objectSnapshotV47',{})
                descriptor=baseline.get('repositoryComparison',{})
                module=baseline.get('objectModuleComparison',{})
                need(baseline.get('objectDescriptorSnapshotVerified') is True
                    and descriptor.get('verified') is True and descriptor.get('descriptorEqual') is True
                    and descriptor.get('serializationProfilesCompatible') is True
                    and descriptor.get('repositoryObjectCaptureScopeVerified') is True
                    and module.get('normalizedLineEndingsEqual') is True
                    and module.get('liveNormalizedSha256')==module.get('sourceNormalizedSha256')==proof['liveTextSha256']
                    and proof['documentModulesComparisonV48'].get('verified') is True,
                    'GC99_FULL_BASELINE_REQUIRED')
                operation=uuid.uuid4().hex
                # A dispatched mutation with no verified result remains unknown.
                proof['goldConfigurationWrites']=None
                proof['goldOwnedConstantOperationV99']=operation
                _,module_text=call('GOLD_OWNED_CONSTANT_V99',operation)
                native=parse_gold_constant_v99(module_text)
                proof['goldOwnedConstantNativeV99']=native
                need(native['operationId']==operation,'GC99_OPERATION_CHANGED')
                need(parse_gold_constant_v99(read_gold_owned_constant_marker_v99(session,RESULT_FILENAME))==native,
                    'GC99_PHYSICAL_RESULT_CHANGED')
                comparison=verify_gold_constant_v99(native,proof['documentModulesComparisonV48']['version'],
                    lambda name:read_gold_owned_constant_marker_v99(session,name))
                proof.update(goldOwnedConstantComparisonV99=comparison,
                    goldOwnedConstantVerifiedV99=comparison['ownConstantVerified'],goldConfigurationWrites=native['writeAttempts'],
                    postGoldFreshReadOnlyRequiredV99=True)
                required=set(PHASES if comparison['ownConstantVerified'] else TERMINAL_PHASES)
                for counter,stage in WRITER_PHASES:
                    if native[counter]:required.update(('before'+stage,'after'+stage))
                phases=[phase for phase in PHASES if phase in required]
                names=[marker_filename(phase) for phase in phases]+[RESULT_FILENAME]
                if native['createdOnlyRegistryVerified']:names.append(REGISTRY_FILENAME)
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v99-gold-owned-constant-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir()
                witnesses={}
                for name in names:
                    data=read_gold_owned_constant_marker_v99(session,name)
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:
                        stream.write(data);stream.flush();os.fsync(stream.fileno())
                    witnesses[name]=dict(path=str(destination),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
                proof['goldOwnedConstantWitnessesV99']=witnesses
                # Descriptor baseline reads precede this own metadata lifecycle.
                # Attach/delete legitimately dirties the editable root, so the
                # general V47 clean gate remains unchanged. A separate fresh
                # read-only process must compare both foreign modules and the
                # descriptor after this host closes; its success is not implied.
                _,after_source=call('READLIVE');need(after_source==one,'GC99_FOREIGN_SOURCE_CHANGED')
                proof['postGoldFreshReadOnlyVerifiedV99']=False
            if args.check_gold_owned_full_object_module_v150:
                from completed_gold_own_module_v82 import _document_control
                from gold_owned_full_object_module_controller_v150 import inspect_physical
                from gold_owned_full_object_module_controller_v150 import terminal_ready
                from gold_owned_full_object_module_controller_v150 import parse_result as parse_gold_full_v150
                _document_control(proof)  # Complete descriptor and both foreign modules, not a partial hash.
                operation=uuid.uuid4().hex
                proof['goldConfigurationWrites']=None
                proof['goldOwnedFullObjectModuleOperationV150']=operation
                _,body=call('GOLD_OWNED_FULL_OBJECT_MODULE_V150',operation)
                native,comparison,bodies=inspect_physical(session,operation,proof['documentModulesComparisonV48']['version'])
                need(parse_gold_full_v150(body.encode('utf-8'))==native,'GD139_PHYSICAL_RESULT_CHANGED')
                proof.update(goldOwnedFullObjectModuleNativeV150=native,goldOwnedFullObjectModuleComparisonV150=comparison,
                    goldOwnedFullObjectModuleVerifiedV150=comparison['ownFullObjectModuleVerified'],goldConfigurationWrites=comparison['writeCount'],
                    postGoldFreshReadOnlyRequiredV150=True,postGoldFreshReadOnlyVerifiedV150=False)
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v150-gold-owned-full-object-module-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir();witnesses={}
                for name,data in bodies.items():
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:
                        stream.write(data);stream.flush();os.fsync(stream.fileno())
                    witnesses[name]=dict(path=str(destination),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
                proof['goldOwnedFullObjectModuleWitnessesV150']=witnesses
                _,after_source=call('READLIVE');need(after_source==one,'GD139_FOREIGN_SOURCE_CHANGED')
            if args.check_gold_owned_document_structure_v139:
                from completed_gold_own_module_v82 import _document_control
                from gold_owned_document_structure_controller_v139 import inspect_physical
                from gold_owned_document_structure_controller_v139 import terminal_ready
                from gold_owned_document_structure_guard_v139 import parse_result as parse_gold_structure_v139
                _document_control(proof)  # Complete descriptor and both foreign modules, not a partial hash.
                operation=uuid.uuid4().hex
                proof['goldConfigurationWrites']=None
                proof['goldOwnedDocumentStructureOperationV139']=operation
                _,body=call('GOLD_OWNED_DOCUMENT_STRUCTURE_V139',operation)
                native,comparison,bodies=inspect_physical(session,operation,proof['documentModulesComparisonV48']['version'])
                need(parse_gold_structure_v139(body.encode('utf-8'))==native,'GD139_PHYSICAL_RESULT_CHANGED')
                proof.update(goldOwnedDocumentStructureNativeV139=native,goldOwnedDocumentStructureComparisonV139=comparison,
                    goldOwnedDocumentStructureVerifiedV139=comparison['ownStructureVerified'],goldConfigurationWrites=comparison['writeCount'],
                    postGoldFreshReadOnlyRequiredV139=True,postGoldFreshReadOnlyVerifiedV139=False)
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v139-gold-owned-document-structure-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir();witnesses={}
                for name,data in bodies.items():
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:
                        stream.write(data);stream.flush();os.fsync(stream.fileno())
                    witnesses[name]=dict(path=str(destination),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
                proof['goldOwnedDocumentStructureWitnessesV139']=witnesses
                _,after_source=call('READLIVE');need(after_source==one,'GD139_FOREIGN_SOURCE_CHANGED')
            if args.check_gold_owned_empty_objects_v130:
                from completed_gold_own_module_v82 import _document_control
                from gold_owned_empty_objects_controller_v130 import inspect_physical
                from gold_owned_empty_objects_controller_v130 import terminal_ready
                from gold_owned_empty_objects_guard_v130 import parse_result as parse_gold_empty_v130
                _document_control(proof)  # Complete descriptor and both foreign modules, not a partial hash.
                operation=uuid.uuid4().hex
                proof['goldConfigurationWrites']=None
                proof['goldOwnedEmptyObjectsOperationV130']=operation
                _,body=call('GOLD_OWNED_EMPTY_OBJECTS_V130',operation)
                native,comparison,bodies=inspect_physical(session,operation,proof['documentModulesComparisonV48']['version'])
                need(parse_gold_empty_v130(body.encode('utf-8'))==native,'GE130_PHYSICAL_RESULT_CHANGED')
                proof.update(goldOwnedEmptyObjectsNativeV130=native,goldOwnedEmptyObjectsComparisonV130=comparison,
                    goldOwnedEmptyObjectsVerifiedV130=comparison['ownEmptyObjectsVerified'],goldConfigurationWrites=comparison['writeCount'],
                    postGoldFreshReadOnlyRequiredV130=True,postGoldFreshReadOnlyVerifiedV130=False)
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v130-gold-owned-empty-objects-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir();witnesses={}
                for name,data in bodies.items():
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:
                        stream.write(data);stream.flush();os.fsync(stream.fileno())
                    witnesses[name]=dict(path=str(destination),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
                proof['goldOwnedEmptyObjectsWitnessesV130']=witnesses
                _,after_source=call('READLIVE');need(after_source==one,'GE130_FOREIGN_SOURCE_CHANGED')
            if args.check_gold_owned_managed_form_v107:
                from completed_gold_own_module_v82 import _document_control
                from gold_owned_managed_form_controller_v116 import inspect_physical
                from gold_owned_managed_form_session_contract_v115 import terminal_ready
                from gold_owned_managed_form_guard_v107 import parse_result as parse_gold_managed_v107
                _document_control(proof)  # Complete descriptor and both foreign modules, not a partial hash.
                operation=uuid.uuid4().hex
                proof['goldConfigurationWrites']=None
                proof['goldOwnedManagedFormOperationV107']=operation
                _,body=call('GOLD_OWNED_MANAGED_FORM_V107',operation)
                native,comparison,bodies=inspect_physical(session,operation,proof['documentModulesComparisonV48']['version'])
                need(parse_gold_managed_v107(body)==native,'GM107_PHYSICAL_RESULT_CHANGED')
                proof.update(goldOwnedManagedFormNativeV107=native,goldOwnedManagedFormComparisonV107=comparison,
                    goldOwnedManagedFormVerifiedV107=comparison['ownManagedFormVerified'],goldConfigurationWrites=comparison['writeCount'],
                    goldOwnedManagedFormCapabilityFailureV107=comparison['capabilityFailureCode'],
                    postGoldFreshReadOnlyRequiredV107=True,postGoldFreshReadOnlyVerifiedV107=False)
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v107-gold-owned-managed-form-'+prepared['nonce']),evidence_root)
                witness_dir.mkdir();witnesses={}
                for name,data in bodies.items():
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:
                        stream.write(data);stream.flush();os.fsync(stream.fileno())
                    witnesses[name]=dict(path=str(destination),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
                proof['goldOwnedManagedFormWitnessesV107']=witnesses
                _,after_source=call('READLIVE');need(after_source==one,'GM107_FOREIGN_SOURCE_CHANGED')
            if args.check_capture_fresh_v81:
                from run_capture_fresh_client_v81 import run_cycle as run_capture_fresh_v81,read_file as read_capture_fresh_v81
                from capture_fresh_guard_v81 import FILENAMES,INTENT_FILENAME,PREPARE_PHASES,TERMINAL_PHASES,marker_filename
                proof['repositoryMutations']=None
                cycle=run_capture_fresh_v81(session/'command-connection.json',process_id=native_identity[0],birth=native_identity[1],
                    session_id=session.name.removeprefix('session-'),lease_owner=owner,call=call)
                proof.update(captureFreshCycleV81=cycle,captureFreshVerifiedV81=True,repositoryMutations=2,
                    goldConfigurationWrites=0,postGoldFreshReadOnlyRequiredV81=True)
                _,after_text=call('STATUS');after=parse_ownership_status(after_text)
                ownership=verify_ownership_status(after,'88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d');fresh=after.get('captureFreshV81',{})
                need(ownership['state']=='FREE' and after.get('repositoryMutations')==2 and after.get('goldConfigurationWrites')==0
                    and all(fresh.get(k) is True for k in ('enabled','prepared','captured','cancelled','safeTerminal'))
                    and fresh.get('unknown') is False,'V81_FRESH_TERMINAL_REJECTED')
                proof.update(captureFreshFinalStatusV81=after,captureFreshFinalOwnershipV81=ownership)
                names=list(FILENAMES)+[INTENT_FILENAME]+[marker_filename(p) for p in PREPARE_PHASES+TERMINAL_PHASES]
                evidence_root=ROOT/'artifacts/designer-bridge'
                witness_dir=contained(evidence_root/('v81-capture-fresh-'+prepared['nonce']),evidence_root);witness_dir.mkdir()
                witnesses={}
                for name in names+['capture-fresh-v81-prepared.json','capture-fresh-v81-terminal.json']:
                    if name in names:data=read_capture_fresh_v81(session,name)
                    else:
                        receipt=contained(session/name,session);need(receipt.parent==session and 0<receipt.stat().st_size<=65536,'V81_RECEIPT_BOUND')
                        data=receipt.read_bytes()
                        from capture_fresh_guard_v81 import parse_result as parse_capture_receipt_v81
                        need(parse_capture_receipt_v81(data)==cycle['preparedNative' if name.endswith('prepared.json') else 'terminalNative'],'V81_RECEIPT_CHANGED')
                    destination=contained(witness_dir/name,witness_dir)
                    with destination.open('xb') as stream:stream.write(data)
                    witnesses[name]=dict(path=str(destination),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
                proof['captureFreshWitnessesV81']=witnesses
                _,after_source=call('READLIVE');need(after_source==one,'V81_FOREIGN_SOURCE_CHANGED')
            close=uuid.uuid4().hex
            proposal,body=call('CLOSE_SAFE',close,True);need(body=='SAFE_CLOSE_PROPOSED' and proposal['replayed'] is False,'V43_CLOSE_PROPOSAL_REJECTED')
            need(host.poll() is None and not owned_process_gone(*native_identity),'V43_UNACKNOWLEDGED_CLOSE')
            ack,body2=call('CLOSE_SAFE',close);need(ack['replayed'] is True and body2==body,'V43_CLOSE_ACK_REJECTED')
            host.wait(timeout=12);terminal=read(build/'gold-read-result.json')
            need(host.returncode==0 and terminal.get('closeConfirmed') is True and terminal.get('closeOperationId')==close
                and terminal.get('processStopped') is True
                and terminal.get('writeCount')==(proof['goldConfigurationWrites'] if args.check_gold_owned_full_object_module_v150 or args.check_gold_owned_document_structure_v139 or args.check_gold_owned_empty_objects_v130 or args.check_gold_owned_managed_form_v107 or args.check_gold_owned_constant_v99 or args.check_gold_own_object_module_v78 or args.check_gold_own_object_module_v82 else 0)
                and (not args.check_gold_own_object_module_v78 or (terminal.get('goldOwnObjectModuleV78') is True
                    and terminal.get('normalDesignerExitClaimed') is False and terminal.get('configurationSaves')==0))
                and (not args.check_gold_own_object_module_v82 or (terminal.get('goldOwnObjectModuleV82') is True
                    and terminal.get('normalDesignerExitClaimed') is False and terminal.get('configurationSaves')==0
                    and terminal.get('databaseUpdates')==0 and terminal.get('repositoryMutations')==0
                    and terminal.get('closeMethod')=='protected-ACK-fresh-CLOSE_VERIFY-and-held-original-loader-Dispose'))
                and (not args.check_gold_owned_constant_v99 or (terminal.get('goldOwnedConstantV99') is True
                    and terminal.get('goldOwnedConstantTerminalVerifiedV99') is True
                    and type(terminal.get('goldOwnedConstantVerifiedV99')) is bool
                    and terminal.get('goldOwnedConstantVerifiedV99') is comparison['ownConstantVerified']
                    and type(terminal.get('writeCount')) is int and 0<=terminal['writeCount']<=6
                    and terminal.get('goldOwnObjectModuleV82') is False and terminal.get('goldOwnObjectModuleV78') is False
                    and terminal.get('captureFreshV81') is False and terminal.get('normalDesignerExitClaimed') is False
                    and all(type(terminal.get(k)) is int and terminal[k]==0 for k in ('configurationSaves','databaseUpdates','repositoryMutations'))
                    and terminal.get('closeMethod')=='protected-ACK-fresh-CLOSE_VERIFY-and-held-original-loader-Dispose'))
                and (not args.check_gold_owned_full_object_module_v150 or terminal_ready(terminal,comparison))
                and (not args.check_managed_input_record_v145 or terminal_ready(terminal,comparison))
                and (not args.check_gold_owned_document_structure_v139 or
                    terminal_ready(terminal,comparison))
                and (not args.check_gold_owned_empty_objects_v130 or
                    terminal_ready(terminal,comparison))
                and (not args.check_gold_owned_managed_form_v107 or
                    terminal_ready(terminal,comparison))
                and (not args.check_capture_fresh_v81 or (terminal.get('captureFreshV81') is True
                    and terminal.get('captureFreshVerifiedV81') is True and terminal.get('repositoryMutations')==2
                    and terminal.get('captureOperationId')==cycle['captureOperationId'] and terminal.get('cancelOperationId')==cycle['cancelOperationId']
                    and terminal.get('closeMethod')=='protected-ACK-fresh-CLOSE_VERIFY-and-held-original-loader-Dispose'
                    and terminal.get('normalDesignerExitClaimed') is False and terminal.get('configurationSaves')==0 and terminal.get('databaseUpdates')==0))
                ,'V43_TERMINAL_REJECTED')
            if args.check_managed_input_record_v145:
                proof.update(managedInputPostDoc2FreshCleanV145=True,managedInputOwn139IdsAbsentPreservedV145=True,managedInputNoGoldWriterV145=True)
            need(wait_for_original_completion(lambda:
                owned_process_gone(*native_identity) and owned_process_gone(*host_identity)
                and owned_process_gone(original['pid'],original['birth']) and not lease_exists(owner)),
                'V43_ORIGINAL_COMPLETION_UNKNOWN')
            proof.update(passed=True,closeConfirmed=True,freshCloseVerify=True,allOriginalsGone=True,leaseReleased=True,
                terminal=terminal,runtimeRetained=False)
            exit_code=0
        except Exception as error:
            code=str(error);proof['failureCode']=code if re.fullmatch('[A-Z][A-Z_0-9]{3,63}',code) else 'V43_TRIAL_FAILED'
            proof['errorType']=type(error).__name__
            proof['launcherTerminal']=host is None or host.poll() is not None
            if (build/'owned-process-v43.json').exists():proof['ownedProcessObserved']=read(build/'owned-process-v43.json')
            if (build/'gold-read-result.json').exists():proof['terminalObserved']=read(build/'gold-read-result.json')
            if owner is not None:proof['leaseStillPresent']=lease_exists(owner)
            # Unknown host/source state retains runtime and route lease; never kill/restart.
        finally:
            proof['elapsedMs']=round((time.perf_counter()-start)*1000,1)
            path=ROOT/'artifacts/designer-bridge'/('v43-gold-startup-'+prepared['nonce']+'.json')
            durable_new(path,proof)
            print(json.dumps({k:proof[k] for k in ('passed','failureCode','startupToPublishedMs','readCount','closeConfirmed','runtimeRetained','captureFreshVerifiedV81','goldOwnedFullObjectModuleVerifiedV150','ownedFullObjectModuleV150AbsentAtStartup','goldOwnedDocumentStructureVerifiedV139','ownedStructureDocumentV139AbsentAtStartup','ownedStructureDocumentAttributeV139AbsentAtStartup','ownedStructureTablePartV139AbsentAtStartup','ownedStructureTablePartAttributeV139AbsentAtStartup','goldOwnedEmptyObjectsVerifiedV130','ownedEmptyDocumentV130AbsentAtStartup','ownedEmptyCatalogV130AbsentAtStartup','goldOwnedManagedFormVerifiedV107','goldOwnedManagedFormCapabilityFailureV107','ownedProcessingV107IdAbsentAtStartup','ownedFormV107IdAbsentAtStartup','goldOwnObjectModuleVerifiedV82','ownedObjectModuleV82IdAbsentAtStartup','goldOwnObjectModuleVerifiedV78','ownedObjectModuleV78IdAbsentAtStartup','ownedValueLifetimeVerifiedV67','ownedValuePersistenceObservationVerifiedV68','ownedValueSerializationVerifiedV68','processingFormObservationVerifiedV69','processingFormDescriptorCloneVerifiedV69','ownedPersistenceRoundTripVerifiedV71','ownedFormTypeVerifiedV72','ownedFormTypeVerifiedV74','ownedManagedBodyVerifiedV73','ownedManagedFormVerifiedV75','ownedManagedFormFailureV75','ownedManagedFormPrewriteGateV75','managedBodyFactoryObservationVerifiedV78','managedBodyFactoryVerifiedV78','managedBodyModuleObservationVerifiedV79','managedBodyModuleFactoryVerifiedV79','managedBodyModuleVerifiedV79','ownedConstantSourceObservationVerifiedV77','ownedConstantVerifiedV77','ownedConstantSafeFailureCloseV77','priorV72PostDocumentModulesVerified') if k in proof}|{'evidence':str(path)}))
    return exit_code

if __name__=='__main__':raise SystemExit(main())
