"""Pure sealed writer249 package renderer. No stage, process, SDK or dispatch.

The caller retains packet originals and the live transport lease. This module
cannot authorize a shared route or turn SDK/hook terminal into saved success.
"""
from dataclasses import dataclass,asdict
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys
import runner_write_admission_v258 as admission
from ram_transport_v238 import Lease

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
PARENT_SHA='04569dda63f46c12956518cec3e474d714fc25c14fc683c17d79f13606a4d681'
COMPOSER_SHA='a27af50b026f444f16aa66feaabc7cbfb842126d1b8f87eae53c38e802cfcf4d'
ADMISSION_SHA='4db843500a1542d64b6f1e68346cd1ccf00f6e3f5bfed46f9c0a4f1eb05cb7a9'
IDENTITY_HELPER_SHA='5341b893bd0b8f6ce04024412e3046bac0f0a75ca27a969194c33c3669f7785a'
NATIVE_SHA='e22ea0a88316fdeca21e70c3e6509619624cbe3203c05d8315a7e241830d6d0c'
ATTACH_SHA='112007654805351263fee5c8f9c08d27d2a665eee8d9202f1d7bc0c45d1b62a4'
HOOK_SHA='33fa5dc780b670dd28ff69b8bc29519c681a80eb44ade8ebb4f30d78155cb7f7'
SHIM_SHA='ab5c81990fe2838b366a3cde486e5b06c0650a1bc9bc9b85f43774eb47699374'
CARRIER='RUNNER_EDITORS_V247'
CARRIER_SPEC=('NativeRunnerEditorsV247.as','ahRunnerEditorsV247',
              'aefd6e34b44fcdfa67eb4a7f245797f0f11d2eda24666a0e2cb12fc3d0731e2f',
              'runner-editors-proof.json')
FILES=frozenset(('sdk_probe_params.h','Continuation.c','OwnedSdkReadonlyAttach.cs',
                 'OwnedSdkDiagnosisHook.cs','run-fixed.ps1'))
NAMESPACE='designer-writer-v263-'
MODE='COMPOSITE_WRITER_V249'
NOTIFY_RECIPE_SHA='e98df896da014d4ad1d5524c527a91083788b864b2afcde9ac8794ea60470c25'
NOTIFY_REVIEWER_SHA='472dcd9f76ea1a347330aeaacb2455df0841219f95d7560c6a1aa5d07071e3aa'


def _need(ok,code):
    if not ok:raise ValueError('V263_'+code)


def _sha(raw):return hashlib.sha256(raw).hexdigest()


def _canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _read(name,pin):
    _need(type(name) is str and '/' not in name and '\\' not in name and '..' not in name,'FIXED_NAME')
    _need(type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin),'SOURCE_PIN_FORMAT')
    path=HERE/name
    for item in (path,*path.parents):
        info=item.lstat()
        _need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'SOURCE_REPARSE')
        if item==ROOT:break
    _need(path.is_file() and 0<path.stat().st_size<=262144,'SOURCE_BOUND')
    raw=path.read_bytes();_need(0<len(raw)<=262144 and _sha(raw)==pin,'SOURCE_PIN')
    return raw


def _load(name,pin):
    # Same inert no-bytecode technique as253; no imported CLI is invoked.
    module_name='_ah1c_writer263_'+name.removesuffix('.py')
    path=HERE/name;_need(module_name not in sys.modules,'IMPORT_IN_PROGRESS')
    class NoCacheLoader(importlib.machinery.SourceFileLoader):
        def get_code(self,fullname):
            _need(fullname==module_name,'MODULE_NAME')
            return self.source_to_code(_read(name,pin),str(path))
    spec=importlib.util.spec_from_file_location(module_name,path,loader=NoCacheLoader(module_name,str(path)))
    _need(spec is not None and spec.loader is not None,'MODULE_SPEC')
    module=importlib.util.module_from_spec(spec);sys.modules[module_name]=module
    try:spec.loader.exec_module(module)
    finally:del sys.modules[module_name]
    return module


def _pins(composition_profile='LEGACY_249'):
    pins={'live_sdk_continuation_v233.py':PARENT_SHA,'runner_composite_v249.py':COMPOSER_SHA,
        'runner_write_admission_v258.py':ADMISSION_SHA,'runner_compile_only_v248.py':IDENTITY_HELPER_SHA,
        'ram_payload_v237.py':admission.CODEC_SHA,'ram_transport_v238.py':admission.TRANSPORT_SHA,
        'NativeSdkGoldDiagnosis.c':NATIVE_SHA,'OwnedSdkReadonlyAttach.cs':ATTACH_SHA,
        'OwnedSdkDiagnosisHook.cs':HOOK_SHA,'NativeSdkCall.s':SHIM_SHA,CARRIER_SPEC[0]:CARRIER_SPEC[2]}
    _need(composition_profile in ('LEGACY_249','SHEET_NOTIFY'),'COMPOSITION_PROFILE')
    if composition_profile=='SHEET_NOTIFY':
        pins.update({'sheet_notify_bootstrap_recipe.py':NOTIFY_RECIPE_SHA,
                     'sheet_notify_main_closure.py':NOTIFY_REVIEWER_SHA})
    for name,pin in pins.items():_read(name,pin)
    return pins


def _replace(text,old,new,count=1):
    _need(text.count(old)==count and new not in text,'CLOSED_ANCHOR')
    changed=text.replace(old,new)
    _need(changed.count(new)==count and changed.replace(new,old)==text,'CLOSED_REVERSE')
    return changed


@dataclass(frozen=True,slots=True)
class TechnicalContext:
    held_nonce:str
    build_directory:str
    registry_sha256:str
    process_id:int
    birth:str
    gui_thread_id:int
    source_manifest_sha256:str
    main_sha256:str
    core_path:str
    snegopat_path:str
    engine_address:int
    module_address:int
    core_base:int
    snegopat_base:int
    engine_table_rva:int=0x28f184
    module_table_rva:int=0x28e454
    module_count:int=1


def _context(intent,lease,technical):
    _need(type(intent) is admission.WriterIntent and type(lease) is Lease,'INTENT_LEASE_TYPES')
    _need(type(technical) is TechnicalContext,'TECHNICAL_CONTEXT_TYPE')
    # Revalidate READY, complete readiness and exact live receipt, not merely a
    # copied metadata hash or the more permissive post-dispatch render_values.
    decision=admission.admit(intent.request,intent.readiness,lease)
    _need(not decision.pending and decision.intent==intent,'ADMITTED_WRITER')
    s=intent.request.session;t=technical
    _need((t.held_nonce,t.process_id,t.birth,t.gui_thread_id,t.main_sha256)==
          (s.nonce,s.pid,s.birth,s.gui_thread,s.main_sha256),'INTENT_CONTEXT_JOIN')
    context=dict(heldNonce=t.held_nonce,buildDirectory=t.build_directory,registrySha256=t.registry_sha256,
        processId=t.process_id,birth=t.birth,guiThreadId=t.gui_thread_id,
        sourceManifestSha256=t.source_manifest_sha256,mainSha256=t.main_sha256,
        corePath=t.core_path,snegopatPath=t.snegopat_path)
    sdk=dict(engineAddress=t.engine_address,moduleAddress=t.module_address,coreBase=t.core_base,
        snegopatBase=t.snegopat_base,engineTableRva=t.engine_table_rva,moduleTableRva=t.module_table_rva,
        moduleCount=t.module_count,guiThreadId=t.gui_thread_id)
    validator=_load('runner_compile_only_v248.py',IDENTITY_HELPER_SHA)
    validator._identity(context,sdk)  # Shape/path/ABI only; never asserts live.
    return context,sdk


def _source(intent,lease,technical,out):
    composer=_load('runner_composite_v249.py',COMPOSER_SHA)
    #249's historical whole-file MAIN pin stays intact. A newer owned main is
    #reviewed again by258/265, including recursive SDK closure, before and after
    #this render. Only the fixed old tool runtime derives the same249 bytes;
    #it is a source dependency, never substituted for current target identity.
    route,source_sha,entry=admission.composition_profile(intent.request.review)
    if intent.request.review.composition_profile=='SHEET_NOTIFY':
        notify=_load('sheet_notify_bootstrap_recipe.py',NOTIFY_RECIPE_SHA)
        raw=notify.derive_composite()
    elif technical.main_sha256==admission.MAIN_SHA:
        raw=composer.derive_source(Path(technical.build_directory)/'runtime/modules/snegopat')
    else:
        _need(type(intent.request.review.main_closure) is admission.MainClosureReview,'CURRENT_MAIN_REVIEW')
        raw=composer.derive_source()
    _need(type(raw) is bytes and _sha(raw)==source_sha,'COMPOSITE_SOURCE_PIN')
    text=raw.decode('utf-8',errors='strict')
    _need(text.count('void '+entry+'()')==1,'COMPOSITE_ENTRY')
    values=intent.render_values(lease)
    values.update(__PACKET_PROOF_PATH__=(out/'packet-proof.json').as_posix(),
        __SHEET_PROOF_PATH__=(out/'sheet-proof.json').as_posix(),
        __COMPOSITE_PROOF_PATH__=(out/'composite-proof.json').as_posix(),
        __PREWRITE_INTENT_PATH__=(out/'native-prewrite-intent.json').as_posix())
    _need(set(values)=={'__'+p+'__' for p in composer.PLACEHOLDERS},'PLACEHOLDER_SET')
    for token,value in values.items():
        _need(text.count(token)==1,'PLACEHOLDER_COUNT');text=text.replace(token,value,1)
    _need(not re.search(r'__[A-Z][A-Z0-9_]+__',text) and 0<len(text.encode())<=65536,'RENDERED_SOURCE')
    return text


def _binding(intent,technical,pins):
    return _sha(_canonical(dict(version=263,intentSha256=intent.sha256(),
                               technicalContext=asdict(technical),sourcePins=pins)))


def _render(intent,lease,technical):
    _need(type(intent) is admission.WriterIntent,'INTENT_LEASE_TYPES')
    profile=intent.request.review.composition_profile
    pins=_pins(profile);context,sdk=_context(intent,lease,technical)
    out=ROOT/'build'/(NAMESPACE+intent.request.receipt.operation_id)
    _need(len(str(out))<=200 and re.fullmatch(r'[A-Za-z]:[\\/][A-Za-z0-9_./\\:-]+',str(out)), 'SEALED_PATH')
    source=_source(intent,lease,technical,out)
    parent=_load('live_sdk_continuation_v233.py',PARENT_SHA)
    _need(parent.FIXED_PROBES.get(CARRIER)==CARRIER_SPEC,'CARRIER_JOIN')
    # Private readonly carrier only produces reviewed host glue. Its source,
    # header and authority are discarded before returning the writer package.
    carrier=dict(probe=CARRIER,probeSha256=CARRIER_SPEC[2],context=context,sdkIdentity=sdk,outputDirectory=str(out))
    files=parent.render(carrier,_read(CARRIER_SPEC[0],CARRIER_SPEC[2]))
    _need(set(files)==FILES and all(type(v) is bytes for v in files.values()),'CARRIER_FILES')
    _need(_sha(files['OwnedSdkReadonlyAttach.cs'])==ATTACH_SHA,'ATTACH_CARRIER_PIN')
    header=files['sdk_probe_params.h'].decode()
    lines=header.splitlines();fixed=[line for line in lines if line.startswith('#define AH_SDK_FIXED_SOURCE ')]
    _need(len(fixed)==1,'SOURCE_HEADER')
    header=_replace(header,fixed[0],'#define AH_SDK_FIXED_SOURCE '+json.dumps(source,ensure_ascii=False))
    header=('#define AH_SDK_WRITER_V263 1\n#define AH_SDK_APPLICATION_EXECUTION_AUTHORIZED 1\n'
            '#define AH_SDK_CONFIGURATION_SAVE_AUTHORIZED 0\n#define AH_SDK_DATABASE_UPDATE_AUTHORIZED 0\n'
            '#define AH_SDK_REPOSITORY_MUTATION_AUTHORIZED 0\n'+header)
    files['sdk_probe_params.h']=header.encode()
    native=files['Continuation.c'].decode()
    native=_replace(native,'/* Fixed readonly same-engine SDK probe.','/* Fixed admitted writer249 same-engine SDK callback.')
    native=_replace(native,'Release it here only after the readonly callback.','Release it here only after the fixed writer callback.')
    native=_replace(native,'#include "sdk_probe_params.h"','#include "sdk_probe_params.h"\n'
        '#if !AH_SDK_WRITER_V263 || !AH_SDK_APPLICATION_EXECUTION_AUTHORIZED\n#error V263_WRITER_REQUIRED\n#endif\n'
        '#if AH_SDK_CONFIGURATION_SAVE_AUTHORIZED || AH_SDK_DATABASE_UPDATE_AUTHORIZED || AH_SDK_REPOSITORY_MUTATION_AUTHORIZED\n'
        '#error V263_SCOPE_FORBIDDEN\n#endif\n'
        '#if defined(AH_SDK_TEST_HOST) || defined(AH_SDK_RECOVER_ENGINE_CONFIG) || defined(AH_SDK_RECOVERY_TEST) || defined(AH_SDK_EXCEPTION_FILE)\n'
        '#error V263_ALTERNATE_BRANCH_FORBIDDEN\n#endif')
    _need(native.count('rc=execute(engine,(void*)AH_SDK_MODULE_ADDRESS,core,0);')==2
          and 'call(context,5,0,0)' in native,'EXECUTE_PATH')
    files['Continuation.c']=native.encode()
    attach=files['OwnedSdkReadonlyAttach.cs'].decode()
    attach=_replace(attach,'// Preload one fixed readonly SDK helper into the owned process.',
                    '// Preload one fixed admitted writer SDK helper into the owned process.')
    files['OwnedSdkReadonlyAttach.cs']=attach.encode()
    hook=files['OwnedSdkDiagnosisHook.cs'].decode()
    hook=_replace(hook,'// The callback executes a fixed, compiled readonly payload on one owned thread.',
                  '// The callback executes fixed admitted writer249 on one owned thread.')
    hook=_replace(hook,'// Preload our immutable readonly DLL and arm its exact GUI-thread callback',
                  '// Preload our immutable writer DLL and arm its exact GUI-thread callback')
    files['OwnedSdkDiagnosisHook.cs']=hook.encode()
    ps=files['run-fixed.ps1'].decode('utf-8-sig')
    scope=("version=263;packageVersion=263;nativeMode='COMPOSITE_WRITER_V249';compileOnly=$false;"
           'writerAuthorized=$true;applicationExecutionAuthorized=$true;applicationWritesKnown=$false;applicationWrites=$null;'
           'applicationMutationPossible=$true;configurationSavesAuthorized=$false;databaseUpdatesAuthorized=$false;'
           'repositoryMutationsAuthorized=$false;savedVerified=$false;intentSha256='+"'"+intent.sha256()+"';"
           +"bindingSha256='"+_binding(intent,technical,pins)+"';operationId='"+intent.request.receipt.operation_id+"';"
           +"heldNonce='"+technical.held_nonce+"';targetPid="+str(technical.process_id)+";targetBirth='"+technical.birth+"';")
    ps=_replace(ps,'version=233;',scope,count=2)
    ps=_replace(ps,"throw 'V233_X86_REQUIRED'","throw 'V263_X86_REQUIRED'")
    _need(ps.count('$hook.Start(')==1 and ps.count('$hook.WaitReadonlyResult(')==1
          and 'if(!$r.knownTerminal){while($true)' in ps,'ONE_ATTEMPT_RETAIN')
    files['run-fixed.ps1']=ps.encode('utf-8-sig')
    _need(all(0<len(v)<=262144 for v in files.values()),'PACKAGE_BOUND')
    _pins(profile);_context(intent,lease,technical)  # Ordinary source/lease drift fails before any output.
    return files,out,pins


def render_stage(intent,lease,technical):
    """Return five tool files in RAM. No source/body/path override is accepted."""
    return _render(intent,lease,technical)[0]


def package_proof(intent,lease,technical):
    """Technical review metadata; neither completed stage nor dispatch authority."""
    files,out,pins=_render(intent,lease,technical)
    route,source_sha,entry=admission.composition_profile(intent.request.review)
    proof=dict(version=263,kind='RENDERED_WRITER_PACKAGE',mode=MODE,operationId=intent.request.receipt.operation_id,
        outputDirectory=str(out),intentSha256=intent.sha256(),technicalContext=asdict(technical),
        bindingSha256=_binding(intent,technical,pins),
        compositeSourceSha256=source_sha,sourcePins=pins,
        packageHashes={name:_sha(raw) for name,raw in files.items()},
        packageByteCounts={name:len(raw) for name,raw in files.items()},
        writerAuthorized=True,applicationExecutionAuthorized=True,applicationWritesKnown=False,applicationWrites=None,
        configurationSavesAuthorized=False,databaseUpdatesAuthorized=False,repositoryMutationsAuthorized=False,
        filesWritten=0,stageCompleted=False,nativeCompilePerformed=False,runtimeExecuted=False,
        rootSharedAuditRecognitionRequired=True,actualSharedAuditPerformed=False,dispatchAuthorized=False,
        sharedMarkerVersion=233,sharedMarkerPath=str(ROOT/'build'/('designer-hot-v233-target-'+technical.held_nonce+'.json')),
        requiredNamespacePrefixes=['designer-hot-v233-','designer-compile-v248-',NAMESPACE],
        priorSameTargetUnfinishedIntentBlocksRegardlessOfMarker=True,
        retainedOnUnknown=['originalPacketRAM','allocation238','templateCheckpoint','nativeDocument',
                          'host','loadedDLLDirectory','sharedMarker','ownIntent'],
        sdkTerminalDoesNotProveAppliedOrSaved=True,releaseOnSdkOrHooksTerminal=False,
        privateCarrierPublished=False)
    if intent.request.review.composition_profile=='SHEET_NOTIFY':
        proof.update(compositionProfile='SHEET_NOTIFY',compositeEntry=entry,writerRoute=route)
    return proof
