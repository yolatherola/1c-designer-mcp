"""Create/edit/delete our native processing/form in an independent memory manager.

Gold supplies read-only version/selection controls. No object is attached to
Gold, no database update/repository mutation or Gold configuration save is performed.
The form body's module is edited, bound to its own metadata external file,
and independently read back. The whole owned configuration is saved/reopened,
then the exact pilot is deleted, saved and independently reopened again.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid

from process_identity import owned_process_gone
from owned_cf_codec import verify_owned_pair, verify_owned_import
from run_pipe_read import ARCHIVES, ROOT, TESTS, checked_extract, read_json
from run_repository_observe import SOURCES as OBSERVE_SOURCES, lease_exists, sample_summary
sys.path.insert(0, str(TESTS.parent / 'research'))
from repository_pe_probe import HASHES, PLATFORM

PROCESSING = '8d64f197-c9b8-4332-90da-18f192cf1a57'
FORM = 'dadd405a-e2dc-435c-b3cd-d1b50ef0f301'
MODULE_FIXTURE = TESTS / 'fixtures/OwnedManagedForm/Module.bsl'
SOURCES = OBSERVE_SOURCES + (
    TESTS / 'NativeOwnedObjectApi.as', TESTS / 'NativeOwnedObjectForm.as',
    TESTS / 'NativeOwnedFormLayout.as',
    TESTS / 'NativeOwnedSourceApply.as', TESTS / 'NativeOwnedSourceApply.v',
    TESTS / 'Test-TargetedLoader.ps1', TESTS / 'run_pipe_read.py',
    TESTS / 'process_identity.py', TESTS / 'test_process_identity.py',
    TESTS / 'run_owned_object_form.py',
    TESTS / 'owned_cf_codec.py', TESTS / 'test_owned_cf_codec.py',
    MODULE_FIXTURE,
)
MODES = (
    ('CaptureStatusRepositoryOwnedDetachedOpros', 'own-memory-graph'),
    ('CaptureStatusRepositoryOwnedWrongSelectionOpros', 'actual-wrong-selection'),
)


def valid_owned(sample):
    own = sample.get('ownedDetached') or {}
    graph = own.get('graph') or {}
    module = graph.get('module') or {}
    api = module.get('apiInventory') or {}
    serial = api.get('serialization') or {}
    binding = api.get('binding') or {}
    layout = api.get('layoutInventory') or {}
    layout_cycle = api.get('layoutEditCycle') or {}
    context = graph.get('context') or {}
    persistence = graph.get('configExtract') or {}
    deletion = graph.get('deletionPersistence') or {}
    return (sample.get('selectionVerified') is True
        and own.get('processorCode') == own.get('formCode') == 'CREATED_DETACHED'
        and all(own.get(key) is True for key in ('attempted', 'idsVerified', 'namesVerified',
            'detached', 'absentFromGold', 'configurationModifiedUnchanged', 'goldEditorTextUnchanged'))
        and all(own.get(key) is False for key in ('configurationModifiedBefore', 'configurationModifiedAfter', 'saved'))
        and all(own.get(key) == 0 for key in ('configurationWrites', 'databaseUpdates', 'repositoryMutations'))
        and all(context.get(key) is True for key in ('managerPresent', 'independentRootPresent', 'ownFileOnly'))
        and context.get('goldRootReplaced') is False
        and all(graph.get(key) is True for key in ('rootAbiVerified', 'ownProcessingAttached',
            'ownProcessingRemoved', 'abiVerified', 'managedTypeVerified', 'formLinkedToOwnProcessing',
            'nameEditedReadback', 'formRemovedReadback', 'processingNameAfterAttachVerified'))
        and all(persistence.get(key) is True for key in ('attempted', 'preSaveCalled', 'postSaveCalled',
            'abiVerified', 'ownManagersOnly', 'ownEvidenceWritten', 'rootLoaded', 'rootIdEqual',
            'freshManager', 'freshRoot', 'freshForm', 'managerContextVerified', 'parentChainVerified',
            'processingNameVerified', 'managedBodyVerified', 'freshBody', 'bodyModuleReopened',
            'processingReopened', 'formReopened', 'moduleReopened', 'formTypeEqual'))
        and persistence.get('extractSlot') == 43 and persistence.get('reopenedProcessingCount') == 1
        and 16 < persistence.get('bytes', 0) <= 1048576
        and all(persistence.get(key) == 0 for key in ('goldConfigurationWrites', 'databaseUpdates', 'repositoryMutations'))
        and all(deletion.get(key) is True for key in ('attempted', 'preSaveCalled', 'postSaveCalled',
            'abiVerified', 'ownManagersOnly', 'ownEvidenceWritten', 'rootLoaded', 'rootIdEqual',
            'freshManager', 'freshRoot', 'managerContextVerified', 'expectedDeleted', 'ownedGraphAbsent'))
        and deletion.get('extractSlot') == 43 and deletion.get('reopenedProcessingCount') == 0
        and 16 < deletion.get('bytes', 0) <= 1048576
        and all(deletion.get(key) == 0 for key in ('goldConfigurationWrites', 'databaseUpdates', 'repositoryMutations'))
        and graph.get('liveRootPassedToMutations') is False
        and module.get('moduleTextWritten') is True and module.get('saved') is False
        and all(layout.get(key) is True for key in ('ownBodyOnly', 'getterAbiVerified', 'object'))
        and layout.get('layout', {}).get('table') == {'module': 'mngcore.dll', 'rva': 6782316}
        and layout.get('classId', '').strip('{}').lower() == '2f64f89d-9c81-4c78-af3d-9f01e546fb8f'
        and layout.get('childCollectionAbiVerified') is True and layout.get('childCount') == 0
        and layout.get('borrowedReferencesBalanced') is True
        and all(layout_cycle.get(key) is True for key in ('attempted', 'ownBodyOnly', 'factoryAbiVerified',
            'initialized', 'added', 'createdNativeReadback', 'edited', 'editedNativeReadback', 'deleted',
            'deletedNativeReadback', 'standardControlsUnchanged', 'moduleTextUnchanged',
            'factoryOutputGuardsVerified', 'newGroupDistinctFromTemplate'))
        and (layout_cycle.get('beforeCount'), layout_cycle.get('linkedCount'), layout_cycle.get('afterCount')) == (0, 1, 0)
        and layout_cycle.get('goldConfigurationWrites') == 0 and layout_cycle.get('businessCodeExecuted') is False
        and (graph.get('beforeCount'), graph.get('linkedCount'), graph.get('afterCount')) == (0, 1, 0)
        and all(api.get(key) is True for key in ('bodyCreated', 'persistentBody', 'persistentDocument',
            'externalPropertyPresent', 'formFileBasenameBound', 'formIndexedInOwnManager'))
        and api.get('bodyClass', '').strip('{}').lower() == '5e44d99d-7d52-49bf-bc73-4dc0b575b8fb'
        and all(serial.get(key) is True for key in ('serializedOwnForm', 'ownBodyModuleWritten',
            'moduleReadbackAfterNativeLoad', 'canonicalNativeRoundTripEqual', 'initialNativeLayoutExpanded', 'moduleEvidenceWritten'))
        and serial.get('businessCodeExecuted') is False and serial.get('configurationWrites') == 0
        and serial.get('moduleCharacters') == len(MODULE_FIXTURE.read_text(encoding='utf-8-sig'))
        and all(binding.get(key) is True for key in ('attempted', 'ownFileOnly', 'bodyReloaded',
            'moduleReadbackFromOwnedBody', 'metadataBodyPresent', 'metadataModuleReadback',
            'boundBodyCodeReadback', 'textResult', 'storeAbiVerified', 'stored'))
        and binding.get('sameBody') is False
        and binding.get('textCharacters') == len(MODULE_FIXTURE.read_text(encoding='utf-8-sig'))
        and binding.get('goldConfigurationWrites') == 0 and binding.get('configurationSaved') is False
        and 0 < serial.get('bytes', 0) < serial.get('roundTripBytes', 0) <= 1048576)


def compact_owned(sample):
    own = dict(sample.get('ownedDetached') or {})
    graph = dict(own.get('graph') or {})
    config_inventory = dict(graph.get('configInventory') or {})
    for key in ('manager', 'inner', 'editService'):
        if config_inventory.get(key):
            config_inventory[key] = {'table': config_inventory[key].get('table')}
    graph['configInventory'] = config_inventory
    persistence = dict(graph.get('configExtract') or {})
    if persistence.get('restoredBodyApi'):
        persistence['restoredBodyApi'] = {'table': persistence['restoredBodyApi'].get('table')}
    graph['configExtract'] = persistence
    module = dict(graph.get('module') or {})
    api = dict(module.get('apiInventory') or {})
    # Keep interface identities, not huge native address tables or source text.
    for key in ('helper', 'moduleHelper', 'formBody'):
        value = api.get(key)
        if value is not None:
            api[key] = {'table': value.get('table')}
    if api:
        layout = dict(api.get('layoutInventory') or {})
        if 'layout' in layout:
            layout['layout'] = {'table': layout['layout'].get('table')}
        if 'persistenceInterface' in layout:
            layout['persistenceInterface'] = {'table': layout['persistenceInterface'].get('table')}
        for key in ('children', 'reservedControls'):
            for child in layout.get(key, []):
                if child.get('primary') is not None:
                    child['primary'] = {'table': child['primary'].get('table')}
                description = child.get('description')
                if description and description.get('primary'):
                    description['primary'] = {'table': description['primary'].get('table')}
        api['layoutInventory'] = layout
        module['apiInventory'] = api
        graph['module'] = module
        own['graph'] = graph
    return sample_summary(sample) | {'ownedObjectForm': own}


def valid_owned_import(applied):
    """Accept only the complete fixed own descriptor/live-object experiment.

    Cached identity, child links and code are mandatory evidence. A persisted
    file alone cannot establish that a live Designer object was refreshed.
    This predicate neither connects to Gold nor grants a production capability.
    """
    if not isinstance(applied, dict):
        return False
    required = ('attempted', 'ownManagerOnly', 'copyReturnedWithoutException',
                'inputConsumedExactly', 'preSaveCalled', 'resultExportedToFreshManager',
                'evidenceWritten', 'freshManagerVerified', 'reopenedNameChanged',
                'formPreserved', 'modulePreserved', 'parentChainPreserved',
                'originalGraphUnchanged', 'goldModifiedUnchanged', 'cachedNameUpdated')
    if not all(applied.get(key) is True for key in required):
        return False
    exact = {'metadataCopyCalls': 1, 'filenameCount': 1, 'nameOccurrences': 1,
             'streamReadbackMethod': 'independent-cf-codec', 'preSaveAll': False,
             'extractSlot': 43, 'cachedObjectModified': False,
             'goldConfigurationWrites': 0, 'databaseUpdates': 0, 'repositoryMutations': 0}
    if not all(type(applied.get(k)) is type(v) and applied[k] == v for k, v in exact.items()):
        return False
    live = applied.get('liveRefresh')
    if not isinstance(live, dict):
        return False
    checks = ('attempted', 'objectIdentityPreserved', 'formIdentityPreserved',
              'formPreserved', 'parentChainPreserved', 'modulePreserved',
              'nameUpdated', 'childContextVerified')
    return (all(live.get(key) is True for key in checks)
            and type(live.get('loadCalls')) is int and live['loadCalls'] == 1
            and type(live.get('loadFlag')) is int and live['loadFlag'] == 1
            and live.get('objectModifiedAfter') is False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-cache', type=Path)
    parser.add_argument('--check-guards', action='store_true')
    parser.add_argument('--prepared-runtime', type=Path,
                        help='Caller-owned verified fixed runtime; retained for independent cleanup.')
    parser.add_argument('--source-import', action='store_true',
                        help='Import one own descriptor into a fresh independent MemoryFile clone.')
    args = parser.parse_args()
    if os.name != 'nt':
        raise SystemExit('WINDOWS_REQUIRED')
    run_id = time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    build_root = (ROOT / 'build').resolve()
    if args.source_import and (not args.prepared_runtime or args.check_guards):
        raise SystemExit('OWN_IMPORT_ARGUMENTS_REJECTED')
    caller_runtime = args.prepared_runtime is not None
    if caller_runtime:
        build = args.prepared_runtime.resolve()
        if build != build_root / 'designer-layout-20261009-914d91af':
            raise SystemExit('OWN_PREPARED_RUNTIME_PATH_REJECTED')
        from run_command_session import verify_runtime
        verify_runtime(build)
    else:
        build = build_root / ('designer-own-' + run_id)
        build.mkdir(exist_ok=False)
    evidence = ROOT / 'artifacts/designer-bridge' / ('owned-object-form-' + run_id + '.json')
    proof = {'runId': run_id, 'passed': False, 'stage': 'prepare', 'target': 'Gold',
        'actualMutationTarget': 'independent-owned-memory-manager', 'processingId': PROCESSING, 'formId': FORM,
        'goldConfigurationWrites': 0, 'databaseUpdates': 0, 'repositoryMutations': 0,
        'bodyBoundToMetadataExternalFile': False, 'configurationSaved': False, 'trials': []}
    proof.update(ownedConfigurationSaved=False, ownDeletionPersisted=False,
                 goldConfigurationSaved=False, sourceImportTrial=args.source_import)
    before = {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCES}
    identities = set()
    owners = []
    host = child = None
    cleanup_allowed = True
    started = time.monotonic()
    exit_code = 1
    try:
        proof['platformSha256'] = {}
        for name, expected in HASHES.items():
            actual = hashlib.sha256((PLATFORM / name).read_bytes()).hexdigest().upper()
            if actual != expected:
                raise RuntimeError('PLATFORM_HASH_REJECTED')
            proof['platformSha256'][name] = actual
        proof['archives'] = {}
        for name, url, expected in ARCHIVES:
            dest = build / name
            if caller_runtime:
                pass
            elif args.archive_cache:
                shutil.copyfile(args.archive_cache.resolve() / name, dest)
            else:
                with urllib.request.urlopen(url, timeout=30) as response, dest.open('wb') as output:
                    shutil.copyfileobj(response, output)
            actual = hashlib.sha256(dest.read_bytes()).hexdigest().upper()
            if actual != expected:
                raise RuntimeError('ARCHIVE_HASH_REJECTED')
            proof['archives'][name] = actual
            if not caller_runtime:
                checked_extract(dest, build / 'runtime')
        powershell = Path(os.environ['WINDIR']) / 'SysWOW64/WindowsPowerShell/v1.0/powershell.exe'
        cleanup_allowed = False
        proof['stage'] = 'own-native-host'
        if not caller_runtime:
            host = subprocess.Popen([str(powershell), '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                str(TESTS / 'Test-TargetedLoader.ps1'), '-BuildDirectory', str(build)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            host.wait(timeout=30)
        native = read_json(build / 'native-host-result.json')
        proof['host'] = native
        for prefix in ('target', 'control'):
            created = native.get(prefix + 'CreationFileTimeUtc')
            if not isinstance(created, str) or re.fullmatch('[0-9a-f]{16}', created) is None:
                raise RuntimeError('HOST_IDENTITY_MISSING')
            identities.add((native[prefix + 'ProcessId'], created))
        cleanup_allowed = all(owned_process_gone(*identity) for identity in identities)
        if (host is not None and host.returncode != 0) or not cleanup_allowed or not all(native.get(key) is True
            for key in ('targetCoreLoaded', 'controlProcessUnaffected')):
            raise RuntimeError('NATIVE_HOST_REJECTED')
        proof['stage'] = 'owned-object-form-cycle'
        modes = ((('CaptureStatusRepositoryOwnedImportOpros', 'own-memory-graph'),)
                 if args.source_import else (MODES if args.check_guards else MODES[:1]))
        for mode, case in modes:
            cleanup_allowed = False
            child = subprocess.Popen([sys.executable, '-B', str(TESTS / 'run_live_probe.py'), str(build), mode],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            stdout, _ = child.communicate(timeout=65)
            lease = next((json.loads(line) for line in reversed(stdout.splitlines())
                if line.startswith('{') and '"leaseReleased"' in line), {})
            owner = lease.get('owner')
            if not isinstance(owner, str) or not re.fullmatch('[a-f0-9]{32}', owner):
                raise RuntimeError('OWNED_LEASE_WITNESS_MISSING')
            owners.append(owner)
            result = read_json(build / 'gold-read-result.json')
            pid = result.get('processId')
            created = result.get('processCreationFileTimeUtc')
            if type(pid) is not int or not isinstance(created, str) or not re.fullmatch('[0-9a-f]{16}', created):
                raise RuntimeError('OWNED_IDENTITY_MISSING')
            identities.add((pid, created))
            gone = owned_process_gone(pid, created)
            lease_absent = not lease_exists(owner)
            cleanup_allowed = gone and lease_absent and lease.get('leaseReleased') is True
            session = max(build.glob('session-*/native-read-0.bsl'), key=lambda p: p.stat().st_mtime).parent
            samples = [read_json(session / f'native-read-{i}.bsl') for i in range(result.get('readCount', 0))]
            record = {'case': case, 'processId': pid, 'processCreationFileTimeUtc': created,
                'leaseOwner': owner, 'ownedProcessGoneIndependently': gone, 'leaseAbsentIndependently': lease_absent,
                'startupMs': result.get('startupMs'), 'readRoundTripMs': result.get('readRoundTripMs'),
                'samples': [compact_owned(sample) for sample in samples]}
            proof['trials'].append(record)
            common = cleanup_allowed and result.get('readCount') == 5 and result.get('writeCount') == 0
            if case == 'own-memory-graph':
                record['verified'] = common and child.returncode == 0 and all(valid_owned(sample) for sample in samples)
                if not record['verified']:
                    raise RuntimeError('OWNED_GRAPH_READBACK_REJECTED')
                proof['bodyBoundToMetadataExternalFile'] = True
                record['physicalOwnedCF'] = verify_owned_pair(
                    (session / 'owned-configuration-copy.cf').read_bytes(),
                    (session / 'owned-configuration-deleted.cf').read_bytes(),
                    samples[0]['ownedDetached']['graph']['configExtract']['sourceRootId'])
                if args.source_import:
                    for sample in samples:
                        applied = sample['ownedDetached']['graph'].get('sourceApply')
                        if not valid_owned_import(applied):
                            raise RuntimeError('OWN_IMPORT_NATIVE_READBACK_REJECTED')
                    record['physicalOwnedImport'] = verify_owned_import(
                        (session / 'owned-configuration-copy.cf').read_bytes(),
                        (session / 'owned-source-import.cf').read_bytes(),
                        samples[0]['ownedDetached']['graph']['configExtract']['sourceRootId'])
                    if record['physicalOwnedImport']['versionCookieChangeCount'] != 4:
                        raise RuntimeError('OWN_IMPORT_VERSION_MAINTENANCE_REJECTED')
                proof['ownedConfigurationSaved'] = True
                proof['ownDeletionPersisted'] = True
                record['bodyFiles'] = {name: {'sha256': hashlib.sha256((session / name).read_bytes()).hexdigest(),
                    'bytes': (session / name).stat().st_size} for name in ('owned-managed-form.bin',
                        'owned-managed-form-after.bin', 'owned-configuration-copy.cf', 'owned-configuration-deleted.cf')}
                native_module_path = session / 'owned-managed-form-module.bsl'
                record['moduleSourceSha256'] = hashlib.sha256(native_module_path.read_bytes()).hexdigest()
                if native_module_path.read_text(encoding='utf-8-sig') != MODULE_FIXTURE.read_text(encoding='utf-8-sig'):
                    raise RuntimeError('OWNED_MODULE_SOURCE_REJECTED')
                # The project's validator accepts the standard module basename.
                module_path = session / 'Form/Module.bsl'
                module_path.parent.mkdir(exist_ok=False)
                shutil.copyfile(native_module_path, module_path)
                validation = subprocess.run([sys.executable, '-B', '-X', 'utf8',
                    str(ROOT / '.codex/skills/ah-1c-forms/scripts/validate_managed_form_changes.py'),
                    str(module_path), '--base', 'HEAD', '--full'], cwd=ROOT,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                record['managedFormLocalValidatorExitCode'] = validation.returncode
                if validation.returncode != 0:
                    raise RuntimeError('OWNED_MANAGED_MODULE_VALIDATION_REJECTED')
            else:
                record['blockedBeforeFactory'] = (common and child.returncode != 0
                    and result.get('clientCode') == 'OBSERVE_SCOPE_REJECTED'
                    and all(sample.get('selectionVerified') is False and sample.get('ownedDetached') ==
                        {'attempted': False, 'error': 'OWN_SCOPE_REJECTED'} for sample in samples))
                if not record['blockedBeforeFactory']:
                    raise RuntimeError('OWNED_SCOPE_GUARD_REJECTED')
        proof['passed'] = True
        exit_code = 0
    except Exception as error:
        message = str(error)
        proof['failureCode'] = message if re.fullmatch('[A-Z][A-Z_0-9]{3,63}', message) else 'OWNED_WRAPPER_FAILED'
        proof['errorType'] = type(error).__name__
    finally:
        failure_path = build / 'native-host-failure.json'
        if failure_path.is_file():
            failure = read_json(failure_path)
            proof['hostFailureWitness'] = failure
            witnessed = failure.get('goldStarted') is False
            for prefix in ('target', 'control'):
                pid, created = failure.get(prefix + 'ProcessId'), failure.get(prefix + 'CreationFileTimeUtc')
                stopped = failure.get(prefix + 'Stopped') is True
                if type(pid) is int and pid > 0 and isinstance(created, str) and re.fullmatch('[0-9a-f]{16}', created):
                    identities.add((pid, created))
                    witnessed = witnessed and stopped and owned_process_gone(pid, created)
                elif pid == 0:
                    witnessed = witnessed and stopped
                else:
                    witnessed = False
            cleanup_allowed = witnessed
        proof['wrapperChildrenAbsent'] = all(p is None or p.poll() is not None for p in (host, child))
        proof['ownedProcessesGoneIndependently'] = all(owned_process_gone(*identity) for identity in identities)
        proof['ownedLeasesAbsentIndependently'] = all(not lease_exists(owner) for owner in owners)
        proof['ownedProcessIdentities'] = [{'processId': pid, 'creationFileTimeUtc': created} for pid, created in sorted(identities)]
        after = {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCES}
        proof['sourceSha256'] = after
        proof['sourceIdentityUnchanged'] = before == after
        resolved = build.resolve()
        if (caller_runtime and cleanup_allowed and proof['wrapperChildrenAbsent']
                and proof['ownedProcessesGoneIndependently'] and proof['ownedLeasesAbsentIndependently']):
            proof['preparedRuntimeRetainedByCaller'] = True
            proof['temporaryFilesRemoved'] = False
        elif (cleanup_allowed and proof['wrapperChildrenAbsent'] and proof['ownedProcessesGoneIndependently']
            and proof['ownedLeasesAbsentIndependently'] and resolved.parent == build_root
            and resolved.name == 'designer-own-' + run_id):
            try:
                shutil.rmtree(resolved)
                proof['temporaryFilesRemoved'] = True
            except OSError:
                proof['temporaryFilesRemoved'] = False
        else:
            proof['temporaryFilesRemoved'] = False
        if not proof['temporaryFilesRemoved'] and not proof.get('preparedRuntimeRetainedByCaller'):
            proof['retainedRuntime'] = str(build)
            proof['passed'] = False
            exit_code = 85
        if not proof['sourceIdentityUnchanged']:
            proof['passed'] = False
            proof['failureCode'] = 'SOURCE_IDENTITY_CHANGED'
            exit_code = 1
        proof['elapsedMs'] = round((time.monotonic() - started) * 1000, 1)
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'passed': proof['passed'], 'evidence': str(evidence), 'verifiedTrials': len(proof['trials']),
            'temporaryFilesRemoved': proof['temporaryFilesRemoved'], 'failureCode': proof.get('failureCode')}, ensure_ascii=False), flush=True)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
