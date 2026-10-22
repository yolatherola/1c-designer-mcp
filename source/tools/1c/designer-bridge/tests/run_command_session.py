"""Verify the native command session using an explicitly prepared owned runtime.

Gold is read-only. OWN_CYCLE mutates only its separate MemoryFile manager.
This research entry point does not install a service or attach a user Designer.
It removes only the session created by this invocation, after PID+birth/lease
checks. The caller still owns preparation, runtime logs and final runtime cleanup.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import statistics
import subprocess
import sys
import time
import uuid
import zipfile
from command_buffer_guard import verify_owned as verify_owned_buffer, verify_status as verify_buffer_status

from process_identity import owned_process_gone
from run_pipe_read import ARCHIVES, ROOT, TESTS, read_json
from run_repository_observe import lease_exists
from run_repository_source import SOURCES as SOURCE_SOURCES, require_positive
from run_owned_object_form import SOURCES as OWN_SOURCES, MODULE_FIXTURE, valid_owned
from owned_cf_codec import verify_owned_pair

sys.path[:0] = [str(TESTS.parent), str(TESTS.parent / 'research')]
from native_source_codec import decode_module_packet
from repository_pe_probe import HASHES, PLATFORM

SOURCES = tuple(dict.fromkeys(SOURCE_SOURCES + OWN_SOURCES + (
    TESTS / 'NativePipeTransport.as', TESTS / 'NativePipeReadProbe.as',
    TESTS / 'NativeCommandSession.as', TESTS / 'NativeBufferGuard.as', TESTS / 'NativeCommandBufferGuard.as',
    TESTS / 'command_buffer_guard.py', TESTS / 'test_command_buffer_guard.py', TESTS / 'NativePipeIO.v',
    TESTS / 'NativeCaptureStatus.v', TESTS.parent / 'NativeCommandClient.cs',
    TESTS / 'NativeGoldWriterInventory.as',
    TESTS / 'validate_gold_inventory.py', TESTS / 'test_gold_inventory.py',
    TESTS.parent / 'LivePipeClient.cs', TESTS / 'run_command_session.py',
    TESTS.parent / 'Invoke-NativeCommand.ps1', TESTS / 'NativeProbeHost.cs',
    TESTS / 'test_command_evidence.py',
    ROOT / 'tools/1c/Import-VRunnerEnvironment.ps1',
    ROOT / 'tools/1c/designer-agent/native_probe.py',
)))
COMMAND_FLAGS = (
    'Passed', 'ActorAclVerified', 'ServerPidBirthVerified', 'WrongPidRejected',
    'WrongBirthRejected', 'WrongSessionRejected', 'WrongScopeRejected',
    'UnknownCommandRejected', 'ChangedCommandReplayRejected',
    'ConsumedOperationRejected', 'ExactReplayVerified',
    'SourceSecondOperationBlocked', 'OwnSecondOperationBlocked',
    'SameConnectionVerified',
    'NonAsciiRejected',
    'OwnBufferGuardVerified', 'OwnBufferGuardSecondOperationBlocked', 'OwnBufferGuardReplayVerified',
    'SelectedBufferGuardVerified',
)


CAPTURE_SESSION_SOURCES = (TESTS / 'NativeCaptureCycle.as', TESTS / 'NativePersistentCapture.as',
    TESTS / 'CaptureSourceSession.ps1', TESTS.parent / 'Invoke-CaptureSourceCommand.ps1')
SOURCES = tuple(dict.fromkeys(SOURCES + CAPTURE_SESSION_SOURCES))


def source_hashes():
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCES}


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def identity(value):
    pid = value.get('processId')
    birth = value.get('processCreationFileTimeUtc')
    require(type(pid) is int and 0 < pid < 2**32 and isinstance(birth, str)
        and re.fullmatch('[a-f0-9]{16}', birth) is not None and int(birth, 16) != 0,
        'COMMAND_IDENTITY_MISSING')
    return pid, birth


def validate_command(result):
    command = result.get('command') or {}
    require(result.get('bridgeReady') is True and result.get('readCount') == 20
        and result.get('writeCount') == 0 and result.get('processStopped') is True
        and result.get('coreLoaded') is True and result.get('snegopatLoaded') is True
        and result.get('transport') == 'native-named-pipe-commands'
        and all(command.get(key) is True for key in COMMAND_FLAGS)
        and command.get('ReadCount') == 20
        and command.get('SourceMetadataRpcCount') == command.get('SourceModuleRpcCount') == 1,
        'COMMAND_RESULT_REJECTED')
    require(all(type(result.get(key)) is int for key in ('readCount', 'writeCount'))
        and all(type(command.get(key)) is int for key in ('ReadCount', 'SourceMetadataRpcCount', 'SourceModuleRpcCount')),
        'COMMAND_COUNTER_TYPE_REJECTED')
    require(re.fullmatch('[a-f0-9]{64}', command.get('LiveTextSha256') or '') is not None,
        'COMMAND_LIVE_HASH_MISSING')
    for key, count in (('ReadRoundTripMs', 20), ('StatusRoundTripMs', 5)):
        times = command.get(key)
        require(isinstance(times, list) and len(times) == count
            and all(type(t) in (int, float) and 0 <= t < 30000 for t in times),
            'COMMAND_TIMING_REJECTED')
    return command


def verify_runtime(build, *, previous_result_name='gold-read-result.json'):
    require(previous_result_name in ('gold-read-result.json', 'gold-capture-result.json'),
        'PREPARED_RESULT_NAME_REJECTED')
    require(build.parent == (ROOT / 'build').resolve() and build.is_dir()
        and not build.is_symlink(), 'PREPARED_RUNTIME_PATH_REJECTED')
    marker = build / 'owned-gold-pid'
    if marker.exists():
        previous = read_json(build / previous_result_name)
        prior_identity = identity(previous)
        require(marker.read_text(encoding='ascii').strip() == str(prior_identity[0])
            and previous.get('processStopped') is True and owned_process_gone(*prior_identity),
            'OWNED_RUNTIME_IN_USE')
    state = Path(os.environ.get('AH1C_BRIDGE_STATE_DIR') or
        (Path(os.environ['LOCALAPPDATA']) / 'AH_1C/bridge')) / 'state.db'
    with sqlite3.connect(state.resolve().as_uri() + '?mode=ro', uri=True) as connection:
        require(connection.execute('SELECT 1 FROM execution_leases WHERE resource=?',
            ('ah1c-write',)).fetchone() is None, 'GOLD_ROUTE_IN_USE')
    host = read_json(build / 'native-host-result.json')
    require(host.get('targetCoreLoaded') is True and host.get('controlProcessUnaffected') is True,
        'PREPARED_NATIVE_HOST_REJECTED')
    for prefix in ('target', 'control'):
        pid, birth = identity({'processId': host.get(prefix + 'ProcessId'),
            'processCreationFileTimeUtc': host.get(prefix + 'CreationFileTimeUtc')})
        require(owned_process_gone(pid, birth), 'PREPARED_HOST_STILL_RUNNING')
    # Check executable runtime images against the pinned archive contents.
    # Later archives win, exactly as in the existing extraction route.
    images, archives = {}, {}
    for name, _, expected in ARCHIVES:
        archive = build / name
        actual = hashlib.sha256(archive.read_bytes()).hexdigest().upper()
        require(actual == expected, 'ARCHIVE_HASH_REJECTED')
        archives[name] = actual
        with zipfile.ZipFile(archive) as package:
            for entry in package.infolist():
                member = entry.filename.replace('\\', '/')
                if member.lower().endswith(('.dll', '.exe')):
                    target = (build / 'runtime' / member).resolve()
                    require(target.is_relative_to((build / 'runtime').resolve()) and ':' not in member,
                        'RUNTIME_IMAGE_PATH_REJECTED')
                    images[target] = hashlib.sha256(package.read(entry)).hexdigest()
    require(bool(images), 'RUNTIME_IMAGES_MISSING')
    for path, expected in images.items():
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'RUNTIME_IMAGE_HASH_REJECTED')
    platform = {}
    for name, expected in HASHES.items():
        actual = hashlib.sha256((PLATFORM / name).read_bytes()).hexdigest().upper()
        require(actual == expected, 'PLATFORM_HASH_REJECTED')
        platform[name] = actual
    return {'archiveSha256': archives, 'platformSha256': platform,
        'runtimeImageSha256': {p.relative_to(build / 'runtime').as_posix(): sha for p, sha in images.items()}}


def remove_owned_session(session, build):
    # A native PowerShell delete uses a verified literal path, without switching
    # shells or composing a command string from untrusted filenames.
    require(session.parent == build and re.fullmatch('session-[a-f0-9]{32}', session.name)
        and not session.is_symlink(), 'SESSION_CLEANUP_PATH_REJECTED')
    shell = Path(os.environ['WINDIR']) / 'SysWOW64/WindowsPowerShell/v1.0/powershell.exe'
    env = os.environ.copy()
    env['AH1C_OWNED_SESSION_DELETE'] = str(session)
    env['AH1C_OWNED_SESSION_PARENT'] = str(build)
    script = '''$ErrorActionPreference='Stop'
$path=[IO.Path]::GetFullPath($env:AH1C_OWNED_SESSION_DELETE)
$parent=[IO.Path]::GetFullPath($env:AH1C_OWNED_SESSION_PARENT)
$item=Get-Item -LiteralPath $path
if([IO.Path]::GetDirectoryName($path) -ne $parent -or $item.Name -notmatch '^session-[a-f0-9]{32}$' -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Cleanup path rejected'}
Remove-Item -LiteralPath $path -Recurse -Force
'''
    deleted = subprocess.run([str(shell), '-NoProfile', '-Command', script], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    require(deleted.returncode == 0 and not session.exists(), 'SESSION_CLEANUP_FAILED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared-runtime', type=Path, required=True,
        help='Existing runtime explicitly owned by this research task; no install performed.')
    args = parser.parse_args()
    require(os.name == 'nt', 'WINDOWS_REQUIRED')
    build = args.prepared_runtime.resolve()
    run_id = time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    evidence = ROOT / 'artifacts/designer-bridge' / ('command-session-' + run_id + '.json')
    proof = {'runId': run_id, 'stage': 'prepared-runtime', 'passed': False,
        'target': 'Gold-readonly', 'actualMutationTarget': 'independent-owned-memory-manager',
        'goldConfigurationWrites': 0, 'databaseUpdates': 0, 'repositoryMutations': 0,
        'publicFreshInstallVerified': False, 'persistentPublicHostImplemented': False}
    before = source_hashes()
    sessions_before = set(build.glob('session-*'))
    child = None
    owned_identity = host_identity = owner = None
    sessions = []
    started = time.monotonic()
    exit_code = 1
    try:
        proof.update(verify_runtime(build))
        proof['stage'] = 'native-command-session'
        child = subprocess.Popen([sys.executable, '-B', str(TESTS / 'run_live_probe.py'), str(build),
            'CaptureStatusRepositoryCommandOpros'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True)
        stdout, _ = child.communicate(timeout=65)
        lease = next((json.loads(line) for line in reversed(stdout.splitlines())
            if line.startswith('{') and '"leaseReleased"' in line), {})
        owner = lease.get('owner')
        require(isinstance(owner, str) and re.fullmatch('[a-f0-9]{32}', owner) is not None,
            'COMMAND_LEASE_MISSING')
        result = read_json(build / 'gold-read-result.json')
        owned_identity = identity(result)
        host_identity = identity(dict(processId=result.get("hostProcessId"),
            processCreationFileTimeUtc=result.get("hostProcessCreationFileTimeUtc")))
        require(host_identity != owned_identity, "COMMAND_HOST_ALIAS")
        proof.update(processId=owned_identity[0], processCreationFileTimeUtc=owned_identity[1],
            hostProcessId=host_identity[0], hostProcessCreationFileTimeUtc=host_identity[1],
            leaseOwner=owner, processStoppedWitness=result.get('processStopped'),
            leaseReleasedWitness=lease.get('leaseReleased'))
        require(child.returncode == 0 and lease.get('leaseReleased') is True
            and owned_process_gone(*owned_identity) and owned_process_gone(*host_identity) and not lease_exists(owner), 'COMMAND_TERMINAL_REJECTED')
        command = validate_command(result)
        sessions = list(set(build.glob('session-*')) - sessions_before)
        require(len(sessions) == 1, 'COMMAND_SESSION_SCOPE_REJECTED')
        session = sessions[0]
        source = read_json(session / 'command-source.json')
        own = read_json(session / 'command-owned.json')
        require(require_positive(source), 'COMMAND_SOURCE_READBACK_REJECTED')
        require(valid_owned(own), 'COMMAND_OWN_READBACK_REJECTED')
        live = (session / 'live-module.bsl').read_bytes().decode('utf-8-sig')
        comparison = decode_module_packet((session / 'repository-module.bin').read_bytes()).summary(live)
        require(comparison['normalizedLineEndingsEqual'] is True
            and hashlib.sha256(live.encode('utf-8')).hexdigest() == command['LiveTextSha256'],
            'COMMAND_SOURCE_EQUALITY_REJECTED')
        buffer_proof = verify_owned_buffer(read_json(session / 'command-buffer-guard.json'),
            (session / 'command-buffer-before.bsl').read_bytes(),
            (session / 'command-buffer-changed.bsl').read_bytes(),
            (session / 'command-buffer-restored.bsl').read_bytes())
        buffer_statuses = []
        for i in range(5):
            status = read_json(session / f'command-status-{i}.json')
            buffer_statuses.append(verify_buffer_status(status.get('selectedBufferGuard'),
                buffer_statuses[-1] if buffer_statuses else None))
            dirty = status.get('dirty') or {}
            require(all(status.get(key) is True for key in ('scopeAlive', 'selectionVerified',
                'repositoryBoundVerified', 'ownerVerified', 'generationVerified'))
                and dirty.get('verified') is True and dirty.get('refreshAllowed') is True
                and all(dirty.get(key) is False for key in ('configurationModified', 'objectModified', 'bufferModified'))
                and status.get('sourceMetadataRpcCount') == status.get('sourceModuleRpcCount') == 1
                and status.get('goldConfigurationWrites') == status.get('repositoryMutations') == 0,
                'COMMAND_FRESH_STATUS_REJECTED')
        require((session / 'owned-managed-form-module.bsl').read_text(encoding='utf-8-sig')
            == MODULE_FIXTURE.read_text(encoding='utf-8-sig'), 'COMMAND_OWN_MODULE_REJECTED')
        physical = verify_owned_pair((session / 'owned-configuration-copy.cf').read_bytes(),
            (session / 'owned-configuration-deleted.cf').read_bytes(),
            own['ownedDetached']['graph']['configExtract']['sourceRootId'])
        proof.update(command=command, moduleComparison=comparison, physicalOwnedCF=physical,
            ownedBufferGuardVerification=buffer_proof, selectedBufferStatusVerification=buffer_statuses,
            independentSourceVerified=True, independentOwnGraphVerified=True,
            ownedConfigurationSaved=True, ownDeletionPersisted=True,
            startupMs=result['startupMs'], readMedianMs=statistics.median(command['ReadRoundTripMs']),
            statusMedianMs=statistics.median(command['StatusRoundTripMs']), passed=True)
        exit_code = 0
    except Exception as error:
        code = str(error)
        proof['failureCode'] = code if re.fullmatch('[A-Z][A-Z_0-9]{3,63}', code) else 'COMMAND_WRAPPER_FAILED'
        proof['errorType'] = type(error).__name__
    finally:
        # Never kill a timed-out launcher or release another operation's lease.
        proof['wrapperExited'] = child is None or child.poll() is not None
        proof['ownedProcessGoneIndependently'] = owned_identity is not None and owned_process_gone(*owned_identity)
        proof['ownedHostGoneIndependently'] = host_identity is not None and owned_process_gone(*host_identity)
        proof['leaseAbsentIndependently'] = owner is not None and not lease_exists(owner)
        proof['sourceSha256'] = source_hashes()
        proof['sourceIdentityUnchanged'] = before == proof['sourceSha256']
        if child is not None:
            sessions = list(set(build.glob('session-*')) - sessions_before)
        terminal = (proof['wrapperExited'] and proof['ownedProcessGoneIndependently'] and proof['ownedHostGoneIndependently']
            and proof['leaseAbsentIndependently'] and proof.get('processStoppedWitness') is True
            and proof.get('leaseReleasedWitness') is True)
        proof['ownedSessionRemoved'] = not sessions
        if terminal and len(sessions) == 1:
            try:
                remove_owned_session(sessions[0], build)
                proof['ownedSessionRemoved'] = True
            except Exception:
                proof['cleanupCode'] = 'OWN_SESSION_RETAINED'
        if sessions and not proof['ownedSessionRemoved']:
            proof['retainedSessionCount'] = len(sessions)
            proof['passed'] = False
            exit_code = 85
        if not proof['sourceIdentityUnchanged']:
            proof.update(passed=False, failureCode='COMMAND_SOURCE_IDENTITY_CHANGED')
            exit_code = 1
        proof['preparedRuntimeRetainedByCaller'] = True
        proof['elapsedMs'] = round((time.monotonic() - started) * 1000, 1)
        evidence.parent.mkdir(exist_ok=True)
        evidence.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({key: proof.get(key) for key in ('passed', 'failureCode', 'readMedianMs',
            'statusMedianMs', 'sourceIdentityUnchanged', 'ownedSessionRemoved', 'elapsedMs')}
            | {'evidence': str(evidence)}, ensure_ascii=False), flush=True)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
