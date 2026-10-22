"""Verify completed V82 transient own-metadata edits before exact cleanup."""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'tests')]
from pending_operation_inspector import contained
from process_identity import owned_process_gone
from prepare_gold_startup_v43 import sha, sources
from stop_original_v40 import durable_new
from gold_own_object_module_guard_v82 import parse_result, verify as verify_native


def need(condition, code):
    if not condition:
        raise ValueError(code)


def _terminal(proof, code):
    need(all(proof.get(k) is True for k in ('passed','freshCloseVerify','allOriginalsGone','leaseReleased'))
         and proof.get('runtimeRetained') is False, code)
    terminal = proof.get('terminal')
    need(type(terminal) is dict and terminal.get('closeConfirmed') is True
         and terminal.get('processStopped') is True, code)


def _identities(proof, prepared=None):
    identities = {(proof['processId'], proof['processCreationFileTimeUtc']),
                  (proof['hostProcessId'], proof['hostProcessCreationFileTimeUtc'])}
    rows = [proof['originalLauncher'], *(row['caller'] for row in proof['calls'])]
    rows += [row['caller'] for row in proof.get('startedCallers', [])]
    if prepared is not None:
        rows += prepared['processes']
    for name in ('benchmarkCaller', 'disconnectCaller'):
        if name in proof:
            rows.append(proof[name])
    for row in rows:
        identities.add((row['pid'], row['birth']))
    need(all(type(pid) is int and 0 < pid <= 0x7fffffff and type(birth) is str
             and re.fullmatch('[a-f0-9]{16}', birth) is not None and birth != '0'*16
             for pid, birth in identities), 'GOM82_CLEANUP_IDENTITY_REJECTED')
    return identities


def _document_control(proof):
    modules = proof.get('documentModulesComparisonV48')
    need(type(modules) is dict and modules.get('verified') is True
         and modules.get('documentModuleTextsComplete') is True
         and modules.get('allPropertiesEnumerated') is True
         and type(modules.get('version')) is int and modules['version'] > 0
         and all(type(modules.get(k)) is int and modules[k] == 0 for k in
                 ('sourceWrites', 'repositoryWrites', 'goldSaves')),
         'GOM82_CLEANUP_FULL_MODULES_REJECTED')
    rows = modules.get('modules')
    need(type(rows) is list and len(rows) == 2 and {row.get('propertyId') for row in rows} == {
        'a637f77f-3840-441d-a1c3-699c8c5cb7e0', 'd1b64a2c-8078-4982-8190-8f81aefda192'}
        and all(row.get('liveModesEqual') is True and row.get('normalizedLineEndingsEqual') is True
                for row in rows), 'GOM82_CLEANUP_FULL_MODULES_REJECTED')
    # Every decoded hash, length and resource fact must match; only timings may differ.
    projection = modules.copy()
    projection['modules'] = sorted([{k: v for k, v in row.items() if k not in
        ('helperElapsedUs', 'repositoryElapsedUs')} for row in rows], key=lambda row: row['propertyId'])
    snapshot = proof.get('objectSnapshotV47')
    need(type(snapshot) is dict and snapshot.get('objectDescriptorSnapshotVerified') is True
         and type(snapshot.get('bytes')) is int and 0 < snapshot['bytes'] <= 4*1024*1024
         and type(snapshot.get('sha256')) is str and re.fullmatch('[a-f0-9]{64}', snapshot['sha256']) is not None,
         'GOM82_CLEANUP_DESCRIPTOR_REJECTED')
    repository = snapshot.get('repositoryComparison')
    need(type(repository) is dict and all(repository.get(k) is True for k in
        ('verified', 'descriptorEqual', 'serializationProfilesCompatible', 'repositoryObjectCaptureScopeVerified')),
         'GOM82_CLEANUP_DESCRIPTOR_REJECTED')
    need(type(proof.get('liveTextBytes')) is int and proof['liveTextBytes'] > 0
         and type(proof.get('liveTextSha256')) is str
         and re.fullmatch('[a-f0-9]{64}', proof['liveTextSha256']) is not None,
         'GOM82_CLEANUP_LIVE_SOURCE_REJECTED')
    return projection, (snapshot['bytes'], snapshot['sha256'], repository), (proof['liveTextBytes'], proof['liveTextSha256'])


def verify_fresh_post(nonce, proof_path, proof):
    path = ROOT/'artifacts/designer-bridge'/('v82-fresh-post-readonly-'+nonce+'.json')
    post = json.loads(contained(path, ROOT/'artifacts/designer-bridge').read_text(encoding='utf-8-sig'))
    need(post.get('stage') == 'V82FreshIndependentPostReadonly' and post.get('passed') is True
         and post.get('originalNonce') == nonce and post.get('originalProofSha256') == sha(proof_path),
         'GOM82_CLEANUP_FRESH_POST_REJECTED')
    fresh_nonce = post.get('freshNonce')
    need(type(fresh_nonce) is str and re.fullmatch('[a-f0-9]{32}', fresh_nonce) is not None
         and fresh_nonce != nonce, 'GOM82_CLEANUP_FRESH_NONCE_REJECTED')
    fresh_path = ROOT/'artifacts/designer-bridge'/('v43-gold-startup-'+fresh_nonce+'.json')
    need(post.get('freshProofSha256') == sha(contained(fresh_path, ROOT/'artifacts/designer-bridge')),
         'GOM82_CLEANUP_FRESH_PROOF_CHANGED')
    fresh = json.loads(fresh_path.read_text(encoding='utf-8-sig'))
    need(fresh.get('stage') == 'V43OwnedGoldReadOnlyStartup' and fresh.get('nonce') == fresh_nonce
         and fresh.get('sourceSha256') == proof['sourceSha256']
         and Path(fresh['runtimeDirectory']) == ROOT/'build'/('designer-v43-'+fresh_nonce)
         and fresh.get('ownedObjectModuleV82IdAbsentAtStartup') is True,
         'GOM82_CLEANUP_FRESH_ROLE_REJECTED')
    _terminal(fresh, 'GOM82_CLEANUP_FRESH_TERMINAL_REJECTED')
    need(fresh.get('dirtyCleanVerified') is True and fresh.get('rootAndSelectionVerified') is True
         and all(type(fresh.get(k)) is int and fresh[k] == 0 for k in
             ('goldConfigurationWrites', 'databaseUpdates', 'repositoryMutations', 'businessCalls'))
         and type(fresh['terminal'].get('writeCount')) is int and fresh['terminal']['writeCount'] == 0
         and fresh['terminal'].get('goldOwnObjectModuleV82') is False
         and fresh['terminal'].get('goldOwnObjectModuleV78') is False
         and fresh['terminal'].get('captureFreshV81') is False,
         'GOM82_CLEANUP_FRESH_WRITE_REJECTED')
    need(_document_control(proof) == _document_control(fresh), 'GOM82_CLEANUP_FRESH_CONTENT_CHANGED')
    need(all(post.get(k) is True for k in ('sourcePinsSame', 'fullObjectDescriptorPreserved',
        'fullLiveSourcePreserved', 'ownProcessingAbsentFresh', 'allFreshOriginalsGone', 'freshLeaseReleased'))
        and type(post.get('completeDocumentModulesCompared')) is int and post['completeDocumentModulesCompared'] == 2
        and all(type(post.get(k)) is int and post[k] == 0 for k in ('configurationWrites',
            'configurationExports', 'configurationImports', 'repositoryPlacement', 'businessCalls',
            'configurationSaves', 'databaseUpdates')), 'GOM82_CLEANUP_FRESH_POST_REJECTED')
    need(all(owned_process_gone(*item) for item in _identities(fresh)), 'GOM82_CLEANUP_FRESH_ORIGINAL_RETAINED')
    return dict(path=str(path),sha256=sha(path),freshNonce=fresh_nonce,freshProofSha256=sha(fresh_path))


def verify(nonce):
    need(type(nonce) is str and re.fullmatch('[a-f0-9]{32}', nonce) is not None, 'GOM82_CLEANUP_NONCE_REJECTED')
    build = contained(ROOT / 'build' / ('designer-v43-' + nonce), ROOT / 'build')
    need(build.parent == ROOT / 'build', 'GOM82_CLEANUP_BOUNDARY_REJECTED')
    proof_path = ROOT / 'artifacts/designer-bridge' / ('v43-gold-startup-' + nonce + '.json')
    proof = json.loads(proof_path.read_text(encoding='utf-8-sig'))
    need(proof.get('stage') == 'V43GoldOwnObjectModuleV82' and proof.get('nonce') == nonce
         and Path(proof['runtimeDirectory']) == build and proof.get('passed') is True,
         'GOM82_CLEANUP_PROOF_REJECTED')
    _terminal(proof,'GOM82_CLEANUP_TERMINAL_REJECTED')
    need(all(type(proof.get(k)) is int and proof[k] == 0 for k in
             ('goldConfigurationSaves', 'databaseUpdates', 'repositoryMutations', 'businessCalls')),
         'GOM82_CLEANUP_SAVED_WRITE_REJECTED')
    need(proof['sourceSha256'] == sources(), 'GOM82_CLEANUP_SOURCE_CHANGED')
    need(proof.get('postGoldFreshReadOnlyRequiredV82') is True, 'GOM82_CLEANUP_FRESH_POST_REQUIRED')
    fresh_post=verify_fresh_post(nonce,proof_path,proof)
    owner = json.loads(contained(build / 'runtime-owner.json', build).read_text())
    prepared = json.loads(contained(build / 'v43-prepared.json', build).read_text())
    need(owner.get('task') == 'DESIGNER-DIRECT-API/V43' and owner.get('nonce') == nonce
         and prepared.get('passed') is True and prepared.get('nonce') == nonce
         and prepared['sourceSha256'] == proof['sourceSha256'], 'GOM82_CLEANUP_OWNER_REJECTED')
    sessions = list(build.glob('session-*'))
    need(len(sessions) == 1, 'GOM82_CLEANUP_SESSION_REJECTED')
    session = contained(sessions[0], build)
    from run_gold_startup_v43 import read_gold_own_module_marker_v82
    native = proof['goldOwnObjectModuleNativeV82']
    # Parse the retained native result independently of the controller's dict.
    result_file = contained(session / 'gold-own-object-module-v82.json', session)
    need(parse_result(read_gold_own_module_marker_v82(session,result_file.name)) == native, 'GOM82_CLEANUP_NATIVE_CHANGED')
    comparison = verify_native(native, proof['documentModulesComparisonV48']['version'],
                               lambda name: read_gold_own_module_marker_v82(session, name))
    need(comparison == proof['goldOwnObjectModuleComparisonV82']
         and comparison['authenticatedDiscardEligible'] is True, 'GOM82_CLEANUP_NATIVE_UNVERIFIED')
    need(type(proof.get('goldConfigurationWrites')) is int
         and proof['goldConfigurationWrites'] == native['writeAttempts'], 'GOM82_CLEANUP_COUNTER_REJECTED')
    terminal = proof['terminal']
    need(terminal.get('closeConfirmed') is True and terminal.get('processStopped') is True
         and terminal.get('goldOwnObjectModuleV82') is True and terminal.get('goldOwnObjectModuleV78') is False
         and terminal.get('captureFreshV81') is False and type(terminal.get('writeCount')) is int
         and terminal.get('writeCount') == native['writeAttempts']
         and terminal.get('closeMethod') == 'protected-ACK-fresh-CLOSE_VERIFY-and-held-original-loader-Dispose'
         and all(type(terminal.get(k)) is int and terminal[k]==0 for k in ('configurationSaves','databaseUpdates','repositoryMutations'))
         and terminal.get('normalDesignerExitClaimed') is False,
         'GOM82_CLEANUP_HOST_TERMINAL_REJECTED')
    identities=_identities(proof,prepared)
    need(all(owned_process_gone(*item) for item in identities), 'GOM82_CLEANUP_ORIGINAL_RETAINED')
    state = Path(os.environ.get('AH1C_BRIDGE_STATE_DIR') or (Path(os.environ['LOCALAPPDATA']) / 'AH_1C/bridge')) / 'state.db'
    with closing(sqlite3.connect(state.as_uri() + '?mode=ro', uri=True)) as db:
        leases = db.execute("SELECT count(*) FROM execution_leases WHERE resource='ah1c-write'").fetchone()[0]
    need(leases == 0, 'GOM82_CLEANUP_ROUTE_BUSY')
    result = dict(stage='V82CompletedOwnModuleRuntimeVerified', nonce=nonce, exactPath=str(build),
                  originalIdentities=[dict(pid=pid, birth=birth, gone=True) for pid, birth in sorted(identities)],
                  allRecordedOriginalsGone=True, wholeRouteLeaseCount=0, sourcePinsCurrent=True,
                  goldProofSha256=sha(proof_path), transientOwnWriteAttempts=native['writeAttempts'],
                  foreignSourceWrites=0, configurationSaves=0, databaseUpdates=0,
                  authenticatedCloseProtocolVerified=True, normalDesignerExitClaimed=False,
                  independentFreshPostReadonly=fresh_post)
    durable_new(ROOT / 'artifacts/designer-bridge' / ('v82-own-module-late-terminal-' + nonce + '.json'), result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nonce', required=True)
    value = verify(parser.parse_args().nonce)
    print(json.dumps(dict(passed=True, nonce=value['nonce'], originalIdentityCount=len(value['originalIdentities']))))
