"""Repeated read-only completed EmptyObjects inspection; CLI writes no receipt.

Only a physically known terminal, authenticated close and separate full fresh
control can allow exact runtime cleanup. No failed/unknown writer recovery,
native calls, process stops or lease mutations exist here.
"""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys

ROOT=Path(__file__).resolve().parents[4]
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'tests')]
from pending_operation_inspector import contained
from completed_gold_own_module_v82 import _identities, _document_control, _terminal
from gold_owned_document_structure_guard_v139 import parse_result, verify as verify_native
from gold_owned_document_structure_controller_v139 import RESULT as RESULT_FILENAME, terminal_ready
from gold_owned_document_structure_guard_v139 import LIMIT
from prepare_gold_startup_v43 import sources
from process_identity import owned_process_gone


def need(ok,code):
    if not ok:raise ValueError(code)


def _read(path,base,limit):
    try:
        path=contained(path,base);before=path.stat()
        need(stat.S_ISREG(before.st_mode) and 0<before.st_size<=limit,'GD139_CLEANUP_SIZE_REJECTED')
        with path.open('rb') as stream:body=stream.read(limit+1)
        after=path.stat()
        need(len(body)==before.st_size==after.st_size and
             (before.st_mtime_ns,before.st_ino)==(after.st_mtime_ns,after.st_ino),'GD139_CLEANUP_FILE_CHANGED')
        return body
    except (OSError,RuntimeError):raise ValueError('GD139_CLEANUP_FILE_REJECTED') from None


def _sha(body):return hashlib.sha256(body).hexdigest()


def _pairs(items):
    result={}
    for key,value in items:
        need(key not in result,'GD139_CLEANUP_DUPLICATE_JSON')
        result[key]=value
    return result


def _json(body):
    try:
        def nonfinite(_):raise ValueError('GD139_CLEANUP_NONFINITE_JSON')
        value=json.loads(body.decode('utf-8-sig','strict'),object_pairs_hook=_pairs,parse_constant=nonfinite)
    except (UnicodeError,json.JSONDecodeError,RecursionError):raise ValueError('GD139_CLEANUP_JSON_REJECTED') from None
    need(type(value) is dict,'GD139_CLEANUP_JSON_SHAPE')
    return value


def _zero(info,keys):
    need(all(type(info.get(k)) is int and info[k]==0 for k in keys),'GD139_CLEANUP_ZERO_COUNTER_REJECTED')


def _required_names(native,comparison):
    return list(comparison['physicalWitnessSha256'])+[RESULT_FILENAME]


def _verify_proofs(nonce,proof,native,bodies,prepared,owner,post,fresh,original_sha,fresh_sha):
    build=ROOT/'build'/('designer-v43-'+nonce)
    need(proof.get('stage')=='V43GoldOwnedDocumentStructureV139' and proof.get('nonce')==nonce
         and type(proof.get('runtimeDirectory')) is str and Path(proof['runtimeDirectory'])==build,
         'GD139_CLEANUP_ROLE_REJECTED')
    _terminal(proof,'GD139_CLEANUP_TERMINAL_REJECTED')
    need(proof.get('closeConfirmed') is True and proof.get('postGoldFreshReadOnlyRequiredV139') is True
         and proof.get('postGoldFreshReadOnlyVerifiedV139') is False,'GD139_CLEANUP_FRESH_REQUIRED')
    _zero(proof,('goldConfigurationSaves','databaseUpdates','repositoryMutations','businessCalls'))
    need(prepared.get('stage')=='V43OwnedReadOnlyStartupPrepared' and prepared.get('passed') is True
         and prepared.get('goldStarted') is False and prepared.get('nonce')==nonce
         and owner.get('task')=='DESIGNER-DIRECT-API/V43' and owner.get('nonce')==nonce
         and proof['sourceSha256']==prepared['sourceSha256']==owner['sourceSha256'],'GD139_CLEANUP_OWNER_REJECTED')
    comparison=verify_native(native,proof['documentModulesComparisonV48']['version'],bodies.__getitem__)
    need(native==proof.get('goldOwnedDocumentStructureNativeV139')
         and native['operationId']==proof.get('goldOwnedDocumentStructureOperationV139')
         and comparison==proof.get('goldOwnedDocumentStructureComparisonV139')
         and comparison['safeTerminalObserved'] is True
         and type(proof.get('goldOwnedDocumentStructureVerifiedV139')) is bool
         and proof['goldOwnedDocumentStructureVerifiedV139'] is comparison['ownStructureVerified'],
         'GD139_CLEANUP_NATIVE_REJECTED')
    need(type(proof.get('goldConfigurationWrites')) is int
         and proof['goldConfigurationWrites']==native['writeAttempts'] and 0<=native['writeAttempts']<=20,
         'GD139_CLEANUP_WRITE_COUNT_REJECTED')
    terminal=proof['terminal']
    need(terminal.get('stage')=='gold-owned-document-structure-v139-host'
         and terminal.get('goldOwnedDocumentStructureV139') is True
         and terminal.get('goldOwnedDocumentStructureTerminalVerifiedV139') is True
         and type(terminal.get('goldOwnedDocumentStructureVerifiedV139')) is bool
         and terminal['goldOwnedDocumentStructureVerifiedV139'] is comparison['ownStructureVerified']
         and all(terminal.get(k) is False for k in ('goldOwnedEmptyObjectsV130','goldOwnedManagedFormV107','goldOwnedConstantV99','goldOwnObjectModuleV82','goldOwnObjectModuleV78','captureFreshV81','normalDesignerExitClaimed'))
         and terminal.get('closeMethod')=='protected-ACK-fresh-CLOSE_VERIFY-and-held-original-loader-Dispose'
         and type(terminal.get('writeCount')) is int and terminal['writeCount']==native['writeAttempts']
         and all(terminal.get(k)==proof.get(k) for k in ('processId','processCreationFileTimeUtc','hostProcessId','hostProcessCreationFileTimeUtc')),
         'GD139_CLEANUP_HOST_REJECTED')
    terminal_ready(terminal,comparison)
    _zero(terminal,('configurationSaves','databaseUpdates','repositoryMutations'))
    need(post.get('stage')=='V139FreshIndependentPostReadonly' and post.get('passed') is True
         and post.get('originalNonce')==nonce and post.get('originalProofSha256')==original_sha
         and post.get('freshProofSha256')==fresh_sha,'GD139_CLEANUP_POST_LINK_REJECTED')
    fresh_nonce=post.get('freshNonce')
    need(type(fresh_nonce) is str and re.fullmatch('[a-f0-9]{32}',fresh_nonce) and fresh_nonce!=nonce
         and fresh.get('stage')=='V43OwnedGoldReadOnlyStartup' and fresh.get('nonce')==fresh_nonce
         and type(fresh.get('runtimeDirectory')) is str
         and Path(fresh['runtimeDirectory'])==ROOT/'build'/('designer-v43-'+fresh_nonce)
         and fresh['sourceSha256']==proof['sourceSha256']
         and all(fresh.get(k) is True for k in ('ownedStructureDocumentV139AbsentAtStartup','ownedStructureDocumentAttributeV139AbsentAtStartup','ownedStructureTablePartV139AbsentAtStartup','ownedStructureTablePartAttributeV139AbsentAtStartup','dirtyCleanVerified','rootAndSelectionVerified')),
         'GD139_CLEANUP_FRESH_ROLE_REJECTED')
    _terminal(fresh,'GD139_CLEANUP_FRESH_TERMINAL_REJECTED')
    _zero(fresh,('goldConfigurationWrites','databaseUpdates','repositoryMutations','businessCalls'))
    _zero(fresh['terminal'],('writeCount',))
    need(all(fresh['terminal'].get(k) is False for k in ('goldOwnedDocumentStructureV139','goldOwnedEmptyObjectsV130','goldOwnedManagedFormV107','goldOwnedConstantV99','goldOwnObjectModuleV82','goldOwnObjectModuleV78','captureFreshV81')),
         'GD139_CLEANUP_FRESH_WRITE_ROLE_REJECTED')
    need(all(fresh['terminal'].get(k)==fresh.get(k) for k in
             ('processId','processCreationFileTimeUtc','hostProcessId','hostProcessCreationFileTimeUtc')),
         'GD139_CLEANUP_FRESH_IDENTITY_CHANGED')
    need(all(post.get(k) is True for k in ('sourcePinsSame','fullObjectDescriptorPreserved','fullLiveSourcePreserved',
        'ownDocumentAbsentFresh','ownDocumentAttributeAbsentFresh','ownTablePartAbsentFresh','ownTablePartAttributeAbsentFresh','allFreshOriginalsGone','freshLeaseReleased'))
         and type(post.get('completeDocumentModulesCompared')) is int and post['completeDocumentModulesCompared']==2,
         'GD139_CLEANUP_FRESH_POST_REJECTED')
    _zero(post,('configurationWrites','configurationExports','configurationImports','repositoryPlacement',
               'businessCalls','configurationSaves','databaseUpdates'))
    need(_document_control(proof)==_document_control(fresh),'GD139_CLEANUP_FRESH_CONTENT_CHANGED')
    return comparison,_identities(proof,prepared)|_identities(fresh)


def _route_count():
    state=Path(os.environ.get('AH1C_BRIDGE_STATE_DIR') or (Path(os.environ['LOCALAPPDATA'])/'AH_1C/bridge'))/'state.db'
    with closing(sqlite3.connect(state.as_uri()+'?mode=ro',uri=True)) as db:
        return db.execute("SELECT count(*) FROM execution_leases WHERE resource='ah1c-write'").fetchone()[0]


def verify(nonce):
    """Read and return observations repeatedly; never write a preflight receipt."""
    need(type(nonce) is str and re.fullmatch('[a-f0-9]{32}',nonce),'GD139_CLEANUP_NONCE_REJECTED')
    evidence=ROOT/'artifacts/designer-bridge';build=contained(ROOT/'build'/('designer-v43-'+nonce),ROOT/'build')
    need(build.parent==ROOT/'build','GD139_CLEANUP_BOUNDARY_REJECTED')
    proof_path=evidence/('v43-gold-startup-'+nonce+'.json');proof_body=_read(proof_path,evidence,1024*1024);proof=_json(proof_body)
    prepared=_json(_read(build/'v43-prepared.json',build,1024*1024))
    owner=_json(_read(build/'runtime-owner.json',build,128*1024))
    sessions=list(build.glob('session-*'));need(len(sessions)==1 and sessions[0].is_dir(),'GD139_CLEANUP_SESSION_REJECTED')
    session=contained(sessions[0],build)
    need(re.fullmatch('session-[a-f0-9]{32}',session.name),'GD139_CLEANUP_SESSION_REJECTED')
    native=parse_result(_read(session/RESULT_FILENAME,session,LIMIT))
    provisional=verify_native(native,proof['documentModulesComparisonV48']['version'],
                             lambda name:_read(session/name,session,1024))
    names=_required_names(native,provisional);witnesses=proof.get('goldOwnedDocumentStructureWitnessesV139')
    need(type(witnesses) is dict and set(witnesses)==set(names),'GD139_CLEANUP_WITNESS_SET_REJECTED')
    witness_dir=evidence/('v139-gold-owned-document-structure-'+nonce);bodies={}
    for name in names:
        limit=LIMIT if name==RESULT_FILENAME else 1024
        body=_read(session/name,session,limit);saved=_read(witness_dir/name,witness_dir,limit);item=witnesses[name]
        need(type(item) is dict and set(item)=={'path','bytes','sha256'} and type(item['path']) is str
             and Path(item['path'])==witness_dir/name and type(item['bytes']) is int and item['bytes']==len(body)
             and item['sha256']==_sha(body) and saved==body,'GD139_CLEANUP_WITNESS_CHANGED')
        bodies[name]=body
    need(_json(_read(build/'gold-read-result.json',build,16384))==proof['terminal'],'GD139_CLEANUP_TERMINAL_CHANGED')
    post=_json(_read(evidence/('v139-fresh-post-readonly-'+nonce+'.json'),evidence,128*1024))
    fresh_nonce=post.get('freshNonce')
    need(type(fresh_nonce) is str and re.fullmatch('[a-f0-9]{32}',fresh_nonce),'GD139_CLEANUP_FRESH_NONCE_REJECTED')
    fresh_path=evidence/('v43-gold-startup-'+fresh_nonce+'.json');fresh_body=_read(fresh_path,evidence,1024*1024);fresh=_json(fresh_body)
    comparison,identities=_verify_proofs(nonce,proof,native,bodies,prepared,owner,post,fresh,_sha(proof_body),_sha(fresh_body))
    need(proof['sourceSha256']==sources(),'GD139_CLEANUP_SOURCE_CHANGED')
    need(all(owned_process_gone(*item) for item in identities),'GD139_CLEANUP_ORIGINAL_RETAINED')
    need(_route_count()==0,'GD139_CLEANUP_ROUTE_BUSY')
    need(all(owned_process_gone(*item) for item in identities) and _route_count()==0 and proof['sourceSha256']==sources(),
         'GD139_CLEANUP_FRESH_BOUNDARY_CHANGED')
    return dict(stage='V139CompletedGoldOwnedDocumentStructureRuntimeVerified',passed=True,nonce=nonce,exactPath=str(build),
        goldProofSha256=_sha(proof_body),freshPostSha256=_sha(_read(evidence/('v139-fresh-post-readonly-'+nonce+'.json'),evidence,128*1024)),
        ownStructureVerified=comparison['ownStructureVerified'],knownTerminalVerified=True,physicalWitnessCount=comparison['physicalWitnessCount'],
        writeAttempts=native['writeAttempts'],configurationSaves=0,databaseUpdates=0,repositoryMutations=0,
        wholeRouteLeaseCount=0,allRecordedOriginalsGone=True,sourcePinsCurrent=True,normalDesignerExitClaimed=False,
        processStopPermitted=False,leaseMutationPermitted=False,
        originalIdentities=[dict(pid=p,birth=b,gone=True) for p,b in sorted(identities)])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--nonce',required=True)
    try:
        result=verify(parser.parse_args().nonce)
        print(json.dumps(dict(passed=True,nonce=result['nonce'],originalIdentityCount=len(result['originalIdentities']),
                              ownStructureVerified=result['ownStructureVerified'])))
    except Exception:
        print(json.dumps(dict(passed=False,code='GD139_COMPLETED_CLEANUP_REJECTED')));sys.exit(1)
