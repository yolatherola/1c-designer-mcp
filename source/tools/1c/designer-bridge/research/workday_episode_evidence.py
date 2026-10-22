"""Once-only bounded protocol3 accepted metadata JSONL; no source/frame I/O.

This validates metadata semantics, not independent SDK/config provenance. Root
must separately replay the physical closure and bind the returned file reference
to its frozen operation/plan. A failed partial CREATE_NEW file is never retried.
"""
import hashlib
import json
import math
from pathlib import Path
import re
import stat

from native_mcp import workday_receipt_observer as observer, workday_wire as wire, ram_wire
from native_mcp.saved_source import SnapshotReceipt, SourceBinding, Target, SavedRefusal, integer

ROOT = Path(__file__).resolve().parents[4]
FILE_NAME = 'workday-receipts.jsonl'
OBSERVER_SHA256 = 'fed1a725843aee2beee628229de5e383e6cd1d3f15b5074f585f3e614b4cdd2f'
MAX_RECORDS = 4096
MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = observer.MAX_RECORD_BYTES
MAX_FILE_BYTES = MAX_METADATA_BYTES + MAX_RECORDS
_RECORD_KEYS = frozenset(('kind', 'capturePhase', 'phase', 'ackConfirmed', 'eofConfirmed',
    'requestMetadata', 'nativeProof', 'epoch', 'snapshotReceipt', 'counts', 'sourceBodyIncluded', 'sourceFrameIncluded'))
_SUMMARY_INTS = frozenset(('profileVersion', 'protocolVersion', 'count', 'bytes', 'metadataBytes',
    'firstSequence', 'lastSequence', 'contexts', 'guardCount', 'readCount', 'closeCount', 'ackConfirmedCount'))
_SUMMARY_STR = frozenset(('kind', 'operationId', 'fileName', 'sha256'))
_SUMMARY_BOOL = frozenset(('closeAckEofObserved', 'metadataOnly', 'sourceBodyIncluded', 'sourceFrameIncluded'))
_SOURCE_COUNTS = ('bodyBytes', 'codePoints', 'crlfCount', 'bomPresent', 'endsLf', 'passes',
                  'propertyReads', 'fileOpens', 'adoptedFiles', 'storedBytes')


def _need(ok, code):
    if not ok:
        raise SavedRefusal('WORKDAY_EVIDENCE_' + code)


def _pins():
    _need(hashlib.sha256(Path(observer.__file__).read_bytes()).hexdigest() == OBSERVER_SHA256, 'OBSERVER_PIN')
    observer._pins()


def _hex(value, size):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None and value != '0'*size


def _plain(value, depth=0):
    """Reject object protocols before dictionary equality or serialization."""
    _need(depth <= 8, 'METADATA_DEPTH')
    kind = type(value)
    if kind is dict:
        _need(len(value) <= 128 and all(type(k) is str and len(k) <= 128 for k in value), 'METADATA_KEYS')
        for child in value.values(): _plain(child, depth+1)
    elif kind is list:
        _need(len(value) <= 32, 'METADATA_LIST')
        for child in value: _plain(child, depth+1)
    elif kind is str:
        _need(len(value) <= 128, 'METADATA_STRING')
    elif kind is int:
        _need(-2**31 <= value <= 2**53-1, 'METADATA_INTEGER')
    elif kind is float:
        _need(math.isfinite(value), 'METADATA_FLOAT')
    else:
        _need(kind in (bool, type(None)), 'METADATA_TYPE')


def _path(build, operation_id):
    _need(_hex(operation_id, 32), 'OPERATION')
    expected = ROOT / 'build' / ('designer-hot-v234-' + operation_id)
    _need(type(build) is type(ROOT) and build.is_absolute() and build == expected, 'PATH')
    for directory in (ROOT, ROOT / 'build', build):
        info = directory.lstat()
        _need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
              and not getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT, 'DIRECTORY')
    _need(build.resolve(strict=True) == expected, 'RESOLVED_PATH')
    return build / FILE_NAME


def _request(value):
    helper = observer._HELPERS
    out = helper['_typed'](value, ('requestId', 'targetUuidHex'),
        ('version', 'opcode', 'sequence', 'selector', 'revision', 'generation', 'guardSequence'), (),
        ('issuedAt', 'requestValidUntil', 'bindingValidUntil'))
    _need(out['version'] == 3 and _hex(out['requestId'], 32)
          and (out['targetUuidHex'] == '' if out['opcode'] == 5 else _hex(out['targetUuidHex'], 32)), 'REQUEST')
    frame = wire._COMMAND.pack(wire.COMMAND_MAGIC, out['version'], out['opcode'], out['sequence'], out['selector'],
        out['requestId'].encode('ascii'), bytes(32) if out['opcode'] == 5 else out['targetUuidHex'].encode('ascii'),
        out['revision'], out['issuedAt'], out['requestValidUntil'], out['generation'], out['bindingValidUntil'],
        out['guardSequence'], bytes(24), wire.TAIL)
    return observer._request(frame)


def _receipt(value):
    helper = observer._HELPERS
    out = helper['_typed'](value, ram_wire._STR, ram_wire._INT, ram_wire._BOOL, ram_wire._TIME, ('binding', 'target'))
    binding = helper['_binding'](value['binding'])
    target = helper['_target'](value['target'])
    # Construct only after exact primitive checks; no arbitrary object protocol.
    item = SnapshotReceipt(**out, binding=SourceBinding(**binding), target=Target(**target))
    result = helper['_receipt'](item)
    _need(0 <= result['byte_count'] <= 4194304 and 0 <= result['crlf_count'] <= 1048576
          and all(result[k] == 0 for k in ('helper_calls', 'source_writes', 'configuration_saves',
                                           'database_updates', 'repository_mutations'))
          and all(result[k] is True for k in ('identity_verified', 'repeated_read_verified', 'schema_verified')), 'RECEIPT')
    return result


def _state():
    return dict(count=0, contexts=0, guardCount=0, readCount=0, closeCount=0, closed=False,
                identity=None, sourceIdentity=None, lastGuard=None)


def _record(value, operation_id, state):
    _plain(value)
    _need(type(value) is dict and value.keys() == _RECORD_KEYS, 'RECORD_SCHEMA')
    _need(value['kind'] == 'WORKDAY_ACCEPTED_RECEIPT_METADATA'
          and value['capturePhase'] == 'VALIDATED_BEFORE_ACK' and value['phase'] == 'ACK_CONFIRMED'
          and value['ackConfirmed'] is True and type(value['eofConfirmed']) is bool
          and value['sourceBodyIncluded'] is False and value['sourceFrameIncluded'] is False, 'RECORD_FLAGS')
    request = _request(value['requestMetadata'])
    proof = observer._HELPERS['_proof'](value['nativeProof'])
    epoch = observer._HELPERS['_epoch'](value['epoch'])
    counts = observer._HELPERS['_typed'](value['counts'], (), ('contexts', 'workerThreadId'), ())
    op = request['opcode']
    _need(not state['closed'] and request['sequence'] == state['count']+1
          and type(proof['version']) is int and proof['version'] == 3
          and proof['operationId'] == operation_id and proof['status'] == (4 if op == 5 else 0)
          and counts['contexts'] == state['contexts']+(op != 5)
          and integer(counts['contexts'], 0, 4095) and integer(counts['workerThreadId'], 1, 2**32-1), 'SEQUENCE')
    for key in ('sequence', 'opcode', 'requestId', 'targetUuidHex', 'issuedAt', 'requestValidUntil',
                'generation', 'bindingValidUntil', 'guardSequence'):
        same = wire._same_double(proof[key], request[key]) if key in wire._PROOF_TIME else (
            type(proof[key]) is type(request[key]) and proof[key] == request[key])
        _need(same, 'REQUEST_JOIN')
    _need(proof['contextCount'] == counts['contexts'] and proof['workerThreadId'] == counts['workerThreadId']
          and epoch['operationId'] == proof['operationId'] and epoch['scopeSha256'] == proof['scopeSha256']
          and epoch['processId'] == proof['processId'] and epoch['executeThreadId'] == proof['guiThreadId'], 'EPOCH_JOIN')
    identity = tuple(proof[k] for k in ('operationId', 'scopeSha256', 'sessionId', 'installNonce',
                                      'processId', 'guiThreadId', 'workerThreadId'))
    _need(state['identity'] in (None, identity), 'IDENTITY_CHANGED')
    # Accepted metadata must describe a completed clean chain. This is not a
    # substitute for the root's pinned classifier/config/address replay.
    _need(proof['sdkRc'] == proof['terminalRc'] == epoch['sdkChainRc'] == 0
          and all(proof[k] is True for k in ('contextCleared', 'handlerRemoved', 'epochClean',
                                            'peerVerified', 'readyVerified', 'drainCompleted'))
          and all(epoch[k] is True for k in ('sdkChainEntered', 'sdkChainReturned', 'sdkChainComplete',
                                            'handlerRegistered', 'handlerRemoved'))
          and all(epoch[k] == 0 for k in ('cppThrows', 'cppThrowsExecuteThread', 'cppThrowsOtherThreads',
              'otherExceptions', 'otherExceptionsExecuteThread', 'otherExceptionsOtherThreads',
              'typeEventCount', 'decodedCppThrows', 'unknownCppThrows', 'listStreamCompatibleThrows'))
          and all(epoch[k] is False for k in ('counterOverflow', 'typeEventOverflow', 'typeDecoderReentry',
                                            'exceptionObjectRead', 'databaseUpdateAuthorized')), 'ACCEPTED_METADATA')
    _need(proof['hookRemoved'] is (op == 5) and proof['functionRetained'] is (op != 5)
          and epoch['executeEntered'] is (op != 5) and epoch['executeReturned'] is (op != 5)
          and epoch['sdkExecuteRc'] == (-2147483647 if op == 5 else 0)
          and value['eofConfirmed'] is (op == 5), 'CLOSE_METADATA')
    if op != 5:
        _need(proof['nativeEnvelopeValid'] is True and proof['nativeStatus'] == 1
              and proof['nativeReason'] == proof['nativeException'] == proof['pendingReference'] == 0
              and all(proof[k] == 1 for k in ('beforeClean', 'afterClean', 'prefixPreserved', 'typedCleared')), 'NATIVE_METADATA')
    if op == 3:
        _need(all(proof[k] == 2 for k in ('passes', 'propertyReads', 'fileOpens', 'adoptedFiles'))
              and integer(proof['storedBytes'], 1, 8*1048576)
              and integer(proof['codePoints'], 0, 1048576), 'READ_METADATA')
    else:
        _need(all(proof[k] == 0 for k in _SOURCE_COUNTS), 'NO_SOURCE_COUNTS')
    _need(request['issuedAt'] <= proof['sampledAt'] and (op == 5 or
          proof['sampledAt'] <= request['requestValidUntil']), 'SAMPLE_TIME')
    receipt = None
    if op == 3:
        receipt = _receipt(value['snapshotReceipt'])
        binding = receipt['binding']
        _need(receipt['request_id'] == request['requestId'] and receipt['revision'] == request['revision']
              and receipt['source_sha256'] == proof['sourceSha256']
              and receipt['saved_resource_sha256'] == proof['savedResourceSha256']
              and receipt['byte_count'] == proof['bodyBytes'] and binding['generation'] == request['generation']
              and binding['session_id'] == proof['sessionId'] and binding['process_id'] == proof['processId']
              and wire._same_double(binding['valid_until'], request['bindingValidUntil'])
              and receipt['target']['object_uuid'].replace('-', '') == request['targetUuidHex']
              and wire._same_double(receipt['sampled_at'], proof['sampledAt'])
              and wire._same_double(receipt['valid_until'], request['requestValidUntil'])
              and receipt['crlf_count'] == proof['crlfCount']
              and int(receipt['bom_present']) == proof['bomPresent'] and int(receipt['ends_lf']) == proof['endsLf'], 'RECEIPT_JOIN')
        guard = state['lastGuard']
        _need(guard is not None and guard['sequence'] == request['guardSequence']
              and all(guard[k] == request[k] for k in ('generation', 'targetUuidHex', 'bindingValidUntil'))
              and request['requestId'] != guard['requestId'] and request['issuedAt'] >= guard['issuedAt']
              and request['requestValidUntil'] <= guard['requestValidUntil'], 'GUARD_TICKET')
    else:
        _need(value['snapshotReceipt'] is None, 'NO_SOURCE_RECEIPT')
    if op == 4:
        guard = proof['guardState']
        _need(type(guard) is dict, 'GUARD_STATE')
        binding = guard['binding']
        _need(binding['generation'] == request['generation'] and binding['session_id'] == proof['sessionId']
              and binding['process_id'] == proof['processId']
              and wire._same_double(binding['valid_until'], request['bindingValidUntil'])
              and guard['target']['object_uuid'].replace('-', '') == request['targetUuidHex']
              and request['issuedAt'] <= guard['checked_at'] <= proof['sampledAt']
              <= guard['valid_until'] <= request['requestValidUntil']
              and proof['bodyBytes'] == 0 and proof['sourceSha256'] == proof['savedResourceSha256'] == '', 'GUARD_JOIN')
    else:
        _need(proof['guardState'] is None, 'GUARD_FORBIDDEN')
    if op != 5:
        source_identity = (binding['root_uuid'], binding['birth'], binding['source_domain'])
        _need(state['sourceIdentity'] in (None, source_identity), 'SOURCE_IDENTITY_CHANGED')
        state['sourceIdentity'] = source_identity
    if op == 5:
        _need(proof['guardState'] is None and proof['nativeEnvelopeValid'] is False
              and proof['bodyBytes'] == 0 and proof['sourceSha256'] == proof['savedResourceSha256'] == '', 'CLOSE_SOURCE')
    state.update(count=state['count']+1, contexts=counts['contexts'], identity=identity,
                 guardCount=state['guardCount']+(op == 4), readCount=state['readCount']+(op == 3),
                 closeCount=state['closeCount']+(op == 5), closed=op == 5,
                 lastGuard=request if op == 4 else None)
    return dict(kind=value['kind'], capturePhase=value['capturePhase'], phase=value['phase'], ackConfirmed=True,
                eofConfirmed=value['eofConfirmed'], requestMetadata=request, nativeProof=proof, epoch=epoch,
                snapshotReceipt=receipt, counts=counts, sourceBodyIncluded=False, sourceFrameIncluded=False)


def _encode(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')
    _need(len(raw) <= MAX_RECORD_BYTES, 'RECORD_BYTES')
    return raw


def _finish(state):
    _need(1 <= state['count'] <= MAX_RECORDS and state['closed'] is True and state['closeCount'] == 1, 'FINAL_CLOSE')


def _summary(operation_id, state, digest, size, metadata_size):
    _finish(state)
    return dict(kind='WORKDAY_EPISODE_RECEIPTS', profileVersion=234, protocolVersion=3, operationId=operation_id,
        fileName=FILE_NAME, sha256=digest, count=state['count'], bytes=size, metadataBytes=metadata_size,
        firstSequence=1, lastSequence=state['count'], contexts=state['contexts'], guardCount=state['guardCount'],
        readCount=state['readCount'], closeCount=state['closeCount'], ackConfirmedCount=state['count'],
        closeAckEofObserved=True, metadataOnly=True, sourceBodyIncluded=False, sourceFrameIncluded=False)


def _pairs(items):
    result = {}
    for key, value in items:
        _need(key not in result, 'DUPLICATE_KEY')
        result[key] = value
    return result


def _constant(_):
    raise SavedRefusal('WORKDAY_EVIDENCE_JSON_CONSTANT')


def _verify(path, operation_id, expected):
    info = path.lstat()
    _need(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
          and not getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
          and 1 <= info.st_size <= MAX_FILE_BYTES, 'FILE')
    state = _state(); digest = hashlib.sha256(); size = metadata_size = 0
    with path.open('rb') as stream:
        while True:
            raw = stream.readline(MAX_RECORD_BYTES+2)
            if not raw: break
            _need(state['count'] < MAX_RECORDS and raw.endswith(b'\n') and not raw.endswith(b'\r\n')
                  and 1 < len(raw) <= MAX_RECORD_BYTES+1, 'LINE')
            size += len(raw); metadata_size += len(raw)-1
            _need(size <= MAX_FILE_BYTES and metadata_size <= MAX_METADATA_BYTES, 'TOTAL_BYTES')
            digest.update(raw)
            value = json.loads(raw[:-1].decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)
            normalized = _record(value, operation_id, state)
            _need(_encode(normalized)+b'\n' == raw, 'CANONICAL')
            raw = value = normalized = None
    result = _summary(operation_id, state, digest.hexdigest(), size, metadata_size)
    _plain(expected)
    _need(type(expected) is dict and expected.keys() == _SUMMARY_INTS | _SUMMARY_STR | _SUMMARY_BOOL, 'SUMMARY_SCHEMA')
    _need(all(type(expected[k]) is int for k in _SUMMARY_INTS)
          and all(type(expected[k]) is str for k in _SUMMARY_STR)
          and all(type(expected[k]) is bool for k in _SUMMARY_BOOL) and expected == result, 'SUMMARY_JOIN')
    return result


def verify_receipts(build, operation_id, summary):
    """Stream hash/revalidate the exact fixed journal; never load all records."""
    failed = False; result = None
    try:
        _pins()
        result = _verify(_path(build, operation_id), operation_id, summary)
    except Exception:
        failed = True
    if failed:
        raise SavedRefusal('WORKDAY_EVIDENCE_VERIFY_UNPROVEN') from None
    return result


def write_receipts(build, operation_id, records):
    """Validate then CREATE_NEW one journal and stream-read it back once.

    Inputs must be detached accepted observer metadata. No second full collection
    is retained. On any post-create failure preserve the partial evidence file;
    never overwrite/retry or return a success summary for it.
    """
    failed = False; result = None
    try:
        _pins()
        path = _path(build, operation_id)
        _need(type(records) is list and 1 <= len(records) <= MAX_RECORDS, 'RECORDS')
        state = _state(); total = 0
        for record in records:
            total += len(_encode(_record(record, operation_id, state)))
            _need(total <= MAX_METADATA_BYTES, 'TOTAL_BYTES')
        _finish(state)
        state = _state(); digest = hashlib.sha256(); size = metadata_size = 0
        with path.open('xb') as stream:
            for record in records:
                raw = _encode(_record(record, operation_id, state))
                metadata_size += len(raw); size += len(raw)+1
                _need(metadata_size <= MAX_METADATA_BYTES and size <= MAX_FILE_BYTES, 'TOTAL_BYTES')
                _need(stream.write(raw+b'\n') == len(raw)+1, 'SHORT_WRITE')
                digest.update(raw+b'\n')
                raw = None
            stream.flush()
        result = _summary(operation_id, state, digest.hexdigest(), size, metadata_size)
        result = _verify(path, operation_id, result)
    except Exception:
        failed = True; result = None
    if failed:
        raise SavedRefusal('WORKDAY_EVIDENCE_WRITE_UNPROVEN') from None
    return result
