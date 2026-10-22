"""Version3 bounded accepted-metadata journal; never stores bodies or frames.

The trusted validator runs first. Only its accepted whitelist metadata is copied;
ACK is recorded after exchange returns. Capacity checks reserve a final CLOSE.
No OS/SDK calls, retries, persistence, or implicit native admission occur here.
"""
import ast
import hashlib
import inspect
import json
from pathlib import Path
import re
import threading

from . import workday_wire as wire, ram_wire
from .saved_source import (SnapshotReceipt, SavedSnapshot, SourceBinding, Target,
                           SavedRefusal, finite, integer)

PINS = {
    'resident_receipt_observer.py': '5ef7207201dca1bf54cc828027ff07c7d1b6caa7159c9c5feacb9cea44d5cbe6',
    'workday_wire.py': '06945271bfa4f22a474e400587ba8d558c4e6a8be2821ad9c4592bdd14790f46',
    'workday_channel.py': '3b601e1164fee759044cb3a77c43c9fb6f439ead0ce426eb9865df362f0bf6d8',
    'ram_wire.py': '4aa2e5c4555850633f1a2af7a0a1944b03e1c01d780f3b150e31a7b725d1776a',
}
MAX_RECORDS = 4096
HARD_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = wire.MAX_PROOF_BYTES + wire.MAX_EPOCH_BYTES + ram_wire.MAX_METADATA_BYTES + 2048


def _need(ok, code):
    if not ok:
        raise SavedRefusal('SAVED_WORKDAY_OBSERVER_' + code)


def _pins():
    here = Path(__file__).resolve().parent
    for name, pin in PINS.items():
        _need(hashlib.sha256((here / name).read_bytes()).hexdigest() == pin, 'DEPENDENCY_PIN')
    _need(wire.MAX_SEQUENCE == MAX_RECORDS and wire.PROTOCOL_VERSION == 3
          and wire.TAIL == 0x33444D43 and 'version' in wire._PROOF_INT, 'WIRE_PROFILE')


def _load_helpers():
    """Copy pinned whitelist helpers into private globals bound to new wire.

    The frozen module is neither imported nor patched. No frozen request/capture
    or 64-command limits are inherited; only primitive metadata selectors remain.
    """
    here = Path(__file__).resolve().parent
    source = (here / 'resident_receipt_observer.py').read_bytes()
    _need(hashlib.sha256(source).hexdigest() == PINS['resident_receipt_observer.py'], 'HELPER_PIN')
    names = {'_hex', '_typed', '_size', '_binding', '_target', '_guard', '_receipt', '_proof', '_epoch'}
    constants = {'_EPOCH_STR', '_EPOCH_INT', '_EPOCH_BOOL', '_EPOCH_KEYS'}
    selected = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            selected.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in node.targets):
            selected.append(node)
    _need({n.name for n in selected if isinstance(n, ast.FunctionDef)} == names, 'HELPER_NAMES')
    namespace = dict(_need=_need, re=re, json=json, wire=wire, ram_wire=ram_wire,
                     SnapshotReceipt=SnapshotReceipt, SourceBinding=SourceBinding,
                     Target=Target, finite=finite, integer=integer)
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<pinned-workday-metadata-helpers>', 'exec'), namespace)
    return {name: namespace[name] for name in names}


_HELPERS = _load_helpers()


def _request(command):
    _need(type(command) is bytes and len(command) == wire.COMMAND_BYTES, 'COMMAND')
    magic, version, op, seq, selector, nonce, target, revision, issued, valid, generation, bvalid, guard, reserved, tail = wire._COMMAND.unpack(command)
    _need(magic == wire.COMMAND_MAGIC and version == 3 and reserved == bytes(24) and tail == wire.TAIL
          and op in (3, 4, 5) and 1 <= seq <= MAX_RECORDS and (seq < MAX_RECORDS or op == 5)
          and selector == (0 if op == 5 else op), 'COMMAND')
    try:
        request_id = nonce.decode('ascii')
        target_id = '' if op == 5 else target.decode('ascii')
    except UnicodeError:
        raise SavedRefusal('SAVED_WORKDAY_OBSERVER_COMMAND') from None
    _need(_HELPERS['_hex'](request_id, 32)
          and (target == bytes(32) if op == 5 else _HELPERS['_hex'](target_id, 32))
          and integer(revision, 0, 2**53-1) and integer(generation, 1, 2**53-1)
          and all(finite(v) and 0 <= v <= 2**53-1 for v in (issued, valid, bvalid))
          and 0 < valid-issued <= 60 and bvalid > 0 and (revision > 0 if op == 3 else revision == 0)
          and (guard == seq-1 and guard > 0 if op == 3 else guard == 0), 'COMMAND')
    return dict(version=version, opcode=op, sequence=seq, selector=selector, requestId=request_id,
                targetUuidHex=target_id, revision=revision, issuedAt=issued,
                requestValidUntil=valid, generation=generation, bindingValidUntil=bvalid, guardSequence=guard)


def _capture(request, result, expected_contexts):
    _need(type(result) is tuple and len(result) == 2 and type(result[0]) is wire.ResidentResponse
          and type(result[1]) is tuple and len(result[1]) == 2, 'VALIDATOR_RESULT')
    response, counts = result
    _need(integer(counts[0], 0, MAX_RECORDS) and integer(counts[1], 1, 2**32-1)
          and counts[0] == expected_contexts, 'COUNTS')
    proof = _HELPERS['_proof'](response.proof)
    epoch = _HELPERS['_epoch'](response.epoch)
    _need(type(proof['version']) is int and proof['version'] == 3, 'PROOF_VERSION')
    _need(type(response.sequence) is int and response.sequence == request['sequence']
          and type(response.opcode) is int and response.opcode == request['opcode']
          and type(response.status) is int and response.status == (4 if response.opcode == 5 else 0), 'RESPONSE')
    for key in ('sequence', 'opcode', 'requestId', 'targetUuidHex', 'issuedAt', 'requestValidUntil',
                'generation', 'bindingValidUntil', 'guardSequence'):
        matched = wire._same_double(proof[key], request[key]) if key in wire._PROOF_TIME else (
            type(proof[key]) is type(request[key]) and proof[key] == request[key])
        _need(matched, 'JOIN')
    _need(proof['status'] == response.status and proof['contextCount'] == counts[0]
          and proof['workerThreadId'] == counts[1] and epoch['operationId'] == proof['operationId']
          and epoch['scopeSha256'] == proof['scopeSha256'] and epoch['processId'] == proof['processId']
          and epoch['executeThreadId'] == proof['guiThreadId'], 'JOIN')
    receipt = None
    if response.opcode == 3:
        _need(type(response.snapshot) is SavedSnapshot, 'SNAPSHOT')
        receipt = _HELPERS['_receipt'](response.snapshot.receipt)
        _need(receipt['request_id'] == request['requestId'] and receipt['revision'] == request['revision']
              and receipt['source_sha256'] == proof['sourceSha256']
              and receipt['saved_resource_sha256'] == proof['savedResourceSha256']
              and receipt['byte_count'] == proof['bodyBytes'], 'RECEIPT_JOIN')
    else:
        _need(response.snapshot is None, 'SNAPSHOT_FORBIDDEN')
    record = dict(kind='WORKDAY_ACCEPTED_RECEIPT_METADATA', capturePhase='VALIDATED_BEFORE_ACK', phase='ACK_CONFIRMED',
                  ackConfirmed=False, eofConfirmed=False, requestMetadata=request, nativeProof=proof, epoch=epoch,
                  snapshotReceipt=receipt, counts=dict(contexts=counts[0], workerThreadId=counts[1]),
                  sourceBodyIncluded=False, sourceFrameIncluded=False)
    _HELPERS['_size'](record, MAX_RECORD_BYTES)
    return record


def _encode(record):
    encoded = json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')
    _need(len(encoded) <= MAX_RECORD_BYTES, 'RECORD_BOUND')
    return encoded


class WorkdayReceiptObserver:
    """One-inflight decorator, 4096 records/64MiB including reserved CLOSE.

    can_accept(n) is a conservative O(1) check, not a reservation. The lifecycle
    must hold its own tool/batch lock across check and dispatch. records() alone
    copies the journal. Stored JSON bytes exclude frames, bodies, response objects
    and exception objects; Python container overhead is separately count-bounded.
    """
    def __init__(self, channel, *, maximum_records=MAX_RECORDS, maximum_bytes=HARD_BYTES):
        _pins()
        _need(integer(maximum_records, 1, MAX_RECORDS) and integer(maximum_bytes, MAX_RECORD_BYTES, HARD_BYTES), 'CAP')
        _need(callable(getattr(channel, 'exchange', None)) and callable(getattr(channel, 'wait_closed', None)), 'CHANNEL')
        self._channel = channel
        self._maximum = maximum_records
        self._hard_bytes = maximum_bytes
        self._records = []
        self._record_bytes = 0
        self._contexts = 0
        self._failed = False
        self._close_recorded = False
        self._eof_confirmed = False
        self._serial = threading.Lock()
        self._metadata = threading.Lock()

    @property
    def path(self): return self._channel.path
    @property
    def closed(self): return self._channel.closed
    @property
    def sealed(self): return self._failed or self._channel.sealed
    @property
    def owner_thread_alive(self): return self._channel.owner_thread_alive

    def connect(self): return self._channel.connect()
    def abort_before_connect(self): return self._channel.abort_before_connect()

    def _ordinary_capacity(self):
        if self._failed or self._close_recorded or self._channel.closed or self._channel.sealed:
            return 0
        return max(0, min(self._maximum-1-len(self._records),
                          (self._hard_bytes-MAX_RECORD_BYTES-self._record_bytes)//MAX_RECORD_BYTES))

    def can_accept(self, commands):
        """Check a whole ordinary batch, preserving a worst-case CLOSE record."""
        _need(integer(commands, 1, MAX_RECORDS-1), 'BATCH')
        with self._metadata:
            return commands <= self._ordinary_capacity()

    def status(self):
        """Return O(1) body-free counters; no full-record polling or copies."""
        with self._metadata:
            return dict(kind='WORKDAY_RECEIPT_OBSERVER_STATUS', version=3, recordCount=len(self._records),
                        recordBytes=self._record_bytes, maximumRecords=self._maximum, hardBytes=self._hard_bytes,
                        maximumRecordBytes=MAX_RECORD_BYTES, ordinaryCapacity=self._ordinary_capacity(),
                        closeReservedRecords=0 if self._close_recorded else 1,
                        closeReservedBytes=0 if self._close_recorded else MAX_RECORD_BYTES,
                        nextSequence=len(self._records)+1, contexts=self._contexts, failed=self._failed,
                        closeRecorded=self._close_recorded, eofConfirmed=self._eof_confirmed,
                        sourceBodyIncluded=False, sourceFrameIncluded=False)

    def records(self):
        """Explicit detached metadata copies; never called by status/capacity."""
        with self._metadata:
            return [json.loads(record) for record in self._records]

    def wait_closed(self, timeout=5.0):
        result = self._channel.wait_closed(timeout)
        if result is True and self._channel.closed is True:
            with self._metadata:
                if self._close_recorded and not self._eof_confirmed:
                    record = json.loads(self._records[-1])
                    record['eofConfirmed'] = True
                    encoded = _encode(record)
                    self._record_bytes += len(encoded)-len(self._records[-1])
                    self._records[-1] = encoded
                    self._eof_confirmed = True
        return result

    def exchange(self, command, validator):
        _need(callable(validator) and not inspect.iscoroutinefunction(validator), 'VALIDATOR')
        _need(self._serial.acquire(blocking=False), 'BUSY')
        capture = None
        result = None
        calls = 0
        failed = False
        try:
            # Known local capacity refusals occur before transport and do not
            # seal the journal: its final CLOSE remains dispatchable.
            request = _request(command)
            with self._metadata:
                _need(not self._failed and not self._close_recorded, 'SEALED')
                _need(request['sequence'] == len(self._records)+1, 'SEQUENCE')
                if request['opcode'] == 5:
                    _need(len(self._records) < self._maximum
                          and self._record_bytes+MAX_RECORD_BYTES <= self._hard_bytes, 'CLOSE_CAP')
                else:
                    _need(self._ordinary_capacity() >= 1, 'CAP')
                expected_contexts = self._contexts+(request['opcode'] != 5)
        except BaseException:
            self._serial.release()
            raise
        try:
            def validate(raw):
                nonlocal capture, calls
                calls += 1
                _need(calls == 1, 'DUPLICATE_VALIDATOR')
                validated = validator(raw)  # Physical/native validator FIRST.
                if inspect.isawaitable(validated):
                    if inspect.iscoroutine(validated): validated.close()
                    raise SavedRefusal('SAVED_WORKDAY_OBSERVER_ASYNC_VALIDATOR')
                capture = _capture(request, validated, expected_contexts)
                return validated
            result = self._channel.exchange(command, validate)
            _need(capture is not None, 'VALIDATOR_NOT_CALLED')
            capture['ackConfirmed'] = True
            if request['opcode'] == 5:
                capture['eofConfirmed'] = self._channel.closed is True
            encoded = _encode(capture)
            with self._metadata:
                _need(self._record_bytes+len(encoded) <= self._hard_bytes, 'TOTAL_BOUND')
                self._records.append(encoded)
                self._record_bytes += len(encoded)
                self._contexts = expected_contexts
                if request['opcode'] == 5:
                    self._close_recorded = True
                    self._eof_confirmed = capture['eofConfirmed']
        except Exception:
            self._failed = True
            failed = True
            result = None
        finally:
            capture = None
            self._serial.release()
        # No original exception/source frame retained as diagnostic __context__.
        if failed:
            raise SavedRefusal('SAVED_WORKDAY_OBSERVER_EXCHANGE_UNPROVEN') from None
        return result
