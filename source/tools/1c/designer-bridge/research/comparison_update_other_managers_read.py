"""Pure projection of the prebound Update29 owner's other-manager list.

No process opener, native invoker, callbacks, writer or CLI exists here. The
caller supplies an already validated VM_READ reader and independently proves
the actual command owner, including its delegated target. A cached false is
only the selection that c1240 would currently make, not a fresh DB comparison.
"""
from __future__ import annotations

import hashlib
import re
import struct


PLATFORM_VERSION = '8.3.18.1208'
PLATFORM_SHA = '5579c1f48bf8fa512fbb87d04603b871a204e48be67ad7868bc7b51749391219'
SPANS = {
    'updateTraversal': (0xc1240, 195, '6b673c49f66cab55027ff37d31543b63af9e54238a4dd40ee6ab7db92d6e4d65'),
    'pendingPredicate': (0xbc420, 341, '7900c5cfa6541d2ae4b54620c7f4a621b93ccaef3467b1c5fc5f2aac2ca1114c'),
    'eligiblePredicate': (0xbc8a0, 266, '77b1631824b95d872e0c49c03e960ceb66837bc59e9eef8d3e5bee98b83ef02b'),
}
MAXIMUM_NODES = 128


def _need(ok, code):
    if not ok:
        raise ValueError('UPDATE_OTHER_MANAGERS_' + code)


def _primary_receipt():
    return {'kind': 'UPDATE_OTHER_MANAGERS_PRIMARY', 'platformVersion': PLATFORM_VERSION,
            'platformSha256': PLATFORM_SHA, 'spanSha256': {k: v[2] for k, v in SPANS.items()},
            'primaryBytesVerified': True, 'runtimeOwnerBindingVerified': False}


def verify_primary_units(bodies):
    """Verify only the three fixed technical bodies; never load a DLL."""
    _need(type(bodies) is dict and set(bodies) == set(SPANS), 'PRIMARY_UNIT_SET')
    for key, (_, size, pin) in SPANS.items():
        raw = bodies[key]
        _need(type(raw) is bytes and len(raw) == size and
              hashlib.sha256(raw).hexdigest() == pin, 'PRIMARY_UNIT_PIN')
    return _primary_receipt()


def verify_primary():
    """Read the existing hash-pinned installed PE offline; no native calls."""
    from repository_pe_probe import PE
    image = PE('config.dll')
    bodies = {}
    for key, (rva, size, _) in SPANS.items():
        offset = image.offset(image.base + rva)
        bodies[key] = image.data[offset:offset + size]
    return verify_primary_units(bodies)


def _pointer(value, code='POINTER'):
    _need(type(value) is int and 0x10000 <= value <= 0xffffffcc and value % 4 == 0, code)
    return value


def project_other_managers(read_exact, *, owner, main_entry, binding, primary_proof,
                           maximum_nodes=MAXIMUM_NODES):
    """Read two bounded technical snapshots, refusing uncertain cached states.

    read_exact(address,size) must independently validate committed readable
    pages and return exactly bytes. No handles/references are acquired here.
    binding is a caller's external provenance assertion, never established by
    this function. The receipt grants neither Update29 nor global pending-clean.
    Unknown/dirty input raises a stable ValueError without returning raw data.
    """
    _need(callable(read_exact), 'READER')
    _pointer(owner); _pointer(main_entry)
    _need(type(maximum_nodes) is int and 1 <= maximum_nodes <= MAXIMUM_NODES, 'BOUND')
    _need(type(primary_proof) is dict and primary_proof == _primary_receipt(), 'PRIMARY_PROOF')
    _need(type(binding) is dict and binding.get('kind') == 'PREBOUND_UPDATE29_OWNER' and
          binding.get('platformVersion') == PLATFORM_VERSION and
          binding.get('ownerPointer') == owner and binding.get('mainEntryPointer') == main_entry and
          type(binding.get('ownerPointer')) is int and type(binding.get('mainEntryPointer')) is int and
          all(binding.get(key) is True for key in ('actualUpdate29OwnerVerified',
              'delegatedTargetResolved', 'readablePagesValidated')) and
          type(binding.get('proofSha256')) is str and
          re.fullmatch('[0-9a-f]{64}', binding['proofSha256']) is not None, 'BINDING_REQUIRED')

    def read(address, size):
        _need(type(address) is int and 0x10000 <= address <= 0xffffffff - size + 1 and
              type(size) is int and 0 < size <= 0x30, 'READ_RANGE')
        try:
            raw = read_exact(address, size)
        except Exception:
            raise ValueError('UPDATE_OTHER_MANAGERS_READ_FAILED') from None
        _need(type(raw) is bytes and len(raw) == size, 'READ_EXACT')
        return raw

    def snapshot():
        chunks = []

        def take(address, size):
            raw = read(address, size)
            chunks.append((address, raw))
            return raw

        owner_fields = take(owner + 0x64, 12)
        actual_main, _, head = struct.unpack('<3I', owner_fields)
        _need(actual_main == main_entry, 'MAIN_BINDING_CHANGED')
        _pointer(head, 'HEAD_POINTER')
        _need(head not in (owner, main_entry), 'STRUCTURE_ALIAS')
        first_raw = take(head, 4)
        node = struct.unpack('<I', first_raw)[0]
        seen = set()
        rows = []
        while node != head:
            _pointer(node, 'NODE_POINTER')
            _need(node not in seen, 'CYCLE')
            _need(node not in (owner, main_entry), 'STRUCTURE_ALIAS')
            _need(len(rows) < maximum_nodes, 'NODE_BOUND')
            seen.add(node)
            node_raw = take(node, 0x1c)
            next_node = struct.unpack_from('<I', node_raw)[0]
            entry = struct.unpack_from('<I', node_raw, 0x18)[0]
            _pointer(entry, 'ENTRY_POINTER')
            _need(entry not in (owner, head) and entry not in seen, 'STRUCTURE_ALIAS')
            entry_raw = take(entry, 0x30)
            rows.append((node, entry, entry_raw[0x14], struct.unpack_from('<I', entry_raw, 0x28)[0]))
            node = next_node
        _need(not any(row[1] in seen for row in rows), 'STRUCTURE_ALIAS')
        _need(take(head, 4) == first_raw and take(owner + 0x64, 12) == owner_fields,
              'IN_PASS_CHANGED')
        return chunks, rows, head

    first, first_rows, head = snapshot()
    second, rows, second_head = snapshot()
    _need(first == second and first_rows == rows and head == second_head, 'TWO_PASS_CHANGED')
    other = [row for row in rows if row[1] != main_entry]
    _need(all(row[2] == 0 for row in other), 'OTHER_NONCACHED_PREDICATE')
    _need(all(row[3] == 2 for row in other), 'OTHER_PENDING_NOT_FALSE')
    digest = hashlib.sha256()
    for address, raw in first:
        digest.update(struct.pack('<II', address, len(raw)))
        digest.update(raw)
    return {
        'kind': 'UPDATE_OTHER_MANAGERS_VM_READ_PROJECTION',
        'status': 'OTHER_MANAGERS_CACHED_FALSE', 'platformVersion': PLATFORM_VERSION,
        'ownerPointer': owner, 'mainEntryPointer': main_entry, 'headPointer': head,
        'listNodes': len(rows), 'otherListOccurrences': len(other),
        'otherUniqueEntries': len({row[1] for row in other}),
        'mainEntryListOccurrences': len(rows) - len(other),
        'emptyList': not rows, 'twoIdenticalPasses': True,
        'snapshotSha256': digest.hexdigest(), 'ownerBindingProofSha256': binding['proofSha256'],
        'callerOwnerBindingAssertionAccepted': True, 'actual29OwnerBindingEstablishedHere': False,
        'otherEntriesCurrentlySkippedByC1240': True, 'freshOtherMainDbEqualityProved': False,
        'mainPendingCompositionProved': False, 'globalPendingClean': False,
        'updateAdmissionGranted': False, 'primaryProof': _primary_receipt(),
        'nativeCalls': 0, 'sourceWrites': 0, 'configurationSaves': 0,
        'databaseUpdates': 0, 'repositoryMutations': 0,
    }
