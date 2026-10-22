"""Bounded, read-only physical verification of this pilot's native CF pair.

No paths are extracted, no configuration is loaded, and no source is printed.
Native reopen proves metadata semantics; this independent check proves that
the exact processing/form/body streams also disappeared from the stored CF.
"""
from __future__ import annotations

import hashlib
import re
import struct
import uuid
import zlib

END = 0x7fffffff
MAX_FILE = 1024 * 1024
MAX_INFLATED = 4 * 1024 * 1024
PAGE = re.compile(rb"\r\n([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) \r\n")
PROCESSING = '8d64f197-c9b8-4332-90da-18f192cf1a57'
FORM = 'dadd405a-e2dc-435c-b3cd-d1b50ef0f301'
GOLD_ROOT = '218b5d00-7e10-486f-874c-73c2368ed5da'
OWN_STREAMS = frozenset((PROCESSING, FORM, FORM + '.0'))
SERVICE_STREAMS = frozenset(('root', 'version', 'versions'))
UUID_NAME = re.compile('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?:\\.0)?')


def _inflate(packet: bytes, remaining: int) -> bytes:
    inflater = zlib.decompressobj(-15)
    try:
        body = inflater.decompress(packet, remaining + 1)
    except zlib.error as error:
        raise ValueError('OWN_CF_DEFLATE_REJECTED') from error
    if len(body) > remaining or inflater.unconsumed_tail or not inflater.eof or inflater.unused_data:
        raise ValueError('OWN_CF_INFLATE_BOUNDS_REJECTED')
    return body


def read_entries(data: bytes, *, profile: str = 'pilot') -> dict[str, bytes]:
    """Read only the observed no-free-page CF layout; reject ambiguous storage."""
    if profile not in ('pilot', 'closure'):
        raise ValueError('OWN_CF_PROFILE_REJECTED')
    max_file, max_inflated, max_entries, max_blocks = ((MAX_FILE, MAX_INFLATED, 32, 256)
        if profile == 'pilot' else (8 * MAX_FILE, 64 * MAX_FILE, 256, 8192))
    names = UUID_NAME if profile == 'pilot' else re.compile('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?:\\.(?:[0-9]|1[0-5]))?')
    if not 16 < len(data) <= max_file:
        raise ValueError('OWN_CF_SIZE_REJECTED')
    free, page_size, count, reserved = struct.unpack_from('<IIII', data)
    if free != END or page_size != 512 or not 1 <= count <= max_entries or reserved != 0:
        raise ValueError('OWN_CF_HEADER_REJECTED')
    blocks = {}
    cursor = 16
    while cursor < len(data):
        match = PAGE.match(data, cursor)
        if not match or len(blocks) >= max_blocks:
            raise ValueError('OWN_CF_PAGE_REJECTED')
        size, capacity, following = (int(match[i], 16) for i in (1, 2, 3))
        end = cursor + 31 + capacity
        if not capacity or size > max_file or end > len(data):
            raise ValueError('OWN_CF_PAGE_BOUNDS_REJECTED')
        blocks[cursor] = (size, capacity, following)
        cursor = end
    owners = set()

    def stream(address: int) -> bytes:
        output = bytearray()
        total = None
        while address != END:
            if address in owners or address not in blocks:
                raise ValueError('OWN_CF_CHAIN_REJECTED')
            owners.add(address)
            size, capacity, following = blocks[address]
            if total is None:
                total = size
            elif len(output) >= total:
                raise ValueError('OWN_CF_CONTINUATION_REJECTED')
            take = min(capacity, total - len(output))
            output.extend(data[address + 31:address + 31 + take])
            address = following
        if total is None or len(output) != total:
            raise ValueError('OWN_CF_TRUNCATED_REJECTED')
        return bytes(output)

    toc = stream(16)
    if len(toc) != count * 12:
        raise ValueError('OWN_CF_COUNT_REJECTED')
    entries = {}
    remaining = max_inflated
    for offset in range(0, len(toc), 12):
        name_at, body_at, sentinel = struct.unpack_from('<III', toc, offset)
        if sentinel != END:
            raise ValueError('OWN_CF_SENTINEL_REJECTED')
        encoded = stream(name_at)
        if not 24 <= len(encoded) <= 128 or encoded[-4:] != bytes(4):
            raise ValueError('OWN_CF_NAME_REJECTED')
        try:
            name = encoded[20:-4].decode('utf-16-le').rstrip('\0')
        except UnicodeError as error:
            raise ValueError('OWN_CF_NAME_REJECTED') from error
        if name in entries or (name not in SERVICE_STREAMS and not names.fullmatch(name)):
            raise ValueError('OWN_CF_SCOPE_REJECTED')
        body = _inflate(stream(body_at), remaining)
        remaining -= len(body)
        entries[name] = body
    if owners != set(blocks):
        raise ValueError('OWN_CF_UNOWNED_PAGE_REJECTED')
    return entries


def verify_owned_pair(before: bytes, after: bytes, root_id: str) -> dict:
    """Require the fixed pilot streams before deletion and their absence after it."""
    try:
        root = str(uuid.UUID(root_id.strip('{}')))
    except (AttributeError, ValueError) as error:
        raise ValueError('OWN_CF_ROOT_REJECTED') from error
    if root in (GOLD_ROOT, PROCESSING, FORM) or uuid.UUID(root).int == 0:
        raise ValueError('OWN_CF_ROOT_REJECTED')
    created = read_entries(before)
    deleted = read_entries(after)
    shared = set(created) - OWN_STREAMS
    if (len(created) != 8 or len(deleted) != 5 or not OWN_STREAMS <= set(created)
            or set(deleted) != shared or not SERVICE_STREAMS | {root} <= shared
            or GOLD_ROOT in created or GOLD_ROOT in deleted):
        raise ValueError('OWN_CF_GRAPH_SCOPE_REJECTED')
    if root.encode() not in created['root'] or root.encode() not in deleted['root']:
        raise ValueError('OWN_CF_ROOT_INDEX_REJECTED')
    if ('АгентПробаИнструментов_c7bce69f'.encode() not in created[PROCESSING]
            or 'ФормаПроверкиИзменена'.encode() not in created[FORM]
            or b'c7bce69f' not in created[FORM + '.0']):
        raise ValueError('OWN_CF_PILOT_CONTENT_REJECTED')
    for name in shared - {root, 'versions'}:
        if created[name] != deleted[name]:
            raise ValueError('OWN_CF_SHARED_STREAM_CHANGED')
    return {
        'verified': True, 'beforeEntryCount': len(created), 'afterEntryCount': len(deleted),
        'ownProcessingFormBodyPhysicallyRemoved': True, 'rootIndexPreserved': True,
        'sharedStreamSetPreserved': True, 'sharedServiceContentPreserved': True,
        'beforeSha256': hashlib.sha256(before).hexdigest(),
        'afterSha256': hashlib.sha256(after).hexdigest(),
        'beforeBytes': len(before), 'afterBytes': len(after),
        'removedStreamNames': sorted(OWN_STREAMS), 'rootId': root,
    }


def verify_owned_import(before: bytes, after: bytes, root_id: str) -> dict:
    """Require one quoted-name edit plus exact native version-cookie maintenance."""
    try:
        root = str(uuid.UUID(root_id.strip('{}')))
    except (AttributeError, ValueError) as error:
        raise ValueError('OWN_IMPORT_ROOT_REJECTED') from error
    if root in (GOLD_ROOT, PROCESSING, FORM) or uuid.UUID(root).int == 0:
        raise ValueError('OWN_IMPORT_ROOT_REJECTED')
    source, result = read_entries(before), read_entries(after)
    if (len(source) != 8 or set(source) != set(result)
            or not OWN_STREAMS | SERVICE_STREAMS | {root} <= set(source)
            or GOLD_ROOT in source or root.encode() not in source['root']):
        raise ValueError('OWN_IMPORT_GRAPH_SCOPE_REJECTED')
    old = '"АгентПробаИнструментов_c7bce69f"'.encode()
    new = '"АгентПробаИнструментов_c7bce69fV16"'.encode()
    if source[PROCESSING].count(old) != 1 or new in source[PROCESSING]:
        raise ValueError('OWN_IMPORT_NAME_OCCURRENCE_REJECTED')
    if result[PROCESSING] != source[PROCESSING].replace(old, new, 1):
        raise ValueError('OWN_IMPORT_DESCRIPTOR_DIFF_REJECTED')
    if any(source[name] != result[name] for name in source if name not in (PROCESSING, 'versions')):
        raise ValueError('OWN_IMPORT_OTHER_STREAM_CHANGED')
    cookie_changes = []
    if source['versions'] != result['versions']:
        cookie_changes = _verify_import_versions(source['versions'], result['versions'], set(source))
    return {'verified': True, 'entryCount': len(source),
            'changedStreamCount': 1 + bool(cookie_changes), 'changedMetadataStreamCount': 1,
            'changedStreamName': PROCESSING, 'nameOccurrences': 1,
            'allOtherContentStreamsByteEqual': True, 'rootId': root,
            'versionCookieChangeCount': len(cookie_changes),
            'versionCookieChangedNames': cookie_changes,
            'beforeSha256': hashlib.sha256(before).hexdigest(),
            'afterSha256': hashlib.sha256(after).hexdigest(),
            'descriptorBeforeSha256': hashlib.sha256(source[PROCESSING]).hexdigest(),
            'descriptorAfterSha256': hashlib.sha256(result[PROCESSING]).hexdigest()}


def _verify_import_versions(before: bytes, after: bytes, filenames: set[str]) -> list[str]:
    """Validate the observed nine-entry native index; only four cookies may advance.

    Metadata/file contents, index keys, order, separators and every other cookie
    must remain identical. This exception does not permit new/removed objects.
    """
    cookie = rb'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
    pair = rb'"[^"\r\n]*",' + cookie
    full = re.compile(rb'\xef\xbb\xbf\{1,9,' + pair + rb'(?:,' + pair + rb'){8}\}')
    pairs = re.compile(rb'"([^"\r\n]*)",(' + cookie + rb')')

    def parse(packet):
        if len(packet) > 2048 or not full.fullmatch(packet):
            raise ValueError('OWN_IMPORT_VERSION_FORMAT_REJECTED')
        rows = [(match[1].decode('ascii'), match[2].decode('ascii')) for match in pairs.finditer(packet)]
        if len(rows) != 9 or len(dict(rows)) != 9 or set(dict(rows)) != filenames | {''}:
            raise ValueError('OWN_IMPORT_VERSION_KEYS_REJECTED')
        values = [uuid.UUID(value) for _, value in rows]
        if len(set(values)) != 9 or any(value.int == 0 for value in values):
            raise ValueError('OWN_IMPORT_VERSION_COOKIE_REJECTED')
        return rows

    source, result = parse(before), parse(after)
    if [name for name, _ in source] != [name for name, _ in result]:
        raise ValueError('OWN_IMPORT_VERSION_ORDER_REJECTED')
    changed = [name for (name, old), (_, new) in zip(source, result) if old != new]
    if set(changed) != {PROCESSING, 'root', 'version', 'versions'}:
        raise ValueError('OWN_IMPORT_VERSION_SCOPE_REJECTED')
    old_values = {value for _, value in source}
    if any(value in old_values for name, value in result if name in changed):
        raise ValueError('OWN_IMPORT_VERSION_FRESHNESS_REJECTED')
    return sorted(changed)
