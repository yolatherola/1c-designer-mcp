"""Bounded read-only decoder for a repository ObjectModule external file.

Accepts the observed raw-DEFLATE Format15 container with exactly info/text.
It never extracts paths or changes a configuration. Proofs expose hashes only.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import struct
import zlib

END = 0x7FFFFFFF
MAX_PACKET = 1024 * 1024
MAX_CONTAINER = 4 * 1024 * 1024
PAGE = re.compile(rb"\r\n([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) \r\n")


def normalize_editor_text(text: str) -> str:
    """Match native editor newline conversion; preserve all other characters."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


@dataclass(frozen=True)
class ModuleSource:
    text: str
    info: bytes
    packet_sha256: str
    text_bytes: int
    container_bytes: int

    def summary(self, live: str) -> dict:
        source = normalize_editor_text(self.text).encode("utf-8")
        current = normalize_editor_text(live).encode("utf-8")
        return {
            "packetSha256": self.packet_sha256,
            "containerBytes": self.container_bytes,
            "textBytes": self.text_bytes,
            "sourceCharacters": len(self.text),
            "liveCharacters": len(live),
            "infoSha256": hashlib.sha256(self.info).hexdigest(),
            "sourceNormalizedSha256": hashlib.sha256(source).hexdigest(),
            "liveNormalizedSha256": hashlib.sha256(current).hexdigest(),
            "rawTextEqual": self.text == live,
            "normalizedLineEndingsEqual": source == current,
            "normalization": "bom-decoding-and-newlines-only",
        }


def decode_module_packet(packet: bytes) -> ModuleSource:
    if not packet or len(packet) > MAX_PACKET:
        raise ValueError("MODULE_PACKET_SIZE_REJECTED")
    inflater = zlib.decompressobj(-15)
    try:
        data = inflater.decompress(packet, MAX_CONTAINER + 1)
    except zlib.error as error:
        raise ValueError("MODULE_DEFLATE_REJECTED") from error
    if (len(data) > MAX_CONTAINER or inflater.unconsumed_tail or
            not inflater.eof or inflater.unused_data):
        raise ValueError("MODULE_DEFLATE_BOUNDS_REJECTED")
    if len(data) < 16 or struct.unpack_from("<IIII", data) != (END, 512, 1, 0):
        raise ValueError("MODULE_CONTAINER_HEADER_REJECTED")
    blocks = {}
    cursor = 16
    while cursor < len(data):
        match = PAGE.match(data, cursor)
        if not match or len(blocks) >= 4096:
            raise ValueError("MODULE_PAGE_HEADER_REJECTED")
        size, capacity, following = (int(match[i], 16) for i in (1, 2, 3))
        last = cursor + 31 + capacity
        if not capacity or size > MAX_CONTAINER or last > len(data):
            raise ValueError("MODULE_PAGE_BOUNDS_REJECTED")
        blocks[cursor] = (size, capacity, following)
        cursor = last
    owners = set()

    def stream(address: int) -> bytes:
        output = bytearray()
        total = None
        while address != END:
            if address in owners or address not in blocks:
                raise ValueError("MODULE_PAGE_CHAIN_REJECTED")
            owners.add(address)
            size, capacity, following = blocks[address]
            if total is None:
                total = size
            elif len(output) >= total:
                raise ValueError("MODULE_PAGE_CONTINUATION_REJECTED")
            take = min(capacity, total - len(output))
            output.extend(data[address + 31:address + 31 + take])
            address = following
        if total is None or len(output) != total:
            raise ValueError("MODULE_STREAM_TRUNCATED")
        return bytes(output)

    toc = stream(16)
    if len(toc) != 24:
        raise ValueError("MODULE_ENTRY_COUNT_REJECTED")
    entries = {}
    for offset in (0, 12):
        name_at, body_at, sentinel = struct.unpack_from("<III", toc, offset)
        if sentinel != END:
            raise ValueError("MODULE_ENTRY_SENTINEL_REJECTED")
        encoded = stream(name_at)
        if len(encoded) < 24 or len(encoded) > 128 or encoded[-4:] != bytes(4):
            raise ValueError("MODULE_ENTRY_NAME_REJECTED")
        try:
            name = encoded[20:-4].decode("utf-16-le").rstrip("\0")
        except UnicodeError as error:
            raise ValueError("MODULE_ENTRY_NAME_REJECTED") from error
        if name not in ("info", "text") or name in entries:
            raise ValueError("MODULE_ENTRY_SCOPE_REJECTED")
        entries[name] = stream(body_at)
    if set(entries) != {"info", "text"} or owners != set(blocks):
        raise ValueError("MODULE_UNOWNED_STREAM_REJECTED")
    if not entries["info"] or len(entries["info"]) > 1024 or not entries["text"]:
        raise ValueError("MODULE_PAYLOAD_SIZE_REJECTED")
    try:
        text = entries["text"].decode("utf-8-sig")
        entries["info"].decode("utf-8-sig")
    except UnicodeError as error:
        raise ValueError("MODULE_PAYLOAD_ENCODING_REJECTED") from error
    return ModuleSource(text, entries["info"], hashlib.sha256(packet).hexdigest(),
                        len(entries["text"]), len(data))
