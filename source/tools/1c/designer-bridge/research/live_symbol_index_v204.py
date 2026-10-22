"""RAM-only symbols/direct calls from verified native-provider text snapshots.

No bodies are retained, no file cache/SQLite/server is used, and no query invokes
a provider. The native provider and MCP integration are separate unverified work.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Callable

from rlm_ram_parser_adapter_v204 import ParsedModule, RamParserRefusal, RlmRamParserAdapter, text_hash

_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_MODULES = 256
MAX_REVISION = 2**53 - 1


class LiveIndexRefusal(ValueError):
    """Stable refusal code; no provider text/exception details are included."""


def _uuid(value: str) -> None:
    if type(value) is not str or not _UUID.fullmatch(value) or value == "00000000-0000-0000-0000-000000000000":
        raise LiveIndexRefusal("IDENTITY_UUID")


def _number(value: int, low: int, high: int, reason: str) -> None:
    if type(value) is not int or not low <= value <= high:
        raise LiveIndexRefusal(reason)


@dataclass(frozen=True, slots=True)
class SourceScope:
    root_uuid: str
    container_token: str
    generation: int
    source_kind: str = "editable"

    def validate(self) -> None:
        _uuid(self.root_uuid)
        if type(self.container_token) is not str or not _TOKEN.fullmatch(self.container_token):
            raise LiveIndexRefusal("CONTAINER_TOKEN")
        _number(self.generation, 1, MAX_REVISION, "SCOPE_GENERATION")
        if type(self.source_kind) is not str or self.source_kind not in {"editable", "database"}:
            raise LiveIndexRefusal("SOURCE_KIND")


@dataclass(frozen=True, slots=True)
class ModuleTarget:
    object_uuid: str
    property_uuid: str

    def validate(self) -> None:
        _uuid(self.object_uuid)
        _uuid(self.property_uuid)
        if self.object_uuid == self.property_uuid:
            raise LiveIndexRefusal("TARGET_ALIAS")


@dataclass(frozen=True, slots=True)
class VerifiedSnapshot:
    scope: SourceScope
    target: ModuleTarget
    source_sha256: str
    revision: int
    text: str = field(repr=False, compare=False)
    identity_verified: bool = False
    freshness_verified: bool = False
    read_only: bool = False


@dataclass(slots=True)
class _ModuleRecord:
    target: ModuleTarget
    source_sha256: str
    revision: int
    parsed: ParsedModule
    stale: bool = False


class LiveSymbolIndex:
    """Small explicit-coverage live index; every result has writer permission false.

    apply_snapshot validates provider observations but does not itself read native
    state. The caller must supply a independently verified provider snapshot.
    """

    def __init__(self, scope: SourceScope, parser: RlmRamParserAdapter | None = None):
        if type(scope) is not SourceScope:
            raise LiveIndexRefusal("SCOPE_TYPE")
        scope.validate()
        self._scope = scope
        self._seen_scopes = {scope}
        self._parser = parser if parser is not None else RlmRamParserAdapter()
        self._records: dict[ModuleTarget, _ModuleRecord] = {}
        self._cache_epoch = 1
        self.provider_read_attempts = 0

    @property
    def scope(self) -> SourceScope:
        return self._scope

    def _target(self, target: ModuleTarget) -> None:
        if type(target) is not ModuleTarget:
            raise LiveIndexRefusal("TARGET_TYPE")
        target.validate()

    def apply_snapshot(self, snapshot: VerifiedSnapshot) -> dict:
        if type(snapshot) is not VerifiedSnapshot or type(snapshot.scope) is not SourceScope:
            raise LiveIndexRefusal("SNAPSHOT_TYPE")
        snapshot.scope.validate()
        if snapshot.scope != self._scope:
            raise LiveIndexRefusal("SCOPE_MISMATCH")
        self._target(snapshot.target)
        _number(snapshot.revision, 1, MAX_REVISION, "REVISION")
        for verified in (snapshot.identity_verified, snapshot.freshness_verified, snapshot.read_only):
            if type(verified) is not bool or verified is not True:
                raise LiveIndexRefusal("UNVERIFIED_SNAPSHOT")
        if type(snapshot.source_sha256) is not str or not _SHA.fullmatch(snapshot.source_sha256):
            raise LiveIndexRefusal("SOURCE_HASH")
        try:
            actual_hash = text_hash(snapshot.text)
        except RamParserRefusal as refusal:
            raise LiveIndexRefusal(str(refusal)) from None
        if actual_hash != snapshot.source_sha256:
            raise LiveIndexRefusal("SOURCE_HASH")
        previous = self._records.get(snapshot.target)
        if previous is not None:
            if snapshot.revision < previous.revision:
                raise LiveIndexRefusal("REVISION_ROLLBACK")
            if snapshot.revision == previous.revision and actual_hash != previous.source_sha256:
                raise LiveIndexRefusal("REVISION_HASH_CONFLICT")
            if previous.source_sha256 == actual_hash:
                previous.revision = snapshot.revision
                previous.stale = False
                return {"status": "UNCHANGED", "source_sha256": actual_hash, "revision": snapshot.revision,
                        "parsed_again": False, "writer_authorized": False}
        if previous is None and len(self._records) >= MAX_MODULES:
            raise LiveIndexRefusal("MODULE_BOUND")
        try:
            parsed = self._parser.parse(snapshot.text)
        except RamParserRefusal as refusal:
            raise LiveIndexRefusal(str(refusal)) from None
        self._records[snapshot.target] = _ModuleRecord(snapshot.target, actual_hash, snapshot.revision, parsed)
        return {"status": "APPLIED", "source_sha256": actual_hash, "revision": snapshot.revision,
                "parsed_again": True, "writer_authorized": False}

    def mark_invalidated(self, target: ModuleTarget) -> bool:
        self._target(target)
        record = self._records.get(target)
        if record is None:
            return False
        record.stale = True
        return True

    def refresh_invalidated(self, target: ModuleTarget,
                            provider: Callable[[SourceScope, ModuleTarget], VerifiedSnapshot]) -> dict:
        self._target(target)
        record = self._records.get(target)
        if record is None:
            raise LiveIndexRefusal("TARGET_NOT_OBSERVED")
        if not record.stale:
            return {"status": "CURRENT", "provider_read": False, "writer_authorized": False}
        if not callable(provider):
            raise LiveIndexRefusal("PROVIDER_TYPE")
        self.provider_read_attempts += 1
        try:
            snapshot = provider(self._scope, target)
        except Exception:
            raise LiveIndexRefusal("PROVIDER_FAILED") from None
        if type(snapshot) is not VerifiedSnapshot or snapshot.target != target:
            raise LiveIndexRefusal("PROVIDER_TARGET")
        result = self.apply_snapshot(snapshot)
        return {**result, "provider_read": True}

    def reset_scope(self, scope: SourceScope) -> None:
        if type(scope) is not SourceScope:
            raise LiveIndexRefusal("SCOPE_TYPE")
        scope.validate()
        if scope in self._seen_scopes:
            raise LiveIndexRefusal("SCOPE_RESET_REUSED")
        if len(self._seen_scopes) >= MAX_MODULES:
            raise LiveIndexRefusal("SCOPE_BOUND")
        self._seen_scopes.add(scope)
        self._scope = scope
        self._records.clear()
        self._cache_epoch += 1

    def coverage(self) -> dict:
        return {"scope": self._scope, "cache_epoch": self._cache_epoch, "coverage": "observed_modules_only",
                "observed_modules": len(self._records),
                "fresh_modules": sum(not record.stale for record in self._records.values()),
                "stale_targets": tuple(target for target, record in self._records.items() if record.stale),
                "body_retained": False, "semantic_validation": "UNVERIFIED", "global_resolution": "UNVERIFIED",
                "native_provider_integrated": False, "writer_authorized": False}

    def search_symbols(self, query: str, include_stale: bool = False) -> tuple[dict, ...]:
        if type(query) is not str or len(query) > 256 or type(include_stale) is not bool:
            raise LiveIndexRefusal("QUERY_BOUND")
        folded = query.casefold()
        matches: list[dict] = []
        for record in self._records.values():
            if record.stale and not include_stale:
                continue
            for index, symbol in enumerate(record.parsed.symbols):
                if folded in symbol.name.casefold():
                    matches.append(self._symbol(record, index))
        return tuple(matches)

    def _symbol(self, record: _ModuleRecord, index: int) -> dict:
        symbol = record.parsed.symbols[index]
        return {"target": record.target, "source_sha256": record.source_sha256, "revision": record.revision,
                "scope": self._scope, "cache_epoch": self._cache_epoch, "stale": record.stale,
                "name": symbol.name, "kind": symbol.kind, "parameters": symbol.parameters,
                "signature": f"{symbol.kind} {symbol.name}({symbol.parameters})" + (" Экспорт" if symbol.exported else ""),
                "exported": symbol.exported, "directives": symbol.directives,
                "start_line": symbol.start_line, "end_line": symbol.end_line, "line_base": 1,
                "parser_coverage": record.parsed.parser_coverage, "semantic_validation": "UNVERIFIED",
                "writer_authorized": False}

    def _call(self, record: _ModuleRecord, callee: str, line: int) -> dict:
        # An unqualified unique definition in this module is the only exact
        # lexical target. Cross-module/type/global dispatch remains unverified.
        local = [i for i, symbol in enumerate(record.parsed.symbols) if symbol.name.casefold() == callee.casefold()]
        if "." not in callee and local:
            resolution = "local" if len(local) == 1 else "ambiguous_local"
            candidates = tuple(self._symbol(record, i) for i in local)
        else:
            resolution, candidates = "unresolved", ()
        return {"callee": callee, "line": line, "line_base": 1, "resolution": resolution,
                "candidates": candidates, "global_resolution": "UNVERIFIED", "writer_authorized": False}

    def get_context(self, target: ModuleTarget, method_name: str, include_stale: bool = False) -> dict:
        self._target(target)
        if type(method_name) is not str or not method_name or len(method_name) > 256 or type(include_stale) is not bool:
            raise LiveIndexRefusal("QUERY_BOUND")
        record = self._records.get(target)
        if record is None:
            return {"status": "NOT_OBSERVED", "coverage": self.coverage(), "writer_authorized": False}
        if record.stale and not include_stale:
            return {"status": "STALE", "source_sha256": record.source_sha256, "revision": record.revision,
                    "coverage": self.coverage(), "writer_authorized": False}
        indices = [i for i, symbol in enumerate(record.parsed.symbols) if symbol.name.casefold() == method_name.casefold()]
        entries = []
        for index in indices:
            calls = tuple(self._call(record, call.callee, call.line) for call in record.parsed.calls if call.caller_index == index)
            entries.append({"symbol": self._symbol(record, index), "direct_calls": calls})
        status = "AMBIGUOUS" if len(entries) > 1 else "FOUND" if entries else "NOT_FOUND"
        return {"status": status, "entries": tuple(entries), "stale": record.stale,
                "body_available": False, "coverage": self.coverage(), "writer_authorized": False}
