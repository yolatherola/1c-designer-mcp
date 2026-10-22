"""RAM input adapter for an audited AST closure of the existing pinned RLM parser.

Whole-package imports, scanners, caches, SQLite and application file I/O are
excluded. Only the two known parser source files are read to build the closure.
"""
from __future__ import annotations

import ast
import __future__
import hashlib
from pathlib import Path
import re
from dataclasses import dataclass
from typing import Any, Mapping

DEFAULT_SOURCE_DIRECTORY = Path("C:/Users/Goldin.AZ/AppData/Local/AH_1C/mcp/rlm-tools-bsl/venv/Lib/site-packages/rlm_tools_bsl")
SOURCE_SHA256 = {
    "bsl_index.py": "208887fb4e1885579a2448d79e4d163f463e017aa1feeb693776802dd38dc425",
    "bsl_knowledge.py": "2ce628209e1e2f32006b78fea28f01952d13cfc0cb3bdad7d8b60c1aa128e0f4",
}
CLOSURE_NAMES = {
    "bsl_knowledge.py": frozenset({"BSL_PATTERNS", "mask_comments_and_strings", "_merge_proc_continuations_with_mask",
        "_count_unquoted_parens", "_PROC_DEF_PREFIX_RE", "_PROC_STRING_LITERAL_RE",
        "_MULTILINE_HARD_CAP_LINES", "_MULTILINE_HARD_CAP_CHARS"}),
    "bsl_index.py": frozenset({"_scan_module", "_parse_procedures_from_lines", "_extract_calls_from_body",
        "_PROC_DEF_RE", "_PROC_END_RE", "_QUALIFIED_CALL_RE", "_SIMPLE_CALL_RE", "_BSL_KEYWORDS",
        "_BSL_KEYWORDS_LOWER", "_BSL_GLOBAL_FUNCS_LOWER"}),
}
MAX_SOURCE_BYTES = 2_097_152
MAX_TEXT_BYTES = 262144
MAX_LINES = 8192
MAX_SYMBOLS = 1024
MAX_CALLS = 8192
SAFE_BUILTINS = {"list": list, "dict": dict, "str": str, "int": int, "bool": bool, "len": len,
    "enumerate": enumerate, "range": range, "min": min, "max": max, "set": set,
    "tuple": tuple, "frozenset": frozenset}
SAFE_ATTRIBUTES = frozenset({"compile", "IGNORECASE", "search", "finditer", "sub", "lower", "casefold",
    "find", "strip", "lstrip", "count", "append", "join", "startswith", "group", "start", "end", "add", "match"})


class RamParserRefusal(ValueError):
    """Stable refusal reason, without source bodies or exception payloads."""


@dataclass(frozen=True, slots=True)
class ParsedSymbol:
    name: str
    kind: str
    parameters: str
    exported: bool
    start_line: int
    end_line: int
    directives: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ParsedCall:
    caller_index: int
    callee: str
    line: int


@dataclass(frozen=True, slots=True)
class ParsedModule:
    symbols: tuple[ParsedSymbol, ...]
    calls: tuple[ParsedCall, ...]
    line_count: int
    parser_coverage: str = "lexical_symbols_and_direct_calls"
    semantic_validation: str = "UNVERIFIED"


def text_hash(text: str) -> str:
    if type(text) is not str:
        raise RamParserRefusal("TEXT_TYPE")
    try:
        raw = text.encode("utf-8")
    except UnicodeError:
        raise RamParserRefusal("TEXT_ENCODING") from None
    if len(raw) > MAX_TEXT_BYTES or "\x00" in text:
        raise RamParserRefusal("TEXT_BOUND")
    return hashlib.sha256(raw).hexdigest()


def _defined_names(node: ast.AST) -> set[str]:
    names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    names.update(n.arg for n in ast.walk(node) if isinstance(n, ast.arg))
    return names


def _audit(nodes: list[ast.stmt]) -> None:
    available = set().union(*CLOSURE_NAMES.values()) | SAFE_BUILTINS.keys() | {"re"}
    forbidden = (ast.Import, ast.ImportFrom, ast.ClassDef, ast.Global, ast.Nonlocal, ast.With,
                 ast.AsyncWith, ast.Try, ast.Raise, ast.Await, ast.Delete)
    for node in nodes:
        if isinstance(node, ast.FunctionDef) and node.decorator_list:
            raise RamParserRefusal("UNSAFE_DEPENDENCY")
        local = _defined_names(node)
        for part in ast.walk(node):
            if isinstance(part, forbidden):
                raise RamParserRefusal("UNSAFE_DEPENDENCY")
            if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Load) and part.id not in available | local:
                raise RamParserRefusal("UNSUPPORTED_DEPENDENCY")
            if isinstance(part, ast.Attribute) and part.attr not in SAFE_ATTRIBUTES:
                raise RamParserRefusal("UNSAFE_DEPENDENCY_ATTRIBUTE")


class RlmRamParserAdapter:
    """Reuse only pinned parser definitions; do not import RLM or scan a project."""

    def __init__(self, source_directory: Path = DEFAULT_SOURCE_DIRECTORY,
                 expected_hashes: Mapping[str, str] | None = None):
        if expected_hashes is not None and dict(expected_hashes) != SOURCE_SHA256:
            raise RamParserRefusal("UNSUPPORTED_SOURCE_PINS")
        self._source_directory = Path(source_directory)
        self._namespace: dict[str, Any] | None = None
        self._closure_sha256: str | None = None
        self.parse_count = 0

    def dependency_identity(self) -> dict[str, Any]:
        self._load()
        return {"source_sha256": dict(SOURCE_SHA256), "closure_sha256": self._closure_sha256,
                "closure_names": {name: sorted(values) for name, values in CLOSURE_NAMES.items()},
                "whole_package_imported": False, "application_scanner_used": False}

    def _load(self) -> None:
        if self._namespace is not None:
            return
        selected: list[ast.stmt] = []
        for filename in ("bsl_knowledge.py", "bsl_index.py"):
            path = self._source_directory / filename
            try:
                raw = path.read_bytes()
            except OSError:
                raise RamParserRefusal("DEPENDENCY_UNAVAILABLE") from None
            if len(raw) > MAX_SOURCE_BYTES or hashlib.sha256(raw).hexdigest() != SOURCE_SHA256[filename]:
                raise RamParserRefusal("DEPENDENCY_HASH")
            try:
                tree = ast.parse(raw.decode("utf-8"), filename=filename)
            except (UnicodeError, SyntaxError):
                raise RamParserRefusal("DEPENDENCY_PARSE") from None
            found: set[str] = set()
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    names = {node.name}
                elif isinstance(node, ast.Assign):
                    names = {target.id for target in node.targets if isinstance(target, ast.Name)}
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    names = {node.target.id}
                else:
                    continue
                wanted = names & CLOSURE_NAMES[filename]
                if wanted:
                    if wanted != names or found & wanted:
                        raise RamParserRefusal("DEPENDENCY_SHAPE")
                    selected.append(node)
                    found |= wanted
            if found != CLOSURE_NAMES[filename]:
                raise RamParserRefusal("DEPENDENCY_CLOSURE")
        _audit(selected)
        module = ast.Module(body=selected, type_ignores=[])
        self._closure_sha256 = hashlib.sha256(ast.dump(module, include_attributes=False).encode()).hexdigest()
        namespace: dict[str, Any] = {"__builtins__": dict(SAFE_BUILTINS), "re": re}
        try:
            # Only audited, hash-bound tool definitions execute here. User BSL
            # is a later parser argument and is never compiled or evaluated.
            code = compile(module, "<pinned-rlm-ram-closure-v204>", "exec",
                           flags=__future__.annotations.compiler_flag, dont_inherit=True)
            exec(code, namespace, namespace)
        except Exception:
            raise RamParserRefusal("DEPENDENCY_CLOSURE_EXECUTION") from None
        self._namespace = namespace

    def parse(self, text: str) -> ParsedModule:
        text_hash(text)
        lines = text.splitlines()
        if len(lines) > MAX_LINES:
            raise RamParserRefusal("LINE_BOUND")
        self._load()
        assert self._namespace is not None
        try:
            methods = self._namespace["_parse_procedures_from_lines"](lines)
            if len(methods) > MAX_SYMBOLS:
                raise RamParserRefusal("SYMBOL_BOUND")
            scanned = {line: code.strip() for line, code, _ in self._namespace["_scan_module"](lines)}
            symbols: list[ParsedSymbol] = []
            calls: list[ParsedCall] = []
            for index, method in enumerate(methods):
                start, end = method["line"], method["end_line"]
                if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines):
                    raise RamParserRefusal("PARSER_RANGE")
                directives: list[str] = []
                previous = start - 1
                while previous >= 1:
                    code_line = scanned[previous]
                    if not code_line:
                        previous -= 1
                        continue
                    if not code_line.startswith("&"):
                        break
                    directive = lines[previous - 1].strip()
                    if len(directive) > 1024 or len(directives) >= 16:
                        raise RamParserRefusal("DIRECTIVE_BOUND")
                    directives.append(directive)
                    previous -= 1
                symbols.append(ParsedSymbol(method["name"], method["type"], method["params"],
                    method["is_export"], start, end, tuple(reversed(directives))))
                for callee, line in self._namespace["_extract_calls_from_body"](lines, start, end):
                    calls.append(ParsedCall(index, callee, line))
                    if len(calls) > MAX_CALLS:
                        raise RamParserRefusal("CALL_BOUND")
        except RamParserRefusal:
            raise
        except Exception:
            raise RamParserRefusal("PARSER_REFUSED") from None
        self.parse_count += 1
        return ParsedModule(tuple(symbols), tuple(calls), len(lines))
