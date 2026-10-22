"""Check the source allowlist and known secret signatures without native imports.

Findings contain only path, line and rule name, never the matched value. This is
a publication guard, not a substitute for human review of newly included code.
"""

import json
from pathlib import Path, PurePosixPath
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SUPPORT_FILES = frozenset({
    ".gitattributes", ".gitignore", "ARCHITECTURE.md", "CHECK_RESULT.json", "CONTRIBUTING.md",
    "LICENSE_STATUS.md", "PUBLISHING.md", "README.md", "ROADMAP.md",
    "SECURITY.md", "SOURCE_MANIFEST.json", "project.json",
    ".github/PULL_REQUEST_TEMPLATE.md", ".github/workflows/check.yml",
    "scripts/check.py", "scripts/review_publication.py",
    "scripts/test_publication_review.py",
})
SOURCE_SUFFIXES = frozenset({".py", ".as", ".c", ".h", ".cs", ".ps1", ".js", ".cjs"})
FORBIDDEN_PARTS = frozenset({
    "artifacts", "build", "runtime-cache", "captures", "receipts",
    "node_modules", ".venv", "venv", "__pycache__",
})
RULES = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("CREDENTIAL_URL", re.compile(r"https?://[^\s/:@]+:[^\s/@]+@", re.I)),
    ("LITERAL_SECRET", re.compile(
        r"\b(?:password|passwd|pwd|api_key|access_token|client_secret)\b"
        r"['\"]?\s*[:=]\s*['\"](?=[^'\"\r\n]{8,}['\"])"
        r"(?![<$])[A-Za-z0-9_+/.=@!-]{8,}['\"]", re.I)),
)


def safe_source_path(relative):
    """Accept only normalized technical source paths; never read env/state files."""
    path = PurePosixPath(relative)
    parts = path.parts
    return bool(parts and not path.is_absolute() and "\\" not in relative
                and path.as_posix() == relative and ".." not in parts
                and ":" not in relative and relative.startswith("source/tools/1c/designer-bridge/")
                and not any(part.lower() in FORBIDDEN_PARTS for part in parts)
                and not any(part.lower().startswith(".env") for part in parts)
                and path.suffix.lower() in SOURCE_SUFFIXES)


def scan_text(relative, text):
    """Report known signatures with no credential contents in the result."""
    return [dict(path=relative, line=text.count("\n", 0, match.start()) + 1, rule=rule)
            for rule, pattern in RULES for match in pattern.finditer(text)]


def review(root):
    """Review only allowed text files; reject unknown paths before opening them."""
    manifest_path = root / "SOURCE_MANIFEST.json"
    if (manifest_path.is_symlink() or not manifest_path.is_file()
            or manifest_path.resolve().parent != root.resolve()):
        return dict(files_reviewed=0, findings=[dict(path="SOURCE_MANIFEST.json",
                    rule="MANIFEST_PATH_REFUSED")], passed=False,
                    scope="allowlist-and-known-signatures-only")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = set(SUPPORT_FILES)
    findings = []
    for item in manifest["files"]:
        relative = item["path"]
        if not safe_source_path(relative):
            findings.append(dict(path=relative, rule="SOURCE_PATH_REFUSED"))
        elif relative in expected:
            findings.append(dict(path=relative, rule="DUPLICATE_SOURCE_PATH"))
        else:
            expected.add(relative)
    actual = set()

    def visit(directory):
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(root).as_posix()
            if relative == ".git":
                continue
            if path.is_symlink():
                findings.append(dict(path=relative, rule="SYMLINK_REFUSED"))
            elif path.is_dir():
                if (path.name.lower() in FORBIDDEN_PARTS
                        or path.name.lower().startswith(".env")):
                    findings.append(dict(path=relative, rule="STATE_DIRECTORY_REFUSED"))
                else:
                    visit(path)
            else:
                actual.add(relative)
                if relative not in expected:
                    findings.append(dict(path=relative, rule="UNLISTED_FILE_NOT_READ"))
                    continue
                raw = path.read_bytes()
                if b"\0" in raw:
                    findings.append(dict(path=relative, rule="BINARY_REFUSED"))
                    continue
                try:
                    text = raw.decode("utf-8-sig")
                except UnicodeDecodeError:
                    findings.append(dict(path=relative, rule="NON_UTF8_REFUSED"))
                    continue
                findings.extend(scan_text(relative, text))

    visit(root)
    findings.extend(dict(path=relative, rule="MISSING_FILE") for relative in sorted(expected - actual))
    return dict(files_reviewed=len(actual & expected), findings=findings,
                passed=not findings, scope="allowlist-and-known-signatures-only")


def main():
    result = review(ROOT)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
