"""Check extracted source and synthetic codec tests without attaching to 1C."""

import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "source"
BRIDGE = SOURCE / "tools/1c/designer-bridge"
ALLOWED = {".py", ".as", ".c", ".h", ".cs", ".ps1", ".js", ".cjs"}
SUITES = ("test_editor_command", "test_editor_change_plan", "test_editor_transport")


def checked_path(relative):
    path = ROOT / relative
    if (path.is_symlink() or not path.is_file()
            or not path.resolve().is_relative_to(SOURCE.resolve())
            or path.suffix.lower() not in ALLOWED):
        raise ValueError("SOURCE_PATH_REFUSED")
    return path


def verify_source(verify_origin):
    manifest = json.loads((ROOT / "SOURCE_MANIFEST.json").read_text(encoding="utf-8"))
    known = set()
    parsed = 0
    for item in manifest["files"]:
        relative = item["path"]
        if relative in known:
            raise ValueError("DUPLICATE_SOURCE_PATH")
        known.add(relative)
        path = checked_path(relative)
        raw = path.read_bytes()
        if verify_origin and hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("SOURCE_SNAPSHOT_CHANGED")
        if path.suffix == ".py":
            ast.parse(raw.decode("utf-8-sig"), filename=relative)
            parsed += 1
    actual = {p.relative_to(ROOT).as_posix() for p in SOURCE.rglob("*") if p.is_file()}
    if actual != known:
        raise ValueError("UNLISTED_OR_MISSING_SOURCE")
    return len(known), parsed


def audit(event, args):
    if event in {"ctypes.dlopen", "subprocess.Popen", "socket.connect", "os.system"}:
        raise RuntimeError("NATIVE_NETWORK_OR_PROCESS_CALL_FORBIDDEN")
    if event == "open" and args and isinstance(args[0], (str, bytes)):
        name = Path(args[0]).name.lower() if isinstance(args[0], str) else ""
        if name.startswith(".env") or name.endswith(".env.local"):
            raise RuntimeError("ENV_FILE_ACCESS_FORBIDDEN")


def run_tests():
    # Pure codec tests import relative modules. Deliberately avoid the runtime
    # package initializer, whose server/SDK dependencies are outside this check.
    # This is a test-only namespace and provides no native authority or backend.
    namespace = types.ModuleType("native_mcp")
    namespace.__path__ = [str(BRIDGE / "native_mcp")]
    sys.modules["native_mcp"] = namespace
    sys.path.insert(0, str(BRIDGE / "tests"))
    sys.addaudithook(audit)
    suite = unittest.defaultTestLoader.loadTestsFromNames(SUITES)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-origin", action="store_true",
                        help="also require every source file to match the extraction snapshot")
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    count, parsed = verify_source(args.verify_origin)
    result = run_tests()
    print(json.dumps(dict(source_files=count, python_files_parsed=parsed,
                          tests=result.testsRun, failures=len(result.failures),
                          errors=len(result.errors), skipped=len(result.skipped),
                          origin_verified=args.verify_origin,
                          scope="synthetic-codec-planner-transport-only",
                          native_runtime_tested=False, mcp_server_started=False,
                          native_calls_authorized=False), ensure_ascii=False))
    return 0 if result.wasSuccessful() and not result.skipped and result.testsRun else 1


if __name__ == "__main__":
    raise SystemExit(main())
