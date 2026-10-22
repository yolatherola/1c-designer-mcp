"""Synthetic publication roots and negative guards; no native calls or network."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from review_publication import SUPPORT_FILES, review, safe_source_path, scan_text


class PublicationReviewTests(unittest.TestCase):
    def test_technical_source_is_allowed(self):
        self.assertTrue(safe_source_path("source/tools/1c/designer-bridge/native_mcp/server.py"))

    def test_escape_and_absolute_paths_are_rejected(self):
        for path in ("../private.py", "source/tools/1c/designer-bridge/../private.py",
                     "F:/private.py", "/private.py", "source\\private.py"):
            with self.subTest(path=path):
                self.assertFalse(safe_source_path(path))

    def test_env_state_and_binaries_are_rejected(self):
        prefix = "source/tools/1c/designer-bridge/"
        for suffix in (".env.local", "build/script.py", "captures/script.py",
                       "receipts/script.py", "runtime-cache/script.py", "private.dll",
                       "__pycache__/module.py", ".env.local/script.py"):
            with self.subTest(path=suffix):
                self.assertFalse(safe_source_path(prefix + suffix))

    def test_synthetic_source_passes(self):
        self.assertEqual(scan_text("example.py", 'password = os.getenv("PASSWORD")\n'), [])

    def test_github_token_is_blocked_and_redacted(self):
        synthetic = "gh" + "p_" + "A" * 36
        result = scan_text("example.py", "\nvalue = '" + synthetic + "'")
        self.assertEqual(result, [dict(path="example.py", line=2, rule="GITHUB_TOKEN")])
        self.assertNotIn(synthetic, str(result))

    def test_private_key_is_blocked(self):
        text = "-----BEGIN " + "RSA PRIVATE KEY-----"
        self.assertEqual(scan_text("example.py", text)[0]["rule"], "PRIVATE_KEY")

    def test_credential_url_is_blocked(self):
        text = "https://" + "fixture:synthetic-value@" + "example.invalid"
        self.assertEqual(scan_text("example.py", text)[0]["rule"], "CREDENTIAL_URL")

    def test_literal_secret_is_blocked(self):
        text = "password = '" + "synthetic-password" + "'"
        self.assertEqual(scan_text("example.py", text)[0]["rule"], "LITERAL_SECRET")


    def _component_publication_fixture(self):
        directory = tempfile.TemporaryDirectory(prefix="publication-component-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for relative in SUPPORT_FILES:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic support file\n", encoding="utf-8")
        (root / "SOURCE_MANIFEST.json").write_text('{"files":[]}\n', encoding="utf-8")
        actual_root = Path(__file__).resolve().parents[1]
        for relative in self.COMPONENT_FILES:
            (root / relative).write_bytes((actual_root / relative).read_bytes())
        return root

    COMPONENT_FILES = (
        "components/saved-resource-diagnostics/README.md",
        "components/saved-resource-diagnostics/policy_saved_null_certificate.py",
        "components/saved-resource-diagnostics/policy_saved_reason_memory.py",
        "components/saved-resource-diagnostics/tests/test_saved_resource_diagnostics.py",
    )

    def test_exact_component_allowlist_and_actual_text_files_pass(self):
        component = {p for p in SUPPORT_FILES if p.startswith("components/")}
        self.assertEqual(component, set(self.COMPONENT_FILES))
        result = review(self._component_publication_fixture())
        self.assertTrue(result["passed"], result["findings"])
        self.assertEqual(result["files_reviewed"], len(SUPPORT_FILES))

    def test_unknown_component_file_is_rejected_before_read(self):
        root = self._component_publication_fixture()
        extra = root / "components/saved-resource-diagnostics/tests/extra.py"
        extra.write_text("synthetic unlisted file\n", encoding="utf-8")
        original = Path.read_bytes
        def only_listed(path):
            if path == extra:
                raise AssertionError("UNLISTED_FILE_WAS_READ")
            return original(path)
        with patch.object(Path, "read_bytes", only_listed):
            result = review(root)
        self.assertFalse(result["passed"])
        self.assertEqual(result["findings"], [dict(
            path="components/saved-resource-diagnostics/tests/extra.py",
            rule="UNLISTED_FILE_NOT_READ")])



if __name__ == "__main__":
    unittest.main()
