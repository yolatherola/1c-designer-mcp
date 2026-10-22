"""Synthetic negative cases for the publication guard; no native imports or I/O."""

import unittest

from review_publication import safe_source_path, scan_text


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


if __name__ == "__main__":
    unittest.main()
