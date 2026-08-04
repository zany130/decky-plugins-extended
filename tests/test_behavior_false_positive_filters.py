"""Regression tests for persistence and encoded-asset false positives."""

import base64
import unittest

import audit_plugins


class BehaviorFalsePositiveFilterTests(unittest.TestCase):
    def _rules(self, content: str, path: str, ext: str) -> list[str]:
        return [
            finding.rule_id
            for finding in audit_plugins.scan_text_content(content, path, ext)
        ]

    def test_javascript_profile_property_is_not_persistence(self):
        content = "const provider = snapshot.profile.providerId;\nconst next = args.profile;\n"
        self.assertNotIn(
            "PERSIST_PROFILE_MOD",
            self._rules(content, "src/store.ts", ".ts"),
        )

    def test_optional_chaining_profile_property_is_not_persistence(self):
        content = "const provider = state.data?.profile?.providerId;\n"
        self.assertNotIn(
            "PERSIST_PROFILE_MOD",
            self._rules(content, "src/store.ts", ".ts"),
        )

    def test_reading_profile_file_is_not_reported_as_modification(self):
        content = 'value = open(Path.home() / ".profile", "r").read()\n'
        self.assertNotIn(
            "PERSIST_PROFILE_MOD",
            self._rules(content, "main.py", ".py"),
        )

    def test_python_profile_append_remains_manual_review(self):
        content = 'open(Path.home() / ".profile", "a").write("export X=1\\n")\n'
        findings = audit_plugins.scan_text_content(content, "main.py", ".py")
        profile = next(f for f in findings if f.rule_id == "PERSIST_PROFILE_MOD")
        self.assertEqual(profile.classification, "MANUAL_REVIEW")
        self.assertEqual(profile.line, 1)

    def test_shell_profile_redirect_remains_manual_review(self):
        content = 'echo "export X=1" >> ~/.profile\n'
        self.assertIn(
            "PERSIST_PROFILE_MOD",
            self._rules(content, "install.sh", ".sh"),
        )

    def test_zprofile_write_is_detected(self):
        content = 'fs.appendFileSync(path.join(home, ".zprofile"), value);\n'
        self.assertIn(
            "PERSIST_PROFILE_MOD",
            self._rules(content, "src/setup.ts", ".ts"),
        )

    def test_embedded_png_base64_is_not_obfuscation(self):
        payload = base64.b64encode(b"\x89PNG\r\n\x1a\n" + (b"\x00" * 300)).decode()
        content = f'const icon = "data:image/png;base64,{payload}";\n'
        self.assertNotIn(
            "OBFUSCATION_LARGE_BASE64",
            self._rules(content, "src/icon.ts", ".ts"),
        )

    def test_embedded_woff2_base64_is_not_obfuscation(self):
        payload = base64.b64encode(b"wOF2" + (b"\x00" * 300)).decode()
        content = f'const font = "data:font/woff2;base64,{payload}";\n'
        self.assertNotIn(
            "OBFUSCATION_LARGE_BASE64",
            self._rules(content, "src/font.ts", ".ts"),
        )

    def test_unknown_large_base64_remains_manual_review(self):
        payload = base64.b64encode(bytes(range(64)) * 6).decode()
        findings = audit_plugins.scan_text_content(
            f'const payload = "{payload}";\n',
            "src/payload.ts",
            ".ts",
        )
        encoded = next(
            f for f in findings if f.rule_id == "OBFUSCATION_LARGE_BASE64"
        )
        self.assertEqual(encoded.classification, "MANUAL_REVIEW")


if __name__ == "__main__":
    unittest.main()
