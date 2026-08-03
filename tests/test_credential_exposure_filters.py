"""Regression tests for credential-exposure classification."""

import base64
import unittest

import audit_plugins


class CredentialExposurePolicyTests(unittest.TestCase):
    def test_runtime_credential_variables_are_not_findings(self):
        findings = audit_plugins.scan_for_secrets(
            "\n".join(
                (
                    'bearer_token = response.json()["access_token"]',
                    "api_key = config.api_key",
                    "password = parsed_url.password",
                )
            ),
            "auth.py",
        )
        self.assertEqual(findings, [])

    def test_generic_hardcoded_literal_warns_but_does_not_block(self):
        findings = audit_plugins.scan_for_secrets(
            'api_key = "aB3dE5fG7hJ9kL2mN4pQ6rS8"\n',
            "config.py",
        )
        self.assertEqual([f.rule_id for f in findings], ["SECRET_GENERIC_API_KEY"])
        self.assertEqual(findings[0].classification, "PASS_WITH_WARNINGS")
        self.assertNotEqual(findings[0].classification, "BLOCK")

    def test_obvious_placeholder_is_ignored(self):
        findings = audit_plugins.scan_for_secrets(
            'api_key = "your_api_key_here"\n',
            "config.py",
        )
        self.assertEqual(findings, [])

    def test_provider_token_requires_review_but_never_blocks(self):
        token = "ghp_" + ("Ab1" * 12)
        findings = audit_plugins.scan_for_secrets(
            f'token = "{token}"\n',
            "auth.py",
        )
        github = next(f for f in findings if f.rule_id == "SECRET_GITHUB_TOKEN")
        self.assertEqual(github.classification, "MANUAL_REVIEW")
        self.assertNotEqual(github.classification, "BLOCK")
        self.assertNotIn(token, github.evidence)
        self.assertIn(audit_plugins.SECRET_REDACT, github.evidence)

    def test_fixture_provider_token_still_requires_review_at_low_severity(self):
        token = "ghp_" + ("Ab1" * 12)
        findings = audit_plugins.scan_for_secrets(
            f'# test fixture: token = "{token}"\n',
            "tests/test_auth.py",
        )
        github = next(f for f in findings if f.rule_id == "SECRET_GITHUB_TOKEN")
        self.assertEqual(github.classification, "MANUAL_REVIEW")
        self.assertEqual(github.severity, "low")
        self.assertNotEqual(github.classification, "BLOCK")

    def test_generic_patterns_are_suppressed_in_generated_content(self):
        findings = audit_plugins.scan_for_secrets(
            '{"api_key":"aB3dE5fG7hJ9kL2mN4pQ6rS8"}',
            "dist/index.js.map",
        )
        self.assertEqual(findings, [])

    def test_provider_patterns_remain_active_in_generated_content(self):
        token = "ghp_" + ("Ab1" * 12)
        findings = audit_plugins.scan_for_secrets(token, "dist/index.js.map")
        self.assertIn("SECRET_GITHUB_TOKEN", {f.rule_id for f in findings})

    def test_header_only_is_a_low_warning(self):
        findings = audit_plugins.scan_for_secrets(
            "key = '-----BEGIN RSA PRIVATE KEY-----\\nMIIE...'\n",
            "config.py",
        )
        header = next(f for f in findings if f.rule_id == "SECRET_PRIVATE_KEY_HEADER")
        self.assertEqual(header.classification, "PASS_WITH_WARNINGS")
        self.assertEqual(header.severity, "low")

    def test_complete_private_key_requires_review(self):
        body = base64.b64encode(bytes(range(96))).decode()
        content = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"{body}\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        findings = audit_plugins.scan_for_secrets(content, "config.py")
        private_key = next(f for f in findings if f.rule_id == "SECRET_PRIVATE_KEY")
        self.assertEqual(private_key.classification, "MANUAL_REVIEW")
        self.assertNotEqual(private_key.classification, "BLOCK")
        self.assertNotIn("SECRET_PRIVATE_KEY_HEADER", {f.rule_id for f in findings})

    def test_fixture_complete_private_key_still_requires_review_at_low_severity(self):
        body = base64.b64encode(bytes(range(96))).decode()
        content = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"{body}\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        findings = audit_plugins.scan_for_secrets(content, "tests/fixtures/test_key.pem")
        private_key = next(f for f in findings if f.rule_id == "SECRET_PRIVATE_KEY")
        self.assertEqual(private_key.classification, "MANUAL_REVIEW")
        self.assertEqual(private_key.severity, "low")
        self.assertNotEqual(private_key.classification, "BLOCK")

    def test_credential_findings_cannot_make_final_result_block(self):
        token = "ghp_" + ("Ab1" * 12)
        findings = audit_plugins.scan_for_secrets(token, "auth.py")
        classification, _ = audit_plugins.classify_findings(findings)
        self.assertEqual(classification, "MANUAL_REVIEW")


if __name__ == "__main__":
    unittest.main()
