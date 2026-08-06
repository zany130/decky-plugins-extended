"""Semgrep findings must not claim false tagged-source line identity."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import audit_plugins


class SemgrepSourceLinkHardeningTests(unittest.TestCase):
    def setUp(self):
        audit_plugins.clear_source_link_cache()

    @staticmethod
    def _api(url, params=None):
        if "/commits/v1.0.0" in url:
            return {
                "sha": "exactcommit123",
                "commit": {"tree": {"sha": "tree123"}},
            }
        if "/git/trees/tree123" in url:
            return {
                "truncated": False,
                "tree": [{"type": "blob", "path": "main.py"}],
            }
        raise AssertionError(f"Unexpected URL: {url}")

    @staticmethod
    def _report(*, message: str, checked: bool, differs: bool):
        report = audit_plugins.AuditReport(
            repository="https://github.com/owner/plugin",
            release="v1.0.0",
            final_classification="MANUAL_REVIEW",
        )
        report.findings = [
            audit_plugins.Finding(
                rule_id="SEMGREP_DECKY_PYTHON_SHELL_COMMAND",
                severity="medium",
                classification="MANUAL_REVIEW",
                path="Plugin/main.py",
                line=12,
                message=message,
                evidence="subprocess.run(command, shell=True)",
                scanner="semgrep",
            )
        ]
        report.source_artifact_diff = {
            "checked": checked,
            "same_path_modified": (
                [
                    {
                        "artifact_path": "Plugin/main.py",
                        "source_path": "main.py",
                        "artifact_sha256": "artifact",
                        "source_sha256": "source",
                    }
                ]
                if differs
                else []
            ),
            "generated_or_dependency_differences": [],
            "other_same_path_differences": [],
            "expected_build_stamp_differences": [],
        }
        return report

    def test_artifact_mismatch_links_file_without_false_line(self):
        report = self._report(
            message="[artifact; plugin_runtime; confidence=high] review",
            checked=True,
            differs=True,
        )
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api):
            audit_plugins.enrich_report_source_links(report)
            data = json.loads(audit_plugins.generate_json_report(report))
            markdown = audit_plugins.generate_markdown_report(report)

        finding = report.findings[0]
        self.assertEqual(finding.source_status, "file-only")
        self.assertFalse(finding.source_line_exact)
        self.assertNotIn("#L12", finding.source_url)
        self.assertIn("release contents differ", finding.source_note)
        self.assertFalse(data["findings"][0]["source_line_exact"])
        self.assertIn("View tagged source file", markdown)
        self.assertNotIn("main.py#L12", markdown)

    def test_unverified_artifact_does_not_claim_exact_line(self):
        report = self._report(
            message="[artifact; plugin_runtime; confidence=high] review",
            checked=False,
            differs=False,
        )
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api):
            markdown = audit_plugins.generate_markdown_report(report)

        finding = report.findings[0]
        self.assertEqual(finding.source_status, "file-only")
        self.assertFalse(finding.source_line_exact)
        self.assertIn("not verified", finding.source_note)
        self.assertNotIn("#L12", finding.source_url)
        self.assertIn("View tagged source file", markdown)

    def test_exact_source_scope_keeps_commit_line_link(self):
        report = self._report(
            message="[source; plugin_runtime; confidence=high] review",
            checked=False,
            differs=True,
        )
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api):
            data = json.loads(audit_plugins.generate_json_report(report))
            markdown = audit_plugins.generate_markdown_report(report)

        finding = report.findings[0]
        self.assertEqual(finding.source_status, "linked")
        self.assertTrue(finding.source_line_exact)
        self.assertTrue(finding.source_url.endswith("main.py#L12"))
        self.assertTrue(data["findings"][0]["source_line_exact"])
        self.assertIn("View upstream code", markdown)
        self.assertIn("main.py#L12", markdown)

    def test_verified_identical_artifact_keeps_commit_line_link(self):
        report = self._report(
            message="[artifact; plugin_runtime; confidence=high] review",
            checked=True,
            differs=False,
        )
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api):
            audit_plugins.generate_json_report(report)

        finding = report.findings[0]
        self.assertEqual(finding.source_status, "linked")
        self.assertTrue(finding.source_line_exact)
        self.assertTrue(finding.source_url.endswith("main.py#L12"))


if __name__ == "__main__":
    unittest.main()
