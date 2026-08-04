"""Regression tests for immutable upstream source links in reports."""

import json
import unittest
from unittest.mock import patch

import audit_plugins


class UpstreamSourceLinkTests(unittest.TestCase):
    def setUp(self):
        audit_plugins.clear_source_link_cache()

    def _report(
        self,
        *,
        path: str = "plugin/src/main.py",
        line: int = 42,
        rule: str = "EXEC_OS_SYSTEM",
    ):
        report = audit_plugins.AuditReport(
            repository="https://github.com/owner/plugin",
            release="v1.2.3",
            final_classification="MANUAL_REVIEW",
        )
        report.findings = [
            audit_plugins.Finding(
                rule_id=rule,
                severity="high",
                classification="MANUAL_REVIEW",
                path=path,
                line=line,
                message="test finding",
                evidence="evidence",
                scanner=(
                    "source-artifact-diff"
                    if rule.startswith("ZIP_ONLY_")
                    else "decky-static-rules"
                ),
            )
        ]
        return report

    def _api(self, tree_paths=("src/main.py",)):
        def side_effect(url, params=None):
            if "/commits/v1.2.3" in url:
                return {
                    "sha": "abc123def456",
                    "commit": {"tree": {"sha": "tree-sha"}},
                }
            if "/git/trees/tree-sha" in url:
                return {
                    "truncated": False,
                    "tree": [
                        {"type": "blob", "path": path}
                        for path in tree_paths
                    ],
                }
            raise AssertionError(f"Unexpected URL: {url}")
        return side_effect

    def test_link_is_pinned_to_commit_and_line(self):
        report = self._report()
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api()):
            audit_plugins.enrich_report_source_links(report)

        finding = report.findings[0]
        self.assertEqual(finding.source_status, "linked")
        self.assertEqual(report.source_commit, "abc123def456")
        self.assertEqual(
            finding.source_url,
            "https://github.com/owner/plugin/blob/abc123def456/src/main.py#L42",
        )
        self.assertNotIn("/blob/main/", finding.source_url)

    def test_line_zero_links_to_file_without_anchor(self):
        report = self._report(line=0)
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api()):
            audit_plugins.enrich_report_source_links(report)
        self.assertEqual(
            report.findings[0].source_url,
            "https://github.com/owner/plugin/blob/abc123def456/src/main.py",
        )

    def test_release_only_file_does_not_get_misleading_link(self):
        report = self._report(
            path="plugin/generated/extra.py",
            line=0,
            rule="ZIP_ONLY_SCRIPT",
        )
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api(tree_paths=())):
            audit_plugins.enrich_report_source_links(report)

        finding = report.findings[0]
        self.assertEqual(finding.source_status, "release-only")
        self.assertEqual(finding.source_url, "")

    def test_json_report_contains_source_metadata(self):
        report = self._report()
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api()):
            audit_plugins.enrich_report_source_links(report)
        data = json.loads(audit_plugins.generate_json_report(report))

        self.assertEqual(data["source_commit"], "abc123def456")
        finding = data["findings"][0]
        self.assertEqual(finding["source_status"], "linked")
        self.assertEqual(finding["source_path"], "src/main.py")
        self.assertTrue(finding["source_url"].endswith("src/main.py#L42"))

    def test_markdown_report_includes_view_source_link(self):
        report = self._report()
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api()):
            markdown = audit_plugins.generate_markdown_report(report)
        self.assertIn("[View upstream code]", markdown)
        self.assertIn("abc123def456/src/main.py#L42", markdown)

    def test_link_api_failure_does_not_change_security_classification(self):
        report = self._report()
        with patch.object(audit_plugins, "_gh_get", side_effect=RuntimeError("offline")):
            audit_plugins.enrich_report_source_links(report)
        self.assertEqual(report.final_classification, "MANUAL_REVIEW")
        self.assertEqual(report.findings[0].source_status, "unresolved")
        self.assertEqual(report.findings[0].source_url, "")


if __name__ == "__main__":
    unittest.main()
