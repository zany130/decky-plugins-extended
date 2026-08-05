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
        network: bool = False,
        comparison_checked: bool = True,
        differences: dict | None = None,
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
        report.source_artifact_diff = {
            "checked": comparison_checked,
            "same_path_modified": [],
            "generated_or_dependency_differences": [],
            "other_same_path_differences": [],
            "expected_build_stamp_differences": [],
            **(differences or {}),
        }
        if network:
            report.extracted_domains = ["api.example.com"]
            report.network_destinations = [
                {
                    "destination": "api.example.com",
                    "confidence": "high",
                    "review_priority": "primary",
                    "reason": "referenced by plugin-owned runtime code",
                    "source_count": 1,
                    "sources": [
                        {
                            "path": path,
                            "line": line,
                            "provenance": "plugin_runtime",
                            "confidence": "high",
                            "kind": "url",
                            "url": "https://api.example.com",
                        }
                    ],
                }
            ]
            report.network_destination_summary = {
                "total_destinations": 1,
                "high_confidence": 1,
                "medium_confidence": 0,
                "low_confidence": 0,
                "source_occurrences": 1,
            }
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

    def test_network_evidence_links_to_exact_commit_line(self):
        report = self._report(network=True)
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api()):
            audit_plugins.enrich_report_source_links(report)

        source = report.network_destinations[0]["sources"][0]
        self.assertEqual(source["source_status"], "linked")
        self.assertEqual(source["source_path"], "src/main.py")
        self.assertEqual(source["source_commit"], "abc123def456")
        self.assertTrue(source["source_line_exact"])
        self.assertEqual(
            source["source_url"],
            "https://github.com/owner/plugin/blob/abc123def456/src/main.py#L42",
        )

        data = json.loads(audit_plugins.generate_json_report(report))
        serialized = data["network_destinations"][0]["sources"][0]
        self.assertEqual(serialized["source_status"], "linked")
        self.assertTrue(serialized["source_line_exact"])
        self.assertTrue(serialized["source_url"].endswith("src/main.py#L42"))

        markdown = audit_plugins.generate_markdown_report(report)
        self.assertIn(
            "[`plugin/src/main.py:42`](https://github.com/owner/plugin/blob/"
            "abc123def456/src/main.py#L42)",
            markdown,
        )

    def test_network_content_mismatch_links_file_without_false_line(self):
        report = self._report(
            network=True,
            differences={
                "same_path_modified": [
                    {
                        "artifact_path": "plugin/src/main.py",
                        "source_path": "src/main.py",
                        "artifact_sha256": "a",
                        "source_sha256": "b",
                    }
                ]
            },
        )
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api()):
            audit_plugins.enrich_report_source_links(report)

        source = report.network_destinations[0]["sources"][0]
        self.assertEqual(source["source_status"], "file-only")
        self.assertFalse(source["source_line_exact"])
        self.assertNotIn("#L42", source["source_url"])
        self.assertIn("release contents differ", source["source_note"])

        markdown = audit_plugins.generate_markdown_report(report)
        self.assertIn("release contents differ from tagged source", markdown)
        self.assertNotIn("src/main.py#L42", markdown)

    def test_network_unverified_comparison_does_not_claim_exact_line(self):
        report = self._report(network=True, comparison_checked=False)
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api()):
            audit_plugins.enrich_report_source_links(report)

        source = report.network_destinations[0]["sources"][0]
        self.assertEqual(source["source_status"], "file-only")
        self.assertFalse(source["source_line_exact"])
        self.assertNotIn("#L42", source["source_url"])
        self.assertIn("not verified", source["source_note"])

    def test_network_release_only_keeps_artifact_location_without_false_link(self):
        report = self._report(network=True)
        with patch.object(audit_plugins, "_gh_get", side_effect=self._api(tree_paths=())):
            audit_plugins.enrich_report_source_links(report)

        source = report.network_destinations[0]["sources"][0]
        self.assertEqual(source["source_status"], "release-only")
        self.assertEqual(source["source_url"], "")
        self.assertFalse(source["source_line_exact"])

        markdown = audit_plugins.generate_markdown_report(report)
        self.assertIn("`plugin/src/main.py:42`", markdown)
        self.assertIn("release-only; no tagged-source line", markdown)

    def test_tree_failure_preserves_resolved_commit(self):
        report = self._report()

        def side_effect(url, params=None):
            if "/commits/v1.2.3" in url:
                return {
                    "sha": "abc123def456",
                    "commit": {"tree": {"sha": "tree-sha"}},
                }
            if "/git/trees/tree-sha" in url:
                raise RuntimeError("tree unavailable")
            raise AssertionError(f"Unexpected URL: {url}")

        with patch.object(audit_plugins, "_gh_get", side_effect=side_effect):
            audit_plugins.enrich_report_source_links(report)

        self.assertEqual(report.source_commit, "abc123def456")
        self.assertIn("tree unavailable", report.source_link_error)
        self.assertEqual(report.findings[0].source_commit, "abc123def456")
        self.assertEqual(report.findings[0].source_status, "unmapped")
        self.assertEqual(report.findings[0].source_url, "")

    def test_link_api_failure_does_not_change_security_classification(self):
        report = self._report()
        with patch.object(audit_plugins, "_gh_get", side_effect=RuntimeError("offline")):
            audit_plugins.enrich_report_source_links(report)
        self.assertEqual(report.final_classification, "MANUAL_REVIEW")
        self.assertEqual(report.findings[0].source_status, "unresolved")
        self.assertEqual(report.findings[0].source_url, "")


if __name__ == "__main__":
    unittest.main()
