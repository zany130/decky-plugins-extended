"""Regression coverage for repeated network evidence locations."""

import unittest
from unittest.mock import patch

import audit_plugins


class RepeatedNetworkSourceLinkTests(unittest.TestCase):
    def setUp(self):
        audit_plugins.clear_source_link_cache()

    @staticmethod
    def _api(url, params=None):
        if "/commits/v1.2.3" in url:
            return {
                "sha": "abc123def456",
                "commit": {"tree": {"sha": "tree-sha"}},
            }
        if "/git/trees/tree-sha" in url:
            return {
                "truncated": False,
                "tree": [{"type": "blob", "path": "src/main.py"}],
            }
        raise AssertionError(f"Unexpected URL: {url}")

    def test_same_line_for_multiple_destinations_never_nests_links(self):
        report = audit_plugins.AuditReport(
            repository="https://github.com/owner/plugin",
            release="v1.2.3",
            final_classification="PASS",
        )
        report.findings = []
        report.extracted_domains = ["api.example.com", "cdn.example.com"]
        source = {
            "path": "plugin/src/main.py",
            "line": 42,
            "provenance": "plugin_runtime",
            "confidence": "high",
            "kind": "url",
            "url": "https://api.example.com",
        }
        report.network_destinations = [
            {
                "destination": "api.example.com",
                "confidence": "high",
                "review_priority": "primary",
                "reason": "referenced by plugin-owned runtime code",
                "source_count": 1,
                "sources": [dict(source)],
            },
            {
                "destination": "cdn.example.com",
                "confidence": "high",
                "review_priority": "primary",
                "reason": "referenced by plugin-owned runtime code",
                "source_count": 1,
                "sources": [{**source, "url": "https://cdn.example.com"}],
            },
        ]
        report.network_destination_summary = {
            "total_destinations": 2,
            "high_confidence": 2,
            "medium_confidence": 0,
            "low_confidence": 0,
            "source_occurrences": 2,
        }
        report.source_artifact_diff = {
            "checked": True,
            "same_path_modified": [],
            "generated_or_dependency_differences": [],
            "other_same_path_differences": [],
            "expected_build_stamp_differences": [],
        }

        with patch.object(audit_plugins, "_gh_get", side_effect=self._api):
            markdown = audit_plugins.generate_markdown_report(report)

        link = (
            "[`plugin/src/main.py:42`](https://github.com/owner/plugin/blob/"
            "abc123def456/src/main.py#L42)"
        )
        self.assertEqual(markdown.count(link), 2)
        self.assertNotIn("[[", markdown)


if __name__ == "__main__":
    unittest.main()
