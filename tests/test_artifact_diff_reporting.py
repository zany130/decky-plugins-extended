"""Regression tests for complete, collapsible source-diff reporting."""

import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import audit_plugins


class ArtifactDiffReportingTests(unittest.TestCase):
    def _mk_extract(self, files: dict[str, bytes | str], executable_paths=None) -> str:
        td = tempfile.TemporaryDirectory()
        executable_paths = executable_paths or set()
        for rel, content in files.items():
            path = Path(td.name) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, str):
                content = content.encode("utf-8")
            path.write_bytes(content)
            if rel in executable_paths:
                path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.addCleanup(td.cleanup)
        return td.name

    def _patch_empty_source_tree(self):
        def side_effect(url, params=None):
            if "/git/ref/tags/" in url:
                return {"object": {"type": "commit", "sha": "sha-commit"}}
            if "/git/commits/" in url:
                return {"tree": {"sha": "sha-tree"}}
            if "/git/trees/" in url:
                return {"truncated": False, "tree": []}
            raise AssertionError(f"Unexpected URL {url}")

        return patch.object(audit_plugins, "_gh_get", side_effect=side_effect)

    def test_group_metadata_preserves_every_path(self):
        paths = {
            "Plugin/py_modules/pkg/a.py": "value = 1\n",
            "Plugin/py_modules/pkg/b.py": "value = 2\n",
            "Plugin/py_modules/pkg/c.py": "value = 3\n",
        }
        extract = self._mk_extract(paths)
        with self._patch_empty_source_tree():
            summary, _, _ = audit_plugins.compare_source_and_artifact(
                extract, "owner", "repo", "v1"
            )

        group = summary["grouped_packaged_outputs"][0]
        self.assertEqual(group["count"], 3)
        self.assertEqual(group["paths"], sorted(paths))
        self.assertEqual(group["sample_paths"], sorted(paths))

    def test_markdown_uses_collapsible_inventory_and_keeps_actionable_files_visible(self):
        summary = {
            "grouped_packaged_outputs": [{
                "category": "python_dependencies",
                "root": "Plugin/py_modules/",
                "kind": "script",
                "rule_id": "BUNDLED_DEPENDENCY_SCRIPTS",
                "severity": "low",
                "classification": "PASS_WITH_WARNINGS",
                "count": 2,
                "sample_paths": ["Plugin/py_modules/pkg/a.py"],
                "paths": [
                    "Plugin/py_modules/pkg/a.py",
                    "Plugin/py_modules/pkg/b.py",
                ],
            }],
            "zip_only_scripts": ["Plugin/bin/unexpected.py"],
            "zip_only_executables": ["Plugin/bin/tool"],
        }
        report = audit_plugins.AuditReport(
            plugin_name="Plugin",
            repository="https://github.com/owner/repo",
            release="v1",
            final_classification="MANUAL_REVIEW",
            source_artifact_diff=summary,
        )

        markdown = audit_plugins.generate_markdown_report(report)

        self.assertIn("## Source vs. Release Artifact Differences", markdown)
        self.assertIn("### Actionable ZIP-only Files", markdown)
        self.assertIn("`Plugin/bin/unexpected.py`", markdown)
        self.assertIn("`Plugin/bin/tool`", markdown)
        self.assertIn("<details>", markdown)
        self.assertIn("2 ZIP-only script-like file(s)", markdown)
        self.assertIn("`Plugin/py_modules/pkg/a.py`", markdown)
        self.assertIn("`Plugin/py_modules/pkg/b.py`", markdown)
        grouped_summary = "<summary>🐍 Bundled Python dependencies — 2 ZIP-only"
        self.assertLess(
            markdown.index("### Actionable ZIP-only Files"),
            markdown.index(grouped_summary),
        )


if __name__ == "__main__":
    unittest.main()
