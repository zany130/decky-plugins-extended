"""Regression tests for grouped ZIP-only packaged output findings."""

import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import audit_plugins


class ArtifactDiffGroupingTests(unittest.TestCase):
    def _mk_extract(
        self,
        files: dict[str, bytes | str],
        executable_paths: set[str] | None = None,
    ) -> str:
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

    def test_python_dependencies_are_collapsed_into_one_warning(self):
        extract = self._mk_extract({
            "Plugin/py_modules/pkg/a.py": "value = 1\n",
            "Plugin/py_modules/pkg/b.py": "value = 2\n",
            "Plugin/py_modules/pkg/c.py": "value = 3\n",
        })
        with self._patch_empty_source_tree():
            summary, findings, status = audit_plugins.compare_source_and_artifact(
                extract, "owner", "repo", "v1"
            )

        self.assertEqual(status.status, "found_issue")
        self.assertEqual(summary["zip_only_scripts"], [])
        grouped = [f for f in findings if f.rule_id == "BUNDLED_DEPENDENCY_SCRIPTS"]
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0].classification, "PASS_WITH_WARNINGS")
        self.assertIn("count=3", grouped[0].evidence)
        self.assertEqual(summary["grouped_zip_only_scripts_count"], 3)

    def test_dependency_native_extensions_are_one_manual_review_finding(self):
        elf = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 32)
        extract = self._mk_extract({
            "Plugin/py_modules/pkg/a.so": elf,
            "Plugin/py_modules/pkg/b.so": elf,
        })
        with self._patch_empty_source_tree():
            summary, findings, _ = audit_plugins.compare_source_and_artifact(
                extract, "owner", "repo", "v1"
            )

        self.assertEqual(summary["zip_only_executables"], [])
        grouped = [
            f for f in findings
            if f.rule_id == "BUNDLED_DEPENDENCY_EXECUTABLES"
        ]
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0].classification, "MANUAL_REVIEW")
        self.assertIn("count=2", grouped[0].evidence)

    def test_generated_dist_scripts_are_collapsed(self):
        extract = self._mk_extract({
            "Plugin/dist/index.js": "console.log('index')\n",
            "Plugin/dist/runtime.js": "console.log('runtime')\n",
        })
        with self._patch_empty_source_tree():
            summary, findings, _ = audit_plugins.compare_source_and_artifact(
                extract, "owner", "repo", "v1"
            )

        self.assertEqual(summary["zip_only_scripts"], [])
        grouped = [f for f in findings if f.rule_id == "GENERATED_BUILD_SCRIPTS"]
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0].classification, "PASS_WITH_WARNINGS")
        self.assertEqual(grouped[0].path, "Plugin/dist/")

    def test_vendored_scripts_remain_manual_review_but_are_collapsed(self):
        extract = self._mk_extract({
            "Plugin/vendor/tool/a.py": "value = 1\n",
            "Plugin/vendor/tool/b.py": "value = 2\n",
        })
        with self._patch_empty_source_tree():
            summary, findings, _ = audit_plugins.compare_source_and_artifact(
                extract, "owner", "repo", "v1"
            )

        self.assertEqual(summary["zip_only_scripts"], [])
        grouped = [
            f for f in findings
            if f.rule_id == "VENDORED_DEPENDENCY_SCRIPTS"
        ]
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0].classification, "MANUAL_REVIEW")

    def test_unexpected_plugin_owned_script_remains_individual(self):
        extract = self._mk_extract({"Plugin/extra.py": "print('unexpected')\n"})
        with self._patch_empty_source_tree():
            summary, findings, _ = audit_plugins.compare_source_and_artifact(
                extract, "owner", "repo", "v1"
            )

        self.assertEqual(summary["zip_only_scripts"], ["Plugin/extra.py"])
        self.assertEqual([f.rule_id for f in findings], ["ZIP_ONLY_SCRIPT"])
        self.assertEqual(findings[0].classification, "MANUAL_REVIEW")

    def test_mixed_bundle_and_plugin_file_preserves_actionable_finding(self):
        extract = self._mk_extract({
            "Plugin/node_modules/pkg/index.js": "module.exports = 1\n",
            "Plugin/extra.py": "print('unexpected')\n",
        })
        with self._patch_empty_source_tree():
            summary, findings, status = audit_plugins.compare_source_and_artifact(
                extract, "owner", "repo", "v1"
            )

        rule_ids = {f.rule_id for f in findings}
        self.assertEqual(status.status, "found_issue")
        self.assertIn("BUNDLED_DEPENDENCY_SCRIPTS", rule_ids)
        self.assertIn("ZIP_ONLY_SCRIPT", rule_ids)
        self.assertEqual(summary["zip_only_scripts"], ["Plugin/extra.py"])
        self.assertEqual(summary["grouped_zip_only_scripts_count"], 1)
        self.assertEqual(summary["actionable_zip_only_scripts_count"], 1)

    def test_similarly_named_file_is_not_dependency_directory(self):
        extract = self._mk_extract({"Plugin/py_modules.py": "print('owned')\n"})
        with self._patch_empty_source_tree():
            summary, findings, _ = audit_plugins.compare_source_and_artifact(
                extract, "owner", "repo", "v1"
            )

        self.assertEqual(summary["zip_only_scripts"], ["Plugin/py_modules.py"])
        self.assertEqual([f.rule_id for f in findings], ["ZIP_ONLY_SCRIPT"])


if __name__ == "__main__":
    unittest.main()
