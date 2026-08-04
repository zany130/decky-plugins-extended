"""Regression tests for exact Decky metadata build-stamp filtering."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import metadata_build_stamp_filters as mbs
import source_content_comparison as scc


@dataclass
class FakeFinding:
    rule_id: str
    path: str


@dataclass
class FakeStatus:
    name: str = "source-artifact-diff"
    status: str = "found_issue"
    detail: str | None = None


class MetadataBuildStampTests(unittest.TestCase):
    def test_package_version_stamp_is_suppressed(self):
        source = json.dumps({"name": "plugin", "version": "0.0.0"}).encode()
        artifact = json.dumps({"name": "plugin", "version": "1.2.3"}).encode()
        self.assertTrue(
            mbs._metadata_diff_is_build_stamped("package.json", source, artifact)
        )

    def test_plugin_exact_build_stamps_are_suppressed(self):
        source = json.dumps({
            "name": "Plugin",
            "version": "0.0.0",
            "flags": ["debug", "root"],
            "publish": {"image": "https://raw.example/repo/main/icon.png"},
        }).encode()
        artifact = json.dumps({
            "name": "Plugin",
            "version": "1.2.3",
            "flags": ["root"],
            "publish": {"image": "https://raw.example/repo/v1.2.3/icon.png"},
        }).encode()
        self.assertTrue(
            mbs._metadata_diff_is_build_stamped("plugin.json", source, artifact)
        )

    def test_added_root_flag_is_not_suppressed(self):
        source = json.dumps({
            "name": "Plugin", "version": "1.2.3", "flags": []
        }).encode()
        artifact = json.dumps({
            "name": "Plugin", "version": "1.2.3", "flags": ["root"]
        }).encode()
        self.assertFalse(
            mbs._metadata_diff_is_build_stamped("plugin.json", source, artifact)
        )

    def test_unrelated_metadata_change_is_not_suppressed(self):
        source = json.dumps({
            "name": "Plugin", "version": "1.2.3", "author": "Alice"
        }).encode()
        artifact = json.dumps({
            "name": "Plugin", "version": "1.2.3", "author": "Mallory"
        }).encode()
        self.assertFalse(
            mbs._metadata_diff_is_build_stamped("plugin.json", source, artifact)
        )

    def test_malformed_json_is_not_suppressed(self):
        self.assertFalse(
            mbs._metadata_diff_is_build_stamped(
                "plugin.json", b"{not json", b"{}"
            )
        )

    def test_wrapper_removes_only_expected_metadata_finding(self):
        core = SimpleNamespace()
        core._source_content_comparison_installed = True

        with tempfile.TemporaryDirectory() as temp:
            artifact_root = Path(temp) / "artifact"
            source_root = Path(temp) / "source"
            artifact_root.mkdir()
            source_root.mkdir()
            (source_root / "plugin.json").write_text(json.dumps({
                "name": "Plugin",
                "version": "0.0.0",
                "flags": ["debug"],
                "publish": {"image": "https://raw.example/repo/main/icon.png"},
            }))
            (artifact_root / "plugin.json").write_text(json.dumps({
                "name": "Plugin",
                "version": "1.0.0",
                "flags": [],
                "publish": {"image": "https://raw.example/repo/v1.0.0/icon.png"},
            }))
            (source_root / "main.py").write_text("source")
            (artifact_root / "main.py").write_text("release")

            records = [
                {
                    "artifact_path": "plugin.json",
                    "source_path": "plugin.json",
                    "artifact_sha256": "a",
                    "source_sha256": "b",
                },
                {
                    "artifact_path": "main.py",
                    "source_path": "main.py",
                    "artifact_sha256": "c",
                    "source_sha256": "d",
                },
            ]
            findings = [
                FakeFinding("SAME_PATH_CONTENT_MISMATCH", "plugin.json"),
                FakeFinding("SAME_PATH_CONTENT_MISMATCH", "main.py"),
            ]
            summary = {
                "same_path_compared": 2,
                "same_path_modified": records,
                "generated_or_dependency_differences": [],
            }
            core.compare_source_and_artifact = lambda *args: (
                summary,
                list(findings),
                FakeStatus(),
            )
            mbs.install(core)

            token = scc._CURRENT_SHARED_SOURCE.set({
                "source_root": str(source_root)
            })
            try:
                result_summary, result_findings, result_status = (
                    core.compare_source_and_artifact(
                        str(artifact_root), "owner", "repo", "v1.0.0"
                    )
                )
            finally:
                scc._CURRENT_SHARED_SOURCE.reset(token)

        self.assertEqual(
            [r["artifact_path"] for r in result_summary["same_path_modified"]],
            ["main.py"],
        )
        self.assertEqual(
            result_summary["expected_build_stamp_differences"][0][
                "artifact_path"
            ],
            "plugin.json",
        )
        self.assertEqual([f.path for f in result_findings], ["main.py"])
        self.assertEqual(result_status.status, "found_issue")
        self.assertIn("1 expected metadata build stamp", result_status.detail)


if __name__ == "__main__":
    unittest.main()
