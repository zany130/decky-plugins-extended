"""Regression tests for exact-release same-path content comparison."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import source_content_comparison as scc
import trivy_source_scanning as tss


@dataclass
class FakeFinding:
    rule_id: str
    severity: str
    classification: str
    path: str
    line: int
    message: str
    evidence: str
    scanner: str
    allowlisted: bool = False


@dataclass
class FakeStatus:
    name: str
    status: str
    version: str | None = None
    db_version: str | None = None
    detail: str | None = None


def make_core():
    core = SimpleNamespace()
    core.Finding = FakeFinding
    core.ScannerStatus = FakeStatus
    core.POLICY_VERSION = "1"
    core.CACHE_DIR = ".audit-cache"
    core.identify_binary = lambda data, path: (
        {"label": "ELF", "path": path} if data.startswith(b"\x7fELF") else None
    )
    core._looks_like_script_asset = lambda path, raw, executable: (
        Path(path).suffix.lower() in {".py", ".js", ".sh"}
        or raw.startswith(b"#!")
        or executable
    )
    return core


class SourceContentComparisonTests(unittest.TestCase):
    def compare(self, artifact_files, source_files, executable=()):
        core = make_core()
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "artifact"
            source = Path(temp) / "source"
            artifact.mkdir()
            source.mkdir()
            for path, data in artifact_files.items():
                target = artifact / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                if path in executable:
                    target.chmod(0o755)
            for path, data in source_files.items():
                target = source / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            return scc._compare_from_local_source(
                core, str(artifact), "v1", str(source), "abc123"
            )

    def test_same_path_script_mismatch_requires_manual_review(self):
        summary, findings, status = self.compare(
            {"backend/main.py": b"print('release')\n"},
            {"backend/main.py": b"print('source')\n"},
        )
        mismatch = [f for f in findings if f.rule_id == "SAME_PATH_CONTENT_MISMATCH"]
        self.assertEqual(len(mismatch), 1)
        self.assertEqual(mismatch[0].classification, "MANUAL_REVIEW")
        self.assertEqual(
            summary["same_path_modified"][0]["source_path"], "backend/main.py"
        )
        self.assertEqual(status.status, "found_issue")

    def test_identical_same_path_file_passes(self):
        summary, findings, status = self.compare(
            {"backend/main.py": b"same\n"},
            {"backend/main.py": b"same\n"},
        )
        self.assertEqual(summary["same_path_compared"], 1)
        self.assertEqual(findings, [])
        self.assertEqual(status.status, "passed")

    def test_release_wrapper_directory_is_normalized(self):
        summary, findings, _status = self.compare(
            {"PluginName/backend/main.py": b"release\n"},
            {"backend/main.py": b"source\n"},
        )
        self.assertEqual(summary["same_path_compared"], 1)
        self.assertEqual(findings[0].rule_id, "SAME_PATH_CONTENT_MISMATCH")
        self.assertEqual(findings[0].path, "PluginName/backend/main.py")

    def test_generated_mismatches_are_grouped_as_warning(self):
        summary, findings, _status = self.compare(
            {
                "dist/assets/app.12345678.js": b"release-a",
                "dist/assets/vendor.87654321.js": b"release-b",
            },
            {
                "dist/assets/app.12345678.js": b"source-a",
                "dist/assets/vendor.87654321.js": b"source-b",
            },
        )
        self.assertEqual(len(summary["generated_or_dependency_differences"]), 2)
        grouped = [
            f for f in findings if f.rule_id == "GENERATED_SAME_PATH_CONTENT_DIFF"
        ]
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0].classification, "PASS_WITH_WARNINGS")
        self.assertFalse(
            any(f.rule_id == "SAME_PATH_CONTENT_MISMATCH" for f in findings)
        )

    def test_native_binary_mismatch_remains_manual_review_in_dist(self):
        _summary, findings, _status = self.compare(
            {"dist/helper": b"\x7fELFrelease"},
            {"dist/helper": b"\x7fELFsource"},
        )
        self.assertTrue(
            any(f.rule_id == "SAME_PATH_CONTENT_MISMATCH" for f in findings)
        )

    def test_zip_only_script_detection_is_preserved(self):
        summary, findings, _status = self.compare(
            {"backend/injected.py": b"print('x')"},
            {},
        )
        self.assertEqual(summary["zip_only_scripts"], ["backend/injected.py"])
        self.assertTrue(any(f.rule_id == "ZIP_ONLY_SCRIPT" for f in findings))

    def test_hidden_path_name_is_not_destroyed_by_normalization(self):
        self.assertEqual(
            scc._normalize_relative("./.github/workflows/a.yml"),
            ".github/workflows/a.yml",
        )

    def test_shared_source_is_fetched_once_for_trivy_and_diff(self):
        core = make_core()
        core._trivy_source_scanning_installed = True
        core._cache_key = lambda repo, release, sha, policy_version="1": (
            f"{repo}|{release}|{sha}|{policy_version}"
        )
        core._raw_run_trivy_artifact_only = lambda directory, policy: (
            FakeStatus("trivy", "passed"),
            [],
        )
        core.compare_source_and_artifact = lambda *args: (
            {"checked": False},
            [],
            FakeStatus("source-artifact-diff", "failed"),
        )

        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "artifact"
            source = Path(temp) / "source"
            artifact.mkdir()
            source.mkdir()
            (artifact / "main.py").write_text("release")
            (source / "main.py").write_text("source")

            def trivy_wrapped_audit(
                repo_url, policy, exceptions, cache_dir, skip_cache
            ):
                exact_token = tss._CURRENT_SOURCE.set({
                    "owner": "owner",
                    "repo": "repo",
                    "commit_sha": "abc123",
                    "error": None,
                })
                try:
                    trivy_status, _ = core.run_trivy(str(artifact), policy)
                    summary, findings, diff_status = core.compare_source_and_artifact(
                        str(artifact), "owner", "repo", "v1"
                    )
                    return SimpleNamespace(
                        scanner_statuses=[trivy_status, diff_status],
                        source_artifact_diff=summary,
                        findings=findings,
                    )
                finally:
                    tss._CURRENT_SOURCE.reset(exact_token)

            core.audit_repository = trivy_wrapped_audit
            scc.install(core)

            with patch.object(
                tss, "_fetch_source_tree", return_value=str(source)
            ) as fetch:
                report = core.audit_repository(
                    "https://github.com/owner/repo", {"archive": {}}, []
                )

            self.assertEqual(fetch.call_count, 1)
            self.assertEqual(report.scanner_statuses[0].status, "passed")
            self.assertTrue(
                any(
                    f.rule_id == "SAME_PATH_CONTENT_MISMATCH"
                    for f in report.findings
                )
            )

    def test_install_versions_cache_key(self):
        core = make_core()
        core._trivy_source_scanning_installed = True
        core._raw_run_trivy_artifact_only = lambda directory, policy: (
            FakeStatus("trivy", "passed"),
            [],
        )
        core.compare_source_and_artifact = lambda *args: (
            {},
            [],
            FakeStatus("source-artifact-diff", "passed"),
        )
        core.audit_repository = lambda *args, **kwargs: None
        core._cache_key = (
            lambda repo, release, sha, policy_version="1": policy_version
        )
        scc.install(core)
        self.assertIn(
            "source-content-v1", core._cache_key("r", "v", "s")
        )


if __name__ == "__main__":
    unittest.main()
