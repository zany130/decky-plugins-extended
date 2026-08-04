"""Regression tests for exact-release source dependency scanning."""

import io
import tarfile
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

import trivy_source_scanning as tss


@dataclass
class FakeFinding:
    rule_id: str = "TRIVY_CVE_TEST"
    severity: str = "high"
    classification: str = "MANUAL_REVIEW"
    path: str = "lodash"
    line: int = 0
    message: str = "CVE in lodash"
    evidence: str = "CVE-TEST lodash@1.0"
    scanner: str = "trivy"
    allowlisted: bool = False


@dataclass
class FakeStatus:
    name: str
    status: str
    detail: str | None = None


class TrivySourceScanningTests(unittest.TestCase):
    def make_core(self, artifact_findings=None, source_findings=None):
        artifact_findings = artifact_findings or []
        source_findings = source_findings or []
        core = SimpleNamespace()
        core.POLICY_VERSION = "1"
        core.CACHE_DIR = ".audit-cache"
        core.DOWNLOAD_TIMEOUT = 120
        core.ScannerStatus = FakeStatus
        core.parse_owner_repo = lambda _url: ("owner", "repo")
        core.get_releases = lambda _o, _r: [
            {"tag_name": "v1.0.0", "assets": [{"name": "plugin.zip"}]}
        ]
        core.find_best_release = lambda releases: releases[0]
        core._gh_get = lambda _url: {
            "object": {"type": "commit", "sha": "abc123"}
        }
        core._cache_key = lambda repo, release, sha, policy_version="1": (
            f"{repo}|{release}|{sha}|{policy_version}"
        )
        calls = []

        def raw_run(directory, _policy):
            calls.append(directory)
            if directory == "/artifact":
                findings = list(artifact_findings)
            else:
                findings = list(source_findings)
            return FakeStatus(
                "trivy", "found_issue" if findings else "passed"
            ), findings

        core.run_trivy = raw_run

        def raw_audit(repo_url, policy, exceptions, cache_dir, skip_cache):
            core.find_best_release(core.get_releases("owner", "repo"))
            status, findings = core.run_trivy("/artifact", policy)
            return SimpleNamespace(
                repository=repo_url,
                release="v1.0.0",
                artifact_sha256="deadbeef",
                scanner_statuses=[status],
                findings=findings,
            )

        core.audit_repository = raw_audit
        core._is_safe_member_path = self.safe_member
        return core, calls

    @staticmethod
    def safe_member(name):
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            return False, "path traversal"
        return True, ""

    def test_scans_exact_source_tree_and_labels_finding(self):
        source = [FakeFinding()]
        core, calls = self.make_core(source_findings=source)
        tss.install(core)

        with patch.object(tss, "_fetch_source_tree", return_value="/source"):
            report = core.audit_repository(
                "https://github.com/owner/repo",
                {"archive": {}},
                [],
            )

        self.assertEqual(calls, ["/artifact", "/source"])
        self.assertEqual(report.findings[0].path, "source:lodash")
        self.assertIn(
            "source scanned (1 findings)", report.scanner_statuses[0].detail
        )

    def test_source_fetch_failure_is_not_reported_as_passed(self):
        core, _ = self.make_core()
        tss.install(core)

        with patch.object(
            tss, "_fetch_source_tree", side_effect=ValueError("boom")
        ):
            report = core.audit_repository(
                "https://github.com/owner/repo",
                {"archive": {}},
                [],
            )

        self.assertEqual(report.scanner_statuses[0].status, "failed")
        self.assertIn(
            "source fetch failed: boom", report.scanner_statuses[0].detail
        )

    def test_duplicate_vulnerability_across_scopes_is_collapsed(self):
        artifact = [FakeFinding()]
        source = [FakeFinding()]
        core, _ = self.make_core(artifact, source)
        tss.install(core)

        with patch.object(tss, "_fetch_source_tree", return_value="/source"):
            report = core.audit_repository(
                "https://github.com/owner/repo",
                {"archive": {}},
                [],
            )

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].path, "artifact+source:lodash")
        self.assertTrue(
            report.findings[0].message.startswith("[artifact+source]")
        )

    def test_cache_key_changes_for_source_scanning(self):
        core, _ = self.make_core()
        original = core._cache_key("repo", "v1", "sha")
        tss.install(core)
        updated = core._cache_key("repo", "v1", "sha")
        self.assertNotEqual(original, updated)
        self.assertIn("trivy-source-v1", updated)

    def test_source_archive_rejects_traversal(self):
        core, _ = self.make_core()
        policy = {"archive": {}}
        with tempfile.TemporaryDirectory() as temp:
            archive_path = Path(temp) / "bad.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                info = tarfile.TarInfo("root/../../escape.txt")
                payload = b"bad"
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            with self.assertRaisesRegex(ValueError, "Unsafe source archive"):
                tss._extract_source_archive(
                    core, archive_path, Path(temp) / "out", policy
                )

    def test_source_archive_skips_symlinks(self):
        core, _ = self.make_core()
        policy = {"archive": {}}
        with tempfile.TemporaryDirectory() as temp:
            archive_path = Path(temp) / "source.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                data = b"lockfileVersion: 9"
                info = tarfile.TarInfo("root/pnpm-lock.yaml")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
                link = tarfile.TarInfo("root/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "pnpm-lock.yaml"
                archive.addfile(link)
            root = Path(
                tss._extract_source_archive(
                    core, archive_path, Path(temp) / "out", policy
                )
            )
            self.assertTrue((root / "pnpm-lock.yaml").is_file())
            self.assertFalse((root / "link").exists())


if __name__ == "__main__":
    unittest.main()
