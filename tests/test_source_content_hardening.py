"""Regression tests for shared-source context and path-collision hardening."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import source_content_comparison as scc
import source_content_hardening as sch
import trivy_source_scanning as tss


@dataclass
class FakeStatus:
    name: str
    status: str
    detail: str | None = None


class SourceContentHardeningTests(unittest.TestCase):
    def make_core(self):
        core = SimpleNamespace()
        core._source_content_comparison_installed = True
        core.ScannerStatus = FakeStatus
        core._raw_run_trivy_artifact_only = Mock(
            return_value=(FakeStatus("trivy", "passed", "artifact only"), [])
        )
        core.run_trivy = Mock(
            return_value=(FakeStatus("trivy", "failed", "shared failed"), [])
        )
        core.compare_source_and_artifact = Mock(
            return_value=(
                {"checked": True},
                [],
                FakeStatus("source-artifact-diff", "passed"),
            )
        )
        return core

    def test_direct_trivy_call_falls_back_to_artifact_only(self):
        core = self.make_core()
        shared_wrapper = core.run_trivy
        sch.install(core)

        exact_token = tss._CURRENT_SOURCE.set({
            "owner": "owner", "repo": "repo", "commit_sha": "abc", "error": None
        })
        try:
            status, findings = core.run_trivy("/artifact", {})
        finally:
            tss._CURRENT_SOURCE.reset(exact_token)

        self.assertEqual(status.status, "passed")
        self.assertEqual(findings, [])
        core._raw_run_trivy_artifact_only.assert_called_once_with("/artifact", {})
        shared_wrapper.assert_not_called()

    def test_full_audit_context_keeps_shared_trivy(self):
        core = self.make_core()
        shared_wrapper = core.run_trivy
        sch.install(core)
        token = scc._CURRENT_SHARED_SOURCE.set({"source_root": "/source"})
        try:
            status, _ = core.run_trivy("/artifact", {})
        finally:
            scc._CURRENT_SHARED_SOURCE.reset(token)
        self.assertEqual(status.status, "failed")
        shared_wrapper.assert_called_once_with("/artifact", {})

    def test_case_colliding_source_paths_fail_closed(self):
        core = self.make_core()
        original_compare = core.compare_source_and_artifact
        sch.install(core)

        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            (source / "Main.py").write_text("one")
            (source / "main.py").write_text("two")
            token = scc._CURRENT_SHARED_SOURCE.set({
                "source_root": str(source),
                "commit_sha": "abc123",
            })
            try:
                summary, findings, status = core.compare_source_and_artifact(
                    "/artifact", "owner", "repo", "v1"
                )
            finally:
                scc._CURRENT_SHARED_SOURCE.reset(token)

        self.assertFalse(summary["checked"])
        self.assertEqual(
            summary["source_case_collisions"], [["Main.py", "main.py"]]
        )
        self.assertEqual(findings, [])
        self.assertEqual(status.status, "failed")
        self.assertIn("Ambiguous", status.detail)
        original_compare.assert_not_called()

    def test_unambiguous_source_delegates_to_comparator(self):
        core = self.make_core()
        original_compare = core.compare_source_and_artifact
        sch.install(core)

        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            (source / "main.py").write_text("one")
            token = scc._CURRENT_SHARED_SOURCE.set({
                "source_root": str(source),
                "commit_sha": "abc123",
            })
            try:
                summary, _findings, status = core.compare_source_and_artifact(
                    "/artifact", "owner", "repo", "v1"
                )
            finally:
                scc._CURRENT_SHARED_SOURCE.reset(token)

        self.assertTrue(summary["checked"])
        self.assertEqual(status.status, "passed")
        original_compare.assert_called_once_with(
            "/artifact", "owner", "repo", "v1"
        )


if __name__ == "__main__":
    unittest.main()
