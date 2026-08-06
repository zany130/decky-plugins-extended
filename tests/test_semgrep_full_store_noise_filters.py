"""Regression tests derived from the first cacheless full-store Semgrep baseline."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import semgrep_source_scanning as semgrep_scanning


@dataclass
class Finding:
    rule_id: str
    severity: str
    classification: str
    path: str
    line: int
    message: str
    evidence: str
    scanner: str
    allowlisted: bool = False


class SemgrepFullStoreNoiseFilterTests(unittest.TestCase):
    @staticmethod
    def _core() -> ModuleType:
        core = ModuleType("fake_semgrep_core")
        core.Finding = Finding
        core.EVIDENCE_MAX_LEN = 256
        core._truncate = lambda value, limit: str(value)[:limit]
        return core

    def test_local_source_restores_evidence_hidden_by_semgrep_oss(self) -> None:
        core = self._core()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "scripts" / "runtime.mjs"
            path.parent.mkdir(parents=True)
            path.write_text(
                "const value = 1;\nexecSync(\"git rev-parse --short HEAD\");\n",
                encoding="utf-8",
            )
            result = {
                "check_id": "decky.javascript.child-process-exec",
                "path": str(path),
                "start": {"line": 2},
                "end": {"line": 2},
                "extra": {
                    "severity": "WARNING",
                    "message": "Node.js invokes a shell-backed child-process API.",
                    "lines": "requires login",
                },
            }
            evidence = semgrep_scanning._result_evidence(
                core, result, root, "scripts/runtime.mjs"
            )

        self.assertEqual(evidence, 'execSync("git rev-parse --short HEAD");')

    def test_repository_packaging_tooling_is_not_runtime_behavior(self) -> None:
        core = self._core()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "scripts" / "package.mjs"
            path.parent.mkdir(parents=True)
            path.write_text('execSync("git rev-parse --short HEAD")\n', encoding="utf-8")
            result = {
                "check_id": "decky.javascript.child-process-exec",
                "path": str(path),
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "WARNING", "lines": "requires login"},
            }
            finding, provenance = semgrep_scanning._result_to_finding(
                core, result, root, "source"
            )

        self.assertIsNone(finding)
        self.assertEqual(provenance, "repository_tooling")

    def test_private_key_header_constant_in_code_defers_to_credential_scanner(self) -> None:
        core = self._core()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "src" / "key_parser.py"
            path.parent.mkdir(parents=True)
            path.write_text(
                'HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----"\n',
                encoding="utf-8",
            )
            result = {
                "check_id": "decky.generic.private-key",
                "path": str(path),
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "ERROR", "lines": "requires login"},
            }
            finding, provenance = semgrep_scanning._result_to_finding(
                core, result, root, "source"
            )

        self.assertIsNone(finding)
        self.assertEqual(provenance, "credential_scanner_owned")

    def test_dependency_and_repository_tooling_parse_errors_are_suppressed(self) -> None:
        core = self._core()
        with tempfile.TemporaryDirectory() as root:
            dependency = Path(root) / "Plugin" / "py_modules" / "urllib3" / "connection.py"
            tooling = Path(root) / "scripts" / "dev_ui_scale.py"
            dependency.parent.mkdir(parents=True)
            tooling.parent.mkdir(parents=True)
            dependency.write_text("broken syntax", encoding="utf-8")
            tooling.write_text("broken syntax", encoding="utf-8")
            findings, suppressed = semgrep_scanning._parse_error_findings(
                core,
                [
                    {"path": str(dependency), "message": "parse error"},
                    {"path": str(tooling), "message": "parse error"},
                ],
                root,
                "artifact",
            )

        self.assertEqual(findings, [])
        self.assertEqual(suppressed, 2)

    def test_plugin_runtime_parse_error_remains_visible_with_detail(self) -> None:
        core = self._core()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "main.py"
            path.write_text("broken syntax", encoding="utf-8")
            findings, suppressed = semgrep_scanning._parse_error_findings(
                core,
                [
                    {
                        "path": str(path),
                        "message": "unexpected token",
                        "location": {"start": {"line": 7}},
                    }
                ],
                root,
                "source",
            )

        self.assertEqual(suppressed, 0)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "main.py")
        self.assertEqual(findings[0].line, 7)
        self.assertIn("unexpected token", findings[0].evidence)

    def test_partial_scan_duplicates_merge_across_artifact_and_source(self) -> None:
        artifact = Finding(
            "SEMGREP_PARTIAL_SCAN",
            "low",
            "PASS_WITH_WARNINGS",
            "Plugin/main.py",
            0,
            "[artifact] Semgrep could not fully analyze 1 plugin-owned target(s).",
            "Plugin/main.py; first error: parse error",
            "semgrep",
        )
        source = Finding(
            "SEMGREP_PARTIAL_SCAN",
            "low",
            "PASS_WITH_WARNINGS",
            "main.py",
            0,
            "[source] Semgrep could not fully analyze 1 plugin-owned target(s).",
            "main.py; first error: parse error",
            "semgrep",
        )

        merged = semgrep_scanning._merge_scoped_findings([artifact], [source])

        self.assertEqual(len(merged), 1)
        self.assertIn("[artifact+source]", merged[0].message)


if __name__ == "__main__":
    unittest.main()
