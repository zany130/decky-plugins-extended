"""Regression tests for local-rule artifact and exact-source Semgrep scanning."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import yaml

import semgrep_source_scanning as semgrep_scanning
import source_content_comparison as source_content


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


@dataclass
class ScannerStatus:
    name: str
    status: str
    version: str | None = None
    db_version: str | None = None
    detail: str | None = None


class SemgrepRuleTests(unittest.TestCase):
    def test_rules_match_the_upstream_decky_baseline(self):
        rules_path = Path(semgrep_scanning._SEMGREP_RULES_FILE)
        data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
        rule_ids = {rule["id"] for rule in data["rules"]}

        self.assertEqual(
            rule_ids,
            {
                "decky.python.dynamic-execution",
                "decky.python.shell-command",
                "decky.javascript.dynamic-execution",
                "decky.javascript.child-process-exec",
                "decky.generic.private-key",
            },
        )
        self.assertNotIn("auto", rules_path.read_text(encoding="utf-8").lower())


class SemgrepIntegrationTests(unittest.TestCase):
    @staticmethod
    def _core() -> ModuleType:
        core = ModuleType("fake_semgrep_core")
        core.Finding = Finding
        core.ScannerStatus = ScannerStatus
        core.EVIDENCE_MAX_LEN = 256
        core.POLICY_VERSION = "1"
        core._truncate = lambda value, limit: str(value)[:limit]
        core._scanner_enabled = lambda policy, name: bool(
            policy.get("scanners", {}).get(name, {}).get("enabled", True)
        )
        core._run_scanner = lambda *_args, **_kwargs: (True, "{}", "")
        core._source_content_comparison_installed = True
        core.run_semgrep = lambda _root, _policy: (
            ScannerStatus("semgrep", "passed"),
            [],
        )
        core._cache_key = lambda repository, release, sha, policy_version="1": (
            f"{repository}|{release}|{sha}|{policy_version}"
        )
        return core

    def test_scope_runner_uses_local_rules_without_registry_or_metrics(self):
        core = self._core()
        payload = json.dumps({"version": "1.132.0", "results": [], "errors": []})
        with tempfile.TemporaryDirectory() as root, patch.object(
            semgrep_scanning.shutil, "which", return_value="/usr/bin/semgrep"
        ), patch.object(core, "_run_scanner", return_value=(True, payload, "")) as run:
            status, findings, suppressed = semgrep_scanning._run_scope(
                core, root, "artifact"
            )

        command = run.call_args.args[0]
        self.assertIn(semgrep_scanning._SEMGREP_RULES_FILE, command)
        self.assertIn("--metrics=off", command)
        self.assertIn("--disable-version-check", command)
        self.assertNotIn("auto", command)
        self.assertEqual(status.status, "passed")
        self.assertEqual(findings, [])
        self.assertEqual(suppressed, 0)

    def test_runtime_finding_includes_scope_provenance_and_reviewer_guidance(self):
        core = self._core()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "src" / "main.py"
            path.parent.mkdir(parents=True)
            path.write_text("exec(payload)\n", encoding="utf-8")
            result = {
                "check_id": "decky.python.dynamic-execution",
                "path": str(path),
                "start": {"line": 1},
                "extra": {
                    "severity": "WARNING",
                    "message": "Dynamic Python execution requires review.",
                    "lines": "exec(payload)",
                },
            }
            finding, provenance = semgrep_scanning._result_to_finding(
                core, result, root, "source"
            )

        self.assertEqual(provenance, "plugin_runtime")
        self.assertEqual(finding.path, "src/main.py")
        self.assertEqual(finding.line, 1)
        self.assertEqual(finding.classification, "MANUAL_REVIEW")
        self.assertEqual(finding.severity, "medium")
        self.assertIn("[source; plugin_runtime", finding.message)
        self.assertIn("Reviewer focus", finding.message)
        self.assertEqual(finding.scanner, "semgrep")

    def test_dependency_code_match_is_suppressed(self):
        core = self._core()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "Plugin" / "node_modules" / "pkg" / "index.js"
            path.parent.mkdir(parents=True)
            path.write_text("eval(code)\n", encoding="utf-8")
            result = {
                "check_id": "decky.javascript.dynamic-execution",
                "path": str(path),
                "start": {"line": 1},
                "extra": {"severity": "WARNING", "lines": "eval(code)"},
            }
            finding, provenance = semgrep_scanning._result_to_finding(
                core, result, root, "artifact"
            )

        self.assertIsNone(finding)
        self.assertEqual(provenance, "dependency_or_vendored")

    def test_private_key_match_remains_visible_in_documentation(self):
        core = self._core()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "docs" / "example.pem"
            path.parent.mkdir(parents=True)
            path.write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
            result = {
                "check_id": "decky.generic.private-key",
                "path": str(path),
                "start": {"line": 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "A private-key block is embedded.",
                    "lines": "-----BEGIN PRIVATE KEY-----",
                },
            }
            finding, provenance = semgrep_scanning._result_to_finding(
                core, result, root, "artifact"
            )

        self.assertEqual(provenance, "documentation_or_test")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.classification, "MANUAL_REVIEW")
        self.assertEqual(finding.severity, "high")

    def test_equivalent_wrapper_and_source_hits_are_deduplicated(self):
        artifact = Finding(
            "SEMGREP_DECKY_PYTHON_SHELL_COMMAND",
            "medium",
            "MANUAL_REVIEW",
            "Plugin/main.py",
            10,
            "[artifact; plugin_runtime; confidence=high] test",
            "subprocess.run(command, shell=True)",
            "semgrep",
        )
        source = Finding(
            "SEMGREP_DECKY_PYTHON_SHELL_COMMAND",
            "medium",
            "MANUAL_REVIEW",
            "main.py",
            10,
            "[source; plugin_runtime; confidence=high] test",
            "subprocess.run(command, shell=True)",
            "semgrep",
        )

        merged = semgrep_scanning._merge_scoped_findings([artifact], [source])

        self.assertEqual(len(merged), 1)
        self.assertIn("[artifact+source;", merged[0].message)

    def test_install_scans_artifact_and_shared_exact_source(self):
        core = self._core()
        semgrep_scanning.install(core)
        artifact = Finding(
            "SEMGREP_A", "medium", "MANUAL_REVIEW", "dist/index.js", 1,
            "[artifact; generated_runtime_bundle; confidence=medium] a", "a", "semgrep"
        )
        source = Finding(
            "SEMGREP_B", "medium", "MANUAL_REVIEW", "src/main.py", 2,
            "[source; plugin_runtime; confidence=high] b", "b", "semgrep"
        )
        token = source_content._CURRENT_SHARED_SOURCE.set({"source_root": "/tmp/source"})
        try:
            with patch.object(
                semgrep_scanning,
                "_run_scope",
                side_effect=[
                    (ScannerStatus("semgrep", "found_issue", detail="artifact"), [artifact], 0),
                    (ScannerStatus("semgrep", "found_issue", detail="source"), [source], 0),
                ],
            ), patch.object(source_content, "_ensure_shared_source", return_value="/tmp/source"):
                status, findings = core.run_semgrep(
                    "/tmp/artifact",
                    {"scanners": {"semgrep": {"enabled": True}}},
                )
        finally:
            source_content._CURRENT_SHARED_SOURCE.reset(token)

        self.assertEqual(status.status, "found_issue")
        self.assertEqual({finding.path for finding in findings}, {"dist/index.js", "src/main.py"})
        self.assertIn("decky-semgrep-v1", core._cache_key("r", "v", "sha"))


if __name__ == "__main__":
    unittest.main()
